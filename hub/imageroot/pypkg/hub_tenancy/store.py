"""Atomic file-locked CRUD on `state/tenants.json` (`0600`) and SHA-256 token management."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Any, Final, Iterator

CUSTOMER_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9-]{1,46}[a-z0-9]\Z")
SITE_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9-]{0,46}[a-z0-9]\Z")
COLLECTOR_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]\Z")
EMAIL_RE: Final[re.Pattern[str]] = re.compile(r"\A[^@\s]+@[^@\s]+\.[^@\s]+\Z")
VIEWER_USER_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-zA-Z0-9._@-]{3,64}\Z")
RESERVED_PORTAL_USERNAMES: Final[frozenset[str]] = frozenset(
    {"admin", "root", "grafana", "system", "anonymous"}
)


def resolve_state_dir(explicit: str | Path | None = None) -> Path:
    """Resolve NS8 module state directory honoring HUB_STATE_DIR, AGENT_STATE_DIR, and STATE_DIR."""
    if explicit is not None:
        return Path(explicit)
    env_dir = (
        os.environ.get("HUB_STATE_DIR")
        or os.environ.get("AGENT_STATE_DIR")
        or os.environ.get("STATE_DIR")
    )
    return Path(env_dir) if env_dir else Path(os.getcwd())


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(dt: datetime | None = None) -> str:
    target = _utc_now() if dt is None else dt.astimezone(timezone.utc)
    return target.strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def _file_lock(lock_path: Path) -> Iterator[None]:
    """Cross-platform advisory file lock (fcntl on Linux/NS8, msvcrt on Windows)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":  # pragma: no cover - Windows test host
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            for _ in range(200):
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.01)
            else:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        else:  # pragma: no cover - Linux NS8 runtime
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _atomic_write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_ns = path.stat().st_mtime_ns if path.exists() else 0
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        try:
            os.chmod(tmp_name, mode)
        except OSError:
            pass
        next_ns = max(time.time_ns(), prev_ns + 1_000_000)
        try:
            os.utime(tmp_name, ns=(next_ns, next_ns))
        except OSError:
            pass
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


def _generate_bearer_token() -> tuple[str, str, str]:
    """Return (raw_token, sha256_hex, redacted_prefix)."""
    raw_token = f"cms_v1_{secrets.token_urlsafe(32)}"
    digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    prefix = f"{raw_token[:11]}..."
    return raw_token, digest, prefix


def _portal_key(state_dir: Path) -> bytes:
    key_path = state_dir / ".portal.key"
    if key_path.exists():
        raw = key_path.read_bytes()
        if len(raw) == 32:
            return raw
    key = os.urandom(32)
    state_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(state_dir), prefix=".portal.key.")
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, key_path)
    return key


def _keystream_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    counter = 0
    offset = 0
    while offset < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        chunk = data[offset : offset + 32]
        for i, b in enumerate(chunk):
            out[offset + i] = b ^ block[i]
        offset += len(chunk)
        counter += 1
    return bytes(out)


def save_portal_viewer_secret(state_dir: str | Path, customer: str, password: str) -> None:
    """Store sealed portal viewer password outside `tenants.json` so cleartext never hits disk."""
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    key = _portal_key(sdir)
    nonce = os.urandom(16)
    ct = _keystream_xor(password.encode("utf-8"), key, nonce)
    mac = hmac.new(key, nonce + ct, hashlib.sha256).hexdigest()

    existing: dict[str, Any] = {}
    if secrets_file.exists():
        try:
            existing = json.loads(secrets_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}

    existing[customer] = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
        "mac": mac,
    }
    _atomic_write_json(secrets_file, existing, mode=0o600)


def load_portal_viewer_secret(state_dir: str | Path, customer: str) -> str | None:
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    if not secrets_file.exists():
        return None
    try:
        doc = json.loads(secrets_file.read_text(encoding="utf-8"))
        entry = doc.get(customer)
        if not isinstance(entry, dict):
            return None
        key = _portal_key(sdir)
        nonce = base64.b64decode(entry["nonce"])
        ct = base64.b64decode(entry["ct"])
        expected_mac = hmac.new(key, nonce + ct, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, str(entry.get("mac", ""))):
            return None
        return _keystream_xor(ct, key, nonce).decode("utf-8")
    except Exception:
        return None


def delete_portal_viewer_secret(state_dir: str | Path, customer: str) -> None:
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    if not secrets_file.exists():
        return
    try:
        doc = json.loads(secrets_file.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and customer in doc:
            del doc[customer]
            _atomic_write_json(secrets_file, doc, mode=0o600)
    except Exception:
        pass


def _read_store_unlocked(tenants_path: Path) -> dict[str, Any]:
    if not tenants_path.exists():
        return {"version": 1, "tenants": []}
    raw = tenants_path.read_text(encoding="utf-8").strip()
    if not raw:
        return {"version": 1, "tenants": []}
    doc = json.loads(raw)
    if isinstance(doc, dict) and isinstance(doc.get("tenants"), list):
        return doc
    if isinstance(doc, list):
        return {"version": 1, "tenants": doc}
    return {"version": 1, "tenants": []}


def load_tenants_raw(state_dir: str | Path) -> list[dict[str, Any]]:
    sdir = Path(state_dir)
    doc = _read_store_unlocked(sdir / "tenants.json")
    return list(doc.get("tenants", []))


def _to_public_tenant(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "customer": rec["customer"],
        "display_name": rec["display_name"],
        "sites": list(rec.get("sites", [])),
        "contact_emails": list(rec.get("contact_emails", [])),
        "token_prefix": rec["token_prefix"],
        "token_created_at": rec["token_created_at"],
        "previous_token_expires_at": rec.get("previous_token_expires_at"),
        "customer_portal_enabled": bool(rec.get("customer_portal_enabled", False)),
        "grafana_org_id": rec.get("grafana_org_id"),
        "portal_viewer_username": str(rec.get("portal_viewer_username") or ""),
        "last_ingest_at": rec.get("last_ingest_at"),
        "notes": str(rec.get("notes") or ""),
        "created_at": rec["created_at"],
        "updated_at": rec["updated_at"],
    }


def list_tenants(
    state_dir: str | Path,
    *,
    search: str = "",
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    sdir = Path(state_dir)
    page = max(1, int(page))
    page_size = min(500, max(1, int(page_size)))
    needle = (search or "").strip().lower()

    raw_list = load_tenants_raw(sdir)
    raw_list.sort(key=lambda item: str(item.get("customer", "")))

    if needle:
        filtered = [
            t
            for t in raw_list
            if needle in str(t.get("customer", "")).lower()
            or needle in str(t.get("display_name", "")).lower()
        ]
    else:
        filtered = raw_list

    total_items = len(filtered)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0
    start = (page - 1) * page_size
    end = start + page_size
    sliced = [_to_public_tenant(t) for t in filtered[start:end]]

    return {
        "tenants": sliced,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total_items,
            "total_pages": total_pages,
        },
    }


def save_tenant(
    state_dir: str | Path, payload: dict[str, Any]
) -> tuple[dict[str, Any], str | None]:
    """Create or update a tenant atomically. Returns (tenant_record, initial_auth_token_or_None)."""
    sdir = Path(state_dir)
    customer = str(payload.get("customer") or "").strip()
    if not CUSTOMER_RE.match(customer):
        raise ValueError(f"Invalid customer slug: {customer!r}")

    display_name = str(payload.get("display_name") or "").strip()
    if not display_name or len(display_name) > 128:
        raise ValueError("display_name must be 1..128 characters")

    raw_sites = payload.get("sites")
    if not isinstance(raw_sites, list) or len(raw_sites) == 0:
        raise ValueError("sites must be a non-empty list of valid site slugs")
    sites: list[str] = []
    seen_sites: set[str] = set()
    for s in raw_sites:
        s_clean = str(s).strip()
        if not SITE_RE.match(s_clean):
            raise ValueError(f"Invalid site slug: {s_clean!r}")
        if s_clean not in seen_sites:
            seen_sites.add(s_clean)
            sites.append(s_clean)

    raw_emails = payload.get("contact_emails") or []
    if not isinstance(raw_emails, list):
        raise ValueError("contact_emails must be a list")
    emails: list[str] = []
    seen_emails: set[str] = set()
    for e in raw_emails:
        e_clean = str(e).strip()
        if not EMAIL_RE.match(e_clean):
            raise ValueError(f"Invalid email address: {e_clean!r}")
        if e_clean not in seen_emails:
            seen_emails.add(e_clean)
            emails.append(e_clean)

    portal_enabled = bool(payload.get("customer_portal_enabled", False))
    viewer_user = str(payload.get("portal_viewer_username") or "").strip()
    viewer_pass = str(payload.get("portal_viewer_password") or "")
    notes = str(payload.get("notes") or "")[:1000]

    if portal_enabled:
        if not VIEWER_USER_RE.match(viewer_user):
            raise ValueError("portal_viewer_username is required when customer_portal_enabled=true")
    elif viewer_user and not VIEWER_USER_RE.match(viewer_user):
        raise ValueError("Invalid portal_viewer_username")

    reserved_names = set(RESERVED_PORTAL_USERNAMES)
    env_admin = os.environ.get("GRAFANA_ADMIN_USER", "admin").strip().lower()
    if env_admin:
        reserved_names.add(env_admin)
    if viewer_user and viewer_user.lower() in reserved_names:
        raise ValueError(f"Reserved portal_viewer_username is not allowed: {viewer_user!r}")

    if viewer_pass and (len(viewer_pass) < 10 or any(c in viewer_pass for c in ("\r", "\n", "\x00"))):
        raise ValueError("portal_viewer_password must be at least 10 valid characters when provided")

    tenants_path = sdir / "tenants.json"
    now_str = _iso_utc()

    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        tenants: list[dict[str, Any]] = store_doc["tenants"]
        existing_idx = next(
            (i for i, t in enumerate(tenants) if t.get("customer") == customer),
            None,
        )

        effective_viewer = viewer_user
        if existing_idx is not None and not effective_viewer and portal_enabled:
            effective_viewer = str(tenants[existing_idx].get("portal_viewer_username") or "").strip()

        if effective_viewer:
            eff_low = effective_viewer.lower()
            if eff_low in reserved_names:
                raise ValueError(f"Reserved portal_viewer_username is not allowed: {effective_viewer!r}")
            for other in tenants:
                if other.get("customer") == customer:
                    continue
                other_viewer = str(other.get("portal_viewer_username") or "").strip().lower()
                if other_viewer and other_viewer == eff_low:
                    raise ValueError(
                        f"portal_viewer_username {effective_viewer!r} is already in use by another tenant"
                    )

        if existing_idx is None:
            raw_token, token_hash, token_prefix = _generate_bearer_token()
            rec: dict[str, Any] = {
                "customer": customer,
                "display_name": display_name,
                "sites": sites,
                "default_site": sites[0],
                "contact_emails": emails,
                "token_sha256": token_hash,
                "token_prefix": token_prefix,
                "token_created_at": now_str,
                "previous_token_sha256": None,
                "previous_token_prefix": None,
                "previous_token_expires_at": None,
                "dedicated_tokens": [],
                "customer_portal_enabled": portal_enabled,
                "grafana_org_id": None,
                "portal_viewer_username": viewer_user,
                "previous_portal_viewer_username": None,
                "last_ingest_at": None,
                "notes": notes,
                "created_at": now_str,
                "updated_at": now_str,
            }
            tenants.append(rec)
            tenants.sort(key=lambda item: str(item.get("customer", "")))
            _atomic_write_json(tenants_path, store_doc, mode=0o600)
            if viewer_pass:
                save_portal_viewer_secret(sdir, customer, viewer_pass)
            return dict(rec), raw_token

        rec = tenants[existing_idx]
        prev_viewer = str(rec.get("portal_viewer_username") or "").strip()
        next_viewer = (
            viewer_user
            if (viewer_user or not portal_enabled)
            else prev_viewer
        )
        if not next_viewer and prev_viewer:
            next_viewer = prev_viewer

        if prev_viewer and next_viewer and prev_viewer.lower() != next_viewer.lower():
            rec["previous_portal_viewer_username"] = prev_viewer

        rec["display_name"] = display_name
        rec["sites"] = sites
        rec["default_site"] = sites[0]
        rec["contact_emails"] = emails
        rec["customer_portal_enabled"] = portal_enabled
        rec["portal_viewer_username"] = next_viewer
        rec["notes"] = notes
        rec["updated_at"] = now_str
        _atomic_write_json(tenants_path, store_doc, mode=0o600)
        if viewer_pass:
            save_portal_viewer_secret(sdir, customer, viewer_pass)
        return dict(rec), None


def clear_previous_portal_viewer_username(state_dir: str | Path, customer: str) -> None:
    sdir = Path(state_dir)
    tenants_path = sdir / "tenants.json"
    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        for rec in store_doc["tenants"]:
            if rec.get("customer") == customer and rec.get("previous_portal_viewer_username"):
                rec["previous_portal_viewer_username"] = None
                _atomic_write_json(tenants_path, store_doc, mode=0o600)
                break


def update_tenant_grafana_org_id(
    state_dir: str | Path, customer: str, grafana_org_id: int | None
) -> None:
    sdir = Path(state_dir)
    tenants_path = sdir / "tenants.json"
    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        for rec in store_doc["tenants"]:
            if rec.get("customer") == customer:
                if rec.get("grafana_org_id") != grafana_org_id:
                    rec["grafana_org_id"] = grafana_org_id
                    _atomic_write_json(tenants_path, store_doc, mode=0o600)
                break


def delete_tenant(state_dir: str | Path, customer: str) -> dict[str, Any] | None:
    sdir = Path(state_dir)
    tenants_path = sdir / "tenants.json"
    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        tenants = store_doc["tenants"]
        removed: dict[str, Any] | None = None
        remaining: list[dict[str, Any]] = []
        for rec in tenants:
            if rec.get("customer") == customer and removed is None:
                removed = dict(rec)
            else:
                remaining.append(rec)
        if removed is not None:
            store_doc["tenants"] = remaining
            _atomic_write_json(tenants_path, store_doc, mode=0o600)
            delete_portal_viewer_secret(sdir, customer)
        return removed


def rotate_token(
    state_dir: str | Path, customer: str, grace_period_minutes: int = 60
) -> dict[str, Any]:
    sdir = Path(state_dir)
    grace = int(grace_period_minutes)
    if grace < 0 or grace > 10080:
        raise ValueError("grace_period_minutes must be between 0 and 10080")

    tenants_path = sdir / "tenants.json"
    now = _utc_now()
    now_str = _iso_utc(now)

    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        rec = next((t for t in store_doc["tenants"] if t.get("customer") == customer), None)
        if rec is None:
            raise KeyError(f"Tenant not found: {customer}")

        raw_token, new_hash, new_prefix = _generate_bearer_token()
        if grace > 0:
            prev_exp = _iso_utc(now + timedelta(minutes=grace))
            rec["previous_token_sha256"] = rec.get("token_sha256")
            rec["previous_token_prefix"] = rec.get("token_prefix")
            rec["previous_token_expires_at"] = prev_exp
        else:
            prev_exp = None
            rec["previous_token_sha256"] = None
            rec["previous_token_prefix"] = None
            rec["previous_token_expires_at"] = None

        rec["token_sha256"] = new_hash
        rec["token_prefix"] = new_prefix
        rec["token_created_at"] = now_str
        rec["updated_at"] = now_str
        _atomic_write_json(tenants_path, store_doc, mode=0o600)

    return {
        "status": "ok",
        "customer": customer,
        "auth_token": raw_token,
        "token_prefix": new_prefix,
        "previous_token_expires_at": prev_exp,
    }


def mint_dedicated_collector_token(
    state_dir: str | Path,
    *,
    customer: str,
    site: str,
    collector_id: str,
) -> tuple[str, str]:
    """Mint a dedicated collector-scoped bearer token bound to `(customer, site, collector_id)`."""
    if not CUSTOMER_RE.match(customer):
        raise ValueError(f"Invalid customer slug: {customer!r}")
    if not SITE_RE.match(site):
        raise ValueError(f"Invalid site slug: {site!r}")
    if not COLLECTOR_RE.match(collector_id):
        raise ValueError(f"Invalid collector_id: {collector_id!r}")

    sdir = Path(state_dir)
    tenants_path = sdir / "tenants.json"
    now_str = _iso_utc()

    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        rec = next((t for t in store_doc["tenants"] if t.get("customer") == customer), None)
        if rec is None:
            raise KeyError(f"Tenant not found: {customer}")
        if site not in rec.get("sites", []):
            raise ValueError(f"Site {site!r} does not belong to customer {customer!r}")

        raw_token, token_hash, token_prefix = _generate_bearer_token()
        ded_list: list[dict[str, Any]] = [
            d
            for d in rec.get("dedicated_tokens", [])
            if isinstance(d, dict) and d.get("collector_id") != collector_id
        ]
        ded_list.append(
            {
                "collector_id": collector_id,
                "site": site,
                "token_sha256": token_hash,
                "token_prefix": token_prefix,
                "created_at": now_str,
            }
        )
        # Keep bounded most recent 100 dedicated collector tokens per tenant
        rec["dedicated_tokens"] = ded_list[-100:]
        rec["updated_at"] = now_str
        _atomic_write_json(tenants_path, store_doc, mode=0o600)

    return raw_token, token_prefix
