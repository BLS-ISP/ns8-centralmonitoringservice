"""Atomic file-locked CRUD on `state/tenants.json` (`0600`), portal users, and SHA-256 tokens."""

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
from typing import Any, Final, Iterator, Mapping

CUSTOMER_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9-]{1,46}[a-z0-9]\Z")
SITE_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9-]{0,46}[a-z0-9]\Z")
COLLECTOR_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]\Z")
EMAIL_RE: Final[re.Pattern[str]] = re.compile(r"\A[^@\s]+@[^@\s]+\.[^@\s]+\Z")
VIEWER_USER_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-zA-Z0-9._@-]{3,64}\Z")
PORTAL_USER_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-zA-Z0-9._-]{3,64}\Z")
ALLOWED_PORTAL_ROLES: Final[tuple[str, str]] = ("Viewer", "Editor")
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


def build_grafana_org_name(display_name: str, customer: str) -> str:
    """Return canonical Grafana Organization name for a Customer Portal tenant."""
    return f"Customer: {display_name} ({customer})"


def _read_traefik_host_from_env_file(env_path: Path) -> str:
    if not env_path.exists():
        return ""
    try:
        raw = env_path.read_text(encoding="utf-8").replace("\r\n", "\n")
        for line in raw.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            key = k.strip()
            if key in ("TRAEFIK_HOST", "HUB_HOST"):
                val = v.strip().strip('"').strip("'")
                if val:
                    return val
    except OSError:
        pass
    return ""


def resolve_grafana_login_url(
    state_dir: str | Path,
    env: Mapping[str, str] | None = None,
) -> str:
    """Return `https://<TRAEFIK_HOST>/login` when configured, or empty string."""
    sdir = Path(state_dir)
    host = ""
    if env:
        host = str(env.get("TRAEFIK_HOST") or env.get("HUB_HOST") or "").strip()
    if not host:
        host = _read_traefik_host_from_env_file(sdir / "environment")
    if not host:
        host = str(os.environ.get("TRAEFIK_HOST") or os.environ.get("HUB_HOST") or "").strip()
    if not host:
        return ""
    cleaned = re.sub(r"\Ahttps?://", "", host, flags=re.IGNORECASE).rstrip("/")
    if not cleaned:
        return ""
    return f"https://{cleaned}/login"


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


def _seal_secret(password: str, key: bytes) -> dict[str, str]:
    nonce = os.urandom(16)
    ct = _keystream_xor(password.encode("utf-8"), key, nonce)
    mac = hmac.new(key, nonce + ct, hashlib.sha256).hexdigest()
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
        "mac": mac,
    }


def _unseal_secret(entry: Any, key: bytes) -> str | None:
    if not isinstance(entry, dict):
        return None
    try:
        nonce = base64.b64decode(entry["nonce"])
        ct = base64.b64decode(entry["ct"])
        expected_mac = hmac.new(key, nonce + ct, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, str(entry.get("mac", ""))):
            return None
        return _keystream_xor(ct, key, nonce).decode("utf-8")
    except Exception:
        return None


def _load_portal_secrets_doc(secrets_file: Path) -> dict[str, Any]:
    if not secrets_file.exists():
        return {}
    try:
        doc = json.loads(secrets_file.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _backfill_legacy_user_secret(
    state_dir: Path,
    customer: str,
    rec: dict[str, Any],
    existing_users: list[dict[str, Any]],
) -> None:
    """Backfill `doc[f"{customer}:{u0.lower()}"]` from `doc[customer]` before multi-user updates."""
    secrets_file = state_dir / "portal-secrets.json"
    if not secrets_file.exists():
        return
    doc = _load_portal_secrets_doc(secrets_file)
    legacy_entry = doc.get(customer)
    if not isinstance(legacy_entry, dict):
        return

    candidates: list[str] = []
    legacy_primary = str(rec.get("portal_viewer_username") or "").strip()
    if legacy_primary:
        candidates.append(legacy_primary)
    elif len(existing_users) == 1 and existing_users[0].get("username"):
        candidates.append(str(existing_users[0]["username"]).strip())

    changed = False
    for u0 in candidates:
        scoped_key = f"{customer}:{u0.lower()}"
        if u0 and scoped_key not in doc and f"{customer}:{u0}" not in doc:
            doc[scoped_key] = dict(legacy_entry)
            changed = True
    if changed:
        _atomic_write_json(secrets_file, doc, mode=0o600)


def save_portal_viewer_secret(
    state_dir: str | Path,
    customer: str,
    password: str,
    username: str | None = None,
) -> None:
    """Store sealed portal user password outside `tenants.json` (`0600`)."""
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    key = _portal_key(sdir)
    sealed = _seal_secret(password, key)

    existing = _load_portal_secrets_doc(secrets_file)
    existing[customer] = sealed
    if username and username.strip():
        existing[f"{customer}:{username.strip().lower()}"] = dict(sealed)
    _atomic_write_json(secrets_file, existing, mode=0o600)


def save_portal_user_secret(
    state_dir: str | Path,
    customer: str,
    username: str,
    password: str,
    *,
    is_primary: bool = False,
) -> None:
    """Store sealed password keyed by `<customer>:<username>` (and `<customer>` if primary)."""
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    key = _portal_key(sdir)
    sealed = _seal_secret(password, key)

    existing = _load_portal_secrets_doc(secrets_file)
    existing[f"{customer}:{username.strip().lower()}"] = sealed
    if is_primary or customer not in existing:
        existing[customer] = dict(sealed)
    _atomic_write_json(secrets_file, existing, mode=0o600)


def load_portal_viewer_secret(
    state_dir: str | Path,
    customer: str,
    username: str | None = None,
) -> str | None:
    """Load sealed password for `<customer>:<username>` (falling back to `<customer>` for legacy)."""
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    if not secrets_file.exists():
        return None
    doc = _load_portal_secrets_doc(secrets_file)
    if not doc:
        return None
    key = _portal_key(sdir)

    if username is not None and username.strip():
        uname = username.strip()
        for cand_key in (f"{customer}:{uname.lower()}", f"{customer}:{uname}"):
            if cand_key in doc:
                val = _unseal_secret(doc[cand_key], key)
                if val is not None:
                    return val
        # Backward-compatible fallback for migrated legacy primary portal_viewer_username
        if customer in doc:
            for rec in load_tenants_raw(sdir):
                if rec.get("customer") == customer:
                    legacy_u = str(rec.get("portal_viewer_username") or "").strip()
                    users = normalize_portal_users(rec)
                    if (
                        (legacy_u and legacy_u.lower() == uname.lower())
                        or (len(users) == 1 and users[0]["username"].lower() == uname.lower())
                    ):
                        return _unseal_secret(doc[customer], key)
                    break
        return None

    # No explicit username requested -> return primary user's password or legacy `<customer>` entry
    for rec in load_tenants_raw(sdir):
        if rec.get("customer") == customer:
            primary_u = str(rec.get("portal_viewer_username") or "").strip()
            if primary_u:
                scoped_key = f"{customer}:{primary_u.lower()}"
                if scoped_key in doc:
                    val = _unseal_secret(doc[scoped_key], key)
                    if val is not None:
                        return val
            break

    if customer in doc:
        return _unseal_secret(doc[customer], key)
    return None


def delete_portal_user_secret(
    state_dir: str | Path,
    customer: str,
    username: str,
    *,
    next_primary_username: str = "",
) -> None:
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    if not secrets_file.exists():
        return
    doc = _load_portal_secrets_doc(secrets_file)
    if not doc:
        return
    uname = username.strip()
    changed = False
    for k in (f"{customer}:{uname.lower()}", f"{customer}:{uname}"):
        if k in doc:
            del doc[k]
            changed = True
    if next_primary_username:
        next_key = f"{customer}:{next_primary_username.strip().lower()}"
        if next_key in doc:
            doc[customer] = dict(doc[next_key])
            changed = True
    elif customer in doc:
        del doc[customer]
        changed = True
    if changed:
        _atomic_write_json(secrets_file, doc, mode=0o600)


def delete_portal_viewer_secret(state_dir: str | Path, customer: str) -> None:
    sdir = Path(state_dir)
    secrets_file = sdir / "portal-secrets.json"
    if not secrets_file.exists():
        return
    doc = _load_portal_secrets_doc(secrets_file)
    if not doc:
        return
    prefix = f"{customer}:"
    keys_to_delete = [k for k in doc if k == customer or k.startswith(prefix)]
    if keys_to_delete:
        for k in keys_to_delete:
            del doc[k]
        _atomic_write_json(secrets_file, doc, mode=0o600)


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


def normalize_portal_users(rec: dict[str, Any]) -> list[dict[str, Any]]:
    """Return normalized multi-user portal accounts, auto-migrating legacy `portal_viewer_username`."""
    customer = str(rec.get("customer") or "")
    display_name = str(rec.get("display_name") or customer)
    default_ts = str(rec.get("created_at") or _iso_utc())
    default_upd = str(rec.get("updated_at") or default_ts)

    raw_users = rec.get("portal_users")
    if isinstance(raw_users, list):
        normalized: list[dict[str, Any]] = []
        seen_lower: set[str] = set()
        for item in raw_users:
            if not isinstance(item, dict):
                continue
            uname = str(item.get("username") or "").strip()
            if not uname or uname.lower() in seen_lower:
                continue
            seen_lower.add(uname.lower())
            role_raw = str(item.get("role") or "Viewer").strip()
            role = "Editor" if role_raw == "Editor" else "Viewer"
            normalized.append(
                {
                    "username": uname,
                    "full_name": str(item.get("full_name") or ""),
                    "email": str(item.get("email") or ""),
                    "role": role,
                    "disabled": bool(item.get("disabled", False)),
                    "created_at": str(item.get("created_at") or default_ts),
                    "updated_at": str(item.get("updated_at") or default_upd),
                }
            )
        return normalized

    # Seamless auto-migration for legacy single-user `portal_viewer_username` records
    legacy_u = str(rec.get("portal_viewer_username") or "").strip()
    if legacy_u:
        return [
            {
                "username": legacy_u,
                "full_name": f"{display_name} Portal Viewer",
                "email": f"{legacy_u}@{customer}.portal.local",
                "role": "Viewer",
                "disabled": False,
                "created_at": default_ts,
                "updated_at": default_upd,
            }
        ]
    return []


def _derive_primary_portal_username(users: list[dict[str, Any]]) -> str:
    for u in users:
        if not bool(u.get("disabled", False)) and u.get("username"):
            return str(u["username"])
    if users and users[0].get("username"):
        return str(users[0]["username"])
    return ""


def _reserved_usernames_set() -> set[str]:
    names = set(RESERVED_PORTAL_USERNAMES)
    env_admin = os.environ.get("GRAFANA_ADMIN_USER", "admin").strip().lower()
    if env_admin:
        names.add(env_admin)
    return names


def _assert_username_globally_available(
    tenants: list[dict[str, Any]],
    customer: str,
    username: str,
) -> None:
    uname_low = username.strip().lower()
    if uname_low in _reserved_usernames_set():
        raise ValueError(f"Reserved Grafana username is not allowed: {username!r}")

    for other in tenants:
        if other.get("customer") == customer:
            continue
        other_legacy = str(other.get("portal_viewer_username") or "").strip().lower()
        if other_legacy and other_legacy == uname_low:
            raise ValueError(
                f"Portal username {username!r} is already in use by another tenant"
            )
        for other_u in normalize_portal_users(other):
            if str(other_u.get("username") or "").strip().lower() == uname_low:
                raise ValueError(
                    f"Portal username {username!r} is already in use by another tenant"
                )


def load_tenants_raw(state_dir: str | Path) -> list[dict[str, Any]]:
    sdir = Path(state_dir)
    doc = _read_store_unlocked(sdir / "tenants.json")
    return list(doc.get("tenants", []))


def _to_public_tenant(rec: dict[str, Any], *, grafana_login_url: str = "") -> dict[str, Any]:
    users = normalize_portal_users(rec)
    primary_viewer = _derive_primary_portal_username(users) or str(
        rec.get("portal_viewer_username") or ""
    )
    customer = rec["customer"]
    display_name = rec["display_name"]
    return {
        "customer": customer,
        "display_name": display_name,
        "sites": list(rec.get("sites", [])),
        "contact_emails": list(rec.get("contact_emails", [])),
        "token_prefix": rec["token_prefix"],
        "token_created_at": rec["token_created_at"],
        "previous_token_expires_at": rec.get("previous_token_expires_at"),
        "customer_portal_enabled": bool(rec.get("customer_portal_enabled", False)),
        "grafana_org_id": rec.get("grafana_org_id"),
        "grafana_org_name": build_grafana_org_name(display_name, customer),
        "grafana_login_url": grafana_login_url,
        "portal_viewer_username": primary_viewer,
        "portal_users_count": len(users),
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
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    sdir = Path(state_dir)
    page = max(1, int(page))
    page_size = min(500, max(1, int(page_size)))
    needle = (search or "").strip().lower()
    login_url = resolve_grafana_login_url(sdir, env)

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
    sliced = [_to_public_tenant(t, grafana_login_url=login_url) for t in filtered[start:end]]

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

    if viewer_user and not VIEWER_USER_RE.match(viewer_user):
        raise ValueError("Invalid portal_viewer_username")
    if viewer_user and viewer_user.lower() in _reserved_usernames_set():
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

        if viewer_user:
            _assert_username_globally_available(tenants, customer, viewer_user)

        if existing_idx is None:
            raw_token, token_hash, token_prefix = _generate_bearer_token()
            initial_users: list[dict[str, Any]] = []
            if viewer_user:
                initial_users.append(
                    {
                        "username": viewer_user,
                        "full_name": f"{display_name} Portal Viewer",
                        "email": f"{viewer_user}@{customer}.portal.local",
                        "role": "Viewer",
                        "disabled": False,
                        "created_at": now_str,
                        "updated_at": now_str,
                    }
                )
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
                "portal_users": initial_users,
                "previous_portal_viewer_username": None,
                "evicted_portal_usernames": [],
                "last_ingest_at": None,
                "notes": notes,
                "created_at": now_str,
                "updated_at": now_str,
            }
            tenants.append(rec)
            tenants.sort(key=lambda item: str(item.get("customer", "")))
            _atomic_write_json(tenants_path, store_doc, mode=0o600)
            if viewer_pass:
                save_portal_viewer_secret(sdir, customer, viewer_pass, username=viewer_user or None)
            return dict(rec), raw_token

        rec = tenants[existing_idx]
        users = normalize_portal_users(rec)
        _backfill_legacy_user_secret(sdir, customer, rec, users)
        for existing_u in users:
            _assert_username_globally_available(tenants, customer, existing_u["username"])

        prev_viewer = str(rec.get("portal_viewer_username") or "").strip()
        evicted: list[str] = [
            str(u).strip()
            for u in (rec.get("evicted_portal_usernames") or [])
            if str(u).strip()
        ]
        renamed_old_viewer: str | None = None

        if viewer_user:
            match_idx = next(
                (i for i, u in enumerate(users) if u["username"].lower() == viewer_user.lower()),
                None,
            )
            if match_idx is not None:
                users[match_idx]["username"] = viewer_user
                users[match_idx]["updated_at"] = now_str
            else:
                prev_idx = (
                    next(
                        (i for i, u in enumerate(users) if u["username"].lower() == prev_viewer.lower()),
                        None,
                    )
                    if prev_viewer
                    else None
                )
                new_entry = {
                    "username": viewer_user,
                    "full_name": f"{display_name} Portal Viewer",
                    "email": f"{viewer_user}@{customer}.portal.local",
                    "role": "Viewer",
                    "disabled": False,
                    "created_at": now_str,
                    "updated_at": now_str,
                }
                if prev_idx is not None:
                    renamed_old_viewer = users[prev_idx]["username"]
                    users[prev_idx] = new_entry
                    rec["previous_portal_viewer_username"] = renamed_old_viewer
                    if renamed_old_viewer.lower() not in {x.lower() for x in evicted}:
                        evicted.append(renamed_old_viewer)
                else:
                    users.insert(0, new_entry)

        primary_viewer = _derive_primary_portal_username(users)

        rec["display_name"] = display_name
        rec["sites"] = sites
        rec["default_site"] = sites[0]
        rec["contact_emails"] = emails
        rec["customer_portal_enabled"] = portal_enabled
        rec["portal_users"] = users
        rec["portal_viewer_username"] = primary_viewer
        rec["evicted_portal_usernames"] = evicted
        rec["notes"] = notes
        rec["updated_at"] = now_str
        _atomic_write_json(tenants_path, store_doc, mode=0o600)

        if renamed_old_viewer:
            delete_portal_user_secret(
                sdir,
                customer,
                renamed_old_viewer,
                next_primary_username=primary_viewer,
            )
        if viewer_pass:
            target_u = viewer_user or primary_viewer
            save_portal_viewer_secret(sdir, customer, viewer_pass, username=target_u or None)
        return dict(rec), None


def list_portal_users(
    state_dir: str | Path,
    customer: str,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return multi-user portal account list & login metadata for a tenant (`list-portal-users`)."""
    sdir = Path(state_dir)
    slug = str(customer or "").strip()
    if not CUSTOMER_RE.match(slug):
        raise ValueError(f"Invalid customer slug: {slug!r}")

    rec = next((t for t in load_tenants_raw(sdir) if t.get("customer") == slug), None)
    if rec is None:
        raise KeyError(f"Tenant not found: {slug}")

    display_name = str(rec["display_name"])
    return {
        "customer": slug,
        "display_name": display_name,
        "customer_portal_enabled": bool(rec.get("customer_portal_enabled", False)),
        "grafana_org_id": rec.get("grafana_org_id"),
        "grafana_login_url": resolve_grafana_login_url(sdir, env),
        "grafana_org_name": build_grafana_org_name(display_name, slug),
        "users": normalize_portal_users(rec),
    }


def save_portal_user(
    state_dir: str | Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Create or update a Customer Organization portal user (`Viewer` or `Editor`)."""
    sdir = Path(state_dir)
    customer = str(payload.get("customer") or "").strip()
    if not CUSTOMER_RE.match(customer):
        raise ValueError(f"Invalid customer slug: {customer!r}")

    username = str(payload.get("username") or "").strip()
    if not PORTAL_USER_RE.match(username):
        raise ValueError(f"Invalid portal username: {username!r}")

    role = str(payload.get("role") or "").strip()
    if role not in ALLOWED_PORTAL_ROLES:
        raise ValueError(f"Invalid portal role {role!r}; allowed: Viewer, Editor")

    full_name = str(payload.get("full_name") or "").strip()
    if len(full_name) > 128 or any(c in full_name for c in ("\r", "\n", "\x00")):
        raise ValueError("full_name must be <= 128 valid characters")

    email = str(payload.get("email") or "").strip()
    if email and (len(email) > 254 or not EMAIL_RE.match(email)):
        raise ValueError(f"Invalid email address: {email!r}")

    disabled = bool(payload.get("disabled", False))
    password = str(payload.get("password") or "")
    password_unchanged = bool(payload.get("password_unchanged", False))

    if password and (
        len(password) < 10
        or len(password) > 256
        or any(c in password for c in ("\r", "\n", "\x00"))
    ):
        raise ValueError("password must be between 10 and 256 valid characters")
    if not password_unchanged and not password:
        raise ValueError("password is required unless password_unchanged is true")

    tenants_path = sdir / "tenants.json"
    now_str = _iso_utc()

    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        tenants: list[dict[str, Any]] = store_doc["tenants"]
        rec = next((t for t in tenants if t.get("customer") == customer), None)
        if rec is None:
            raise KeyError(f"Tenant not found: {customer}")

        _assert_username_globally_available(tenants, customer, username)

        users = normalize_portal_users(rec)
        _backfill_legacy_user_secret(sdir, customer, rec, users)
        existing_idx = next(
            (i for i, u in enumerate(users) if u["username"].lower() == username.lower()),
            None,
        )

        if existing_idx is None:
            if not password:
                raise ValueError("password is required when creating a new portal user")
            saved_user = {
                "username": username,
                "full_name": full_name,
                "email": email,
                "role": role,
                "disabled": disabled,
                "created_at": now_str,
                "updated_at": now_str,
            }
            users.append(saved_user)
        else:
            prev_u = users[existing_idx]
            saved_user = {
                "username": username,
                "full_name": full_name,
                "email": email,
                "role": role,
                "disabled": disabled,
                "created_at": str(prev_u.get("created_at") or now_str),
                "updated_at": now_str,
            }
            users[existing_idx] = saved_user

        # Remove from pending eviction list if re-created with same username
        evicted = [
            str(u).strip()
            for u in (rec.get("evicted_portal_usernames") or [])
            if str(u).strip() and str(u).strip().lower() != username.lower()
        ]
        primary_viewer = _derive_primary_portal_username(users)
        rec["portal_users"] = users
        rec["portal_viewer_username"] = primary_viewer
        rec["evicted_portal_usernames"] = evicted
        rec["updated_at"] = now_str
        _atomic_write_json(tenants_path, store_doc, mode=0o600)

        if password:
            save_portal_user_secret(
                sdir,
                customer,
                username,
                password,
                is_primary=(primary_viewer.lower() == username.lower()),
            )

    return dict(saved_user)


def delete_portal_user(
    state_dir: str | Path,
    customer: str,
    username: str,
) -> tuple[bool, dict[str, Any] | None]:
    """Delete a Customer Organization portal user (`delete-portal-user`)."""
    sdir = Path(state_dir)
    slug = str(customer or "").strip()
    if not CUSTOMER_RE.match(slug):
        raise ValueError(f"Invalid customer slug: {slug!r}")
    uname = str(username or "").strip()
    if not VIEWER_USER_RE.match(uname):
        raise ValueError(f"Invalid portal username: {uname!r}")

    tenants_path = sdir / "tenants.json"
    now_str = _iso_utc()

    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        rec = next((t for t in store_doc["tenants"] if t.get("customer") == slug), None)
        if rec is None:
            return False, None

        users = normalize_portal_users(rec)
        _backfill_legacy_user_secret(sdir, slug, rec, users)
        remaining = [u for u in users if u["username"].lower() != uname.lower()]
        removed = len(remaining) != len(users)

        if removed:
            next_primary = _derive_primary_portal_username(remaining)
            evicted = [
                str(u).strip()
                for u in (rec.get("evicted_portal_usernames") or [])
                if str(u).strip()
            ]
            if uname.lower() not in {x.lower() for x in evicted}:
                evicted.append(uname)
            rec["portal_users"] = remaining
            rec["portal_viewer_username"] = next_primary
            rec["evicted_portal_usernames"] = evicted
            rec["updated_at"] = now_str
            _atomic_write_json(tenants_path, store_doc, mode=0o600)
            delete_portal_user_secret(
                sdir,
                slug,
                uname,
                next_primary_username=next_primary,
            )

        return removed, dict(rec)


def clear_previous_portal_viewer_username(state_dir: str | Path, customer: str) -> None:
    sdir = Path(state_dir)
    tenants_path = sdir / "tenants.json"
    with _file_lock(sdir / ".tenants.lock"):
        store_doc = _read_store_unlocked(tenants_path)
        for rec in store_doc["tenants"]:
            if rec.get("customer") == customer and (
                rec.get("previous_portal_viewer_username") or rec.get("evicted_portal_usernames")
            ):
                rec["previous_portal_viewer_username"] = None
                rec["evicted_portal_usernames"] = []
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
