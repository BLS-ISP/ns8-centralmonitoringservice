"""Alertmanager v2 Maintenance Windows (Silences) Manager with Restic State Persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Final
from urllib.parse import quote
import uuid

from hub_alerting import (
    ValidationFailure,
    atomic_write_json,
    file_lock,
    load_json_file,
    pod_http_request,
    resolve_state_dir,
)

_SILENCE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{4,128}\Z")
_RFC3339_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):?(\d{2}))?\Z"
)
ALLOWED_SILENCE_ROLES: Final[frozenset[str]] = frozenset(
    {
        "",
        "ns8",
        "linux",
        "windows",
        "proxmox",
        "web",
        "snmp-network",
        "snmp-ups",
        "snmp-nas",
        "snmp-firewall",
        "snmp-printer",
    }
)


def _alertmanager_base_url() -> str:
    return os.environ.get("ALERTMANAGER_URL", "http://127.0.0.1:9093").rstrip("/")


def _parse_rfc3339(ts_str: str, field: str) -> datetime:
    """Parse RFC3339 / ISO-8601 timestamps cleanly on Python 3.9+ (including Go RFC3339Nano fractional digits)."""
    cleaned = ts_str.strip()
    match = _RFC3339_RE.match(cleaned)
    if not match:
        raise ValidationFailure(field, ts_str, "invalid_timestamp", f"Invalid RFC3339 timestamp: {ts_str}")

    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    frac = match.group(7) or ""
    microsecond = int((frac + "000000")[:6]) if frac else 0

    if match.group(9):
        sign = 1 if match.group(9) == "+" else -1
        tz_hours = int(match.group(10))
        tz_mins = int(match.group(11))
        if tz_hours > 23 or tz_mins > 59:
            raise ValidationFailure(field, ts_str, "invalid_timestamp", f"Invalid timezone offset in: {ts_str}")
        tz_info = timezone(sign * timedelta(hours=tz_hours, minutes=tz_mins))
    else:
        tz_info = timezone.utc

    try:
        parsed = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tz_info)
    except ValueError as exc:
        raise ValidationFailure(field, ts_str, "invalid_timestamp", f"Invalid calendar date/time: {ts_str}") from exc
    return parsed.astimezone(timezone.utc)


def _format_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _compute_silence_state(record: dict[str, Any], now: datetime | None = None) -> str:
    if record.get("expired_explicitly") or record.get("state") == "expired":
        return "expired"
    ref_now = now or datetime.now(timezone.utc)
    try:
        starts_dt = _parse_rfc3339(str(record["starts_at"]), "starts_at")
        ends_dt = _parse_rfc3339(str(record["ends_at"]), "ends_at")
    except ValidationFailure:
        return str(record.get("state") or "active")

    if ref_now >= ends_dt:
        return "expired"
    if ref_now < starts_dt:
        return "pending"
    return "active"


def _to_am_matchers(matchers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": str(m["name"]),
            "value": str(m["value"]),
            "isRegex": bool(m.get("is_regex", False)),
            "isEqual": bool(m.get("is_equal", True)),
        }
        for m in matchers
    ]


def _from_am_silence(am_obj: dict[str, Any]) -> dict[str, Any]:
    raw_status = am_obj.get("status") or {}
    state = str(raw_status.get("state") or "active")
    if state not in {"active", "pending", "expired"}:
        state = "active"
    matchers = [
        {
            "name": str(m["name"]),
            "value": str(m["value"]),
            "is_regex": bool(m.get("isRegex", m.get("is_regex", False))),
            "is_equal": bool(m.get("isEqual", m.get("is_equal", True))),
        }
        for m in (am_obj.get("matchers") or [])
    ]
    return {
        "id": str(am_obj["id"]),
        "state": state,
        "starts_at": str(am_obj.get("startsAt") or am_obj.get("starts_at") or ""),
        "ends_at": str(am_obj.get("endsAt") or am_obj.get("ends_at") or ""),
        "created_by": str(am_obj.get("createdBy") or am_obj.get("created_by") or ""),
        "comment": str(am_obj.get("comment") or ""),
        "matchers": matchers,
    }


def _build_silence_matchers(payload: dict[str, Any]) -> list[dict[str, Any]]:
    matchers: list[dict[str, Any]] = []
    customer = str(payload.get("customer") if "customer" in payload else "*").strip()
    site = str(payload.get("site") or "").strip()
    role = str(payload.get("device_role") or "").strip()
    if role not in ALLOWED_SILENCE_ROLES:
        raise ValidationFailure("device_role", role, "invalid_device_role", f"Invalid device_role: {role}")

    if customer and customer != "*":
        matchers.append({"name": "customer", "value": customer, "is_regex": False, "is_equal": True})
    if site:
        matchers.append({"name": "site", "value": site, "is_regex": False, "is_equal": True})
    if role:
        matchers.append({"name": "device_role", "value": role, "is_regex": False, "is_equal": True})

    for extra in payload.get("extra_matchers") or []:
        matchers.append(
            {
                "name": str(extra["name"]).strip(),
                "value": str(extra["value"]),
                "is_regex": bool(extra.get("is_regex", False)),
                "is_equal": bool(extra.get("is_equal", True)),
            }
        )

    # Alertmanager v2 requires at least one matcher; global maintenance (customer="*") matches alertname=~".+"
    if not matchers:
        matchers.append({"name": "alertname", "value": ".+", "is_regex": True, "is_equal": True})

    return matchers


def _post_silence_to_alertmanager(
    matchers: list[dict[str, Any]],
    starts_iso: str,
    ends_iso: str,
    created_by: str,
    comment: str,
) -> str | None:
    am_payload = {
        "matchers": _to_am_matchers(matchers),
        "startsAt": starts_iso,
        "endsAt": ends_iso,
        "createdBy": created_by,
        "comment": comment,
    }
    raw = json.dumps(am_payload).encode("utf-8")
    status, body = pod_http_request(
        f"{_alertmanager_base_url()}/api/v2/silences",
        method="POST",
        data=raw,
        headers={"Content-Type": "application/json"},
        timeout=4.0,
    )
    if 200 <= status < 300 and body:
        try:
            parsed = json.loads(body.decode("utf-8"))
            sid = parsed.get("silenceID") or parsed.get("id")
            if sid and _SILENCE_ID_RE.match(str(sid)):
                return str(sid)
        except json.JSONDecodeError:
            return None
    return None


def create_silence(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """Validate maintenance window, push to Alertmanager /api/v2/silences, and persist state/silences.json."""
    sdir = resolve_state_dir(state_dir)
    starts_dt = _parse_rfc3339(str(payload["starts_at"]), "starts_at")
    ends_dt = _parse_rfc3339(str(payload["ends_at"]), "ends_at")
    if ends_dt <= starts_dt:
        raise ValidationFailure(
            "ends_at",
            payload["ends_at"],
            "invalid_time_range",
            "ends_at must be strictly after starts_at",
        )

    starts_iso = _format_rfc3339(starts_dt)
    ends_iso = _format_rfc3339(ends_dt)
    created_by = str(payload["created_by"]).strip()
    comment = str(payload["comment"]).strip()
    matchers = _build_silence_matchers(payload)

    am_silence_id = _post_silence_to_alertmanager(matchers, starts_iso, ends_iso, created_by, comment)
    silence_id = am_silence_id or f"local-sil-{uuid.uuid4().hex[:12]}"

    record = {
        "id": silence_id,
        "starts_at": starts_iso,
        "ends_at": ends_iso,
        "created_by": created_by,
        "comment": comment,
        "matchers": matchers,
        "expired_explicitly": False,
    }
    record["state"] = _compute_silence_state(record)

    with file_lock(sdir / ".silences.lock"):
        store = load_json_file(sdir / "silences.json", {"silences": []})
        silences_list: list[dict[str, Any]] = [
            s for s in store.get("silences", []) if str(s.get("id")) != silence_id
        ]
        silences_list.append(record)
        atomic_write_json(sdir / "silences.json", {"silences": silences_list}, mode=0o600)

    return {"status": "ok", "silence_id": silence_id}


def list_silences(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """List silences reconciling Alertmanager /api/v2/silences with persisted state/silences.json."""
    sdir = resolve_state_dir(state_dir)
    customer_filter = str(payload.get("customer") or "").strip()
    include_expired = bool(payload.get("include_expired", False))

    store = load_json_file(sdir / "silences.json", {"silences": []})
    merged_by_id: dict[str, dict[str, Any]] = {}

    now = datetime.now(timezone.utc)
    for local_item in store.get("silences", []):
        sid = str(local_item["id"])
        merged_by_id[sid] = {
            "id": sid,
            "state": _compute_silence_state(local_item, now),
            "starts_at": str(local_item["starts_at"]),
            "ends_at": str(local_item["ends_at"]),
            "created_by": str(local_item["created_by"]),
            "comment": str(local_item["comment"]),
            "matchers": [
                {
                    "name": str(m["name"]),
                    "value": str(m["value"]),
                    "is_regex": bool(m.get("is_regex", False)),
                    "is_equal": bool(m.get("is_equal", True)),
                }
                for m in (local_item.get("matchers") or [])
            ],
        }

    status, body = pod_http_request(
        f"{_alertmanager_base_url()}/api/v2/silences",
        method="GET",
        timeout=3.0,
    )
    if 200 <= status < 300 and body:
        try:
            am_items = json.loads(body.decode("utf-8"))
            if isinstance(am_items, list):
                for raw_am in am_items:
                    converted = _from_am_silence(raw_am)
                    if converted["state"] != "expired":
                        converted["state"] = _compute_silence_state(converted, now)
                    merged_by_id[converted["id"]] = converted
        except json.JSONDecodeError:
            pass

    results: list[dict[str, Any]] = []
    for item in merged_by_id.values():
        if not include_expired and item["state"] == "expired":
            continue
        if customer_filter:
            has_customer_match = any(
                m["name"] == "customer" and m["value"] == customer_filter and m["is_equal"]
                for m in item["matchers"]
            )
            if not has_customer_match:
                continue
        results.append(item)

    results.sort(key=lambda s: (s["starts_at"], s["id"]))
    return {"silences": results}


def delete_silence(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """Expire/delete a silence in Alertmanager /api/v2/silence/<id> and state/silences.json."""
    sdir = resolve_state_dir(state_dir)
    raw_silence_id = str(payload.get("silence_id") or "")
    if not _SILENCE_ID_RE.match(raw_silence_id):
        raise ValidationFailure(
            "silence_id",
            raw_silence_id,
            "invalid_silence_id",
            "silence_id must match ^[A-Za-z0-9_-]{4,128}\\Z",
        )
    silence_id = raw_silence_id
    encoded_id = quote(silence_id, safe="")

    status, _ = pod_http_request(
        f"{_alertmanager_base_url()}/api/v2/silence/{encoded_id}",
        method="DELETE",
        timeout=3.0,
    )
    deleted_remote = 200 <= status < 300

    deleted_local = False
    with file_lock(sdir / ".silences.lock"):
        store = load_json_file(sdir / "silences.json", {"silences": []})
        silences_list: list[dict[str, Any]] = list(store.get("silences", []))
        for item in silences_list:
            if str(item.get("id")) == silence_id:
                item["expired_explicitly"] = True
                item["state"] = "expired"
                deleted_local = True
        if deleted_local:
            atomic_write_json(sdir / "silences.json", {"silences": silences_list}, mode=0o600)

    return {"status": "ok", "silence_id": silence_id, "deleted": bool(deleted_remote or deleted_local)}


def restore_silences_to_alertmanager(state_dir: str | Path | None = None) -> int:
    """Re-apply non-expired silences from state/silences.json to Alertmanager after Restic restore."""
    sdir = resolve_state_dir(state_dir)
    now = datetime.now(timezone.utc)
    restored = 0

    with file_lock(sdir / ".silences.lock"):
        store = load_json_file(sdir / "silences.json", {"silences": []})
        silences_list: list[dict[str, Any]] = list(store.get("silences", []))
        changed = False
        for item in silences_list:
            if _compute_silence_state(item, now) == "expired":
                continue
            new_sid = _post_silence_to_alertmanager(
                item.get("matchers") or [],
                str(item["starts_at"]),
                str(item["ends_at"]),
                str(item["created_by"]),
                str(item["comment"]),
            )
            if new_sid:
                item["id"] = new_sid
                restored += 1
                changed = True
        if changed:
            atomic_write_json(sdir / "silences.json", {"silences": silences_list}, mode=0o600)

    return restored
