"""Central Pull/Probe Target CRUD, Atomic file_sd Generator & Federation Job Renderer."""

from __future__ import annotations

from datetime import datetime, timezone
import math
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import uuid

from hub_alerting import (
    ValidationFailure,
    atomic_write_json,
    atomic_write_text,
    file_lock,
    load_json_file,
    load_tenants_map,
    resolve_config_dir,
    resolve_state_dir,
    trigger_http_reload,
    yaml_quote,
)
from hub_alerting.blackbox_config import render_blackbox_config
from hub_alerting.snmp_config import render_snmp_config
from hub_alerting.ssrf_guard import assert_not_internal_pod_endpoint

DEFAULT_MATCH_SELECTORS = ['{__name__=~"node_.+|ns8_.+|up|restic_.+|systemd_.+"}']

ALLOWED_DEVICE_ROLES = frozenset(
    {
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

ALLOWED_SNMP_MODULES = frozenset(
    {
        "if_mib",
        "apcupsd",
        "synology",
        "qnap",
        "mikrotik",
        "fortigate",
        "printer",
        "generic",
    }
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _prometheus_reload_url() -> str:
    return os.environ.get("PROMETHEUS_RELOAD_URL", "http://127.0.0.1:9090/-/reload")


def _snmp_reload_url() -> str:
    return os.environ.get("SNMP_RELOAD_URL", "http://127.0.0.1:9116/-/reload")


def _normalize_host_port_endpoint(raw: str) -> str:
    cleaned = raw.strip()
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.netloc:
            return parsed.netloc
    return cleaned


def _has_target_secret(target: dict[str, Any]) -> bool:
    ttype = target.get("target_type")
    if ttype in {"ns8-federation", "exporter"}:
        return bool(target.get("basic_auth_password") or target.get("bearer_token"))
    if ttype == "snmp":
        if target.get("snmp_version", "v2c") == "v3":
            v3 = target.get("snmp_v3") or {}
            return bool(v3.get("auth_password") or v3.get("priv_password"))
        comm = target.get("snmp_community", "")
        return bool(comm)
    return bool(target.get("basic_auth_password") or target.get("bearer_token"))


def _redact_target_for_output(target: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(target["id"]),
        "name": str(target["name"]),
        "enabled": bool(target.get("enabled", True)),
        "target_type": str(target["target_type"]),
        "customer": str(target["customer"]),
        "site": str(target["site"]),
        "device_role": str(target["device_role"]),
        "scrape_interval": str(target.get("scrape_interval", "30s")),
        "endpoints": list(target.get("endpoints", [])),
        "has_secret": _has_target_secret(target),
        "created_at": str(target.get("created_at", "")),
        "updated_at": str(target.get("updated_at", "")),
    }
    ttype = target["target_type"]
    if ttype in {"ns8-federation", "exporter"}:
        out["scheme"] = str(target.get("scheme", "https"))
        out["metrics_path"] = str(target.get("metrics_path", "/federate" if ttype == "ns8-federation" else "/metrics"))
        out["tls_skip_verify"] = bool(target.get("tls_skip_verify", False))
        out["basic_auth_user"] = str(target.get("basic_auth_user", ""))
    if ttype == "ns8-federation":
        out["match_selectors"] = list(target.get("match_selectors") or DEFAULT_MATCH_SELECTORS)
    elif ttype == "blackbox":
        out["blackbox_module"] = str(target.get("blackbox_module", "http_2xx"))
        out["tls_skip_verify"] = bool(target.get("tls_skip_verify", False))
    elif ttype == "snmp":
        out["snmp_module"] = str(target.get("snmp_module", "if_mib"))
        snmp_ver = str(target.get("snmp_version", "v2c"))
        out["snmp_version"] = snmp_ver
        if snmp_ver == "v3":
            v3 = target.get("snmp_v3") or {}
            out["snmp_v3"] = {
                "username": str(v3.get("username") or ""),
                "security_level": str(v3.get("security_level") or "authPriv"),
                "auth_protocol": str(v3.get("auth_protocol") or "SHA256"),
                "priv_protocol": str(v3.get("priv_protocol") or "AES"),
            }
    return out


def build_prometheus_relabel_configs() -> dict[str, dict[str, Any]]:
    """Return canonical Prometheus file_sd scrape_config blocks for exporters, blackbox, and snmp."""
    return {
        "exporters": {
            "job_name": "hub-central-exporters",
            "honor_labels": False,
            "file_sd_configs": [{"files": ["/etc/prometheus/file_sd/exporters/*.json"], "refresh_interval": "30s"}],
        },
        "blackbox": {
            "job_name": "hub-central-blackbox",
            "honor_labels": False,
            "metrics_path": "/probe",
            "file_sd_configs": [{"files": ["/etc/prometheus/file_sd/blackbox/*.json"], "refresh_interval": "30s"}],
            "relabel_configs": [
                {"source_labels": ["__address__"], "target_label": "__param_target"},
                {"source_labels": ["__param_target"], "target_label": "instance"},
                {"target_label": "__address__", "replacement": "127.0.0.1:9115"},
            ],
        },
        "snmp": {
            "job_name": "hub-central-snmp",
            "honor_labels": False,
            "metrics_path": "/snmp",
            "file_sd_configs": [{"files": ["/etc/prometheus/file_sd/snmp/*.json"], "refresh_interval": "30s"}],
            "relabel_configs": [
                {"source_labels": ["__address__"], "target_label": "__param_target"},
                {"source_labels": ["__param_target"], "target_label": "instance"},
                {"target_label": "__address__", "replacement": "127.0.0.1:9116"},
            ],
        },
    }


def _render_federation_jobs(
    federation_targets: list[dict[str, Any]],
    prom_dir: Path,
) -> str:
    secrets_dir = prom_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    active_secret_files: set[str] = set()

    lines = [
        "# Generated by central-monitoring-hub (hub_alerting.targets_manager)",
        "# Loaded via Prometheus scrape_config_files: ['/etc/prometheus/federation_jobs.yml']",
    ]
    enabled_fed = [
        t
        for t in sorted(federation_targets, key=lambda item: str(item.get("id", "")))
        if t.get("target_type") == "ns8-federation" and t.get("enabled", True)
    ]

    if not enabled_fed:
        lines.append("scrape_configs: []")
    else:
        lines.append("scrape_configs:")
        for target in enabled_fed:
            tid = str(target["id"])
            scheme = str(target.get("scheme", "https"))
            raw_path = str(target.get("metrics_path", "/metrics"))
            metrics_path = "/federate" if raw_path in {"", "/metrics"} else raw_path
            interval = str(target.get("scrape_interval", "30s"))
            skip_verify = "true" if target.get("tls_skip_verify", False) else "false"
            selectors = list(target.get("match_selectors") or DEFAULT_MATCH_SELECTORS)
            endpoints = [_normalize_host_port_endpoint(ep) for ep in target.get("endpoints", [])]

            job_name = f"ns8-federation-{tid}"
            lines.append(f"  - job_name: {yaml_quote(job_name)}")
            lines.append("    honor_labels: false")
            lines.append(f"    scrape_interval: {interval}")
            lines.append(f"    scheme: {scheme}")
            lines.append(f"    metrics_path: {yaml_quote(metrics_path)}")
            lines.append("    params:")
            lines.append('      "match[]":')
            for sel in selectors:
                lines.append(f"        - {yaml_quote(sel)}")
            lines.append("    tls_config:")
            lines.append(f"      insecure_skip_verify: {skip_verify}")

            bearer = str(target.get("bearer_token") or "")
            basic_user = str(target.get("basic_auth_user") or "")
            basic_pw = str(target.get("basic_auth_password") or "")
            secret_filename = f"{tid}.secret"
            secret_host_path = secrets_dir / secret_filename
            secret_container_path = f"/etc/prometheus/secrets/{secret_filename}"

            if bearer:
                atomic_write_text(secret_host_path, bearer.strip(), mode=0o600)
                os.chmod(secret_host_path, 0o600)
                active_secret_files.add(secret_filename)
                # Rewrite without trailing newline if Prometheus credentials_file trims/reads raw
                secret_host_path.write_bytes(bearer.strip().encode("utf-8"))
                os.chmod(secret_host_path, 0o600)
                lines.append("    authorization:")
                lines.append('      type: "Bearer"')
                lines.append(f"      credentials_file: {yaml_quote(secret_container_path)}")
            elif basic_user and basic_pw:
                atomic_write_text(secret_host_path, basic_pw, mode=0o600)
                secret_host_path.write_bytes(basic_pw.encode("utf-8"))
                os.chmod(secret_host_path, 0o600)
                active_secret_files.add(secret_filename)
                lines.append("    basic_auth:")
                lines.append(f"      username: {yaml_quote(basic_user)}")
                lines.append(f"      password_file: {yaml_quote(secret_container_path)}")

            lines.append("    static_configs:")
            lines.append("      - targets:")
            for ep in endpoints:
                lines.append(f"          - {yaml_quote(ep)}")
            lines.append("        labels:")
            lines.append(f"          customer: {yaml_quote(str(target['customer']))}")
            lines.append(f"          site: {yaml_quote(str(target['site']))}")
            lines.append(f"          device_role: {yaml_quote(str(target['device_role']))}")
            lines.append('          collector_id: "hub-central"')

    # Remove stale secret files
    for existing in secrets_dir.glob("*.secret"):
        if existing.name not in active_secret_files:
            existing.unlink(missing_ok=True)

    rendered = "\n".join(lines) + "\n"
    atomic_write_text(prom_dir / "federation_jobs.yml", rendered, mode=0o600)
    return rendered


def sync_target_configs(
    targets: list[dict[str, Any]],
    *,
    state_dir: str | Path | None = None,
    reload_federation: bool = False,
    reload_snmp: bool = False,
) -> None:
    """Materialize file_sd JSONs, federation_jobs.yml, blackbox.yml, and snmp.yml atomically."""
    cdir = resolve_config_dir(state_dir)
    prom_dir = cdir / "prometheus"
    sd_dirs = {
        "exporter": prom_dir / "file_sd" / "exporters",
        "blackbox": prom_dir / "file_sd" / "blackbox",
        "snmp": prom_dir / "file_sd" / "snmp",
    }
    for folder in sd_dirs.values():
        folder.mkdir(parents=True, exist_ok=True)

    bb_path = cdir / "blackbox" / "blackbox.yml"
    if not bb_path.is_file() or "http_post_2xx:" not in bb_path.read_text(encoding="utf-8"):
        render_blackbox_config(bb_path, state_dir=state_dir)

    expected_sd_files: dict[str, set[str]] = {"exporter": set(), "blackbox": set(), "snmp": set()}

    for target in targets:
        ttype = str(target.get("target_type", ""))
        tid = str(target.get("id", ""))
        if not target.get("enabled", True) or ttype not in sd_dirs:
            continue

        fname = f"{tid}.json"
        expected_sd_files[ttype].add(fname)
        base_labels: dict[str, str] = {
            "customer": str(target["customer"]),
            "site": str(target["site"]),
            "device_role": str(target["device_role"]),
            "collector_id": "hub-central",
            "__scrape_interval__": str(target.get("scrape_interval", "30s")),
        }

        if ttype == "exporter":
            ep_list = [_normalize_host_port_endpoint(ep) for ep in target.get("endpoints", [])]
            base_labels["__scheme__"] = str(target.get("scheme", "https"))
            base_labels["__metrics_path__"] = str(target.get("metrics_path", "/metrics"))
        elif ttype == "blackbox":
            ep_list = [str(ep).strip() for ep in target.get("endpoints", [])]
            bb_mod = str(target.get("blackbox_module", "http_2xx"))
            effective_mod = (
                f"{bb_mod}_insecure"
                if target.get("tls_skip_verify", False) and bb_mod in {"http_2xx", "http_post_2xx"}
                else bb_mod
            )
            base_labels["module"] = bb_mod
            base_labels["__param_module"] = effective_mod
        else:  # snmp
            ep_list = [_normalize_host_port_endpoint(ep) for ep in target.get("endpoints", [])]
            snmp_mod = str(target.get("snmp_module", "if_mib"))
            base_labels["snmp_module"] = snmp_mod
            base_labels["__param_module"] = snmp_mod
            base_labels["__param_auth"] = f"target_{tid}"

        sd_payload = [{"targets": ep_list, "labels": base_labels}]
        atomic_write_json(sd_dirs[ttype] / fname, sd_payload, mode=0o640)

    for ttype, folder in sd_dirs.items():
        for existing in folder.glob("*.json"):
            if existing.name not in expected_sd_files[ttype]:
                existing.unlink(missing_ok=True)

    render_snmp_config(
        [t for t in targets if t.get("target_type") == "snmp"],
        cdir / "snmp" / "snmp.yml",
        state_dir=state_dir,
    )
    _render_federation_jobs(targets, prom_dir)

    if reload_snmp:
        trigger_http_reload(_snmp_reload_url())
    if reload_federation or reload_snmp:
        trigger_http_reload(_prometheus_reload_url())


def _validate_tenant_and_site(customer: str, site: str, state_dir: str | Path | None) -> None:
    tenants = load_tenants_map(state_dir)
    tenant = tenants.get(customer)
    if tenant is None:
        raise ValidationFailure("customer", customer, "unknown_tenant", f"Unknown customer tenant: {customer}")
    allowed_sites = tenant.get("sites") or []
    if site not in allowed_sites:
        raise ValidationFailure("site", site, "unknown_site", f"Site {site!r} is not registered for {customer!r}")


def save_target(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """Create or update a pull/probe target in state/targets.json and update file_sd atomically."""
    sdir = resolve_state_dir(state_dir)
    customer = str(payload["customer"]).strip()
    site = str(payload["site"]).strip()
    _validate_tenant_and_site(customer, site, sdir)

    endpoints = [str(ep).strip() for ep in payload.get("endpoints", [])]
    for ep in endpoints:
        assert_not_internal_pod_endpoint(ep, field="endpoints")

    ttype = str(payload["target_type"])
    device_role = str(payload["device_role"]).strip()
    if device_role not in ALLOWED_DEVICE_ROLES:
        raise ValidationFailure("device_role", device_role, "invalid_device_role", f"Invalid device_role: {device_role}")
    snmp_mod_in = str(payload.get("snmp_module") or "if_mib").strip()
    if ttype == "snmp" and snmp_mod_in not in ALLOWED_SNMP_MODULES:
        raise ValidationFailure("snmp_module", snmp_mod_in, "invalid_snmp_module", f"Invalid snmp_module: {snmp_mod_in}")
    secret_unchanged = bool(payload.get("secret_unchanged", False))

    with file_lock(sdir / ".targets.lock"):
        store = load_json_file(sdir / "targets.json", {"targets": []})
        targets_list: list[dict[str, Any]] = list(store.get("targets", []))
        by_id = {str(t["id"]): idx for idx, t in enumerate(targets_list)}

        req_id = str(payload.get("id") or "").strip()
        now_iso = _utc_now_iso()

        if req_id and req_id in by_id:
            created = False
            existing = targets_list[by_id[req_id]]
            target_id = req_id
            created_at = str(existing.get("created_at") or now_iso)
        else:
            created = True
            existing = {}
            target_id = req_id or f"tgt_{uuid.uuid4().hex[:12]}"
            created_at = now_iso

        basic_pw = str(payload.get("basic_auth_password") or "")
        bearer_tok = str(payload.get("bearer_token") or "")
        snmp_comm = str(payload.get("snmp_community") if "snmp_community" in payload else "public")
        raw_v3 = dict(payload.get("snmp_v3") or {})

        if not created and secret_unchanged:
            if not basic_pw:
                basic_pw = str(existing.get("basic_auth_password") or "")
            if not bearer_tok:
                bearer_tok = str(existing.get("bearer_token") or "")
            if "snmp_community" not in payload or not payload.get("snmp_community"):
                snmp_comm = str(existing.get("snmp_community") or "public")
            existing_v3 = dict(existing.get("snmp_v3") or {})
            if not raw_v3.get("auth_password") and existing_v3.get("auth_password"):
                raw_v3["auth_password"] = existing_v3["auth_password"]
            if not raw_v3.get("priv_password") and existing_v3.get("priv_password"):
                raw_v3["priv_password"] = existing_v3["priv_password"]

        if ttype == "snmp" and payload.get("snmp_version", "v2c") == "v3":
            username = str(raw_v3.get("username") or "").strip()
            if not username:
                raise ValidationFailure("snmp_v3.username", "", "missing_snmp_v3_username", "SNMPv3 username required")
            sec_level = str(raw_v3.get("security_level") or "authPriv")
            if sec_level in {"authNoPriv", "authPriv"} and not raw_v3.get("auth_password"):
                raise ValidationFailure(
                    "snmp_v3.auth_password", "", "missing_snmp_v3_auth_password", "SNMPv3 auth password required"
                )
            if sec_level == "authPriv" and not raw_v3.get("priv_password"):
                raise ValidationFailure(
                    "snmp_v3.priv_password", "", "missing_snmp_v3_priv_password", "SNMPv3 priv password required"
                )
            raw_v3 = {
                "username": username,
                "security_level": sec_level,
                "auth_protocol": str(raw_v3.get("auth_protocol") or "SHA256"),
                "auth_password": str(raw_v3.get("auth_password") or ""),
                "priv_protocol": str(raw_v3.get("priv_protocol") or "AES"),
                "priv_password": str(raw_v3.get("priv_password") or ""),
            }

        default_path = "/federate" if ttype == "ns8-federation" else "/metrics"
        raw_metrics_path = str(payload.get("metrics_path") or default_path)
        if ttype == "ns8-federation" and raw_metrics_path == "/metrics" and "metrics_path" not in payload:
            raw_metrics_path = "/federate"

        record: dict[str, Any] = {
            "id": target_id,
            "name": str(payload["name"]).strip(),
            "enabled": bool(payload.get("enabled", True)),
            "target_type": ttype,
            "customer": customer,
            "site": site,
            "device_role": str(payload["device_role"]),
            "scrape_interval": str(payload.get("scrape_interval") or "30s"),
            "endpoints": endpoints,
            "scheme": str(payload.get("scheme") or "https"),
            "metrics_path": raw_metrics_path,
            "tls_skip_verify": bool(payload.get("tls_skip_verify", False)),
            "basic_auth_user": str(payload.get("basic_auth_user") or ""),
            "basic_auth_password": basic_pw,
            "bearer_token": bearer_tok,
            "match_selectors": list(payload.get("match_selectors") or DEFAULT_MATCH_SELECTORS),
            "blackbox_module": str(payload.get("blackbox_module") or "http_2xx"),
            "snmp_module": str(payload.get("snmp_module") or "if_mib"),
            "snmp_version": str(payload.get("snmp_version") or "v2c"),
            "snmp_community": snmp_comm,
            "snmp_v3": raw_v3,
            "created_at": created_at,
            "updated_at": now_iso,
        }

        prev_type = str(existing.get("target_type") or "")
        if created:
            targets_list.append(record)
        else:
            targets_list[by_id[target_id]] = record

        atomic_write_json(sdir / "targets.json", {"targets": targets_list}, mode=0o600)

        need_fed_reload = "ns8-federation" in {ttype, prev_type}
        need_snmp_reload = "snmp" in {ttype, prev_type}
        sync_target_configs(
            targets_list,
            state_dir=sdir,
            reload_federation=need_fed_reload,
            reload_snmp=need_snmp_reload,
        )

    return {"status": "ok", "id": target_id, "created": created}


def list_targets(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """List pull/probe targets with optional filtering, pagination, and full secret redaction."""
    sdir = resolve_state_dir(state_dir)
    customer_filter = str(payload.get("customer") or "").strip()
    type_filter = str(payload.get("target_type") or "").strip()
    page = max(1, int(payload.get("page") or 1))
    page_size = min(500, max(1, int(payload.get("page_size") or 100)))

    store = load_json_file(sdir / "targets.json", {"targets": []})
    raw_targets: list[dict[str, Any]] = list(store.get("targets", []))

    filtered = [
        t
        for t in raw_targets
        if (not customer_filter or t.get("customer") == customer_filter)
        and (not type_filter or t.get("target_type") == type_filter)
    ]
    total_items = len(filtered)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0
    start = (page - 1) * page_size
    page_slice = filtered[start : start + page_size]

    return {
        "targets": [_redact_target_for_output(t) for t in page_slice],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total_items,
            "total_pages": total_pages,
        },
    }


def delete_target(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """Delete a target by ID from state/targets.json and clean up its file_sd / secret artifacts."""
    sdir = resolve_state_dir(state_dir)
    target_id = str(payload["id"]).strip()

    with file_lock(sdir / ".targets.lock"):
        store = load_json_file(sdir / "targets.json", {"targets": []})
        raw_targets: list[dict[str, Any]] = list(store.get("targets", []))
        removed = [t for t in raw_targets if str(t.get("id")) == target_id]
        remaining = [t for t in raw_targets if str(t.get("id")) != target_id]
        deleted = len(removed) > 0

        if deleted:
            atomic_write_json(sdir / "targets.json", {"targets": remaining}, mode=0o600)
            removed_types = {str(t.get("target_type")) for t in removed}
            sync_target_configs(
                remaining,
                state_dir=sdir,
                reload_federation="ns8-federation" in removed_types,
                reload_snmp="snmp" in removed_types,
            )

    return {"status": "ok", "id": target_id, "deleted": deleted}
