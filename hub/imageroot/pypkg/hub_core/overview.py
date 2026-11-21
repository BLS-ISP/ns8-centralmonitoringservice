"""Operational overview, component health, and configuration reader (never overrides get-status)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from hub_core import ALL_COMPONENT_KEYS, resolve_state_dir
from hub_core.env_store import build_urls, read_module_env, read_secrets
from hub_core.pod_http import pod_fetch_json

COMPONENT_SERVICE_UNITS: dict[str, str] = {
    "hub_gateway": "hub-gateway.service",
    "prometheus": "prometheus.service",
    "loki": "loki.service",
    "grafana": "grafana.service",
    "alertmanager": "alertmanager.service",
    "prom_label_proxy": "prom-label-proxy.service",
    "blackbox_exporter": "blackbox-exporter.service",
    "snmp_exporter": "snmp-exporter.service",
    "thanos_sidecar": "thanos-sidecar.service",
    "thanos_store": "thanos-store.service",
    "thanos_query": "thanos-query.service",
}

THANOS_KEYS: frozenset[str] = frozenset({"thanos_sidecar", "thanos_store", "thanos_query"})


def _extract_records(path: Path, list_key: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        nested = raw.get(list_key)
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
        if isinstance(nested, dict):
            return [item for item in nested.values() if isinstance(item, dict)]
    return []


def _directory_size_bytes(path: Path | None) -> int:
    if path is None or not path.exists():
        return 0
    if path.is_file():
        try:
            return max(0, path.stat().st_size)
        except OSError:
            return 0
    total = 0
    for root, _, files in os.walk(path):
        root_path = Path(root)
        for fname in files:
            try:
                total += (root_path / fname).stat().st_size
            except OSError:
                continue
    return max(0, total)


def collect_storage_usage_bytes(state_dir: Path) -> dict[str, int]:
    """Compute disk usage across Prometheus, Loki, and Grafana volumes/directories."""
    volume_dirs: dict[str, Path | None] = {
        "prometheus-data": Path(p) if (p := os.environ.get("PROMETHEUS_DATA_DIR")) else None,
        "loki-data": Path(p) if (p := os.environ.get("LOKI_DATA_DIR")) else None,
        "grafana-data": Path(p) if (p := os.environ.get("GRAFANA_DATA_DIR")) else None,
    }
    if shutil.which("podman") is not None:
        for vol_name, current in list(volume_dirs.items()):
            if current is not None:
                continue
            proc = subprocess.run(
                ["podman", "volume", "inspect", "--format", "{{.Mountpoint}}", vol_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                volume_dirs[vol_name] = Path(proc.stdout.strip())

    prom_bytes = _directory_size_bytes(volume_dirs["prometheus-data"])
    loki_bytes = _directory_size_bytes(volume_dirs["loki-data"])
    graf_bytes = _directory_size_bytes(volume_dirs["grafana-data"])
    if graf_bytes == 0 and (bak := state_dir / "grafana.db.bak").is_file():
        graf_bytes = _directory_size_bytes(bak)

    return {
        "prometheus_bytes": prom_bytes,
        "loki_bytes": loki_bytes,
        "grafana_bytes": graf_bytes,
        "total_bytes": prom_bytes + loki_bytes + graf_bytes,
    }


def _default_unit_probe(unit_name: str) -> str:
    if shutil.which("systemctl") is None:
        return "unhealthy"
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "is-active", unit_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        state = proc.stdout.strip()
        if state == "active":
            return "healthy"
        return "unhealthy"
    except (OSError, subprocess.SubprocessError):
        return "unhealthy"


def collect_component_health(
    *,
    configured: bool,
    storage_mode: str,
    probe_unit: Callable[[str], str] | None = None,
) -> dict[str, str]:
    """Evaluate health status ('healthy' | 'unhealthy' | 'disabled') for all 11 Hub components."""
    checker = probe_unit or _default_unit_probe
    statuses: dict[str, str] = {}
    for comp_key in ALL_COMPONENT_KEYS:
        if comp_key in THANOS_KEYS and storage_mode != "s3":
            statuses[comp_key] = "disabled"
            continue
        if not configured:
            statuses[comp_key] = "disabled"
            continue
        unit_status = checker(COMPONENT_SERVICE_UNITS[comp_key])
        statuses[comp_key] = unit_status if unit_status in ("healthy", "unhealthy", "disabled") else "unhealthy"
    return statuses


def _fetch_json_short(url: str, timeout: float = 0.6) -> dict[str, Any] | None:
    return pod_fetch_json(url, timeout=timeout)


def collect_runtime_counts(
    state_dir: Path,
    *,
    configured: bool,
    promql_base_url: str,
    fetch_json: Callable[[str], dict[str, Any] | None] | None = None,
) -> dict[str, int]:
    """Gather tenant, target, silence, series, and firing alert counts safely."""
    tenants = _extract_records(state_dir / "tenants.json", "tenants")
    targets = _extract_records(state_dir / "targets.json", "targets")
    silences = _extract_records(state_dir / "silences.json", "silences")

    tenants_count = len(tenants)
    portal_count = sum(1 for t in tenants if bool(t.get("customer_portal_enabled", False)))
    active_targets = sum(1 for t in targets if bool(t.get("enabled", True)))
    active_silences = sum(
        1 for s in silences if str(s.get("state", "active")).lower() == "active"
    )

    active_series = 0
    firing_critical = 0
    firing_warning = 0

    if configured and (fetch_json is not None or shutil.which("systemctl") is not None):
        fetcher = fetch_json or _fetch_json_short
        tsdb = fetcher("http://127.0.0.1:9090/api/v1/status/tsdb")
        if isinstance(tsdb, dict):
            head_stats = (tsdb.get("data") or {}).get("headStats") or {}
            active_series = max(0, int(head_stats.get("numSeries", 0) or 0))

        alerts_doc = fetcher(f"{promql_base_url.rstrip('/')}/api/v1/alerts")
        if isinstance(alerts_doc, dict):
            alert_list = (alerts_doc.get("data") or {}).get("alerts") or []
            for alert in alert_list:
                if not isinstance(alert, dict) or alert.get("state") != "firing":
                    continue
                sev = str((alert.get("labels") or {}).get("severity", "warning")).lower()
                if sev == "critical":
                    firing_critical += 1
                else:
                    firing_warning += 1

    return {
        "tenants": tenants_count,
        "portal_enabled_tenants": portal_count,
        "central_targets": active_targets,
        "active_series": active_series,
        "firing_alerts_critical": firing_critical,
        "firing_alerts_warning": firing_warning,
        "active_silences": active_silences,
    }


def list_available_ldap_domains() -> list[str]:
    """Query NS8 Ldapproxy for configured user domains without failing if unavailable."""
    try:
        from agent.ldapproxy import Ldapproxy

        proxy = Ldapproxy()
        if hasattr(proxy, "get_domains_list"):
            return sorted(str(d) for d in proxy.get_domains_list())
        if hasattr(proxy, "get_domains"):
            domains = proxy.get_domains()
            if isinstance(domains, dict):
                return sorted(str(k) for k in domains.keys())
            return sorted(str(d) for d in domains)
    except Exception:
        return []
    return []


def build_get_configuration_response(
    state_dir: str | Path | None = None,
    *,
    probe_unit: Callable[[str], str] | None = None,
    fetch_json: Callable[[str], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Construct schema-compliant output for get-configuration/20read with secrets redacted."""
    sdir = resolve_state_dir(state_dir)
    env = read_module_env(sdir)
    secrets_map = read_secrets(sdir)

    configured = env.get("CONFIGURED", "false").lower() == "true"
    host = env.get("TRAEFIK_HOST", "")
    storage_mode = env.get("STORAGE_MODE", "local")
    if storage_mode not in ("local", "s3"):
        storage_mode = "local"
    promql_url = env.get(
        "PROMQL_UPSTREAM_URL",
        "http://127.0.0.1:10902" if storage_mode == "s3" else "http://127.0.0.1:9090",
    )

    urls = build_urls(host)
    components = collect_component_health(
        configured=configured,
        storage_mode=storage_mode,
        probe_unit=probe_unit,
    )
    counts = collect_runtime_counts(
        sdir,
        configured=configured,
        promql_base_url=promql_url,
        fetch_json=fetch_json,
    )
    storage_bytes = collect_storage_usage_bytes(sdir)

    return {
        "configured": configured,
        "host": host,
        "lets_encrypt": env.get("TRAEFIK_LETS_ENCRYPT", "true").lower() == "true",
        "http2https": env.get("TRAEFIK_HTTP2HTTPS", "true").lower() == "true",
        "retention_days": max(1, int(env.get("RETENTION_DAYS", "30") or "30")),
        "retention_size_gb": max(0, int(env.get("RETENTION_SIZE_GB", "50") or "50")),
        "loki_retention_days": max(1, int(env.get("LOKI_RETENTION_DAYS", "30") or "30")),
        "backup_include_tsdb": env.get("BACKUP_INCLUDE_TSDB", "false").lower() == "true",
        "storage_mode": storage_mode,
        "s3": {
            "endpoint": env.get("S3_ENDPOINT", ""),
            "bucket": env.get("S3_BUCKET", ""),
            "region": env.get("S3_REGION", "us-east-1") or "us-east-1",
            "access_key": env.get("S3_ACCESS_KEY", ""),
            "has_secret_key": bool(secrets_map.get("S3_SECRET_KEY", "")),
            "insecure": env.get("S3_INSECURE", "false").lower() == "true",
            "path_style": env.get("S3_PATH_STYLE", "true").lower() == "true",
        },
        "ldap_enabled": env.get("LDAP_ENABLED", "false").lower() == "true",
        "ldap_domain": env.get("LDAP_DOMAIN", ""),
        "ldap_admin_group": env.get("LDAP_ADMIN_GROUP", "Domain Admins"),
        "ldap_editor_group": env.get("LDAP_EDITOR_GROUP", ""),
        "available_ldap_domains": list_available_ldap_domains(),
        "has_grafana_admin_password": bool(secrets_map.get("GRAFANA_ADMIN_PASSWORD", "")),
        "grafana_url": urls["grafana_url"],
        "ingest_metrics_url": urls["ingest_metrics_url"],
        "ingest_logs_url": urls["ingest_logs_url"],
        "health": {
            "components": components,
            "active_tenants_count": counts["tenants"],
            "active_targets_count": counts["central_targets"],
            "firing_alerts_count": counts["firing_alerts_critical"] + counts["firing_alerts_warning"],
            "active_silences_count": counts["active_silences"],
            "storage_usage_bytes": storage_bytes,
        },
    }


def build_get_overview_response(
    state_dir: str | Path | None = None,
    *,
    probe_unit: Callable[[str], str] | None = None,
    fetch_json: Callable[[str], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Construct schema-compliant output for get-overview/20read."""
    sdir = resolve_state_dir(state_dir)
    env = read_module_env(sdir)

    configured = env.get("CONFIGURED", "false").lower() == "true"
    host = env.get("TRAEFIK_HOST", "")
    storage_mode = env.get("STORAGE_MODE", "local")
    if storage_mode not in ("local", "s3"):
        storage_mode = "local"
    promql_url = env.get(
        "PROMQL_UPSTREAM_URL",
        "http://127.0.0.1:10902" if storage_mode == "s3" else "http://127.0.0.1:9090",
    )

    urls = build_urls(host)
    result: dict[str, Any] = {
        "configured": configured,
        "grafana_url": urls["grafana_url"],
        "ingest_metrics_url": urls["ingest_metrics_url"],
        "ingest_logs_url": urls["ingest_logs_url"],
        "storage_mode": storage_mode,
        "components": collect_component_health(
            configured=configured,
            storage_mode=storage_mode,
            probe_unit=probe_unit,
        ),
        "counts": collect_runtime_counts(
            sdir,
            configured=configured,
            promql_base_url=promql_url,
            fetch_json=fetch_json,
        ),
        "storage_usage_bytes": collect_storage_usage_bytes(sdir),
    }
    if storage_mode == "s3" or env.get("S3_BUCKET"):
        result["s3_bucket"] = env.get("S3_BUCKET", "")
    return result
