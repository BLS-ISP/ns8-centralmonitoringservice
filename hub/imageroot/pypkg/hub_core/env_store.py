"""Environment and 0600 secret persistence for central-monitoring-hub."""

from __future__ import annotations

import os
import secrets as py_secrets
from pathlib import Path
from typing import Any

from hub_core import (
    atomic_write_text,
    resolve_pinned_images,
    resolve_state_dir,
)
from hub_core.storage_s3 import normalize_s3_settings


_FORBIDDEN_SECRET_CHARS = ("\r", "\n", "\x00", "\u2028", "\u2029")


def _validate_secret_value(key: str, val: str) -> None:
    if any(ch in val for ch in _FORBIDDEN_SECRET_CHARS):
        raise ValueError(f"Secret {key!r} must not contain control or line-separator characters")


def _parse_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").split("\n"):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        key, val = raw_line.split("=", 1)
        key = key.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
            if raw_line.split("=", 1)[1].strip().startswith('"'):
                val = (
                    val.replace('\\"', '"')
                    .replace("\\n", "\n")
                    .replace("\\\\", "\\")
                )
        data[key] = val
    return data


def _parse_raw_env_file(path: Path) -> dict[str, str]:
    """Parse Podman --env-file format (raw literal KEY=VALUE after first '=')."""
    if not path.exists():
        return {}
    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").split("\n"):
        if raw_line.endswith("\r"):
            raw_line = raw_line[:-1]
        if not raw_line.strip() or raw_line.lstrip().startswith("#") or "=" not in raw_line:
            continue
        key, val = raw_line.split("=", 1)
        data[key.strip()] = val
    return data


def _format_env_value(val: str) -> str:
    if any(ch in val for ch in _FORBIDDEN_SECRET_CHARS):
        raise ValueError("Environment value must not contain control or line-separator characters")
    if any(ch in val for ch in (' ', '"', "'", "#", "$", "\\", "\t")):
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return val


def read_secrets(state_dir: str | Path | None = None) -> dict[str, str]:
    """Read state/secrets.env without exposing secrets into the global environment."""
    sdir = resolve_state_dir(state_dir)
    return _parse_raw_env_file(sdir / "secrets.env")


def write_secrets(state_dir: str | Path | None, secrets_map: dict[str, str]) -> Path:
    """Persist state/secrets.env atomically (0600) in raw Podman --env-file KEY=VALUE format."""
    sdir = resolve_state_dir(state_dir)
    target = sdir / "secrets.env"
    lines: list[str] = []
    for key, val in sorted(secrets_map.items()):
        str_key = str(key).strip()
        str_val = str(val)
        _validate_secret_value(str_key, str_val)
        lines.append(f"{str_key}={str_val}")
    atomic_write_text(target, "\n".join(lines), mode=0o600)
    return target


def ensure_initial_secrets(state_dir: str | Path | None = None) -> dict[str, str]:
    """Create initial Grafana admin password and internal cryptographic keys if missing."""
    current = read_secrets(state_dir)
    changed = False
    if not current.get("GRAFANA_ADMIN_PASSWORD"):
        current["GRAFANA_ADMIN_PASSWORD"] = py_secrets.token_urlsafe(18)
        changed = True
    if not current.get("GRAFANA_SECRET_KEY"):
        current["GRAFANA_SECRET_KEY"] = py_secrets.token_hex(32)
        changed = True
    if not current.get("HUB_INTERNAL_SECRET"):
        current["HUB_INTERNAL_SECRET"] = py_secrets.token_hex(32)
        changed = True
    # Keep GF_SECURITY_* aliases in secrets.env so Grafana container env-file works directly
    if current.get("GF_SECURITY_ADMIN_PASSWORD") != current["GRAFANA_ADMIN_PASSWORD"]:
        current["GF_SECURITY_ADMIN_PASSWORD"] = current["GRAFANA_ADMIN_PASSWORD"]
        changed = True
    if current.get("GF_SECURITY_SECRET_KEY") != current["GRAFANA_SECRET_KEY"]:
        current["GF_SECURITY_SECRET_KEY"] = current["GRAFANA_SECRET_KEY"]
        changed = True
    if changed or not (resolve_state_dir(state_dir) / "secrets.env").exists():
        write_secrets(state_dir, current)
    return current


def regenerate_clone_secrets(state_dir: str | Path | None = None) -> dict[str, str]:
    """Regenerate instance-specific cryptographic secrets during clone-module."""
    current = ensure_initial_secrets(state_dir)
    current["GRAFANA_SECRET_KEY"] = py_secrets.token_hex(32)
    current["GF_SECURITY_SECRET_KEY"] = current["GRAFANA_SECRET_KEY"]
    current["HUB_INTERNAL_SECRET"] = py_secrets.token_hex(32)
    write_secrets(state_dir, current)
    return current


def read_module_env(state_dir: str | Path | None = None) -> dict[str, str]:
    """Merge persisted state/environment with active os.environ values."""
    import agent

    sdir = resolve_state_dir(state_dir)
    merged: dict[str, str] = {}
    env_path = sdir / "environment"
    if hasattr(agent, "read_envfile") and env_path.exists():
        merged.update(agent.read_envfile(str(env_path)))
    else:
        merged.update(_parse_env_file(env_path))
    for key, val in os.environ.items():
        if key in merged or key.startswith(
            (
                "MODULE_",
                "NODE_",
                "TCP_",
                "TRAEFIK_",
                "STORAGE_",
                "PROM",
                "RETENTION_",
                "LOKI_",
                "BACKUP_",
                "S3_",
                "LDAP_",
                "CONFIGURED",
                "CENTRAL_MONITORING_",
                "ALERTMANAGER_",
                "GRAFANA_",
                "BLACKBOX_",
                "SNMP_",
                "THANOS_",
            )
        ):
            merged[key] = val
    return merged


def initialize_default_env(state_dir: str | Path | None = None) -> dict[str, str]:
    """Seed initial NS8 module environment variables on create-module and call dump_env()."""
    import agent

    ensure_initial_secrets(state_dir)
    existing = read_module_env(state_dir)

    defaults = {
        "CONFIGURED": "false",
        "TRAEFIK_HOST": "",
        "TRAEFIK_LETS_ENCRYPT": "true",
        "TRAEFIK_HTTP2HTTPS": "true",
        "RETENTION_DAYS": "30",
        "RETENTION_SIZE_GB": "50",
        "LOKI_RETENTION_DAYS": "30",
        "BACKUP_INCLUDE_TSDB": "false",
        "STORAGE_MODE": "local",
        "PROMQL_UPSTREAM_URL": "http://127.0.0.1:9090",
        "PROMETHEUS_EXTRA_ARGS": "--storage.tsdb.retention.size=50GB",
        "S3_ENDPOINT": "",
        "S3_BUCKET": "",
        "S3_REGION": "us-east-1",
        "S3_ACCESS_KEY": "",
        "S3_INSECURE": "false",
        "S3_PATH_STYLE": "true",
        "LDAP_ENABLED": "false",
        "LDAP_DOMAIN": "",
        "LDAP_ADMIN_GROUP": "Domain Admins",
        "LDAP_EDITOR_GROUP": "",
    }
    for img_key, img_val in resolve_pinned_images(state_dir).items():
        if not existing.get(img_key):
            agent.set_env(img_key, img_val)

    for key, default_val in defaults.items():
        if key not in existing:
            agent.set_env(key, default_val)

    # NS8 Rule #2: Always flush environment to disk immediately after set_env()
    agent.dump_env()
    return read_module_env(state_dir)


def build_prometheus_extra_args(storage_mode: str, retention_size_gb: int) -> str:
    args: list[str] = []
    if retention_size_gb > 0:
        args.append(f"--storage.tsdb.retention.size={retention_size_gb}GB")
    if storage_mode == "s3":
        args.append("--storage.tsdb.min-block-duration=2h")
        args.append("--storage.tsdb.max-block-duration=2h")
    return " ".join(args)


def build_urls(host: str) -> dict[str, str]:
    clean_host = host.strip().lower()
    if not clean_host:
        return {
            "grafana_url": "",
            "ingest_metrics_url": "",
            "ingest_logs_url": "",
        }
    base = f"https://{clean_host}"
    return {
        "grafana_url": base,
        "ingest_metrics_url": f"{base}/api/v1/write",
        "ingest_logs_url": f"{base}/loki/api/v1/push",
    }


def apply_configuration(state_dir: str | Path | None, request: dict[str, Any]) -> dict[str, str]:
    """Validate and persist configure-module settings to environment + secrets.env."""
    import agent

    sdir = resolve_state_dir(state_dir)
    secrets_map = ensure_initial_secrets(sdir)

    host = str(request["host"]).strip().lower()
    lets_encrypt = bool(request["lets_encrypt"])
    http2https = bool(request["http2https"])
    retention_days = int(request.get("retention_days", 30))
    retention_size_gb = int(request.get("retention_size_gb", 50))
    loki_retention_days = int(request.get("loki_retention_days", 30))
    backup_include_tsdb = bool(request.get("backup_include_tsdb", False))
    storage_mode = str(request.get("storage_mode", "local"))

    if storage_mode not in ("local", "s3"):
        raise ValueError(f"Unsupported storage_mode: {storage_mode!r}")

    s3_cfg, resolved_s3_secret = normalize_s3_settings(
        storage_mode=storage_mode,
        raw_s3=request.get("s3") or {},
        existing_secret=secrets_map.get("S3_SECRET_KEY", ""),
    )
    if resolved_s3_secret:
        secrets_map["S3_SECRET_KEY"] = resolved_s3_secret
    elif not s3_cfg["secret_key_unchanged"] and "s3" in request:
        secrets_map.pop("S3_SECRET_KEY", None)

    new_admin_pw = str(request.get("grafana_admin_password", ""))
    if new_admin_pw:
        if len(new_admin_pw) < 8:
            raise ValueError("grafana_admin_password must be at least 8 characters when non-empty")
        secrets_map["GRAFANA_ADMIN_PASSWORD"] = new_admin_pw
        secrets_map["GF_SECURITY_ADMIN_PASSWORD"] = new_admin_pw

    write_secrets(sdir, secrets_map)

    ldap_enabled = bool(request.get("ldap_enabled", False))
    ldap_domain = str(request.get("ldap_domain", "")).strip()
    ldap_admin_group = str(request.get("ldap_admin_group", "Domain Admins")).strip()
    ldap_editor_group = str(request.get("ldap_editor_group", "")).strip()

    promql_upstream = "http://127.0.0.1:10902" if storage_mode == "s3" else "http://127.0.0.1:9090"
    prom_extra_args = build_prometheus_extra_args(storage_mode, retention_size_gb)

    env_updates = {
        "CONFIGURED": "true",
        "TRAEFIK_HOST": host,
        "TRAEFIK_LETS_ENCRYPT": "true" if lets_encrypt else "false",
        "TRAEFIK_HTTP2HTTPS": "true" if http2https else "false",
        "RETENTION_DAYS": str(retention_days),
        "RETENTION_SIZE_GB": str(retention_size_gb),
        "LOKI_RETENTION_DAYS": str(loki_retention_days),
        "BACKUP_INCLUDE_TSDB": "true" if backup_include_tsdb else "false",
        "STORAGE_MODE": storage_mode,
        "PROMQL_UPSTREAM_URL": promql_upstream,
        "PROMETHEUS_EXTRA_ARGS": prom_extra_args,
        "S3_ENDPOINT": s3_cfg["endpoint"],
        "S3_BUCKET": s3_cfg["bucket"],
        "S3_REGION": s3_cfg["region"],
        "S3_ACCESS_KEY": s3_cfg["access_key"],
        "S3_INSECURE": "true" if s3_cfg["insecure"] else "false",
        "S3_PATH_STYLE": "true" if s3_cfg["path_style"] else "false",
        "LDAP_ENABLED": "true" if ldap_enabled else "false",
        "LDAP_DOMAIN": ldap_domain,
        "LDAP_ADMIN_GROUP": ldap_admin_group,
        "LDAP_EDITOR_GROUP": ldap_editor_group,
    }
    existing = read_module_env(sdir)
    for img_key, img_val in resolve_pinned_images(state_dir).items():
        if not existing.get(img_key):
            agent.set_env(img_key, img_val)

    for key, val in env_updates.items():
        agent.set_env(key, val)

    # NS8 Rule #2: Flush state/environment BEFORE 80start_services runs!
    agent.dump_env()
    return read_module_env(sdir)


def discover_smarthost(state_dir: str | Path | None = None) -> Path:
    """Query NS8 Redis cluster/smarthost and write state/smarthost.env (0600)."""
    import agent

    sdir = resolve_state_dir(state_dir)
    raw: dict[str, str] = {}
    try:
        rdb = agent.redis_connect()
        fetched = rdb.hgetall("cluster/smarthost") or {}
        for k, v in fetched.items():
            key_str = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            val_str = v.decode("utf-8") if isinstance(v, bytes) else str(v)
            raw[key_str] = val_str
    except Exception:
        raw = {}

    host = raw.get("host", "")
    port = raw.get("port", "25") if host else ""
    username = raw.get("username", "")
    password = raw.get("password", "")
    encrypt_smtp = raw.get("encrypt_smtp", "")
    tls_verify = raw.get("tls_verify", "1")
    enabled = "true" if host else "false"

    pairs = {
        "SMARTHOST_ENABLED": enabled,
        "SMARTHOST_HOST": host,
        "HOST": host,
        "SMARTHOST_PORT": port,
        "PORT": port,
        "SMARTHOST_USERNAME": username,
        "USERNAME": username,
        "SMARTHOST_PASSWORD": password,
        "PASSWORD": password,
        "SMARTHOST_ENCRYPT_SMTP": encrypt_smtp,
        "ENCRYPT_SMTP": encrypt_smtp,
        "SMARTHOST_TLS_VERIFY": tls_verify,
        "TLS_VERIFY": tls_verify,
    }
    lines: list[str] = []
    for k, v in sorted(pairs.items()):
        sanitized = "".join(c for c in v if c not in _FORBIDDEN_SECRET_CHARS)
        formatted = _format_env_value(sanitized)
        lines.append(f"{k}={formatted}")
    target = sdir / "smarthost.env"
    atomic_write_text(target, "\n".join(lines), mode=0o600)
    return target
