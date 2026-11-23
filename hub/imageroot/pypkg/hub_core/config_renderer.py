"""Deterministic pure-stdlib configuration renderer for Prometheus, Loki, Grafana, and defaults."""

from __future__ import annotations

import socket
from pathlib import Path

from hub_core import (
    atomic_write_text,
    resolve_config_dir,
    resolve_etc_dir,
    resolve_shared_dir,
    resolve_state_dir,
    yaml_quote,
)
from hub_core.backup_state import update_state_include
from hub_core.env_store import ensure_initial_secrets, read_module_env, read_secrets
from hub_core.storage_s3 import render_loki_storage_blocks, write_thanos_objstore_file


def render_prometheus_yaml(
    module_id: str,
    *,
    monitor_local_ns8_node: bool = True,
    local_node_customer: str = "_msp_internal",
    local_node_site: str = "hub",
    node_instance: str = "",
) -> str:
    """Render /etc/prometheus/prometheus.yml supporting Remote Write, file_sd, Thanos, and Hub self-monitoring."""
    resolved_instance = (node_instance or "").strip() or module_id
    lines = [
        "global:",
        "  scrape_interval: 30s",
        "  evaluation_interval: 30s",
        "  external_labels:",
        f"    cluster: {yaml_quote(module_id)}",
        '    prometheus_replica: "0"',
        "",
        "alerting:",
        "  alertmanagers:",
        "    - static_configs:",
        '        - targets: ["127.0.0.1:9093"]',
        "",
        "rule_files:",
        '  - "/etc/prometheus/rules/*.yml"',
        '  - "/etc/prometheus/custom-rules/*.yml"',
        "",
        "scrape_config_files:",
        '  - "/etc/prometheus/federation_jobs.yml"',
        "",
        "scrape_configs:",
        "  - job_name: hub-prometheus",
        "    static_configs:",
        '      - targets: ["127.0.0.1:9090"]',
        "        labels:",
        '          customer: "_msp_internal"',
        '          site: "hub"',
        '          device_role: "ns8"',
        '          collector_id: "hub-central"',
        "",
    ]

    if monitor_local_ns8_node:
        lines.extend(
            [
                "  - job_name: hub-ns8-node",
                "    metrics_path: /metrics/ns8-node",
                "    static_configs:",
                '      - targets: ["127.0.0.1:9097"]',
                "        labels:",
                f"          customer: {yaml_quote(local_node_customer or '_msp_internal')}",
                f"          site: {yaml_quote(local_node_site or 'hub')}",
                f"          instance: {yaml_quote(resolved_instance)}",
                '          device_role: "ns8"',
                '          collector_id: "hub-local"',
                "",
            ]
        )

    lines.extend(
        [
            "  - job_name: central-exporters",
            "    file_sd_configs:",
            "      - files:",
            '          - "/etc/prometheus/file_sd/exporters/*.json"',
            "        refresh_interval: 30s",
            "",
            "  - job_name: central-blackbox",
            "    metrics_path: /probe",
            "    file_sd_configs:",
            "      - files:",
            '          - "/etc/prometheus/file_sd/blackbox/*.json"',
            "        refresh_interval: 30s",
            "    relabel_configs:",
            "      - source_labels: [blackbox_module]",
            "        regex: (.+)",
            "        target_label: __param_module",
            "      - source_labels: [__address__]",
            "        target_label: __param_target",
            "      - source_labels: [__param_target]",
            "        target_label: instance",
            "      - target_label: __address__",
            "        replacement: 127.0.0.1:9115",
            "",
            "  - job_name: central-snmp",
            "    metrics_path: /snmp",
            "    file_sd_configs:",
            "      - files:",
            '          - "/etc/prometheus/file_sd/snmp/*.json"',
            "        refresh_interval: 30s",
            "    relabel_configs:",
            "      - source_labels: [snmp_module]",
            "        regex: (.+)",
            "        target_label: __param_module",
            "      - source_labels: [snmp_auth]",
            "        regex: (.+)",
            "        target_label: __param_auth",
            "      - source_labels: [__address__]",
            "        target_label: __param_target",
            "      - source_labels: [__param_target]",
            "        target_label: instance",
            "      - target_label: __address__",
            "        replacement: 127.0.0.1:9116",
        ]
    )
    return "\n".join(lines) + "\n"


def render_loki_yaml(
    *,
    storage_mode: str,
    loki_retention_days: int,
    s3_endpoint: str = "",
    s3_bucket: str = "",
    s3_region: str = "us-east-1",
    s3_access_key: str = "",
    s3_secret_key: str = "",
    s3_insecure: bool = False,
    s3_path_style: bool = True,
) -> str:
    """Render multi-tenant Loki 3.1 TSDB v13 configuration for local or S3 storage."""
    retention_hours = max(24, int(loki_retention_days) * 24)
    object_store, storage_block, delete_store = render_loki_storage_blocks(
        storage_mode=storage_mode,
        endpoint=s3_endpoint,
        bucket=s3_bucket,
        region=s3_region,
        access_key=s3_access_key,
        secret_key=s3_secret_key,
        insecure=s3_insecure,
        path_style=s3_path_style,
    )
    lines = [
        "auth_enabled: true",
        "",
        "server:",
        "  http_listen_address: 127.0.0.1",
        "  http_listen_port: 3100",
        "  grpc_listen_address: 127.0.0.1",
        "  grpc_listen_port: 9096",
        "",
        "common:",
        "  path_prefix: /var/lib/loki",
        "  replication_factor: 1",
        "  ring:",
        "    instance_addr: 127.0.0.1",
        "    kvstore:",
        "      store: inmemory",
        "",
        "querier:",
        "  multi_tenant_queries_enabled: true",
        "",
        "schema_config:",
        "  configs:",
        '    - from: "2024-01-01"',
        "      store: tsdb",
        f"      object_store: {object_store}",
        "      schema: v13",
        "      index:",
        "        prefix: index_",
        "        period: 24h",
        "",
        storage_block,
        "",
        "compactor:",
        "  working_directory: /var/lib/loki/compactor",
        "  compaction_interval: 10m",
        "  retention_enabled: true",
        "  retention_delete_delay: 2h",
        "  retention_delete_worker_count: 150",
        f"  delete_request_store: {delete_store}",
        "",
        "limits_config:",
        f"  retention_period: {retention_hours}h",
        "  reject_old_samples: true",
        "  reject_old_samples_max_age: 168h",
    ]
    return "\n".join(lines) + "\n"


def _format_ini_value(raw: str, *, force_triple_quote: bool = False) -> str:
    """Strip control/line-separator chars and quote INI values containing ; # or quotes."""
    cleaned = "".join(
        ch
        for ch in raw
        if ch not in ("\r", "\n", "\x00", "\u2028", "\u2029") and ord(ch) >= 0x20 and ord(ch) != 0x7F
    )
    needs_quote = (
        force_triple_quote
        or cleaned != cleaned.strip()
        or any(ch in cleaned for ch in (";", "#", '"', "'", "`", "\\", "[", "]"))
    )
    if needs_quote:
        escaped = cleaned.replace('"""', '\\"\\"\\"')
        return f'"""{escaped}"""'
    return cleaned


def render_grafana_ini(*, host: str, ldap_enabled: bool, secret_key: str) -> str:
    """Render hardened Grafana OSS grafana.ini bound to 127.0.0.1:3000 inside pod."""
    clean_host = "".join(
        ch
        for ch in host.strip().lower()
        if ch not in ("\r", "\n", "\x00", "\u2028", "\u2029") and ord(ch) >= 0x20 and ord(ch) != 0x7F
    ) or "localhost"
    domain_ini = _format_ini_value(clean_host)
    root_url_ini = _format_ini_value(f"https://{clean_host}/")
    secret_ini = _format_ini_value(secret_key, force_triple_quote=True)
    ldap_flag = "true" if ldap_enabled else "false"
    lines = [
        "[paths]",
        "data = /var/lib/grafana",
        "provisioning = /etc/grafana/provisioning",
        "",
        "[server]",
        "protocol = http",
        "http_addr = 127.0.0.1",
        "http_port = 3000",
        f"domain = {domain_ini}",
        f"root_url = {root_url_ini}",
        "serve_from_sub_path = false",
        "",
        "[database]",
        "type = sqlite3",
        "path = /var/lib/grafana/grafana.db",
        "wal = true",
        "",
        "[security]",
        "admin_user = admin",
        f"secret_key = {secret_ini}",
        "cookie_secure = true",
        "cookie_samesite = lax",
        "allow_embedding = false",
        "disable_gravatar = true",
        "",
        "[users]",
        "allow_sign_up = false",
        "allow_org_create = false",
        "auto_assign_org = true",
        "auto_assign_org_id = 1",
        "auto_assign_org_role = Viewer",
        "",
        "[auth.anonymous]",
        "enabled = false",
        "",
        "[auth.ldap]",
        f"enabled = {ldap_flag}",
        "config_file = /etc/grafana/ldap.toml",
        "allow_sign_up = true",
        "skip_org_role_sync = false",
        "",
        "[alerting]",
        "enabled = false",
        "",
        "[unified_alerting]",
        "enabled = false",
        "",
        "[analytics]",
        "reporting_enabled = false",
        "check_for_updates = false",
    ]
    return "\n".join(lines) + "\n"


def _ensure_bootstrap_auxiliary_configs(config_dir: Path, shared_dir: Path) -> None:
    """Ensure initial valid Alertmanager, Blackbox, SNMP, Federation, Rules, and Dashboards exist."""
    for sub in ("exporters", "blackbox", "snmp"):
        (config_dir / "prometheus" / "file_sd" / sub).mkdir(parents=True, exist_ok=True)
    (config_dir / "custom-rules").mkdir(parents=True, exist_ok=True)

    fed_file = config_dir / "prometheus" / "federation_jobs.yml"
    if not fed_file.exists():
        atomic_write_text(fed_file, "scrape_configs: []\n", mode=0o600)

    # Sync shared rule packs into available-rules/ and populate initial rules/ if empty
    avail_rules_dir = config_dir / "prometheus" / "available-rules"
    active_rules_dir = config_dir / "prometheus" / "rules"
    avail_rules_dir.mkdir(parents=True, exist_ok=True)
    active_rules_dir.mkdir(parents=True, exist_ok=True)

    src_rules_dir = shared_dir / "rules"
    if src_rules_dir.is_dir():
        existing_active = list(active_rules_dir.glob("*.yml"))
        for rule_file in sorted(src_rules_dir.glob("*.yml")):
            rule_text = rule_file.read_text(encoding="utf-8")
            atomic_write_text(
                avail_rules_dir / rule_file.name,
                rule_text,
                mode=0o644,
            )
            if not existing_active or (active_rules_dir / rule_file.name).is_file():
                atomic_write_text(
                    active_rules_dir / rule_file.name,
                    rule_text,
                    mode=0o644,
                )

    # Copy all starter dashboards & provisioning descriptor atomically
    dashboards_dst = config_dir / "grafana" / "dashboards"
    dashboards_dst.mkdir(parents=True, exist_ok=True)
    src_dashboards = shared_dir / "dashboards"
    if src_dashboards.is_dir():
        for dash_file in sorted(src_dashboards.glob("*.json")):
            atomic_write_text(
                dashboards_dst / dash_file.name,
                dash_file.read_text(encoding="utf-8"),
                mode=0o644,
            )

    dash_prov = config_dir / "grafana" / "provisioning" / "dashboards" / "starter-dashboards.yaml"
    atomic_write_text(
        dash_prov,
        "\n".join(
            [
                "apiVersion: 1",
                "providers:",
                "  - name: msp-starter-dashboards",
                "    orgId: 1",
                '    folder: "MSP Central Monitoring"',
                "    type: file",
                "    disableDeletion: false",
                "    allowUiUpdates: true",
                "    updateIntervalSeconds: 60",
                "    options:",
                "      path: /etc/grafana/dashboards",
            ]
        ),
        mode=0o644,
    )
    (config_dir / "grafana" / "provisioning" / "datasources").mkdir(parents=True, exist_ok=True)

    ldap_toml = config_dir / "grafana" / "ldap.toml"
    if not ldap_toml.exists():
        atomic_write_text(ldap_toml, "# Managed by central-monitoring-hub ldap_sync\n", mode=0o600)

    am_cfg = config_dir / "alertmanager" / "alertmanager.yml"
    (config_dir / "alertmanager" / "templates").mkdir(parents=True, exist_ok=True)
    if not am_cfg.exists():
        atomic_write_text(
            am_cfg,
            "\n".join(
                [
                    "route:",
                    "  group_by: ['customer', 'site', 'alertname']",
                    "  group_wait: 30s",
                    "  group_interval: 5m",
                    "  repeat_interval: 4h",
                    "  receiver: default-null",
                    "receivers:",
                    "  - name: default-null",
                ]
            ),
            mode=0o600,
        )

    bb_cfg = config_dir / "blackbox" / "blackbox.yml"
    if not bb_cfg.exists():
        try:
            from hub_alerting.blackbox_config import render_blackbox_yaml

            atomic_write_text(bb_cfg, render_blackbox_yaml(), mode=0o644)
        except ImportError:
            atomic_write_text(
                bb_cfg,
                "\n".join(
                    [
                        "modules:",
                        "  http_2xx:",
                        "    prober: http",
                        "    timeout: 10s",
                        "    http:",
                        '      preferred_ip_protocol: "ip4"',
                        "      ip_protocol_fallback: true",
                        "      follow_redirects: false",
                        "  http_2xx_insecure:",
                        "    prober: http",
                        "    timeout: 10s",
                        "    http:",
                        '      preferred_ip_protocol: "ip4"',
                        "      ip_protocol_fallback: true",
                        "      follow_redirects: false",
                        "      tls_config:",
                        "        insecure_skip_verify: true",
                        "  http_post_2xx:",
                        "    prober: http",
                        "    timeout: 10s",
                        "    http:",
                        "      method: POST",
                        '      preferred_ip_protocol: "ip4"',
                        "      ip_protocol_fallback: true",
                        "      follow_redirects: false",
                        "  http_post_2xx_insecure:",
                        "    prober: http",
                        "    timeout: 10s",
                        "    http:",
                        "      method: POST",
                        '      preferred_ip_protocol: "ip4"',
                        "      ip_protocol_fallback: true",
                        "      follow_redirects: false",
                        "      tls_config:",
                        "        insecure_skip_verify: true",
                        "  tcp_connect:",
                        "    prober: tcp",
                        "    timeout: 5s",
                        "  dns_tcp:",
                        "    prober: dns",
                        "    timeout: 5s",
                        "    dns:",
                        '      transport_protocol: "tcp"',
                        '      query_name: "nethserver.org"',
                        '      query_type: "A"',
                        "  dns_udp:",
                        "    prober: dns",
                        "    timeout: 5s",
                        "    dns:",
                        '      transport_protocol: "udp"',
                        '      query_name: "nethserver.org"',
                        '      query_type: "A"',
                        "  icmp:",
                        "    prober: icmp",
                        "    timeout: 5s",
                        "    icmp:",
                        '      preferred_ip_protocol: "ip4"',
                        "      ip_protocol_fallback: true",
                    ]
                ),
                mode=0o644,
            )

    snmp_cfg = config_dir / "snmp" / "snmp.yml"
    if not snmp_cfg.exists():
        atomic_write_text(snmp_cfg, "auths: {}\nmodules: {}\n", mode=0o600)


def render_all_configs(state_dir: str | Path | None = None) -> dict[str, Path]:
    """Render all core configuration files atomically for the current environment."""
    sdir = resolve_state_dir(state_dir)
    cdir = resolve_config_dir(sdir)
    edir = resolve_etc_dir(sdir)
    shared_dir = resolve_shared_dir(sdir)

    ensure_initial_secrets(sdir)
    env = read_module_env(sdir)
    secrets_map = read_secrets(sdir)

    module_id = env.get("MODULE_ID", "central-monitoring-hub1")
    host = env.get("TRAEFIK_HOST", "")
    storage_mode = env.get("STORAGE_MODE", "local")
    loki_retention_days = int(env.get("LOKI_RETENTION_DAYS", "30") or "30")
    backup_include_tsdb = env.get("BACKUP_INCLUDE_TSDB", "false").lower() == "true"
    ldap_enabled = env.get("LDAP_ENABLED", "false").lower() == "true"

    s3_endpoint = env.get("S3_ENDPOINT", "")
    s3_bucket = env.get("S3_BUCKET", "")
    s3_region = env.get("S3_REGION", "us-east-1")
    s3_access_key = env.get("S3_ACCESS_KEY", "")
    s3_secret_key = secrets_map.get("S3_SECRET_KEY", "")
    s3_insecure = env.get("S3_INSECURE", "false").lower() == "true"
    s3_path_style = env.get("S3_PATH_STYLE", "true").lower() == "true"

    monitor_local_ns8_node = env.get("MONITOR_LOCAL_NS8_NODE", "true").lower() == "true"
    local_node_customer = env.get("LOCAL_NODE_CUSTOMER", "_msp_internal") or "_msp_internal"
    local_node_site = env.get("LOCAL_NODE_SITE", "hub") or "hub"
    raw_hostname = socket.gethostname().strip()
    node_instance = (
        env.get("NODE_HOSTNAME", "").strip()
        or host.strip()
        or (raw_hostname if raw_hostname and raw_hostname != "localhost" else module_id)
    )

    prom_path = cdir / "prometheus" / "prometheus.yml"
    atomic_write_text(
        prom_path,
        render_prometheus_yaml(
            module_id,
            monitor_local_ns8_node=monitor_local_ns8_node,
            local_node_customer=local_node_customer,
            local_node_site=local_node_site,
            node_instance=node_instance,
        ),
        mode=0o640,
    )

    loki_path = cdir / "loki" / "loki.yaml"
    atomic_write_text(
        loki_path,
        render_loki_yaml(
            storage_mode=storage_mode,
            loki_retention_days=loki_retention_days,
            s3_endpoint=s3_endpoint,
            s3_bucket=s3_bucket,
            s3_region=s3_region,
            s3_access_key=s3_access_key,
            s3_secret_key=s3_secret_key,
            s3_insecure=s3_insecure,
            s3_path_style=s3_path_style,
        ),
        mode=0o600,
    )

    grafana_path = cdir / "grafana" / "grafana.ini"
    atomic_write_text(
        grafana_path,
        render_grafana_ini(
            host=host,
            ldap_enabled=ldap_enabled,
            secret_key=secrets_map["GRAFANA_SECRET_KEY"],
        ),
        mode=0o600,
    )

    written: dict[str, Path] = {
        "prometheus": prom_path,
        "loki": loki_path,
        "grafana": grafana_path,
    }

    if storage_mode == "s3":
        written["thanos_objstore"] = write_thanos_objstore_file(
            cdir,
            endpoint=s3_endpoint,
            bucket=s3_bucket,
            region=s3_region,
            access_key=s3_access_key,
            secret_key=s3_secret_key,
            insecure=s3_insecure,
            path_style=s3_path_style,
        )

    _ensure_bootstrap_auxiliary_configs(cdir, shared_dir)
    written["state_include"] = update_state_include(edir, backup_include_tsdb=backup_include_tsdb)
    return written
