"""Alertmanager v0.27 Multi-Channel & Per-Customer Routing Configurer + Test Alert Dispatcher."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Final

from hub_alerting import (
    ValidationFailure,
    atomic_write_json,
    atomic_write_text,
    file_lock,
    load_json_file,
    load_tenants_map,
    pod_http_request,
    resolve_config_dir,
    resolve_state_dir,
    trigger_http_reload,
    yaml_quote,
)
from hub_alerting.blackbox_config import render_blackbox_config
from hub_alerting.rules_manager import DEFAULT_ENABLED_RULE_PACKS, get_rule_packs_status, sync_rule_packs
from hub_alerting.ssrf_guard import SSRFValidationError, assert_not_internal_pod_endpoint, validate_webhook_url
from hub_alerting.targets_manager import sync_target_configs

INTERNAL_NTFY_RELAY_URL = "http://127.0.0.1:9097/alert-relay/ntfy"
INTERNAL_GOTIFY_RELAY_URL = "http://127.0.0.1:9097/alert-relay/gotify"
_NTFY_TOPIC_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._-]{1,128}\Z")


def _alertmanager_base_url() -> str:
    return os.environ.get("ALERTMANAGER_URL", "http://127.0.0.1:9093").rstrip("/")


def _default_alerting_config() -> dict[str, Any]:
    return {
        "group_wait": "30s",
        "group_interval": "5m",
        "repeat_interval": "4h",
        "smarthost_email": {
            "enabled": False,
            "use_ns8_smarthost": True,
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_user": "",
            "smtp_tls": True,
            "from_address": "",
            "default_to_addresses": [],
            "send_resolved": True,
        },
        "webhook_psa": {
            "enabled": False,
            "url": "",
            "send_resolved": True,
        },
        "chat": {
            "teams_enabled": False,
            "slack_enabled": False,
            "slack_channel": "",
            "send_resolved": True,
        },
        "push": {
            "enabled": False,
            "provider": "none",
            "min_severity": "critical",
            "ntfy_url": "https://ntfy.sh",
            "ntfy_topic": "",
            "telegram_chat_id": "",
            "gotify_url": "",
        },
        "customer_email_routing": {
            "enabled": False,
            "min_severity": "critical",
            "send_resolved": True,
        },
        "enabled_rule_packs": list(DEFAULT_ENABLED_RULE_PACKS),
    }


def _default_alerting_secrets() -> dict[str, Any]:
    return {
        "smtp_password": "",
        "webhook_auth_secret": "",
        "teams_webhook_url": "",
        "slack_webhook_url": "",
        "ntfy_token": "",
        "telegram_bot_token": "",
        "gotify_token": "",
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "",
        "gotify_url": "",
        "ntfy": {"url": "https://ntfy.sh", "topic": "", "token": ""},
        "gotify": {"url": "", "token": ""},
    }


def discover_smarthost_env(state_dir: str | Path | None = None) -> dict[str, Any]:
    """Read NS8 state/smarthost.env and resolve Podman-reachable smarthost host:port."""
    sdir = resolve_state_dir(state_dir)
    env_file = sdir / "smarthost.env"
    values: dict[str, str] = {}
    if env_file.is_file():
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            values[key.strip().upper()] = val.strip().strip('"').strip("'")

    enabled_flag = values.get("SMARTHOST_ENABLED", values.get("ENABLED", ""))
    raw_host = values.get("SMARTHOST_HOST", values.get("HOST", "")).strip()
    raw_port = values.get("SMARTHOST_PORT", values.get("PORT", "25")).strip() or "25"
    username = values.get("SMARTHOST_USER", values.get("SMARTHOST_USERNAME", values.get("USERNAME", "")))
    password = values.get("SMARTHOST_PASSWORD", values.get("PASSWORD", ""))
    tls_raw = (
        values.get("SMARTHOST_ENCRYPT_SMTP")
        or values.get("ENCRYPT_SMTP")
        or values.get("SMARTHOST_TLS")
        or values.get("SMARTHOST_ENCRYPT")
        or values.get("TLS")
        or "0"
    ).lower()
    require_tls = tls_raw in {"1", "true", "yes", "starttls", "tls", "ssl"}

    available = bool(raw_host) and enabled_flag.lower() not in {"0", "false", "no"}
    if not available:
        return {
            "available": False,
            "smarthost": "",
            "username": "",
            "password": "",
            "require_tls": False,
        }

    effective_host = "10.0.2.2" if raw_host.lower() in {"127.0.0.1", "localhost", "::1"} else raw_host
    try:
        port_num = int(raw_port)
    except ValueError:
        port_num = 25

    return {
        "available": True,
        "smarthost": f"{effective_host}:{port_num}",
        "username": username,
        "password": password,
        "require_tls": require_tls,
    }


def _resolve_smtp_transport(
    cfg: dict[str, Any],
    secrets: dict[str, Any],
    smarthost_info: dict[str, Any],
) -> dict[str, Any] | None:
    email_cfg = cfg.get("smarthost_email") or {}
    from_addr = str(email_cfg.get("from_address") or "").strip()
    if not from_addr:
        from_addr = "monitoring@localhost"

    if email_cfg.get("use_ns8_smarthost", True):
        sh_addr = smarthost_info["smarthost"] if smarthost_info["available"] else "10.0.2.2:25"
        return {
            "smarthost": sh_addr,
            "from": from_addr,
            "username": str(smarthost_info.get("username") or ""),
            "password": str(smarthost_info.get("password") or ""),
            "require_tls": bool(smarthost_info.get("require_tls", False)),
        }

    host = str(email_cfg.get("smtp_host") or "").strip()
    port = int(email_cfg.get("smtp_port") or 587)
    if not host:
        return None
    return {
        "smarthost": f"{host}:{port}",
        "from": from_addr,
        "username": str(email_cfg.get("smtp_user") or ""),
        "password": str(secrets.get("smtp_password") or ""),
        "require_tls": bool(email_cfg.get("smtp_tls", True)),
    }


def _severity_matcher(min_severity: str) -> str:
    if min_severity == "warning":
        return 'severity=~"warning|critical"'
    return 'severity="critical"'


def render_alertmanager_yaml(
    cfg: dict[str, Any],
    secrets: dict[str, Any],
    smarthost_info: dict[str, Any],
    tenants_map: dict[str, dict[str, Any]],
) -> str:
    """Render deterministic Alertmanager v0.27 YAML without external PyYAML dependency."""
    group_wait = str(cfg.get("group_wait") or "30s")
    group_interval = str(cfg.get("group_interval") or "5m")
    repeat_interval = str(cfg.get("repeat_interval") or "4h")

    email_cfg = cfg.get("smarthost_email") or {}
    psa_cfg = cfg.get("webhook_psa") or {}
    chat_cfg = cfg.get("chat") or {}
    push_cfg = cfg.get("push") or {}
    cust_cfg = cfg.get("customer_email_routing") or {}

    smtp_transport = _resolve_smtp_transport(cfg, secrets, smarthost_info)
    email_to_list = [str(e).strip() for e in (email_cfg.get("default_to_addresses") or []) if str(e).strip()]
    has_msp_email = bool(email_cfg.get("enabled") and smtp_transport and email_to_list)

    psa_url = str(psa_cfg.get("url") or "").strip()
    has_psa = bool(psa_cfg.get("enabled") and psa_url)

    teams_url = str(secrets.get("teams_webhook_url") or "").strip()
    has_teams = bool(chat_cfg.get("teams_enabled") and teams_url)

    slack_url = str(secrets.get("slack_webhook_url") or "").strip()
    has_slack = bool(chat_cfg.get("slack_enabled") and slack_url)

    push_provider = str(push_cfg.get("provider") or "none")
    has_push = False
    if push_cfg.get("enabled") and push_provider in {"ntfy", "telegram", "gotify"}:
        if push_provider == "telegram":
            has_push = bool(secrets.get("telegram_bot_token") and push_cfg.get("telegram_chat_id"))
        elif push_provider == "ntfy":
            has_push = bool(push_cfg.get("ntfy_url") and push_cfg.get("ntfy_topic"))
        elif push_provider == "gotify":
            has_push = bool(push_cfg.get("gotify_url") and secrets.get("gotify_token"))

    customer_routes: list[tuple[str, list[str]]] = []
    if cust_cfg.get("enabled") and smtp_transport:
        for slug in sorted(tenants_map.keys()):
            emails = [
                str(addr).strip()
                for addr in (tenants_map[slug].get("contact_emails") or [])
                if str(addr).strip()
            ]
            if emails:
                customer_routes.append((slug, emails))

    lines: list[str] = [
        "# Generated by central-monitoring-hub (hub_alerting.alertmanager_config)",
        "global:",
        "  resolve_timeout: 5m",
        "",
        "route:",
        '  receiver: "null-sink"',
        '  group_by: ["customer", "site", "alertname"]',
        f"  group_wait: {group_wait}",
        f"  group_interval: {group_interval}",
        f"  repeat_interval: {repeat_interval}",
        "  routes:",
    ]

    route_entries: list[list[str]] = []

    # 1. Targeted single-channel test routes (continue: false)
    if has_msp_email:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"smarthost_email\\""]',
                '      receiver: "msp-smarthost-email"',
                "      continue: false",
            ]
        )
    if has_psa:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"webhook_psa\\""]',
                '      receiver: "msp-webhook-psa"',
                "      continue: false",
            ]
        )
    if has_teams:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"teams\\""]',
                '      receiver: "msp-chat-teams"',
                "      continue: false",
            ]
        )
    if has_slack:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"slack\\""]',
                '      receiver: "msp-chat-slack"',
                "      continue: false",
            ]
        )
    if has_push:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"push\\""]',
                '      receiver: "msp-push"',
                "      continue: false",
            ]
        )
    for slug, _ in customer_routes:
        route_entries.append(
            [
                "    - matchers:",
                '        - "test_channel=\\"customer_email\\""',
                f"        - {yaml_quote(f'customer=\"{slug}\"')}",
                f"      receiver: {yaml_quote(f'customer-email-{slug}')}",
                "      continue: false",
            ]
        )

    # 2. Normal production fan-out routes (continue: true)
    if has_msp_email:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"\\""]',
                '      receiver: "msp-smarthost-email"',
                "      continue: true",
            ]
        )
    if has_psa:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"\\""]',
                '      receiver: "msp-webhook-psa"',
                "      continue: true",
            ]
        )
    if has_teams:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"\\""]',
                '      receiver: "msp-chat-teams"',
                "      continue: true",
            ]
        )
    if has_slack:
        route_entries.append(
            [
                '    - matchers: ["test_channel=\\"\\""]',
                '      receiver: "msp-chat-slack"',
                "      continue: true",
            ]
        )
    if has_push:
        push_sev = _severity_matcher(str(push_cfg.get("min_severity") or "critical"))
        route_entries.append(
            [
                "    - matchers:",
                '        - "test_channel=\\"\\""',
                f"        - {yaml_quote(push_sev)}",
                '      receiver: "msp-push"',
                "      continue: true",
            ]
        )
    cust_sev = _severity_matcher(str(cust_cfg.get("min_severity") or "critical"))
    for slug, _ in customer_routes:
        route_entries.append(
            [
                "    - matchers:",
                '        - "test_channel=\\"\\""',
                f"        - {yaml_quote(f'customer=\"{slug}\"')}",
                f"        - {yaml_quote(cust_sev)}",
                f"      receiver: {yaml_quote(f'customer-email-{slug}')}",
                "      continue: true",
            ]
        )

    if not route_entries:
        lines[-1] = "  routes: []"
    else:
        for block in route_entries:
            lines.extend(block)

    lines.extend(
        [
            "",
            "inhibit_rules:",
            "  - source_matchers:",
            '      - "severity=\\"critical\\""',
            "    target_matchers:",
            '      - "severity=\\"warning\\""',
            '    equal: ["customer", "site", "instance", "category"]',
            "",
            "receivers:",
            '  - name: "null-sink"',
        ]
    )

    if has_msp_email and smtp_transport is not None:
        lines.extend(
            _render_email_receiver(
                "msp-smarthost-email",
                to_addresses=email_to_list,
                smtp_transport=smtp_transport,
                send_resolved=bool(email_cfg.get("send_resolved", True)),
            )
        )

    if has_psa:
        psa_resolved = "true" if psa_cfg.get("send_resolved", True) else "false"
        lines.extend(
            [
                '  - name: "msp-webhook-psa"',
                "    webhook_configs:",
                f"      - url: {yaml_quote(psa_url)}",
                f"        send_resolved: {psa_resolved}",
            ]
        )
        auth_sec = str(secrets.get("webhook_auth_secret") or "")
        if auth_sec:
            lines.extend(
                [
                    "        http_config:",
                    "          authorization:",
                    '            type: "Bearer"',
                    f"            credentials: {yaml_quote(auth_sec)}",
                ]
            )

    chat_resolved = "true" if chat_cfg.get("send_resolved", True) else "false"
    if has_teams:
        lines.extend(
            [
                '  - name: "msp-chat-teams"',
                "    msteams_configs:",
                f"      - webhook_url: {yaml_quote(teams_url)}",
                f"        send_resolved: {chat_resolved}",
            ]
        )

    if has_slack:
        lines.extend(
            [
                '  - name: "msp-chat-slack"',
                "    slack_configs:",
                f"      - api_url: {yaml_quote(slack_url)}",
                f"        send_resolved: {chat_resolved}",
            ]
        )
        slack_chan = str(chat_cfg.get("slack_channel") or "").strip()
        if slack_chan:
            lines.append(f"        channel: {yaml_quote(slack_chan)}")

    if has_push:
        lines.append('  - name: "msp-push"')
        if push_provider == "telegram":
            bot_tok = str(secrets.get("telegram_bot_token") or "")
            raw_chat_id = str(push_cfg.get("telegram_chat_id") or "").strip()
            try:
                chat_id_literal = str(int(raw_chat_id))
            except ValueError:
                chat_id_literal = yaml_quote(raw_chat_id)
            lines.extend(
                [
                    "    telegram_configs:",
                    f"      - bot_token: {yaml_quote(bot_tok)}",
                    f"        chat_id: {chat_id_literal}",
                    "        send_resolved: true",
                ]
            )
        elif push_provider == "ntfy":
            lines.extend(
                [
                    "    webhook_configs:",
                    f"      - url: {yaml_quote(INTERNAL_NTFY_RELAY_URL)}",
                    "        send_resolved: true",
                ]
            )
        elif push_provider == "gotify":
            lines.extend(
                [
                    "    webhook_configs:",
                    f"      - url: {yaml_quote(INTERNAL_GOTIFY_RELAY_URL)}",
                    "        send_resolved: true",
                ]
            )

    cust_resolved = bool(cust_cfg.get("send_resolved", True))
    if smtp_transport is not None:
        for slug, emails in customer_routes:
            lines.extend(
                _render_email_receiver(
                    f"customer-email-{slug}",
                    to_addresses=emails,
                    smtp_transport=smtp_transport,
                    send_resolved=cust_resolved,
                )
            )

    return "\n".join(lines) + "\n"


def _render_email_receiver(
    name: str,
    *,
    to_addresses: list[str],
    smtp_transport: dict[str, Any],
    send_resolved: bool,
) -> list[str]:
    to_joined = ", ".join(to_addresses)
    req_tls = "true" if smtp_transport["require_tls"] else "false"
    resolved_str = "true" if send_resolved else "false"
    block = [
        f"  - name: {yaml_quote(name)}",
        "    email_configs:",
        f"      - to: {yaml_quote(to_joined)}",
        f"        from: {yaml_quote(smtp_transport['from'])}",
        f"        smarthost: {yaml_quote(smtp_transport['smarthost'])}",
        f"        require_tls: {req_tls}",
        f"        send_resolved: {resolved_str}",
    ]
    if smtp_transport.get("username"):
        block.append(f"        auth_username: {yaml_quote(smtp_transport['username'])}")
    if smtp_transport.get("password"):
        block.append(f"        auth_password: {yaml_quote(smtp_transport['password'])}")
    return block


def sync_alertmanager(state_dir: str | Path | None = None) -> bool:
    """Re-render alertmanager.yml (and ensure baseline probe/rule configs exist) then reload Alertmanager.

    Safe cross-module hook invoked by hub_core (configure-module / smarthost-changed)
    and hub_tenancy (save-tenant / delete-tenant when contact_emails change).
    """
    sdir = resolve_state_dir(state_dir)
    cdir = resolve_config_dir(sdir)

    with file_lock(sdir / ".alerting.lock"):
        cfg = {**_default_alerting_config(), **load_json_file(sdir / "alerting.json", {})}
        secrets = {**_default_alerting_secrets(), **load_json_file(sdir / "alerting-secrets.json", {})}
        smarthost_info = discover_smarthost_env(sdir)
        tenants_map = load_tenants_map(sdir)

        # Keep relay metadata mirrored inside state/alerting-secrets.json (0600)
        push_cfg = cfg.get("push") or {}
        ntfy_url = str(push_cfg.get("ntfy_url") or "https://ntfy.sh")
        ntfy_topic = str(push_cfg.get("ntfy_topic") or "")
        gotify_url = str(push_cfg.get("gotify_url") or "")
        secrets["ntfy_url"] = ntfy_url
        secrets["ntfy_topic"] = ntfy_topic
        secrets["gotify_url"] = gotify_url
        secrets["ntfy"] = {
            "url": ntfy_url,
            "topic": ntfy_topic,
            "token": str(secrets.get("ntfy_token") or ""),
        }
        secrets["gotify"] = {
            "url": gotify_url,
            "token": str(secrets.get("gotify_token") or ""),
        }
        atomic_write_json(sdir / "alerting-secrets.json", secrets, mode=0o600)

        rendered_am = render_alertmanager_yaml(cfg, secrets, smarthost_info, tenants_map)
        atomic_write_text(cdir / "alertmanager" / "alertmanager.yml", rendered_am, mode=0o600)

    # Ensure baseline probe & rule configs exist on first-boot configure-module
    if not (cdir / "blackbox" / "blackbox.yml").is_file():
        render_blackbox_config(cdir / "blackbox" / "blackbox.yml", state_dir=sdir)
    if not (cdir / "snmp" / "snmp.yml").is_file() or not (cdir / "prometheus" / "federation_jobs.yml").is_file():
        targets_store = load_json_file(sdir / "targets.json", {"targets": []})
        sync_target_configs(list(targets_store.get("targets", [])), state_dir=sdir)
    if not (cdir / "prometheus" / "rules").is_dir():
        sync_rule_packs(cfg.get("enabled_rule_packs"), state_dir=sdir, reload_prometheus=False)

    return trigger_http_reload(f"{_alertmanager_base_url()}/-/reload")


def get_alerting(state_dir: str | Path | None = None) -> dict[str, Any]:
    """Return Alertmanager & rule-pack configuration with all secrets redacted."""
    sdir = resolve_state_dir(state_dir)
    cfg = {**_default_alerting_config(), **load_json_file(sdir / "alerting.json", {})}
    secrets = {**_default_alerting_secrets(), **load_json_file(sdir / "alerting-secrets.json", {})}
    smarthost_info = discover_smarthost_env(sdir)

    email_cfg = {**_default_alerting_config()["smarthost_email"], **(cfg.get("smarthost_email") or {})}
    psa_cfg = {**_default_alerting_config()["webhook_psa"], **(cfg.get("webhook_psa") or {})}
    chat_cfg = {**_default_alerting_config()["chat"], **(cfg.get("chat") or {})}
    push_cfg = {**_default_alerting_config()["push"], **(cfg.get("push") or {})}
    cust_cfg = {**_default_alerting_config()["customer_email_routing"], **(cfg.get("customer_email_routing") or {})}

    enabled_packs = cfg.get("enabled_rule_packs")
    rule_packs = get_rule_packs_status(enabled_packs, state_dir=sdir)

    return {
        "group_wait": str(cfg.get("group_wait") or "30s"),
        "group_interval": str(cfg.get("group_interval") or "5m"),
        "repeat_interval": str(cfg.get("repeat_interval") or "4h"),
        "ns8_smarthost_available": bool(smarthost_info["available"]),
        "ns8_smarthost_host": str(smarthost_info["smarthost"]),
        "smarthost_email": {
            "enabled": bool(email_cfg["enabled"]),
            "use_ns8_smarthost": bool(email_cfg["use_ns8_smarthost"]),
            "smtp_host": str(email_cfg["smtp_host"]),
            "smtp_port": int(email_cfg["smtp_port"]),
            "smtp_user": str(email_cfg["smtp_user"]),
            "has_smtp_password": bool(secrets.get("smtp_password")),
            "smtp_tls": bool(email_cfg["smtp_tls"]),
            "from_address": str(email_cfg["from_address"]),
            "default_to_addresses": list(email_cfg["default_to_addresses"]),
            "send_resolved": bool(email_cfg["send_resolved"]),
        },
        "webhook_psa": {
            "enabled": bool(psa_cfg["enabled"]),
            "url": str(psa_cfg["url"]),
            "has_auth_secret": bool(secrets.get("webhook_auth_secret")),
            "send_resolved": bool(psa_cfg["send_resolved"]),
        },
        "chat": {
            "teams_enabled": bool(chat_cfg["teams_enabled"]),
            "has_teams_webhook_url": bool(secrets.get("teams_webhook_url")),
            "slack_enabled": bool(chat_cfg["slack_enabled"]),
            "has_slack_webhook_url": bool(secrets.get("slack_webhook_url")),
            "slack_channel": str(chat_cfg["slack_channel"]),
            "send_resolved": bool(chat_cfg["send_resolved"]),
        },
        "push": {
            "enabled": bool(push_cfg["enabled"]),
            "provider": str(push_cfg["provider"]),
            "min_severity": str(push_cfg["min_severity"]),
            "ntfy_url": str(push_cfg["ntfy_url"]),
            "ntfy_topic": str(push_cfg["ntfy_topic"]),
            "has_ntfy_token": bool(secrets.get("ntfy_token")),
            "telegram_chat_id": str(push_cfg["telegram_chat_id"]),
            "has_telegram_bot_token": bool(secrets.get("telegram_bot_token")),
            "gotify_url": str(push_cfg["gotify_url"]),
            "has_gotify_token": bool(secrets.get("gotify_token")),
        },
        "customer_email_routing": {
            "enabled": bool(cust_cfg["enabled"]),
            "min_severity": str(cust_cfg["min_severity"]),
            "send_resolved": bool(cust_cfg["send_resolved"]),
        },
        "rule_packs": rule_packs,
    }


def configure_alerting(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """Validate, persist, render, and reload multi-channel Alertmanager routing + Prometheus rule packs."""
    sdir = resolve_state_dir(state_dir)

    email_in = payload["smarthost_email"]
    psa_in = payload["webhook_psa"]
    chat_in = payload["chat"]
    push_in = payload["push"]
    cust_in = payload["customer_email_routing"]

    # SSRF & input validation on custom SMTP host, webhook URLs, and ntfy_topic
    smtp_host_in = str(email_in.get("smtp_host") or "").strip()
    if email_in.get("enabled") and not email_in.get("use_ns8_smarthost", True):
        if not smtp_host_in:
            raise ValidationFailure("smarthost_email.smtp_host", "", "missing_smtp_host", "Custom SMTP host required")
    if smtp_host_in:
        if ":" in smtp_host_in or "/" in smtp_host_in:
            raise SSRFValidationError("smarthost_email.smtp_host", smtp_host_in, "SMTP host must be a bare hostname/IP")
        assert_not_internal_pod_endpoint(smtp_host_in, field="smarthost_email.smtp_host")

    psa_url = str(psa_in.get("url") or "").strip()
    if psa_in.get("enabled") or psa_url:
        if not psa_url and psa_in.get("enabled"):
            raise ValidationFailure("webhook_psa.url", "", "missing_webhook_url", "PSA webhook URL required")
        if psa_url:
            validate_webhook_url(psa_url, field="webhook_psa.url")

    teams_url_in = str(chat_in.get("teams_webhook_url") or "").strip()
    if teams_url_in:
        validate_webhook_url(teams_url_in, field="chat.teams_webhook_url")

    slack_url_in = str(chat_in.get("slack_webhook_url") or "").strip()
    if slack_url_in:
        validate_webhook_url(slack_url_in, field="chat.slack_webhook_url")

    ntfy_url_in = str(push_in.get("ntfy_url") or "https://ntfy.sh").strip()
    ntfy_topic_in = str(push_in.get("ntfy_topic") or "").strip()
    if push_in.get("enabled") and push_in.get("provider") == "ntfy":
        validate_webhook_url(ntfy_url_in, field="push.ntfy_url")
        if not ntfy_topic_in or not _NTFY_TOPIC_RE.match(ntfy_topic_in):
            raise ValidationFailure(
                "push.ntfy_topic",
                ntfy_topic_in,
                "invalid_ntfy_topic",
                "Ntfy topic must match ^[A-Za-z0-9._-]+\\Z",
            )
    else:
        if ntfy_url_in and ntfy_url_in != "https://ntfy.sh":
            validate_webhook_url(ntfy_url_in, field="push.ntfy_url")
        if ntfy_topic_in and not _NTFY_TOPIC_RE.match(ntfy_topic_in):
            raise ValidationFailure(
                "push.ntfy_topic",
                ntfy_topic_in,
                "invalid_ntfy_topic",
                "Ntfy topic must match ^[A-Za-z0-9._-]+\\Z",
            )

    gotify_url_in = str(push_in.get("gotify_url") or "").strip()
    if (push_in.get("enabled") and push_in.get("provider") == "gotify") or gotify_url_in:
        if not gotify_url_in:
            raise ValidationFailure("push.gotify_url", "", "missing_gotify_url", "Gotify URL required")
        validate_webhook_url(gotify_url_in, field="push.gotify_url")

    with file_lock(sdir / ".alerting.lock"):
        prev_cfg = {**_default_alerting_config(), **load_json_file(sdir / "alerting.json", {})}
        prev_secrets = {**_default_alerting_secrets(), **load_json_file(sdir / "alerting-secrets.json", {})}

        def _pick_secret(new_val: str, unchanged_flag: bool, prev_key: str) -> str:
            if unchanged_flag:
                return str(prev_secrets.get(prev_key) or "")
            return new_val

        smtp_pw = _pick_secret(
            str(email_in.get("smtp_password") or ""),
            bool(email_in.get("smtp_password_unchanged", False)),
            "smtp_password",
        )
        psa_secret = _pick_secret(
            str(psa_in.get("auth_secret") or ""),
            bool(psa_in.get("auth_secret_unchanged", False)),
            "webhook_auth_secret",
        )
        teams_url = _pick_secret(
            teams_url_in,
            bool(chat_in.get("teams_webhook_unchanged", False)),
            "teams_webhook_url",
        )
        slack_url = _pick_secret(
            slack_url_in,
            bool(chat_in.get("slack_webhook_unchanged", False)),
            "slack_webhook_url",
        )
        ntfy_tok = _pick_secret(
            str(push_in.get("ntfy_token") or ""),
            bool(push_in.get("ntfy_token_unchanged", False)),
            "ntfy_token",
        )
        tg_tok = _pick_secret(
            str(push_in.get("telegram_bot_token") or ""),
            bool(push_in.get("telegram_bot_token_unchanged", False)),
            "telegram_bot_token",
        )
        gotify_tok = _pick_secret(
            str(push_in.get("gotify_token") or ""),
            bool(push_in.get("gotify_token_unchanged", False)),
            "gotify_token",
        )

        if chat_in.get("teams_enabled") and not teams_url:
            raise ValidationFailure(
                "chat.teams_webhook_url", "", "missing_teams_webhook_url", "Teams webhook URL required"
            )
        if chat_in.get("slack_enabled") and not slack_url:
            raise ValidationFailure(
                "chat.slack_webhook_url", "", "missing_slack_webhook_url", "Slack webhook URL required"
            )

        enabled_packs = (
            list(payload["enabled_rule_packs"])
            if "enabled_rule_packs" in payload
            else list(prev_cfg.get("enabled_rule_packs") or DEFAULT_ENABLED_RULE_PACKS)
        )

        new_cfg: dict[str, Any] = {
            "group_wait": str(payload.get("group_wait") or prev_cfg.get("group_wait") or "30s"),
            "group_interval": str(payload.get("group_interval") or prev_cfg.get("group_interval") or "5m"),
            "repeat_interval": str(payload.get("repeat_interval") or prev_cfg.get("repeat_interval") or "4h"),
            "smarthost_email": {
                "enabled": bool(email_in["enabled"]),
                "use_ns8_smarthost": bool(email_in.get("use_ns8_smarthost", True)),
                "smtp_host": str(email_in.get("smtp_host") or "").strip(),
                "smtp_port": int(email_in.get("smtp_port") or 587),
                "smtp_user": str(email_in.get("smtp_user") or "").strip(),
                "smtp_tls": bool(email_in.get("smtp_tls", True)),
                "from_address": str(email_in["from_address"]).strip(),
                "default_to_addresses": [str(a).strip() for a in email_in["default_to_addresses"]],
                "send_resolved": bool(email_in.get("send_resolved", True)),
            },
            "webhook_psa": {
                "enabled": bool(psa_in["enabled"]),
                "url": psa_url,
                "send_resolved": bool(psa_in.get("send_resolved", True)),
            },
            "chat": {
                "teams_enabled": bool(chat_in["teams_enabled"]),
                "slack_enabled": bool(chat_in["slack_enabled"]),
                "slack_channel": str(chat_in.get("slack_channel") or "").strip(),
                "send_resolved": bool(chat_in.get("send_resolved", True)),
            },
            "push": {
                "enabled": bool(push_in["enabled"]),
                "provider": str(push_in["provider"]),
                "min_severity": str(push_in.get("min_severity") or "critical"),
                "ntfy_url": ntfy_url_in,
                "ntfy_topic": str(push_in.get("ntfy_topic") or "").strip(),
                "telegram_chat_id": str(push_in.get("telegram_chat_id") or "").strip(),
                "gotify_url": gotify_url_in,
            },
            "customer_email_routing": {
                "enabled": bool(cust_in["enabled"]),
                "min_severity": str(cust_in["min_severity"]),
                "send_resolved": bool(cust_in.get("send_resolved", True)),
            },
            "enabled_rule_packs": enabled_packs,
        }

        ntfy_topic_val = new_cfg["push"]["ntfy_topic"]
        new_secrets: dict[str, Any] = {
            "smtp_password": smtp_pw,
            "webhook_auth_secret": psa_secret,
            "teams_webhook_url": teams_url,
            "slack_webhook_url": slack_url,
            "ntfy_token": ntfy_tok,
            "telegram_bot_token": tg_tok,
            "gotify_token": gotify_tok,
            "ntfy_url": ntfy_url_in,
            "ntfy_topic": ntfy_topic_val,
            "gotify_url": gotify_url_in,
            "ntfy": {"url": ntfy_url_in, "topic": ntfy_topic_val, "token": ntfy_tok},
            "gotify": {"url": gotify_url_in, "token": gotify_tok},
        }

        atomic_write_json(sdir / "alerting.json", new_cfg, mode=0o600)
        atomic_write_json(sdir / "alerting-secrets.json", new_secrets, mode=0o600)

    sync_rule_packs(enabled_packs, state_dir=sdir, reload_prometheus=True)
    reloaded = sync_alertmanager(sdir)
    return {"status": "ok", "reloaded": reloaded}


def send_test_alert(payload: dict[str, Any], *, state_dir: str | Path | None = None) -> dict[str, Any]:
    """Validate requested channel and dispatch a synthetic Alertmanager v2 alert."""
    sdir = resolve_state_dir(state_dir)
    channel = str(payload["channel"])
    customer = str(payload.get("customer") or "").strip()

    cfg = {**_default_alerting_config(), **load_json_file(sdir / "alerting.json", {})}
    secrets = {**_default_alerting_secrets(), **load_json_file(sdir / "alerting-secrets.json", {})}
    tenants_map = load_tenants_map(sdir)

    if channel == "smarthost_email" and not cfg["smarthost_email"].get("enabled"):
        return {"status": "error", "delivered": False, "message": "Smarthost/SMTP email channel is disabled."}
    if channel == "webhook_psa" and not cfg["webhook_psa"].get("enabled"):
        return {"status": "error", "delivered": False, "message": "PSA webhook channel is disabled."}
    if channel == "teams" and not (cfg["chat"].get("teams_enabled") and secrets.get("teams_webhook_url")):
        return {"status": "error", "delivered": False, "message": "MS Teams channel is disabled or unconfigured."}
    if channel == "slack" and not (cfg["chat"].get("slack_enabled") and secrets.get("slack_webhook_url")):
        return {"status": "error", "delivered": False, "message": "Slack channel is disabled or unconfigured."}
    if channel == "push" and (not cfg["push"].get("enabled") or cfg["push"].get("provider") == "none"):
        return {"status": "error", "delivered": False, "message": "Push notification channel is disabled."}
    if channel == "customer_email":
        if not cfg["customer_email_routing"].get("enabled"):
            return {"status": "error", "delivered": False, "message": "Per-customer email routing is disabled."}
        if not customer or customer not in tenants_map:
            return {"status": "error", "delivered": False, "message": f"Unknown customer tenant: {customer!r}"}
        if not (tenants_map[customer].get("contact_emails") or []):
            return {
                "status": "error",
                "delivered": False,
                "message": f"Customer {customer!r} has no contact_emails configured.",
            }

    now = datetime.now(timezone.utc).replace(microsecond=0)
    ends = now + timedelta(minutes=3)
    target_customer = customer or (sorted(tenants_map.keys())[0] if tenants_map else "msp-test")

    labels: dict[str, str] = {
        "alertname": "CentralMonitoringTestAlert",
        "severity": "critical",
        "category": "cluster",
        "customer": target_customer,
        "site": "hq",
        "device_role": "ns8",
        "collector_id": "hub-central",
        "instance": "central-monitoring-hub",
    }
    if channel != "all":
        labels["test_channel"] = channel

    am_alerts = [
        {
            "labels": labels,
            "annotations": {
                "summary": f"[TEST] NS8 Central Monitoring test notification ({channel})",
                "description": f"Synthetic verification alert dispatched via test-alert for channel '{channel}'.",
            },
            "startsAt": now.isoformat().replace("+00:00", "Z"),
            "endsAt": ends.isoformat().replace("+00:00", "Z"),
        }
    ]

    body = json.dumps(am_alerts).encode("utf-8")
    status, _ = pod_http_request(
        f"{_alertmanager_base_url()}/api/v2/alerts",
        method="POST",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=5.0,
    )
    if 200 <= status < 300:
        return {
            "status": "ok",
            "delivered": True,
            "message": f"Test alert accepted by Alertmanager v2 API for channel '{channel}'.",
        }
    if status > 0:
        return {
            "status": "error",
            "delivered": False,
            "message": f"Alertmanager returned HTTP {status}.",
        }
    return {
        "status": "error",
        "delivered": False,
        "message": "Unable to reach Alertmanager v2 API.",
    }
