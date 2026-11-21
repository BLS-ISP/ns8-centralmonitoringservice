from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hub_alerting.alertmanager_config import sync_alertmanager


def test_get_alerting_defaults_and_rule_pack_counts(hub_env: dict[str, Any]) -> None:
    run_action = hub_env["run_action"]
    info = run_action("get-alerting", "20read", {})

    assert info["ns8_smarthost_available"] is True
    assert info["ns8_smarthost_host"] == "10.0.2.2:2525"
    assert len(info["rule_packs"]) == 6
    pack_ids = [p["pack_id"] for p in info["rule_packs"]]
    assert pack_ids == [
        "ns8-cluster",
        "linux-node",
        "windows-node",
        "proxmox-ve",
        "blackbox-web-ssl",
        "snmp-network-ups",
    ]
    assert sum(p["rules_count"] for p in info["rule_packs"]) == 78
    assert all(p["enabled"] is True for p in info["rule_packs"])


def test_configure_alerting_multichannel_customer_routes_secret_preservation_and_sync(
    hub_env: dict[str, Any],
) -> None:
    run_action = hub_env["run_action"]
    state_dir: Path = hub_env["state_dir"]
    config_dir: Path = hub_env["config_dir"]
    backends = hub_env["backends"]

    payload = {
        "group_wait": "30s",
        "group_interval": "5m",
        "repeat_interval": "4h",
        "smarthost_email": {
            "enabled": True,
            "use_ns8_smarthost": True,
            "from_address": "alerts@msp.example.com",
            "default_to_addresses": ["noc@msp.example.com"],
            "send_resolved": True,
        },
        "webhook_psa": {
            "enabled": True,
            "url": "https://psa.msp.example.com/webhooks/alertmanager",
            "auth_secret": "psa-bearer-secret-999",
            "send_resolved": True,
        },
        "chat": {
            "teams_enabled": True,
            "teams_webhook_url": "https://outlook.office.com/webhook/abc-123",
            "slack_enabled": True,
            "slack_webhook_url": "https://hooks.slack.com/services/T1/B2/S3",
            "slack_channel": "#msp-noc",
            "send_resolved": True,
        },
        "push": {
            "enabled": True,
            "provider": "ntfy",
            "min_severity": "critical",
            "ntfy_url": "https://ntfy.msp.example.com",
            "ntfy_topic": "msp-critical",
            "ntfy_token": "tk_ntfy_secret_abc",
        },
        "customer_email_routing": {
            "enabled": True,
            "min_severity": "warning",
            "send_resolved": True,
        },
        "enabled_rule_packs": ["ns8-cluster", "linux-node", "blackbox-web-ssl"],
    }

    res = run_action("configure-alerting", "20configure", payload)
    assert res == {"status": "ok", "reloaded": True}
    assert backends.am_reloads >= 1

    # Verify deployed rule packs
    rules_dir = config_dir / "prometheus" / "rules"
    deployed_files = sorted(p.name for p in rules_dir.glob("*.yml"))
    assert deployed_files == ["blackbox-web-ssl.yml", "linux-node.yml", "ns8-cluster.yml"]

    # Verify rendered alertmanager.yml
    am_yml = (config_dir / "alertmanager" / "alertmanager.yml").read_text(encoding="utf-8")
    assert "10.0.2.2:2525" in am_yml
    assert "https://psa.msp.example.com/webhooks/alertmanager" in am_yml
    assert "psa-bearer-secret-999" in am_yml
    assert "msteams_configs:" in am_yml
    assert "slack_configs:" in am_yml
    assert "http://127.0.0.1:9097/alert-relay/ntfy" in am_yml
    assert "customer-email-acme-corp" in am_yml
    assert "noc@acme.example.com" in am_yml
    # beta-gmbh has empty contact_emails so no customer route should be generated for it
    assert "customer-email-beta-gmbh" not in am_yml

    # Verify state/alerting-secrets.json for hub-gateway relay
    secrets_json = json.loads((state_dir / "alerting-secrets.json").read_text(encoding="utf-8"))
    assert secrets_json["ntfy"]["token"] == "tk_ntfy_secret_abc"
    assert secrets_json["ntfy_token"] == "tk_ntfy_secret_abc"

    # Verify get-alerting redacts all secrets while setting has_* flags
    read_back = run_action("get-alerting", "20read", {})
    raw_read = json.dumps(read_back)
    assert "psa-bearer-secret-999" not in raw_read
    assert "https://outlook.office.com/webhook/abc-123" not in raw_read
    assert "https://hooks.slack.com/services/T1/B2/S3" not in raw_read
    assert "tk_ntfy_secret_abc" not in raw_read
    assert read_back["webhook_psa"]["has_auth_secret"] is True
    assert read_back["chat"]["has_teams_webhook_url"] is True
    assert read_back["chat"]["has_slack_webhook_url"] is True
    assert read_back["push"]["has_ntfy_token"] is True

    # Update to Telegram push while keeping PSA/Teams/Slack/Ntfy secrets unchanged
    payload_tg = {
        "smarthost_email": {
            "enabled": True,
            "use_ns8_smarthost": False,
            "smtp_host": "smtp.msp.example.com",
            "smtp_port": 587,
            "smtp_user": "mailer",
            "smtp_password": "SmtpSecretPassword!",
            "smtp_tls": True,
            "from_address": "alerts@msp.example.com",
            "default_to_addresses": ["noc@msp.example.com"],
        },
        "webhook_psa": {
            "enabled": True,
            "url": "https://psa.msp.example.com/webhooks/alertmanager",
            "auth_secret_unchanged": True,
        },
        "chat": {
            "teams_enabled": True,
            "teams_webhook_unchanged": True,
            "slack_enabled": True,
            "slack_webhook_unchanged": True,
            "slack_channel": "#msp-noc",
        },
        "push": {
            "enabled": True,
            "provider": "telegram",
            "min_severity": "warning",
            "ntfy_token_unchanged": True,
            "telegram_bot_token": "123456:ABCDEF_tg_secret",
            "telegram_chat_id": "-100987654321",
        },
        "customer_email_routing": {
            "enabled": True,
            "min_severity": "critical",
        },
    }
    run_action("configure-alerting", "20configure", payload_tg)

    am_yml_tg = (config_dir / "alertmanager" / "alertmanager.yml").read_text(encoding="utf-8")
    assert "telegram_configs:" in am_yml_tg
    assert "chat_id: -100987654321" in am_yml_tg
    assert "psa-bearer-secret-999" in am_yml_tg
    assert "https://outlook.office.com/webhook/abc-123" in am_yml_tg
    assert "smtp.msp.example.com:587" in am_yml_tg

    # Test cross-module sync_alertmanager(state_dir) when beta-gmbh adds contact_emails
    tenants_data = json.loads((state_dir / "tenants.json").read_text(encoding="utf-8"))
    tenants_data["tenants"][1]["contact_emails"] = ["it@beta.example.com"]
    (state_dir / "tenants.json").write_text(
        json.dumps(tenants_data, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    assert sync_alertmanager(state_dir) is True
    am_yml_synced = (config_dir / "alertmanager" / "alertmanager.yml").read_text(encoding="utf-8")
    assert "customer-email-beta-gmbh" in am_yml_synced
    assert "it@beta.example.com" in am_yml_synced


def test_configure_alerting_rejects_ssrf_webhook_urls(hub_env: dict[str, Any]) -> None:
    run_action = hub_env["run_action"]

    bad_payload = {
        "smarthost_email": {
            "enabled": False,
            "use_ns8_smarthost": True,
            "from_address": "alerts@msp.example.com",
            "default_to_addresses": [],
        },
        "webhook_psa": {
            "enabled": True,
            "url": "http://10.0.2.2:9095/api/v1/query",
        },
        "chat": {"teams_enabled": False, "slack_enabled": False},
        "push": {"enabled": False, "provider": "none"},
        "customer_email_routing": {"enabled": False, "min_severity": "critical"},
    }
    proc = run_action("configure-alerting", "20configure", bad_payload, expect_success=False)
    assert proc.returncode == 2
    err = json.loads(proc.stdout)
    assert err[0]["error"] == "FORBIDDEN_INTERNAL_ENDPOINT"


def test_test_alert_dispatches_to_alertmanager_v2_api(hub_env: dict[str, Any]) -> None:
    run_action = hub_env["run_action"]
    backends = hub_env["backends"]

    # First test when slack is not configured -> returns status="error", delivered=False
    not_cfg = run_action("test-alert", "20test", {"channel": "slack"})
    assert not_cfg["status"] == "error"
    assert not_cfg["delivered"] is False

    # Configure Slack + Customer Email Routing
    run_action(
        "configure-alerting",
        "20configure",
        {
            "smarthost_email": {
                "enabled": True,
                "use_ns8_smarthost": True,
                "from_address": "alerts@msp.example.com",
                "default_to_addresses": ["noc@msp.example.com"],
            },
            "webhook_psa": {"enabled": False, "url": ""},
            "chat": {
                "teams_enabled": False,
                "slack_enabled": True,
                "slack_webhook_url": "https://hooks.slack.com/services/T1/B2/S3",
            },
            "push": {"enabled": False, "provider": "none"},
            "customer_email_routing": {"enabled": True, "min_severity": "warning"},
        },
    )

    ok_slack = run_action("test-alert", "20test", {"channel": "slack"})
    assert ok_slack["status"] == "ok"
    assert ok_slack["delivered"] is True
    assert len(backends.received_alerts) == 1
    assert backends.received_alerts[0]["labels"]["test_channel"] == "slack"

    ok_cust = run_action(
        "test-alert",
        "20test",
        {"channel": "customer_email", "customer": "acme-corp"},
    )
    assert ok_cust["status"] == "ok"
    assert ok_cust["delivered"] is True
    assert backends.received_alerts[-1]["labels"]["customer"] == "acme-corp"

    # Gotify relay + channel="all" fan-out test
    run_action(
        "configure-alerting",
        "20configure",
        {
            "smarthost_email": {
                "enabled": True,
                "use_ns8_smarthost": True,
                "from_address": "alerts@msp.example.com",
                "default_to_addresses": ["noc@msp.example.com"],
            },
            "webhook_psa": {"enabled": False, "url": ""},
            "chat": {"teams_enabled": False, "slack_enabled": True, "slack_webhook_unchanged": True},
            "push": {
                "enabled": True,
                "provider": "gotify",
                "min_severity": "critical",
                "gotify_url": "https://gotify.msp.example.com",
                "gotify_token": "gotify_app_token_xyz",
            },
            "customer_email_routing": {"enabled": True, "min_severity": "warning"},
        },
    )
    am_gotify = (hub_env["config_dir"] / "alertmanager" / "alertmanager.yml").read_text(encoding="utf-8")
    assert "http://127.0.0.1:9097/alert-relay/gotify" in am_gotify
    ok_all = run_action("test-alert", "20test", {"channel": "all"})
    assert ok_all["status"] == "ok"
    assert ok_all["delivered"] is True
    assert "test_channel" not in backends.received_alerts[-1]["labels"]
