"""Comprehensive static, i18n, NS8 Cockpit UI rule, schema contract, and build verification tests for hub/ui."""

from __future__ import annotations

import json
import re
import struct
import zlib
from pathlib import Path
from typing import Any

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_UI_ROOT = REPO_ROOT / "hub" / "ui"
HUB_SRC_ROOT = HUB_UI_ROOT / "src"
SCHEMAS_ROOT = REPO_ROOT / "shared" / "schemas"

MANDATORY_NS8_I18N_KEYS = (
    "action.list-installed-modules",
    "task.cannot_create_task",
    "error.cannot_retrieve_installed_modules",
    "error.cannot_retrieve_module_info",
)

ALL_HUB_ACTIONS = (
    "configure-module",
    "get-configuration",
    "get-overview",
    "discover-ldap-groups",
    "test-ldap-user",
    "list-tenants",
    "save-tenant",
    "delete-tenant",
    "rotate-token",
    "generate-agent-bundle",
    "list-portal-users",
    "save-portal-user",
    "delete-portal-user",
    "list-targets",
    "save-target",
    "delete-target",
    "get-alerting",
    "configure-alerting",
    "test-alert",
    "list-silences",
    "create-silence",
    "delete-silence",
)


def _iter_source_files() -> list[Path]:
    exts = {".vue", ".js", ".mjs", ".json", ".scss", ".css", ".html"}
    files: list[Path] = []
    for path in sorted(HUB_UI_ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(HUB_UI_ROOT).parts
        if "node_modules" in rel_parts or "dist" in rel_parts:
            continue
        if path.name == "package-lock.json":
            continue
        if path.suffix in exts:
            files.append(path)
    return files


def _flatten_json_keys(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            out.update(_flatten_json_keys(value, full_key))
        else:
            out[full_key] = value
    return out


def _split_top_level_args(arg_str: str) -> list[str]:
    args: list[str] = []
    depth = 0
    current: list[str] = []
    quote_char: str | None = None
    escaped = False

    for ch in arg_str:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            current.append(ch)
            escaped = True
            continue
        if quote_char:
            current.append(ch)
            if ch == quote_char:
                quote_char = None
            continue
        if ch in ("'", '"', "`"):
            quote_char = ch
            current.append(ch)
            continue
        if ch in ("(", "[", "{"):
            depth += 1
            current.append(ch)
            continue
        if ch in (")", "]", "}"):
            depth -= 1
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            token = "".join(current).strip()
            if token:
                args.append(token)
            current = []
            continue
        current.append(ch)

    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def _extract_balanced_call_args(source: str, func_name: str) -> list[str]:
    pattern = re.compile(rf"\b{re.escape(func_name)}\s*\(")
    calls: list[str] = []
    for match in pattern.finditer(source):
        idx = match.end()
        depth = 1
        quote_char: str | None = None
        escaped = False
        chars: list[str] = []
        while idx < len(source) and depth > 0:
            ch = source[idx]
            idx += 1
            if escaped:
                chars.append(ch)
                escaped = False
                continue
            if ch == "\\":
                chars.append(ch)
                escaped = True
                continue
            if quote_char:
                chars.append(ch)
                if ch == quote_char:
                    quote_char = None
                continue
            if ch in ("'", '"', "`"):
                quote_char = ch
                chars.append(ch)
                continue
            if ch == "(":
                depth += 1
                chars.append(ch)
            elif ch == ")":
                depth -= 1
                if depth > 0:
                    chars.append(ch)
            else:
                chars.append(ch)
        calls.append("".join(chars))
    return calls


def _load_schema(filename: str) -> dict[str, Any]:
    path = SCHEMAS_ROOT / filename
    return json.loads(path.read_text(encoding="utf-8"))


def test_utf8_no_bom_and_lf_line_endings() -> None:
    source_files = _iter_source_files()
    assert len(source_files) >= 14
    for file_path in source_files + sorted(Path(__file__).parent.glob("*.py")):
        raw = file_path.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM found in {file_path}"
        assert b"\r\n" not in raw, f"CRLF line endings found in {file_path}"


def test_ns8_rule_1_task_service_notifications_and_xss_safety() -> None:
    code_files = sorted(HUB_SRC_ROOT.rglob("*.vue")) + sorted(HUB_SRC_ROOT.rglob("*.js"))
    assert len(code_files) >= 10

    error_call_count = 0
    for path in code_files:
        text = path.read_text(encoding="utf-8")
        assert "createSuccessNotificationForApp" not in text, (
            f"NS8 UI Rule #1 violation: createSuccessNotificationForApp does not exist ({path.name})"
        )
        assert "v-html" not in text, f"XSS boundary violation: v-html forbidden ({path.name})"

        for arg_blob in _extract_balanced_call_args(text, "createErrorNotificationForApp"):
            args = _split_top_level_args(arg_blob)
            assert len(args) == 2, (
                f"{path.name}: createErrorNotificationForApp must pass 2 arguments, got {len(args)}: {arg_blob}"
            )
            error_call_count += 1

    assert error_call_count >= 15, "Expected error notification handlers across all views"


def test_arch_12_ns8_core_event_bus_listeners() -> None:
    """Ensure task $once listeners attach to window.parent.core.$root when inside NS8 Cockpit."""
    code_files = sorted(HUB_SRC_ROOT.rglob("*.vue")) + sorted(HUB_SRC_ROOT.rglob("*.js"))
    core_bus_once_count = 0
    for path in code_files:
        text = path.read_text(encoding="utf-8")
        assert "this.$root.$once(" not in text, (
            f"{path.name}: must use (this.core && this.core.$root ? this.core.$root : this.$root).$once(...)"
        )
        core_bus_once_count += text.count(
            "(this.core && this.core.$root ? this.core.$root : this.$root).$once("
        )
    assert core_bus_once_count >= 40


def test_arch_13_targets_blackbox_tls_toggle_and_snmp_v3_edit_hydration() -> None:
    """Verify Targets.vue exposes tls_skip_verify on blackbox probes and hydrates snmp_v3 on edit."""
    targets_src = (HUB_SRC_ROOT / "views" / "Targets.vue").read_text(encoding="utf-8")
    assert 'value="blackboxTlsSkipVerify"' in targets_src
    assert "rowV3.username" in targets_src
    assert "rowV3.security_level" in targets_src
    assert "rowV3.auth_protocol" in targets_src
    assert "rowV3.priv_protocol" in targets_src

    list_out_schema = _load_schema("hub-list-targets-output.json")
    sample_output = {
        "targets": [
            {
                "id": "tgt_snmp_v3",
                "name": "Core Switch SNMPv3",
                "enabled": True,
                "target_type": "snmp",
                "customer": "acme-corp",
                "site": "hq",
                "device_role": "snmp-network",
                "scrape_interval": "30s",
                "endpoints": ["10.20.0.2"],
                "snmp_module": "if_mib",
                "snmp_version": "v3",
                "has_secret": True,
                "snmp_v3": {
                    "username": "msp-snmp",
                    "security_level": "authPriv",
                    "auth_protocol": "SHA256",
                    "priv_protocol": "AES",
                },
            }
        ],
        "pagination": {"page": 1, "page_size": 200, "total_items": 1, "total_pages": 1},
    }
    jsonschema.validate(instance=sample_output, schema=list_out_schema)


def test_ns8_rule_2_carbon_icons_registered_in_components_and_data() -> None:
    vue_files = sorted(HUB_SRC_ROOT.rglob("*.vue"))
    icons_es_dir = HUB_UI_ROOT / "node_modules" / "@carbon" / "icons-vue" / "es"

    checked_tag_icons = 0
    checked_prop_icons = 0

    for path in vue_files:
        text = path.read_text(encoding="utf-8")
        tpl_match = re.search(r"<template>([\s\S]*?)</template>", text)
        script_match = re.search(r"<script>([\s\S]*?)</script>", text)
        assert tpl_match and script_match, f"Missing <template> or <script> in {path.name}"

        tpl = tpl_match.group(1)
        script = script_match.group(1)

        imported_icons: dict[str, str] = {}
        for imp_match in re.finditer(
            r'import\s+([A-Za-z0-9_]+)\s+from\s+"@carbon/icons-vue/es/([^"]+)";',
            script,
        ):
            ident, sub_path = imp_match.group(1), imp_match.group(2)
            imported_icons[ident] = sub_path
            if icons_es_dir.is_dir():
                assert (icons_es_dir / f"{sub_path}.js").is_file(), (
                    f"{path.name}: missing icon module @carbon/icons-vue/es/{sub_path}.js"
                )

        comp_match = re.search(r"components\s*:\s*\{([\s\S]*?)\}", script)
        comp_block = comp_match.group(1) if comp_match else ""

        data_match = re.search(r"data\s*\(\)\s*\{[\s\S]*?return\s*\{([\s\S]*?)\n\s*\};", script)
        data_block = data_match.group(1) if data_match else ""

        for tag_match in re.finditer(r"<([A-Z][A-Za-z0-9_]*(?:16|20|24|32))\b", tpl):
            icon_name = tag_match.group(1)
            assert icon_name in imported_icons, (
                f"{path.name}: <{icon_name} /> used in template but not imported from @carbon/icons-vue"
            )
            assert re.search(rf"\b{re.escape(icon_name)}\b", comp_block), (
                f"{path.name}: <{icon_name} /> used in template but missing from components: {{ ... }}"
            )
            checked_tag_icons += 1

        for prop_match in re.finditer(r':icon="([A-Z][A-Za-z0-9_]*)"', tpl):
            icon_name = prop_match.group(1)
            assert icon_name in imported_icons, (
                f"{path.name}: :icon=\"{icon_name}\" used in template but not imported from @carbon/icons-vue"
            )
            assert re.search(rf"\b{re.escape(icon_name)}\b", data_block), (
                f"{path.name}: :icon=\"{icon_name}\" used in template but missing from data()"
            )
            checked_prop_icons += 1

    assert checked_tag_icons >= 6
    assert checked_prop_icons >= 15


def test_ns8_rule_3_vue_i18n_setup_and_en_de_key_parity() -> None:
    main_js = (HUB_SRC_ROOT / "main.js").read_text(encoding="utf-8")
    assert '../public/i18n/en/translation.json' in main_js
    assert '../public/i18n/de/translation.json' in main_js
    assert 'fallbackLocale: "en"' in main_js
    assert re.search(r"messages\s*:\s*\{[\s\S]*?\ben\s*:\s*enMessages[\s\S]*?\bde\s*:\s*deMessages", main_js)

    en_data = json.loads((HUB_UI_ROOT / "public" / "i18n" / "en" / "translation.json").read_text(encoding="utf-8"))
    de_data = json.loads((HUB_UI_ROOT / "public" / "i18n" / "de" / "translation.json").read_text(encoding="utf-8"))

    en_flat = _flatten_json_keys(en_data)
    de_flat = _flatten_json_keys(de_data)

    assert set(en_flat.keys()) == set(de_flat.keys()), (
        f"Translation key mismatch! EN-only={set(en_flat) - set(de_flat)}, DE-only={set(de_flat) - set(en_flat)}"
    )

    for key in MANDATORY_NS8_I18N_KEYS:
        assert key in en_flat and isinstance(en_flat[key], str) and en_flat[key].strip()
        assert key in de_flat and isinstance(de_flat[key], str) and de_flat[key].strip()

    for key, val in en_flat.items():
        assert isinstance(val, str) and val.strip(), f"Empty EN translation for {key}"
    for key, val in de_flat.items():
        assert isinstance(val, str) and val.strip(), f"Empty DE translation for {key}"

    code_files = sorted(HUB_SRC_ROOT.rglob("*.vue")) + sorted(HUB_SRC_ROOT.rglob("*.js"))
    resolved_count = 0
    for path in code_files:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"\$t\(\s*['\"]([a-zA-Z0-9_.-]+)['\"]", text):
            t_key = m.group(1)
            assert t_key in en_flat, f"{path.name} references missing i18n key '{t_key}'"
            assert t_key in de_flat, f"{path.name} references missing DE i18n key '{t_key}'"
            resolved_count += 1

    assert resolved_count >= 120


def test_all_17_hub_actions_invoked_across_views() -> None:
    combined_sources = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(HUB_SRC_ROOT.rglob("*.vue"))
    )

    assert '"get-status"' in combined_sources
    assert '"list-installed-modules"' in combined_sources

    for action_name in ALL_HUB_ACTIONS:
        assert f'"{action_name}"' in combined_sources, (
            f"Hub NS8 action '{action_name}' is not invoked in any hub/ui Vue component"
        )

    status_vue = (HUB_SRC_ROOT / "views" / "Status.vue").read_text(encoding="utf-8")
    assert '"get-status"' in status_vue
    assert '"get-overview"' in status_vue


@pytest.mark.parametrize(
    ("schema_file", "ui_payload"),
    [
        ("hub-get-overview-input.json", {}),
        ("hub-get-configuration-input.json", {}),
        (
            "hub-configure-module-input.json",
            {
                "host": "monitoring.msp.example.com",
                "lets_encrypt": True,
                "http2https": True,
                "retention_days": 30,
                "retention_size_gb": 50,
                "loki_retention_days": 30,
                "backup_include_tsdb": False,
                "storage_mode": "local",
                "s3": {
                    "endpoint": "",
                    "bucket": "",
                    "region": "us-east-1",
                    "access_key": "",
                    "secret_key": "",
                    "secret_key_unchanged": False,
                    "insecure": False,
                    "path_style": True,
                },
                "ldap_enabled": False,
                "ldap_domain": "",
                "ldap_admin_group": "Domain Admins",
                "ldap_editor_group": "",
                "grafana_admin_password": "",
            },
        ),
        (
            "hub-configure-module-input.json",
            {
                "host": "monitoring.msp.example.com",
                "lets_encrypt": True,
                "http2https": True,
                "retention_days": 14,
                "retention_size_gb": 100,
                "loki_retention_days": 90,
                "backup_include_tsdb": False,
                "storage_mode": "s3",
                "s3": {
                    "endpoint": "minio.msp.lan:9000",
                    "bucket": "ns8-monitoring-tsdb",
                    "region": "eu-central-1",
                    "access_key": "minioadmin",
                    "secret_key": "",
                    "secret_key_unchanged": True,
                    "insecure": False,
                    "path_style": True,
                },
                "ldap_enabled": True,
                "ldap_domain": "ad.msp.example.com",
                "ldap_admin_principals": [
                    "CN=Domain Admins,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
                    "CN=Genera,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
                ],
                "ldap_editor_principals": [
                    "CN=MSP Technicians,CN=Users,DC=ad,DC=msp,DC=example,DC=com"
                ],
                "ldap_viewer_principals": [
                    "CN=MSP Viewers,CN=Users,DC=ad,DC=msp,DC=example,DC=com"
                ],
                "ldap_admin_group": "CN=Domain Admins,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
                "ldap_editor_group": "CN=MSP Technicians,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
                "ldap_viewer_group": "CN=MSP Viewers,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
                "grafana_admin_password": "StrongAdminPassword123!",
            },
        ),
        (
            "hub-discover-ldap-groups-input.json",
            {"domain": "ad.bls-isp.net"},
        ),
        (
            "hub-test-ldap-user-input.json",
            {
                "domain": "ad.bls-isp.net",
                "username": "Genera",
                "ldap_admin_principals": [
                    "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
                    "CN=Genera,CN=Users,DC=ad,DC=bls-isp,DC=net",
                ],
                "ldap_editor_principals": [],
                "ldap_viewer_principals": [],
                "ldap_admin_group": "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
                "ldap_editor_group": "",
                "ldap_viewer_group": "",
            },
        ),
        (
            "hub-list-tenants-input.json",
            {"search": "", "page": 1, "page_size": 200},
        ),
        (
            "hub-save-tenant-input.json",
            {
                "customer": "acme-corp",
                "display_name": "ACME Corporation GmbH",
                "sites": ["hq", "branch-berlin"],
                "contact_emails": ["it@acme.example.com"],
                "customer_portal_enabled": True,
                "portal_viewer_username": "",
                "portal_viewer_password": "",
                "notes": "24x7 SLA customer",
            },
        ),
        (
            "hub-list-portal-users-input.json",
            {"customer": "acme-corp"},
        ),
        (
            "hub-save-portal-user-input.json",
            {
                "customer": "acme-corp",
                "username": "acme-admin",
                "full_name": "Max Mustermann",
                "email": "m.mustermann@acme.example.com",
                "role": "Editor",
                "disabled": False,
                "password": "StrongPortalPassword123!",
                "password_unchanged": False,
            },
        ),
        (
            "hub-save-portal-user-input.json",
            {
                "customer": "acme-corp",
                "username": "acme-admin",
                "full_name": "Max Mustermann",
                "email": "m.mustermann@acme.example.com",
                "role": "Viewer",
                "disabled": True,
                "password": "",
                "password_unchanged": True,
            },
        ),
        (
            "hub-delete-portal-user-input.json",
            {"customer": "acme-corp", "username": "acme-admin"},
        ),
        (
            "hub-delete-tenant-input.json",
            {"customer": "acme-corp", "delete_central_targets": True},
        ),
        (
            "hub-rotate-token-input.json",
            {"customer": "acme-corp", "grace_period_minutes": 60},
        ),
        (
            "hub-generate-agent-bundle-input.json",
            {
                "customer": "acme-corp",
                "site": "hq",
                "platform": "windows",
                "collector_id": "",
                "issue_dedicated_token": True,
                "syslog_port": 5514,
            },
        ),
        (
            "hub-list-targets-input.json",
            {"customer": "", "target_type": "", "page": 1, "page_size": 200},
        ),
        (
            "hub-save-target-input.json",
            {
                "id": "",
                "name": "ACME Firewall SNMPv3",
                "enabled": True,
                "target_type": "snmp",
                "customer": "acme-corp",
                "site": "hq",
                "device_role": "snmp-firewall",
                "scrape_interval": "30s",
                "endpoints": ["10.20.0.1"],
                "scheme": "https",
                "metrics_path": "/metrics",
                "tls_skip_verify": False,
                "basic_auth_user": "",
                "basic_auth_password": "",
                "bearer_token": "",
                "secret_unchanged": False,
                "match_selectors": ['{__name__=~"node_.+|ns8_.+|up|restic_.+|systemd_.+"}'],
                "blackbox_module": "http_2xx",
                "snmp_module": "fortigate",
                "snmp_version": "v3",
                "snmp_community": "",
                "snmp_v3": {
                    "username": "msp-snmp",
                    "security_level": "authPriv",
                    "auth_protocol": "SHA256",
                    "auth_password": "AuthSecretPassword",
                    "priv_protocol": "AES",
                    "priv_password": "PrivSecretPassword",
                },
            },
        ),
        ("hub-delete-target-input.json", {"id": "tgt_acme_fw1"}),
        ("hub-get-alerting-input.json", {}),
        (
            "hub-configure-alerting-input.json",
            {
                "group_wait": "30s",
                "group_interval": "5m",
                "repeat_interval": "4h",
                "smarthost_email": {
                    "enabled": True,
                    "use_ns8_smarthost": True,
                    "smtp_host": "",
                    "smtp_port": 587,
                    "smtp_user": "",
                    "smtp_password": "",
                    "smtp_password_unchanged": True,
                    "smtp_tls": True,
                    "from_address": "monitoring@msp.example.com",
                    "default_to_addresses": ["noc@msp.example.com"],
                    "send_resolved": True,
                },
                "webhook_psa": {
                    "enabled": True,
                    "url": "https://psa.msp.example.com/webhook",
                    "auth_secret": "",
                    "auth_secret_unchanged": True,
                    "send_resolved": True,
                },
                "chat": {
                    "teams_enabled": True,
                    "teams_webhook_url": "",
                    "teams_webhook_unchanged": True,
                    "slack_enabled": False,
                    "slack_webhook_url": "",
                    "slack_webhook_unchanged": False,
                    "slack_channel": "",
                    "send_resolved": True,
                },
                "push": {
                    "enabled": True,
                    "provider": "ntfy",
                    "min_severity": "critical",
                    "ntfy_url": "https://ntfy.sh",
                    "ntfy_topic": "msp-critical",
                    "ntfy_token": "",
                    "ntfy_token_unchanged": True,
                    "telegram_bot_token": "",
                    "telegram_bot_token_unchanged": False,
                    "telegram_chat_id": "",
                    "gotify_url": "",
                    "gotify_token": "",
                    "gotify_token_unchanged": False,
                },
                "customer_email_routing": {
                    "enabled": True,
                    "min_severity": "critical",
                    "send_resolved": True,
                },
                "enabled_rule_packs": [
                    "ns8-cluster",
                    "linux-node",
                    "windows-node",
                    "proxmox-ve",
                    "blackbox-web-ssl",
                    "snmp-network-ups",
                ],
            },
        ),
        (
            "hub-test-alert-input.json",
            {"channel": "customer_email", "customer": "acme-corp"},
        ),
        (
            "hub-list-silences-input.json",
            {"customer": "", "include_expired": False},
        ),
        (
            "hub-create-silence-input.json",
            {
                "customer": "acme-corp",
                "site": "hq",
                "device_role": "windows",
                "extra_matchers": [
                    {
                        "name": "alertname",
                        "value": "WindowsNodeRebooted",
                        "is_regex": False,
                        "is_equal": True,
                    }
                ],
                "starts_at": "2026-11-21T02:00:00Z",
                "ends_at": "2026-11-21T04:00:00Z",
                "created_by": "msp-admin",
                "comment": "Monthly Patch Tuesday window",
            },
        ),
        ("hub-delete-silence-input.json", {"silence_id": "sil_987654"}),
    ],
)
def test_ui_payload_shapes_validate_against_hub_schemas(
    schema_file: str, ui_payload: dict[str, Any]
) -> None:
    schema = _load_schema(schema_file)
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.validate(instance=ui_payload, schema=schema)


def test_view_payload_keys_match_input_schema_properties() -> None:
    """Verify key builders in Settings, Tenants, Targets, and Alerting match schema property names."""
    settings_src = (HUB_SRC_ROOT / "views" / "Settings.vue").read_text(encoding="utf-8")
    cfg_schema = _load_schema("hub-configure-module-input.json")
    for req_key in cfg_schema["required"]:
        assert f"{req_key}:" in settings_src, f"Settings.vue missing required key {req_key}"
    for s3_key in ("endpoint", "bucket", "region", "access_key", "secret_key", "secret_key_unchanged", "insecure", "path_style"):
        assert f"{s3_key}:" in settings_src, f"Settings.vue missing s3.{s3_key}"
    for ldap_key in (
        "ldap_admin_principals",
        "ldap_editor_principals",
        "ldap_viewer_principals",
        "ldap_admin_group",
        "ldap_editor_group",
        "ldap_viewer_group",
    ):
        assert f"{ldap_key}:" in settings_src, f"Settings.vue missing {ldap_key}"

    tenants_src = (HUB_SRC_ROOT / "views" / "Tenants.vue").read_text(encoding="utf-8")
    save_tenant_schema = _load_schema("hub-save-tenant-input.json")
    for prop in save_tenant_schema["properties"]:
        assert prop in tenants_src, f"Tenants.vue missing save-tenant property {prop}"
    bundle_out_schema = _load_schema("hub-generate-agent-bundle-output.json")
    for out_prop in ("config_filename", "config_content", "installer_filename", "installer_content", "instructions"):
        assert out_prop in bundle_out_schema["properties"]
        assert out_prop in tenants_src, f"Tenants.vue does not read {out_prop}"

    targets_src = (HUB_SRC_ROOT / "views" / "Targets.vue").read_text(encoding="utf-8")
    save_target_schema = _load_schema("hub-save-target-input.json")
    for prop in save_target_schema["properties"]:
        assert prop in targets_src, f"Targets.vue missing save-target property {prop}"

    alerting_src = (HUB_SRC_ROOT / "views" / "Alerting.vue").read_text(encoding="utf-8")
    cfg_alerting_schema = _load_schema("hub-configure-alerting-input.json")
    for prop in cfg_alerting_schema["properties"]:
        assert prop in alerting_src, f"Alerting.vue missing configure-alerting property {prop}"


def test_vue_config_and_production_dist_bundle_exists() -> None:
    vue_cfg = (HUB_UI_ROOT / "vue.config.js").read_text(encoding="utf-8")
    assert 'publicPath: "./"' in vue_cfg

    dist_dir = HUB_UI_ROOT / "dist"
    index_html = dist_dir / "index.html"
    assert index_html.is_file(), "hub/ui/dist/index.html missing — run 'npm --prefix hub/ui run build'"
    html_text = index_html.read_text(encoding="utf-8")
    assert "<div id=" in html_text
    assert "./js/" in html_text or "js/" in html_text

    assert (dist_dir / "config.json").is_file()
    assert (dist_dir / "metadata.json").is_file()
    assert (dist_dir / "module_default_icon.png").is_file()
    assert (dist_dir / "i18n" / "en" / "translation.json").is_file()
    assert (dist_dir / "i18n" / "de" / "translation.json").is_file()
    js_chunks = list((dist_dir / "js").glob("*.js"))
    assert len(js_chunks) >= 1


def test_software_center_metadata_and_png_icon() -> None:
    """Validate NS8 Software Center metadata.json and 128x128 RGBA PNG icon in public/ and dist/."""
    meta_path = HUB_UI_ROOT / "public" / "metadata.json"
    assert meta_path.is_file()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["name"] == "Central Monitoring Hub"
    assert isinstance(meta["description"]["en"], str) and meta["description"]["en"].strip()
    assert isinstance(meta["description"]["de"], str) and meta["description"]["de"].strip()
    assert meta["categories"] == ["monitoring", "administration"]
    assert isinstance(meta["authors"], list) and len(meta["authors"]) >= 1
    assert "documentation_url" in meta["docs"]
    assert "bug_url" in meta["docs"]
    assert "code_url" in meta["docs"]
    assert meta["source"].startswith("ghcr.io/")

    icon_path = HUB_UI_ROOT / "public" / "module_default_icon.png"
    assert icon_path.is_file()
    png = icon_path.read_bytes()
    assert png.startswith(b"\x89PNG\r\n\x1a\n")

    offset = 8
    chunks: list[tuple[bytes, bytes]] = []
    while offset < len(png):
        length = struct.unpack(">I", png[offset : offset + 4])[0]
        chunk_type = png[offset + 4 : offset + 8]
        chunk_data = png[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", png[offset + 8 + length : offset + 12 + length])[0]
        actual_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        assert actual_crc == expected_crc, f"Invalid PNG CRC on chunk {chunk_type!r}"
        chunks.append((chunk_type, chunk_data))
        offset += 12 + length

    assert offset == len(png)
    assert chunks[0][0] == b"IHDR"
    assert chunks[-1][0] == b"IEND"
    width, height, bit_depth, color_type, comp, filt, interlace = struct.unpack(">IIBBBBB", chunks[0][1])
    assert (width, height, bit_depth, color_type, comp, filt, interlace) == (128, 128, 8, 6, 0, 0, 0)

    idat_bytes = b"".join(data for ctype, data in chunks if ctype == b"IDAT")
    raw_scanlines = zlib.decompress(idat_bytes)
    assert len(raw_scanlines) == 128 * (1 + 128 * 4)

    dist_dir = HUB_UI_ROOT / "dist"
    assert (dist_dir / "metadata.json").read_bytes() == meta_path.read_bytes()
    assert (dist_dir / "module_default_icon.png").read_bytes() == png


def test_extended_snmp_qnap_printer_and_roles_in_ui() -> None:
    """Verify qnap, printer, snmp-printer, and full SHA-2 SNMPv3 options across UI and schemas."""
    targets_src = (HUB_SRC_ROOT / "views" / "Targets.vue").read_text(encoding="utf-8")
    alerting_src = (HUB_SRC_ROOT / "views" / "Alerting.vue").read_text(encoding="utf-8")
    en_flat = _flatten_json_keys(
        json.loads((HUB_UI_ROOT / "public" / "i18n" / "en" / "translation.json").read_text(encoding="utf-8"))
    )
    de_flat = _flatten_json_keys(
        json.loads((HUB_UI_ROOT / "public" / "i18n" / "de" / "translation.json").read_text(encoding="utf-8"))
    )

    for token in ('"qnap"', '"printer"', '"snmp-printer"', '"SHA512"', '"SHA384"', '"SHA224"'):
        assert token in targets_src, f"Targets.vue missing {token}"
    assert '"snmp-printer"' in alerting_src

    for i18n_key in ("targets.roles.snmp-printer", "targets.snmp_modules.qnap", "targets.snmp_modules.printer"):
        assert i18n_key in en_flat and en_flat[i18n_key].strip()
        assert i18n_key in de_flat and de_flat[i18n_key].strip()

    save_target_schema = _load_schema("hub-save-target-input.json")
    for mod, role in (("qnap", "snmp-nas"), ("printer", "snmp-printer")):
        payload = {
            "id": "",
            "name": f"Target {mod}",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": role,
            "scrape_interval": "60s",
            "endpoints": ["10.20.0.50"],
            "snmp_module": mod,
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "snmp-monitor",
                "security_level": "authPriv",
                "auth_protocol": "SHA512",
                "auth_password": "AuthPassphrase123",
                "priv_protocol": "AES256",
                "priv_password": "PrivPassphrase123",
            },
        }
        jsonschema.validate(instance=payload, schema=save_target_schema)

    silence_schema = _load_schema("hub-create-silence-input.json")
    jsonschema.validate(
        instance={
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "snmp-printer",
            "starts_at": "2026-11-22T02:00:00Z",
            "ends_at": "2026-11-22T04:00:00Z",
            "created_by": "msp-admin",
            "comment": "Printer firmware update window",
        },
        schema=silence_schema,
    )


def test_v104_settings_ldap_multiselect_groups_users_and_tester() -> None:
    """Verify v1.0.4 AD/LDAP live group+user discovery, NsMultiSelect pickers, and interactive user tester."""
    pkg_data = json.loads((HUB_UI_ROOT / "package.json").read_text(encoding="utf-8"))
    cfg_data = json.loads((HUB_UI_ROOT / "public" / "config.json").read_text(encoding="utf-8"))
    assert pkg_data["version"] == "1.0.4"
    assert cfg_data["version"] == "1.0.4"

    settings_src = (HUB_SRC_ROOT / "views" / "Settings.vue").read_text(encoding="utf-8")
    for token in (
        '"discover-ldap-groups"',
        '"test-ldap-user"',
        "<NsMultiSelect",
        "ldap_admin_principals",
        "ldap_editor_principals",
        "ldap_viewer_principals",
        "ldap_viewer_group",
        "discoveredLdapGroups",
        "discoveredLdapUsers",
        "ldapOptionScope",
        "ldapMultiSelectOptionsFor",
        "normalizePrincipalsListWithDiscovered",
        "acceptUserInput",
        "showItemType",
        "member_of",
        "matched_role",
    ):
        assert token in settings_src, f"Settings.vue missing v1.0.4 token {token}"

    en_data = json.loads((HUB_UI_ROOT / "public" / "i18n" / "en" / "translation.json").read_text(encoding="utf-8"))
    de_data = json.loads((HUB_UI_ROOT / "public" / "i18n" / "de" / "translation.json").read_text(encoding="utf-8"))
    en_helper = en_data["settings"]["ldap_editor_group_helper"]
    de_helper = de_data["settings"]["ldap_editor_group_helper"]
    assert "denied" in en_helper.lower()
    assert "abgewiesen" in de_helper.lower()
    assert "{users}" in en_data["settings"]["ldap_discovered_summary"]
    assert "{users}" in de_data["settings"]["ldap_discovered_summary"]

    discover_out_schema = _load_schema("hub-discover-ldap-groups-output.json")
    jsonschema.validate(
        instance={
            "ok": True,
            "domain": "ad.bls-isp.net",
            "schema": "ad",
            "base_dn": "DC=ad,DC=bls-isp,DC=net",
            "groups": [
                {
                    "name": "Domain Admins",
                    "dn": "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
                    "description": "Designated administrators of the domain",
                }
            ],
            "users": [
                {
                    "username": "Genera",
                    "display_name": "Genera Admin",
                    "email": "genera@bls-isp.net",
                    "dn": "CN=Genera,CN=Users,DC=ad,DC=bls-isp,DC=net",
                }
            ],
            "error": "",
        },
        schema=discover_out_schema,
    )

    get_cfg_out_schema = _load_schema("hub-get-configuration-output.json")
    healthy_map = {
        "hub_gateway": "healthy",
        "prometheus": "healthy",
        "loki": "healthy",
        "grafana": "healthy",
        "alertmanager": "healthy",
        "prom_label_proxy": "healthy",
        "blackbox_exporter": "healthy",
        "snmp_exporter": "healthy",
        "thanos_sidecar": "disabled",
        "thanos_store": "disabled",
        "thanos_query": "disabled",
    }
    jsonschema.validate(
        instance={
            "configured": True,
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "retention_days": 30,
            "retention_size_gb": 50,
            "loki_retention_days": 30,
            "backup_include_tsdb": False,
            "storage_mode": "local",
            "s3": {
                "endpoint": "",
                "bucket": "",
                "region": "us-east-1",
                "access_key": "",
                "has_secret_key": False,
                "insecure": False,
                "path_style": True,
            },
            "ldap_enabled": True,
            "ldap_domain": "ad.bls-isp.net",
            "ldap_admin_group": "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
            "ldap_editor_group": "",
            "ldap_viewer_group": "",
            "ldap_admin_principals": [
                "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
                "CN=Genera,CN=Users,DC=ad,DC=bls-isp,DC=net",
            ],
            "ldap_editor_principals": [],
            "ldap_viewer_principals": [],
            "available_ldap_domains": ["ad.bls-isp.net"],
            "has_grafana_admin_password": True,
            "grafana_url": "https://monitoring.msp.example.com",
            "ingest_metrics_url": "https://monitoring.msp.example.com/api/v1/ingest/metrics",
            "ingest_logs_url": "https://monitoring.msp.example.com/api/v1/ingest/logs",
            "health": {
                "components": healthy_map,
                "active_tenants_count": 3,
                "active_targets_count": 12,
                "firing_alerts_count": 0,
                "active_silences_count": 1,
                "storage_usage_bytes": {
                    "prometheus_bytes": 1048576,
                    "loki_bytes": 2097152,
                    "grafana_bytes": 524288,
                    "total_bytes": 3670016,
                },
            },
        },
        schema=get_cfg_out_schema,
    )

    test_user_out_schema = _load_schema("hub-test-ldap-user-output.json")
    jsonschema.validate(
        instance={
            "ok": True,
            "found": True,
            "username": "Genera",
            "user_dn": "CN=Genera,CN=Users,DC=ad,DC=bls-isp,DC=net",
            "display_name": "Genera Admin",
            "email": "genera@bls-isp.net",
            "member_of": ["CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"],
            "matched_role": "Admin",
            "grafana_admin": True,
            "message": "Matched Org 1 Admin group.",
        },
        schema=test_user_out_schema,
    )


def test_v102_tenants_portal_explanation_and_multi_user_manager() -> None:
    """Verify v1.0.2 Customer Portal explanation bar, portal_users_count, and multi-user modal."""
    tenants_src = (HUB_SRC_ROOT / "views" / "Tenants.vue").read_text(encoding="utf-8")
    for required_token in (
        '"list-portal-users"',
        '"save-portal-user"',
        '"delete-portal-user"',
        "portal_users_count",
        "grafana_login_url",
        "grafana_org_name",
        "generateStrongPortalPassword",
        "getRandomValues",
        "copy_credentials_summary_btn",
        "password_unchanged",
    ):
        assert required_token in tenants_src, f"Tenants.vue missing {required_token}"

    list_users_out_schema = _load_schema("hub-list-portal-users-output.json")
    jsonschema.validate(
        instance={
            "customer": "acme-corp",
            "display_name": "ACME Corp",
            "customer_portal_enabled": True,
            "grafana_org_id": 4,
            "grafana_login_url": "https://monitoring.msp.example.com/login",
            "grafana_org_name": "Customer: ACME Corp (acme-corp)",
            "users": [
                {
                    "username": "acme-ceo",
                    "full_name": "Erika Musterfrau",
                    "email": "erika@acme.example.com",
                    "role": "Viewer",
                    "disabled": False,
                    "created_at": "2026-11-23T10:00:00Z",
                    "updated_at": "2026-11-23T10:00:00Z",
                },
                {
                    "username": "acme-devops",
                    "full_name": "Max Mustermann",
                    "email": "max@acme.example.com",
                    "role": "Editor",
                    "disabled": False,
                    "created_at": "2026-11-23T10:05:00Z",
                    "updated_at": "2026-11-23T10:05:00Z",
                },
            ],
        },
        schema=list_users_out_schema,
    )
