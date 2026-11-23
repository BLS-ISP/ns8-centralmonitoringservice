"""Automated contract tests for SPEC-telemetry-contract.md (`shared/`)."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "shared" / "schemas"
RULES_DIR = REPO_ROOT / "shared" / "rules"
DASHBOARDS_DIR = REPO_ROOT / "shared" / "dashboards"
TEMPLATES_DIR = REPO_ROOT / "shared" / "alloy-templates"

EXPECTED_RULE_PACKS = (
    "ns8-cluster.yml",
    "linux-node.yml",
    "windows-node.yml",
    "proxmox-ve.yml",
    "blackbox-web-ssl.yml",
    "snmp-network-ups.yml",
)

EXPECTED_DASHBOARDS = (
    "ns8-multi-cluster-overview.json",
    "linux-windows-servers.json",
    "proxmox-snmp-infrastructure.json",
    "web-ssl-uptime.json",
)

EXPECTED_TEMPLATES = (
    "config-linux.alloy.tmpl",
    "config-windows.alloy.tmpl",
    "config-docker.alloy.tmpl",
    "install-linux.sh.tmpl",
    "install-windows.ps1.tmpl",
    "docker-compose.yml.tmpl",
)

ALLOWED_PLACEHOLDERS = frozenset({
    "HUB_URL",
    "AUTH_TOKEN",
    "CUSTOMER",
    "SITE",
    "COLLECTOR_ID",
    "SYSLOG_PORT",
})


def _collect_refs(node: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                refs.append(value)
            else:
                refs.extend(_collect_refs(value))
    elif isinstance(node, list):
        for item in node:
            refs.extend(_collect_refs(item))
    return refs


def _load_schema(filename: str) -> dict[str, Any]:
    return json.loads((SCHEMAS_DIR / filename).read_text(encoding="utf-8"))


def test_all_57_shared_schemas_are_self_contained_draft07() -> None:
    schema_files = sorted(SCHEMAS_DIR.glob("*.json"))
    assert len(schema_files) == 57

    for path in schema_files:
        assert "get-status" not in path.name, f"Forbidden get-status override: {path.name}"
        raw = path.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM in {path.name}"
        assert b"\r\n" not in raw, f"CRLF in {path.name}"

        schema = json.loads(raw.decode("utf-8"))
        assert schema.get("$schema") == "http://json-schema.org/draft-07/schema#"
        jsonschema.Draft7Validator.check_schema(schema)

        for ref in _collect_refs(schema):
            assert ref.startswith("#/"), f"External $ref {ref!r} forbidden in {path.name}"


def test_schema_positive_and_negative_abuse_cases() -> None:
    hub_cfg_in = _load_schema("hub-configure-module-input.json")
    jsonschema.validate(
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "s3",
            "s3": {
                "endpoint": "minio.lan:9000",
                "bucket": "ns8-monitoring",
                "region": "eu-central-1",
                "access_key": "minioadmin",
                "secret_key": "supersecret",
                "insecure": False,
                "path_style": True,
            },
            "ldap_enabled": True,
            "ldap_domain": "ad.example.com",
        },
        hub_cfg_in,
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "host": "monitoring.msp.example.com",
                "lets_encrypt": True,
                "http2https": True,
                "storage_mode": "s3",
            },
            hub_cfg_in,
        )

    save_tenant_in = _load_schema("hub-save-tenant-input.json")
    jsonschema.validate(
        {
            "customer": "acme-corp",
            "display_name": "ACME Corp GmbH",
            "sites": ["hq", "branch-berlin"],
            "customer_portal_enabled": True,
            "portal_viewer_username": "acme-viewer",
            "portal_viewer_password": "StrongPassword123!",
        },
        save_tenant_in,
    )
    for bad_customer in ("Customer_A", "../etc/passwd", "ab", "-leading"):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(
                {
                    "customer": bad_customer,
                    "display_name": "Invalid",
                    "sites": ["hq"],
                    "customer_portal_enabled": False,
                },
                save_tenant_in,
            )

    del_silence_in = _load_schema("hub-delete-silence-input.json")
    jsonschema.validate({"silence_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}, del_silence_in)
    for bad_silence_id in ("../admin", "abc/def", "id?foo=1", "a b c d"):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"silence_id": bad_silence_id}, del_silence_in)


def test_v102_ldap_discovery_tester_and_multi_user_portal_schemas() -> None:
    hub_cfg_in = _load_schema("hub-configure-module-input.json")
    long_ad_dn = (
        "CN=MSP Central Monitoring ReadOnly Operations Group,"
        "OU=Role Based Access Control Groups,OU=Managed Services,"
        "DC=corp,DC=ad,DC=bls-isp,DC=net"
    )
    jsonschema.validate(
        {
            "host": "monitoring.bls-isp.net",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "ldap_enabled": True,
            "ldap_domain": "ad.bls-isp.net",
            "ldap_admin_group": "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
            "ldap_editor_group": "MSP Engineers",
            "ldap_viewer_group": long_ad_dn,
        },
        hub_cfg_in,
    )

    disc_in = _load_schema("hub-discover-ldap-groups-input.json")
    disc_out = _load_schema("hub-discover-ldap-groups-output.json")
    jsonschema.validate({"domain": "ad.bls-isp.net"}, disc_in)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"domain": ""}, disc_in)
    jsonschema.validate(
        {
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
            "error": "",
        },
        disc_out,
    )

    test_ldap_in = _load_schema("hub-test-ldap-user-input.json")
    test_ldap_out = _load_schema("hub-test-ldap-user-output.json")
    jsonschema.validate(
        {
            "domain": "ad.bls-isp.net",
            "username": "jdoe",
            "ldap_admin_group": "Domain Admins",
            "ldap_editor_group": "MSP Engineers",
            "ldap_viewer_group": long_ad_dn,
        },
        test_ldap_in,
    )
    jsonschema.validate(
        {
            "ok": True,
            "found": True,
            "username": "jdoe",
            "user_dn": "CN=Jane Doe,OU=Staff,DC=ad,DC=bls-isp,DC=net",
            "display_name": "Jane Doe",
            "email": "jdoe@bls-isp.net",
            "member_of": [long_ad_dn],
            "matched_role": "Viewer",
            "grafana_admin": False,
            "message": "Matched Viewer role via ldap_viewer_group",
        },
        test_ldap_out,
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "ok": True,
                "found": True,
                "username": "jdoe",
                "user_dn": "CN=Jane Doe,DC=ad,DC=bls-isp,DC=net",
                "display_name": "Jane Doe",
                "email": "jdoe@bls-isp.net",
                "member_of": [],
                "matched_role": "SuperAdmin",
                "grafana_admin": True,
                "message": "Invalid enum",
            },
            test_ldap_out,
        )

    # Tenant saving with customer_portal_enabled=True and empty portal_viewer_username (multi-user flow)
    save_tenant_in = _load_schema("hub-save-tenant-input.json")
    jsonschema.validate(
        {
            "customer": "acme-corp",
            "display_name": "ACME Corp GmbH",
            "sites": ["hq"],
            "customer_portal_enabled": True,
            "portal_viewer_username": "",
            "portal_viewer_password": "",
        },
        save_tenant_in,
    )

    list_tenants_out = _load_schema("hub-list-tenants-output.json")
    jsonschema.validate(
        {
            "tenants": [
                {
                    "customer": "acme-corp",
                    "display_name": "ACME Corp GmbH",
                    "sites": ["hq"],
                    "contact_emails": [],
                    "token_prefix": "cms_v1_abcd...",
                    "token_created_at": "2026-11-23T10:00:00Z",
                    "customer_portal_enabled": True,
                    "grafana_org_id": 2,
                    "grafana_org_name": "Customer: ACME Corp GmbH (acme-corp)",
                    "grafana_login_url": "https://monitoring.bls-isp.net/login",
                    "portal_viewer_username": "acme-ops",
                    "portal_users_count": 2,
                    "notes": "",
                    "created_at": "2026-11-23T10:00:00Z",
                    "updated_at": "2026-11-23T10:05:00Z",
                }
            ],
            "pagination": {"page": 1, "page_size": 100, "total_items": 1, "total_pages": 1},
        },
        list_tenants_out,
    )

    list_pu_in = _load_schema("hub-list-portal-users-input.json")
    list_pu_out = _load_schema("hub-list-portal-users-output.json")
    save_pu_in = _load_schema("hub-save-portal-user-input.json")
    save_pu_out = _load_schema("hub-save-portal-user-output.json")
    del_pu_in = _load_schema("hub-delete-portal-user-input.json")
    del_pu_out = _load_schema("hub-delete-portal-user-output.json")

    jsonschema.validate({"customer": "acme-corp"}, list_pu_in)
    user_obj = {
        "username": "acme.cto",
        "full_name": "ACME CTO",
        "email": "cto@acme.de",
        "role": "Editor",
        "disabled": False,
        "created_at": "2026-11-23T10:00:00Z",
        "updated_at": "2026-11-23T10:05:00Z",
    }
    jsonschema.validate(
        {
            "customer": "acme-corp",
            "display_name": "ACME Corp GmbH",
            "customer_portal_enabled": True,
            "grafana_login_url": "https://monitoring.bls-isp.net/login",
            "grafana_org_name": "Customer: ACME Corp GmbH (acme-corp)",
            "users": [user_obj],
        },
        list_pu_out,
    )

    # Create user requires >= 10 char password when password_unchanged is omitted/false
    jsonschema.validate(
        {
            "customer": "acme-corp",
            "username": "acme.cto",
            "full_name": "ACME CTO",
            "email": "cto@acme.de",
            "role": "Editor",
            "disabled": False,
            "password": "VerySecurePortalPassword!",
            "password_unchanged": False,
        },
        save_pu_in,
    )
    # Edit user with password_unchanged=True allows empty password
    jsonschema.validate(
        {
            "customer": "acme-corp",
            "username": "acme.cto",
            "role": "Viewer",
            "password": "",
            "password_unchanged": True,
        },
        save_pu_in,
    )
    # Reject missing/short password on create, Admin role escalation, or invalid username chars
    for bad_pu in (
        {"customer": "acme-corp", "username": "acme.cto", "role": "Viewer", "password": "short"},
        {"customer": "acme-corp", "username": "acme.cto", "role": "Viewer", "password": "", "password_unchanged": False},
        {"customer": "acme-corp", "username": "acme.cto", "role": "Admin", "password": "VerySecurePortalPassword!"},
        {"customer": "acme-corp", "username": "bad space", "role": "Viewer", "password": "VerySecurePortalPassword!"},
    ):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad_pu, save_pu_in)

    jsonschema.validate(
        {
            "status": "saved",
            "customer": "acme-corp",
            "grafana_login_url": "https://monitoring.bls-isp.net/login",
            "grafana_org_name": "Customer: ACME Corp GmbH (acme-corp)",
            "grafana_synced": True,
            "user": user_obj,
        },
        save_pu_out,
    )
    jsonschema.validate({"customer": "acme-corp", "username": "acme.cto"}, del_pu_in)
    jsonschema.validate(
        {"status": "deleted", "customer": "acme-corp", "username": "acme.cto", "grafana_synced": True},
        del_pu_out,
    )


def test_snmp_v3_roundtrip_metadata_in_hub_and_collector_list_targets_outputs() -> None:
    hub_out = _load_schema("hub-list-targets-output.json")
    jsonschema.validate(
        {
            "targets": [
                {
                    "id": "tgt-snmp-v3",
                    "name": "Core Switch",
                    "enabled": True,
                    "target_type": "snmp",
                    "customer": "acme-corp",
                    "site": "hq",
                    "device_role": "snmp-network",
                    "scrape_interval": "30s",
                    "endpoints": ["10.10.0.1"],
                    "snmp_module": "if_mib",
                    "snmp_version": "v3",
                    "has_secret": True,
                    "snmp_v3": {
                        "username": "monitoring-ro",
                        "security_level": "authPriv",
                        "auth_protocol": "SHA256",
                        "priv_protocol": "AES",
                    },
                }
            ],
            "pagination": {"page": 1, "page_size": 100, "total_items": 1, "total_pages": 1},
        },
        hub_out,
    )
    # Reject accidental secret leakage inside snmp_v3 output
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "targets": [
                    {
                        "id": "tgt-snmp-v3",
                        "name": "Core Switch",
                        "enabled": True,
                        "target_type": "snmp",
                        "customer": "acme-corp",
                        "site": "hq",
                        "device_role": "snmp-network",
                        "scrape_interval": "30s",
                        "endpoints": ["10.10.0.1"],
                        "snmp_v3": {
                            "username": "monitoring-ro",
                            "security_level": "authPriv",
                            "auth_password": "leaked-secret",
                        },
                    }
                ],
                "pagination": {"page": 1, "page_size": 100, "total_items": 1, "total_pages": 1},
            },
            hub_out,
        )

    col_out = _load_schema("collector-list-local-targets-output.json")
    jsonschema.validate(
        {
            "targets": [
                {
                    "id": "lan-ups-01",
                    "name": "APC Smart-UPS",
                    "enabled": True,
                    "target_type": "snmp",
                    "device_role": "snmp-ups",
                    "host": "192.168.10.50",
                    "port": 161,
                    "scrape_interval": "30s",
                    "snmp_module": "apcupsd",
                    "snmp_version": "v3",
                    "has_snmp_secret": True,
                    "snmp_v3": {
                        "username": "snmp-ups",
                        "security_level": "authNoPriv",
                        "auth_protocol": "SHA512",
                    },
                }
            ]
        },
        col_out,
    )


def test_extended_snmp_profiles_qnap_and_printer_consistency() -> None:
    contract = _load_schema("telemetry-contract.schema.json")
    canonical_roles = set(contract["definitions"]["deviceRole"]["enum"])
    canonical_snmp = set(contract["definitions"]["snmpModule"]["enum"])
    assert "snmp-printer" in canonical_roles
    assert {"qnap", "printer"}.issubset(canonical_snmp)

    hub_save_in = _load_schema("hub-save-target-input.json")
    hub_list_out = _load_schema("hub-list-targets-output.json")
    hub_silence_in = _load_schema("hub-create-silence-input.json")
    col_save_in = _load_schema("collector-save-local-target-input.json")
    col_list_out = _load_schema("collector-list-local-targets-output.json")

    assert set(hub_save_in["properties"]["device_role"]["enum"]) == canonical_roles
    assert set(hub_list_out["properties"]["targets"]["items"]["properties"]["device_role"]["enum"]) == canonical_roles
    assert set(hub_silence_in["properties"]["device_role"]["enum"]) == canonical_roles | {""}
    assert set(col_save_in["properties"]["device_role"]["enum"]) == canonical_roles
    assert set(col_list_out["properties"]["targets"]["items"]["properties"]["device_role"]["enum"]) == canonical_roles

    for mod, role in (("qnap", "snmp-nas"), ("printer", "snmp-printer")):
        jsonschema.validate(
            {
                "name": f"Target {mod}",
                "enabled": True,
                "target_type": "snmp",
                "customer": "acme-corp",
                "site": "hq",
                "device_role": role,
                "endpoints": ["10.20.30.40"],
                "snmp_module": mod,
                "snmp_version": "v2c",
            },
            hub_save_in,
        )
        jsonschema.validate(
            {
                "name": f"Local {mod}",
                "enabled": True,
                "target_type": "snmp",
                "device_role": role,
                "host": "192.168.1.55",
                "snmp_module": mod,
                "snmp_version": "v2c",
            },
            col_save_in,
        )


def _check_balanced_promql(expr: str) -> None:
    sanitized = re.sub(r'"(?:\\.|[^"\\])*"', '""', expr)
    stack: list[str] = []
    closing = {")": "(", "}": "{", "]": "["}
    for ch in sanitized:
        if ch in "({[":
            stack.append(ch)
        elif ch in closing:
            assert stack and stack[-1] == closing[ch], f"Unbalanced {ch!r} in PromQL: {expr}"
            stack.pop()
    assert not stack, f"Unclosed {stack} in PromQL: {expr}"


def test_all_6_prometheus_rule_packs_preserve_tenant_labels_and_categories() -> None:
    contract = _load_schema("telemetry-contract.schema.json")
    allowed_severities = set(contract["definitions"]["alertSeverity"]["enum"])
    allowed_categories = set(contract["definitions"]["alertCategory"]["enum"])

    for filename in EXPECTED_RULE_PACKS:
        path = RULES_DIR / filename
        assert path.is_file(), f"Missing rule pack: {filename}"
        raw = path.read_bytes()
        assert b"\r\n" not in raw
        text = raw.decode("utf-8")

        alerts = re.split(r"\n\s*-\s+alert:\s+", text)[1:]
        assert alerts, f"No alerts found in {filename}"

        for block in alerts:
            alert_name = block.splitlines()[0].strip()
            sev_match = re.search(r"^\s+severity:\s*(\S+)", block, re.MULTILINE)
            cat_match = re.search(r"^\s+category:\s*(\S+)", block, re.MULTILINE)
            assert sev_match and sev_match.group(1).strip("\"'") in allowed_severities, (
                f"{filename}:{alert_name} invalid severity"
            )
            assert cat_match and cat_match.group(1).strip("\"'") in allowed_categories, (
                f"{filename}:{alert_name} invalid category"
            )
            assert "summary:" in block and "description:" in block, (
                f"{filename}:{alert_name} missing summary/description annotation"
            )
            assert "$labels.customer" in block and "$labels.site" in block, (
                f"{filename}:{alert_name} annotations must reference customer and site labels"
            )

            for by_clause in re.findall(r"\b(?:by|on)\s*\(([^)]+)\)", block):
                grouped_labels = {lbl.strip() for lbl in by_clause.split(",")}
                assert {"customer", "site"}.issubset(grouped_labels), (
                    f"{filename}:{alert_name} clause ({by_clause}) drops customer/site labels"
                )

            _check_balanced_promql(block)


def _collect_ds_uids(node: Any) -> set[str]:
    uids: set[str] = set()
    if isinstance(node, dict):
        ds = node.get("datasource")
        if isinstance(ds, dict) and isinstance(ds.get("uid"), str):
            uids.add(ds["uid"])
        for val in node.values():
            uids.update(_collect_ds_uids(val))
    elif isinstance(node, list):
        for item in node:
            uids.update(_collect_ds_uids(item))
    return uids


def test_all_4_grafana_dashboards_conform_to_multi_org_contract() -> None:
    allowed_uids = {"prometheus", "loki", "-- Grafana --", "$datasource", "${datasource}"}
    for filename in EXPECTED_DASHBOARDS:
        path = DASHBOARDS_DIR / filename
        assert path.is_file(), f"Missing dashboard: {filename}"
        raw = path.read_bytes()
        assert b"\r\n" not in raw
        doc = json.loads(raw.decode("utf-8"))

        assert doc.get("schemaVersion", 0) >= 39
        assert isinstance(doc.get("panels"), list) and len(doc["panels"]) > 0

        vars_list = doc.get("templating", {}).get("list", [])
        var_names = {v.get("name") for v in vars_list if isinstance(v, dict)}
        assert {"customer", "site"}.issubset(var_names), f"{filename} missing $customer/$site"

        found_uids = _collect_ds_uids(doc["panels"])
        assert found_uids.issubset(allowed_uids), f"{filename} unexpected UIDs: {found_uids - allowed_uids}"


def test_all_6_standalone_alloy_templates_have_valid_placeholders_and_sinks() -> None:
    for filename in EXPECTED_TEMPLATES:
        path = TEMPLATES_DIR / filename
        assert path.is_file(), f"Missing Alloy template: {filename}"
        raw = path.read_bytes()
        assert b"\r\n" not in raw
        text = raw.decode("utf-8")

        assert text.count("{{") == text.count("}}")
        placeholders = set(re.findall(r"\{\{(.*?)\}\}", text))
        assert placeholders, f"{filename} has no placeholders"
        assert placeholders.issubset(ALLOWED_PLACEHOLDERS), (
            f"{filename} unknown placeholders: {placeholders - ALLOWED_PLACEHOLDERS}"
        )

        if filename.endswith(".alloy.tmpl"):
            assert "prometheus.remote_write" in text
            assert "loki.write" in text
            assert "{{CUSTOMER}}" in text and "{{SITE}}" in text and "{{COLLECTOR_ID}}" in text
