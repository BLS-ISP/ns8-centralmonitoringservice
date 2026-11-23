"""End-to-end tests for hub-core NS8 actions, events, update-module.d, and cross-module hooks."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from tests.hub_core.conftest import (
    IMAGEROOT,
    FakeNS8Env,
    execute_script,
    validate_against_schema,
)


def test_create_module_initializes_env_and_flushes_dump_env(ns8_env: FakeNS8Env) -> None:
    exit_code, _, stderr = execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    assert exit_code == 0, stderr

    # NS8 Rule #2: dump_env() must be called after the last set_env()
    ops = [op for op, _ in ns8_env.call_log if op in ("set_env", "dump_env")]
    assert ops and ops[-1] == "dump_env"
    assert ns8_env.persisted_env["STORAGE_MODE"] == "local"
    assert ns8_env.persisted_env["PROMQL_UPSTREAM_URL"] == "http://127.0.0.1:9090"
    assert (ns8_env.state_dir / "secrets.env").exists()


def test_01hostname_validation_rejects_colliding_domain_with_exit_code_2(ns8_env: FakeNS8Env) -> None:
    ns8_env.routes_in_use.add("taken.msp.example.com")

    payload = {
        "host": "taken.msp.example.com",
        "lets_encrypt": True,
        "http2https": True,
        "storage_mode": "local",
    }
    validate_against_schema("hub-configure-module-input.json", payload)

    exit_code, stdout, _ = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "01hostname-validation",
        payload=payload,
    )
    assert exit_code == 2
    assert ns8_env.status == "validation-failed"
    errors = json.loads(stdout)
    assert errors == [
        {
            "field": "host",
            "parameter": "host",
            "value": "taken.msp.example.com",
            "error": "domain_already_used",
        }
    ]


def test_01hostname_validation_allows_unchanged_domain_on_reconfigure(ns8_env: FakeNS8Env) -> None:
    ns8_env.set_env("TRAEFIK_HOST", "monitoring.msp.example.com")
    ns8_env.dump_env()
    ns8_env.routes_in_use.add("monitoring.msp.example.com")

    payload = {
        "host": "Monitoring.MSP.Example.com",
        "lets_encrypt": True,
        "http2https": True,
        "storage_mode": "local",
    }
    exit_code, stdout, stderr = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "01hostname-validation",
        payload=payload,
    )
    assert exit_code == 0, stderr
    assert stdout.strip() == ""


def test_configure_module_local_and_s3_lifecycle_and_hooks(
    ns8_env: FakeNS8Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")

    # Install spy modules for hub_tenancy and hub_alerting integration hooks
    hook_calls: list[str] = []
    tenancy_pkg = types.ModuleType("hub_tenancy")
    ldap_mod = types.ModuleType("hub_tenancy.ldap_sync")
    graf_mod = types.ModuleType("hub_tenancy.grafana_sync")
    alert_pkg = types.ModuleType("hub_alerting")
    am_mod = types.ModuleType("hub_alerting.alertmanager_config")

    ldap_mod.sync_ldap_config = lambda state_dir, env: hook_calls.append("sync_ldap_config")  # type: ignore[attr-defined]
    graf_mod.sync_all_orgs_if_running = lambda state_dir, env: hook_calls.append("sync_all_orgs_if_running")  # type: ignore[attr-defined]
    am_mod.sync_alertmanager = lambda state_dir: hook_calls.append("sync_alertmanager")  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "hub_tenancy", tenancy_pkg)
    monkeypatch.setitem(sys.modules, "hub_tenancy.ldap_sync", ldap_mod)
    monkeypatch.setitem(sys.modules, "hub_tenancy.grafana_sync", graf_mod)
    monkeypatch.setitem(sys.modules, "hub_alerting", alert_pkg)
    monkeypatch.setitem(sys.modules, "hub_alerting.alertmanager_config", am_mod)

    local_payload = {
        "host": "monitoring.msp.example.com",
        "lets_encrypt": True,
        "http2https": True,
        "retention_days": 30,
        "retention_size_gb": 50,
        "loki_retention_days": 30,
        "backup_include_tsdb": False,
        "storage_mode": "local",
        "ldap_enabled": True,
        "ldap_domain": "ad.msp.example.com",
        "ldap_admin_group": "MSP-Monitoring-Admins",
        "ldap_editor_group": "MSP-Technicians",
        "grafana_admin_password": "StrongAdminPassword!2026",
    }
    validate_against_schema("hub-configure-module-input.json", local_payload)

    rc_20, out_20, err_20 = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload=local_payload,
    )
    assert rc_20 == 0, err_20
    resp_20 = json.loads(out_20)
    validate_against_schema("hub-configure-module-output.json", resp_20)
    assert resp_20 == {
        "status": "ok",
        "grafana_url": "https://monitoring.msp.example.com",
        "ingest_metrics_url": "https://monitoring.msp.example.com/api/v1/write",
        "ingest_logs_url": "https://monitoring.msp.example.com/loki/api/v1/push",
        "storage_mode": "local",
    }

    assert "sync_ldap_config" in hook_calls
    assert "sync_all_orgs_if_running" in hook_calls
    assert "sync_alertmanager" in hook_calls

    rc_80, _, err_80 = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "80start_services",
        payload=local_payload,
    )
    assert rc_80 == 0, err_80
    assert ns8_env.systemctl_state.get("central-monitoring-hub.service") == "active"
    assert ns8_env.systemctl_state.get("prometheus.service") == "active"
    assert ns8_env.systemctl_state.get("thanos-sidecar.service") == "inactive"
    assert ns8_env.systemctl_state.get("thanos-store.service") == "inactive"
    assert ns8_env.systemctl_state.get("thanos-query.service") == "inactive"

    # Switch to S3 mode and verify Thanos units become active!
    s3_payload = {
        "host": "monitoring.msp.example.com",
        "lets_encrypt": True,
        "http2https": True,
        "retention_days": 14,
        "retention_size_gb": 50,
        "loki_retention_days": 180,
        "backup_include_tsdb": True,
        "storage_mode": "s3",
        "s3": {
            "endpoint": "minio.msp.internal:9000",
            "bucket": "central-monitoring-prod",
            "region": "eu-central-1",
            "access_key": "AKIA_PROD_KEY",
            "secret_key": "SUPER_SECRET_S3_KEY_DO_NOT_LEAK",
            "secret_key_unchanged": False,
            "insecure": False,
            "path_style": True,
        },
        "ldap_enabled": True,
        "ldap_domain": "ad.msp.example.com",
        "grafana_admin_password": "",
    }
    validate_against_schema("hub-configure-module-input.json", s3_payload)

    rc_20_s3, out_20_s3, err_20_s3 = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload=s3_payload,
    )
    assert rc_20_s3 == 0, err_20_s3
    resp_20_s3 = json.loads(out_20_s3)
    validate_against_schema("hub-configure-module-output.json", resp_20_s3)
    assert resp_20_s3["storage_mode"] == "s3"

    rc_80_s3, _, err_80_s3 = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "80start_services",
        payload=s3_payload,
    )
    assert rc_80_s3 == 0, err_80_s3
    assert ns8_env.systemctl_state.get("thanos-sidecar.service") == "active"
    assert ns8_env.systemctl_state.get("thanos-store.service") == "active"
    assert ns8_env.systemctl_state.get("thanos-query.service") == "active"


def test_get_configuration_and_get_overview_validate_schemas_and_redact_secrets(
    ns8_env: FakeNS8Env,
) -> None:
    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    s3_secret = "ULTRA_SENSITIVE_S3_SECRET_999"
    admin_pw = "ULTRA_SENSITIVE_GRAFANA_PW_999"

    execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload={
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "retention_days": 30,
            "retention_size_gb": 50,
            "loki_retention_days": 60,
            "backup_include_tsdb": False,
            "storage_mode": "s3",
            "s3": {
                "endpoint": "s3.eu-central-1.amazonaws.com",
                "bucket": "msp-telemetry-bucket",
                "region": "eu-central-1",
                "access_key": "AKIA_MSP",
                "secret_key": s3_secret,
                "secret_key_unchanged": False,
                "insecure": False,
                "path_style": False,
            },
            "ldap_enabled": True,
            "ldap_domain": "ad.msp.example.com",
            "grafana_admin_password": admin_pw,
        },
    )

    # Seed state JSON files to test overview & health aggregations
    (ns8_env.state_dir / "tenants.json").write_text(
        json.dumps(
            {
                "tenants": [
                    {"customer": "acme-corp", "customer_portal_enabled": True},
                    {"customer": "beta-gmbh", "customer_portal_enabled": False},
                ]
            }
        ),
        encoding="utf-8",
    )
    (ns8_env.state_dir / "targets.json").write_text(
        json.dumps(
            {
                "targets": [
                    {"id": "t1", "enabled": True},
                    {"id": "t2", "enabled": True},
                    {"id": "t3", "enabled": False},
                ]
            }
        ),
        encoding="utf-8",
    )
    (ns8_env.state_dir / "silences.json").write_text(
        json.dumps(
            {
                "silences": [
                    {"id": "s1", "state": "active"},
                    {"id": "s2", "state": "expired"},
                ]
            }
        ),
        encoding="utf-8",
    )

    rc_cfg, out_cfg, err_cfg = execute_script(
        IMAGEROOT / "actions" / "get-configuration" / "20read",
        payload={},
    )
    assert rc_cfg == 0, err_cfg
    assert s3_secret not in out_cfg
    assert admin_pw not in out_cfg

    cfg_data = json.loads(out_cfg)
    validate_against_schema("hub-get-configuration-output.json", cfg_data)
    assert cfg_data["configured"] is True
    assert cfg_data["s3"]["has_secret_key"] is True
    assert cfg_data["has_grafana_admin_password"] is True
    assert cfg_data["available_ldap_domains"] == ["ad.msp.example.com"]
    assert cfg_data["health"]["active_tenants_count"] == 2
    assert cfg_data["health"]["active_targets_count"] == 2
    assert cfg_data["health"]["active_silences_count"] == 1

    rc_ov, out_ov, err_ov = execute_script(
        IMAGEROOT / "actions" / "get-overview" / "20read",
        payload={},
    )
    assert rc_ov == 0, err_ov
    ov_data = json.loads(out_ov)
    validate_against_schema("hub-get-overview-output.json", ov_data)
    assert ov_data["storage_mode"] == "s3"
    assert ov_data["s3_bucket"] == "msp-telemetry-bucket"
    assert ov_data["counts"]["tenants"] == 2
    assert ov_data["counts"]["portal_enabled_tenants"] == 1
    assert ov_data["counts"]["central_targets"] == 2
    assert ov_data["counts"]["active_silences"] == 1


def test_events_smarthost_user_domain_destroy_and_pull_images(
    ns8_env: FakeNS8Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    ns8_env.set_env("TRAEFIK_HOST", "monitoring.msp.example.com")
    ns8_env.dump_env()

    events_triggered: list[str] = []
    tenancy_pkg = types.ModuleType("hub_tenancy")
    ldap_mod = types.ModuleType("hub_tenancy.ldap_sync")
    alert_pkg = types.ModuleType("hub_alerting")
    am_mod = types.ModuleType("hub_alerting.alertmanager_config")
    ldap_mod.sync_ldap_config = lambda s, e: events_triggered.append("ldap_sync")  # type: ignore[attr-defined]
    am_mod.sync_alertmanager = lambda s: events_triggered.append("am_sync")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hub_tenancy", tenancy_pkg)
    monkeypatch.setitem(sys.modules, "hub_tenancy.ldap_sync", ldap_mod)
    monkeypatch.setitem(sys.modules, "hub_alerting", alert_pkg)
    monkeypatch.setitem(sys.modules, "hub_alerting.alertmanager_config", am_mod)

    rc_sh, _, err_sh = execute_script(IMAGEROOT / "events" / "smarthost-changed" / "10reload_services")
    assert rc_sh == 0, err_sh
    smarthost_env = ns8_env.read_envfile(ns8_env.state_dir / "smarthost.env")
    assert smarthost_env["SMARTHOST_HOST"] == "mail.msp.internal"
    assert smarthost_env["SMARTHOST_PORT"] == "587"
    assert "am_sync" in events_triggered

    rc_ud, _, err_ud = execute_script(IMAGEROOT / "events" / "user-domain-changed" / "10handler")
    assert rc_ud == 0, err_ud
    assert "ldap_sync" in events_triggered

    rc_up, _, err_up = execute_script(IMAGEROOT / "update-module.d" / "20pull_images")
    assert rc_up == 0, err_up
    pulled = [args for args in ns8_env.helper_calls if len(args) >= 2 and args[:2] == ("podman", "pull")]
    assert len(pulled) == 9

    rc_rm, _, err_rm = execute_script(IMAGEROOT / "actions" / "destroy-module" / "20destroy")
    assert rc_rm == 0, err_rm
    del_routes = [c for c in ns8_env.task_calls if c["action"] == "delete-route"]
    assert len(del_routes) == 1
    assert del_routes[0]["data"]["instance"] == "central-monitoring-hub1"


def test_v102_ldap_viewer_group_persistence_and_live_grafana_ldap_reload(
    ns8_env: FakeNS8Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64

    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")

    reload_calls: list[tuple[str, str, dict[str, str]]] = []

    def spy_pod_http_request(
        url: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 2.0,
        **kwargs: Any,
    ) -> tuple[int, bytes] | None:
        reload_calls.append((method, url, dict(headers or {})))
        return 200, b'{"message":"LDAP config reloaded"}'

    import hub_core.pod_http

    monkeypatch.setattr(hub_core.pod_http, "pod_http_request", spy_pod_http_request)

    admin_dn = "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"
    editor_dn = "CN=MSP-Engineers,OU=Groups,DC=ad,DC=bls-isp,DC=net"
    viewer_dn = "CN=MSP-Viewers,OU=Groups,DC=ad,DC=bls-isp,DC=net"
    admin_pw = "GrafanaAdminPw!102"

    payload = {
        "host": "monitoring.bls-isp.net",
        "lets_encrypt": True,
        "http2https": True,
        "storage_mode": "local",
        "ldap_enabled": True,
        "ldap_domain": "ad.msp.example.com",
        "ldap_admin_group": admin_dn,
        "ldap_editor_group": editor_dn,
        "ldap_viewer_group": viewer_dn,
        "grafana_admin_password": admin_pw,
    }
    validate_against_schema("hub-configure-module-input.json", payload)

    rc_cfg, out_cfg, err_cfg = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload=payload,
    )
    assert rc_cfg == 0, err_cfg
    validate_against_schema("hub-configure-module-output.json", json.loads(out_cfg))
    assert ns8_env.persisted_env["LDAP_ADMIN_GROUP"] == admin_dn
    assert ns8_env.persisted_env["LDAP_EDITOR_GROUP"] == editor_dn
    assert ns8_env.persisted_env["LDAP_VIEWER_GROUP"] == viewer_dn

    expected_basic = "Basic " + base64.b64encode(f"admin:{admin_pw}".encode("utf-8")).decode("ascii")
    ldap_reloads = [
        hdrs
        for method, url, hdrs in reload_calls
        if method == "POST" and url == "http://127.0.0.1:3000/api/admin/provisioning/ldap/reload"
    ]
    assert len(ldap_reloads) >= 1
    assert ldap_reloads[-1].get("Authorization") == expected_basic

    rc_read, out_read, err_read = execute_script(
        IMAGEROOT / "actions" / "get-configuration" / "20read",
        payload={},
    )
    assert rc_read == 0, err_read
    read_doc = json.loads(out_read)
    validate_against_schema("hub-get-configuration-output.json", read_doc)
    assert read_doc["ldap_admin_group"] == admin_dn
    assert read_doc["ldap_editor_group"] == editor_dn
    assert read_doc["ldap_viewer_group"] == viewer_dn

    # Also verify user-domain-changed event triggers live Grafana LDAP reload
    reload_calls.clear()
    rc_ev, _, err_ev = execute_script(IMAGEROOT / "events" / "user-domain-changed" / "10handler")
    assert rc_ev == 0, err_ev
    ev_reloads = [
        hdrs
        for method, url, hdrs in reload_calls
        if method == "POST" and url == "http://127.0.0.1:3000/api/admin/provisioning/ldap/reload"
    ]
    assert len(ev_reloads) >= 1
    assert ev_reloads[-1].get("Authorization") == expected_basic


def test_in_place_update_module_upgrades_gateway_image_rerenders_configs_and_restarts_pod(
    ns8_env: FakeNS8Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload={
            "host": "monitoring.bls-isp.net",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "ldap_enabled": True,
            "ldap_domain": "ad.msp.example.com",
        },
    )

    # Simulate pre-existing v1.0.1 state before update-module
    ns8_env.set_env(
        "CENTRAL_MONITORING_HUB_GATEWAY_IMAGE",
        "ghcr.io/bls-isp/central-monitoring-hub-gateway:1.0.1",
    )
    ns8_env.unset_env("LDAP_VIEWER_GROUP")
    ns8_env.dump_env()
    (ns8_env.config_dir / "grafana" / "grafana.ini").write_bytes(b"[server]\nhttp_port = 3000\n")

    # Simulate newly unpacked v1.0.2 defaults.env
    (ns8_env.etc_dir / "defaults.env").write_bytes(
        b"CENTRAL_MONITORING_HUB_GATEWAY_IMAGE=ghcr.io/bls-isp/central-monitoring-hub-gateway:1.0.2\n"
    )
    ns8_env.helper_calls.clear()
    ns8_env.systemctl_state.clear()

    hooks_called: list[str] = []
    tenancy_pkg = types.ModuleType("hub_tenancy")
    ldap_mod = types.ModuleType("hub_tenancy.ldap_sync")
    graf_mod = types.ModuleType("hub_tenancy.grafana_sync")
    alert_pkg = types.ModuleType("hub_alerting")
    am_mod = types.ModuleType("hub_alerting.alertmanager_config")
    ldap_mod.sync_ldap_config = lambda s, e=None: hooks_called.append("ldap_sync")  # type: ignore[attr-defined]
    graf_mod.sync_all_orgs_if_running = lambda s, e=None: hooks_called.append("grafana_orgs")  # type: ignore[attr-defined]
    am_mod.render_all_probe_configs = lambda s: hooks_called.append("probe_configs")  # type: ignore[attr-defined]
    am_mod.sync_alertmanager = lambda s: hooks_called.append("am_sync")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hub_tenancy", tenancy_pkg)
    monkeypatch.setitem(sys.modules, "hub_tenancy.ldap_sync", ldap_mod)
    monkeypatch.setitem(sys.modules, "hub_tenancy.grafana_sync", graf_mod)
    monkeypatch.setitem(sys.modules, "hub_alerting", alert_pkg)
    monkeypatch.setitem(sys.modules, "hub_alerting.alertmanager_config", am_mod)

    rc_pull, _, err_pull = execute_script(IMAGEROOT / "update-module.d" / "20pull_images")
    assert rc_pull == 0, err_pull
    assert (
        ns8_env.persisted_env["CENTRAL_MONITORING_HUB_GATEWAY_IMAGE"]
        == "ghcr.io/bls-isp/central-monitoring-hub-gateway:1.0.2"
    )
    assert ns8_env.persisted_env["LDAP_VIEWER_GROUP"] == ""
    assert (
        "podman",
        "pull",
        "ghcr.io/bls-isp/central-monitoring-hub-gateway:1.0.2",
    ) in ns8_env.helper_calls

    rc_upd, _, err_upd = execute_script(IMAGEROOT / "update-module.d" / "50update")
    assert rc_upd == 0, err_upd
    updated_ini = (ns8_env.config_dir / "grafana" / "grafana.ini").read_text(encoding="utf-8")
    assert "[unified_alerting]\nenabled = false" in updated_ini
    assert {"ldap_sync", "probe_configs", "am_sync", "grafana_orgs"} <= set(hooks_called)
    assert ns8_env.systemctl_state.get("central-monitoring-hub.service") == "active"
    assert ns8_env.systemctl_state.get("grafana.service") == "active"
    assert ns8_env.systemctl_state.get("hub-gateway.service") == "active"


def test_v104_multi_principal_configure_read_and_update_module_backfill(
    ns8_env: FakeNS8Env,
) -> None:
    from hub_core.env_store import decode_ldap_principals

    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    assert decode_ldap_principals(
        ns8_env.persisted_env,
        "LDAP_ADMIN_PRINCIPALS_B64",
        "LDAP_ADMIN_GROUP",
    ) == ["Domain Admins"]
    assert decode_ldap_principals(
        ns8_env.persisted_env,
        "LDAP_EDITOR_PRINCIPALS_B64",
        "LDAP_EDITOR_GROUP",
    ) == []

    admin_principals = [
        "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
        "CN=Genera,CN=Users,DC=ad,DC=bls-isp,DC=net",
    ]
    editor_principals = [
        "CN=MSP-Engineers,OU=Groups,DC=ad,DC=bls-isp,DC=net",
    ]
    viewer_principals = [
        "CN=MSP-Support,OU=Groups,DC=ad,DC=bls-isp,DC=net",
        "CN=j.doe,CN=Users,DC=ad,DC=bls-isp,DC=net",
    ]

    rc_cfg, _, err_cfg = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload={
            "host": "monitoring.bls-isp.net",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "ldap_enabled": True,
            "ldap_domain": "ad.msp.example.com",
            "ldap_admin_principals": admin_principals,
            "ldap_editor_principals": editor_principals,
            "ldap_viewer_principals": viewer_principals,
        },
    )
    assert rc_cfg == 0, err_cfg
    assert ns8_env.persisted_env["LDAP_ADMIN_GROUP"] == admin_principals[0]
    assert ns8_env.persisted_env["LDAP_EDITOR_GROUP"] == editor_principals[0]
    assert ns8_env.persisted_env["LDAP_VIEWER_GROUP"] == viewer_principals[0]

    rc_read, out_read, err_read = execute_script(
        IMAGEROOT / "actions" / "get-configuration" / "20read",
        payload={},
    )
    assert rc_read == 0, err_read
    doc = json.loads(out_read)
    assert doc["ldap_admin_principals"] == admin_principals
    assert doc["ldap_editor_principals"] == editor_principals
    assert doc["ldap_viewer_principals"] == viewer_principals
    assert doc["ldap_admin_group"] == admin_principals[0]
    assert doc["ldap_editor_group"] == editor_principals[0]
    assert doc["ldap_viewer_group"] == viewer_principals[0]

    # Simulate v1.0.3 -> v1.0.4 update-module backfill when *_PRINCIPALS_B64 keys do not exist yet
    ns8_env.unset_env("LDAP_ADMIN_PRINCIPALS_B64")
    ns8_env.unset_env("LDAP_EDITOR_PRINCIPALS_B64")
    ns8_env.unset_env("LDAP_VIEWER_PRINCIPALS_B64")
    ns8_env.set_env("LDAP_ADMIN_GROUP", "CN=LegacyAdmins,CN=Users,DC=ad,DC=bls-isp,DC=net")
    ns8_env.set_env("LDAP_EDITOR_GROUP", "")
    ns8_env.set_env("LDAP_VIEWER_GROUP", "CN=LegacyViewers,CN=Users,DC=ad,DC=bls-isp,DC=net")
    ns8_env.dump_env()

    rc_up, _, err_up = execute_script(IMAGEROOT / "update-module.d" / "20pull_images")
    assert rc_up == 0, err_up
    assert decode_ldap_principals(
        ns8_env.persisted_env, "LDAP_ADMIN_PRINCIPALS_B64", "LDAP_ADMIN_GROUP"
    ) == ["CN=LegacyAdmins,CN=Users,DC=ad,DC=bls-isp,DC=net"]
    assert decode_ldap_principals(
        ns8_env.persisted_env, "LDAP_EDITOR_PRINCIPALS_B64", "LDAP_EDITOR_GROUP"
    ) == []
    assert decode_ldap_principals(
        ns8_env.persisted_env, "LDAP_VIEWER_PRINCIPALS_B64", "LDAP_VIEWER_GROUP"
    ) == ["CN=LegacyViewers,CN=Users,DC=ad,DC=bls-isp,DC=net"]


def test_v104_ns8_env_teardown_leaves_no_process_environ_leak() -> None:
    import os

    for leaked_key in (
        "LDAP_ADMIN_PRINCIPALS_B64",
        "LDAP_EDITOR_PRINCIPALS_B64",
        "LDAP_VIEWER_PRINCIPALS_B64",
        "LDAP_ADMIN_GROUP",
        "LDAP_EDITOR_GROUP",
        "LDAP_VIEWER_GROUP",
        "GRAFANA_ADMIN_PASSWORD",
        "PORTAL_ENCRYPTION_KEY",
    ):
        assert leaked_key not in os.environ, f"{leaked_key} leaked across pytest fixtures!"
