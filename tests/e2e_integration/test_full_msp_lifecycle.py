"""End-to-End Cross-Module Integration Tests for NS8-CentralMonitoringService.

Exercises real NS8 module actions, config renderers, Restic backup/restore/clone scripts,
and live async HTTP/HTTPS wire protocols across `hub-core`, `hub-tenancy-gateway`,
`hub-probes-alerting`, `site-collector`, and `telemetry-packs`.
"""

from __future__ import annotations

import ast
import asyncio
import datetime
import json
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import struct
import sys
from typing import Any
import zlib

import aiohttp
import pytest
from yarl import URL

from hub_gateway.loki_push import LokiEntry, LokiStream, build_loki_push_request
from hub_gateway.prom_remote_write import Sample, TimeSeries, build_write_request
from hub_gateway.snappy_codec import snappy_compress
from hub_tenancy.store import load_portal_viewer_secret
from tests.e2e_integration.harness import (
    REPO_ROOT,
    LiveBERLDAPv3Server,
    LiveObservabilityBackends,
    NS8ModuleInstance,
    build_ad_object_sid,
    parse_prom_textfile_to_timeseries,
)


def _default_alerting_payload(
    *,
    customer_email_enabled: bool = True,
    push_enabled: bool = False,
    push_provider: str = "none",
    ntfy_url: str = "https://ntfy.sh",
    ntfy_topic: str = "",
    ntfy_token: str = "",
    ntfy_token_unchanged: bool = False,
    gotify_url: str = "",
    gotify_token: str = "",
    gotify_token_unchanged: bool = False,
) -> dict:
    return {
        "group_wait": "30s",
        "group_interval": "5m",
        "repeat_interval": "4h",
        "smarthost_email": {
            "enabled": True,
            "use_ns8_smarthost": True,
            "from_address": "monitoring@msp.example.com",
            "default_to_addresses": ["noc@msp.example.com"],
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
            "enabled": push_enabled,
            "provider": push_provider,
            "min_severity": "critical",
            "ntfy_url": ntfy_url,
            "ntfy_topic": ntfy_topic,
            "ntfy_token": ntfy_token,
            "ntfy_token_unchanged": ntfy_token_unchanged,
            "gotify_url": gotify_url,
            "gotify_token": gotify_token,
            "gotify_token_unchanged": gotify_token_unchanged,
        },
        "customer_email_routing": {
            "enabled": customer_email_enabled,
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
    }


@pytest.mark.asyncio
async def test_01_hub_provisioning_local_and_s3_modes(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify full Hub provisioning across `local` and `s3` (Thanos + Loki S3 + LDAP) modes."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_home",
        module_id="central-monitoring-hub1",
        tcp_port=20080,
        backends=live_backends,
    )

    # 1. Unconfigured bootstrap via create-module/20initialize
    await hub.run_script("actions/create-module/20initialize")
    assert hub.read_meta()["dump_env_count"] >= 1
    assert (hub.state_dir / "secrets.env").is_file()

    _, _, _, init_cfg = await hub.run_script("actions/get-configuration/20read", {})
    assert init_cfg["configured"] is False
    assert init_cfg["storage_mode"] == "local"
    assert init_cfg["available_ldap_domains"] == ["ad.msp.example.com"]

    _, _, _, init_ov = await hub.run_script("actions/get-overview/20read", {})
    assert init_ov["configured"] is False
    assert init_ov["components"]["prometheus"] == "disabled"
    assert init_ov["components"]["thanos_query"] == "disabled"

    # 2. Traefik FQDN collision check must reject already-used domain with exit code 2
    hub.set_routes_in_use(["taken.msp.example.com"])
    _, collision_stdout, _, collision_err = await hub.run_script(
        "actions/configure-module/01hostname-validation",
        {
            "host": "taken.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
        expect_rc=2,
    )
    assert hub.read_meta()["status"] == "validation-failed"
    assert collision_err[0]["error"] == "domain_already_used"
    assert "taken.msp.example.com" in collision_stdout

    # 3. Configure Hub in `local` mode with NS8 LDAP SSO enabled
    local_req = {
        "host": "monitoring.msp.example.com",
        "lets_encrypt": True,
        "http2https": True,
        "retention_days": 45,
        "retention_size_gb": 80,
        "loki_retention_days": 30,
        "backup_include_tsdb": False,
        "storage_mode": "local",
        "ldap_enabled": True,
        "ldap_domain": "ad.msp.example.com",
        "ldap_admin_group": "MSP-Admins",
        "ldap_editor_group": "MSP-Engineers",
        "grafana_admin_password": "MspStrongPassword!2026",
    }
    await hub.run_script("actions/configure-module/01hostname-validation", local_req)
    _, _, _, cfg_out = await hub.run_script("actions/configure-module/20configure", local_req)
    await hub.run_script("actions/configure-module/80start_services", local_req)

    assert cfg_out == {
        "status": "ok",
        "grafana_url": "https://monitoring.msp.example.com",
        "ingest_metrics_url": "https://monitoring.msp.example.com/api/v1/write",
        "ingest_logs_url": "https://monitoring.msp.example.com/loki/api/v1/push",
        "storage_mode": "local",
    }

    prom_yml = (hub.config_dir / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    assert 'cluster: "central-monitoring-hub1"' in prom_yml
    assert "/etc/prometheus/file_sd/exporters/*.json" in prom_yml
    assert "/etc/prometheus/file_sd/blackbox/*.json" in prom_yml
    assert "/etc/prometheus/file_sd/snmp/*.json" in prom_yml

    loki_yml = (hub.config_dir / "loki" / "loki.yaml").read_text(encoding="utf-8")
    assert "auth_enabled: true" in loki_yml
    assert "multi_tenant_queries_enabled: true" in loki_yml
    assert "object_store: filesystem" in loki_yml
    assert "schema: v13" in loki_yml

    grafana_ini = (hub.config_dir / "grafana" / "grafana.ini").read_text(encoding="utf-8")
    assert "http_addr = 127.0.0.1" in grafana_ini
    assert "http_port = 3000" in grafana_ini
    assert "domain = monitoring.msp.example.com" in grafana_ini
    assert "enabled = true" in grafana_ini

    ldap_toml = (hub.config_dir / "grafana" / "ldap.toml").read_text(encoding="utf-8")
    assert "10.0.2.2" in ldap_toml
    assert "20001" in ldap_toml
    assert "org_id = 1" in ldap_toml

    state_inc_local = (hub.etc_dir / "state-include.conf").read_text(encoding="utf-8")
    assert "volumes/prometheus-data" not in state_inc_local

    meta_local = hub.read_meta()
    assert meta_local["systemctl_state"]["prometheus.service"] == "active"
    assert meta_local["systemctl_state"]["hub-gateway.service"] == "active"
    assert meta_local["systemctl_state"]["thanos-query.service"] == "inactive"
    assert any(
        c["action"] == "set-route"
        and c["data"]["url"] == "http://127.0.0.1:20080"
        and c["data"]["host"] == "monitoring.msp.example.com"
        for c in meta_local["task_calls"]
    )

    _, local_read_raw, _, local_read = await hub.run_script("actions/get-configuration/20read", {})
    assert local_read["configured"] is True
    assert local_read["storage_mode"] == "local"
    assert local_read["has_grafana_admin_password"] is True
    assert "MspStrongPassword!2026" not in local_read_raw

    # 4. Switch Hub to `s3` mode (Thanos Sidecar/Store/Query + Loki S3 + backup_include_tsdb=True)
    s3_req = {
        "host": "monitoring.msp.example.com",
        "lets_encrypt": True,
        "http2https": True,
        "retention_days": 14,
        "retention_size_gb": 50,
        "loki_retention_days": 90,
        "backup_include_tsdb": True,
        "storage_mode": "s3",
        "s3": {
            "endpoint": "minio.msp.example.com:9000",
            "bucket": "msp-longterm-tsdb",
            "region": "eu-central-1",
            "access_key": "MSP_MINIO_AK",
            "secret_key": "MSP_MINIO_SUPER_SECRET_KEY",
            "secret_key_unchanged": False,
            "insecure": False,
            "path_style": True,
        },
        "ldap_enabled": True,
        "ldap_domain": "ad.msp.example.com",
    }
    await hub.run_script("actions/configure-module/01hostname-validation", s3_req)
    _, _, _, s3_out = await hub.run_script("actions/configure-module/20configure", s3_req)
    await hub.run_script("actions/configure-module/80start_services", s3_req)
    assert s3_out["storage_mode"] == "s3"

    objstore_path = hub.config_dir / "thanos" / "objstore.yml"
    assert objstore_path.is_file()
    objstore_txt = objstore_path.read_text(encoding="utf-8")
    assert 'bucket: "msp-longterm-tsdb"' in objstore_txt
    assert 'endpoint: "minio.msp.example.com:9000"' in objstore_txt
    assert 'secret_key: "MSP_MINIO_SUPER_SECRET_KEY"' in objstore_txt

    loki_s3_yml = (hub.config_dir / "loki" / "loki.yaml").read_text(encoding="utf-8")
    assert "object_store: s3" in loki_s3_yml
    assert 'bucketnames: "msp-longterm-tsdb"' in loki_s3_yml
    assert "s3forcepathstyle: true" in loki_s3_yml

    state_inc_s3 = (hub.etc_dir / "state-include.conf").read_text(encoding="utf-8")
    assert "volumes/prometheus-data" in state_inc_s3
    assert "volumes/loki-data" in state_inc_s3

    meta_s3 = hub.read_meta()
    assert meta_s3["persisted_env"]["PROMQL_UPSTREAM_URL"] == "http://127.0.0.1:10902"
    assert "--storage.tsdb.min-block-duration=2h" in meta_s3["persisted_env"]["PROMETHEUS_EXTRA_ARGS"]
    assert "--storage.tsdb.max-block-duration=2h" in meta_s3["persisted_env"]["PROMETHEUS_EXTRA_ARGS"]
    assert meta_s3["systemctl_state"]["thanos-sidecar.service"] == "active"
    assert meta_s3["systemctl_state"]["thanos-store.service"] == "active"
    assert meta_s3["systemctl_state"]["thanos-query.service"] == "active"

    # Re-save with secret_key_unchanged=True and verify secret preservation & redaction
    s3_update_req = dict(s3_req)
    s3_update_req["s3"] = {
        **s3_req["s3"],
        "secret_key": "",
        "secret_key_unchanged": True,
    }
    await hub.run_script("actions/configure-module/20configure", s3_update_req)
    _, s3_cfg_raw, _, s3_cfg = await hub.run_script("actions/get-configuration/20read", {})
    assert s3_cfg["storage_mode"] == "s3"
    assert s3_cfg["s3"]["has_secret_key"] is True
    assert "MSP_MINIO_SUPER_SECRET_KEY" not in s3_cfg_raw

    _, _, _, s3_ov = await hub.run_script("actions/get-overview/20read", {})
    assert s3_ov["storage_mode"] == "s3"
    assert s3_ov["s3_bucket"] == "msp-longterm-tsdb"


@pytest.mark.asyncio
async def test_02_multi_tenant_creation_alertmanager_and_grafana_cross_hooks(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify save-tenant + configure-alerting cross-hooks for Alertmanager & Grafana Multi-Org."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_tenancy_home",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )

    # Enable customer_email_routing BEFORE creating tenants to test save-tenant -> sync_alertmanager hook
    await hub.run_script(
        "actions/configure-alerting/20configure",
        _default_alerting_payload(customer_email_enabled=True),
    )

    # Create acme-gmbh (portal enabled) and victim-gmbh
    _, _, _, acme_out = await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq", "branch"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": True,
            "portal_viewer_username": "acme-viewer",
            "portal_viewer_password": "AcmePortalPassword!2026",
        },
    )
    assert acme_out["created"] is True
    acme_token = acme_out["auth_token"]
    assert isinstance(acme_token, str) and acme_token.startswith("cms_v1_")
    assert isinstance(acme_out["grafana_org_id"], int) and acme_out["grafana_org_id"] > 1

    _, _, _, victim_out = await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "victim-gmbh",
            "display_name": "Victim GmbH",
            "sites": ["hq"],
            "contact_emails": ["secops@victim.de"],
            "customer_portal_enabled": False,
        },
    )
    assert victim_out["created"] is True
    victim_token = victim_out["auth_token"]
    assert isinstance(victim_token, str) and victim_token.startswith("cms_v1_")

    # Verify plaintext tokens are NEVER persisted to state/tenants.json or returned by list-tenants
    raw_tenants_disk = (hub.state_dir / "tenants.json").read_text(encoding="utf-8")
    assert acme_token not in raw_tenants_disk
    assert victim_token not in raw_tenants_disk

    _, list_raw, _, listed = await hub.run_script("actions/list-tenants/20read", {})
    assert listed["pagination"]["total_items"] == 2
    assert acme_token not in list_raw
    assert victim_token not in list_raw

    # Verify Alertmanager cross-hook wrote customer-email-acme-gmbh with Smarthost 10.0.2.2:587
    am_yml = (hub.config_dir / "alertmanager" / "alertmanager.yml").read_text(encoding="utf-8")
    assert 'receiver: "customer-email-acme-gmbh"' in am_yml
    assert 'name: "customer-email-acme-gmbh"' in am_yml
    assert 'to: "it@acme.de"' in am_yml
    assert 'smarthost: "10.0.2.2:587"' in am_yml
    assert 'receiver: "customer-email-victim-gmbh"' in am_yml
    assert live_backends.am_reloads >= 3

    # Verify Grafana Multi-Org isolation provisioned automatically on save-tenant
    gf = live_backends.grafana
    org1_loki = gf.datasources[1]["loki"]
    assert org1_loki["editable"] is False
    assert (
        org1_loki["secureJsonData"]["httpHeaderValue1"]
        == "acme-gmbh|victim-gmbh|_msp_internal"
    )
    expected_dash_uids = {
        "ns8-multi-cluster-overview",
        "ns8-pods-and-modules",
        "linux-windows-servers",
        "proxmox-snmp-infrastructure",
        "web-ssl-uptime",
        "central-log-explorer",
    }
    assert len(gf.dashboards[1]) == 6
    assert set(gf.dashboards[1].keys()) == expected_dash_uids

    acme_oid = acme_out["grafana_org_id"]
    assert set(gf.dashboards[acme_oid].keys()) == expected_dash_uids
    cust_prom = gf.datasources[acme_oid]["prometheus"]
    cust_loki = gf.datasources[acme_oid]["loki"]
    assert cust_prom["url"] == "http://127.0.0.1:9095"
    assert cust_prom["editable"] is False
    assert cust_prom["secureJsonData"]["httpHeaderValue1"] == "acme-gmbh"
    assert cust_loki["url"] == "http://127.0.0.1:3100"
    assert cust_loki["editable"] is False
    assert cust_loki["secureJsonData"]["httpHeaderValue1"] == "acme-gmbh"

    viewer_user = next(u for u in gf.users.values() if u["login"] == "acme-viewer")
    viewer_uid = viewer_user["id"]
    assert gf.org_members[acme_oid].get(viewer_uid) == "Viewer"
    assert viewer_uid not in gf.org_members[1], (
        "Customer Portal Viewer must NEVER remain in MSP Main Org 1!"
    )

    # Verify central pull/probe targets for acme-gmbh stamp collector_id="hub-central"
    _, _, _, bb_saved = await hub.run_script(
        "actions/save-target/20save",
        {
            "customer": "acme-gmbh",
            "site": "hq",
            "name": "Acme Shop HTTPS",
            "enabled": True,
            "target_type": "blackbox",
            "device_role": "web",
            "endpoints": ["https://shop.acme.de"],
            "blackbox_module": "http_2xx",
        },
    )
    assert bb_saved["created"] is True
    bb_sd_files = list((hub.config_dir / "prometheus" / "file_sd" / "blackbox").glob("*.json"))
    assert bb_sd_files, "Expected blackbox file_sd JSON to be written"
    bb_sd_txt = bb_sd_files[0].read_text(encoding="utf-8")
    assert '"customer": "acme-gmbh"' in bb_sd_txt
    assert '"collector_id": "hub-central"' in bb_sd_txt

    _, _, _, ov = await hub.run_script("actions/get-overview/20read", {})
    assert ov["counts"]["tenants"] == 2
    assert ov["counts"]["portal_enabled_tenants"] == 1
    assert ov["counts"]["central_targets"] == 1


@pytest.mark.asyncio
async def test_03_live_collector_to_live_hub_gateway_wire_integration(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify live Collector -> live hub_gateway HTTPS wire integration & adversarial anti-spoofing."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_wire_home",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )

    _, _, _, acme_out = await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq", "branch"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": False,
        },
    )
    acme_token: str = acme_out["auth_token"]

    await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "victim-gmbh",
            "display_name": "Victim GmbH",
            "sites": ["hq"],
            "contact_emails": ["noc@victim.de"],
            "customer_portal_enabled": False,
        },
    )

    # Start LIVE async aiohttp hub_gateway pointed at the EXACT state_dir written by Hub actions
    live_gw = await live_backends.start_hub_gateway(hub.state_dir, tmp_path / "tls_certs")

    # Provision site-collector with acme-gmbh's real minted token
    collector = NS8ModuleInstance(
        kind="collector",
        install_dir=tmp_path / "collector_home",
        module_id="central-monitoring-collector1",
        backends=live_backends,
    )
    await collector.run_script("actions/create-module/20initialize")
    col_cfg_req = {
        "hub_url": live_gw.https_url,
        "auth_token": acme_token,
        "auth_token_unchanged": False,
        "customer": "acme-gmbh",
        "site": "hq",
        "collect_local_ns8": True,
        "enable_syslog_receiver": True,
        "syslog_port": 5514,
        "wal_max_disk_mb": 2048,
        "tls_skip_verify": True,
    }
    _, _, _, col_cfg_out = await collector.run_script(
        "actions/configure-module/20configure",
        col_cfg_req,
    )
    await collector.run_script("actions/configure-module/80start_services", col_cfg_req)
    collector_id = col_cfg_out["collector_id"]

    # Add LAN scrape targets: Proxmox VE, Windows Server, and SNMP UPS
    await collector.run_script(
        "actions/save-local-target/20save",
        {
            "name": "PVE Cluster HQ",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "192.168.10.10",
            "port": 8006,
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "pve-secret-token-value-123",
        },
    )
    await collector.run_script(
        "actions/save-local-target/20save",
        {
            "name": "DC01 Windows Server",
            "enabled": True,
            "target_type": "windows",
            "device_role": "windows",
            "host": "192.168.10.20",
            "port": 9182,
        },
    )
    await collector.run_script(
        "actions/save-local-target/20save",
        {
            "name": "APC Smart-UPS 3000",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-ups",
            "host": "192.168.10.30",
            "port": 161,
            "snmp_module": "apcupsd",
            "snmp_version": "v2c",
            "snmp_community": "apc-private-ro",
        },
    )
    assert live_backends.alloy_reloads == 3

    alloy_cfg = (collector.state_dir / "config.alloy").read_text(encoding="utf-8")
    assert f"{live_gw.https_url}/api/v1/write" in alloy_cfg
    assert f"{live_gw.https_url}/loki/api/v1/push" in alloy_cfg
    assert 'bearer_token_file = "/etc/alloy/secrets/hub.token"' in alloy_cfg
    assert acme_token not in alloy_cfg
    assert (collector.state_dir / "pve.yml").is_file()
    assert (collector.state_dir / "secrets" / "snmp-auths.yml").is_file()

    _, list_targets_raw, _, col_targets = await collector.run_script(
        "actions/list-local-targets/20read", {}
    )
    assert len(col_targets["targets"]) == 3
    assert "pve-secret-token-value-123" not in list_targets_raw
    assert "apc-private-ro" not in list_targets_raw

    _, _, _, col_get_cfg = await collector.run_script("actions/get-configuration/20read", {})
    assert col_get_cfg["configured"] is True
    assert col_get_cfg["health"]["alloy_status"] == "healthy"
    assert col_get_cfg["health"]["pve_exporter_status"] == "healthy"
    assert col_get_cfg["health"]["local_targets_count"] == 3

    # Seed NS8 backup records and execute real bin/collect-ns8-metrics -> ns8.prom
    (collector.state_dir / "ns8-backups.json").write_bytes(
        (
            json.dumps(
                {
                    "backups": [
                        {
                            "module_id": "mail1",
                            "succeeded": True,
                            "last_success_timestamp": 1763670000,
                        },
                        {
                            "module_id": "nextcloud1",
                            "succeeded": False,
                            "last_success_timestamp": 1763580000,
                        },
                    ]
                }
            )
            + "\n"
        ).encode("utf-8")
    )
    await collector.run_script("bin/collect-ns8-metrics", validate_io=False)
    ns8_prom_file = collector.state_dir / "textfile" / "ns8.prom"
    assert ns8_prom_file.is_file()
    ns8_prom_text = ns8_prom_file.read_text(encoding="utf-8")
    assert 'ns8_backup_status{module_id="mail1"} 1' in ns8_prom_text
    assert 'ns8_backup_failed{module_id="nextcloud1"} 1' in ns8_prom_text

    # Execute real collector test-hub-connection/20test against LIVE HTTPS hub_gateway!
    # Case A: Fallback to stored module token (auth_token="") with tls_skip_verify=True
    _, _, _, conn_ok = await collector.run_script(
        "actions/test-hub-connection/20test",
        {
            "hub_url": live_gw.https_url,
            "auth_token": "",
            "tls_skip_verify": True,
        },
    )
    assert conn_ok["ok"] is True
    assert conn_ok["http_status"] == 200
    assert conn_ok["verified_customer"] == "acme-gmbh"

    # Case B: Strict TLS verification (tls_skip_verify=False) using generated CA cert
    _, _, _, conn_strict_tls = await collector.run_script(
        "actions/test-hub-connection/20test",
        {
            "hub_url": live_gw.https_url,
            "auth_token": acme_token,
            "tls_skip_verify": False,
        },
        extra_env={"SSL_CERT_FILE": str(live_gw.ca_cert_path)},
    )
    assert conn_strict_tls["ok"] is True
    assert conn_strict_tls["verified_customer"] == "acme-gmbh"

    # Case C: Forged token rejected with HTTP 401
    _, _, _, conn_bad = await collector.run_script(
        "actions/test-hub-connection/20test",
        {
            "hub_url": live_gw.https_url,
            "auth_token": "cms_v1_forged_invalid_token_value_000000000000",
            "tls_skip_verify": True,
        },
    )
    assert conn_bad["ok"] is False
    assert conn_bad["http_status"] == 401
    assert conn_bad["verified_customer"] is None

    # Push real Snappy+Protobuf WriteRequest (containing ns8.prom metrics + adversarial
    # spoofed customer="victim-gmbh" labels!) to LIVE HTTPS hub_gateway /api/v1/write
    stored_token = (collector.state_dir / "secrets" / "hub.token").read_text(encoding="utf-8").strip()
    assert stored_token == acme_token

    spoofed_ns8_series = parse_prom_textfile_to_timeseries(
        ns8_prom_text,
        extra_labels={
            "customer": "victim-gmbh",
            "site": "hq",
            "device_role": "ns8",
            "collector_id": collector_id,
        },
    )
    spoofed_ns8_series.append(
        TimeSeries(
            labels=[
                ("__name__", "pve_up"),
                ("collector_id", collector_id),
                ("customer", "victim-gmbh"),
                ("device_role", "proxmox"),
                ("instance", "192.168.10.10:8006"),
                ("site", "branch"),
            ],
            samples=[Sample(value=1.0, timestamp_ms=1763676000000)],
        )
    )
    compressed_write = snappy_compress(build_write_request(spoofed_ns8_series))

    client_ssl = ssl.create_default_context(cafile=str(live_gw.ca_cert_path))
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{live_gw.https_url}/api/v1/write",
            data=compressed_write,
            headers={
                "Authorization": f"Bearer {stored_token}",
                "Content-Type": "application/x-protobuf",
                "Content-Encoding": "snappy",
                "X-Prometheus-Remote-Write-Version": "0.1.0",
            },
            ssl=client_ssl,
        ) as wr_resp:
            assert wr_resp.status == 204

        # Verify upstream Prometheus received ONLY customer="acme-gmbh" in sorted order
        assert len(live_backends.prom_writes) == 1
        received_series = live_backends.prom_writes[0]
        assert len(received_series) == len(spoofed_ns8_series)
        for ts in received_series:
            keys = [k for k, _ in ts.labels]
            assert keys == sorted(keys), f"Labels not lexicographically sorted: {keys}"
            lmap = dict(ts.labels)
            assert lmap["customer"] == "acme-gmbh"
            assert lmap["customer"] != "victim-gmbh"

        # Push Loki JSON logs with spoofed X-Scope-OrgID & stream customer="victim-gmbh"
        loki_json_body = {
            "streams": [
                {
                    "stream": {
                        "customer": "victim-gmbh",
                        "site": "hq",
                        "device_role": "ns8",
                        "collector_id": collector_id,
                        "job": "systemd-journal",
                    },
                    "values": [["1763676000000000000", "ns8 backup failed on nextcloud1"]],
                }
            ]
        }
        async with session.post(
            f"{live_gw.https_url}/loki/api/v1/push",
            json=loki_json_body,
            headers={
                "Authorization": f"Bearer {stored_token}",
                "X-Scope-OrgID": "victim-gmbh",
            },
            ssl=client_ssl,
        ) as loki_json_resp:
            assert loki_json_resp.status == 204

        # Push Loki Snappy+Protobuf PushRequest with spoofed X-Scope-OrgID & {customer="victim-gmbh"}
        pb_loki_raw = build_loki_push_request(
            [
                LokiStream(
                    labels=f'{{customer="victim-gmbh", site="branch", device_role="snmp-ups", collector_id="{collector_id}", job="syslog"}}',
                    entries=[
                        LokiEntry(
                            timestamp_seconds=1763676005,
                            timestamp_nanos=0,
                            line="<134>APC UPS on battery at branch site",
                        )
                    ],
                )
            ]
        )
        async with session.post(
            f"{live_gw.https_url}/loki/api/v1/push",
            data=snappy_compress(pb_loki_raw),
            headers={
                "Authorization": f"Bearer {stored_token}",
                "Content-Type": "application/x-protobuf",
                "Content-Encoding": "snappy",
                "X-Scope-OrgID": "victim-gmbh",
            },
            ssl=client_ssl,
        ) as loki_pb_resp:
            assert loki_pb_resp.status == 204

        assert len(live_backends.loki_pushes) == 2
        for pushed in live_backends.loki_pushes:
            assert pushed.org_id == "acme-gmbh"
            assert pushed.labels["customer"] == "acme-gmbh"
            assert "victim-gmbh" not in pushed.labels.values()

        # Verify Grafana UI proxy works while internal Prometheus/Admin paths return 403
        async with session.get(f"{live_gw.https_url}/login", ssl=client_ssl) as gf_resp:
            assert gf_resp.status == 200
            assert "Grafana" in await gf_resp.text()

        for blocked_path in ("/api/v1/query?query=up", "/-/reload", "/metrics"):
            async with session.get(
                f"{live_gw.https_url}{blocked_path}", ssl=client_ssl
            ) as blk_resp:
                assert blk_resp.status == 403

        # Verify live token rotation grace window & immediate revocation on live hub_gateway
        _, _, _, rot_grace = await hub.run_script(
            "actions/rotate-token/20rotate",
            {"customer": "acme-gmbh", "grace_period_minutes": 60},
        )
        new_token_1 = rot_grace["auth_token"]
        for tok in (stored_token, new_token_1):
            async with session.get(
                f"{live_gw.https_url}/api/v1/ingest/verify",
                headers={"Authorization": f"Bearer {tok}"},
                ssl=client_ssl,
            ) as v_resp:
                assert v_resp.status == 200

        _, _, _, rot_immediate = await hub.run_script(
            "actions/rotate-token/20rotate",
            {"customer": "acme-gmbh", "grace_period_minutes": 0},
        )
        new_token_2 = rot_immediate["auth_token"]
        async with session.get(
            f"{live_gw.https_url}/api/v1/ingest/verify",
            headers={"Authorization": f"Bearer {new_token_1}"},
            ssl=client_ssl,
        ) as old_resp:
            assert old_resp.status == 401
        async with session.get(
            f"{live_gw.https_url}/api/v1/ingest/verify",
            headers={"Authorization": f"Bearer {new_token_2}"},
            ssl=client_ssl,
        ) as cur_resp:
            assert cur_resp.status == 200


@pytest.mark.asyncio
async def test_04_live_alert_relay_silences_agent_bundles_and_restic_dr(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify live :9097 Ntfy/Gotify relay, Silences, Agent Bundles, and Restic Backup/Restore/Clone."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_dr_home",
        module_id="central-monitoring-hub1",
        tcp_port=20080,
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )

    _, _, _, acme_saved = await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq", "branch"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": True,
            "portal_viewer_username": "acme-viewer",
            "portal_viewer_password": "AcmePortalPassword!2026",
        },
    )
    acme_token: str = acme_saved["auth_token"]

    live_gw = await live_backends.start_hub_gateway(hub.state_dir, tmp_path / "dr_tls")

    # 1. Configure Ntfy in configure-alerting -> send Alertmanager v4 webhook to LIVE :9097 relay
    await hub.run_script(
        "actions/configure-alerting/20configure",
        _default_alerting_payload(
            customer_email_enabled=True,
            push_enabled=True,
            push_provider="ntfy",
            ntfy_url=f"http://ntfy.msp.example.com:{live_backends.push_port}",
            ntfy_topic="msp-critical",
            ntfy_token="ntfy-secret-token-e2e",
        ),
    )
    am_ntfy_yml = (hub.config_dir / "alertmanager" / "alertmanager.yml").read_text(encoding="utf-8")
    assert "http://127.0.0.1:9097/alert-relay/ntfy" in am_ntfy_yml

    am_v4_webhook = {
        "version": "4",
        "status": "firing",
        "receiver": "msp-push",
        "commonLabels": {
            "alertname": "NS8BackupFailed",
            "customer": "acme-gmbh",
            "site": "hq",
            "severity": "critical",
        },
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "NS8BackupFailed",
                    "customer": "acme-gmbh",
                    "site": "hq",
                    "device_role": "ns8",
                    "instance": "ns8-hq.acme.de",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "Restic backup failed on module nextcloud1",
                    "description": "Last backup exit status was non-zero.",
                },
            }
        ],
    }

    client_ssl = ssl.create_default_context(cafile=str(live_gw.ca_cert_path))
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{live_gw.relay_url}/alert-relay/ntfy",
            json=am_v4_webhook,
        ) as ntfy_resp:
            assert ntfy_resp.status == 200
            ntfy_json = await ntfy_resp.json()
            assert ntfy_json == {"status": "ok", "provider": "ntfy", "forwarded_alerts": 1}

        assert len(live_backends.ntfy_requests) == 1
        ntfy_hit = live_backends.ntfy_requests[0]
        assert ntfy_hit["topic"] == "msp-critical"
        assert ntfy_hit["headers"]["Authorization"] == "Bearer ntfy-secret-token-e2e"
        assert ntfy_hit["headers"]["Priority"] == "urgent"
        assert ntfy_hit["headers"]["Tags"] == "rotating_light"
        assert "[FIRING:1] NS8BackupFailed (acme-gmbh / hq)" in ntfy_hit["headers"]["Title"]
        assert "Restic backup failed on module nextcloud1" in ntfy_hit["body"]

        # Switch push provider to Gotify (preserving ntfy_token_unchanged=True) and test LIVE relay
        await hub.run_script(
            "actions/configure-alerting/20configure",
            _default_alerting_payload(
                customer_email_enabled=True,
                push_enabled=True,
                push_provider="gotify",
                ntfy_url=f"http://ntfy.msp.example.com:{live_backends.push_port}",
                ntfy_topic="msp-critical",
                ntfy_token_unchanged=True,
                gotify_url=f"http://gotify.msp.example.com:{live_backends.push_port}",
                gotify_token="gotify-app-token-e2e",
            ),
        )
        am_gotify_yml = (hub.config_dir / "alertmanager" / "alertmanager.yml").read_text(
            encoding="utf-8"
        )
        assert "http://127.0.0.1:9097/alert-relay/gotify" in am_gotify_yml

        async with session.post(
            f"{live_gw.relay_url}/alert-relay/gotify",
            json=am_v4_webhook,
        ) as gotify_resp:
            assert gotify_resp.status == 200
            gotify_json = await gotify_resp.json()
            assert gotify_json == {"status": "ok", "provider": "gotify", "forwarded_alerts": 1}

        assert len(live_backends.gotify_requests) == 1
        gotify_hit = live_backends.gotify_requests[0]
        assert gotify_hit["headers"]["X-Gotify-Key"] == "gotify-app-token-e2e"
        assert gotify_hit["json"]["priority"] == 8
        assert "NS8BackupFailed" in gotify_hit["json"]["title"]
        assert "Restic backup failed on module nextcloud1" in gotify_hit["json"]["message"]

        # Verify test-alert action dispatches synthetic v2 alert to Alertmanager
        _, _, _, test_alert_out = await hub.run_script(
            "actions/test-alert/20test",
            {"channel": "customer_email", "customer": "acme-gmbh"},
        )
        assert test_alert_out["status"] == "ok"
        assert len(live_backends.am_alerts) >= 1

        # 2. Silences lifecycle (create, list, delete, and retain active silence for Restic DR)
        now = datetime.datetime.now(datetime.timezone.utc)
        starts_iso = (now - datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ends_iso = (now + datetime.timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")

        _, _, _, sil_keep = await hub.run_script(
            "actions/create-silence/20create",
            {
                "customer": "acme-gmbh",
                "site": "hq",
                "device_role": "proxmox",
                "starts_at": starts_iso,
                "ends_at": ends_iso,
                "created_by": "msp-admin",
                "comment": "Proxmox kernel maintenance window",
            },
        )
        _, _, _, sil_temp = await hub.run_script(
            "actions/create-silence/20create",
            {
                "customer": "acme-gmbh",
                "site": "branch",
                "starts_at": starts_iso,
                "ends_at": ends_iso,
                "created_by": "msp-admin",
                "comment": "Temporary router reboot",
            },
        )
        _, _, _, sil_listed = await hub.run_script(
            "actions/list-silences/20read", {"customer": "acme-gmbh"}
        )
        assert len(sil_listed["silences"]) == 2

        await hub.run_script(
            "actions/delete-silence/20delete", {"silence_id": sil_temp["silence_id"]}
        )
        _, _, _, sil_after_del = await hub.run_script(
            "actions/list-silences/20read", {"customer": "acme-gmbh"}
        )
        assert [s["id"] for s in sil_after_del["silences"]] == [sil_keep["silence_id"]]

        # 3. Standalone Agent Bundles (linux, windows, docker) + live dedicated token check
        minted_bundle_tokens: dict[str, str] = {}
        for platform in ("linux", "windows", "docker"):
            _, _, _, bundle = await hub.run_script(
                "actions/generate-agent-bundle/20generate",
                {
                    "customer": "acme-gmbh",
                    "site": "branch",
                    "platform": platform,
                    "issue_dedicated_token": True,
                    "syslog_port": 5514,
                },
            )
            assert bundle["customer"] == "acme-gmbh"
            assert bundle["site"] == "branch"
            assert "acme-gmbh" in bundle["config_content"]
            assert "branch" in bundle["config_content"]
            assert "{{" not in bundle["config_content"]
            assert "}}" not in bundle["config_content"]
            assert "{{" not in bundle["installer_content"]
            assert "}}" not in bundle["installer_content"]

            tok_match = re.search(r"cms_v1_[A-Za-z0-9_-]+", bundle["config_content"])
            assert tok_match is not None, f"Dedicated token missing from {platform} bundle"
            minted_bundle_tokens[platform] = tok_match.group(0)

        linux_ded_token = minted_bundle_tokens["linux"]
        async with session.get(
            f"{live_gw.https_url}/api/v1/ingest/verify",
            headers={"Authorization": f"Bearer {linux_ded_token}"},
            ssl=client_ssl,
        ) as b_ver_resp:
            assert b_ver_resp.status == 200
            b_ver = await b_ver_resp.json()
            assert b_ver["customer"] == "acme-gmbh"
            assert b_ver["site"] == "branch"
            assert b_ver["collector_id"] == "acme-gmbh-branch-linux"

        # Dedicated branch token must NOT be allowed to push metrics claiming site="hq"
        unauthorized_site_pb = build_write_request(
            [
                TimeSeries(
                    labels=[
                        ("__name__", "up"),
                        ("device_role", "linux"),
                        ("site", "hq"),
                    ],
                    samples=[Sample(value=1.0, timestamp_ms=1763676000000)],
                )
            ]
        )
        async with session.post(
            f"{live_gw.https_url}/api/v1/write",
            data=snappy_compress(unauthorized_site_pb),
            headers={
                "Authorization": f"Bearer {linux_ded_token}",
                "Content-Type": "application/x-protobuf",
                "Content-Encoding": "snappy",
            },
            ssl=client_ssl,
        ) as unauth_site_resp:
            assert unauth_site_resp.status == 422

    # 4A. Hub Restic Backup (module-dump-state) -> Restore (06copyenv + 50configure) -> Clone
    src_grafana_db = hub.volumes_dir / "grafana-data" / "grafana.db"
    src_grafana_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(src_grafana_db))
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("CREATE TABLE e2e_marker (k TEXT PRIMARY KEY, v TEXT);")
        conn.execute("INSERT INTO e2e_marker (k, v) VALUES ('restore_probe', 'intact-after-restic');")
        conn.commit()
    finally:
        conn.close()

    src_am_dir = hub.volumes_dir / "alertmanager-data"
    src_am_dir.mkdir(parents=True, exist_ok=True)
    (src_am_dir / "nflog").write_bytes(b"nflog-binary-snapshot")
    (src_am_dir / "silences").write_bytes(b"silences-binary-snapshot")

    await hub.run_script("bin/module-dump-state", validate_io=False)
    assert (hub.state_dir / "grafana.db.bak").is_file()
    assert (hub.state_dir / "alertmanager-state.tar.gz").is_file()

    # Simulate Restic restore into a brand-new Hub instance using ONLY state-include.conf paths
    live_backends.am_silences.clear()
    restored_hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_restored_home",
        module_id="central-monitoring-hub2",
        tcp_port=20081,
        backends=live_backends,
    )
    hub.copy_restic_snapshot_to(restored_hub.install_dir)
    await hub.run_script("bin/module-cleanup-state", validate_io=False)
    assert not (hub.state_dir / "grafana.db.bak").exists()

    orig_hub_env = json.loads(hub.meta_file.read_text(encoding="utf-8"))["persisted_env"]
    await restored_hub.run_script(
        "actions/restore-module/06copyenv",
        {"environment": orig_hub_env},
        validate_io=False,
    )
    await restored_hub.run_script("actions/restore-module/50configure", {}, validate_io=False)

    restored_db = restored_hub.volumes_dir / "grafana-data" / "grafana.db"
    assert restored_db.is_file()
    rconn = sqlite3.connect(str(restored_db))
    try:
        row = rconn.execute("SELECT v FROM e2e_marker WHERE k = 'restore_probe'").fetchone()
        assert row == ("intact-after-restic",)
    finally:
        rconn.close()

    assert (restored_hub.volumes_dir / "alertmanager-data" / "nflog").read_bytes() == b"nflog-binary-snapshot"
    assert not (restored_hub.state_dir / "grafana.db.bak").exists()
    restored_am_yml = (restored_hub.config_dir / "alertmanager" / "alertmanager.yml").read_text(
        encoding="utf-8"
    )
    assert 'receiver: "customer-email-acme-gmbh"' in restored_am_yml
    assert len(live_backends.am_silences) == 1, "Active silence must be restored to Alertmanager"

    # Verify original tenant token still authenticates on a live gateway backed by restored_hub
    restored_gw = await live_backends.start_hub_gateway(
        restored_hub.state_dir, tmp_path / "restored_tls"
    )
    restored_ssl = ssl.create_default_context(cafile=str(restored_gw.ca_cert_path))
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{restored_gw.https_url}/api/v1/ingest/verify",
            headers={"Authorization": f"Bearer {acme_token}"},
            ssl=restored_ssl,
        ) as rgw_resp:
            assert rgw_resp.status == 200
            assert (await rgw_resp.json())["customer"] == "acme-gmbh"

    # Clone Hub -> verify internal cryptographic secrets regenerated & colliding FQDN cleared
    cloned_hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_cloned_home",
        module_id="central-monitoring-hub3",
        tcp_port=20082,
        backends=live_backends,
    )
    shutil.copytree(restored_hub.state_dir, cloned_hub.state_dir, dirs_exist_ok=True)
    cloned_hub.set_routes_in_use(["monitoring.msp.example.com"])
    await cloned_hub.run_script("actions/clone-module/50configure", {}, validate_io=False)

    src_secrets = (restored_hub.state_dir / "secrets.env").read_text(encoding="utf-8")
    clone_secrets = (cloned_hub.state_dir / "secrets.env").read_text(encoding="utf-8")
    assert src_secrets != clone_secrets
    assert cloned_hub.read_meta()["persisted_env"]["TRAEFIK_HOST"] == ""
    assert cloned_hub.read_meta()["persisted_env"]["CONFIGURED"] == "false"

    # 4B. Collector Restic Backup -> Restore -> Clone
    collector = NS8ModuleInstance(
        kind="collector",
        install_dir=tmp_path / "collector_dr_home",
        module_id="central-monitoring-collector1",
        backends=live_backends,
    )
    await collector.run_script("actions/create-module/20initialize")
    _, _, _, col_cfg = await collector.run_script(
        "actions/configure-module/20configure",
        {
            "hub_url": live_gw.https_url,
            "auth_token": acme_token,
            "customer": "acme-gmbh",
            "site": "hq",
            "tls_skip_verify": True,
        },
    )
    source_cid = col_cfg["collector_id"]
    await collector.run_script(
        "actions/save-local-target/20save",
        {
            "name": "PVE HQ",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "192.168.10.10",
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "pve-dr-secret",
        },
    )

    # Create transient WAL file to verify Restic state-include.conf excludes alloy-wal
    wal_dummy = collector.state_dir / "alloy-wal" / "000001"
    wal_dummy.parent.mkdir(parents=True, exist_ok=True)
    wal_dummy.write_bytes(b"transient-wal-bytes" * 100)

    await collector.run_script("bin/module-dump-state", validate_io=False)
    await collector.run_script("bin/module-cleanup-state", validate_io=False)

    restored_collector = NS8ModuleInstance(
        kind="collector",
        install_dir=tmp_path / "collector_restored_home",
        module_id="central-monitoring-collector2",
        backends=live_backends,
    )
    collector.copy_restic_snapshot_to(restored_collector.install_dir)
    assert not (restored_collector.state_dir / "alloy-wal").exists()

    orig_col_env = json.loads(collector.meta_file.read_text(encoding="utf-8"))["persisted_env"]
    await restored_collector.run_script(
        "actions/restore-module/06copyenv",
        {"environment": orig_col_env},
        validate_io=False,
    )
    await restored_collector.run_script(
        "actions/restore-module/50configure", {}, validate_io=False
    )

    assert (
        (restored_collector.state_dir / "secrets" / "hub.token").read_text(encoding="utf-8").strip()
        == acme_token
    )
    assert (restored_collector.state_dir / "config.alloy").is_file()
    assert (restored_collector.state_dir / "pve.yml").is_file()

    # Clone Collector -> verify fresh unique collector_id regenerated & persisted via dump_env()
    cloned_collector = NS8ModuleInstance(
        kind="collector",
        install_dir=tmp_path / "collector_cloned_home",
        module_id="central-monitoring-collector3",
        backends=live_backends,
    )
    shutil.copytree(
        restored_collector.state_dir, cloned_collector.state_dir, dirs_exist_ok=True
    )
    await cloned_collector.run_script("actions/clone-module/50configure", {}, validate_io=False)

    cloned_cid = cloned_collector.read_meta()["persisted_env"]["COLLECTOR_ID"]
    assert cloned_cid != source_cid
    cloned_alloy_txt = (cloned_collector.state_dir / "config.alloy").read_text(encoding="utf-8")
    assert cloned_cid in cloned_alloy_txt


@pytest.mark.asyncio
async def test_05_hub_restic_backup_preserves_customer_portal_viewer_secrets(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify Restic state-include.conf backs up sealed Customer Portal viewer credentials."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_portal_src",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )
    await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": True,
            "portal_viewer_username": "acme-viewer",
            "portal_viewer_password": "AcmePortalPassword!2026",
        },
    )
    assert load_portal_viewer_secret(hub.state_dir, "acme-gmbh") == "AcmePortalPassword!2026"

    await hub.run_script("bin/module-dump-state", validate_io=False)
    restored_hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_portal_restored",
        module_id="central-monitoring-hub2",
        backends=live_backends,
    )
    hub.copy_restic_snapshot_to(restored_hub.install_dir)

    assert (
        load_portal_viewer_secret(restored_hub.state_dir, "acme-gmbh")
        == "AcmePortalPassword!2026"
    ), (
        "Customer portal viewer password lost during Restic backup/restore because "
        "state/portal-secrets.json and state/.portal.key are omitted from state-include.conf!"
    )


@pytest.mark.asyncio
async def test_06_hub_actions_honor_ns8_agent_state_dir_across_all_subpackages(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify hub_core, hub_tenancy, and hub_alerting all resolve AGENT_STATE_DIR consistently."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_env_contract",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    unrelated_cwd = tmp_path / "unrelated_caller_cwd"
    unrelated_cwd.mkdir(parents=True, exist_ok=True)

    await hub.run_script(
        "actions/create-module/20initialize",
        cwd=unrelated_cwd,
        omit_env_keys=("STATE_DIR",),
    )
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
        cwd=unrelated_cwd,
        omit_env_keys=("STATE_DIR",),
    )
    await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": False,
        },
        cwd=unrelated_cwd,
        omit_env_keys=("STATE_DIR",),
    )

    assert not (unrelated_cwd / "tenants.json").exists(), (
        "save-tenant ignored AGENT_STATE_DIR/HUB_STATE_DIR and polluted caller working directory!"
    )
    _, _, _, ov = await hub.run_script(
        "actions/get-overview/20read",
        {},
        cwd=unrelated_cwd,
        omit_env_keys=("STATE_DIR",),
    )
    assert ov["counts"]["tenants"] == 1


@pytest.mark.asyncio
async def test_07_hub_ldap_disabled_keeps_bind_mountable_ldap_toml_for_podman(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify configure-module with ldap_enabled=False keeps config/grafana/ldap.toml on disk for grafana.service."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_ldap_disabled",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "ldap_enabled": False,
        },
    )
    assert (hub.config_dir / "grafana" / "ldap.toml").is_file(), (
        "config/grafana/ldap.toml was unlinked when ldap_enabled=False, breaking "
        "grafana.service --volume=%S/config/grafana/ldap.toml:/etc/grafana/ldap.toml:Z!"
    )


@pytest.mark.asyncio
async def test_08_e2e_security_and_snmpv3_roundtrip_regressions(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify CRIT-01 proxy allowlist/slashes, CRIT-02 token exfil guard, and SNMPv3 round-trip."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_sec_reg",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )
    _, _, _, acme_saved = await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq", "branch"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": False,
        },
    )
    acme_token: str = acme_saved["auth_token"]

    live_gw = await live_backends.start_hub_gateway(hub.state_dir, tmp_path / "sec_tls")
    client_ssl = ssl.create_default_context(cafile=str(live_gw.ca_cert_path))

    # 1. CRIT-01: Live hub_gateway blocks /api/datasources/proxy/uid/loki/config,
    #    /api/datasources/proxy/uid/loki/loki/api/v1/push, and //metrics (without touching Grafana),
    #    while allowing /api/datasources/proxy/uid/prometheus/api/v1/query through to Grafana!
    live_backends.grafana.ds_proxy_hits.clear()
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{live_gw.https_url}/api/datasources/proxy/uid/loki/config",
            ssl=client_ssl,
        ) as loki_cfg_resp:
            assert loki_cfg_resp.status == 403

        async with session.post(
            f"{live_gw.https_url}/api/datasources/proxy/uid/loki/loki/api/v1/push",
            json={"streams": []},
            ssl=client_ssl,
        ) as loki_push_bypass_resp:
            assert loki_push_bypass_resp.status == 403

        async with session.post(
            f"{live_gw.https_url}/api/datasources/proxy/uid/prometheus/api/v1/write",
            data=b"bad",
            ssl=client_ssl,
        ) as prom_write_bypass_resp:
            assert prom_write_bypass_resp.status == 403

        # Use encoded=True so aiohttp sends raw double-slash paths (`//metrics`, `//api/...`) on wire
        for raw_slash_path in (
            "//metrics",
            "/api//datasources/proxy/uid/loki/loki/api/v1/delete",
            "/api/datasources/proxy/uid/loki/loki//api/v1/delete",
        ):
            raw_url = URL(f"{live_gw.https_url}{raw_slash_path}", encoded=True)
            async with session.get(raw_url, ssl=client_ssl) as slash_resp:
                assert slash_resp.status == 403, f"Expected 403 for {raw_slash_path}"

        assert live_backends.grafana.ds_proxy_hits == [], (
            "Forbidden datasource proxy or double-slash paths must never reach upstream Grafana!"
        )

        # Legitimate read-only query subpaths MUST pass through to Grafana
        async with session.get(
            f"{live_gw.https_url}/api/datasources/proxy/uid/prometheus/api/v1/query?query=up",
            ssl=client_ssl,
        ) as allowed_prom_resp:
            assert allowed_prom_resp.status == 200
            prom_proxy_json = await allowed_prom_resp.json()
            assert prom_proxy_json["proxied_by_grafana"] is True

        async with session.post(
            f"{live_gw.https_url}/api/datasources/proxy/uid/loki/loki/api/v1/query_range",
            data={"query": '{customer="acme-gmbh"}'},
            ssl=client_ssl,
        ) as allowed_loki_resp:
            assert allowed_loki_resp.status == 200
            loki_proxy_json = await allowed_loki_resp.json()
            assert loki_proxy_json["proxied_by_grafana"] is True

        assert len(live_backends.grafana.ds_proxy_hits) == 2

    # 2. CRIT-02: Collector test-hub-connection refuses stored token fallback when hub_url
    #    differs from persisted HUB_URL, while succeeding when hub_url matches persisted HUB_URL!
    decoy_hits: list[dict[str, str]] = []
    decoy_app = aiohttp.web.Application()

    async def _decoy_verify(req: aiohttp.web.Request) -> aiohttp.web.Response:
        decoy_hits.append(dict(req.headers))
        return aiohttp.web.json_response({"status": "ok", "customer": "exfiltrated"})

    decoy_app.router.add_get("/api/v1/ingest/verify", _decoy_verify)
    decoy_runner = aiohttp.web.AppRunner(decoy_app, access_log=None)
    await decoy_runner.setup()
    decoy_tls_ctx, _ = (
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
        None,
    )
    decoy_tls_ctx.load_cert_chain(
        certfile=str(live_gw.ca_cert_path),
        keyfile=str(live_gw.ca_cert_path.parent / "hub-e2e-key.pem"),
    )
    decoy_site = aiohttp.web.TCPSite(
        decoy_runner, host="127.0.0.1", port=0, ssl_context=decoy_tls_ctx
    )
    await decoy_site.start()
    decoy_port = int(decoy_site._server.sockets[0].getsockname()[1])  # type: ignore[union-attr]

    try:
        collector = NS8ModuleInstance(
            kind="collector",
            install_dir=tmp_path / "collector_sec_reg",
            module_id="central-monitoring-collector1",
            backends=live_backends,
        )
        await collector.run_script("actions/create-module/20initialize")
        await collector.run_script(
            "actions/configure-module/20configure",
            {
                "hub_url": live_gw.https_url,
                "auth_token": acme_token,
                "customer": "acme-gmbh",
                "site": "hq",
                "tls_skip_verify": True,
            },
        )

        # Matching saved HUB_URL (with trailing slash normalization) -> succeeds with stored token
        _, _, _, match_probe = await collector.run_script(
            "actions/test-hub-connection/20test",
            {
                "hub_url": f"{live_gw.https_url}/",
                "auth_token": "",
                "tls_skip_verify": True,
            },
        )
        assert match_probe["ok"] is True
        assert match_probe["http_status"] == 200
        assert match_probe["verified_customer"] == "acme-gmbh"

        # Different hub_url with empty auth_token -> MUST refuse stored token fallback and never connect
        _, _, _, diff_probe = await collector.run_script(
            "actions/test-hub-connection/20test",
            {
                "hub_url": f"https://127.0.0.1:{decoy_port}",
                "auth_token": "",
                "tls_skip_verify": True,
            },
        )
        assert diff_probe["ok"] is False
        assert diff_probe["http_status"] == 0
        assert diff_probe["verified_customer"] is None
        assert decoy_hits == [], "Stored bearer token must NEVER be sent to a modified hub_url!"
    finally:
        await decoy_runner.cleanup()

    # 3. SNMPv3 target save + list-targets (Hub) & list-local-targets (Collector) metadata round-trip
    _, _, _, hub_v3_saved = await hub.run_script(
        "actions/save-target/20save",
        {
            "name": "FortiGate HQ SNMPv3",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-gmbh",
            "site": "hq",
            "device_role": "snmp-firewall",
            "endpoints": ["203.0.113.25"],
            "snmp_module": "fortigate",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "msp-forti-ro",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "auth_password": "HubSnmpV3AuthSecret!2026",
                "priv_protocol": "AES256",
                "priv_password": "HubSnmpV3PrivSecret!2026",
            },
        },
    )
    _, hub_list_raw, _, hub_listed = await hub.run_script("actions/list-targets/20read", {})
    assert "HubSnmpV3AuthSecret!2026" not in hub_list_raw
    assert "HubSnmpV3PrivSecret!2026" not in hub_list_raw
    hub_v3_row = next(t for t in hub_listed["targets"] if t["id"] == hub_v3_saved["id"])
    assert hub_v3_row["has_secret"] is True
    assert hub_v3_row["snmp_v3"] == {
        "username": "msp-forti-ro",
        "security_level": "authPriv",
        "auth_protocol": "SHA256",
        "priv_protocol": "AES256",
    }

    # Edit round-trip with secret_unchanged=True preserves passphrases in snmp.yml
    await hub.run_script(
        "actions/save-target/20save",
        {
            "id": hub_v3_saved["id"],
            "name": "FortiGate HQ Cluster SNMPv3",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-gmbh",
            "site": "hq",
            "device_role": "snmp-firewall",
            "endpoints": ["203.0.113.25"],
            "snmp_module": "fortigate",
            "snmp_version": "v3",
            "secret_unchanged": True,
            "snmp_v3": hub_v3_row["snmp_v3"],
        },
    )
    hub_snmp_yml = (hub.config_dir / "snmp" / "snmp.yml").read_text(encoding="utf-8")
    assert "HubSnmpV3AuthSecret!2026" in hub_snmp_yml
    assert "HubSnmpV3PrivSecret!2026" in hub_snmp_yml

    # Collector LAN SNMPv3 save + list-local-targets round-trip + secret_unchanged edit
    _, _, _, col_v3_saved = await collector.run_script(
        "actions/save-local-target/20save",
        {
            "name": "Synology NAS Rack 1",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-nas",
            "host": "192.168.10.50",
            "port": 161,
            "snmp_module": "synology",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "nas-monitor-v3",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "auth_password": "ColSnmpV3AuthSecret!2026",
                "priv_protocol": "AES",
                "priv_password": "ColSnmpV3PrivSecret!2026",
            },
        },
    )
    _, col_list_raw, _, col_listed = await collector.run_script(
        "actions/list-local-targets/20read", {}
    )
    assert "ColSnmpV3AuthSecret!2026" not in col_list_raw
    assert "ColSnmpV3PrivSecret!2026" not in col_list_raw
    col_v3_row = next(t for t in col_listed["targets"] if t["id"] == col_v3_saved["id"])
    assert col_v3_row["has_snmp_secret"] is True
    assert col_v3_row["snmp_v3"] == {
        "username": "nas-monitor-v3",
        "security_level": "authPriv",
        "auth_protocol": "SHA256",
        "priv_protocol": "AES",
    }

    await collector.run_script(
        "actions/save-local-target/20save",
        {
            "id": col_v3_saved["id"],
            "name": "Synology NAS Rack 1 Updated",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-nas",
            "host": "192.168.10.50",
            "port": 161,
            "snmp_module": "synology",
            "snmp_version": "v3",
            "secret_unchanged": True,
            "snmp_v3": col_v3_row["snmp_v3"],
        },
    )
    col_snmp_auths = (collector.state_dir / "secrets" / "snmp-auths.yml").read_text(
        encoding="utf-8"
    )
    assert "ColSnmpV3AuthSecret!2026" in col_snmp_auths
    assert "ColSnmpV3PrivSecret!2026" in col_snmp_auths


def _resp2_bulk(val: str) -> bytes:
    raw = val.encode("utf-8")
    return f"${len(raw)}\r\n".encode("ascii") + raw + b"\r\n"


def _resp2_array(items: list[bytes]) -> bytes:
    return f"*{len(items)}\r\n".encode("ascii") + b"".join(items)


def _verify_png_header_and_crc(raw: bytes) -> tuple[int, int]:
    assert raw.startswith(b"\x89PNG\r\n\x1a\n"), "Invalid PNG magic header"
    offset = 8
    width = height = 0
    saw_iend = False
    while offset + 8 <= len(raw):
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        ctype = raw[offset + 4 : offset + 8]
        cdata = raw[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", raw[offset + 8 + length : offset + 12 + length])[0]
        actual_crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        assert expected_crc == actual_crc, f"PNG CRC mismatch in chunk {ctype!r}"
        if ctype == b"IHDR":
            width, height = struct.unpack(">II", cdata[:8])
        elif ctype == b"IEND":
            saw_iend = True
            break
        offset += 12 + length
    assert width > 0 and height > 0 and saw_iend
    return width, height


@pytest.mark.asyncio
async def test_09_phase2_cluster_ns8_harvesting_qnap_printer_and_repomd(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify Phase-2 cluster-wide NS8 harvesting, QNAP/Printer SNMP profiles, and repomd catalog."""
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_phase2_home",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )
    _, _, _, acme_saved = await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq", "branch"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": False,
        },
    )
    acme_token: str = acme_saved["auth_token"]

    live_gw = await live_backends.start_hub_gateway(hub.state_dir, tmp_path / "phase2_tls")
    client_ssl = ssl.create_default_context(cafile=str(live_gw.ca_cert_path))

    # 1. Start live mock NS8 host node_exporter (:9100 equivalent) + live TCP RESP2 Redis server
    ne_hits = 0
    ne_app = aiohttp.web.Application()
    ne_exposition = "\n".join(
        [
            "# HELP ns8_container_info NS8 rootless module container metadata.",
            "# TYPE ns8_container_info gauge",
            'ns8_container_info{module_id="mail1",container="postfix",image="ghcr.io/nethserver/mail-postfix:1.5.0",unit="postfix.service"} 1',
            'ns8_container_start_time_seconds{module_id="mail1",container="postfix"} 1763700000',
            'ns8_container_restarts_total{module_id="mail1",container="postfix"} 0',
            'ns8_container_info{module_id="nextcloud1",container="nextcloud-app",image="ghcr.io/nethserver/nextcloud-app:1.3.0",unit="nextcloud-app.service"} 1',
            'ns8_container_running{module_id="nextcloud1",container="nextcloud-app"} 1',
            'ns8_container_restarts_total{module_id="nextcloud1",container="nextcloud-app"} 2',
            'ns8_container_info{module_id="samba1",container="samba-dc",image="ghcr.io/nethserver/samba-dc:2.1.0",unit="samba-dc.service"} 1',
            'ns8_container_running{module_id="samba1",container="samba-dc"} 0',
            'ns8_container_restarts_total{module_id="samba1",container="samba-dc"} 5',
            'node_systemd_unit_state{name="samba-dc.service",state="failed"} 1',
            'node_systemd_unit_state{name="postfix.service",state="active"} 1',
            "",
        ]
    )

    async def _serve_ne_metrics(_req: aiohttp.web.Request) -> aiohttp.web.Response:
        nonlocal ne_hits
        ne_hits += 1
        return aiohttp.web.Response(text=ne_exposition, content_type="text/plain; version=0.0.4")

    ne_app.router.add_get("/metrics", _serve_ne_metrics)
    ne_runner = aiohttp.web.AppRunner(ne_app, access_log=None)
    await ne_runner.setup()
    ne_site = aiohttp.web.TCPSite(ne_runner, host="127.0.0.1", port=0)
    await ne_site.start()
    ne_port = int(ne_site._server.sockets[0].getsockname()[1])  # type: ignore[union-attr]

    redis_hashes: dict[str, dict[str, str]] = {
        "node/1/vpn": {"ip_address": "10.5.4.1"},
        "module/mail1/backup": {"status": "ok", "last_success": "1763740000"},
        "module/nextcloud1/backup": {"status": "failed", "last_success": "1763650000"},
        "module/samba1/backup": {"exit_code": "0", "completed": "1763742000"},
    }
    redis_commands_seen: list[list[str]] = []

    async def _handle_resp2(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while not reader.at_eof():
                header = await reader.readline()
                if not header:
                    break
                assert header.startswith(b"*")
                argc = int(header[1:].rstrip(b"\r\n"))
                cmd_args: list[str] = []
                for _ in range(argc):
                    blen_line = await reader.readline()
                    assert blen_line.startswith(b"$")
                    blen = int(blen_line[1:].rstrip(b"\r\n"))
                    raw_val = await reader.readexactly(blen + 2)
                    cmd_args.append(raw_val[:-2].decode("utf-8"))

                redis_commands_seen.append(cmd_args)
                verb = cmd_args[0].upper()
                if verb == "AUTH":
                    writer.write(b"+OK\r\n")
                elif verb == "SCAN":
                    backup_keys = [
                        _resp2_bulk(k) for k in sorted(redis_hashes) if "backup" in k
                    ]
                    writer.write(_resp2_array([_resp2_bulk("0"), _resp2_array(backup_keys)]))
                elif verb == "TYPE":
                    key = cmd_args[1]
                    writer.write(b"+hash\r\n" if key in redis_hashes else b"+none\r\n")
                elif verb == "HGETALL":
                    key = cmd_args[1]
                    hmap = redis_hashes.get(key, {})
                    flat: list[bytes] = []
                    for hk, hv in hmap.items():
                        flat.append(_resp2_bulk(hk))
                        flat.append(_resp2_bulk(hv))
                    writer.write(_resp2_array(flat))
                else:
                    writer.write(b"-ERR unsupported command in mock\r\n")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()

    redis_server = await asyncio.start_server(_handle_resp2, host="127.0.0.1", port=0)
    redis_port = int(redis_server.sockets[0].getsockname()[1])

    try:
        collector = NS8ModuleInstance(
            kind="collector",
            install_dir=tmp_path / "collector_phase2_home",
            module_id="central-monitoring-collector1",
            backends=live_backends,
        )
        await collector.run_script("actions/create-module/20initialize")
        _, _, _, col_cfg = await collector.run_script(
            "actions/configure-module/20configure",
            {
                "hub_url": live_gw.https_url,
                "auth_token": acme_token,
                "customer": "acme-gmbh",
                "site": "hq",
                "tls_skip_verify": True,
            },
        )
        collector_id = col_cfg["collector_id"]

        # Harvest cluster-wide NS8 rootless containers & backups via live HTTP + live RESP2 Redis
        await collector.run_script(
            "bin/collect-ns8-metrics",
            validate_io=False,
            extra_env={
                "NS8_NODE_EXPORTER_URL": f"http://127.0.0.1:{ne_port}/metrics",
                "REDIS_ADDRESS": f"127.0.0.1:{redis_port}",
                "REDIS_PASSWORD": "e2e-redis-replica-pw",
            },
        )
        assert ne_hits >= 1
        assert any(cmd[0].upper() == "AUTH" for cmd in redis_commands_seen)
        assert any(cmd[0].upper() == "SCAN" for cmd in redis_commands_seen)

        ns8_prom_txt = (collector.state_dir / "textfile" / "ns8.prom").read_text(encoding="utf-8")
        # Verify all 3 rootless NS8 modules (mail1, nextcloud1, samba1) harvested for containers & backups
        assert 'ns8_backup_status{module_id="mail1"} 1' in ns8_prom_txt
        assert 'ns8_backup_status{module_id="nextcloud1"} 0' in ns8_prom_txt
        assert 'ns8_backup_failed{module_id="nextcloud1"} 1' in ns8_prom_txt
        assert 'ns8_backup_status{module_id="samba1"} 1' in ns8_prom_txt
        assert 'ns8_container_running{module_id="mail1",container="postfix"} 1' in ns8_prom_txt
        assert (
            'ns8_container_running{module_id="nextcloud1",container="nextcloud-app"} 1'
            in ns8_prom_txt
        )
        assert 'ns8_container_running{module_id="samba1",container="samba-dc"} 0' in ns8_prom_txt
        assert (
            'ns8_container_restarts_total{module_id="samba1",container="samba-dc"} 5'
            in ns8_prom_txt
        )
        assert 'ns8_systemd_unit_failed{name="samba-dc.service"} 1' in ns8_prom_txt

        # Push harvested cluster-wide ns8_* metrics + RFC 3805 snmp-printer metrics & logs through live hub_gateway
        live_backends.prom_writes.clear()
        live_backends.loki_pushes.clear()

        phase2_series = parse_prom_textfile_to_timeseries(
            ns8_prom_txt,
            extra_labels={
                "customer": "victim-gmbh",  # Adversarial spoof stripped to acme-gmbh
                "site": "hq",
                "device_role": "ns8",
                "collector_id": collector_id,
            },
        )
        # Append RFC 3805 Printer-MIB metrics with device_role="snmp-printer"
        for metric_name, val in (
            ("prtMarkerLifeCount", 148250.0),
            ("prtMarkerSuppliesMaxCapacity", 10000.0),
            ("prtMarkerSuppliesLevel", 200.0),
            ("prtAlertSeverityLevel", 3.0),
        ):
            phase2_series.append(
                TimeSeries(
                    labels=[
                        ("__name__", metric_name),
                        ("collector_id", collector_id),
                        ("customer", "victim-gmbh"),
                        ("device_role", "snmp-printer"),
                        ("instance", "192.168.10.80"),
                        ("site", "branch"),
                    ],
                    samples=[Sample(value=val, timestamp_ms=1763742500000)],
                )
            )

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{live_gw.https_url}/api/v1/write",
                data=snappy_compress(build_write_request(phase2_series)),
                headers={
                    "Authorization": f"Bearer {acme_token}",
                    "Content-Type": "application/x-protobuf",
                    "Content-Encoding": "snappy",
                    "X-Prometheus-Remote-Write-Version": "0.1.0",
                },
                ssl=client_ssl,
            ) as p_resp:
                assert p_resp.status == 204

            assert len(live_backends.prom_writes) == 1
            pushed_series = live_backends.prom_writes[0]
            assert len(pushed_series) == len(phase2_series)
            roles_seen = {dict(ts.labels)["device_role"] for ts in pushed_series}
            assert roles_seen == {"ns8", "snmp-printer"}
            assert all(dict(ts.labels)["customer"] == "acme-gmbh" for ts in pushed_series)

            printer_pb_logs = build_loki_push_request(
                [
                    LokiStream(
                        labels=(
                            f'{{customer="victim-gmbh", site="branch", '
                            f'device_role="snmp-printer", collector_id="{collector_id}", job="syslog"}}'
                        ),
                        entries=[
                            LokiEntry(
                                timestamp_seconds=1763742505,
                                timestamp_nanos=0,
                                line="<132>Kyocera TASKalfa 4053ci: Toner Black below 2%",
                            )
                        ],
                    )
                ]
            )
            async with session.post(
                f"{live_gw.https_url}/loki/api/v1/push",
                data=snappy_compress(printer_pb_logs),
                headers={
                    "Authorization": f"Bearer {acme_token}",
                    "Content-Type": "application/x-protobuf",
                    "Content-Encoding": "snappy",
                    "X-Scope-OrgID": "victim-gmbh",
                },
                ssl=client_ssl,
            ) as l_resp:
                assert l_resp.status == 204

            assert len(live_backends.loki_pushes) == 1
            assert live_backends.loki_pushes[0].org_id == "acme-gmbh"
            assert live_backends.loki_pushes[0].labels["customer"] == "acme-gmbh"
            assert live_backends.loki_pushes[0].labels["device_role"] == "snmp-printer"

        # 2. Save QNAP (snmp-nas) & Printer (snmp-printer) targets on both Hub and Collector
        await hub.run_script(
            "actions/save-target/20save",
            {
                "name": "QNAP TS-h886 Backup NAS",
                "enabled": True,
                "target_type": "snmp",
                "customer": "acme-gmbh",
                "site": "hq",
                "device_role": "snmp-nas",
                "endpoints": ["203.0.113.60"],
                "snmp_module": "qnap",
                "snmp_version": "v3",
                "snmp_v3": {
                    "username": "qnap-snmp-ro",
                    "security_level": "authPriv",
                    "auth_protocol": "SHA512",
                    "auth_password": "QnapAuthPassword!2026",
                    "priv_protocol": "AES256",
                    "priv_password": "QnapPrivPassword!2026",
                },
            },
        )
        await hub.run_script(
            "actions/save-target/20save",
            {
                "name": "Kyocera Floor 2 MFP",
                "enabled": True,
                "target_type": "snmp",
                "customer": "acme-gmbh",
                "site": "branch",
                "device_role": "snmp-printer",
                "endpoints": ["203.0.113.80"],
                "snmp_module": "printer",
                "snmp_version": "v2c",
                "snmp_community": "printer-ro-comm",
            },
        )
        _, hub_targets_raw, _, hub_targets = await hub.run_script(
            "actions/list-targets/20read", {}
        )
        assert len(hub_targets["targets"]) == 2
        assert "QnapAuthPassword!2026" not in hub_targets_raw
        assert "printer-ro-comm" not in hub_targets_raw
        hub_snmp_cfg = (hub.config_dir / "snmp" / "snmp.yml").read_text(encoding="utf-8")
        assert "qnapVolumeStatus" in hub_snmp_cfg
        assert "qnapDiskTemperature" in hub_snmp_cfg
        assert "prtMarkerSuppliesLevel" in hub_snmp_cfg
        assert "prtAlertSeverityLevel" in hub_snmp_cfg

        await collector.run_script(
            "actions/save-local-target/20save",
            {
                "name": "LAN QNAP NAS",
                "enabled": True,
                "target_type": "snmp",
                "device_role": "snmp-nas",
                "host": "192.168.10.60",
                "snmp_module": "qnap",
                "snmp_version": "v3",
                "snmp_v3": {
                    "username": "lan-qnap-v3",
                    "security_level": "authPriv",
                    "auth_protocol": "SHA384",
                    "auth_password": "LanQnapAuthPassword!2026",
                    "priv_protocol": "AES256",
                    "priv_password": "LanQnapPrivPassword!2026",
                },
            },
        )
        await collector.run_script(
            "actions/save-local-target/20save",
            {
                "name": "LAN Brother LaserJet",
                "enabled": True,
                "target_type": "snmp",
                "device_role": "snmp-printer",
                "host": "192.168.10.80",
                "snmp_module": "printer",
                "snmp_version": "v2c",
                "snmp_community": "lan-printer-ro",
            },
        )
        _, col_targets_raw, _, col_targets = await collector.run_script(
            "actions/list-local-targets/20read", {}
        )
        assert len(col_targets["targets"]) == 2
        assert "LanQnapAuthPassword!2026" not in col_targets_raw
        assert "lan-printer-ro" not in col_targets_raw
        col_alloy_cfg = (collector.state_dir / "config.alloy").read_text(encoding="utf-8")
        col_snmp_yml = (collector.state_dir / "secrets" / "snmp-auths.yml").read_text(
            encoding="utf-8"
        )
        assert '"snmp-printer"' in col_alloy_cfg
        assert "qnapVolumeStatus" in col_snmp_yml
        assert "prtMarkerSuppliesLevel" in col_snmp_yml
    finally:
        redis_server.close()
        await redis_server.wait_closed()
        await ne_runner.cleanup()

    # 3. Execute scripts/generate-repomd.py --org msp-hosting --tag v1.0.0 --strict-assets
    repomd_out = tmp_path / "ns8_software_center_repo"
    gen_proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(REPO_ROOT / "scripts" / "generate-repomd.py"),
        "--org",
        "msp-hosting",
        "--tag",
        "v1.0.0",
        "--strict-assets",
        "--output-dir",
        str(repomd_out),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    gen_stdout, gen_stderr = await gen_proc.communicate()
    assert gen_proc.returncode == 0, (
        f"generate-repomd.py failed: {gen_stdout.decode()} / {gen_stderr.decode()}"
    )

    for expected_rel in (
        "repomd.json",
        "repodata.json",
        "repodata/repomd.json",
        ".nojekyll",
        "index.html",
    ):
        fpath = repomd_out / expected_rel
        assert fpath.is_file(), f"Missing generated catalog file: {expected_rel}"
        assert b"\r\n" not in fpath.read_bytes(), f"CRLF detected in {expected_rel}"

    catalog = json.loads((repomd_out / "repomd.json").read_text(encoding="utf-8"))
    by_id = {entry["id"]: entry for entry in catalog}
    assert set(by_id.keys()) == {"central-monitoring-hub", "central-monitoring-collector"}

    for mod_id in ("central-monitoring-hub", "central-monitoring-collector"):
        entry = by_id[mod_id]
        assert entry["source"] == f"ghcr.io/msp-hosting/{mod_id}"
        assert entry["description"]["en"].strip()
        assert entry["description"]["de"].strip()
        assert entry["versions"][0]["tag"] == "1.0.0"
        assert entry["versions"][0]["testing"] is False

        for icon_name in ("logo.png", "module_default_icon.png"):
            icon_path = repomd_out / mod_id / icon_name
            assert icon_path.is_file()
            w, h = _verify_png_header_and_crc(icon_path.read_bytes())
            assert (w, h) == (128, 128)

    hub_images = by_id["central-monitoring-hub"]["versions"][0]["labels"]["org.nethserver.images"]
    assert "ghcr.io/msp-hosting/central-monitoring-hub-gateway:1.0.0" in hub_images


@pytest.mark.asyncio
async def test_10_live_ns8_probe_restore_clone_and_py39_compat(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify LIVE-NS8-02 full 8-module blackbox & target/rule restore/clone + LIVE-NS8-04 Py3.9."""
    # 1. LIVE-NS8-04: Verify all tests/e2e_integration/*.py + fake-agent shims parse under Python 3.9
    import tests.e2e_integration.harness as e2e_harness

    def _assert_no_py310_stdlib_kwargs(tree: ast.AST, label: str) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "write_text":
                    assert not any(kw.arg == "newline" for kw in node.keywords), (
                        f"Python 3.10+ write_text(newline=...) in {label}"
                    )
                if isinstance(node.func, ast.Name) and node.func.id == "dataclass":
                    assert not any(kw.arg == "slots" for kw in node.keywords), (
                        f"Python 3.10+ dataclass(slots=...) in {label}"
                    )

    e2e_dir = Path(__file__).resolve().parent
    py_files = sorted(e2e_dir.glob("*.py"))
    assert len(py_files) >= 4
    for py_file in py_files:
        raw = py_file.read_bytes()
        assert b"\r\n" not in raw and not raw.startswith(b"\xef\xbb\xbf")
        src = raw.decode("utf-8")
        assert "from __future__ import annotations" in src, f"Missing future import in {py_file.name}"
        parsed_tree = ast.parse(src, filename=str(py_file), feature_version=(3, 9))
        _assert_no_py310_stdlib_kwargs(parsed_tree, py_file.name)

    for shim_name, shim_src in (
        ("agent/__init__.py", e2e_harness._FAKE_AGENT_INIT_PY),
        ("agent/tasks.py", e2e_harness._FAKE_AGENT_TASKS_PY),
        ("agent/ldapproxy.py", e2e_harness._FAKE_AGENT_LDAPPROXY_PY),
    ):
        shim_tree = ast.parse(shim_src, filename=shim_name, feature_version=(3, 9))
        _assert_no_py310_stdlib_kwargs(shim_tree, shim_name)

    # 2. LIVE-NS8-02: Verify configure-module upgrades bootstrap blackbox.yml to all 8 modules
    #    and restore-module + clone-module re-render blackbox.yml, file_sd, snmp.yml, and rules!
    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_live_ns8_src",
        module_id="central-monitoring-hub1",
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")
    await hub.run_script(
        "actions/configure-module/20configure",
        {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )

    expected_bb_modules = (
        "http_2xx:",
        "http_2xx_insecure:",
        "http_post_2xx:",
        "http_post_2xx_insecure:",
        "tcp_connect:",
        "dns_tcp:",
        "dns_udp:",
        "icmp:",
    )
    bb_cfg_txt = (hub.config_dir / "blackbox" / "blackbox.yml").read_text(encoding="utf-8")
    for mod_token in expected_bb_modules:
        assert mod_token in bb_cfg_txt, f"Missing {mod_token} in rendered blackbox.yml"

    await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "acme-gmbh",
            "display_name": "Acme GmbH",
            "sites": ["hq"],
            "contact_emails": ["it@acme.de"],
            "customer_portal_enabled": False,
        },
    )
    await hub.run_script(
        "actions/save-target/20save",
        {
            "name": "Acme Webhook Health",
            "enabled": True,
            "target_type": "blackbox",
            "customer": "acme-gmbh",
            "site": "hq",
            "device_role": "web",
            "endpoints": ["https://api.acme.de/health"],
            "blackbox_module": "http_post_2xx",
            "tls_skip_verify": True,
        },
    )
    await hub.run_script(
        "actions/save-target/20save",
        {
            "name": "Acme Core UPS",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-gmbh",
            "site": "hq",
            "device_role": "snmp-ups",
            "endpoints": ["203.0.113.44"],
            "snmp_module": "apcupsd",
            "snmp_version": "v2c",
            "snmp_community": "ups-restore-ro",
        },
    )

    custom_packs_payload = _default_alerting_payload(customer_email_enabled=True)
    custom_packs_payload["enabled_rule_packs"] = ["ns8-cluster", "proxmox-ve"]
    await hub.run_script("actions/configure-alerting/20configure", custom_packs_payload)

    # Simulate Restic restore into clean Hub home (where config/ starts empty!)
    await hub.run_script("bin/module-dump-state", validate_io=False)
    restored_hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_live_ns8_restored",
        module_id="central-monitoring-hub2",
        backends=live_backends,
    )
    hub.copy_restic_snapshot_to(restored_hub.install_dir)
    orig_env = json.loads(hub.meta_file.read_text(encoding="utf-8"))["persisted_env"]
    await restored_hub.run_script(
        "actions/restore-module/06copyenv", {"environment": orig_env}, validate_io=False
    )
    await restored_hub.run_script("actions/restore-module/50configure", {}, validate_io=False)

    restored_bb = (restored_hub.config_dir / "blackbox" / "blackbox.yml").read_text(encoding="utf-8")
    for mod_token in expected_bb_modules:
        assert mod_token in restored_bb
    assert list((restored_hub.config_dir / "prometheus" / "file_sd" / "blackbox").glob("*.json"))
    assert list((restored_hub.config_dir / "prometheus" / "file_sd" / "snmp").glob("*.json"))
    assert "ups-restore-ro" in (restored_hub.config_dir / "snmp" / "snmp.yml").read_text(
        encoding="utf-8"
    )
    restored_rules = sorted(
        p.name for p in (restored_hub.config_dir / "prometheus" / "rules").glob("*.yml")
    )
    assert restored_rules == ["ns8-cluster.yml", "proxmox-ve.yml"]

    # Simulate clone-module into clean Hub home and verify probe/target/rule configs re-render too
    cloned_hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_live_ns8_cloned",
        module_id="central-monitoring-hub3",
        backends=live_backends,
    )
    shutil.copytree(restored_hub.state_dir, cloned_hub.state_dir, dirs_exist_ok=True)
    await cloned_hub.run_script(
        "actions/clone-module/50configure",
        {"host": "monitoring-clone.msp.example.com"},
        validate_io=False,
    )
    cloned_bb = (cloned_hub.config_dir / "blackbox" / "blackbox.yml").read_text(encoding="utf-8")
    for mod_token in expected_bb_modules:
        assert mod_token in cloned_bb
    assert list((cloned_hub.config_dir / "prometheus" / "file_sd" / "blackbox").glob("*.json"))
    assert list((cloned_hub.config_dir / "prometheus" / "file_sd" / "snmp").glob("*.json"))
    assert "ups-restore-ro" in (cloned_hub.config_dir / "snmp" / "snmp.yml").read_text(
        encoding="utf-8"
    )
    cloned_rules = sorted(
        p.name for p in (cloned_hub.config_dir / "prometheus" / "rules").glob("*.yml")
    )
    assert cloned_rules == ["ns8-cluster.yml", "proxmox-ve.yml"]


@pytest.mark.asyncio
async def test_11_v102_live_ad_ldap_discovery_tester_and_multi_user_customer_portal(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify v1.0.2 live AD LDAPv3 group discovery/login tester, Viewer SSO, and multi-user Customer Portals."""
    base_dn = "DC=ad,DC=bls-isp,DC=net"
    bind_dn = f"CN=ldapsvc,CN=Users,{base_dn}"
    bind_pw = "AdBlsIspBindSecret!2026"

    da_dn = f"CN=Domain Admins,CN=Users,{base_dn}"
    du_dn = f"CN=Domain Users,CN=Users,{base_dn}"
    ops_dn = f"CN=MSP Operations,OU=Groups,{base_dn}"
    noc_dn = f"CN=MSP Tier-1 NOC,OU=SubTeams,OU=Groups,{base_dn}"
    ro_dn = f"CN=MSP ReadOnly,OU=Groups,{base_dn}"

    genera_dn = f"CN=Genera,OU=MSP,{base_dn}"
    nested_dn = f"CN=Nora Engineer,OU=MSP,{base_dn}"
    viewer_dn = f"CN=Viktor Auditor,OU=MSP,{base_dn}"

    ad_entries = [
        {
            "dn": da_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "Domain Admins",
                "sAMAccountName": "Domain Admins",
                "description": "Designated administrators of the domain",
                "primaryGroupToken": "512",
                "member": [genera_dn],
            },
        },
        {
            "dn": du_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "Domain Users",
                "sAMAccountName": "Domain Users",
                "description": "All domain users",
                "objectSid": build_ad_object_sid(513),
                "member": [],
            },
        },
        {
            "dn": ops_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP Operations",
                "sAMAccountName": "MSP-Operations",
                "description": "MSP Org 1 Editor team",
                "member": [noc_dn],
            },
        },
        {
            "dn": noc_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP Tier-1 NOC",
                "sAMAccountName": "MSP-Tier1-NOC",
                "description": "Nested child NOC group",
                "member": [nested_dn],
            },
        },
        {
            "dn": ro_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP ReadOnly",
                "sAMAccountName": "MSP-ReadOnly",
                "description": "MSP Org 1 Viewer audit group",
                "member": [viewer_dn],
            },
        },
        {
            "dn": genera_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Genera",
                "displayName": "Genera MSP Superadmin",
                "sAMAccountName": "Genera",
                "userPrincipalName": "Genera@ad.bls-isp.net",
                "mail": "genera@bls-isp.net",
                "memberOf": [da_dn],
                "primaryGroupID": "513",
            },
        },
        {
            "dn": nested_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Nora Engineer",
                "givenName": "Nora",
                "sn": "Engineer",
                "sAMAccountName": "n.engineer",
                "userPrincipalName": "n.engineer@ad.bls-isp.net",
                "mail": "nora@bls-isp.net",
                "memberOf": [noc_dn],
                "primaryGroupID": "513",
            },
        },
        {
            "dn": viewer_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Viktor Auditor",
                "displayName": "Viktor ReadOnly Auditor",
                "sAMAccountName": "v.auditor",
                "userPrincipalName": "v.auditor@ad.bls-isp.net",
                "mail": "viktor@bls-isp.net",
                "memberOf": [ro_dn],
                "primaryGroupID": "513",
            },
        },
    ]

    ldap_srv = LiveBERLDAPv3Server(
        expected_bind_dn=bind_dn,
        expected_bind_pw=bind_pw,
        entries=ad_entries,
        max_page_size=2,
        emit_referral=True,
    )
    ldap_srv.start()
    try:
        ad_domain_cfg = {
            "host": "127.0.0.1",
            "port": str(ldap_srv.port),
            "schema": "ad",
            "base_dn": base_dn,
            "bind_dn": bind_dn,
            "bind_password": bind_pw,
            "tls": False,
        }

        hub = NS8ModuleInstance(
            kind="hub",
            install_dir=tmp_path / "hub_v102_src",
            module_id="central-monitoring-hub1",
            tcp_port=20080,
            backends=live_backends,
        )
        hub.set_ldap_domain("ad.bls-isp.net", ad_domain_cfg)

        await hub.run_script("actions/create-module/20initialize")
        _, _, _, init_cfg = await hub.run_script("actions/get-configuration/20read", {})
        assert "ad.bls-isp.net" in init_cfg["available_ldap_domains"]
        assert init_cfg["ldap_viewer_group"] == ""

        # 1. Live `discover-ldap-groups` action over RFC 4511 BER + RFC 2696 paging + AD referral skip
        _, _, _, disc = await hub.run_script(
            "actions/discover-ldap-groups/20read",
            {"domain": "ad.bls-isp.net"},
        )
        assert disc["ok"] is True
        assert disc["schema"] == "ad"
        assert disc["base_dn"] == base_dn
        assert len(disc["groups"]) == 5
        groups_by_name = {g["name"]: g["dn"] for g in disc["groups"]}
        assert groups_by_name["Domain Admins"] == da_dn
        assert groups_by_name["MSP Operations"] == ops_dn
        assert groups_by_name["MSP ReadOnly"] == ro_dn
        assert ldap_srv.unbind_count >= 1

        # 2. Configure Hub with short AD group names + `ldap_viewer_group` and verify `ldap.toml` + live reload
        reloads_before = live_backends.grafana.ldap_reloads
        v102_cfg_req = {
            "host": "monitoring.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "ldap_enabled": True,
            "ldap_domain": "ad.bls-isp.net",
            "ldap_admin_group": "Domain Admins",
            "ldap_editor_group": "MSP Operations",
            "ldap_viewer_group": "MSP ReadOnly",
            "grafana_admin_password": "MspV102AdminPassword!",
        }
        await hub.run_script("actions/configure-module/01hostname-validation", v102_cfg_req)
        await hub.run_script("actions/configure-module/20configure", v102_cfg_req)
        await hub.run_script("actions/configure-module/80start_services", v102_cfg_req)

        assert live_backends.grafana.ldap_reloads > reloads_before
        _, _, _, read_cfg = await hub.run_script("actions/get-configuration/20read", {})
        assert read_cfg["ldap_enabled"] is True
        assert read_cfg["ldap_domain"] == "ad.bls-isp.net"
        assert read_cfg["ldap_admin_group"] == "Domain Admins"
        assert read_cfg["ldap_editor_group"] == "MSP Operations"
        assert read_cfg["ldap_viewer_group"] == "MSP ReadOnly"

        ldap_toml = (hub.config_dir / "grafana" / "ldap.toml").read_text(encoding="utf-8")
        assert f'group_dn = "{da_dn}"' in ldap_toml
        assert f'group_dn = "{ops_dn}"' in ldap_toml
        assert f'group_dn = "{ro_dn}"' in ldap_toml
        assert 'org_role = "Viewer"' in ldap_toml
        assert "grafana_admin = true" in ldap_toml
        assert (
            'group_search_filter = "(|(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))'
            '(&(objectClass=user)(distinguishedName=%s)))"' in ldap_toml
        )
        assert 'group_search_filter_user_attribute = "distinguishedName"' in ldap_toml
        assert 'member_of = "distinguishedName"' in ldap_toml
        assert 'group_dn = "*"' not in ldap_toml

        grafana_ini = (hub.config_dir / "grafana" / "grafana.ini").read_text(encoding="utf-8")
        assert "[alerting]\nenabled = false" in grafana_ini
        assert "[unified_alerting]\nenabled = false" in grafana_ini
        assert "skip_org_role_sync = false" in grafana_ini

        # 3. Live `test-ldap-user` action: direct Admin (`Genera`), nested Editor (`n.engineer`),
        #    Viewer (`v.auditor`), and RFC 4515 filter-injection defense
        _, _, _, test_genera = await hub.run_script(
            "actions/test-ldap-user/20test",
            {
                "domain": "ad.bls-isp.net",
                "username": "Genera",
                "ldap_admin_group": "Domain Admins",
                "ldap_editor_group": "MSP Operations",
                "ldap_viewer_group": "MSP ReadOnly",
            },
        )
        assert test_genera["ok"] is True
        assert test_genera["found"] is True
        assert test_genera["user_dn"] == genera_dn
        assert test_genera["matched_role"] == "Admin"
        assert test_genera["grafana_admin"] is True
        assert da_dn in test_genera["member_of"]
        assert du_dn in test_genera["member_of"]

        _, _, _, test_nested = await hub.run_script(
            "actions/test-ldap-user/20test",
            {
                "domain": "ad.bls-isp.net",
                "username": "n.engineer",
                "ldap_admin_group": "Domain Admins",
                "ldap_editor_group": "MSP-Operations",
                "ldap_viewer_group": "MSP ReadOnly",
            },
        )
        assert test_nested["ok"] is True
        assert test_nested["found"] is True
        assert test_nested["user_dn"] == nested_dn
        assert test_nested["matched_role"] == "Editor"
        assert test_nested["grafana_admin"] is False
        assert ops_dn in test_nested["member_of"]

        _, _, _, test_viewer = await hub.run_script(
            "actions/test-ldap-user/20test",
            {
                "domain": "ad.bls-isp.net",
                "username": "v.auditor",
                "ldap_admin_group": "Domain Admins",
                "ldap_editor_group": "MSP Operations",
                "ldap_viewer_group": "MSP ReadOnly",
            },
        )
        assert test_viewer["ok"] is True
        assert test_viewer["found"] is True
        assert test_viewer["matched_role"] == "Viewer"
        assert test_viewer["grafana_admin"] is False

        _, _, _, test_inj = await hub.run_script(
            "actions/test-ldap-user/20test",
            {
                "domain": "ad.bls-isp.net",
                "username": "Genera)(|(objectClass=*",
                "ldap_admin_group": "Domain Admins",
            },
        )
        assert test_inj["ok"] is True
        assert test_inj["found"] is False
        assert test_inj["matched_role"] == "None"
        assert test_inj["grafana_admin"] is False

        # 4. Multi-User Customer Grafana Account Management (`Viewer` + `Editor`, suspend/re-enable,
        #    password reset, cross-tenant collision rejection, delete, and Restic backup/restore)
        _, _, _, saved_acme = await hub.run_script(
            "actions/save-tenant/20save",
            {
                "customer": "acme-gmbh",
                "display_name": "Acme GmbH",
                "sites": ["hq", "branch"],
                "contact_emails": ["it@acme.de"],
                "customer_portal_enabled": True,
            },
        )
        acme_oid = int(saved_acme["grafana_org_id"])
        assert acme_oid > 1
        assert saved_acme["grafana_login_url"] == "https://monitoring.msp.example.com/login"
        assert saved_acme["portal_users_count"] == 0

        _, _, _, saved_rival = await hub.run_script(
            "actions/save-tenant/20save",
            {
                "customer": "rival-gmbh",
                "display_name": "Rival GmbH",
                "sites": ["hq"],
                "customer_portal_enabled": True,
            },
        )
        rival_oid = int(saved_rival["grafana_org_id"])
        assert rival_oid > 1 and rival_oid != acme_oid

        _, u_view_raw, _, u_view_out = await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.viewer",
                "full_name": "Acme NOC Viewer",
                "email": "noc@acme.de",
                "role": "Viewer",
                "disabled": False,
                "password": "AcmeViewerPassword!2026",
            },
        )
        assert u_view_out["grafana_synced"] is True
        assert u_view_out["user"]["role"] == "Viewer"
        assert "AcmeViewerPassword!2026" not in u_view_raw

        _, u_edit_raw, _, u_edit_out = await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.editor",
                "full_name": "Acme Lead Engineer",
                "email": "lead@acme.de",
                "role": "Editor",
                "disabled": False,
                "password": "AcmeEditorPassword!2026",
            },
        )
        assert u_edit_out["grafana_synced"] is True
        assert u_edit_out["user"]["role"] == "Editor"
        assert "AcmeEditorPassword!2026" not in u_edit_raw

        viewer_uid = next(
            u["id"] for u in live_backends.grafana.users.values() if u["login"] == "acme.viewer"
        )
        editor_uid = next(
            u["id"] for u in live_backends.grafana.users.values() if u["login"] == "acme.editor"
        )
        assert live_backends.grafana.org_members[acme_oid] == {
            1: "Admin",
            viewer_uid: "Viewer",
            editor_uid: "Editor",
        }
        assert set(live_backends.grafana.org_members[1].keys()) == {1}
        assert viewer_uid not in live_backends.grafana.org_members[1]
        assert editor_uid not in live_backends.grafana.org_members[1]
        assert viewer_uid not in live_backends.grafana.org_members[rival_oid]
        assert editor_uid not in live_backends.grafana.org_members[rival_oid]
        assert live_backends.grafana.users[viewer_uid]["isGrafanaAdmin"] is False
        assert live_backends.grafana.users[editor_uid]["isGrafanaAdmin"] is False

        _, lp_raw, _, lp_out = await hub.run_script(
            "actions/list-portal-users/20read",
            {"customer": "acme-gmbh"},
        )
        assert len(lp_out["users"]) == 2
        assert lp_out["grafana_login_url"] == "https://monitoring.msp.example.com/login"
        assert lp_out["grafana_org_name"] == "Customer: Acme GmbH (acme-gmbh)"
        assert "AcmeViewerPassword!2026" not in lp_raw
        assert "AcmeEditorPassword!2026" not in lp_raw

        _, _, _, lt_out = await hub.run_script("actions/list-tenants/20read", {})
        acme_row = next(t for t in lt_out["tenants"] if t["customer"] == "acme-gmbh")
        assert acme_row["portal_users_count"] == 2
        assert acme_row["grafana_login_url"] == "https://monitoring.msp.example.com/login"

        # Suspend (`disabled: true`) and re-enable (`disabled: false`) with `password_unchanged: true`
        await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.editor",
                "full_name": "Acme Lead Engineer",
                "email": "lead@acme.de",
                "role": "Editor",
                "disabled": True,
                "password": "",
                "password_unchanged": True,
            },
        )
        assert live_backends.grafana.users[editor_uid]["isDisabled"] is True
        assert editor_uid not in live_backends.grafana.org_members[acme_oid]
        assert (
            load_portal_viewer_secret(hub.state_dir, "acme-gmbh", "acme.editor")
            == "AcmeEditorPassword!2026"
        )

        await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.editor",
                "full_name": "Acme Lead Engineer",
                "email": "lead@acme.de",
                "role": "Editor",
                "disabled": False,
                "password": "",
                "password_unchanged": True,
            },
        )
        assert live_backends.grafana.users[editor_uid]["isDisabled"] is False
        assert live_backends.grafana.org_members[acme_oid][editor_uid] == "Editor"

        # Password reset on `acme.editor`
        await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.editor",
                "full_name": "Acme Lead Engineer",
                "email": "lead@acme.de",
                "role": "Editor",
                "disabled": False,
                "password": "AcmeEditorRotated!2026",
                "password_unchanged": False,
            },
        )
        assert (
            load_portal_viewer_secret(hub.state_dir, "acme-gmbh", "acme.editor")
            == "AcmeEditorRotated!2026"
        )
        assert live_backends.grafana.users[editor_uid]["password"] == "AcmeEditorRotated!2026"

        # Cross-tenant case-insensitive duplicate username MUST be rejected with exit code 2
        _, dup_stdout, _, dup_err = await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "rival-gmbh",
                "username": "ACME.EDITOR",
                "role": "Viewer",
                "password": "RivalAttemptPassword!1",
            },
            expect_rc=2,
        )
        assert hub.read_meta()["status"] == "validation-failed"
        assert "already in use" in dup_stdout
        assert dup_err[0]["field"] == "username"

        # Create & delete temporary user `acme.temp` via `delete-portal-user`
        await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.temp",
                "role": "Viewer",
                "password": "TempPortalUserPass!2026",
            },
        )
        temp_uid = next(
            u["id"] for u in live_backends.grafana.users.values() if u["login"] == "acme.temp"
        )
        _, _, _, del_out = await hub.run_script(
            "actions/delete-portal-user/20delete",
            {"customer": "acme-gmbh", "username": "acme.temp"},
        )
        assert del_out["status"] == "deleted"
        assert del_out["grafana_synced"] is True
        assert del_out["deleted"] is True
        assert temp_uid in live_backends.grafana.deleted_user_ids
        assert temp_uid not in live_backends.grafana.users
        assert load_portal_viewer_secret(hub.state_dir, "acme-gmbh", "acme.temp") is None

        # 5. Restic Backup & Restore (`module-dump-state` + `restore-module`) preserves ALL multi-user
        #    portal accounts, individual sealed passwords, and `ldap_viewer_group` rendering!
        await hub.run_script("bin/module-dump-state", validate_io=False)
        restored_hub = NS8ModuleInstance(
            kind="hub",
            install_dir=tmp_path / "hub_v102_restored",
            module_id="central-monitoring-hub2",
            tcp_port=20081,
            backends=live_backends,
        )
        restored_hub.set_ldap_domain("ad.bls-isp.net", ad_domain_cfg)
        hub.copy_restic_snapshot_to(restored_hub.install_dir)

        orig_env = json.loads(hub.meta_file.read_text(encoding="utf-8"))["persisted_env"]
        await restored_hub.run_script(
            "actions/restore-module/06copyenv", {"environment": orig_env}, validate_io=False
        )
        await restored_hub.run_script("actions/restore-module/50configure", {}, validate_io=False)

        assert (
            load_portal_viewer_secret(restored_hub.state_dir, "acme-gmbh", "acme.viewer")
            == "AcmeViewerPassword!2026"
        )
        assert (
            load_portal_viewer_secret(restored_hub.state_dir, "acme-gmbh", "acme.editor")
            == "AcmeEditorRotated!2026"
        )
        _, _, _, restored_lp = await restored_hub.run_script(
            "actions/list-portal-users/20read",
            {"customer": "acme-gmbh"},
        )
        restored_roles = {u["username"]: u["role"] for u in restored_lp["users"]}
        assert restored_roles == {"acme.viewer": "Viewer", "acme.editor": "Editor"}

        restored_ldap_toml = (restored_hub.config_dir / "grafana" / "ldap.toml").read_text(
            encoding="utf-8"
        )
        assert f'group_dn = "{da_dn}"' in restored_ldap_toml
        assert f'group_dn = "{ops_dn}"' in restored_ldap_toml
        assert f'group_dn = "{ro_dn}"' in restored_ldap_toml
        assert 'org_role = "Viewer"' in restored_ldap_toml

        # 6. `V102-SEC-01` Live `hub_gateway` SSRF & Datasource-Mutation Block (`403` on
        #    `/api/alertmanager/...`, `/api/ruler/...`, `/api/v1/provisioning/...`, and mutating `/api/datasources`)
        v102_gw = await live_backends.start_hub_gateway(hub.state_dir, tmp_path / "v102_gw_tls")
        v102_ssl = ssl.create_default_context(cafile=str(v102_gw.ca_cert_path))
        async with aiohttp.ClientSession() as session:
            for method, blocked_path in (
                ("POST", "/api/alertmanager/grafana/config/api/v1/receivers/test"),
                ("GET", "/api/alertmanager/grafana/api/v2/status"),
                ("GET", "/api/ruler/grafana/api/v1/rules"),
                ("POST", "/api/v1/provisioning/contact-points"),
                ("POST", "/api/datasources"),
                ("PUT", "/api/datasources/1"),
                ("DELETE", "/api/datasources/uid/prometheus"),
            ):
                async with session.request(
                    method,
                    f"{v102_gw.https_url}{blocked_path}",
                    json={"probe": True} if method in ("POST", "PUT") else None,
                    ssl=v102_ssl,
                ) as blocked_resp:
                    assert blocked_resp.status == 403, (
                        f"Expected 403 for {method} {blocked_path}, got {blocked_resp.status}"
                    )

            async with session.get(
                f"{v102_gw.https_url}/api/datasources/proxy/uid/prometheus/api/v1/query?query=up",
                ssl=v102_ssl,
            ) as allowed_ds_resp:
                assert allowed_ds_resp.status == 200

        # 7. `V102-ARCH-01` Live NS8 `update-module.d/20pull_images` + `50update` (`1.0.1` -> `1.0.2`)
        (restored_hub.etc_dir / "defaults.env").write_bytes(
            b"CENTRAL_MONITORING_HUB_GATEWAY_IMAGE=ghcr.io/bls-isp/central-monitoring-hub-gateway:1.0.2\n"
        )
        stale_meta = restored_hub.read_meta()
        stale_meta["persisted_env"]["CENTRAL_MONITORING_HUB_GATEWAY_IMAGE"] = (
            "ghcr.io/bls-isp/central-monitoring-hub-gateway:1.0.1"
        )
        stale_meta["persisted_env"].pop("LDAP_VIEWER_GROUP", None)
        restored_hub.meta_file.write_bytes((json.dumps(stale_meta, indent=2) + "\n").encode("utf-8"))
        stale_env_lines = [
            f"{k}={v}"
            for k, v in sorted(stale_meta["persisted_env"].items())
        ]
        restored_hub.env_file.write_bytes(("\n".join(stale_env_lines) + "\n").encode("utf-8"))
        (restored_hub.config_dir / "grafana" / "grafana.ini").write_bytes(b"[server]\nhttp_port = 3000\n")

        await restored_hub.run_script("update-module.d/20pull_images", validate_io=False)
        await restored_hub.run_script("update-module.d/50update", validate_io=False)

        upgraded_meta = restored_hub.read_meta()
        assert upgraded_meta["persisted_env"]["CENTRAL_MONITORING_HUB_GATEWAY_IMAGE"].endswith(
            ":1.0.2"
        )
        assert "LDAP_VIEWER_GROUP" in upgraded_meta["persisted_env"]
        upgraded_ini = (restored_hub.config_dir / "grafana" / "grafana.ini").read_text(
            encoding="utf-8"
        )
        assert "[unified_alerting]\nenabled = false" in upgraded_ini
        assert upgraded_meta["systemctl_state"]["hub-gateway.service"] == "active"
        assert upgraded_meta["systemctl_state"]["grafana.service"] == "active"
    finally:
        ldap_srv.stop()


def _parse_ldap_group_mappings(ldap_toml_text: str) -> list[dict[str, Any]]:
    """Extract ordered `[[servers.group_mappings]]` stanzas from rendered `ldap.toml`."""
    blocks: list[dict[str, Any]] = []
    parts = ldap_toml_text.split("[[servers.group_mappings]]")
    for raw_part in parts[1:]:
        stanza: dict[str, Any] = {}
        for raw_line in raw_part.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                break
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            k = key.strip()
            v = val.strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                stanza[k] = v[1:-1]
            elif v in ("true", "false"):
                stanza[k] = v == "true"
            elif v.isdigit():
                stanza[k] = int(v)
            else:
                stanza[k] = v
        blocks.append(stanza)
    return blocks


@pytest.mark.asyncio
async def test_12_v103_msp_simulated_customer_view_and_home_dashboard(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify v1.0.3 Org Home Dashboard, 1-way MSP staff Customer Org sync, and multi-org `ldap.toml`."""
    base_dn = "DC=ad,DC=bls-isp,DC=net"
    bind_dn = f"CN=ldapsvc,CN=Users,{base_dn}"
    bind_pw = "AdBlsIspV103Secret!2026"

    da_dn = f"CN=Domain Admins,CN=Users,{base_dn}"
    genera_grp_dn = f"CN=Genera,OU=MSP,{base_dn}"
    audit_grp_dn = f"CN=MSP Audit,OU=MSP,{base_dn}"

    ad_entries = [
        {
            "dn": da_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "Domain Admins",
                "sAMAccountName": "Domain Admins",
                "description": "MSP Superadmins",
                "primaryGroupToken": "512",
                "member": [],
            },
        },
        {
            "dn": genera_grp_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "Genera",
                "sAMAccountName": "Genera",
                "description": "MSP Support Engineers (Org 1 Editor, Customer Org Viewer)",
                "member": [],
            },
        },
        {
            "dn": audit_grp_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP Audit",
                "sAMAccountName": "MSP-Audit",
                "description": "MSP ReadOnly Auditors",
                "member": [],
            },
        },
    ]

    ldap_srv = LiveBERLDAPv3Server(
        expected_bind_dn=bind_dn,
        expected_bind_pw=bind_pw,
        entries=ad_entries,
        max_page_size=2,
        emit_referral=False,
    )
    ldap_srv.start()
    try:
        hub = NS8ModuleInstance(
            kind="hub",
            install_dir=tmp_path / "hub_v103_home",
            module_id="central-monitoring-hub1",
            tcp_port=20080,
            backends=live_backends,
        )
        hub.set_ldap_domain(
            "ad.bls-isp.net",
            {
                "host": "127.0.0.1",
                "port": str(ldap_srv.port),
                "schema": "ad",
                "base_dn": base_dn,
                "bind_dn": bind_dn,
                "bind_password": bind_pw,
                "tls": False,
            },
        )

        # Simulate existing Grafana Org 1 users:
        # - `msp.admin` (`Domain Admins` via LDAP, `isExternal=True`, Org 1 `Admin`)
        # - `msp.support` (`Genera` via LDAP, `isExternal=True`, Org 1 `Editor`)
        # - `stray.local` (non-external unprivileged local account — MUST NOT propagate!)
        gf = live_backends.grafana
        msp_admin_uid = gf.add_org1_user(
            login="msp.admin",
            email="admin@bls-isp.net",
            org1_role="Admin",
            is_external=True,
            is_grafana_admin=True,
        )
        msp_support_uid = gf.add_org1_user(
            login="msp.support",
            email="support@bls-isp.net",
            org1_role="Editor",
            is_external=True,
            is_grafana_admin=False,
        )
        stray_local_uid = gf.add_org1_user(
            login="stray.local",
            email="stray@local.invalid",
            org1_role="Viewer",
            is_external=False,
            is_grafana_admin=False,
            auth_labels=[],
        )

        await hub.run_script("actions/create-module/20initialize")
        cfg_req = {
            "host": "monitoring.bls-isp.net",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "ldap_enabled": True,
            "ldap_domain": "ad.bls-isp.net",
            "ldap_admin_group": "Domain Admins",
            "ldap_editor_group": "Genera",
            "ldap_viewer_group": "MSP Audit",
            "grafana_admin_password": "MspV103AdminPassword!",
        }
        await hub.run_script("actions/configure-module/01hostname-validation", cfg_req)
        await hub.run_script("actions/configure-module/20configure", cfg_req)

        # 1. Verify Org 1 Home Dashboard provisioned immediately on `configure-module`
        assert gf.org_preferences[1].get("homeDashboardUID") == "ns8-multi-cluster-overview"

        # 2. Provision two portal-enabled Customer Orgs (`acme-gmbh` & `globex-gmbh`) + portal users
        _, _, _, acme_saved = await hub.run_script(
            "actions/save-tenant/20save",
            {
                "customer": "acme-gmbh",
                "display_name": "Acme GmbH",
                "sites": ["hq"],
                "contact_emails": ["it@acme.de"],
                "customer_portal_enabled": True,
            },
        )
        acme_oid = int(acme_saved["grafana_org_id"])
        assert acme_oid > 1

        _, _, _, globex_saved = await hub.run_script(
            "actions/save-tenant/20save",
            {
                "customer": "globex-gmbh",
                "display_name": "Globex GmbH",
                "sites": ["berlin"],
                "contact_emails": ["ops@globex.de"],
                "customer_portal_enabled": True,
            },
        )
        globex_oid = int(globex_saved["grafana_org_id"])
        assert globex_oid > 1 and globex_oid != acme_oid

        await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.viewer",
                "role": "Viewer",
                "password": "AcmePortalViewer!2026",
            },
        )
        await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "acme-gmbh",
                "username": "acme.editor",
                "role": "Editor",
                "password": "AcmePortalEditor!2026",
            },
        )
        await hub.run_script(
            "actions/save-portal-user/20save",
            {
                "customer": "globex-gmbh",
                "username": "globex.viewer",
                "role": "Viewer",
                "password": "GlobexPortalViewer!2026",
            },
        )

        acme_v_uid = next(u["id"] for u in gf.users.values() if u["login"] == "acme.viewer")
        acme_e_uid = next(u["id"] for u in gf.users.values() if u["login"] == "acme.editor")
        globex_v_uid = next(u["id"] for u in gf.users.values() if u["login"] == "globex.viewer")

        # 3. Verify `homeDashboardUID == "ns8-multi-cluster-overview"` on Org 1 and BOTH Customer Orgs
        assert gf.org_preferences[1].get("homeDashboardUID") == "ns8-multi-cluster-overview"
        assert gf.org_preferences[acme_oid].get("homeDashboardUID") == "ns8-multi-cluster-overview"
        assert gf.org_preferences[globex_oid].get("homeDashboardUID") == "ns8-multi-cluster-overview"

        # 4. Verify 1-way MSP staff propagation (`Domain Admins -> Admin`, `Genera -> Viewer`)
        #    and strict non-propagation of stray local users & customer portal users!
        assert gf.org_members[acme_oid] == {
            1: "Admin",
            msp_admin_uid: "Admin",
            msp_support_uid: "Viewer",
            acme_v_uid: "Viewer",
            acme_e_uid: "Editor",
        }
        assert gf.org_members[globex_oid] == {
            1: "Admin",
            msp_admin_uid: "Admin",
            msp_support_uid: "Viewer",
            globex_v_uid: "Viewer",
        }
        assert stray_local_uid not in gf.org_members[acme_oid]
        assert stray_local_uid not in gf.org_members[globex_oid]

        for portal_uid in (acme_v_uid, acme_e_uid, globex_v_uid):
            assert portal_uid not in gf.org_members[1]
        assert acme_v_uid not in gf.org_members[globex_oid]
        assert acme_e_uid not in gf.org_members[globex_oid]
        assert globex_v_uid not in gf.org_members[acme_oid]

        # MSP staff active default Org (`orgId`) MUST stay `1` (never switched via `/using/<oid>`)!
        msp_uids = {1, msp_admin_uid, msp_support_uid}
        for staff_uid in msp_uids:
            assert gf.users[staff_uid]["orgId"] == 1
        assert all(switched_uid not in msp_uids for switched_uid, _ in gf.org_switch_calls)
        assert gf.users[acme_v_uid]["orgId"] == acme_oid
        assert gf.users[globex_v_uid]["orgId"] == globex_oid

        # 5. Verify `ldap.toml` multi-org mappings: `org_id = 1` blocks FIRST, followed by sorted
        #    active Customer Orgs (`Admin` for `Domain Admins` without `grafana_admin`, `Viewer` for `Genera`)!
        ldap_toml_both = (hub.config_dir / "grafana" / "ldap.toml").read_text(encoding="utf-8")
        mappings_both = _parse_ldap_group_mappings(ldap_toml_both)
        expected_c_oids = sorted([acme_oid, globex_oid])
        assert [m["org_id"] for m in mappings_both] == [
            1,
            1,
            1,
            expected_c_oids[0],
            expected_c_oids[0],
            expected_c_oids[0],
            expected_c_oids[1],
            expected_c_oids[1],
            expected_c_oids[1],
        ]
        assert mappings_both[:3] == [
            {"group_dn": da_dn, "org_role": "Admin", "grafana_admin": True, "org_id": 1},
            {"group_dn": genera_grp_dn, "org_role": "Editor", "org_id": 1},
            {"group_dn": audit_grp_dn, "org_role": "Viewer", "org_id": 1},
        ]
        for idx, c_oid in enumerate(expected_c_oids):
            offset = 3 + idx * 3
            assert mappings_both[offset : offset + 3] == [
                {"group_dn": da_dn, "org_role": "Admin", "org_id": c_oid},
                {"group_dn": genera_grp_dn, "org_role": "Viewer", "org_id": c_oid},
                {"group_dn": audit_grp_dn, "org_role": "Viewer", "org_id": c_oid},
            ]

        # 6. Disabling portal on `globex-gmbh` removes `org_id = <globex_oid>` from `ldap.toml`
        await hub.run_script(
            "actions/save-tenant/20save",
            {
                "customer": "globex-gmbh",
                "display_name": "Globex GmbH",
                "sites": ["berlin"],
                "contact_emails": ["ops@globex.de"],
                "customer_portal_enabled": False,
            },
        )
        mappings_after_disable = _parse_ldap_group_mappings(
            (hub.config_dir / "grafana" / "ldap.toml").read_text(encoding="utf-8")
        )
        assert [m["org_id"] for m in mappings_after_disable] == [
            1,
            1,
            1,
            acme_oid,
            acme_oid,
            acme_oid,
        ]
        assert globex_v_uid not in gf.org_members[1]
        assert globex_v_uid not in gf.org_members[acme_oid]

        # 7. Deleting `acme-gmbh` removes `org_id = <acme_oid>` from `ldap.toml`, leaving ONLY `org_id = 1`
        await hub.run_script("actions/delete-tenant/20delete", {"customer": "acme-gmbh"})
        mappings_after_delete = _parse_ldap_group_mappings(
            (hub.config_dir / "grafana" / "ldap.toml").read_text(encoding="utf-8")
        )
        assert [m["org_id"] for m in mappings_after_delete] == [1, 1, 1]
    finally:
        ldap_srv.stop()


@pytest.mark.asyncio
async def test_13_v104_multi_select_ldap_group_and_user_discovery(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify v1.0.4 AD group+user discovery, computer/`krbtgt` filtering, multi-principal `ldap.toml`, and upgrade backfill."""
    base_dn = "DC=ad,DC=bls-isp,DC=net"
    bind_dn = f"CN=ldapsvc,CN=Users,{base_dn}"
    bind_pw = "AdBlsIspV104Secret!2026"

    da_dn = f"CN=Domain Admins,CN=Users,{base_dn}"
    sec_admins_dn = f"CN=MSP Security Admins,OU=Groups,{base_dn}"
    child_admin_team_dn = f"CN=MSP SecOps Tier-3,OU=SubTeams,OU=Groups,{base_dn}"
    ops_dn = f"CN=MSP Operations,OU=Groups,{base_dn}"
    audit_dn = f"CN=MSP ReadOnly,OU=Groups,{base_dn}"

    genera_user_dn = f"CN=Genera,OU=MSP,{base_dn}"
    nested_admin_user_dn = f"CN=Clara SecOps,OU=MSP,{base_dn}"
    direct_viewer_user_dn = f"CN=Erik Exec,OU=Management,{base_dn}"
    unmapped_user_dn = f"CN=Guest Partner,OU=External,{base_dn}"
    computer_dn = f"CN=SRV01,OU=Domain Controllers,{base_dn}"
    krbtgt_dn = f"CN=krbtgt,CN=Users,{base_dn}"

    ad_entries = [
        {
            "dn": da_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "Domain Admins",
                "sAMAccountName": "Domain Admins",
                "description": "Domain superadmins",
                "primaryGroupToken": "512",
                "member": [],
            },
        },
        {
            "dn": sec_admins_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP Security Admins",
                "sAMAccountName": "MSP-Security-Admins",
                "description": "Secondary Admin group with nested child team",
                "member": [child_admin_team_dn],
            },
        },
        {
            "dn": child_admin_team_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP SecOps Tier-3",
                "sAMAccountName": "MSP-SecOps-Tier3",
                "description": "Nested child team under MSP Security Admins",
                "member": [nested_admin_user_dn],
            },
        },
        {
            "dn": ops_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP Operations",
                "sAMAccountName": "MSP-Operations",
                "description": "Org 1 Editor group",
                "member": [],
            },
        },
        {
            "dn": audit_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP ReadOnly",
                "sAMAccountName": "MSP-ReadOnly",
                "description": "Org 1 Viewer group",
                "member": [],
            },
        },
        {
            "dn": genera_user_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Genera",
                "displayName": "Genera Engineer",
                "sAMAccountName": "Genera",
                "userPrincipalName": "Genera@ad.bls-isp.net",
                "mail": "genera@bls-isp.net",
                "memberOf": [],
            },
        },
        {
            "dn": nested_admin_user_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Clara SecOps",
                "displayName": "Clara Security Architect",
                "sAMAccountName": "c.secops",
                "userPrincipalName": "c.secops@ad.bls-isp.net",
                "mail": "clara@bls-isp.net",
                "memberOf": [child_admin_team_dn],
            },
        },
        {
            "dn": direct_viewer_user_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Erik Exec",
                "displayName": "Erik Executive",
                "sAMAccountName": "e.exec",
                "userPrincipalName": "e.exec@ad.bls-isp.net",
                "mail": "erik@bls-isp.net",
                "memberOf": [],
            },
        },
        {
            "dn": unmapped_user_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Guest Partner",
                "displayName": "External Guest",
                "sAMAccountName": "g.partner",
                "userPrincipalName": "g.partner@ad.bls-isp.net",
                "mail": "guest@partner.example",
                "memberOf": [],
            },
        },
        {
            "dn": computer_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
                "cn": "SRV01",
                "sAMAccountName": "SRV01$",
                "memberOf": [],
            },
        },
        {
            "dn": krbtgt_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "krbtgt",
                "sAMAccountName": "krbtgt",
                "memberOf": [],
            },
        },
    ]

    ldap_srv = LiveBERLDAPv3Server(
        expected_bind_dn=bind_dn,
        expected_bind_pw=bind_pw,
        entries=ad_entries,
        max_page_size=3,
        emit_referral=True,
    )
    ldap_srv.start()
    try:
        ad_cfg = {
            "host": "127.0.0.1",
            "port": str(ldap_srv.port),
            "schema": "ad",
            "base_dn": base_dn,
            "bind_dn": bind_dn,
            "bind_password": bind_pw,
            "tls": False,
        }
        hub = NS8ModuleInstance(
            kind="hub",
            install_dir=tmp_path / "hub_v104_home",
            module_id="central-monitoring-hub1",
            tcp_port=20080,
            backends=live_backends,
        )
        hub.set_ldap_domain("ad.bls-isp.net", ad_cfg)
        await hub.run_script("actions/create-module/20initialize")

        # 1. Real `discover-ldap-groups/20read`: validates schema, returns BOTH `groups` and `users`,
        #    includes human user `Genera`, and strictly excludes `SRV01$` and `krbtgt`!
        _, _, _, disc = await hub.run_script(
            "actions/discover-ldap-groups/20read",
            {"domain": "ad.bls-isp.net"},
        )
        assert disc["ok"] is True
        assert len(disc["groups"]) == 5
        discovered_usernames = [u["username"] for u in disc["users"]]
        assert "Genera" in discovered_usernames
        assert "c.secops" in discovered_usernames
        assert "e.exec" in discovered_usernames
        assert "SRV01$" not in discovered_usernames
        assert "SRV01" not in discovered_usernames
        assert "krbtgt" not in discovered_usernames
        genera_disc = next(u for u in disc["users"] if u["username"] == "Genera")
        assert genera_disc["dn"] == genera_user_dn

        # Create active Customer Org `acme-gmbh` so multi-org `ldap.toml` rendering is verified too
        _, _, _, acme_saved = await hub.run_script(
            "actions/save-tenant/20save",
            {
                "customer": "acme-gmbh",
                "display_name": "Acme GmbH",
                "sites": ["hq"],
                "contact_emails": ["it@acme.de"],
                "customer_portal_enabled": True,
            },
        )
        acme_oid = int(acme_saved["grafana_org_id"])
        assert acme_oid > 1

        # 2. Real `configure-module` + `get-configuration` round-trip with multi-select arrays
        #    mixing multiple groups, bare short username `"Genera"`, and explicit user DN!
        v104_cfg_req = {
            "host": "monitoring.bls-isp.net",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "ldap_enabled": True,
            "ldap_domain": "ad.bls-isp.net",
            "ldap_admin_principals": ["Domain Admins", sec_admins_dn],
            "ldap_editor_principals": [ops_dn, "Genera"],
            "ldap_viewer_principals": [audit_dn, direct_viewer_user_dn],
            "grafana_admin_password": "MspV104AdminPassword!",
        }
        await hub.run_script("actions/configure-module/01hostname-validation", v104_cfg_req)
        await hub.run_script("actions/configure-module/20configure", v104_cfg_req)

        _, _, _, read_cfg = await hub.run_script("actions/get-configuration/20read", {})
        assert read_cfg["ldap_admin_principals"] == ["Domain Admins", sec_admins_dn]
        assert read_cfg["ldap_editor_principals"] == [ops_dn, "Genera"]
        assert read_cfg["ldap_viewer_principals"] == [audit_dn, direct_viewer_user_dn]
        assert read_cfg["ldap_admin_group"] == "Domain Admins"
        assert read_cfg["ldap_editor_group"] == ops_dn
        assert read_cfg["ldap_viewer_group"] == audit_dn

        # 3. Verify `ldap.toml` contains `member_of = "distinguishedName"`, compound `group_search_filter`,
        #    and ordered `[[servers.group_mappings]]` across `org_id = 1` AND `org_id = <acme_oid>`!
        ldap_toml = (hub.config_dir / "grafana" / "ldap.toml").read_text(encoding="utf-8")
        assert 'member_of = "distinguishedName"' in ldap_toml
        assert (
            'search_filter = "(&(objectClass=user)(!(objectClass=computer))'
            '(|(sAMAccountName=%s)(userPrincipalName=%s)))"' in ldap_toml
        )
        assert (
            'group_search_filter = "(|(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))'
            '(&(objectClass=user)(distinguishedName=%s)))"' in ldap_toml
        )
        assert 'group_dn = "*"' not in ldap_toml

        mappings = _parse_ldap_group_mappings(ldap_toml)
        assert mappings == [
            {"group_dn": da_dn, "org_role": "Admin", "grafana_admin": True, "org_id": 1},
            {"group_dn": sec_admins_dn, "org_role": "Admin", "grafana_admin": True, "org_id": 1},
            {"group_dn": ops_dn, "org_role": "Editor", "org_id": 1},
            {"group_dn": genera_user_dn, "org_role": "Editor", "org_id": 1},
            {"group_dn": audit_dn, "org_role": "Viewer", "org_id": 1},
            {"group_dn": direct_viewer_user_dn, "org_role": "Viewer", "org_id": 1},
            {"group_dn": da_dn, "org_role": "Admin", "org_id": acme_oid},
            {"group_dn": sec_admins_dn, "org_role": "Admin", "org_id": acme_oid},
            {"group_dn": ops_dn, "org_role": "Viewer", "org_id": acme_oid},
            {"group_dn": genera_user_dn, "org_role": "Viewer", "org_id": acme_oid},
            {"group_dn": audit_dn, "org_role": "Viewer", "org_id": acme_oid},
            {"group_dn": direct_viewer_user_dn, "org_role": "Viewer", "org_id": acme_oid},
        ]

        # 4. Real `actions/test-ldap-user/20test` with `ldap_*_principals`:
        #    - `Genera` -> `Editor` via direct user DN
        #    - `c.secops` -> `Admin` via nested AD group `sec_admins_dn`
        #    - `e.exec` -> `Viewer` via direct user DN
        #    - `g.partner` -> `None`
        #    - `SRV01$` -> `found: False` (computer account rejected!)
        principals_payload = {
            "ldap_admin_principals": ["Domain Admins", sec_admins_dn],
            "ldap_editor_principals": [ops_dn, "Genera"],
            "ldap_viewer_principals": [audit_dn, direct_viewer_user_dn],
        }

        _, _, _, test_genera = await hub.run_script(
            "actions/test-ldap-user/20test",
            {"domain": "ad.bls-isp.net", "username": "Genera", **principals_payload},
        )
        assert test_genera["ok"] is True
        assert test_genera["found"] is True
        assert test_genera["matched_role"] == "Editor"
        assert test_genera["grafana_admin"] is False
        assert f"via user '{genera_user_dn}'" in test_genera["message"]

        _, _, _, test_clara = await hub.run_script(
            "actions/test-ldap-user/20test",
            {"domain": "ad.bls-isp.net", "username": "c.secops", **principals_payload},
        )
        assert test_clara["ok"] is True
        assert test_clara["found"] is True
        assert test_clara["matched_role"] == "Admin"
        assert test_clara["grafana_admin"] is True
        assert f"via group '{sec_admins_dn}'" in test_clara["message"]

        _, _, _, test_erik = await hub.run_script(
            "actions/test-ldap-user/20test",
            {"domain": "ad.bls-isp.net", "username": "e.exec", **principals_payload},
        )
        assert test_erik["ok"] is True
        assert test_erik["found"] is True
        assert test_erik["matched_role"] == "Viewer"
        assert test_erik["grafana_admin"] is False
        assert f"via user '{direct_viewer_user_dn}'" in test_erik["message"]

        _, _, _, test_guest = await hub.run_script(
            "actions/test-ldap-user/20test",
            {"domain": "ad.bls-isp.net", "username": "g.partner", **principals_payload},
        )
        assert test_guest["ok"] is True
        assert test_guest["found"] is True
        assert test_guest["matched_role"] == "None"
        assert test_guest["grafana_admin"] is False

        _, _, _, test_comp = await hub.run_script(
            "actions/test-ldap-user/20test",
            {"domain": "ad.bls-isp.net", "username": "SRV01$", **principals_payload},
        )
        assert test_comp["ok"] is True
        assert test_comp["found"] is False
        assert test_comp["matched_role"] == "None"

        # 5. Legacy v1.0.1 -> v1.0.4 upgrade backfill (`LDAP_EDITOR_GROUP="Genera"` without `*_B64`
        #    -> backfilled to `["Genera"]` -> resolved to `CN=Genera,OU=MSP,...` in `ldap.toml`!)
        legacy_hub = NS8ModuleInstance(
            kind="hub",
            install_dir=tmp_path / "hub_v101_legacy_upgrade",
            module_id="central-monitoring-hub2",
            tcp_port=20081,
            backends=live_backends,
        )
        legacy_hub.set_ldap_domain("ad.bls-isp.net", ad_cfg)
        await legacy_hub.run_script("actions/create-module/20initialize")

        leg_meta = legacy_hub.read_meta()
        leg_env = leg_meta["persisted_env"]
        leg_env["CONFIGURED"] = "true"
        leg_env["TRAEFIK_HOST"] = "monitoring-legacy.bls-isp.net"
        leg_env["LDAP_ENABLED"] = "true"
        leg_env["LDAP_DOMAIN"] = "ad.bls-isp.net"
        leg_env["LDAP_ADMIN_GROUP"] = "Domain Admins"
        leg_env["LDAP_EDITOR_GROUP"] = "Genera"
        leg_env["LDAP_VIEWER_GROUP"] = ""
        for b64_k in (
            "LDAP_ADMIN_PRINCIPALS_B64",
            "LDAP_EDITOR_PRINCIPALS_B64",
            "LDAP_VIEWER_PRINCIPALS_B64",
        ):
            leg_env.pop(b64_k, None)
        legacy_hub.meta_file.write_bytes((json.dumps(leg_meta, indent=2) + "\n").encode("utf-8"))
        leg_lines = [f"{k}={v}" for k, v in sorted(leg_env.items())]
        legacy_hub.env_file.write_bytes(("\n".join(leg_lines) + "\n").encode("utf-8"))

        await legacy_hub.run_script("update-module.d/20pull_images", validate_io=False)
        await legacy_hub.run_script("update-module.d/50update", validate_io=False)

        _, _, _, upg_cfg = await legacy_hub.run_script("actions/get-configuration/20read", {})
        assert upg_cfg["ldap_admin_principals"] == ["Domain Admins"]
        assert upg_cfg["ldap_editor_principals"] == ["Genera"]
        assert upg_cfg["ldap_viewer_principals"] == []

        upg_toml = (legacy_hub.config_dir / "grafana" / "ldap.toml").read_text(encoding="utf-8")
        upg_mappings = _parse_ldap_group_mappings(upg_toml)
        assert upg_mappings == [
            {"group_dn": da_dn, "org_role": "Admin", "grafana_admin": True, "org_id": 1},
            {"group_dn": genera_user_dn, "org_role": "Editor", "org_id": 1},
        ]
    finally:
        ldap_srv.stop()


def _write_cgroup_slice_files(
    cg_dir: Path,
    *,
    usage_usec: int = 0,
    throttled_usec: int = 0,
    mem_current: int = 0,
    inactive_file: int = 0,
    mem_swap: int = 0,
    mem_max: str = "max",
    oom_kill: int = 0,
    pids: int = 0,
    rbytes: int = 0,
    wbytes: int = 0,
) -> None:
    cg_dir.mkdir(parents=True, exist_ok=True)
    (cg_dir / "cpu.stat").write_bytes(
        f"usage_usec {usage_usec}\nthrottled_usec {throttled_usec}\n".encode("utf-8")
    )
    (cg_dir / "memory.current").write_bytes(f"{mem_current}\n".encode("utf-8"))
    (cg_dir / "memory.stat").write_bytes(f"inactive_file {inactive_file}\n".encode("utf-8"))
    (cg_dir / "memory.swap.current").write_bytes(f"{mem_swap}\n".encode("utf-8"))
    (cg_dir / "memory.max").write_bytes(f"{mem_max}\n".encode("utf-8"))
    (cg_dir / "memory.events").write_bytes(f"oom 0\noom_kill {oom_kill}\n".encode("utf-8"))
    (cg_dir / "pids.current").write_bytes(f"{pids}\n".encode("utf-8"))
    (cg_dir / "io.stat").write_bytes(f"253:0 rbytes={rbytes} wbytes={wbytes}\n".encode("utf-8"))


@pytest.mark.asyncio
async def test_14_v110_cgroups_v2_pod_metrics_hub_self_monitoring_and_6_noc_dashboards(
    tmp_path: Path, live_backends: LiveObservabilityBackends
) -> None:
    """Verify v1.1.0 rootless cgroups-v2 NS8 pod metrics, Hub `:9097/metrics/ns8-node`, and 6 NOC dashboards."""
    fake_cgroup = tmp_path / "fake_cgroup_v2"
    fake_passwd = tmp_path / "fake_passwd"
    fake_proc = tmp_path / "fake_proc"
    fake_proc.mkdir(parents=True, exist_ok=True)

    fake_passwd.write_bytes(
        (
            "root:x:0:0:root:/root:/bin/bash\n"
            "mail1:x:1001:1001:NS8 Mail:/home/mail1:/bin/bash\n"
            "nextcloud1:x:1002:1002:NS8 Nextcloud:/home/nextcloud1:/bin/bash\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        ).encode("utf-8")
    )

    # 1. Build synthetic cgroups-v2 tree:
    #    - `mail1` (rootless UID 1001) with `dovecot.service`, `clamd.service`, and ignored `dbus.service`
    #    - `nextcloud1` (rootless UID 1002) with `oom_kill 2`
    #    - `samba1` (rootful `system.slice/samba1.service`)
    mail_slice = fake_cgroup / "user.slice" / "user-1001.slice"
    _write_cgroup_slice_files(
        mail_slice,
        usage_usec=42_500_000,
        throttled_usec=500_000,
        mem_current=800_000_000,
        inactive_file=200_000_000,
        mem_swap=1_048_576,
        mem_max="2147483648",
        oom_kill=0,
        pids=28,
        rbytes=12_000_000,
        wbytes=4_500_000,
    )
    mail_app_slice = mail_slice / "user@1001.service" / "app.slice"
    _write_cgroup_slice_files(
        mail_app_slice / "dovecot.service",
        usage_usec=15_000_000,
        mem_current=220_000_000,
        inactive_file=20_000_000,
        pids=8,
    )
    _write_cgroup_slice_files(
        mail_app_slice / "clamd.service",
        usage_usec=22_000_000,
        mem_current=450_000_000,
        inactive_file=50_000_000,
        pids=6,
    )
    _write_cgroup_slice_files(
        mail_app_slice / "dbus.service",
        usage_usec=100_000,
        mem_current=4_000_000,
        pids=1,
    )

    nc_slice = fake_cgroup / "user.slice" / "user-1002.slice"
    _write_cgroup_slice_files(
        nc_slice,
        usage_usec=18_000_000,
        mem_current=1_200_000_000,
        inactive_file=100_000_000,
        oom_kill=2,
        pids=35,
    )

    samba_slice = fake_cgroup / "system.slice" / "samba1.service"
    _write_cgroup_slice_files(
        samba_slice,
        usage_usec=8_500_000,
        mem_current=512_000_000,
        inactive_file=64_000_000,
        pids=19,
    )

    # Minimal synthetic `/proc` files for Hub host telemetry
    (fake_proc / "stat").write_bytes(
        b"cpu  1000 20 300 8000 50 0 10 5 0 0\ncpu0 1000 20 300 8000 50 0 10 5 0 0\nbtime 1763000000\n"
    )
    (fake_proc / "meminfo").write_bytes(
        (
            "MemTotal:       16384000 kB\n"
            "MemFree:         4096000 kB\n"
            "MemAvailable:    8192000 kB\n"
            "Buffers:          512000 kB\n"
            "Cached:          3584000 kB\n"
            "SwapTotal:       2097152 kB\n"
            "SwapFree:        2097152 kB\n"
        ).encode("utf-8")
    )
    (fake_proc / "loadavg").write_bytes(b"0.42 0.35 0.28 2/410 12345\n")
    (fake_proc / "vmstat").write_bytes(b"oom_kill 0\n")

    cg_env = {
        "NS8_CGROUP_ROOT": str(fake_cgroup),
        "NS8_PASSWD_FILE": str(fake_passwd),
        "NS8_PROC_ROOT": str(fake_proc),
    }

    # 2. Verify Collector `bin/collect-ns8-metrics` harvests the full cgroups-v2 tree without root
    collector = NS8ModuleInstance(
        kind="collector",
        install_dir=tmp_path / "collector_v110_home",
        module_id="central-monitoring-collector1",
        backends=live_backends,
    )
    await collector.run_script("actions/create-module/20initialize")
    await collector.run_script("bin/collect-ns8-metrics", validate_io=False, extra_env=cg_env)

    col_prom = (collector.state_dir / "textfile" / "ns8.prom").read_text(encoding="utf-8")
    for expected_sample in (
        'ns8_module_up{module_id="mail1",module_type="rootless"} 1',
        'ns8_module_cpu_seconds_total{module_id="mail1",module_type="rootless"} 42.5',
        'ns8_module_cpu_throttled_seconds_total{module_id="mail1",module_type="rootless"} 0.5',
        'ns8_module_memory_working_set_bytes{module_id="mail1",module_type="rootless"} 600000000',
        'ns8_module_memory_bytes{module_id="mail1",module_type="rootless"} 800000000',
        'ns8_module_memory_swap_bytes{module_id="mail1",module_type="rootless"} 1048576',
        'ns8_module_memory_limit_bytes{module_id="mail1",module_type="rootless"} 2147483648',
        'ns8_module_io_read_bytes_total{module_id="mail1",module_type="rootless"} 12000000',
        'ns8_module_io_write_bytes_total{module_id="mail1",module_type="rootless"} 4500000',
        'ns8_module_pids{module_id="mail1",module_type="rootless"} 28',
        'ns8_module_oom_kills_total{module_id="nextcloud1",module_type="rootless"} 2',
        'ns8_module_up{module_id="samba1",module_type="rootful"} 1',
        'ns8_pod_unit_memory_working_set_bytes{module_id="mail1",unit="dovecot"} 200000000',
        'ns8_pod_unit_memory_working_set_bytes{module_id="mail1",unit="clamd"} 400000000',
        'ns8_container_running{module_id="mail1",container="dovecot"} 1',
        'ns8_container_running{module_id="mail1",container="clamd"} 1',
    ):
        assert expected_sample in col_prom, f"Collector ns8.prom missing: {expected_sample}"
    assert 'unit="dbus"' not in col_prom

    # 3. Simulate Grafana 11 file-provisioned Org 1 (`400 Cannot save provisioned dashboard`),
    #    configure Hub self-monitoring (`monitor_local_ns8_node=True`, `local_node_customer="bls-isp"`),
    #    and verify live `:9097/metrics/ns8-node` vs public `:8080` block!
    gf = live_backends.grafana
    gf.simulate_org1_file_provisioned = True
    msp_support_uid = gf.add_org1_user(
        login="msp.noc",
        email="noc@bls-isp.net",
        org1_role="Editor",
        is_external=True,
        is_grafana_admin=False,
    )

    hub = NS8ModuleInstance(
        kind="hub",
        install_dir=tmp_path / "hub_v110_home",
        module_id="central-monitoring-hub1",
        tcp_port=20080,
        backends=live_backends,
    )
    await hub.run_script("actions/create-module/20initialize")

    v110_cfg_on = {
        "host": "monitoring.bls-isp.net",
        "lets_encrypt": True,
        "http2https": True,
        "storage_mode": "local",
        "monitor_local_ns8_node": True,
        "local_node_customer": "bls-isp",
        "local_node_site": "hub",
        "grafana_admin_password": "MspV110AdminPassword!",
    }
    await hub.run_script("actions/configure-module/01hostname-validation", v110_cfg_on)
    await hub.run_script("actions/configure-module/20configure", v110_cfg_on, extra_env=cg_env)
    await hub.run_script("actions/configure-module/80start_services", v110_cfg_on)

    _, _, _, read_on = await hub.run_script("actions/get-configuration/20read", {})
    assert read_on["monitor_local_ns8_node"] is True
    assert read_on["local_node_customer"] == "bls-isp"
    assert read_on["local_node_site"] == "hub"
    assert hub.read_meta()["systemctl_state"]["hub-ns8-metrics.timer"] == "active"

    prom_yml_on = (hub.config_dir / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    assert "job_name: hub-ns8-node" in prom_yml_on
    assert "metrics_path: /metrics/ns8-node" in prom_yml_on
    assert '"127.0.0.1:9097"' in prom_yml_on
    assert 'customer: "bls-isp"' in prom_yml_on
    assert 'site: "hub"' in prom_yml_on
    assert 'collector_id: "hub-local"' in prom_yml_on

    v110_gw = await live_backends.start_hub_gateway(hub.state_dir, tmp_path / "v110_gw_tls")
    v110_ssl = ssl.create_default_context(cafile=str(v110_gw.ca_cert_path))

    async with aiohttp.ClientSession() as session:
        # Loopback `:9097/metrics/ns8-node` serves full host + cgroups-v2 exposition
        async with session.get(f"{v110_gw.relay_url}/metrics/ns8-node") as relay_resp:
            assert relay_resp.status == 200
            relay_body = await relay_resp.text()
            for expected_hub_sample in (
                "node_memory_MemTotal_bytes",
                'ns8_module_up{module_id="mail1",module_type="rootless"} 1',
                'ns8_module_memory_working_set_bytes{module_id="mail1",module_type="rootless"} 600000000',
                'ns8_module_oom_kills_total{module_id="nextcloud1",module_type="rootless"} 2',
                'ns8_module_up{module_id="samba1",module_type="rootful"} 1',
                'ns8_pod_unit_memory_working_set_bytes{module_id="mail1",unit="dovecot"} 200000000',
                'ns8_pod_unit_memory_working_set_bytes{module_id="mail1",unit="clamd"} 400000000',
            ):
                assert expected_hub_sample in relay_body, (
                    f"Hub /metrics/ns8-node missing: {expected_hub_sample}"
                )
            assert 'unit="dbus"' not in relay_body

        # Public `hub-gateway` (`:8080`) MUST NEVER expose `/metrics/ns8-node` or `/metrics`!
        for pub_path in (
            "/metrics/ns8-node",
            "/metrics",
            "/api/datasources/proxy/uid/prometheus/metrics/ns8-node",
        ):
            async with session.get(
                f"{v110_gw.https_url}{pub_path}",
                ssl=v110_ssl,
            ) as blocked_pub_resp:
                assert blocked_pub_resp.status in (403, 404), (
                    f"Public gateway exposed {pub_path}: status={blocked_pub_resp.status}"
                )

    # 4. Provision Customer Org `bls-isp` + portal user while `simulate_org1_file_provisioned=True`:
    #    verify `/api/admin/provisioning/dashboards/reload` ran, `400 Cannot save provisioned dashboard`
    #    in Org 1 was gracefully tolerated, and ALL 6 locked dashboards + users synced to `bls_oid`!
    _, _, _, bls_saved = await hub.run_script(
        "actions/save-tenant/20save",
        {
            "customer": "bls-isp",
            "display_name": "BLS ISP Internal",
            "sites": ["hub", "hq"],
            "contact_emails": ["noc@bls-isp.net"],
            "customer_portal_enabled": True,
        },
    )
    bls_oid = int(bls_saved["grafana_org_id"])
    assert bls_oid > 1

    _, _, _, bls_user_out = await hub.run_script(
        "actions/save-portal-user/20save",
        {
            "customer": "bls-isp",
            "username": "bls.portal",
            "role": "Viewer",
            "password": "BlsPortalPassword!2026",
        },
    )
    assert bls_user_out["grafana_synced"] is True

    assert gf.dashboard_reloads >= 1
    assert gf.org1_provisioned_rejections >= 6

    expected_6_uids = {
        "ns8-multi-cluster-overview",
        "ns8-pods-and-modules",
        "linux-windows-servers",
        "proxmox-snmp-infrastructure",
        "web-ssl-uptime",
        "central-log-explorer",
    }
    assert set(gf.dashboards[bls_oid].keys()) == expected_6_uids
    for uid, dash_model in gf.dashboards[bls_oid].items():
        assert dash_model["editable"] is False, f"Dashboard {uid} must be non-editable in Customer Org"
        cust_vars = [
            v
            for v in dash_model.get("templating", {}).get("list", [])
            if isinstance(v, dict) and v.get("name") == "customer"
        ]
        assert len(cust_vars) == 1
        assert cust_vars[0]["type"] == "constant"
        assert cust_vars[0]["query"] == "bls-isp"
        assert cust_vars[0]["hide"] == 2

    log_dash_vars = {
        v["name"]: v
        for v in gf.dashboards[bls_oid]["central-log-explorer"].get("templating", {}).get("list", [])
        if isinstance(v, dict) and "name" in v
    }
    assert log_dash_vars["log_search"]["type"] == "textbox"
    assert log_dash_vars["site"]["type"] != "constant"

    bls_portal_uid = next(u["id"] for u in gf.users.values() if u["login"] == "bls.portal")
    assert gf.org_members[bls_oid] == {
        1: "Admin",
        msp_support_uid: "Viewer",
        bls_portal_uid: "Viewer",
    }
    assert bls_portal_uid not in gf.org_members[1]

    # 5. Toggle `monitor_local_ns8_node=False` -> verify `hub-ns8-node` removed from `prometheus.yml`
    #    and `hub-ns8-metrics.timer` stopped/disabled!
    v110_cfg_off = dict(v110_cfg_on)
    v110_cfg_off["monitor_local_ns8_node"] = False
    await hub.run_script("actions/configure-module/20configure", v110_cfg_off, extra_env=cg_env)
    await hub.run_script("actions/configure-module/80start_services", v110_cfg_off)

    _, _, _, read_off = await hub.run_script("actions/get-configuration/20read", {})
    assert read_off["monitor_local_ns8_node"] is False
    prom_yml_off = (hub.config_dir / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    assert "hub-ns8-node" not in prom_yml_off
    assert hub.read_meta()["systemctl_state"]["hub-ns8-metrics.timer"] == "inactive"








