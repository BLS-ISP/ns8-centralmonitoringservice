from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hub_alerting.blackbox_config import render_blackbox_config
from hub_alerting.targets_manager import build_prometheus_relabel_configs


def test_blackbox_config_renders_all_six_rootless_safe_modules(tmp_path: Path) -> None:
    out_path = tmp_path / "config" / "blackbox" / "blackbox.yml"
    rendered = render_blackbox_config(out_path)
    assert out_path.is_file()
    assert "\r\n" not in rendered
    for mod in ("http_2xx:", "http_post_2xx:", "tcp_connect:", "dns_tcp:", "dns_udp:", "icmp:"):
        assert mod in rendered
    assert 'preferred_ip_protocol: "ip4"' in rendered
    assert "CAP_NET_RAW" not in rendered


def test_exporter_blackbox_snmp_and_federation_target_crud_and_secret_redaction(
    hub_env: dict[str, Any],
) -> None:
    run_action = hub_env["run_action"]
    config_dir: Path = hub_env["config_dir"]
    state_dir: Path = hub_env["state_dir"]
    backends = hub_env["backends"]

    # 1. Save an exporter target
    res_exp = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme Linux VPN Exporter",
            "enabled": True,
            "target_type": "exporter",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "linux",
            "scrape_interval": "30s",
            "endpoints": ["198.51.100.11:9100", "198.51.100.12:9100"],
            "scheme": "http",
            "metrics_path": "/metrics",
        },
    )
    assert res_exp["status"] == "ok"
    assert res_exp["created"] is True
    exp_id = res_exp["id"]

    exp_sd_file = config_dir / "prometheus" / "file_sd" / "exporters" / f"{exp_id}.json"
    assert exp_sd_file.is_file()
    exp_sd = json.loads(exp_sd_file.read_text(encoding="utf-8"))
    assert exp_sd[0]["targets"] == ["198.51.100.11:9100", "198.51.100.12:9100"]
    assert exp_sd[0]["labels"]["customer"] == "acme-corp"
    assert exp_sd[0]["labels"]["site"] == "hq"
    assert exp_sd[0]["labels"]["device_role"] == "linux"
    assert exp_sd[0]["labels"]["collector_id"] == "hub-central"

    # 2. Save a blackbox target
    res_bb = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme Portal HTTPS",
            "enabled": True,
            "target_type": "blackbox",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "web",
            "scrape_interval": "60s",
            "endpoints": ["https://portal.acme.example.com"],
            "blackbox_module": "http_2xx",
        },
    )
    bb_id = res_bb["id"]
    bb_sd_file = config_dir / "prometheus" / "file_sd" / "blackbox" / f"{bb_id}.json"
    assert bb_sd_file.is_file()
    bb_sd = json.loads(bb_sd_file.read_text(encoding="utf-8"))
    assert bb_sd[0]["targets"] == ["https://portal.acme.example.com"]
    assert bb_sd[0]["labels"]["__param_module"] == "http_2xx"
    assert bb_sd[0]["labels"]["module"] == "http_2xx"
    assert bb_sd[0]["labels"]["collector_id"] == "hub-central"

    # 3. Save an SNMPv3 authPriv target + an SNMPv2c target
    res_snmp_v3 = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme Core Fortigate",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-corp",
            "site": "dc1",
            "device_role": "snmp-firewall",
            "scrape_interval": "60s",
            "endpoints": ["198.51.100.254"],
            "snmp_module": "fortigate",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "msp-snmp-ro",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "auth_password": "SuperSecretAuthPassword!",
                "priv_protocol": "AES",
                "priv_password": "SuperSecretPrivPassword!",
            },
        },
    )
    snmp_v3_id = res_snmp_v3["id"]

    res_snmp_v2 = run_action(
        "save-target",
        "20save",
        {
            "name": "Beta APC UPS",
            "enabled": True,
            "target_type": "snmp",
            "customer": "beta-gmbh",
            "site": "berlin",
            "device_role": "snmp-ups",
            "scrape_interval": "30s",
            "endpoints": ["203.0.113.45"],
            "snmp_module": "apcupsd",
            "snmp_version": "v2c",
            "snmp_community": "BetaPrivateComm99",
        },
    )
    snmp_v2_id = res_snmp_v2["id"]

    snmp_sd_file = config_dir / "prometheus" / "file_sd" / "snmp" / f"{snmp_v3_id}.json"
    assert snmp_sd_file.is_file()
    snmp_sd = json.loads(snmp_sd_file.read_text(encoding="utf-8"))
    assert snmp_sd[0]["labels"]["__param_module"] == "fortigate"
    assert snmp_sd[0]["labels"]["__param_auth"] == f"target_{snmp_v3_id}"

    snmp_yml = (config_dir / "snmp" / "snmp.yml").read_text(encoding="utf-8")
    assert f"target_{snmp_v3_id}:" in snmp_yml
    assert "SuperSecretAuthPassword!" in snmp_yml
    assert "SuperSecretPrivPassword!" in snmp_yml
    assert "BetaPrivateComm99" in snmp_yml
    for mod in ("if_mib:", "apcupsd:", "synology:", "mikrotik:", "fortigate:", "generic:"):
        assert mod in snmp_yml
    assert backends.snmp_reloads >= 2

    # 4. Save an ns8-federation target with bearer token
    prev_prom_reloads = backends.prom_reloads
    res_fed = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme NS8 Cluster Federation",
            "enabled": True,
            "target_type": "ns8-federation",
            "customer": "acme-corp",
            "site": "dc1",
            "device_role": "ns8",
            "scrape_interval": "30s",
            "endpoints": ["ns8.acme.example.com:443"],
            "scheme": "https",
            "bearer_token": "fed_secret_token_12345",
        },
    )
    fed_id = res_fed["id"]
    assert backends.prom_reloads > prev_prom_reloads

    fed_yml = (config_dir / "prometheus" / "federation_jobs.yml").read_text(encoding="utf-8")
    assert f"ns8-federation-{fed_id}" in fed_yml
    assert "honor_labels: false" in fed_yml
    assert 'metrics_path: "/federate"' in fed_yml
    assert "fed_secret_token_12345" not in fed_yml
    secret_file = config_dir / "prometheus" / "secrets" / f"{fed_id}.secret"
    assert secret_file.is_file()
    assert secret_file.read_text(encoding="utf-8") == "fed_secret_token_12345"

    # 5. Update SNMPv3 target with secret_unchanged=True and verify secrets survive
    res_upd = run_action(
        "save-target",
        "20save",
        {
            "id": snmp_v3_id,
            "name": "Acme Core Fortigate HA",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-corp",
            "site": "dc1",
            "device_role": "snmp-firewall",
            "scrape_interval": "60s",
            "endpoints": ["198.51.100.254"],
            "snmp_module": "fortigate",
            "snmp_version": "v3",
            "secret_unchanged": True,
            "snmp_v3": {
                "username": "msp-snmp-ro",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "priv_protocol": "AES",
            },
        },
    )
    assert res_upd["created"] is False
    assert "SuperSecretAuthPassword!" in (config_dir / "snmp" / "snmp.yml").read_text(encoding="utf-8")

    # 6. list-targets filtering, pagination, and strict secret redaction
    listed = run_action("list-targets", "20read", {"customer": "acme-corp", "page": 1, "page_size": 50})
    raw_listed = json.dumps(listed)
    assert "SuperSecretAuthPassword!" not in raw_listed
    assert "SuperSecretPrivPassword!" not in raw_listed
    assert "BetaPrivateComm99" not in raw_listed
    assert "fed_secret_token_12345" not in raw_listed
    assert listed["pagination"]["total_items"] == 4

    by_id = {t["id"]: t for t in listed["targets"]}
    assert by_id[snmp_v3_id]["has_secret"] is True
    assert by_id[fed_id]["has_secret"] is True
    assert by_id[exp_id]["has_secret"] is False

    # 7. Delete target removes file_sd & secret file cleanly
    del_res = run_action("delete-target", "20delete", {"id": snmp_v2_id})
    assert del_res == {"status": "ok", "id": snmp_v2_id, "deleted": True}
    assert not (config_dir / "prometheus" / "file_sd" / "snmp" / f"{snmp_v2_id}.json").exists()
    assert "BetaPrivateComm99" not in (config_dir / "snmp" / "snmp.yml").read_text(encoding="utf-8")

    # Deleting non-existent ID returns deleted=False cleanly
    del_missing = run_action("delete-target", "20delete", {"id": "nonexistent_id"})
    assert del_missing["deleted"] is False

    # Check state/targets.json exists
    assert (state_dir / "targets.json").is_file()

    # Check relabeling helper has standard multi-target relabeling
    relabel_jobs = build_prometheus_relabel_configs()
    raw_relabel = json.dumps(relabel_jobs)
    assert "127.0.0.1:9115" in raw_relabel
    assert "127.0.0.1:9116" in raw_relabel
    assert "__param_target" in raw_relabel


def test_disabled_target_and_federation_basic_auth_and_snmpv3_levels(
    hub_env: dict[str, Any],
) -> None:
    run_action = hub_env["run_action"]
    config_dir: Path = hub_env["config_dir"]

    # Federation with Basic Auth
    fed_basic = run_action(
        "save-target",
        "20save",
        {
            "name": "Beta Federation BasicAuth",
            "enabled": True,
            "target_type": "ns8-federation",
            "customer": "beta-gmbh",
            "site": "berlin",
            "device_role": "ns8",
            "endpoints": ["https://ns8.beta.example.com:8443/federate"],
            "basic_auth_user": "prom-fed",
            "basic_auth_password": "BasicFedPassword!",
            "tls_skip_verify": True,
        },
    )
    fed_id = fed_basic["id"]
    fed_yml = (config_dir / "prometheus" / "federation_jobs.yml").read_text(encoding="utf-8")
    assert 'username: "prom-fed"' in fed_yml
    assert "insecure_skip_verify: true" in fed_yml
    assert "BasicFedPassword!" not in fed_yml
    assert (config_dir / "prometheus" / "secrets" / f"{fed_id}.secret").read_text(
        encoding="utf-8"
    ) == "BasicFedPassword!"

    # Disable target -> removed from active scrape_configs while remaining in list-targets
    run_action(
        "save-target",
        "20save",
        {
            "id": fed_id,
            "name": "Beta Federation BasicAuth",
            "enabled": False,
            "target_type": "ns8-federation",
            "customer": "beta-gmbh",
            "site": "berlin",
            "device_role": "ns8",
            "endpoints": ["ns8.beta.example.com:8443"],
            "basic_auth_user": "prom-fed",
            "secret_unchanged": True,
        },
    )
    fed_yml_disabled = (config_dir / "prometheus" / "federation_jobs.yml").read_text(encoding="utf-8")
    assert f"ns8-federation-{fed_id}" not in fed_yml_disabled

    # SNMPv3 noAuthNoPriv and authNoPriv
    snmp_noauth = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme Switch noAuthNoPriv",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "snmp-network",
            "endpoints": ["198.51.100.200"],
            "snmp_module": "mikrotik",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "ro-noauth",
                "security_level": "noAuthNoPriv",
            },
        },
    )
    assert snmp_noauth["status"] == "ok"
    snmp_yml = (config_dir / "snmp" / "snmp.yml").read_text(encoding="utf-8")
    assert "security_level: noAuthNoPriv" in snmp_yml


def test_save_target_rejects_unknown_tenant_site_and_ssrf_with_exit_code_2(
    hub_env: dict[str, Any],
) -> None:
    run_action = hub_env["run_action"]

    # Unknown tenant
    proc_tenant = run_action(
        "save-target",
        "20save",
        {
            "name": "Bad Tenant Target",
            "enabled": True,
            "target_type": "exporter",
            "customer": "ghost-corp",
            "site": "hq",
            "device_role": "linux",
            "endpoints": ["198.51.100.50:9100"],
        },
        expect_success=False,
    )
    assert proc_tenant.returncode == 2
    err_tenant = json.loads(proc_tenant.stdout)
    assert err_tenant[0]["field"] == "customer"

    # Unknown site for known tenant
    proc_site = run_action(
        "save-target",
        "20save",
        {
            "name": "Bad Site Target",
            "enabled": True,
            "target_type": "exporter",
            "customer": "acme-corp",
            "site": "munich",
            "device_role": "linux",
            "endpoints": ["198.51.100.50:9100"],
        },
        expect_success=False,
    )
    assert proc_site.returncode == 2
    err_site = json.loads(proc_site.stdout)
    assert err_site[0]["field"] == "site"

    # SSRF endpoint
    proc_ssrf = run_action(
        "save-target",
        "20save",
        {
            "name": "Internal Prometheus Scrape Attempt",
            "enabled": True,
            "target_type": "blackbox",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "web",
            "endpoints": ["http://127.0.0.1:9090/-/reload"],
            "blackbox_module": "http_2xx",
        },
        expect_success=False,
    )
    assert proc_ssrf.returncode == 2
    err_ssrf = json.loads(proc_ssrf.stdout)
    assert err_ssrf[0]["error"] == "FORBIDDEN_INTERNAL_ENDPOINT"
