"""Unit tests for collector_lib.alloy_renderer (Alloy River + pve.yml + snmp-auths.yml + hub.token)."""

from __future__ import annotations

from pathlib import Path

import pytest


def _assert_balanced_river(text: str) -> None:
    """Verify balanced {}, [], () and string quotes outside comments in River config."""
    stack: list[str] = []
    pairs = {"}": "{", "]": "[", ")": "("}
    in_str = False
    escape = False

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        i = 0
        while i < len(raw_line):
            ch = raw_line[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == "/" and i + 1 < len(raw_line) and raw_line[i + 1] == "/":
                    break
                if ch == '"':
                    in_str = True
                elif ch in "{[(":
                    stack.append(ch)
                elif ch in "}])":
                    assert stack, f"Unmatched closing {ch!r} on line {line_no}"
                    top = stack.pop()
                    assert top == pairs[ch], f"Mismatched {top!r} vs {ch!r} on line {line_no}"
            i += 1
        assert not in_str, f"Unterminated string literal on line {line_no}"

    assert not stack, f"Unclosed delimiters at EOF: {stack}"


def test_render_full_collector_config_all_target_types_and_syslog(state_dir: Path) -> None:
    from collector_lib.alloy_renderer import CollectorConfig, render_collector_artifacts

    secret_token = "cms_v1_SuperSecretBearerTokenValue1234567890ABCD"
    cfg = CollectorConfig(
        configured=True,
        hub_url="https://monitoring.msp.example.com/",
        auth_token=secret_token,
        customer="acme-corp",
        site="hq-berlin",
        collector_id="acme-corp-hq-ns8",
        collect_local_ns8=True,
        enable_syslog_receiver=True,
        syslog_port=5514,
        wal_max_disk_mb=4096,
        tls_skip_verify=False,
    )
    targets = [
        {
            "id": "tgt_pve01",
            "name": "PVE Cluster",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "192.168.1.10",
            "port": 8006,
            "scrape_interval": "60s",
            "scheme": "https",
            "tls_skip_verify": True,
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "pve-secret-token-value",
        },
        {
            "id": "tgt_win01",
            "name": "Win DC01",
            "enabled": True,
            "target_type": "windows",
            "device_role": "windows",
            "host": "192.168.1.20",
            "port": 9182,
            "scrape_interval": "30s",
            "scheme": "http",
            "metrics_path": "/metrics",
        },
        {
            "id": "tgt_lin01",
            "name": "Linux ERP",
            "enabled": True,
            "target_type": "linux",
            "device_role": "linux",
            "host": "192.168.1.21",
            "port": 9100,
            "scrape_interval": "30s",
            "scheme": "http",
            "metrics_path": "/metrics",
        },
        {
            "id": "tgt_sw01",
            "name": "Core Switch",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-network",
            "host": "192.168.1.2",
            "port": 161,
            "scrape_interval": "60s",
            "snmp_module": "if_mib",
            "snmp_version": "v2c",
            "snmp_community": "corp-ro-comm",
        },
        {
            "id": "tgt_ups01",
            "name": "APC SmartUPS",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-ups",
            "host": "192.168.1.3",
            "port": 161,
            "scrape_interval": "60s",
            "snmp_module": "apcupsd",
            "snmp_version": "v2c",
            "snmp_community": "ups-ro",
        },
        {
            "id": "tgt_nas01",
            "name": "Synology Backup NAS",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-nas",
            "host": "192.168.1.4",
            "port": 161,
            "scrape_interval": "60s",
            "snmp_module": "synology",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "nasmon",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "auth_password": "nas-auth-pass",
                "priv_protocol": "AES",
                "priv_password": "nas-priv-pass",
            },
        },
        {
            "id": "tgt_fw01",
            "name": "Edge Firewall",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-firewall",
            "host": "192.168.1.1",
            "port": 161,
            "scrape_interval": "30s",
            "snmp_module": "generic",
            "snmp_version": "v2c",
            "snmp_community": "fw-ro",
        },
        {
            "id": "tgt_custom01",
            "name": "Custom Web App Metrics",
            "enabled": True,
            "target_type": "custom-exporter",
            "device_role": "web",
            "host": "192.168.1.99",
            "port": 9113,
            "scrape_interval": "15s",
            "scheme": "https",
            "metrics_path": "/custom-metrics",
            "tls_skip_verify": True,
        },
    ]

    result = render_collector_artifacts(state_dir, cfg, targets)
    assert result.pve_exporter_enabled is True

    alloy_text = result.alloy_config_path.read_text(encoding="utf-8")
    _assert_balanced_river(alloy_text)
    assert b"\r\n" not in result.alloy_config_path.read_bytes()

    # Never embed raw secrets in config.alloy!
    assert secret_token not in alloy_text
    assert "pve-secret-token-value" not in alloy_text
    assert "corp-ro-comm" not in alloy_text
    assert "nas-auth-pass" not in alloy_text
    assert 'bearer_token_file = "/etc/alloy/secrets/hub.token"' in alloy_text

    # Token file written cleanly without trailing newline
    assert result.token_file_path.read_text(encoding="utf-8") == secret_token

    # Hub endpoints stripped of double slashes
    assert 'url               = "https://monitoring.msp.example.com/api/v1/write"' in alloy_text
    assert 'url               = "https://monitoring.msp.example.com/loki/api/v1/push"' in alloy_text

    # Local NS8 collection + textfile + journal
    assert 'prometheus.exporter.unix "local_ns8"' in alloy_text
    assert 'directory = "/etc/alloy/textfile"' in alloy_text
    assert 'loki.source.journal "local_ns8_journal"' in alloy_text
    assert 'replacement  = "ns8"' in alloy_text

    # Proxmox via local 127.0.0.1:9221 sidecar + pve.yml
    assert "127.0.0.1:9221" in alloy_text
    pve_yml = result.pve_config_path.read_text(encoding="utf-8")
    assert 'user: "monitoring@pve"' in pve_yml
    assert 'token_name: "alloy"' in pve_yml
    assert 'token_value: "pve-secret-token-value"' in pve_yml
    assert "verify_ssl: false" in pve_yml

    # Windows, Linux, Custom Exporter, SNMP modules & roles, Syslog
    assert "192.168.1.20:9182" in alloy_text
    assert "192.168.1.21:9100" in alloy_text
    assert "192.168.1.99:9113" in alloy_text
    assert 'metrics_path    = "/custom-metrics"' in alloy_text
    for role in (
        "ns8",
        "proxmox",
        "windows",
        "linux",
        "snmp-network",
        "snmp-ups",
        "snmp-nas",
        "snmp-firewall",
        "web",
    ):
        assert f'"{role}"' in alloy_text

    for snmp_mod in ("if_mib", "apcupsd", "synology", "generic"):
        assert f'module  = "{snmp_mod}"' in alloy_text

    snmp_yml = result.snmp_auths_path.read_text(encoding="utf-8")
    assert "corp-ro-comm" in snmp_yml
    assert "nas-auth-pass" in snmp_yml
    assert "SHA256" in snmp_yml

    assert 'loki.source.syslog "lan_syslog"' in alloy_text
    assert 'customer     = "acme-corp"' in alloy_text
    assert 'site         = "hq-berlin"' in alloy_text
    assert 'collector_id = "acme-corp-hq-ns8"' in alloy_text


def test_disabling_local_ns8_proxmox_and_syslog_omits_optional_blocks(state_dir: Path) -> None:
    from collector_lib.alloy_renderer import CollectorConfig, render_collector_artifacts

    cfg = CollectorConfig(
        configured=True,
        hub_url="https://hub.example.org",
        auth_token="cms_v1_AnotherValidBearerToken1234567890abcd",
        customer="beta-gmbh",
        site="branch1",
        collector_id="beta-gmbh-branch1-c1",
        collect_local_ns8=False,
        enable_syslog_receiver=False,
        syslog_port=5514,
        wal_max_disk_mb=512,
        tls_skip_verify=True,
    )
    targets = [
        {
            "id": "tgt_pve_disabled",
            "name": "Disabled PVE",
            "enabled": False,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "10.10.10.5",
            "port": 8006,
            "scrape_interval": "60s",
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "unused",
        }
    ]

    result = render_collector_artifacts(state_dir, cfg, targets)
    assert result.pve_exporter_enabled is False

    alloy_text = result.alloy_config_path.read_text(encoding="utf-8")
    _assert_balanced_river(alloy_text)
    assert "local_ns8" not in alloy_text
    assert "lan_syslog" not in alloy_text
    assert "127.0.0.1:9221" not in alloy_text
    assert "insecure_skip_verify = true" in alloy_text


def test_river_escaping_prevents_quote_or_block_injection(state_dir: Path) -> None:
    from collector_lib.alloy_renderer import CollectorConfig, render_collector_artifacts

    cfg = CollectorConfig(
        configured=True,
        hub_url="https://hub.example.org",
        auth_token="cms_v1_Token123456789012345678901234567890",
        customer="acme-corp",
        site="hq",
        collector_id="acme-hq-1",
    )
    targets = [
        {
            "id": "tgt_inj",
            "name": 'Evil " }\nexec { cmd = "pwn" } //',
            "enabled": True,
            "target_type": "linux",
            "device_role": "linux",
            "host": "192.168.1.77",
            "port": 9100,
            "scrape_interval": "30s",
        }
    ]
    result = render_collector_artifacts(state_dir, cfg, targets)
    alloy_text = result.alloy_config_path.read_text(encoding="utf-8")
    _assert_balanced_river(alloy_text)
    assert '\nexec {' not in alloy_text
