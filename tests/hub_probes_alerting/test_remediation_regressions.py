from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hub_alerting import pod_http_request
from hub_alerting.alertmanager_config import configure_alerting, discover_smarthost_env
from hub_alerting.blackbox_config import render_blackbox_config
from hub_alerting.silences_manager import delete_silence
from hub_alerting.snmp_config import render_snmp_config
from hub_alerting.ssrf_guard import (
    SSRFValidationError,
    assert_not_internal_pod_endpoint,
)


@pytest.mark.parametrize(
    "non_canonical_or_slirp_target",
    [
        "0x7f000001:9090",
        "0x7f.0.0.1:9090",
        "0177.0.0.1:9090",
        "127.1:9090",
        "10.514:9095",
        "10.0.2.1:53",
        "10.0.2.3:53",
        "10.0.2.100:8080",
        "[::ffff:10.0.2.1]:8080",
        "2130706433",
    ],
)
def test_high02_ssrf_rejects_hex_octal_short_ipv4_and_entire_slirp4netns_subnet(
    non_canonical_or_slirp_target: str,
) -> None:
    with pytest.raises(SSRFValidationError) as exc_info:
        assert_not_internal_pod_endpoint(non_canonical_or_slirp_target, field="endpoints")
    assert exc_info.value.code == "FORBIDDEN_INTERNAL_ENDPOINT"


def test_high02_blackbox_http_post_disables_redirects(tmp_path: Path) -> None:
    rendered = render_blackbox_config(tmp_path / "blackbox.yml")
    post_section = rendered.split("http_post_2xx:", 1)[1].split("tcp_connect:", 1)[0]
    assert "follow_redirects: false" in post_section
    assert "follow_redirects: true" not in post_section


def test_high02_custom_smtp_host_ssrf_and_ntfy_topic_traversal_rejected(
    hub_env: dict[str, Any],
) -> None:
    state_dir: Path = hub_env["state_dir"]

    # Custom smtp_host pointing to loopback/slirp4netns must fail SSRF check
    with pytest.raises(SSRFValidationError):
        configure_alerting(
            {
                "smarthost_email": {
                    "enabled": True,
                    "use_ns8_smarthost": False,
                    "smtp_host": "127.0.0.1",
                    "smtp_port": 25,
                    "from_address": "alerts@msp.example.com",
                    "default_to_addresses": ["noc@msp.example.com"],
                },
                "webhook_psa": {"enabled": False, "url": ""},
                "chat": {"teams_enabled": False, "slack_enabled": False},
                "push": {"enabled": False, "provider": "none"},
                "customer_email_routing": {"enabled": False, "min_severity": "critical"},
            },
            state_dir=state_dir,
        )

    # ntfy_topic containing ../ or query injection must fail validation
    from hub_alerting import ValidationFailure

    with pytest.raises(ValidationFailure) as topic_exc:
        configure_alerting(
            {
                "smarthost_email": {
                    "enabled": False,
                    "use_ns8_smarthost": True,
                    "from_address": "alerts@msp.example.com",
                    "default_to_addresses": [],
                },
                "webhook_psa": {"enabled": False, "url": ""},
                "chat": {"teams_enabled": False, "slack_enabled": False},
                "push": {
                    "enabled": True,
                    "provider": "ntfy",
                    "ntfy_url": "https://ntfy.msp.example.com",
                    "ntfy_topic": "../admin?foo=bar",
                },
                "customer_email_routing": {"enabled": False, "min_severity": "critical"},
            },
            state_dir=state_dir,
        )
    assert topic_exc.value.field == "push.ntfy_topic"


def test_med03_delete_silence_rejects_path_traversal_silence_id(hub_env: dict[str, Any]) -> None:
    from hub_alerting import ValidationFailure

    with pytest.raises(ValidationFailure) as exc_info:
        delete_silence({"silence_id": "../../-/quit"}, state_dir=hub_env["state_dir"])
    assert exc_info.value.field == "silence_id"


def test_arch09_discover_smarthost_reads_encrypt_smtp_keys(tmp_path: Path) -> None:
    sdir = tmp_path / "state"
    sdir.mkdir(parents=True)
    (sdir / "smarthost.env").write_text(
        "SMARTHOST_ENABLED=true\n"
        "SMARTHOST_HOST=smtp.relay.example.com\n"
        "SMARTHOST_PORT=587\n"
        "SMARTHOST_ENCRYPT_SMTP=starttls\n"
        "ENCRYPT_SMTP=starttls\n",
        encoding="utf-8",
        newline="\n",
    )
    info = discover_smarthost_env(sdir)
    assert info["available"] is True
    assert info["smarthost"] == "smtp.relay.example.com:587"
    assert info["require_tls"] is True


def test_arch10_snmp_config_includes_hc_octets_ifname_lookups_and_ups_load(tmp_path: Path) -> None:
    rendered = render_snmp_config([], tmp_path / "snmp.yml")

    mikrotik_block = rendered.split("  mikrotik:\n", 1)[1].split("  fortigate:\n", 1)[0]
    assert "name: ifHCInOctets" in mikrotik_block
    assert "name: ifHCOutOctets" in mikrotik_block
    assert "labelname: ifName" in mikrotik_block

    fortigate_block = rendered.split("  fortigate:\n", 1)[1].split("  generic:\n", 1)[0]
    assert "name: ifHCInOctets" in fortigate_block
    assert "name: ifHCOutOctets" in fortigate_block

    apcupsd_block = rendered.split("  apcupsd:\n", 1)[1].split("  synology:\n", 1)[0]
    assert "name: upsAdvOutputLoad" in apcupsd_block
    assert "name: upsOutputPercentLoad" in apcupsd_block


def test_arch11_list_targets_returns_non_secret_snmp_v3_metadata(hub_env: dict[str, Any]) -> None:
    run_action = hub_env["run_action"]
    saved = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme Core Switch v3",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "snmp-network",
            "endpoints": ["198.51.100.77"],
            "snmp_module": "if_mib",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "snmpv3-operator",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "auth_password": "TopSecretAuthPassword123",
                "priv_protocol": "AES256",
                "priv_password": "TopSecretPrivPassword456",
            },
        },
    )
    listed = run_action("list-targets", "20read", {"customer": "acme-corp"})
    target = next(t for t in listed["targets"] if t["id"] == saved["id"])
    assert target["snmp_v3"] == {
        "username": "snmpv3-operator",
        "security_level": "authPriv",
        "auth_protocol": "SHA256",
        "priv_protocol": "AES256",
    }
    raw = json.dumps(target)
    assert "TopSecretAuthPassword123" not in raw
    assert "TopSecretPrivPassword456" not in raw


def test_arch08_pod_http_request_falls_back_to_podman_netns_when_loopback_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_cmds: list[list[str]] = []

    def fake_runner(cmd: list[str], stdin_bytes: bytes, timeout: float) -> tuple[int, str]:
        captured_cmds.append(cmd)
        req_meta = json.loads(stdin_bytes.decode("utf-8"))
        assert req_meta["url"] == "http://127.0.0.1:1/api/v2/silences"
        assert req_meta["method"] == "GET"
        return 0, json.dumps({"status": 200, "body_b64": "W10="})

    monkeypatch.setenv("HUB_PODMAN_BIN", "/usr/bin/podman")
    status, body = pod_http_request(
        "http://127.0.0.1:1/api/v2/silences",
        method="GET",
        timeout=0.3,
        _podman_exec=fake_runner,
    )
    assert status == 200
    assert body == b"[]"
    assert len(captured_cmds) == 1
    assert captured_cmds[0][:4] == ["/usr/bin/podman", "exec", "-i", "hub-gateway"]


def test_phase2_qnap_and_printer_snmp_profiles_and_snmp_printer_role(
    hub_env: dict[str, Any],
) -> None:
    run_action = hub_env["run_action"]
    config_dir: Path = hub_env["config_dir"]

    # 1. Save QNAP NAS SNMP target
    res_qnap = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme QNAP TS-h973AX",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-corp",
            "site": "dc1",
            "device_role": "snmp-nas",
            "endpoints": ["198.51.100.88"],
            "snmp_module": "qnap",
            "snmp_version": "v2c",
            "snmp_community": "QnapReadComm",
        },
    )
    assert res_qnap["status"] == "ok"

    # 2. Save RFC 3805 Printer SNMP target with device_role="snmp-printer"
    res_prt = run_action(
        "save-target",
        "20save",
        {
            "name": "Acme Floor 2 Laser Printer",
            "enabled": True,
            "target_type": "snmp",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "snmp-printer",
            "endpoints": ["198.51.100.89"],
            "snmp_module": "printer",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "prt-monitor",
                "security_level": "authPriv",
                "auth_protocol": "SHA512",
                "auth_password": "PrinterAuthPassword123",
                "priv_protocol": "AES256",
                "priv_password": "PrinterPrivPassword456",
            },
        },
    )
    assert res_prt["status"] == "ok"

    # 3. Verify list-targets output schema validation & metadata
    listed = run_action("list-targets", "20read", {"customer": "acme-corp"})
    by_id = {t["id"]: t for t in listed["targets"]}
    assert by_id[res_qnap["id"]]["snmp_module"] == "qnap"
    assert by_id[res_prt["id"]]["device_role"] == "snmp-printer"
    assert by_id[res_prt["id"]]["snmp_module"] == "printer"
    assert by_id[res_prt["id"]]["snmp_v3"]["auth_protocol"] == "SHA512"

    # 4. Verify rendered snmp.yml has complete qnap and printer MIB metrics
    snmp_yml = (config_dir / "snmp" / "snmp.yml").read_text(encoding="utf-8")
    assert "  qnap:\n" in snmp_yml
    for qnap_metric in ("qnapVolumeStatus", "qnapVolumeDescr", "qnapDiskTemperature", "qnapDiskID"):
        assert qnap_metric in snmp_yml

    assert "  printer:\n" in snmp_yml
    for prt_metric in (
        "1.3.6.1.2.1.43",
        "prtMarkerSuppliesLevel",
        "prtMarkerSuppliesMaxCapacity",
        "prtMarkerSuppliesDescription",
        "prtAlertSeverityLevel",
        "prtAlertDescription",
        "prtMarkerLifeCount",
    ):
        assert prt_metric in snmp_yml

    # 5. Create & list silence scoped to device_role="snmp-printer"
    sil = run_action(
        "create-silence",
        "20create",
        {
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "snmp-printer",
            "starts_at": "2026-11-20T00:00:00Z",
            "ends_at": "2099-12-31T23:59:59Z",
            "created_by": "helpdesk@msp.example.com",
            "comment": "Toner cartridge replacement maintenance",
        },
    )
    sil_list = run_action("list-silences", "20read", {"customer": "acme-corp"})
    matched_sil = next(s for s in sil_list["silences"] if s["id"] == sil["silence_id"])
    assert {"name": "device_role", "value": "snmp-printer", "is_regex": False, "is_equal": True} in matched_sil[
        "matchers"
    ]

    # 6. Direct Python API validation rejects unsupported device_role
    from hub_alerting import ValidationFailure
    from hub_alerting.silences_manager import create_silence
    from hub_alerting.targets_manager import save_target

    with pytest.raises(ValidationFailure) as role_exc:
        save_target(
            {
                "name": "Invalid Role Target",
                "enabled": True,
                "target_type": "snmp",
                "customer": "acme-corp",
                "site": "hq",
                "device_role": "snmp-toaster",
                "endpoints": ["198.51.100.90"],
                "snmp_module": "printer",
            },
            state_dir=hub_env["state_dir"],
        )
    assert role_exc.value.field == "device_role"

    with pytest.raises(ValidationFailure) as sil_role_exc:
        create_silence(
            {
                "customer": "acme-corp",
                "device_role": "snmp-toaster",
                "starts_at": "2026-11-20T00:00:00Z",
                "ends_at": "2099-12-31T23:59:59Z",
                "created_by": "admin",
                "comment": "Invalid silence role test",
            },
            state_dir=hub_env["state_dir"],
        )
    assert sil_role_exc.value.field == "device_role"
