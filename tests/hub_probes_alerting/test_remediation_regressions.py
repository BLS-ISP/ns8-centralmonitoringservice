from __future__ import annotations

import json
from pathlib import Path
import sys
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
    (sdir / "smarthost.env").write_bytes(
        b"SMARTHOST_ENABLED=true\n"
        b"SMARTHOST_HOST=smtp.relay.example.com\n"
        b"SMARTHOST_PORT=587\n"
        b"SMARTHOST_ENCRYPT_SMTP=starttls\n"
        b"ENCRYPT_SMTP=starttls\n"
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


def test_python39_strict_syntax_and_runtime_compatibility() -> None:
    """Enforce Rocky Linux 9 (/usr/bin/python3 = Python 3.9) syntax & runtime compatibility across all owned files."""
    import ast
    from tests.hub_probes_alerting.conftest import ACTIONS_DIR, PYPKG_DIR, REPO_ROOT
    from tests.hub_probes_alerting.test_silences_and_schemas import OWNED_ACTIONS

    runtime_files: list[Path] = sorted(
        [p for p in (PYPKG_DIR / "hub_alerting").rglob("*.py")]
        + [
            p
            for action in OWNED_ACTIONS
            for p in (ACTIONS_DIR / action).iterdir()
            if p.is_file() and not p.name.endswith(".json")
        ]
    )
    assert len(runtime_files) == 17
    test_files: list[Path] = sorted(
        p for p in (REPO_ROOT / "tests" / "hub_probes_alerting").rglob("*.py") if p.stat().st_size > 0
    )
    target_files = runtime_files + test_files

    forbidden_py310_attrs = {
        ("datetime", "UTC"),
        ("typing", "Self"),
        ("typing", "TypeAlias"),
        ("typing", "Never"),
        ("typing", "Required"),
        ("typing", "NotRequired"),
    }

    violations: list[str] = []
    for fpath in target_files:
        src = fpath.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src, filename=str(fpath), feature_version=(3, 9))
        except SyntaxError as exc:
            violations.append(f"{fpath}:{exc.lineno}: Python 3.9 SyntaxError: {exc.msg}")
            continue

        has_future_annotations = any(
            isinstance(stmt, ast.ImportFrom)
            and stmt.module == "__future__"
            and any(alias.name == "annotations" for alias in stmt.names)
            for stmt in tree.body
            if isinstance(stmt, (ast.ImportFrom, ast.Expr))
        )
        if not has_future_annotations:
            violations.append(f"{fpath}: missing 'from __future__ import annotations'")

        # Collect annotation node IDs so we also catch unannotated runtime `X = A | B` unions
        ann_node_ids: set[int] = set()
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if n.returns:
                    ann_node_ids.update(id(x) for x in ast.walk(n.returns))
                all_args = (
                    list(n.args.posonlyargs)
                    + list(n.args.args)
                    + list(n.args.kwonlyargs)
                    + ([n.args.vararg] if n.args.vararg else [])
                    + ([n.args.kwarg] if n.args.kwarg else [])
                )
                for arg in all_args:
                    if arg.annotation:
                        ann_node_ids.update(id(x) for x in ast.walk(arg.annotation))
            elif isinstance(n, ast.AnnAssign) and n.annotation:
                ann_node_ids.update(id(x) for x in ast.walk(n.annotation))

        for node in ast.walk(tree):
            # 1. No Python 3.10+ match/case or Python 3.11+ except* or Python 3.12+ type params
            if hasattr(ast, "Match") and isinstance(node, ast.Match):
                violations.append(f"{fpath}:{node.lineno}: Python 3.10+ match/case statement")
            if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
                violations.append(f"{fpath}:{node.lineno}: Python 3.11+ except* statement")
            if getattr(node, "type_params", None):
                violations.append(f"{fpath}:{node.lineno}: Python 3.12+ PEP 695 type_params")

            # 2. No isinstance(x, A | B) / issubclass(x, A | B), zip(strict=...), or fromisoformat in runtime pkg
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"isinstance", "issubclass"}:
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.BinOp) and isinstance(
                        node.args[1].op, ast.BitOr
                    ):
                        violations.append(f"{fpath}:{node.lineno}: runtime union in {node.func.id}()")
                if isinstance(node.func, ast.Name) and node.func.id == "zip":
                    if any(kw.arg == "strict" for kw in node.keywords):
                        violations.append(f"{fpath}:{node.lineno}: Python 3.10+ zip(strict=...)")
                if (
                    fpath in runtime_files
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "fromisoformat"
                ):
                    violations.append(f"{fpath}:{node.lineno}: avoid datetime.fromisoformat (Python 3.9 Z/nano trap)")
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "write_text"
                    and any(kw.arg == "newline" for kw in node.keywords)
                ):
                    violations.append(f"{fpath}:{node.lineno}: Python 3.10+ Path.write_text(newline=...)")

            # 3. No Python 3.11+ tomllib or forbidden typing/datetime attributes
            if isinstance(node, ast.Import) and any(a.name == "tomllib" for a in node.names):
                violations.append(f"{fpath}:{node.lineno}: Python 3.11+ tomllib import")
            if isinstance(node, ast.ImportFrom) and node.module in {"datetime", "typing"}:
                for alias in node.names:
                    if (node.module, alias.name) in forbidden_py310_attrs:
                        violations.append(f"{fpath}:{node.lineno}: Python 3.10+ {node.module}.{alias.name}")
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if (node.value.id, node.attr) in forbidden_py310_attrs:
                    violations.append(f"{fpath}:{node.lineno}: Python 3.10+ {node.value.id}.{node.attr}")

            # 4. No PEP 701 (Python 3.12+) f-string constructs (on Python < 3.12, ast.parse already rejects PEP 701 natively
            #    and FormattedValue shares the outer JoinedStr source span rather than the {...} slice)
            if sys.version_info >= (3, 12) and isinstance(node, ast.JoinedStr):
                jseg = ast.get_source_segment(src, node) or ""
                stripped = jseg.lstrip("fFrR")
                is_triple = stripped.startswith(('"""', "'''"))
                outer_quote = stripped[:3] if is_triple else stripped[:1]
                for val in node.values:
                    if isinstance(val, ast.FormattedValue):
                        vseg = ast.get_source_segment(src, val) or ""
                        if "\\" in vseg:
                            violations.append(f"{fpath}:{val.lineno}: PEP 701 backslash in f-string {vseg}")
                        if not is_triple and "\n" in vseg:
                            violations.append(f"{fpath}:{val.lineno}: PEP 701 newline in f-string {vseg}")
                        if "#" in vseg:
                            violations.append(f"{fpath}:{val.lineno}: PEP 701 comment in f-string {vseg}")
                        for sub in ast.walk(val):
                            if sub is not val and isinstance(sub, ast.JoinedStr):
                                violations.append(f"{fpath}:{val.lineno}: nested f-string {jseg}")
                        inner_expr = vseg[1:-1]
                        if outer_quote and outer_quote in inner_expr:
                            violations.append(
                                f"{fpath}:{val.lineno}: PEP 701 quote reuse ({outer_quote}) in f-string {jseg}"
                            )

    assert not violations, "Python 3.9 compatibility violations:\n" + "\n".join(violations)


@pytest.mark.parametrize(
    "rfc3339_sample",
    [
        "2026-11-23T10:15:30Z",
        "2026-11-23t10:15:30z",
        "2026-11-23T10:15:30.4Z",
        "2026-11-23T10:15:30.42Z",
        "2026-11-23T10:15:30.123Z",
        "2026-11-23T10:15:30.123456789Z",
        "2026-11-23T11:15:30.123456789+01:00",
        "2026-11-23T05:15:30-0500",
    ],
)
def test_python39_rfc3339_parser_handles_go_nanoseconds_and_offsets_without_py311_fromisoformat(
    rfc3339_sample: str,
) -> None:
    from hub_alerting.silences_manager import _parse_rfc3339

    parsed = _parse_rfc3339(rfc3339_sample, "starts_at")
    assert parsed.year == 2026
    assert parsed.hour == 10
    assert parsed.minute == 15
    assert parsed.second == 30


def test_live_ns8_02_render_all_probe_configs_overwrites_stub_and_restores_targets_and_rules(
    hub_env: dict[str, Any],
) -> None:
    from hub_alerting import render_all_probe_configs as pkg_render_all
    from hub_alerting.alertmanager_config import render_all_probe_configs

    state_dir: Path = hub_env["state_dir"]
    config_dir: Path = hub_env["config_dir"]
    run_action = hub_env["run_action"]

    # Save a target and custom rule-pack subset into state_dir
    saved = run_action(
        "save-target",
        "20save",
        {
            "name": "Restored Blackbox Probe",
            "enabled": True,
            "target_type": "blackbox",
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "web",
            "endpoints": ["https://app.acme.example.com"],
            "blackbox_module": "http_post_2xx",
            "tls_skip_verify": True,
        },
    )
    run_action(
        "configure-alerting",
        "20configure",
        {
            "smarthost_email": {
                "enabled": False,
                "use_ns8_smarthost": True,
                "from_address": "alerts@msp.example.com",
                "default_to_addresses": [],
            },
            "webhook_psa": {"enabled": False, "url": ""},
            "chat": {"teams_enabled": False, "slack_enabled": False},
            "push": {"enabled": False, "provider": "none"},
            "customer_email_routing": {"enabled": False, "min_severity": "critical"},
            "enabled_rule_packs": ["ns8-cluster", "snmp-network-ups"],
        },
    )

    # Simulate Restic restore / create-module state: wipe rendered config_dir and write a 2-module stub blackbox.yml
    import shutil

    shutil.rmtree(config_dir)
    stub_bb = config_dir / "blackbox" / "blackbox.yml"
    stub_bb.parent.mkdir(parents=True, exist_ok=True)
    stub_bb.write_bytes(b"modules:\n  http_2xx:\n    prober: http\n  tcp_connect:\n    prober: tcp\n")

    summary = render_all_probe_configs(state_dir)
    assert pkg_render_all is not None
    assert summary["targets_synced"] == 1

    # 1. Stub blackbox.yml must be replaced with full 8-module config
    bb_text = stub_bb.read_text(encoding="utf-8")
    for mod in (
        "http_2xx:",
        "http_2xx_insecure:",
        "http_post_2xx:",
        "http_post_2xx_insecure:",
        "tcp_connect:",
        "dns_tcp:",
        "dns_udp:",
        "icmp:",
    ):
        assert mod in bb_text

    # 2. Restored file_sd, federation_jobs.yml, and snmp.yml must exist
    restored_sd = config_dir / "prometheus" / "file_sd" / "blackbox" / f"{saved['id']}.json"
    assert restored_sd.is_file()
    assert (config_dir / "prometheus" / "federation_jobs.yml").is_file()
    assert (config_dir / "snmp" / "snmp.yml").is_file()

    # 3. Restored rule packs from state/alerting.json must be materialized
    deployed_rules = sorted(p.name for p in (config_dir / "prometheus" / "rules").glob("*.yml"))
    assert deployed_rules == ["ns8-cluster.yml", "snmp-network-ups.yml"]
