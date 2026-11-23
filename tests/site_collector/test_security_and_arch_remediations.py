"""Regression tests for Security (#24), E2E (#25), and Architecture (#26) remediations."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import jsonschema
import pytest

from tests.site_collector.conftest import COLLECTOR_ROOT, IMAGEROOT
from tests.site_collector.test_actions_and_ns8_rules import (
    _run_action_script,
    _write_fake_agent_module,
)


def test_crit02_test_hub_connection_blocks_stored_token_exfiltration_to_different_url(
    tmp_path: Path, load_schema
) -> None:
    """Stored bearer token must NEVER be sent when caller supplies a changed hub_url."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = tmp_path / "fake_agent"
    _write_fake_agent_module(agent_dir)

    secret_token = "cms_v1_ConfidentialStoredTenantBearerToken999999"
    captured_headers: list[str] = []

    class _AttackerServer(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            captured_headers.append(self.headers.get("Authorization", ""))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok","customer":"attacker"}')

    srv = HTTPServer(("127.0.0.1", 0), _AttackerServer)
    attacker_port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    try:
        cfg_res = _run_action_script(
            "actions/configure-module/20configure",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload={
                "hub_url": "https://legit-hub.msp.example.com",
                "auth_token": secret_token,
                "auth_token_unchanged": False,
                "customer": "acme-corp",
                "site": "hq",
            },
        )
        assert cfg_res.returncode == 0, cfg_res.stderr

        # Attempt to exfiltrate stored token by changing hub_url while passing auth_token=""
        exfil_res = _run_action_script(
            "actions/test-hub-connection/20test",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload={
                "hub_url": f"https://127.0.0.1:{attacker_port}",
                "auth_token": "",
                "tls_skip_verify": True,
            },
            extra_env={"HUB_PROBE_ALLOW_LOOPBACK": "1"},
        )
        assert exfil_res.returncode == 0
        exfil_out = json.loads(exfil_res.stdout)
        jsonschema.validate(exfil_out, load_schema("collector-test-hub-connection-output.json"))
        assert exfil_out["ok"] is False
        assert exfil_out["latency_ms"] == 0.0
        assert "modified Hub URL" in exfil_out["message"]
        assert captured_headers == [], "Attacker server must NEVER receive stored token!"
    finally:
        srv.shutdown()
        srv.server_close()


def test_crit02_ssrf_and_control_char_guards_in_hub_probe(
    load_schema, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collector_lib import hub_probe

    monkeypatch.delenv("HUB_PROBE_ALLOW_LOOPBACK", raising=False)
    schema = load_schema("collector-test-hub-connection-output.json")
    tok = "cms_v1_ValidTestToken12345678901234567890"

    for ssrf_url in (
        "https://127.0.0.1/api",
        "https://localhost:8443",
        "https://[::1]:8443",
        "https://169.254.169.254",
        "https://10.0.2.2:8080",
        "https://0x7f000001",
        "https://0177.0.0.1",
        "https://127.1",
    ):
        res = hub_probe.verify_hub_connection(hub_url=ssrf_url, auth_token=tok)
        assert res["ok"] is False, f"SSRF URL should be rejected: {ssrf_url}"
        assert res["http_status"] == 0
        jsonschema.validate(res, schema)

    # Control characters / CRLF header injection in auth_token must not crash with ValueError
    res_crlf = hub_probe.verify_hub_connection(
        hub_url="https://monitoring.msp.example.com",
        auth_token="cms_v1_BadToken\r\nX-Injected: pwned",
    )
    assert res_crlf["ok"] is False
    assert res_crlf["http_status"] == 0
    jsonschema.validate(res_crlf, schema)


def test_med02_regex_trailing_newline_and_secret_newline_rejection(state_dir: Path) -> None:
    from collector_lib.runtime import COLLECTOR_ID_RE, save_stored_auth_token

    assert COLLECTOR_ID_RE.match("acme-hq-collector1") is not None
    assert COLLECTOR_ID_RE.match("acme-hq-collector1\n") is None

    for bad_secret in (
        "cms_v1_evil\nINJECTED_VAR=1",
        "cms_v1_evil\rINJECTED=1",
        "cms_v1_evil\u2028INJECTED=1",
        "cms_v1_evil with space",
    ):
        with pytest.raises(ValueError):
            save_stored_auth_token(state_dir, bad_secret)


def test_med03_targets_store_rejects_loopback_and_link_local_hosts_and_locks(
    tmp_path: Path,
) -> None:
    from collector_lib.targets_store import TargetsStore

    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = tmp_path / "fake_agent"
    _write_fake_agent_module(agent_dir)

    store = TargetsStore(state_dir)
    for forbidden_host in (
        "127.0.0.1",
        "127.0.0.5",
        "localhost",
        "::1",
        "169.254.169.254",
        "10.0.2.2",
        "0x7f000001",
    ):
        with pytest.raises(ValueError):
            store.save_target(
                {
                    "name": "Bad Loopback Target",
                    "enabled": True,
                    "target_type": "linux",
                    "device_role": "linux",
                    "host": forbidden_host,
                }
            )

    # Action script must return NS8 validation error exit code 2 on loopback host
    res = _run_action_script(
        "actions/save-local-target/20save",
        state_dir=state_dir,
        agent_dir=agent_dir,
        stdin_payload={
            "name": "Alloy Internal Port Probe",
            "enabled": True,
            "target_type": "custom-exporter",
            "device_role": "linux",
            "host": "127.0.0.1",
            "port": 12345,
        },
    )
    assert res.returncode == 2
    errs = json.loads(res.stdout)
    assert errs[0]["field"] == "host"

    # Valid LAN target creates lockfile
    store.save_target(
        {
            "name": "Valid LAN Host",
            "enabled": True,
            "target_type": "linux",
            "device_role": "linux",
            "host": "192.168.20.15",
        }
    )
    assert (state_dir / ".local-targets.lock").is_file()


def test_arch15_arch16_systemd_specifiers_rootless_uid_and_agent_state_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collector_lib.runtime import get_state_dir

    # AGENT_STATE_DIR honored when COLLECTOR_STATE_DIR unset
    monkeypatch.delenv("COLLECTOR_STATE_DIR", raising=False)
    agent_sdir = tmp_path / "ns8_agent_state"
    monkeypatch.setenv("AGENT_STATE_DIR", str(agent_sdir))
    assert get_state_dir() == agent_sdir

    systemd_dir = IMAGEROOT / "systemd" / "user"
    for svc in systemd_dir.glob("*.service"):
        content = svc.read_text(encoding="utf-8")
        assert "%S/" not in content, f"{svc.name} must use %E/ (~/.config), never %S/ (~/.local/state)"

    pve_svc = (systemd_dir / "pve-exporter.service").read_text(encoding="utf-8")
    alloy_svc = (systemd_dir / "alloy.service").read_text(encoding="utf-8")
    assert "--user=0:0" in pve_svc or "--user 0:0" in pve_svc
    assert "--user=0:0" in alloy_svc or "--user 0:0" in alloy_svc
    assert "--group-add=keep-groups" in alloy_svc or "--group-add keep-groups" in alloy_svc


def test_arch18_snmp_auths_yml_includes_full_apcupsd_and_generic_metrics(
    state_dir: Path,
) -> None:
    from collector_lib.alloy_renderer import CollectorConfig, render_collector_artifacts

    cfg = CollectorConfig(
        configured=True,
        hub_url="https://monitoring.msp.example.com",
        auth_token="cms_v1_ValidTestToken12345678901234567890",
        customer="acme-corp",
        site="hq",
        collector_id="acme-hq-ns8",
    )
    res = render_collector_artifacts(state_dir, cfg, [])
    snmp_yml = res.snmp_auths_path.read_text(encoding="utf-8")

    for req_metric in (
        "name: upsBatteryStatus",
        "name: upsEstimatedChargeRemaining",
        "name: upsOutputSource",
        "name: upsOutputPercentLoad",
        "name: upsAdvOutputLoad",
        "name: upsAdvBatteryReplaceIndicator",
        "name: upsBasicOutputStatus",
        "name: sysUpTime",
        "name: ifOperStatus",
        "name: ifAdminStatus",
        "name: ifHCInOctets",
        "name: ifHCOutOctets",
    ):
        assert req_metric in snmp_yml, f"Missing SNMP metric definition in snmp-auths.yml: {req_metric}"


def test_arch14_collector_ui_cockpit_runtime_wiring() -> None:
    ui_root = COLLECTOR_ROOT / "ui"
    pkg = json.loads((ui_root / "package.json").read_text(encoding="utf-8"))
    assert "axios" in pkg["dependencies"]
    assert pkg["devDependencies"].get("vue-template-compiler") == "2.7.16"

    main_js = (ui_root / "src" / "main.js").read_text(encoding="utf-8")
    assert "Vue.prototype.axios = axios" in main_js

    app_vue = (ui_root / "src" / "App.vue").read_text(encoding="utf-8")
    assert "window.parent.location.hash" in app_vue

    for view_name in ("Status.vue", "LocalTargets.vue", "Settings.vue"):
        view_text = (ui_root / "src" / "views" / view_name).read_text(encoding="utf-8")
        assert "this.core.$root" in view_text, (
            f"{view_name} must register task listeners on this.core.$root when inside NS8 Cockpit"
        )

    targets_vue = (ui_root / "src" / "views" / "LocalTargets.vue").read_text(encoding="utf-8")
    assert "Array.isArray(validationErrors)" in targets_vue
    assert "item.snmp_v3" in targets_vue


def test_arch19b_snmp_v3_non_secret_metadata_round_trips_in_list_local_targets(
    state_dir: Path, load_schema
) -> None:
    from collector_lib.targets_store import TargetsStore

    store = TargetsStore(state_dir)
    store.save_target(
        {
            "name": "Synology RackStation",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-nas",
            "host": "192.168.30.40",
            "snmp_module": "synology",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "synomon",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "auth_password": "top-secret-auth-pw",
                "priv_protocol": "AES256",
                "priv_password": "top-secret-priv-pw",
            },
        }
    )

    items = store.list_public_targets(target_type="snmp")
    assert len(items) == 1
    item = items[0]
    assert item["has_snmp_secret"] is True
    assert item["snmp_v3"] == {
        "username": "synomon",
        "security_level": "authPriv",
        "auth_protocol": "SHA256",
        "priv_protocol": "AES256",
    }
    assert "auth_password" not in item["snmp_v3"]
    assert "priv_password" not in item["snmp_v3"]
    jsonschema.validate(
        {"targets": items}, load_schema("collector-list-local-targets-output.json")
    )


def test_rocky9_python39_ast_tokenize_and_selinux_mount_safety() -> None:
    """Ensure all collector and test Python files parse cleanly under Python 3.9 rules and use safe SELinux :z mounts."""
    import ast
    import io
    import tokenize

    tests_root = Path(__file__).resolve().parent
    py_files: list[Path] = []
    for scan_root in (COLLECTOR_ROOT, tests_root):
        for p in sorted(scan_root.rglob("*")):
            if not p.is_file() or "node_modules" in p.parts or "__pycache__" in p.parts or "dist" in p.parts:
                continue
            if p.suffix == ".py" or (p.suffix == "" and p.read_bytes().startswith(b"#!/usr/bin/env python")):
                py_files.append(p)

    assert len(py_files) >= 30
    for path in py_files:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(path), feature_version=(3, 9))
        has_future_ann = any(
            isinstance(n, ast.ImportFrom)
            and n.module == "__future__"
            and any(a.name == "annotations" for a in n.names)
            for n in tree.body[:5]
        )
        assert has_future_ann, f"{path} missing 'from __future__ import annotations' for Python 3.9"

        # Forbid Python 3.10+ runtime keyword args (dataclass slots/kw_only, zip strict, Path.write_text newline)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn_name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
                )
                for kw in node.keywords:
                    assert kw.arg not in ("slots", "kw_only", "match_args", "strict"), (
                        f"{path}:{node.lineno} uses Python 3.10+ keyword '{kw.arg}=' in {fn_name}()"
                    )
                    if fn_name == "write_text":
                        assert kw.arg != "newline", (
                            f"{path}:{node.lineno} uses Python 3.10+ Path.write_text(..., newline=...)"
                        )

        # Forbid PEP 701 nested f-strings, backslashes inside {...}, or quote reuse inside {...}
        fstack: list[dict[str, object]] = []
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            tname = tokenize.tok_name[tok.type]
            if tname == "FSTRING_START":
                assert not fstack, f"{path}:{tok.start[0]} uses nested f-string (Python 3.12+ only)"
                fstack.append({"quote": tok.string.lstrip("fFrR"), "expr": 0})
            elif tname == "FSTRING_END":
                fstack.pop()
            elif fstack:
                top = fstack[-1]
                if tok.string == "{":
                    top["expr"] = int(top["expr"]) + 1
                elif tok.string == "}":
                    top["expr"] = max(0, int(top["expr"]) - 1)
                elif int(top["expr"]) > 0:
                    assert "\\" not in tok.string, (
                        f"{path}:{tok.start[0]} uses backslash inside f-string expression"
                    )
                    q = str(top["quote"])
                    if q in ('"', "'"):
                        assert q not in tok.string, (
                            f"{path}:{tok.start[0]} reuses outer f-string quote inside expression"
                        )

    # SELinux mount safety: module state mounts use lowercase :z / :ro,z; host /proc,/sys,/,/var/log/journal never relabeled
    systemd_dir = IMAGEROOT / "systemd" / "user"
    for svc in systemd_dir.glob("*.service"):
        svc_text = svc.read_text(encoding="utf-8")
        assert ":Z" not in svc_text and ",Z" not in svc_text, (
            f"{svc.name} must use shared lowercase :z / :ro,z instead of exclusive :Z"
        )
        for sys_mount in ("/proc:/host/proc:ro", "/sys:/host/sys:ro", "/:/host/root:ro", "/var/log/journal:/var/log/journal:ro"):
            if sys_mount.split(":")[0] + ":" in svc_text:
                assert f"{sys_mount}," not in svc_text and f"{sys_mount}:z" not in svc_text


def test_live_ns8_01_and_03_directory_mounts_volumes_label_and_envfile_guards(
    tmp_path: Path,
) -> None:
    """Verify LIVE-NS8-01 directory bind mounts for live reload and LIVE-NS8-03 volumes/envfile guards."""
    from collector_lib.alloy_renderer import CollectorConfig, render_collector_artifacts

    # 1. LIVE-NS8-01: systemd units mount directories (never single files) so os.replace() updates live containers
    alloy_svc = (IMAGEROOT / "systemd" / "user" / "alloy.service").read_text(encoding="utf-8")
    assert "%E/state/alloy-conf" in alloy_svc
    assert "-v %E/state/alloy-conf:/etc/alloy/conf:ro,z" in alloy_svc
    assert "/etc/alloy/conf/config.alloy" in alloy_svc
    assert "%E/state/config.alloy:" not in alloy_svc

    pve_svc = (IMAGEROOT / "systemd" / "user" / "pve-exporter.service").read_text(encoding="utf-8")
    assert "%E/state/pve-conf" in pve_svc
    assert "-v %E/state/pve-conf:/etc/prometheus:ro,z" in pve_svc
    assert "--config.file=/etc/prometheus/pve.yml" in pve_svc
    assert "%E/state/pve.yml:" not in pve_svc

    # Verify render_collector_artifacts keeps alloy-conf/config.alloy & pve-conf/pve.yml in sync across updates
    state_dir = tmp_path / "state"
    cfg = CollectorConfig(
        configured=True,
        hub_url="https://monitoring.msp.example.com",
        auth_token="cms_v1_LiveMountSyncToken1234567890123456789",
        customer="acme-corp",
        site="dc1",
        collector_id="acme-corp-dc1-ns8",
    )
    render_collector_artifacts(state_dir, cfg, [])
    assert (state_dir / "alloy-conf" / "config.alloy").read_text(encoding="utf-8") == (
        state_dir / "config.alloy"
    ).read_text(encoding="utf-8")
    assert (state_dir / "pve-conf" / "pve.yml").read_text(encoding="utf-8") == (
        state_dir / "pve.yml"
    ).read_text(encoding="utf-8")

    updated_targets = [
        {
            "id": "pve-01",
            "name": "PVE Node 01",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "192.168.10.20",
            "port": 8006,
            "scrape_interval": "60s",
            "pve_token_id": "mon@pve!alloy",
            "pve_token_secret": "secret-pve-tok",
            "tls_skip_verify": True,
        }
    ]
    render_collector_artifacts(state_dir, cfg, updated_targets)
    alloy_mounted = (state_dir / "alloy-conf" / "config.alloy").read_text(encoding="utf-8")
    pve_mounted = (state_dir / "pve-conf" / "pve.yml").read_text(encoding="utf-8")
    assert "192.168.10.20" in alloy_mounted
    assert alloy_mounted == (state_dir / "config.alloy").read_text(encoding="utf-8")
    assert "secret-pve-tok" in pve_mounted
    assert pve_mounted == (state_dir / "pve.yml").read_text(encoding="utf-8")

    # 2. LIVE-NS8-03: Containerfile drops unused alloy-wal-data volume
    cf_text = (COLLECTOR_ROOT / "Containerfile").read_text(encoding="utf-8")
    assert "alloy-wal-data" not in cf_text
    assert 'org.nethserver.volumes=""' in cf_text

    # 3. LIVE-NS8-03: restore-module & clone-module guard missing state/environment safely
    empty_state = tmp_path / "empty_state"
    empty_state.mkdir(parents=True, exist_ok=True)
    strict_agent = tmp_path / "strict_agent"
    strict_agent.mkdir(parents=True, exist_ok=True)
    (strict_agent / "agent.py").write_bytes(
        (
            "from __future__ import annotations\n"
            "import os\n"
            "from pathlib import Path\n"
            "_MEM = {}\n"
            "def read_envfile(path: str) -> dict[str, str]:\n"
            "    assert isinstance(path, str), f'Expected str path, got {type(path)}'\n"
            "    p = Path(path)\n"
            "    if not p.is_file():\n"
            "        raise FileNotFoundError(path)\n"
            "    out = {}\n"
            "    for ln in p.read_text(encoding='utf-8').splitlines():\n"
            "        if '=' in ln and not ln.startswith('#'):\n"
            "            k, v = ln.split('=', 1)\n"
            "            out[k.strip()] = v.strip()\n"
            "    return out\n"
            "def set_env(key: str, val: str) -> None:\n"
            "    _MEM[str(key)] = str(val)\n"
            "def dump_env() -> None:\n"
            "    p = Path(os.environ['COLLECTOR_STATE_DIR']) / 'environment'\n"
            "    existing = read_envfile(str(p)) if p.is_file() else {}\n"
            "    existing.update(_MEM)\n"
            "    p.write_bytes(('\\n'.join(f'{k}={v}' for k, v in sorted(existing.items())) + '\\n').encode('utf-8'))\n"
            "def run_helper(*args: str) -> None:\n"
            "    return None\n"
        ).encode("utf-8")
    )

    for rel_script in (
        "actions/restore-module/06copyenv",
        "actions/restore-module/50configure",
        "actions/clone-module/50configure",
    ):
        # Delete environment before each call so missing-file guard is exercised directly
        env_f = empty_state / "environment"
        if env_f.exists():
            env_f.unlink()
        res = _run_action_script(
            rel_script,
            state_dir=empty_state,
            agent_dir=strict_agent,
            stdin_payload={} if "06copyenv" in rel_script else None,
        )
        assert res.returncode == 0, f"{rel_script} failed on missing state/environment: {res.stderr}"
