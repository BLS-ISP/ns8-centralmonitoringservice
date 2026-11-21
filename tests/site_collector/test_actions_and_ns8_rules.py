"""Integration, schema, and NS8 Backend Rule tests for collector/imageroot and Containerfile."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from tests.site_collector.conftest import COLLECTOR_ROOT, IMAGEROOT, REPO_ROOT, SCHEMAS_DIR

ACTION_SCHEMA_PAIRS = [
    ("configure-module", "input", "collector-configure-module-input.json"),
    ("configure-module", "output", "collector-configure-module-output.json"),
    ("get-configuration", "input", "collector-get-configuration-input.json"),
    ("get-configuration", "output", "collector-get-configuration-output.json"),
    ("list-local-targets", "input", "collector-list-local-targets-input.json"),
    ("list-local-targets", "output", "collector-list-local-targets-output.json"),
    ("save-local-target", "input", "collector-save-local-target-input.json"),
    ("save-local-target", "output", "collector-save-local-target-output.json"),
    ("delete-local-target", "input", "collector-delete-local-target-input.json"),
    ("delete-local-target", "output", "collector-delete-local-target-output.json"),
    ("test-hub-connection", "input", "collector-test-hub-connection-input.json"),
    ("test-hub-connection", "output", "collector-test-hub-connection-output.json"),
]


def _write_fake_agent_module(agent_dir: Path) -> None:
    """Create a realistic NS8 `agent` Python module stub recording set_env/dump_env ordering."""
    code = '''"""Fake NS8 agent module for isolated action testing."""
from __future__ import annotations
import os
from pathlib import Path

_PENDING_ENV: dict[str, str] = {}


def _state_dir() -> Path:
    override = os.environ.get("COLLECTOR_STATE_DIR", "").strip()
    p = Path(override) if override else (Path.home() / ".config" / "state")
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_envfile(path: str | Path) -> dict[str, str]:
    p = Path(path)
    if not p.is_file():
        return {}
    result: dict[str, str] = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"')
    return result


def set_env(key: str, value: str) -> None:
    _PENDING_ENV[str(key)] = str(value)
    os.environ[str(key)] = str(value)


def dump_env() -> None:
    env_path = _state_dir() / "environment"
    current = read_envfile(env_path)
    current.update(_PENDING_ENV)
    lines = [f"{k}={v}" for k, v in sorted(current.items())]
    with open(env_path, "w", encoding="utf-8", newline="\\n") as fh:
        fh.write("\\n".join(lines) + "\\n")
    marker = _state_dir() / ".dump_env_called"
    count = int(marker.read_text(encoding="utf-8").strip()) if marker.is_file() else 0
    with open(marker, "w", encoding="utf-8", newline="\\n") as mfh:
        mfh.write(f"{count + 1}\\n")


def set_status(status: str) -> None:
    with open(_state_dir() / ".agent_status", "w", encoding="utf-8", newline="\\n") as fh:
        fh.write(f"{status}\\n")


def run_helper(*cmd, **kwargs):
    log_path = _state_dir() / ".helper_calls.log"
    with open(log_path, "a", encoding="utf-8", newline="\\n") as fh:
        fh.write(" ".join(str(c) for c in cmd) + "\\n")
    class _Res:
        returncode = 0
    return _Res()
'''
    agent_dir.mkdir(parents=True, exist_ok=True)
    with open(agent_dir / "agent.py", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(code)


def _run_action_script(
    script_rel: str,
    *,
    state_dir: Path,
    agent_dir: Path,
    stdin_payload: dict[str, Any] | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    script_path = IMAGEROOT / script_rel
    assert script_path.is_file(), f"Missing action script: {script_path}"

    env = dict(os.environ)
    # Merge persisted state/environment just like NS8's agent action runner
    env_file = state_dir / "environment"
    if env_file.is_file():
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" in raw_line and not raw_line.startswith("#"):
                k, v = raw_line.split("=", 1)
                env[k.strip()] = v.strip()

    env["COLLECTOR_STATE_DIR"] = str(state_dir)
    env.setdefault("MODULE_ID", "central-monitoring-collector1")
    py_paths = [str(agent_dir), str(IMAGEROOT / "pypkg")]
    if env.get("PYTHONPATH"):
        py_paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(py_paths)

    if extra_env:
        env.update(extra_env)

    stdin_text = json.dumps(stdin_payload) if stdin_payload is not None else "{}"
    return subprocess.run(
        [sys.executable, str(script_path)],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
        check=False,
    )


def test_all_12_action_schemas_match_shared_schemas_byte_for_byte() -> None:
    for action_name, direction, shared_name in ACTION_SCHEMA_PAIRS:
        action_schema_path = IMAGEROOT / "actions" / action_name / f"validate-{direction}.json"
        shared_schema_path = SCHEMAS_DIR / shared_name
        assert action_schema_path.is_file(), f"Missing {action_schema_path}"
        action_bytes = action_schema_path.read_bytes()
        shared_bytes = shared_schema_path.read_bytes()
        assert b"\r\n" not in action_bytes
        assert action_bytes == shared_bytes, (
            f"{action_schema_path} is not byte-for-byte identical to {shared_schema_path}"
        )


def test_full_module_lifecycle_actions_reload_restore_and_clone(
    tmp_path: Path, load_schema
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = tmp_path / "fake_agent"
    _write_fake_agent_module(agent_dir)

    # Start a local mock Alloy HTTP server to verify /-/reload and /-/healthy
    reload_hits: list[str] = []

    class _AlloyMockHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/-/healthy":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"All Alloy components are healthy.\n")
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/-/reload":
                reload_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"config reloaded\n")
            else:
                self.send_response(404)
                self.end_headers()

    alloy_server = HTTPServer(("127.0.0.1", 0), _AlloyMockHandler)
    alloy_port = alloy_server.server_address[1]
    threading.Thread(target=alloy_server.serve_forever, daemon=True).start()
    alloy_env = {
        "ALLOY_RELOAD_URL": f"http://127.0.0.1:{alloy_port}/-/reload",
        "ALLOY_HEALTH_URL": f"http://127.0.0.1:{alloy_port}/-/healthy",
    }

    try:
        # 1. create-module/20initialize
        init_res = _run_action_script(
            "actions/create-module/20initialize",
            state_dir=state_dir,
            agent_dir=agent_dir,
            extra_env=alloy_env,
        )
        assert init_res.returncode == 0, init_res.stderr
        assert (state_dir / ".dump_env_called").is_file()

        # 2. get-configuration before configure-module
        get_unconf = _run_action_script(
            "actions/get-configuration/20read",
            state_dir=state_dir,
            agent_dir=agent_dir,
            extra_env=alloy_env,
        )
        assert get_unconf.returncode == 0, get_unconf.stderr
        unconf_data = json.loads(get_unconf.stdout)
        jsonschema.validate(unconf_data, load_schema("collector-get-configuration-output.json"))
        assert unconf_data["configured"] is False
        assert unconf_data["has_auth_token"] is False
        assert unconf_data["health"]["alloy_status"] == "disabled"
        assert unconf_data["health"]["pve_exporter_status"] == "disabled"

        # 3. configure-module/20configure + 80start_services
        token = "cms_v1_ActionTestSecretBearerToken9876543210abcd"
        cfg_in = {
            "hub_url": "https://monitoring.msp.example.com",
            "auth_token": token,
            "auth_token_unchanged": False,
            "customer": "acme-corp",
            "site": "hq",
            "collector_id": "",
            "collect_local_ns8": True,
            "enable_syslog_receiver": True,
            "syslog_port": 5514,
            "wal_max_disk_mb": 2048,
            "tls_skip_verify": False,
        }
        jsonschema.validate(cfg_in, load_schema("collector-configure-module-input.json"))

        cfg_res = _run_action_script(
            "actions/configure-module/20configure",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload=cfg_in,
            extra_env=alloy_env,
        )
        assert cfg_res.returncode == 0, cfg_res.stderr
        cfg_out = json.loads(cfg_res.stdout)
        jsonschema.validate(cfg_out, load_schema("collector-configure-module-output.json"))
        original_collector_id = cfg_out["collector_id"]

        start_res = _run_action_script(
            "actions/configure-module/80start_services",
            state_dir=state_dir,
            agent_dir=agent_dir,
            extra_env=alloy_env,
        )
        assert start_res.returncode == 0, start_res.stderr
        assert (state_dir / "textfile" / "ns8.prom").is_file()

        # Simulate 4 KiB WAL segment file and verify get-configuration redacts token
        (state_dir / "alloy-wal" / "000001").write_bytes(b"x" * 4096)
        get_conf = _run_action_script(
            "actions/get-configuration/20read",
            state_dir=state_dir,
            agent_dir=agent_dir,
            extra_env=alloy_env,
        )
        assert get_conf.returncode == 0, get_conf.stderr
        assert token not in get_conf.stdout
        conf_data = json.loads(get_conf.stdout)
        jsonschema.validate(conf_data, load_schema("collector-get-configuration-output.json"))
        assert conf_data["configured"] is True
        assert conf_data["has_auth_token"] is True
        assert conf_data["auth_token_prefix"].startswith("cms_v1_")
        assert conf_data["health"]["alloy_status"] == "healthy"
        assert conf_data["health"]["wal_usage_bytes"] == 4096

        # 4. configure-module with auth_token_unchanged=True keeps stored token
        cfg_unchanged = dict(cfg_in)
        cfg_unchanged["auth_token"] = ""
        cfg_unchanged["auth_token_unchanged"] = True
        cfg_unchanged["enable_syslog_receiver"] = False
        cfg_res2 = _run_action_script(
            "actions/configure-module/20configure",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload=cfg_unchanged,
            extra_env=alloy_env,
        )
        assert cfg_res2.returncode == 0, cfg_res2.stderr
        assert (state_dir / "secrets" / "hub.token").read_text(encoding="utf-8") == token

        # 5. save-local-target triggers live HTTP POST /-/reload
        save_in = {
            "name": "PVE Hypervisor 01",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "192.168.50.10",
            "port": 8006,
            "scrape_interval": "60s",
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "pve-secret-xyz",
            "tls_skip_verify": True,
        }
        jsonschema.validate(save_in, load_schema("collector-save-local-target-input.json"))
        save_res = _run_action_script(
            "actions/save-local-target/20save",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload=save_in,
            extra_env=alloy_env,
        )
        assert save_res.returncode == 0, save_res.stderr
        save_out = json.loads(save_res.stdout)
        jsonschema.validate(save_out, load_schema("collector-save-local-target-output.json"))
        assert len(reload_hits) == 1

        # 6. list-local-targets redacts pve_token_secret
        list_res = _run_action_script(
            "actions/list-local-targets/20read",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload={"target_type": "proxmox"},
            extra_env=alloy_env,
        )
        assert list_res.returncode == 0, list_res.stderr
        assert "pve-secret-xyz" not in list_res.stdout
        list_out = json.loads(list_res.stdout)
        jsonschema.validate(list_out, load_schema("collector-list-local-targets-output.json"))
        assert len(list_out["targets"]) == 1

        # 7. delete-local-target triggers live HTTP POST /-/reload
        del_res = _run_action_script(
            "actions/delete-local-target/20delete",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload={"id": save_out["id"]},
            extra_env=alloy_env,
        )
        assert del_res.returncode == 0, del_res.stderr
        del_out = json.loads(del_res.stdout)
        jsonschema.validate(del_out, load_schema("collector-delete-local-target-output.json"))
        assert del_out["deleted"] is True
        assert len(reload_hits) == 2

        # 8. test-hub-connection falls back to stored token ONLY when hub_url matches saved HUB_URL
        probe_res = _run_action_script(
            "actions/test-hub-connection/20test",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload={"hub_url": "https://monitoring.msp.example.com", "auth_token": "", "tls_skip_verify": True},
            extra_env={**alloy_env, "HUB_PROBE_TIMEOUT_SECONDS": "0.5"},
        )
        assert probe_res.returncode == 0, probe_res.stderr
        probe_out = json.loads(probe_res.stdout)
        jsonschema.validate(probe_out, load_schema("collector-test-hub-connection-output.json"))
        assert "No bearer token" not in probe_out["message"]
        assert "modified Hub URL" not in probe_out["message"]

        # 9. restore-module/06copyenv + 50configure restores hub.token from secrets.env
        (state_dir / "secrets" / "hub.token").unlink()
        rest06 = _run_action_script(
            "actions/restore-module/06copyenv",
            state_dir=state_dir,
            agent_dir=agent_dir,
            stdin_payload={"environment": {"CUSTOMER": "acme-corp", "SITE": "hq", "CONFIGURED": "1", "HUB_URL": "https://monitoring.msp.example.com", "COLLECTOR_ID": original_collector_id}},
            extra_env=alloy_env,
        )
        assert rest06.returncode == 0, rest06.stderr
        rest50 = _run_action_script(
            "actions/restore-module/50configure",
            state_dir=state_dir,
            agent_dir=agent_dir,
            extra_env=alloy_env,
        )
        assert rest50.returncode == 0, rest50.stderr
        assert (state_dir / "secrets" / "hub.token").read_text(encoding="utf-8") == token

        # 10. clone-module/50configure mints a unique non-colliding collector_id!
        clone_res = _run_action_script(
            "actions/clone-module/50configure",
            state_dir=state_dir,
            agent_dir=agent_dir,
            extra_env={**alloy_env, "MODULE_ID": "central-monitoring-collector2"},
        )
        assert clone_res.returncode == 0, clone_res.stderr
        env_after_clone = (state_dir / "environment").read_text(encoding="utf-8")
        m_cid = re.search(r"^COLLECTOR_ID=(.+)$", env_after_clone, flags=re.MULTILINE)
        assert m_cid is not None
        cloned_collector_id = m_cid.group(1).strip()
        assert cloned_collector_id != original_collector_id
        assert cloned_collector_id in (state_dir / "config.alloy").read_text(encoding="utf-8")

        # 11. destroy-module/20destroy
        destroy_res = _run_action_script(
            "actions/destroy-module/20destroy",
            state_dir=state_dir,
            agent_dir=agent_dir,
            extra_env=alloy_env,
        )
        assert destroy_res.returncode == 0, destroy_res.stderr
    finally:
        alloy_server.shutdown()
        alloy_server.server_close()


def test_ns8_backend_8_rules_and_containerfile_compliance() -> None:
    # Rule 1: NEVER override get-status
    assert not (IMAGEROOT / "actions" / "get-status").exists()

    # Rule 2: Every Python file calling set_env must also call dump_env
    checked_py = 0
    for path in IMAGEROOT.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".py" or text.startswith("#!/usr/bin/env python"):
            checked_py += 1
            tree = ast.parse(text, filename=str(path))
            attrs = {
                node.func.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            }
            if "set_env" in attrs:
                assert "dump_env" in attrs, f"{path} calls set_env() without dump_env()"
    assert checked_py >= 10

    # Rules 3, 5, 6: Systemd units
    systemd_dir = IMAGEROOT / "systemd" / "user"
    expected_units = {
        "central-monitoring-collector.service",
        "alloy.service",
        "pve-exporter.service",
        "ns8-collector-textfile.service",
        "ns8-collector-textfile.timer",
    }
    assert expected_units.issubset({p.name for p in systemd_dir.iterdir()})

    for svc in systemd_dir.glob("*.service"):
        svc_text = svc.read_text(encoding="utf-8")
        assert "--pull=always" not in svc_text
        assert not re.search(r"(?:--publish|-p)\s+[^\s]*12345", svc_text), (
            f"{svc} must never publish internal Alloy port 12345 to host"
        )
        if "podman run" in svc_text:
            assert "--pull=missing" in svc_text
            assert "--restart=on-failure" in svc_text

    alloy_svc = (systemd_dir / "alloy.service").read_text(encoding="utf-8")
    assert "9221" in alloy_svc, "alloy.service must include readiness check for pve-exporter (:9221)"
    assert "--server.http.listen-addr=127.0.0.1:12345" in alloy_svc
    for ro_mount in (
        "/proc:/host/proc:ro",
        "/sys:/host/sys:ro",
        "/:/host/root:ro",
        "/var/log/journal:/var/log/journal:ro",
    ):
        assert ro_mount in alloy_svc

    # Rule 7: Restic state-include.conf + backup/restore/clone hooks
    state_inc = (IMAGEROOT / "etc" / "state-include.conf").read_text(encoding="utf-8")
    for req_entry in ("state/environment", "state/secrets.env", "state/local-targets.json"):
        assert req_entry in state_inc
    assert "alloy-wal" not in [
        ln.strip() for ln in state_inc.splitlines() if not ln.strip().startswith("#")
    ]
    assert (IMAGEROOT / "bin" / "module-dump-state").is_file()
    assert (IMAGEROOT / "bin" / "module-cleanup-state").is_file()
    assert (IMAGEROOT / "update-module.d" / "20pull_images").is_file()

    # Rule 8 & Containerfile metadata
    cf_text = (COLLECTOR_ROOT / "Containerfile").read_text(encoding="utf-8")
    assert "docker.io/grafana/alloy:v1.4.2" in cf_text
    assert "docker.io/prompve/prometheus-pve-exporter:3.4.5" in cf_text
    assert "org.nethserver.rootfull=0" in cf_text
    assert "sed -i 's/\\r$//'" in cf_text
    assert "chmod +x" in cf_text
    assert (COLLECTOR_ROOT / "build-images.sh").is_file()
