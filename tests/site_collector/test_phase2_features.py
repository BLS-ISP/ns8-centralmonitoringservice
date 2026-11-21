"""Unit and integration tests for Phase-2 Site Collector capabilities (#64)."""

from __future__ import annotations

import json
import socket
import struct
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


def _encode_resp(value) -> bytes:
    if isinstance(value, str):
        b = value.encode("utf-8")
        return f"${len(b)}\r\n".encode("ascii") + b + b"\r\n"
    if isinstance(value, int):
        return f":{value}\r\n".encode("ascii")
    if isinstance(value, list):
        out = [f"*{len(value)}\r\n".encode("ascii")]
        for item in value:
            out.append(_encode_resp(item))
        return b"".join(out)
    return b"$-1\r\n"


def _serve_single_redis_session(srv_sock: socket.socket, kv_hashes: dict[str, dict[str, str]]) -> None:
    """Minimal RESP2 mock server handling PING, AUTH, SCAN, TYPE, HGETALL, GET."""
    srv_sock.settimeout(5.0)
    while True:
        try:
            conn, _ = srv_sock.accept()
        except OSError:
            break
        with conn:
            conn.settimeout(2.0)
            buf = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\r\n" in buf:
                    if not buf.startswith(b"*"):
                        break
                    lines = buf.split(b"\r\n")
                    argc = int(lines[0][1:])
                    needed = 1 + argc * 2
                    if len(lines) <= needed:
                        break
                    args = [lines[2 + i * 2].decode("utf-8") for i in range(argc)]
                    consumed = b"\r\n".join(lines[:needed]) + b"\r\n"
                    buf = buf[len(consumed) :]

                    cmd = args[0].upper()
                    if cmd == "PING":
                        conn.sendall(b"+PONG\r\n")
                    elif cmd == "AUTH":
                        conn.sendall(b"+OK\r\n")
                    elif cmd == "SCAN":
                        conn.sendall(_encode_resp(["0", list(kv_hashes.keys())]))
                    elif cmd == "TYPE":
                        k = args[1]
                        conn.sendall(b"+hash\r\n" if k in kv_hashes else b"+none\r\n")
                    elif cmd == "HGETALL":
                        h = kv_hashes.get(args[1], {})
                        flat: list[str] = []
                        for hk, hv in h.items():
                            flat.extend([hk, hv])
                        conn.sendall(_encode_resp(flat))
                    elif cmd == "QUIT":
                        conn.sendall(b"+OK\r\n")
                        break
                    else:
                        conn.sendall(_encode_resp([]))


def test_cluster_wide_ns8_node_exporter_and_redis_backup_harvest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collector_lib.ns8_metrics import collect_and_write_ns8_metrics

    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    # 1. Start mock NS8 Core node_exporter serving cluster-wide module containers & systemd failures
    node_metrics_payload = "\n".join(
        [
            '# HELP ns8_container_info NS8 rootless module container metadata.',
            '# TYPE ns8_container_info gauge',
            'ns8_container_info{module="mail1",container="postfix",image="ghcr.io/nethserver/mail-postfix:1.4.0",unit="postfix.service"} 1',
            'ns8_container_info{module="nextcloud1",container="nextcloud-app",image="ghcr.io/nethserver/nextcloud-app:1.2.0",unit="nextcloud-app.service"} 1',
            'ns8_container_start_time_seconds{module="mail1",container="postfix"} 1763600000',
            'ns8_container_start_time_seconds{module="nextcloud1",container="nextcloud-app"} 0',
            'ns8_container_restarts_total{module="nextcloud1",container="nextcloud-app"} 5',
            'node_systemd_unit_state{name="nextcloud-app.service",state="failed"} 1',
            "",
        ]
    ).encode("utf-8")

    class _NodeExpHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(node_metrics_payload)))
            self.end_headers()
            self.wfile.write(node_metrics_payload)

    http_srv = HTTPServer(("127.0.0.1", 0), _NodeExpHandler)
    ne_port = http_srv.server_address[1]
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()

    # 2. Start mock NS8 Redis replica serving cluster-wide module backup hashes
    redis_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    redis_sock.bind(("127.0.0.1", 0))
    redis_sock.listen(4)
    redis_port = redis_sock.getsockname()[1]
    redis_data = {
        "module/mail1/backup": {
            "status": "ok",
            "last_success": "1763700000",
        },
        "module/samba1/backup": {
            "status": "failed",
            "last_success": "1763500000",
        },
    }
    redis_thread = threading.Thread(
        target=_serve_single_redis_session,
        args=(redis_sock, redis_data),
        daemon=True,
    )
    redis_thread.start()

    try:
        monkeypatch.setenv("NS8_NODE_EXPORTER_URL", f"http://127.0.0.1:{ne_port}/metrics")
        monkeypatch.setenv("REDIS_ADDRESS", f"127.0.0.1:{redis_port}")
        monkeypatch.setenv("COLLECTOR_STATE_DIR", str(state_dir))

        prom_path = collect_and_write_ns8_metrics(state_dir)
        rendered = prom_path.read_text(encoding="utf-8")

        # Cluster-wide backups from Redis
        assert 'ns8_backup_status{module_id="mail1"} 1' in rendered
        assert 'ns8_backup_failed{module_id="mail1"} 0' in rendered
        assert 'ns8_backup_last_success_timestamp_seconds{module_id="mail1"} 1763700000' in rendered
        assert 'ns8_backup_status{module_id="samba1"} 0' in rendered
        assert 'ns8_backup_failed{module_id="samba1"} 1' in rendered

        # Cluster-wide module containers from NS8 Core node_exporter
        assert (
            'ns8_container_info{module_id="mail1",container="postfix",'
            'image="ghcr.io/nethserver/mail-postfix:1.4.0"} 1'
        ) in rendered
        assert 'ns8_container_running{module_id="mail1",container="postfix"} 1' in rendered
        assert 'ns8_container_running{module_id="nextcloud1",container="nextcloud-app"} 0' in rendered
        assert (
            'ns8_container_restarts_total{module_id="nextcloud1",container="nextcloud-app"} 5'
            in rendered
        )
        assert 'ns8_systemd_unit_failed{name="nextcloud-app.service"} 1' in rendered
    finally:
        http_srv.shutdown()
        http_srv.server_close()
        redis_sock.close()


def test_ns8_node_exporter_rejects_public_wan_url_for_ssrf_safety(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collector_lib.ns8_metrics import _validate_node_exporter_url

    assert _validate_node_exporter_url("http://127.0.0.1:9100/metrics") is True
    assert _validate_node_exporter_url("http://10.5.4.1:9100/metrics") is True
    assert _validate_node_exporter_url("http://93.184.216.34:9100/metrics") is False
    assert _validate_node_exporter_url("http://169.254.169.254/latest/meta-data") is False


def test_qnap_and_printer_snmp_profiles_and_snmp_printer_role(
    tmp_path: Path, load_schema
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = tmp_path / "fake_agent"
    _write_fake_agent_module(agent_dir)

    _run_action_script(
        "actions/configure-module/20configure",
        state_dir=state_dir,
        agent_dir=agent_dir,
        stdin_payload={
            "hub_url": "https://monitoring.msp.example.com",
            "auth_token": "cms_v1_Phase2SnmpTestToken123456789012345678",
            "auth_token_unchanged": False,
            "customer": "acme-corp",
            "site": "hq",
        },
    )

    qnap_payload = {
        "name": "QNAP TS-h886 Backup NAS",
        "enabled": True,
        "target_type": "snmp",
        "device_role": "snmp-nas",
        "host": "192.168.40.10",
        "port": 161,
        "scrape_interval": "60s",
        "snmp_module": "qnap",
        "snmp_version": "v3",
        "snmp_v3": {
            "username": "qnapmon",
            "security_level": "authPriv",
            "auth_protocol": "SHA512",
            "auth_password": "qnap-auth-secret-pass",
            "priv_protocol": "AES256",
            "priv_password": "qnap-priv-secret-pass",
        },
    }
    jsonschema.validate(qnap_payload, load_schema("collector-save-local-target-input.json"))
    qnap_res = _run_action_script(
        "actions/save-local-target/20save",
        state_dir=state_dir,
        agent_dir=agent_dir,
        stdin_payload=qnap_payload,
    )
    assert qnap_res.returncode == 0, qnap_res.stderr

    printer_payload = {
        "name": "HP LaserJet Floor 2",
        "enabled": True,
        "target_type": "snmp",
        "device_role": "snmp-printer",
        "host": "192.168.40.25",
        "port": 161,
        "scrape_interval": "120s",
        "snmp_module": "printer",
        "snmp_version": "v2c",
        "snmp_community": "printer-ro",
    }
    jsonschema.validate(printer_payload, load_schema("collector-save-local-target-input.json"))
    prt_res = _run_action_script(
        "actions/save-local-target/20save",
        state_dir=state_dir,
        agent_dir=agent_dir,
        stdin_payload=printer_payload,
    )
    assert prt_res.returncode == 0, prt_res.stderr

    list_res = _run_action_script(
        "actions/list-local-targets/20read",
        state_dir=state_dir,
        agent_dir=agent_dir,
        stdin_payload={"target_type": "snmp"},
    )
    assert list_res.returncode == 0
    listed = json.loads(list_res.stdout)
    jsonschema.validate(listed, load_schema("collector-list-local-targets-output.json"))
    assert len(listed["targets"]) == 2

    alloy_cfg = (state_dir / "config.alloy").read_text(encoding="utf-8")
    assert 'module  = "qnap"' in alloy_cfg
    assert 'module  = "printer"' in alloy_cfg
    assert 'replacement  = "snmp-printer"' in alloy_cfg

    snmp_yml = (state_dir / "secrets" / "snmp-auths.yml").read_text(encoding="utf-8")
    for expected_token in (
        "  qnap:",
        "name: qnapVolumeStatus",
        "labelname: qnapVolumeDescr",
        "name: qnapDiskTemperature",
        "labelname: qnapDiskID",
        "  printer:",
        "name: prtMarkerSuppliesLevel",
        "name: prtMarkerSuppliesMaxCapacity",
        "labelname: prtMarkerSuppliesDescription",
        "name: prtAlertSeverityLevel",
        "labelname: prtAlertDescription",
    ):
        assert expected_token in snmp_yml, f"Missing {expected_token!r} in snmp-auths.yml"


def test_software_center_metadata_png_icon_containerfile_and_robot_suite() -> None:
    ui_pub = COLLECTOR_ROOT / "ui" / "public"
    ui_dist = COLLECTOR_ROOT / "ui" / "dist"

    # 1. metadata.json in public/ and dist/
    for meta_path in (ui_pub / "metadata.json", ui_dist / "metadata.json"):
        assert meta_path.is_file(), f"Missing {meta_path}"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta.get("name") == "Central Monitoring Collector"
        assert meta.get("description", {}).get("en")
        assert meta.get("description", {}).get("de")
        assert "monitoring" in meta.get("categories", [])
        assert meta.get("docs", {}).get("documentation_url")

    # 2. Valid 128x128 8-bit RGBA PNG icon in public/ and dist/
    for icon_path in (ui_pub / "module_default_icon.png", ui_dist / "module_default_icon.png"):
        assert icon_path.is_file(), f"Missing {icon_path}"
        raw = icon_path.read_bytes()
        assert raw[:8] == b"\x89PNG\r\n\x1a\n"
        ihdr_len = struct.unpack(">I", raw[8:12])[0]
        assert ihdr_len == 13
        assert raw[12:16] == b"IHDR"
        width, height, bit_depth, color_type = struct.unpack(">IIBB", raw[16:26])
        assert (width, height) == (128, 128)
        assert (bit_depth, color_type) == (8, 6)  # 8-bit RGBA
        assert b"IDAT" in raw
        assert raw[-8:-4] == b"IEND"

    # 3. Containerfile cluster:accountconsumer auth & build-images.sh REPO_OWNER support
    cf_text = (COLLECTOR_ROOT / "Containerfile").read_text(encoding="utf-8")
    assert 'org.nethserver.authorizations="node:fwadm cluster:accountconsumer"' in cf_text
    assert "COPY tests" not in cf_text

    build_sh = (COLLECTOR_ROOT / "build-images.sh").read_text(encoding="utf-8")
    assert "REPO_OWNER" in build_sh

    # 4. Robot Framework live VM test suite
    for rel in (
        "test-module.sh",
        "tests/__init__.robot",
        "tests/10__collector_lifecycle.robot",
    ):
        fpath = COLLECTOR_ROOT / rel
        assert fpath.is_file(), f"Missing Robot suite file: {fpath}"
        assert b"\r\n" not in fpath.read_bytes()

    test_mod_sh = (COLLECTOR_ROOT / "test-module.sh").read_text(encoding="utf-8")
    assert "--network=host" in test_mod_sh
    assert "ghcr.io/nethserver/robotframework:latest" in test_mod_sh
    assert "robot \\" in test_mod_sh or "robot " in test_mod_sh
