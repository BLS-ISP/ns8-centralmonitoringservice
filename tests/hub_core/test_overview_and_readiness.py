"""Edge-case tests for overview metrics, component health, readiness poller, and validation failures."""

from __future__ import annotations

import http.server
import importlib.machinery
import importlib.util
import json
import threading
from pathlib import Path
from typing import Any

from tests.hub_core.conftest import (
    IMAGEROOT,
    FakeNS8Env,
    execute_script,
    validate_against_schema,
)


def _load_wait_pod_endpoints() -> Any:
    script_path = IMAGEROOT / "bin" / "wait-pod-endpoints"
    loader = importlib.machinery.SourceFileLoader("wait_pod_endpoints", str(script_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_wait_pod_endpoints_retries_until_200_and_times_out_when_down() -> None:
    wait_mod = _load_wait_pod_endpoints()
    attempts = {"count": 0}

    class FlakyReadyHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            attempts["count"] += 1
            if attempts["count"] < 2:
                self.send_response(503)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ready\n")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), FlakyReadyHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ok = wait_mod.wait_for_urls([f"http://127.0.0.1:{port}/-/ready"], timeout_seconds=5.0)
        assert ok is True
        assert attempts["count"] >= 2
    finally:
        server.shutdown()
        server.server_close()

    # Unreachable port times out cleanly and returns False
    assert wait_mod.wait_for_urls([f"http://127.0.0.1:{port}/-/ready"], timeout_seconds=0.6) is False


def test_overview_and_configuration_aggregate_prometheus_series_and_alerts(
    ns8_env: FakeNS8Env,
) -> None:
    from hub_core.env_store import apply_configuration, ensure_initial_secrets
    from hub_core.overview import build_get_configuration_response, build_get_overview_response

    ensure_initial_secrets(ns8_env.state_dir)
    apply_configuration(
        ns8_env.state_dir,
        {
            "host": "hub.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )

    def fake_probe(unit_name: str) -> str:
        return "healthy" if unit_name != "snmp-exporter.service" else "unhealthy"

    def fake_fetch_json(url: str) -> dict[str, Any] | None:
        if url.endswith("/api/v1/status/tsdb"):
            return {"status": "success", "data": {"headStats": {"numSeries": 184250}}}
        if url.endswith("/api/v1/alerts"):
            return {
                "status": "success",
                "data": {
                    "alerts": [
                        {"state": "firing", "labels": {"severity": "critical"}},
                        {"state": "firing", "labels": {"severity": "critical"}},
                        {"state": "firing", "labels": {"severity": "warning"}},
                        {"state": "pending", "labels": {"severity": "critical"}},
                    ]
                },
            }
        return None

    ov = build_get_overview_response(
        ns8_env.state_dir,
        probe_unit=fake_probe,
        fetch_json=fake_fetch_json,
    )
    validate_against_schema("hub-get-overview-output.json", ov)
    assert ov["components"]["prometheus"] == "healthy"
    assert ov["components"]["snmp_exporter"] == "unhealthy"
    assert ov["components"]["thanos_sidecar"] == "disabled"
    assert ov["components"]["thanos_store"] == "disabled"
    assert ov["components"]["thanos_query"] == "disabled"
    assert ov["counts"]["active_series"] == 184250
    assert ov["counts"]["firing_alerts_critical"] == 2
    assert ov["counts"]["firing_alerts_warning"] == 1

    cfg = build_get_configuration_response(
        ns8_env.state_dir,
        probe_unit=fake_probe,
        fetch_json=fake_fetch_json,
    )
    validate_against_schema("hub-get-configuration-output.json", cfg)
    assert cfg["health"]["firing_alerts_count"] == 3


def test_20configure_exits_2_on_missing_s3_secret_key(ns8_env: FakeNS8Env) -> None:
    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")

    rc, stdout, _ = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload={
            "host": "hub.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "s3",
            "s3": {
                "endpoint": "minio.lan:9000",
                "bucket": "msp-bucket",
                "access_key": "minioadmin",
                "secret_key": "",
                "secret_key_unchanged": True,
            },
        },
    )
    assert rc == 2
    assert ns8_env.status == "validation-failed"
    err_list = json.loads(stdout)
    assert err_list[0]["field"] == "s3"


def test_clone_module_registers_route_when_non_colliding_host_provided(ns8_env: FakeNS8Env) -> None:
    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    ns8_env.set_env("MODULE_ID", "central-monitoring-hub2")
    ns8_env.dump_env()

    rc, _, stderr = execute_script(
        IMAGEROOT / "actions" / "clone-module" / "50configure",
        payload={"host": "staging-hub.msp.example.com"},
    )
    assert rc == 0, stderr
    assert ns8_env.persisted_env["TRAEFIK_HOST"] == "staging-hub.msp.example.com"
    routes = [c for c in ns8_env.task_calls if c["action"] == "set-route"]
    assert len(routes) == 1
    assert routes[0]["data"]["host"] == "staging-hub.msp.example.com"


def test_pod_http_helper_falls_back_to_podman_exec_on_connection_refused(
    monkeypatch: Any,
) -> None:
    import shutil
    import subprocess
    import urllib.error

    from hub_core.pod_http import pod_fetch_json, pod_http_request

    def always_refused(*args: object, **kwargs: object) -> object:
        raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))

    exec_calls: list[list[str]] = []

    def fake_podman_runner(
        cmd: list[str], *, input: str | None = None, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        exec_calls.append(list(cmd))
        req_meta = json.loads(input or "{}")
        if req_meta.get("url", "").endswith("/api/v1/status/tsdb"):
            body = json.dumps({"status": "success", "data": {"headStats": {"numSeries": 4200}}})
            out = json.dumps({"status": 200, "body": body})
            return subprocess.CompletedProcess(cmd, 0, out, "")
        out = json.dumps({"status": 200, "body": ""})
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr("urllib.request.urlopen", always_refused)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/podman" if name == "podman" else None)

    tsdb_doc = pod_fetch_json("http://127.0.0.1:9090/api/v1/status/tsdb", runner=fake_podman_runner)
    assert tsdb_doc == {"status": "success", "data": {"headStats": {"numSeries": 4200}}}
    assert exec_calls and exec_calls[0][:3] == ["podman", "exec", "-i"]

    reload_res = pod_http_request("http://127.0.0.1:9093/-/reload", method="POST", runner=fake_podman_runner)
    assert reload_res is not None
    assert reload_res[0] == 200
