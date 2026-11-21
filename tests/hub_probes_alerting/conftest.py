from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import uuid

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "shared" / "schemas"
ACTIONS_DIR = REPO_ROOT / "hub" / "imageroot" / "actions"
PYPKG_DIR = REPO_ROOT / "hub" / "imageroot" / "pypkg"

if str(PYPKG_DIR) not in sys.path:
    sys.path.insert(0, str(PYPKG_DIR))


def load_schema(action: str, direction: str) -> dict[str, Any]:
    schema_path = SCHEMAS_DIR / f"hub-{action}-{direction}.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_payload(action: str, direction: str, payload: dict[str, Any]) -> None:
    schema = load_schema(action, direction)
    jsonschema.validate(instance=payload, schema=schema, cls=jsonschema.Draft7Validator)


class MockObservabilityHTTPServer:
    """Real localhost HTTP server simulating Prometheus and Alertmanager v2 APIs."""

    def __init__(self) -> None:
        self.prom_reloads = 0
        self.snmp_reloads = 0
        self.am_reloads = 0
        self.received_alerts: list[dict[str, Any]] = []
        self.silences: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send_json(self, status: int, body: Any) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/api/v2/silences"):
                    with outer._lock:
                        items = list(outer.silences.values())
                    self._send_json(200, items)
                    return
                self._send_json(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b""
                if self.path == "/prom/-/reload":
                    with outer._lock:
                        outer.prom_reloads += 1
                    self.send_response(200)
                    self.end_headers()
                    return
                if self.path == "/snmp/-/reload":
                    with outer._lock:
                        outer.snmp_reloads += 1
                    self.send_response(200)
                    self.end_headers()
                    return
                if self.path == "/am/-/reload" or self.path == "/-/reload":
                    with outer._lock:
                        outer.am_reloads += 1
                    self.send_response(200)
                    self.end_headers()
                    return
                if self.path == "/api/v2/alerts":
                    parsed = json.loads(raw_body.decode("utf-8"))
                    with outer._lock:
                        outer.received_alerts.extend(parsed)
                    self._send_json(200, {"status": "success"})
                    return
                if self.path == "/api/v2/silences":
                    parsed = json.loads(raw_body.decode("utf-8"))
                    silence_id = parsed.get("id") or f"am-sil-{uuid.uuid4().hex[:12]}"
                    record = {
                        "id": silence_id,
                        "status": {"state": "active"},
                        "startsAt": parsed["startsAt"],
                        "endsAt": parsed["endsAt"],
                        "createdBy": parsed["createdBy"],
                        "comment": parsed["comment"],
                        "matchers": parsed["matchers"],
                    }
                    with outer._lock:
                        outer.silences[silence_id] = record
                    self._send_json(200, {"silenceID": silence_id})
                    return
                self._send_json(404, {"error": "not found"})

            def do_DELETE(self) -> None:  # noqa: N802
                prefix = "/api/v2/silence/"
                if self.path.startswith(prefix):
                    silence_id = self.path[len(prefix) :]
                    with outer._lock:
                        if silence_id in outer.silences:
                            outer.silences[silence_id]["status"] = {"state": "expired"}
                            self.send_response(200)
                            self.end_headers()
                            return
                    self._send_json(404, {"message": "silence not found"})
                    return
                self._send_json(404, {"error": "not found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


@pytest.fixture()
def mock_backends() -> Any:
    srv = MockObservabilityHTTPServer()
    try:
        yield srv
    finally:
        srv.close()


@pytest.fixture()
def hub_env(
    tmp_path: Path,
    mock_backends: MockObservabilityHTTPServer,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    state_dir = tmp_path / "state"
    config_dir = tmp_path / "config"
    state_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)

    tenants_payload = {
        "version": 1,
        "tenants": [
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp GmbH",
                "sites": ["hq", "dc1"],
                "default_site": "hq",
                "contact_emails": ["noc@acme.example.com", "cto@acme.example.com"],
                "customer_portal_enabled": True,
            },
            {
                "customer": "beta-gmbh",
                "display_name": "Beta Logistics GmbH",
                "sites": ["berlin"],
                "default_site": "berlin",
                "contact_emails": [],
                "customer_portal_enabled": False,
            },
        ],
    }
    (state_dir / "tenants.json").write_text(
        json.dumps(tenants_payload, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (state_dir / "smarthost.env").write_text(
        "SMARTHOST_ENABLED=1\nSMARTHOST_HOST=127.0.0.1\nSMARTHOST_PORT=2525\nSMARTHOST_TLS=0\n",
        encoding="utf-8",
        newline="\n",
    )

    env_overrides = {
        "AGENT_STATE_DIR": str(state_dir),
        "HUB_CONFIG_DIR": str(config_dir),
        "HUB_AVAILABLE_RULES_DIR": str(REPO_ROOT / "shared" / "rules"),
        "PROMETHEUS_RELOAD_URL": f"{mock_backends.base_url}/prom/-/reload",
        "SNMP_RELOAD_URL": f"{mock_backends.base_url}/snmp/-/reload",
        "ALERTMANAGER_URL": mock_backends.base_url,
    }
    for k, v in env_overrides.items():
        monkeypatch.setenv(k, v)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PYPKG_DIR) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )

    def run_action(
        action: str,
        script_name: str,
        payload: dict[str, Any],
        *,
        expect_success: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str] | dict[str, Any]:
        validate_payload(action, "input", payload)
        script_path = ACTIONS_DIR / action / script_name
        merged_env = env.copy()
        if extra_env:
            merged_env.update(extra_env)
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            cwd=str(state_dir),
            env=merged_env,
            check=False,
        )
        if not expect_success:
            return proc
        assert proc.returncode == 0, (
            f"Action {action}/{script_name} failed (rc={proc.returncode}):\n"
            f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        )
        out = json.loads(proc.stdout)
        validate_payload(action, "output", out)
        return out

    return {
        "tmp_path": tmp_path,
        "state_dir": state_dir,
        "config_dir": config_dir,
        "env": env,
        "backends": mock_backends,
        "run_action": run_action,
    }
