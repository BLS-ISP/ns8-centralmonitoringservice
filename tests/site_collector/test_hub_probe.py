"""Unit and schema tests for collector_lib.hub_probe (test-hub-connection)."""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import jsonschema


class _MockHubHandler(BaseHTTPRequestHandler):
    expected_token = "cms_v1_ValidTestToken12345678901234567890"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/api/v1/ingest/verify":
            self.send_response(404)
            self.end_headers()
            return

        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {self.expected_token}":
            body = json.dumps(
                {
                    "status": "ok",
                    "customer": "acme-corp",
                    "token_prefix": "cms_v1_Valid",
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = json.dumps(
                {
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "Missing, malformed, or revoked bearer token.",
                    }
                }
            ).encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def test_hub_probe_rejects_plain_http_and_missing_token(load_schema) -> None:
    from collector_lib.hub_probe import verify_hub_connection

    schema = load_schema("collector-test-hub-connection-output.json")

    res_http = verify_hub_connection(
        hub_url="http://insecure.example.com",
        auth_token="cms_v1_ValidTestToken12345678901234567890",
    )
    assert res_http["ok"] is False
    assert res_http["http_status"] == 0
    assert res_http["verified_customer"] is None
    jsonschema.validate(res_http, schema)

    res_no_token = verify_hub_connection(
        hub_url="https://monitoring.msp.example.com",
        auth_token="",
    )
    assert res_no_token["ok"] is False
    assert res_no_token["verified_customer"] is None
    jsonschema.validate(res_no_token, schema)


def test_hub_probe_200_401_and_connection_error(load_schema, monkeypatch) -> None:
    from collector_lib import hub_probe

    schema = load_schema("collector-test-hub-connection-output.json")

    server = HTTPServer(("127.0.0.1", 0), _MockHubHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Allow local loopback HTTP transport replacement in unit test while keeping https:// validation
        monkeypatch.setenv("HUB_PROBE_ALLOW_LOOPBACK", "1")
        monkeypatch.setattr(
            hub_probe,
            "_REWRITE_LOOPBACK_HTTPS_TO_HTTP_FOR_TESTS",
            True,
        )

        res_ok = hub_probe.verify_hub_connection(
            hub_url=f"https://127.0.0.1:{port}",
            auth_token=_MockHubHandler.expected_token,
            tls_skip_verify=True,
        )
        assert res_ok["ok"] is True
        assert res_ok["http_status"] == 200
        assert res_ok["verified_customer"] == "acme-corp"
        assert res_ok["latency_ms"] >= 0
        jsonschema.validate(res_ok, schema)

        res_401 = hub_probe.verify_hub_connection(
            hub_url=f"https://127.0.0.1:{port}/",
            auth_token="cms_v1_WrongBearerToken00000000000000000000",
            tls_skip_verify=True,
        )
        assert res_401["ok"] is False
        assert res_401["http_status"] == 401
        assert res_401["verified_customer"] is None
        assert "401" in res_401["message"] or "revoked" in res_401["message"]
        jsonschema.validate(res_401, schema)
    finally:
        server.shutdown()
        server.server_close()

    # Unreachable port (with loopback allowed for test) -> graceful connection failure
    monkeypatch.setenv("HUB_PROBE_ALLOW_LOOPBACK", "1")
    res_conn_err = hub_probe.verify_hub_connection(
        hub_url="https://127.0.0.1:1",
        auth_token=_MockHubHandler.expected_token,
        tls_skip_verify=True,
        timeout_seconds=0.5,
    )
    assert res_conn_err["ok"] is False
    assert res_conn_err["http_status"] == 0
    assert res_conn_err["verified_customer"] is None
    jsonschema.validate(res_conn_err, schema)


def test_hub_probe_handles_tls_verification_error(load_schema, monkeypatch) -> None:
    import urllib.error
    import urllib.request
    from collector_lib import hub_probe

    schema = load_schema("collector-test-hub-connection-output.json")

    def _raise_ssl(*args, **kwargs):
        raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "self-signed certificate"))

    monkeypatch.setattr(hub_probe, "_resolve_and_validate_hub_host", lambda host, port, **kw: ["93.184.216.34"])
    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: type("O", (), {"open": _raise_ssl})())

    res_tls = hub_probe.verify_hub_connection(
        hub_url="https://self-signed.msp.example.com",
        auth_token="cms_v1_ValidTestToken12345678901234567890",
        tls_skip_verify=False,
    )
    assert res_tls["ok"] is False
    assert res_tls["http_status"] == 0
    assert res_tls["verified_customer"] is None
    assert "TLS" in res_tls["message"] or "certificate" in res_tls["message"].lower()
    jsonschema.validate(res_tls, schema)
