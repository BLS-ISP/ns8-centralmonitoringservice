import json
from pathlib import Path
import aiohttp
from aiohttp import web
import jsonschema
import pytest
import pytest_asyncio

from hub_gateway.app import GatewaySettings, create_gateway_app
from hub_gateway.alert_relay import AlertRelaySettings, create_alert_relay_app
from hub_gateway.loki_push import (
    LokiEntry,
    LokiStream,
    build_loki_push_request,
    parse_loki_label_selector,
    parse_loki_push_request,
)
from hub_gateway.prom_remote_write import (
    Sample,
    TimeSeries,
    build_write_request,
    parse_write_request,
)
from hub_gateway.snappy_codec import encode_varint, snappy_compress, snappy_decompress
from hub_tenancy.store import mint_dedicated_collector_token, rotate_token, save_tenant

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_SCHEMA = json.loads(
    (REPO_ROOT / "shared" / "schemas" / "telemetry-contract.schema.json").read_text(encoding="utf-8")
)
API_ERROR_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "definitions": CONTRACT_SCHEMA["definitions"],
    "$ref": "#/definitions/apiError",
}


@pytest_asyncio.fixture
async def mock_upstreams(aiohttp_server):
    """Spin up realistic local mock Prometheus, Loki, and Grafana HTTP/WS servers."""
    recorded = {
        "prom_writes": [],
        "loki_pushes": [],
        "grafana_requests": [],
        "ntfy_requests": [],
        "gotify_requests": [],
    }

    # Mock Prometheus (:9090 equivalent)
    prom_app = web.Application()

    async def prom_write(request: web.Request) -> web.Response:
        raw = await request.read()
        decompressed = snappy_decompress(raw)
        series = parse_write_request(decompressed)
        recorded["prom_writes"].append(
            {
                "headers": dict(request.headers),
                "series": series,
            }
        )
        return web.Response(status=204)

    async def prom_ready(_request: web.Request) -> web.Response:
        return web.Response(status=200, text="Prometheus Server is Ready.\n")

    prom_app.router.add_post("/api/v1/write", prom_write)
    prom_app.router.add_get("/-/ready", prom_ready)
    prom_srv = await aiohttp_server(prom_app)

    # Mock Loki (:3100 equivalent)
    loki_app = web.Application()

    async def loki_push(request: web.Request) -> web.Response:
        raw = await request.read()
        ct = request.headers.get("Content-Type", "")
        org_id = request.headers.get("X-Scope-OrgID")
        if "json" in ct:
            parsed = json.loads(raw.decode("utf-8"))
        else:
            decompressed = snappy_decompress(raw)
            streams = parse_loki_push_request(decompressed)
            parsed = [
                {
                    "labels": parse_loki_label_selector(s.labels),
                    "lines": [e.line for e in s.entries],
                }
                for s in streams
            ]
        recorded["loki_pushes"].append(
            {
                "org_id": org_id,
                "content_type": ct,
                "payload": parsed,
            }
        )
        return web.Response(status=204)

    async def loki_ready(_request: web.Request) -> web.Response:
        return web.Response(status=200, text="ready\n")

    loki_app.router.add_post("/loki/api/v1/push", loki_push)
    loki_app.router.add_get("/ready", loki_ready)
    loki_srv = await aiohttp_server(loki_app)

    # Mock Grafana (:3000 equivalent with HTTP + /api/live/ws WebSocket)
    grafana_app = web.Application()

    async def grafana_ws(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                await ws.send_str(f"grafana-live:{msg.data}")
        return ws

    async def grafana_any(request: web.Request) -> web.Response:
        recorded["grafana_requests"].append(
            {
                "method": request.method,
                "path_qs": request.path_qs,
                "headers": dict(request.headers),
            }
        )
        return web.json_response({"grafana": True, "path": request.path})

    grafana_app.router.add_get("/api/live/ws", grafana_ws)
    grafana_app.router.add_route("*", "/{tail:.*}", grafana_any)
    grafana_srv = await aiohttp_server(grafana_app)

    # Mock Ntfy & Gotify servers
    push_app = web.Application()

    async def ntfy_handler(request: web.Request) -> web.Response:
        body = (await request.read()).decode("utf-8")
        recorded["ntfy_requests"].append(
            {"path": request.path, "headers": dict(request.headers), "body": body}
        )
        return web.json_response({"id": "ntfy-1"})

    async def gotify_handler(request: web.Request) -> web.Response:
        body = await request.json()
        recorded["gotify_requests"].append(
            {
                "path": request.path,
                "query": dict(request.query),
                "headers": dict(request.headers),
                "body": body,
            }
        )
        return web.json_response({"id": 1})

    push_app.router.add_post("/ntfy/{topic}", ntfy_handler)
    push_app.router.add_post("/gotify/message", gotify_handler)
    push_srv = await aiohttp_server(push_app)

    return {
        "recorded": recorded,
        "prom_url": f"http://127.0.0.1:{prom_srv.port}",
        "loki_url": f"http://127.0.0.1:{loki_srv.port}",
        "grafana_url": f"http://127.0.0.1:{grafana_srv.port}",
        "push_url": f"http://127.0.0.1:{push_srv.port}",
    }


@pytest_asyncio.fixture
async def gateway_env(tmp_path, aiohttp_client, mock_upstreams):
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)

    _, attacker_token = save_tenant(
        state_dir,
        {
            "customer": "attacker-corp",
            "display_name": "Attacker Corp",
            "sites": ["hq", "branch-berlin"],
            "contact_emails": [],
            "customer_portal_enabled": False,
        },
    )
    _, victim_token = save_tenant(
        state_dir,
        {
            "customer": "victim-corp",
            "display_name": "Victim Corp",
            "sites": ["hq"],
            "contact_emails": ["sec@victim.example.com"],
            "customer_portal_enabled": False,
        },
    )

    settings = GatewaySettings(
        tenants_file=state_dir / "tenants.json",
        prom_write_url=f"{mock_upstreams['prom_url']}/api/v1/write",
        prom_ready_url=f"{mock_upstreams['prom_url']}/-/ready",
        loki_push_url=f"{mock_upstreams['loki_url']}/loki/api/v1/push",
        loki_ready_url=f"{mock_upstreams['loki_url']}/ready",
        grafana_upstream_url=mock_upstreams["grafana_url"],
        auth_rate_limit_max_failures=5,
        auth_rate_limit_window_seconds=300,
    )
    app = create_gateway_app(settings)
    client = await aiohttp_client(app)
    return {
        "state_dir": state_dir,
        "client": client,
        "attacker_token": attacker_token,
        "victim_token": victim_token,
        "recorded": mock_upstreams["recorded"],
        "upstreams": mock_upstreams,
    }


@pytest.mark.asyncio
class TestGatewayAbuseAndSecuritySuite:
    async def test_1_cross_tenant_metric_spoofing_overwritten_and_sorted(self, gateway_env):
        client = gateway_env["client"]
        spoofed_pb = build_write_request(
            [
                TimeSeries(
                    labels=[
                        ("__name__", "up"),
                        ("customer", "victim-corp"),
                        ("site", "hq"),
                        ("device_role", "linux"),
                        ("collector_id", "c1"),
                    ],
                    samples=[Sample(value=1.0, timestamp_ms=1700000000000)],
                )
            ]
        )
        resp = await client.post(
            "/api/v1/write",
            data=snappy_compress(spoofed_pb),
            headers={
                "Authorization": f"Bearer {gateway_env['attacker_token']}",
                "Content-Type": "application/x-protobuf",
                "Content-Encoding": "snappy",
            },
        )
        assert resp.status == 204
        writes = gateway_env["recorded"]["prom_writes"]
        assert len(writes) == 1
        series = writes[0]["series"][0]
        names = [k for k, _ in series.labels]
        assert names == sorted(names)
        labels = dict(series.labels)
        assert labels["customer"] == "attacker-corp"
        assert "victim-corp" not in labels.values()

    async def test_2_cross_tenant_loki_header_and_stream_spoofing_json_and_protobuf(self, gateway_env):
        client = gateway_env["client"]

        # 2a: JSON Loki push spoofing both X-Scope-OrgID and stream.customer
        json_payload = {
            "streams": [
                {
                    "stream": {"customer": "victim-corp", "job": "syslog"},
                    "values": [["1700000000000000000", "spoof attempt json"]],
                }
            ]
        }
        resp_json = await client.post(
            "/loki/api/v1/push",
            json=json_payload,
            headers={
                "Authorization": f"Bearer {gateway_env['attacker_token']}",
                "X-Scope-OrgID": "victim-corp",
            },
        )
        assert resp_json.status == 204

        # 2b: Snappy+Protobuf logproto.PushRequest (Alloy loki.write format) spoofing both
        pb_payload = build_loki_push_request(
            [
                LokiStream(
                    labels='{customer="victim-corp", job="systemd-journal", site="branch-berlin", device_role="ns8", collector_id="ns8-01"}',
                    entries=[LokiEntry(1700000005, 0, "spoof attempt protobuf")],
                )
            ]
        )
        resp_pb = await client.post(
            "/loki/api/v1/push",
            data=snappy_compress(pb_payload),
            headers={
                "Authorization": f"Bearer {gateway_env['attacker_token']}",
                "Content-Type": "application/x-protobuf",
                "Content-Encoding": "snappy",
                "X-Scope-OrgID": "victim-corp",
            },
        )
        assert resp_pb.status == 204

        pushes = gateway_env["recorded"]["loki_pushes"]
        assert len(pushes) == 2

        assert pushes[0]["org_id"] == "attacker-corp"
        assert pushes[0]["payload"]["streams"][0]["stream"]["customer"] == "attacker-corp"

        assert pushes[1]["org_id"] == "attacker-corp"
        assert pushes[1]["payload"][0]["labels"]["customer"] == "attacker-corp"
        assert pushes[1]["payload"][0]["labels"]["site"] == "branch-berlin"
        assert pushes[1]["payload"][0]["lines"] == ["spoof attempt protobuf"]

    async def test_3_internal_admin_endpoints_and_path_traversal_blocked(self, gateway_env):
        client = gateway_env["client"]

        blocked_requests = [
            ("GET", "/api/v1/query?query=up"),
            ("POST", "/-/reload"),
            ("POST", "/-/quit"),
            ("GET", "/metrics"),
            ("GET", "/federate?match[]={__name__=~'.+'}"),
            ("GET", "/loki/api/v1/query?query={job='syslog'}"),
            ("POST", "/alert-relay/ntfy"),
            ("GET", "/api/datasources/proxy/uid/prometheus/api/v1/admin/tsdb/delete_series"),
        ]
        for method, path in blocked_requests:
            resp = await client.request(method, path)
            assert resp.status == 403, f"Expected 403 on {method} {path}, got {resp.status}"
            err = await resp.json()
            jsonschema.validate(err, API_ERROR_SCHEMA)

        # Encoded path traversal attempts must never reach Grafana or internal services
        for traversal in (
            "/api/datasources/proxy/uid/prometheus/..%2f..%2f-/reload",
            "/public/..%2F..%2Fetc/passwd",
        ):
            resp = await client.get(traversal)
            assert resp.status in (400, 403)

        assert len(gateway_env["recorded"]["grafana_requests"]) == 0

        # Legitimate Grafana HTTP + WebSocket routes work and strip spoofed X-Scope-OrgID
        healthy_resp = await client.get("/-/healthy")
        assert healthy_resp.status == 200
        assert (await healthy_resp.json()) == {"status": "ok"}

        g_resp = await client.get("/d/ns8-multi-cluster-overview", headers={"X-Scope-OrgID": "victim-corp"})
        assert g_resp.status == 200
        assert g_resp.headers.get("X-Content-Type-Options") == "nosniff"
        proxied_headers = gateway_env["recorded"]["grafana_requests"][0]["headers"]
        assert "X-Scope-OrgID" not in proxied_headers

        async with client.ws_connect("/api/live/ws") as ws:
            await ws.send_str("ping-live")
            reply = await ws.receive_str()
            assert reply == "grafana-live:ping-live"

    async def test_4_decompression_bomb_and_compressed_size_cap_return_413(
        self, gateway_env, aiohttp_client
    ):
        client = gateway_env["client"]
        headers = {
            "Authorization": f"Bearer {gateway_env['attacker_token']}",
            "Content-Type": "application/x-protobuf",
            "Content-Encoding": "snappy",
        }
        # Snappy varint claiming 100 MiB (> 64 MiB cap)
        bomb = encode_varint(100 * 1024 * 1024) + b"\x00X"
        for path in ("/api/v1/write", "/loki/api/v1/push"):
            resp = await client.post(path, data=bomb, headers=headers)
            assert resp.status == 413
            body = await resp.json()
            jsonschema.validate(body, API_ERROR_SCHEMA)
            assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"

        # Compressed body cap enforcement (test with 1 KiB cap)
        small_cap_app = create_gateway_app(
            GatewaySettings(
                tenants_file=gateway_env["state_dir"] / "tenants.json",
                max_compressed_bytes=1024,
            )
        )
        small_cap_client = await aiohttp_client(small_cap_app)
        oversized_compressed = b"x" * 2048
        resp_cap = await small_cap_client.post(
            "/api/v1/write", data=oversized_compressed, headers=headers
        )
        assert resp_cap.status == 413
        cap_body = await resp_cap.json()
        jsonschema.validate(cap_body, API_ERROR_SCHEMA)
        assert cap_body["error"]["code"] == "PAYLOAD_TOO_LARGE"

    async def test_5_token_rotation_grace_window_dedicated_tokens_and_rate_limiting(self, gateway_env):
        client = gateway_env["client"]
        state_dir = gateway_env["state_dir"]
        old_token = gateway_env["attacker_token"]

        # Rotate with 60-minute grace period -> BOTH old and new tokens work immediately via mtime reload
        rot_grace = rotate_token(state_dir, "attacker-corp", grace_period_minutes=60)
        new_token = rot_grace["auth_token"]
        assert new_token != old_token

        r_old = await client.get("/api/v1/ingest/verify", headers={"Authorization": f"Bearer {old_token}"})
        r_new = await client.get("/api/v1/ingest/verify", headers={"Authorization": f"Bearer {new_token}"})
        assert r_old.status == 200
        assert r_new.status == 200
        verify_json = await r_new.json()
        assert verify_json["status"] == "ok"
        assert verify_json["customer"] == "attacker-corp"
        assert verify_json["backends"] == {"prometheus": True, "loki": True}

        # Rotate with grace_period_minutes=0 -> previous token revoked immediately
        rot_immediate = rotate_token(state_dir, "attacker-corp", grace_period_minutes=0)
        newest_token = rot_immediate["auth_token"]

        r_revoked = await client.get("/api/v1/ingest/verify", headers={"Authorization": f"Bearer {new_token}"})
        assert r_revoked.status == 401
        err_401 = await r_revoked.json()
        jsonschema.validate(err_401, API_ERROR_SCHEMA)
        assert err_401["error"]["code"] == "UNAUTHORIZED"

        r_newest = await client.get("/api/v1/ingest/verify", headers={"Authorization": f"Bearer {newest_token}"})
        assert r_newest.status == 200

        # Dedicated collector token is strictly scoped to its assigned site
        ded_token, _ = mint_dedicated_collector_token(
            state_dir,
            customer="attacker-corp",
            site="branch-berlin",
            collector_id="attacker-berlin-linux",
        )
        wrong_site_pb = build_write_request(
            [
                TimeSeries(
                    labels=[("__name__", "up"), ("site", "hq"), ("device_role", "linux")],
                    samples=[Sample(1.0, 1700000000000)],
                )
            ]
        )
        r_wrong_site = await client.post(
            "/api/v1/write",
            data=snappy_compress(wrong_site_pb),
            headers={"Authorization": f"Bearer {ded_token}"},
        )
        assert r_wrong_site.status == 422

        # Per-IP failed auth rate limiter (configured to 5 failures in fixture)
        for _ in range(5):
            bad = await client.get(
                "/api/v1/ingest/verify",
                headers={
                    "Authorization": "Bearer cms_v1_invalid_brute_force_guess_000000000000",
                    "X-Forwarded-For": "203.0.113.99",
                },
            )
            assert bad.status == 401

        rate_limited = await client.get(
            "/api/v1/ingest/verify",
            headers={
                "Authorization": f"Bearer {newest_token}",
                "X-Forwarded-For": "203.0.113.99",
            },
        )
        assert rate_limited.status == 429
        err_429 = await rate_limited.json()
        jsonschema.validate(err_429, API_ERROR_SCHEMA)
        assert err_429["error"]["code"] == "RATE_LIMITED"

        # Different IP is unaffected
        ok_other_ip = await client.get(
            "/api/v1/ingest/verify",
            headers={
                "Authorization": f"Bearer {newest_token}",
                "X-Forwarded-For": "198.51.100.42",
            },
        )
        assert ok_other_ip.status == 200

    async def test_6_internal_alert_relay_ntfy_and_gotify_and_ssrf_guard(
        self, tmp_path, aiohttp_client, mock_upstreams
    ):
        state_dir = tmp_path / "relay-state"
        state_dir.mkdir(parents=True)
        secrets_path = state_dir / "alerting-secrets.json"
        secrets_path.write_text(
            json.dumps(
                {
                    "push": {
                        "ntfy_url": f"{mock_upstreams['push_url']}/ntfy",
                        "ntfy_topic": "msp-critical",
                        "ntfy_token": "tk_secret_ntfy_123",
                        "gotify_url": f"{mock_upstreams['push_url']}/gotify",
                        "gotify_token": "gotify_app_secret_456",
                    }
                }
            ),
            encoding="utf-8",
        )

        relay_app = create_alert_relay_app(
            AlertRelaySettings(state_dir=state_dir, allow_loopback_upstream=True)
        )
        relay_client = await aiohttp_client(relay_app)

        am_webhook = {
            "version": "4",
            "status": "firing",
            "commonLabels": {
                "alertname": "LinuxHostDown",
                "customer": "acme-corp",
                "site": "hq",
                "severity": "critical",
            },
            "commonAnnotations": {
                "summary": "Linux server srv01 is down",
                "description": "up == 0 for 5m on srv01",
            },
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "LinuxHostDown",
                        "customer": "acme-corp",
                        "site": "hq",
                        "instance": "srv01.acme.lan",
                        "severity": "critical",
                    },
                    "annotations": {
                        "summary": "Linux server srv01 is down",
                        "description": "up == 0 for 5m on srv01",
                    },
                }
            ],
        }

        r_ntfy = await relay_client.post("/alert-relay/ntfy", json=am_webhook)
        assert r_ntfy.status == 200
        ntfy_calls = mock_upstreams["recorded"]["ntfy_requests"]
        assert len(ntfy_calls) == 1
        assert ntfy_calls[0]["path"] == "/ntfy/msp-critical"
        assert ntfy_calls[0]["headers"]["Authorization"] == "Bearer tk_secret_ntfy_123"
        assert ntfy_calls[0]["headers"]["Priority"] == "urgent"
        assert "acme-corp" in ntfy_calls[0]["headers"]["Title"]
        assert "srv01" in ntfy_calls[0]["body"]

        r_gotify = await relay_client.post("/alert-relay/gotify", json=am_webhook)
        assert r_gotify.status == 200
        gotify_calls = mock_upstreams["recorded"]["gotify_requests"]
        assert len(gotify_calls) == 1
        assert gotify_calls[0]["path"] == "/gotify/message"
        assert gotify_calls[0]["headers"]["X-Gotify-Key"] == "gotify_app_secret_456"
        assert gotify_calls[0]["body"]["priority"] >= 8
        assert "srv01" in gotify_calls[0]["body"]["message"]

        # SSRF protection: pointing ntfy_url at internal Prometheus (:9090) must be blocked!
        secrets_path.write_text(
            json.dumps(
                {
                    "ntfy_url": "http://127.0.0.1:9090",
                    "ntfy_topic": "-/reload",
                }
            ),
            encoding="utf-8",
        )
        r_ssrf = await relay_client.post("/alert-relay/ntfy", json=am_webhook)
        assert r_ssrf.status in (400, 403, 502)
