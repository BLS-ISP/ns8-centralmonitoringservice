"""Regression tests for security audit (#24), E2E (#25), and architecture (#26) findings."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

from aiohttp import web
from multidict import CIMultiDict
import pytest
from yarl import URL

from hub_gateway.alert_relay import AlertRelaySettings, create_alert_relay_app
from hub_gateway.app import GatewaySettings, create_gateway_app
from hub_gateway.prom_remote_write import (
    COLLECTOR_RE,
    CUSTOMER_RE,
    LABEL_NAME_RE,
    SITE_RE,
    Sample,
    TimeSeries,
    build_write_request,
    parse_write_request,
)
from hub_gateway.snappy_codec import snappy_compress, snappy_decompress
from hub_tenancy.bundle_renderer import generate_agent_bundle
from hub_tenancy.grafana_sync import _parse_env_file, sync_all_orgs
from hub_tenancy.ldap_sync import sync_ldap_config
from hub_tenancy.store import mint_dedicated_collector_token, save_tenant

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTIONS_DIR = REPO_ROOT / "hub" / "imageroot" / "actions"


@pytest.mark.asyncio
class TestGatewayAuditRemediations:
    async def test_crit01_double_slash_and_datasource_proxy_allowlist(
        self, aiohttp_server, aiohttp_client, tmp_path
    ):
        upstream_hits: list[dict] = []
        g_app = web.Application()

        async def g_ws(req: web.Request) -> web.WebSocketResponse:
            ws = web.WebSocketResponse()
            await ws.prepare(req)
            await ws.send_str("ok")
            await ws.close()
            return ws

        async def g_any(req: web.Request) -> web.Response:
            upstream_hits.append({"method": req.method, "path": req.path, "headers": dict(req.headers)})
            headers = CIMultiDict()
            headers.add("Set-Cookie", "grafana_session=abc; HttpOnly")
            headers.add("Set-Cookie", "grafana_session_expiry=123; HttpOnly")
            return web.Response(status=200, text="ok", headers=headers)

        g_app.router.add_get("/api/live/ws", g_ws)
        g_app.router.add_get("/other/ws", g_ws)
        g_app.router.add_route("*", "/{tail:.*}", g_any)
        g_srv = await aiohttp_server(g_app)

        gw_app = create_gateway_app(
            GatewaySettings(
                tenants_file=tmp_path / "tenants.json",
                grafana_upstream_url=f"http://127.0.0.1:{g_srv.port}",
            )
        )
        client = await aiohttp_client(gw_app)

        # CRIT-01 & SEC-REVERIFY-01: Double-slash, single-dot (/./), case-variants (/API/..., /Metrics),
        # and dangerous datasource proxy subpaths/methods MUST all return 403 and NEVER reach Grafana
        forbidden_cases = [
            ("GET", "//metrics"),
            ("GET", "/./metrics"),
            ("GET", "/Metrics"),
            ("POST", "///-/reload"),
            ("POST", "/./-/Reload"),
            ("GET", "//api//v1//query?query=up"),
            ("GET", "/api/./datasources/proxy/uid/loki/config"),
            ("POST", "/api/./datasources/proxy/uid/loki/loki/api/v1/push"),
            ("GET", "/API/datasources/proxy/uid/loki/config"),
            ("POST", "/API/datasources/proxy/uid/loki/loki/api/v1/push"),
            ("POST", "/api/datasources/proxy/uid/loki/loki/api/v1/push"),
            ("POST", "/api/datasources/proxy/uid/prometheus/api/v1/write"),
            ("GET", "/api/datasources/proxy/uid/loki/config"),
            ("GET", "/api/datasources/proxy/uid/loki/metrics"),
            ("POST", "/api/datasources/proxy/uid/loki/flush"),
            ("GET", "/api/datasources/proxy/uid/loki/ring"),
            ("DELETE", "/api/datasources/proxy/uid/loki/loki/api/v1/query"),
            ("PUT", "/api/datasources/proxy/uid/prometheus/api/v1/query"),
            ("GET", "/api//datasources/proxy/uid/loki/loki//api/v1/delete"),
        ]
        for method, path in forbidden_cases:
            raw_url = URL.build(
                scheme="http",
                host="127.0.0.1",
                port=client.port,
            ).with_path(path.split("?", 1)[0], encoded=True)
            if "?" in path:
                raw_url = URL(f"http://127.0.0.1:{client.port}{path}", encoded=True)
            resp = await client.session.request(method, raw_url)
            assert resp.status == 403, f"Expected 403 for {method} {path}, got {resp.status}"

        assert len(upstream_hits) == 0

        # Legitimate read-only datasource proxy queries MUST pass
        allowed_cases = [
            ("POST", "/api/datasources/proxy/uid/prometheus/api/v1/query"),
            ("GET", "/api/datasources/proxy/uid/prometheus/api/v1/query_range?query=up"),
            ("GET", "/api/datasources/proxy/uid/prometheus/api/v1/label/site/values"),
            ("GET", "/api/datasources/proxy/uid/loki/loki/api/v1/query_range"),
            ("GET", "/api/datasources/proxy/uid/loki/loki/api/v1/label/job/values"),
            ("GET", "/api/datasources/proxy/uid/loki/loki/api/v1/index/stats"),
        ]
        for method, path in allowed_cases:
            resp = await client.request(
                method,
                path,
                headers={
                    "X-WEBAUTH-USER": "admin",
                    "X-Real-IP": "1.2.3.4",
                    "Connection": "keep-alive, X-Smuggled-Secret",
                    "X-Smuggled-Secret": "should-be-stripped",
                },
            )
            assert resp.status == 200, f"Expected 200 for {method} {path}, got {resp.status}"
            # HIGH-01: Multiple Set-Cookie headers preserved
            cookies = resp.headers.getall("Set-Cookie")
            assert len(cookies) == 2

        # HIGH-01: Verify X-WEBAUTH-*, X-Real-IP, and Connection-nominated headers were stripped
        forwarded_hdrs = {k.lower(): v for k, v in upstream_hits[0]["headers"].items()}
        assert "x-webauth-user" not in forwarded_hdrs
        assert "x-real-ip" not in forwarded_hdrs
        assert "x-smuggled-secret" not in forwarded_hdrs

        # HIGH-01: WebSocket upgrade restricted strictly to /api/live/ws
        ws_forbidden = await client.get(
            "/other/ws",
            headers={"Upgrade": "websocket", "Connection": "Upgrade"},
        )
        assert ws_forbidden.status == 403

    async def test_high01_rightmost_xff_rate_limiter_defeats_spoofing(
        self, aiohttp_client, tmp_path
    ):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        _, valid_tok = save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": False,
            },
        )
        gw_app = create_gateway_app(
            GatewaySettings(
                tenants_file=state_dir / "tenants.json",
                auth_rate_limit_max_failures=3,
                auth_rate_limit_window_seconds=300,
            )
        )
        client = await aiohttp_client(gw_app)

        # Attacker rotates fake leftmost XFF IPs, but Traefik appends attacker's real IP 198.51.100.77 rightmost
        for i in range(3):
            r = await client.get(
                "/api/v1/ingest/verify",
                headers={
                    "Authorization": "Bearer cms_v1_wrong_token_000000000000000000000000",
                    "X-Forwarded-For": f"10.99.0.{i}, 198.51.100.77",
                },
            )
            assert r.status == 401

        r_blocked = await client.get(
            "/api/v1/ingest/verify",
            headers={
                "Authorization": f"Bearer {valid_tok}",
                "X-Forwarded-For": "10.99.0.99, 198.51.100.77",
            },
        )
        assert r_blocked.status == 429

        # Victim whose IP was spoofed in the leftmost position is NOT locked out
        r_victim = await client.get(
            "/api/v1/ingest/verify",
            headers={
                "Authorization": f"Bearer {valid_tok}",
                "X-Forwarded-For": "203.0.113.10",
            },
        )
        assert r_victim.status == 200

    async def test_high02_alert_relay_ssrf_blocks_loopback_host_and_topic_traversal(
        self, aiohttp_client, tmp_path
    ):
        state_dir = tmp_path / "relay-state"
        state_dir.mkdir()
        secrets_path = state_dir / "alerting-secrets.json"

        # Default AlertRelaySettings has allow_loopback_upstream=False
        relay_app = create_alert_relay_app(AlertRelaySettings(state_dir=state_dir))
        client = await aiohttp_client(relay_app)
        webhook = {"status": "firing", "commonLabels": {"alertname": "Test"}, "alerts": []}

        ssrf_targets = [
            {"ntfy_url": "http://127.0.0.1:18888", "ntfy_topic": "alerts"},
            {"ntfy_url": "http://10.0.2.2:6379", "ntfy_topic": "alerts"},
            {"ntfy_url": "http://[::ffff:127.0.0.1]:8080", "ntfy_topic": "alerts"},
            {"ntfy_url": "http://0x7f000001:8080", "ntfy_topic": "alerts"},
            {"ntfy_url": "https://ntfy.sh", "ntfy_topic": "../admin/config"},
            {"ntfy_url": "https://ntfy.sh", "ntfy_topic": "alerts?poll=1"},
        ]
        for cfg in ssrf_targets:
            secrets_path.write_text(json.dumps(cfg), encoding="utf-8")
            resp = await client.post("/alert-relay/ntfy", json=webhook)
            assert resp.status in (400, 403), f"Expected SSRF block for {cfg}, got {resp.status}"

    async def test_sec_reverify02_dns_rebinding_blocked_at_connector_dial_time(
        self, aiohttp_server, aiohttp_client, tmp_path
    ):
        import socket
        import aiohttp
        from aiohttp.abc import AbstractResolver
        from hub_gateway.alert_relay import RELAY_HTTP_SESSION_KEY

        victim_hits: list[str] = []
        victim_app = web.Application()

        async def _victim_handler(req: web.Request) -> web.Response:
            victim_hits.append(req.path)
            return web.json_response({"ok": True})

        victim_app.router.add_post("/{tail:.*}", _victim_handler)
        victim_srv = await aiohttp_server(victim_app)

        class RebindingResolver(AbstractResolver):
            """Simulates TTL=0 DNS rebinding: 1st lookup returns public IP, 2nd returns 127.0.0.1."""

            def __init__(self) -> None:
                self.calls = 0

            async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
                self.calls += 1
                ip = "93.184.216.34" if self.calls == 1 else "127.0.0.1"
                return [
                    {
                        "hostname": host,
                        "host": ip,
                        "port": port,
                        "family": socket.AF_INET,
                        "proto": 0,
                        "flags": socket.AI_NUMERICHOST,
                    }
                ]

            async def close(self) -> None:
                pass

        state_dir = tmp_path / "rebind-state"
        state_dir.mkdir()
        (state_dir / "alerting-secrets.json").write_text(
            json.dumps(
                {
                    "ntfy_url": f"http://rebind.attacker.example:{victim_srv.port}",
                    "ntfy_topic": "alerts",
                }
            ),
            encoding="utf-8",
        )

        relay_settings = AlertRelaySettings(state_dir=state_dir, allow_loopback_upstream=False)
        relay_app = create_alert_relay_app(relay_settings)

        async def _inject_rebinding_resolver(app: web.Application) -> None:
            await app[RELAY_HTTP_SESSION_KEY].close()
            connector = aiohttp.TCPConnector(resolver=RebindingResolver())
            app[RELAY_HTTP_SESSION_KEY] = aiohttp.ClientSession(connector=connector)

        relay_app.on_startup.append(_inject_rebinding_resolver)
        client = await aiohttp_client(relay_app)

        resp = await client.post(
            "/alert-relay/ntfy",
            json={"status": "firing", "commonLabels": {"alertname": "Test"}, "alerts": []},
        )
        assert resp.status == 403
        assert victim_hits == []

    async def test_med02_bound_collector_id_overwrites_spoofed_collector_id(
        self, aiohttp_server, aiohttp_client, tmp_path
    ):
        received: list = []
        prom_app = web.Application()

        async def prom_w(req: web.Request) -> web.Response:
            raw = snappy_decompress(await req.read())
            received.append(parse_write_request(raw))
            return web.Response(status=204)

        prom_app.router.add_post("/api/v1/write", prom_w)
        prom_srv = await aiohttp_server(prom_app)

        state_dir = tmp_path / "state"
        state_dir.mkdir()
        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": False,
            },
        )
        ded_tok, _ = mint_dedicated_collector_token(
            state_dir,
            customer="acme-corp",
            site="hq",
            collector_id="acme-hq-srv01",
        )
        gw_app = create_gateway_app(
            GatewaySettings(
                tenants_file=state_dir / "tenants.json",
                prom_write_url=f"http://127.0.0.1:{prom_srv.port}/api/v1/write",
            )
        )
        client = await aiohttp_client(gw_app)

        # Compromised srv01 attempts to spoof collector_id="acme-hq-domain-controller"
        pb = build_write_request(
            [
                TimeSeries(
                    labels=[
                        ("__name__", "up"),
                        ("site", "hq"),
                        ("device_role", "linux"),
                        ("collector_id", "acme-hq-domain-controller"),
                    ],
                    samples=[Sample(1.0, 1700000000000)],
                )
            ]
        )
        resp = await client.post(
            "/api/v1/write",
            data=snappy_compress(pb),
            headers={"Authorization": f"Bearer {ded_tok}"},
        )
        assert resp.status == 204
        labels = dict(received[0][0].labels)
        assert labels["collector_id"] == "acme-hq-srv01"

    async def test_phase2_snmp_printer_device_role_accepted_on_metrics_and_logs(
        self, aiohttp_server, aiohttp_client, tmp_path
    ):
        from hub_gateway.loki_push import (
            LokiEntry,
            LokiStream,
            build_loki_push_request,
            parse_loki_label_selector,
            parse_loki_push_request,
        )

        prom_series: list = []
        loki_streams: list = []

        prom_app = web.Application()

        async def _prom_w(req: web.Request) -> web.Response:
            prom_series.extend(parse_write_request(snappy_decompress(await req.read())))
            return web.Response(status=204)

        prom_app.router.add_post("/api/v1/write", _prom_w)
        prom_srv = await aiohttp_server(prom_app)

        loki_app = web.Application()

        async def _loki_p(req: web.Request) -> web.Response:
            raw = await req.read()
            if "json" in req.headers.get("Content-Type", ""):
                loki_streams.append(json.loads(raw.decode("utf-8")))
            else:
                parsed = parse_loki_push_request(snappy_decompress(raw))
                loki_streams.append([parse_loki_label_selector(s.labels) for s in parsed])
            return web.Response(status=204)

        loki_app.router.add_post("/loki/api/v1/push", _loki_p)
        loki_srv = await aiohttp_server(loki_app)

        state_dir = tmp_path / "state"
        state_dir.mkdir()
        _, tok = save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": False,
            },
        )
        gw_app = create_gateway_app(
            GatewaySettings(
                tenants_file=state_dir / "tenants.json",
                prom_write_url=f"http://127.0.0.1:{prom_srv.port}/api/v1/write",
                loki_push_url=f"http://127.0.0.1:{loki_srv.port}/loki/api/v1/push",
            )
        )
        client = await aiohttp_client(gw_app)
        auth_hdr = {"Authorization": f"Bearer {tok}"}

        pb = build_write_request(
            [
                TimeSeries(
                    labels=[
                        ("__name__", "prtMarkerSuppliesLevel"),
                        ("site", "hq"),
                        ("device_role", "snmp-printer"),
                        ("collector_id", "acme-hq-col"),
                    ],
                    samples=[Sample(85.0, 1700000000000)],
                )
            ]
        )
        r_prom = await client.post("/api/v1/write", data=snappy_compress(pb), headers=auth_hdr)
        assert r_prom.status == 204
        assert dict(prom_series[0].labels)["device_role"] == "snmp-printer"
        assert dict(prom_series[0].labels)["customer"] == "acme-corp"

        loki_pb = build_loki_push_request(
            [
                LokiStream(
                    labels='{site="hq", device_role="snmp-printer", collector_id="acme-hq-col", job="syslog"}',
                    entries=[LokiEntry(1700000001, 0, "Toner low warning")],
                )
            ]
        )
        r_loki_pb = await client.post(
            "/loki/api/v1/push",
            data=snappy_compress(loki_pb),
            headers={**auth_hdr, "Content-Type": "application/x-protobuf"},
        )
        assert r_loki_pb.status == 204
        assert loki_streams[0][0]["device_role"] == "snmp-printer"

        r_loki_json = await client.post(
            "/loki/api/v1/push",
            json={
                "streams": [
                    {
                        "stream": {"site": "hq", "device_role": "snmp-printer", "job": "printer-syslog"},
                        "values": [["1700000002000000000", "Paper tray 2 empty"]],
                    }
                ]
            },
            headers=auth_hdr,
        )
        assert r_loki_json.status == 204
        assert loki_streams[1]["streams"][0]["stream"]["device_role"] == "snmp-printer"


class TestTenancyAndSyncAuditRemediations:
    def test_crit03_rejects_reserved_and_duplicate_portal_viewer_usernames(self, tmp_path):
        state_dir = tmp_path / "state"
        state_dir.mkdir()

        for reserved in ("admin", "ADMIN", "root"):
            with pytest.raises(ValueError):
                save_tenant(
                    state_dir,
                    {
                        "customer": "acme-corp",
                        "display_name": "Acme",
                        "sites": ["hq"],
                        "customer_portal_enabled": True,
                        "portal_viewer_username": reserved,
                        "portal_viewer_password": "StrongPassword123!",
                    },
                )

        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": True,
                "portal_viewer_username": "shared-viewer",
                "portal_viewer_password": "StrongPassword123!",
            },
        )
        with pytest.raises(ValueError, match="already in use"):
            save_tenant(
                state_dir,
                {
                    "customer": "beta-corp",
                    "display_name": "Beta",
                    "sites": ["hq"],
                    "customer_portal_enabled": True,
                    "portal_viewer_username": "SHARED-VIEWER",
                    "portal_viewer_password": "StrongPassword123!",
                },
            )

    @pytest.mark.asyncio
    async def test_crit03_grafana_sync_refuses_admin_and_cleans_renamed_viewer_and_other_orgs(
        self, tmp_path, aiohttp_server
    ):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": True,
                "portal_viewer_username": "acme-v1",
                "portal_viewer_password": "StrongPassword123!",
            },
        )

        # Mock Grafana with Org 1, stray Org 99 membership, and superadmin protection check
        orgs = {1: {"id": 1, "name": "Main Org."}, 99: {"id": 99, "name": "Other Org"}}
        users = {
            "admin": {"id": 1, "login": "admin", "isGrafanaAdmin": True},
        }
        org_members = {1: {1: "Admin"}, 99: {}}
        pw_updates: list[tuple[int, str]] = []
        next_ids = {"org": 2, "user": 2, "ds": 1}

        app = web.Application()

        async def _health(_r: web.Request) -> web.Response:
            return web.json_response({"database": "ok"})

        async def _list_orgs(_r: web.Request) -> web.Response:
            return web.json_response(list(orgs.values()))

        async def _get_org(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            return web.json_response(orgs[oid]) if oid in orgs else web.json_response({}, status=404)

        async def _not_found(_r: web.Request) -> web.Response:
            return web.json_response({}, status=404)

        async def _ok_ds(_r: web.Request) -> web.Response:
            return web.json_response({"id": 1})

        async def _ok_folder(_r: web.Request) -> web.Response:
            return web.json_response({"uid": "x"})

        async def _ok_dash(_r: web.Request) -> web.Response:
            return web.json_response({"status": "success"})

        async def _lookup(r: web.Request) -> web.Response:
            login = r.query.get("loginOrEmail")
            return web.json_response(users[login]) if login in users else web.json_response({}, status=404)

        async def _empty_ok(_r: web.Request) -> web.Response:
            return web.json_response({})

        async def _get_ou(r: web.Request) -> web.Response:
            return web.json_response(
                [{"userId": u, "role": role} for u, role in org_members.get(int(r.match_info["oid"]), {}).items()]
            )

        app.router.add_get("/api/health", _health)
        app.router.add_get("/api/orgs", _list_orgs)
        app.router.add_get("/api/orgs/{oid:\\d+}", _get_org)
        app.router.add_get("/api/orgs/name/{name}", _not_found)

        async def create_org(r: web.Request) -> web.Response:
            b = await r.json()
            oid = next_ids["org"]
            next_ids["org"] += 1
            orgs[oid] = {"id": oid, "name": b["name"]}
            org_members[oid] = {}
            return web.json_response({"orgId": oid})

        app.router.add_post("/api/orgs", create_org)
        app.router.add_get("/api/datasources/uid/{uid}", _not_found)
        app.router.add_post("/api/datasources", _ok_ds)
        app.router.add_get("/api/folders/{uid}", _ok_folder)
        app.router.add_post("/api/dashboards/db", _ok_dash)
        app.router.add_get("/api/users/lookup", _lookup)

        async def create_user(r: web.Request) -> web.Response:
            b = await r.json()
            # Assert temporary password used during creation is NOT the final customer password
            assert b["password"] != "StrongPassword123!"
            uid = next_ids["user"]
            next_ids["user"] += 1
            users[b["login"]] = {"id": uid, "login": b["login"], "isGrafanaAdmin": False}
            org_members[1][uid] = "Viewer"
            org_members[99][uid] = "Viewer"  # Simulate accidental cross-org membership
            return web.json_response({"id": uid})

        async def set_pw(r: web.Request) -> web.Response:
            uid = int(r.match_info["uid"])
            b = await r.json()
            # At the moment final password is set, user must ALREADY be removed from Org 1 and Org 99!
            assert uid not in org_members[1]
            assert uid not in org_members[99]
            pw_updates.append((uid, b["password"]))
            return web.json_response({"message": "ok"})

        app.router.add_post("/api/admin/users", create_user)
        app.router.add_put("/api/admin/users/{uid:\\d+}/password", set_pw)
        app.router.add_post("/api/admin/users/{uid:\\d+}/{act}", _empty_ok)
        app.router.add_get("/api/orgs/{oid:\\d+}/users", _get_ou)

        async def add_ou(r: web.Request) -> web.Response:
            b = await r.json()
            uid = users[b["loginOrEmail"]]["id"]
            org_members[int(r.match_info["oid"])][uid] = b["role"]
            return web.json_response({})

        async def del_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            uid = int(r.match_info["uid"])
            org_members.get(oid, {}).pop(uid, None)
            return web.json_response({})

        app.router.add_post("/api/orgs/{oid:\\d+}/users", add_ou)
        app.router.add_delete("/api/orgs/{oid:\\d+}/users/{uid:\\d+}", del_ou)
        app.router.add_post("/api/users/{uid:\\d+}/using/{oid:\\d+}", _empty_ok)

        srv = await aiohttp_server(app)
        env = {"GRAFANA_URL": f"http://127.0.0.1:{srv.port}", "GRAFANA_ADMIN_PASSWORD": "pw"}

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: sync_all_orgs(state_dir, env))
        v1_uid = users["acme-v1"]["id"]
        assert org_members[2] == {v1_uid: "Viewer"}
        assert pw_updates == [(v1_uid, "StrongPassword123!")]

        # Rename portal_viewer_username -> old user acme-v1 MUST be evicted from Customer Org 2!
        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": True,
                "portal_viewer_username": "acme-v2",
                "portal_viewer_password": "NewStrongPassword456!",
            },
        )
        await loop.run_in_executor(None, lambda: sync_all_orgs(state_dir, env))
        v2_uid = users["acme-v2"]["id"]
        assert v1_uid not in org_members[2]
        assert org_members[2] == {v2_uid: "Viewer"}

    def test_high03_and_med01_ldap_disabled_stub_and_no_wildcard_viewer(self, tmp_path):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        config_dir = tmp_path / "config"
        ldap_path = config_dir / "grafana" / "ldap.toml"
        ldap_path.parent.mkdir(parents=True)
        ldap_path.write_text("# initial\n", encoding="utf-8")

        # E2E-BUG-04 / ARCH-05: ldap_enabled=false MUST keep ldap.toml present as a 0600 comment stub
        res = sync_ldap_config(state_dir, {"LDAP_ENABLED": "false"})
        assert res is None
        assert ldap_path.exists()
        assert "LDAP disabled" in ldap_path.read_text(encoding="utf-8")

        # MED-01: When enabled with admin_group, wildcard group_dn = "*" MUST NOT exist
        class FakeLdap:
            def get_domain(self, _d: str) -> dict:
                return {
                    "port": 20389,
                    "schema": "ad",
                    "base_dn": "DC=example,DC=com",
                    "bind_dn": "",
                    "bind_password": "",
                }

        enabled_path = sync_ldap_config(
            state_dir,
            {"LDAP_ENABLED": "true", "LDAP_DOMAIN": "example.com", "LDAP_ADMIN_GROUP": "MSP Admins"},
            ldapproxy_factory=FakeLdap,
        )
        assert enabled_path == ldap_path
        toml_txt = ldap_path.read_text(encoding="utf-8")
        assert 'group_dn = "*"' not in toml_txt
        assert "org_id = 1" in toml_txt

    def test_high03_raw_secrets_env_parsing_and_e2e_bug03_agent_state_dir(self, tmp_path):
        # Raw Podman --env-file preserves quotes literally
        sec_file = tmp_path / "secrets.env"
        sec_file.write_text('GRAFANA_ADMIN_PASSWORD="My#Quoted$Pass"\n', encoding="utf-8")
        parsed = _parse_env_file(sec_file, strip_quotes=False)
        assert parsed["GRAFANA_ADMIN_PASSWORD"] == '"My#Quoted$Pass"'

        # E2E-BUG-03 / ARCH-07: Action scripts honor AGENT_STATE_DIR when cwd != AGENT_STATE_DIR
        agent_state = tmp_path / "ns8_agent_state"
        other_cwd = tmp_path / "other_cwd"
        agent_state.mkdir()
        other_cwd.mkdir()

        env = os.environ.copy()
        env.pop("STATE_DIR", None)
        env.pop("HUB_STATE_DIR", None)
        env["AGENT_STATE_DIR"] = str(agent_state)

        proc = subprocess.run(
            [sys.executable, str(ACTIONS_DIR / "save-tenant" / "20save")],
            input=json.dumps(
                {
                    "customer": "agent-dir-test",
                    "display_name": "Agent Dir Test",
                    "sites": ["hq"],
                    "customer_portal_enabled": False,
                }
            ),
            text=True,
            capture_output=True,
            cwd=str(other_cwd),
            env=env,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert (agent_state / "tenants.json").exists()
        assert not (other_cwd / "tenants.json").exists()

    def test_med02_strict_z_regex_anchors_and_https_only_bundle_url(self, tmp_path):
        # Trailing newline must be rejected by \Z anchors
        assert CUSTOMER_RE.match("acme-corp\n") is None
        assert SITE_RE.match("hq\n") is None
        assert COLLECTOR_RE.match("col-01\n") is None
        assert LABEL_NAME_RE.match("metric_name\n") is None

        state_dir = tmp_path / "state"
        state_dir.mkdir()
        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": False,
            },
        )
        # Plaintext http:// hub_url must be rejected in generate_agent_bundle
        with pytest.raises(ValueError, match="hub_url"):
            generate_agent_bundle(
                state_dir,
                customer="acme-corp",
                site="hq",
                platform="linux",
                hub_url="http://monitoring.msp.example.com",
            )

        # SEC-REVERIFY-03: Custom syslog_port != 5514 updates hardened 127.0.0.1:5514:5514 binding
        docker_bundle = generate_agent_bundle(
            state_dir,
            customer="acme-corp",
            site="hq",
            platform="docker",
            hub_url="https://monitoring.msp.example.com",
            syslog_port=6514,
        )
        assert '"127.0.0.1:6514:6514/udp"' in docker_bundle["installer_content"]
        assert '"127.0.0.1:6514:6514/tcp"' in docker_bundle["installer_content"]
        assert '"127.0.0.1:5514:5514/udp"' not in docker_bundle["installer_content"]

    def test_arch06_pod_netns_fallback_when_host_loopback_refused(self, monkeypatch):
        import hub_tenancy.grafana_sync as gs
        from urllib.error import URLError

        def fake_urlopen(_req, timeout=None):
            raise URLError("Connection refused")

        def fake_run(cmd, input=None, **_kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="4321\n", stderr="")
            req_spec = json.loads(input)
            assert req_spec["url"] == "http://127.0.0.1:3000/api/health"
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=json.dumps({"status": 200, "body": '{"database":"ok"}'}),
                stderr="",
            )

        monkeypatch.setattr(gs, "urlopen", fake_urlopen)
        monkeypatch.setattr(gs.os, "name", "posix")
        monkeypatch.setattr(gs.shutil, "which", lambda _b: "/usr/bin/podman")
        monkeypatch.setattr(gs.subprocess, "run", fake_run)

        client = gs.GrafanaApiClient("http://127.0.0.1:3000", "admin", "secret", timeout=1.0)
        assert client.is_healthy() is True
