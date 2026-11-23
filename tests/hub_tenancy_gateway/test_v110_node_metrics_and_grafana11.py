"""v1.1.0 Tests: Loopback `GET /metrics/ns8-node` & Grafana 11 6-Dashboard Provisioning Sync."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from aiohttp import web
import pytest
from yarl import URL

import hub_gateway
from hub_gateway.alert_relay import AlertRelaySettings, create_alert_relay_app
from hub_gateway.app import GatewaySettings, create_gateway_app
from hub_tenancy.grafana_sync import DASHBOARD_FILENAMES, HOME_DASHBOARD_UID, sync_all_orgs
from hub_tenancy.store import save_portal_user, save_tenant


def _seed_six_dashboards(dash_dir: Path) -> None:
    dash_dir.mkdir(parents=True, exist_ok=True)
    interactive_vars = [
        {"name": "customer", "type": "query", "query": "label_values(up, customer)", "hide": 0, "multi": True},
        {"name": "site", "type": "query", "query": 'label_values(up{customer=~"$customer"}, site)', "hide": 0, "multi": True},
        {"name": "instance", "type": "query", "query": "label_values(up, instance)", "hide": 0, "multi": True},
        {"name": "module_id", "type": "query", "query": "label_values(ns8_module_up, module_id)", "hide": 0, "multi": True},
        {"name": "device_role", "type": "custom", "query": "ns8,linux,windows", "hide": 0, "multi": True},
        {"name": "job", "type": "query", "query": "label_values(job)", "hide": 0, "multi": True},
        {"name": "level", "type": "custom", "query": ".*", "hide": 0, "multi": False},
        {"name": "log_search", "type": "textbox", "query": "", "hide": 0},
    ]
    for idx, fname in enumerate(DASHBOARD_FILENAMES, start=1):
        uid = fname[:-5]
        doc = {
            "id": None,
            "uid": uid,
            "title": f"Dashboard {idx} ({uid})",
            "schemaVersion": 39,
            "editable": True,
            "templating": {"list": [dict(v) for v in interactive_vars]},
            "panels": [{"id": 1, "type": "stat", "title": "KPI", "datasource": {"uid": "prometheus"}}],
        }
        (dash_dir / fname).write_bytes(json.dumps(doc, indent=2).encode("utf-8"))


class TestV110NodeMetricsAndGrafana11Provisioning:
    @pytest.mark.asyncio
    async def test_loopback_ns8_node_metrics_warmup_and_live_textfile_isolated_from_public_gateway(
        self, tmp_path: Path, aiohttp_server: Any, aiohttp_client: Any
    ) -> None:
        assert hub_gateway.__version__ == "1.1.0"

        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        relay_app = create_alert_relay_app(AlertRelaySettings(state_dir=state_dir))
        relay_client = await aiohttp_client(relay_app)

        # 1. Warmup fallback before `collect-hub-ns8-metrics` writes `ns8-hub-node.prom`
        r_warm = await relay_client.get("/metrics/ns8-node")
        assert r_warm.status == 200
        assert r_warm.headers["Content-Type"] == "text/plain; version=0.0.4; charset=utf-8"
        warm_txt = await r_warm.text()
        assert warm_txt == "# Hub local NS8 telemetry warming up\n"

        # 2. Live textfile exposition
        prom_path = state_dir / "textfile" / "ns8-hub-node.prom"
        prom_path.parent.mkdir(parents=True)
        sample_metrics = (
            '# HELP ns8_module_up Active state of NS8 module cgroup slice.\n'
            '# TYPE ns8_module_up gauge\n'
            'ns8_module_up{module_id="central-monitoring-hub1",module_type="rootless"} 1\n'
            'ns8_module_memory_working_set_bytes{module_id="central-monitoring-hub1",module_type="rootless"} 268435456\n'
        )
        prom_path.write_bytes(sample_metrics.encode("utf-8"))

        r_live = await relay_client.get("/metrics/ns8-node")
        assert r_live.status == 200
        assert r_live.headers["Content-Type"] == "text/plain; version=0.0.4; charset=utf-8"
        live_txt = await r_live.text()
        assert live_txt == sample_metrics

        # 3. Public `:8080` gateway deterministically blocks `/metrics/*` with HTTP 403
        upstream_hits: list[str] = []
        g_app = web.Application()

        async def _g_any(req: web.Request) -> web.Response:
            upstream_hits.append(req.path)
            return web.Response(status=200, text="Grafana SPA")

        g_app.router.add_route("*", "/{tail:.*}", _g_any)
        g_srv = await aiohttp_server(g_app)
        gw_app = create_gateway_app(
            GatewaySettings(
                tenants_file=state_dir / "tenants.json",
                grafana_upstream_url=f"http://127.0.0.1:{g_srv.port}",
            )
        )
        gw_client = await aiohttp_client(gw_app)
        for blocked_path in ("/metrics/ns8-node", "//metrics//ns8-node", "/Metrics/ns8-node"):
            raw_url = URL.build(
                scheme="http",
                host="127.0.0.1",
                port=gw_client.port,
            ).with_path(blocked_path, encoded=True)
            r_pub = await gw_client.session.get(raw_url)
            pub_txt = await r_pub.text()
            assert r_pub.status == 403
            assert "ns8_module_up" not in pub_txt
        assert upstream_hits == []

    @pytest.mark.asyncio
    async def test_grafana11_six_dashboards_provisioned_400_resilience_and_customer_var_locking(
        self, tmp_path: Path, aiohttp_server: Any
    ) -> None:
        assert DASHBOARD_FILENAMES == (
            "ns8-multi-cluster-overview.json",
            "ns8-pods-and-modules.json",
            "linux-windows-servers.json",
            "proxmox-snmp-infrastructure.json",
            "web-ssl-uptime.json",
            "central-log-explorer.json",
        )

        state_dir = tmp_path / "state"
        dash_dir = tmp_path / "dashboards"
        state_dir.mkdir(parents=True)
        _seed_six_dashboards(dash_dir)

        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp",
                "sites": ["hq", "branch"],
                "customer_portal_enabled": True,
            },
        )
        save_portal_user(
            state_dir,
            {
                "customer": "acme-corp",
                "username": "acme.noc",
                "role": "Viewer",
                "password": "AcmeNocPassword!2026",
            },
        )

        orgs: dict[int, dict[str, Any]] = {1: {"id": 1, "name": "Main Org."}}
        users: dict[int, dict[str, Any]] = {}
        org_members: dict[int, dict[int, str]] = {1: {}}
        cust_dashboards: dict[int, list[dict[str, Any]]] = {}
        org_prefs: dict[int, dict[str, Any]] = {}
        dash_reloads: list[int] = []
        org1_400_hits: list[str] = []
        seq = {"org": 2, "user": 2}

        app = web.Application()

        def _oid(req: web.Request) -> int:
            return int(req.headers.get("X-Grafana-Org-Id", "1"))

        async def _health(_r: web.Request) -> web.Response:
            return web.json_response({"database": "ok"})

        async def _list_orgs(_r: web.Request) -> web.Response:
            return web.json_response(list(orgs.values()))

        async def _get_org(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            return web.json_response(orgs[oid]) if oid in orgs else web.json_response({}, status=404)

        async def _nf(_r: web.Request) -> web.Response:
            return web.json_response({}, status=404)

        async def _ok(_r: web.Request) -> web.Response:
            return web.json_response({"id": 1})

        async def _mk_org(r: web.Request) -> web.Response:
            b = await r.json()
            oid = seq["org"]
            seq["org"] += 1
            orgs[oid] = {"id": oid, "name": b["name"]}
            org_members[oid] = {}
            return web.json_response({"orgId": oid})

        async def _dash_reload(r: web.Request) -> web.Response:
            dash_reloads.append(_oid(r))
            return web.json_response({"message": "Dashboards config reloaded"})

        async def _post_dash(r: web.Request) -> web.Response:
            oid = _oid(r)
            b = await r.json()
            dash = b["dashboard"]
            if oid == 1:
                # Simulate real Grafana 11 file-provisioned Org 1 rejecting UI/API overwrites with HTTP 400!
                org1_400_hits.append(dash["uid"])
                return web.json_response(
                    {"message": "Cannot save provisioned dashboard"},
                    status=400,
                )
            cust_dashboards.setdefault(oid, []).append(dash)
            return web.json_response({"status": "success", "uid": dash["uid"]})

        async def _put_prefs(r: web.Request) -> web.Response:
            org_prefs[_oid(r)] = await r.json()
            return web.json_response({})

        async def _lookup_u(r: web.Request) -> web.Response:
            q = (r.query.get("loginOrEmail") or "").lower()
            for u in users.values():
                if u["login"].lower() == q:
                    return web.json_response(u)
            return web.json_response({}, status=404)

        async def _mk_u(r: web.Request) -> web.Response:
            b = await r.json()
            uid = seq["user"]
            seq["user"] += 1
            users[uid] = {"id": uid, "login": b["login"], "isGrafanaAdmin": False}
            org_members[1][uid] = "Viewer"
            return web.json_response({"id": uid})

        async def _get_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            return web.json_response(
                [
                    {"userId": uid, "login": users[uid]["login"], "role": role}
                    for uid, role in org_members.get(oid, {}).items()
                    if uid in users
                ]
            )

        async def _add_ou(r: web.Request) -> web.Response:
            b = await r.json()
            u = next(x for x in users.values() if x["login"].lower() == b["loginOrEmail"].lower())
            org_members.setdefault(int(r.match_info["oid"]), {})[u["id"]] = b["role"]
            return web.json_response({})

        async def _del_ou(r: web.Request) -> web.Response:
            org_members.get(int(r.match_info["oid"]), {}).pop(int(r.match_info["uid"]), None)
            return web.json_response({})

        app.router.add_get("/api/health", _health)
        app.router.add_get("/api/orgs", _list_orgs)
        app.router.add_get("/api/orgs/{oid:\\d+}", _get_org)
        app.router.add_get("/api/orgs/name/{name}", _nf)
        app.router.add_post("/api/orgs", _mk_org)
        app.router.add_put("/api/org/preferences", _put_prefs)
        app.router.add_post("/api/admin/provisioning/dashboards/reload", _dash_reload)
        app.router.add_get("/api/datasources/uid/{uid}", _nf)
        app.router.add_post("/api/datasources", _ok)
        app.router.add_get("/api/folders/{uid}", _ok)
        app.router.add_post("/api/dashboards/db", _post_dash)
        app.router.add_get("/api/users/lookup", _lookup_u)
        app.router.add_get("/api/users/{uid:\\d+}", _nf)
        app.router.add_post("/api/admin/users", _mk_u)
        app.router.add_put("/api/admin/users/{uid:\\d+}/password", _ok)
        app.router.add_post("/api/admin/users/{uid:\\d+}/{act}", _ok)
        app.router.add_post("/api/users/{uid:\\d+}/using/{oid:\\d+}", _ok)
        app.router.add_get("/api/orgs/{oid:\\d+}/users", _get_ou)
        app.router.add_post("/api/orgs/{oid:\\d+}/users", _add_ou)
        app.router.add_delete("/api/orgs/{oid:\\d+}/users/{uid:\\d+}", _del_ou)

        srv = await aiohttp_server(app)
        env = {
            "GRAFANA_URL": f"http://127.0.0.1:{srv.port}",
            "GRAFANA_ADMIN_PASSWORD": "pw",
            "DASHBOARDS_DIR": str(dash_dir),
        }
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, lambda: sync_all_orgs(state_dir, env))

        assert res == {"synced": True, "customer_orgs": 1}
        assert dash_reloads == [1]
        assert len(org1_400_hits) == 6
        assert org_prefs[1] == {"homeDashboardUID": HOME_DASHBOARD_UID}
        assert org_prefs[2] == {"homeDashboardUID": HOME_DASHBOARD_UID}

        # Customer Org 2 received all 6 locked dashboards AND isolated `acme.noc` user!
        assert [d["uid"] for d in cust_dashboards[2]] == [f[:-5] for f in DASHBOARD_FILENAMES]
        for dash in cust_dashboards[2]:
            assert dash["editable"] is False
            vars_by_name = {v["name"]: v for v in dash["templating"]["list"]}
            assert vars_by_name["customer"]["type"] == "constant"
            assert vars_by_name["customer"]["query"] == "acme-corp"
            assert vars_by_name["customer"]["hide"] == 2
            # All non-customer filter variables MUST remain interactive!
            for open_var in ("site", "instance", "module_id", "device_role", "job", "level", "log_search"):
                assert vars_by_name[open_var]["hide"] == 0
                assert vars_by_name[open_var]["type"] != "constant"

        noc_uid = next(u["id"] for u in users.values() if u["login"] == "acme.noc")
        assert org_members[2] == {noc_uid: "Viewer"}
        assert noc_uid not in org_members[1]
