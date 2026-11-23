"""v1.0.3 Tests: Org Home Dashboard, 1-Way MSP Staff Propagation & Multi-Org `ldap.toml` Sync."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from aiohttp import web
import pytest

from hub_tenancy.grafana_sync import HOME_DASHBOARD_UID, sync_all_orgs
from hub_tenancy.store import save_portal_user, save_tenant
from tests.hub_tenancy_gateway.test_tenancy_actions_and_sync import run_ns8_action
from tests.hub_tenancy_gateway.test_v102_ldap_and_portal_users import (
    MockLDAPv3Server,
    _sample_ad_directory_entries,
)


def _parse_toml_group_mappings(toml_text: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    parts = toml_text.split("[[servers.group_mappings]]")
    for raw_block in parts[1:]:
        item: dict[str, Any] = {}
        for raw_line in raw_block.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                break
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            key = k.strip()
            val = v.strip()
            if val.startswith('"') and val.endswith('"'):
                item[key] = val[1:-1]
            elif val in ("true", "false"):
                item[key] = val == "true"
            elif val.isdigit():
                item[key] = int(val)
            else:
                item[key] = val
        blocks.append(item)
    return blocks


class TestV103SimulatedCustomerViewAndMultiOrgSSO:
    @pytest.mark.asyncio
    async def test_org_home_dashboard_and_one_way_msp_staff_propagation_isolation(
        self, tmp_path: Path, aiohttp_server: Any
    ) -> None:
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp",
                "sites": ["hq"],
                "customer_portal_enabled": True,
            },
        )
        save_tenant(
            state_dir,
            {
                "customer": "beta-corp",
                "display_name": "Beta Corp",
                "sites": ["berlin"],
                "customer_portal_enabled": True,
            },
        )
        save_portal_user(
            state_dir,
            {
                "customer": "acme-corp",
                "username": "acme.portal",
                "role": "Viewer",
                "password": "AcmePortalPassword11!",
            },
        )
        save_portal_user(
            state_dir,
            {
                "customer": "beta-corp",
                "username": "beta.portal",
                "role": "Editor",
                "password": "BetaPortalPassword22!",
            },
        )

        # Pre-seed Org 1 with:
        #   uid=1: built-in `admin` (`isGrafanaAdmin=True`) -> Customer Org `Admin`
        #   uid=10: LDAP Org-1 Admin `ad.boss` (`isExternal=True`) -> Customer Org `Admin`
        #   uid=11: LDAP Org-1 Editor `ad.genera` (`authLabels=["LDAP"]`) -> Customer Org `Viewer`
        #   uid=12: LDAP Org-1 Viewer `ad.readonly` (`authLabels=["LDAP"]`) -> Customer Org `Viewer`
        #   uid=13: Unverified local non-admin `stray.local` -> MUST NOT propagate!
        users: dict[int, dict[str, Any]] = {
            1: {"id": 1, "login": "admin", "isGrafanaAdmin": True, "isExternal": False, "authLabels": []},
            10: {"id": 10, "login": "ad.boss", "isGrafanaAdmin": True, "isExternal": True, "authLabels": ["LDAP"]},
            11: {"id": 11, "login": "ad.genera", "isGrafanaAdmin": False, "isExternal": True, "authLabels": ["LDAP"]},
            12: {"id": 12, "login": "ad.readonly", "isGrafanaAdmin": False, "isExternal": True, "authLabels": ["LDAP"]},
            13: {"id": 13, "login": "stray.local", "isGrafanaAdmin": False, "isExternal": False, "authLabels": []},
        }
        orgs: dict[int, dict[str, Any]] = {1: {"id": 1, "name": "Main Org."}}
        org_members: dict[int, dict[int, str]] = {
            1: {
                1: "Admin",
                10: "Admin",
                11: "Editor",
                12: "Viewer",
                13: "Viewer",
            }
        }
        org_prefs: dict[int, dict[str, Any]] = {}
        using_org_calls: list[tuple[int, int]] = []
        seq = {"org": 2, "user": 20}

        app = web.Application()

        def _req_oid(req: web.Request) -> int:
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

        async def _empty(_r: web.Request) -> web.Response:
            return web.json_response({})

        async def _mk_org(r: web.Request) -> web.Response:
            b = await r.json()
            oid = seq["org"]
            seq["org"] += 1
            orgs[oid] = {"id": oid, "name": b["name"]}
            org_members[oid] = {}
            return web.json_response({"orgId": oid})

        async def _put_prefs(r: web.Request) -> web.Response:
            oid = _req_oid(r)
            org_prefs[oid] = await r.json()
            return web.json_response({"message": "Preferences updated"})

        async def _get_user(r: web.Request) -> web.Response:
            uid = int(r.match_info["uid"])
            return web.json_response(users[uid]) if uid in users else web.json_response({}, status=404)

        async def _lookup_user(r: web.Request) -> web.Response:
            q = (r.query.get("loginOrEmail") or "").lower()
            for u in users.values():
                if u["login"].lower() == q:
                    return web.json_response(u)
            return web.json_response({}, status=404)

        async def _mk_user(r: web.Request) -> web.Response:
            b = await r.json()
            uid = seq["user"]
            seq["user"] += 1
            users[uid] = {
                "id": uid,
                "login": b["login"],
                "name": b.get("name", ""),
                "email": b.get("email", ""),
                "isGrafanaAdmin": False,
                "isExternal": False,
                "authLabels": [],
            }
            org_members[1][uid] = "Viewer"
            return web.json_response({"id": uid})

        async def _get_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            return web.json_response(
                [
                    {
                        "userId": uid,
                        "login": users[uid]["login"],
                        "role": role,
                        "authLabels": users[uid].get("authLabels", []),
                    }
                    for uid, role in org_members.get(oid, {}).items()
                    if uid in users
                ]
            )

        async def _add_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            b = await r.json()
            u = next(x for x in users.values() if x["login"].lower() == b["loginOrEmail"].lower())
            org_members.setdefault(oid, {})[u["id"]] = b["role"]
            return web.json_response({})

        async def _patch_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            uid = int(r.match_info["uid"])
            b = await r.json()
            org_members.setdefault(oid, {})[uid] = b["role"]
            return web.json_response({})

        async def _del_ou(r: web.Request) -> web.Response:
            org_members.get(int(r.match_info["oid"]), {}).pop(int(r.match_info["uid"]), None)
            return web.json_response({})

        async def _using_org(r: web.Request) -> web.Response:
            using_org_calls.append((int(r.match_info["uid"]), int(r.match_info["oid"])))
            return web.json_response({})

        async def _ds_ok(_r: web.Request) -> web.Response:
            return web.json_response({"id": 1})

        async def _fld_ok(_r: web.Request) -> web.Response:
            return web.json_response({"uid": "f"})

        async def _dsh_ok(_r: web.Request) -> web.Response:
            return web.json_response({"status": "success"})

        app.router.add_get("/api/health", _health)
        app.router.add_get("/api/orgs", _list_orgs)
        app.router.add_get("/api/orgs/{oid:\\d+}", _get_org)
        app.router.add_get("/api/orgs/name/{name}", _nf)
        app.router.add_post("/api/orgs", _mk_org)
        app.router.add_put("/api/org/preferences", _put_prefs)
        app.router.add_get("/api/datasources/uid/{uid}", _nf)
        app.router.add_post("/api/datasources", _ds_ok)
        app.router.add_get("/api/folders/{uid}", _fld_ok)
        app.router.add_post("/api/dashboards/db", _dsh_ok)
        app.router.add_get("/api/users/lookup", _lookup_user)
        app.router.add_get("/api/users/{uid:\\d+}", _get_user)
        app.router.add_put("/api/users/{uid:\\d+}", _empty)
        app.router.add_post("/api/admin/users", _mk_user)
        app.router.add_put("/api/admin/users/{uid:\\d+}/password", _empty)
        app.router.add_post("/api/admin/users/{uid:\\d+}/{act}", _empty)
        app.router.add_post("/api/users/{uid:\\d+}/using/{oid:\\d+}", _using_org)
        app.router.add_get("/api/orgs/{oid:\\d+}/users", _get_ou)
        app.router.add_post("/api/orgs/{oid:\\d+}/users", _add_ou)
        app.router.add_patch("/api/orgs/{oid:\\d+}/users/{uid:\\d+}", _patch_ou)
        app.router.add_delete("/api/orgs/{oid:\\d+}/users/{uid:\\d+}", _del_ou)

        srv = await aiohttp_server(app)
        env = {"GRAFANA_URL": f"http://127.0.0.1:{srv.port}", "GRAFANA_ADMIN_PASSWORD": "pw"}
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, lambda: sync_all_orgs(state_dir, env))
        assert res["synced"] is True
        assert res["customer_orgs"] == 2

        acme_oid = next(oid for oid, o in orgs.items() if "(acme-corp)" in o["name"])
        beta_oid = next(oid for oid, o in orgs.items() if "(beta-corp)" in o["name"])
        acme_portal_uid = next(u["id"] for u in users.values() if u["login"] == "acme.portal")
        beta_portal_uid = next(u["id"] for u in users.values() if u["login"] == "beta.portal")

        # 1. Home dashboard `ns8-multi-cluster-overview` set on Org 1 AND both Customer Orgs!
        assert org_prefs[1] == {"homeDashboardUID": HOME_DASHBOARD_UID}
        assert org_prefs[acme_oid] == {"homeDashboardUID": HOME_DASHBOARD_UID}
        assert org_prefs[beta_oid] == {"homeDashboardUID": HOME_DASHBOARD_UID}

        # 2. Verified MSP staff propagated 1-way (`Admin` -> `Admin`, `Editor`/`Viewer` -> `Viewer`)
        #    while unverified local account `stray.local` (uid=13) and cross-tenant portal users NEVER leak!
        assert org_members[acme_oid] == {
            acme_portal_uid: "Viewer",
            1: "Admin",
            10: "Admin",
            11: "Viewer",
            12: "Viewer",
        }
        assert org_members[beta_oid] == {
            beta_portal_uid: "Editor",
            1: "Admin",
            10: "Admin",
            11: "Viewer",
            12: "Viewer",
        }
        assert acme_portal_uid not in org_members[1]
        assert beta_portal_uid not in org_members[1]
        assert 13 not in org_members[acme_oid]
        assert 13 not in org_members[beta_oid]

        # 3. Default active org (`/api/users/<uid>/using/<oid>`) NEVER switched for MSP staff!
        switched_uids = {uid for uid, _ in using_org_calls}
        assert switched_uids == {acme_portal_uid, beta_portal_uid}

        # 4. Drift healing: if `ad.genera` (uid=11) was manually bumped to `Editor` in Customer Org,
        #    next sync_all_orgs patches `ad.genera` back to `Viewer`!
        org_members[acme_oid][11] = "Editor"
        await loop.run_in_executor(None, lambda: sync_all_orgs(state_dir, env))
        assert org_members[acme_oid][11] == "Viewer"

    @pytest.mark.asyncio
    async def test_ldap_toml_multi_org_mappings_synced_across_save_and_delete_tenant_lifecycle(
        self, tmp_path: Path, aiohttp_server: Any
    ) -> None:
        state_dir = tmp_path / "state"
        config_dir = tmp_path / "config"
        state_dir.mkdir(parents=True)
        config_dir.mkdir(parents=True)

        ldap_srv = MockLDAPv3Server(entries=_sample_ad_directory_entries(), emit_referral=False)
        ldap_srv.start()

        orgs: dict[int, dict[str, Any]] = {1: {"id": 1, "name": "Main Org."}}
        ldap_reloads: list[int] = []
        seq = {"org": 2}

        g_app = web.Application()

        async def _health(_r: web.Request) -> web.Response:
            return web.json_response({"database": "ok"})

        async def _list_orgs(_r: web.Request) -> web.Response:
            return web.json_response(list(orgs.values()))

        async def _get_org(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            return web.json_response(orgs[oid]) if oid in orgs else web.json_response({}, status=404)

        async def _del_org(r: web.Request) -> web.Response:
            orgs.pop(int(r.match_info["oid"]), None)
            return web.json_response({})

        async def _mk_org(r: web.Request) -> web.Response:
            b = await r.json()
            oid = seq["org"]
            seq["org"] += 1
            orgs[oid] = {"id": oid, "name": b["name"]}
            return web.json_response({"orgId": oid})

        async def _nf(_r: web.Request) -> web.Response:
            return web.json_response({}, status=404)

        async def _ok(_r: web.Request) -> web.Response:
            return web.json_response({"id": 1, "status": "success"})

        async def _empty_list(_r: web.Request) -> web.Response:
            return web.json_response([])

        async def _ldap_reload(_r: web.Request) -> web.Response:
            ldap_reloads.append(1)
            return web.json_response({"message": "reloaded"})

        g_app.router.add_get("/api/health", _health)
        g_app.router.add_get("/api/orgs", _list_orgs)
        g_app.router.add_get("/api/orgs/{oid:\\d+}", _get_org)
        g_app.router.add_delete("/api/orgs/{oid:\\d+}", _del_org)
        g_app.router.add_get("/api/orgs/name/{name}", _nf)
        g_app.router.add_post("/api/orgs", _mk_org)
        g_app.router.add_put("/api/org/preferences", _ok)
        g_app.router.add_get("/api/datasources/uid/{uid}", _nf)
        g_app.router.add_post("/api/datasources", _ok)
        g_app.router.add_get("/api/folders/{uid}", _ok)
        g_app.router.add_post("/api/dashboards/db", _ok)
        g_app.router.add_get("/api/orgs/{oid:\\d+}/users", _empty_list)
        g_app.router.add_post("/api/admin/provisioning/ldap/reload", _ldap_reload)

        g_srv = await aiohttp_server(g_app)

        # Inject a fake `agent.ldapproxy` module on PYTHONPATH so subprocess `save-tenant` and
        # `delete-tenant` execute `sync_ldap_config` end-to-end!
        fake_pypkg = tmp_path / "fake_agent_pkg"
        agent_dir = fake_pypkg / "agent"
        agent_dir.mkdir(parents=True)
        (agent_dir / "__init__.py").write_bytes(b"from __future__ import annotations\n")
        lp_code = (
            "from __future__ import annotations\n"
            "class Ldapproxy:\n"
            "    def get_domain(self, domain: str) -> dict:\n"
            "        return {\n"
            '            "host": "127.0.0.1",\n'
            f'            "port": {ldap_srv.port},\n'
            '            "schema": "ad",\n'
            '            "base_dn": "DC=ad,DC=bls-isp,DC=net",\n'
            '            "bind_dn": "",\n'
            '            "bind_password": "",\n'
            "        }\n"
        )
        (agent_dir / "ldapproxy.py").write_bytes(lp_code.encode("utf-8"))

        extra_env = {
            "PYTHONPATH": str(fake_pypkg),
            "GRAFANA_URL": f"http://127.0.0.1:{g_srv.port}",
            "GRAFANA_ADMIN_PASSWORD": "pw",
            "HUB_CONFIG_DIR": str(config_dir),
            "LDAP_ENABLED": "true",
            "LDAP_DOMAIN": "ad.bls-isp.net",
            "LDAP_ADMIN_GROUP": "Domain Admins",
            "LDAP_EDITOR_GROUP": "MSP Operations",
            "LDAP_VIEWER_GROUP": "MSP ReadOnly",
        }
        loop = asyncio.get_running_loop()

        async def _act(action: str, payload: dict[str, Any]) -> tuple[int, str, str]:
            return await loop.run_in_executor(
                None,
                lambda: run_ns8_action(action, payload, state_dir, extra_env=extra_env),
            )

        try:
            # 1. Create `acme-corp` (portal ON -> oid=2), `beta-corp` (portal ON -> oid=3), `gamma-corp` (portal OFF)
            rc1, out1, err1 = await _act(
                "save-tenant",
                {
                    "customer": "acme-corp",
                    "display_name": "Acme Corp",
                    "sites": ["hq"],
                    "customer_portal_enabled": True,
                },
            )
            assert rc1 == 0, err1
            assert json.loads(out1)["grafana_org_id"] == 2

            rc2, out2, err2 = await _act(
                "save-tenant",
                {
                    "customer": "beta-corp",
                    "display_name": "Beta Corp",
                    "sites": ["hq"],
                    "customer_portal_enabled": True,
                },
            )
            assert rc2 == 0, err2
            assert json.loads(out2)["grafana_org_id"] == 3

            rc3, _, err3 = await _act(
                "save-tenant",
                {
                    "customer": "gamma-corp",
                    "display_name": "Gamma Corp",
                    "sites": ["hq"],
                    "customer_portal_enabled": False,
                },
            )
            assert rc3 == 0, err3

            ldap_toml_path = config_dir / "grafana" / "ldap.toml"
            assert ldap_toml_path.is_file()
            mappings = _parse_toml_group_mappings(ldap_toml_path.read_text(encoding="utf-8"))

            da_dn = "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"
            ops_dn = "CN=MSP Operations,OU=Groups,DC=ad,DC=bls-isp,DC=net"
            ro_dn = "CN=MSP ReadOnly,OU=Groups,DC=ad,DC=bls-isp,DC=net"

            assert mappings == [
                {"group_dn": da_dn, "org_role": "Admin", "grafana_admin": True, "org_id": 1},
                {"group_dn": ops_dn, "org_role": "Editor", "org_id": 1},
                {"group_dn": ro_dn, "org_role": "Viewer", "org_id": 1},
                {"group_dn": da_dn, "org_role": "Admin", "org_id": 2},
                {"group_dn": ops_dn, "org_role": "Viewer", "org_id": 2},
                {"group_dn": ro_dn, "org_role": "Viewer", "org_id": 2},
                {"group_dn": da_dn, "org_role": "Admin", "org_id": 3},
                {"group_dn": ops_dn, "org_role": "Viewer", "org_id": 3},
                {"group_dn": ro_dn, "org_role": "Viewer", "org_id": 3},
            ]
            assert len(ldap_reloads) >= 3

            # 2. Disabling `beta-corp` portal removes `org_id = 3` from `ldap.toml` immediately
            rc_dis, _, err_dis = await _act(
                "save-tenant",
                {
                    "customer": "beta-corp",
                    "display_name": "Beta Corp",
                    "sites": ["hq"],
                    "customer_portal_enabled": False,
                },
            )
            assert rc_dis == 0, err_dis
            mappings_after_dis = _parse_toml_group_mappings(ldap_toml_path.read_text(encoding="utf-8"))
            assert {m["org_id"] for m in mappings_after_dis} == {1, 2}

            # 3. Deleting `acme-corp` removes `org_id = 2` from `ldap.toml` immediately
            rc_del, _, err_del = await _act(
                "delete-tenant",
                {"customer": "acme-corp", "delete_central_targets": False},
            )
            assert rc_del == 0, err_del
            mappings_after_del = _parse_toml_group_mappings(ldap_toml_path.read_text(encoding="utf-8"))
            assert [m["org_id"] for m in mappings_after_del] == [1, 1, 1]
        finally:
            ldap_srv.stop()
