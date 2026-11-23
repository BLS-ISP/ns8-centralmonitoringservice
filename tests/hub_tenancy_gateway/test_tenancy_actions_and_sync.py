from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from aiohttp import web
import jsonschema
import pytest

from hub_tenancy.bundle_renderer import generate_agent_bundle
from hub_tenancy.grafana_sync import sync_all_orgs, sync_all_orgs_if_running
from hub_tenancy.ldap_sync import sync_ldap_config

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "shared" / "schemas"
ACTIONS_DIR = REPO_ROOT / "hub" / "imageroot" / "actions"

TENANCY_ACTIONS = {
    "list-tenants": "20read",
    "save-tenant": "20save",
    "delete-tenant": "20delete",
    "rotate-token": "20rotate",
    "generate-agent-bundle": "20generate",
}


def load_schema(action: str, direction: str) -> dict:
    path = SCHEMAS_DIR / f"hub-{action}-{direction}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def run_ns8_action(action: str, payload: dict, state_dir: Path, extra_env: dict | None = None) -> tuple[int, str, str]:
    script_name = TENANCY_ACTIONS[action]
    script_path = ACTIONS_DIR / action / script_name
    jsonschema.validate(payload, load_schema(action, "input"))

    env = os.environ.copy()
    env["STATE_DIR"] = str(state_dir)
    env["TRAEFIK_HOST"] = "monitoring.msp.example.com"
    if extra_env:
        env.update(extra_env)

    proc = subprocess.run(
        [sys.executable, str(script_path)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=str(state_dir),
        env=env,
        check=False,
    )
    if proc.returncode == 0:
        out_json = json.loads(proc.stdout)
        jsonschema.validate(out_json, load_schema(action, "output"))
    return proc.returncode, proc.stdout, proc.stderr


class TestTenancyActionsAndSchemas:
    def test_action_schemas_match_shared_schemas_byte_for_byte(self):
        for action in TENANCY_ACTIONS:
            for direction in ("input", "output"):
                shared_bytes = (SCHEMAS_DIR / f"hub-{action}-{direction}.json").read_bytes()
                action_bytes = (ACTIONS_DIR / action / f"validate-{direction}.json").read_bytes()
                assert action_bytes == shared_bytes, f"Mismatch for {action}/validate-{direction}.json"

    def test_full_tenant_crud_rotation_redaction_and_alertmanager_hook(self, tmp_path):
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        # Create fake hub_alerting package on PYTHONPATH to verify cross-module sync_alertmanager hook
        fake_pypkg = tmp_path / "fake_pypkg"
        am_pkg = fake_pypkg / "hub_alerting"
        am_pkg.mkdir(parents=True)
        hook_marker = tmp_path / "am_synced.txt"
        (am_pkg / "__init__.py").write_bytes(b"")
        hook_path_repr = repr(str(hook_marker))
        am_stub = (
            "from pathlib import Path\n"
            "def sync_alertmanager(state_dir):\n"
            f"    Path({hook_path_repr}).write_bytes(str(state_dir).encode('utf-8'))\n"
        )
        (am_pkg / "alertmanager_config.py").write_bytes(am_stub.encode("utf-8"))
        extra_env = {"PYTHONPATH": str(fake_pypkg)}

        # 1. Create tenant
        rc, out, err = run_ns8_action(
            "save-tenant",
            {
                "customer": "acme-corp",
                "display_name": "Acme Corporation GmbH",
                "sites": ["hq", "dc-frankfurt"],
                "contact_emails": ["alerts@acme.example.com"],
                "customer_portal_enabled": True,
                "portal_viewer_username": "acme-viewer",
                "portal_viewer_password": "VeryStrongPassword123!",
                "notes": "24/7 Gold SLA",
            },
            state_dir,
            extra_env=extra_env,
        )
        assert rc == 0, err
        created_res = json.loads(out)
        assert created_res["created"] is True
        assert created_res["auth_token"].startswith("cms_v1_")
        raw_secret = created_res["auth_token"]
        assert hook_marker.exists()

        # Verify plaintext secret is NEVER persisted to disk
        disk_text = (state_dir / "tenants.json").read_text(encoding="utf-8")
        assert raw_secret not in disk_text
        assert "VeryStrongPassword123!" not in disk_text

        # 2. Update tenant -> created=False, auth_token=None
        rc, out, err = run_ns8_action(
            "save-tenant",
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp Updated",
                "sites": ["hq", "dc-frankfurt", "branch-munich"],
                "contact_emails": ["alerts@acme.example.com"],
                "customer_portal_enabled": True,
                "portal_viewer_username": "acme-viewer",
                "portal_viewer_password": "",
                "notes": "Updated sites",
            },
            state_dir,
            extra_env=extra_env,
        )
        assert rc == 0, err
        updated_res = json.loads(out)
        assert updated_res["created"] is False
        assert updated_res["auth_token"] is None

        # 3. List tenants (with search + pagination) -> redacted token_prefix only
        rc, out, err = run_ns8_action(
            "list-tenants",
            {"search": "updated", "page": 1, "page_size": 10},
            state_dir,
        )
        assert rc == 0, err
        listed = json.loads(out)
        assert listed["pagination"]["total_items"] == 1
        assert listed["tenants"][0]["display_name"] == "Acme Corp Updated"
        assert listed["tenants"][0]["token_prefix"].startswith("cms_v1_")
        assert raw_secret not in out

        # 4. Rotate token
        rc, out, err = run_ns8_action(
            "rotate-token",
            {"customer": "acme-corp", "grace_period_minutes": 120},
            state_dir,
        )
        assert rc == 0, err
        rot_res = json.loads(out)
        assert rot_res["auth_token"].startswith("cms_v1_")
        assert rot_res["auth_token"] != raw_secret
        assert rot_res["previous_token_expires_at"] is not None

        # 5. Generate agent bundles for linux, windows, docker via NS8 action
        for platform, expected_cfg, expected_inst in (
            ("linux", "config.alloy", "install-linux.sh"),
            ("windows", "config.alloy", "install-windows.ps1"),
            ("docker", "config.alloy", "docker-compose.yml"),
        ):
            rc, out, err = run_ns8_action(
                "generate-agent-bundle",
                {
                    "customer": "acme-corp",
                    "site": "dc-frankfurt",
                    "platform": platform,
                    "issue_dedicated_token": True,
                    "syslog_port": 5515,
                },
                state_dir,
            )
            assert rc == 0, err
            bundle = json.loads(out)
            assert bundle["config_filename"] == expected_cfg
            assert bundle["installer_filename"] == expected_inst
            assert re.search(r"\{\{[^{}]*\}\}", bundle["config_content"]) is None
            assert re.search(r"\{\{[^{}]*\}\}", bundle["installer_content"]) is None
            assert "\r\n" not in bundle["config_content"]
            assert "\r\n" not in bundle["installer_content"]
            assert "https://monitoring.msp.example.com" in bundle["config_content"]
            assert "acme-corp" in bundle["config_content"]
            assert "dc-frankfurt" in bundle["config_content"]

        # 6. Delete tenant
        hook_marker.unlink()
        rc, out, err = run_ns8_action(
            "delete-tenant",
            {"customer": "acme-corp", "delete_central_targets": True},
            state_dir,
            extra_env=extra_env,
        )
        assert rc == 0, err
        del_res = json.loads(out)
        assert del_res["deleted"] is True
        assert hook_marker.exists()

        # 7. Rotating token for deleted/non-existent tenant exits with NS8 validation status 2
        rc_missing, out_missing, _ = run_ns8_action(
            "rotate-token",
            {"customer": "acme-corp", "grace_period_minutes": 30},
            state_dir,
        )
        assert rc_missing == 2
        val_err = json.loads(out_missing)
        assert val_err[0]["error"] == "tenant_not_found"


class TestGrafanaOrgAndLdapSync:
    @pytest.mark.asyncio
    async def test_grafana_multi_org_sync_msp_org1_and_customer_portal_isolation(
        self, tmp_path, aiohttp_server
    ):
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        # Seed two tenants: acme-corp (portal enabled) and beta-gmbh (portal disabled)
        from hub_tenancy.store import save_tenant, load_tenants_raw

        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp",
                "sites": ["hq"],
                "contact_emails": [],
                "customer_portal_enabled": True,
                "portal_viewer_username": "acme-viewer",
                "portal_viewer_password": "AcmePortalPassword99!",
            },
        )
        save_tenant(
            state_dir,
            {
                "customer": "beta-gmbh",
                "display_name": "Beta GmbH",
                "sites": ["berlin"],
                "contact_emails": [],
                "customer_portal_enabled": False,
            },
        )

        # Stateful mock Grafana HTTP API tracking orgs, datasources, folders, dashboards, and users
        grafana_state = {
            "next_org_id": 2,
            "next_ds_id": 1,
            "next_user_id": 2,
            "orgs": {1: {"id": 1, "name": "Main Org."}},
            "datasources": {1: {}},  # org_id -> {uid -> ds_dict}
            "folders": {1: {}},
            "dashboards": {1: []},
            "users": {},  # login -> user_dict
            "org_users": {1: {}},  # org_id -> {user_id -> role}
            "disabled_users": set(),
        }

        g_app = web.Application()

        def org_id_from_req(req: web.Request) -> int:
            return int(req.headers.get("X-Grafana-Org-Id", "1"))

        async def api_health(_req: web.Request) -> web.Response:
            return web.json_response({"database": "ok"})

        async def get_orgs(_req: web.Request) -> web.Response:
            return web.json_response(list(grafana_state["orgs"].values()))

        async def get_org_by_id(req: web.Request) -> web.Response:
            oid = int(req.match_info["org_id"])
            if oid not in grafana_state["orgs"]:
                return web.json_response({"message": "Not found"}, status=404)
            return web.json_response(grafana_state["orgs"][oid])

        async def get_org_by_name(req: web.Request) -> web.Response:
            name = req.match_info["name"]
            for org in grafana_state["orgs"].values():
                if org["name"] == name:
                    return web.json_response(org)
            return web.json_response({"message": "Not found"}, status=404)

        async def create_org(req: web.Request) -> web.Response:
            body = await req.json()
            oid = grafana_state["next_org_id"]
            grafana_state["next_org_id"] += 1
            grafana_state["orgs"][oid] = {"id": oid, "name": body["name"]}
            grafana_state["datasources"][oid] = {}
            grafana_state["folders"][oid] = {}
            grafana_state["dashboards"][oid] = []
            grafana_state["org_users"][oid] = {}
            return web.json_response({"orgId": oid, "message": "Organization created"})

        async def update_org(req: web.Request) -> web.Response:
            oid = int(req.match_info["org_id"])
            body = await req.json()
            grafana_state["orgs"][oid]["name"] = body["name"]
            return web.json_response({"message": "Organization updated"})

        async def get_ds_by_uid(req: web.Request) -> web.Response:
            oid = org_id_from_req(req)
            uid = req.match_info["uid"]
            ds = grafana_state["datasources"].get(oid, {}).get(uid)
            if not ds:
                return web.json_response({"message": "Data source not found"}, status=404)
            return web.json_response(ds)

        async def create_ds(req: web.Request) -> web.Response:
            oid = org_id_from_req(req)
            body = await req.json()
            ds_id = grafana_state["next_ds_id"]
            grafana_state["next_ds_id"] += 1
            body["id"] = ds_id
            grafana_state["datasources"].setdefault(oid, {})[body["uid"]] = body
            return web.json_response({"datasource": body, "id": ds_id})

        async def update_ds(req: web.Request) -> web.Response:
            oid = org_id_from_req(req)
            ds_id = int(req.match_info["id"])
            body = await req.json()
            body["id"] = ds_id
            grafana_state["datasources"].setdefault(oid, {})[body["uid"]] = body
            return web.json_response({"datasource": body, "id": ds_id})

        async def get_folder(req: web.Request) -> web.Response:
            oid = org_id_from_req(req)
            uid = req.match_info["uid"]
            f = grafana_state["folders"].get(oid, {}).get(uid)
            if not f:
                return web.json_response({"message": "Folder not found"}, status=404)
            return web.json_response(f)

        async def create_folder(req: web.Request) -> web.Response:
            oid = org_id_from_req(req)
            body = await req.json()
            grafana_state["folders"].setdefault(oid, {})[body["uid"]] = body
            return web.json_response(body)

        async def post_dashboard(req: web.Request) -> web.Response:
            oid = org_id_from_req(req)
            body = await req.json()
            grafana_state["dashboards"].setdefault(oid, []).append(body["dashboard"])
            return web.json_response({"status": "success", "uid": body["dashboard"]["uid"]})

        async def lookup_user(req: web.Request) -> web.Response:
            login = req.query.get("loginOrEmail", "")
            u = grafana_state["users"].get(login)
            if not u:
                return web.json_response({"message": "User not found"}, status=404)
            return web.json_response(u)

        async def admin_create_user(req: web.Request) -> web.Response:
            body = await req.json()
            uid = grafana_state["next_user_id"]
            grafana_state["next_user_id"] += 1
            u = {"id": uid, "login": body["login"], "email": body.get("email", "")}
            grafana_state["users"][body["login"]] = u
            # Simulate Grafana default auto_assign_org=true placing new user in Org 1 initially!
            grafana_state["org_users"][1][uid] = "Viewer"
            target_org = body.get("OrgId")
            if target_org and target_org in grafana_state["org_users"]:
                grafana_state["org_users"][target_org][uid] = "Viewer"
            return web.json_response({"id": uid, "message": "User created"})

        async def admin_user_password(req: web.Request) -> web.Response:
            return web.json_response({"message": "User password updated"})

        async def admin_user_enable(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            grafana_state["disabled_users"].discard(uid)
            return web.json_response({"message": "User enabled"})

        async def admin_user_disable(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            grafana_state["disabled_users"].add(uid)
            return web.json_response({"message": "User disabled"})

        async def get_org_users(req: web.Request) -> web.Response:
            oid = int(req.match_info["org_id"])
            res = []
            for uid, role in grafana_state["org_users"].get(oid, {}).items():
                login = next((k for k, v in grafana_state["users"].items() if v["id"] == uid), "")
                res.append({"userId": uid, "login": login, "role": role})
            return web.json_response(res)

        async def add_org_user(req: web.Request) -> web.Response:
            oid = int(req.match_info["org_id"])
            body = await req.json()
            u = grafana_state["users"][body["loginOrEmail"]]
            grafana_state["org_users"].setdefault(oid, {})[u["id"]] = body["role"]
            return web.json_response({"message": "User added"})

        async def patch_org_user(req: web.Request) -> web.Response:
            oid = int(req.match_info["org_id"])
            uid = int(req.match_info["uid"])
            body = await req.json()
            grafana_state["org_users"].setdefault(oid, {})[uid] = body["role"]
            return web.json_response({"message": "User updated"})

        async def del_org_user(req: web.Request) -> web.Response:
            oid = int(req.match_info["org_id"])
            uid = int(req.match_info["uid"])
            if uid not in grafana_state["org_users"].get(oid, {}):
                return web.json_response({"message": "Not found"}, status=404)
            del grafana_state["org_users"][oid][uid]
            return web.json_response({"message": "User removed"})

        async def switch_user_org(_req: web.Request) -> web.Response:
            return web.json_response({"message": "Active organization changed"})

        g_app.router.add_get("/api/health", api_health)
        g_app.router.add_get("/api/orgs", get_orgs)
        g_app.router.add_get("/api/orgs/{org_id:\\d+}", get_org_by_id)
        g_app.router.add_get("/api/orgs/name/{name}", get_org_by_name)
        g_app.router.add_post("/api/orgs", create_org)
        g_app.router.add_put("/api/orgs/{org_id:\\d+}", update_org)
        g_app.router.add_get("/api/datasources/uid/{uid}", get_ds_by_uid)
        g_app.router.add_post("/api/datasources", create_ds)
        g_app.router.add_put("/api/datasources/{id:\\d+}", update_ds)
        g_app.router.add_get("/api/folders/{uid}", get_folder)
        g_app.router.add_post("/api/folders", create_folder)
        g_app.router.add_post("/api/dashboards/db", post_dashboard)
        g_app.router.add_get("/api/users/lookup", lookup_user)
        g_app.router.add_post("/api/admin/users", admin_create_user)
        g_app.router.add_put("/api/admin/users/{uid:\\d+}/password", admin_user_password)
        g_app.router.add_post("/api/admin/users/{uid:\\d+}/enable", admin_user_enable)
        g_app.router.add_post("/api/admin/users/{uid:\\d+}/disable", admin_user_disable)
        g_app.router.add_post("/api/admin/users/{uid:\\d+}/revoke-auth-token", admin_user_disable)
        g_app.router.add_get("/api/orgs/{org_id:\\d+}/users", get_org_users)
        g_app.router.add_post("/api/orgs/{org_id:\\d+}/users", add_org_user)
        g_app.router.add_patch("/api/orgs/{org_id:\\d+}/users/{uid:\\d+}", patch_org_user)
        g_app.router.add_delete("/api/orgs/{org_id:\\d+}/users/{uid:\\d+}", del_org_user)
        g_app.router.add_post("/api/users/{uid:\\d+}/using/{org_id:\\d+}", switch_user_org)

        g_srv = await aiohttp_server(g_app)
        grafana_url = f"http://127.0.0.1:{g_srv.port}"

        env = {
            "GRAFANA_URL": grafana_url,
            "GRAFANA_ADMIN_PASSWORD": "test-admin-password",
            "STORAGE_MODE": "s3",
            "PROMQL_UPSTREAM_URL": "http://127.0.0.1:10902",
        }

        # Run sync in executor so aiohttp mock server event loop serves the requests!
        import asyncio

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: sync_all_orgs(state_dir, env))
        assert result["synced"] is True

        # Verify Org 1 datasources & 4 dashboards
        org1_prom = grafana_state["datasources"][1]["prometheus"]
        assert org1_prom["url"] == "http://127.0.0.1:10902"
        assert org1_prom["editable"] is False

        org1_loki = grafana_state["datasources"][1]["loki"]
        assert org1_loki["url"] == "http://127.0.0.1:3100"
        assert org1_loki["editable"] is False
        assert org1_loki["jsonData"]["httpHeaderName1"] == "X-Scope-OrgID"
        assert org1_loki["secureJsonData"]["httpHeaderValue1"] == "acme-corp|beta-gmbh|_msp_internal"
        assert len(grafana_state["dashboards"][1]) == 4

        # Verify Customer Org 2 created for acme-corp with prom-label-proxy (:9095) and single-tenant Loki
        raw_tenants = load_tenants_raw(state_dir)
        acme_rec = next(t for t in raw_tenants if t["customer"] == "acme-corp")
        cust_org_id = acme_rec["grafana_org_id"]
        assert cust_org_id == 2
        assert grafana_state["orgs"][cust_org_id]["name"] == "Customer: Acme Corp (acme-corp)"

        cust_prom = grafana_state["datasources"][cust_org_id]["prometheus"]
        assert cust_prom["url"] == "http://127.0.0.1:9095"
        assert cust_prom["editable"] is False
        assert cust_prom["secureJsonData"]["httpHeaderValue1"] == "acme-corp"

        cust_loki = grafana_state["datasources"][cust_org_id]["loki"]
        assert cust_loki["url"] == "http://127.0.0.1:3100"
        assert cust_loki["editable"] is False
        assert cust_loki["secureJsonData"]["httpHeaderValue1"] == "acme-corp"

        # Verify Viewer user is strictly Viewer in Customer Org AND removed from Org 1!
        viewer_uid = grafana_state["users"]["acme-viewer"]["id"]
        assert grafana_state["org_users"][cust_org_id][viewer_uid] == "Viewer"
        assert viewer_uid not in grafana_state["org_users"][1]

        # Verify Customer Org dashboards are non-editable and lock/hide $customer to acme-corp
        assert len(grafana_state["dashboards"][cust_org_id]) == 4
        for dash in grafana_state["dashboards"][cust_org_id]:
            assert dash["editable"] is False
            cust_var = next(v for v in dash["templating"]["list"] if v["name"] == "customer")
            assert cust_var["type"] == "constant"
            assert cust_var["query"] == "acme-corp"
            assert cust_var["hide"] == 2

        # Toggling customer_portal_enabled=False revokes viewer access immediately
        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp",
                "sites": ["hq"],
                "contact_emails": [],
                "customer_portal_enabled": False,
                "portal_viewer_username": "acme-viewer",
            },
        )
        await loop.run_in_executor(None, lambda: sync_all_orgs_if_running(state_dir, env))
        assert viewer_uid not in grafana_state["org_users"][cust_org_id]
        assert viewer_uid in grafana_state["disabled_users"]

    def test_ldap_sync_renders_grafana_ldap_toml_scoped_to_org_1(self, tmp_path):
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        class FakeLdapproxy:
            def get_domain(self, domain: str) -> dict:
                assert domain == "ad.msp.example.com"
                return {
                    "host": "127.0.0.1",
                    "port": 20089,
                    "schema": "ad",
                    "base_dn": "DC=ad,DC=msp,DC=example,DC=com",
                    "bind_dn": "CN=ldapservice,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
                    "bind_password": 'Sec"ret\\Pass!',
                    "tls": False,
                }

        toml_path = sync_ldap_config(
            state_dir,
            {
                "LDAP_ENABLED": "true",
                "LDAP_DOMAIN": "ad.msp.example.com",
                "LDAP_ADMIN_GROUP": "CN=MSP Admins,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
                "LDAP_EDITOR_GROUP": "CN=MSP Techs,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
            },
            ldapproxy_factory=FakeLdapproxy,
        )
        assert toml_path is not None and toml_path.exists()
        content = toml_path.read_text(encoding="utf-8")
        assert 'host = "10.0.2.2"' in content
        assert "port = 20089" in content
        assert 'bind_password = "Sec\\"ret\\\\Pass!"' in content
        assert content.count("org_id = 1") >= 2
        assert "org_id = 2" not in content

    def test_bundle_renderer_rejects_injection_characters(self, tmp_path):
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)
        from hub_tenancy.store import save_tenant

        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme",
                "sites": ["hq"],
                "customer_portal_enabled": False,
            },
        )
        with pytest.raises(ValueError):
            generate_agent_bundle(
                state_dir,
                customer="acme-corp",
                site="hq",
                platform="linux",
                collector_id='bad"; rm -rf / #',
                hub_url="https://monitoring.msp.example.com",
            )


class TestStaticHygieneAndLFCompliance:
    def test_zero_crlf_zero_bom_and_no_pypkg_init(self):
        assert not (REPO_ROOT / "hub" / "imageroot" / "pypkg" / "__init__.py").exists()

        owned_roots = [
            REPO_ROOT / "hub" / "gateway",
            REPO_ROOT / "hub" / "imageroot" / "pypkg" / "hub_tenancy",
            *(ACTIONS_DIR / a for a in TENANCY_ACTIONS),
            REPO_ROOT / "tests" / "hub_tenancy_gateway",
        ]
        for root in owned_roots:
            assert root.exists(), f"Missing owned path: {root}"
            for p in root.rglob("*"):
                if p.is_file() and "__pycache__" not in p.parts:
                    raw = p.read_bytes()
                    assert not raw.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM in {p}"
                    assert b"\r\n" not in raw, f"CRLF line ending in {p}"

        containerfile = (REPO_ROOT / "hub" / "gateway" / "Containerfile").read_text(encoding="utf-8")
        assert "python:3.12-slim" in containerfile
        assert "USER " in containerfile

    def test_strict_python39_compatibility_across_all_owned_files(self):
        python_roots = [
            REPO_ROOT / "hub" / "gateway" / "hub_gateway",
            REPO_ROOT / "hub" / "imageroot" / "pypkg" / "hub_tenancy",
            *(ACTIONS_DIR / a for a in TENANCY_ACTIONS),
            REPO_ROOT / "tests" / "hub_tenancy_gateway",
        ]
        py_files = [
            p
            for root in python_roots
            for p in sorted(root.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".json")
        ]
        assert len(py_files) >= 24

        for p in py_files:
            src = p.read_text(encoding="utf-8")
            tree = ast.parse(src, filename=str(p), feature_version=(3, 9))

            has_future = any(
                isinstance(n, ast.ImportFrom)
                and n.module == "__future__"
                and any(a.name == "annotations" for a in n.names)
                for n in tree.body
            )
            assert has_future, f"Missing 'from __future__ import annotations' in {p}"

            for node in ast.walk(tree):
                if hasattr(ast, "Match"):
                    assert not isinstance(node, ast.Match), f"Python 3.10+ match/case in {p}:{node.lineno}"
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "write_text":
                        for kw in node.keywords:
                            assert kw.arg != "newline", (
                                f"Python 3.10+ Path.write_text(newline=...) in {p}:{node.lineno}"
                            )
                    for kw in node.keywords:
                        assert kw.arg not in (
                            "slots",
                            "kw_only",
                            "match_args",
                            "strict",
                        ), f"Python 3.10+ keyword '{kw.arg}=' in {p}:{node.lineno}"
                    if (
                        isinstance(node.func, ast.Name)
                        and node.func.id in ("isinstance", "issubclass")
                        and len(node.args) >= 2
                        and isinstance(node.args[1], ast.BinOp)
                        and isinstance(node.args[1].op, ast.BitOr)
                    ):
                        raise AssertionError(f"Python 3.10+ isinstance union in {p}:{node.lineno}")
                if isinstance(node, ast.Attribute):
                    assert node.attr != "UTC", f"Python 3.11+ datetime.UTC in {p}:{node.lineno}"
                    if node.attr == "walk" and not (
                        isinstance(node.value, ast.Name) and node.value.id in ("ast", "os")
                    ):
                        raise AssertionError(f"Python 3.12+ Path.walk in {p}:{node.lineno}")
                if sys.version_info >= (3, 12) and isinstance(node, ast.JoinedStr):
                    seg = ast.get_source_segment(src, node) or ""
                    stripped = seg.lstrip("rRfF")
                    is_triple = stripped.startswith('"""') or stripped.startswith("'''")
                    outer_q = stripped[:3] if is_triple else stripped[:1]
                    for val in node.values:
                        if isinstance(val, ast.FormattedValue):
                            vseg = ast.get_source_segment(src, val) or ""
                            inner = vseg[1:-1] if vseg.startswith("{") and vseg.endswith("}") else vseg
                            assert "\\" not in inner, f"PEP 701 backslash in f-string {p}:{node.lineno}"
                            if not is_triple:
                                assert "\n" not in inner, f"PEP 701 newline in f-string {p}:{node.lineno}"
                            if outer_q:
                                assert outer_q not in inner, (
                                    f"PEP 701 nested same-quote in f-string {p}:{node.lineno}"
                                )
