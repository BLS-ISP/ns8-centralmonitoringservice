"""Idempotent Grafana Multi-Org, Datasource, Dashboard & Portal Viewer Provisioner.

Provisions:
1. MSP Main Org (Org 1):
   - `Prometheus` (`uid: "prometheus"`, `${PROMQL_UPSTREAM_URL}`, `editable: false`)
   - `Loki` (`uid: "loki"`, `http://127.0.0.1:3100`, `X-Scope-OrgID: slug1|slug2|_msp_internal`)
   - Folder `MSP Central Monitoring` + all 4 starter dashboards from `shared/dashboards/`
2. Customer Portal Organizations (`customer_portal_enabled: true`):
   - Dedicated Org `Customer: <display_name> (<customer>)`
   - `Prometheus` pointing strictly to `prom-label-proxy` (`http://127.0.0.1:9095`, `X-Scope-OrgID: <customer>`)
   - `Loki` pointing to `http://127.0.0.1:3100` (`X-Scope-OrgID: <customer>`)
   - `<portal_viewer_username>` granted strictly `Viewer` in Customer Org, stripped from all
     other Orgs (including Org 1), protected against superadmin/external account collisions,
     and provisioned with temporary password before Org isolation completes.
"""

from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from hub_tenancy.store import (
    RESERVED_PORTAL_USERNAMES,
    clear_previous_portal_viewer_username,
    load_portal_viewer_secret,
    load_tenants_raw,
    update_tenant_grafana_org_id,
)

DASHBOARD_FILENAMES = (
    "ns8-multi-cluster-overview.json",
    "linux-windows-servers.json",
    "proxmox-snmp-infrastructure.json",
    "web-ssl-uptime.json",
)

_POD_NSENTER_HTTP_HELPER = (
    "import base64, json, sys, urllib.error, urllib.request\n"
    "req_spec = json.loads(sys.stdin.read())\n"
    "data = base64.b64decode(req_spec['body_b64']) if req_spec.get('body_b64') else None\n"
    "req = urllib.request.Request(req_spec['url'], data=data, headers=req_spec['headers'], method=req_spec['method'])\n"
    "try:\n"
    "    with urllib.request.urlopen(req, timeout=req_spec['timeout']) as r:\n"
    "        sys.stdout.write(json.dumps({'status': r.status, 'body': r.read().decode('utf-8')}))\n"
    "except urllib.error.HTTPError as e:\n"
    "    body = e.read().decode('utf-8', errors='replace')\n"
    "    sys.stdout.write(json.dumps({'status': e.code, 'body': body, 'http_error': True}))\n"
)


def _parse_env_file(path: Path, *, strip_quotes: bool = True) -> dict[str, str]:
    """Parse KEY=VALUE lines; `strip_quotes=False` matches Podman `--env-file` raw semantics."""
    result: dict[str, str] = {}
    if not path.exists():
        return result
    try:
        raw_text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        for raw_line in raw_text.split("\n"):
            stripped_leading = raw_line.lstrip()
            if not stripped_leading or stripped_leading.startswith("#") or "=" not in raw_line:
                continue
            k, v = raw_line.split("=", 1)
            key = k.strip()
            if not key:
                continue
            if strip_quotes:
                v_clean = v.strip()
                if len(v_clean) >= 2 and v_clean[0] == v_clean[-1] and v_clean[0] in ('"', "'"):
                    inner = v_clean[1:-1]
                    if v_clean[0] == '"':
                        inner = (
                            inner.replace('\\"', '"')
                            .replace("\\n", "\n")
                            .replace("\\\\", "\\")
                        )
                    v_clean = inner
                result[key] = v_clean
            else:
                result[key] = v
    except OSError:
        pass
    return result


def _merged_env(state_dir: Path, env: Mapping[str, str] | None) -> dict[str, str]:
    merged: dict[str, str] = {}
    merged.update(_parse_env_file(state_dir / "environment", strip_quotes=True))
    merged.update(_parse_env_file(state_dir / "secrets.env", strip_quotes=False))
    if "GRAFANA_ADMIN_PASSWORD" not in merged and "GF_SECURITY_ADMIN_PASSWORD" in merged:
        merged["GRAFANA_ADMIN_PASSWORD"] = merged["GF_SECURITY_ADMIN_PASSWORD"]
    merged.update(os.environ)
    if env:
        for k, v in env.items():
            if v is not None:
                merged[str(k)] = str(v)
    return merged


def _resolve_dashboards_dir(state_dir: Path, env_map: Mapping[str, str]) -> Path:
    explicit = env_map.get("DASHBOARDS_DIR")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            state_dir.parent / "etc" / "shared" / "dashboards",
            Path(__file__).resolve().parents[2] / "etc" / "shared" / "dashboards",
            Path("/imageroot/etc/shared/dashboards"),
            Path(__file__).resolve().parents[4] / "shared" / "dashboards",
        ]
    )
    for cand in candidates:
        if cand.is_dir() and any(cand.glob("*.json")):
            return cand
    return candidates[-1]


def _find_pod_pid() -> str | None:
    if os.name == "nt":
        return None
    podman_bin = shutil.which("podman")
    if not podman_bin:
        return None
    for cname in ("grafana", "central-monitoring-hub-grafana", "hub-gateway"):
        try:
            proc = subprocess.run(
                [podman_bin, "container", "inspect", "-f", "{{.State.Pid}}", cname],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            pid = proc.stdout.strip()
            if proc.returncode == 0 and pid.isdigit() and int(pid) > 0:
                return pid
        except (OSError, subprocess.SubprocessError):
            continue
    return None


class GrafanaApiClient:
    """Minimal stdlib HTTP client for Grafana Admin & Org APIs with rootless pod-netns fallback."""

    def __init__(
        self,
        base_url: str,
        admin_user: str,
        admin_password: str,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_user = admin_user
        token_bytes = f"{admin_user}:{admin_password}".encode("utf-8")
        self._auth_header = "Basic " + base64.b64encode(token_bytes).decode("ascii")
        self.timeout = timeout

    def _pod_netns_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        data: bytes | None,
        *,
        allow_404: bool,
    ) -> tuple[int, Any] | None:
        parsed = urlparse(url)
        if os.name == "nt" or (parsed.hostname or "").lower() not in ("127.0.0.1", "localhost"):
            return None
        podman_bin = shutil.which("podman")
        pid = _find_pod_pid()
        if not podman_bin or not pid:
            return None

        spec = {
            "url": url,
            "method": method,
            "headers": headers,
            "body_b64": base64.b64encode(data).decode("ascii") if data is not None else None,
            "timeout": max(2.0, float(self.timeout)),
        }
        try:
            proc = subprocess.run(
                [podman_bin, "unshare", "nsenter", "-t", pid, "-n", "python3", "-c", _POD_NSENTER_HTTP_HELPER],
                input=json.dumps(spec),
                capture_output=True,
                text=True,
                timeout=max(5.0, float(self.timeout) + 3.0),
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return None
            envelope = json.loads(proc.stdout)
            status = int(envelope["status"])
            raw_body = str(envelope.get("body") or "")
            if envelope.get("http_error"):
                if allow_404 and status == 404:
                    return 404, None
                raise RuntimeError(f"Grafana API {method} {url} failed ({status}): {raw_body[:300]}")
            return status, (json.loads(raw_body) if raw_body.strip() else {})
        except RuntimeError:
            raise
        except Exception:
            return None

    def request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        *,
        org_id: int = 1,
        allow_404: bool = False,
    ) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": self._auth_header,
            "Accept": "application/json",
            "X-Grafana-Org-Id": str(org_id),
        }
        data: bytes | None = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, (json.loads(raw) if raw.strip() else {})
        except HTTPError as exc:
            if allow_404 and exc.code == 404:
                return 404, None
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            raise RuntimeError(f"Grafana API {method} {path} failed ({exc.code}): {body}") from exc
        except (URLError, OSError):
            fallback = self._pod_netns_request(method, url, headers, data, allow_404=allow_404)
            if fallback is not None:
                return fallback
            raise

    def is_healthy(self) -> bool:
        try:
            status, _ = self.request("GET", "/api/health")
            return 200 <= status < 300
        except (URLError, RuntimeError, OSError):
            return False


def _upsert_datasource(client: GrafanaApiClient, org_id: int, ds_spec: dict[str, Any]) -> None:
    uid = ds_spec["uid"]
    status, existing = client.request(
        "GET", f"/api/datasources/uid/{quote(uid)}", org_id=org_id, allow_404=True
    )
    if status == 404 or not isinstance(existing, dict) or "id" not in existing:
        client.request("POST", "/api/datasources", ds_spec, org_id=org_id)
    else:
        ds_id = existing["id"]
        updated = dict(ds_spec)
        updated["id"] = ds_id
        client.request("PUT", f"/api/datasources/{ds_id}", updated, org_id=org_id)


def _load_dashboard_models(dashboards_dir: Path) -> list[dict[str, Any]]:
    models: list[dict[str, Any]] = []
    for fname in DASHBOARD_FILENAMES:
        fpath = dashboards_dir / fname
        if fpath.exists():
            models.append(json.loads(fpath.read_text(encoding="utf-8")))
    if not models and dashboards_dir.is_dir():
        for fpath in sorted(dashboards_dir.glob("*.json")):
            models.append(json.loads(fpath.read_text(encoding="utf-8")))
    return models


def _lock_dashboard_for_customer(model: dict[str, Any], customer: str) -> dict[str, Any]:
    locked = copy.deepcopy(model)
    locked["id"] = None
    locked["editable"] = False
    templating = locked.get("templating")
    if isinstance(templating, dict) and isinstance(templating.get("list"), list):
        for var in templating["list"]:
            if isinstance(var, dict) and var.get("name") == "customer":
                var["type"] = "constant"
                var["query"] = customer
                var["definition"] = customer
                var["hide"] = 2
                var["includeAll"] = False
                var["multi"] = False
                var["current"] = {"selected": True, "text": customer, "value": customer}
                var["options"] = [{"selected": True, "text": customer, "value": customer}]
    return locked


def _sync_org1(
    client: GrafanaApiClient,
    tenants: list[dict[str, Any]],
    promql_upstream_url: str,
    loki_upstream_url: str,
    dashboards: list[dict[str, Any]],
) -> None:
    _upsert_datasource(
        client,
        1,
        {
            "uid": "prometheus",
            "name": "Prometheus",
            "type": "prometheus",
            "access": "proxy",
            "url": promql_upstream_url,
            "isDefault": True,
            "editable": False,
            "jsonData": {"httpMethod": "POST", "timeInterval": "30s"},
        },
    )

    slugs = sorted(str(t["customer"]) for t in tenants if t.get("customer"))
    pipe_joined_orgs = "|".join([*slugs, "_msp_internal"])
    _upsert_datasource(
        client,
        1,
        {
            "uid": "loki",
            "name": "Loki",
            "type": "loki",
            "access": "proxy",
            "url": loki_upstream_url,
            "isDefault": False,
            "editable": False,
            "jsonData": {"httpHeaderName1": "X-Scope-OrgID", "maxLines": 2000},
            "secureJsonData": {"httpHeaderValue1": pipe_joined_orgs},
        },
    )

    folder_uid = "msp-central-monitoring"
    f_status, _ = client.request("GET", f"/api/folders/{folder_uid}", org_id=1, allow_404=True)
    if f_status == 404:
        client.request(
            "POST",
            "/api/folders",
            {"uid": folder_uid, "title": "MSP Central Monitoring"},
            org_id=1,
        )

    for model in dashboards:
        m_copy = copy.deepcopy(model)
        m_copy["id"] = None
        client.request(
            "POST",
            "/api/dashboards/db",
            {"dashboard": m_copy, "folderUid": folder_uid, "overwrite": True},
            org_id=1,
        )


def _ensure_customer_org(
    client: GrafanaApiClient, state_dir: Path, tenant: dict[str, Any]
) -> int:
    customer = tenant["customer"]
    desired_name = f"Customer: {tenant['display_name']} ({customer})"
    stored_org_id = tenant.get("grafana_org_id")

    if isinstance(stored_org_id, int) and stored_org_id > 1:
        st, existing = client.request("GET", f"/api/orgs/{stored_org_id}", allow_404=True)
        if st == 200 and isinstance(existing, dict):
            if existing.get("name") != desired_name:
                client.request("PUT", f"/api/orgs/{stored_org_id}", {"name": desired_name})
            return stored_org_id

    st, by_name = client.request(
        "GET", f"/api/orgs/name/{quote(desired_name, safe='')}", allow_404=True
    )
    if st == 200 and isinstance(by_name, dict) and "id" in by_name:
        oid = int(by_name["id"])
        update_tenant_grafana_org_id(state_dir, customer, oid)
        return oid

    _, all_orgs = client.request("GET", "/api/orgs")
    if isinstance(all_orgs, list):
        suffix = f"({customer})"
        for o in all_orgs:
            if isinstance(o, dict) and str(o.get("name", "")).endswith(suffix) and int(o["id"]) > 1:
                oid = int(o["id"])
                if o.get("name") != desired_name:
                    client.request("PUT", f"/api/orgs/{oid}", {"name": desired_name})
                update_tenant_grafana_org_id(state_dir, customer, oid)
                return oid

    _, created = client.request("POST", "/api/orgs", {"name": desired_name})
    oid = int(created["orgId"])
    update_tenant_grafana_org_id(state_dir, customer, oid)
    return oid


def _is_privileged_or_external_user(user_obj: dict[str, Any], admin_user: str) -> bool:
    login = str(user_obj.get("login") or "").strip().lower()
    if login in RESERVED_PORTAL_USERNAMES or login == admin_user.strip().lower():
        return True
    if bool(user_obj.get("isGrafanaAdmin")) or bool(user_obj.get("isAdmin")):
        return True
    if bool(user_obj.get("isExternal")) or bool(user_obj.get("authLabels")):
        return True
    if int(user_obj.get("id", -1)) == 1 and login == "admin":
        return True
    return False


def _remove_user_from_other_orgs(
    client: GrafanaApiClient, uid: int, *, keep_org_id: int | None
) -> None:
    _, all_orgs = client.request("GET", "/api/orgs")
    if isinstance(all_orgs, list):
        for org_obj in all_orgs:
            if not isinstance(org_obj, dict) or "id" not in org_obj:
                continue
            oid = int(org_obj["id"])
            if keep_org_id is None or oid != keep_org_id:
                client.request("DELETE", f"/api/orgs/{oid}/users/{uid}", allow_404=True)
    else:
        if keep_org_id != 1:
            client.request("DELETE", f"/api/orgs/1/users/{uid}", allow_404=True)


def _evict_previous_viewer_if_renamed(
    client: GrafanaApiClient, state_dir: Path, tenant: dict[str, Any]
) -> None:
    prev_username = str(tenant.get("previous_portal_viewer_username") or "").strip()
    curr_username = str(tenant.get("portal_viewer_username") or "").strip()
    if not prev_username:
        return
    if prev_username.lower() != curr_username.lower():
        st, prev_obj = client.request(
            "GET", f"/api/users/lookup?loginOrEmail={quote(prev_username)}", allow_404=True
        )
        if st == 200 and isinstance(prev_obj, dict) and "id" in prev_obj:
            if not _is_privileged_or_external_user(prev_obj, client.admin_user):
                prev_uid = int(prev_obj["id"])
                _remove_user_from_other_orgs(client, prev_uid, keep_org_id=None)
                client.request("POST", f"/api/admin/users/{prev_uid}/disable", {}, allow_404=True)
    clear_previous_portal_viewer_username(state_dir, tenant["customer"])


def _sync_portal_viewer_user(
    client: GrafanaApiClient,
    state_dir: Path,
    tenant: dict[str, Any],
    org_id: int | None,
) -> None:
    _evict_previous_viewer_if_renamed(client, state_dir, tenant)

    username = str(tenant.get("portal_viewer_username") or "").strip()
    if not username:
        return

    if username.lower() in RESERVED_PORTAL_USERNAMES or username.lower() == client.admin_user.lower():
        raise RuntimeError(f"Refusing to provision reserved Grafana username: {username!r}")

    customer = tenant["customer"]
    enabled = bool(tenant.get("customer_portal_enabled", False))
    st, user_obj = client.request(
        "GET", f"/api/users/lookup?loginOrEmail={quote(username)}", allow_404=True
    )

    if st == 200 and isinstance(user_obj, dict):
        if _is_privileged_or_external_user(user_obj, client.admin_user):
            raise RuntimeError(
                f"Refusing to mutate privileged or external Grafana account {username!r}"
            )

    if not enabled:
        if st == 200 and isinstance(user_obj, dict) and "id" in user_obj:
            uid = int(user_obj["id"])
            _remove_user_from_other_orgs(client, uid, keep_org_id=None)
            client.request("POST", f"/api/admin/users/{uid}/disable", {}, allow_404=True)
        return

    if org_id is None or org_id <= 1:
        return

    sealed_password = load_portal_viewer_secret(state_dir, customer)
    created_new = False

    if st == 404 or not isinstance(user_obj, dict) or "id" not in user_obj:
        # Provision with random one-time bootstrap secret FIRST so customer cannot authenticate
        # during the brief window before Org 1 auto-assignment is stripped.
        bootstrap_pw = secrets.token_urlsafe(32)
        _, created_u = client.request(
            "POST",
            "/api/admin/users",
            {
                "name": f"{tenant['display_name']} Portal Viewer",
                "login": username,
                "email": f"{username}@{customer}.portal.local",
                "password": bootstrap_pw,
                "OrgId": org_id,
            },
        )
        uid = int(created_u["id"])
        created_new = True
    else:
        uid = int(user_obj["id"])

    _, org_users = client.request("GET", f"/api/orgs/{org_id}/users", org_id=org_id)
    member = None
    if isinstance(org_users, list):
        member = next((m for m in org_users if int(m.get("userId", -1)) == uid), None)

    if member is None:
        client.request(
            "POST",
            f"/api/orgs/{org_id}/users",
            {"loginOrEmail": username, "role": "Viewer"},
            org_id=org_id,
        )
    elif member.get("role") != "Viewer":
        client.request(
            "PATCH",
            f"/api/orgs/{org_id}/users/{uid}",
            {"role": "Viewer"},
            org_id=org_id,
        )

    # Mandatory isolation: strip user from Org 1 AND every other Customer Organization
    _remove_user_from_other_orgs(client, uid, keep_org_id=org_id)
    client.request("POST", f"/api/users/{uid}/using/{org_id}", {}, allow_404=True)
    client.request("POST", f"/api/admin/users/{uid}/enable", {}, allow_404=True)

    # Set customer's sealed password LAST after all unauthorized org memberships are removed
    if sealed_password:
        client.request(
            "PUT",
            f"/api/admin/users/{uid}/password",
            {"password": sealed_password},
        )
    elif created_new:
        client.request(
            "PUT",
            f"/api/admin/users/{uid}/password",
            {"password": secrets.token_urlsafe(24)},
        )


def sync_all_orgs(
    state_dir: str | Path,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Synchronize MSP Main Org 1 and all Customer Portal Organizations against Grafana."""
    sdir = Path(state_dir)
    env_map = _merged_env(sdir, env)

    grafana_url = env_map.get("GRAFANA_URL", "http://127.0.0.1:3000")
    admin_user = env_map.get("GRAFANA_ADMIN_USER", "admin")
    admin_password = env_map.get("GRAFANA_ADMIN_PASSWORD", "admin")
    storage_mode = env_map.get("STORAGE_MODE", "local").lower()
    default_prom = "http://127.0.0.1:10902" if storage_mode == "s3" else "http://127.0.0.1:9090"
    promql_upstream = env_map.get("PROMQL_UPSTREAM_URL") or default_prom
    loki_upstream = env_map.get("LOKI_UPSTREAM_URL", "http://127.0.0.1:3100")
    prom_label_proxy_url = env_map.get("PROM_LABEL_PROXY_URL", "http://127.0.0.1:9095")

    client = GrafanaApiClient(grafana_url, admin_user, admin_password)
    dashboards_dir = _resolve_dashboards_dir(sdir, env_map)
    dashboards = _load_dashboard_models(dashboards_dir)
    tenants = load_tenants_raw(sdir)

    _sync_org1(client, tenants, promql_upstream, loki_upstream, dashboards)

    synced_customer_orgs = 0
    for tenant in tenants:
        if bool(tenant.get("customer_portal_enabled", False)):
            oid = _ensure_customer_org(client, sdir, tenant)
            customer = tenant["customer"]
            _upsert_datasource(
                client,
                oid,
                {
                    "uid": "prometheus",
                    "name": "Prometheus",
                    "type": "prometheus",
                    "access": "proxy",
                    "url": prom_label_proxy_url,
                    "isDefault": True,
                    "editable": False,
                    "jsonData": {
                        "httpHeaderName1": "X-Scope-OrgID",
                        "httpMethod": "POST",
                        "timeInterval": "30s",
                    },
                    "secureJsonData": {"httpHeaderValue1": customer},
                },
            )
            _upsert_datasource(
                client,
                oid,
                {
                    "uid": "loki",
                    "name": "Loki",
                    "type": "loki",
                    "access": "proxy",
                    "url": loki_upstream,
                    "isDefault": False,
                    "editable": False,
                    "jsonData": {"httpHeaderName1": "X-Scope-OrgID", "maxLines": 1000},
                    "secureJsonData": {"httpHeaderValue1": customer},
                },
            )
            for model in dashboards:
                locked_model = _lock_dashboard_for_customer(model, customer)
                client.request(
                    "POST",
                    "/api/dashboards/db",
                    {"dashboard": locked_model, "overwrite": True},
                    org_id=oid,
                )
            _sync_portal_viewer_user(client, sdir, tenant, oid)
            synced_customer_orgs += 1
        else:
            existing_oid = tenant.get("grafana_org_id")
            _sync_portal_viewer_user(
                client,
                sdir,
                tenant,
                int(existing_oid) if isinstance(existing_oid, int) else None,
            )

    return {"synced": True, "customer_orgs": synced_customer_orgs}


def sync_all_orgs_if_running(
    state_dir: str | Path,
    env: Mapping[str, str] | None = None,
    *,
    max_wait_seconds: float | None = None,
) -> dict[str, Any]:
    """Best-effort Grafana sync with bounded readiness retry when Grafana container is starting."""
    sdir = Path(state_dir)
    env_map = _merged_env(sdir, env)
    client = GrafanaApiClient(
        env_map.get("GRAFANA_URL", "http://127.0.0.1:3000"),
        env_map.get("GRAFANA_ADMIN_USER", "admin"),
        env_map.get("GRAFANA_ADMIN_PASSWORD", "admin"),
        timeout=0.5,
    )

    if max_wait_seconds is not None:
        wait_budget = max(0.0, float(max_wait_seconds))
    elif env_map.get("GRAFANA_SYNC_WAIT_SECONDS"):
        wait_budget = max(0.0, float(env_map["GRAFANA_SYNC_WAIT_SECONDS"]))
    elif _find_pod_pid() is not None:
        wait_budget = 15.0
    else:
        wait_budget = 0.0

    deadline = time.monotonic() + wait_budget
    healthy = client.is_healthy()
    while not healthy and time.monotonic() < deadline:
        time.sleep(0.5)
        healthy = client.is_healthy()

    if not healthy:
        return {"synced": False, "reason": "grafana_unreachable"}
    try:
        return sync_all_orgs(sdir, env_map)
    except (URLError, OSError, RuntimeError) as exc:
        return {"synced": False, "reason": str(exc)}


def cleanup_deleted_tenant_if_running(
    state_dir: str | Path,
    env: Mapping[str, str] | None,
    removed_tenant: dict[str, Any],
) -> None:
    """Disable portal viewer user and remove Customer Org when a tenant is deleted."""
    sdir = Path(state_dir)
    env_map = _merged_env(sdir, env)
    client = GrafanaApiClient(
        env_map.get("GRAFANA_URL", "http://127.0.0.1:3000"),
        env_map.get("GRAFANA_ADMIN_USER", "admin"),
        env_map.get("GRAFANA_ADMIN_PASSWORD", "admin"),
        timeout=0.5,
    )
    if not client.is_healthy():
        return
    try:
        disabled_copy = dict(removed_tenant)
        disabled_copy["customer_portal_enabled"] = False
        oid = removed_tenant.get("grafana_org_id")
        _sync_portal_viewer_user(
            client, sdir, disabled_copy, int(oid) if isinstance(oid, int) else None
        )
        if isinstance(oid, int) and oid > 1:
            client.request("DELETE", f"/api/orgs/{oid}", allow_404=True)
    except Exception:
        pass
