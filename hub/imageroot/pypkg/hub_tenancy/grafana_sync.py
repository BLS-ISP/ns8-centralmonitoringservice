"""Idempotent Grafana Multi-Org, Datasource, Dashboard & Multi-User Portal Provisioner.

Provisions:
1. MSP Main Org (Org 1):
   - `Prometheus` (`uid: "prometheus"`, `${PROMQL_UPSTREAM_URL}`, `editable: false`)
   - `Loki` (`uid: "loki"`, `http://127.0.0.1:3100`, `X-Scope-OrgID: slug1|slug2|_msp_internal`)
   - Folder `MSP Central Monitoring` + all 4 starter dashboards from `shared/dashboards/`
2. Customer Portal Organizations (`customer_portal_enabled: true`):
   - Dedicated Org `Customer: <display_name> (<customer>)`
   - `Prometheus` pointing strictly to `prom-label-proxy` (`http://127.0.0.1:9095`, `X-Scope-OrgID: <customer>`)
   - `Loki` pointing to `http://127.0.0.1:3100` (`X-Scope-OrgID: <customer>`)
   - Multi-user portal accounts (`Viewer` or `Editor` strictly inside Customer Org `oid > 1`),
     stripped from Org 1 and all other Orgs, protected against superadmin/external collisions,
     enabled/disabled cleanly, and provisioned with bootstrap secret before Org isolation completes.
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
    ALLOWED_PORTAL_ROLES,
    RESERVED_PORTAL_USERNAMES,
    build_grafana_org_name,
    clear_previous_portal_viewer_username,
    load_portal_viewer_secret,
    load_tenants_raw,
    normalize_portal_users,
    update_tenant_grafana_org_id,
)

DASHBOARD_FILENAMES = (
    "ns8-multi-cluster-overview.json",
    "ns8-pods-and-modules.json",
    "linux-windows-servers.json",
    "proxmox-snmp-infrastructure.json",
    "web-ssl-uptime.json",
    "central-log-explorer.json",
)
HOME_DASHBOARD_UID = "ns8-multi-cluster-overview"

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


def _set_org_home_dashboard(
    client: GrafanaApiClient,
    org_id: int,
    dashboards: list[dict[str, Any]],
) -> None:
    """Set the Organization Home Dashboard to `ns8-multi-cluster-overview` when imported."""
    if not any(m.get("uid") == HOME_DASHBOARD_UID for m in dashboards):
        return
    try:
        client.request(
            "PUT",
            "/api/org/preferences",
            {"homeDashboardUID": HOME_DASHBOARD_UID},
            org_id=org_id,
            allow_404=True,
        )
    except RuntimeError:
        pass


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

    try:
        client.request(
            "POST",
            "/api/admin/provisioning/dashboards/reload",
            {},
            org_id=1,
            allow_404=True,
        )
    except RuntimeError:
        pass

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
        try:
            client.request(
                "POST",
                "/api/dashboards/db",
                {"dashboard": m_copy, "folderUid": folder_uid, "overwrite": True},
                org_id=1,
            )
        except RuntimeError as exc:
            err_low = str(exc).lower()
            if "provisioned" in err_low or "(400)" in err_low:
                continue
            raise

    _set_org_home_dashboard(client, 1, dashboards)


def _ensure_customer_org(
    client: GrafanaApiClient, state_dir: Path, tenant: dict[str, Any]
) -> int:
    customer = tenant["customer"]
    desired_name = build_grafana_org_name(tenant["display_name"], customer)
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


def _delete_or_disable_grafana_user(client: GrafanaApiClient, username: str) -> None:
    uname = username.strip()
    if not uname:
        return
    st, user_obj = client.request(
        "GET", f"/api/users/lookup?loginOrEmail={quote(uname)}", allow_404=True
    )
    if st != 200 or not isinstance(user_obj, dict) or "id" not in user_obj:
        return
    if _is_privileged_or_external_user(user_obj, client.admin_user):
        return
    uid = int(user_obj["id"])
    _remove_user_from_other_orgs(client, uid, keep_org_id=None)
    client.request("POST", f"/api/admin/users/{uid}/disable", {}, allow_404=True)
    try:
        client.request("DELETE", f"/api/admin/users/{uid}", allow_404=True)
    except RuntimeError:
        pass


def _evict_removed_portal_users(
    client: GrafanaApiClient,
    state_dir: Path,
    tenant: dict[str, Any],
    active_usernames_lower: set[str],
) -> None:
    pending: list[str] = []
    prev_u = str(tenant.get("previous_portal_viewer_username") or "").strip()
    if prev_u:
        pending.append(prev_u)
    for item in tenant.get("evicted_portal_usernames") or []:
        s = str(item or "").strip()
        if s:
            pending.append(s)
    if not pending:
        return

    seen: set[str] = set()
    for uname in pending:
        ulow = uname.lower()
        if ulow in seen or ulow in active_usernames_lower:
            continue
        seen.add(ulow)
        _delete_or_disable_grafana_user(client, uname)
    clear_previous_portal_viewer_username(state_dir, tenant["customer"])


def _sync_single_portal_user(
    client: GrafanaApiClient,
    state_dir: Path,
    tenant: dict[str, Any],
    user_spec: dict[str, Any],
    org_id: int | None,
) -> None:
    username = str(user_spec.get("username") or "").strip()
    if not username:
        return

    if username.lower() in RESERVED_PORTAL_USERNAMES or username.lower() == client.admin_user.lower():
        raise RuntimeError(f"Refusing to provision reserved Grafana username: {username!r}")

    customer = tenant["customer"]
    portal_enabled = bool(tenant.get("customer_portal_enabled", False))
    user_disabled = bool(user_spec.get("disabled", False))
    raw_role = str(user_spec.get("role") or "Viewer").strip()
    desired_role = raw_role if raw_role in ALLOWED_PORTAL_ROLES else "Viewer"

    st, user_obj = client.request(
        "GET", f"/api/users/lookup?loginOrEmail={quote(username)}", allow_404=True
    )
    if st == 200 and isinstance(user_obj, dict):
        if _is_privileged_or_external_user(user_obj, client.admin_user):
            raise RuntimeError(
                f"Refusing to mutate privileged or external Grafana account {username!r}"
            )

    if not portal_enabled or user_disabled:
        if st == 200 and isinstance(user_obj, dict) and "id" in user_obj:
            uid = int(user_obj["id"])
            _remove_user_from_other_orgs(client, uid, keep_org_id=None)
            client.request("POST", f"/api/admin/users/{uid}/disable", {}, allow_404=True)
        return

    if org_id is None or org_id <= 1:
        return

    full_name = (
        str(user_spec.get("full_name") or "").strip()
        or f"{tenant['display_name']} Portal {desired_role}"
    )
    email = (
        str(user_spec.get("email") or "").strip()
        or f"{username}@{customer}.portal.local"
    )
    sealed_password = load_portal_viewer_secret(state_dir, customer, username)
    created_new = False

    if st == 404 or not isinstance(user_obj, dict) or "id" not in user_obj:
        # Provision with random one-time bootstrap secret FIRST so customer cannot authenticate
        # during the brief window before Org 1 auto-assignment is stripped.
        bootstrap_pw = secrets.token_urlsafe(32)
        _, created_u = client.request(
            "POST",
            "/api/admin/users",
            {
                "name": full_name,
                "login": username,
                "email": email,
                "password": bootstrap_pw,
                "OrgId": org_id,
            },
        )
        uid = int(created_u["id"])
        created_new = True
    else:
        uid = int(user_obj["id"])
        if user_obj.get("name") != full_name or user_obj.get("email") != email:
            try:
                client.request(
                    "PUT",
                    f"/api/users/{uid}",
                    {
                        "login": username,
                        "name": full_name,
                        "email": email,
                    },
                    allow_404=True,
                )
            except RuntimeError:
                pass

    _, org_users = client.request("GET", f"/api/orgs/{org_id}/users", org_id=org_id)
    member = None
    if isinstance(org_users, list):
        member = next((m for m in org_users if int(m.get("userId", -1)) == uid), None)

    if member is None:
        client.request(
            "POST",
            f"/api/orgs/{org_id}/users",
            {"loginOrEmail": username, "role": desired_role},
            org_id=org_id,
        )
    elif member.get("role") != desired_role:
        client.request(
            "PATCH",
            f"/api/orgs/{org_id}/users/{uid}",
            {"role": desired_role},
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


def _collect_globally_active_portal_usernames(tenants: list[dict[str, Any]]) -> set[str]:
    return {
        str(u["username"]).strip().lower()
        for t in tenants
        for u in normalize_portal_users(t)
        if u.get("username")
    }


def _sync_portal_users(
    client: GrafanaApiClient,
    state_dir: Path,
    tenant: dict[str, Any],
    org_id: int | None,
    *,
    globally_active_lower: set[str] | None = None,
) -> None:
    users = normalize_portal_users(tenant)
    active_set = (
        globally_active_lower
        if globally_active_lower is not None
        else _collect_globally_active_portal_usernames(load_tenants_raw(state_dir))
    )
    _evict_removed_portal_users(client, state_dir, tenant, active_set)
    for user_spec in users:
        _sync_single_portal_user(client, state_dir, tenant, user_spec, org_id)


def _sync_msp_staff_to_customer_orgs(
    client: GrafanaApiClient,
    active_customer_org_ids: list[int],
    globally_active_portal_lower: set[str],
) -> None:
    """Propagate verified MSP Org-1 staff (1-way) into active Customer Orgs (`?orgId=<id>`)."""
    if not active_customer_org_ids:
        return

    st, org1_users = client.request("GET", "/api/orgs/1/users", org_id=1, allow_404=True)
    if st != 200 or not isinstance(org1_users, list):
        return

    admin_login_lower = client.admin_user.strip().lower()
    msp_staff: list[tuple[int, str, str]] = []
    seen_uids: set[int] = set()

    for member in org1_users:
        if not isinstance(member, dict) or "userId" not in member:
            continue
        uid = int(member["userId"])
        if uid in seen_uids:
            continue

        detail: dict[str, Any] = member
        try:
            u_st, u_obj = client.request("GET", f"/api/users/{uid}", allow_404=True)
            if u_st == 200 and isinstance(u_obj, dict):
                detail = u_obj
        except RuntimeError:
            pass

        login = str(detail.get("login") or member.get("login") or "").strip()
        login_lower = login.lower()
        if not login_lower or login_lower in globally_active_portal_lower:
            continue

        is_verified_msp = (
            login_lower == admin_login_lower
            or bool(detail.get("isGrafanaAdmin"))
            or bool(detail.get("isAdmin"))
            or bool(detail.get("isExternal"))
            or bool(detail.get("authLabels"))
            or bool(member.get("authLabels"))
        )
        if not is_verified_msp:
            continue

        org1_role = str(member.get("role") or "").strip()
        if (
            org1_role == "Admin"
            or login_lower == admin_login_lower
            or bool(detail.get("isGrafanaAdmin"))
            or bool(detail.get("isAdmin"))
        ):
            desired_role = "Admin"
        else:
            desired_role = "Viewer"

        seen_uids.add(uid)
        msp_staff.append((uid, login, desired_role))

    if not msp_staff:
        return

    for oid in active_customer_org_ids:
        if oid <= 1:
            continue
        ou_st, existing_ou = client.request(
            "GET", f"/api/orgs/{oid}/users", org_id=oid, allow_404=True
        )
        existing_roles: dict[int, str] = {}
        if ou_st == 200 and isinstance(existing_ou, list):
            for item in existing_ou:
                if isinstance(item, dict) and "userId" in item:
                    existing_roles[int(item["userId"])] = str(item.get("role") or "")

        for uid, login, desired_role in msp_staff:
            if uid not in existing_roles:
                client.request(
                    "POST",
                    f"/api/orgs/{oid}/users",
                    {"loginOrEmail": login, "role": desired_role},
                    org_id=oid,
                )
            elif existing_roles[uid] != desired_role:
                client.request(
                    "PATCH",
                    f"/api/orgs/{oid}/users/{uid}",
                    {"role": desired_role},
                    org_id=oid,
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
    globally_active_lower = _collect_globally_active_portal_usernames(tenants)

    _sync_org1(client, tenants, promql_upstream, loki_upstream, dashboards)

    # Evict deferred/renamed portal users across all tenants FIRST before provisioning active users
    # so a username freed on Tenant Z and newly claimed by Tenant A is never clobbered.
    for tenant in tenants:
        _evict_removed_portal_users(client, sdir, tenant, globally_active_lower)

    synced_customer_orgs = 0
    active_customer_org_ids: list[int] = []
    for tenant in tenants:
        if bool(tenant.get("customer_portal_enabled", False)):
            oid = _ensure_customer_org(client, sdir, tenant)
            active_customer_org_ids.append(oid)
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
            _set_org_home_dashboard(client, oid, dashboards)
            _sync_portal_users(
                client,
                sdir,
                tenant,
                oid,
                globally_active_lower=globally_active_lower,
            )
            synced_customer_orgs += 1
        else:
            existing_oid = tenant.get("grafana_org_id")
            _sync_portal_users(
                client,
                sdir,
                tenant,
                int(existing_oid) if isinstance(existing_oid, int) else None,
                globally_active_lower=globally_active_lower,
            )

    _sync_msp_staff_to_customer_orgs(
        client,
        sorted(set(active_customer_org_ids)),
        globally_active_lower,
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
    has_explicit_url = bool((env or {}).get("GRAFANA_URL") or os.environ.get("GRAFANA_URL"))
    probe_timeout = 0.5 if (has_explicit_url or os.name != "nt") else 0.15
    client = GrafanaApiClient(
        env_map.get("GRAFANA_URL", "http://127.0.0.1:3000"),
        env_map.get("GRAFANA_ADMIN_USER", "admin"),
        env_map.get("GRAFANA_ADMIN_PASSWORD", "admin"),
        timeout=probe_timeout,
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


def delete_grafana_portal_user_if_running(
    state_dir: str | Path,
    env: Mapping[str, str] | None,
    username: str,
    *,
    customer: str = "",
) -> bool:
    """Evict and delete a portal user from Grafana (`DELETE /api/admin/users/<id>`) when running."""
    sdir = Path(state_dir)
    env_map = _merged_env(sdir, env)
    has_explicit_url = bool((env or {}).get("GRAFANA_URL") or os.environ.get("GRAFANA_URL"))
    probe_timeout = 1.0 if (has_explicit_url or os.name != "nt") else 0.15
    client = GrafanaApiClient(
        env_map.get("GRAFANA_URL", "http://127.0.0.1:3000"),
        env_map.get("GRAFANA_ADMIN_USER", "admin"),
        env_map.get("GRAFANA_ADMIN_PASSWORD", "admin"),
        timeout=probe_timeout,
    )
    if not client.is_healthy():
        return False
    try:
        globally_active = _collect_globally_active_portal_usernames(load_tenants_raw(sdir))
        if username.strip().lower() not in globally_active:
            _delete_or_disable_grafana_user(client, username)
        if customer:
            clear_previous_portal_viewer_username(sdir, customer)
        return True
    except Exception:
        return False


def cleanup_deleted_tenant_if_running(
    state_dir: str | Path,
    env: Mapping[str, str] | None,
    removed_tenant: dict[str, Any],
) -> None:
    """Delete all portal users and remove Customer Org when a tenant is deleted."""
    sdir = Path(state_dir)
    env_map = _merged_env(sdir, env)
    has_explicit_url = bool((env or {}).get("GRAFANA_URL") or os.environ.get("GRAFANA_URL"))
    probe_timeout = 0.5 if (has_explicit_url or os.name != "nt") else 0.15
    client = GrafanaApiClient(
        env_map.get("GRAFANA_URL", "http://127.0.0.1:3000"),
        env_map.get("GRAFANA_ADMIN_USER", "admin"),
        env_map.get("GRAFANA_ADMIN_PASSWORD", "admin"),
        timeout=probe_timeout,
    )
    if not client.is_healthy():
        return
    try:
        globally_active = _collect_globally_active_portal_usernames(load_tenants_raw(sdir))
        for user_spec in normalize_portal_users(removed_tenant):
            uname = str(user_spec.get("username") or "").strip()
            if uname and uname.lower() not in globally_active:
                _delete_or_disable_grafana_user(client, uname)
        oid = removed_tenant.get("grafana_org_id")
        if isinstance(oid, int) and oid > 1:
            client.request("DELETE", f"/api/orgs/{oid}", allow_404=True)
    except Exception:
        pass
