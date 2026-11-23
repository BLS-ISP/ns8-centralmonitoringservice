"""NS8 `Ldapproxy` discovery, AD/LDAP group DN resolution, and Grafana `ldap.toml` sync."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Mapping

from hub_tenancy.grafana_sync import GrafanaApiClient, _merged_env
from hub_tenancy.ldap_client import (
    AD_IN_CHAIN_OID,
    discover_domain_groups_raw,
    resolve_group_dn,
)
from hub_tenancy.store import load_tenants_raw


def _toml_escape(value: str) -> str:
    cleaned = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "")
        .replace("\n", "")
        .replace("\t", " ")
    )
    return f'"{cleaned}"'


def _is_truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    return str(val or "").strip().lower() in ("1", "true", "yes", "on")


def _atomic_write_toml(toml_path: Path, content: str) -> None:
    toml_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(toml_path.parent), prefix=".ldap.toml.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        os.replace(tmp_name, toml_path)
    except Exception:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


def reload_grafana_ldap_if_running(
    state_dir: str | Path,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Trigger live Grafana `/api/admin/provisioning/ldap/reload` when Grafana is running."""
    sdir = Path(state_dir)
    env_map = _merged_env(sdir, env)
    has_explicit_url = bool((env or {}).get("GRAFANA_URL") or os.environ.get("GRAFANA_URL"))
    probe_timeout = 1.5 if (has_explicit_url or os.name != "nt") else 0.15

    client = GrafanaApiClient(
        env_map.get("GRAFANA_URL", "http://127.0.0.1:3000"),
        env_map.get("GRAFANA_ADMIN_USER", "admin"),
        env_map.get("GRAFANA_ADMIN_PASSWORD", "admin"),
        timeout=probe_timeout,
    )
    if not client.is_healthy():
        return False
    try:
        status, _ = client.request(
            "POST",
            "/api/admin/provisioning/ldap/reload",
            {},
            allow_404=True,
        )
        return 200 <= status < 300
    except Exception:
        return False


def sync_ldap_config(
    state_dir: str | Path,
    env: Mapping[str, str] | None = None,
    *,
    ldapproxy_factory: Callable[[], Any] | None = None,
) -> Path | None:
    """Render `/etc/grafana/ldap.toml` (`%E/config/grafana/ldap.toml`) from NS8 Ldapproxy."""
    sdir = Path(state_dir)
    env_map = _merged_env(sdir, env)

    config_dir = Path(
        env_map.get("HUB_CONFIG_DIR") or (sdir.resolve().parent / "config")
    )
    toml_path = Path(
        env_map.get("GRAFANA_LDAP_CONFIG_PATH") or (config_dir / "grafana" / "ldap.toml")
    )

    ldap_enabled = _is_truthy(
        env_map.get("LDAP_ENABLED", env_map.get("ldap_enabled", "false"))
    )
    ldap_domain = str(
        env_map.get("LDAP_DOMAIN") or env_map.get("ldap_domain") or ""
    ).strip()

    if not ldap_enabled or not ldap_domain:
        # Keep a valid 0600 stub file so grafana.service bind-mount always succeeds
        _atomic_write_toml(toml_path, "# Managed by central-monitoring-hub (LDAP disabled)\n")
        reload_grafana_ldap_if_running(sdir, env)
        return None

    if ldapproxy_factory is not None:
        lp = ldapproxy_factory()
    else:  # pragma: no cover - NS8 host runtime
        from agent.ldapproxy import Ldapproxy  # type: ignore[import-not-found]

        lp = Ldapproxy()

    domain_info = lp.get_domain(ldap_domain)
    port = int(domain_info["port"])
    schema = str(domain_info.get("schema") or "ad").strip().lower()
    base_dn = str(domain_info.get("base_dn") or "").strip()
    bind_dn = str(domain_info.get("bind_dn") or "")
    bind_password = str(domain_info.get("bind_password") or "")

    if "LDAP_ADMIN_GROUP" in env_map or "ldap_admin_group" in env_map:
        raw_admin = (
            env_map["LDAP_ADMIN_GROUP"]
            if "LDAP_ADMIN_GROUP" in env_map
            else env_map.get("ldap_admin_group", "")
        )
        admin_group = str(raw_admin or "").strip()
    else:
        admin_group = "Domain Admins"

    editor_group = str(
        env_map.get("LDAP_EDITOR_GROUP") or env_map.get("ldap_editor_group") or ""
    ).strip()
    viewer_group = str(
        env_map.get("LDAP_VIEWER_GROUP") or env_map.get("ldap_viewer_group") or ""
    ).strip()

    discovered_groups: list[dict[str, str]] | None = None
    if any(g and "=" not in g for g in (admin_group, editor_group, viewer_group)):
        try:
            discovered_groups = discover_domain_groups_raw(
                ldap_domain,
                ldapproxy_factory=ldapproxy_factory,
                timeout=1.5 if os.name != "nt" else 0.5,
            )
        except Exception:
            discovered_groups = None

    if schema == "ad":
        search_filter = "(&(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))"
        username_attr = "sAMAccountName"
        member_of_attr = "memberOf"
        group_search_filter = f"(&(objectClass=group)(member:{AD_IN_CHAIN_OID}:=%s))"
        group_search_user_attr = "distinguishedName"
    else:
        search_filter = "(|(uid=%s)(mail=%s))"
        username_attr = "uid"
        member_of_attr = "memberOf"
        group_search_filter = "(&(objectClass=posixGroup)(memberUid=%s))"
        group_search_user_attr = ""

    lines = [
        "# Auto-generated by NS8 Central Monitoring Hub (hub_tenancy.ldap_sync)",
        "# Scoped exclusively to MSP Main Organization (org_id = 1)",
        "",
        "[[servers]]",
        'host = "10.0.2.2"',
        f"port = {port}",
        "use_ssl = false",
        "start_tls = false",
        "ssl_skip_verify = true",
    ]
    if bind_dn:
        lines.append(f"bind_dn = {_toml_escape(bind_dn)}")
    if bind_password:
        lines.append(f"bind_password = {_toml_escape(bind_password)}")
    lines.extend(
        [
            f"search_filter = {_toml_escape(search_filter)}",
            f"search_base_dns = [{_toml_escape(base_dn)}]",
        ]
    )
    if group_search_filter:
        lines.append(f"group_search_filter = {_toml_escape(group_search_filter)}")
        if group_search_user_attr:
            lines.append(
                f"group_search_filter_user_attribute = {_toml_escape(group_search_user_attr)}"
            )
        lines.append(f"group_search_base_dns = [{_toml_escape(base_dn)}]")

    lines.extend(
        [
            "",
            "[servers.attributes]",
            'name = "givenName"',
            'surname = "sn"',
            f"username = {_toml_escape(username_attr)}",
            f"member_of = {_toml_escape(member_of_attr)}",
            'email = "mail"',
        ]
    )

    admin_dn = (
        resolve_group_dn(
            admin_group,
            base_dn=base_dn,
            schema=schema,
            discovered_groups=discovered_groups,
        )
        if admin_group
        else ""
    )
    ed_dn = (
        resolve_group_dn(
            editor_group,
            base_dn=base_dn,
            schema=schema,
            discovered_groups=discovered_groups,
        )
        if editor_group
        else ""
    )
    vw_dn = (
        resolve_group_dn(
            viewer_group,
            base_dn=base_dn,
            schema=schema,
            discovered_groups=discovered_groups,
        )
        if viewer_group
        else ""
    )

    if admin_dn:
        lines.extend(
            [
                "",
                "[[servers.group_mappings]]",
                f"group_dn = {_toml_escape(admin_dn)}",
                'org_role = "Admin"',
                "grafana_admin = true",
                "org_id = 1",
            ]
        )

    if ed_dn:
        lines.extend(
            [
                "",
                "[[servers.group_mappings]]",
                f"group_dn = {_toml_escape(ed_dn)}",
                'org_role = "Editor"',
                "org_id = 1",
            ]
        )

    if vw_dn:
        lines.extend(
            [
                "",
                "[[servers.group_mappings]]",
                f"group_dn = {_toml_escape(vw_dn)}",
                'org_role = "Viewer"',
                "org_id = 1",
            ]
        )

    tenants = load_tenants_raw(sdir)
    customer_org_ids = sorted(
        {
            int(t["grafana_org_id"])
            for t in tenants
            if bool(t.get("customer_portal_enabled"))
            and isinstance(t.get("grafana_org_id"), int)
            and int(t["grafana_org_id"]) > 1
        }
    )

    for c_oid in customer_org_ids:
        if admin_dn:
            lines.extend(
                [
                    "",
                    "[[servers.group_mappings]]",
                    f"group_dn = {_toml_escape(admin_dn)}",
                    'org_role = "Admin"',
                    f"org_id = {c_oid}",
                ]
            )
        if ed_dn:
            lines.extend(
                [
                    "",
                    "[[servers.group_mappings]]",
                    f"group_dn = {_toml_escape(ed_dn)}",
                    'org_role = "Viewer"',
                    f"org_id = {c_oid}",
                ]
            )
        if vw_dn:
            lines.extend(
                [
                    "",
                    "[[servers.group_mappings]]",
                    f"group_dn = {_toml_escape(vw_dn)}",
                    'org_role = "Viewer"',
                    f"org_id = {c_oid}",
                ]
            )

    lines.append("")
    _atomic_write_toml(toml_path, "\n".join(lines))
    reload_grafana_ldap_if_running(sdir, env)
    return toml_path
