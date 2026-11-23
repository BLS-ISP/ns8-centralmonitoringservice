"""NS8 `Ldapproxy` discovery, Multi-Group/Multi-User DN resolution, and Grafana `ldap.toml` sync."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Mapping, Sequence

from hub_tenancy.grafana_sync import GrafanaApiClient, _merged_env
from hub_tenancy.ldap_client import (
    AD_IN_CHAIN_OID,
    discover_directory_principals_raw,
    resolve_principal_dn,
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


def _clean_principal_items(items: Sequence[Any]) -> list[str]:
    result: list[str] = []
    seen_low: set[str] = set()
    for raw in items:
        s = (
            str(raw or "")
            .replace("\r", "")
            .replace("\n", "")
            .replace("\x00", "")
            .strip()
        )
        if not s:
            continue
        slow = s.lower()
        if slow not in seen_low:
            seen_low.add(slow)
            result.append(s)
    return result


def _decode_role_principals(
    env_map: Mapping[str, Any],
    *,
    b64_key: str,
    list_key_upper: str,
    list_key_lower: str,
    legacy_key_upper: str,
    legacy_key_lower: str,
    default_fallback: Sequence[str],
) -> list[str]:
    for list_key in (list_key_upper, list_key_lower):
        if list_key in env_map and env_map[list_key] is not None:
            raw_list = env_map[list_key]
            if isinstance(raw_list, (list, tuple)):
                return _clean_principal_items(raw_list)
            raw_str = str(raw_list).strip()
            if raw_str.startswith("["):
                try:
                    parsed_direct = json.loads(raw_str)
                    if isinstance(parsed_direct, list):
                        return _clean_principal_items(parsed_direct)
                except Exception:
                    pass

    b64_raw = str(env_map.get(b64_key) or "").strip()
    if b64_raw:
        try:
            padded = b64_raw + "=" * ((4 - len(b64_raw) % 4) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            parsed_b64 = json.loads(decoded_bytes.decode("utf-8"))
            if isinstance(parsed_b64, list):
                return _clean_principal_items(parsed_b64)
        except Exception:
            pass

    if legacy_key_upper in env_map or legacy_key_lower in env_map:
        raw_legacy = (
            env_map[legacy_key_upper]
            if legacy_key_upper in env_map
            else env_map.get(legacy_key_lower, "")
        )
        return _clean_principal_items([raw_legacy])

    return _clean_principal_items(default_fallback)


def _needs_directory_lookup(spec: str) -> bool:
    s = str(spec or "").strip()
    slow = s.lower()
    if slow.startswith("group:"):
        s = s[6:].strip()
    elif slow.startswith("user:"):
        s = s[5:].strip()
    return bool(s and "=" not in s)


def _resolve_unique_dns(
    specs: Sequence[str],
    *,
    base_dn: str,
    schema: str,
    discovered_groups: list[dict[str, str]] | None,
    discovered_users: list[dict[str, str]] | None,
) -> list[str]:
    dns: list[str] = []
    seen_low: set[str] = set()
    for spec in specs:
        dn = resolve_principal_dn(
            spec,
            base_dn=base_dn,
            schema=schema,
            discovered_groups=discovered_groups,
            discovered_users=discovered_users,
        )
        if not dn:
            continue
        dlow = dn.lower()
        if dlow not in seen_low:
            seen_low.add(dlow)
            dns.append(dn)
    return dns


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
    env: Mapping[str, Any] | None = None,
    *,
    ldapproxy_factory: Callable[[], Any] | None = None,
) -> Path | None:
    """Render `/etc/grafana/ldap.toml` (`%E/config/grafana/ldap.toml`) from NS8 Ldapproxy."""
    sdir = Path(state_dir)
    str_env: dict[str, str] | None = None
    if env is not None:
        str_env = {
            str(k): str(v)
            for k, v in env.items()
            if v is not None and not isinstance(v, (list, tuple))
        }
    env_map: dict[str, Any] = dict(_merged_env(sdir, str_env))
    if env is not None:
        for k, v in env.items():
            if isinstance(v, (list, tuple)):
                env_map[str(k)] = v
        # Explicit legacy `LDAP_<ROLE>_GROUP` in `env` (without `*_PRINCIPALS*` in `env`)
        # overrides any inherited `LDAP_<ROLE>_PRINCIPALS_B64` from `os.environ` / `state/environment`.
        for role_tok in ("ADMIN", "EDITOR", "VIEWER"):
            leg_up = f"LDAP_{role_tok}_GROUP"
            leg_lo = f"ldap_{role_tok.lower()}_group"
            b64_k = f"LDAP_{role_tok}_PRINCIPALS_B64"
            lst_up = f"LDAP_{role_tok}_PRINCIPALS"
            lst_lo = f"ldap_{role_tok.lower()}_principals"
            if (leg_up in env or leg_lo in env) and not any(
                pk in env for pk in (b64_k, lst_up, lst_lo)
            ):
                env_map.pop(b64_k, None)
                env_map.pop(lst_up, None)
                env_map.pop(lst_lo, None)

    config_dir = Path(
        str(env_map.get("HUB_CONFIG_DIR") or (sdir.resolve().parent / "config"))
    )
    toml_path = Path(
        str(env_map.get("GRAFANA_LDAP_CONFIG_PATH") or (config_dir / "grafana" / "ldap.toml"))
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
        reload_grafana_ldap_if_running(sdir, str_env)
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

    admin_specs = _decode_role_principals(
        env_map,
        b64_key="LDAP_ADMIN_PRINCIPALS_B64",
        list_key_upper="LDAP_ADMIN_PRINCIPALS",
        list_key_lower="ldap_admin_principals",
        legacy_key_upper="LDAP_ADMIN_GROUP",
        legacy_key_lower="ldap_admin_group",
        default_fallback=("Domain Admins",),
    )
    editor_specs = _decode_role_principals(
        env_map,
        b64_key="LDAP_EDITOR_PRINCIPALS_B64",
        list_key_upper="LDAP_EDITOR_PRINCIPALS",
        list_key_lower="ldap_editor_principals",
        legacy_key_upper="LDAP_EDITOR_GROUP",
        legacy_key_lower="ldap_editor_group",
        default_fallback=(),
    )
    viewer_specs = _decode_role_principals(
        env_map,
        b64_key="LDAP_VIEWER_PRINCIPALS_B64",
        list_key_upper="LDAP_VIEWER_PRINCIPALS",
        list_key_lower="ldap_viewer_principals",
        legacy_key_upper="LDAP_VIEWER_GROUP",
        legacy_key_lower="ldap_viewer_group",
        default_fallback=(),
    )

    discovered_groups: list[dict[str, str]] | None = None
    discovered_users: list[dict[str, str]] | None = None
    all_specs = (*admin_specs, *editor_specs, *viewer_specs)
    if any(_needs_directory_lookup(s) for s in all_specs):
        try:
            discovered_groups, discovered_users = discover_directory_principals_raw(
                ldap_domain,
                ldapproxy_factory=ldapproxy_factory,
                timeout=1.5 if os.name != "nt" else 0.5,
            )
        except Exception:
            discovered_groups = None
            discovered_users = None

    if schema == "ad":
        search_filter = (
            "(&(objectClass=user)(!(objectClass=computer))"
            "(|(sAMAccountName=%s)(userPrincipalName=%s)))"
        )
        username_attr = "sAMAccountName"
        member_of_attr = "distinguishedName"
        group_search_filter = (
            f"(|(&(objectClass=group)(member:{AD_IN_CHAIN_OID}:=%s))"
            "(&(objectClass=user)(distinguishedName=%s)))"
        )
        group_search_user_attr = "distinguishedName"
    else:
        search_filter = "(|(uid=%s)(mail=%s))"
        username_attr = "uid"
        member_of_attr = "dn"
        group_search_filter = (
            "(|(&(objectClass=posixGroup)(memberUid=%s))"
            "(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson))(uid=%s)))"
        )
        group_search_user_attr = "uid"

    lines = [
        "# Auto-generated by NS8 Central Monitoring Hub (hub_tenancy.ldap_sync)",
        "# Multi-group & multi-user LDAP/AD mappings (Org 1 primary + active Customer Orgs)",
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

    admin_dns = _resolve_unique_dns(
        admin_specs,
        base_dn=base_dn,
        schema=schema,
        discovered_groups=discovered_groups,
        discovered_users=discovered_users,
    )
    editor_dns = _resolve_unique_dns(
        editor_specs,
        base_dn=base_dn,
        schema=schema,
        discovered_groups=discovered_groups,
        discovered_users=discovered_users,
    )
    viewer_dns = _resolve_unique_dns(
        viewer_specs,
        base_dn=base_dn,
        schema=schema,
        discovered_groups=discovered_groups,
        discovered_users=discovered_users,
    )

    for dn in admin_dns:
        lines.extend(
            [
                "",
                "[[servers.group_mappings]]",
                f"group_dn = {_toml_escape(dn)}",
                'org_role = "Admin"',
                "grafana_admin = true",
                "org_id = 1",
            ]
        )

    for dn in editor_dns:
        lines.extend(
            [
                "",
                "[[servers.group_mappings]]",
                f"group_dn = {_toml_escape(dn)}",
                'org_role = "Editor"',
                "org_id = 1",
            ]
        )

    for dn in viewer_dns:
        lines.extend(
            [
                "",
                "[[servers.group_mappings]]",
                f"group_dn = {_toml_escape(dn)}",
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
        for dn in admin_dns:
            lines.extend(
                [
                    "",
                    "[[servers.group_mappings]]",
                    f"group_dn = {_toml_escape(dn)}",
                    'org_role = "Admin"',
                    f"org_id = {c_oid}",
                ]
            )
        for dn in editor_dns:
            lines.extend(
                [
                    "",
                    "[[servers.group_mappings]]",
                    f"group_dn = {_toml_escape(dn)}",
                    'org_role = "Viewer"',
                    f"org_id = {c_oid}",
                ]
            )
        for dn in viewer_dns:
            lines.extend(
                [
                    "",
                    "[[servers.group_mappings]]",
                    f"group_dn = {_toml_escape(dn)}",
                    'org_role = "Viewer"',
                    f"org_id = {c_oid}",
                ]
            )

    lines.append("")
    _atomic_write_toml(toml_path, "\n".join(lines))
    reload_grafana_ldap_if_running(sdir, str_env)
    return toml_path
