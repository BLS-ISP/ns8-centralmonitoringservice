"""v1.0.4 Tests: Live AD/LDAP Group + User Discovery, Multi-Principal Role Tester & `ldap.toml` Sync."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from hub_tenancy.ldap_client import AD_IN_CHAIN_OID, resolve_principal_dn
from hub_tenancy.ldap_sync import sync_ldap_config
from hub_tenancy.store import save_tenant, update_tenant_grafana_org_id
from tests.hub_tenancy_gateway.test_tenancy_actions_and_sync import run_ns8_action
from tests.hub_tenancy_gateway.test_v102_ldap_and_portal_users import (
    MockLDAPv3Server,
    _sample_ad_directory_entries,
)
from tests.hub_tenancy_gateway.test_v103_simulated_customer_view import (
    _parse_toml_group_mappings,
)


def _b64_principals(items: list[str]) -> str:
    raw = json.dumps(items, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


class TestV104MultiPrincipalLdapDiscoveryAndSync:
    def test_ad_group_and_user_discovery_filters_computers_and_evaluates_multi_principals(
        self, tmp_path: Path
    ) -> None:
        entries = _sample_ad_directory_entries()
        # Add AD computer & krbtgt system accounts that MUST be excluded from `users`
        entries.extend(
            [
                {
                    "dn": "CN=DC01,OU=Domain Controllers,DC=ad,DC=bls-isp,DC=net",
                    "attrs": {
                        "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
                        "cn": "DC01",
                        "sAMAccountName": "DC01$",
                    },
                },
                {
                    "dn": "CN=SQLSRV01,CN=Computers,DC=ad,DC=bls-isp,DC=net",
                    "attrs": {
                        "objectClass": ["top", "person", "organizationalPerson", "user"],
                        "cn": "SQLSRV01",
                        "sAMAccountName": "SQLSRV01$",
                    },
                },
                {
                    "dn": "CN=krbtgt,CN=Users,DC=ad,DC=bls-isp,DC=net",
                    "attrs": {
                        "objectClass": ["top", "person", "organizationalPerson", "user"],
                        "cn": "krbtgt",
                        "sAMAccountName": "krbtgt",
                    },
                },
            ]
        )

        srv = MockLDAPv3Server(entries=entries, max_page_size=3)
        srv.start()
        try:
            state_dir = tmp_path / "state"
            state_dir.mkdir(parents=True)
            mock_lp_env = {
                "HUB_TEST_LDAPPROXY_JSON": json.dumps(
                    {
                        "ad.bls-isp.net": {
                            "host": "127.0.0.1",
                            "port": srv.port,
                            "schema": "ad",
                            "base_dn": "DC=ad,DC=bls-isp,DC=net",
                            "bind_dn": "",
                            "bind_password": "",
                        }
                    }
                )
            }

            # 1. `discover-ldap-groups` returns BOTH sorted `groups` AND sorted human `users`
            rc, out, err = run_ns8_action(
                "discover-ldap-groups",
                {"domain": "ad.bls-isp.net"},
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc == 0, err
            disc = json.loads(out)
            assert disc["ok"] is True
            assert len(disc["groups"]) == 5
            usernames = [u["username"] for u in disc["users"]]
            assert usernames == ["contractor", "Genera", "n.engineer", "v.viewer"]
            assert "DC01$" not in usernames
            assert "SQLSRV01$" not in usernames
            assert "krbtgt" not in usernames

            genera_u = next(u for u in disc["users"] if u["username"] == "Genera")
            assert genera_u["dn"] == "CN=Genera Admin,CN=Users,DC=ad,DC=bls-isp,DC=net"
            assert genera_u["display_name"] == "Genera MSP Admin"
            assert genera_u["email"] == "genera@bls-isp.net"

            # 2. `test-ldap-user` with mixed multi-select groups + direct users (`ldap_*_principals`)
            #    - `v.viewer` is in group `MSP ReadOnly` (Viewer), BUT directly assigned to `ldap_admin_principals`!
            rc_adm, out_adm, err_adm = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ad.bls-isp.net",
                    "username": "v.viewer",
                    "ldap_admin_principals": ["Domain Admins", "v.viewer"],
                    "ldap_editor_principals": ["MSP Operations", "contractor"],
                    "ldap_viewer_principals": ["MSP ReadOnly"],
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc_adm == 0, err_adm
            adm_doc = json.loads(out_adm)
            assert adm_doc["matched_role"] == "Admin"
            assert adm_doc["grafana_admin"] is True
            assert (
                adm_doc["message"]
                == "Matched Org 1 Admin role via user 'CN=Viktor Viewer,OU=Staff,DC=ad,DC=bls-isp,DC=net'."
            )

            #    - `contractor` has NO groups at all, matched directly via `ldap_editor_principals`!
            rc_ed, out_ed, err_ed = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ad.bls-isp.net",
                    "username": "contractor",
                    "ldap_admin_principals": ["Domain Admins"],
                    "ldap_editor_principals": ["MSP Operations", "user:contractor"],
                    "ldap_viewer_principals": ["MSP ReadOnly"],
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc_ed == 0, err_ed
            ed_doc = json.loads(out_ed)
            assert ed_doc["matched_role"] == "Editor"
            assert ed_doc["grafana_admin"] is False
            assert (
                ed_doc["message"]
                == "Matched Org 1 Editor role via user 'CN=External Contractor,OU=Guests,DC=ad,DC=bls-isp,DC=net'."
            )

            #    - Passing explicit `ldap_admin_principals: []` overrides legacy `ldap_admin_group`!
            rc_empty, out_empty, _ = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ad.bls-isp.net",
                    "username": "Genera",
                    "ldap_admin_group": "Domain Admins",
                    "ldap_admin_principals": [],
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc_empty == 0
            assert json.loads(out_empty)["matched_role"] == "None"
        finally:
            srv.stop()

    def test_ldap_toml_multi_group_and_multi_user_b64_rendering_for_ad_and_rfc2307(
        self, tmp_path: Path
    ) -> None:
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        # Seed one active Customer Org (`oid = 2`) to verify multi-principal x multi-org rendering
        save_tenant(
            state_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp",
                "sites": ["hq"],
                "customer_portal_enabled": True,
            },
        )
        update_tenant_grafana_org_id(state_dir, "acme-corp", 2)

        ad_srv = MockLDAPv3Server(entries=_sample_ad_directory_entries(), emit_referral=False)
        ad_srv.start()
        try:

            class AdLdapproxy:
                def get_domain(self, _d: str) -> dict[str, Any]:
                    return {
                        "host": "127.0.0.1",
                        "port": ad_srv.port,
                        "schema": "ad",
                        "base_dn": "DC=ad,DC=bls-isp,DC=net",
                        "bind_dn": "",
                        "bind_password": "",
                    }

            toml_ad = sync_ldap_config(
                state_dir,
                {
                    "LDAP_ENABLED": "true",
                    "LDAP_DOMAIN": "ad.bls-isp.net",
                    "LDAP_ADMIN_PRINCIPALS_B64": _b64_principals(["Domain Admins", "Genera"]),
                    "LDAP_EDITOR_PRINCIPALS_B64": _b64_principals(["MSP Operations", "contractor"]),
                    "LDAP_VIEWER_PRINCIPALS_B64": _b64_principals(["MSP ReadOnly"]),
                },
                ldapproxy_factory=AdLdapproxy,
            )
            assert toml_ad is not None
            ad_txt = toml_ad.read_text(encoding="utf-8")

            assert (
                'search_filter = "(&(objectClass=user)(!(objectClass=computer))(|(sAMAccountName=%s)(userPrincipalName=%s)))"'
                in ad_txt
            )
            assert (
                f'group_search_filter = "(|(&(objectClass=group)(member:{AD_IN_CHAIN_OID}:=%s))(&(objectClass=user)(distinguishedName=%s)))"'
                in ad_txt
            )
            assert 'group_search_filter_user_attribute = "distinguishedName"' in ad_txt
            assert 'member_of = "distinguishedName"' in ad_txt

            da_dn = "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"
            gen_dn = "CN=Genera Admin,CN=Users,DC=ad,DC=bls-isp,DC=net"
            ops_dn = "CN=MSP Operations,OU=Groups,DC=ad,DC=bls-isp,DC=net"
            con_dn = "CN=External Contractor,OU=Guests,DC=ad,DC=bls-isp,DC=net"
            ro_dn = "CN=MSP ReadOnly,OU=Groups,DC=ad,DC=bls-isp,DC=net"

            mappings = _parse_toml_group_mappings(ad_txt)
            assert mappings == [
                {"group_dn": da_dn, "org_role": "Admin", "grafana_admin": True, "org_id": 1},
                {"group_dn": gen_dn, "org_role": "Admin", "grafana_admin": True, "org_id": 1},
                {"group_dn": ops_dn, "org_role": "Editor", "org_id": 1},
                {"group_dn": con_dn, "org_role": "Editor", "org_id": 1},
                {"group_dn": ro_dn, "org_role": "Viewer", "org_id": 1},
                {"group_dn": da_dn, "org_role": "Admin", "org_id": 2},
                {"group_dn": gen_dn, "org_role": "Admin", "org_id": 2},
                {"group_dn": ops_dn, "org_role": "Viewer", "org_id": 2},
                {"group_dn": con_dn, "org_role": "Viewer", "org_id": 2},
                {"group_dn": ro_dn, "org_role": "Viewer", "org_id": 2},
            ]

            # Explicit empty B64 array `[]` produces zero mappings for that role (never falls back to Domain Admins)
            toml_empty_admin = sync_ldap_config(
                state_dir,
                {
                    "LDAP_ENABLED": "true",
                    "LDAP_DOMAIN": "ad.bls-isp.net",
                    "LDAP_ADMIN_PRINCIPALS_B64": _b64_principals([]),
                    "LDAP_VIEWER_PRINCIPALS_B64": _b64_principals(["Genera"]),
                },
                ldapproxy_factory=AdLdapproxy,
            )
            assert toml_empty_admin is not None
            empty_mappings = _parse_toml_group_mappings(toml_empty_admin.read_text(encoding="utf-8"))
            assert empty_mappings == [
                {"group_dn": gen_dn, "org_role": "Viewer", "org_id": 1},
                {"group_dn": gen_dn, "org_role": "Viewer", "org_id": 2},
            ]
        finally:
            ad_srv.stop()

        # Verify OpenLDAP / RFC2307 `member_of = "dn"` & `group_search_filter_user_attribute = "uid"`
        class RfcLdapproxy:
            def get_domain(self, _d: str) -> dict[str, Any]:
                return {
                    "host": "127.0.0.1",
                    "port": ad_srv.port,  # offline port -> tests offline `user:` & `group:` fallback too!
                    "schema": "rfc2307",
                    "base_dn": "dc=ldap,dc=example,dc=org",
                    "bind_dn": "",
                    "bind_password": "",
                }

        toml_rfc = sync_ldap_config(
            state_dir,
            {
                "LDAP_ENABLED": "true",
                "LDAP_DOMAIN": "ldap.example.org",
                "LDAP_ADMIN_PRINCIPALS_B64": _b64_principals(["msp-admins", "user:alice"]),
            },
            ldapproxy_factory=RfcLdapproxy,
        )
        assert toml_rfc is not None
        rfc_txt = toml_rfc.read_text(encoding="utf-8")
        assert (
            'group_search_filter = "(|(&(objectClass=posixGroup)(memberUid=%s))(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson))(uid=%s)))"'
            in rfc_txt
        )
        assert 'group_search_filter_user_attribute = "uid"' in rfc_txt
        assert 'member_of = "dn"' in rfc_txt
        assert 'group_dn = "cn=msp-admins,ou=Groups,dc=ldap,dc=example,dc=org"' in rfc_txt
        assert 'group_dn = "uid=alice,ou=People,dc=ldap,dc=example,dc=org"' in rfc_txt
        assert (
            resolve_principal_dn("group:ops", base_dn="dc=example,dc=org", schema="rfc2307")
            == "cn=ops,ou=Groups,dc=example,dc=org"
        )

    def test_v104_e2e_bug01_explicit_legacy_env_overrides_inherited_os_environ_b64(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        # Simulate leaked process-level `LDAP_*_PRINCIPALS_B64` in `os.environ`
        monkeypatch.setenv("LDAP_ADMIN_PRINCIPALS_B64", _b64_principals(["Stale Group"]))
        monkeypatch.setenv("LDAP_EDITOR_PRINCIPALS_B64", _b64_principals([]))
        monkeypatch.setenv("LDAP_VIEWER_PRINCIPALS_B64", _b64_principals([]))

        class OfflineAdLdapproxy:
            def get_domain(self, _d: str) -> dict[str, Any]:
                return {
                    "host": "127.0.0.1",
                    "port": 1,
                    "schema": "ad",
                    "base_dn": "DC=ad,DC=bls-isp,DC=net",
                    "bind_dn": "",
                    "bind_password": "",
                }

        toml_path = sync_ldap_config(
            state_dir,
            {
                "LDAP_ENABLED": "true",
                "LDAP_DOMAIN": "ad.bls-isp.net",
                "LDAP_ADMIN_GROUP": "CN=MSP Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
                "LDAP_EDITOR_GROUP": "CN=MSP Ops,OU=Groups,DC=ad,DC=bls-isp,DC=net",
                "LDAP_VIEWER_GROUP": "CN=MSP View,OU=Groups,DC=ad,DC=bls-isp,DC=net",
            },
            ldapproxy_factory=OfflineAdLdapproxy,
        )
        assert toml_path is not None
        txt = toml_path.read_text(encoding="utf-8")
        assert 'group_dn = "CN=MSP Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"' in txt
        assert 'group_dn = "CN=MSP Ops,OU=Groups,DC=ad,DC=bls-isp,DC=net"' in txt
        assert 'group_dn = "CN=MSP View,OU=Groups,DC=ad,DC=bls-isp,DC=net"' in txt
        assert "Stale Group" not in txt
