"""v1.0.2 Tests: Pure-Python LDAPv3 BER Client, AD Nested/Short-Name Group Sync & Multi-User Portals."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import struct
import threading
from typing import Any

from aiohttp import web
import pytest

from hub_tenancy.ldap_client import (
    AD_IN_CHAIN_OID,
    PAGED_RESULTS_OID,
    _ber_bool,
    _ber_int,
    _ber_octet_string,
    _ber_seq,
    _ber_tlv,
    _decode_ber_int,
    _decode_ber_tlv,
    escape_ldap_filter_value,
)
from hub_tenancy.ldap_sync import sync_ldap_config
from hub_tenancy.store import load_portal_viewer_secret
from tests.hub_tenancy_gateway.test_tenancy_actions_and_sync import run_ns8_action


# ---------------------------------------------------------------------------
# Real Local TCP RFC 4511 ASN.1 BER LDAPv3 Server Fixture
# ---------------------------------------------------------------------------


def _build_ad_sid(rid: int) -> bytes:
    """Build a valid binary Windows/Samba4 objectSid ending with 32-bit little-endian `rid`."""
    # S-1-5-21-11111111-22222222-33333333-<rid> (revision=1, sub_auth_count=5)
    header = bytes([1, 5, 0, 0, 0, 0, 0, 5])
    subs = struct.pack("<IIIII", 21, 11111111, 22222222, 33333333, rid)
    return header + subs


class MockLDAPv3Server:
    """Stateful TCP RFC 4511 BER server evaluating real BER filters, AD IN_CHAIN, and paging."""

    def __init__(
        self,
        *,
        expected_bind_dn: str = "",
        expected_bind_pw: str = "",
        entries: list[dict[str, Any]] | None = None,
        max_page_size: int = 2,
        emit_referral: bool = True,
    ) -> None:
        self.expected_bind_dn = expected_bind_dn
        self.expected_bind_pw = expected_bind_pw
        self.entries = list(entries or [])
        self.max_page_size = max_page_size
        self.emit_referral = emit_referral
        self.recorded_filters: list[Any] = []
        self.bind_count = 0
        self.unbind_count = 0
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.port = 0

    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        self._sock = srv
        self.port = int(srv.getsockname()[1])
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            t.start()

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _recv_ber_msg(self, conn: socket.socket) -> bytes | None:
        hdr = self._recv_exact(conn, 2)
        if not hdr or hdr[0] != 0x30:
            return None
        first_len = hdr[1]
        if first_len < 0x80:
            body_len = first_len
            extra = b""
        else:
            n_oct = first_len & 0x7F
            extra_raw = self._recv_exact(conn, n_oct)
            if extra_raw is None:
                return None
            extra = extra_raw
            body_len = int.from_bytes(extra, "big", signed=False)
        body = self._recv_exact(conn, body_len)
        if body is None:
            return None
        return hdr + extra + body

    def _parse_ber_filter(self, buf: bytes, offset: int = 0) -> tuple[Any, int]:
        tag, body, next_pos = _decode_ber_tlv(buf, offset)
        if tag == 0xA0:  # AND
            items = []
            p = 0
            while p < len(body):
                sub, p = self._parse_ber_filter(body, p)
                items.append(sub)
            return ("and", items), next_pos
        if tag == 0xA1:  # OR
            items = []
            p = 0
            while p < len(body):
                sub, p = self._parse_ber_filter(body, p)
                items.append(sub)
            return ("or", items), next_pos
        if tag == 0xA2:  # NOT
            sub, _ = self._parse_ber_filter(body, 0)
            return ("not", sub), next_pos
        if tag == 0xA3:  # equalityMatch
            _, attr_b, p = _decode_ber_tlv(body, 0)
            _, val_b, _ = _decode_ber_tlv(body, p)
            return ("eq", attr_b.decode("utf-8"), val_b.decode("utf-8", errors="replace")), next_pos
        if tag == 0x87:  # present
            return ("present", body.decode("utf-8")), next_pos
        if tag == 0xA4:  # substrings
            _, attr_b, p = _decode_ber_tlv(body, 0)
            _, seq_b, _ = _decode_ber_tlv(body, p)
            parts = []
            sp = 0
            while sp < len(seq_b):
                st, sb, sp = _decode_ber_tlv(seq_b, sp)
                parts.append((st, sb.decode("utf-8", errors="replace")))
            return ("substr", attr_b.decode("utf-8"), parts), next_pos
        if tag == 0xA9:  # extensibleMatch
            rule = ""
            attr = ""
            val = ""
            p = 0
            while p < len(body):
                ft, fb, p = _decode_ber_tlv(body, p)
                if ft == 0x81:
                    rule = fb.decode("utf-8")
                elif ft == 0x82:
                    attr = fb.decode("utf-8")
                elif ft == 0x83:
                    val = fb.decode("utf-8", errors="replace")
            return ("ext", attr, rule, val), next_pos
        raise ValueError(f"Unsupported filter tag 0x{tag:02x}")

    def _get_entry_vals(self, entry: dict[str, Any], attr: str) -> list[str]:
        alow = attr.lower()
        if alow == "distinguishedname":
            return [entry["dn"]]
        for k, v in entry.get("attrs", {}).items():
            if k.lower() == alow:
                if isinstance(v, list):
                    return [str(x) for x in v if not isinstance(x, bytes)]
                if not isinstance(v, bytes):
                    return [str(v)]
        return []

    def _is_member_in_chain(self, group_dn: str, target_dn: str, visited: set[str]) -> bool:
        glow = group_dn.lower()
        if glow in visited:
            return False
        visited.add(glow)
        grp = next((e for e in self.entries if e["dn"].lower() == glow), None)
        if grp is None:
            return False
        members = [m.lower() for m in self._get_entry_vals(grp, "member")]
        if target_dn.lower() in members:
            return True
        for child_dn in members:
            if self._is_member_in_chain(child_dn, target_dn, visited):
                return True
        return False

    def _eval_filter(self, ast_node: Any, entry: dict[str, Any]) -> bool:
        kind = ast_node[0]
        if kind == "and":
            return all(self._eval_filter(c, entry) for c in ast_node[1])
        if kind == "or":
            return any(self._eval_filter(c, entry) for c in ast_node[1])
        if kind == "not":
            return not self._eval_filter(ast_node[1], entry)
        if kind == "present":
            return len(self._get_entry_vals(entry, ast_node[1])) > 0
        if kind == "eq":
            _, attr, val = ast_node
            vlow = val.lower()
            return any(item.lower() == vlow for item in self._get_entry_vals(entry, attr))
        if kind == "ext":
            _, attr, rule, val = ast_node
            if attr.lower() == "member" and rule == AD_IN_CHAIN_OID:
                return self._is_member_in_chain(entry["dn"], val, set())
            return False
        return False

    def _decode_req_paged_cookie(self, controls_body: bytes | None) -> tuple[bool, int, bytes]:
        if not controls_body:
            return False, 0, b""
        pos = 0
        while pos < len(controls_body):
            ct, cb, pos = _decode_ber_tlv(controls_body, pos)
            if ct != 0x30:
                continue
            _, oid_b, ip = _decode_ber_tlv(cb, 0)
            if oid_b.decode("ascii", errors="replace") != PAGED_RESULTS_OID:
                continue
            val_b = b""
            while ip < len(cb):
                ft, fb, ip = _decode_ber_tlv(cb, ip)
                if ft == 0x04:
                    val_b = fb
            _, sb, _ = _decode_ber_tlv(val_b, 0)
            _, sz_b, sp = _decode_ber_tlv(sb, 0)
            _, ck_b, _ = _decode_ber_tlv(sb, sp)
            return True, _decode_ber_int(sz_b), ck_b
        return False, 0, b""

    def _encode_entry_msg(self, msg_id: int, entry: dict[str, Any]) -> bytes:
        part_attrs: list[bytes] = []
        for k, raw_v in entry.get("attrs", {}).items():
            vals = raw_v if isinstance(raw_v, list) else [raw_v]
            enc_vals = [
                _ber_octet_string(v if isinstance(v, bytes) else str(v).encode("utf-8"))
                for v in vals
            ]
            part_attrs.append(
                _ber_seq(
                    [
                        _ber_octet_string(k.encode("utf-8")),
                        _ber_seq(enc_vals, tag=0x31),
                    ]
                )
            )
        op = _ber_seq(
            [
                _ber_octet_string(entry["dn"].encode("utf-8")),
                _ber_seq(part_attrs),
            ],
            tag=0x64,
        )
        return _ber_seq([_ber_int(msg_id), op])

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        try:
            while not self._stop.is_set():
                pkt = self._recv_ber_msg(conn)
                if pkt is None:
                    break
                _, msg_body, _ = _decode_ber_tlv(pkt, 0)
                _, id_b, pos = _decode_ber_tlv(msg_body, 0)
                msg_id = _decode_ber_int(id_b)
                op_tag, op_body, pos = _decode_ber_tlv(msg_body, pos)
                controls_body: bytes | None = None
                if pos < len(msg_body):
                    ct, cb, _ = _decode_ber_tlv(msg_body, pos)
                    if ct == 0xA0:
                        controls_body = cb

                if op_tag == 0x60:  # BindRequest
                    self.bind_count += 1
                    _, ver_b, bp = _decode_ber_tlv(op_body, 0)
                    assert _decode_ber_int(ver_b) == 3
                    _, dn_b, bp = _decode_ber_tlv(op_body, bp)
                    _, pw_b, _ = _decode_ber_tlv(op_body, bp)
                    dn_s = dn_b.decode("utf-8")
                    pw_s = pw_b.decode("utf-8")
                    if self.expected_bind_dn and (
                        dn_s != self.expected_bind_dn or pw_s != self.expected_bind_pw
                    ):
                        res = _ber_seq(
                            [
                                _ber_int(49, tag=0x0A),
                                _ber_octet_string(b""),
                                _ber_octet_string(b"Invalid credentials"),
                            ],
                            tag=0x61,
                        )
                    else:
                        res = _ber_seq(
                            [
                                _ber_int(0, tag=0x0A),
                                _ber_octet_string(b""),
                                _ber_octet_string(b""),
                            ],
                            tag=0x61,
                        )
                    conn.sendall(_ber_seq([_ber_int(msg_id), res]))

                elif op_tag == 0x63:  # SearchRequest
                    _, _base_b, sp = _decode_ber_tlv(op_body, 0)
                    _, _scope_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _deref_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _size_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _time_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _types_b, sp = _decode_ber_tlv(op_body, sp)
                    filter_ast, _ = self._parse_ber_filter(op_body, sp)
                    self.recorded_filters.append(filter_ast)

                    matched = [e for e in self.entries if self._eval_filter(filter_ast, e)]
                    has_pg, req_pg_size, cookie = self._decode_req_paged_cookie(controls_body)

                    start_idx = int(cookie.decode("ascii")) if cookie else 0
                    eff_page = min(req_pg_size or self.max_page_size, self.max_page_size)
                    sliced = matched[start_idx : start_idx + eff_page] if has_pg else matched
                    next_idx = start_idx + len(sliced)
                    next_cookie = (
                        str(next_idx).encode("ascii")
                        if (has_pg and next_idx < len(matched))
                        else b""
                    )

                    for item in sliced:
                        conn.sendall(self._encode_entry_msg(msg_id, item))

                    if self.emit_referral and start_idx == 0:
                        ref_op = _ber_seq(
                            [_ber_octet_string(b"ldap://ForestDnsZones.ad.bls-isp.net/DC=ad")],
                            tag=0x73,
                        )
                        conn.sendall(_ber_seq([_ber_int(msg_id), ref_op]))

                    done_op = _ber_seq(
                        [
                            _ber_int(0, tag=0x0A),
                            _ber_octet_string(b""),
                            _ber_octet_string(b""),
                        ],
                        tag=0x65,
                    )
                    done_items = [_ber_int(msg_id), done_op]
                    if has_pg:
                        cval = _ber_seq([_ber_int(len(matched)), _ber_octet_string(next_cookie)])
                        ctrl = _ber_seq(
                            [
                                _ber_octet_string(PAGED_RESULTS_OID.encode("ascii")),
                                _ber_bool(False),
                                _ber_octet_string(cval),
                            ]
                        )
                        done_items.append(_ber_seq([ctrl], tag=0xA0))
                    conn.sendall(_ber_seq(done_items))

                elif op_tag == 0x42:  # UnbindRequest
                    self.unbind_count += 1
                    break
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _sample_ad_directory_entries() -> list[dict[str, Any]]:
    da_dn = "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"
    du_dn = "CN=Domain Users,CN=Users,DC=ad,DC=bls-isp,DC=net"
    ops_dn = "CN=MSP Operations,OU=Groups,DC=ad,DC=bls-isp,DC=net"
    noc_dn = "CN=MSP Tier-1 NOC,OU=SubTeams,OU=Groups,DC=ad,DC=bls-isp,DC=net"
    ro_dn = "CN=MSP ReadOnly,OU=Groups,DC=ad,DC=bls-isp,DC=net"

    genera_dn = "CN=Genera Admin,CN=Users,DC=ad,DC=bls-isp,DC=net"
    nested_user_dn = "CN=Nora Engineer,OU=Staff,DC=ad,DC=bls-isp,DC=net"
    viewer_user_dn = "CN=Viktor Viewer,OU=Staff,DC=ad,DC=bls-isp,DC=net"
    unmapped_dn = "CN=External Contractor,OU=Guests,DC=ad,DC=bls-isp,DC=net"

    return [
        {
            "dn": da_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "Domain Admins",
                "sAMAccountName": "Domain Admins",
                "description": "Designated administrators of the domain",
                "primaryGroupToken": "512",
                "member": [genera_dn],
            },
        },
        {
            "dn": du_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "Domain Users",
                "sAMAccountName": "Domain Users",
                "description": "All domain users",
                "objectSid": _build_ad_sid(513),
                "member": [],
            },
        },
        {
            "dn": ops_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP Operations",
                "sAMAccountName": "MSP-Operations",
                "description": "Org 1 Editor engineering group",
                # Nested AD group: noc_dn is a member of ops_dn!
                "member": [noc_dn],
            },
        },
        {
            "dn": noc_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP Tier-1 NOC",
                "sAMAccountName": "MSP-Tier1-NOC",
                "description": "Nested child NOC team",
                "member": [nested_user_dn],
            },
        },
        {
            "dn": ro_dn,
            "attrs": {
                "objectClass": ["top", "group"],
                "cn": "MSP ReadOnly",
                "sAMAccountName": "MSP-ReadOnly",
                "description": "Org 1 Viewer audit group",
                "member": [viewer_user_dn],
            },
        },
        {
            "dn": genera_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Genera Admin",
                "displayName": "Genera MSP Admin",
                "sAMAccountName": "Genera",
                "userPrincipalName": "Genera@ad.bls-isp.net",
                "mail": "genera@bls-isp.net",
                "memberOf": [da_dn],
                "primaryGroupID": "513",
            },
        },
        {
            "dn": nested_user_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Nora Engineer",
                "givenName": "Nora",
                "sn": "Engineer",
                "sAMAccountName": "n.engineer",
                "userPrincipalName": "n.engineer@ad.bls-isp.net",
                "mail": "nora@bls-isp.net",
                # Direct member ONLY of child group noc_dn; inherits ops_dn via 1.2.840.113556.1.4.1941!
                "memberOf": [noc_dn],
                "primaryGroupID": "513",
            },
        },
        {
            "dn": viewer_user_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "Viktor Viewer",
                "displayName": "Viktor ReadOnly",
                "sAMAccountName": "v.viewer",
                "mail": "viktor@bls-isp.net",
                "memberOf": [ro_dn],
                "primaryGroupID": "513",
            },
        },
        {
            "dn": unmapped_dn,
            "attrs": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": "External Contractor",
                "sAMAccountName": "contractor",
                "mail": "ext@partner.example",
                "memberOf": [],
                "primaryGroupID": "513",
            },
        },
    ]


class TestLiveLDAPv3ClientDiscoveryAndTester:
    def test_ad_paged_group_discovery_login_tester_nested_groups_and_filter_injection_block(
        self, tmp_path: Path
    ) -> None:
        bind_dn = "CN=ldapsvc,CN=Users,DC=ad,DC=bls-isp,DC=net"
        bind_pw = "S3cr3t#BindPass!"
        srv = MockLDAPv3Server(
            expected_bind_dn=bind_dn,
            expected_bind_pw=bind_pw,
            entries=_sample_ad_directory_entries(),
            max_page_size=2,  # Force 3 RFC 2696 pages across 5 AD groups!
        )
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
                            "bind_dn": bind_dn,
                            "bind_password": bind_pw,
                            "tls": False,
                        }
                    }
                )
            }

            # 1. Execute real NS8 `discover-ldap-groups` action (paged BER search + referral skip)
            rc, out, err = run_ns8_action(
                "discover-ldap-groups",
                {"domain": "ad.bls-isp.net"},
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc == 0, err
            disc = json.loads(out)
            assert disc["ok"] is True
            assert disc["schema"] == "ad"
            assert disc["base_dn"] == "DC=ad,DC=bls-isp,DC=net"
            assert len(disc["groups"]) == 5
            by_name = {g["name"]: g["dn"] for g in disc["groups"]}
            assert by_name["Domain Admins"] == "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"
            assert by_name["MSP Operations"] == "CN=MSP Operations,OU=Groups,DC=ad,DC=bls-isp,DC=net"
            assert by_name["MSP ReadOnly"] == "CN=MSP ReadOnly,OU=Groups,DC=ad,DC=bls-isp,DC=net"
            assert srv.unbind_count >= 1

            # 2. Test Admin user (`Genera`) using short group name `"Domain Admins"`
            rc, out, err = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ad.bls-isp.net",
                    "username": "Genera",
                    "ldap_admin_group": "Domain Admins",
                    "ldap_editor_group": "MSP Operations",
                    "ldap_viewer_group": "MSP ReadOnly",
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc == 0, err
            res_admin = json.loads(out)
            assert res_admin["ok"] is True
            assert res_admin["found"] is True
            assert res_admin["matched_role"] == "Admin"
            assert res_admin["grafana_admin"] is True
            assert "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net" in res_admin["member_of"]
            # Primary group RID 513 (`Domain Users`) resolved from binary objectSid!
            assert "CN=Domain Users,CN=Users,DC=ad,DC=bls-isp,DC=net" in res_admin["member_of"]

            # 3. Test Nested AD Group user (`n.engineer` in child `MSP Tier-1 NOC` -> parent `MSP Operations`)
            rc, out, err = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ad.bls-isp.net",
                    "username": "n.engineer",
                    "ldap_admin_group": "Domain Admins",
                    "ldap_editor_group": "MSP-Operations",  # matched by sAMAccountName!
                    "ldap_viewer_group": "MSP ReadOnly",
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc == 0, err
            res_nested = json.loads(out)
            assert res_nested["found"] is True
            assert res_nested["display_name"] == "Nora Engineer"
            assert res_nested["matched_role"] == "Editor"
            assert res_nested["grafana_admin"] is False
            assert "CN=MSP Operations,OU=Groups,DC=ad,DC=bls-isp,DC=net" in res_nested["member_of"]

            # 4. Test Org 1 Viewer user (`v.viewer`)
            rc, out, err = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ad.bls-isp.net",
                    "username": "v.viewer",
                    "ldap_admin_group": "Domain Admins",
                    "ldap_editor_group": "MSP Operations",
                    "ldap_viewer_group": "CN=MSP ReadOnly,OU=Groups,DC=ad,DC=bls-isp,DC=net",
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc == 0, err
            res_viewer = json.loads(out)
            assert res_viewer["matched_role"] == "Viewer"
            assert res_viewer["grafana_admin"] is False

            # 5. Test unmapped user (`contractor`) -> matched_role == "None"
            rc, out, err = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ad.bls-isp.net",
                    "username": "contractor",
                    "ldap_admin_group": "Domain Admins",
                    "ldap_editor_group": "MSP Operations",
                    "ldap_viewer_group": "MSP ReadOnly",
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc == 0, err
            res_none = json.loads(out)
            assert res_none["found"] is True
            assert res_none["matched_role"] == "None"
            assert res_none["grafana_admin"] is False

            # 6. RFC 4515 LDAP Filter-Injection Attempts MUST be escaped and never match `Genera`!
            assert (
                escape_ldap_filter_value("Genera)(|(objectClass=*")
                == "Genera\\29\\28|\\28objectClass=\\2a"
            )
            assert escape_ldap_filter_value("a\\b\x00c") == "a\\5cb\\00c"

            for payload_user in (
                "Genera)(|(objectClass=*",
                "*)(sAMAccountName=Genera",
                "Genera*",
                "Genera\x00injected",
            ):
                srv.recorded_filters.clear()
                rc, out, err = run_ns8_action(
                    "test-ldap-user",
                    {
                        "domain": "ad.bls-isp.net",
                        "username": payload_user,
                        "ldap_admin_group": "Domain Admins",
                    },
                    state_dir,
                    extra_env=mock_lp_env,
                )
                assert rc == 0, err
                inj_res = json.loads(out)
                assert inj_res["found"] is False, f"Filter injection succeeded for {payload_user!r}"
                assert inj_res["matched_role"] == "None"
                # Confirm wire BER filter compiled strictly to equalityMatch (`eq`), never `present`/`substr`!
                user_search_ast = srv.recorded_filters[0]
                or_branch = user_search_ast[1][1]
                assert or_branch[0] == "or"
                for leaf in or_branch[1]:
                    assert leaf[0] == "eq"
                    assert leaf[2] == payload_user
        finally:
            srv.stop()

    def test_openldap_rfc2307_discovery_and_posixgroup_memberuid_tester(
        self, tmp_path: Path
    ) -> None:
        entries = [
            {
                "dn": "cn=msp-admins,ou=Groups,dc=ldap,dc=example,dc=org",
                "attrs": {
                    "objectClass": ["top", "posixGroup"],
                    "cn": "msp-admins",
                    "description": "POSIX Admins",
                    "memberUid": ["alice"],
                },
            },
            {
                "dn": "cn=msp-viewers,ou=Groups,dc=ldap,dc=example,dc=org",
                "attrs": {
                    "objectClass": ["top", "groupOfNames"],
                    "cn": "msp-viewers",
                    "description": "LDAP Viewers",
                    "member": ["uid=bob,ou=People,dc=ldap,dc=example,dc=org"],
                },
            },
            {
                "dn": "uid=alice,ou=People,dc=ldap,dc=example,dc=org",
                "attrs": {
                    "objectClass": ["inetOrgPerson", "posixAccount"],
                    "uid": "alice",
                    "cn": "Alice Operator",
                    "mail": "alice@example.org",
                },
            },
            {
                "dn": "uid=bob,ou=People,dc=ldap,dc=example,dc=org",
                "attrs": {
                    "objectClass": ["inetOrgPerson", "posixAccount"],
                    "uid": "bob",
                    "cn": "Bob Auditor",
                    "mail": "bob@example.org",
                },
            },
        ]
        srv = MockLDAPv3Server(entries=entries, emit_referral=False)
        srv.start()
        try:
            state_dir = tmp_path / "state"
            state_dir.mkdir(parents=True)
            mock_lp_env = {
                "HUB_TEST_LDAPPROXY_JSON": json.dumps(
                    {
                        "ldap.example.org": {
                            "host": "127.0.0.1",
                            "port": srv.port,
                            "schema": "rfc2307",
                            "base_dn": "dc=ldap,dc=example,dc=org",
                            "bind_dn": "",
                            "bind_password": "",
                        }
                    }
                )
            }
            rc, out, err = run_ns8_action(
                "discover-ldap-groups",
                {"domain": "ldap.example.org"},
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc == 0, err
            disc = json.loads(out)
            assert disc["ok"] is True
            assert [g["name"] for g in disc["groups"]] == ["msp-admins", "msp-viewers"]

            rc_a, out_a, _ = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ldap.example.org",
                    "username": "alice",
                    "ldap_admin_group": "msp-admins",
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc_a == 0
            assert json.loads(out_a)["matched_role"] == "Admin"

            rc_b, out_b, _ = run_ns8_action(
                "test-ldap-user",
                {
                    "domain": "ldap.example.org",
                    "username": "bob@example.org",
                    "ldap_viewer_group": "msp-viewers",
                },
                state_dir,
                extra_env=mock_lp_env,
            )
            assert rc_b == 0
            assert json.loads(out_b)["matched_role"] == "Viewer"
        finally:
            srv.stop()

    @pytest.mark.asyncio
    async def test_ldap_sync_short_name_ad_resolution_offline_fallback_and_live_grafana_reload(
        self, tmp_path: Path, aiohttp_server: Any
    ) -> None:
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        reload_hits: list[str] = []
        g_app = web.Application()

        async def _health(_r: web.Request) -> web.Response:
            return web.json_response({"database": "ok"})

        async def _ldap_reload(r: web.Request) -> web.Response:
            reload_hits.append(r.headers.get("Authorization", ""))
            return web.json_response({"message": "LDAP config reloaded"})

        g_app.router.add_get("/api/health", _health)
        g_app.router.add_post("/api/admin/provisioning/ldap/reload", _ldap_reload)
        g_srv = await aiohttp_server(g_app)
        grafana_url = f"http://127.0.0.1:{g_srv.port}"

        ldap_srv = MockLDAPv3Server(entries=_sample_ad_directory_entries())
        ldap_srv.start()
        try:

            class LiveFakeLdapproxy:
                def get_domain(self, _d: str) -> dict[str, Any]:
                    return {
                        "host": "127.0.0.1",
                        "port": ldap_srv.port,
                        "schema": "ad",
                        "base_dn": "DC=ad,DC=bls-isp,DC=net",
                        "bind_dn": "",
                        "bind_password": "",
                    }

            loop = asyncio.get_running_loop()
            toml_path = await loop.run_in_executor(
                None,
                lambda: sync_ldap_config(
                    state_dir,
                    {
                        "GRAFANA_URL": grafana_url,
                        "GRAFANA_ADMIN_PASSWORD": "adm-pw",
                        "LDAP_ENABLED": "true",
                        "LDAP_DOMAIN": "ad.bls-isp.net",
                        "LDAP_ADMIN_GROUP": "Domain Admins",
                        "LDAP_EDITOR_GROUP": "MSP Operations",
                        "LDAP_VIEWER_GROUP": "MSP ReadOnly",
                    },
                    ldapproxy_factory=LiveFakeLdapproxy,
                ),
            )
            assert toml_path is not None and toml_path.exists()
            txt = toml_path.read_text(encoding="utf-8")

            # Verified true AD Distinguished Names resolved from live LDAPv3 discovery!
            assert 'group_dn = "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"' in txt
            assert 'group_dn = "CN=MSP Operations,OU=Groups,DC=ad,DC=bls-isp,DC=net"' in txt
            assert 'group_dn = "CN=MSP ReadOnly,OU=Groups,DC=ad,DC=bls-isp,DC=net"' in txt
            assert 'org_role = "Viewer"' in txt
            # Verified recursive AD nested-group OID & distinguishedName user attribute!
            assert (
                f'group_search_filter = "(&(objectClass=group)(member:{AD_IN_CHAIN_OID}:=%s))"'
                in txt
            )
            assert 'group_search_filter_user_attribute = "distinguishedName"' in txt
            assert 'group_search_base_dns = ["DC=ad,DC=bls-isp,DC=net"]' in txt
            assert 'group_dn = "*"' not in txt
            assert len(reload_hits) == 1
        finally:
            ldap_srv.stop()

        # Now test offline fallback when Ldapproxy port is closed: MUST emit CN=...,CN=Users,<base_dn>!
        class OfflineLdapproxy:
            def get_domain(self, _d: str) -> dict[str, Any]:
                return {
                    "host": "127.0.0.1",
                    "port": ldap_srv.port,  # already stopped!
                    "schema": "ad",
                    "base_dn": "DC=ad,DC=bls-isp,DC=net",
                    "bind_dn": "",
                    "bind_password": "",
                }

        offline_toml = await loop.run_in_executor(
            None,
            lambda: sync_ldap_config(
                state_dir,
                {
                    "GRAFANA_URL": grafana_url,
                    "LDAP_ENABLED": "true",
                    "LDAP_DOMAIN": "ad.bls-isp.net",
                    "LDAP_ADMIN_GROUP": "Domain Admins",
                },
                ldapproxy_factory=OfflineLdapproxy,
            ),
        )
        assert offline_toml is not None
        off_txt = offline_toml.read_text(encoding="utf-8")
        assert 'group_dn = "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net"' in off_txt
        assert 'group_dn = "CN=Domain Admins,DC=ad,DC=bls-isp,DC=net"' not in off_txt
        assert len(reload_hits) == 2


class TestMultiUserCustomerPortalLifecycle:
    @pytest.mark.asyncio
    async def test_multi_user_portal_crud_roles_disable_delete_uniqueness_and_legacy_migration(
        self, tmp_path: Path, aiohttp_server: Any
    ) -> None:
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)

        g_state: dict[str, Any] = {
            "next_org_id": 2,
            "next_ds_id": 1,
            "next_user_id": 2,
            "orgs": {1: {"id": 1, "name": "Main Org."}},
            "datasources": {1: {}},
            "folders": {1: {}},
            "dashboards": {1: []},
            "users": {},  # uid -> user dict
            "org_users": {1: {}},  # oid -> {uid: role}
            "disabled_uids": set(),
            "deleted_uids": set(),
        }

        g_app = web.Application()

        def _oid(req: web.Request) -> int:
            return int(req.headers.get("X-Grafana-Org-Id", "1"))

        async def _health(_r: web.Request) -> web.Response:
            return web.json_response({"database": "ok"})

        async def _get_orgs(_r: web.Request) -> web.Response:
            return web.json_response(list(g_state["orgs"].values()))

        async def _get_org(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            if oid not in g_state["orgs"]:
                return web.json_response({}, status=404)
            return web.json_response(g_state["orgs"][oid])

        async def _get_org_by_name(r: web.Request) -> web.Response:
            name = r.match_info["name"]
            for o in g_state["orgs"].values():
                if o["name"] == name:
                    return web.json_response(o)
            return web.json_response({}, status=404)

        async def _create_org(r: web.Request) -> web.Response:
            body = await r.json()
            oid = g_state["next_org_id"]
            g_state["next_org_id"] += 1
            g_state["orgs"][oid] = {"id": oid, "name": body["name"]}
            g_state["datasources"][oid] = {}
            g_state["org_users"][oid] = {}
            return web.json_response({"orgId": oid})

        async def _put_org(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            body = await r.json()
            g_state["orgs"][oid]["name"] = body["name"]
            return web.json_response({})

        async def _get_ds(r: web.Request) -> web.Response:
            ds = g_state["datasources"].get(_oid(r), {}).get(r.match_info["uid"])
            return web.json_response(ds) if ds else web.json_response({}, status=404)

        async def _post_ds(r: web.Request) -> web.Response:
            b = await r.json()
            b["id"] = g_state["next_ds_id"]
            g_state["next_ds_id"] += 1
            g_state["datasources"].setdefault(_oid(r), {})[b["uid"]] = b
            return web.json_response({"id": b["id"]})

        async def _put_ds(r: web.Request) -> web.Response:
            b = await r.json()
            b["id"] = int(r.match_info["id"])
            g_state["datasources"].setdefault(_oid(r), {})[b["uid"]] = b
            return web.json_response({"id": b["id"]})

        async def _folder(r: web.Request) -> web.Response:
            f = g_state["folders"].get(_oid(r), {}).get(r.match_info.get("uid", ""))
            return web.json_response(f) if f else web.json_response({}, status=404)

        async def _post_folder(r: web.Request) -> web.Response:
            b = await r.json()
            g_state["folders"].setdefault(_oid(r), {})[b["uid"]] = b
            return web.json_response(b)

        async def _post_dash(r: web.Request) -> web.Response:
            b = await r.json()
            g_state["dashboards"].setdefault(_oid(r), []).append(b["dashboard"])
            return web.json_response({"status": "success"})

        async def _lookup_user(r: web.Request) -> web.Response:
            q = (r.query.get("loginOrEmail") or "").lower()
            for u in g_state["users"].values():
                if u["login"].lower() == q:
                    return web.json_response(u)
            return web.json_response({}, status=404)

        async def _create_user(r: web.Request) -> web.Response:
            b = await r.json()
            uid = g_state["next_user_id"]
            g_state["next_user_id"] += 1
            g_state["users"][uid] = {
                "id": uid,
                "login": b["login"],
                "name": b.get("name", ""),
                "email": b.get("email", ""),
                "password": b.get("password", ""),
                "isGrafanaAdmin": False,
            }
            # Grafana default auto_assign_org=true puts every created user in Org 1 first
            g_state["org_users"][1][uid] = "Viewer"
            return web.json_response({"id": uid})

        async def _put_user(r: web.Request) -> web.Response:
            uid = int(r.match_info["uid"])
            b = await r.json()
            if uid in g_state["users"]:
                g_state["users"][uid]["name"] = b.get("name", "")
                g_state["users"][uid]["email"] = b.get("email", "")
            return web.json_response({})

        async def _put_pw(r: web.Request) -> web.Response:
            uid = int(r.match_info["uid"])
            b = await r.json()
            g_state["users"][uid]["password"] = b["password"]
            return web.json_response({})

        async def _enable_u(r: web.Request) -> web.Response:
            g_state["disabled_uids"].discard(int(r.match_info["uid"]))
            return web.json_response({})

        async def _disable_u(r: web.Request) -> web.Response:
            g_state["disabled_uids"].add(int(r.match_info["uid"]))
            return web.json_response({})

        async def _delete_u(r: web.Request) -> web.Response:
            uid = int(r.match_info["uid"])
            if uid not in g_state["users"]:
                return web.json_response({}, status=404)
            del g_state["users"][uid]
            for members in g_state["org_users"].values():
                members.pop(uid, None)
            g_state["deleted_uids"].add(uid)
            return web.json_response({"message": "User deleted"})

        async def _get_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            return web.json_response(
                [
                    {"userId": uid, "login": g_state["users"][uid]["login"], "role": role}
                    for uid, role in g_state["org_users"].get(oid, {}).items()
                    if uid in g_state["users"]
                ]
            )

        async def _add_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            b = await r.json()
            u = next(
                x for x in g_state["users"].values() if x["login"].lower() == b["loginOrEmail"].lower()
            )
            g_state["org_users"].setdefault(oid, {})[u["id"]] = b["role"]
            return web.json_response({})

        async def _patch_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            uid = int(r.match_info["uid"])
            b = await r.json()
            g_state["org_users"].setdefault(oid, {})[uid] = b["role"]
            return web.json_response({})

        async def _del_ou(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            uid = int(r.match_info["uid"])
            if uid not in g_state["org_users"].get(oid, {}):
                return web.json_response({}, status=404)
            del g_state["org_users"][oid][uid]
            return web.json_response({})

        async def _using(_r: web.Request) -> web.Response:
            return web.json_response({})

        g_app.router.add_get("/api/health", _health)
        g_app.router.add_get("/api/orgs", _get_orgs)
        g_app.router.add_get("/api/orgs/{oid:\\d+}", _get_org)
        g_app.router.add_get("/api/orgs/name/{name}", _get_org_by_name)
        g_app.router.add_post("/api/orgs", _create_org)
        g_app.router.add_put("/api/orgs/{oid:\\d+}", _put_org)
        g_app.router.add_get("/api/datasources/uid/{uid}", _get_ds)
        g_app.router.add_post("/api/datasources", _post_ds)
        g_app.router.add_put("/api/datasources/{id:\\d+}", _put_ds)
        g_app.router.add_get("/api/folders/{uid}", _folder)
        g_app.router.add_post("/api/folders", _post_folder)
        g_app.router.add_post("/api/dashboards/db", _post_dash)
        g_app.router.add_get("/api/users/lookup", _lookup_user)
        g_app.router.add_post("/api/admin/users", _create_user)
        g_app.router.add_put("/api/users/{uid:\\d+}", _put_user)
        g_app.router.add_put("/api/admin/users/{uid:\\d+}/password", _put_pw)
        g_app.router.add_post("/api/admin/users/{uid:\\d+}/enable", _enable_u)
        g_app.router.add_post("/api/admin/users/{uid:\\d+}/disable", _disable_u)
        g_app.router.add_delete("/api/admin/users/{uid:\\d+}", _delete_u)
        g_app.router.add_get("/api/orgs/{oid:\\d+}/users", _get_ou)
        g_app.router.add_post("/api/orgs/{oid:\\d+}/users", _add_ou)
        g_app.router.add_patch("/api/orgs/{oid:\\d+}/users/{uid:\\d+}", _patch_ou)
        g_app.router.add_delete("/api/orgs/{oid:\\d+}/users/{uid:\\d+}", _del_ou)
        g_app.router.add_post("/api/users/{uid:\\d+}/using/{oid:\\d+}", _using)

        g_srv = await aiohttp_server(g_app)
        extra_env = {
            "GRAFANA_URL": f"http://127.0.0.1:{g_srv.port}",
            "GRAFANA_ADMIN_PASSWORD": "test-admin-password",
            "TRAEFIK_HOST": "monitoring.msp.example.com",
        }
        loop = asyncio.get_running_loop()

        async def _act(action: str, payload: dict[str, Any]) -> tuple[int, str, str]:
            return await loop.run_in_executor(
                None,
                lambda: run_ns8_action(action, payload, state_dir, extra_env=extra_env),
            )

        # 1. Create tenant with `customer_portal_enabled=True` and 0 initial users (`portal_viewer_username=""`)
        rc, out, err = await _act(
            "save-tenant",
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp GmbH",
                "sites": ["hq"],
                "customer_portal_enabled": True,
                "portal_viewer_username": "",
                "portal_viewer_password": "",
            },
        )
        assert rc == 0, err
        saved_t = json.loads(out)
        assert saved_t["grafana_org_id"] == 2
        assert saved_t["grafana_org_name"] == "Customer: Acme Corp GmbH (acme-corp)"
        assert saved_t["grafana_login_url"] == "https://monitoring.msp.example.com/login"
        assert saved_t["portal_users_count"] == 0

        # Also create second tenant `beta-gmbh` to test cross-tenant username collision blocking
        rc_b, _, err_b = await _act(
            "save-tenant",
            {
                "customer": "beta-gmbh",
                "display_name": "Beta GmbH",
                "sites": ["berlin"],
                "customer_portal_enabled": True,
            },
        )
        assert rc_b == 0, err_b

        # 2. Create Portal User 1 (`Viewer`) and Portal User 2 (`Editor`) on `acme-corp`
        rc1, out1, err1 = await _act(
            "save-portal-user",
            {
                "customer": "acme-corp",
                "username": "acme.ops",
                "full_name": "Acme NOC Viewer",
                "email": "ops@acme.example.com",
                "role": "Viewer",
                "disabled": False,
                "password": "ViewerStrongPassword1!",
            },
        )
        assert rc1 == 0, err1
        res_u1 = json.loads(out1)
        assert res_u1["grafana_synced"] is True
        assert res_u1["user"]["role"] == "Viewer"
        assert "ViewerStrongPassword1!" not in out1

        rc2, out2, err2 = await _act(
            "save-portal-user",
            {
                "customer": "acme-corp",
                "username": "acme.cto",
                "full_name": "Acme CTO",
                "email": "cto@acme.example.com",
                "role": "Editor",
                "disabled": False,
                "password": "EditorStrongPassword2!",
            },
        )
        assert rc2 == 0, err2
        res_u2 = json.loads(out2)
        assert res_u2["grafana_synced"] is True
        assert res_u2["user"]["role"] == "Editor"

        # Verify strict isolation in Grafana: Org 2 has Viewer + Editor, Org 1 & Org 3 have NEITHER!
        u1_id = next(u["id"] for u in g_state["users"].values() if u["login"] == "acme.ops")
        u2_id = next(u["id"] for u in g_state["users"].values() if u["login"] == "acme.cto")
        assert g_state["org_users"][2] == {u1_id: "Viewer", u2_id: "Editor"}
        assert u1_id not in g_state["org_users"][1]
        assert u2_id not in g_state["org_users"][1]
        assert u1_id not in g_state["org_users"][3]
        assert u2_id not in g_state["org_users"][3]
        assert g_state["users"][u1_id]["isGrafanaAdmin"] is False
        assert g_state["users"][u2_id]["isGrafanaAdmin"] is False
        assert g_state["users"][u1_id]["password"] == "ViewerStrongPassword1!"
        assert g_state["users"][u2_id]["password"] == "EditorStrongPassword2!"

        # Plaintext passwords MUST NOT appear in `tenants.json`
        tenants_disk = (state_dir / "tenants.json").read_text(encoding="utf-8")
        assert "ViewerStrongPassword1!" not in tenants_disk
        assert "EditorStrongPassword2!" not in tenants_disk

        # 3. `list-tenants` and `list-portal-users` expose accurate counts & metadata
        rc_lt, out_lt, _ = await _act("list-tenants", {})
        assert rc_lt == 0
        acme_row = next(t for t in json.loads(out_lt)["tenants"] if t["customer"] == "acme-corp")
        assert acme_row["portal_users_count"] == 2
        assert acme_row["portal_viewer_username"] == "acme.ops"
        assert acme_row["grafana_login_url"] == "https://monitoring.msp.example.com/login"

        rc_lp, out_lp, _ = await _act("list-portal-users", {"customer": "acme-corp"})
        assert rc_lp == 0
        lp_doc = json.loads(out_lp)
        assert len(lp_doc["users"]) == 2
        assert lp_doc["grafana_org_name"] == "Customer: Acme Corp GmbH (acme-corp)"

        # 4. Cross-tenant case-insensitive duplicate username & reserved username MUST fail (exit 2)
        rc_dup, out_dup, _ = await _act(
            "save-portal-user",
            {
                "customer": "beta-gmbh",
                "username": "ACME.CTO",
                "role": "Viewer",
                "password": "AnotherStrongPassword3!",
            },
        )
        assert rc_dup == 2
        assert "already in use" in out_dup

        rc_res, _, _ = await _act(
            "save-portal-user",
            {
                "customer": "beta-gmbh",
                "username": "admin",
                "role": "Viewer",
                "password": "AnotherStrongPassword3!",
            },
        )
        assert rc_res == 2

        # 5. Update `acme.cto` with `password_unchanged=True` + `disabled=True` -> evicted & disabled!
        rc_dis, _, err_dis = await _act(
            "save-portal-user",
            {
                "customer": "acme-corp",
                "username": "acme.cto",
                "full_name": "Acme CTO (On Leave)",
                "email": "cto@acme.example.com",
                "role": "Viewer",
                "disabled": True,
                "password": "",
                "password_unchanged": True,
            },
        )
        assert rc_dis == 0, err_dis
        assert u2_id not in g_state["org_users"][2]
        assert u2_id in g_state["disabled_uids"]
        # Sealed password preserved across `password_unchanged=True`!
        assert load_portal_viewer_secret(state_dir, "acme-corp", "acme.cto") == "EditorStrongPassword2!"

        # Re-enable `acme.cto` with `password_unchanged=True` -> restored in Org 2 with preserved password!
        rc_en, _, err_en = await _act(
            "save-portal-user",
            {
                "customer": "acme-corp",
                "username": "acme.cto",
                "full_name": "Acme CTO",
                "email": "cto@acme.example.com",
                "role": "Editor",
                "disabled": False,
                "password": "",
                "password_unchanged": True,
            },
        )
        assert rc_en == 0, err_en
        assert g_state["org_users"][2][u2_id] == "Editor"
        assert u2_id not in g_state["disabled_uids"]

        # 6. Delete `acme.ops` via `delete-portal-user` -> deleted from Grafana (`DELETE /api/admin/users/<id>`)!
        rc_del, out_del, err_del = await _act(
            "delete-portal-user",
            {"customer": "acme-corp", "username": "acme.ops"},
        )
        assert rc_del == 0, err_del
        del_doc = json.loads(out_del)
        assert del_doc["status"] == "deleted"
        assert del_doc["grafana_synced"] is True
        assert u1_id in g_state["deleted_uids"]
        assert u1_id not in g_state["users"]
        assert load_portal_viewer_secret(state_dir, "acme-corp", "acme.ops") is None
        # `acme.cto` automatically promoted to primary secret compatibility slot!
        assert load_portal_viewer_secret(state_dir, "acme-corp") == "EditorStrongPassword2!"

    def test_seamless_auto_migration_of_legacy_v100_portal_viewer_username(
        self, tmp_path: Path
    ) -> None:
        state_dir = tmp_path / "legacy_state"
        state_dir.mkdir(parents=True)

        # Write a v1.0.0-format `tenants.json` without `portal_users` key + legacy `<customer>` secret
        from hub_tenancy.store import save_portal_viewer_secret

        legacy_doc = {
            "version": 1,
            "tenants": [
                {
                    "customer": "legacy-co",
                    "display_name": "Legacy Co",
                    "sites": ["hq"],
                    "default_site": "hq",
                    "contact_emails": [],
                    "token_sha256": "0" * 64,
                    "token_prefix": "cms_v1_0000...",
                    "token_created_at": "2026-01-01T00:00:00Z",
                    "customer_portal_enabled": True,
                    "grafana_org_id": 5,
                    "portal_viewer_username": "legacy-viewer",
                    "notes": "",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ],
        }
        (state_dir / "tenants.json").write_bytes(json.dumps(legacy_doc, indent=2).encode("utf-8"))
        save_portal_viewer_secret(state_dir, "legacy-co", "LegacySecretPass99!")

        rc_lt, out_lt, err_lt = run_ns8_action("list-tenants", {}, state_dir)
        assert rc_lt == 0, err_lt
        row = json.loads(out_lt)["tenants"][0]
        assert row["portal_users_count"] == 1
        assert row["portal_viewer_username"] == "legacy-viewer"

        rc_lp, out_lp, err_lp = run_ns8_action(
            "list-portal-users", {"customer": "legacy-co"}, state_dir
        )
        assert rc_lp == 0, err_lp
        users = json.loads(out_lp)["users"]
        assert len(users) == 1
        assert users[0]["username"] == "legacy-viewer"
        assert users[0]["role"] == "Viewer"
        assert users[0]["disabled"] is False
        assert (
            load_portal_viewer_secret(state_dir, "legacy-co", "legacy-viewer")
            == "LegacySecretPass99!"
        )


class TestV102AuditRemediations:
    @pytest.mark.asyncio
    async def test_v102_sec01_gateway_blocks_unified_alerting_and_datasource_mutations(
        self, tmp_path: Path, aiohttp_server: Any, aiohttp_client: Any
    ) -> None:
        import hub_gateway
        from hub_gateway.app import GatewaySettings, create_gateway_app

        assert hub_gateway.__version__ == "1.0.2"

        upstream_hits: list[tuple[str, str]] = []
        g_app = web.Application()

        async def _g_any(req: web.Request) -> web.Response:
            upstream_hits.append((req.method, req.path))
            return web.json_response({"ok": True})

        g_app.router.add_route("*", "/{tail:.*}", _g_any)
        g_srv = await aiohttp_server(g_app)

        gw_app = create_gateway_app(
            GatewaySettings(
                tenants_file=tmp_path / "tenants.json",
                grafana_upstream_url=f"http://127.0.0.1:{g_srv.port}",
            )
        )
        client = await aiohttp_client(gw_app)

        forbidden = [
            ("GET", "/api/alertmanager"),
            ("POST", "/api/alertmanager/grafana/config/api/v1/receivers/test"),
            ("POST", "/api/alertmanager/grafana/config/api/v1/alerts"),
            ("GET", "/api/ruler"),
            ("POST", "/api/ruler/grafana/api/v1/rules/folder"),
            ("GET", "/api/v1/provisioning"),
            ("POST", "/api/v1/provisioning/contact-points"),
            ("POST", "/api/datasources"),
            ("PUT", "/api/datasources/1"),
            ("DELETE", "/api/datasources/1"),
            ("DELETE", "/api/datasources/uid/prometheus"),
            ("POST", "/api/datasources/1/health"),
        ]
        for method, path in forbidden:
            resp = await client.request(method, path)
            assert resp.status == 403, f"Expected 403 for {method} {path}, got {resp.status}"

        assert upstream_hits == []

        # Read-only datasource metadata GETs and allowlisted datasource proxy queries still work
        for method, path in (
            ("GET", "/api/datasources"),
            ("GET", "/api/datasources/uid/prometheus"),
            ("POST", "/api/datasources/proxy/uid/prometheus/api/v1/query"),
        ):
            resp = await client.request(method, path)
            assert resp.status == 200, f"Expected 200 for {method} {path}, got {resp.status}"

    @pytest.mark.asyncio
    async def test_v102_sec02_cross_tenant_deferred_eviction_and_legacy_secret_backfill(
        self, tmp_path: Path, aiohttp_server: Any
    ) -> None:
        from hub_tenancy.grafana_sync import sync_all_orgs
        from hub_tenancy.store import (
            delete_portal_user,
            save_portal_user,
            save_portal_viewer_secret,
            save_tenant,
        )

        # Part A: Legacy v1.0.0 primary user secret backfill before multi-user updates
        leg_dir = tmp_path / "legacy_backfill"
        leg_dir.mkdir(parents=True)
        leg_doc = {
            "version": 1,
            "tenants": [
                {
                    "customer": "legacy-co",
                    "display_name": "Legacy Co",
                    "sites": ["hq"],
                    "default_site": "hq",
                    "contact_emails": [],
                    "token_sha256": "0" * 64,
                    "token_prefix": "cms_v1_0000...",
                    "token_created_at": "2026-01-01T00:00:00Z",
                    "customer_portal_enabled": True,
                    "grafana_org_id": 5,
                    "portal_viewer_username": "u1-legacy",
                    "notes": "",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ],
        }
        (leg_dir / "tenants.json").write_bytes(json.dumps(leg_doc).encode("utf-8"))
        # Simulate v1.0.0 `portal-secrets.json` containing ONLY `doc["legacy-co"]` (no `legacy-co:u1-legacy`)
        save_portal_viewer_secret(leg_dir, "legacy-co", "OriginalLegacyPass11!")

        # Disable `u1-legacy` (`password_unchanged=True`), then add active `u2-new` (who becomes primary)
        save_portal_user(
            leg_dir,
            {
                "customer": "legacy-co",
                "username": "u1-legacy",
                "role": "Viewer",
                "disabled": True,
                "password": "",
                "password_unchanged": True,
            },
        )
        save_portal_user(
            leg_dir,
            {
                "customer": "legacy-co",
                "username": "u2-new",
                "role": "Editor",
                "disabled": False,
                "password": "SecondNewUserPass22!",
            },
        )
        # Re-enable `u1-legacy` (`password_unchanged=True`) -> original password MUST NOT be clobbered!
        save_portal_user(
            leg_dir,
            {
                "customer": "legacy-co",
                "username": "u1-legacy",
                "role": "Viewer",
                "disabled": False,
                "password": "",
                "password_unchanged": True,
            },
        )
        assert load_portal_viewer_secret(leg_dir, "legacy-co", "u1-legacy") == "OriginalLegacyPass11!"
        assert load_portal_viewer_secret(leg_dir, "legacy-co", "u2-new") == "SecondNewUserPass22!"

        # Part B: Deferred eviction on Tenant Z (`zeta-corp`) MUST NOT clobber newly created `jdoe` on Tenant A (`acme-corp`)
        ev_dir = tmp_path / "evict_order"
        ev_dir.mkdir(parents=True)
        save_tenant(
            ev_dir,
            {
                "customer": "acme-corp",
                "display_name": "Acme Corp",
                "sites": ["hq"],
                "customer_portal_enabled": True,
            },
        )
        save_tenant(
            ev_dir,
            {
                "customer": "zeta-corp",
                "display_name": "Zeta Corp",
                "sites": ["hq"],
                "customer_portal_enabled": True,
            },
        )
        # Create `jdoe` on `zeta-corp`, then delete `jdoe` while Grafana is offline (queues in `zeta-corp.evicted_portal_usernames`)
        save_portal_user(
            ev_dir,
            {
                "customer": "zeta-corp",
                "username": "jdoe",
                "role": "Viewer",
                "password": "ZetaOldPassword11!",
            },
        )
        delete_portal_user(ev_dir, "zeta-corp", "jdoe")
        # Now `acme-corp` (alphabetically before `zeta-corp`) claims freed username `jdoe`
        save_portal_user(
            ev_dir,
            {
                "customer": "acme-corp",
                "username": "jdoe",
                "role": "Editor",
                "password": "AcmeNewPassword22!",
            },
        )

        orgs: dict[int, dict[str, Any]] = {1: {"id": 1, "name": "Main Org."}}
        users: dict[int, dict[str, Any]] = {}
        org_members: dict[int, dict[int, str]] = {1: {}}
        seq = {"org": 2, "user": 2}

        app = web.Application()

        async def _h_ok(_r: web.Request) -> web.Response:
            return web.json_response({"database": "ok"})

        async def _list_o(_r: web.Request) -> web.Response:
            return web.json_response(list(orgs.values()))

        async def _get_o(r: web.Request) -> web.Response:
            oid = int(r.match_info["oid"])
            return web.json_response(orgs[oid]) if oid in orgs else web.json_response({}, status=404)

        async def _nf(_r: web.Request) -> web.Response:
            return web.json_response({}, status=404)

        async def _empty(_r: web.Request) -> web.Response:
            return web.json_response({})

        async def _ds_ok(_r: web.Request) -> web.Response:
            return web.json_response({"id": 1})

        async def _fld_ok(_r: web.Request) -> web.Response:
            return web.json_response({"uid": "f"})

        async def _dsh_ok(_r: web.Request) -> web.Response:
            return web.json_response({"status": "success"})

        async def _lu(r: web.Request) -> web.Response:
            q = (r.query.get("loginOrEmail") or "").lower()
            for u in users.values():
                if u["login"].lower() == q:
                    return web.json_response(u)
            return web.json_response({}, status=404)

        async def _mk_org(r: web.Request) -> web.Response:
            b = await r.json()
            oid = seq["org"]
            seq["org"] += 1
            orgs[oid] = {"id": oid, "name": b["name"]}
            org_members[oid] = {}
            return web.json_response({"orgId": oid})

        async def _mk_user(r: web.Request) -> web.Response:
            b = await r.json()
            uid = seq["user"]
            seq["user"] += 1
            users[uid] = {"id": uid, "login": b["login"], "isGrafanaAdmin": False}
            org_members[1][uid] = "Viewer"
            return web.json_response({"id": uid})

        async def _del_user(r: web.Request) -> web.Response:
            uid = int(r.match_info["uid"])
            users.pop(uid, None)
            for m in org_members.values():
                m.pop(uid, None)
            return web.json_response({})

        async def _get_ou(r: web.Request) -> web.Response:
            return web.json_response(
                [
                    {"userId": uid, "role": role}
                    for uid, role in org_members.get(int(r.match_info["oid"]), {}).items()
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

        app.router.add_get("/api/health", _h_ok)
        app.router.add_get("/api/orgs", _list_o)
        app.router.add_get("/api/orgs/{oid:\\d+}", _get_o)
        app.router.add_get("/api/orgs/name/{name}", _nf)
        app.router.add_post("/api/orgs", _mk_org)
        app.router.add_get("/api/datasources/uid/{uid}", _nf)
        app.router.add_post("/api/datasources", _ds_ok)
        app.router.add_get("/api/folders/{uid}", _fld_ok)
        app.router.add_post("/api/dashboards/db", _dsh_ok)
        app.router.add_get("/api/users/lookup", _lu)
        app.router.add_post("/api/admin/users", _mk_user)
        app.router.add_delete("/api/admin/users/{uid:\\d+}", _del_user)
        app.router.add_put("/api/admin/users/{uid:\\d+}/password", _empty)
        app.router.add_post("/api/admin/users/{uid:\\d+}/{act}", _empty)
        app.router.add_put("/api/users/{uid:\\d+}", _empty)
        app.router.add_post("/api/users/{uid:\\d+}/using/{oid:\\d+}", _empty)
        app.router.add_get("/api/orgs/{oid:\\d+}/users", _get_ou)
        app.router.add_post("/api/orgs/{oid:\\d+}/users", _add_ou)
        app.router.add_delete("/api/orgs/{oid:\\d+}/users/{uid:\\d+}", _del_ou)

        srv = await aiohttp_server(app)
        env = {"GRAFANA_URL": f"http://127.0.0.1:{srv.port}", "GRAFANA_ADMIN_PASSWORD": "pw"}
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: sync_all_orgs(ev_dir, env))

        jdoe_obj = next((u for u in users.values() if u["login"] == "jdoe"), None)
        assert jdoe_obj is not None, "jdoe on acme-corp was clobbered by zeta-corp deferred eviction!"
        acme_oid = next(oid for oid, o in orgs.items() if "(acme-corp)" in o["name"])
        zeta_oid = next(oid for oid, o in orgs.items() if "(zeta-corp)" in o["name"])
        assert org_members[acme_oid] == {jdoe_obj["id"]: "Editor"}
        assert jdoe_obj["id"] not in org_members[zeta_oid]
        assert jdoe_obj["id"] not in org_members[1]

    def test_v102_sec03_ldap_search_per_page_frame_cap_aborts_flood(self) -> None:
        from hub_tenancy.ldap_client import LDAPProtocolError, LDAPv3Connection

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(2)
        port = int(srv.getsockname()[1])

        def _flood_worker() -> None:
            try:
                conn, _ = srv.accept()
                conn.settimeout(2.0)
                # Read BindRequest and send valid BindResponse (msg_id=1, resultCode=0)
                conn.recv(4096)
                bind_ok = _ber_seq(
                    [_ber_int(0, tag=0x0A), _ber_octet_string(b""), _ber_octet_string(b"")],
                    tag=0x61,
                )
                conn.sendall(_ber_seq([_ber_int(1), bind_ok]))
                # Read SearchRequest (msg_id=2) and flood >2050 small referral frames without SearchResultDone
                conn.recv(4096)
                ref_frame = _ber_seq(
                    [
                        _ber_int(2),
                        _ber_seq([_ber_octet_string(b"ldap://ref.example/dc=x")], tag=0x73),
                    ]
                )
                conn.sendall(ref_frame * 2100)
                conn.close()
            except OSError:
                pass
            finally:
                srv.close()

        t = threading.Thread(target=_flood_worker, daemon=True)
        t.start()
        try:
            with LDAPv3Connection("127.0.0.1", port, timeout=3.0) as ldap_conn:
                ldap_conn.simple_bind()
                with pytest.raises(LDAPProtocolError, match="maximum frame cap"):
                    ldap_conn.search("DC=example,DC=com", "(objectClass=group)", ["cn"], size_limit=10)
        finally:
            t.join(timeout=2.0)
