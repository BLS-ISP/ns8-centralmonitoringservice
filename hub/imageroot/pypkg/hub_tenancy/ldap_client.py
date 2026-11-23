"""Pure-Python 3.9 stdlib RFC 4511 LDAPv3 BER client & RFC 4515 filter compiler.

Connects to NS8 `Ldapproxy` (`127.0.0.1:<port>`) with zero third-party dependencies to:
1. Enumerate Active Directory and RFC2307/OpenLDAP groups with true Distinguished Names
   (supporting RFC 2696 Simple Paged Results `1.2.840.113556.1.4.319`).
2. Resolve short group names (e.g. `Domain Admins`) to real AD/LDAP Distinguished Names.
3. Test user lookup, nested AD group membership (`1.2.840.113556.1.4.1941`), primary AD
   group RID matching, RFC2307 `memberUid`/`member`, and Grafana Org 1 role mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import socket
import ssl
import struct
from typing import Any, Callable, Sequence

MAX_BER_MESSAGE_BYTES = 16 * 1024 * 1024
PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"
AD_IN_CHAIN_OID = "1.2.840.113556.1.4.1941"

_WELL_KNOWN_AD_RIDS = {
    "512": "domain admins",
    "513": "domain users",
    "514": "domain guests",
    "515": "domain computers",
    "516": "domain controllers",
    "519": "enterprise admins",
}


class LDAPError(RuntimeError):
    """Base error raised on LDAPv3 transport, protocol, or bind/search failures."""


class LDAPProtocolError(LDAPError):
    """Malformed ASN.1 BER packet or unexpected LDAPv3 message structure."""


class LDAPBindError(LDAPError):
    """LDAPv3 Simple Bind rejected by directory server."""


class LDAPSearchError(LDAPError):
    """LDAPv3 SearchRequest failed with a non-recoverable resultCode."""


@dataclass
class LDAPEntry:
    dn: str
    attributes: dict[str, list[str]]
    raw_attributes: dict[str, list[bytes]]

    def first_str(self, *names: str) -> str:
        lower_map = {k.lower(): v for k, v in self.attributes.items()}
        for name in names:
            vals = lower_map.get(name.lower())
            if vals:
                for item in vals:
                    cleaned = item.strip()
                    if cleaned:
                        return cleaned
        return ""

    def all_strs(self, name: str) -> list[str]:
        lower_map = {k.lower(): v for k, v in self.attributes.items()}
        vals = lower_map.get(name.lower(), [])
        return [v.strip() for v in vals if v.strip()]

    def first_bytes(self, name: str) -> bytes | None:
        lower_map = {k.lower(): v for k, v in self.raw_attributes.items()}
        vals = lower_map.get(name.lower())
        if vals:
            return vals[0]
        return None


def escape_ldap_filter_value(value: str) -> str:
    """Strictly escape arbitrary input per RFC 4515 Section 3 so filter injection is impossible."""
    out: list[str] = []
    for ch in str(value):
        if ch == "\\":
            out.append("\\5c")
        elif ch == "*":
            out.append("\\2a")
        elif ch == "(":
            out.append("\\28")
        elif ch == ")":
            out.append("\\29")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def extract_first_rdn_value(dn: str) -> str:
    """Extract the unescaped value of the first RDN component in an RFC 4514 Distinguished Name."""
    text = dn.strip()
    if not text or "=" not in text:
        return text
    _, rest = text.split("=", 1)
    buf: list[str] = []
    idx = 0
    while idx < len(rest):
        ch = rest[idx]
        if ch == "\\" and idx + 1 < len(rest):
            nxt = rest[idx + 1]
            if idx + 2 < len(rest) and all(c in "0123456789abcdefABCDEF" for c in rest[idx + 1 : idx + 3]):
                buf.append(chr(int(rest[idx + 1 : idx + 3], 16)))
                idx += 3
                continue
            buf.append(nxt)
            idx += 2
            continue
        if ch in (",", "+"):
            break
        buf.append(ch)
        idx += 1
    return "".join(buf).strip()


# ---------------------------------------------------------------------------
# ASN.1 BER Primitives (Definite-Length Encoding & Decoding per RFC 4511 5.1)
# ---------------------------------------------------------------------------


def _ber_len(length: int) -> bytes:
    if length < 0:
        raise ValueError("BER length cannot be negative")
    if length < 0x80:
        return bytes([length])
    raw: list[int] = []
    rem = length
    while rem > 0:
        raw.append(rem & 0xFF)
        rem >>= 8
    raw.reverse()
    return bytes([0x80 | len(raw), *raw])


def _ber_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(value: int, tag: int = 0x02) -> bytes:
    bit_len = value.bit_length()
    byte_len = max(1, (bit_len + 8) // 8)
    return _ber_tlv(tag, value.to_bytes(byte_len, "big", signed=True))


def _ber_bool(value: bool, tag: int = 0x01) -> bytes:
    return _ber_tlv(tag, b"\xff" if value else b"\x00")


def _ber_octet_string(value: bytes, tag: int = 0x04) -> bytes:
    return _ber_tlv(tag, value)


def _ber_seq(items: list[bytes], tag: int = 0x30) -> bytes:
    return _ber_tlv(tag, b"".join(items))


def _decode_ber_tlv(buf: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Decode one BER TLV at `buf[offset:]`, returning `(tag, value_bytes, next_offset)`."""
    if offset >= len(buf):
        raise LDAPProtocolError("Unexpected EOF reading BER tag")
    tag = buf[offset]
    pos = offset + 1
    if (tag & 0x1F) == 0x1F:
        raise LDAPProtocolError("Unsupported multi-byte BER tag in LDAPv3 stream")
    if pos >= len(buf):
        raise LDAPProtocolError("Unexpected EOF reading BER length")
    first_len = buf[pos]
    pos += 1
    if first_len < 0x80:
        length = first_len
    elif first_len == 0x80:
        raise LDAPProtocolError("Indefinite BER length is forbidden by RFC 4511")
    else:
        num_octets = first_len & 0x7F
        if num_octets > 4 or pos + num_octets > len(buf):
            raise LDAPProtocolError("Invalid or truncated multi-byte BER length")
        length = int.from_bytes(buf[pos : pos + num_octets], "big", signed=False)
        pos += num_octets
    if length > MAX_BER_MESSAGE_BYTES or pos + length > len(buf):
        raise LDAPProtocolError("BER value exceeds packet bounds or 16 MiB cap")
    return tag, buf[pos : pos + length], pos + length


def _decode_ber_int(body: bytes) -> int:
    if not body:
        return 0
    return int.from_bytes(body, "big", signed=True)


# ---------------------------------------------------------------------------
# RFC 4515 String Filter -> RFC 4511 BER Filter Compiler
# ---------------------------------------------------------------------------


def _unescape_assertion_bytes(raw: str) -> bytes:
    """Convert an RFC 4515 assertion value (`\\XX` hex escapes) to raw wire UTF-8 bytes."""
    chunks: list[bytes] = []
    idx = 0
    while idx < len(raw):
        ch = raw[idx]
        if ch == "\\":
            if idx + 2 >= len(raw):
                raise ValueError(f"Incomplete RFC 4515 backslash escape in {raw!r}")
            hex_pair = raw[idx + 1 : idx + 3]
            if not all(c in "0123456789abcdefABCDEF" for c in hex_pair):
                raise ValueError(f"Invalid RFC 4515 hex escape \\{hex_pair} in {raw!r}")
            chunks.append(bytes([int(hex_pair, 16)]))
            idx += 3
        elif ch in ("(", ")"):
            raise ValueError(f"Unescaped parenthesis {ch!r} in LDAP filter assertion")
        else:
            chunks.append(ch.encode("utf-8"))
            idx += 1
    return b"".join(chunks)


def _split_unescaped_stars(raw: str) -> list[str]:
    """Split an RFC 4515 assertion value on unescaped `*` characters only (`\\2a` is literal)."""
    parts: list[str] = []
    cur: list[str] = []
    idx = 0
    while idx < len(raw):
        ch = raw[idx]
        if ch == "\\" and idx + 2 < len(raw):
            cur.append(raw[idx : idx + 3])
            idx += 3
        elif ch == "*":
            parts.append("".join(cur))
            cur = []
            idx += 1
        else:
            cur.append(ch)
            idx += 1
    parts.append("".join(cur))
    return parts


def _split_child_filters(inner: str) -> list[str]:
    children: list[str] = []
    text = inner.strip()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        if text[idx] != "(":
            raise ValueError(f"Expected '(' in compound LDAP filter near {text[idx:]!r}")
        start = idx
        depth = 0
        while idx < len(text):
            ch = text[idx]
            if ch == "\\" and idx + 2 < len(text):
                idx += 3
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    idx += 1
                    children.append(text[start:idx])
                    break
            idx += 1
        else:
            raise ValueError(f"Unbalanced '(' in LDAP filter: {inner!r}")
    if not children:
        raise ValueError("Compound LDAP filter must contain at least one child filter")
    return children


def compile_ldap_filter(filter_str: str) -> bytes:
    """Compile an RFC 4515 LDAP search filter string into RFC 4511 BER Filter bytes."""
    expr = filter_str.strip()
    if len(expr) < 3 or not expr.startswith("(") or not expr.endswith(")"):
        raise ValueError(f"LDAP filter must be enclosed in parentheses: {filter_str!r}")

    # Verify outer parentheses match each other (not `(a=1)(b=2)` without `&`/`|`)
    depth = 0
    idx = 0
    while idx < len(expr):
        ch = expr[idx]
        if ch == "\\" and idx + 2 < len(expr):
            idx += 3
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and idx != len(expr) - 1:
                raise ValueError(f"Top-level LDAP filter has trailing expression: {filter_str!r}")
        idx += 1
    if depth != 0:
        raise ValueError(f"Unbalanced parentheses in LDAP filter: {filter_str!r}")

    body = expr[1:-1].strip()
    if not body:
        raise ValueError("Empty LDAP filter '()'")

    op = body[0]
    if op == "&":
        children = [compile_ldap_filter(c) for c in _split_child_filters(body[1:])]
        return _ber_seq(children, tag=0xA0)
    if op == "|":
        children = [compile_ldap_filter(c) for c in _split_child_filters(body[1:])]
        return _ber_seq(children, tag=0xA1)
    if op == "!":
        children = _split_child_filters(body[1:])
        if len(children) != 1:
            raise ValueError("LDAP 'not' (!) filter must wrap exactly one child filter")
        return _ber_tlv(0xA2, compile_ldap_filter(children[0]))

    eq_idx = body.find("=")
    if eq_idx <= 0:
        raise ValueError(f"Unsupported or missing operator in LDAP filter item: {expr!r}")

    # Extensible match (`attr:oid:=val`, `attr:dn:oid:=val`, `:oid:=val`) -> [9] 0xA9
    if body[eq_idx - 1] == ":":
        lhs = body[: eq_idx - 1]
        raw_val = body[eq_idx + 1 :]
        lhs_parts = lhs.split(":")
        attr_name = lhs_parts[0].strip()
        dn_attrs = False
        matching_rule = ""
        for part in lhs_parts[1:]:
            p_clean = part.strip()
            if p_clean.lower() == "dn":
                dn_attrs = True
            elif p_clean:
                matching_rule = p_clean
        if not attr_name and not matching_rule:
            raise ValueError(f"Invalid extensibleMatch LDAP filter: {expr!r}")
        ext_items: list[bytes] = []
        if matching_rule:
            ext_items.append(_ber_octet_string(matching_rule.encode("utf-8"), tag=0x81))
        if attr_name:
            ext_items.append(_ber_octet_string(attr_name.encode("utf-8"), tag=0x82))
        ext_items.append(_ber_octet_string(_unescape_assertion_bytes(raw_val), tag=0x83))
        if dn_attrs:
            ext_items.append(_ber_bool(True, tag=0x84))
        return _ber_seq(ext_items, tag=0xA9)

    attr_name = body[:eq_idx].strip()
    raw_val = body[eq_idx + 1 :]
    if not attr_name or any(c in attr_name for c in ("(", ")", "*", "\\", " ")):
        raise ValueError(f"Invalid attribute description in LDAP filter: {attr_name!r}")

    star_parts = _split_unescaped_stars(raw_val)
    if len(star_parts) == 2 and star_parts[0] == "" and star_parts[1] == "":
        # Present filter `(attr=*)` -> [7] primitive 0x87
        return _ber_octet_string(attr_name.encode("utf-8"), tag=0x87)

    if len(star_parts) > 1:
        # Substrings filter `(attr=init*any*final)` -> [4] constructed 0xA4
        sub_items: list[bytes] = []
        if star_parts[0] != "":
            sub_items.append(_ber_octet_string(_unescape_assertion_bytes(star_parts[0]), tag=0x80))
        for mid in star_parts[1:-1]:
            if mid != "":
                sub_items.append(_ber_octet_string(_unescape_assertion_bytes(mid), tag=0x81))
        if star_parts[-1] != "":
            sub_items.append(_ber_octet_string(_unescape_assertion_bytes(star_parts[-1]), tag=0x82))
        return _ber_seq(
            [
                _ber_octet_string(attr_name.encode("utf-8")),
                _ber_seq(sub_items),
            ],
            tag=0xA4,
        )

    # Equality filter `(attr=value)` -> [3] constructed 0xA3
    return _ber_seq(
        [
            _ber_octet_string(attr_name.encode("utf-8")),
            _ber_octet_string(_unescape_assertion_bytes(raw_val)),
        ],
        tag=0xA3,
    )


# ---------------------------------------------------------------------------
# LDAPv3 Wire Client
# ---------------------------------------------------------------------------


def _encode_paged_results_control(page_size: int, cookie: bytes) -> bytes:
    ctrl_val = _ber_seq(
        [
            _ber_int(page_size),
            _ber_octet_string(cookie),
        ]
    )
    ctrl = _ber_seq(
        [
            _ber_octet_string(PAGED_RESULTS_OID.encode("ascii")),
            _ber_bool(False),
            _ber_octet_string(ctrl_val),
        ]
    )
    return _ber_seq([ctrl], tag=0xA0)


def _extract_paged_cookie(controls_body: bytes | None) -> bytes:
    if not controls_body:
        return b""
    pos = 0
    while pos < len(controls_body):
        c_tag, c_body, pos = _decode_ber_tlv(controls_body, pos)
        if c_tag != 0x30:
            continue
        inner_pos = 0
        oid_tag, oid_bytes, inner_pos = _decode_ber_tlv(c_body, inner_pos)
        if oid_tag != 0x04 or oid_bytes.decode("ascii", errors="replace") != PAGED_RESULTS_OID:
            continue
        val_bytes = b""
        while inner_pos < len(c_body):
            f_tag, f_body, inner_pos = _decode_ber_tlv(c_body, inner_pos)
            if f_tag == 0x04:
                val_bytes = f_body
        if not val_bytes:
            return b""
        s_tag, s_body, _ = _decode_ber_tlv(val_bytes, 0)
        if s_tag != 0x30:
            return b""
        _, _, after_size = _decode_ber_tlv(s_body, 0)
        ck_tag, ck_bytes, _ = _decode_ber_tlv(s_body, after_size)
        if ck_tag == 0x04:
            return ck_bytes
    return b""


class LDAPv3Connection:
    """Minimal synchronous RFC 4511 LDAPv3 client over TCP / optional TLS."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        use_tls: bool = False,
        tls_verify: bool = False,
        timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.use_tls = use_tls
        self.tls_verify = tls_verify
        self.timeout = float(timeout)
        self._sock: socket.socket | None = None
        self._next_msg_id = 1

    def __enter__(self) -> LDAPv3Connection:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def connect(self) -> None:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw_sock.settimeout(self.timeout)
        if self.use_tls:
            ctx = ssl.create_default_context()
            if not self.tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
            self._sock.settimeout(self.timeout)
        else:
            self._sock = raw_sock

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            msg_id = self._alloc_msg_id()
            unbind_pkt = _ber_seq([_ber_int(msg_id), _ber_tlv(0x42, b"")])
            sock.sendall(unbind_pkt)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _alloc_msg_id(self) -> int:
        mid = self._next_msg_id
        self._next_msg_id += 1
        return mid

    def _recv_exact(self, count: int) -> bytes:
        if self._sock is None:
            raise LDAPError("LDAP socket is not connected")
        buf = bytearray()
        while len(buf) < count:
            chunk = self._sock.recv(count - len(buf))
            if not chunk:
                raise LDAPProtocolError("LDAP connection closed unexpectedly by server")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_message(self) -> tuple[int, int, bytes, bytes | None]:
        header = self._recv_exact(2)
        tag = header[0]
        if tag != 0x30:
            raise LDAPProtocolError(f"Expected LDAPMessage SEQUENCE (0x30), got 0x{tag:02x}")
        first_len = header[1]
        if first_len < 0x80:
            body_len = first_len
        elif first_len == 0x80:
            raise LDAPProtocolError("Indefinite BER length in LDAPMessage")
        else:
            num_octets = first_len & 0x7F
            if num_octets > 4:
                raise LDAPProtocolError("LDAPMessage length header too wide")
            len_bytes = self._recv_exact(num_octets)
            body_len = int.from_bytes(len_bytes, "big", signed=False)
        if body_len > MAX_BER_MESSAGE_BYTES:
            raise LDAPProtocolError("LDAPMessage exceeds 16 MiB safety cap")

        msg_body = self._recv_exact(body_len)
        id_tag, id_bytes, pos = _decode_ber_tlv(msg_body, 0)
        if id_tag != 0x02:
            raise LDAPProtocolError("Missing INTEGER messageID in LDAPMessage")
        msg_id = _decode_ber_int(id_bytes)
        op_tag, op_body, pos = _decode_ber_tlv(msg_body, pos)
        controls_body: bytes | None = None
        if pos < len(msg_body):
            c_tag, c_body, _ = _decode_ber_tlv(msg_body, pos)
            if c_tag == 0xA0:
                controls_body = c_body
        return msg_id, op_tag, op_body, controls_body

    def simple_bind(self, bind_dn: str = "", bind_password: str = "") -> None:
        if self._sock is None:
            raise LDAPError("LDAP socket is not connected")
        dn_bytes = bind_dn.encode("utf-8") if bind_dn else b""
        pw_bytes = bind_password.encode("utf-8") if (bind_dn and bind_password) else b""
        bind_req = _ber_seq(
            [
                _ber_int(3),
                _ber_octet_string(dn_bytes),
                _ber_octet_string(pw_bytes, tag=0x80),
            ],
            tag=0x60,
        )
        msg_id = self._alloc_msg_id()
        self._sock.sendall(_ber_seq([_ber_int(msg_id), bind_req]))

        resp_id, op_tag, op_body, _ = self._recv_message()
        if resp_id != msg_id or op_tag != 0x61:
            raise LDAPProtocolError(f"Unexpected response tag 0x{op_tag:02x} to BindRequest")
        rc, diag = _decode_ldap_result(op_body)
        if rc != 0:
            detail = f": {diag}" if diag else ""
            raise LDAPBindError(f"LDAP Simple Bind failed with resultCode={rc}{detail}")

    def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str],
        *,
        scope: int = 2,
        size_limit: int = 1000,
        time_limit: int = 5,
        use_paging: bool = True,
        page_size: int = 500,
        max_pages: int = 10,
    ) -> list[LDAPEntry]:
        if self._sock is None:
            raise LDAPError("LDAP socket is not connected")
        compiled_filter = compile_ldap_filter(filter_str)
        attr_seq = _ber_seq([_ber_octet_string(a.encode("utf-8")) for a in attributes])

        entries: list[LDAPEntry] = []
        cookie = b""
        pages = 0

        while pages < max_pages:
            pages += 1
            search_req = _ber_seq(
                [
                    _ber_octet_string(base_dn.encode("utf-8")),
                    _ber_int(scope, tag=0x0A),
                    _ber_int(0, tag=0x0A),
                    _ber_int(size_limit),
                    _ber_int(time_limit),
                    _ber_bool(False),
                    compiled_filter,
                    attr_seq,
                ],
                tag=0x63,
            )
            msg_id = self._alloc_msg_id()
            msg_items = [_ber_int(msg_id), search_req]
            if use_paging:
                msg_items.append(_encode_paged_results_control(page_size, cookie))
            self._sock.sendall(_ber_seq(msg_items))

            done_controls: bytes | None = None
            max_frames = max(int(size_limit) * 2 + 64, 2048)
            frames_seen = 0
            while True:
                frames_seen += 1
                if frames_seen > max_frames:
                    raise LDAPProtocolError(
                        f"LDAP search page exceeded maximum frame cap ({max_frames})"
                    )
                resp_id, op_tag, op_body, controls = self._recv_message()
                if resp_id != msg_id:
                    continue
                if op_tag == 0x64:  # SearchResultEntry
                    entries.append(_decode_search_entry(op_body))
                elif op_tag == 0x73:  # SearchResultReference (AD referrals — safely ignored)
                    continue
                elif op_tag == 0x65:  # SearchResultDone
                    rc, diag = _decode_ldap_result(op_body)
                    # resultCode 0 = success, 4 = sizeLimitExceeded (keep partial entries)
                    if rc not in (0, 4):
                        detail = f": {diag}" if diag else ""
                        raise LDAPSearchError(f"LDAP search failed with resultCode={rc}{detail}")
                    done_controls = controls
                    break
                else:
                    raise LDAPProtocolError(f"Unexpected LDAP search response tag 0x{op_tag:02x}")

            if not use_paging:
                break
            cookie = _extract_paged_cookie(done_controls)
            if not cookie:
                break

        return entries


def _decode_ldap_result(op_body: bytes) -> tuple[int, str]:
    rc_tag, rc_bytes, pos = _decode_ber_tlv(op_body, 0)
    if rc_tag != 0x0A:
        raise LDAPProtocolError("Missing ENUMERATED resultCode in LDAPResult")
    rc = _decode_ber_int(rc_bytes)
    _, _, pos = _decode_ber_tlv(op_body, pos)  # matchedDN
    _, diag_bytes, _ = _decode_ber_tlv(op_body, pos)  # diagnosticMessage
    return rc, diag_bytes.decode("utf-8", errors="replace")


def _decode_search_entry(op_body: bytes) -> LDAPEntry:
    dn_tag, dn_bytes, pos = _decode_ber_tlv(op_body, 0)
    if dn_tag != 0x04:
        raise LDAPProtocolError("Missing OCTET STRING objectName in SearchResultEntry")
    dn = dn_bytes.decode("utf-8", errors="replace")

    attrs_tag, attrs_body, _ = _decode_ber_tlv(op_body, pos)
    if attrs_tag != 0x30:
        raise LDAPProtocolError("Missing PartialAttributeList SEQUENCE in SearchResultEntry")

    str_attrs: dict[str, list[str]] = {}
    raw_attrs: dict[str, list[bytes]] = {}
    apos = 0
    while apos < len(attrs_body):
        pa_tag, pa_body, apos = _decode_ber_tlv(attrs_body, apos)
        if pa_tag != 0x30:
            continue
        t_tag, t_bytes, ppos = _decode_ber_tlv(pa_body, 0)
        if t_tag != 0x04:
            continue
        attr_name = t_bytes.decode("utf-8", errors="replace")
        v_tag, v_body, _ = _decode_ber_tlv(pa_body, ppos)
        if v_tag != 0x31:
            continue
        s_vals: list[str] = []
        b_vals: list[bytes] = []
        vpos = 0
        while vpos < len(v_body):
            item_tag, item_bytes, vpos = _decode_ber_tlv(v_body, vpos)
            if item_tag == 0x04:
                b_vals.append(item_bytes)
                s_vals.append(item_bytes.decode("utf-8", errors="replace"))
        str_attrs[attr_name] = s_vals
        raw_attrs[attr_name] = b_vals

    return LDAPEntry(dn=dn, attributes=str_attrs, raw_attributes=raw_attrs)


# ---------------------------------------------------------------------------
# High-Level NS8 Domain Group Discovery & User Login Role Tester
# ---------------------------------------------------------------------------


def _get_domain_info(
    domain: str, ldapproxy_factory: Callable[[], Any] | None = None
) -> dict[str, Any]:
    if ldapproxy_factory is not None:
        lp = ldapproxy_factory()
        info = lp.get_domain(domain)
    else:  # pragma: no cover - NS8 host runtime + local test harness fallback
        try:
            from agent.ldapproxy import Ldapproxy  # type: ignore[import-not-found]

            lp = Ldapproxy()
            info = lp.get_domain(domain)
        except ImportError as exc:
            mock_raw = os.environ.get("HUB_TEST_LDAPPROXY_JSON", "").strip()
            if not mock_raw:
                raise LDAPError("NS8 agent.ldapproxy module is unavailable") from exc
            domains_map = json.loads(mock_raw)
            info = domains_map.get(domain) if isinstance(domains_map, dict) else None
    if not isinstance(info, dict) or "port" not in info:
        raise LDAPError(f"NS8 domain {domain!r} was not found in Ldapproxy")
    return info


def _extract_ad_sid_rid(entry: LDAPEntry) -> str:
    token = entry.first_str("primaryGroupToken")
    if token.isdigit():
        return token
    raw_sid = entry.first_bytes("objectSid")
    if raw_sid and len(raw_sid) >= 12 and raw_sid[0] == 1:
        sub_count = raw_sid[1]
        expected_len = 8 + 4 * sub_count
        if len(raw_sid) >= expected_len and sub_count >= 1:
            rid = struct.unpack("<I", raw_sid[expected_len - 4 : expected_len])[0]
            return str(rid)
    return ""


def _query_groups_internal(
    conn: LDAPv3Connection, base_dn: str, schema: str
) -> list[dict[str, str]]:
    if schema == "ad":
        group_filter = "(objectClass=group)"
        attrs = ["cn", "sAMAccountName", "name", "description", "primaryGroupToken", "objectSid"]
    else:
        group_filter = "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
        attrs = ["cn", "description"]

    entries = conn.search(base_dn, group_filter, attrs)
    by_dn: dict[str, dict[str, str]] = {}
    for entry in entries:
        dn = entry.dn.strip()
        if not dn:
            continue
        cn = entry.first_str("cn", "name")
        sam = entry.first_str("sAMAccountName")
        rdn_val = extract_first_rdn_value(dn)
        display_name = cn or sam or rdn_val or dn
        desc = entry.first_str("description")
        rid = _extract_ad_sid_rid(entry) if schema == "ad" else ""
        by_dn[dn.lower()] = {
            "name": display_name,
            "cn": cn,
            "sam": sam,
            "rdn": rdn_val,
            "rid": rid,
            "dn": dn,
            "description": desc,
        }

    items = list(by_dn.values())
    items.sort(key=lambda g: (g["name"].lower(), g["dn"].lower()))
    return items


def _query_users_internal(
    conn: LDAPv3Connection, base_dn: str, schema: str
) -> list[dict[str, str]]:
    if schema == "ad":
        user_filter = "(&(objectClass=user)(!(objectClass=computer)))"
        attrs = [
            "distinguishedName",
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "cn",
            "givenName",
            "sn",
            "mail",
        ]
    else:
        user_filter = "(|(objectClass=inetOrgPerson)(objectClass=posixAccount))"
        attrs = ["uid", "cn", "displayName", "givenName", "sn", "mail"]

    entries = conn.search(base_dn, user_filter, attrs)
    by_dn: dict[str, dict[str, str]] = {}
    for entry in entries:
        dn = (entry.first_str("distinguishedName") if schema == "ad" else "") or entry.dn.strip()
        if not dn:
            continue
        rdn_val = extract_first_rdn_value(dn)
        cn = entry.first_str("cn")
        given_sn = " ".join(
            p for p in (entry.first_str("givenName"), entry.first_str("sn")) if p
        ).strip()
        mail = entry.first_str("mail")

        if schema == "ad":
            sam = entry.first_str("sAMAccountName")
            if sam.endswith("$") or rdn_val.endswith("$") or sam.lower() == "krbtgt":
                continue
            username = sam or rdn_val or dn
            upn = entry.first_str("userPrincipalName")
        else:
            uid = entry.first_str("uid")
            username = uid or cn or rdn_val or dn
            upn = ""

        display_name = entry.first_str("displayName") or given_sn or cn or username
        by_dn[dn.lower()] = {
            "username": username,
            "display_name": display_name,
            "email": mail,
            "upn": upn,
            "cn": cn,
            "rdn": rdn_val,
            "dn": dn,
        }

    items = list(by_dn.values())
    items.sort(key=lambda u: (u["username"].lower(), u["dn"].lower()))
    return items


def resolve_group_dn(
    group_value: str,
    *,
    base_dn: str,
    schema: str,
    discovered_groups: list[dict[str, str]] | None = None,
) -> str:
    """Resolve a short group name or full DN to an authoritative Distinguished Name."""
    spec = str(group_value or "").strip()
    if not spec:
        return ""
    if "=" in spec:
        return spec

    needle = spec.lower()
    if discovered_groups:
        for grp in discovered_groups:
            candidates = (
                str(grp.get("name") or "").strip().lower(),
                str(grp.get("cn") or "").strip().lower(),
                str(grp.get("sam") or "").strip().lower(),
                str(grp.get("rdn") or extract_first_rdn_value(str(grp.get("dn") or ""))).strip().lower(),
            )
            if needle in candidates and grp.get("dn"):
                return str(grp["dn"])

    if not base_dn:
        return f"CN={spec}"
    if schema.lower() == "ad":
        return f"CN={spec},CN=Users,{base_dn}"
    if "ou=groups" in base_dn.lower():
        return f"cn={spec},{base_dn}"
    return f"cn={spec},ou=Groups,{base_dn}"


def resolve_principal_dn(
    spec_value: str,
    *,
    base_dn: str,
    schema: str,
    discovered_groups: list[dict[str, str]] | None = None,
    discovered_users: list[dict[str, str]] | None = None,
) -> str:
    """Resolve a group or user principal (short name, `group:x`/`user:x`, or full DN) to its DN."""
    raw = str(spec_value or "").strip()
    if not raw:
        return ""

    kind = "any"
    raw_low = raw.lower()
    if raw_low.startswith("group:"):
        kind = "group"
        spec = raw[6:].strip()
    elif raw_low.startswith("user:"):
        kind = "user"
        spec = raw[5:].strip()
    else:
        spec = raw

    if not spec:
        return ""
    if "=" in spec:
        return spec

    needle = spec.lower()
    if kind in ("any", "group") and discovered_groups:
        for grp in discovered_groups:
            g_candidates = (
                str(grp.get("name") or "").strip().lower(),
                str(grp.get("cn") or "").strip().lower(),
                str(grp.get("sam") or "").strip().lower(),
                str(grp.get("rdn") or extract_first_rdn_value(str(grp.get("dn") or ""))).strip().lower(),
            )
            if needle in g_candidates and grp.get("dn"):
                return str(grp["dn"])

    if kind in ("any", "user") and discovered_users:
        for usr in discovered_users:
            u_candidates = (
                str(usr.get("username") or "").strip().lower(),
                str(usr.get("upn") or "").strip().lower(),
                str(usr.get("cn") or "").strip().lower(),
                str(usr.get("display_name") or "").strip().lower(),
                str(usr.get("email") or "").strip().lower(),
                str(usr.get("rdn") or extract_first_rdn_value(str(usr.get("dn") or ""))).strip().lower(),
            )
            if needle in u_candidates and usr.get("dn"):
                return str(usr["dn"])

    if kind == "user" and schema.lower() != "ad":
        if not base_dn:
            return f"uid={spec}"
        if "ou=people" in base_dn.lower() or "ou=users" in base_dn.lower():
            return f"uid={spec},{base_dn}"
        return f"uid={spec},ou=People,{base_dn}"

    return resolve_group_dn(spec, base_dn=base_dn, schema=schema, discovered_groups=None)


def discover_directory_principals_raw(
    domain: str,
    *,
    ldapproxy_factory: Callable[[], Any] | None = None,
    timeout: float = 5.0,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Query both groups and users in one bound LDAPv3 session."""
    dom = str(domain or "").strip()
    info = _get_domain_info(dom, ldapproxy_factory=ldapproxy_factory)
    host = str(info.get("host") or "127.0.0.1").strip() or "127.0.0.1"
    port = int(info["port"])
    schema = str(info.get("schema") or "ad").strip().lower()
    base_dn = str(info.get("base_dn") or "").strip()
    bind_dn = str(info.get("bind_dn") or "")
    bind_pw = str(info.get("bind_password") or "")
    use_tls = bool(info.get("tls", False))
    tls_verify = bool(info.get("tls_verify", False))

    with LDAPv3Connection(
        host,
        port,
        use_tls=use_tls,
        tls_verify=tls_verify,
        timeout=timeout,
    ) as conn:
        conn.simple_bind(bind_dn, bind_pw)
        groups = _query_groups_internal(conn, base_dn, schema)
        users = _query_users_internal(conn, base_dn, schema)
        return groups, users


def discover_domain_groups_raw(
    domain: str,
    *,
    ldapproxy_factory: Callable[[], Any] | None = None,
    timeout: float = 5.0,
) -> list[dict[str, str]]:
    """Query full group metadata (`name`, `cn`, `sam`, `rdn`, `dn`, `description`) for DN resolution."""
    groups, _ = discover_directory_principals_raw(
        domain,
        ldapproxy_factory=ldapproxy_factory,
        timeout=timeout,
    )
    return groups


def discover_domain_groups(
    domain: str,
    *,
    ldapproxy_factory: Callable[[], Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Enumerate directory groups and users for `discover-ldap-groups` action."""
    dom = str(domain or "").strip()
    schema = ""
    base_dn = ""
    try:
        info = _get_domain_info(dom, ldapproxy_factory=ldapproxy_factory)
        schema = str(info.get("schema") or "ad").strip().lower()
        base_dn = str(info.get("base_dn") or "").strip()
        raw_groups, raw_users = discover_directory_principals_raw(
            dom,
            ldapproxy_factory=ldapproxy_factory,
            timeout=timeout,
        )
        public_groups = [
            {
                "name": g["name"],
                "dn": g["dn"],
                "description": g["description"],
            }
            for g in raw_groups
        ]
        public_users = [
            {
                "username": u["username"],
                "display_name": u["display_name"],
                "email": u["email"],
                "dn": u["dn"],
            }
            for u in raw_users
        ]
        return {
            "ok": True,
            "domain": dom,
            "schema": schema,
            "base_dn": base_dn,
            "groups": public_groups,
            "users": public_users,
            "error": "",
        }
    except Exception as exc:
        return {
            "ok": False,
            "domain": dom,
            "schema": schema,
            "base_dn": base_dn,
            "groups": [],
            "users": [],
            "error": str(exc),
        }


def _normalize_principal_list(
    principals: Sequence[str] | None,
    legacy_single: str,
) -> list[str]:
    if principals is not None:
        source = list(principals)
    elif legacy_single and str(legacy_single).strip():
        source = [str(legacy_single).strip()]
    else:
        source = []

    result: list[str] = []
    seen_low: set[str] = set()
    for item in source:
        val = str(item or "").strip()
        if not val:
            continue
        vlow = val.lower()
        if vlow not in seen_low:
            seen_low.add(vlow)
            result.append(val)
    return result


def _resolve_principal_dns(
    specs: Sequence[str],
    *,
    base_dn: str,
    schema: str,
    discovered_groups: list[dict[str, str]] | None,
    discovered_users: list[dict[str, str]] | None,
) -> list[str]:
    resolved: list[str] = []
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
            resolved.append(dn)
    return resolved


def _match_principal_role(
    role_name: str,
    principal_dns: Sequence[str],
    user_dn: str,
    member_lower: set[str],
) -> str | None:
    user_dn_low = user_dn.lower()
    for dn in principal_dns:
        dlow = dn.lower()
        if user_dn_low and dlow == user_dn_low:
            return f"Matched Org 1 {role_name} role via user '{dn}'."
        if dlow in member_lower:
            return f"Matched Org 1 {role_name} role via group '{dn}'."
    return None


def test_domain_user(
    domain: str,
    username: str,
    *,
    ldap_admin_group: str = "",
    ldap_editor_group: str = "",
    ldap_viewer_group: str = "",
    ldap_admin_principals: Sequence[str] | None = None,
    ldap_editor_principals: Sequence[str] | None = None,
    ldap_viewer_principals: Sequence[str] | None = None,
    ldapproxy_factory: Callable[[], Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Search a user in NS8 AD/OpenLDAP and evaluate Grafana Org 1 multi-principal role mapping."""
    dom = str(domain or "").strip()
    uname = str(username or "").strip()
    try:
        info = _get_domain_info(dom, ldapproxy_factory=ldapproxy_factory)
        host = str(info.get("host") or "127.0.0.1").strip() or "127.0.0.1"
        port = int(info["port"])
        schema = str(info.get("schema") or "ad").strip().lower()
        base_dn = str(info.get("base_dn") or "").strip()
        bind_dn = str(info.get("bind_dn") or "")
        bind_pw = str(info.get("bind_password") or "")
        use_tls = bool(info.get("tls", False))
        tls_verify = bool(info.get("tls_verify", False))

        esc_user = escape_ldap_filter_value(uname)
        with LDAPv3Connection(
            host,
            port,
            use_tls=use_tls,
            tls_verify=tls_verify,
            timeout=timeout,
        ) as conn:
            conn.simple_bind(bind_dn, bind_pw)

            if schema == "ad":
                user_filter = (
                    f"(&(objectClass=user)(!(objectClass=computer))"
                    f"(|(sAMAccountName={esc_user})(userPrincipalName={esc_user})))"
                )
                user_attrs = [
                    "distinguishedName",
                    "sAMAccountName",
                    "userPrincipalName",
                    "displayName",
                    "cn",
                    "givenName",
                    "sn",
                    "mail",
                    "memberOf",
                    "primaryGroupID",
                ]
            else:
                user_filter = f"(|(uid={esc_user})(mail={esc_user}))"
                user_attrs = [
                    "uid",
                    "cn",
                    "displayName",
                    "givenName",
                    "sn",
                    "mail",
                    "memberOf",
                    "gidNumber",
                ]

            found_entries = conn.search(base_dn, user_filter, user_attrs, size_limit=5)
            if not found_entries:
                return {
                    "ok": True,
                    "found": False,
                    "username": uname,
                    "user_dn": "",
                    "display_name": "",
                    "email": "",
                    "member_of": [],
                    "matched_role": "None",
                    "grafana_admin": False,
                    "message": f"User '{uname}' was not found in domain '{dom}'.",
                }

            user_entry = found_entries[0]
            user_dn = user_entry.first_str("distinguishedName") or user_entry.dn.strip()
            resolved_username = (
                user_entry.first_str("sAMAccountName", "uid") or uname
            )
            given_sn = " ".join(
                p for p in (user_entry.first_str("givenName"), user_entry.first_str("sn")) if p
            ).strip()
            display_name = (
                user_entry.first_str("displayName")
                or given_sn
                or user_entry.first_str("cn")
                or resolved_username
            )
            email = user_entry.first_str("mail")

            group_dn_map: dict[str, str] = {}
            for direct_dn in user_entry.all_strs("memberOf"):
                group_dn_map[direct_dn.lower()] = direct_dn

            all_groups = _query_groups_internal(conn, base_dn, schema)
            all_users = _query_users_internal(conn, base_dn, schema)

            if schema == "ad" and user_dn:
                esc_dn = escape_ldap_filter_value(user_dn)
                in_chain_filter = f"(&(objectClass=group)(member:{AD_IN_CHAIN_OID}:={esc_dn}))"
                nested_entries = conn.search(base_dn, in_chain_filter, ["distinguishedName", "cn"])
                for ne in nested_entries:
                    ndn = ne.first_str("distinguishedName") or ne.dn.strip()
                    if ndn:
                        group_dn_map.setdefault(ndn.lower(), ndn)

                primary_gid = user_entry.first_str("primaryGroupID")
                if primary_gid:
                    for grp in all_groups:
                        if grp.get("rid") == primary_gid:
                            group_dn_map.setdefault(grp["dn"].lower(), grp["dn"])
                            break
                    else:
                        wk_name = _WELL_KNOWN_AD_RIDS.get(primary_gid)
                        if wk_name:
                            for grp in all_groups:
                                if grp["name"].lower() == wk_name or grp["sam"].lower() == wk_name:
                                    group_dn_map.setdefault(grp["dn"].lower(), grp["dn"])
                                    break
            elif user_dn:
                esc_dn = escape_ldap_filter_value(user_dn)
                esc_resolved = escape_ldap_filter_value(resolved_username)
                rfc_group_filter = (
                    f"(|(&(objectClass=posixGroup)(memberUid={esc_resolved}))"
                    f"(&(objectClass=groupOfNames)(member={esc_dn}))"
                    f"(&(objectClass=groupOfUniqueNames)(uniqueMember={esc_dn})))"
                )
                rfc_entries = conn.search(base_dn, rfc_group_filter, ["cn"])
                for re_entry in rfc_entries:
                    rdn = re_entry.dn.strip()
                    if rdn:
                        group_dn_map.setdefault(rdn.lower(), rdn)

        member_of = sorted(group_dn_map.values(), key=lambda d: d.lower())
        member_lower = set(group_dn_map.keys())

        admin_specs = _normalize_principal_list(ldap_admin_principals, ldap_admin_group)
        editor_specs = _normalize_principal_list(ldap_editor_principals, ldap_editor_group)
        viewer_specs = _normalize_principal_list(ldap_viewer_principals, ldap_viewer_group)

        admin_dns = _resolve_principal_dns(
            admin_specs,
            base_dn=base_dn,
            schema=schema,
            discovered_groups=all_groups,
            discovered_users=all_users,
        )
        editor_dns = _resolve_principal_dns(
            editor_specs,
            base_dn=base_dn,
            schema=schema,
            discovered_groups=all_groups,
            discovered_users=all_users,
        )
        viewer_dns = _resolve_principal_dns(
            viewer_specs,
            base_dn=base_dn,
            schema=schema,
            discovered_groups=all_groups,
            discovered_users=all_users,
        )

        admin_match = _match_principal_role("Admin", admin_dns, user_dn, member_lower)
        editor_match = _match_principal_role("Editor", editor_dns, user_dn, member_lower)
        viewer_match = _match_principal_role("Viewer", viewer_dns, user_dn, member_lower)

        if admin_match:
            matched_role = "Admin"
            grafana_admin = True
            msg = admin_match
        elif editor_match:
            matched_role = "Editor"
            grafana_admin = False
            msg = editor_match
        elif viewer_match:
            matched_role = "Viewer"
            grafana_admin = False
            msg = viewer_match
        else:
            matched_role = "None"
            grafana_admin = False
            msg = (
                "User found in directory, but is not a member of any mapped "
                "Grafana Org 1 group or user principal (Admin/Editor/Viewer)."
            )

        return {
            "ok": True,
            "found": True,
            "username": resolved_username,
            "user_dn": user_dn,
            "display_name": display_name,
            "email": email,
            "member_of": member_of,
            "matched_role": matched_role,
            "grafana_admin": grafana_admin,
            "message": msg,
        }
    except Exception as exc:
        return {
            "ok": False,
            "found": False,
            "username": uname,
            "user_dn": "",
            "display_name": "",
            "email": "",
            "member_of": [],
            "matched_role": "None",
            "grafana_admin": False,
            "message": f"LDAP query failed: {exc}",
        }
