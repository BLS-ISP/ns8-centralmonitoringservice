"""Loki Push payload validator and tenant label enforcer (JSON & Snappy+Protobuf).

Supports both:
1. `application/json` (`/loki/api/v1/push` `{"streams": [{"stream": {...}, "values": [...]}]}`)
2. `application/x-protobuf` Snappy-compressed `logproto.PushRequest` (used by Grafana Alloy
   `loki.write` and Promtail), rewriting `StreamAdapter.labels` (`{k="v", ...}`) server-side.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any

from hub_gateway.prom_remote_write import (
    ALLOWED_DEVICE_ROLES,
    DEVICE_ROLES,
    LABEL_NAME_RE,
    ProtobufDecodeError,
    _decode_pb_varint,
    _encode_len_delimited,
    _encode_pb_varint,
    _iter_pb_fields,
    enforce_canonical_labels,
)
from hub_gateway.snappy_codec import (
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    snappy_compress,
    snappy_decompress,
)


class LokiDecodeError(ValueError):
    """Raised when a Loki JSON or Protobuf PushRequest payload is malformed."""


@dataclass
class LokiEntry:
    timestamp_seconds: int
    timestamp_nanos: int
    line: str


@dataclass
class LokiStream:
    labels: str
    entries: list[LokiEntry] = field(default_factory=list)


def parse_loki_label_selector(selector: str) -> dict[str, str]:
    """Parse a LogQL/Prometheus stream label selector `{k1="v1", k2="v2"}` into a dict."""
    s = selector.strip()
    if len(s) < 2 or not s.startswith("{") or not s.endswith("}"):
        raise LokiDecodeError(f"Malformed Loki label selector: {selector!r}")

    inner = s[1:-1].strip()
    if not inner:
        return {}

    labels: dict[str, str] = {}
    pos = 0
    n = len(inner)

    while pos < n:
        while pos < n and inner[pos] in " \t\r\n":
            pos += 1
        if pos >= n:
            break

        eq_pos = inner.find("=", pos)
        if eq_pos == -1:
            raise LokiDecodeError(f"Missing '=' in Loki label selector: {selector!r}")
        name = inner[pos:eq_pos].strip()
        if not LABEL_NAME_RE.match(name):
            raise LokiDecodeError(f"Invalid label name {name!r} in Loki selector")

        pos = eq_pos + 1
        while pos < n and inner[pos] in " \t\r\n":
            pos += 1
        if pos >= n or inner[pos] != '"':
            raise LokiDecodeError(f"Expected quoted value for label {name!r}")
        pos += 1

        val_chars: list[str] = []
        closed = False
        while pos < n:
            ch = inner[pos]
            pos += 1
            if ch == '"':
                closed = True
                break
            if ch == "\\":
                if pos >= n:
                    raise LokiDecodeError("Unterminated escape in Loki label value")
                esc = inner[pos]
                pos += 1
                if esc == "n":
                    val_chars.append("\n")
                elif esc == "r":
                    val_chars.append("\r")
                elif esc == "t":
                    val_chars.append("\t")
                elif esc in ('"', "\\"):
                    val_chars.append(esc)
                else:
                    val_chars.append(esc)
            else:
                val_chars.append(ch)

        if not closed:
            raise LokiDecodeError(f"Unterminated string literal for label {name!r}")

        labels[name] = "".join(val_chars)

        while pos < n and inner[pos] in " \t\r\n":
            pos += 1
        if pos < n:
            if inner[pos] != ",":
                raise LokiDecodeError(f"Expected ',' between Loki labels in {selector!r}")
            pos += 1

    return labels


def _escape_loki_value(val: str) -> str:
    return (
        val.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def format_loki_label_selector(labels: dict[str, str]) -> str:
    """Format a label dictionary into canonical sorted `{k1="v1", k2="v2"}` form."""
    parts = [
        f'{k}="{_escape_loki_value(v)}"'
        for k, v in sorted(labels.items(), key=lambda kv: kv[0])
    ]
    return "{" + ", ".join(parts) + "}"


def rewrite_loki_json_payload(
    raw_body: bytes,
    *,
    authoritative_customer: str,
    allowed_sites: frozenset[str] | None = None,
    default_site: str,
    default_role: str = "linux",
    default_collector_id: str,
    bound_collector_id: str | None = None,
) -> bytes:
    """Validate and rewrite Loki JSON `/loki/api/v1/push` streams with authoritative tenant labels."""
    try:
        doc: Any = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LokiDecodeError(f"Malformed Loki JSON body: {exc}") from exc

    if not isinstance(doc, dict) or not isinstance(doc.get("streams"), list):
        raise LokiDecodeError("Loki JSON push body must contain a 'streams' list")

    for stream_obj in doc["streams"]:
        if not isinstance(stream_obj, dict):
            raise LokiDecodeError("Each entry in Loki 'streams' must be an object")
        raw_labels = stream_obj.get("stream")
        if raw_labels is None:
            raw_labels = {}
        if not isinstance(raw_labels, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw_labels.items()
        ):
            raise LokiDecodeError("Loki stream 'stream' field must be a string-to-string object")

        stream_obj["stream"] = enforce_canonical_labels(
            raw_labels,
            authoritative_customer=authoritative_customer,
            allowed_sites=allowed_sites,
            default_site=default_site,
            default_role=default_role,
            default_collector_id=default_collector_id,
            bound_collector_id=bound_collector_id,
        )

    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def rewrite_loki_protobuf_payload(
    compressed_body: bytes,
    *,
    authoritative_customer: str,
    allowed_sites: frozenset[str] | None = None,
    default_site: str,
    default_role: str = "linux",
    default_collector_id: str,
    bound_collector_id: str | None = None,
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> bytes:
    """Decompress Snappy+Protobuf logproto.PushRequest, rewrite stream labels, re-compress."""
    raw_pb = snappy_decompress(compressed_body, max_length=max_decompressed_bytes)

    out_push = bytearray()
    try:
        for field_num, wire_type, raw_field, payload in _iter_pb_fields(memoryview(raw_pb)):
            if field_num != 1:
                out_push.extend(raw_field)
                continue
            if wire_type != 2:
                raise LokiDecodeError("Invalid wire type for PushRequest.streams")

            selector_text = "{}"
            preserved_entries = bytearray()

            for s_fnum, s_wtype, s_raw, s_payload in _iter_pb_fields(payload):
                if s_fnum == 1:
                    if s_wtype != 2:
                        raise LokiDecodeError("Invalid wire type for StreamAdapter.labels")
                    try:
                        selector_text = bytes(s_payload).decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise LokiDecodeError("Invalid UTF-8 in StreamAdapter.labels") from exc
                elif s_fnum == 2:
                    if s_wtype != 2:
                        raise LokiDecodeError("Invalid wire type for StreamAdapter.entries")
                    # Validate inner EntryAdapter Protobuf structure
                    for _ in _iter_pb_fields(s_payload):
                        pass
                    preserved_entries.extend(s_raw)
                elif s_fnum == 3:
                    # Drop client-supplied stream hash so Loki hashes the rewritten label set
                    continue
                else:
                    preserved_entries.extend(s_raw)

            parsed_labels = parse_loki_label_selector(selector_text)
            stamped = enforce_canonical_labels(
                parsed_labels,
                authoritative_customer=authoritative_customer,
                allowed_sites=allowed_sites,
                default_site=default_site,
                default_role=default_role,
                default_collector_id=default_collector_id,
                bound_collector_id=bound_collector_id,
            )
            rewritten_selector = format_loki_label_selector(stamped).encode("utf-8")

            stream_out = bytearray()
            stream_out.extend(_encode_len_delimited(1, rewritten_selector))
            stream_out.extend(preserved_entries)
            out_push.extend(_encode_len_delimited(1, stream_out))
    except ProtobufDecodeError as exc:
        raise LokiDecodeError(f"Malformed Loki PushRequest protobuf: {exc}") from exc

    return snappy_compress(bytes(out_push))


def _encode_timestamp(seconds: int, nanos: int) -> bytes:
    out = bytearray()
    if seconds != 0:
        out.append(0x08)  # field 1, varint
        out.extend(_encode_pb_varint(seconds))
    if nanos != 0:
        out.append(0x10)  # field 2, varint
        out.extend(_encode_pb_varint(nanos))
    return bytes(out)


def _decode_timestamp(buf: memoryview) -> tuple[int, int]:
    sec = 0
    nanos = 0
    for fnum, wtype, _raw, payload in _iter_pb_fields(buf):
        if fnum == 1 and wtype == 0:
            sec = int(payload)
        elif fnum == 2 and wtype == 0:
            nanos = int(payload)
    return sec, nanos


def build_loki_push_request(streams: list[LokiStream]) -> bytes:
    """Serialize LokiStream objects into raw (uncompressed) logproto.PushRequest Protobuf bytes."""
    out = bytearray()
    for stream in streams:
        s_buf = bytearray()
        s_buf.extend(_encode_len_delimited(1, stream.labels.encode("utf-8")))
        for entry in stream.entries:
            e_buf = bytearray()
            e_buf.extend(
                _encode_len_delimited(1, _encode_timestamp(entry.timestamp_seconds, entry.timestamp_nanos))
            )
            e_buf.extend(_encode_len_delimited(2, entry.line.encode("utf-8")))
            s_buf.extend(_encode_len_delimited(2, e_buf))
        out.extend(_encode_len_delimited(1, s_buf))
    return bytes(out)


def parse_loki_push_request(raw_pb: bytes) -> list[LokiStream]:
    """Parse raw (uncompressed) logproto.PushRequest Protobuf bytes into LokiStream objects."""
    streams: list[LokiStream] = []
    for fnum, wtype, _raw, payload in _iter_pb_fields(memoryview(raw_pb)):
        if fnum != 1 or wtype != 2:
            continue
        labels = "{}"
        entries: list[LokiEntry] = []
        for s_fnum, s_wtype, _s_raw, s_payload in _iter_pb_fields(payload):
            if s_fnum == 1 and s_wtype == 2:
                labels = bytes(s_payload).decode("utf-8")
            elif s_fnum == 2 and s_wtype == 2:
                sec = 0
                nanos = 0
                line = ""
                for e_fnum, e_wtype, _e_raw, e_payload in _iter_pb_fields(s_payload):
                    if e_fnum == 1 and e_wtype == 2:
                        sec, nanos = _decode_timestamp(e_payload)
                    elif e_fnum == 2 and e_wtype == 2:
                        line = bytes(e_payload).decode("utf-8")
                entries.append(LokiEntry(timestamp_seconds=sec, timestamp_nanos=nanos, line=line))
        streams.append(LokiStream(labels=labels, entries=entries))
    return streams
