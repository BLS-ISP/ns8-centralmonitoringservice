"""Protobuf wire-format codec & authoritative tenant label stamper for Prometheus Remote Write.

Implements `prometheus.WriteRequest` (`prompb/remote.proto` & `prompb/types.proto`)
without requiring generated protobuf C-extensions, guaranteeing 100% portability
across Python 3.12+ Linux containers and Python 3.14 Windows test hosts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import struct
from typing import Final

CUSTOMER_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9-]{1,46}[a-z0-9]\Z")
SITE_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9-]{0,46}[a-z0-9]\Z")
COLLECTOR_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]\Z")
LABEL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-zA-Z_:][a-zA-Z0-9_:]*\Z")
DEVICE_ROLES: Final[frozenset[str]] = frozenset(
    {
        "ns8",
        "linux",
        "windows",
        "proxmox",
        "web",
        "snmp-network",
        "snmp-ups",
        "snmp-nas",
        "snmp-firewall",
        "snmp-printer",
    }
)
ALLOWED_DEVICE_ROLES: Final[frozenset[str]] = DEVICE_ROLES


class ProtobufDecodeError(ValueError):
    """Raised when a Protobuf wire message is truncated or structurally invalid."""


class LabelValidationError(ValueError):
    """Raised when canonical telemetry labels (site, device_role, collector_id) are invalid."""


@dataclass
class Sample:
    value: float
    timestamp_ms: int


@dataclass
class TimeSeries:
    labels: list[tuple[str, str]]
    samples: list[Sample] = field(default_factory=list)


def infer_role_from_job(job: str | None, fallback: str = "linux") -> str:
    """Infer canonical device_role when omitted by a generic exporter/log shipper."""
    if not job:
        return fallback
    lowered = job.lower()
    if "windows" in lowered:
        return "windows"
    if "pve" in lowered or "proxmox" in lowered:
        return "proxmox"
    if "blackbox" in lowered or "http" in lowered:
        return "web"
    if "ns8" in lowered:
        return "ns8"
    if "ups" in lowered or "apcups" in lowered:
        return "snmp-ups"
    if "synology" in lowered or "qnap" in lowered or "nas" in lowered:
        return "snmp-nas"
    if "printer" in lowered:
        return "snmp-printer"
    if "fortigate" in lowered or "firewall" in lowered:
        return "snmp-firewall"
    if "snmp" in lowered:
        return "snmp-network"
    return fallback


def enforce_canonical_labels(
    raw_labels: dict[str, str],
    *,
    authoritative_customer: str,
    allowed_sites: frozenset[str] | None = None,
    default_site: str,
    default_role: str = "linux",
    default_collector_id: str,
    bound_collector_id: str | None = None,
) -> dict[str, str]:
    """Strip any spoofed customer label, validate site/role/collector_id, and sort keys."""
    if not CUSTOMER_RE.match(authoritative_customer):
        raise LabelValidationError(f"Invalid authoritative customer slug: {authoritative_customer!r}")

    clean: dict[str, str] = {}
    for k, v in raw_labels.items():
        if k == "customer":
            continue
        if not LABEL_NAME_RE.match(k):
            raise LabelValidationError(f"Invalid Prometheus/Loki label name: {k!r}")
        clean[k] = v

    clean["customer"] = authoritative_customer

    site = clean.get("site") or default_site
    if not SITE_RE.match(site):
        raise LabelValidationError(f"Invalid site label format: {site!r}")
    if allowed_sites is not None and len(allowed_sites) > 0 and site not in allowed_sites:
        raise LabelValidationError(
            f"Unauthorized site label {site!r} for customer {authoritative_customer!r}"
        )
    clean["site"] = site

    role = clean.get("device_role") or infer_role_from_job(clean.get("job"), default_role)
    if role not in DEVICE_ROLES:
        raise LabelValidationError(f"Invalid device_role label: {role!r}")
    clean["device_role"] = role

    if bound_collector_id:
        collector_id = bound_collector_id
    else:
        collector_id = clean.get("collector_id") or default_collector_id
    if not COLLECTOR_RE.match(collector_id):
        raise LabelValidationError(f"Invalid collector_id label: {collector_id!r}")
    clean["collector_id"] = collector_id

    return dict(sorted(clean.items(), key=lambda kv: kv[0]))


def _encode_pb_varint(value: int) -> bytes:
    if value < 0:
        # Protobuf int64 negative values are 10-byte two's complement varints
        value &= (1 << 64) - 1
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _decode_pb_varint(buf: memoryview, pos: int) -> tuple[int, int]:
    n = len(buf)
    result = 0
    shift = 0
    for _ in range(10):
        if pos >= n:
            raise ProtobufDecodeError("Truncated Protobuf varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    raise ProtobufDecodeError("Protobuf varint exceeds 10 bytes")


def _iter_pb_fields(buf: memoryview):
    """Yield (field_number, wire_type, raw_field_bytes, payload_view_or_int) across message."""
    pos = 0
    n = len(buf)
    while pos < n:
        field_start = pos
        tag, pos = _decode_pb_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 0:
            raise ProtobufDecodeError("Invalid Protobuf field number 0")

        if wire_type == 0:  # Varint
            val, pos = _decode_pb_varint(buf, pos)
            yield field_num, wire_type, buf[field_start:pos], val
        elif wire_type == 1:  # 64-bit
            if pos + 8 > n:
                raise ProtobufDecodeError("Truncated Protobuf fixed64 field")
            val_view = buf[pos : pos + 8]
            pos += 8
            yield field_num, wire_type, buf[field_start:pos], val_view
        elif wire_type == 2:  # Length-delimited
            length, pos = _decode_pb_varint(buf, pos)
            if pos + length > n:
                raise ProtobufDecodeError("Truncated Protobuf length-delimited field")
            val_view = buf[pos : pos + length]
            pos += length
            yield field_num, wire_type, buf[field_start:pos], val_view
        elif wire_type == 5:  # 32-bit
            if pos + 4 > n:
                raise ProtobufDecodeError("Truncated Protobuf fixed32 field")
            val_view = buf[pos : pos + 4]
            pos += 4
            yield field_num, wire_type, buf[field_start:pos], val_view
        else:
            raise ProtobufDecodeError(f"Unsupported Protobuf wire type: {wire_type}")


def _encode_len_delimited(field_num: int, payload: bytes | bytearray | memoryview) -> bytes:
    tag = (field_num << 3) | 2
    return _encode_pb_varint(tag) + _encode_pb_varint(len(payload)) + bytes(payload)


def _encode_label(name: str, value: str) -> bytes:
    out = bytearray()
    if name:
        out.extend(_encode_len_delimited(1, name.encode("utf-8")))
    if value:
        out.extend(_encode_len_delimited(2, value.encode("utf-8")))
    return bytes(out)


def _decode_label(buf: memoryview) -> tuple[str, str]:
    name = ""
    value = ""
    for field_num, wire_type, _raw, payload in _iter_pb_fields(buf):
        if wire_type != 2:
            raise ProtobufDecodeError("Invalid wire type inside prometheus.Label")
        try:
            text = bytes(payload).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtobufDecodeError("Invalid UTF-8 in prometheus.Label") from exc
        if field_num == 1:
            name = text
        elif field_num == 2:
            value = text
    return name, value


def _encode_sample(sample: Sample) -> bytes:
    out = bytearray()
    # double value = 1 (wire type 1 -> tag 0x09)
    out.append(0x09)
    out.extend(struct.pack("<d", sample.value))
    # int64 timestamp = 2 (wire type 0 -> tag 0x10)
    if sample.timestamp_ms != 0:
        out.append(0x10)
        out.extend(_encode_pb_varint(sample.timestamp_ms))
    return bytes(out)


def _decode_sample(buf: memoryview) -> Sample:
    value = 0.0
    ts = 0
    for field_num, wire_type, _raw, payload in _iter_pb_fields(buf):
        if field_num == 1 and wire_type == 1:
            value = struct.unpack("<d", payload)[0]
        elif field_num == 2 and wire_type == 0:
            # Signed 64-bit conversion
            raw_int = int(payload)
            ts = raw_int - (1 << 64) if raw_int >= (1 << 63) else raw_int
    return Sample(value=value, timestamp_ms=ts)


def rewrite_write_request_labels(
    raw_pb: bytes,
    *,
    authoritative_customer: str,
    allowed_sites: frozenset[str] | None = None,
    default_site: str,
    default_role: str = "linux",
    default_collector_id: str,
    bound_collector_id: str | None = None,
) -> bytes:
    """Decode WriteRequest, overwrite customer label, sort labels, and re-encode."""
    mv = memoryview(raw_pb)
    out_request = bytearray()

    for field_num, wire_type, raw_field, payload in _iter_pb_fields(mv):
        if field_num != 1:
            # Preserve MetricMetadata (field 3) and any future WriteRequest fields verbatim
            out_request.extend(raw_field)
            continue

        if wire_type != 2:
            raise ProtobufDecodeError("Invalid wire type for WriteRequest.timeseries")

        raw_labels: dict[str, str] = {}
        preserved_ts_fields = bytearray()

        for ts_fnum, ts_wtype, ts_raw_field, ts_payload in _iter_pb_fields(payload):
            if ts_fnum == 1:
                if ts_wtype != 2:
                    raise ProtobufDecodeError("Invalid wire type for TimeSeries.labels")
                lname, lval = _decode_label(ts_payload)
                raw_labels[lname] = lval
            else:
                # Validate inner Sample/Exemplar/Histogram wire framing while keeping exact bytes
                if ts_wtype == 2:
                    for _ in _iter_pb_fields(ts_payload):
                        pass
                preserved_ts_fields.extend(ts_raw_field)

        stamped_labels = enforce_canonical_labels(
            raw_labels,
            authoritative_customer=authoritative_customer,
            allowed_sites=allowed_sites,
            default_site=default_site,
            default_role=default_role,
            default_collector_id=default_collector_id,
            bound_collector_id=bound_collector_id,
        )

        ts_out = bytearray()
        for lname, lval in stamped_labels.items():
            ts_out.extend(_encode_len_delimited(1, _encode_label(lname, lval)))
        ts_out.extend(preserved_ts_fields)

        out_request.extend(_encode_len_delimited(1, ts_out))

    return bytes(out_request)


def build_write_request(series_list: list[TimeSeries]) -> bytes:
    """Serialize a list of TimeSeries into a Prometheus WriteRequest Protobuf message."""
    out = bytearray()
    for ts in series_list:
        ts_buf = bytearray()
        for lname, lval in ts.labels:
            ts_buf.extend(_encode_len_delimited(1, _encode_label(lname, lval)))
        for sample in ts.samples:
            ts_buf.extend(_encode_len_delimited(2, _encode_sample(sample)))
        out.extend(_encode_len_delimited(1, ts_buf))
    return bytes(out)


def parse_write_request(raw_pb: bytes) -> list[TimeSeries]:
    """Parse a Prometheus WriteRequest Protobuf payload into TimeSeries objects."""
    series_list: list[TimeSeries] = []
    for field_num, wire_type, _raw, payload in _iter_pb_fields(memoryview(raw_pb)):
        if field_num != 1:
            continue
        if wire_type != 2:
            raise ProtobufDecodeError("Invalid TimeSeries wire type")
        labels: list[tuple[str, str]] = []
        samples: list[Sample] = []
        for ts_fnum, ts_wtype, _ts_raw, ts_payload in _iter_pb_fields(payload):
            if ts_fnum == 1 and ts_wtype == 2:
                labels.append(_decode_label(ts_payload))
            elif ts_fnum == 2 and ts_wtype == 2:
                samples.append(_decode_sample(ts_payload))
        series_list.append(TimeSeries(labels=labels, samples=samples))
    return series_list
