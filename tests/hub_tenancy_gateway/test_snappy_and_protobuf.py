import json
import struct
import pytest

from hub_gateway.snappy_codec import (
    SnappyCorruptError,
    SnappyTooLargeError,
    encode_varint,
    snappy_compress,
    snappy_decompress,
)
from hub_gateway.prom_remote_write import (
    LabelValidationError,
    ProtobufDecodeError,
    Sample,
    TimeSeries,
    build_write_request,
    parse_write_request,
    rewrite_write_request_labels,
)
from hub_gateway.loki_push import (
    LokiDecodeError,
    LokiEntry,
    LokiStream,
    build_loki_push_request,
    format_loki_label_selector,
    parse_loki_label_selector,
    parse_loki_push_request,
    rewrite_loki_json_payload,
    rewrite_loki_protobuf_payload,
)


class TestSnappyCodec:
    def test_empty_and_short_literals_roundtrip(self):
        assert snappy_decompress(snappy_compress(b""), force_pure_python=True) == b""
        payload = b"up{customer='acme-corp'} 1"
        compressed = snappy_compress(payload, force_pure_python=True)
        assert snappy_decompress(compressed, force_pure_python=True) == payload

    def test_repetitive_multi_block_rle_and_backreferences_roundtrip(self):
        # >150 KiB payload exercising multiple 64 KiB Snappy blocks, RLE (offset < length),
        # copy-1, copy-2, and long literals (>60 bytes).
        chunk_a = b"A" * 500  # RLE overlap copy
        chunk_b = b"metric_name{customer=\"acme-corp\",site=\"hq\",device_role=\"linux\",collector_id=\"col-01\"} "
        unique_tail = bytes(range(256)) * 3
        original = (chunk_a + chunk_b * 40 + unique_tail) * 30
        assert len(original) > 130_000

        compressed = snappy_compress(original, force_pure_python=True)
        assert len(compressed) < len(original) // 4
        restored = snappy_decompress(compressed, force_pure_python=True)
        assert restored == original

    def test_decompression_bomb_rejected_before_allocation(self):
        # Craft a tiny Snappy header claiming 128 MiB uncompressed size (> 64 MiB cap)
        declared_size = 128 * 1024 * 1024
        bomb_payload = encode_varint(declared_size) + b"\x00A"
        with pytest.raises(SnappyTooLargeError):
            snappy_decompress(bomb_payload, max_length=64 * 1024 * 1024)

    def test_corrupt_snappy_inputs_rejected(self):
        # Empty input (missing varint header)
        with pytest.raises(SnappyCorruptError):
            snappy_decompress(b"", force_pure_python=True)

        # Declared length 10, but literal only supplies 2 bytes
        bad_len = encode_varint(10) + bytes([(1 << 2) | 0x00]) + b"hi"
        with pytest.raises(SnappyCorruptError):
            snappy_decompress(bad_len, force_pure_python=True)

        # Copy with offset 0 (illegal in Snappy)
        zero_offset = encode_varint(8) + bytes([(0 << 2) | 0x00]) + b"a" + bytes([0x01, 0x00])
        with pytest.raises(SnappyCorruptError):
            snappy_decompress(zero_offset, force_pure_python=True)


class TestPromRemoteWriteCodec:
    def test_write_request_spoofed_customer_stripped_and_sorted(self):
        raw = build_write_request(
            [
                TimeSeries(
                    labels=[
                        ("__name__", "up"),
                        ("z_custom", "val"),
                        ("customer", "victim-corp"),
                        ("site", "hq"),
                        ("device_role", "linux"),
                        ("collector_id", "col-1"),
                    ],
                    samples=[Sample(value=1.0, timestamp_ms=1700000000123)],
                ),
                TimeSeries(
                    labels=[
                        ("__name__", "node_cpu_seconds_total"),
                        ("customer", "another-victim"),
                        # Omit site, device_role, collector_id to verify defaults
                        ("mode", "idle"),
                    ],
                    samples=[
                        Sample(value=42.5, timestamp_ms=1700000000000),
                        Sample(value=43.5, timestamp_ms=1700000015000),
                    ],
                ),
            ]
        )

        rewritten_bytes = rewrite_write_request_labels(
            raw,
            authoritative_customer="attacker-corp",
            allowed_sites=frozenset({"hq", "dc1"}),
            default_site="hq",
            default_role="linux",
            default_collector_id="attacker-corp-push",
        )

        series = parse_write_request(rewritten_bytes)
        assert len(series) == 2

        # Series 0: customer overwritten, labels strictly sorted lexicographically by name
        s0_names = [k for k, _ in series[0].labels]
        assert s0_names == sorted(s0_names)
        s0_dict = dict(series[0].labels)
        assert s0_dict["customer"] == "attacker-corp"
        assert "victim-corp" not in s0_dict.values()
        assert s0_dict["site"] == "hq"
        assert s0_dict["device_role"] == "linux"
        assert s0_dict["collector_id"] == "col-1"
        assert s0_dict["z_custom"] == "val"
        assert len(series[0].samples) == 1
        assert series[0].samples[0].value == pytest.approx(1.0)
        assert series[0].samples[0].timestamp_ms == 1700000000123

        # Series 1: defaults stamped and sorted
        s1_names = [k for k, _ in series[1].labels]
        assert s1_names == sorted(s1_names)
        s1_dict = dict(series[1].labels)
        assert s1_dict["customer"] == "attacker-corp"
        assert s1_dict["site"] == "hq"
        assert s1_dict["device_role"] == "linux"
        assert s1_dict["collector_id"] == "attacker-corp-push"
        assert [s.timestamp_ms for s in series[1].samples] == [1700000000000, 1700000015000]

    def test_rejects_unauthorized_site_or_invalid_device_role(self):
        bad_site_pb = build_write_request(
            [
                TimeSeries(
                    labels=[
                        ("__name__", "up"),
                        ("site", "unauthorized-branch"),
                        ("device_role", "linux"),
                        ("collector_id", "col-1"),
                    ],
                    samples=[Sample(value=1.0, timestamp_ms=1700000000000)],
                )
            ]
        )
        with pytest.raises(LabelValidationError, match="site"):
            rewrite_write_request_labels(
                bad_site_pb,
                authoritative_customer="acme-corp",
                allowed_sites=frozenset({"hq"}),
                default_site="hq",
                default_role="linux",
                default_collector_id="acme-corp-push",
            )

        bad_role_pb = build_write_request(
            [
                TimeSeries(
                    labels=[
                        ("__name__", "up"),
                        ("site", "hq"),
                        ("device_role", "smart-fridge"),
                        ("collector_id", "col-1"),
                    ],
                    samples=[Sample(value=1.0, timestamp_ms=1700000000000)],
                )
            ]
        )
        with pytest.raises(LabelValidationError, match="device_role"):
            rewrite_write_request_labels(
                bad_role_pb,
                authoritative_customer="acme-corp",
                allowed_sites=frozenset({"hq"}),
                default_site="hq",
                default_role="linux",
                default_collector_id="acme-corp-push",
            )

    def test_malformed_protobuf_raises_decode_error(self):
        # Truncated length-delimited field
        with pytest.raises(ProtobufDecodeError):
            rewrite_write_request_labels(
                b"\x0a\x50truncated",
                authoritative_customer="acme-corp",
                allowed_sites=frozenset({"hq"}),
                default_site="hq",
                default_role="linux",
                default_collector_id="acme-corp-push",
            )


class TestLokiPushCodec:
    def test_selector_parse_and_format_with_escapes(self):
        raw_sel = '{customer="victim-corp", msg="quote:\\" slash:\\\\ line:\\n", job="syslog"}'
        parsed = parse_loki_label_selector(raw_sel)
        assert parsed["customer"] == "victim-corp"
        assert parsed["msg"] == 'quote:" slash:\\ line:\n'
        assert parsed["job"] == "syslog"

        formatted = format_loki_label_selector(parsed)
        reparsed = parse_loki_label_selector(formatted)
        assert reparsed == parsed

    def test_loki_protobuf_push_request_rewrites_customer_and_preserves_entries(self):
        pb = build_loki_push_request(
            [
                LokiStream(
                    labels='{customer="victim-corp", job="systemd-journal", unit="sshd.service"}',
                    entries=[
                        LokiEntry(timestamp_seconds=1700000001, timestamp_nanos=500000000, line="Accepted publickey"),
                        LokiEntry(timestamp_seconds=1700000002, timestamp_nanos=0, line="Failed password"),
                    ],
                )
            ]
        )
        compressed = snappy_compress(pb, force_pure_python=True)
        rewritten_compressed = rewrite_loki_protobuf_payload(
            compressed,
            authoritative_customer="attacker-corp",
            allowed_sites=frozenset({"hq"}),
            default_site="hq",
            default_role="linux",
            default_collector_id="attacker-col-01",
        )
        decompressed = snappy_decompress(rewritten_compressed, force_pure_python=True)
        streams = parse_loki_push_request(decompressed)
        assert len(streams) == 1
        labels = parse_loki_label_selector(streams[0].labels)
        assert labels["customer"] == "attacker-corp"
        assert labels["site"] == "hq"
        assert labels["device_role"] == "linux"
        assert labels["collector_id"] == "attacker-col-01"
        assert labels["unit"] == "sshd.service"
        assert [e.line for e in streams[0].entries] == ["Accepted publickey", "Failed password"]
        assert streams[0].entries[0].timestamp_seconds == 1700000001
        assert streams[0].entries[0].timestamp_nanos == 500000000

    def test_loki_json_payload_rewrites_customer(self):
        body = json.dumps(
            {
                "streams": [
                    {
                        "stream": {"customer": "victim-corp", "job": "syslog"},
                        "values": [["1700000000000000000", "firewall drop"]],
                    }
                ]
            }
        ).encode("utf-8")
        rewritten = rewrite_loki_json_payload(
            body,
            authoritative_customer="attacker-corp",
            allowed_sites=frozenset({"hq"}),
            default_site="hq",
            default_role="linux",
            default_collector_id="attacker-col-01",
        )
        doc = json.loads(rewritten.decode("utf-8"))
        stream_labels = doc["streams"][0]["stream"]
        assert stream_labels["customer"] == "attacker-corp"
        assert stream_labels["site"] == "hq"
        assert stream_labels["device_role"] == "linux"
        assert stream_labels["collector_id"] == "attacker-col-01"
        assert doc["streams"][0]["values"] == [["1700000000000000000", "firewall drop"]]
