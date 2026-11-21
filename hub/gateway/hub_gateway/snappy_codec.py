"""Pure-Python Snappy block format codec with optional C-extension fast path.

Implements Google Snappy raw block format (used by Prometheus Remote Write v1
and Grafana Loki / Alloy logproto.PushRequest) with strict upfront varint size
enforcement to defeat decompression-bomb DoS attacks before buffer allocation.
"""

from __future__ import annotations

from typing import Final

try:
    import snappy as _c_snappy  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - optional C acceleration inside Linux container
    _c_snappy = None

DEFAULT_MAX_DECOMPRESSED_BYTES: Final[int] = 64 * 1024 * 1024
_BLOCK_SIZE: Final[int] = 65536
_HASH_BITS: Final[int] = 12
_HASH_SHIFT: Final[int] = 32 - _HASH_BITS
_HASH_MULTIPLIER: Final[int] = 0x1E35A7BD


class SnappyError(ValueError):
    """Base error for Snappy block encoding/decoding failures."""


class SnappyCorruptError(SnappyError):
    """Raised when compressed Snappy block bytes are malformed or truncated."""


class SnappyTooLargeError(SnappyError):
    """Raised when declared or decoded uncompressed bytes exceed max_length."""


def encode_varint(value: int) -> bytes:
    """Encode non-negative integer as unsigned base-128 varint."""
    if value < 0:
        raise ValueError("Varint value must be non-negative")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_varint32(data: bytes | memoryview, pos: int = 0) -> tuple[int, int]:
    """Decode unsigned 32-bit varint starting at pos, returning (value, next_pos)."""
    n = len(data)
    result = 0
    shift = 0
    for i in range(5):
        if pos >= n:
            raise SnappyCorruptError("Truncated Snappy varint header")
        b = data[pos]
        pos += 1
        if i == 4 and b >= 0x10:
            raise SnappyCorruptError("Snappy varint32 overflow")
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    raise SnappyCorruptError("Unterminated Snappy varint header")


def snappy_decompress(
    data: bytes,
    *,
    max_length: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
    force_pure_python: bool = False,
) -> bytes:
    """Decompress Snappy raw block format, aborting immediately if > max_length."""
    if not data:
        raise SnappyCorruptError("Empty Snappy payload")

    mv = memoryview(data)
    uncompressed_len, pos = decode_varint32(mv, 0)
    if uncompressed_len > max_length:
        raise SnappyTooLargeError(
            f"Declared uncompressed Snappy length {uncompressed_len} exceeds limit {max_length}"
        )

    if uncompressed_len == 0:
        if pos != len(mv):
            raise SnappyCorruptError("Trailing bytes after zero-length Snappy header")
        return b""

    if _c_snappy is not None and not force_pure_python:  # pragma: no cover
        try:
            decoded = _c_snappy.decompress(data)
        except Exception as exc:
            raise SnappyCorruptError(f"Invalid Snappy stream: {exc}") from exc
        if len(decoded) != uncompressed_len:
            raise SnappyCorruptError("Decoded Snappy length mismatch")
        if len(decoded) > max_length:
            raise SnappyTooLargeError("Decoded Snappy length exceeds limit")
        return decoded

    n = len(mv)
    out = bytearray()

    while pos < n:
        tag = mv[pos]
        pos += 1
        tag_type = tag & 0x03

        if tag_type == 0:
            len_minus_1 = tag >> 2
            if len_minus_1 < 60:
                lit_len = len_minus_1 + 1
            else:
                extra_bytes = len_minus_1 - 59
                if pos + extra_bytes > n:
                    raise SnappyCorruptError("Truncated Snappy literal length")
                lit_len = int.from_bytes(mv[pos : pos + extra_bytes], "little") + 1
                pos += extra_bytes

            if pos + lit_len > n or len(out) + lit_len > uncompressed_len:
                raise SnappyCorruptError("Snappy literal exceeds payload or target length")
            out.extend(mv[pos : pos + lit_len])
            pos += lit_len
        else:
            if tag_type == 1:
                copy_len = ((tag >> 2) & 0x07) + 4
                if pos >= n:
                    raise SnappyCorruptError("Truncated Snappy copy-1 offset")
                offset = ((tag & 0xE0) << 3) | mv[pos]
                pos += 1
            elif tag_type == 2:
                copy_len = (tag >> 2) + 1
                if pos + 2 > n:
                    raise SnappyCorruptError("Truncated Snappy copy-2 offset")
                offset = mv[pos] | (mv[pos + 1] << 8)
                pos += 2
            else:
                copy_len = (tag >> 2) + 1
                if pos + 4 > n:
                    raise SnappyCorruptError("Truncated Snappy copy-4 offset")
                offset = int.from_bytes(mv[pos : pos + 4], "little")
                pos += 4

            if offset <= 0 or offset > len(out):
                raise SnappyCorruptError("Invalid Snappy backreference offset")
            if len(out) + copy_len > uncompressed_len:
                raise SnappyCorruptError("Snappy copy exceeds declared uncompressed length")

            start = len(out) - offset
            if offset >= copy_len:
                out.extend(out[start : start + copy_len])
            else:
                pattern = bytes(out[start:])
                repeats, rem = divmod(copy_len, offset)
                out.extend(pattern * repeats)
                if rem:
                    out.extend(pattern[:rem])

    if len(out) != uncompressed_len:
        raise SnappyCorruptError(
            f"Decoded Snappy length {len(out)} does not match declared {uncompressed_len}"
        )
    return bytes(out)


def _hash4(block: memoryview, pos: int) -> int:
    val = int.from_bytes(block[pos : pos + 4], "little")
    return ((val * _HASH_MULTIPLIER) & 0xFFFFFFFF) >> _HASH_SHIFT


def _emit_literal(out: bytearray, lit: memoryview) -> None:
    length = len(lit)
    if length == 0:
        return
    n = length - 1
    if n < 60:
        out.append(n << 2)
    elif n < 0x100:
        out.append(60 << 2)
        out.append(n)
    elif n < 0x10000:
        out.append(61 << 2)
        out.extend(n.to_bytes(2, "little"))
    elif n < 0x1000000:
        out.append(62 << 2)
        out.extend(n.to_bytes(3, "little"))
    else:
        out.append(63 << 2)
        out.extend(n.to_bytes(4, "little"))
    out.extend(lit)


def _emit_copies(out: bytearray, offset: int, length: int) -> None:
    while length >= 68:
        out.append(((64 - 1) << 2) | 0x02)
        out.extend(offset.to_bytes(2, "little"))
        length -= 64
    if length > 64:
        out.append(((60 - 1) << 2) | 0x02)
        out.extend(offset.to_bytes(2, "little"))
        length -= 60
    if 4 <= length <= 11 and offset < 2048:
        out.append(((offset >> 8) << 5) | ((length - 4) << 2) | 0x01)
        out.append(offset & 0xFF)
    else:
        out.append(((length - 1) << 2) | 0x02)
        out.extend(offset.to_bytes(2, "little"))


def snappy_compress(data: bytes, *, force_pure_python: bool = False) -> bytes:
    """Compress raw bytes into Snappy block format."""
    if _c_snappy is not None and not force_pure_python:  # pragma: no cover
        return _c_snappy.compress(data)

    out = bytearray(encode_varint(len(data)))
    if not data:
        return bytes(out)

    mv = memoryview(data)
    total = len(mv)

    for b_start in range(0, total, _BLOCK_SIZE):
        block = mv[b_start : min(b_start + _BLOCK_SIZE, total)]
        blen = len(block)
        if blen < 15:
            _emit_literal(out, block)
            continue

        table = [0] * (1 << _HASH_BITS)
        next_emit = 0
        ip = 1
        ip_limit = blen - 10
        table[_hash4(block, 0)] = 0

        while ip <= ip_limit:
            h = _hash4(block, ip)
            cand = table[h]
            table[h] = ip

            if block[ip : ip + 4] == block[cand : cand + 4]:
                if ip > next_emit:
                    _emit_literal(out, block[next_emit:ip])

                match_len = 4
                max_match = blen - ip
                while match_len < max_match and block[cand + match_len] == block[ip + match_len]:
                    match_len += 1

                offset = ip - cand
                _emit_copies(out, offset, match_len)
                ip += match_len
                next_emit = ip
                if ip <= ip_limit:
                    table[_hash4(block, ip - 1)] = ip - 1
            else:
                ip += 1 + ((ip - next_emit) >> 5)

        if next_emit < blen:
            _emit_literal(out, block[next_emit:blen])

    return bytes(out)
