"""SSRF Protection for user-supplied scrape targets and Alertmanager webhook/push URLs."""

from __future__ import annotations

import ipaddress
import re
from typing import Final
from urllib.parse import urlparse

from hub_alerting import ValidationFailure

FORBIDDEN_CODE: Final[str] = "FORBIDDEN_INTERNAL_ENDPOINT"

SLIRP4NETNS_NETWORK: Final[ipaddress.IPv4Network] = ipaddress.ip_network("10.0.2.0/24")

FORBIDDEN_HOSTNAMES: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "10.0.2.2",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)

INTERNAL_POD_PORTS: Final[frozenset[int]] = frozenset(
    {
        3000,
        3100,
        8080,
        9090,
        9093,
        9095,
        9096,
        9097,
        9115,
        9116,
        *range(10901, 10923),
    }
)

_CONTROL_OR_SPACE_RE: Final[re.Pattern[str]] = re.compile(r"[\s\x00-\x1f\x7f]")
_NUMERIC_OR_HEX_LABEL_RE: Final[re.Pattern[str]] = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)\Z")


class SSRFValidationError(ValidationFailure):
    """Raised when a user-supplied target or webhook points to an internal/metadata address."""

    def __init__(self, field: str, value: str, reason: str) -> None:
        super().__init__(field=field, value=value, code=FORBIDDEN_CODE, message=reason)


def _check_ip_forbidden(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, raw_value: str, field: str) -> None:
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip_obj]
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        candidates.append(ip_obj.ipv4_mapped)

    for candidate in candidates:
        if isinstance(candidate, ipaddress.IPv4Address) and candidate in SLIRP4NETNS_NETWORK:
            raise SSRFValidationError(
                field,
                raw_value,
                f"Pod slirp4netns subnet 10.0.2.0/24 is forbidden: {candidate}",
            )
        if (
            candidate.is_loopback
            or candidate.is_unspecified
            or candidate.is_link_local
            or candidate.is_multicast
        ):
            raise SSRFValidationError(
                field,
                raw_value,
                f"Loopback, unspecified, link-local, or metadata IP forbidden: {candidate}",
            )


def _extract_host_and_port(raw_endpoint: str, field: str, *, require_http_scheme: bool) -> tuple[str, int | None]:
    cleaned = raw_endpoint.strip()
    if not cleaned or _CONTROL_OR_SPACE_RE.search(cleaned):
        raise SSRFValidationError(field, raw_endpoint, "Empty or malformed endpoint")

    if not require_http_scheme and "://" not in cleaned:
        # Handle bare IPv6 address without brackets (e.g. "::1" or "fe80::1")
        try:
            bare_ip = ipaddress.ip_address(cleaned)
            return str(bare_ip).lower(), None
        except ValueError:
            pass

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise SSRFValidationError(field, raw_endpoint, f"Disallowed URL scheme: {scheme!r}")
    else:
        if require_http_scheme:
            raise SSRFValidationError(field, raw_endpoint, "Webhook URL must start with http:// or https://")
        parsed = urlparse(f"http://{cleaned}")

    if parsed.username or parsed.password:
        raise SSRFValidationError(field, raw_endpoint, "Embedded URL credentials are forbidden")

    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise SSRFValidationError(field, raw_endpoint, "Missing hostname in endpoint")

    try:
        port = parsed.port
    except ValueError as exc:
        raise SSRFValidationError(field, raw_endpoint, f"Invalid port in endpoint: {exc}") from exc

    return host, port


def assert_not_internal_pod_endpoint(raw_endpoint: str, *, field: str = "endpoints") -> None:
    """Validate that a scrape/probe endpoint does not target pod loopback, link-local, metadata, or 10.0.2.0/24."""
    host, port = _extract_host_and_port(raw_endpoint, field, require_http_scheme=False)
    _validate_host_and_port(host, port, raw_endpoint, field)


def validate_webhook_url(raw_url: str, *, field: str = "url") -> None:
    """Validate that a webhook/push URL uses http(s) and does not target internal/metadata hosts."""
    host, port = _extract_host_and_port(raw_url, field, require_http_scheme=True)
    _validate_host_and_port(host, port, raw_url, field)


def _validate_host_and_port(host: str, port: int | None, raw_value: str, field: str) -> None:
    if host in FORBIDDEN_HOSTNAMES or host.endswith(".localhost") or host.endswith(".internal"):
        if host == "10.0.2.2" and port in INTERNAL_POD_PORTS:
            raise SSRFValidationError(field, raw_value, f"Internal pod/host port on 10.0.2.2:{port} forbidden")
        if host in FORBIDDEN_HOSTNAMES or host.endswith(".localhost") or host == "metadata.google.internal":
            raise SSRFValidationError(field, raw_value, f"Internal or metadata host forbidden: {host}")

    # Reject non-canonical IPv4 forms accepted by inet_aton (hex 0x7f000001, octal 0177.0.0.1, short 127.1, int)
    labels = host.split(".")
    if labels and all(_NUMERIC_OR_HEX_LABEL_RE.match(lbl) for lbl in labels):
        try:
            canonical_v4 = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError as exc:
            raise SSRFValidationError(
                field,
                raw_value,
                f"Non-canonical numeric/hex/octal IPv4 literal forbidden: {host}",
            ) from exc
        if str(canonical_v4) != host:
            raise SSRFValidationError(field, raw_value, f"Non-canonical IPv4 literal forbidden: {host}")
        _check_ip_forbidden(canonical_v4, raw_value, field)
        return

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return

    _check_ip_forbidden(ip_obj, raw_value, field)
