"""HTTPS connectivity and bearer token probe against central-monitoring-hub with SSRF protection."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_REWRITE_LOOPBACK_HTTPS_TO_HTTP_FOR_TESTS = False
_SLIRP_SUBNET = ipaddress.ip_network("10.0.2.0/24")
_NUMERIC_OR_HEX_IPV4_TOKEN_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[0-9]+)\Z")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP redirects so bearer tokens can never be redirected to untrusted hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ARG002
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"Unexpected HTTP redirect ({code}) refused for Hub ingest endpoint.",
            headers,
            fp,
        )


def _has_control_or_space(value: str) -> bool:
    return any(
        ord(ch) < 0x21 or ord(ch) == 0x7F or ch.isspace() or ch in "\u2028\u2029"
        for ch in value
    )


def _is_noncanonical_ipv4_literal(host: str) -> bool:
    """Detect hex (0x7f000001), octal (0177.0.0.1), or shortened (127.1) IPv4 notations."""
    parts = host.split(".")
    if not parts or not all(_NUMERIC_OR_HEX_IPV4_TOKEN_RE.match(p) for p in parts):
        return False
    if len(parts) != 4:
        return True
    for part in parts:
        if part.lower().startswith("0x"):
            return True
        if len(part) > 1 and part.startswith("0"):
            return True
    return False


def _validate_resolved_ip(
    ip_str: str,
    *,
    allow_loopback: bool,
) -> None:
    raw_ip = ipaddress.ip_address(ip_str)
    ip_obj = raw_ip.ipv4_mapped if isinstance(raw_ip, ipaddress.IPv6Address) and raw_ip.ipv4_mapped else raw_ip

    if ip_obj.is_unspecified or ip_obj.is_link_local or ip_obj.is_multicast:
        raise ValueError(f"Hub address {ip_str} resolves to a forbidden reserved network range.")
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _SLIRP_SUBNET:
        raise ValueError(f"Hub address {ip_str} resolves to internal container gateway subnet.")
    if ip_obj.is_loopback and not allow_loopback:
        raise ValueError("Hub URL must not target loopback addresses.")


def _resolve_and_validate_hub_host(
    hostname: str,
    port: int,
    *,
    allow_loopback: bool = False,
) -> list[str]:
    """Validate hostname against SSRF bypasses and return validated resolved IP addresses."""
    lower_host = hostname.strip().lower().rstrip(".")
    if not lower_host:
        raise ValueError("Missing Hub hostname.")

    if (lower_host == "localhost" or lower_host.endswith(".localhost")) and not allow_loopback:
        raise ValueError("Hub URL must not target localhost.")

    if _is_noncanonical_ipv4_literal(lower_host):
        raise ValueError("Non-canonical IPv4 address encoding is forbidden.")

    # Direct IP literal check before DNS lookup
    try:
        ip_lit = ipaddress.ip_address(lower_host)
    except ValueError:
        ip_lit = None

    if ip_lit is not None:
        _validate_resolved_ip(str(ip_lit), allow_loopback=allow_loopback)
        return [str(ip_lit)]

    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"Unable to resolve Hub hostname {hostname!r}.")

    resolved_ips: list[str] = []
    for _fam, _socktype, _proto, _canon, sockaddr in infos:
        ip_str = str(sockaddr[0]).split("%", 1)[0]
        _validate_resolved_ip(ip_str, allow_loopback=allow_loopback)
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    return resolved_ips


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated IP while preserving original hostname for TLS SNI & cert verification."""

    def __init__(
        self,
        host: str,
        *,
        pinned_ip: str,
        port: int | None = None,
        context: ssl.SSLContext | None = None,
        timeout: float = 8.0,
    ) -> None:
        super().__init__(host, port=port, context=context, timeout=timeout)
        self._pinned_ip = pinned_ip
        self._sni_host = self.host

    def connect(self) -> None:
        raw_sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        server_hostname = self._sni_host if self._context.check_hostname else None
        self.sock = self._context.wrap_socket(raw_sock, server_hostname=server_hostname)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, *, context: ssl.SSLContext, pinned_ip: str) -> None:
        super().__init__(context=context)
        self._ssl_ctx = context
        self._pinned_ip = pinned_ip

    def https_open(self, req: urllib.request.Request):
        def _factory(host: str, port: int | None = None, timeout: float = 8.0, **kwargs):  # noqa: ARG001
            return _PinnedHTTPSConnection(
                host,
                pinned_ip=self._pinned_ip,
                port=port,
                context=self._ssl_ctx,
                timeout=timeout,
            )

        return self.do_open(_factory, req)


def verify_hub_connection(
    *,
    hub_url: str,
    auth_token: str,
    tls_skip_verify: bool = False,
    timeout_seconds: float = 8.0,
) -> dict[str, Any]:
    """Probe GET ${HUB_URL}/api/v1/ingest/verify and return schema-compliant result."""
    raw_url = hub_url or ""
    if any(ch in raw_url for ch in ("\r", "\n", "\x00", "\u2028", "\u2029")):
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": "Hub URL contains invalid control characters.",
        }

    clean_url = raw_url.strip().rstrip("/")
    if not clean_url or _has_control_or_space(clean_url):
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": "Hub URL must be a valid https:// address.",
        }

    try:
        parsed = urllib.parse.urlparse(clean_url)
        port = parsed.port or 443
    except ValueError:
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": "Hub URL is malformed.",
        }

    if parsed.scheme != "https" or not parsed.hostname:
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": "Hub URL must be a valid https:// address.",
        }

    raw_token = auth_token or ""
    if any(ch in raw_token for ch in ("\r", "\n", "\x00", "\u2028", "\u2029")):
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": "Bearer token contains invalid control characters.",
        }

    clean_token = raw_token.strip()
    if not clean_token:
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": "No bearer token provided or stored.",
        }
    if _has_control_or_space(clean_token):
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": "Bearer token contains invalid whitespace or control characters.",
        }

    allow_loopback = (
        os.environ.get("HUB_PROBE_ALLOW_LOOPBACK", "0") == "1"
        or _REWRITE_LOOPBACK_HTTPS_TO_HTTP_FOR_TESTS
    )

    t0 = time.perf_counter()
    try:
        resolved_ips = _resolve_and_validate_hub_host(
            parsed.hostname,
            port,
            allow_loopback=allow_loopback,
        )
    except ValueError as exc:
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": 0.0,
            "verified_customer": None,
            "message": f"Hub URL rejected by SSRF guard: {exc}",
        }
    except OSError as exc:
        latency_ms = round(max(0.0, (time.perf_counter() - t0) * 1000.0), 2)
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": latency_ms,
            "verified_customer": None,
            "message": f"Connection to Hub failed: {exc}",
        }

    target_url = f"{clean_url}/api/v1/ingest/verify"
    if _REWRITE_LOOPBACK_HTTPS_TO_HTTP_FOR_TESTS and parsed.hostname == "127.0.0.1":
        target_url = "http://" + target_url[len("https://") :]
        opener = urllib.request.build_opener(_NoRedirectHandler())
    else:
        if tls_skip_verify:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        else:
            cafile = os.environ.get("SSL_CERT_FILE") or None
            ssl_ctx = ssl.create_default_context(cafile=cafile)
        opener = urllib.request.build_opener(
            _PinnedHTTPSHandler(context=ssl_ctx, pinned_ip=resolved_ips[0]),
            _NoRedirectHandler(),
        )

    req = urllib.request.Request(
        target_url,
        method="GET",
        headers={
            "Authorization": f"Bearer {clean_token}",
            "Accept": "application/json",
            "User-Agent": "central-monitoring-collector/1.0",
        },
    )

    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            latency_ms = round(max(0.0, (time.perf_counter() - t0) * 1000.0), 2)
            status_code = int(getattr(resp, "status", 200))
            raw_body = resp.read(65536).decode("utf-8", errors="replace")
            payload: dict[str, Any] = {}
            if raw_body.strip():
                try:
                    loaded = json.loads(raw_body)
                    if isinstance(loaded, dict):
                        payload = loaded
                except ValueError:
                    payload = {}

            verified_customer = payload.get("customer")
            if verified_customer is not None:
                verified_customer = str(verified_customer)

            if 200 <= status_code < 300:
                suffix = f" (customer: {verified_customer})" if verified_customer else ""
                return {
                    "ok": True,
                    "http_status": status_code,
                    "latency_ms": latency_ms,
                    "verified_customer": verified_customer,
                    "message": f"Hub connection verified successfully{suffix}.",
                }

            return {
                "ok": False,
                "http_status": status_code,
                "latency_ms": latency_ms,
                "verified_customer": None,
                "message": f"Unexpected HTTP {status_code} from Hub.",
            }

    except urllib.error.HTTPError as exc:
        latency_ms = round(max(0.0, (time.perf_counter() - t0) * 1000.0), 2)
        err_detail = exc.reason or f"HTTP {exc.code}"
        try:
            err_body = exc.read(65536).decode("utf-8", errors="replace")
            parsed_err = json.loads(err_body)
            if isinstance(parsed_err, dict) and isinstance(parsed_err.get("error"), dict):
                err_detail = str(parsed_err["error"].get("message") or err_detail)
        except Exception:
            pass
        code = int(exc.code) if 0 <= int(exc.code) <= 599 else 500
        return {
            "ok": False,
            "http_status": code,
            "latency_ms": latency_ms,
            "verified_customer": None,
            "message": f"Hub rejected request (HTTP {code}): {err_detail}",
        }

    except urllib.error.URLError as exc:
        latency_ms = round(max(0.0, (time.perf_counter() - t0) * 1000.0), 2)
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            return {
                "ok": False,
                "http_status": 0,
                "latency_ms": latency_ms,
                "verified_customer": None,
                "message": f"TLS certificate verification failed: {reason}",
            }
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return {
                "ok": False,
                "http_status": 0,
                "latency_ms": latency_ms,
                "verified_customer": None,
                "message": "Connection to Hub timed out.",
            }
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": latency_ms,
            "verified_customer": None,
            "message": f"Connection to Hub failed: {reason}",
        }

    except (ssl.SSLError, TimeoutError, socket.timeout, OSError) as exc:
        latency_ms = round(max(0.0, (time.perf_counter() - t0) * 1000.0), 2)
        prefix = (
            "TLS certificate verification failed"
            if isinstance(exc, ssl.SSLError)
            else "Connection to Hub failed"
        )
        return {
            "ok": False,
            "http_status": 0,
            "latency_ms": latency_ms,
            "verified_customer": None,
            "message": f"{prefix}: {exc}",
        }
