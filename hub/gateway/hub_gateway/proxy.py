"""Safe HTTP and WebSocket (`/api/live/ws`) reverse proxy to internal Grafana (:3000).

Enforces strict path-traversal sanitization (including `.` and `..` dot-segments),
collapses duplicate slashes (`//`), enforces case-insensitive internal route blocking,
allowlists read-only query endpoints under `/api/datasources/proxy/`, re-validates
`yarl.URL` parsed upstream targets for zero parser differential, strips auth-proxy /
`Connection`-nominated headers, and preserves multi-value `Set-Cookie` headers.
"""

from __future__ import annotations

import asyncio
import re
from typing import Final
from urllib.parse import unquote
import aiohttp
from aiohttp import web
from multidict import CIMultiDict
from yarl import URL

HOP_BY_HOP_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "x-scope-orgid",
        "x-real-ip",
    }
)

SECURITY_RESPONSE_HEADERS: Final[dict[str, str]] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

FORBIDDEN_EXACT_PATHS: Final[frozenset[str]] = frozenset(
    {
        "/metrics",
        "/-/reload",
        "/-/quit",
        "/-/ready",
        "/federate",
        "/flush",
        "/ready",
        "/config",
        "/ring",
        "/api/alertmanager",
        "/api/ruler",
        "/api/v1/provisioning",
        "/api/v1/query",
        "/api/v1/query_range",
        "/api/v1/series",
        "/api/v1/labels",
        "/api/v1/targets",
        "/api/v1/rules",
        "/api/v1/alerts",
        "/loki/api/v1/query",
        "/loki/api/v1/query_range",
        "/loki/api/v1/labels",
        "/loki/api/v1/series",
        "/loki/api/v1/tail",
        "/loki/api/v1/delete",
    }
)

FORBIDDEN_PATH_PREFIXES: Final[tuple[str, ...]] = (
    "/alert-relay",
    "/metrics/",
    "/api/alertmanager/",
    "/api/ruler/",
    "/api/v1/provisioning/",
    "/api/v1/label/",
    "/api/v1/status/",
    "/api/v1/admin/",
    "/loki/api/v1/label/",
    "/ingester/",
    "/compactor/",
)

_MULTI_SLASH_RE: Final[re.Pattern[str]] = re.compile(r"/+")
_DS_PROXY_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"\A/api/datasources/proxy/(?:uid/[^/]+|[0-9]+)(/.*)?\Z"
)
_ALLOWED_DS_PROXY_EXACT: Final[frozenset[str]] = frozenset(
    {
        "/api/v1/query",
        "/api/v1/query_range",
        "/api/v1/series",
        "/api/v1/labels",
        "/api/v1/metadata",
        "/loki/api/v1/query",
        "/loki/api/v1/query_range",
        "/loki/api/v1/labels",
        "/loki/api/v1/series",
    }
)
_ALLOWED_DS_PROXY_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\A/api/v1/label/[A-Za-z0-9_:]+/values\Z"),
    re.compile(r"\A/loki/api/v1/label/[A-Za-z0-9_:]+/values\Z"),
    re.compile(r"\A/loki/api/v1/index/[A-Za-z0-9_-]+\Z"),
)


def normalize_request_path(raw_path_with_qs: str) -> str:
    """Decode URL-encoding, collapse `//+`, and resolve RFC 3986 `.` and `..` dot-segments."""
    raw_path = raw_path_with_qs.split("?", 1)[0]
    decoded = _MULTI_SLASH_RE.sub("/", unquote(raw_path))
    resolved: list[str] = []
    for seg in decoded.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if resolved:
                resolved.pop()
            continue
        resolved.append(seg)
    trailing_slash = decoded.endswith("/") and len(resolved) > 0
    collapsed = "/" + "/".join(resolved)
    if trailing_slash and collapsed != "/":
        collapsed += "/"
    return collapsed


def has_path_traversal(raw_path_with_qs: str) -> bool:
    """Detect raw or URL-encoded `.` / `..` dot-segments or path-traversal sequences."""
    raw_path = raw_path_with_qs.split("?", 1)[0]
    lowered = raw_path.lower()
    if (
        "%2e" in lowered
        or "%5c" in lowered
        or "%00" in lowered
        or "\\" in raw_path
        or "\x00" in raw_path
    ):
        return True

    decoded_once = unquote(raw_path)
    decoded_twice = unquote(decoded_once)
    for candidate in (raw_path, decoded_once, decoded_twice):
        if "\\" in candidate or "\x00" in candidate:
            return True
        segments = candidate.split("/")
        if "." in segments or ".." in segments:
            return True
    return False


def _is_allowed_datasource_proxy_request(collapsed_path: str, method: str) -> bool:
    if method.upper() not in ("GET", "POST"):
        return False
    m = _DS_PROXY_PREFIX_RE.match(collapsed_path)
    if m is None:
        return False
    subpath = (m.group(1) or "").rstrip("/")
    if not subpath:
        return False
    if subpath in _ALLOWED_DS_PROXY_EXACT:
        return True
    return any(pat.match(subpath) is not None for pat in _ALLOWED_DS_PROXY_PATTERNS)


def is_forbidden_internal_route(path_or_raw: str, *, method: str = "GET") -> bool:
    """Return True if path targets internal admin/query endpoints or disallowed proxy subpaths."""
    collapsed = normalize_request_path(path_or_raw)
    collapsed_lower = collapsed.lower()
    trimmed_lower = collapsed_lower.rstrip("/") or "/"

    if trimmed_lower in FORBIDDEN_EXACT_PATHS or collapsed_lower in FORBIDDEN_EXACT_PATHS:
        return True
    for prefix in FORBIDDEN_PATH_PREFIXES:
        if collapsed_lower.startswith(prefix) or trimmed_lower == prefix.rstrip("/"):
            return True

    if collapsed_lower == "/api/datasources/proxy" or collapsed_lower.startswith(
        "/api/datasources/proxy/"
    ):
        if not _is_allowed_datasource_proxy_request(collapsed, method):
            return True
    elif collapsed_lower == "/api/datasources" or collapsed_lower.startswith(
        "/api/datasources/"
    ):
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            return True

    return False


def _extract_connection_tokens(headers: Any) -> set[str]:
    tokens: set[str] = set()
    raw_vals = headers.getall("Connection", []) if hasattr(headers, "getall") else []
    if not raw_vals and "Connection" in headers:
        raw_vals = [headers["Connection"]]
    for val in raw_vals:
        for part in str(val).split(","):
            tok = part.strip().lower()
            if tok:
                tokens.add(tok)
    return tokens


def _build_upstream_headers(request: web.Request) -> dict[str, str]:
    dynamic_hop = _extract_connection_tokens(request.headers)
    headers: dict[str, str] = {}
    for k, v in request.headers.items():
        k_low = k.lower()
        if k_low in HOP_BY_HOP_HEADERS or k_low in dynamic_hop or k_low.startswith("x-webauth"):
            continue
        headers[k] = v

    remote = request.remote or "127.0.0.1"
    existing_xff = request.headers.get("X-Forwarded-For", "").strip()
    headers["X-Forwarded-For"] = f"{existing_xff}, {remote}" if existing_xff else remote
    if "X-Forwarded-Proto" not in headers:
        headers["X-Forwarded-Proto"] = request.scheme
    if "Host" in request.headers:
        headers["X-Forwarded-Host"] = request.headers["Host"]
    return headers


async def proxy_websocket_to_grafana(
    request: web.Request,
    session: aiohttp.ClientSession,
    grafana_base_url: str,
) -> web.StreamResponse:
    """Bi-directional WebSocket proxy restricted strictly to Grafana Live (`/api/live/ws`)."""
    ws_base = grafana_base_url.rstrip("/")
    if ws_base.startswith("https://"):
        ws_url = "wss://" + ws_base[len("https://") :] + request.path_qs
    elif ws_base.startswith("http://"):
        ws_url = "ws://" + ws_base[len("http://") :] + request.path_qs
    else:
        ws_url = ws_base + request.path_qs

    parsed_ws = URL(ws_url)
    if (
        has_path_traversal(parsed_ws.raw_path)
        or is_forbidden_internal_route(parsed_ws.raw_path, method=request.method)
        or normalize_request_path(parsed_ws.raw_path) != "/api/live/ws"
    ):
        return web.json_response(
            {
                "error": {
                    "code": "FORBIDDEN",
                    "message": "WebSocket upgrade is permitted only on /api/live/ws.",
                }
            },
            status=403,
            headers=SECURITY_RESPONSE_HEADERS,
        )

    ws_server = web.WebSocketResponse(autoping=True)
    await ws_server.prepare(request)

    upstream_headers = _build_upstream_headers(request)
    protocols_hdr = request.headers.get("Sec-WebSocket-Protocol", "")
    protocols = [p.strip() for p in protocols_hdr.split(",") if p.strip()]

    try:
        async with session.ws_connect(
            parsed_ws,
            headers=upstream_headers,
            protocols=protocols,
            autoping=True,
        ) as ws_client:

            async def client_to_upstream() -> None:
                async for msg in ws_server:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await ws_client.send_str(msg.data)
                    elif msg.type == aiohttp.WSMsgType.BINARY:
                        await ws_client.send_bytes(msg.data)
                    elif msg.type == aiohttp.WSMsgType.CLOSE:
                        await ws_client.close()
                        break

            async def upstream_to_client() -> None:
                async for msg in ws_client:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await ws_server.send_str(msg.data)
                    elif msg.type == aiohttp.WSMsgType.BINARY:
                        await ws_server.send_bytes(msg.data)
                    elif msg.type == aiohttp.WSMsgType.CLOSE:
                        await ws_server.close()
                        break

            tasks = [
                asyncio.create_task(client_to_upstream()),
                asyncio.create_task(upstream_to_client()),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, *done, return_exceptions=True)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        await ws_server.close(code=aiohttp.WSCloseCode.TRY_AGAIN_LATER)

    return ws_server


async def proxy_http_to_grafana(
    request: web.Request,
    session: aiohttp.ClientSession,
    grafana_base_url: str,
) -> web.StreamResponse:
    """Forward HTTP request to internal Grafana (:3000) with security headers."""
    is_ws_upgrade = (
        request.headers.get("Upgrade", "").lower() == "websocket"
        and "upgrade" in request.headers.get("Connection", "").lower()
    )
    if is_ws_upgrade:
        if normalize_request_path(request.raw_path) != "/api/live/ws":
            return web.json_response(
                {
                    "error": {
                        "code": "FORBIDDEN",
                        "message": "WebSocket upgrade is permitted only on /api/live/ws.",
                    }
                },
                status=403,
                headers=SECURITY_RESPONSE_HEADERS,
            )
        return await proxy_websocket_to_grafana(request, session, grafana_base_url)

    target_url = f"{grafana_base_url.rstrip('/')}{request.path_qs}"
    parsed_target = URL(target_url)
    if has_path_traversal(parsed_target.raw_path) or is_forbidden_internal_route(
        parsed_target.raw_path, method=request.method
    ):
        return web.json_response(
            {
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Normalized upstream route is forbidden.",
                }
            },
            status=403,
            headers=SECURITY_RESPONSE_HEADERS,
        )

    upstream_headers = _build_upstream_headers(request)
    body = await request.read() if request.can_read_body else None

    try:
        async with session.request(
            request.method,
            parsed_target,
            headers=upstream_headers,
            data=body,
            allow_redirects=False,
        ) as upstream_resp:
            resp_body = await upstream_resp.read()
            upstream_conn_tokens = _extract_connection_tokens(upstream_resp.headers)
            resp_headers: CIMultiDict[str] = CIMultiDict()
            for k, v in upstream_resp.headers.items():
                k_low = k.lower()
                if (
                    k_low in HOP_BY_HOP_HEADERS
                    or k_low in upstream_conn_tokens
                    or k_low == "content-length"
                ):
                    continue
                resp_headers.add(k, v)
            for sec_k, sec_v in SECURITY_RESPONSE_HEADERS.items():
                if sec_k not in resp_headers:
                    resp_headers.add(sec_k, sec_v)
            return web.Response(
                status=upstream_resp.status,
                body=resp_body,
                headers=resp_headers,
            )
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return web.json_response(
            {
                "error": {
                    "code": "UPSTREAM_UNAVAILABLE",
                    "message": "Grafana UI backend is temporarily unavailable.",
                }
            },
            status=502,
            headers=SECURITY_RESPONSE_HEADERS,
        )
