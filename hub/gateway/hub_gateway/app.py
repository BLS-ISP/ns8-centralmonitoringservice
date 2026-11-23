"""Hub Multi-Tenant Auth & Telemetry Stamping Gateway (`:8080` ingress + `127.0.0.1:9097` relay)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import signal
from typing import Final
import aiohttp
from aiohttp import web

from hub_gateway.alert_relay import AlertRelaySettings, create_alert_relay_app
from hub_gateway.auth import AuthRateLimiter, TokenRecord, TokenStoreWatcher
from hub_gateway.loki_push import (
    LokiDecodeError,
    rewrite_loki_json_payload,
    rewrite_loki_protobuf_payload,
)
from hub_gateway.prom_remote_write import (
    LabelValidationError,
    ProtobufDecodeError,
    rewrite_write_request_labels,
)
from hub_gateway.proxy import (
    SECURITY_RESPONSE_HEADERS,
    has_path_traversal,
    is_forbidden_internal_route,
    proxy_http_to_grafana,
)
from hub_gateway.snappy_codec import (
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    SnappyCorruptError,
    SnappyTooLargeError,
    snappy_compress,
    snappy_decompress,
)

LOGGER = logging.getLogger("hub_gateway")
DEFAULT_MAX_COMPRESSED_BYTES: Final[int] = 16 * 1024 * 1024
TOKEN_WATCHER_KEY: web.AppKey[TokenStoreWatcher] = web.AppKey("token_watcher", TokenStoreWatcher)
RATE_LIMITER_KEY: web.AppKey[AuthRateLimiter] = web.AppKey("rate_limiter", AuthRateLimiter)
HTTP_SESSION_KEY: web.AppKey[aiohttp.ClientSession] = web.AppKey(
    "http_session", aiohttp.ClientSession
)


@dataclass
class GatewaySettings:
    tenants_file: Path
    prom_write_url: str = "http://127.0.0.1:9090/api/v1/write"
    prom_ready_url: str = "http://127.0.0.1:9090/-/ready"
    loki_push_url: str = "http://127.0.0.1:3100/loki/api/v1/push"
    loki_ready_url: str = "http://127.0.0.1:3100/ready"
    grafana_upstream_url: str = "http://127.0.0.1:3000"
    max_compressed_bytes: int = DEFAULT_MAX_COMPRESSED_BYTES
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES
    auth_rate_limit_max_failures: int = 20
    auth_rate_limit_window_seconds: float = 300.0
    upstream_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> GatewaySettings:
        state_dir = Path(
            os.environ.get("HUB_STATE_DIR")
            or os.environ.get("STATE_DIR")
            or "/state"
        )
        tenants_file = Path(os.environ.get("TENANTS_FILE") or (state_dir / "tenants.json"))
        return cls(
            tenants_file=tenants_file,
            prom_write_url=os.environ.get(
                "PROMETHEUS_WRITE_URL", "http://127.0.0.1:9090/api/v1/write"
            ),
            prom_ready_url=os.environ.get(
                "PROMETHEUS_READY_URL", "http://127.0.0.1:9090/-/ready"
            ),
            loki_push_url=os.environ.get(
                "LOKI_PUSH_URL", "http://127.0.0.1:3100/loki/api/v1/push"
            ),
            loki_ready_url=os.environ.get(
                "LOKI_READY_URL", "http://127.0.0.1:3100/ready"
            ),
            grafana_upstream_url=os.environ.get(
                "GRAFANA_UPSTREAM_URL", "http://127.0.0.1:3000"
            ),
        )


def _api_error(
    status: int,
    code: str,
    message: str,
    *,
    extra_headers: dict[str, str] | None = None,
) -> web.Response:
    headers = dict(SECURITY_RESPONSE_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    return web.json_response(
        {"error": {"code": code, "message": message}},
        status=status,
        headers=headers,
    )


async def _read_bounded_body(request: web.Request, max_bytes: int) -> bytes:
    content_length = request.content_length
    if content_length is not None and content_length > max_bytes:
        raise web.HTTPRequestEntityTooLarge(
            max_size=max_bytes, actual_size=content_length
        )
    chunks = bytearray()
    async for chunk in request.content.iter_chunked(65536):
        chunks.extend(chunk)
        if len(chunks) > max_bytes:
            raise web.HTTPRequestEntityTooLarge(
                max_size=max_bytes, actual_size=len(chunks)
            )
    return bytes(chunks)


def create_gateway_app(settings: GatewaySettings) -> web.Application:
    token_watcher = TokenStoreWatcher(settings.tenants_file)
    rate_limiter = AuthRateLimiter(
        max_failures=settings.auth_rate_limit_max_failures,
        window_seconds=settings.auth_rate_limit_window_seconds,
    )

    @web.middleware
    async def security_and_error_middleware(request: web.Request, handler):
        if has_path_traversal(request.raw_path):
            return _api_error(
                403,
                "FORBIDDEN",
                "Path traversal sequences are strictly forbidden.",
            )
        if is_forbidden_internal_route(request.raw_path, method=request.method):
            return _api_error(
                403,
                "FORBIDDEN",
                "External access to internal telemetry admin/query endpoints is forbidden.",
            )
        try:
            return await handler(request)
        except web.HTTPRequestEntityTooLarge:
            return _api_error(
                413,
                "PAYLOAD_TOO_LARGE",
                f"Compressed request payload exceeds {settings.max_compressed_bytes} bytes.",
            )
        except web.HTTPMethodNotAllowed:
            return _api_error(
                405,
                "BAD_REQUEST",
                f"HTTP method {request.method} is not allowed on {request.path}.",
            )
        except Exception:
            LOGGER.exception("Unhandled exception in hub-gateway request %s %s", request.method, request.path)
            return _api_error(
                500,
                "INTERNAL_ERROR",
                "An unexpected internal error occurred.",
            )

    # Set aiohttp's parser cap slightly above max_compressed_bytes so our handler/middleware
    # returns the canonical JSON apiError envelope cleanly.
    app = web.Application(
        middlewares=[security_and_error_middleware],
        client_max_size=settings.max_compressed_bytes + 1024 * 1024,
    )
    app[TOKEN_WATCHER_KEY] = token_watcher
    app[RATE_LIMITER_KEY] = rate_limiter

    async def on_startup(a: web.Application) -> None:
        timeout = aiohttp.ClientTimeout(total=settings.upstream_timeout_seconds)
        a[HTTP_SESSION_KEY] = aiohttp.ClientSession(timeout=timeout)

    async def on_cleanup(a: web.Application) -> None:
        await a[HTTP_SESSION_KEY].close()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    def _authenticate(request: web.Request) -> tuple[TokenRecord | None, web.Response | None]:
        client_ip = rate_limiter.extract_client_ip(request)
        limited, retry_after = rate_limiter.check(client_ip)
        if limited:
            return None, _api_error(
                429,
                "RATE_LIMITED",
                "Too many failed authentication attempts. Please retry later.",
                extra_headers={"Retry-After": str(retry_after)},
            )

        rec = token_watcher.verify_bearer_header(request.headers.get("Authorization"))
        if rec is None:
            rate_limiter.record_failure(client_ip)
            return None, _api_error(
                401,
                "UNAUTHORIZED",
                "Missing, malformed, or revoked bearer token.",
                extra_headers={"WWW-Authenticate": 'Bearer realm="central-monitoring-hub"'},
            )
        return rec, None

    async def handle_healthy(_request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"}, headers=SECURITY_RESPONSE_HEADERS)

    async def handle_prom_remote_write(request: web.Request) -> web.Response:
        token_rec, err_resp = _authenticate(request)
        if err_resp is not None or token_rec is None:
            return err_resp  # type: ignore[return-value]

        compressed = await _read_bounded_body(request, settings.max_compressed_bytes)
        if not compressed:
            return _api_error(400, "BAD_REQUEST", "Empty Prometheus Remote Write body.")

        try:
            raw_pb = snappy_decompress(compressed, max_length=settings.max_decompressed_bytes)
            stamped_pb = rewrite_write_request_labels(
                raw_pb,
                authoritative_customer=token_rec.customer,
                allowed_sites=token_rec.allowed_sites,
                default_site=token_rec.default_site,
                default_role="linux",
                default_collector_id=token_rec.bound_collector_id or f"{token_rec.customer}-push",
                bound_collector_id=token_rec.bound_collector_id,
            )
            recompressed = snappy_compress(stamped_pb)
        except SnappyTooLargeError as exc:
            return _api_error(413, "PAYLOAD_TOO_LARGE", str(exc))
        except LabelValidationError as exc:
            return _api_error(422, "VALIDATION_ERROR", str(exc))
        except (SnappyCorruptError, ProtobufDecodeError) as exc:
            return _api_error(400, "BAD_REQUEST", f"Malformed Remote Write payload: {exc}")

        session: aiohttp.ClientSession = request.app[HTTP_SESSION_KEY]
        try:
            async with session.post(
                settings.prom_write_url,
                data=recompressed,
                headers={
                    "Content-Type": "application/x-protobuf",
                    "Content-Encoding": "snappy",
                    "X-Prometheus-Remote-Write-Version": "0.1.0",
                },
                allow_redirects=False,
            ) as upstream_resp:
                if upstream_resp.status >= 500:
                    return _api_error(
                        502,
                        "UPSTREAM_UNAVAILABLE",
                        f"Prometheus remote-write receiver returned HTTP {upstream_resp.status}.",
                    )
                if upstream_resp.status >= 400:
                    msg = (await upstream_resp.text())[:300] or "Prometheus rejected payload."
                    return _api_error(400, "BAD_REQUEST", msg)
                return web.Response(status=204, headers=SECURITY_RESPONSE_HEADERS)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return _api_error(
                503,
                "UPSTREAM_UNAVAILABLE",
                "Prometheus remote-write receiver is temporarily unreachable.",
            )

    async def handle_loki_push(request: web.Request) -> web.Response:
        token_rec, err_resp = _authenticate(request)
        if err_resp is not None or token_rec is None:
            return err_resp  # type: ignore[return-value]

        raw_body = await _read_bounded_body(request, settings.max_compressed_bytes)
        if not raw_body:
            return _api_error(400, "BAD_REQUEST", "Empty Loki push body.")

        content_type = request.headers.get("Content-Type", "").lower()
        content_encoding = request.headers.get("Content-Encoding", "").lower()
        default_col = token_rec.bound_collector_id or f"{token_rec.customer}-push"

        is_json = "application/json" in content_type and content_encoding != "snappy"

        try:
            if is_json:
                if len(raw_body) > settings.max_decompressed_bytes:
                    raise SnappyTooLargeError("JSON Loki payload exceeds decompressed limit")
                outbound_body = rewrite_loki_json_payload(
                    raw_body,
                    authoritative_customer=token_rec.customer,
                    allowed_sites=token_rec.allowed_sites,
                    default_site=token_rec.default_site,
                    default_role="linux",
                    default_collector_id=default_col,
                    bound_collector_id=token_rec.bound_collector_id,
                )
                outbound_headers = {
                    "Content-Type": "application/json",
                    "X-Scope-OrgID": token_rec.customer,
                }
            else:
                outbound_body = rewrite_loki_protobuf_payload(
                    raw_body,
                    authoritative_customer=token_rec.customer,
                    allowed_sites=token_rec.allowed_sites,
                    default_site=token_rec.default_site,
                    default_role="linux",
                    default_collector_id=default_col,
                    bound_collector_id=token_rec.bound_collector_id,
                    max_decompressed_bytes=settings.max_decompressed_bytes,
                )
                outbound_headers = {
                    "Content-Type": "application/x-protobuf",
                    "Content-Encoding": "snappy",
                    "X-Scope-OrgID": token_rec.customer,
                }
        except SnappyTooLargeError as exc:
            return _api_error(413, "PAYLOAD_TOO_LARGE", str(exc))
        except LabelValidationError as exc:
            return _api_error(422, "VALIDATION_ERROR", str(exc))
        except (SnappyCorruptError, LokiDecodeError) as exc:
            return _api_error(400, "BAD_REQUEST", f"Malformed Loki push payload: {exc}")

        session: aiohttp.ClientSession = request.app[HTTP_SESSION_KEY]
        try:
            async with session.post(
                settings.loki_push_url,
                data=outbound_body,
                headers=outbound_headers,
                allow_redirects=False,
            ) as upstream_resp:
                if upstream_resp.status >= 500:
                    return _api_error(
                        502,
                        "UPSTREAM_UNAVAILABLE",
                        f"Loki distributor returned HTTP {upstream_resp.status}.",
                    )
                if upstream_resp.status >= 400:
                    msg = (await upstream_resp.text())[:300] or "Loki rejected log push."
                    return _api_error(400, "BAD_REQUEST", msg)
                return web.Response(status=204, headers=SECURITY_RESPONSE_HEADERS)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return _api_error(
                503,
                "UPSTREAM_UNAVAILABLE",
                "Loki push receiver is temporarily unreachable.",
            )

    async def handle_ingest_verify(request: web.Request) -> web.Response:
        token_rec, err_resp = _authenticate(request)
        if err_resp is not None or token_rec is None:
            return err_resp  # type: ignore[return-value]

        session: aiohttp.ClientSession = request.app[HTTP_SESSION_KEY]
        prom_ok = False
        loki_ok = False
        probe_timeout = aiohttp.ClientTimeout(total=3.0)

        try:
            async with session.get(settings.prom_ready_url, timeout=probe_timeout) as r:
                prom_ok = 200 <= r.status < 300
        except (aiohttp.ClientError, asyncio.TimeoutError):
            prom_ok = False

        try:
            async with session.get(settings.loki_ready_url, timeout=probe_timeout) as r:
                loki_ok = 200 <= r.status < 300
        except (aiohttp.ClientError, asyncio.TimeoutError):
            loki_ok = False

        return web.json_response(
            {
                "status": "ok" if (prom_ok and loki_ok) else "degraded",
                "ok": bool(prom_ok and loki_ok),
                "customer": token_rec.customer,
                "display_name": token_rec.display_name,
                "sites": list(token_rec.sites),
                "default_site": token_rec.default_site,
                "site": token_rec.default_site,
                "collector_id": token_rec.bound_collector_id,
                "token_prefix": token_rec.token_prefix,
                "backends": {
                    "prometheus": prom_ok,
                    "loki": loki_ok,
                },
            },
            status=200,
            headers=SECURITY_RESPONSE_HEADERS,
        )

    async def handle_grafana_catchall(request: web.Request) -> web.StreamResponse:
        session: aiohttp.ClientSession = request.app[HTTP_SESSION_KEY]
        return await proxy_http_to_grafana(request, session, settings.grafana_upstream_url)

    app.router.add_get("/-/healthy", handle_healthy)
    app.router.add_post("/api/v1/write", handle_prom_remote_write)
    app.router.add_post("/loki/api/v1/push", handle_loki_push)
    app.router.add_get("/api/v1/ingest/verify", handle_ingest_verify)
    app.router.add_route("*", "/{tail:.*}", handle_grafana_catchall)
    return app


async def _run_servers() -> None:  # pragma: no cover - container entrypoint
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    gw_settings = GatewaySettings.from_env()
    relay_settings = AlertRelaySettings.from_env()

    gw_app = create_gateway_app(gw_settings)
    relay_app = create_alert_relay_app(relay_settings)

    gw_host = os.environ.get("GATEWAY_LISTEN_HOST", "0.0.0.0")
    gw_port = int(os.environ.get("GATEWAY_LISTEN_PORT", "8080"))
    relay_host = os.environ.get("RELAY_LISTEN_HOST", "127.0.0.1")
    relay_port = int(os.environ.get("RELAY_LISTEN_PORT", "9097"))

    gw_runner = web.AppRunner(gw_app, access_log=None)
    relay_runner = web.AppRunner(relay_app, access_log=None)
    await gw_runner.setup()
    await relay_runner.setup()

    gw_site = web.TCPSite(gw_runner, host=gw_host, port=gw_port)
    relay_site = web.TCPSite(relay_runner, host=relay_host, port=relay_port)
    await gw_site.start()
    await relay_site.start()
    LOGGER.info(
        "hub-gateway listening on %s:%d (ingress) and %s:%d (alert-relay)",
        gw_host,
        gw_port,
        relay_host,
        relay_port,
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    if hasattr(signal, "SIGHUP"):
        loop.add_signal_handler(signal.SIGHUP, gw_app[TOKEN_WATCHER_KEY].reload)
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:
                pass

    await stop_event.wait()
    await relay_runner.cleanup()
    await gw_runner.cleanup()


def main() -> None:  # pragma: no cover
    asyncio.run(_run_servers())


if __name__ == "__main__":  # pragma: no cover
    main()
