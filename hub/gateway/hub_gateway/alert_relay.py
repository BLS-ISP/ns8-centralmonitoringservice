"""Internal Loopback Push Relay (`127.0.0.1:9097`) for Ntfy and Gotify notifications.

Translates Alertmanager v4 webhook JSON payloads into formatted Ntfy / Gotify
HTTP push requests using credentials stored in `state/alerting-secrets.json` (`0600`),
with strict topic validation and dial-time `SafePushResolver` IP SSRF enforcement
to defeat DNS-rebinding TOCTOU attacks.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from typing import Any, Final
from urllib.parse import urlparse
import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver

FORBIDDEN_INTERNAL_POD_PORTS: Final[frozenset[int]] = frozenset(
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
        10901,
        10902,
        10911,
        10912,
        10921,
        10922,
    }
)
SLIRP_NET: Final[ipaddress.IPv4Network] = ipaddress.ip_network("10.0.2.0/24")
NTFY_TOPIC_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")
SUSPECT_NUMERIC_HOST_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(?:0x[0-9a-f]+|[0-9]+(?:\.[0-9a-fx]+)*)\Z", re.IGNORECASE
)
RELAY_HTTP_SESSION_KEY: web.AppKey[aiohttp.ClientSession] = web.AppKey(
    "http_session", aiohttp.ClientSession
)


class PushSSRFBlockedError(OSError):
    """Raised at DNS-resolve / dial time when a push destination resolves to a forbidden IP."""


class SafePushResolver(AbstractResolver):
    """Connector-level DNS resolver wrapper enforcing SSRF policy on every dial lookup."""

    def __init__(
        self,
        inner: AbstractResolver | None = None,
        *,
        allow_loopback: bool = False,
    ) -> None:
        self._inner = inner or DefaultResolver()
        self._allow_loopback = allow_loopback

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        records = await self._inner.resolve(host, port, family)
        for item in records:
            addr_txt = str(item.get("host") or "").split("%", 1)[0]
            if not addr_txt:
                continue
            try:
                ip_obj = ipaddress.ip_address(addr_txt)
                _check_ip_allowed(ip_obj, port, allow_loopback=self._allow_loopback)
            except ValueError as exc:
                raise PushSSRFBlockedError(str(exc)) from exc
        return records

    async def close(self) -> None:
        await self._inner.close()


def _ensure_safe_connector_resolver(
    session: aiohttp.ClientSession, *, allow_loopback: bool
) -> None:
    connector = session.connector
    if isinstance(connector, aiohttp.TCPConnector):
        current = getattr(connector, "_resolver", None)
        if current is not None and not isinstance(current, SafePushResolver):
            connector._resolver = SafePushResolver(current, allow_loopback=allow_loopback)


def _is_ssrf_connector_error(exc: BaseException) -> bool:
    if isinstance(exc, PushSSRFBlockedError):
        return True
    os_err = getattr(exc, "os_error", None)
    if isinstance(os_err, PushSSRFBlockedError):
        return True
    cause = getattr(exc, "__cause__", None)
    return isinstance(cause, PushSSRFBlockedError)


@dataclass
class AlertRelaySettings:
    state_dir: Path
    secrets_file: Path | None = None
    request_timeout_seconds: float = 10.0
    allow_loopback_upstream: bool = False

    @classmethod
    def from_env(cls) -> AlertRelaySettings:
        state_dir = Path(
            os.environ.get("HUB_STATE_DIR")
            or os.environ.get("STATE_DIR")
            or "/state"
        )
        secrets_env = os.environ.get("ALERTING_SECRETS_FILE")
        allow_lb = os.environ.get("ALERT_RELAY_ALLOW_LOOPBACK", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        return cls(
            state_dir=state_dir,
            secrets_file=Path(secrets_env) if secrets_env else None,
            allow_loopback_upstream=allow_lb,
        )

    def resolve_secrets_file(self) -> Path:
        return self.secrets_file or (self.state_dir / "alerting-secrets.json")


def _check_ip_allowed(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
    *,
    allow_loopback: bool,
) -> None:
    effective = (
        ip_obj.ipv4_mapped
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped
        else ip_obj
    )

    if effective.is_unspecified or effective.is_link_local or effective.is_multicast:
        raise ValueError(f"Forbidden link-local/unspecified/multicast IP: {ip_obj}")

    if isinstance(effective, ipaddress.IPv4Address) and effective in SLIRP_NET:
        raise ValueError(f"Forbidden slirp4netns host gateway subnet IP: {ip_obj}")

    if effective.is_loopback or ip_obj.is_loopback:
        if port in FORBIDDEN_INTERNAL_POD_PORTS:
            raise ValueError(f"SSRF blocked: internal Hub pod port {port} is forbidden")
        if not allow_loopback:
            raise ValueError(f"SSRF blocked: loopback destination {ip_obj} is forbidden")


async def _validate_and_resolve_push_url(
    raw_url: str,
    session: aiohttp.ClientSession,
    *,
    allow_loopback: bool,
) -> None:
    _ensure_safe_connector_resolver(session, allow_loopback=allow_loopback)

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Push target URL must use http:// or https:// with a valid hostname")

    host = parsed.hostname.strip().lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if host in ("metadata.google.internal", "0.0.0.0"):
        raise ValueError(f"Forbidden push destination host: {host}")
    if host == "localhost" or host.endswith(".localhost"):
        if port in FORBIDDEN_INTERNAL_POD_PORTS or not allow_loopback:
            raise ValueError(f"Forbidden localhost destination: {host}:{port}")
        return

    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        if SUSPECT_NUMERIC_HOST_RE.match(host):
            raise ValueError(f"Non-canonical numeric/hex/octal IP literal forbidden: {host}")
        literal_ip = None

    if literal_ip is not None:
        if isinstance(literal_ip, ipaddress.IPv4Address) and str(literal_ip) != host:
            raise ValueError(f"Non-canonical IPv4 literal forbidden: {host}")
        _check_ip_allowed(literal_ip, port, allow_loopback=allow_loopback)
        return

    connector = session.connector
    resolver = getattr(connector, "_resolver", None) if connector is not None else None

    try:
        if resolver is not None:
            await resolver.resolve(host, port, socket.AF_UNSPEC)
        else:
            loop = asyncio.get_running_loop()
            addrinfos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            for _fam, _type, _proto, _canon, sockaddr in addrinfos:
                addr_txt = str(sockaddr[0]).split("%", 1)[0]
                _check_ip_allowed(
                    ipaddress.ip_address(addr_txt), port, allow_loopback=allow_loopback
                )
    except PushSSRFBlockedError as exc:
        raise ValueError(str(exc)) from exc
    except OSError:
        return


def _load_push_credentials(settings: AlertRelaySettings) -> dict[str, str]:
    merged: dict[str, Any] = {}
    for candidate in (settings.state_dir / "alerting.json", settings.resolve_secrets_file()):
        if not candidate.exists():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            merged.update(data)

    push_block = merged.get("push") if isinstance(merged.get("push"), dict) else {}
    ntfy_block = merged.get("ntfy") if isinstance(merged.get("ntfy"), dict) else {}
    gotify_block = merged.get("gotify") if isinstance(merged.get("gotify"), dict) else {}

    def _pick(*vals: Any) -> str:
        for v in vals:
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    return {
        "ntfy_url": _pick(ntfy_block.get("url"), push_block.get("ntfy_url"), merged.get("ntfy_url")),
        "ntfy_topic": _pick(
            ntfy_block.get("topic"), push_block.get("ntfy_topic"), merged.get("ntfy_topic")
        ),
        "ntfy_token": _pick(
            ntfy_block.get("token"), push_block.get("ntfy_token"), merged.get("ntfy_token")
        ),
        "gotify_url": _pick(
            gotify_block.get("url"), push_block.get("gotify_url"), merged.get("gotify_url")
        ),
        "gotify_token": _pick(
            gotify_block.get("token"), push_block.get("gotify_token"), merged.get("gotify_token")
        ),
    }


def _sanitize_header_line(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").strip()[:200]


def _format_alertmanager_payload(payload: dict[str, Any]) -> tuple[str, str, str, str, int]:
    """Return (status, severity, title, message_body, alert_count)."""
    status = str(payload.get("status") or "firing").lower()
    common_labels = (
        payload.get("commonLabels") if isinstance(payload.get("commonLabels"), dict) else {}
    )
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []

    alertname = str(common_labels.get("alertname") or "MonitoringAlert")
    customer = str(common_labels.get("customer") or "global")
    site = str(common_labels.get("site") or "-")
    severity = str(common_labels.get("severity") or "warning").lower()
    for a in alerts:
        if isinstance(a, dict) and isinstance(a.get("labels"), dict):
            if str(a["labels"].get("severity", "")).lower() == "critical":
                severity = "critical"
                break

    badge = "RESOLVED" if status == "resolved" else f"FIRING:{max(1, len(alerts))}"
    title = _sanitize_header_line(f"[{badge}] {alertname} ({customer} / {site})")

    lines: list[str] = []
    for alert in alerts[:15]:
        if not isinstance(alert, dict):
            continue
        labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
        annotations = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}
        inst = str(labels.get("instance") or labels.get("site") or customer)
        summary = str(annotations.get("summary") or alertname)
        desc = str(annotations.get("description") or "").strip()
        line = f"- [{labels.get('severity', severity).upper()}] {inst}: {summary}"
        if desc:
            line += f"\n  {desc}"
        lines.append(line)

    if not lines:
        common_ann = (
            payload.get("commonAnnotations")
            if isinstance(payload.get("commonAnnotations"), dict)
            else {}
        )
        lines.append(str(common_ann.get("summary") or common_ann.get("description") or title))

    return status, severity, title, "\n".join(lines), len(alerts)


def create_alert_relay_app(settings: AlertRelaySettings) -> web.Application:
    app = web.Application(client_max_size=2 * 1024 * 1024)

    async def on_startup(a: web.Application) -> None:
        timeout = aiohttp.ClientTimeout(total=settings.request_timeout_seconds)
        safe_resolver = SafePushResolver(
            DefaultResolver(), allow_loopback=settings.allow_loopback_upstream
        )
        connector = aiohttp.TCPConnector(resolver=safe_resolver)
        a[RELAY_HTTP_SESSION_KEY] = aiohttp.ClientSession(
            connector=connector, timeout=timeout
        )

    async def on_cleanup(a: web.Application) -> None:
        await a[RELAY_HTTP_SESSION_KEY].close()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    async def handle_healthy(_req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def handle_ntfy(request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except Exception:
            return web.json_response(
                {"error": {"code": "BAD_REQUEST", "message": "Invalid Alertmanager JSON body."}},
                status=400,
            )
        if not isinstance(payload, dict):
            return web.json_response(
                {"error": {"code": "BAD_REQUEST", "message": "Expected JSON object."}},
                status=400,
            )

        creds = _load_push_credentials(settings)
        ntfy_url = creds["ntfy_url"]
        ntfy_topic = creds["ntfy_topic"].strip()
        if not ntfy_url or not ntfy_topic:
            return web.json_response(
                {
                    "error": {
                        "code": "UPSTREAM_UNAVAILABLE",
                        "message": "Ntfy URL or topic is not configured.",
                    }
                },
                status=503,
            )

        if not NTFY_TOPIC_RE.match(ntfy_topic):
            return web.json_response(
                {
                    "error": {
                        "code": "FORBIDDEN",
                        "message": f"Invalid ntfy_topic format: {ntfy_topic!r}",
                    }
                },
                status=403,
            )

        session: aiohttp.ClientSession = request.app[RELAY_HTTP_SESSION_KEY]
        target = f"{ntfy_url.rstrip('/')}/{ntfy_topic}"
        try:
            await _validate_and_resolve_push_url(
                target,
                session,
                allow_loopback=settings.allow_loopback_upstream,
            )
        except ValueError as exc:
            return web.json_response(
                {"error": {"code": "FORBIDDEN", "message": str(exc)}},
                status=403,
            )

        status, severity, title, body, count = _format_alertmanager_payload(payload)
        if status == "resolved":
            priority = "default"
            tags = "white_check_mark"
        elif severity == "critical":
            priority = "urgent"
            tags = "rotating_light"
        else:
            priority = "high"
            tags = "warning"

        headers = {
            "Title": title,
            "Priority": priority,
            "Tags": tags,
            "Content-Type": "text/plain; charset=utf-8",
        }
        if creds["ntfy_token"]:
            headers["Authorization"] = f"Bearer {_sanitize_header_line(creds['ntfy_token'])}"

        try:
            async with session.post(
                target,
                data=body.encode("utf-8"),
                headers=headers,
                allow_redirects=False,
            ) as resp:
                if resp.status >= 400:
                    return web.json_response(
                        {
                            "error": {
                                "code": "UPSTREAM_UNAVAILABLE",
                                "message": f"Ntfy server returned HTTP {resp.status}.",
                            }
                        },
                        status=502,
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError, PushSSRFBlockedError) as exc:
            if _is_ssrf_connector_error(exc):
                return web.json_response(
                    {"error": {"code": "FORBIDDEN", "message": str(exc)}},
                    status=403,
                )
            return web.json_response(
                {
                    "error": {
                        "code": "UPSTREAM_UNAVAILABLE",
                        "message": "Failed to reach Ntfy push endpoint.",
                    }
                },
                status=502,
            )

        return web.json_response({"status": "ok", "provider": "ntfy", "forwarded_alerts": count})

    async def handle_gotify(request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except Exception:
            return web.json_response(
                {"error": {"code": "BAD_REQUEST", "message": "Invalid Alertmanager JSON body."}},
                status=400,
            )
        if not isinstance(payload, dict):
            return web.json_response(
                {"error": {"code": "BAD_REQUEST", "message": "Expected JSON object."}},
                status=400,
            )

        creds = _load_push_credentials(settings)
        gotify_url = creds["gotify_url"]
        gotify_token = creds["gotify_token"]
        if not gotify_url or not gotify_token:
            return web.json_response(
                {
                    "error": {
                        "code": "UPSTREAM_UNAVAILABLE",
                        "message": "Gotify URL or application token is not configured.",
                    }
                },
                status=503,
            )

        session: aiohttp.ClientSession = request.app[RELAY_HTTP_SESSION_KEY]
        target = f"{gotify_url.rstrip('/')}/message"
        try:
            await _validate_and_resolve_push_url(
                target,
                session,
                allow_loopback=settings.allow_loopback_upstream,
            )
        except ValueError as exc:
            return web.json_response(
                {"error": {"code": "FORBIDDEN", "message": str(exc)}},
                status=403,
            )

        status, severity, title, body, count = _format_alertmanager_payload(payload)
        if status == "resolved":
            priority = 2
        elif severity == "critical":
            priority = 8
        else:
            priority = 5

        headers = {
            "X-Gotify-Key": _sanitize_header_line(gotify_token),
            "Content-Type": "application/json",
        }
        gotify_doc = {
            "title": title,
            "message": body,
            "priority": priority,
            "extras": {"client::display": {"contentType": "text/markdown"}},
        }

        try:
            async with session.post(
                target,
                json=gotify_doc,
                headers=headers,
                allow_redirects=False,
            ) as resp:
                if resp.status >= 400:
                    return web.json_response(
                        {
                            "error": {
                                "code": "UPSTREAM_UNAVAILABLE",
                                "message": f"Gotify server returned HTTP {resp.status}.",
                            }
                        },
                        status=502,
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError, PushSSRFBlockedError) as exc:
            if _is_ssrf_connector_error(exc):
                return web.json_response(
                    {"error": {"code": "FORBIDDEN", "message": str(exc)}},
                    status=403,
                )
            return web.json_response(
                {
                    "error": {
                        "code": "UPSTREAM_UNAVAILABLE",
                        "message": "Failed to reach Gotify push endpoint.",
                    }
                },
                status=502,
            )

        return web.json_response({"status": "ok", "provider": "gotify", "forwarded_alerts": count})

    app.router.add_get("/-/healthy", handle_healthy)
    app.router.add_post("/alert-relay/ntfy", handle_ntfy)
    app.router.add_post("/alert-relay/gotify", handle_gotify)
    return app
