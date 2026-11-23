"""Live async HTTP & NS8 action execution harness for E2E cross-module integration tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import datetime
import inspect
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import sys
import threading
from typing import Any

import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_ROOT = REPO_ROOT / "hub"
HUB_IMAGEROOT = HUB_ROOT / "imageroot"
HUB_PYPKG = HUB_IMAGEROOT / "pypkg"
GATEWAY_PKG_ROOT = HUB_ROOT / "gateway"
COLLECTOR_ROOT = REPO_ROOT / "collector"
COLLECTOR_IMAGEROOT = COLLECTOR_ROOT / "imageroot"
COLLECTOR_PYPKG = COLLECTOR_IMAGEROOT / "pypkg"
SCHEMAS_DIR = REPO_ROOT / "shared" / "schemas"

for _pkg_path in (GATEWAY_PKG_ROOT, HUB_PYPKG, COLLECTOR_PYPKG):
    _s = str(_pkg_path)
    if _s not in sys.path:
        sys.path.insert(0, _s)

from hub_gateway.alert_relay import (  # noqa: E402
    RELAY_HTTP_SESSION_KEY,
    AlertRelaySettings,
    create_alert_relay_app,
)
from hub_gateway.app import GatewaySettings, create_gateway_app  # noqa: E402
from hub_gateway.loki_push import (  # noqa: E402
    parse_loki_label_selector,
    parse_loki_push_request,
)
from hub_gateway.prom_remote_write import (  # noqa: E402
    Sample,
    TimeSeries,
    parse_write_request,
)
from hub_gateway.snappy_codec import snappy_decompress  # noqa: E402
from hub_tenancy.ldap_client import (  # noqa: E402
    AD_IN_CHAIN_OID,
    PAGED_RESULTS_OID,
    _ber_bool,
    _ber_int,
    _ber_octet_string,
    _ber_seq,
    _decode_ber_int,
    _decode_ber_tlv,
)


def validate_schema(schema_filename: str, payload: Any) -> None:
    """Validate a payload against an authoritative Draft-07 schema in shared/schemas/."""
    schema_path = SCHEMAS_DIR / schema_filename
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda err: list(err.path))
    assert not errors, (
        f"Schema validation failed for {schema_filename}: "
        f"{[(list(e.path), e.message) for e in errors]}"
    )


def generate_ephemeral_tls_context(cert_dir: Path) -> tuple[ssl.SSLContext, Path]:
    """Generate an ephemeral self-signed X.509 cert for 127.0.0.1 & monitoring.msp.example.com."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NS8 Central Monitoring E2E"),
            x509.NameAttribute(NameOID.COMMON_NAME, "monitoring.msp.example.com"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("monitoring.msp.example.com"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert_dir / "hub-e2e-cert.pem"
    key_pem = cert_dir / "hub-e2e-key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(cert_pem), keyfile=str(key_pem))
    return server_ctx, cert_pem


class StaticHostResolver(AbstractResolver):
    """Custom aiohttp DNS resolver mapping test external FQDNs to 127.0.0.1."""

    def __init__(self, host_map: dict[str, str]) -> None:
        self._host_map = {k.lower(): v for k, v in host_map.items()}
        self._fallback = DefaultResolver()

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        mapped = self._host_map.get(host.lower())
        if mapped is not None:
            return [
                {
                    "hostname": host,
                    "host": mapped,
                    "port": port,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            ]
        return await self._fallback.resolve(host, port, family)

    async def close(self) -> None:
        await self._fallback.close()


@dataclass
class RecordedLokiStream:
    org_id: str
    encoding: str
    labels: dict[str, str]
    lines: list[str]


class MockGrafanaState:
    """In-memory multi-org Grafana API state faithfully modeling Org 1 auto-assignment."""

    def __init__(self) -> None:
        self.next_org_id = 2
        self.next_ds_id = 1
        self.next_user_id = 2
        self.orgs: dict[int, dict[str, Any]] = {1: {"id": 1, "name": "Main Org."}}
        self.datasources: dict[int, dict[str, dict[str, Any]]] = {1: {}}
        self.folders: dict[int, dict[str, dict[str, Any]]] = {1: {}}
        self.dashboards: dict[int, dict[str, dict[str, Any]]] = {1: {}}
        self.users: dict[int, dict[str, Any]] = {
            1: {
                "id": 1,
                "login": "admin",
                "email": "admin@localhost",
                "orgId": 1,
                "isDisabled": False,
                "isGrafanaAdmin": True,
            }
        }
        # org_id -> {user_id -> role}
        self.org_members: dict[int, dict[int, str]] = {1: {1: "Admin"}}
        self.org_preferences: dict[int, dict[str, Any]] = {1: {}}
        self.org_switch_calls: list[tuple[int, int]] = []
        self.deleted_user_ids: set[int] = set()
        self.ldap_reloads: int = 0
        self.dashboard_reloads: int = 0
        self.simulate_org1_file_provisioned: bool = False
        self.org1_provisioned_rejections: int = 0
        self.ds_proxy_hits: list[tuple[str, str]] = []

    def add_org1_user(
        self,
        *,
        login: str,
        email: str,
        org1_role: str,
        is_external: bool = True,
        is_grafana_admin: bool = False,
        auth_labels: list[str] | None = None,
    ) -> int:
        uid = self.next_user_id
        self.next_user_id += 1
        self.users[uid] = {
            "id": uid,
            "login": login,
            "email": email,
            "name": login,
            "orgId": 1,
            "isDisabled": False,
            "isGrafanaAdmin": is_grafana_admin,
            "isExternal": is_external,
            "authLabels": list(auth_labels) if auth_labels is not None else (["LDAP"] if is_external else []),
        }
        self.org_members.setdefault(1, {})[uid] = org1_role
        return uid


@dataclass
class LiveGatewayHandle:
    https_port: int
    http_port: int
    relay_port: int
    ca_cert_path: Path
    gw_https_runner: web.AppRunner
    relay_runner: web.AppRunner

    @property
    def https_url(self) -> str:
        return f"https://127.0.0.1:{self.https_port}"

    @property
    def http_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    @property
    def relay_url(self) -> str:
        return f"http://127.0.0.1:{self.relay_port}"

    async def close(self) -> None:
        await self.relay_runner.cleanup()
        await self.gw_https_runner.cleanup()


@dataclass
class LiveObservabilityBackends:
    """Real async HTTP upstream servers for Prometheus, Loki, Grafana, Alertmanager, Push & Alloy."""

    prom_port: int = 0
    loki_port: int = 0
    grafana_port: int = 0
    am_port: int = 0
    push_port: int = 0
    alloy_port: int = 0

    prom_reloads: int = 0
    snmp_reloads: int = 0
    am_reloads: int = 0
    alloy_reloads: int = 0

    prom_writes: list[list[TimeSeries]] = field(default_factory=list)
    loki_pushes: list[RecordedLokiStream] = field(default_factory=list)
    am_alerts: list[dict[str, Any]] = field(default_factory=list)
    am_silences: dict[str, dict[str, Any]] = field(default_factory=dict)
    ntfy_requests: list[dict[str, Any]] = field(default_factory=list)
    gotify_requests: list[dict[str, Any]] = field(default_factory=list)
    grafana: MockGrafanaState = field(default_factory=MockGrafanaState)

    _runners: list[web.AppRunner] = field(default_factory=list)
    _gateways: list[LiveGatewayHandle] = field(default_factory=list)

    async def _start_app(self, app: web.Application) -> int:
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, host="127.0.0.1", port=0)
        await site.start()
        self._runners.append(runner)
        sockets = site._server.sockets  # type: ignore[union-attr]
        return int(sockets[0].getsockname()[1])

    async def start_all(self) -> None:
        self.prom_port = await self._start_app(self._build_prom_app())
        self.loki_port = await self._start_app(self._build_loki_app())
        self.grafana_port = await self._start_app(self._build_grafana_app())
        self.am_port = await self._start_app(self._build_am_app())
        self.push_port = await self._start_app(self._build_push_app())
        self.alloy_port = await self._start_app(self._build_alloy_app())

    async def close_all(self) -> None:
        for gw in reversed(self._gateways):
            await gw.close()
        for runner in reversed(self._runners):
            await runner.cleanup()

    async def start_hub_gateway(self, state_dir: Path, tls_dir: Path) -> LiveGatewayHandle:
        """Start live hub_gateway (:8080 HTTP+HTTPS) and alert_relay (:9097) against state_dir."""
        tls_ctx, ca_cert = generate_ephemeral_tls_context(tls_dir)
        gw_settings = GatewaySettings(
            tenants_file=state_dir / "tenants.json",
            prom_write_url=f"http://127.0.0.1:{self.prom_port}/api/v1/write",
            prom_ready_url=f"http://127.0.0.1:{self.prom_port}/-/ready",
            loki_push_url=f"http://127.0.0.1:{self.loki_port}/loki/api/v1/push",
            loki_ready_url=f"http://127.0.0.1:{self.loki_port}/ready",
            grafana_upstream_url=f"http://127.0.0.1:{self.grafana_port}",
        )
        gw_app = create_gateway_app(gw_settings)

        relay_kwargs: dict[str, Any] = {"state_dir": state_dir}
        relay_sig = inspect.signature(AlertRelaySettings)
        if "allow_loopback_upstream" in relay_sig.parameters:
            relay_kwargs["allow_loopback_upstream"] = True
        os.environ.setdefault("ALERT_RELAY_ALLOW_LOOPBACK", "1")
        relay_settings = AlertRelaySettings(**relay_kwargs)
        relay_app = create_alert_relay_app(relay_settings)

        # Inject test DNS resolver so external push FQDNs (ntfy.msp.example.com /
        # gotify.msp.example.com) pass SSRF validation and resolve to 127.0.0.1.
        async def _override_relay_session(app: web.Application) -> None:
            await app[RELAY_HTTP_SESSION_KEY].close()
            resolver = StaticHostResolver(
                {
                    "ntfy.msp.example.com": "127.0.0.1",
                    "gotify.msp.example.com": "127.0.0.1",
                }
            )
            connector = aiohttp.TCPConnector(resolver=resolver)
            timeout = aiohttp.ClientTimeout(total=relay_settings.request_timeout_seconds)
            app[RELAY_HTTP_SESSION_KEY] = aiohttp.ClientSession(
                connector=connector, timeout=timeout
            )

        relay_app.on_startup.append(_override_relay_session)

        gw_runner = web.AppRunner(gw_app, access_log=None)
        await gw_runner.setup()
        https_site = web.TCPSite(gw_runner, host="127.0.0.1", port=0, ssl_context=tls_ctx)
        http_site = web.TCPSite(gw_runner, host="127.0.0.1", port=0)
        await https_site.start()
        await http_site.start()
        https_port = int(https_site._server.sockets[0].getsockname()[1])  # type: ignore[union-attr]
        http_port = int(http_site._server.sockets[0].getsockname()[1])  # type: ignore[union-attr]

        relay_runner = web.AppRunner(relay_app, access_log=None)
        await relay_runner.setup()
        relay_site = web.TCPSite(relay_runner, host="127.0.0.1", port=0)
        await relay_site.start()
        relay_port = int(relay_site._server.sockets[0].getsockname()[1])  # type: ignore[union-attr]

        handle = LiveGatewayHandle(
            https_port=https_port,
            http_port=http_port,
            relay_port=relay_port,
            ca_cert_path=ca_cert,
            gw_https_runner=gw_runner,
            relay_runner=relay_runner,
        )
        self._gateways.append(handle)
        return handle

    def _build_prom_app(self) -> web.Application:
        app = web.Application()

        async def ready(_req: web.Request) -> web.Response:
            return web.Response(text="Prometheus Server is Ready.\n", status=200)

        async def reload_cfg(_req: web.Request) -> web.Response:
            self.prom_reloads += 1
            return web.Response(status=200)

        async def snmp_reload(_req: web.Request) -> web.Response:
            self.snmp_reloads += 1
            return web.Response(status=200)

        async def remote_write(req: web.Request) -> web.Response:
            assert req.headers.get("Content-Encoding", "").lower() == "snappy"
            compressed = await req.read()
            raw_pb = snappy_decompress(compressed)
            series = parse_write_request(raw_pb)
            self.prom_writes.append(series)
            return web.Response(status=204)

        async def tsdb_status(_req: web.Request) -> web.Response:
            series_count = sum(len(batch) for batch in self.prom_writes)
            return web.json_response(
                {"status": "success", "data": {"headStats": {"numSeries": series_count}}}
            )

        async def prom_alerts(_req: web.Request) -> web.Response:
            return web.json_response({"status": "success", "data": {"alerts": []}})

        app.router.add_get("/-/ready", ready)
        app.router.add_post("/-/reload", reload_cfg)
        app.router.add_post("/snmp/-/reload", snmp_reload)
        app.router.add_post("/api/v1/write", remote_write)
        app.router.add_get("/api/v1/status/tsdb", tsdb_status)
        app.router.add_get("/api/v1/alerts", prom_alerts)
        return app

    def _build_loki_app(self) -> web.Application:
        app = web.Application()

        async def ready(_req: web.Request) -> web.Response:
            return web.Response(text="ready\n", status=200)

        async def push(req: web.Request) -> web.Response:
            org_id = req.headers.get("X-Scope-OrgID", "")
            ctype = req.headers.get("Content-Type", "").lower()
            cenc = req.headers.get("Content-Encoding", "").lower()
            raw = await req.read()

            if "application/json" in ctype and cenc != "snappy":
                doc = json.loads(raw.decode("utf-8"))
                for stream_obj in doc.get("streams", []):
                    labels = dict(stream_obj.get("stream", {}))
                    lines = [str(v[1]) for v in stream_obj.get("values", []) if len(v) >= 2]
                    self.loki_pushes.append(
                        RecordedLokiStream(
                            org_id=org_id,
                            encoding="json",
                            labels=labels,
                            lines=lines,
                        )
                    )
            else:
                raw_pb = snappy_decompress(raw)
                streams = parse_loki_push_request(raw_pb)
                for st in streams:
                    labels = parse_loki_label_selector(st.labels)
                    lines = [e.line for e in st.entries]
                    self.loki_pushes.append(
                        RecordedLokiStream(
                            org_id=org_id,
                            encoding="protobuf",
                            labels=labels,
                            lines=lines,
                        )
                    )
            return web.Response(status=204)

        app.router.add_get("/ready", ready)
        app.router.add_post("/loki/api/v1/push", push)
        return app

    def _build_grafana_app(self) -> web.Application:
        app = web.Application()
        state = self.grafana

        def _org_id(req: web.Request) -> int:
            return int(req.headers.get("X-Grafana-Org-Id", "1") or "1")

        async def health(_req: web.Request) -> web.Response:
            return web.json_response({"database": "ok", "version": "11.2.2"})

        async def login_page(_req: web.Request) -> web.Response:
            return web.Response(
                text="<!doctype html><html><title>Grafana</title><body>MSP Grafana</body></html>",
                content_type="text/html",
            )

        async def list_orgs(_req: web.Request) -> web.Response:
            return web.json_response(list(state.orgs.values()))

        async def get_org(req: web.Request) -> web.Response:
            oid = int(req.match_info["oid"])
            if oid not in state.orgs:
                return web.json_response({"message": "Org not found"}, status=404)
            return web.json_response(state.orgs[oid])

        async def get_org_by_name(req: web.Request) -> web.Response:
            name = req.match_info["name"]
            for org in state.orgs.values():
                if org["name"] == name:
                    return web.json_response(org)
            return web.json_response({"message": "Org not found"}, status=404)

        async def create_org(req: web.Request) -> web.Response:
            body = await req.json()
            oid = state.next_org_id
            state.next_org_id += 1
            state.orgs[oid] = {"id": oid, "name": body["name"]}
            state.datasources[oid] = {}
            state.folders[oid] = {}
            state.dashboards[oid] = {}
            state.org_members[oid] = {}
            return web.json_response({"orgId": oid, "message": "Organization created"})

        async def update_org(req: web.Request) -> web.Response:
            oid = int(req.match_info["oid"])
            body = await req.json()
            if oid not in state.orgs:
                return web.json_response({"message": "Org not found"}, status=404)
            state.orgs[oid]["name"] = body["name"]
            return web.json_response({"message": "Organization updated"})

        async def delete_org(req: web.Request) -> web.Response:
            oid = int(req.match_info["oid"])
            state.orgs.pop(oid, None)
            state.datasources.pop(oid, None)
            state.folders.pop(oid, None)
            state.dashboards.pop(oid, None)
            state.org_members.pop(oid, None)
            state.org_preferences.pop(oid, None)
            return web.json_response({"message": "Organization deleted"})

        async def get_org_preferences(req: web.Request) -> web.Response:
            oid = _org_id(req)
            return web.json_response(state.org_preferences.get(oid, {}))

        async def put_org_preferences(req: web.Request) -> web.Response:
            oid = _org_id(req)
            body = await req.json()
            prefs = state.org_preferences.setdefault(oid, {})
            if isinstance(body, dict):
                prefs.update(body)
            return web.json_response({"message": "Preferences updated"})

        async def get_ds_by_uid(req: web.Request) -> web.Response:
            oid = _org_id(req)
            uid = req.match_info["uid"]
            ds = state.datasources.get(oid, {}).get(uid)
            if ds is None:
                return web.json_response({"message": "Data source not found"}, status=404)
            return web.json_response(ds)

        async def create_ds(req: web.Request) -> web.Response:
            oid = _org_id(req)
            body = await req.json()
            ds_id = state.next_ds_id
            state.next_ds_id += 1
            stored = {**body, "id": ds_id, "orgId": oid}
            state.datasources.setdefault(oid, {})[body["uid"]] = stored
            return web.json_response({"id": ds_id, "datasource": stored})

        async def update_ds(req: web.Request) -> web.Response:
            oid = _org_id(req)
            ds_id = int(req.match_info["id"])
            body = await req.json()
            stored = {**body, "id": ds_id, "orgId": oid}
            state.datasources.setdefault(oid, {})[body["uid"]] = stored
            return web.json_response({"id": ds_id, "datasource": stored})

        async def get_folder(req: web.Request) -> web.Response:
            oid = _org_id(req)
            uid = req.match_info["uid"]
            folder = state.folders.get(oid, {}).get(uid)
            if folder is None:
                return web.json_response({"message": "Folder not found"}, status=404)
            return web.json_response(folder)

        async def create_folder(req: web.Request) -> web.Response:
            oid = _org_id(req)
            body = await req.json()
            state.folders.setdefault(oid, {})[body["uid"]] = body
            return web.json_response(body)

        async def upsert_dashboard(req: web.Request) -> web.Response:
            oid = _org_id(req)
            if oid == 1 and state.simulate_org1_file_provisioned:
                state.org1_provisioned_rejections += 1
                return web.json_response(
                    {"message": "Cannot save provisioned dashboard"},
                    status=400,
                )
            body = await req.json()
            dash = body["dashboard"]
            uid = str(dash.get("uid") or dash.get("title"))
            state.dashboards.setdefault(oid, {})[uid] = dash
            return web.json_response({"status": "success", "uid": uid})

        async def admin_reload_dashboards(_req: web.Request) -> web.Response:
            state.dashboard_reloads += 1
            return web.json_response({"message": "Dashboards config reloaded"})

        async def lookup_user(req: web.Request) -> web.Response:
            login = req.query.get("loginOrEmail", "").strip().lower()
            for u in state.users.values():
                if u["login"].lower() == login or str(u.get("email") or "").lower() == login:
                    return web.json_response(u)
            return web.json_response({"message": "User not found"}, status=404)

        async def get_user_by_id(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            if uid not in state.users:
                return web.json_response({"message": "User not found"}, status=404)
            return web.json_response(state.users[uid])

        async def admin_create_user(req: web.Request) -> web.Response:
            body = await req.json()
            uid = state.next_user_id
            state.next_user_id += 1
            user_rec = {
                "id": uid,
                "login": body["login"],
                "email": body.get("email", ""),
                "name": body.get("name", ""),
                "password": body.get("password", ""),
                "orgId": 1,
                "isDisabled": False,
                "isGrafanaAdmin": False,
            }
            state.users[uid] = user_rec
            # Faithfully simulate Grafana's auto_assign_org=true adding new users to Org 1
            state.org_members.setdefault(1, {})[uid] = "Viewer"
            if isinstance(body.get("OrgId"), int):
                state.org_members.setdefault(int(body["OrgId"]), {})[uid] = "Viewer"
            return web.json_response({"id": uid, "message": "User created"})

        async def update_user(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            body = await req.json()
            if uid in state.users:
                if "name" in body:
                    state.users[uid]["name"] = body["name"]
                if "email" in body:
                    state.users[uid]["email"] = body["email"]
            return web.json_response({"message": "User updated"})

        async def admin_delete_user(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            if uid not in state.users:
                return web.json_response({"message": "User not found"}, status=404)
            del state.users[uid]
            for members in state.org_members.values():
                members.pop(uid, None)
            state.deleted_user_ids.add(uid)
            return web.json_response({"message": "User deleted"})

        async def admin_reload_ldap(_req: web.Request) -> web.Response:
            state.ldap_reloads += 1
            return web.json_response({"message": "LDAP config reloaded"})

        async def admin_toggle_user(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            action = req.match_info["toggle"]
            if uid in state.users:
                state.users[uid]["isDisabled"] = action == "disable"
            return web.json_response({"message": "ok"})

        async def admin_set_password(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            body = await req.json()
            if uid in state.users:
                state.users[uid]["password"] = body.get("password", "")
            return web.json_response({"message": "Password updated"})

        async def get_org_users(req: web.Request) -> web.Response:
            oid = int(req.match_info["oid"])
            members = state.org_members.get(oid, {})
            out = [
                {
                    "orgId": oid,
                    "userId": uid,
                    "login": state.users[uid]["login"],
                    "role": role,
                }
                for uid, role in members.items()
                if uid in state.users
            ]
            return web.json_response(out)

        async def add_org_user(req: web.Request) -> web.Response:
            oid = int(req.match_info["oid"])
            body = await req.json()
            login = body["loginOrEmail"].strip().lower()
            user = next((u for u in state.users.values() if u["login"].lower() == login), None)
            if user is None:
                return web.json_response({"message": "User not found"}, status=404)
            state.org_members.setdefault(oid, {})[user["id"]] = body["role"]
            return web.json_response({"message": "User added to organization"})

        async def patch_org_user(req: web.Request) -> web.Response:
            oid = int(req.match_info["oid"])
            uid = int(req.match_info["uid"])
            body = await req.json()
            state.org_members.setdefault(oid, {})[uid] = body["role"]
            return web.json_response({"message": "Organization user updated"})

        async def delete_org_user(req: web.Request) -> web.Response:
            oid = int(req.match_info["oid"])
            uid = int(req.match_info["uid"])
            members = state.org_members.get(oid, {})
            if uid not in members:
                return web.json_response({"message": "User not in org"}, status=404)
            del members[uid]
            return web.json_response({"message": "User removed from organization"})

        async def switch_user_org(req: web.Request) -> web.Response:
            uid = int(req.match_info["uid"])
            oid = int(req.match_info["oid"])
            state.org_switch_calls.append((uid, oid))
            if uid in state.users:
                state.users[uid]["orgId"] = oid
            return web.json_response({"message": "Active organization changed"})

        async def datasource_proxy(req: web.Request) -> web.Response:
            state.ds_proxy_hits.append((req.method, req.path))
            return web.json_response(
                {
                    "status": "success",
                    "proxied_by_grafana": True,
                    "method": req.method,
                    "path": req.path,
                }
            )

        app.router.add_get("/api/health", health)
        app.router.add_route("*", "/api/datasources/proxy/{tail:.*}", datasource_proxy)
        app.router.add_get("/", login_page)
        app.router.add_get("/login", login_page)
        app.router.add_get("/api/org/preferences", get_org_preferences)
        app.router.add_put("/api/org/preferences", put_org_preferences)
        app.router.add_get("/api/orgs", list_orgs)
        app.router.add_post("/api/orgs", create_org)
        app.router.add_get("/api/orgs/name/{name}", get_org_by_name)
        app.router.add_get("/api/orgs/{oid:[0-9]+}", get_org)
        app.router.add_put("/api/orgs/{oid:[0-9]+}", update_org)
        app.router.add_delete("/api/orgs/{oid:[0-9]+}", delete_org)
        app.router.add_get("/api/orgs/{oid:[0-9]+}/users", get_org_users)
        app.router.add_post("/api/orgs/{oid:[0-9]+}/users", add_org_user)
        app.router.add_patch("/api/orgs/{oid:[0-9]+}/users/{uid:[0-9]+}", patch_org_user)
        app.router.add_delete("/api/orgs/{oid:[0-9]+}/users/{uid:[0-9]+}", delete_org_user)
        app.router.add_get("/api/datasources/uid/{uid}", get_ds_by_uid)
        app.router.add_post("/api/datasources", create_ds)
        app.router.add_put("/api/datasources/{id:[0-9]+}", update_ds)
        app.router.add_get("/api/folders/{uid}", get_folder)
        app.router.add_post("/api/folders", create_folder)
        app.router.add_post("/api/dashboards/db", upsert_dashboard)
        app.router.add_get("/api/users/lookup", lookup_user)
        app.router.add_get("/api/users/{uid:[0-9]+}", get_user_by_id)
        app.router.add_put("/api/users/{uid:[0-9]+}", update_user)
        app.router.add_post("/api/admin/users", admin_create_user)
        app.router.add_delete("/api/admin/users/{uid:[0-9]+}", admin_delete_user)
        app.router.add_post("/api/admin/users/{uid:[0-9]+}/{toggle:(?:enable|disable)}", admin_toggle_user)
        app.router.add_put("/api/admin/users/{uid:[0-9]+}/password", admin_set_password)
        app.router.add_post("/api/admin/provisioning/ldap/reload", admin_reload_ldap)
        app.router.add_post("/api/admin/provisioning/dashboards/reload", admin_reload_dashboards)
        app.router.add_post("/api/users/{uid:[0-9]+}/using/{oid:[0-9]+}", switch_user_org)
        return app

    def _build_am_app(self) -> web.Application:
        app = web.Application()
        seq = {"n": 0}

        async def reload_am(_req: web.Request) -> web.Response:
            self.am_reloads += 1
            return web.Response(status=200)

        async def receive_alerts(req: web.Request) -> web.Response:
            items = await req.json()
            if isinstance(items, list):
                self.am_alerts.extend(items)
            return web.json_response({"status": "success"})

        async def get_silences(_req: web.Request) -> web.Response:
            return web.json_response(list(self.am_silences.values()))

        async def post_silence(req: web.Request) -> web.Response:
            body = await req.json()
            seq["n"] += 1
            sid = body.get("id") or f"am-e2e-sil-{seq['n']:04d}"
            self.am_silences[sid] = {
                "id": sid,
                "status": {"state": "active"},
                "startsAt": body["startsAt"],
                "endsAt": body["endsAt"],
                "createdBy": body["createdBy"],
                "comment": body["comment"],
                "matchers": body["matchers"],
            }
            return web.json_response({"silenceID": sid})

        async def delete_silence(req: web.Request) -> web.Response:
            sid = req.match_info["sid"]
            if sid not in self.am_silences:
                return web.json_response({"message": "not found"}, status=404)
            self.am_silences[sid]["status"] = {"state": "expired"}
            return web.Response(status=200)

        app.router.add_post("/-/reload", reload_am)
        app.router.add_post("/api/v2/alerts", receive_alerts)
        app.router.add_get("/api/v2/silences", get_silences)
        app.router.add_post("/api/v2/silences", post_silence)
        app.router.add_delete("/api/v2/silence/{sid}", delete_silence)
        return app

    def _build_push_app(self) -> web.Application:
        app = web.Application()

        async def gotify_msg(req: web.Request) -> web.Response:
            body = await req.json()
            self.gotify_requests.append(
                {
                    "headers": dict(req.headers),
                    "json": body,
                }
            )
            return web.json_response({"id": 1}, status=200)

        async def ntfy_topic(req: web.Request) -> web.Response:
            raw = await req.text()
            self.ntfy_requests.append(
                {
                    "topic": req.match_info["topic"],
                    "headers": dict(req.headers),
                    "body": raw,
                }
            )
            return web.json_response({"id": "ntfy-msg-1"}, status=200)

        app.router.add_post("/message", gotify_msg)
        app.router.add_post("/{topic}", ntfy_topic)
        return app

    def _build_alloy_app(self) -> web.Application:
        app = web.Application()

        async def healthy(_req: web.Request) -> web.Response:
            return web.Response(text="All Alloy components are healthy.\n", status=200)

        async def reload_alloy(_req: web.Request) -> web.Response:
            self.alloy_reloads += 1
            return web.Response(status=200)

        async def pve_root(_req: web.Request) -> web.Response:
            return web.Response(text="PVE Exporter OK\n", status=200)

        app.router.add_get("/-/healthy", healthy)
        app.router.add_post("/-/reload", reload_alloy)
        app.router.add_get("/pve/", pve_root)
        return app


_FAKE_AGENT_INIT_PY = '''"""Subprocess-safe NS8 Python agent test double enforcing agent.dump_env()."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import ldapproxy, tasks


def _meta_path() -> Path:
    return Path(os.environ["E2E_FAKE_AGENT_META"])


def _env_file_path() -> Path:
    return Path(os.environ["E2E_FAKE_AGENT_ENV_FILE"])


def _load_meta() -> dict[str, Any]:
    p = _meta_path()
    if not p.exists():
        return {
            "persisted_env": {},
            "routes_in_use": [],
            "status": "running",
            "task_calls": [],
            "helper_calls": [],
            "systemctl_state": {},
            "dump_env_count": 0,
            "smarthost": {},
            "backups": {},
        }
    return json.loads(p.read_text(encoding="utf-8"))


def _save_meta(meta: dict[str, Any]) -> None:
    p = _meta_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes((json.dumps(meta, indent=2) + "\\n").encode("utf-8"))


_PENDING_ENV: dict[str, str] | None = None


def _ensure_pending() -> dict[str, str]:
    global _PENDING_ENV
    if _PENDING_ENV is None:
        meta = _load_meta()
        _PENDING_ENV = dict(meta.get("persisted_env", {}))
    return _PENDING_ENV


def set_env(key: str, value: Any) -> None:
    pending = _ensure_pending()
    sval = str(value)
    pending[str(key)] = sval
    os.environ[str(key)] = sval


def unset_env(key: str) -> None:
    pending = _ensure_pending()
    pending.pop(str(key), None)
    os.environ.pop(str(key), None)


def dump_env() -> None:
    pending = _ensure_pending()
    meta = _load_meta()
    meta["persisted_env"] = dict(pending)
    meta["dump_env_count"] = int(meta.get("dump_env_count", 0)) + 1
    _save_meta(meta)

    env_path = _env_file_path()
    env_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for k, v in sorted(pending.items()):
        if any(ch in v for ch in (" ", "\\"", "'", "#", "$", "\\\\")):
            esc = v.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
            lines.append(f'{k}="{esc}"')
        else:
            lines.append(f"{k}={v}")
    env_path.write_bytes(("\\n".join(lines) + "\\n").encode("utf-8"))


def read_envfile(path: str | Path) -> dict[str, str]:
    p = Path(path)
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", "\\""):
            v = v[1:-1]
        out[k.strip()] = v
    return out


def http_route_in_use(domain: str) -> bool:
    meta = _load_meta()
    in_use = {str(d).strip().lower() for d in meta.get("routes_in_use", [])}
    return domain.strip().lower() in in_use


def set_status(status: str) -> None:
    meta = _load_meta()
    meta["status"] = str(status)
    _save_meta(meta)


def resolve_agent_id(name: str) -> str:
    if name.startswith("traefik@"):
        return "module/traefik1"
    return f"module/{name}"


def run_helper(*args: Any, **_kwargs: Any) -> Any:
    str_args = [str(a) for a in args]
    meta = _load_meta()
    meta.setdefault("helper_calls", []).append(str_args)
    if len(str_args) >= 3 and str_args[0] == "systemctl" and str_args[1] == "--user":
        verb = str_args[2]
        units = [u for u in str_args[3:] if not u.startswith("-")]
        st = meta.setdefault("systemctl_state", {})
        for unit in units:
            if verb in ("enable", "start", "restart", "reload-or-restart"):
                st[unit] = "active"
            elif verb in ("disable", "stop"):
                st[unit] = "inactive"
    _save_meta(meta)

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    return _Completed()


class _FakeRedis:
    def __init__(self, meta: dict[str, Any]) -> None:
        self._meta = meta

    def hgetall(self, key: str) -> dict[str, str]:
        if key == "cluster/smarthost":
            return dict(self._meta.get("smarthost", {}))
        backups = self._meta.get("backups", {})
        if key in backups:
            return dict(backups[key])
        return {}

    def scan_iter(self, _pattern: str):
        return iter(self._meta.get("backups", {}).keys())


def redis_connect(*_args: Any, **_kwargs: Any) -> _FakeRedis:
    return _FakeRedis(_load_meta())
'''

_FAKE_AGENT_TASKS_PY = '''from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def run(agent_id: str, action: str, data: dict[str, Any] | None = None, **_kwargs: Any) -> dict[str, Any]:
    p = Path(os.environ["E2E_FAKE_AGENT_META"])
    meta = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    meta.setdefault("task_calls", []).append(
        {"agent_id": agent_id, "action": action, "data": data or {}}
    )
    p.write_bytes((json.dumps(meta, indent=2) + "\\n").encode("utf-8"))
    return {"exit_code": 0, "output": {"status": "ok"}, "error": ""}
'''

_FAKE_AGENT_LDAPPROXY_PY = '''from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class Ldapproxy:
    DEFAULT_DOMAINS: dict[str, dict[str, Any]] = {
        "ad.msp.example.com": {
            "host": "127.0.0.1",
            "port": "20001",
            "schema": "ad",
            "base_dn": "DC=ad,DC=msp,DC=example,DC=com",
            "bind_dn": "CN=ldapsvc,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
            "bind_password": "ldap-e2e-bind-secret",
            "tls": False,
        }
    }

    def _domains(self) -> dict[str, dict[str, Any]]:
        merged = {k: dict(v) for k, v in self.DEFAULT_DOMAINS.items()}
        meta_path = os.environ.get("E2E_FAKE_AGENT_META", "")
        if meta_path and Path(meta_path).is_file():
            meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))
            custom = meta.get("ldap_domains")
            if isinstance(custom, dict):
                for dom_name, dom_cfg in custom.items():
                    if isinstance(dom_cfg, dict):
                        merged[str(dom_name)] = dict(dom_cfg)
        return merged

    def get_domains_list(self) -> list[str]:
        return sorted(self._domains().keys())

    def get_domain(self, name: str) -> dict[str, Any]:
        domains = self._domains()
        if name not in domains:
            raise KeyError(f"Unknown LDAP domain: {name}")
        return dict(domains[name])
'''


def _install_fake_agent_pkg(pkg_root: Path) -> Path:
    agent_dir = pkg_root / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "__init__.py").write_bytes(_FAKE_AGENT_INIT_PY.encode("utf-8"))
    (agent_dir / "tasks.py").write_bytes(_FAKE_AGENT_TASKS_PY.encode("utf-8"))
    (agent_dir / "ldapproxy.py").write_bytes(_FAKE_AGENT_LDAPPROXY_PY.encode("utf-8"))
    return pkg_root


class NS8ModuleInstance:
    """Isolated NS8 rootless module home executing real imageroot scripts via subprocess."""

    def __init__(
        self,
        *,
        kind: str,
        install_dir: Path,
        module_id: str,
        tcp_port: int = 20080,
        backends: LiveObservabilityBackends | None = None,
    ) -> None:
        assert kind in ("hub", "collector")
        self.kind = kind
        self.install_dir = install_dir
        self.state_dir = install_dir / "state"
        self.config_dir = install_dir / "config"
        self.etc_dir = install_dir / "etc"
        self.volumes_dir = install_dir / "volumes"
        for d in (self.state_dir, self.config_dir, self.etc_dir, self.volumes_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.imageroot = HUB_IMAGEROOT if kind == "hub" else COLLECTOR_IMAGEROOT
        self.pypkg = HUB_PYPKG if kind == "hub" else COLLECTOR_PYPKG
        src_include = self.imageroot / "etc" / "state-include.conf"
        if src_include.is_file():
            shutil.copyfile(src_include, self.etc_dir / "state-include.conf")

        self.agent_pkg_root = _install_fake_agent_pkg(install_dir / ".fake_agent_pkg")
        self.meta_file = install_dir / ".fake_agent_meta.json"
        self.env_file = self.state_dir / "environment"
        self.backends = backends

        initial_env: dict[str, str] = {
            "MODULE_ID": module_id,
            "NODE_ID": "1",
            "AGENT_ID": f"module/{module_id}",
            "AGENT_STATE_DIR": str(self.state_dir),
            "AGENT_INSTALL_DIR": str(self.install_dir),
        }
        self.runtime_wiring_env: dict[str, str] = {}
        if kind == "hub":
            initial_env["TCP_PORT"] = str(tcp_port)
            self.runtime_wiring_env.update(
                {
                    "HUB_STATE_DIR": str(self.state_dir),
                    "STATE_DIR": str(self.state_dir),
                    "HUB_CONFIG_DIR": str(self.config_dir),
                    "HUB_ETC_DIR": str(self.etc_dir),
                    "HUB_AVAILABLE_RULES_DIR": str(REPO_ROOT / "shared" / "rules"),
                    "GRAFANA_DB_PATH": str(self.volumes_dir / "grafana-data" / "grafana.db"),
                    "ALERTMANAGER_DATA_DIR": str(self.volumes_dir / "alertmanager-data"),
                }
            )
            if backends is not None:
                self.runtime_wiring_env.update(
                    {
                        "PROMETHEUS_RELOAD_URL": f"http://127.0.0.1:{backends.prom_port}/-/reload",
                        "SNMP_RELOAD_URL": f"http://127.0.0.1:{backends.prom_port}/snmp/-/reload",
                        "ALERTMANAGER_URL": f"http://127.0.0.1:{backends.am_port}",
                        "GRAFANA_URL": f"http://127.0.0.1:{backends.grafana_port}",
                    }
                )
        else:
            self.runtime_wiring_env.update(
                {
                    "COLLECTOR_STATE_DIR": str(self.state_dir),
                    "HUB_PROBE_ALLOW_LOOPBACK": "1",
                }
            )
            if backends is not None:
                self.runtime_wiring_env.update(
                    {
                        "ALLOY_RELOAD_URL": f"http://127.0.0.1:{backends.alloy_port}/-/reload",
                        "ALLOY_HEALTH_URL": f"http://127.0.0.1:{backends.alloy_port}/-/healthy",
                        "PVE_EXPORTER_HEALTH_URL": f"http://127.0.0.1:{backends.alloy_port}/pve/",
                    }
                )

        meta = {
            "persisted_env": dict(initial_env),
            "routes_in_use": [],
            "status": "running",
            "task_calls": [],
            "helper_calls": [],
            "systemctl_state": {},
            "dump_env_count": 0,
            "smarthost": {
                "host": "127.0.0.1",
                "port": "587",
                "username": "alerts@msp.example.com",
                "password": "smarthost-smtp-secret",
                "encrypt_smtp": "starttls",
                "tls_verify": "1",
            },
            "backups": {},
        }
        self.meta_file.write_bytes((json.dumps(meta, indent=2) + "\n").encode("utf-8"))
        if not self.env_file.exists():
            lines = [f"{k}={v}" for k, v in sorted(initial_env.items())]
            self.env_file.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))

    def read_meta(self) -> dict[str, Any]:
        return json.loads(self.meta_file.read_text(encoding="utf-8"))

    def set_routes_in_use(self, domains: list[str]) -> None:
        meta = self.read_meta()
        meta["routes_in_use"] = list(domains)
        self.meta_file.write_bytes((json.dumps(meta, indent=2) + "\n").encode("utf-8"))

    def set_ldap_domain(self, domain: str, info: dict[str, Any]) -> None:
        meta = self.read_meta()
        meta.setdefault("ldap_domains", {})[str(domain)] = dict(info)
        self.meta_file.write_bytes((json.dumps(meta, indent=2) + "\n").encode("utf-8"))

    def _build_subprocess_env(
        self,
        *,
        extra_env: dict[str, str] | None = None,
        omit_env_keys: tuple[str, ...] = (),
    ) -> dict[str, str]:
        meta = self.read_meta()
        persisted = dict(meta.get("persisted_env", {}))

        # Re-read state/environment as systemd EnvironmentFile=%S/state/environment does
        if self.env_file.is_file():
            for raw_line in self.env_file.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                    v = v[1:-1]
                persisted[k.strip()] = v

        env = os.environ.copy()
        env.update(persisted)
        env.update(self.runtime_wiring_env)
        # Ensure instance-bound NS8 variables always reflect this module instance
        for inst_key in ("MODULE_ID", "NODE_ID", "TCP_PORT", "AGENT_ID", "AGENT_STATE_DIR", "AGENT_INSTALL_DIR"):
            if inst_key in meta.get("persisted_env", {}):
                env[inst_key] = meta["persisted_env"][inst_key]
        env["E2E_FAKE_AGENT_META"] = str(self.meta_file)
        env["E2E_FAKE_AGENT_ENV_FILE"] = str(self.env_file)
        env["PYTHONPATH"] = os.pathsep.join([str(self.agent_pkg_root), str(self.pypkg)])
        if extra_env:
            env.update(extra_env)
        for k in omit_env_keys:
            env.pop(k, None)
        return env

    async def run_script(
        self,
        rel_script_path: str,
        payload: dict[str, Any] | None = None,
        *,
        expect_rc: int = 0,
        validate_io: bool = True,
        cwd: Path | None = None,
        extra_env: dict[str, str] | None = None,
        omit_env_keys: tuple[str, ...] = (),
    ) -> tuple[int, str, str, Any]:
        """Execute an imageroot script as a real async subprocess and validate JSON schemas."""
        script_path = self.imageroot / rel_script_path
        assert script_path.is_file(), f"Missing script: {script_path}"

        parts = Path(rel_script_path).parts
        action_name = parts[1] if len(parts) >= 3 and parts[0] == "actions" else None
        schema_prefix = "hub" if self.kind == "hub" else "collector"

        if validate_io and action_name and payload is not None:
            in_schema = f"{schema_prefix}-{action_name}-input.json"
            if (SCHEMAS_DIR / in_schema).is_file():
                validate_schema(in_schema, payload)

        env = self._build_subprocess_env(extra_env=extra_env, omit_env_keys=omit_env_keys)
        stdin_bytes = (json.dumps(payload) if payload is not None else "{}").encode("utf-8")

        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(script_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd or self.state_dir),
            env=env,
        )
        out_bytes, err_bytes = await proc.communicate(stdin_bytes)
        rc = int(proc.returncode or 0)
        stdout_str = out_bytes.decode("utf-8", errors="replace")
        stderr_str = err_bytes.decode("utf-8", errors="replace")

        assert rc == expect_rc, (
            f"Script {self.kind}/{rel_script_path} exited with rc={rc} (expected {expect_rc}).\n"
            f"STDOUT:\n{stdout_str}\nSTDERR:\n{stderr_str}"
        )

        parsed_out: Any = None
        if stdout_str.strip():
            parsed_out = json.loads(stdout_str)
            if validate_io and rc == 0 and action_name:
                out_schema = f"{schema_prefix}-{action_name}-output.json"
                if (SCHEMAS_DIR / out_schema).is_file():
                    validate_schema(out_schema, parsed_out)

        return rc, stdout_str, stderr_str, parsed_out

    def copy_restic_snapshot_to(self, dest_install_dir: Path) -> None:
        """Simulate NS8 Restic backup+restore by copying ONLY entries in etc/state-include.conf."""
        include_file = self.etc_dir / "state-include.conf"
        assert include_file.is_file(), f"Missing {include_file}"

        for raw_line in include_file.read_text(encoding="utf-8").splitlines():
            entry = raw_line.strip().lstrip("/")
            if not entry or entry.startswith("#"):
                continue
            src = self.install_dir / entry
            dst = dest_install_dir / entry
            if src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            elif src.is_dir():
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)


_PROM_LINE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?)$"
)
_PROM_LABEL_PAIR_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


def parse_prom_textfile_to_timeseries(
    prom_text: str,
    *,
    extra_labels: dict[str, str],
    timestamp_ms: int = 1763676000000,
) -> list[TimeSeries]:
    """Parse Prometheus exposition text (e.g. ns8.prom) into WriteRequest TimeSeries objects."""
    series: list[TimeSeries] = []
    for raw_line in prom_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _PROM_LINE_RE.match(line)
        assert match is not None, f"Failed to parse Prometheus exposition line: {line!r}"
        metric_name, labels_blob, value_str = match.groups()
        labels: dict[str, str] = {"__name__": metric_name}
        if labels_blob:
            for lmatch in _PROM_LABEL_PAIR_RE.finditer(labels_blob):
                k, v = lmatch.groups()
                labels[k] = v.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        labels.update(extra_labels)
        sorted_pairs = sorted(labels.items(), key=lambda kv: kv[0])
        series.append(
            TimeSeries(
                labels=sorted_pairs,
                samples=[Sample(value=float(value_str), timestamp_ms=timestamp_ms)],
            )
        )
    return series


def build_ad_object_sid(rid: int) -> bytes:
    """Build a valid binary Windows/Samba4 objectSid ending with 32-bit little-endian `rid`."""
    header = bytes([1, 5, 0, 0, 0, 0, 0, 5])
    subs = struct.pack("<IIIII", 21, 11111111, 22222222, 33333333, rid)
    return header + subs


class LiveBERLDAPv3Server:
    """Real local TCP RFC 4511 ASN.1 BER LDAPv3 server for E2E NS8 AD/LDAP actions."""

    def __init__(
        self,
        *,
        expected_bind_dn: str = "",
        expected_bind_pw: str = "",
        entries: list[dict[str, Any]] | None = None,
        max_page_size: int = 2,
        emit_referral: bool = True,
    ) -> None:
        self.expected_bind_dn = expected_bind_dn
        self.expected_bind_pw = expected_bind_pw
        self.entries = list(entries or [])
        self.max_page_size = max_page_size
        self.emit_referral = emit_referral
        self.bind_count = 0
        self.unbind_count = 0
        self.recorded_filters: list[Any] = []
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.port = 0

    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        self._sock = srv
        self.port = int(srv.getsockname()[1])
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            worker.start()

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _recv_ber_msg(self, conn: socket.socket) -> bytes | None:
        hdr = self._recv_exact(conn, 2)
        if not hdr or hdr[0] != 0x30:
            return None
        first_len = hdr[1]
        if first_len < 0x80:
            body_len = first_len
            extra = b""
        else:
            n_oct = first_len & 0x7F
            extra_raw = self._recv_exact(conn, n_oct)
            if extra_raw is None:
                return None
            extra = extra_raw
            body_len = int.from_bytes(extra, "big", signed=False)
        body = self._recv_exact(conn, body_len)
        if body is None:
            return None
        return hdr + extra + body

    def _parse_ber_filter(self, buf: bytes, offset: int = 0) -> tuple[Any, int]:
        tag, body, next_pos = _decode_ber_tlv(buf, offset)
        if tag == 0xA0:
            items = []
            pos = 0
            while pos < len(body):
                sub, pos = self._parse_ber_filter(body, pos)
                items.append(sub)
            return ("and", items), next_pos
        if tag == 0xA1:
            items = []
            pos = 0
            while pos < len(body):
                sub, pos = self._parse_ber_filter(body, pos)
                items.append(sub)
            return ("or", items), next_pos
        if tag == 0xA2:
            sub, _ = self._parse_ber_filter(body, 0)
            return ("not", sub), next_pos
        if tag == 0xA3:
            _, attr_b, pos = _decode_ber_tlv(body, 0)
            _, val_b, _ = _decode_ber_tlv(body, pos)
            return ("eq", attr_b.decode("utf-8"), val_b.decode("utf-8", errors="replace")), next_pos
        if tag == 0x87:
            return ("present", body.decode("utf-8")), next_pos
        if tag == 0xA4:
            _, attr_b, pos = _decode_ber_tlv(body, 0)
            _, seq_b, _ = _decode_ber_tlv(body, pos)
            parts = []
            sp = 0
            while sp < len(seq_b):
                st, sb, sp = _decode_ber_tlv(seq_b, sp)
                parts.append((st, sb.decode("utf-8", errors="replace")))
            return ("substr", attr_b.decode("utf-8"), parts), next_pos
        if tag == 0xA9:
            rule = ""
            attr = ""
            val = ""
            pos = 0
            while pos < len(body):
                ft, fb, pos = _decode_ber_tlv(body, pos)
                if ft == 0x81:
                    rule = fb.decode("utf-8")
                elif ft == 0x82:
                    attr = fb.decode("utf-8")
                elif ft == 0x83:
                    val = fb.decode("utf-8", errors="replace")
            return ("ext", attr, rule, val), next_pos
        raise ValueError(f"Unsupported BER filter tag 0x{tag:02x}")

    def _get_entry_vals(self, entry: dict[str, Any], attr: str) -> list[str]:
        alow = attr.lower()
        if alow == "distinguishedname":
            return [entry["dn"]]
        for k, v in entry.get("attrs", {}).items():
            if k.lower() == alow:
                if isinstance(v, list):
                    return [str(x) for x in v if not isinstance(x, bytes)]
                if not isinstance(v, bytes):
                    return [str(v)]
        return []

    def _is_member_in_chain(self, group_dn: str, target_dn: str, visited: set[str]) -> bool:
        glow = group_dn.lower()
        if glow in visited:
            return False
        visited.add(glow)
        grp = next((e for e in self.entries if e["dn"].lower() == glow), None)
        if grp is None:
            return False
        members = [m.lower() for m in self._get_entry_vals(grp, "member")]
        if target_dn.lower() in members:
            return True
        for child_dn in members:
            if self._is_member_in_chain(child_dn, target_dn, visited):
                return True
        return False

    def _eval_filter(self, ast_node: Any, entry: dict[str, Any]) -> bool:
        kind = ast_node[0]
        if kind == "and":
            return all(self._eval_filter(c, entry) for c in ast_node[1])
        if kind == "or":
            return any(self._eval_filter(c, entry) for c in ast_node[1])
        if kind == "not":
            return not self._eval_filter(ast_node[1], entry)
        if kind == "present":
            return len(self._get_entry_vals(entry, ast_node[1])) > 0
        if kind == "eq":
            _, attr, val = ast_node
            vlow = val.lower()
            return any(item.lower() == vlow for item in self._get_entry_vals(entry, attr))
        if kind == "ext":
            _, attr, rule, val = ast_node
            if attr.lower() == "member" and rule == AD_IN_CHAIN_OID:
                return self._is_member_in_chain(entry["dn"], val, set())
            return False
        return False

    def _decode_req_paged_cookie(self, controls_body: bytes | None) -> tuple[bool, int, bytes]:
        if not controls_body:
            return False, 0, b""
        pos = 0
        while pos < len(controls_body):
            ct, cb, pos = _decode_ber_tlv(controls_body, pos)
            if ct != 0x30:
                continue
            _, oid_b, ip = _decode_ber_tlv(cb, 0)
            if oid_b.decode("ascii", errors="replace") != PAGED_RESULTS_OID:
                continue
            val_b = b""
            while ip < len(cb):
                ft, fb, ip = _decode_ber_tlv(cb, ip)
                if ft == 0x04:
                    val_b = fb
            _, sb, _ = _decode_ber_tlv(val_b, 0)
            _, sz_b, sp = _decode_ber_tlv(sb, 0)
            _, ck_b, _ = _decode_ber_tlv(sb, sp)
            return True, _decode_ber_int(sz_b), ck_b
        return False, 0, b""

    def _encode_entry_msg(self, msg_id: int, entry: dict[str, Any]) -> bytes:
        part_attrs: list[bytes] = []
        raw_attrs = dict(entry.get("attrs", {}))
        if not any(k.lower() == "distinguishedname" for k in raw_attrs):
            raw_attrs["distinguishedName"] = entry["dn"]
        for k, raw_v in raw_attrs.items():
            vals = raw_v if isinstance(raw_v, list) else [raw_v]
            enc_vals = [
                _ber_octet_string(v if isinstance(v, bytes) else str(v).encode("utf-8"))
                for v in vals
            ]
            part_attrs.append(
                _ber_seq(
                    [
                        _ber_octet_string(k.encode("utf-8")),
                        _ber_seq(enc_vals, tag=0x31),
                    ]
                )
            )
        op = _ber_seq(
            [
                _ber_octet_string(entry["dn"].encode("utf-8")),
                _ber_seq(part_attrs),
            ],
            tag=0x64,
        )
        return _ber_seq([_ber_int(msg_id), op])

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        try:
            while not self._stop.is_set():
                pkt = self._recv_ber_msg(conn)
                if pkt is None:
                    break
                _, msg_body, _ = _decode_ber_tlv(pkt, 0)
                _, id_b, pos = _decode_ber_tlv(msg_body, 0)
                msg_id = _decode_ber_int(id_b)
                op_tag, op_body, pos = _decode_ber_tlv(msg_body, pos)
                controls_body: bytes | None = None
                if pos < len(msg_body):
                    ct, cb, _ = _decode_ber_tlv(msg_body, pos)
                    if ct == 0xA0:
                        controls_body = cb

                if op_tag == 0x60:
                    self.bind_count += 1
                    _, ver_b, bp = _decode_ber_tlv(op_body, 0)
                    assert _decode_ber_int(ver_b) == 3
                    _, dn_b, bp = _decode_ber_tlv(op_body, bp)
                    _, pw_b, _ = _decode_ber_tlv(op_body, bp)
                    dn_s = dn_b.decode("utf-8")
                    pw_s = pw_b.decode("utf-8")
                    if self.expected_bind_dn and (
                        dn_s != self.expected_bind_dn or pw_s != self.expected_bind_pw
                    ):
                        res = _ber_seq(
                            [
                                _ber_int(49, tag=0x0A),
                                _ber_octet_string(b""),
                                _ber_octet_string(b"Invalid credentials"),
                            ],
                            tag=0x61,
                        )
                    else:
                        res = _ber_seq(
                            [
                                _ber_int(0, tag=0x0A),
                                _ber_octet_string(b""),
                                _ber_octet_string(b""),
                            ],
                            tag=0x61,
                        )
                    conn.sendall(_ber_seq([_ber_int(msg_id), res]))

                elif op_tag == 0x63:
                    _, _base_b, sp = _decode_ber_tlv(op_body, 0)
                    _, _scope_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _deref_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _size_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _time_b, sp = _decode_ber_tlv(op_body, sp)
                    _, _types_b, sp = _decode_ber_tlv(op_body, sp)
                    filter_ast, _ = self._parse_ber_filter(op_body, sp)
                    self.recorded_filters.append(filter_ast)

                    matched = [e for e in self.entries if self._eval_filter(filter_ast, e)]
                    has_pg, req_pg_size, cookie = self._decode_req_paged_cookie(controls_body)
                    start_idx = int(cookie.decode("ascii")) if cookie else 0
                    eff_page = min(req_pg_size or self.max_page_size, self.max_page_size)
                    sliced = matched[start_idx : start_idx + eff_page] if has_pg else matched
                    next_idx = start_idx + len(sliced)
                    next_cookie = (
                        str(next_idx).encode("ascii")
                        if (has_pg and next_idx < len(matched))
                        else b""
                    )

                    for item in sliced:
                        conn.sendall(self._encode_entry_msg(msg_id, item))

                    if self.emit_referral and start_idx == 0:
                        ref_op = _ber_seq(
                            [_ber_octet_string(b"ldap://ForestDnsZones.ad.bls-isp.net/DC=ad")],
                            tag=0x73,
                        )
                        conn.sendall(_ber_seq([_ber_int(msg_id), ref_op]))

                    done_op = _ber_seq(
                        [
                            _ber_int(0, tag=0x0A),
                            _ber_octet_string(b""),
                            _ber_octet_string(b""),
                        ],
                        tag=0x65,
                    )
                    done_items = [_ber_int(msg_id), done_op]
                    if has_pg:
                        cval = _ber_seq([_ber_int(len(matched)), _ber_octet_string(next_cookie)])
                        ctrl = _ber_seq(
                            [
                                _ber_octet_string(PAGED_RESULTS_OID.encode("ascii")),
                                _ber_bool(False),
                                _ber_octet_string(cval),
                            ]
                        )
                        done_items.append(_ber_seq([ctrl], tag=0xA0))
                    conn.sendall(_ber_seq(done_items))

                elif op_tag == 0x42:
                    self.unbind_count += 1
                    break
        finally:
            try:
                conn.close()
            except OSError:
                pass
