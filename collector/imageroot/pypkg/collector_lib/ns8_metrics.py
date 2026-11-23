"""Collects cluster-wide & local NS8 Restic backup, cgroups v2 pod/module, container, and systemd metrics.

Zero-Root Cluster-Wide & Local NS8 Discovery Architecture:
  Running in the host network namespace via `ns8-collector-textfile.timer` (without root privileges):
  1. Harvests Linux cgroups v2 (`0444` world-readable `/sys/fs/cgroup`) CPU, CPU throttling,
     memory working-set/RSS/swap/limits, OOM kills, block I/O bytes, and PID counts across ALL
     local rootless (`user.slice/user-<UID>.slice`) and rootful (`system.slice/<mid>.service`)
     NS8 modules plus per-container sub-units (`user@<UID>.service/{app,user}.slice/*.service`),
     combining `/etc/passwd`, NS8 Redis `module/*/environment`, and cgroup slice discovery.
  2. Harvests NS8 Core 3.22+'s node-wide `ns8_container_info`, `ns8_container_start_time_seconds`,
     and `node_systemd_unit_state` across ALL modules from NS8's local host `node_exporter`
     (`http://127.0.0.1:9100/metrics` or WireGuard VPN IP), synthesizing `ContainerRecord` entries
     from cgroup sub-units when `ns8-metrics` is not installed.
  3. Harvests cluster-wide Restic backup statuses/timestamps from the local NS8 Redis replica
     (`agent.redis_connect(use_replica=True)` or stdlib read-only RESP2 fallback on `REDIS_ADDRESS`
     / `127.0.0.1:6379`).
  4. Merges and falls back cleanly to JSON state files (`ns8-backups.json`, `ns8-containers.json`),
     local `podman ps -a`, and `systemctl --user`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from collector_lib.runtime import atomic_write_text

_PROM_SAMPLE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?)"
)
_PROM_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
_NS8_MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]*[0-9]+\Z")
_SYSTEM_SERVICE_RE = re.compile(r"^[a-z][a-z0-9_-]*\.service\Z")
_KNOWN_ROOTFUL_SERVICE_RE = re.compile(
    r"^(?P<mid>(?:samba|crowdsec|nethvoice(?:-[a-z0-9]+)?|ldapproxy|metrics|"
    r"nethsecurity(?:-[a-z0-9]+)?|openvpn|dnscrypt|ejabberd)[0-9]+)(?:-[a-z0-9_-]+)?\.service\Z"
)


@dataclass(frozen=True)
class BackupRecord:
    module_id: str
    succeeded: bool
    last_success_timestamp: int


@dataclass(frozen=True)
class ContainerRecord:
    module_id: str
    container: str
    image: str
    running: bool
    restarts: int


@dataclass(frozen=True)
class SystemdUnitRecord:
    name: str
    failed: bool


@dataclass(frozen=True)
class ModuleCgroupRecord:
    module_id: str
    module_type: str  # "rootless" | "rootful"
    up: bool
    cpu_seconds_total: float
    cpu_throttled_seconds_total: float
    memory_working_set_bytes: int
    memory_bytes: int
    memory_swap_bytes: int
    memory_limit_bytes: int
    oom_kills_total: int
    io_read_bytes_total: int
    io_write_bytes_total: int
    pids: int


@dataclass(frozen=True)
class PodUnitCgroupRecord:
    module_id: str
    unit: str
    cpu_seconds_total: float
    memory_working_set_bytes: int
    pids: int = 0
    memory_bytes: int = 0


@dataclass(frozen=True)
class _RawCgroupStats:
    cpu_seconds_total: float
    cpu_throttled_seconds_total: float
    memory_working_set_bytes: int
    memory_bytes: int
    memory_swap_bytes: int
    memory_limit_bytes: int
    oom_kills_total: int
    io_read_bytes_total: int
    io_write_bytes_total: int
    pids: int


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ARG002
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


def _prom_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _prom_unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")


def _fmt_float(value: float) -> str:
    clean = max(0.0, float(value))
    text = f"{clean:.6f}".rstrip("0").rstrip(".")
    return text or "0"


def format_ns8_prom(
    *,
    backups: list[BackupRecord],
    containers: list[ContainerRecord],
    systemd_units: list[SystemdUnitRecord],
    modules: list[ModuleCgroupRecord] | None = None,
    pod_units: list[PodUnitCgroupRecord] | None = None,
) -> str:
    """Format Prometheus textfile exposition matching shared/rules/ns8-cluster.yml & SPEC-telemetry-contract.md."""
    lines: list[str] = [
        "# HELP ns8_backup_status Status of the last NS8 Restic backup for a module (1=ok, 0=failed).",
        "# TYPE ns8_backup_status gauge",
    ]
    ordered_backups = sorted(backups, key=lambda x: x.module_id)
    for b in ordered_backups:
        mid = _prom_escape(b.module_id)
        val_i = 1 if b.succeeded else 0
        lines.append(f'ns8_backup_status{{module_id="{mid}"}} {val_i}')

    lines.extend(
        [
            "# HELP ns8_backup_failed Whether the last NS8 Restic backup failed for a module (1=failed, 0=ok).",
            "# TYPE ns8_backup_failed gauge",
        ]
    )
    for b in ordered_backups:
        mid = _prom_escape(b.module_id)
        val_i = 0 if b.succeeded else 1
        lines.append(f'ns8_backup_failed{{module_id="{mid}"}} {val_i}')

    lines.extend(
        [
            "# HELP ns8_backup_last_success_timestamp_seconds Unix timestamp of the last successful NS8 Restic backup.",
            "# TYPE ns8_backup_last_success_timestamp_seconds gauge",
        ]
    )
    for b in ordered_backups:
        mid = _prom_escape(b.module_id)
        ts_i = int(b.last_success_timestamp)
        lines.append(f'ns8_backup_last_success_timestamp_seconds{{module_id="{mid}"}} {ts_i}')

    lines.extend(
        [
            "# HELP ns8_container_info Metadata inventory of NS8 Podman containers.",
            "# TYPE ns8_container_info gauge",
        ]
    )
    ordered_ctrs = sorted(containers, key=lambda x: (x.module_id, x.container))
    for c in ordered_ctrs:
        mid = _prom_escape(c.module_id)
        cname = _prom_escape(c.container)
        cimg = _prom_escape(c.image)
        lines.append(
            f'ns8_container_info{{module_id="{mid}",container="{cname}",image="{cimg}"}} 1'
        )

    lines.extend(
        [
            "# HELP ns8_container_running Running state of NS8 Podman containers (1=running, 0=not running).",
            "# TYPE ns8_container_running gauge",
        ]
    )
    for c in ordered_ctrs:
        mid = _prom_escape(c.module_id)
        cname = _prom_escape(c.container)
        run_i = 1 if c.running else 0
        lines.append(f'ns8_container_running{{module_id="{mid}",container="{cname}"}} {run_i}')

    lines.extend(
        [
            "# HELP ns8_container_restarts_total Total restart count of NS8 Podman containers.",
            "# TYPE ns8_container_restarts_total counter",
        ]
    )
    for c in ordered_ctrs:
        mid = _prom_escape(c.module_id)
        cname = _prom_escape(c.container)
        restarts_i = max(0, int(c.restarts))
        lines.append(
            f'ns8_container_restarts_total{{module_id="{mid}",container="{cname}"}} {restarts_i}'
        )

    lines.extend(
        [
            "# HELP ns8_systemd_unit_failed Failed state of NS8 systemd user/system units (1=failed, 0=healthy).",
            "# TYPE ns8_systemd_unit_failed gauge",
        ]
    )
    for u in sorted(systemd_units, key=lambda x: x.name):
        uname = _prom_escape(u.name)
        fail_i = 1 if u.failed else 0
        lines.append(f'ns8_systemd_unit_failed{{name="{uname}"}} {fail_i}')

    # cgroups v2 per-module resource telemetry
    ordered_mods = sorted(modules or [], key=lambda x: (x.module_id, x.module_type))

    lines.extend(
        [
            "# HELP ns8_module_up Whether the NS8 module cgroup slice has active processes or memory (1=up, 0=down).",
            "# TYPE ns8_module_up gauge",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        up_i = 1 if m.up else 0
        lines.append(f'ns8_module_up{{module_id="{mid}",module_type="{mtype}"}} {up_i}')

    lines.extend(
        [
            "# HELP ns8_module_cpu_seconds_total Cumulative CPU time consumed by the NS8 module cgroup in seconds.",
            "# TYPE ns8_module_cpu_seconds_total counter",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        cpu_s = _fmt_float(m.cpu_seconds_total)
        lines.append(
            f'ns8_module_cpu_seconds_total{{module_id="{mid}",module_type="{mtype}"}} {cpu_s}'
        )

    lines.extend(
        [
            "# HELP ns8_module_cpu_throttled_seconds_total Cumulative throttled CPU time of the NS8 module cgroup in seconds.",
            "# TYPE ns8_module_cpu_throttled_seconds_total counter",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        throt_s = _fmt_float(m.cpu_throttled_seconds_total)
        lines.append(
            f'ns8_module_cpu_throttled_seconds_total{{module_id="{mid}",module_type="{mtype}"}} {throt_s}'
        )

    lines.extend(
        [
            "# HELP ns8_module_memory_working_set_bytes Working-set memory (memory.current - inactive_file) of the NS8 module in bytes.",
            "# TYPE ns8_module_memory_working_set_bytes gauge",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        ws_b = max(0, int(m.memory_working_set_bytes))
        lines.append(
            f'ns8_module_memory_working_set_bytes{{module_id="{mid}",module_type="{mtype}"}} {ws_b}'
        )

    lines.extend(
        [
            "# HELP ns8_module_memory_bytes Total cgroup memory.current of the NS8 module in bytes.",
            "# TYPE ns8_module_memory_bytes gauge",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        mem_b = max(0, int(m.memory_bytes))
        lines.append(f'ns8_module_memory_bytes{{module_id="{mid}",module_type="{mtype}"}} {mem_b}')

    lines.extend(
        [
            "# HELP ns8_module_memory_swap_bytes Current swap usage (memory.swap.current) of the NS8 module in bytes.",
            "# TYPE ns8_module_memory_swap_bytes gauge",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        swap_b = max(0, int(m.memory_swap_bytes))
        lines.append(
            f'ns8_module_memory_swap_bytes{{module_id="{mid}",module_type="{mtype}"}} {swap_b}'
        )

    lines.extend(
        [
            "# HELP ns8_module_memory_limit_bytes Configured memory.max limit of the NS8 module in bytes (0=unlimited).",
            "# TYPE ns8_module_memory_limit_bytes gauge",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        lim_b = max(0, int(m.memory_limit_bytes))
        lines.append(
            f'ns8_module_memory_limit_bytes{{module_id="{mid}",module_type="{mtype}"}} {lim_b}'
        )

    lines.extend(
        [
            "# HELP ns8_module_oom_kills_total Total OOM kills recorded in memory.events for the NS8 module.",
            "# TYPE ns8_module_oom_kills_total counter",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        oom_i = max(0, int(m.oom_kills_total))
        lines.append(
            f'ns8_module_oom_kills_total{{module_id="{mid}",module_type="{mtype}"}} {oom_i}'
        )

    lines.extend(
        [
            "# HELP ns8_module_io_read_bytes_total Cumulative block I/O bytes read by the NS8 module.",
            "# TYPE ns8_module_io_read_bytes_total counter",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        ior_b = max(0, int(m.io_read_bytes_total))
        lines.append(
            f'ns8_module_io_read_bytes_total{{module_id="{mid}",module_type="{mtype}"}} {ior_b}'
        )

    lines.extend(
        [
            "# HELP ns8_module_io_write_bytes_total Cumulative block I/O bytes written by the NS8 module.",
            "# TYPE ns8_module_io_write_bytes_total counter",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        iow_b = max(0, int(m.io_write_bytes_total))
        lines.append(
            f'ns8_module_io_write_bytes_total{{module_id="{mid}",module_type="{mtype}"}} {iow_b}'
        )

    lines.extend(
        [
            "# HELP ns8_module_pids Current process/thread count (pids.current) in the NS8 module cgroup.",
            "# TYPE ns8_module_pids gauge",
        ]
    )
    for m in ordered_mods:
        mid = _prom_escape(m.module_id)
        mtype = _prom_escape(m.module_type)
        pids_i = max(0, int(m.pids))
        lines.append(f'ns8_module_pids{{module_id="{mid}",module_type="{mtype}"}} {pids_i}')

    # cgroups v2 per-pod sub-unit breakdown
    ordered_units = sorted(pod_units or [], key=lambda x: (x.module_id, x.unit))

    lines.extend(
        [
            "# HELP ns8_pod_unit_cpu_seconds_total Cumulative CPU time consumed by a systemd sub-unit inside an NS8 module pod.",
            "# TYPE ns8_pod_unit_cpu_seconds_total counter",
        ]
    )
    for pu in ordered_units:
        mid = _prom_escape(pu.module_id)
        uname = _prom_escape(pu.unit)
        cpu_s = _fmt_float(pu.cpu_seconds_total)
        lines.append(f'ns8_pod_unit_cpu_seconds_total{{module_id="{mid}",unit="{uname}"}} {cpu_s}')

    lines.extend(
        [
            "# HELP ns8_pod_unit_memory_working_set_bytes Working-set memory of a systemd sub-unit inside an NS8 module pod in bytes.",
            "# TYPE ns8_pod_unit_memory_working_set_bytes gauge",
        ]
    )
    for pu in ordered_units:
        mid = _prom_escape(pu.module_id)
        uname = _prom_escape(pu.unit)
        ws_b = max(0, int(pu.memory_working_set_bytes))
        lines.append(
            f'ns8_pod_unit_memory_working_set_bytes{{module_id="{mid}",unit="{uname}"}} {ws_b}'
        )

    return "\n".join(lines) + "\n"


def write_ns8_prom_atomic(output_path: Path, prom_text: str) -> None:
    atomic_write_text(output_path, prom_text, mode=0o644)


# ---------------------------------------------------------------------------
# Pure-Stdlib Read-Only RESP2 Client (for local NS8 Redis replica fallback)
# ---------------------------------------------------------------------------


class _RespSocket:
    """Minimal read-only RESP2 client bounded to local loopback NS8 Redis."""

    def __init__(self, host: str, port: int, timeout: float = 1.5) -> None:
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)
        self._fp = self._sock.makefile("rb")

    def close(self) -> None:
        try:
            self._fp.close()
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> _RespSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def execute(self, *args: str) -> Any:
        parts = [f"*{len(args)}\r\n".encode("ascii")]
        for arg in args:
            raw = str(arg).encode("utf-8")
            parts.append(f"${len(raw)}\r\n".encode("ascii") + raw + b"\r\n")
        self._sock.sendall(b"".join(parts))
        return self._read_reply()

    def _read_reply(self) -> Any:
        line = self._fp.readline(65536)
        if not line:
            raise OSError("Unexpected EOF from Redis")
        prefix = line[:1]
        payload = line[1:].rstrip(b"\r\n")

        if prefix == b"+":
            return payload.decode("utf-8", errors="replace")
        if prefix == b"-":
            raise RuntimeError(payload.decode("utf-8", errors="replace"))
        if prefix == b":":
            return int(payload)
        if prefix == b"$":
            length = int(payload)
            if length < 0:
                return None
            data = self._fp.read(length)
            self._fp.read(2)  # trailing \r\n
            return data.decode("utf-8", errors="replace")
        if prefix == b"*":
            count = int(payload)
            if count < 0:
                return None
            return [self._read_reply() for _ in range(count)]
        raise ValueError(f"Unknown RESP prefix: {prefix!r}")


def _parse_loopback_redis_endpoint() -> tuple[str, int] | None:
    raw_addr = os.environ.get("REDIS_ADDRESS", "127.0.0.1:6379").strip()
    if not raw_addr:
        return None
    if raw_addr.startswith("redis://"):
        parsed = urllib.parse.urlparse(raw_addr)
        host = parsed.hostname or ""
        port = parsed.port or 6379
    elif ":" in raw_addr:
        host, port_s = raw_addr.rsplit(":", 1)
        host = host.strip("[]")
        if not port_s.isdigit():
            return None
        port = int(port_s)
    else:
        host, port = raw_addr, 6379

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        if host.lower() == "localhost":
            return ("127.0.0.1", port)
        return None

    if not ip_obj.is_loopback or not (1 <= port <= 65535):
        return None
    return (str(ip_obj), port)


def _parse_backup_hash(mid: str, mapping: dict[str, str]) -> BackupRecord | None:
    if not mid or not mapping:
        return None
    raw_status = str(
        mapping.get("status")
        or mapping.get("result")
        or ("0" if mapping.get("exit_code") == "0" else mapping.get("exit_code", "ok"))
    ).strip().lower()
    failed_flag = str(mapping.get("failed") or mapping.get("error_count") or "0").strip().lower()
    succeeded = (
        raw_status in ("ok", "success", "succeeded", "true", "0", "completed")
        and failed_flag in ("0", "false", "")
    )
    if raw_status in ("failed", "error", "false"):
        succeeded = False
    elif raw_status == "1" and "status" in mapping:
        succeeded = True

    ts_raw = (
        mapping.get("last_success")
        or mapping.get("last_success_timestamp")
        or mapping.get("completed")
        or mapping.get("end_time")
        or mapping.get("timestamp")
        or "0"
    )
    try:
        ts_val = int(float(ts_raw))
    except (ValueError, TypeError):
        ts_val = 0
    return BackupRecord(module_id=mid, succeeded=succeeded, last_success_timestamp=max(0, ts_val))


def _harvest_redis_state() -> tuple[dict[str, BackupRecord], str, set[str]]:
    """Query NS8 Redis replica for backups, WireGuard IP, and local-node NS8 modules."""
    records: dict[str, BackupRecord] = {}
    local_modules: set[str] = set()
    vpn_ip = ""
    node_id = os.environ.get("NODE_ID", "1").strip() or "1"

    # Path A: NS8 agent.redis_connect(use_replica=True)
    try:
        import agent  # type: ignore[import-not-found]

        try:
            rdb = agent.redis_connect(use_replica=True)
        except TypeError:
            rdb = agent.redis_connect()

        try:
            raw_vpn = rdb.hget(f"node/{node_id}/vpn", "ip_address")
            if raw_vpn:
                vpn_ip = (
                    raw_vpn.decode("utf-8", errors="ignore")
                    if isinstance(raw_vpn, bytes)
                    else str(raw_vpn)
                )
        except Exception:
            pass

        for key in rdb.scan_iter("*backup*"):
            key_str = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else str(key)
            parts = key_str.split("/")
            if len(parts) >= 3 and parts[0] == "module" and "backup" in "/".join(parts[2:]).lower():
                mid = parts[1]
                data = rdb.hgetall(key)
                decoded = {
                    (k.decode() if isinstance(k, bytes) else str(k)): (
                        v.decode() if isinstance(v, bytes) else str(v)
                    )
                    for k, v in data.items()
                }
                rec = _parse_backup_hash(mid, decoded)
                if rec is not None:
                    records[mid] = rec

        for key in rdb.scan_iter("module/*/environment"):
            key_str = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else str(key)
            parts = key_str.split("/")
            if len(parts) == 3 and parts[0] == "module" and parts[2] == "environment":
                mid = parts[1]
                if not _NS8_MODULE_ID_RE.match(mid):
                    continue
                data = rdb.hgetall(key)
                decoded = {
                    (k.decode() if isinstance(k, bytes) else str(k)): (
                        v.decode() if isinstance(v, bytes) else str(v)
                    )
                    for k, v in data.items()
                }
                if str(decoded.get("NODE_ID") or "").strip() == node_id:
                    local_modules.add(mid)

        if records or local_modules or vpn_ip:
            return records, vpn_ip.strip(), local_modules
    except Exception:
        pass

    # Path B: Pure-stdlib read-only RESP2 client against local loopback Redis replica
    endpoint = _parse_loopback_redis_endpoint()
    if endpoint is None:
        return records, vpn_ip, local_modules

    # Only probe default 6379 automatically on Linux or when REDIS_ADDRESS is explicitly set
    if os.name == "nt" and "REDIS_ADDRESS" not in os.environ:
        return records, vpn_ip, local_modules

    host, port = endpoint
    redis_user = os.environ.get("REDIS_USER", "").strip()
    redis_pw = os.environ.get("REDIS_PASSWORD", "").strip()

    try:
        with _RespSocket(host, port, timeout=1.5) as client:
            if redis_pw:
                if redis_user:
                    client.execute("AUTH", redis_user, redis_pw)
                else:
                    client.execute("AUTH", redis_pw)

            try:
                vpn_hash = client.execute("HGETALL", f"node/{node_id}/vpn")
                if isinstance(vpn_hash, list) and len(vpn_hash) >= 2:
                    vmap = dict(zip(vpn_hash[0::2], vpn_hash[1::2]))
                    vpn_ip = str(vmap.get("ip_address") or "").strip()
            except Exception:
                pass

            seen_keys: set[str] = set()
            for match_pattern in ("*backup*", "module/*/environment"):
                cursor = "0"
                for _ in range(50):
                    scan_res = client.execute("SCAN", cursor, "MATCH", match_pattern, "COUNT", "200")
                    if not isinstance(scan_res, list) or len(scan_res) != 2:
                        break
                    cursor = str(scan_res[0])
                    keys = scan_res[1] if isinstance(scan_res[1], list) else []
                    for raw_key in keys:
                        key_str = str(raw_key)
                        if key_str in seen_keys:
                            continue
                        seen_keys.add(key_str)
                        parts = key_str.split("/")
                        if len(parts) < 3 or parts[0] != "module":
                            continue
                        mid = parts[1]
                        tail = "/".join(parts[2:]).lower()
                        is_env_key = len(parts) == 3 and parts[2] == "environment"
                        is_backup_key = "backup" in tail
                        if not is_env_key and not is_backup_key:
                            continue
                        ktype = str(client.execute("TYPE", key_str)).lower()
                        if ktype != "hash":
                            continue
                        flat = client.execute("HGETALL", key_str)
                        if not isinstance(flat, list):
                            continue
                        decoded = dict(zip(flat[0::2], flat[1::2]))
                        if is_env_key:
                            if (
                                _NS8_MODULE_ID_RE.match(mid)
                                and str(decoded.get("NODE_ID") or "").strip() == node_id
                            ):
                                local_modules.add(mid)
                        elif is_backup_key:
                            rec = _parse_backup_hash(mid, decoded)
                            if rec is not None:
                                records[mid] = rec
                    if cursor == "0":
                        break
    except Exception:
        pass

    return records, vpn_ip, local_modules


def _harvest_redis_backups_and_vpn() -> tuple[dict[str, BackupRecord], str]:
    """Backward-compatible wrapper returning (backup_records, vpn_ip)."""
    records, vpn_ip, _ = _harvest_redis_state()
    return records, vpn_ip


# ---------------------------------------------------------------------------
# Zero-Root Linux cgroups v2 NS8 Pod & Module Harvester
# ---------------------------------------------------------------------------


def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _parse_kv_ints(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for raw_line in text.splitlines():
        parts = raw_line.strip().split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return out


def _read_uint_file(path: Path) -> int:
    raw = _read_text_safe(path).strip()
    if not raw:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _read_memory_limit_bytes(path: Path) -> int:
    raw = _read_text_safe(path).strip()
    if not raw or raw == "max":
        return 0
    if raw.isdigit():
        return max(0, int(raw))
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _read_io_stat_bytes(path: Path) -> tuple[int, int]:
    rbytes_total = 0
    wbytes_total = 0
    for raw_line in _read_text_safe(path).splitlines():
        for token in raw_line.strip().split():
            if token.startswith("rbytes="):
                val_s = token.split("=", 1)[1]
                if val_s.isdigit():
                    rbytes_total += int(val_s)
            elif token.startswith("wbytes="):
                val_s = token.split("=", 1)[1]
                if val_s.isdigit():
                    wbytes_total += int(val_s)
    return rbytes_total, wbytes_total


def _read_cgroup_dir_metrics(cg_dir: Path) -> _RawCgroupStats:
    if not cg_dir.is_dir():
        return _RawCgroupStats(
            cpu_seconds_total=0.0,
            cpu_throttled_seconds_total=0.0,
            memory_working_set_bytes=0,
            memory_bytes=0,
            memory_swap_bytes=0,
            memory_limit_bytes=0,
            oom_kills_total=0,
            io_read_bytes_total=0,
            io_write_bytes_total=0,
            pids=0,
        )

    cpu_kv = _parse_kv_ints(_read_text_safe(cg_dir / "cpu.stat"))
    cpu_seconds = max(0.0, cpu_kv.get("usage_usec", 0) / 1_000_000.0)
    throttled_seconds = max(0.0, cpu_kv.get("throttled_usec", 0) / 1_000_000.0)

    mem_current = _read_uint_file(cg_dir / "memory.current")
    mem_stat_kv = _parse_kv_ints(_read_text_safe(cg_dir / "memory.stat"))
    inactive_file = max(0, mem_stat_kv.get("inactive_file", 0))
    mem_working_set = max(0, mem_current - inactive_file)

    mem_swap = _read_uint_file(cg_dir / "memory.swap.current")
    mem_limit = _read_memory_limit_bytes(cg_dir / "memory.max")

    mem_events_kv = _parse_kv_ints(_read_text_safe(cg_dir / "memory.events"))
    oom_kills = max(0, mem_events_kv.get("oom_kill", 0))

    pids = _read_uint_file(cg_dir / "pids.current")
    io_r, io_w = _read_io_stat_bytes(cg_dir / "io.stat")

    return _RawCgroupStats(
        cpu_seconds_total=cpu_seconds,
        cpu_throttled_seconds_total=throttled_seconds,
        memory_working_set_bytes=mem_working_set,
        memory_bytes=mem_current,
        memory_swap_bytes=mem_swap,
        memory_limit_bytes=mem_limit,
        oom_kills_total=oom_kills,
        io_read_bytes_total=io_r,
        io_write_bytes_total=io_w,
        pids=pids,
    )


def _parse_ns8_passwd_users(passwd_file: Path | None) -> dict[str, int]:
    """Return {module_id: uid} for rootless NS8 module accounts in /etc/passwd."""
    users: dict[str, int] = {}
    if passwd_file is None or not passwd_file.is_file():
        return users

    for raw_line in _read_text_safe(passwd_file).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 6:
            continue
        username = parts[0].strip()
        uid_s = parts[2].strip()
        home_dir = parts[5].strip().rstrip("/")
        if not _NS8_MODULE_ID_RE.match(username):
            continue
        try:
            uid = int(uid_s)
        except ValueError:
            continue
        if uid < 1000 or uid == 65534:
            continue
        if home_dir != f"/home/{username}":
            continue
        users[username] = uid
    return users


def _is_ignored_user_subunit(service_filename: str) -> bool:
    name = service_filename.strip()
    if not name.endswith(".service"):
        return True
    if name in (
        "dbus.service",
        "dbus-broker.service",
        "init.scope",
        "ns8-collector-textfile.service",
        "hub-ns8-metrics.service",
    ):
        return True
    if name.startswith("systemd-") or name.startswith("podman-pause"):
        return True
    return False


def harvest_ns8_cgroups_v2(
    *,
    cgroup_root: Path | None = None,
    passwd_path: Path | None = None,
    redis_local_modules: set[str] | None = None,
) -> tuple[list[ModuleCgroupRecord], list[PodUnitCgroupRecord]]:
    """Discover local rootless & rootful NS8 modules and read cgroups v2 telemetry without root."""
    env_cg = os.environ.get("NS8_CGROUP_ROOT", "").strip()
    env_pw = os.environ.get("NS8_PASSWD_FILE", "").strip()

    if (
        os.name == "nt"
        and cgroup_root is None
        and not env_cg
        and passwd_path is None
        and not env_pw
    ):
        return [], []

    resolved_cgroup = (
        cgroup_root
        if cgroup_root is not None
        else Path(env_cg if env_cg else "/sys/fs/cgroup")
    )
    resolved_passwd: Path | None
    if passwd_path is not None:
        resolved_passwd = passwd_path
    elif env_pw:
        resolved_passwd = Path(env_pw)
    elif os.name != "nt":
        resolved_passwd = Path("/etc/passwd")
    else:
        resolved_passwd = None

    passwd_users = _parse_ns8_passwd_users(resolved_passwd)
    modules_out: list[ModuleCgroupRecord] = []
    pod_units_out: list[PodUnitCgroupRecord] = []

    # 1. Rootless NS8 modules (/sys/fs/cgroup/user.slice/user-<UID>.slice)
    for mid, uid in sorted(passwd_users.items()):
        slice_dir = resolved_cgroup / "user.slice" / f"user-{uid}.slice"
        stats = _read_cgroup_dir_metrics(slice_dir)
        modules_out.append(
            ModuleCgroupRecord(
                module_id=mid,
                module_type="rootless",
                up=(stats.pids > 0 or stats.memory_bytes > 0),
                cpu_seconds_total=stats.cpu_seconds_total,
                cpu_throttled_seconds_total=stats.cpu_throttled_seconds_total,
                memory_working_set_bytes=stats.memory_working_set_bytes,
                memory_bytes=stats.memory_bytes,
                memory_swap_bytes=stats.memory_swap_bytes,
                memory_limit_bytes=stats.memory_limit_bytes,
                oom_kills_total=stats.oom_kills_total,
                io_read_bytes_total=stats.io_read_bytes_total,
                io_write_bytes_total=stats.io_write_bytes_total,
                pids=stats.pids,
            )
        )

        # Inspect per-container systemd sub-units under user@<UID>.service/{app,user}.slice/*.service
        user_mgr_dir = slice_dir / f"user@{uid}.service"
        seen_subunits: dict[str, PodUnitCgroupRecord] = {}
        for sub_slice_name in ("app.slice", "user.slice"):
            sub_slice_dir = user_mgr_dir / sub_slice_name
            if not sub_slice_dir.is_dir():
                continue
            try:
                entries = sorted(sub_slice_dir.iterdir(), key=lambda p: p.name)
            except OSError:
                continue
            for svc_dir in entries:
                if not svc_dir.is_dir() or _is_ignored_user_subunit(svc_dir.name):
                    continue
                unit_stem = svc_dir.name[:-8]
                if not unit_stem or unit_stem in seen_subunits:
                    continue
                ustats = _read_cgroup_dir_metrics(svc_dir)
                seen_subunits[unit_stem] = PodUnitCgroupRecord(
                    module_id=mid,
                    unit=unit_stem,
                    cpu_seconds_total=ustats.cpu_seconds_total,
                    memory_working_set_bytes=ustats.memory_working_set_bytes,
                    pids=ustats.pids,
                    memory_bytes=ustats.memory_bytes,
                )
        pod_units_out.extend(seen_subunits.values())

    # 2. Rootful NS8 modules (/sys/fs/cgroup/system.slice/<mid>.service & <mid>-*.service)
    known_rootful = {
        m
        for m in (redis_local_modules or set())
        if _NS8_MODULE_ID_RE.match(m) and m not in passwd_users
    }
    ordered_known_rootful = sorted(known_rootful, key=lambda x: (-len(x), x))
    rootful_dirs: dict[str, list[Path]] = {m: [] for m in known_rootful}

    system_slice = resolved_cgroup / "system.slice"
    if system_slice.is_dir():
        try:
            sys_entries = sorted(system_slice.iterdir(), key=lambda p: p.name)
        except OSError:
            sys_entries = []

        for svc_dir in sys_entries:
            if not svc_dir.is_dir() or not _SYSTEM_SERVICE_RE.match(svc_dir.name):
                continue
            stem = svc_dir.name[:-8]
            matched_mid = ""
            for candidate_mid in ordered_known_rootful:
                if stem == candidate_mid or stem.startswith(f"{candidate_mid}-"):
                    matched_mid = candidate_mid
                    break
            if not matched_mid:
                m_known = _KNOWN_ROOTFUL_SERVICE_RE.match(svc_dir.name)
                if m_known:
                    cand = m_known.group("mid")
                    if cand not in passwd_users:
                        matched_mid = cand
            if matched_mid:
                rootful_dirs.setdefault(matched_mid, []).append(svc_dir)

    for mid in sorted(rootful_dirs):
        unit_dirs = rootful_dirs[mid]
        cpu_total = 0.0
        throt_total = 0.0
        ws_total = 0
        mem_total = 0
        swap_total = 0
        finite_limits: list[int] = []
        oom_total = 0
        io_r_total = 0
        io_w_total = 0
        pids_total = 0

        for svc_dir in unit_dirs:
            ustats = _read_cgroup_dir_metrics(svc_dir)
            cpu_total += ustats.cpu_seconds_total
            throt_total += ustats.cpu_throttled_seconds_total
            ws_total += ustats.memory_working_set_bytes
            mem_total += ustats.memory_bytes
            swap_total += ustats.memory_swap_bytes
            if ustats.memory_limit_bytes > 0:
                finite_limits.append(ustats.memory_limit_bytes)
            oom_total += ustats.oom_kills_total
            io_r_total += ustats.io_read_bytes_total
            io_w_total += ustats.io_write_bytes_total
            pids_total += ustats.pids

            unit_stem = svc_dir.name[:-8]
            if unit_stem:
                pod_units_out.append(
                    PodUnitCgroupRecord(
                        module_id=mid,
                        unit=unit_stem,
                        cpu_seconds_total=ustats.cpu_seconds_total,
                        memory_working_set_bytes=ustats.memory_working_set_bytes,
                        pids=ustats.pids,
                        memory_bytes=ustats.memory_bytes,
                    )
                )

        modules_out.append(
            ModuleCgroupRecord(
                module_id=mid,
                module_type="rootful",
                up=(pids_total > 0 or mem_total > 0),
                cpu_seconds_total=cpu_total,
                cpu_throttled_seconds_total=throt_total,
                memory_working_set_bytes=ws_total,
                memory_bytes=mem_total,
                memory_swap_bytes=swap_total,
                memory_limit_bytes=max(finite_limits) if finite_limits else 0,
                oom_kills_total=oom_total,
                io_read_bytes_total=io_r_total,
                io_write_bytes_total=io_w_total,
                pids=pids_total,
            )
        )

    return modules_out, pod_units_out


# ---------------------------------------------------------------------------
# NS8 Core Local Host node_exporter Harvester (Zero-Root Cluster Visibility)
# ---------------------------------------------------------------------------


def _validate_node_exporter_url(url: str) -> bool:
    """Allow ONLY loopback or private WireGuard/RFC1918 node_exporter endpoints (never public/metadata)."""
    clean = (url or "").strip()
    if not clean or any(ch.isspace() or ord(ch) < 0x21 for ch in clean):
        return False
    try:
        parsed = urllib.parse.urlparse(clean)
        port = parsed.port or 80
    except ValueError:
        return False

    if parsed.scheme != "http" or not parsed.hostname or not (1 <= port <= 65535):
        return False

    host = parsed.hostname.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False

    if ip_obj.is_unspecified or ip_obj.is_link_local or ip_obj.is_multicast:
        return False
    return bool(ip_obj.is_loopback or ip_obj.is_private)


def parse_ns8_node_exporter_metrics(
    prom_text: str,
) -> tuple[list[ContainerRecord], list[SystemdUnitRecord]]:
    """Extract cluster-wide NS8 module containers and failed systemd units from node_exporter output."""
    info_entries: dict[tuple[str, str], dict[str, str]] = {}
    running_map: dict[tuple[str, str], bool] = {}
    start_time_map: dict[tuple[str, str], float] = {}
    restarts_map: dict[tuple[str, str], int] = {}
    unit_active_map: dict[str, bool] = {}
    failed_units: dict[str, SystemdUnitRecord] = {}

    for raw_line in prom_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PROM_SAMPLE_RE.match(line)
        if not m:
            continue
        metric_name, raw_labels, raw_val = m.group(1), m.group(2) or "", m.group(3)
        try:
            val = float(raw_val)
        except ValueError:
            continue

        labels = {
            lm.group(1): _prom_unescape(lm.group(2))
            for lm in _PROM_LABEL_RE.finditer(raw_labels)
        }

        if metric_name == "ns8_container_info":
            mid = labels.get("module_id") or labels.get("module") or ""
            cname = labels.get("container") or labels.get("name") or ""
            if mid and cname:
                info_entries[(mid, cname)] = {
                    "image": labels.get("image") or labels.get("unit") or "ns8-module",
                    "unit": labels.get("unit") or "",
                    "info_val": "1" if val > 0 else "0",
                }

        elif metric_name == "ns8_container_running":
            mid = labels.get("module_id") or labels.get("module") or ""
            cname = labels.get("container") or labels.get("name") or ""
            if mid and cname:
                running_map[(mid, cname)] = val > 0

        elif metric_name == "ns8_container_start_time_seconds":
            mid = labels.get("module_id") or labels.get("module") or ""
            cname = labels.get("container") or labels.get("name") or ""
            if mid and cname:
                start_time_map[(mid, cname)] = val

        elif metric_name in ("ns8_container_restarts_total", "ns8_module_restarts_total"):
            mid = labels.get("module_id") or labels.get("module") or ""
            cname = labels.get("container") or labels.get("name") or ""
            if mid and cname:
                restarts_map[(mid, cname)] = max(0, int(val))

        elif metric_name == "node_systemd_unit_state":
            uname = labels.get("name") or ""
            ustate = (labels.get("state") or "").lower()
            if uname.endswith(".service"):
                if ustate == "active":
                    unit_active_map[uname] = val >= 1.0
                elif ustate == "failed" and val >= 1.0:
                    failed_units[uname] = SystemdUnitRecord(name=uname, failed=True)

    containers: list[ContainerRecord] = []
    for (mid, cname), meta in info_entries.items():
        if (mid, cname) in running_map:
            is_running = running_map[(mid, cname)]
        elif (mid, cname) in start_time_map:
            is_running = start_time_map[(mid, cname)] > 0
        elif meta["unit"] and meta["unit"] in unit_active_map:
            is_running = unit_active_map[meta["unit"]]
        else:
            is_running = meta["info_val"] == "1"

        containers.append(
            ContainerRecord(
                module_id=mid,
                container=cname,
                image=meta["image"],
                running=is_running,
                restarts=restarts_map.get((mid, cname), 0),
            )
        )

    return containers, list(failed_units.values())


def _harvest_node_exporter(vpn_ip: str = "") -> tuple[list[ContainerRecord], list[SystemdUnitRecord]]:
    override_url = os.environ.get("NS8_NODE_EXPORTER_URL", "").strip()
    if override_url:
        candidate_urls = [override_url]
    elif os.name == "nt":
        return [], []
    else:
        candidate_urls = ["http://127.0.0.1:9100/metrics"]
        if vpn_ip:
            candidate_urls.append(f"http://{vpn_ip}:9100/metrics")

    opener = urllib.request.build_opener(_NoRedirect())
    for url in candidate_urls:
        if not _validate_node_exporter_url(url):
            continue
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={"Accept": "text/plain", "User-Agent": "ns8-collector-textfile/1.1"},
            )
            with opener.open(req, timeout=2.0) as resp:
                if 200 <= getattr(resp, "status", 200) < 300:
                    body = resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
                    return parse_ns8_node_exporter_metrics(body)
        except Exception:
            continue

    return [], []


def _discover_backups(state_dir: Path, redis_backups: dict[str, BackupRecord]) -> list[BackupRecord]:
    records: dict[str, BackupRecord] = dict(redis_backups)
    status_file_env = os.environ.get("NS8_BACKUP_STATUS_FILE", "").strip()
    candidates = [Path(status_file_env)] if status_file_env else []
    candidates.extend(
        [
            state_dir / "ns8-backups.json",
            Path("/run/nethserver/central-monitoring/ns8-backups.json"),
        ]
    )

    for candidate in candidates:
        if candidate.is_file():
            try:
                raw = json.loads(candidate.read_text(encoding="utf-8"))
                items = raw.get("backups", raw) if isinstance(raw, dict) else raw
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict) or not item.get("module_id"):
                            continue
                        mid = str(item["module_id"])
                        records[mid] = BackupRecord(
                            module_id=mid,
                            succeeded=bool(item.get("succeeded", True)),
                            last_success_timestamp=int(item.get("last_success_timestamp") or 0),
                        )
            except (OSError, ValueError, TypeError):
                pass

    return list(records.values())


def _discover_local_podman_containers(
    state_dir: Path, default_module_id: str
) -> list[ContainerRecord]:
    records: dict[tuple[str, str], ContainerRecord] = {}

    # Optional JSON container inventory file
    ctr_file_env = os.environ.get("NS8_CONTAINERS_STATUS_FILE", "").strip()
    file_candidates = [Path(ctr_file_env)] if ctr_file_env else []
    file_candidates.extend(
        [
            state_dir / "ns8-containers.json",
            Path("/run/nethserver/central-monitoring/ns8-containers.json"),
        ]
    )
    for cpath in file_candidates:
        if cpath.is_file():
            try:
                raw = json.loads(cpath.read_text(encoding="utf-8"))
                items = raw.get("containers", raw) if isinstance(raw, dict) else raw
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and item.get("module_id") and item.get("container"):
                            key = (str(item["module_id"]), str(item["container"]))
                            records[key] = ContainerRecord(
                                module_id=key[0],
                                container=key[1],
                                image=str(item.get("image") or "unknown"),
                                running=bool(item.get("running", True)),
                                restarts=int(item.get("restarts") or 0),
                            )
            except (OSError, ValueError, TypeError):
                pass

    podman_bin = shutil.which("podman")
    if not podman_bin:
        return list(records.values())

    try:
        proc = subprocess.run(
            [podman_bin, "ps", "-a", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            parsed: Any = json.loads(proc.stdout)
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    names = item.get("Names") or item.get("Name") or []
                    if isinstance(names, list):
                        cname = str(names[0]) if names else str(item.get("Id", "unknown"))[:12]
                    else:
                        cname = str(names)

                    image = str(item.get("Image") or item.get("ImageName") or "unknown")
                    state = str(item.get("State") or item.get("Status") or "").lower()
                    running = state == "running" or state.startswith("up")
                    restarts = int(item.get("Restarts") or item.get("RestartCount") or 0)
                    labels = item.get("Labels") or {}
                    mid = default_module_id
                    if isinstance(labels, dict):
                        mid = str(
                            labels.get("org.nethserver.module")
                            or labels.get("io.podman.compose.project")
                            or default_module_id
                        )
                    records[(mid, cname)] = ContainerRecord(
                        module_id=mid,
                        container=cname,
                        image=image,
                        running=running,
                        restarts=restarts,
                    )
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass

    return list(records.values())


def _discover_systemd_units() -> list[SystemdUnitRecord]:
    systemctl_bin = shutil.which("systemctl")
    if not systemctl_bin or os.name == "nt":
        return []

    units: dict[str, SystemdUnitRecord] = {}
    commands = [
        [
            systemctl_bin,
            "--user",
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
        [
            systemctl_bin,
            "list-units",
            "--type=service",
            "--state=failed",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
    ]
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if proc.returncode != 0:
                continue
            for raw_line in proc.stdout.splitlines():
                parts = raw_line.split()
                if len(parts) >= 4 and parts[0].endswith(".service"):
                    unit_name = parts[0]
                    active_state = parts[2].lower()
                    sub_state = parts[3].lower()
                    is_failed = active_state == "failed" or sub_state == "failed"
                    prev = units.get(unit_name)
                    units[unit_name] = SystemdUnitRecord(
                        name=unit_name,
                        failed=is_failed or (prev.failed if prev else False),
                    )
        except (OSError, subprocess.SubprocessError):
            continue

    return list(units.values())


def collect_and_write_ns8_metrics(
    state_dir: Path,
    *,
    cgroup_root: Path | None = None,
    passwd_path: Path | None = None,
) -> Path:
    """Gather cluster-wide & local NS8 backup, cgroups v2, container, and systemd health into ns8.prom."""
    module_id = os.environ.get("MODULE_ID", "central-monitoring-collector1").strip()

    redis_backups, vpn_ip, redis_local_modules = _harvest_redis_state()
    ne_containers, ne_failed_units = _harvest_node_exporter(vpn_ip=vpn_ip)
    cgroup_modules, cgroup_pod_units = harvest_ns8_cgroups_v2(
        cgroup_root=cgroup_root,
        passwd_path=passwd_path,
        redis_local_modules=redis_local_modules,
    )

    backups = _discover_backups(state_dir, redis_backups)

    merged_containers: dict[tuple[str, str], ContainerRecord] = {
        (c.module_id, c.container): c for c in ne_containers
    }
    for local_ctr in _discover_local_podman_containers(state_dir, module_id):
        merged_containers[(local_ctr.module_id, local_ctr.container)] = local_ctr

    # Synthesize ContainerRecord for cgroup systemd sub-units not already reported by node_exporter/podman
    for pu in cgroup_pod_units:
        key = (pu.module_id, pu.unit)
        if key not in merged_containers:
            merged_containers[key] = ContainerRecord(
                module_id=pu.module_id,
                container=pu.unit,
                image="ns8-systemd-unit",
                running=(pu.pids > 0 or pu.memory_bytes > 0),
                restarts=0,
            )

    merged_units: dict[str, SystemdUnitRecord] = {u.name: u for u in ne_failed_units}
    for local_unit in _discover_systemd_units():
        prev = merged_units.get(local_unit.name)
        merged_units[local_unit.name] = SystemdUnitRecord(
            name=local_unit.name,
            failed=local_unit.failed or (prev.failed if prev else False),
        )

    prom_text = format_ns8_prom(
        backups=backups,
        containers=list(merged_containers.values()),
        systemd_units=list(merged_units.values()),
        modules=cgroup_modules,
        pod_units=cgroup_pod_units,
    )
    output_path = state_dir / "textfile" / "ns8.prom"
    write_ns8_prom_atomic(output_path, prom_text)
    return output_path
