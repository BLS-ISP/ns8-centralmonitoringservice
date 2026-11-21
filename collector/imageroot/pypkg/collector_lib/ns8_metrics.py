"""Collects cluster-wide & local NS8 Restic backup, Podman container, and systemd metrics into ns8.prom.

Zero-Root Cluster-Wide NS8 Discovery Architecture:
  Running in the host network namespace via `ns8-collector-textfile.timer` (without root privileges):
  1. Harvests NS8 Core 3.22+'s node-wide `ns8_container_info`, `ns8_container_start_time_seconds`,
     and `node_systemd_unit_state` across ALL rootless modules (`mail1`, `nextcloud1`, `samba1`, etc.)
     from NS8's local host `node_exporter` (`http://127.0.0.1:9100/metrics` or WireGuard VPN IP).
  2. Harvests cluster-wide Restic backup statuses/timestamps from the local NS8 Redis replica
     (`agent.redis_connect(use_replica=True)` or stdlib read-only RESP2 fallback on `REDIS_ADDRESS`
     / `127.0.0.1:6379`).
  3. Merges and falls back cleanly to JSON state files (`ns8-backups.json`, `ns8-containers.json`),
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ARG002
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


def _prom_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _prom_unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")


def format_ns8_prom(
    *,
    backups: list[BackupRecord],
    containers: list[ContainerRecord],
    systemd_units: list[SystemdUnitRecord],
) -> str:
    """Format Prometheus textfile exposition matching shared/rules/ns8-cluster.yml."""
    lines: list[str] = [
        "# HELP ns8_backup_status Status of the last NS8 Restic backup for a module (1=ok, 0=failed).",
        "# TYPE ns8_backup_status gauge",
    ]
    for b in sorted(backups, key=lambda x: x.module_id):
        mid = _prom_escape(b.module_id)
        lines.append(f'ns8_backup_status{{module_id="{mid}"}} {1 if b.succeeded else 0}')

    lines.extend(
        [
            "# HELP ns8_backup_failed Whether the last NS8 Restic backup failed for a module (1=failed, 0=ok).",
            "# TYPE ns8_backup_failed gauge",
        ]
    )
    for b in sorted(backups, key=lambda x: x.module_id):
        mid = _prom_escape(b.module_id)
        lines.append(f'ns8_backup_failed{{module_id="{mid}"}} {0 if b.succeeded else 1}')

    lines.extend(
        [
            "# HELP ns8_backup_last_success_timestamp_seconds Unix timestamp of the last successful NS8 Restic backup.",
            "# TYPE ns8_backup_last_success_timestamp_seconds gauge",
        ]
    )
    for b in sorted(backups, key=lambda x: x.module_id):
        mid = _prom_escape(b.module_id)
        lines.append(
            f'ns8_backup_last_success_timestamp_seconds{{module_id="{mid}"}} {int(b.last_success_timestamp)}'
        )

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
        lines.append(
            f'ns8_container_running{{module_id="{mid}",container="{cname}"}} {1 if c.running else 0}'
        )

    lines.extend(
        [
            "# HELP ns8_container_restarts_total Total restart count of NS8 Podman containers.",
            "# TYPE ns8_container_restarts_total counter",
        ]
    )
    for c in ordered_ctrs:
        mid = _prom_escape(c.module_id)
        cname = _prom_escape(c.container)
        lines.append(
            f'ns8_container_restarts_total{{module_id="{mid}",container="{cname}"}} {max(0, int(c.restarts))}'
        )

    lines.extend(
        [
            "# HELP ns8_systemd_unit_failed Failed state of NS8 systemd user/system units (1=failed, 0=healthy).",
            "# TYPE ns8_systemd_unit_failed gauge",
        ]
    )
    for u in sorted(systemd_units, key=lambda x: x.name):
        uname = _prom_escape(u.name)
        lines.append(f'ns8_systemd_unit_failed{{name="{uname}"}} {1 if u.failed else 0}')

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


def _harvest_redis_backups_and_vpn() -> tuple[dict[str, BackupRecord], str]:
    """Query NS8 Redis replica (agent.redis_connect or stdlib RESP2) for backups & WireGuard IP."""
    records: dict[str, BackupRecord] = {}
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
                vpn_ip = raw_vpn.decode("utf-8", errors="ignore") if isinstance(raw_vpn, bytes) else str(raw_vpn)
        except Exception:
            pass

        for key in rdb.scan_iter("*backup*"):
            key_str = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else str(key)
            parts = key_str.split("/")
            if len(parts) >= 3 and parts[0] == "module":
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
        if records:
            return records, vpn_ip.strip()
    except Exception:
        pass

    # Path B: Pure-stdlib read-only RESP2 client against local loopback Redis replica
    endpoint = _parse_loopback_redis_endpoint()
    if endpoint is None:
        return records, vpn_ip

    # Only probe default 6379 automatically on Linux or when REDIS_ADDRESS is explicitly set
    if os.name == "nt" and "REDIS_ADDRESS" not in os.environ:
        return records, vpn_ip

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

            cursor = "0"
            for _ in range(50):
                scan_res = client.execute("SCAN", cursor, "MATCH", "*backup*", "COUNT", "200")
                if not isinstance(scan_res, list) or len(scan_res) != 2:
                    break
                cursor = str(scan_res[0])
                keys = scan_res[1] if isinstance(scan_res[1], list) else []
                for key_str in keys:
                    parts = str(key_str).split("/")
                    if len(parts) >= 3 and parts[0] == "module":
                        mid = parts[1]
                        ktype = str(client.execute("TYPE", key_str)).lower()
                        if ktype == "hash":
                            flat = client.execute("HGETALL", key_str)
                            if isinstance(flat, list):
                                decoded = dict(zip(flat[0::2], flat[1::2]))
                                rec = _parse_backup_hash(mid, decoded)
                                if rec is not None:
                                    records[mid] = rec
                if cursor == "0":
                    break
    except Exception:
        pass

    return records, vpn_ip


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
                headers={"Accept": "text/plain", "User-Agent": "ns8-collector-textfile/1.0"},
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


def collect_and_write_ns8_metrics(state_dir: Path) -> Path:
    """Gather cluster-wide & local NS8 backup, container, and systemd health into ns8.prom."""
    module_id = os.environ.get("MODULE_ID", "central-monitoring-collector1").strip()

    redis_backups, vpn_ip = _harvest_redis_backups_and_vpn()
    ne_containers, ne_failed_units = _harvest_node_exporter(vpn_ip=vpn_ip)

    backups = _discover_backups(state_dir, redis_backups)

    merged_containers: dict[tuple[str, str], ContainerRecord] = {
        (c.module_id, c.container): c for c in ne_containers
    }
    for local_ctr in _discover_local_podman_containers(state_dir, module_id):
        merged_containers[(local_ctr.module_id, local_ctr.container)] = local_ctr

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
    )
    output_path = state_dir / "textfile" / "ns8.prom"
    write_ns8_prom_atomic(output_path, prom_text)
    return output_path
