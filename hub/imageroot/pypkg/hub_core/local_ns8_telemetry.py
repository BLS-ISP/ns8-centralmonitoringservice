"""Rootless Linux host (/proc, statvfs) and cgroups-v2 NS8 pod/module exporter for central-monitoring-hub."""

from __future__ import annotations

import ipaddress
import json
import math
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
from typing import Any, Callable

from hub_core import atomic_write_text, resolve_state_dir

_PROM_SAMPLE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?)"
)
_PROM_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
_NS8_MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]*[0-9]+\Z")
_SYSTEM_SERVICE_RE = re.compile(r"^[a-z][a-z0-9_-]*\.service\Z")
_KNOWN_ROOTFUL_SERVICE_RE = re.compile(
    r"^(?P<mid>(?:samba|crowdsec|nethvoice(?:-[a-z0-9]+)?|ldapproxy|metrics|"
    r"nethsecurity(?:-[a-z0-9]+)?|openvpn|dnscrypt|ejabberd|mattermost|wireguard)[0-9]+)(?:-[a-z0-9_-]+)?\.service\Z"
)
_DISK_PARTITION_RE = re.compile(
    r"^(?:ram[0-9]+|loop[0-9]+|fd[0-9]+|sr[0-9]+|zram[0-9]+"
    r"|(?:h|s|v|xv)d[a-z]+[0-9]+|nvme[0-9]+n[0-9]+p[0-9]+|mmcblk[0-9]+p[0-9]+)\Z"
)
_IGNORED_FSTYPES = frozenset(
    {
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "efivarfs",
        "fuse.gvfsd-fuse",
        "fuse.portal",
        "fusectl",
        "hugetlbfs",
        "iso9660",
        "mqueue",
        "nsfs",
        "overlay",
        "proc",
        "pstore",
        "ramfs",
        "rpc_pipefs",
        "securityfs",
        "selinuxfs",
        "squashfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    }
)
_IGNORED_MOUNT_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/containers/storage/overlay",
)
_IGNORED_SUBUNIT_PREFIXES = (
    "dbus",
    "systemd-",
    "podman-pause",
    "init",
)
_IGNORED_SUBUNIT_EXACT = frozenset(
    {
        "dbus.service",
        "hub-ns8-metrics.service",
        "ns8-collector-textfile.service",
    }
)
_CPU_MODE_COLUMNS: tuple[tuple[int, str], ...] = (
    (3, "idle"),
    (0, "user"),
    (2, "system"),
    (4, "iowait"),
    (7, "steal"),
    (1, "nice"),
    (5, "irq"),
    (6, "softirq"),
)


@dataclass(frozen=True)
class HostTelemetry:
    cpu_seconds: list[tuple[str, str, float]]
    mem_total_bytes: int | None
    mem_available_bytes: int | None
    mem_buffers_bytes: int | None
    mem_cached_bytes: int | None
    swap_total_bytes: int | None
    swap_free_bytes: int | None
    load1: float | None
    load5: float | None
    load15: float | None
    boot_time_seconds: int | None
    oom_kill_total: int | None
    filesystems: list[tuple[str, str, str, int, int]]
    disks: list[tuple[str, int, int, int, int, float, float]]
    net_devices: list[tuple[str, int, int, int, int, int, int]]
    md_arrays: list[tuple[str, int, int, int, int]]


@dataclass(frozen=True)
class ModuleCgroupRecord:
    module_id: str
    module_type: str
    up: bool
    cpu_seconds_total: float
    cpu_throttled_seconds_total: float
    memory_bytes: int
    memory_working_set_bytes: int
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
    running: bool


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


def _fmt_float(value: float) -> str:
    if not math.isfinite(value):
        return "0"
    rendered = f"{value:.6f}"
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _unescape_mount_token(token: str) -> str:
    return (
        token.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _read_text_safe(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_int_safe(path: Path) -> int:
    raw = _read_text_safe(path)
    if raw is None:
        return 0
    token = raw.strip()
    if not token or token == "max":
        return 0
    try:
        return max(0, int(token))
    except ValueError:
        return 0


def _parse_kv_stat(path: Path) -> dict[str, int]:
    raw = _read_text_safe(path)
    if raw is None:
        return {}
    result: dict[str, int] = {}
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) == 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return result


def _parse_io_stat(path: Path) -> tuple[int, int]:
    raw = _read_text_safe(path)
    if raw is None:
        return 0, 0
    rbytes = 0
    wbytes = 0
    for line in raw.splitlines():
        for token in line.strip().split():
            if token.startswith("rbytes="):
                try:
                    rbytes += max(0, int(token.split("=", 1)[1]))
                except ValueError:
                    pass
            elif token.startswith("wbytes="):
                try:
                    wbytes += max(0, int(token.split("=", 1)[1]))
                except ValueError:
                    pass
    return rbytes, wbytes


def _clk_tck() -> float:
    if hasattr(os, "sysconf"):
        try:
            val = int(os.sysconf("SC_CLK_TCK"))
            if val > 0:
                return float(val)
        except (OSError, ValueError, TypeError):
            pass
    return 100.0


def harvest_host_telemetry(
    proc_root: Path | None,
    *,
    statvfs_fn: Callable[[str], Any] | None = None,
) -> HostTelemetry:
    """Harvest Linux /proc and filesystem capacity metrics without root privileges."""
    if proc_root is None or not proc_root.is_dir():
        return HostTelemetry(
            cpu_seconds=[],
            mem_total_bytes=None,
            mem_available_bytes=None,
            mem_buffers_bytes=None,
            mem_cached_bytes=None,
            swap_total_bytes=None,
            swap_free_bytes=None,
            load1=None,
            load5=None,
            load15=None,
            boot_time_seconds=None,
            oom_kill_total=None,
            filesystems=[],
            disks=[],
            net_devices=[],
            md_arrays=[],
        )

    hz = _clk_tck()
    cpu_seconds: list[tuple[str, str, float]] = []
    boot_time_seconds: int | None = None

    stat_text = _read_text_safe(proc_root / "stat")
    if stat_text is not None:
        for line in stat_text.splitlines():
            parts = line.split()
            if not parts:
                continue
            head = parts[0]
            if head.startswith("cpu") and len(head) > 3 and head[3:].isdigit():
                cpu_id = head[3:]
                nums: list[int] = []
                for raw_num in parts[1:10]:
                    try:
                        nums.append(max(0, int(raw_num)))
                    except ValueError:
                        nums.append(0)
                while len(nums) < 8:
                    nums.append(0)
                for col_idx, mode_name in _CPU_MODE_COLUMNS:
                    cpu_seconds.append((cpu_id, mode_name, nums[col_idx] / hz))
            elif head == "btime" and len(parts) >= 2:
                try:
                    boot_time_seconds = max(0, int(parts[1]))
                except ValueError:
                    pass

    mem_total_bytes: int | None = None
    mem_available_bytes: int | None = None
    mem_buffers_bytes: int | None = None
    mem_cached_bytes: int | None = None
    swap_total_bytes: int | None = None
    swap_free_bytes: int | None = None

    meminfo_text = _read_text_safe(proc_root / "meminfo")
    if meminfo_text is not None:
        mem_kib: dict[str, int] = {}
        for line in meminfo_text.splitlines():
            if ":" not in line:
                continue
            key_part, val_part = line.split(":", 1)
            tokens = val_part.strip().split()
            if not tokens:
                continue
            try:
                mem_kib[key_part.strip()] = max(0, int(tokens[0]))
            except ValueError:
                continue
        if "MemTotal" in mem_kib:
            mem_total_bytes = mem_kib["MemTotal"] * 1024
            buffers_kib = mem_kib.get("Buffers", 0)
            cached_kib = mem_kib.get("Cached", 0)
            avail_kib = mem_kib.get(
                "MemAvailable",
                mem_kib.get("MemFree", 0) + buffers_kib + cached_kib,
            )
            mem_available_bytes = avail_kib * 1024
            mem_buffers_bytes = buffers_kib * 1024
            mem_cached_bytes = cached_kib * 1024
            swap_total_bytes = mem_kib.get("SwapTotal", 0) * 1024
            swap_free_bytes = mem_kib.get("SwapFree", 0) * 1024

    load1: float | None = None
    load5: float | None = None
    load15: float | None = None
    loadavg_text = _read_text_safe(proc_root / "loadavg")
    if loadavg_text is not None:
        lparts = loadavg_text.strip().split()
        if len(lparts) >= 3:
            try:
                load1 = float(lparts[0])
                load5 = float(lparts[1])
                load15 = float(lparts[2])
            except ValueError:
                pass

    oom_kill_total: int | None = None
    vmstat_text = _read_text_safe(proc_root / "vmstat")
    if vmstat_text is not None:
        oom_kill_total = 0
        for line in vmstat_text.splitlines():
            vparts = line.strip().split()
            if len(vparts) == 2 and vparts[0] == "oom_kill":
                try:
                    oom_kill_total = max(0, int(vparts[1]))
                except ValueError:
                    oom_kill_total = 0
                break

    filesystems: list[tuple[str, str, str, int, int]] = []
    vfs_fn = statvfs_fn if statvfs_fn is not None else getattr(os, "statvfs", None)
    mounts_text = _read_text_safe(proc_root / "mounts")
    if mounts_text is not None and callable(vfs_fn):
        seen_mounts: set[str] = set()
        for line in mounts_text.splitlines():
            mparts = line.split()
            if len(mparts) < 3:
                continue
            dev = _unescape_mount_token(mparts[0])
            mnt = _unescape_mount_token(mparts[1])
            fstype = _unescape_mount_token(mparts[2])
            if fstype in _IGNORED_FSTYPES:
                continue
            if any(
                mnt == pfx or mnt.startswith(f"{pfx}/")
                for pfx in _IGNORED_MOUNT_PREFIXES
            ):
                continue
            if mnt in seen_mounts:
                continue
            seen_mounts.add(mnt)
            try:
                st = vfs_fn(mnt)
                frsize = int(getattr(st, "f_frsize", 0) or getattr(st, "f_bsize", 0))
                size_b = max(0, int(st.f_blocks) * frsize)
                avail_b = max(0, int(st.f_bavail) * frsize)
                if size_b > 0:
                    filesystems.append((dev, fstype, mnt, size_b, avail_b))
            except OSError:
                continue

    disks: list[tuple[str, int, int, int, int, float, float]] = []
    diskstats_text = _read_text_safe(proc_root / "diskstats")
    if diskstats_text is not None:
        for line in diskstats_text.splitlines():
            dparts = line.split()
            if len(dparts) < 11:
                continue
            dev_name = dparts[2]
            if "/" in dev_name or _DISK_PARTITION_RE.match(dev_name):
                continue
            try:
                reads_completed = max(0, int(dparts[3]))
                sectors_read = max(0, int(dparts[5]))
                ms_reading = max(0, int(dparts[6]))
                writes_completed = max(0, int(dparts[7]))
                sectors_written = max(0, int(dparts[9]))
                ms_writing = max(0, int(dparts[10]))
            except ValueError:
                continue
            if reads_completed == 0 and writes_completed == 0 and sectors_read == 0 and sectors_written == 0:
                continue
            disks.append(
                (
                    dev_name,
                    sectors_read * 512,
                    sectors_written * 512,
                    reads_completed,
                    writes_completed,
                    ms_reading / 1000.0,
                    ms_writing / 1000.0,
                )
            )

    net_devices: list[tuple[str, int, int, int, int, int, int]] = []
    netdev_text = _read_text_safe(proc_root / "net" / "dev")
    if netdev_text is not None:
        for line in netdev_text.splitlines()[2:]:
            if ":" not in line:
                continue
            iface_raw, rest = line.split(":", 1)
            iface = iface_raw.strip()
            if not iface or iface == "lo" or iface.startswith("veth"):
                continue
            nparts = rest.split()
            if len(nparts) < 12:
                continue
            try:
                rx_bytes = max(0, int(nparts[0]))
                rx_errs = max(0, int(nparts[2]))
                rx_drop = max(0, int(nparts[3]))
                tx_bytes = max(0, int(nparts[8]))
                tx_errs = max(0, int(nparts[10]))
                tx_drop = max(0, int(nparts[11]))
            except ValueError:
                continue
            net_devices.append((iface, rx_bytes, tx_bytes, rx_errs, tx_errs, rx_drop, tx_drop))

    md_arrays: list[tuple[str, int, int, int, int]] = []
    mdstat_text = _read_text_safe(proc_root / "mdstat")
    if mdstat_text is not None:
        md_lines = mdstat_text.splitlines()
        idx = 0
        while idx < len(md_lines):
            raw_line = md_lines[idx]
            if ":" in raw_line and raw_line.lstrip().startswith("md"):
                left, right = raw_line.split(":", 1)
                md_dev = left.strip()
                right_tokens = right.split()
                if right_tokens and right_tokens[0] in ("active", "inactive"):
                    failed_cnt = sum(1 for tok in right_tokens if "(F)" in tok)
                    spare_cnt = sum(1 for tok in right_tokens if "(S)" in tok)
                    req_cnt = 0
                    act_cnt = 0
                    if idx + 1 < len(md_lines):
                        status_line = md_lines[idx + 1]
                        m_counts = re.search(r"\[([0-9]+)/([0-9]+)\]", status_line)
                        if m_counts:
                            req_cnt = int(m_counts.group(1))
                            act_cnt = int(m_counts.group(2))
                    if req_cnt == 0:
                        member_cnt = sum(1 for tok in right_tokens[2:] if "[" in tok and "(S)" not in tok)
                        req_cnt = max(0, member_cnt)
                        act_cnt = max(0, member_cnt - failed_cnt)
                    md_arrays.append((md_dev, req_cnt, act_cnt, failed_cnt, spare_cnt))
            idx += 1

    return HostTelemetry(
        cpu_seconds=cpu_seconds,
        mem_total_bytes=mem_total_bytes,
        mem_available_bytes=mem_available_bytes,
        mem_buffers_bytes=mem_buffers_bytes,
        mem_cached_bytes=mem_cached_bytes,
        swap_total_bytes=swap_total_bytes,
        swap_free_bytes=swap_free_bytes,
        load1=load1,
        load5=load5,
        load15=load15,
        boot_time_seconds=boot_time_seconds,
        oom_kill_total=oom_kill_total,
        filesystems=filesystems,
        disks=disks,
        net_devices=net_devices,
        md_arrays=md_arrays,
    )


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
            self._fp.read(2)
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


def _decode_redis_hash(raw_map: Any) -> dict[str, str]:
    if not isinstance(raw_map, dict):
        return {}
    return {
        (k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)): (
            v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
        )
        for k, v in raw_map.items()
    }


def _harvest_redis_state(local_node_id: str) -> tuple[dict[str, BackupRecord], set[str], dict[str, int], str]:
    """Query NS8 Redis for Restic backups, local node modules, UID hints, and WireGuard IP."""
    backups: dict[str, BackupRecord] = {}
    local_modules: set[str] = set()
    uid_hints: dict[str, int] = {}
    vpn_ip = ""

    try:
        import agent  # type: ignore[import-not-found]

        try:
            rdb = agent.redis_connect(use_replica=True)
        except TypeError:
            rdb = agent.redis_connect()

        if hasattr(rdb, "hget"):
            try:
                raw_vpn = rdb.hget(f"node/{local_node_id}/vpn", "ip_address")
                if raw_vpn:
                    vpn_ip = raw_vpn.decode("utf-8", errors="ignore") if isinstance(raw_vpn, bytes) else str(raw_vpn)
            except Exception:
                pass
        elif hasattr(rdb, "hgetall"):
            vpn_map = _decode_redis_hash(rdb.hgetall(f"node/{local_node_id}/vpn"))
            vpn_ip = str(vpn_map.get("ip_address") or "")

        all_keys: list[str] = []
        if hasattr(rdb, "scan_iter"):
            for k in rdb.scan_iter("module/*"):
                all_keys.append(k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k))
        elif isinstance(getattr(rdb, "hashes", None), dict):
            all_keys.extend(str(k) for k in rdb.hashes.keys() if str(k).startswith("module/"))

        for key_str in all_keys:
            parts = key_str.split("/")
            if len(parts) < 3 or parts[0] != "module":
                continue
            mid = parts[1]
            suffix = parts[2]
            if suffix == "environment":
                env_map = _decode_redis_hash(rdb.hgetall(key_str))
                if str(env_map.get("NODE_ID", "")).strip() == local_node_id and _NS8_MODULE_ID_RE.match(mid):
                    local_modules.add(mid)
                    raw_uid = env_map.get("MODULE_UID") or env_map.get("UID") or ""
                    if str(raw_uid).isdigit() and int(raw_uid) >= 1000:
                        uid_hints[mid] = int(raw_uid)
            elif "backup" in key_str:
                b_map = _decode_redis_hash(rdb.hgetall(key_str))
                rec = _parse_backup_hash(mid, b_map)
                if rec is not None:
                    backups[mid] = rec

        if backups or local_modules:
            return backups, local_modules, uid_hints, vpn_ip.strip()
    except Exception:
        pass

    endpoint = _parse_loopback_redis_endpoint()
    if endpoint is None:
        return backups, local_modules, uid_hints, vpn_ip
    if os.name == "nt" and "REDIS_ADDRESS" not in os.environ:
        return backups, local_modules, uid_hints, vpn_ip

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
                vpn_flat = client.execute("HGETALL", f"node/{local_node_id}/vpn")
                if isinstance(vpn_flat, list) and len(vpn_flat) >= 2:
                    vmap = dict(zip(vpn_flat[0::2], vpn_flat[1::2]))
                    vpn_ip = str(vmap.get("ip_address") or "").strip()
            except Exception:
                pass

            cursor = "0"
            for _ in range(60):
                scan_res = client.execute("SCAN", cursor, "MATCH", "module/*", "COUNT", "200")
                if not isinstance(scan_res, list) or len(scan_res) != 2:
                    break
                cursor = str(scan_res[0])
                keys = scan_res[1] if isinstance(scan_res[1], list) else []
                for key_raw in keys:
                    key_str = str(key_raw)
                    parts = key_str.split("/")
                    if len(parts) < 3 or parts[0] != "module":
                        continue
                    mid = parts[1]
                    if parts[2] == "environment":
                        if str(client.execute("TYPE", key_str)).lower() == "hash":
                            flat = client.execute("HGETALL", key_str)
                            if isinstance(flat, list):
                                emap = dict(zip(flat[0::2], flat[1::2]))
                                if str(emap.get("NODE_ID", "")).strip() == local_node_id and _NS8_MODULE_ID_RE.match(mid):
                                    local_modules.add(mid)
                                    raw_uid = str(emap.get("MODULE_UID") or emap.get("UID") or "")
                                    if raw_uid.isdigit() and int(raw_uid) >= 1000:
                                        uid_hints[mid] = int(raw_uid)
                    elif "backup" in key_str:
                        if str(client.execute("TYPE", key_str)).lower() == "hash":
                            flat = client.execute("HGETALL", key_str)
                            if isinstance(flat, list):
                                bmap = dict(zip(flat[0::2], flat[1::2]))
                                rec = _parse_backup_hash(mid, bmap)
                                if rec is not None:
                                    backups[mid] = rec
                if cursor == "0":
                    break
    except Exception:
        pass

    return backups, local_modules, uid_hints, vpn_ip.strip()


def _parse_passwd_ns8_users(passwd_path: Path | None) -> dict[str, int]:
    """Discover NS8 rootless module accounts (UID >= 1000, /home/<mid>) from /etc/passwd."""
    if passwd_path is None:
        return {}
    raw = _read_text_safe(passwd_path)
    if raw is None:
        return {}
    users: dict[str, int] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split(":")
        if len(fields) < 6:
            continue
        username = fields[0].strip()
        uid_str = fields[2].strip()
        home_dir = fields[5].strip().rstrip("/")
        if not uid_str.isdigit():
            continue
        uid = int(uid_str)
        if uid < 1000:
            continue
        if not _NS8_MODULE_ID_RE.match(username):
            continue
        if home_dir == f"/home/{username}" or home_dir.endswith(f"/home/{username}"):
            users[username] = uid
    return users


def _read_cgroup_slice_metrics(
    slice_dirs: list[Path],
    module_id: str,
    module_type: str,
) -> ModuleCgroupRecord:
    cpu_usec = 0
    throttled_usec = 0
    mem_current = 0
    inactive_file = 0
    mem_swap = 0
    finite_limits: list[int] = []
    oom_kills = 0
    io_read = 0
    io_write = 0
    pids = 0

    for sdir in slice_dirs:
        cpu_kv = _parse_kv_stat(sdir / "cpu.stat")
        cpu_usec += max(0, cpu_kv.get("usage_usec", 0))
        throttled_usec += max(0, cpu_kv.get("throttled_usec", 0))

        cur_b = _read_int_safe(sdir / "memory.current")
        mem_stat = _parse_kv_stat(sdir / "memory.stat")
        inact_b = max(0, mem_stat.get("inactive_file", 0))
        mem_current += cur_b
        inactive_file += min(cur_b, inact_b)

        mem_swap += _read_int_safe(sdir / "memory.swap.current")
        lim_b = _read_int_safe(sdir / "memory.max")
        if lim_b > 0:
            finite_limits.append(lim_b)

        events_kv = _parse_kv_stat(sdir / "memory.events")
        oom_kills += max(0, events_kv.get("oom_kill", 0))

        r_b, w_b = _parse_io_stat(sdir / "io.stat")
        io_read += r_b
        io_write += w_b
        pids += _read_int_safe(sdir / "pids.current")

    mem_limit = max(finite_limits) if finite_limits else 0
    working_set = max(0, mem_current - inactive_file)
    is_up = pids > 0 or mem_current > 0
    return ModuleCgroupRecord(
        module_id=module_id,
        module_type=module_type,
        up=is_up,
        cpu_seconds_total=cpu_usec / 1_000_000.0,
        cpu_throttled_seconds_total=throttled_usec / 1_000_000.0,
        memory_bytes=mem_current,
        memory_working_set_bytes=working_set,
        memory_swap_bytes=mem_swap,
        memory_limit_bytes=mem_limit,
        oom_kills_total=oom_kills,
        io_read_bytes_total=io_read,
        io_write_bytes_total=io_write,
        pids=pids,
    )


def _should_skip_subunit(service_filename: str) -> bool:
    if service_filename in _IGNORED_SUBUNIT_EXACT:
        return True
    stem = service_filename[:-8] if service_filename.endswith(".service") else service_filename
    return any(stem.startswith(pfx) for pfx in _IGNORED_SUBUNIT_PREFIXES)


def harvest_cgroups_v2_ns8_modules(
    cgroup_root: Path | None,
    *,
    passwd_path: Path | None,
    redis_local_modules: set[str],
    redis_uid_hints: dict[str, int],
    self_module_id: str = "",
) -> tuple[list[ModuleCgroupRecord], list[PodUnitCgroupRecord]]:
    """Harvest rootless & rootful NS8 module + sub-unit cgroups-v2 telemetry."""
    if cgroup_root is None and passwd_path is None:
        return [], []

    effective_cgroup = cgroup_root if cgroup_root is not None else Path("/sys/fs/cgroup")

    uid_by_module = _parse_passwd_ns8_users(passwd_path)
    for mid, hinted_uid in redis_uid_hints.items():
        if mid not in uid_by_module and hinted_uid >= 1000:
            uid_by_module[mid] = hinted_uid

    if passwd_path is None and "NS8_PASSWD_FILE" not in os.environ and os.name != "nt":
        try:
            import pwd

            for mid in sorted(redis_local_modules):
                if mid not in uid_by_module:
                    try:
                        pw_ent = pwd.getpwnam(mid)
                        if pw_ent.pw_uid >= 1000:
                            uid_by_module[mid] = int(pw_ent.pw_uid)
                    except KeyError:
                        continue
        except ImportError:
            pass

        if hasattr(os, "getuid") and self_module_id and _NS8_MODULE_ID_RE.match(self_module_id):
            cur_uid = os.getuid()
            if cur_uid >= 1000 and self_module_id not in uid_by_module:
                uid_by_module[self_module_id] = cur_uid

    module_records: dict[str, ModuleCgroupRecord] = {}
    pod_unit_records: dict[tuple[str, str], PodUnitCgroupRecord] = {}

    user_slice_root = effective_cgroup / "user.slice"
    for mid, uid in sorted(uid_by_module.items()):
        slice_dir = user_slice_root / f"user-{uid}.slice"
        module_records[mid] = _read_cgroup_slice_metrics([slice_dir], mid, "rootless")
        if not slice_dir.is_dir():
            continue

        user_mgr_dir = slice_dir / f"user@{uid}.service"
        candidate_unit_dirs: list[Path] = []
        for sub_slice_name in ("app.slice", "user.slice"):
            sub_slice = user_mgr_dir / sub_slice_name
            if sub_slice.is_dir():
                try:
                    candidate_unit_dirs.extend(
                        sorted(p for p in sub_slice.iterdir() if p.is_dir() and p.name.endswith(".service"))
                    )
                except OSError:
                    continue

        for udir in candidate_unit_dirs:
            if _should_skip_subunit(udir.name):
                continue
            unit_stem = udir.name[:-8]
            u_cpu_kv = _parse_kv_stat(udir / "cpu.stat")
            u_cpu_sec = max(0, u_cpu_kv.get("usage_usec", 0)) / 1_000_000.0
            u_mem_cur = _read_int_safe(udir / "memory.current")
            u_mem_stat = _parse_kv_stat(udir / "memory.stat")
            u_inact = max(0, u_mem_stat.get("inactive_file", 0))
            u_ws = max(0, u_mem_cur - u_inact)
            u_pids = _read_int_safe(udir / "pids.current")
            pod_unit_records[(mid, unit_stem)] = PodUnitCgroupRecord(
                module_id=mid,
                unit=unit_stem,
                cpu_seconds_total=u_cpu_sec,
                memory_working_set_bytes=u_ws,
                running=(u_pids > 0 or u_mem_cur > 0),
            )

    known_rootful = {
        mid for mid in redis_local_modules if mid not in module_records and _NS8_MODULE_ID_RE.match(mid)
    }
    ordered_known_rootful = sorted(known_rootful, key=lambda x: (-len(x), x))
    rootful_dirs: dict[str, list[Path]] = {mid: [] for mid in known_rootful}

    sys_slice_root = effective_cgroup / "system.slice"
    if sys_slice_root.is_dir():
        try:
            sys_services = sorted(
                p for p in sys_slice_root.iterdir() if p.is_dir() and _SYSTEM_SERVICE_RE.match(p.name)
            )
        except OSError:
            sys_services = []

        for svc_dir in sys_services:
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
                    if cand not in module_records:
                        matched_mid = cand
            if matched_mid:
                rootful_dirs.setdefault(matched_mid, []).append(svc_dir)

    for rmid in sorted(rootful_dirs):
        matched_dirs = rootful_dirs[rmid]
        module_records[rmid] = _read_cgroup_slice_metrics(matched_dirs, rmid, "rootful")
        for mdir in matched_dirs:
            unit_stem = mdir.name[:-8]
            u_cpu_kv = _parse_kv_stat(mdir / "cpu.stat")
            u_cpu_sec = max(0, u_cpu_kv.get("usage_usec", 0)) / 1_000_000.0
            u_mem_cur = _read_int_safe(mdir / "memory.current")
            u_mem_stat = _parse_kv_stat(mdir / "memory.stat")
            u_inact = max(0, u_mem_stat.get("inactive_file", 0))
            u_ws = max(0, u_mem_cur - u_inact)
            u_pids = _read_int_safe(mdir / "pids.current")
            pod_unit_records[(rmid, unit_stem)] = PodUnitCgroupRecord(
                module_id=rmid,
                unit=unit_stem,
                cpu_seconds_total=u_cpu_sec,
                memory_working_set_bytes=u_ws,
                running=(u_pids > 0 or u_mem_cur > 0),
            )

    return (
        [module_records[k] for k in sorted(module_records)],
        [pod_unit_records[k] for k in sorted(pod_unit_records)],
    )


def _validate_node_exporter_url(url: str) -> bool:
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


def _parse_ns8_node_exporter_metrics(
    prom_text: str,
) -> tuple[list[ContainerRecord], list[SystemdUnitRecord]]:
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
                headers={"Accept": "text/plain", "User-Agent": "central-monitoring-hub-ns8/1.1"},
            )
            with opener.open(req, timeout=1.5) as resp:
                if 200 <= getattr(resp, "status", 200) < 300:
                    body = resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
                    return _parse_ns8_node_exporter_metrics(body)
        except Exception:
            continue
    return [], []


def _discover_backups(state_dir: Path, redis_backups: dict[str, BackupRecord]) -> list[BackupRecord]:
    records: dict[str, BackupRecord] = dict(redis_backups)
    status_file_env = os.environ.get("NS8_BACKUP_STATUS_FILE", "").strip()
    candidates = [Path(status_file_env)] if status_file_env else []
    candidates.append(state_dir / "ns8-backups.json")
    if os.name != "nt":
        candidates.append(Path("/run/nethserver/central-monitoring/ns8-backups.json"))

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


def _discover_local_podman_containers(state_dir: Path, default_module_id: str) -> list[ContainerRecord]:
    records: dict[tuple[str, str], ContainerRecord] = {}
    ctr_file_env = os.environ.get("NS8_CONTAINERS_STATUS_FILE", "").strip()
    file_candidates = [Path(ctr_file_env)] if ctr_file_env else []
    file_candidates.append(state_dir / "ns8-containers.json")
    if os.name != "nt":
        file_candidates.append(Path("/run/nethserver/central-monitoring/ns8-containers.json"))

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

    if os.name == "nt":
        return list(records.values())

    podman_bin = shutil.which("podman")
    if not podman_bin:
        return list(records.values())

    try:
        proc = subprocess.run(
            [podman_bin, "ps", "-a", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=8,
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
    if os.name == "nt":
        return []
    systemctl_bin = shutil.which("systemctl")
    if not systemctl_bin:
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
                timeout=6,
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


def format_hub_ns8_prom(
    *,
    host: HostTelemetry,
    modules: list[ModuleCgroupRecord],
    pod_units: list[PodUnitCgroupRecord],
    backups: list[BackupRecord],
    containers: list[ContainerRecord],
    systemd_units: list[SystemdUnitRecord],
) -> str:
    """Render Prometheus text exposition format for Hub host + cgroups-v2 NS8 pod self-monitoring."""
    lines: list[str] = []

    if host.cpu_seconds:
        lines.extend(
            [
                "# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.",
                "# TYPE node_cpu_seconds_total counter",
            ]
        )
        for cpu_id, mode_name, secs in host.cpu_seconds:
            lines.append(
                f'node_cpu_seconds_total{{cpu="{_prom_escape(cpu_id)}",mode="{_prom_escape(mode_name)}"}} {_fmt_float(secs)}'
            )

    if host.mem_total_bytes is not None:
        lines.extend(
            [
                "# HELP node_memory_MemTotal_bytes Memory information field MemTotal_bytes.",
                "# TYPE node_memory_MemTotal_bytes gauge",
                f"node_memory_MemTotal_bytes {host.mem_total_bytes}",
                "# HELP node_memory_MemAvailable_bytes Memory information field MemAvailable_bytes.",
                "# TYPE node_memory_MemAvailable_bytes gauge",
                f"node_memory_MemAvailable_bytes {host.mem_available_bytes or 0}",
                "# HELP node_memory_Buffers_bytes Memory information field Buffers_bytes.",
                "# TYPE node_memory_Buffers_bytes gauge",
                f"node_memory_Buffers_bytes {host.mem_buffers_bytes or 0}",
                "# HELP node_memory_Cached_bytes Memory information field Cached_bytes.",
                "# TYPE node_memory_Cached_bytes gauge",
                f"node_memory_Cached_bytes {host.mem_cached_bytes or 0}",
                "# HELP node_memory_SwapTotal_bytes Memory information field SwapTotal_bytes.",
                "# TYPE node_memory_SwapTotal_bytes gauge",
                f"node_memory_SwapTotal_bytes {host.swap_total_bytes or 0}",
                "# HELP node_memory_SwapFree_bytes Memory information field SwapFree_bytes.",
                "# TYPE node_memory_SwapFree_bytes gauge",
                f"node_memory_SwapFree_bytes {host.swap_free_bytes or 0}",
            ]
        )

    if host.load1 is not None:
        lines.extend(
            [
                "# HELP node_load1 1m load average.",
                "# TYPE node_load1 gauge",
                f"node_load1 {_fmt_float(host.load1)}",
                "# HELP node_load5 5m load average.",
                "# TYPE node_load5 gauge",
                f"node_load5 {_fmt_float(host.load5 or 0.0)}",
                "# HELP node_load15 15m load average.",
                "# TYPE node_load15 gauge",
                f"node_load15 {_fmt_float(host.load15 or 0.0)}",
            ]
        )

    if host.boot_time_seconds is not None:
        lines.extend(
            [
                "# HELP node_boot_time_seconds Node boot time, in unixtime.",
                "# TYPE node_boot_time_seconds gauge",
                f"node_boot_time_seconds {host.boot_time_seconds}",
            ]
        )

    if host.oom_kill_total is not None:
        lines.extend(
            [
                "# HELP node_vmstat_oom_kill /proc/vmstat information field oom_kill.",
                "# TYPE node_vmstat_oom_kill counter",
                f"node_vmstat_oom_kill {host.oom_kill_total}",
            ]
        )

    if host.filesystems:
        lines.extend(
            [
                "# HELP node_filesystem_size_bytes Filesystem size in bytes.",
                "# TYPE node_filesystem_size_bytes gauge",
            ]
        )
        for dev, fstype, mnt, size_b, _ in host.filesystems:
            d_esc = _prom_escape(dev)
            f_esc = _prom_escape(fstype)
            m_esc = _prom_escape(mnt)
            lines.append(
                f'node_filesystem_size_bytes{{device="{d_esc}",fstype="{f_esc}",mountpoint="{m_esc}"}} {size_b}'
            )
        lines.extend(
            [
                "# HELP node_filesystem_avail_bytes Filesystem space available to non-root users in bytes.",
                "# TYPE node_filesystem_avail_bytes gauge",
            ]
        )
        for dev, fstype, mnt, _, avail_b in host.filesystems:
            d_esc = _prom_escape(dev)
            f_esc = _prom_escape(fstype)
            m_esc = _prom_escape(mnt)
            lines.append(
                f'node_filesystem_avail_bytes{{device="{d_esc}",fstype="{f_esc}",mountpoint="{m_esc}"}} {avail_b}'
            )

    if host.disks:
        lines.extend(
            [
                "# HELP node_disk_read_bytes_total The total number of bytes read successfully.",
                "# TYPE node_disk_read_bytes_total counter",
            ]
        )
        for dev, rb, _, _, _, _, _ in host.disks:
            lines.append(f'node_disk_read_bytes_total{{device="{_prom_escape(dev)}"}} {rb}')

        lines.extend(
            [
                "# HELP node_disk_written_bytes_total The total number of bytes written successfully.",
                "# TYPE node_disk_written_bytes_total counter",
            ]
        )
        for dev, _, wb, _, _, _, _ in host.disks:
            lines.append(f'node_disk_written_bytes_total{{device="{_prom_escape(dev)}"}} {wb}')

        lines.extend(
            [
                "# HELP node_disk_reads_completed_total The total number of reads completed successfully.",
                "# TYPE node_disk_reads_completed_total counter",
            ]
        )
        for dev, _, _, rc, _, _, _ in host.disks:
            lines.append(f'node_disk_reads_completed_total{{device="{_prom_escape(dev)}"}} {rc}')

        lines.extend(
            [
                "# HELP node_disk_writes_completed_total The total number of writes completed successfully.",
                "# TYPE node_disk_writes_completed_total counter",
            ]
        )
        for dev, _, _, _, wc, _, _ in host.disks:
            lines.append(f'node_disk_writes_completed_total{{device="{_prom_escape(dev)}"}} {wc}')

        lines.extend(
            [
                "# HELP node_disk_read_time_seconds_total The total number of seconds spent by all reads.",
                "# TYPE node_disk_read_time_seconds_total counter",
            ]
        )
        for dev, _, _, _, _, rsec, _ in host.disks:
            lines.append(f'node_disk_read_time_seconds_total{{device="{_prom_escape(dev)}"}} {_fmt_float(rsec)}')

        lines.extend(
            [
                "# HELP node_disk_write_time_seconds_total The total number of seconds spent by all writes.",
                "# TYPE node_disk_write_time_seconds_total counter",
            ]
        )
        for dev, _, _, _, _, _, wsec in host.disks:
            lines.append(f'node_disk_write_time_seconds_total{{device="{_prom_escape(dev)}"}} {_fmt_float(wsec)}')

    if host.net_devices:
        lines.extend(
            [
                "# HELP node_network_receive_bytes_total Network device statistic receive_bytes.",
                "# TYPE node_network_receive_bytes_total counter",
            ]
        )
        for dev, rxb, _, _, _, _, _ in host.net_devices:
            lines.append(f'node_network_receive_bytes_total{{device="{_prom_escape(dev)}"}} {rxb}')

        lines.extend(
            [
                "# HELP node_network_transmit_bytes_total Network device statistic transmit_bytes.",
                "# TYPE node_network_transmit_bytes_total counter",
            ]
        )
        for dev, _, txb, _, _, _, _ in host.net_devices:
            lines.append(f'node_network_transmit_bytes_total{{device="{_prom_escape(dev)}"}} {txb}')

        lines.extend(
            [
                "# HELP node_network_receive_errs_total Network device statistic receive_errs.",
                "# TYPE node_network_receive_errs_total counter",
            ]
        )
        for dev, _, _, rxe, _, _, _ in host.net_devices:
            lines.append(f'node_network_receive_errs_total{{device="{_prom_escape(dev)}"}} {rxe}')

        lines.extend(
            [
                "# HELP node_network_transmit_errs_total Network device statistic transmit_errs.",
                "# TYPE node_network_transmit_errs_total counter",
            ]
        )
        for dev, _, _, _, txe, _, _ in host.net_devices:
            lines.append(f'node_network_transmit_errs_total{{device="{_prom_escape(dev)}"}} {txe}')

        lines.extend(
            [
                "# HELP node_network_receive_drop_total Network device statistic receive_drop.",
                "# TYPE node_network_receive_drop_total counter",
            ]
        )
        for dev, _, _, _, _, rxd, _ in host.net_devices:
            lines.append(f'node_network_receive_drop_total{{device="{_prom_escape(dev)}"}} {rxd}')

        lines.extend(
            [
                "# HELP node_network_transmit_drop_total Network device statistic transmit_drop.",
                "# TYPE node_network_transmit_drop_total counter",
            ]
        )
        for dev, _, _, _, _, _, txd in host.net_devices:
            lines.append(f'node_network_transmit_drop_total{{device="{_prom_escape(dev)}"}} {txd}')

    if host.md_arrays:
        lines.extend(
            [
                "# HELP node_md_disks Number of active/failed/spare disks of mdadm array.",
                "# TYPE node_md_disks gauge",
            ]
        )
        for md_dev, _, act_cnt, fail_cnt, spare_cnt in host.md_arrays:
            m_esc = _prom_escape(md_dev)
            lines.append(f'node_md_disks{{device="{m_esc}",state="active"}} {act_cnt}')
            lines.append(f'node_md_disks{{device="{m_esc}",state="failed"}} {fail_cnt}')
            lines.append(f'node_md_disks{{device="{m_esc}",state="spare"}} {spare_cnt}')

        lines.extend(
            [
                "# HELP node_md_disks_required Total number of disks of mdadm array.",
                "# TYPE node_md_disks_required gauge",
            ]
        )
        for md_dev, req_cnt, _, _, _ in host.md_arrays:
            lines.append(f'node_md_disks_required{{device="{_prom_escape(md_dev)}"}} {req_cnt}')

    ordered_mods = sorted(modules, key=lambda x: x.module_id)

    lines.extend(
        [
            "# HELP ns8_module_up Running state of NS8 module cgroup slice (1=active, 0=inactive).",
            "# TYPE ns8_module_up gauge",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_up{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {1 if m.up else 0}'
        )

    lines.extend(
        [
            "# HELP ns8_module_cpu_seconds_total Cumulative CPU time consumed by NS8 module cgroup slice.",
            "# TYPE ns8_module_cpu_seconds_total counter",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_cpu_seconds_total{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {_fmt_float(m.cpu_seconds_total)}'
        )

    lines.extend(
        [
            "# HELP ns8_module_cpu_throttled_seconds_total Cumulative throttled CPU time for NS8 module cgroup slice.",
            "# TYPE ns8_module_cpu_throttled_seconds_total counter",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_cpu_throttled_seconds_total{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {_fmt_float(m.cpu_throttled_seconds_total)}'
        )

    lines.extend(
        [
            "# HELP ns8_module_memory_working_set_bytes Working-set RAM (memory.current - inactive_file) of NS8 module.",
            "# TYPE ns8_module_memory_working_set_bytes gauge",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_memory_working_set_bytes{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.memory_working_set_bytes}'
        )

    lines.extend(
        [
            "# HELP ns8_module_memory_bytes Total cgroup memory.current bytes of NS8 module.",
            "# TYPE ns8_module_memory_bytes gauge",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_memory_bytes{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.memory_bytes}'
        )

    lines.extend(
        [
            "# HELP ns8_module_memory_swap_bytes Current swap usage bytes of NS8 module.",
            "# TYPE ns8_module_memory_swap_bytes gauge",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_memory_swap_bytes{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.memory_swap_bytes}'
        )

    lines.extend(
        [
            "# HELP ns8_module_memory_limit_bytes Configured memory.max limit of NS8 module (0=unlimited).",
            "# TYPE ns8_module_memory_limit_bytes gauge",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_memory_limit_bytes{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.memory_limit_bytes}'
        )

    lines.extend(
        [
            "# HELP ns8_module_oom_kills_total Total OOM kills recorded in memory.events for NS8 module.",
            "# TYPE ns8_module_oom_kills_total counter",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_oom_kills_total{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.oom_kills_total}'
        )

    lines.extend(
        [
            "# HELP ns8_module_io_read_bytes_total Total block I/O bytes read by NS8 module.",
            "# TYPE ns8_module_io_read_bytes_total counter",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_io_read_bytes_total{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.io_read_bytes_total}'
        )

    lines.extend(
        [
            "# HELP ns8_module_io_write_bytes_total Total block I/O bytes written by NS8 module.",
            "# TYPE ns8_module_io_write_bytes_total counter",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_io_write_bytes_total{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.io_write_bytes_total}'
        )

    lines.extend(
        [
            "# HELP ns8_module_pids Current process/thread count (pids.current) of NS8 module.",
            "# TYPE ns8_module_pids gauge",
        ]
    )
    for m in ordered_mods:
        lines.append(
            f'ns8_module_pids{{module_id="{_prom_escape(m.module_id)}",module_type="{_prom_escape(m.module_type)}"}} {m.pids}'
        )

    ordered_units = sorted(pod_units, key=lambda x: (x.module_id, x.unit))
    lines.extend(
        [
            "# HELP ns8_pod_unit_cpu_seconds_total Cumulative CPU time of individual container/unit inside NS8 module pod.",
            "# TYPE ns8_pod_unit_cpu_seconds_total counter",
        ]
    )
    for pu in ordered_units:
        lines.append(
            f'ns8_pod_unit_cpu_seconds_total{{module_id="{_prom_escape(pu.module_id)}",unit="{_prom_escape(pu.unit)}"}} {_fmt_float(pu.cpu_seconds_total)}'
        )

    lines.extend(
        [
            "# HELP ns8_pod_unit_memory_working_set_bytes Working-set RAM of individual container/unit inside NS8 module pod.",
            "# TYPE ns8_pod_unit_memory_working_set_bytes gauge",
        ]
    )
    for pu in ordered_units:
        lines.append(
            f'ns8_pod_unit_memory_working_set_bytes{{module_id="{_prom_escape(pu.module_id)}",unit="{_prom_escape(pu.unit)}"}} {pu.memory_working_set_bytes}'
        )

    ordered_backups = sorted(backups, key=lambda x: x.module_id)
    lines.extend(
        [
            "# HELP ns8_backup_status Status of the last NS8 Restic backup for a module (1=ok, 0=failed).",
            "# TYPE ns8_backup_status gauge",
        ]
    )
    for b in ordered_backups:
        lines.append(f'ns8_backup_status{{module_id="{_prom_escape(b.module_id)}"}} {1 if b.succeeded else 0}')

    lines.extend(
        [
            "# HELP ns8_backup_failed Whether the last NS8 Restic backup failed for a module (1=failed, 0=ok).",
            "# TYPE ns8_backup_failed gauge",
        ]
    )
    for b in ordered_backups:
        lines.append(f'ns8_backup_failed{{module_id="{_prom_escape(b.module_id)}"}} {0 if b.succeeded else 1}')

    lines.extend(
        [
            "# HELP ns8_backup_last_success_timestamp_seconds Unix timestamp of the last successful NS8 Restic backup.",
            "# TYPE ns8_backup_last_success_timestamp_seconds gauge",
        ]
    )
    for b in ordered_backups:
        lines.append(
            f'ns8_backup_last_success_timestamp_seconds{{module_id="{_prom_escape(b.module_id)}"}} {int(b.last_success_timestamp)}'
        )

    ordered_ctrs = sorted(containers, key=lambda x: (x.module_id, x.container))
    lines.extend(
        [
            "# HELP ns8_container_info Metadata inventory of NS8 Podman containers.",
            "# TYPE ns8_container_info gauge",
        ]
    )
    for c in ordered_ctrs:
        lines.append(
            f'ns8_container_info{{module_id="{_prom_escape(c.module_id)}",container="{_prom_escape(c.container)}",image="{_prom_escape(c.image)}"}} 1'
        )

    lines.extend(
        [
            "# HELP ns8_container_running Running state of NS8 Podman containers (1=running, 0=not running).",
            "# TYPE ns8_container_running gauge",
        ]
    )
    for c in ordered_ctrs:
        lines.append(
            f'ns8_container_running{{module_id="{_prom_escape(c.module_id)}",container="{_prom_escape(c.container)}"}} {1 if c.running else 0}'
        )

    lines.extend(
        [
            "# HELP ns8_container_restarts_total Total restart count of NS8 Podman containers.",
            "# TYPE ns8_container_restarts_total counter",
        ]
    )
    for c in ordered_ctrs:
        lines.append(
            f'ns8_container_restarts_total{{module_id="{_prom_escape(c.module_id)}",container="{_prom_escape(c.container)}"}} {max(0, int(c.restarts))}'
        )

    lines.extend(
        [
            "# HELP ns8_systemd_unit_failed Failed state of NS8 systemd user/system units (1=failed, 0=healthy).",
            "# TYPE ns8_systemd_unit_failed gauge",
        ]
    )
    for u in sorted(systemd_units, key=lambda x: x.name):
        lines.append(f'ns8_systemd_unit_failed{{name="{_prom_escape(u.name)}"}} {1 if u.failed else 0}')

    return "\n".join(lines) + "\n"


def collect_hub_ns8_metrics(
    state_dir: str | Path | None = None,
    *,
    proc_root: Path | None = None,
    cgroup_root: Path | None = None,
    passwd_path: Path | None = None,
    statvfs_fn: Callable[[str], Any] | None = None,
) -> Path:
    """Collect local NS8 host + cgroups-v2 pod metrics and write state/textfile/ns8-hub-node.prom."""
    sdir = resolve_state_dir(state_dir)
    module_id = os.environ.get("MODULE_ID", "central-monitoring-hub1").strip() or "central-monitoring-hub1"
    node_id = os.environ.get("NODE_ID", "1").strip() or "1"

    resolved_proc = (
        proc_root
        if proc_root is not None
        else (
            Path(os.environ["NS8_PROC_ROOT"])
            if "NS8_PROC_ROOT" in os.environ
            else (Path("/proc") if os.name != "nt" else None)
        )
    )
    resolved_cgroup = (
        cgroup_root
        if cgroup_root is not None
        else (
            Path(os.environ["NS8_CGROUP_ROOT"])
            if "NS8_CGROUP_ROOT" in os.environ
            else (Path("/sys/fs/cgroup") if os.name != "nt" else None)
        )
    )
    resolved_passwd = (
        passwd_path
        if passwd_path is not None
        else (
            Path(os.environ["NS8_PASSWD_FILE"])
            if "NS8_PASSWD_FILE" in os.environ
            else (Path("/etc/passwd") if os.name != "nt" else None)
        )
    )

    host_telemetry = harvest_host_telemetry(resolved_proc, statvfs_fn=statvfs_fn)
    redis_backups, redis_local_modules, redis_uid_hints, vpn_ip = _harvest_redis_state(node_id)
    modules, pod_units = harvest_cgroups_v2_ns8_modules(
        resolved_cgroup,
        passwd_path=resolved_passwd,
        redis_local_modules=redis_local_modules,
        redis_uid_hints=redis_uid_hints,
        self_module_id=module_id,
    )

    ne_containers, ne_failed_units = _harvest_node_exporter(vpn_ip=vpn_ip)
    backups = _discover_backups(sdir, redis_backups)

    merged_containers: dict[tuple[str, str], ContainerRecord] = {
        (c.module_id, c.container): c for c in ne_containers
    }
    for local_ctr in _discover_local_podman_containers(sdir, module_id):
        merged_containers[(local_ctr.module_id, local_ctr.container)] = local_ctr

    for pu in pod_units:
        if (pu.module_id, pu.unit) not in merged_containers:
            merged_containers[(pu.module_id, pu.unit)] = ContainerRecord(
                module_id=pu.module_id,
                container=pu.unit,
                image="ns8-systemd-unit",
                running=pu.running,
                restarts=0,
            )

    merged_units: dict[str, SystemdUnitRecord] = {u.name: u for u in ne_failed_units}
    for local_unit in _discover_systemd_units():
        prev = merged_units.get(local_unit.name)
        merged_units[local_unit.name] = SystemdUnitRecord(
            name=local_unit.name,
            failed=local_unit.failed or (prev.failed if prev else False),
        )

    prom_text = format_hub_ns8_prom(
        host=host_telemetry,
        modules=modules,
        pod_units=pod_units,
        backups=backups,
        containers=list(merged_containers.values()),
        systemd_units=list(merged_units.values()),
    )
    output_path = sdir / "textfile" / "ns8-hub-node.prom"
    atomic_write_text(output_path, prom_text, mode=0o644)
    return output_path
