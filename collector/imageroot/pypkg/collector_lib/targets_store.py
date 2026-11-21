"""Atomic CRUD, file locking, host SSRF validation, and secret-redacting projection for LAN targets."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from collector_lib.runtime import atomic_write_text

DEFAULT_PORTS: dict[str, int] = {
    "proxmox": 8006,
    "windows": 9182,
    "linux": 9100,
    "snmp": 161,
    "custom-exporter": 9100,
}

_SLIRP_SUBNET = ipaddress.ip_network("10.0.2.0/24")
_NUMERIC_OR_HEX_IPV4_TOKEN_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[0-9]+)\Z")


def validate_lan_target_host(raw_host: str) -> str:
    """Reject loopback, link-local, unspecified, or Podman slirp4netns gateway LAN target hosts."""
    if any(ch in raw_host for ch in ("\r", "\n", "\x00", "\u2028", "\u2029")):
        raise ValueError("Target host contains invalid control characters.")
    host = raw_host.strip()
    if not host or any(ch.isspace() or ch in ("/", ":") and not host.count(":") >= 2 for ch in host):
        if ":" in host and "::" not in host and host.count(":") < 2:
            raise ValueError("Target host must not include port or URL path.")
        if not host or any(ch.isspace() or ch == "/" for ch in host):
            raise ValueError("Target host is invalid.")

    lower_host = host.lower().strip("[]").rstrip(".")
    if not lower_host or lower_host == "localhost" or lower_host.endswith(".localhost"):
        raise ValueError("Loopback host 'localhost' is forbidden as a LAN scrape target.")

    parts = lower_host.split(".")
    if parts and all(_NUMERIC_OR_HEX_IPV4_TOKEN_RE.match(p) for p in parts):
        if len(parts) != 4 or any(
            p.startswith("0x") or (len(p) > 1 and p.startswith("0")) for p in parts
        ):
            raise ValueError("Non-canonical IPv4 encoding is forbidden.")

    try:
        ip_raw = ipaddress.ip_address(lower_host)
    except ValueError:
        ip_raw = None

    if ip_raw is not None:
        ip_obj = (
            ip_raw.ipv4_mapped
            if isinstance(ip_raw, ipaddress.IPv6Address) and ip_raw.ipv4_mapped
            else ip_raw
        )
        if (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
            or ip_obj.is_multicast
            or (isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _SLIRP_SUBNET)
        ):
            raise ValueError(
                f"Target host {host!r} is in a forbidden loopback, link-local, or internal gateway range."
            )

    return lower_host if ip_raw is not None and isinstance(ip_raw, ipaddress.IPv6Address) else host


@contextmanager
def _exclusive_file_lock(lock_path: Path) -> Iterator[None]:
    """Acquire an exclusive cross-platform advisory lock for state/local-targets.json mutations."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+b") as lock_fh:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass

        if os.name == "nt":
            import msvcrt

            lock_fh.seek(0)
            if lock_fh.tell() == 0:
                lock_fh.write(b"\0")
                lock_fh.flush()
            lock_fh.seek(0)
            msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_fh.seek(0)
                msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


class TargetsStore:
    """Manages ~/.config/state/local-targets.json with 0600 permissions and file locking."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.file_path = state_dir / "local-targets.json"
        self.lock_path = state_dir / ".local-targets.lock"

    def _load_unlocked(self) -> list[dict[str, Any]]:
        if not self.file_path.is_file():
            return []
        raw = self.file_path.read_text(encoding="utf-8").strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            items = parsed.get("targets", [])
        elif isinstance(parsed, list):
            items = parsed
        else:
            items = []
        return [dict(item) for item in items if isinstance(item, dict)]

    def load_all(self) -> list[dict[str, Any]]:
        with _exclusive_file_lock(self.lock_path):
            return self._load_unlocked()

    def _write_unlocked(self, targets: list[dict[str, Any]]) -> None:
        ordered = sorted(targets, key=lambda item: str(item.get("id", "")))
        serialized = json.dumps({"targets": ordered}, indent=2, sort_keys=False) + "\n"
        atomic_write_text(self.file_path, serialized, mode=0o600)

    def save_target(self, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Create or update a LAN target, preserving existing secrets when secret_unchanged=True."""
        validated_host = validate_lan_target_host(str(payload["host"]))

        with _exclusive_file_lock(self.lock_path):
            targets = self._load_unlocked()
            raw_id = str(payload.get("id") or "").strip()
            existing_idx: int | None = None
            existing: dict[str, Any] = {}

            if raw_id:
                for idx, item in enumerate(targets):
                    if item.get("id") == raw_id:
                        existing_idx = idx
                        existing = item
                        break

            created = existing_idx is None
            target_id = raw_id if raw_id else f"tgt_{secrets.token_hex(6)}"
            target_type = str(payload["target_type"])
            secret_unchanged = bool(payload.get("secret_unchanged", False))

            raw_port = payload.get("port")
            if isinstance(raw_port, int) and 1 <= raw_port <= 65535:
                port = raw_port
            elif existing.get("port") and not raw_port and not created:
                port = int(existing["port"])
            else:
                port = DEFAULT_PORTS.get(target_type, 9100)

            default_scheme = "https" if target_type == "proxmox" else "http"
            scheme = str(payload.get("scheme") or existing.get("scheme") or default_scheme)
            if scheme not in ("http", "https"):
                scheme = default_scheme

            record: dict[str, Any] = {
                "id": target_id,
                "name": str(payload["name"]).strip(),
                "enabled": bool(payload.get("enabled", True)),
                "target_type": target_type,
                "device_role": str(payload["device_role"]),
                "host": validated_host,
                "port": port,
                "scrape_interval": str(payload.get("scrape_interval") or "30s"),
                "scheme": scheme,
                "metrics_path": str(payload.get("metrics_path") or "/metrics"),
                "tls_skip_verify": bool(payload.get("tls_skip_verify", False)),
            }

            if target_type == "proxmox":
                record["pve_token_id"] = str(
                    payload.get("pve_token_id") or existing.get("pve_token_id") or ""
                ).strip()
                new_secret = str(payload.get("pve_token_secret") or "")
                if secret_unchanged and not new_secret and existing:
                    record["pve_token_secret"] = str(existing.get("pve_token_secret") or "")
                else:
                    record["pve_token_secret"] = new_secret

            elif target_type == "snmp":
                snmp_module = str(
                    payload.get("snmp_module") or existing.get("snmp_module") or "if_mib"
                )
                snmp_version = str(
                    payload.get("snmp_version") or existing.get("snmp_version") or "v2c"
                )
                record["snmp_module"] = snmp_module
                record["snmp_version"] = snmp_version

                if snmp_version == "v2c":
                    provided_comm = payload.get("snmp_community")
                    if secret_unchanged and not provided_comm and existing:
                        record["snmp_community"] = str(existing.get("snmp_community") or "public")
                    else:
                        record["snmp_community"] = str(provided_comm or "public")
                else:
                    in_v3 = dict(payload.get("snmp_v3") or {})
                    old_v3 = dict(existing.get("snmp_v3") or {})
                    auth_pw = str(in_v3.get("auth_password") or "")
                    priv_pw = str(in_v3.get("priv_password") or "")
                    if secret_unchanged and not auth_pw:
                        auth_pw = str(old_v3.get("auth_password") or "")
                    if secret_unchanged and not priv_pw:
                        priv_pw = str(old_v3.get("priv_password") or "")

                    record["snmp_v3"] = {
                        "username": str(in_v3.get("username") or old_v3.get("username") or ""),
                        "security_level": str(
                            in_v3.get("security_level")
                            or old_v3.get("security_level")
                            or "authPriv"
                        ),
                        "auth_protocol": str(
                            in_v3.get("auth_protocol")
                            or old_v3.get("auth_protocol")
                            or "SHA256"
                        ),
                        "auth_password": auth_pw,
                        "priv_protocol": str(
                            in_v3.get("priv_protocol")
                            or old_v3.get("priv_protocol")
                            or "AES"
                        ),
                        "priv_password": priv_pw,
                    }

            if existing_idx is not None:
                targets[existing_idx] = record
            else:
                targets.append(record)

            self._write_unlocked(targets)
            return record, created

    def delete_target(self, target_id: str) -> bool:
        with _exclusive_file_lock(self.lock_path):
            targets = self._load_unlocked()
            remaining = [item for item in targets if item.get("id") != target_id]
            if len(remaining) == len(targets):
                return False
            self._write_unlocked(remaining)
            return True

    @staticmethod
    def to_public_target(record: dict[str, Any]) -> dict[str, Any]:
        """Project stored target to collector-list-local-targets-output.json item (secrets redacted)."""
        target_type = str(record.get("target_type") or "custom-exporter")
        pub: dict[str, Any] = {
            "id": str(record["id"]),
            "name": str(record["name"]),
            "enabled": bool(record.get("enabled", True)),
            "target_type": target_type,
            "device_role": str(record["device_role"]),
            "host": str(record["host"]),
            "port": int(record.get("port") or DEFAULT_PORTS.get(target_type, 9100)),
            "scrape_interval": str(record.get("scrape_interval") or "30s"),
            "scheme": str(
                record.get("scheme") or ("https" if target_type == "proxmox" else "http")
            ),
            "metrics_path": str(record.get("metrics_path") or "/metrics"),
            "tls_skip_verify": bool(record.get("tls_skip_verify", False)),
        }

        if target_type == "proxmox":
            pub["pve_token_id"] = str(record.get("pve_token_id") or "")
            pub["has_pve_token_secret"] = bool(record.get("pve_token_secret"))
        elif target_type == "snmp":
            snmp_ver = str(record.get("snmp_version") or "v2c")
            pub["snmp_module"] = str(record.get("snmp_module") or "if_mib")
            pub["snmp_version"] = snmp_ver
            if snmp_ver == "v3":
                v3 = dict(record.get("snmp_v3") or {})
                pub["has_snmp_secret"] = bool(
                    v3.get("auth_password") or v3.get("priv_password") or v3.get("username")
                )
                pub["snmp_v3"] = {
                    "username": str(v3.get("username") or ""),
                    "security_level": str(v3.get("security_level") or "authPriv"),
                    "auth_protocol": str(v3.get("auth_protocol") or "SHA256"),
                    "priv_protocol": str(v3.get("priv_protocol") or "AES"),
                }
            else:
                pub["has_snmp_secret"] = bool(record.get("snmp_community"))

        return pub

    def list_public_targets(self, target_type: str = "") -> list[dict[str, Any]]:
        targets = self.load_all()
        filt = target_type.strip()
        if filt:
            targets = [item for item in targets if item.get("target_type") == filt]
        return [self.to_public_target(item) for item in targets]
