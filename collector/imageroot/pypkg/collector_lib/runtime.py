"""Runtime paths, atomic secret-safe file I/O, collector_id helpers, firewall sync, and Alloy hot-reload."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

COLLECTOR_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]\Z")
_FORBIDDEN_SECRET_CHARS = ("\r", "\n", "\x00", "\u2028", "\u2029")


def get_state_dir() -> Path:
    """Resolve module state directory (COLLECTOR_STATE_DIR -> AGENT_STATE_DIR -> STATE_DIR -> ~/.config/state)."""
    for env_key in ("COLLECTOR_STATE_DIR", "AGENT_STATE_DIR", "STATE_DIR"):
        override = os.environ.get(env_key, "").strip()
        if override:
            path = Path(override)
            path.mkdir(parents=True, exist_ok=True)
            return path
    path = Path.home() / ".config" / "state"
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Write UTF-8 text with strict LF line endings atomically and apply file permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    tmp_path = path.parent / f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(normalized)
        try:
            os.chmod(tmp_path, mode)
        except OSError:
            pass
        os.replace(tmp_path, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def validate_auth_token_format(token: str) -> str:
    """Validate that a non-empty bearer token contains zero line-breaks, control chars, or whitespace."""
    if any(ch in token for ch in _FORBIDDEN_SECRET_CHARS):
        raise ValueError("Bearer token must not contain newline or control characters.")
    clean = token.strip()
    if clean and any(ord(ch) < 0x21 or ord(ch) == 0x7F or ch.isspace() for ch in clean):
        raise ValueError("Bearer token must not contain whitespace or control characters.")
    return clean


def save_stored_auth_token(state_dir: Path, token: str) -> Path:
    """Persist Hub bearer token into 0600 secrets.env (Restic-backed) and secrets/hub.token."""
    clean = validate_auth_token_format(token)
    secrets_dir = state_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(secrets_dir, 0o700)
    except OSError:
        pass

    token_file = secrets_dir / "hub.token"
    atomic_write_text(token_file, clean, mode=0o600)

    secrets_env = state_dir / "secrets.env"
    atomic_write_text(secrets_env, f"HUB_AUTH_TOKEN={clean}\n", mode=0o600)
    return token_file


def load_stored_auth_token(state_dir: Path) -> str:
    """Load Hub bearer token from secrets/hub.token or Restic-restored secrets.env."""
    token_file = state_dir / "secrets" / "hub.token"
    if token_file.is_file():
        val = token_file.read_text(encoding="utf-8").strip()
        if val:
            return val

    secrets_env = state_dir / "secrets.env"
    if secrets_env.is_file():
        for raw_line in secrets_env.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("HUB_AUTH_TOKEN="):
                return line.split("=", 1)[1].strip()
    return ""


def redact_token_prefix(token: str) -> str:
    """Return a safe display prefix for UI display without leaking secret entropy."""
    clean = token.strip()
    if not clean:
        return ""
    if len(clean) <= 12:
        return clean[:4] + "..."
    return clean[:12] + "..."


def build_collector_id(
    customer: str = "",
    site: str = "",
    module_id: str = "",
    *,
    unique_suffix: str = "",
) -> str:
    """Generate a canonical collector_id matching ^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]\\Z."""
    parts = [p for p in (customer, site, module_id or "ns8-collector", unique_suffix) if p]
    raw = "-".join(parts).lower()
    sanitized = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("._-")
    if len(sanitized) < 3:
        sanitized = f"ns8-{sanitized or 'collector'}"
    if len(sanitized) > 64:
        if unique_suffix:
            keep = 64 - len(unique_suffix) - 1
            sanitized = f"{sanitized[:max(3, keep)].rstrip('._-')}-{unique_suffix}"
        else:
            sanitized = sanitized[:64].rstrip("._-")
    if not sanitized[-1].isalnum():
        sanitized = sanitized[:-1] + "0"
    if not sanitized[0].isalnum():
        sanitized = "c" + sanitized[1:]
    if not COLLECTOR_ID_RE.match(sanitized):
        return "ns8-central-collector"
    return sanitized


def sync_syslog_firewall_ports(
    *,
    enable: bool,
    port: int,
    previous_enabled: bool = False,
    previous_port: int = 5514,
    runner: Callable[..., object] | None = None,
) -> None:
    """Open or close unprivileged LAN Syslog UDP/TCP port via firewall-cmd (node:fwadm)."""
    fw_bin = shutil.which("firewall-cmd")
    if not fw_bin or os.name == "nt":
        return

    def _exec(*args: str) -> None:
        try:
            if runner is not None:
                runner(fw_bin, *args)
            else:
                subprocess.run([fw_bin, *args], capture_output=True, timeout=10, check=False)
        except Exception:
            pass

    changed = False
    if previous_enabled and (not enable or previous_port != port) and 1024 <= previous_port <= 65535:
        _exec(f"--remove-port={previous_port}/udp")
        _exec(f"--remove-port={previous_port}/tcp")
        changed = True

    if enable and 1024 <= port <= 65535:
        _exec(f"--add-port={port}/udp")
        _exec(f"--add-port={port}/tcp")
        changed = True

    if changed:
        _exec("--runtime-to-permanent")


def reload_alloy_config(
    reload_url: str | None = None,
    timeout_seconds: float = 5.0,
) -> bool:
    """Trigger live Alloy config reload over HTTP POST without interrupting WAL queues."""
    effective_url = reload_url or os.environ.get("ALLOY_RELOAD_URL", "http://127.0.0.1:12345/-/reload")
    req = urllib.request.Request(effective_url, data=b"", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # Fallback on NS8 rootless Podman host when :12345 is isolated inside the pod netns
    podman_bin = shutil.which("podman")
    if podman_bin and os.name != "nt":
        try:
            pid_proc = subprocess.run(
                [podman_bin, "container", "inspect", "-f", "{{.State.Pid}}", "alloy"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            pid = pid_proc.stdout.strip()
            if pid_proc.returncode == 0 and pid.isdigit() and int(pid) > 0:
                py_snippet = (
                    "import urllib.request; "
                    f"r = urllib.request.Request({effective_url!r}, data=b'', method='POST'); "
                    "resp = urllib.request.urlopen(r, timeout=5); "
                    "raise SystemExit(0 if 200 <= resp.status < 300 else 1)"
                )
                ns_proc = subprocess.run(
                    [podman_bin, "unshare", "nsenter", "-t", pid, "-n", "python3", "-c", py_snippet],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
                if ns_proc.returncode == 0:
                    return True
        except (OSError, subprocess.SubprocessError):
            pass

    return False


def check_alloy_status(
    configured: bool,
    health_url: str | None = None,
    timeout_seconds: float = 2.0,
) -> str:
    """Return 'disabled', 'healthy', or 'unhealthy' for Alloy runtime status."""
    if not configured:
        return "disabled"

    effective_url = health_url or os.environ.get("ALLOY_HEALTH_URL", "http://127.0.0.1:12345/-/healthy")
    try:
        with urllib.request.urlopen(effective_url, timeout=timeout_seconds) as resp:
            if 200 <= resp.status < 300:
                return "healthy"
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    systemctl_bin = shutil.which("systemctl")
    if systemctl_bin and os.name != "nt":
        try:
            proc = subprocess.run(
                [systemctl_bin, "--user", "is-active", "--quiet", "alloy.service"],
                capture_output=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0:
                return "healthy"
        except (OSError, subprocess.SubprocessError):
            pass

    return "unhealthy"


def check_pve_exporter_status(
    pve_enabled: bool,
    pve_url: str | None = None,
    timeout_seconds: float = 2.0,
) -> str:
    """Return 'disabled', 'healthy', or 'unhealthy' for optional pve-exporter sidecar."""
    if not pve_enabled:
        return "disabled"

    effective_url = pve_url or os.environ.get("PVE_EXPORTER_HEALTH_URL", "http://127.0.0.1:9221/")
    try:
        with urllib.request.urlopen(effective_url, timeout=timeout_seconds) as resp:
            if 200 <= resp.status < 500:
                return "healthy"
    except urllib.error.HTTPError as exc:
        if 200 <= exc.code < 500:
            return "healthy"
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    systemctl_bin = shutil.which("systemctl")
    if systemctl_bin and os.name != "nt":
        try:
            proc = subprocess.run(
                [systemctl_bin, "--user", "is-active", "--quiet", "pve-exporter.service"],
                capture_output=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0:
                return "healthy"
        except (OSError, subprocess.SubprocessError):
            pass

    return "unhealthy"


def compute_wal_usage_bytes(state_dir: Path) -> int:
    """Sum disk bytes consumed by Alloy's local Write-Ahead-Log directory."""
    wal_dir = state_dir / "alloy-wal"
    if not wal_dir.is_dir():
        return 0
    total = 0
    for root, _dirs, files in os.walk(wal_dir):
        for fname in files:
            fpath = Path(root) / fname
            try:
                total += fpath.stat().st_size
            except OSError:
                continue
    return max(0, total)
