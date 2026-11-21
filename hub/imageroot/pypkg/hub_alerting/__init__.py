"""Observability Probing, Target Management, Rule Packs, Alertmanager Routing & Silences."""

from __future__ import annotations

import base64
from collections.abc import Callable
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterator
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlparse

__all__ = [
    "ValidationFailure",
    "atomic_write_json",
    "atomic_write_text",
    "emit_validation_error_and_exit",
    "file_lock",
    "load_json_file",
    "load_tenants_map",
    "pod_http_request",
    "resolve_config_dir",
    "resolve_state_dir",
    "trigger_http_reload",
    "yaml_quote",
]

_POD_HTTP_SCRIPT = (
    "import base64, json, sys, urllib.error, urllib.request\n"
    "m = json.loads(sys.stdin.read())\n"
    "body = base64.b64decode(m['body_b64']) if m.get('body_b64') else None\n"
    "req = urllib.request.Request(m['url'], data=body, headers=m.get('headers') or {}, method=m['method'])\n"
    "try:\n"
    "    with urllib.request.urlopen(req, timeout=float(m.get('timeout', 4.0))) as r:\n"
    "        out = {'status': r.status, 'body_b64': base64.b64encode(r.read()).decode('ascii')}\n"
    "except urllib.error.HTTPError as e:\n"
    "    out = {'status': e.code, 'body_b64': base64.b64encode(e.read()).decode('ascii')}\n"
    "sys.stdout.write(json.dumps(out))\n"
)


class ValidationFailure(ValueError):
    """Structured NS8 action validation error."""

    def __init__(self, field: str, value: Any, code: str, message: str = "") -> None:
        self.field = field
        self.value = value
        self.code = code
        self.detail = message or code
        super().__init__(f"{code}: {self.detail} ({field}={value!r})")


def resolve_state_dir(state_dir: str | Path | None = None) -> Path:
    if state_dir is not None:
        return Path(state_dir).resolve()
    env_dir = (
        os.environ.get("AGENT_STATE_DIR")
        or os.environ.get("HUB_STATE_DIR")
        or os.environ.get("STATE_DIR")
    )
    if env_dir:
        return Path(env_dir).resolve()
    return Path.cwd().resolve()


def resolve_config_dir(state_dir: str | Path | None = None) -> Path:
    env_cfg = os.environ.get("HUB_CONFIG_DIR")
    if env_cfg:
        return Path(env_cfg).resolve()
    resolved_state = resolve_state_dir(state_dir)
    return (resolved_state.parent / "config").resolve()


@contextmanager
def file_lock(lock_path: Path) -> Iterator[None]:
    """Cross-platform advisory file lock (fcntl on Linux/NS8, msvcrt on Windows)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    """Write UTF-8 text with strict LF line endings and atomic rename."""
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(normalized)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def atomic_write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    """Serialize JSON with deterministic formatting, LF endings, and atomic rename."""
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(path, rendered, mode=mode)


def load_json_file(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return default
    return json.loads(raw)


def load_tenants_map(state_dir: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load state/tenants.json regardless of whether stored as {'tenants': [...]}, dict, or list."""
    sdir = resolve_state_dir(state_dir)
    data = load_json_file(sdir / "tenants.json", {})
    result: dict[str, dict[str, Any]] = {}
    if isinstance(data, dict):
        tenants_raw = data.get("tenants", data)
        if isinstance(tenants_raw, list):
            for item in tenants_raw:
                if isinstance(item, dict) and item.get("customer"):
                    result[str(item["customer"])] = item
        elif isinstance(tenants_raw, dict):
            for slug, item in tenants_raw.items():
                if isinstance(item, dict):
                    rec = dict(item)
                    rec.setdefault("customer", str(slug))
                    result[str(rec["customer"])] = rec
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("customer"):
                result[str(item["customer"])] = item
    return result


def yaml_quote(value: str) -> str:
    """Safely double-quote a YAML scalar string without external PyYAML dependency."""
    escaped = (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _default_podman_exec(cmd: list[str], stdin_bytes: bytes, timeout: float) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        input=stdin_bytes,
        capture_output=True,
        timeout=max(timeout + 3.0, 6.0),
        check=False,
    )
    return proc.returncode, proc.stdout.decode("utf-8", errors="replace")


def pod_http_request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 4.0,
    _podman_exec: Callable[[list[str], bytes, float], tuple[int, str]] | None = None,
) -> tuple[int, bytes]:
    """Perform an HTTP request, falling back to the rootless Podman pod netns for 127.0.0.1 services."""
    req = urllib_request.Request(url=url, data=data, headers=headers or {}, method=method)
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return int(resp.status), resp.read()
    except urllib_error.HTTPError as exc:
        return int(exc.code), exc.read()
    except (urllib_error.URLError, TimeoutError, OSError):
        pass

    parsed_host = (urlparse(url).hostname or "").lower()
    if parsed_host not in {"127.0.0.1", "localhost", "::1"}:
        return 0, b""

    podman_bin = os.environ.get("HUB_PODMAN_BIN") or (shutil.which("podman") if os.name != "nt" else None)
    if not podman_bin:
        return 0, b""

    stdin_payload = json.dumps(
        {
            "url": url,
            "method": method,
            "headers": headers or {},
            "body_b64": base64.b64encode(data).decode("ascii") if data is not None else "",
            "timeout": timeout,
        }
    ).encode("utf-8")
    runner = _podman_exec or _default_podman_exec

    # 1. Try executing via hub-gateway (python:3.12-slim inside central-monitoring-hub pod)
    try:
        rc, out_str = runner(
            [podman_bin, "exec", "-i", "hub-gateway", "python3", "-c", _POD_HTTP_SCRIPT],
            stdin_payload,
            timeout,
        )
        if rc == 0 and out_str.strip():
            parsed = json.loads(out_str)
            return int(parsed["status"]), base64.b64decode(parsed.get("body_b64", ""))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        pass

    # 2. Fallback: enter pod network namespace via podman unshare nsenter on any active pod container
    if _podman_exec is None:
        for container_name in ("alertmanager", "prometheus", "loki", "grafana"):
            try:
                pid_proc = subprocess.run(
                    [podman_bin, "container", "inspect", "-f", "{{.State.Pid}}", container_name],
                    capture_output=True,
                    text=True,
                    timeout=4.0,
                    check=False,
                )
                pid = pid_proc.stdout.strip()
                if pid_proc.returncode == 0 and pid.isdigit() and int(pid) > 0:
                    rc, out_str = runner(
                        [podman_bin, "unshare", "nsenter", "-t", pid, "-n", "python3", "-c", _POD_HTTP_SCRIPT],
                        stdin_payload,
                        timeout,
                    )
                    if rc == 0 and out_str.strip():
                        parsed = json.loads(out_str)
                        return int(parsed["status"]), base64.b64decode(parsed.get("body_b64", ""))
            except (OSError, subprocess.SubprocessError, ValueError, KeyError):
                continue

    return 0, b""


def trigger_http_reload(url: str, timeout: float = 3.0) -> bool:
    """POST to Prometheus/Alertmanager/SNMP-Exporter /-/reload lifecycle endpoint (pod-netns aware)."""
    status, _ = pod_http_request(url, method="POST", data=b"", timeout=timeout)
    return 200 <= status < 300


def emit_validation_error_and_exit(exc: ValidationFailure) -> None:
    """Emit NS8 validation-failed status and structured JSON error list on stdout, exiting 2."""
    try:
        import agent  # type: ignore[import-not-found]

        agent.set_status("validation-failed")
    except ImportError:
        pass
    err_payload = [
        {
            "field": exc.field,
            "parameter": exc.field,
            "value": exc.value,
            "error": exc.code,
        }
    ]
    sys.stdout.write(json.dumps(err_payload) + "\n")
    sys.stdout.flush()
    sys.exit(2)
