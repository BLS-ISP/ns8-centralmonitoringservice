"""Pod-aware loopback HTTP helper bridging host NS8 actions into the slirp4netns pod."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

_IN_POD_HTTP_SCRIPT = (
    "import base64,json,sys,urllib.error,urllib.request\n"
    "req_doc=json.loads(sys.stdin.read())\n"
    "raw_body=base64.b64decode(req_doc['body_b64']) if req_doc.get('body_b64') else None\n"
    "req=urllib.request.Request(req_doc['url'],data=raw_body,headers=req_doc.get('headers') or {},method=req_doc.get('method','GET'))\n"
    "try:\n"
    " with urllib.request.urlopen(req,timeout=float(req_doc.get('timeout',2.0))) as r:\n"
    "  sys.stdout.write(json.dumps({'status':r.status,'body':r.read().decode('utf-8','replace')}))\n"
    "except urllib.error.HTTPError as e:\n"
    " sys.stdout.write(json.dumps({'status':e.code,'body':e.read().decode('utf-8','replace')}))\n"
)


def _is_loopback_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return (parsed.hostname or "").strip().lower() in ("127.0.0.1", "localhost", "::1")


def _parse_pod_stdout(stdout_text: str) -> tuple[int, bytes] | None:
    stripped = stdout_text.strip()
    if not stripped:
        return None
    try:
        doc = json.loads(stripped)
        status = int(doc["status"])
        body_bytes = str(doc.get("body", "")).encode("utf-8")
        return status, body_bytes
    except (ValueError, KeyError, TypeError):
        return None


def pod_http_request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 2.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[int, bytes] | None:
    """Perform an internal loopback HTTP request, falling back to the Podman pod netns."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - strictly internal pod loopback
            return resp.status, resp.read()
    except urllib.error.HTTPError as http_err:
        return http_err.code, http_err.read()
    except (OSError, urllib.error.URLError, TimeoutError):
        pass

    if not _is_loopback_url(url) or shutil.which("podman") is None:
        return None

    payload_json = json.dumps(
        {
            "url": url,
            "method": method,
            "headers": headers or {},
            "body_b64": base64.b64encode(data).decode("ascii") if data is not None else None,
            "timeout": timeout,
        }
    )

    try:
        exec_proc = runner(
            ["podman", "exec", "-i", "hub-gateway", "python3", "-c", _IN_POD_HTTP_SCRIPT],
            input=payload_json,
            capture_output=True,
            text=True,
            timeout=max(4.0, timeout + 2.0),
            check=False,
        )
        if exec_proc.returncode == 0:
            parsed_res = _parse_pod_stdout(exec_proc.stdout)
            if parsed_res is not None:
                return parsed_res

        infra_proc = runner(
            ["podman", "pod", "inspect", "--format", "{{.InfraContainerID}}", "central-monitoring-hub"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        infra_id = infra_proc.stdout.strip()
        if infra_proc.returncode == 0 and infra_id:
            pid_proc = runner(
                ["podman", "inspect", "--format", "{{.State.Pid}}", infra_id],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            pid = pid_proc.stdout.strip()
            if pid_proc.returncode == 0 and pid.isdigit() and int(pid) > 0:
                ns_proc = runner(
                    ["podman", "unshare", "nsenter", "-t", pid, "-n", "python3", "-c", _IN_POD_HTTP_SCRIPT],
                    input=payload_json,
                    capture_output=True,
                    text=True,
                    timeout=max(4.0, timeout + 2.0),
                    check=False,
                )
                if ns_proc.returncode == 0:
                    return _parse_pod_stdout(ns_proc.stdout)
    except (OSError, subprocess.SubprocessError):
        return None

    return None


def pod_fetch_json(
    url: str,
    *,
    timeout: float = 1.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any] | None:
    """Fetch and parse a JSON object from an internal pod HTTP endpoint."""
    res = pod_http_request(url, method="GET", timeout=timeout, runner=runner)
    if res is None:
        return None
    status, raw_bytes = res
    if status != 200:
        return None
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
