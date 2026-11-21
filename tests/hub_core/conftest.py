"""Shared pytest fixtures and NS8 agent double for hub-core tests."""

from __future__ import annotations

import io
import json
import os
import runpy
import sys
import types
from pathlib import Path
from typing import Any

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_ROOT = REPO_ROOT / "hub"
IMAGEROOT = HUB_ROOT / "imageroot"
PYPKG_DIR = IMAGEROOT / "pypkg"
SCHEMAS_DIR = REPO_ROOT / "shared" / "schemas"


class FakeRedis:
    """In-memory Redis stub supporting NS8 cluster/smarthost discovery."""

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self.hashes: dict[str, dict[str, str]] = data or {
            "cluster/smarthost": {
                "host": "mail.msp.internal",
                "port": "587",
                "username": "alerts@msp.internal",
                "password": "smtp-secret-value",
                "encrypt_smtp": "starttls",
                "tls_verify": "1",
            }
        }

    def hgetall(self, key: str) -> dict[str, str]:
        return dict(self.hashes.get(key, {}))

    def get(self, key: str) -> str | None:
        val = self.hashes.get(key)
        return str(val) if isinstance(val, str) else None


class FakeLdapproxy:
    """In-memory NS8 Ldapproxy stub."""

    domains: dict[str, dict[str, Any]] = {
        "ad.msp.example.com": {
            "host": "10.0.2.2",
            "port": "20001",
            "schema": "ad",
            "base_dn": "DC=ad,DC=msp,DC=example,DC=com",
            "bind_dn": "CN=ldapservice,CN=Users,DC=ad,DC=msp,DC=example,DC=com",
            "bind_password": "ldap-bind-secret",
            "tls": False,
        }
    }

    def get_domains_list(self) -> list[str]:
        return sorted(self.domains.keys())

    def get_domain(self, name: str) -> dict[str, Any]:
        if name not in self.domains:
            raise KeyError(f"Unknown LDAP domain: {name}")
        return dict(self.domains[name])


class FakeNS8Env:
    """Authentic NS8 environment test double enforcing explicit agent.dump_env()."""

    def __init__(self, install_dir: Path) -> None:
        self.install_dir = install_dir
        self.state_dir = install_dir / "state"
        self.config_dir = install_dir / "config"
        self.etc_dir = install_dir / "etc"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.etc_dir.mkdir(parents=True, exist_ok=True)

        self.env_file = self.state_dir / "environment"
        self.pending_env: dict[str, str] = {}
        self.persisted_env: dict[str, str] = {}
        self.call_log: list[tuple[str, Any]] = []
        self.status: str = "running"
        self.routes_in_use: set[str] = set()
        self.task_calls: list[dict[str, Any]] = []
        self.helper_calls: list[tuple[str, ...]] = []
        self.systemctl_state: dict[str, str] = {}
        self.redis = FakeRedis()

        # Seed standard NS8 module variables
        initial = {
            "MODULE_ID": "central-monitoring-hub1",
            "NODE_ID": "1",
            "TCP_PORT": "20080",
            "AGENT_ID": "module/central-monitoring-hub1",
            "AGENT_STATE_DIR": str(self.state_dir),
            "AGENT_INSTALL_DIR": str(self.install_dir),
            "HUB_CONFIG_DIR": str(self.config_dir),
            "HUB_ETC_DIR": str(self.etc_dir),
        }
        self.persisted_env.update(initial)
        self.pending_env.update(initial)
        self._write_env_file(self.persisted_env)

    def _write_env_file(self, mapping: dict[str, str]) -> None:
        lines = [f"{k}={v}" for k, v in sorted(mapping.items())]
        self.env_file.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))

    def set_env(self, key: str, value: Any) -> None:
        str_val = str(value)
        self.pending_env[key] = str_val
        os.environ[key] = str_val
        self.call_log.append(("set_env", (key, str_val)))

    def unset_env(self, key: str) -> None:
        self.pending_env.pop(key, None)
        os.environ.pop(key, None)
        self.call_log.append(("unset_env", key))

    def dump_env(self) -> None:
        self.persisted_env = dict(self.pending_env)
        self._write_env_file(self.persisted_env)
        self.call_log.append(("dump_env", dict(self.persisted_env)))

    def read_envfile(self, path: str | Path) -> dict[str, str]:
        p = Path(path)
        if not p.exists():
            return {}
        result: dict[str, str] = {}
        for raw_line in p.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                v = v[1:-1]
            result[k.strip()] = v
        return result

    def http_route_in_use(self, domain: str) -> bool:
        normalized = domain.strip().lower()
        self.call_log.append(("http_route_in_use", normalized))
        return normalized in self.routes_in_use

    def set_status(self, status: str) -> None:
        self.status = status
        self.call_log.append(("set_status", status))

    def resolve_agent_id(self, name: str) -> str:
        if name.startswith("traefik@"):
            return "module/traefik1"
        return f"module/{name}"

    def run_helper(self, *args: Any, **kwargs: Any) -> Any:
        str_args = tuple(str(a) for a in args)
        self.helper_calls.append(str_args)
        self.call_log.append(("run_helper", str_args))
        if len(str_args) >= 3 and str_args[0] == "systemctl" and str_args[1] == "--user":
            verb = str_args[2]
            for unit in str_args[3:]:
                if unit.startswith("-"):
                    continue
                if verb in ("enable", "start", "restart", "reload-or-restart"):
                    self.systemctl_state[unit] = "active"
                elif verb in ("disable", "stop"):
                    self.systemctl_state[unit] = "inactive"

        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        return Completed()

    def tasks_run(self, agent_id: str, action: str, data: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        entry = {"agent_id": agent_id, "action": action, "data": data or {}}
        self.task_calls.append(entry)
        self.call_log.append(("tasks.run", entry))
        return {"exit_code": 0, "output": {"status": "ok"}, "error": ""}


@pytest.fixture()
def ns8_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeNS8Env:
    """Install isolated NS8 agent module & environment for a single test."""
    fake = FakeNS8Env(tmp_path / "module_home")

    if str(PYPKG_DIR) not in sys.path:
        monkeypatch.syspath_prepend(str(PYPKG_DIR))

    for k, v in fake.persisted_env.items():
        monkeypatch.setenv(k, v)

    # Clear optional variables from outer environment
    for key in (
        "CONFIGURED",
        "TRAEFIK_HOST",
        "TRAEFIK_LETS_ENCRYPT",
        "TRAEFIK_HTTP2HTTPS",
        "STORAGE_MODE",
        "PROMQL_UPSTREAM_URL",
        "PROMETHEUS_EXTRA_ARGS",
        "BACKUP_INCLUDE_TSDB",
        "S3_ENDPOINT",
        "S3_BUCKET",
        "S3_REGION",
        "S3_ACCESS_KEY",
        "S3_INSECURE",
        "S3_PATH_STYLE",
        "LDAP_ENABLED",
        "LDAP_DOMAIN",
        "LDAP_ADMIN_GROUP",
        "LDAP_EDITOR_GROUP",
    ):
        monkeypatch.delenv(key, raising=False)

    agent_mod = types.ModuleType("agent")
    tasks_mod = types.ModuleType("agent.tasks")
    ldapproxy_mod = types.ModuleType("agent.ldapproxy")

    tasks_mod.run = fake.tasks_run  # type: ignore[attr-defined]
    ldapproxy_mod.Ldapproxy = FakeLdapproxy  # type: ignore[attr-defined]

    agent_mod.set_env = fake.set_env  # type: ignore[attr-defined]
    agent_mod.unset_env = fake.unset_env  # type: ignore[attr-defined]
    agent_mod.dump_env = fake.dump_env  # type: ignore[attr-defined]
    agent_mod.read_envfile = fake.read_envfile  # type: ignore[attr-defined]
    agent_mod.http_route_in_use = fake.http_route_in_use  # type: ignore[attr-defined]
    agent_mod.set_status = fake.set_status  # type: ignore[attr-defined]
    agent_mod.resolve_agent_id = fake.resolve_agent_id  # type: ignore[attr-defined]
    agent_mod.run_helper = fake.run_helper  # type: ignore[attr-defined]
    agent_mod.redis_connect = lambda *a, **kw: fake.redis  # type: ignore[attr-defined]
    agent_mod.tasks = tasks_mod  # type: ignore[attr-defined]
    agent_mod.ldapproxy = ldapproxy_mod  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "agent", agent_mod)
    monkeypatch.setitem(sys.modules, "agent.tasks", tasks_mod)
    monkeypatch.setitem(sys.modules, "agent.ldapproxy", ldapproxy_mod)
    return fake


def load_schema(schema_filename: str) -> dict[str, Any]:
    path = SCHEMAS_DIR / schema_filename
    return json.loads(path.read_text(encoding="utf-8"))


def validate_against_schema(schema_filename: str, payload: Any) -> None:
    schema = load_schema(schema_filename)
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
    assert not errors, f"Schema {schema_filename} validation failed: {[e.message for e in errors]}"


def execute_script(
    script_path: Path,
    payload: dict[str, Any] | None = None,
) -> tuple[int, str, str]:
    """Execute a Python NS8 action/bin/event script in-process, capturing stdout/stderr/exit code."""
    stdin_buf = io.StringIO(json.dumps(payload) if payload is not None else "{}")
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    old_stdin, old_stdout, old_stderr = sys.stdin, sys.stdout, sys.stderr
    old_argv = sys.argv[:]
    sys.stdin, sys.stdout, sys.stderr = stdin_buf, stdout_buf, stderr_buf
    sys.argv = [str(script_path)]
    exit_code = 0
    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as exc:
        if exc.code is None:
            exit_code = 0
        elif isinstance(exc.code, int):
            exit_code = exc.code
        else:
            exit_code = 1
    finally:
        sys.stdin, sys.stdout, sys.stderr = old_stdin, old_stdout, old_stderr
        sys.argv = old_argv

    return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()
