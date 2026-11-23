#!/usr/bin/env python3
"""Standalone static, schema, and NethServer 8 architectural validator.

Validates the entire NS8-CentralMonitoringService monorepo using only the
Python 3 standard library plus `jsonschema` (Draft-07):
  1. Zero CRLF (\\r\\n) bytes and zero UTF-8 BOM across scripts, configs,
     Containerfiles, schemas, templates, rules, dashboards, Robot tests, UI,
     LICENSE, and docs (explicitly excluding binary assets such as `.png`).
  2. All JSON Schemas in `shared/schemas/` are valid self-contained Draft-07
     schemas with zero `get-status` overrides.
  3. Every action `validate-input.json` / `validate-output.json` in
     `hub/imageroot/actions/` and `collector/imageroot/actions/` (when present)
     matches its authoritative `shared/schemas/` counterpart.
  4. All 8 NethServer 8 Backend Rules (+ `%E/` XDG systemd specifier rule)
     across `hub/` and `collector/` (when present).
  5. All 3 NethServer 8 Cockpit UI Rules across `hub/ui/` and `collector/ui/`
     (when present).
  6. Grafana dashboard JSONs, standalone Alloy templates, and Prometheus rule
     packs have valid structure and balanced delimiters/placeholders.
  7. Root `LICENSE` (GPL-3.0), NS8 Software Center `metadata.json` & PNG icons
     (`module_default_icon.png`), and `scripts/generate-repomd.py` smoke test.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import ast
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import tempfile
import tokenize
from typing import Any
import zlib

import jsonschema

REPO_ROOT = Path(__file__).resolve().parent.parent

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

IGNORED_DIRS: frozenset[str] = frozenset({
    ".git",
    "node_modules",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "scratch",
    ".npm",
    "htmlcov",
    "_site",
    "repodata",
})

BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".gz",
    ".tar",
    ".zip",
    ".pdf",
})

TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".sh",
    ".py",
    ".yml",
    ".yaml",
    ".json",
    ".alloy",
    ".tmpl",
    ".vue",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".css",
    ".scss",
    ".html",
    ".md",
    ".service",
    ".timer",
    ".conf",
    ".toml",
    ".ini",
    ".prom",
    ".ps1",
    ".robot",
    ".txt",
})

TEXT_FILENAMES: frozenset[str] = frozenset({
    "Containerfile",
    "Dockerfile",
    "LICENSE",
    ".gitattributes",
    ".gitignore",
})

ALLOWED_ALLOY_PLACEHOLDERS: frozenset[str] = frozenset({
    "HUB_URL",
    "AUTH_TOKEN",
    "CUSTOMER",
    "SITE",
    "COLLECTOR_ID",
    "SYSLOG_PORT",
})

MANDATORY_NS8_UI_KEYS: tuple[str, ...] = (
    "action.list-installed-modules",
    "task.cannot_create_task",
    "error.cannot_retrieve_installed_modules",
    "error.cannot_retrieve_module_info",
)

EXPECTED_RULE_FILES: tuple[str, ...] = (
    "ns8-cluster.yml",
    "linux-node.yml",
    "windows-node.yml",
    "proxmox-ve.yml",
    "blackbox-web-ssl.yml",
    "snmp-network-ups.yml",
)

EXPECTED_DASHBOARD_FILES: tuple[str, ...] = (
    "ns8-multi-cluster-overview.json",
    "linux-windows-servers.json",
    "proxmox-snmp-infrastructure.json",
    "web-ssl-uptime.json",
)

EXPECTED_TEMPLATE_FILES: tuple[str, ...] = (
    "config-linux.alloy.tmpl",
    "config-windows.alloy.tmpl",
    "config-docker.alloy.tmpl",
    "install-linux.sh.tmpl",
    "install-windows.ps1.tmpl",
    "docker-compose.yml.tmpl",
)

LIFECYCLE_ONLY_ACTIONS: frozenset[str] = frozenset({
    "create-module",
    "restore-module",
    "clone-module",
    "destroy-module",
})


class ValidationReport:
    """Collects validation errors and summary statistics."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checked_counts: dict[str, int] = {}

    def error(self, category: str, message: str) -> None:
        self.errors.append(f"[{category}] {message}")

    def bump(self, key: str, count: int = 1) -> None:
        self.checked_counts[key] = self.checked_counts.get(key, 0) + count


def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def iter_repo_files(root: Path) -> list[Path]:
    results: list[Path] = []
    for path in sorted(root.rglob("*")):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            results.append(path)
    return results


def is_text_candidate(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return False
    if path.name in TEXT_FILENAMES or path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    parts = path.parts
    if "imageroot" in parts:
        idx = parts.index("imageroot")
        subparts = parts[idx + 1 :]
        if subparts and subparts[0] in {"actions", "bin", "events", "update-module.d", "etc", "systemd"}:
            return True
    return False


# ---------------------------------------------------------------------------
# 1. Line Endings (LF) & UTF-8 Validation
# ---------------------------------------------------------------------------


def _slice_source_span(
    lines: list[str],
    start: tuple[int, int],
    end: tuple[int, int],
) -> str:
    sline, scol = start
    eline, ecol = end
    if sline < 1 or eline > len(lines) or sline > eline:
        return ""
    if sline == eline:
        return lines[sline - 1][scol:ecol]
    chunks = [lines[sline - 1][scol:]]
    for mid in range(sline, eline - 1):
        chunks.append(lines[mid])
    chunks.append(lines[eline - 1][:ecol])
    return "".join(chunks)


def _scan_pep701_fstrings(text: str) -> list[str]:
    """Detect Python 3.12+ PEP 701 f-string constructs even when run on Python 3.12+."""
    fstring_start = getattr(tokenize, "FSTRING_START", None)
    fstring_middle = getattr(tokenize, "FSTRING_MIDDLE", None)
    fstring_end = getattr(tokenize, "FSTRING_END", None)
    if fstring_start is None:
        return []

    errors: list[str] = []
    lines = text.splitlines(keepends=True)
    stack: list[dict[str, Any]] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except tokenize.TokenError as exc:
        return [f"tokenize error: {exc}"]

    for tok in tokens:
        ttype, tstr, start_pos, end_pos, _ = tok
        sline = start_pos[0]

        if ttype == fstring_start:
            idx = 0
            while idx < len(tstr) and tstr[idx] not in ('"', "'"):
                idx += 1
            qpart = tstr[idx:]
            triple = len(qpart) == 3
            qchar = qpart[0] if qpart else '"'
            for outer in stack:
                if outer["expr_depth"] > 0:
                    outer_q = outer["quote"]
                    outer_qpart = outer_q * (3 if outer["triple"] else 1)
                    if qpart == outer_qpart or (not outer["triple"] and qchar == outer_q):
                        errors.append(
                            f"line {sline}: PEP 701 nested f-string reuses outer quote {outer_q!r}"
                        )
                        break
            stack.append(
                {
                    "quote": qchar,
                    "triple": triple,
                    "expr_depth": 0,
                    "expr_open_end": None,
                }
            )
            continue

        if ttype == fstring_end:
            if stack:
                stack.pop()
            continue

        if ttype == fstring_middle or not stack:
            continue

        top = stack[-1]
        if ttype == tokenize.OP and tstr == "{" and top["expr_depth"] == 0:
            top["expr_depth"] = 1
            top["expr_open_end"] = end_pos
            continue

        if top["expr_depth"] > 0:
            if ttype == tokenize.OP:
                if tstr in ("{", "(", "["):
                    top["expr_depth"] += 1
                elif tstr in ("}", ")", "]"):
                    top["expr_depth"] -= 1
                    if top["expr_depth"] == 0:
                        open_end = top.get("expr_open_end")
                        if open_end is not None:
                            raw_expr = _slice_source_span(lines, open_end, start_pos)
                            if "\\" in raw_expr:
                                open_line = open_end[0]
                                errors.append(
                                    f"line {open_line}: PEP 701 backslash inside f-string expression"
                                )
                        top["expr_open_end"] = None
                        continue

            if ttype == tokenize.COMMENT:
                errors.append(f"line {sline}: PEP 701 comment inside f-string expression")
            if ttype in (tokenize.NL, tokenize.NEWLINE) and not top["triple"]:
                errors.append(
                    f"line {sline}: PEP 701 newline inside single-quoted f-string expression"
                )
            if ttype == tokenize.STRING:
                idx = 0
                while idx < len(tstr) and tstr[idx] not in ('"', "'"):
                    idx += 1
                tail = tstr[idx:]
                qpart = tail[:3] if tail[:3] in ('"""', "'''") else tail[:1]
                qchar = qpart[0] if qpart else ""
                outer_q = top["quote"]
                if not top["triple"] and qchar == outer_q:
                    errors.append(
                        f"line {sline}: PEP 701 string literal inside f-string reuses outer quote {outer_q!r}"
                    )
                elif top["triple"] and qpart == outer_q * 3:
                    errors.append(
                        f"line {sline}: PEP 701 triple-quoted string inside f-string reuses outer triple quote"
                    )

    return errors


def _validate_python_39_compat(
    path: Path,
    text: str,
    root: Path,
    report: ValidationReport,
) -> None:
    """Enforce Rocky Linux 9 (/usr/bin/python3 = Python 3.9) grammar & runtime compatibility."""
    rel_path = rel(path, root)
    report.bump("py39_compat")

    try:
        tree = ast.parse(text, filename=rel_path, feature_version=(3, 9))
    except SyntaxError as exc:
        report.error("PY39-COMPAT", f"{rel_path}:{exc.lineno}: Python 3.9 syntax error: {exc.msg}")
        return

    for fstr_err in _scan_pep701_fstrings(text):
        report.error("PY39-COMPAT", f"{rel_path}: {fstr_err}")

    requires_future_annotations = (
        rel_path.startswith("hub/imageroot/")
        or rel_path.startswith("collector/imageroot/")
        or rel_path.startswith("hub/gateway/")
    )
    if requires_future_annotations:
        has_future_annotations = any(
            isinstance(stmt, ast.ImportFrom)
            and stmt.module == "__future__"
            and any(alias.name == "annotations" for alias in stmt.names)
            for stmt in tree.body
        )
        if not has_future_annotations:
            report.error(
                "PY39-COMPAT",
                f"{rel_path} must include 'from __future__ import annotations' for Python 3.9 runtime safety",
            )

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name == "dataclass" and any(kw.arg == "slots" for kw in node.keywords):
                report.error(
                    "PY39-COMPAT",
                    f"{rel_path}:{node.lineno}: forbidden dataclass(..., slots=...) (Python 3.10+ only)",
                )

            if isinstance(node.func, ast.Attribute) and node.func.attr == "write_text":
                if any(kw.arg == "newline" for kw in node.keywords):
                    report.error(
                        "PY39-COMPAT",
                        f"{rel_path}:{node.lineno}: forbidden Path.write_text(..., newline=...) (Python 3.10+ only)",
                    )

            if func_name == "zip" and any(kw.arg == "strict" for kw in node.keywords):
                report.error(
                    "PY39-COMPAT",
                    f"{rel_path}:{node.lineno}: forbidden zip(..., strict=...) (Python 3.10+ only)",
                )

            if func_name in ("isinstance", "issubclass") and len(node.args) >= 2:
                if any(
                    isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr)
                    for sub in ast.walk(node.args[1])
                ):
                    report.error(
                        "PY39-COMPAT",
                        f"{rel_path}:{node.lineno}: forbidden {func_name}(..., A | B) runtime union (use (A, B) tuple)",
                    )

        if (
            isinstance(node, ast.Attribute)
            and node.attr == "UTC"
            and isinstance(node.value, ast.Name)
            and node.value.id == "datetime"
        ):
            report.error(
                "PY39-COMPAT",
                f"{rel_path}:{node.lineno}: forbidden datetime.UTC (Python 3.11+ only; use timezone.utc)",
            )


def validate_line_endings_and_utf8(root: Path, report: ValidationReport) -> None:
    for path in iter_repo_files(root):
        if not is_text_candidate(path):
            continue
        raw = path.read_bytes()
        report.bump("lf_files")

        if raw.startswith(b"\xef\xbb\xbf"):
            report.error("UTF8-BOM", f"{rel(path, root)} starts with a UTF-8 BOM (must be UTF-8 without BOM)")

        if b"\r\n" in raw:
            report.error("CRLF", f"{rel(path, root)} contains Windows CRLF (\\r\\n) bytes (must use LF \\n)")
        elif b"\r" in raw:
            report.error("CR", f"{rel(path, root)} contains bare CR (\\r) bytes (must use LF \\n)")

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            report.error("UTF8", f"{rel(path, root)} is not valid UTF-8: {exc}")
            continue

        # In-memory Python syntax & Python 3.9 compatibility verification (never writes .pyc files)
        is_python = path.suffix == ".py" or text.startswith("#!/usr/bin/env python") or text.startswith("#!/usr/bin/python")
        if is_python:
            report.bump("python_ast")
            try:
                ast.parse(text, filename=rel(path, root))
            except SyntaxError as exc:
                report.error("PYTHON-SYNTAX", f"{rel(path, root)}:{exc.lineno}: {exc.msg}")
                continue
            _validate_python_39_compat(path, text, root, report)


# ---------------------------------------------------------------------------
# 2. JSON Schemas (`shared/schemas/`) & Action Schema Parity
# ---------------------------------------------------------------------------


def _collect_refs(node: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                refs.append(value)
            else:
                refs.extend(_collect_refs(value))
    elif isinstance(node, list):
        for item in node:
            refs.extend(_collect_refs(item))
    return refs


def validate_shared_schemas(root: Path, report: ValidationReport) -> dict[str, Any]:
    schemas_dir = root / "shared" / "schemas"
    parsed_schemas: dict[str, Any] = {}
    if not schemas_dir.is_dir():
        report.error("SCHEMAS", "shared/schemas/ directory is missing")
        return parsed_schemas

    schema_files = sorted(schemas_dir.glob("*.json"))
    if len(schema_files) < 47:
        report.error("SCHEMAS", f"Expected at least 47 schemas in shared/schemas/, found {len(schema_files)}")

    for path in schema_files:
        report.bump("shared_schemas")
        if "get-status" in path.name:
            report.error("NS8-RULE-1", f"{rel(path, root)} defines a forbidden get-status schema override")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            report.error("SCHEMAS", f"{rel(path, root)} invalid JSON: {exc}")
            continue

        if not isinstance(data, dict):
            report.error("SCHEMAS", f"{rel(path, root)} root must be a JSON object")
            continue

        schema_uri = data.get("$schema", "")
        if "draft-07" not in str(schema_uri):
            report.error("SCHEMAS", f"{rel(path, root)} must declare Draft-07 $schema, got {schema_uri!r}")

        try:
            jsonschema.Draft7Validator.check_schema(data)
        except jsonschema.exceptions.SchemaError as exc:
            report.error("SCHEMAS", f"{rel(path, root)} failed Draft7Validator.check_schema: {exc.message}")

        for ref_target in _collect_refs(data):
            if not ref_target.startswith("#/"):
                report.error(
                    "SCHEMAS",
                    f"{rel(path, root)} uses external $ref {ref_target!r} (NS8 requires self-contained Draft-07 schemas)",
                )

        parsed_schemas[path.name] = data

    return parsed_schemas


def validate_action_schema_sync(
    root: Path,
    parsed_schemas: dict[str, Any],
    report: ValidationReport,
    *,
    strict: bool,
) -> None:
    for mod_dir_name, schema_prefix in (("hub", "hub"), ("collector", "collector")):
        actions_dir = root / mod_dir_name / "imageroot" / "actions"
        if not actions_dir.is_dir():
            if strict:
                report.error("ACTIONS", f"Missing required directory {mod_dir_name}/imageroot/actions/")
            continue

        for action_dir in sorted(p for p in actions_dir.iterdir() if p.is_dir()):
            action_name = action_dir.name
            for direction in ("input", "output"):
                val_file = action_dir / f"validate-{direction}.json"
                if not val_file.is_file():
                    continue
                report.bump("action_schemas")
                try:
                    action_schema = json.loads(val_file.read_text(encoding="utf-8"))
                    jsonschema.Draft7Validator.check_schema(action_schema)
                except (json.JSONDecodeError, jsonschema.exceptions.SchemaError) as exc:
                    report.error("ACTIONS", f"{rel(val_file, root)} invalid Draft-07 schema: {exc}")
                    continue

                expected_name = f"{schema_prefix}-{action_name}-{direction}.json"
                if expected_name in parsed_schemas:
                    if action_schema != parsed_schemas[expected_name]:
                        report.error(
                            "SCHEMA-SYNC",
                            f"{rel(val_file, root)} diverges from shared/schemas/{expected_name}",
                        )
                elif action_name not in LIFECYCLE_ONLY_ACTIONS:
                    report.error(
                        "SCHEMA-SYNC",
                        f"{rel(val_file, root)} has no matching shared/schemas/{expected_name}",
                    )

        if strict:
            prefix_token = f"{schema_prefix}-"
            for schema_filename in sorted(parsed_schemas):
                if not schema_filename.startswith(prefix_token):
                    continue
                for suffix, direction in (("-input.json", "input"), ("-output.json", "output")):
                    if schema_filename.endswith(suffix):
                        act_name = schema_filename[len(prefix_token) : -len(suffix)]
                        expected_path = actions_dir / act_name / f"validate-{direction}.json"
                        if not expected_path.is_file():
                            report.error(
                                "SCHEMA-SYNC",
                                f"Missing {rel(expected_path, root)} for shared/schemas/{schema_filename}",
                            )


# ---------------------------------------------------------------------------
# 3. All 8 NethServer 8 Backend Rules (`hub/` & `collector/`)
# ---------------------------------------------------------------------------


def _ast_calls_attr(tree: ast.AST, attr_name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == attr_name:
                return True
            if isinstance(func, ast.Name) and func.id == attr_name:
                return True
    return False


def _strip_service_comments(content: str) -> str:
    lines = [
        line
        for line in content.splitlines()
        if not line.lstrip().startswith("#") and not line.lstrip().startswith(";")
    ]
    return "\n".join(lines)


def validate_ns8_backend_module(
    root: Path,
    mod_name: str,
    report: ValidationReport,
    *,
    has_traefik_route: bool,
    strict: bool,
) -> None:
    mod_root = root / mod_name
    imageroot = mod_root / "imageroot"
    containerfile = mod_root / "Containerfile"

    if not mod_root.exists():
        if strict:
            report.error("NS8-BACKEND", f"Module directory {mod_name}/ does not exist")
        return

    report.bump("ns8_backend_modules")

    # Rule #1: NEVER override imageroot/actions/get-status
    get_status_dir = imageroot / "actions" / "get-status"
    if get_status_dir.exists():
        report.error("NS8-RULE-1", f"{rel(get_status_dir, root)} must NEVER exist (overrides NS8 core get-status)")

    # Rule #2: ALWAYS call agent.dump_env() whenever agent.set_env() is used
    if imageroot.is_dir():
        for path in sorted(imageroot.rglob("*")):
            if not path.is_file() or path.suffix.lower() in BINARY_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            is_python = path.suffix == ".py" or text.startswith("#!/usr/bin/env python") or text.startswith("#!/usr/bin/python")
            if is_python:
                try:
                    tree = ast.parse(text, filename=rel(path, root))
                except SyntaxError:
                    continue
                if _ast_calls_attr(tree, "set_env") and not _ast_calls_attr(tree, "dump_env"):
                    report.error(
                        "NS8-RULE-2",
                        f"{rel(path, root)} calls set_env() without calling dump_env() in the same module/script",
                    )

    # Rule #4: Validate Traefik hostname collisions in configure-module/01hostname-validation
    if has_traefik_route:
        cfg_mod_dir = imageroot / "actions" / "configure-module"
        if cfg_mod_dir.is_dir():
            hostname_val = cfg_mod_dir / "01hostname-validation"
            if not hostname_val.is_file():
                if strict or (cfg_mod_dir / "20configure").is_file():
                    report.error(
                        "NS8-RULE-4",
                        f"Missing {rel(hostname_val, root)} for Traefik hostname collision validation",
                    )
            else:
                hv_text = hostname_val.read_text(encoding="utf-8")
                if "http_route_in_use" not in hv_text or "validation-failed" not in hv_text:
                    report.error(
                        "NS8-RULE-4",
                        f"{rel(hostname_val, root)} must check http_route_in_use and set status 'validation-failed'",
                    )

    # Rules #3, #5, #6: Systemd units (port binding, %E/ specifier, no --pull=always, restart & ordering)
    systemd_dir = imageroot / "systemd" / "user"
    if systemd_dir.is_dir():
        service_files = sorted(systemd_dir.glob("*.service"))
        if strict and not service_files:
            report.error("NS8-BACKEND", f"No .service files found in {rel(systemd_dir, root)}")

        found_localhost_tcp_port = False
        for svc_file in service_files:
            report.bump("systemd_units")
            active_text = _strip_service_comments(svc_file.read_text(encoding="utf-8"))

            # NS8 Systemd XDG Specifier Rule (ARCH-02 / ARCH-15): forbid %S/ (~/.local/state on systemd >= 252); require %E/ (~/.config)
            if "%S/" in active_text:
                report.error(
                    "NS8-SYSTEMD-SPECIFIER",
                    f"{rel(svc_file, root)} uses forbidden '%S/' specifier (resolves to ~/.local/state on systemd >= 252; use '%E/' for ~/.config)",
                )

            # Rule #5: Never use --pull=always
            if "--pull=always" in active_text or "--pull always" in active_text:
                report.error("NS8-RULE-5", f"{rel(svc_file, root)} uses forbidden --pull=always")

            # Rule #3: Host HTTP port bindings must strictly bind 127.0.0.1:${TCP_PORT}
            if "127.0.0.1:${TCP_PORT}" in active_text or "127.0.0.1:${TCP_PORT}:" in active_text:
                found_localhost_tcp_port = True

            if re.search(r"(?:--publish|-p)\s+(?:0\.0\.0\.0:)?\$\{?TCP_PORT\}?:", active_text):
                report.error(
                    "NS8-RULE-3",
                    f"{rel(svc_file, root)} publishes ${{TCP_PORT}} without mandatory 127.0.0.1: loopback bind",
                )

            if mod_name == "collector" and re.search(r"(?:--publish|-p)\s+(?!127\.0\.0\.1:)[^\s]*12345", active_text):
                report.error(
                    "NS8-RULE-3",
                    f"{rel(svc_file, root)} exposes internal Alloy HTTP port 12345 outside loopback",
                )

            # Rule #6: Detached container units (`podman run`) must configure restart policy
            is_oneshot = bool(re.search(r"^\s*Type\s*=\s*oneshot\b", active_text, flags=re.MULTILINE))
            if "podman run" in active_text and not is_oneshot:
                has_restart = (
                    "--restart=on-failure" in active_text
                    or bool(re.search(r"^\s*Restart\s*=\s*(?:on-failure|always)\b", active_text, flags=re.MULTILINE))
                )
                if not has_restart:
                    report.error(
                        "NS8-RULE-6",
                        f"{rel(svc_file, root)} runs a container without --restart=on-failure or systemd Restart=",
                    )

        if has_traefik_route and service_files and not found_localhost_tcp_port:
            report.error(
                "NS8-RULE-3",
                f"{rel(systemd_dir, root)} has no unit publishing 127.0.0.1:${{TCP_PORT}}",
            )

    elif strict:
        report.error("NS8-BACKEND", f"Missing systemd user unit directory {rel(systemd_dir, root)}")

    # Rule #7: Backup, Restore & Clone Support
    if containerfile.is_file() or strict:
        state_include = imageroot / "etc" / "state-include.conf"
        dump_state = imageroot / "bin" / "module-dump-state"
        restore_dir = imageroot / "actions" / "restore-module"
        clone_dir = imageroot / "actions" / "clone-module"
        update_dir = imageroot / "update-module.d"

        if not state_include.is_file() or not state_include.read_text(encoding="utf-8").strip():
            report.error("NS8-RULE-7", f"Missing or empty {rel(state_include, root)}")
        if not dump_state.is_file():
            report.error("NS8-RULE-7", f"Missing {rel(dump_state, root)}")
        if not restore_dir.is_dir() or not any(restore_dir.iterdir()):
            report.error("NS8-RULE-7", f"Missing or empty {rel(restore_dir, root)}")
        if not clone_dir.is_dir() or not any(clone_dir.iterdir()):
            report.error("NS8-RULE-7", f"Missing or empty {rel(clone_dir, root)}")
        if not update_dir.is_dir() or not any(update_dir.iterdir()):
            report.error("NS8-RULE-5", f"Missing or empty {rel(update_dir, root)} for image updates")

    # Rules #5 & #8: Containerfile labels, CRLF sanitization, and chmod +x
    if containerfile.is_file():
        cf_text = containerfile.read_text(encoding="utf-8")
        if "org.nethserver.images" not in cf_text:
            report.error("NS8-RULE-5", f"{rel(containerfile, root)} missing org.nethserver.images label")
        if not re.search(r"sed\s+-i.*\\r", cf_text):
            report.error(
                "NS8-RULE-8",
                f"{rel(containerfile, root)} missing CRLF stripping command (sed -i 's/\\r$//')",
            )
        if "chmod +x" not in cf_text and "chmod 755" not in cf_text and "chmod a+x" not in cf_text:
            report.error(
                "NS8-RULE-8",
                f"{rel(containerfile, root)} missing executable permission setup (chmod +x) on imageroot scripts",
            )
    elif strict:
        report.error("NS8-RULE-8", f"Missing {rel(containerfile, root)}")


# ---------------------------------------------------------------------------
# 4. All 3 NethServer 8 Cockpit UI Rules (`hub/ui/` & `collector/ui/`)
# ---------------------------------------------------------------------------


def _strip_js_and_html_comments(text: str) -> str:
    no_html = re.sub(r"<!--[\s\S]*?-->", "", text)
    no_block = re.sub(r"/\*[\s\S]*?\*/", "", no_html)
    no_line = re.sub(r"(?m)^\s*//.*$", "", no_block)
    return no_line


def _flatten_json_keys(obj: Any, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                keys.update(_flatten_json_keys(v, full))
            else:
                keys.add(full)
    return keys


def _extract_balanced_call_args(source: str, call_name: str) -> list[str]:
    results: list[str] = []
    pattern = re.compile(rf"\b{re.escape(call_name)}\s*\(")
    for match in pattern.finditer(source):
        idx = match.end()
        depth = 1
        in_str: str | None = None
        escaped = False
        buf: list[str] = []
        while idx < len(source) and depth > 0:
            ch = source[idx]
            if in_str:
                buf.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == in_str:
                    in_str = None
            else:
                if ch in ("'", '"', "`"):
                    in_str = ch
                    buf.append(ch)
                elif ch == "(":
                    depth += 1
                    buf.append(ch)
                elif ch == ")":
                    depth -= 1
                    if depth > 0:
                        buf.append(ch)
                else:
                    buf.append(ch)
            idx += 1
        if depth == 0:
            results.append("".join(buf))
    return results


def _count_top_level_args(arg_str: str) -> int:
    stripped = arg_str.strip()
    if not stripped:
        return 0
    count = 1
    depth = 0
    in_str: str | None = None
    escaped = False
    for ch in stripped:
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_str:
                in_str = None
        else:
            if ch in ("'", '"', "`"):
                in_str = ch
            elif ch in ("(", "[", "{"):
                depth += 1
            elif ch in (")", "]", "}"):
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                count += 1
    return count


def validate_ns8_ui_module(root: Path, mod_name: str, report: ValidationReport, *, strict: bool) -> None:
    ui_dir = root / mod_name / "ui"
    if not ui_dir.is_dir():
        if strict:
            report.error("NS8-UI", f"Missing UI directory {mod_name}/ui/")
        return

    report.bump("ns8_ui_modules")
    src_dir = ui_dir / "src"
    i18n_dir = ui_dir / "public" / "i18n"

    # Rules #1 & #2: Scan Vue & JS files
    if src_dir.is_dir():
        ui_files = sorted(list(src_dir.rglob("*.vue")) + list(src_dir.rglob("*.js")))
        for path in ui_files:
            report.bump("ui_source_files")
            raw_text = path.read_text(encoding="utf-8")
            clean_text = _strip_js_and_html_comments(raw_text)

            # UI Rule #1: Never call createSuccessNotificationForApp
            if re.search(r"\bcreateSuccessNotificationForApp\b", clean_text):
                report.error(
                    "NS8-UI-RULE-1",
                    f"{rel(path, root)} references forbidden non-existent method createSuccessNotificationForApp",
                )

            # UI Rule #1: createErrorNotificationForApp(err, message) takes 2 arguments
            for arg_str in _extract_balanced_call_args(clean_text, "createErrorNotificationForApp"):
                arg_count = _count_top_level_args(arg_str)
                if arg_count != 2:
                    report.error(
                        "NS8-UI-RULE-1",
                        f"{rel(path, root)} calls createErrorNotificationForApp with {arg_count} arg(s); expected 2",
                    )

            # UI Rule #2: Carbon Icons registration in .vue SFCs
            if path.suffix == ".vue":
                tmpl_match = re.search(r"<template[^>]*>([\s\S]*)</template>", raw_text)
                script_match = re.search(r"<script[^>]*>([\s\S]*?)</script>", raw_text)
                if tmpl_match and script_match:
                    template_body = re.sub(r"<!--[\s\S]*?-->", "", tmpl_match.group(1))
                    script_body = _strip_js_and_html_comments(script_match.group(1))

                    imported_icons = re.findall(
                        r"import\s+([A-Za-z0-9_]+)\s+from\s+['\"]@carbon/icons-vue/[^'\"]+['\"]",
                        script_body,
                    )
                    comp_block_match = re.search(r"components\s*:\s*\{([\s\S]*?)\}", script_body)
                    comp_block = comp_block_match.group(1) if comp_block_match else ""
                    data_block_match = re.search(r"data\s*\(\s*\)\s*\{([\s\S]*?)\n\s*\}", script_body)
                    data_block = data_block_match.group(1) if data_block_match else script_body

                    for icon_id in imported_icons:
                        used_as_tag = bool(re.search(rf"<\s*{re.escape(icon_id)}\b", template_body))
                        used_as_prop = bool(
                            re.search(rf"(?::icon|v-bind:icon)\s*=\s*['\"][^'\"]*\b{re.escape(icon_id)}\b", template_body)
                        )
                        if used_as_tag and not re.search(rf"\b{re.escape(icon_id)}\b", comp_block):
                            report.error(
                                "NS8-UI-RULE-2",
                                f"{rel(path, root)} uses <{icon_id} /> in <template> without registering it in components",
                            )
                        if used_as_prop and not re.search(rf"\b{re.escape(icon_id)}\b", data_block):
                            report.error(
                                "NS8-UI-RULE-2",
                                f"{rel(path, root)} binds :icon=\"{icon_id}\" without exposing {icon_id} in data()",
                            )

        # UI Rule #3: main.js loads en + de and configures fallbackLocale
        main_js = src_dir / "main.js"
        if main_js.is_file():
            main_text = main_js.read_text(encoding="utf-8")
            if "fallbackLocale" not in main_text or "en" not in main_text or "de" not in main_text:
                report.error(
                    "NS8-UI-RULE-3",
                    f"{rel(main_js, root)} must register both 'en' and 'de' locales with fallbackLocale: 'en'",
                )
        elif strict:
            report.error("NS8-UI-RULE-3", f"Missing {rel(main_js, root)}")

    # UI Rule #3: i18n en + de translation key parity & mandatory NS8 keys
    en_file = i18n_dir / "en" / "translation.json"
    de_file = i18n_dir / "de" / "translation.json"
    if en_file.is_file() or de_file.is_file() or strict:
        if not en_file.is_file():
            report.error("NS8-UI-RULE-3", f"Missing {rel(en_file, root)}")
        if not de_file.is_file():
            report.error("NS8-UI-RULE-3", f"Missing {rel(de_file, root)}")
        if en_file.is_file() and de_file.is_file():
            try:
                en_data = json.loads(en_file.read_text(encoding="utf-8"))
                de_data = json.loads(de_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                report.error("NS8-UI-RULE-3", f"Invalid i18n JSON in {mod_name}/ui: {exc}")
                return

            en_keys = _flatten_json_keys(en_data)
            de_keys = _flatten_json_keys(de_data)

            for req_key in MANDATORY_NS8_UI_KEYS:
                if req_key not in en_keys:
                    report.error("NS8-UI-RULE-3", f"{rel(en_file, root)} missing mandatory NS8 key {req_key!r}")
                if req_key not in de_keys:
                    report.error("NS8-UI-RULE-3", f"{rel(de_file, root)} missing mandatory NS8 key {req_key!r}")

            missing_in_de = sorted(en_keys - de_keys)
            missing_in_en = sorted(de_keys - en_keys)
            if missing_in_de:
                report.error(
                    "NS8-UI-RULE-3",
                    f"{rel(de_file, root)} missing {len(missing_in_de)} key(s) present in en: {missing_in_de[:5]}",
                )
            if missing_in_en:
                report.error(
                    "NS8-UI-RULE-3",
                    f"{rel(en_file, root)} missing {len(missing_in_en)} key(s) present in de: {missing_in_en[:5]}",
                )


# ---------------------------------------------------------------------------
# 5. Dashboards, Alloy Templates & Prometheus Alert Rule Packs
# ---------------------------------------------------------------------------


def _collect_dashboard_datasource_uids(node: Any) -> set[str]:
    uids: set[str] = set()
    if isinstance(node, dict):
        ds = node.get("datasource")
        if isinstance(ds, dict) and isinstance(ds.get("uid"), str):
            uids.add(ds["uid"])
        for value in node.values():
            uids.update(_collect_dashboard_datasource_uids(value))
    elif isinstance(node, list):
        for item in node:
            uids.update(_collect_dashboard_datasource_uids(item))
    return uids


def validate_dashboards(root: Path, report: ValidationReport) -> None:
    dash_dir = root / "shared" / "dashboards"
    if not dash_dir.is_dir():
        report.error("DASHBOARDS", "shared/dashboards/ directory is missing")
        return

    for expected in EXPECTED_DASHBOARD_FILES:
        if not (dash_dir / expected).is_file():
            report.error("DASHBOARDS", f"Missing required starter dashboard shared/dashboards/{expected}")

    allowed_ds_uids = {"prometheus", "loki", "-- Grafana --", "$datasource", "${datasource}"}
    for path in sorted(dash_dir.glob("*.json")):
        report.bump("dashboards")
        raw = path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            report.error("DASHBOARDS", f"{rel(path, root)} invalid JSON: {exc}")
            continue

        if not isinstance(data, dict):
            report.error("DASHBOARDS", f"{rel(path, root)} root must be a JSON object")
            continue

        schema_ver = data.get("schemaVersion", 0)
        if not isinstance(schema_ver, int) or schema_ver < 39:
            report.error("DASHBOARDS", f"{rel(path, root)} schemaVersion must be >= 39, got {schema_ver!r}")

        panels = data.get("panels")
        if not isinstance(panels, list) or not panels:
            report.error("DASHBOARDS", f"{rel(path, root)} must contain a non-empty panels list")

        templating_list = data.get("templating", {}).get("list", [])
        var_names = {v.get("name") for v in templating_list if isinstance(v, dict)}
        for req_var in ("customer", "site"):
            if req_var not in var_names:
                report.error("DASHBOARDS", f"{rel(path, root)} missing template variable '${req_var}'")

        ds_uids = _collect_dashboard_datasource_uids(panels)
        unknown_uids = sorted(ds_uids - allowed_ds_uids)
        if unknown_uids:
            report.error("DASHBOARDS", f"{rel(path, root)} uses non-canonical datasource UIDs: {unknown_uids}")

        for tok in ALLOWED_ALLOY_PLACEHOLDERS:
            if f"{{{{{tok}}}}}" in raw:
                report.error("DASHBOARDS", f"{rel(path, root)} contains unrendered Alloy placeholder {{{{{tok}}}}}")


def _check_alloy_river_balance(text: str) -> str | None:
    """Strip comments and strings from Alloy River config and verify balanced delimiters."""
    sanitized = re.sub(r"\{\{[A-Z0-9_]+\}\}", "placeholder", text)
    idx = 0
    n = len(sanitized)
    stack: list[tuple[str, int]] = []
    line = 1
    pairs = {"{": "}", "[": "]", "(": ")"}
    closing = {"}": "{", "]": "[", ")": "("}

    while idx < n:
        ch = sanitized[idx]
        nxt = sanitized[idx + 1] if idx + 1 < n else ""

        if ch == "\n":
            line += 1
            idx += 1
            continue

        if ch == "/" and nxt == "/":
            while idx < n and sanitized[idx] != "\n":
                idx += 1
            continue

        if ch == "/" and nxt == "*":
            idx += 2
            while idx + 1 < n and not (sanitized[idx] == "*" and sanitized[idx + 1] == "/"):
                if sanitized[idx] == "\n":
                    line += 1
                idx += 1
            if idx + 1 >= n:
                return "unclosed /* block comment"
            idx += 2
            continue

        if ch in ('"', "`"):
            quote = ch
            idx += 1
            while idx < n and sanitized[idx] != quote:
                if sanitized[idx] == "\\" and quote == '"':
                    idx += 2
                    continue
                if sanitized[idx] == "\n":
                    line += 1
                idx += 1
            if idx >= n:
                return f"unclosed {quote} string literal starting before EOF"
            idx += 1
            continue

        if ch in pairs:
            stack.append((ch, line))
        elif ch in closing:
            if not stack or stack[-1][0] != closing[ch]:
                return f"unexpected closing {ch!r} on line {line}"
            stack.pop()

        idx += 1

    if stack:
        opener, open_line = stack[-1]
        return f"unclosed {opener!r} opened on line {open_line}"
    return None


def validate_alloy_templates(root: Path, report: ValidationReport) -> None:
    tmpl_dir = root / "shared" / "alloy-templates"
    if not tmpl_dir.is_dir():
        report.error("TEMPLATES", "shared/alloy-templates/ directory is missing")
        return

    for expected in EXPECTED_TEMPLATE_FILES:
        if not (tmpl_dir / expected).is_file():
            report.error("TEMPLATES", f"Missing required template shared/alloy-templates/{expected}")

    for path in sorted(tmpl_dir.glob("*.tmpl")):
        report.bump("alloy_templates")
        text = path.read_text(encoding="utf-8")

        open_count = text.count("{{")
        close_count = text.count("}}")
        if open_count != close_count:
            report.error(
                "TEMPLATES",
                f"{rel(path, root)} has unbalanced '{{{{' ({open_count}) vs '}}}}' ({close_count}) delimiters",
            )

        tokens = re.findall(r"\{\{(.*?)\}\}", text)
        if not tokens:
            report.error("TEMPLATES", f"{rel(path, root)} contains zero '{{{{...}}}}' template placeholders")

        for tok in tokens:
            if tok not in ALLOWED_ALLOY_PLACEHOLDERS:
                report.error(
                    "TEMPLATES",
                    f"{rel(path, root)} uses unknown placeholder '{{{{{tok}}}}}' (allowed: {sorted(ALLOWED_ALLOY_PLACEHOLDERS)})",
                )

        if path.name.endswith(".alloy.tmpl"):
            balance_err = _check_alloy_river_balance(text)
            if balance_err:
                report.error("TEMPLATES", f"{rel(path, root)} River syntax delimiter error: {balance_err}")
            if "prometheus.remote_write" not in text or "loki.write" not in text:
                report.error(
                    "TEMPLATES",
                    f"{rel(path, root)} must include both prometheus.remote_write and loki.write blocks",
                )


def validate_alert_rules(root: Path, report: ValidationReport) -> None:
    rules_dir = root / "shared" / "rules"
    if not rules_dir.is_dir():
        report.error("RULES", "shared/rules/ directory is missing")
        return

    for expected in EXPECTED_RULE_FILES:
        if not (rules_dir / expected).is_file():
            report.error("RULES", f"Missing required Prometheus rule pack shared/rules/{expected}")

    for path in sorted(rules_dir.glob("*.yml")):
        report.bump("rule_packs")
        text = path.read_text(encoding="utf-8")
        if "groups:" not in text or "- alert:" not in text:
            report.error("RULES", f"{rel(path, root)} missing 'groups:' or '- alert:' definitions")
        for req_token in ("severity:", "category:", "summary:", "description:"):
            if req_token not in text:
                report.error("RULES", f"{rel(path, root)} missing required rule field {req_token!r}")


# ---------------------------------------------------------------------------
# 6. LICENSE, Software Center Metadata/PNG Icons & `generate-repomd.py` Check
# ---------------------------------------------------------------------------


def _validate_png_file(path: Path) -> str | None:
    raw = path.read_bytes()
    if len(raw) < 33 or not raw.startswith(PNG_SIGNATURE):
        return "invalid 8-byte PNG signature"
    offset = 8
    saw_ihdr = False
    saw_iend = False
    while offset + 8 <= len(raw):
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        ctype = raw[offset + 4 : offset + 8]
        data_end = offset + 8 + length
        crc_end = data_end + 4
        if crc_end > len(raw):
            return f"truncated PNG chunk {ctype!r}"
        cdata = raw[offset + 8 : data_end]
        expected_crc = struct.unpack(">I", raw[data_end:crc_end])[0]
        actual_crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            return f"CRC mismatch in PNG chunk {ctype!r}"
        if ctype == b"IHDR":
            if len(cdata) != 13:
                return "IHDR chunk length != 13"
            width, height = struct.unpack(">II", cdata[:8])
            if width <= 0 or height <= 0:
                return "IHDR dimensions must be > 0"
            saw_ihdr = True
        elif ctype == b"IEND":
            saw_iend = True
            break
        offset = crc_end
    if not saw_ihdr or not saw_iend:
        return "missing required IHDR or IEND chunk"
    return None


def validate_license_and_software_center(
    root: Path,
    report: ValidationReport,
    *,
    strict: bool,
) -> None:
    # 1. Root LICENSE (GPL-3.0)
    license_path = root / "LICENSE"
    if license_path.is_file():
        report.bump("license")
        lic_text = license_path.read_text(encoding="utf-8", errors="replace")
        if "GNU GENERAL PUBLIC LICENSE" not in lic_text or "Version 3" not in lic_text:
            report.error("LICENSE", "LICENSE must contain standard GNU GENERAL PUBLIC LICENSE Version 3 text")
    elif root == REPO_ROOT:
        report.error("LICENSE", "Missing root LICENSE file")

    # 2. Module Software Center metadata.json + module_default_icon.png
    for mod_name in ("hub", "collector"):
        public_dir = root / mod_name / "ui" / "public"
        if not public_dir.is_dir():
            continue

        meta_file = public_dir / "metadata.json"
        icon_file = public_dir / "module_default_icon.png"

        if meta_file.is_file():
            report.bump("module_metadata")
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                report.error("SOFTWARE-CENTER", f"{rel(meta_file, root)} invalid JSON: {exc}")
                meta = None
            if isinstance(meta, dict):
                if not isinstance(meta.get("name"), str) or not meta["name"].strip():
                    report.error("SOFTWARE-CENTER", f"{rel(meta_file, root)} missing non-empty 'name'")
                desc = meta.get("description")
                if not isinstance(desc, dict) or not str(desc.get("en") or "").strip() or not str(desc.get("de") or "").strip():
                    report.error("SOFTWARE-CENTER", f"{rel(meta_file, root)} must include non-empty description.en and description.de")
                cats = meta.get("categories")
                if not isinstance(cats, list) or not cats:
                    report.error("SOFTWARE-CENTER", f"{rel(meta_file, root)} must include a non-empty 'categories' list")
                docs = meta.get("docs")
                if not isinstance(docs, dict) or not all(str(docs.get(k) or "").strip() for k in ("documentation_url", "bug_url", "code_url")):
                    report.error(
                        "SOFTWARE-CENTER",
                        f"{rel(meta_file, root)} must include docs.documentation_url, docs.bug_url, and docs.code_url",
                    )
            elif meta is not None:
                report.error("SOFTWARE-CENTER", f"{rel(meta_file, root)} root must be a JSON object")
        elif strict:
            report.error("SOFTWARE-CENTER", f"Missing {rel(meta_file, root)}")

        if icon_file.is_file():
            report.bump("module_icons")
            png_err = _validate_png_file(icon_file)
            if png_err:
                report.error("SOFTWARE-CENTER", f"{rel(icon_file, root)} invalid PNG: {png_err}")
        elif strict:
            report.error("SOFTWARE-CENTER", f"Missing {rel(icon_file, root)}")

    # 3. Smoke-test scripts/generate-repomd.py when present
    repomd_script = root / "scripts" / "generate-repomd.py"
    if repomd_script.is_file():
        report.bump("repomd_smoke")
        try:
            spec = importlib.util.spec_from_file_location("_ns8_gen_repomd", repomd_script)
            if spec is None or spec.loader is None:
                raise RuntimeError("Unable to load scripts/generate-repomd.py module spec")
            mod = importlib.util.module_from_spec(spec)
            sys.modules["_ns8_gen_repomd"] = mod
            spec.loader.exec_module(mod)
            with tempfile.TemporaryDirectory() as tmp_out:
                out_path = Path(tmp_out) / "pages"
                catalog = mod.generate_repository(
                    root=root,
                    org="msp-example",
                    tag="v1.2.3",
                    output_dir=out_path,
                    strict_assets=strict,
                )
                if len(catalog) != 2:
                    report.error("REPOMD", f"generate-repomd.py produced {len(catalog)} modules; expected 2")
                for idx_file in (out_path / "repodata.json", out_path / "repomd.json", out_path / "repodata" / "repomd.json"):
                    if not idx_file.is_file():
                        report.error("REPOMD", f"generate-repomd.py failed to emit {idx_file.name}")
                    else:
                        parsed = json.loads(idx_file.read_text(encoding="utf-8"))
                        if not isinstance(parsed, list) or len(parsed) != 2:
                            report.error("REPOMD", f"{idx_file.name} must contain 2 catalog entries")
                for mod_id in ("central-monitoring-hub", "central-monitoring-collector"):
                    logo_path = out_path / mod_id / "logo.png"
                    if not logo_path.is_file() or _validate_png_file(logo_path) is not None:
                        report.error("REPOMD", f"generate-repomd.py produced missing/invalid PNG for {mod_id}")
        except Exception as exc:
            report.error("REPOMD", f"scripts/generate-repomd.py smoke test failed: {exc}")
    elif root == REPO_ROOT:
        report.error("REPOMD", "Missing scripts/generate-repomd.py")


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


def run_validation(root: Path, *, strict: bool = False) -> ValidationReport:
    report = ValidationReport()
    validate_line_endings_and_utf8(root, report)
    parsed_schemas = validate_shared_schemas(root, report)
    validate_action_schema_sync(root, parsed_schemas, report, strict=strict)
    validate_ns8_backend_module(root, "hub", report, has_traefik_route=True, strict=strict)
    validate_ns8_backend_module(root, "collector", report, has_traefik_route=False, strict=strict)
    validate_ns8_ui_module(root, "hub", report, strict=strict)
    validate_ns8_ui_module(root, "collector", report, strict=strict)
    validate_dashboards(root, report)
    validate_alloy_templates(root, report)
    validate_alert_rules(root, report)
    validate_license_and_software_center(root, report, strict=strict)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate NS8-CentralMonitoringService LF endings, Draft-07 schemas, NS8 rules, UI rules, Software Center catalog, and observability packs."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Path to monorepo root (defaults to repository root).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Require both hub/ and collector/ modules, UIs, Software Center icons/metadata, and all action schemas to be completely present.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    report = run_validation(root, strict=args.strict)

    summary_parts = [f"{k}={v}" for k, v in sorted(report.checked_counts.items())]
    print(f"Monorepo validation scan ({', '.join(summary_parts)})")

    if report.errors:
        print(f"\nFAILED with {len(report.errors)} validation error(s):", file=sys.stderr)
        for err in report.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("OK: All LF line-ending, JSON Schema Draft-07, NS8 Backend/UI, Software Center, Dashboard, Template, and Rule checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
