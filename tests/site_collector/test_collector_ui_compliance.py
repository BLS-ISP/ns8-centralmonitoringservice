"""NS8 Cockpit UI compliance, i18n key parity, build output, and LF line-ending tests."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tests.site_collector.conftest import COLLECTOR_ROOT, REPO_ROOT

UI_ROOT = COLLECTOR_ROOT / "ui"
MANDATORY_NS8_I18N_KEYS = (
    "action.list-installed-modules",
    "task.cannot_create_task",
    "error.cannot_retrieve_installed_modules",
    "error.cannot_retrieve_module_info",
)


def _flatten_keys(node: Any, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            full = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(_flatten_keys(v, full))
            else:
                out.add(full)
    return out


def _count_call_args(source: str, fn_name: str) -> list[int]:
    counts: list[int] = []
    for match in re.finditer(rf"\b{re.escape(fn_name)}\s*\(", source):
        idx = match.end()
        depth = 1
        in_str: str | None = None
        esc = False
        buf: list[str] = []
        while idx < len(source) and depth > 0:
            ch = source[idx]
            if in_str:
                buf.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
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

        inner = "".join(buf).strip()
        if not inner:
            counts.append(0)
            continue
        arg_count = 1
        d = 0
        s: str | None = None
        e = False
        for c in inner:
            if s:
                if e:
                    e = False
                elif c == "\\":
                    e = True
                elif c == s:
                    s = None
            else:
                if c in ("'", '"', "`"):
                    s = c
                elif c in ("(", "[", "{"):
                    d += 1
                elif c in (")", "]", "}"):
                    d = max(0, d - 1)
                elif c == "," and d == 0:
                    arg_count += 1
        counts.append(arg_count)
    return counts


def test_ui_structure_and_package_metadata() -> None:
    pkg_path = UI_ROOT / "package.json"
    assert pkg_path.is_file()
    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))

    deps = pkg.get("dependencies", {})
    dev_deps = pkg.get("devDependencies", {})
    assert deps.get("vue", "").startswith("^2.7")
    assert "@nethserver/ns8-ui-lib" in deps
    assert "@carbon/vue" in deps
    assert "@carbon/icons-vue" in deps
    assert "vue-i18n" in deps
    assert dev_deps.get("@vue/cli-service", "").startswith("^5.")

    for rel_file in (
        "vue.config.js",
        "public/index.html",
        "public/config.json",
        "src/main.js",
        "src/App.vue",
        "src/router/index.js",
        "src/store/index.js",
        "src/views/Status.vue",
        "src/views/LocalTargets.vue",
        "src/views/Settings.vue",
        "src/views/About.vue",
    ):
        assert (UI_ROOT / rel_file).is_file(), f"Missing UI file: {rel_file}"


def test_ns8_ui_rules_notifications_icons_and_xss_safety() -> None:
    src_files = sorted(list((UI_ROOT / "src").rglob("*.vue")) + list((UI_ROOT / "src").rglob("*.js")))
    assert len(src_files) >= 7

    for path in src_files:
        text = path.read_text(encoding="utf-8")
        # NS8 UI Rule 1: Never call createSuccessNotificationForApp
        assert "createSuccessNotificationForApp" not in text, (
            f"{path} must never reference createSuccessNotificationForApp"
        )
        # NS8 UI Rule 1: createErrorNotificationForApp takes 2 arguments
        for arg_count in _count_call_args(text, "createErrorNotificationForApp"):
            assert arg_count == 2, f"{path} calls createErrorNotificationForApp with {arg_count} args"

        if path.suffix == ".vue":
            # XSS safety: forbid v-html
            assert "v-html" not in text, f"{path} must not use v-html"

            tmpl_m = re.search(r"<template[^>]*>([\s\S]*)</template>", text)
            script_m = re.search(r"<script[^>]*>([\s\S]*?)</script>", text)
            assert tmpl_m and script_m, f"{path} missing <template> or <script>"
            tmpl = tmpl_m.group(1)
            script = script_m.group(1)

            imported_icons = re.findall(
                r"import\s+([A-Za-z0-9_]+)\s+from\s+['\"]@carbon/icons-vue/[^'\"]+['\"]",
                script,
            )
            comp_m = re.search(r"components\s*:\s*\{([\s\S]*?)\}", script)
            comp_body = comp_m.group(1) if comp_m else ""
            data_m = re.search(r"data\s*\(\s*\)\s*\{([\s\S]*?)\n\s*\}", script)
            data_body = data_m.group(1) if data_m else ""

            # NS8 UI Rule 2: Carbon Icons registration
            for icon_id in imported_icons:
                if re.search(rf"<\s*{re.escape(icon_id)}\b", tmpl):
                    assert re.search(rf"\b{re.escape(icon_id)}\b", comp_body), (
                        f"{path} renders <{icon_id} /> without registering it in components"
                    )
                if re.search(rf":icon\s*=\s*['\"]\s*{re.escape(icon_id)}\s*['\"]", tmpl):
                    assert re.search(rf"\b{re.escape(icon_id)}\b", data_body), (
                        f"{path} passes :icon=\"{icon_id}\" without exposing it in data()"
                    )


def test_ns8_ui_rule3_i18n_parity_and_referenced_keys_exist() -> None:
    main_js = (UI_ROOT / "src" / "main.js").read_text(encoding="utf-8")
    assert "fallbackLocale" in main_js
    assert "enMessages" in main_js and "deMessages" in main_js

    en_data = json.loads((UI_ROOT / "public" / "i18n" / "en" / "translation.json").read_text(encoding="utf-8"))
    de_data = json.loads((UI_ROOT / "public" / "i18n" / "de" / "translation.json").read_text(encoding="utf-8"))

    en_keys = _flatten_keys(en_data)
    de_keys = _flatten_keys(de_data)
    assert en_keys == de_keys, f"i18n key mismatch: en-de={en_keys - de_keys}, de-en={de_keys - en_keys}"

    for req_key in MANDATORY_NS8_I18N_KEYS:
        assert req_key in en_keys, f"Missing mandatory NS8 key {req_key}"

    # Every static $t('key.path') referenced in Vue views must exist in translation.json
    for vue_file in (UI_ROOT / "src").rglob("*.vue"):
        content = vue_file.read_text(encoding="utf-8")
        for key_match in re.findall(r"\$t\(\s*['\"]([a-zA-Z0-9_.-]+)['\"]", content):
            assert key_match in en_keys, f"{vue_file.name} references missing i18n key {key_match!r}"


def test_views_wire_all_collector_actions_and_dist_bundle_exists() -> None:
    status_vue = (UI_ROOT / "src" / "views" / "Status.vue").read_text(encoding="utf-8")
    assert "get-status" in status_vue
    assert "get-configuration" in status_vue

    targets_vue = (UI_ROOT / "src" / "views" / "LocalTargets.vue").read_text(encoding="utf-8")
    for act in ("list-local-targets", "save-local-target", "delete-local-target"):
        assert act in targets_vue

    settings_vue = (UI_ROOT / "src" / "views" / "Settings.vue").read_text(encoding="utf-8")
    for act in ("get-configuration", "configure-module", "test-hub-connection"):
        assert act in settings_vue

    dist_index = UI_ROOT / "dist" / "index.html"
    assert dist_index.is_file(), "collector/ui/dist/index.html missing — run npm --prefix collector/ui run build"


def test_zero_crlf_across_collector_and_site_collector_tests() -> None:
    ignored = {"node_modules", ".git", "__pycache__", ".pytest_cache"}
    binary_exts = {".png", ".ico", ".woff", ".woff2", ".ttf", ".jpg", ".jpeg", ".gif", ".webp"}
    text_exts = {
        ".py",
        ".sh",
        ".json",
        ".yml",
        ".yaml",
        ".alloy",
        ".vue",
        ".js",
        ".css",
        ".scss",
        ".html",
        ".conf",
        ".service",
        ".timer",
        ".robot",
    }
    bad_files: list[str] = []
    for base in (COLLECTOR_ROOT, REPO_ROOT / "tests" / "site_collector"):
        for p in base.rglob("*"):
            if any(part in ignored for part in p.parts) or not p.is_file():
                continue
            if p.suffix.lower() in binary_exts:
                continue
            if p.suffix.lower() in text_exts or p.name == "Containerfile" or "imageroot" in p.parts:
                raw = p.read_bytes()
                if b"\r\n" in raw or raw.startswith(b"\xef\xbb\xbf"):
                    bad_files.append(str(p.relative_to(REPO_ROOT)))

    assert not bad_files, f"CRLF or UTF-8 BOM detected in files: {bad_files}"
