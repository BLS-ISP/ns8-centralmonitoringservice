"""Static architectural audit enforcing all 8 NS8 Backend Rules, LF line endings, and schema parity."""

from __future__ import annotations

import json
from pathlib import Path

from tests.hub_core.conftest import HUB_ROOT, IMAGEROOT, PYPKG_DIR, REPO_ROOT, SCHEMAS_DIR

EXPECTED_SYSTEMD_UNITS = {
    "central-monitoring-hub.service",
    "prometheus.service",
    "loki.service",
    "alertmanager.service",
    "grafana.service",
    "prom-label-proxy.service",
    "blackbox-exporter.service",
    "snmp-exporter.service",
    "hub-gateway.service",
    "thanos-sidecar.service",
    "thanos-store.service",
    "thanos-query.service",
}

EXPECTED_PINNED_IMAGE_REPOS = [
    "central-monitoring-hub-gateway",
    "quay.io/prometheus/prometheus:v2.54.1",
    "quay.io/prometheus/alertmanager:v0.27.0",
    "docker.io/grafana/loki:3.1.1",
    "docker.io/grafana/grafana-oss:11.2.2",
    "quay.io/prometheuscommunity/prom-label-proxy:v0.11.0",
    "quay.io/prometheus/blackbox-exporter:v0.25.0",
    "quay.io/prometheus/snmp-exporter:v0.26.0",
    "quay.io/thanos/thanos:v0.36.1",
]


def test_ns8_rule_1_no_get_status_action_override() -> None:
    assert not (IMAGEROOT / "actions" / "get-status").exists(), (
        "NS8 Rule #1 violation: imageroot/actions/get-status MUST NOT exist!"
    )


def test_pypkg_has_no_root_init_for_namespace_isolation() -> None:
    assert not (PYPKG_DIR / "__init__.py").exists(), (
        "hub/imageroot/pypkg/__init__.py MUST NOT exist so hub_core, hub_tenancy, and hub_alerting stay independent."
    )


def test_ns8_rule_2_every_set_env_caller_invokes_dump_env() -> None:
    owned_python_files = list((PYPKG_DIR / "hub_core").rglob("*.py"))
    for action_name in (
        "create-module",
        "configure-module",
        "get-configuration",
        "get-overview",
        "restore-module",
        "clone-module",
        "destroy-module",
    ):
        action_dir = IMAGEROOT / "actions" / action_name
        if action_dir.exists():
            owned_python_files.extend(p for p in action_dir.iterdir() if p.is_file() and not p.name.endswith(".json"))

    assert owned_python_files
    for path in owned_python_files:
        text = path.read_text(encoding="utf-8")
        if "set_env(" in text:
            assert "dump_env()" in text, f"NS8 Rule #2 violation: {path} calls set_env() without dump_env()!"


def test_ns8_rules_3_5_6_systemd_units_compliance() -> None:
    systemd_dir = IMAGEROOT / "systemd" / "user"
    actual_units = {p.name for p in systemd_dir.glob("*.service")}
    assert actual_units == EXPECTED_SYSTEMD_UNITS

    pod_unit = (systemd_dir / "central-monitoring-hub.service").read_text(encoding="utf-8")
    assert "127.0.0.1:${TCP_PORT}:8080" in pod_unit
    assert "slirp4netns:allow_host_loopback=true" in pod_unit

    for unit_name in EXPECTED_SYSTEMD_UNITS:
        content = (systemd_dir / unit_name).read_text(encoding="utf-8")
        assert "--pull=always" not in content, f"NS8 Rule #5 violation in {unit_name}: --pull=always forbidden!"
        assert "%S/" not in content, f"ARCH-02 violation in {unit_name}: use %E/ (~/.config), never %S/ (~/.local/state)!"
        assert "%E/state/environment" in content
        if unit_name != "central-monitoring-hub.service":
            assert "--pull=missing" in content, f"NS8 Rule #5 violation in {unit_name}: missing --pull=missing"
            assert "--restart=on-failure" in content, f"NS8 Rule #6 violation in {unit_name}: missing --restart=on-failure"
            assert "--user 0:0" in content, f"Missing rootless userns UID 0 mapping (--user 0:0) in {unit_name}"

    for dependent_unit in ("grafana.service", "hub-gateway.service", "thanos-sidecar.service"):
        dep_content = (systemd_dir / dependent_unit).read_text(encoding="utf-8")
        assert "ExecStartPre=" in dep_content and ("/-/ready" in dep_content or "/ready" in dep_content), (
            f"NS8 Rule #6 violation: {dependent_unit} lacks readiness wait loop in ExecStartPre!"
        )
        assert "--entrypoint=python3" in dep_content, (
            f"ARCH-01 violation: {dependent_unit} ExecStartPre must pass --entrypoint=python3!"
        )
        assert "${CENTRAL_MONITORING_HUB_GATEWAY_IMAGE} /wait-pod-endpoints" in dep_content


def test_ns8_rules_5_7_8_containerfile_and_backup_files() -> None:
    containerfile = (HUB_ROOT / "Containerfile").read_text(encoding="utf-8")
    assert "org.nethserver.images" in containerfile
    assert 'org.nethserver.tcp-ports-demand="1"' in containerfile or "org.nethserver.tcp-ports-demand=1" in containerfile
    assert 'org.nethserver.rootfull="0"' in containerfile or "org.nethserver.rootfull=0" in containerfile
    assert "org.nethserver.authorizations" in containerfile
    assert "sed -i 's/\\r$//'" in containerfile
    assert "chmod +x" in containerfile

    for img in EXPECTED_PINNED_IMAGE_REPOS:
        assert img in containerfile, f"Missing pinned image {img} in hub/Containerfile"

    assert (HUB_ROOT / "build-images.sh").exists()
    assert (IMAGEROOT / "etc" / "state-include.conf").exists()
    assert (IMAGEROOT / "bin" / "module-dump-state").exists()
    assert (IMAGEROOT / "bin" / "module-cleanup-state").exists()
    assert (IMAGEROOT / "bin" / "discover-smarthost").exists()
    assert (IMAGEROOT / "bin" / "render-hub-configs").exists()
    assert (IMAGEROOT / "update-module.d" / "20pull_images").exists()


def test_action_schemas_match_shared_schemas_exactly() -> None:
    for action in ("configure-module", "get-configuration", "get-overview"):
        for direction in ("input", "output"):
            action_schema = IMAGEROOT / "actions" / action / f"validate-{direction}.json"
            shared_schema = SCHEMAS_DIR / f"hub-{action}-{direction}.json"
            assert action_schema.exists(), f"Missing {action_schema}"
            assert json.loads(action_schema.read_text(encoding="utf-8")) == json.loads(
                shared_schema.read_text(encoding="utf-8")
            )
            assert action_schema.read_bytes() == shared_schema.read_bytes()


def test_zero_crlf_and_zero_bom_on_all_hub_core_files() -> None:
    owned_roots = [
        HUB_ROOT / "Containerfile",
        HUB_ROOT / "build-images.sh",
        IMAGEROOT / "etc",
        IMAGEROOT / "bin",
        PYPKG_DIR / "hub_core",
        IMAGEROOT / "actions" / "create-module",
        IMAGEROOT / "actions" / "configure-module",
        IMAGEROOT / "actions" / "get-configuration",
        IMAGEROOT / "actions" / "get-overview",
        IMAGEROOT / "actions" / "restore-module",
        IMAGEROOT / "actions" / "clone-module",
        IMAGEROOT / "actions" / "destroy-module",
        IMAGEROOT / "events",
        IMAGEROOT / "update-module.d",
        IMAGEROOT / "systemd" / "user",
        HUB_ROOT / "test-module.sh",
        HUB_ROOT / "tests",
        REPO_ROOT / "tests" / "hub_core",
    ]
    binary_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".gz", ".tar", ".zip"}
    checked = 0
    for root in owned_roots:
        if not root.exists():
            continue
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
        for f in files:
            if f.suffix.lower() in binary_exts:
                continue
            raw = f.read_bytes()
            assert not raw.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM detected in {f}"
            assert b"\r\n" not in raw, f"CRLF (\\r\\n) detected in {f}"
            checked += 1
    assert checked >= 30


def test_registry_namespace_parameterization_and_defaults_env_override(tmp_path: Path) -> None:
    from hub_core import resolve_default_gateway_image

    build_sh = (HUB_ROOT / "build-images.sh").read_text(encoding="utf-8")
    assert "REPO_OWNER" in build_sh
    assert "IMAGE_ORG" in build_sh
    assert "defaults.env" in build_sh
    assert "GATEWAY_IMAGE=" in build_sh

    containerfile = (HUB_ROOT / "Containerfile").read_text(encoding="utf-8")
    assert "ARG GATEWAY_IMAGE=" in containerfile
    assert "/imageroot/etc/defaults.env" in containerfile
    assert "hub/tests" not in containerfile
    assert "test-module.sh" not in containerfile

    # Verify custom org gateway image in etc/defaults.env is honored dynamically
    custom_install = tmp_path / "custom_org_home"
    custom_state = custom_install / "state"
    custom_etc = custom_install / "etc"
    custom_state.mkdir(parents=True)
    custom_etc.mkdir(parents=True)
    (custom_etc / "defaults.env").write_text(
        "CENTRAL_MONITORING_HUB_GATEWAY_IMAGE=ghcr.io/acme-msp/central-monitoring-hub-gateway:2.1.0\n",
        encoding="utf-8",
    )
    assert (
        resolve_default_gateway_image(custom_state)
        == "ghcr.io/acme-msp/central-monitoring-hub-gateway:2.1.0"
    )


def test_robot_framework_suite_and_test_module_runner_exist_and_cover_lifecycle() -> None:
    runner_sh = HUB_ROOT / "test-module.sh"
    robot_dir = HUB_ROOT / "tests"
    init_robot = robot_dir / "__init__.robot"
    install_robot = robot_dir / "10__install_and_configure.robot"
    features_robot = robot_dir / "20__tenancy_targets_alerting.robot"

    for path in (runner_sh, init_robot, install_robot, features_robot):
        assert path.is_file(), f"Missing Robot test artifact: {path}"

    runner_text = runner_sh.read_text(encoding="utf-8")
    assert "robotframework" in runner_text

    combined_robot = "\n".join(
        p.read_text(encoding="utf-8") for p in (init_robot, install_robot, features_robot)
    )
    for required_keyword in (
        "*** Settings ***",
        "api-cli",
        "add-module",
        "configure-module",
        "get-overview",
        "save-tenant",
        "generate-agent-bundle",
        "save-target",
        "configure-alerting",
        "create-silence",
        "remove-module",
    ):
        assert required_keyword in combined_robot, (
            f"Robot suite missing required NS8 action/section: {required_keyword}"
        )
