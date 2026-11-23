"""Core backend package for NethServer 8 module central-monitoring-hub."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Final

DEFAULT_GATEWAY_IMAGE: Final[str] = "ghcr.io/bls-isp/central-monitoring-hub-gateway:latest"
_MODULE_FILE: Final[Path] = Path(__file__).resolve()

PINNED_IMAGES: Final[dict[str, str]] = {
    "CENTRAL_MONITORING_HUB_GATEWAY_IMAGE": DEFAULT_GATEWAY_IMAGE,
    "PROMETHEUS_IMAGE": "quay.io/prometheus/prometheus:v2.54.1",
    "ALERTMANAGER_IMAGE": "quay.io/prometheus/alertmanager:v0.27.0",
    "LOKI_IMAGE": "docker.io/grafana/loki:3.1.1",
    "GRAFANA_OSS_IMAGE": "docker.io/grafana/grafana-oss:11.2.2",
    "PROM_LABEL_PROXY_IMAGE": "quay.io/prometheuscommunity/prom-label-proxy:v0.11.0",
    "BLACKBOX_EXPORTER_IMAGE": "quay.io/prometheus/blackbox-exporter:v0.25.0",
    "SNMP_EXPORTER_IMAGE": "quay.io/prometheus/snmp-exporter:v0.26.0",
    "THANOS_IMAGE": "quay.io/thanos/thanos:v0.36.1",
}

POD_SERVICE: Final[str] = "central-monitoring-hub.service"

CORE_CONTAINER_SERVICES: Final[tuple[str, ...]] = (
    "prometheus.service",
    "loki.service",
    "alertmanager.service",
    "grafana.service",
    "prom-label-proxy.service",
    "blackbox-exporter.service",
    "snmp-exporter.service",
    "hub-gateway.service",
)

THANOS_SERVICES: Final[tuple[str, ...]] = (
    "thanos-sidecar.service",
    "thanos-store.service",
    "thanos-query.service",
)

METRICS_SERVICE_UNIT: Final[str] = "hub-ns8-metrics.service"
METRICS_TIMER_UNIT: Final[str] = "hub-ns8-metrics.timer"

ALL_COMPONENT_KEYS: Final[tuple[str, ...]] = (
    "hub_gateway",
    "prometheus",
    "loki",
    "grafana",
    "alertmanager",
    "prom_label_proxy",
    "blackbox_exporter",
    "snmp_exporter",
    "thanos_sidecar",
    "thanos_store",
    "thanos_query",
)


def resolve_state_dir(state_dir: str | Path | None = None) -> Path:
    """Resolve the NS8 module state directory (~/.config/state)."""
    if state_dir is not None:
        return Path(state_dir)
    env_dir = os.environ.get("AGENT_STATE_DIR") or os.environ.get("HUB_STATE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".config" / "state"


def resolve_config_dir(state_dir: str | Path | None = None) -> Path:
    """Resolve the rendered container config directory (~/.config/config)."""
    explicit = os.environ.get("HUB_CONFIG_DIR")
    if explicit:
        return Path(explicit)
    return resolve_state_dir(state_dir).parent / "config"


def resolve_etc_dir(state_dir: str | Path | None = None) -> Path:
    """Resolve the static module etc directory (~/.config/etc)."""
    explicit = os.environ.get("HUB_ETC_DIR")
    if explicit:
        return Path(explicit)
    return resolve_state_dir(state_dir).parent / "etc"


def resolve_shared_dir(state_dir: str | Path | None = None) -> Path:
    """Locate baked-in shared assets (etc/shared) or repository shared/ fallback."""
    candidates = [
        resolve_etc_dir(state_dir) / "shared",
        _MODULE_FILE.parents[2] / "etc" / "shared",
        _MODULE_FILE.parents[4] / "shared",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def resolve_default_gateway_image(state_dir: str | Path | None = None) -> str:
    """Resolve the default gateway image from etc/defaults.env (supporting custom GitHub orgs)."""
    candidates = [
        resolve_etc_dir(state_dir) / "defaults.env",
        _MODULE_FILE.parents[2] / "etc" / "defaults.env",
    ]
    for defaults_path in candidates:
        if not defaults_path.is_file():
            continue
        for raw_line in defaults_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("CENTRAL_MONITORING_HUB_GATEWAY_IMAGE="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if value:
                    return value
    return DEFAULT_GATEWAY_IMAGE


def resolve_pinned_images(state_dir: str | Path | None = None) -> dict[str, str]:
    """Return pinned container images map with custom-org gateway image applied."""
    images = dict(PINNED_IMAGES)
    images["CENTRAL_MONITORING_HUB_GATEWAY_IMAGE"] = resolve_default_gateway_image(state_dir)
    return images


def atomic_write_text(path: Path, content: str, mode: int = 0o640) -> None:
    """Atomically write UTF-8 text with strict LF line endings and file permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
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


def yaml_quote(value: str) -> str:
    """Format a scalar string safely as a double-quoted YAML string."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'
