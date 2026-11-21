"""Manages built-in MSP Prometheus Alert Rule Packs (shared/rules/*.yml -> config/prometheus/rules/)."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Final

from hub_alerting import atomic_write_text, resolve_config_dir, resolve_state_dir, trigger_http_reload

RULE_PACKS: Final[tuple[tuple[str, str], ...]] = (
    ("ns8-cluster", "ns8-cluster.yml"),
    ("linux-node", "linux-node.yml"),
    ("windows-node", "windows-node.yml"),
    ("proxmox-ve", "proxmox-ve.yml"),
    ("blackbox-web-ssl", "blackbox-web-ssl.yml"),
    ("snmp-network-ups", "snmp-network-ups.yml"),
)

DEFAULT_ENABLED_RULE_PACKS: Final[list[str]] = [pack_id for pack_id, _ in RULE_PACKS]

_ALERT_DEF_RE: Final[re.Pattern[str]] = re.compile(r"^\s*-\s+alert:\s+\S+", re.MULTILINE)


def _locate_available_rules_dir(state_dir: str | Path | None = None) -> Path:
    sdir = resolve_state_dir(state_dir)
    cdir = resolve_config_dir(sdir)

    candidates: list[Path] = []
    env_dir = os.environ.get("HUB_AVAILABLE_RULES_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.extend(
        [
            cdir / "prometheus" / "available-rules",
            sdir.parent / "etc" / "shared" / "rules",
            Path("/etc/prometheus/available-rules"),
            Path(__file__).resolve().parents[2] / "etc" / "shared" / "rules",
            Path(__file__).resolve().parents[4] / "shared" / "rules",
        ]
    )
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "ns8-cluster.yml").is_file():
            return candidate.resolve()
    return candidates[-1].resolve()


def count_rules_in_yaml(yaml_text: str) -> int:
    return len(_ALERT_DEF_RE.findall(yaml_text))


def get_rule_packs_status(
    enabled_pack_ids: list[str] | None = None,
    *,
    state_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return rule pack metadata matching hub-get-alerting-output.json#/properties/rule_packs."""
    active_ids = set(DEFAULT_ENABLED_RULE_PACKS if enabled_pack_ids is None else enabled_pack_ids)
    avail_dir = _locate_available_rules_dir(state_dir)

    result: list[dict[str, Any]] = []
    for pack_id, filename in RULE_PACKS:
        src = avail_dir / filename
        count = count_rules_in_yaml(src.read_text(encoding="utf-8")) if src.is_file() else 0
        result.append(
            {
                "pack_id": pack_id,
                "filename": filename,
                "enabled": pack_id in active_ids,
                "rules_count": count,
            }
        )
    return result


def sync_rule_packs(
    enabled_pack_ids: list[str] | None = None,
    *,
    state_dir: str | Path | None = None,
    reload_prometheus: bool = True,
) -> list[dict[str, Any]]:
    """Deploy enabled built-in rule packs to config/prometheus/rules/ and remove disabled ones."""
    active_ids = set(DEFAULT_ENABLED_RULE_PACKS if enabled_pack_ids is None else enabled_pack_ids)
    avail_dir = _locate_available_rules_dir(state_dir)
    cdir = resolve_config_dir(state_dir)
    rules_dir = cdir / "prometheus" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    changed = False
    for pack_id, filename in RULE_PACKS:
        src = avail_dir / filename
        dst = rules_dir / filename
        if pack_id in active_ids:
            if src.is_file():
                content = src.read_text(encoding="utf-8").replace("\r\n", "\n")
                if not dst.is_file() or dst.read_text(encoding="utf-8") != content:
                    atomic_write_text(dst, content, mode=0o644)
                    changed = True
        else:
            if dst.exists():
                dst.unlink(missing_ok=True)
                changed = True

    if changed and reload_prometheus:
        prom_reload_url = os.environ.get("PROMETHEUS_RELOAD_URL", "http://127.0.0.1:9090/-/reload")
        trigger_http_reload(prom_reload_url)

    return get_rule_packs_status(list(active_ids), state_dir=state_dir)
