"""NS8 Central Monitoring Site Collector Python library (collector_lib)."""

from __future__ import annotations

from collector_lib.alloy_renderer import (
    CollectorConfig,
    RenderResult,
    has_enabled_proxmox_targets,
    render_collector_artifacts,
)
from collector_lib.hub_probe import verify_hub_connection
from collector_lib.ns8_metrics import (
    BackupRecord,
    ContainerRecord,
    ModuleCgroupRecord,
    PodUnitCgroupRecord,
    SystemdUnitRecord,
    collect_and_write_ns8_metrics,
    format_ns8_prom,
    harvest_ns8_cgroups_v2,
    write_ns8_prom_atomic,
)
from collector_lib.runtime import (
    atomic_write_text,
    build_collector_id,
    check_alloy_status,
    check_pve_exporter_status,
    compute_wal_usage_bytes,
    get_state_dir,
    load_stored_auth_token,
    reload_alloy_config,
    save_stored_auth_token,
    sync_syslog_firewall_ports,
    validate_auth_token_format,
)
from collector_lib.targets_store import TargetsStore

__all__ = [
    "BackupRecord",
    "CollectorConfig",
    "ContainerRecord",
    "ModuleCgroupRecord",
    "PodUnitCgroupRecord",
    "RenderResult",
    "SystemdUnitRecord",
    "TargetsStore",
    "atomic_write_text",
    "build_collector_id",
    "check_alloy_status",
    "check_pve_exporter_status",
    "collect_and_write_ns8_metrics",
    "compute_wal_usage_bytes",
    "format_ns8_prom",
    "get_state_dir",
    "harvest_ns8_cgroups_v2",
    "has_enabled_proxmox_targets",
    "load_stored_auth_token",
    "reload_alloy_config",
    "render_collector_artifacts",
    "save_stored_auth_token",
    "verify_hub_connection",
    "write_ns8_prom_atomic",
]
