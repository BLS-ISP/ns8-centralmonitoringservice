"""Unit and contract tests for NS8 textfile metrics (ns8.prom vs shared/rules/ns8-cluster.yml)."""

from __future__ import annotations

import re
from pathlib import Path

from tests.site_collector.conftest import REPO_ROOT


REQUIRED_NS8_TEXTFILE_METRICS = {
    "ns8_backup_status",
    "ns8_backup_failed",
    "ns8_backup_last_success_timestamp_seconds",
    "ns8_container_info",
    "ns8_container_running",
    "ns8_container_restarts_total",
    "ns8_systemd_unit_failed",
}


def test_emitted_ns8_metrics_match_ns8_cluster_alert_rules(state_dir: Path) -> None:
    from collector_lib.ns8_metrics import (
        BackupRecord,
        ContainerRecord,
        SystemdUnitRecord,
        format_ns8_prom,
        write_ns8_prom_atomic,
    )

    rules_text = (REPO_ROOT / "shared" / "rules" / "ns8-cluster.yml").read_text(encoding="utf-8")
    rule_ns8_metrics = set(re.findall(r"\b(ns8_[a-z0-9_]+)\b", rules_text))
    assert rule_ns8_metrics == REQUIRED_NS8_TEXTFILE_METRICS

    prom_text = format_ns8_prom(
        backups=[
            BackupRecord(
                module_id="mail1",
                succeeded=True,
                last_success_timestamp=1732000000,
            ),
            BackupRecord(
                module_id="nextcloud1",
                succeeded=False,
                last_success_timestamp=1731900000,
            ),
        ],
        containers=[
            ContainerRecord(
                module_id="central-monitoring-collector1",
                container="alloy",
                image="docker.io/grafana/alloy:v1.4.2",
                running=True,
                restarts=0,
            ),
            ContainerRecord(
                module_id="nextcloud1",
                container="nextcloud-app",
                image='ghcr.io/nethserver/nextcloud:1.2"special',
                running=False,
                restarts=4,
            ),
        ],
        systemd_units=[
            SystemdUnitRecord(name="alloy.service", failed=False),
            SystemdUnitRecord(name="broken-app.service", failed=True),
        ],
    )

    out_file = state_dir / "textfile" / "ns8.prom"
    write_ns8_prom_atomic(out_file, prom_text)

    raw_bytes = out_file.read_bytes()
    assert b"\r\n" not in raw_bytes
    rendered = out_file.read_text(encoding="utf-8")

    # Every ns8_* metric referenced in shared/rules/ns8-cluster.yml must be emitted
    for metric_name in rule_ns8_metrics:
        assert f"# TYPE {metric_name} " in rendered
        assert re.search(rf"^{metric_name}\{{", rendered, flags=re.MULTILINE), (
            f"Missing sample line for {metric_name}"
        )

    assert 'ns8_backup_status{module_id="mail1"} 1' in rendered
    assert 'ns8_backup_failed{module_id="mail1"} 0' in rendered
    assert 'ns8_backup_status{module_id="nextcloud1"} 0' in rendered
    assert 'ns8_backup_failed{module_id="nextcloud1"} 1' in rendered
    assert 'ns8_backup_last_success_timestamp_seconds{module_id="mail1"} 1732000000' in rendered

    assert (
        'ns8_container_info{module_id="central-monitoring-collector1",container="alloy",'
        'image="docker.io/grafana/alloy:v1.4.2"} 1'
    ) in rendered
    assert 'ns8_container_running{module_id="nextcloud1",container="nextcloud-app"} 0' in rendered
    assert (
        'ns8_container_restarts_total{module_id="nextcloud1",container="nextcloud-app"} 4'
        in rendered
    )
    assert 'image="ghcr.io/nethserver/nextcloud:1.2\\"special"' in rendered

    assert 'ns8_systemd_unit_failed{name="alloy.service"} 0' in rendered
    assert 'ns8_systemd_unit_failed{name="broken-app.service"} 1' in rendered
