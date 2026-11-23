"""Unit and contract tests for NS8 textfile & cgroups v2 metrics (ns8.prom vs ns8-cluster.yml)."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from tests.site_collector.conftest import IMAGEROOT, REPO_ROOT
from tests.site_collector.test_phase2_features import _serve_single_redis_session

LEGACY_NS8_TEXTFILE_METRICS = {
    "ns8_backup_status",
    "ns8_backup_failed",
    "ns8_backup_last_success_timestamp_seconds",
    "ns8_container_info",
    "ns8_container_running",
    "ns8_container_restarts_total",
    "ns8_systemd_unit_failed",
}

CGROUP_V2_NS8_METRICS = {
    "ns8_module_up",
    "ns8_module_cpu_seconds_total",
    "ns8_module_cpu_throttled_seconds_total",
    "ns8_module_memory_working_set_bytes",
    "ns8_module_memory_bytes",
    "ns8_module_memory_swap_bytes",
    "ns8_module_memory_limit_bytes",
    "ns8_module_oom_kills_total",
    "ns8_module_io_read_bytes_total",
    "ns8_module_io_write_bytes_total",
    "ns8_module_pids",
    "ns8_pod_unit_cpu_seconds_total",
    "ns8_pod_unit_memory_working_set_bytes",
}

ALL_EMITTED_NS8_TEXTFILE_METRICS = LEGACY_NS8_TEXTFILE_METRICS | CGROUP_V2_NS8_METRICS


def _write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def test_emitted_ns8_metrics_match_ns8_cluster_alert_rules(state_dir: Path) -> None:
    from collector_lib.ns8_metrics import (
        BackupRecord,
        ContainerRecord,
        ModuleCgroupRecord,
        PodUnitCgroupRecord,
        SystemdUnitRecord,
        format_ns8_prom,
        write_ns8_prom_atomic,
    )

    rules_text = (REPO_ROOT / "shared" / "rules" / "ns8-cluster.yml").read_text(encoding="utf-8")
    rule_ns8_metrics = set(re.findall(r"\b(ns8_[a-z0-9_]+)\b", rules_text))
    assert LEGACY_NS8_TEXTFILE_METRICS.issubset(rule_ns8_metrics)
    assert rule_ns8_metrics.issubset(ALL_EMITTED_NS8_TEXTFILE_METRICS), (
        f"Unrecognized ns8_* metric in ns8-cluster.yml: {rule_ns8_metrics - ALL_EMITTED_NS8_TEXTFILE_METRICS}"
    )

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
        modules=[
            ModuleCgroupRecord(
                module_id="mail1",
                module_type="rootless",
                up=True,
                cpu_seconds_total=42.5,
                cpu_throttled_seconds_total=0.125,
                memory_working_set_bytes=268435456,
                memory_bytes=335544320,
                memory_swap_bytes=4194304,
                memory_limit_bytes=1073741824,
                oom_kills_total=1,
                io_read_bytes_total=10485760,
                io_write_bytes_total=5242880,
                pids=24,
            )
        ],
        pod_units=[
            PodUnitCgroupRecord(
                module_id="mail1",
                unit="dovecot",
                cpu_seconds_total=18.25,
                memory_working_set_bytes=134217728,
                pids=10,
                memory_bytes=150000000,
            )
        ],
    )

    out_file = state_dir / "textfile" / "ns8.prom"
    write_ns8_prom_atomic(out_file, prom_text)

    raw_bytes = out_file.read_bytes()
    assert b"\r\n" not in raw_bytes
    rendered = out_file.read_text(encoding="utf-8")

    # Every emitted metric family (including all metrics referenced in ns8-cluster.yml) has TYPE & sample
    for metric_name in ALL_EMITTED_NS8_TEXTFILE_METRICS:
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

    assert 'ns8_module_up{module_id="mail1",module_type="rootless"} 1' in rendered
    assert 'ns8_module_cpu_seconds_total{module_id="mail1",module_type="rootless"} 42.5' in rendered
    assert (
        'ns8_module_cpu_throttled_seconds_total{module_id="mail1",module_type="rootless"} 0.125'
        in rendered
    )
    assert (
        'ns8_module_memory_working_set_bytes{module_id="mail1",module_type="rootless"} 268435456'
        in rendered
    )
    assert 'ns8_module_memory_bytes{module_id="mail1",module_type="rootless"} 335544320' in rendered
    assert (
        'ns8_module_memory_swap_bytes{module_id="mail1",module_type="rootless"} 4194304'
        in rendered
    )
    assert (
        'ns8_module_memory_limit_bytes{module_id="mail1",module_type="rootless"} 1073741824'
        in rendered
    )
    assert 'ns8_module_oom_kills_total{module_id="mail1",module_type="rootless"} 1' in rendered
    assert (
        'ns8_module_io_read_bytes_total{module_id="mail1",module_type="rootless"} 10485760'
        in rendered
    )
    assert (
        'ns8_module_io_write_bytes_total{module_id="mail1",module_type="rootless"} 5242880'
        in rendered
    )
    assert 'ns8_module_pids{module_id="mail1",module_type="rootless"} 24' in rendered
    assert 'ns8_pod_unit_cpu_seconds_total{module_id="mail1",unit="dovecot"} 18.25' in rendered
    assert (
        'ns8_pod_unit_memory_working_set_bytes{module_id="mail1",unit="dovecot"} 134217728'
        in rendered
    )


def test_cgroups_v2_rootless_and_rootful_harvester_full_fidelity(tmp_path: Path) -> None:
    from collector_lib.ns8_metrics import harvest_ns8_cgroups_v2

    passwd_file = tmp_path / "passwd"
    _write_lf(
        passwd_file,
        "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin",
                "rocky:x:1000:1000:Rocky Admin:/home/rocky:/bin/bash",
                "wronghome1:x:1002:1002::/var/lib/wronghome1:/bin/bash",
                "mail1:x:1005:1005::/home/mail1:/bin/bash",
                "nextcloud1:x:1008:1008::/home/nextcloud1:/bin/bash",
            ]
        )
        + "\n",
    )

    cg_root = tmp_path / "cgroup"
    # Rootless mail1 (UID 1005) active slice + sub-units + ignored noise units
    mail_slice = cg_root / "user.slice" / "user-1005.slice"
    _write_lf(mail_slice / "cpu.stat", "usage_usec 48500000\nthrottled_usec 250000\n")
    _write_lf(mail_slice / "memory.current", "536870912\n")
    _write_lf(mail_slice / "memory.stat", "anon 400000000\ninactive_file 136870912\n")
    _write_lf(mail_slice / "memory.swap.current", "10485760\n")
    _write_lf(mail_slice / "memory.max", "1073741824\n")
    _write_lf(mail_slice / "memory.events", "low 0\noom 2\noom_kill 2\n")
    _write_lf(mail_slice / "pids.current", "37\n")
    _write_lf(
        mail_slice / "io.stat",
        "253:0 rbytes=1000000 wbytes=500000 rios=10 wios=5\n"
        "8:0 rbytes=250000 wbytes=125000 rios=4 wios=2\n",
    )

    app_slice = mail_slice / "user@1005.service" / "app.slice"
    _write_lf(app_slice / "dovecot.service" / "cpu.stat", "usage_usec 15250000\n")
    _write_lf(app_slice / "dovecot.service" / "memory.current", "150000000\n")
    _write_lf(app_slice / "dovecot.service" / "memory.stat", "inactive_file 30000000\n")
    _write_lf(app_slice / "dovecot.service" / "pids.current", "12\n")

    _write_lf(app_slice / "rspamd.service" / "cpu.stat", "usage_usec 22750000\n")
    _write_lf(app_slice / "rspamd.service" / "memory.current", "210000000\n")
    _write_lf(app_slice / "rspamd.service" / "memory.stat", "inactive_file 10000000\n")
    _write_lf(app_slice / "rspamd.service" / "pids.current", "8\n")

    # Noise units that MUST be skipped (including transient metrics timer oneshot units)
    for ignored_unit in (
        "dbus.service",
        "dbus-broker.service",
        "systemd-tmpfiles-setup.service",
        "init.scope",
        "podman-pause-deadbeef.service",
        "ns8-collector-textfile.service",
        "hub-ns8-metrics.service",
    ):
        _write_lf(app_slice / ignored_unit / "pids.current", "1\n")

    user_sub_slice = mail_slice / "user@1005.service" / "user.slice"
    _write_lf(user_sub_slice / "clamd.service" / "cpu.stat", "usage_usec 10500000\n")
    _write_lf(user_sub_slice / "clamd.service" / "memory.current", "0\n")
    _write_lf(user_sub_slice / "clamd.service" / "pids.current", "0\n")

    # Rootful modules under system.slice (samba1 + samba1-dc, crowdsec1, Redis-known custom-erp1, plus OS noise)
    sys_slice = cg_root / "system.slice"
    _write_lf(sys_slice / "samba1.service" / "cpu.stat", "usage_usec 12000000\n")
    _write_lf(sys_slice / "samba1.service" / "memory.current", "200000000\n")
    _write_lf(sys_slice / "samba1.service" / "memory.stat", "inactive_file 20000000\n")
    _write_lf(sys_slice / "samba1.service" / "memory.max", "max\n")
    _write_lf(sys_slice / "samba1.service" / "pids.current", "14\n")

    _write_lf(sys_slice / "samba1-winbindd.service" / "cpu.stat", "usage_usec 3000000\n")
    _write_lf(sys_slice / "samba1-winbindd.service" / "memory.current", "50000000\n")
    _write_lf(sys_slice / "samba1-winbindd.service" / "memory.stat", "inactive_file 5000000\n")
    _write_lf(sys_slice / "samba1-winbindd.service" / "pids.current", "4\n")

    _write_lf(sys_slice / "crowdsec1.service" / "cpu.stat", "usage_usec 6500000\n")
    _write_lf(sys_slice / "crowdsec1.service" / "memory.current", "90000000\n")
    _write_lf(sys_slice / "crowdsec1.service" / "pids.current", "9\n")

    _write_lf(sys_slice / "custom-erp1.service" / "cpu.stat", "usage_usec 9000000\n")
    _write_lf(sys_slice / "custom-erp1.service" / "memory.current", "128000000\n")
    _write_lf(sys_slice / "custom-erp1.service" / "pids.current", "6\n")

    # OS system services ending with digits or standard names -> MUST NOT be picked up as NS8 modules
    for os_noise in ("sshd.service", "udisks2.service", "dbus-1.service", "polkit-1.service"):
        _write_lf(sys_slice / os_noise / "pids.current", "3\n")

    modules, pod_units = harvest_ns8_cgroups_v2(
        cgroup_root=cg_root,
        passwd_path=passwd_file,
        redis_local_modules={"mail1", "custom-erp1", "stopped-rootful1"},
    )

    by_mid = {(m.module_id, m.module_type): m for m in modules}
    assert set(by_mid) == {
        ("mail1", "rootless"),
        ("nextcloud1", "rootless"),
        ("crowdsec1", "rootful"),
        ("custom-erp1", "rootful"),
        ("samba1", "rootful"),
        ("stopped-rootful1", "rootful"),
    }

    mail = by_mid[("mail1", "rootless")]
    assert mail.up is True
    assert mail.cpu_seconds_total == pytest.approx(48.5)
    assert mail.cpu_throttled_seconds_total == pytest.approx(0.25)
    assert mail.memory_bytes == 536870912
    assert mail.memory_working_set_bytes == 400000000
    assert mail.memory_swap_bytes == 10485760
    assert mail.memory_limit_bytes == 1073741824
    assert mail.oom_kills_total == 2
    assert mail.io_read_bytes_total == 1250000
    assert mail.io_write_bytes_total == 625000
    assert mail.pids == 37

    # nextcloud1 is in /etc/passwd but has no active user-1008.slice -> clean zeros & up=False
    nc = by_mid[("nextcloud1", "rootless")]
    assert nc.up is False
    assert nc.memory_bytes == 0
    assert nc.pids == 0

    # samba1 aggregates samba1.service + samba1-winbindd.service and maps memory.max="max" -> 0
    samba = by_mid[("samba1", "rootful")]
    assert samba.up is True
    assert samba.cpu_seconds_total == pytest.approx(15.0)
    assert samba.memory_bytes == 250000000
    assert samba.memory_working_set_bytes == 225000000
    assert samba.memory_limit_bytes == 0
    assert samba.pids == 18

    stopped_rf = by_mid[("stopped-rootful1", "rootful")]
    assert stopped_rf.up is False

    unit_map = {(u.module_id, u.unit): u for u in pod_units}
    assert ("mail1", "dovecot") in unit_map
    assert ("mail1", "rspamd") in unit_map
    assert ("mail1", "clamd") in unit_map
    assert unit_map[("mail1", "dovecot")].memory_working_set_bytes == 120000000
    assert ("mail1", "dbus") not in unit_map
    assert ("mail1", "dbus-broker") not in unit_map
    assert ("mail1", "ns8-collector-textfile") not in unit_map
    assert ("mail1", "hub-ns8-metrics") not in unit_map
    assert not any(u.unit.startswith("systemd-") or u.unit.startswith("podman-pause") for u in pod_units)


def test_cgroups_v2_synthesizes_container_records_without_overwriting_node_exporter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collector_lib.ns8_metrics import collect_and_write_ns8_metrics

    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    passwd_file = tmp_path / "passwd"
    _write_lf(passwd_file, "mail1:x:1005:1005::/home/mail1:/bin/bash\n")

    cg_root = tmp_path / "cgroup"
    mail_slice = cg_root / "user.slice" / "user-1005.slice"
    _write_lf(mail_slice / "memory.current", "300000000\n")
    _write_lf(mail_slice / "pids.current", "20\n")
    app_slice = mail_slice / "user@1005.service" / "app.slice"
    _write_lf(app_slice / "dovecot.service" / "memory.current", "100000000\n")
    _write_lf(app_slice / "dovecot.service" / "pids.current", "8\n")
    _write_lf(app_slice / "rspamd.service" / "memory.current", "120000000\n")
    _write_lf(app_slice / "rspamd.service" / "pids.current", "6\n")
    _write_lf(app_slice / "clamd.service" / "memory.current", "0\n")
    _write_lf(app_slice / "clamd.service" / "pids.current", "0\n")

    sys_slice = cg_root / "system.slice"
    _write_lf(sys_slice / "custom-erp1.service" / "memory.current", "64000000\n")
    _write_lf(sys_slice / "custom-erp1.service" / "pids.current", "5\n")

    # Mock node_exporter ONLY reporting dovecot (with real OCI image & restarts=3)
    ne_payload = "\n".join(
        [
            'ns8_container_info{module="mail1",container="dovecot",image="ghcr.io/nethserver/mail-dovecot:1.4.2"} 1',
            'ns8_container_running{module="mail1",container="dovecot"} 1',
            'ns8_container_restarts_total{module="mail1",container="dovecot"} 3',
            "",
        ]
    ).encode("utf-8")

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(ne_payload)))
            self.end_headers()
            self.wfile.write(ne_payload)

    http_srv = HTTPServer(("127.0.0.1", 0), _Handler)
    ne_port = http_srv.server_address[1]
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()

    # Mock Redis with local NODE_ID=1 vs remote NODE_ID=2 module environments + backup
    redis_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    redis_sock.bind(("127.0.0.1", 0))
    redis_sock.listen(4)
    redis_port = redis_sock.getsockname()[1]
    redis_hashes = {
        "module/mail1/backup": {"status": "ok", "last_success": "1764000000"},
        "module/mail1/environment": {"NODE_ID": "1"},
        "module/custom-erp1/environment": {"NODE_ID": "1"},
        "module/remote-only2/environment": {"NODE_ID": "2"},
    }
    threading.Thread(
        target=_serve_single_redis_session,
        args=(redis_sock, redis_hashes),
        daemon=True,
    ).start()

    try:
        monkeypatch.setenv("NODE_ID", "1")
        monkeypatch.setenv("NS8_NODE_EXPORTER_URL", f"http://127.0.0.1:{ne_port}/metrics")
        monkeypatch.setenv("REDIS_ADDRESS", f"127.0.0.1:{redis_port}")
        monkeypatch.setenv("NS8_CGROUP_ROOT", str(cg_root))
        monkeypatch.setenv("NS8_PASSWD_FILE", str(passwd_file))

        out_path = collect_and_write_ns8_metrics(state_dir)
        rendered = out_path.read_text(encoding="utf-8")

        # 1. dovecot preserves node_exporter's real OCI image and restart count
        assert (
            'ns8_container_info{module_id="mail1",container="dovecot",'
            'image="ghcr.io/nethserver/mail-dovecot:1.4.2"} 1'
        ) in rendered
        assert 'ns8_container_restarts_total{module_id="mail1",container="dovecot"} 3' in rendered

        # 2. rspamd (active) and clamd (inactive) are synthesized from cgroups v2!
        assert (
            'ns8_container_info{module_id="mail1",container="rspamd",image="ns8-systemd-unit"} 1'
            in rendered
        )
        assert 'ns8_container_running{module_id="mail1",container="rspamd"} 1' in rendered
        assert 'ns8_container_running{module_id="mail1",container="clamd"} 0' in rendered

        # 3. custom-erp1 (NODE_ID=1) harvested as rootful, remote-only2 (NODE_ID=2) excluded
        assert 'ns8_module_up{module_id="custom-erp1",module_type="rootful"} 1' in rendered
        assert 'ns8_container_running{module_id="custom-erp1",container="custom-erp1"} 1' in rendered
        assert "remote-only2" not in rendered

        # 4. Redis backup hash was NOT polluted by module/*/environment hashes
        assert 'ns8_backup_status{module_id="mail1"} 1' in rendered
        assert 'ns8_backup_status{module_id="custom-erp1"}' not in rendered
    finally:
        http_srv.shutdown()
        http_srv.server_close()
        redis_sock.close()


def test_cgroups_v2_cli_collect_ns8_metrics_without_node_exporter(tmp_path: Path) -> None:
    """Verify bin/collect-ns8-metrics emits full pod & container telemetry without ns8-metrics."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    passwd_file = tmp_path / "passwd"
    _write_lf(passwd_file, "traefik1:x:1001:1001::/home/traefik1:/bin/bash\n")

    cg_root = tmp_path / "cgroup"
    t_slice = cg_root / "user.slice" / "user-1001.slice"
    _write_lf(t_slice / "cpu.stat", "usage_usec 7500000\n")
    _write_lf(t_slice / "memory.current", "67108864\n")
    _write_lf(t_slice / "memory.stat", "inactive_file 7108864\n")
    _write_lf(t_slice / "pids.current", "5\n")
    _write_lf(
        t_slice / "user@1001.service" / "app.slice" / "traefik.service" / "memory.current",
        "60000000\n",
    )
    _write_lf(
        t_slice / "user@1001.service" / "app.slice" / "traefik.service" / "pids.current",
        "4\n",
    )

    env = dict(os.environ)
    env["COLLECTOR_STATE_DIR"] = str(state_dir)
    env["NS8_CGROUP_ROOT"] = str(cg_root)
    env["NS8_PASSWD_FILE"] = str(passwd_file)
    env["NS8_NODE_EXPORTER_URL"] = "http://127.0.0.1:1/unreachable"

    res = subprocess.run(
        [sys.executable, str(IMAGEROOT / "bin" / "collect-ns8-metrics")],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    rendered = (state_dir / "textfile" / "ns8.prom").read_text(encoding="utf-8")
    assert 'ns8_module_up{module_id="traefik1",module_type="rootless"} 1' in rendered
    assert (
        'ns8_module_memory_working_set_bytes{module_id="traefik1",module_type="rootless"} 60000000'
        in rendered
    )
    assert 'ns8_container_running{module_id="traefik1",container="traefik"} 1' in rendered
