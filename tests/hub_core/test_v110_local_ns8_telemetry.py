"""Tests for v1.1.0 Hub local NS8 host (/proc) and cgroups-v2 pod/module self-monitoring."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.hub_core.conftest import (
    IMAGEROOT,
    FakeNS8Env,
    execute_script,
    validate_against_schema,
)


@dataclass(frozen=True)
class _FakeStatVfs:
    f_blocks: int
    f_bavail: int
    f_frsize: int = 4096


def _write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


def test_v110_host_proc_and_cgroups_v2_harvester_end_to_end(
    ns8_env: FakeNS8Env,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hub_core.local_ns8_telemetry import collect_hub_ns8_metrics

    proc_root = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    passwd_file = tmp_path / "passwd"

    # 1. Synthetic /proc tree
    _write_lf(
        proc_root / "stat",
        "\n".join(
            [
                "cpu  3000 100 1000 50000 400 20 30 50 0 0",
                "cpu0 1500 50 500 25000 200 10 15 25 0 0",
                "cpu1 1500 50 500 25000 200 10 15 25 0 0",
                "btime 1700000000",
                "",
            ]
        ),
    )
    _write_lf(
        proc_root / "meminfo",
        "\n".join(
            [
                "MemTotal:       16777216 kB",
                "MemFree:         2097152 kB",
                "MemAvailable:    8388608 kB",
                "Buffers:          524288 kB",
                "Cached:          4194304 kB",
                "SwapTotal:       4194304 kB",
                "SwapFree:        3145728 kB",
                "",
            ]
        ),
    )
    _write_lf(proc_root / "loadavg", "1.25 0.85 0.42 2/512 9912\n")
    _write_lf(
        proc_root / "vmstat",
        "\n".join(
            [
                "pgpgin 123456",
                "oom_kill 3",
                "",
            ]
        ),
    )
    _write_lf(
        proc_root / "mounts",
        "\n".join(
            [
                "/dev/vda2 / xfs rw,relatime 0 0",
                "/dev/nvme0n1p1 /var/lib/containers ext4 rw,relatime 0 0",
                "tmpfs /run tmpfs rw,nosuid 0 0",
                "overlay /var/lib/containers/storage/overlay/abc/merged overlay rw 0 0",
                "",
            ]
        ),
    )
    _write_lf(
        proc_root / "diskstats",
        "\n".join(
            [
                "   7       0 loop0 10 0 80 5 0 0 0 0 0 5 5",
                " 252       0 vda 1000 0 2048 500 2000 0 4096 1500 0 800 2000",
                " 252       1 vda1 500 0 1024 250 1000 0 2048 750 0 400 1000",
                " 259       0 nvme0n1 400 0 1024 100 600 0 2048 250 0 200 350",
                " 259       1 nvme0n1p1 400 0 1024 100 600 0 2048 250 0 200 350",
                "",
            ]
        ),
    )
    _write_lf(
        proc_root / "net" / "dev",
        "\n".join(
            [
                "Inter-|   Receive                                                |  Transmit",
                " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
                "    lo: 9999999    1000    0    0    0     0          0         0  9999999    1000    0    0    0     0       0          0",
                "veth99:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0",
                "  eth0: 5000000   12000    2    4    0     0          0         0  8000000   15000    1    3    0     0       0          0",
                "   wg0:  250000     800    0    0    0     0          0         0   300000     850    0    0    0     0       0          0",
                "",
            ]
        ),
    )
    _write_lf(
        proc_root / "mdstat",
        "\n".join(
            [
                "Personalities : [raid1]",
                "md0 : active raid1 sdb1[1] sda1[0]",
                "      1047552 blocks super 1.2 [2/2] [UU]",
                "md1 : active raid1 sdd1[2](F) sdc1[0]",
                "      2097152 blocks super 1.2 [2/1] [U_]",
                "unused devices: <none>",
                "",
            ]
        ),
    )

    # 2. Synthetic /etc/passwd + NS8 Redis state + cgroups-v2 tree
    _write_lf(
        passwd_file,
        "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "adminuser:x:1001:1001:Admin:/home/adminuser:/bin/bash",
                "mail1:x:1005:1005:NS8 Mail:/home/mail1:/bin/bash",
                "central-monitoring-hub1:x:1008:1008:NS8 Hub:/home/central-monitoring-hub1:/bin/bash",
                "",
            ]
        ),
    )
    ns8_env.redis.hashes["module/mail1/environment"] = {"NODE_ID": "1"}
    ns8_env.redis.hashes["module/samba1/environment"] = {"NODE_ID": "1"}
    ns8_env.redis.hashes["module/mail1/backup"] = {
        "status": "ok",
        "last_success": "1700050000",
    }
    ns8_env.redis.hashes["module/samba1/backup"] = {
        "status": "failed",
        "failed": "1",
        "last_success": "1699900000",
    }

    # Rootless mail1 (UID 1005)
    mail_slice = cgroup_root / "user.slice" / "user-1005.slice"
    _write_lf(mail_slice / "cpu.stat", "usage_usec 42500000\nthrottled_usec 1500000\n")
    _write_lf(mail_slice / "memory.current", "1073741824\n")
    _write_lf(mail_slice / "memory.stat", "anon 536870912\ninactive_file 268435456\n")
    _write_lf(mail_slice / "memory.swap.current", "67108864\n")
    _write_lf(mail_slice / "memory.max", "2147483648\n")
    _write_lf(mail_slice / "memory.events", "low 0\nhigh 0\nmax 0\noom 1\noom_kill 2\n")
    _write_lf(mail_slice / "pids.current", "38\n")
    _write_lf(
        mail_slice / "io.stat",
        "252:0 rbytes=10485760 wbytes=20971520 rios=100 wios=200\n259:0 rbytes=5242880 wbytes=1048576\n",
    )

    dovecot_unit = mail_slice / "user@1005.service" / "app.slice" / "dovecot.service"
    _write_lf(dovecot_unit / "cpu.stat", "usage_usec 12000000\n")
    _write_lf(dovecot_unit / "memory.current", "402653184\n")
    _write_lf(dovecot_unit / "memory.stat", "inactive_file 67108864\n")
    _write_lf(dovecot_unit / "pids.current", "14\n")

    rspamd_unit = mail_slice / "user@1005.service" / "user.slice" / "rspamd.service"
    _write_lf(rspamd_unit / "cpu.stat", "usage_usec 8500000\n")
    _write_lf(rspamd_unit / "memory.current", "268435456\n")
    _write_lf(rspamd_unit / "memory.stat", "inactive_file 0\n")
    _write_lf(rspamd_unit / "pids.current", "9\n")

    # Ignored generic sub-units
    _write_lf(mail_slice / "user@1005.service" / "app.slice" / "dbus.service" / "pids.current", "1\n")
    _write_lf(mail_slice / "user@1005.service" / "app.slice" / "podman-pause-123.service" / "pids.current", "1\n")

    # Rootless central-monitoring-hub1 (UID 1008)
    hub_slice = cgroup_root / "user.slice" / "user-1008.slice"
    _write_lf(hub_slice / "cpu.stat", "usage_usec 95000000\nthrottled_usec 0\n")
    _write_lf(hub_slice / "memory.current", "1610612736\n")
    _write_lf(hub_slice / "memory.stat", "inactive_file 134217728\n")
    _write_lf(hub_slice / "memory.swap.current", "0\n")
    _write_lf(hub_slice / "memory.max", "max\n")
    _write_lf(hub_slice / "memory.events", "oom_kill 0\n")
    _write_lf(hub_slice / "pids.current", "64\n")
    _write_lf(hub_slice / "io.stat", "252:0 rbytes=4096 wbytes=8192\n")

    # Rootful samba1 in system.slice (plus generic sshd.service that must be ignored)
    samba_slice = cgroup_root / "system.slice" / "samba1.service"
    _write_lf(samba_slice / "cpu.stat", "usage_usec 18750000\nthrottled_usec 250000\n")
    _write_lf(samba_slice / "memory.current", "536870912\n")
    _write_lf(samba_slice / "memory.stat", "inactive_file 33554432\n")
    _write_lf(samba_slice / "memory.swap.current", "16777216\n")
    _write_lf(samba_slice / "memory.max", "max\n")
    _write_lf(samba_slice / "memory.events", "oom_kill 0\n")
    _write_lf(samba_slice / "pids.current", "22\n")
    _write_lf(samba_slice / "io.stat", "252:0 rbytes=1024 wbytes=2048\n")
    _write_lf(cgroup_root / "system.slice" / "sshd.service" / "pids.current", "2\n")

    vfs_map = {
        "/": _FakeStatVfs(f_blocks=25_000_000, f_bavail=15_000_000),
        "/var/lib/containers": _FakeStatVfs(f_blocks=50_000_000, f_bavail=40_000_000),
    }

    out_path = collect_hub_ns8_metrics(
        ns8_env.state_dir,
        proc_root=proc_root,
        cgroup_root=cgroup_root,
        passwd_path=passwd_file,
        statvfs_fn=lambda mnt: vfs_map[mnt],
    )
    assert out_path == ns8_env.state_dir / "textfile" / "ns8-hub-node.prom"
    raw_bytes = out_path.read_bytes()
    assert b"\r\n" not in raw_bytes
    prom = raw_bytes.decode("utf-8")

    # Verify host /proc metrics
    assert 'node_cpu_seconds_total{cpu="0",mode="idle"} ' in prom
    assert 'node_cpu_seconds_total{cpu="1",mode="iowait"} ' in prom
    assert f"node_memory_MemTotal_bytes {16777216 * 1024}\n" in prom
    assert f"node_memory_MemAvailable_bytes {8388608 * 1024}\n" in prom
    assert f"node_memory_Buffers_bytes {524288 * 1024}\n" in prom
    assert f"node_memory_Cached_bytes {4194304 * 1024}\n" in prom
    assert f"node_memory_SwapTotal_bytes {4194304 * 1024}\n" in prom
    assert f"node_memory_SwapFree_bytes {3145728 * 1024}\n" in prom
    assert "node_load1 1.25\n" in prom
    assert "node_load5 0.85\n" in prom
    assert "node_load15 0.42\n" in prom
    assert "node_boot_time_seconds 1700000000\n" in prom
    assert "node_vmstat_oom_kill 3\n" in prom
    assert (
        f'node_filesystem_size_bytes{{device="/dev/vda2",fstype="xfs",mountpoint="/"}} {25_000_000 * 4096}\n'
        in prom
    )
    assert (
        f'node_filesystem_avail_bytes{{device="/dev/nvme0n1p1",fstype="ext4",mountpoint="/var/lib/containers"}} {40_000_000 * 4096}\n'
        in prom
    )
    assert 'mountpoint="/run"' not in prom
    assert "overlay" not in prom

    # Disks (partitions & loop0 skipped)
    assert f'node_disk_read_bytes_total{{device="vda"}} {2048 * 512}\n' in prom
    assert f'node_disk_written_bytes_total{{device="vda"}} {4096 * 512}\n' in prom
    assert 'node_disk_reads_completed_total{device="vda"} 1000\n' in prom
    assert 'node_disk_writes_completed_total{device="vda"} 2000\n' in prom
    assert 'node_disk_read_time_seconds_total{device="vda"} 0.5\n' in prom
    assert 'node_disk_write_time_seconds_total{device="vda"} 1.5\n' in prom
    assert 'device="vda1"' not in prom
    assert 'device="nvme0n1p1"' not in prom
    assert 'device="loop0"' not in prom

    # Network (lo & veth99 skipped; eth0 & wg0 included)
    assert 'node_network_receive_bytes_total{device="eth0"} 5000000\n' in prom
    assert 'node_network_transmit_bytes_total{device="eth0"} 8000000\n' in prom
    assert 'node_network_receive_errs_total{device="eth0"} 2\n' in prom
    assert 'node_network_transmit_errs_total{device="eth0"} 1\n' in prom
    assert 'node_network_receive_drop_total{device="eth0"} 4\n' in prom
    assert 'node_network_transmit_drop_total{device="eth0"} 3\n' in prom
    assert 'node_network_receive_bytes_total{device="wg0"} 250000\n' in prom
    assert 'device="lo"' not in prom
    assert 'device="veth99"' not in prom

    # mdadm RAID arrays
    assert 'node_md_disks{device="md0",state="active"} 2\n' in prom
    assert 'node_md_disks{device="md0",state="failed"} 0\n' in prom
    assert 'node_md_disks_required{device="md0"} 2\n' in prom
    assert 'node_md_disks{device="md1",state="active"} 1\n' in prom
    assert 'node_md_disks{device="md1",state="failed"} 1\n' in prom
    assert 'node_md_disks_required{device="md1"} 2\n' in prom

    # NS8 cgroups-v2 modules (rootless mail1, central-monitoring-hub1, rootful samba1; sshd excluded)
    assert 'ns8_module_up{module_id="mail1",module_type="rootless"} 1\n' in prom
    assert 'ns8_module_cpu_seconds_total{module_id="mail1",module_type="rootless"} 42.5\n' in prom
    assert 'ns8_module_cpu_throttled_seconds_total{module_id="mail1",module_type="rootless"} 1.5\n' in prom
    assert (
        f'ns8_module_memory_working_set_bytes{{module_id="mail1",module_type="rootless"}} {1073741824 - 268435456}\n'
        in prom
    )
    assert 'ns8_module_memory_bytes{module_id="mail1",module_type="rootless"} 1073741824\n' in prom
    assert 'ns8_module_memory_swap_bytes{module_id="mail1",module_type="rootless"} 67108864\n' in prom
    assert 'ns8_module_memory_limit_bytes{module_id="mail1",module_type="rootless"} 2147483648\n' in prom
    assert 'ns8_module_oom_kills_total{module_id="mail1",module_type="rootless"} 2\n' in prom
    assert (
        f'ns8_module_io_read_bytes_total{{module_id="mail1",module_type="rootless"}} {10485760 + 5242880}\n'
        in prom
    )
    assert (
        f'ns8_module_io_write_bytes_total{{module_id="mail1",module_type="rootless"}} {20971520 + 1048576}\n'
        in prom
    )
    assert 'ns8_module_pids{module_id="mail1",module_type="rootless"} 38\n' in prom

    assert 'ns8_module_up{module_id="samba1",module_type="rootful"} 1\n' in prom
    assert 'ns8_module_memory_limit_bytes{module_id="samba1",module_type="rootful"} 0\n' in prom
    assert 'module_id="sshd"' not in prom
    assert 'module_id="adminuser"' not in prom

    # Sub-units & synthesized containers
    assert 'ns8_pod_unit_cpu_seconds_total{module_id="mail1",unit="dovecot"} 12\n' in prom
    assert (
        f'ns8_pod_unit_memory_working_set_bytes{{module_id="mail1",unit="dovecot"}} {402653184 - 67108864}\n'
        in prom
    )
    assert 'ns8_pod_unit_cpu_seconds_total{module_id="mail1",unit="rspamd"} 8.5\n' in prom
    assert 'ns8_container_running{module_id="mail1",container="dovecot"} 1\n' in prom
    assert 'unit="dbus"' not in prom
    assert "podman-pause" not in prom

    # Restic backups from Redis
    assert 'ns8_backup_status{module_id="mail1"} 1\n' in prom
    assert 'ns8_backup_failed{module_id="samba1"} 1\n' in prom
    assert 'ns8_backup_last_success_timestamp_seconds{module_id="mail1"} 1700050000\n' in prom


def test_v110_self_monitoring_configure_toggle_timer_and_backfill(
    ns8_env: FakeNS8Env,
) -> None:
    rc_init, _, err_init = execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    assert rc_init == 0, err_init
    assert ns8_env.persisted_env["MONITOR_LOCAL_NS8_NODE"] == "true"
    assert ns8_env.persisted_env["LOCAL_NODE_CUSTOMER"] == "_msp_internal"
    assert ns8_env.persisted_env["LOCAL_NODE_SITE"] == "hub"

    # 1. Configure with custom tenant + site for local NS8 Hub node
    enable_payload = {
        "host": "hub.bls-isp.net",
        "lets_encrypt": True,
        "http2https": True,
        "storage_mode": "local",
        "monitor_local_ns8_node": True,
        "local_node_customer": "bls-isp",
        "local_node_site": "dc-karlsruhe",
    }
    validate_against_schema("hub-configure-module-input.json", enable_payload)

    rc_20, out_20, err_20 = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload=enable_payload,
    )
    assert rc_20 == 0, err_20
    validate_against_schema("hub-configure-module-output.json", json.loads(out_20))

    prom_yml = (ns8_env.config_dir / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    assert "job_name: hub-ns8-node" in prom_yml
    assert "metrics_path: /metrics/ns8-node" in prom_yml
    assert 'targets: ["127.0.0.1:9097"]' in prom_yml
    assert 'customer: "bls-isp"' in prom_yml
    assert 'site: "dc-karlsruhe"' in prom_yml
    assert 'instance: "hub.bls-isp.net"' in prom_yml
    assert 'device_role: "ns8"' in prom_yml
    assert 'collector_id: "hub-local"' in prom_yml
    assert (ns8_env.state_dir / "textfile" / "ns8-hub-node.prom").is_file()

    copied_dashboards = {
        p.name for p in (ns8_env.config_dir / "grafana" / "dashboards").glob("*.json")
    }
    assert copied_dashboards >= {
        "ns8-multi-cluster-overview.json",
        "ns8-pods-and-modules.json",
        "linux-windows-servers.json",
        "proxmox-snmp-infrastructure.json",
        "web-ssl-uptime.json",
        "central-log-explorer.json",
    }

    rc_80, _, err_80 = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "80start_services",
        payload={},
    )
    assert rc_80 == 0, err_80
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "active"

    rc_read, out_read, err_read = execute_script(
        IMAGEROOT / "actions" / "get-configuration" / "20read",
        payload={},
    )
    assert rc_read == 0, err_read
    cfg_doc = json.loads(out_read)
    validate_against_schema("hub-get-configuration-output.json", cfg_doc)
    assert cfg_doc["monitor_local_ns8_node"] is True
    assert cfg_doc["local_node_customer"] == "bls-isp"
    assert cfg_doc["local_node_site"] == "dc-karlsruhe"

    # Also verify bin/collect-hub-ns8-metrics runs cleanly via CLI entrypoint
    rc_bin, _, err_bin = execute_script(IMAGEROOT / "bin" / "collect-hub-ns8-metrics")
    assert rc_bin == 0, err_bin

    # 2. Disable monitor_local_ns8_node -> removes job from prometheus.yml and stops timer
    disable_payload = {
        "host": "hub.bls-isp.net",
        "lets_encrypt": True,
        "http2https": True,
        "storage_mode": "local",
        "monitor_local_ns8_node": False,
        "local_node_customer": "bls-isp",
        "local_node_site": "dc-karlsruhe",
    }
    validate_against_schema("hub-configure-module-input.json", disable_payload)

    rc_20_off, _, err_20_off = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload=disable_payload,
    )
    assert rc_20_off == 0, err_20_off
    prom_yml_off = (ns8_env.config_dir / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    assert "job_name: hub-ns8-node" not in prom_yml_off
    assert not (ns8_env.state_dir / "textfile" / "ns8-hub-node.prom").exists()

    rc_80_off, _, err_80_off = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "80start_services",
        payload={},
    )
    assert rc_80_off == 0, err_80_off
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "inactive"

    # 3. Reject invalid local_node_customer with exit code 2
    rc_bad, out_bad, _ = execute_script(
        IMAGEROOT / "actions" / "configure-module" / "20configure",
        payload={
            "host": "hub.bls-isp.net",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "local_node_customer": "../invalid",
        },
    )
    assert rc_bad == 2
    bad_errors = json.loads(out_bad)
    assert bad_errors[0]["field"] == "local_node_customer"

    # 4. Verify v1.0.4 -> v1.1.0 update-module (20pull_images + 50update) and 06copyenv backfill
    ns8_env.unset_env("MONITOR_LOCAL_NS8_NODE")
    ns8_env.unset_env("LOCAL_NODE_CUSTOMER")
    ns8_env.unset_env("LOCAL_NODE_SITE")
    ns8_env.dump_env()

    rc_pull, _, err_pull = execute_script(IMAGEROOT / "update-module.d" / "20pull_images")
    assert rc_pull == 0, err_pull
    assert ns8_env.persisted_env["MONITOR_LOCAL_NS8_NODE"] == "true"
    assert ns8_env.persisted_env["LOCAL_NODE_CUSTOMER"] == "_msp_internal"
    assert ns8_env.persisted_env["LOCAL_NODE_SITE"] == "hub"

    rc_upd, _, err_upd = execute_script(IMAGEROOT / "update-module.d" / "50update")
    assert rc_upd == 0, err_upd
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "active"
    assert (ns8_env.state_dir / "textfile" / "ns8-hub-node.prom").is_file()


def test_v110_sec02_restore_and_clone_reconcile_metrics_timer_and_prom_file(
    ns8_env: FakeNS8Env,
) -> None:
    execute_script(IMAGEROOT / "actions" / "create-module" / "20initialize")
    prom_file = ns8_env.state_dir / "textfile" / "ns8-hub-node.prom"

    # 1. Restore with MONITOR_LOCAL_NS8_NODE=true -> writes ns8-hub-node.prom and starts timer
    rc_copy_on, _, err_copy_on = execute_script(
        IMAGEROOT / "actions" / "restore-module" / "06copyenv",
        payload={
            "environment": {
                "TRAEFIK_HOST": "restored-on.bls-isp.net",
                "CONFIGURED": "true",
                "STORAGE_MODE": "local",
                "MONITOR_LOCAL_NS8_NODE": "true",
                "LOCAL_NODE_CUSTOMER": "bls-isp",
                "LOCAL_NODE_SITE": "hub",
            }
        },
    )
    assert rc_copy_on == 0, err_copy_on
    rc_rest_on, _, err_rest_on = execute_script(IMAGEROOT / "actions" / "restore-module" / "50configure")
    assert rc_rest_on == 0, err_rest_on
    assert prom_file.is_file()
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "active"

    # 2. Restore with MONITOR_LOCAL_NS8_NODE=false -> unlinks stale ns8-hub-node.prom and stops timer
    rc_copy_off, _, err_copy_off = execute_script(
        IMAGEROOT / "actions" / "restore-module" / "06copyenv",
        payload={
            "environment": {
                "TRAEFIK_HOST": "restored-off.bls-isp.net",
                "CONFIGURED": "true",
                "STORAGE_MODE": "local",
                "MONITOR_LOCAL_NS8_NODE": "false",
            }
        },
    )
    assert rc_copy_off == 0, err_copy_off
    rc_rest_off, _, err_rest_off = execute_script(IMAGEROOT / "actions" / "restore-module" / "50configure")
    assert rc_rest_off == 0, err_rest_off
    assert not prom_file.exists()
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "inactive"

    # 3. Clone with MONITOR_LOCAL_NS8_NODE=true -> writes ns8-hub-node.prom and starts timer
    ns8_env.set_env("MONITOR_LOCAL_NS8_NODE", "true")
    ns8_env.dump_env()
    rc_clone_on, _, err_clone_on = execute_script(
        IMAGEROOT / "actions" / "clone-module" / "50configure",
        payload={"host": "cloned-on.bls-isp.net"},
    )
    assert rc_clone_on == 0, err_clone_on
    assert prom_file.is_file()
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "active"

    # 4. Clone with MONITOR_LOCAL_NS8_NODE=false -> unlinks stale ns8-hub-node.prom and stops timer
    ns8_env.set_env("MONITOR_LOCAL_NS8_NODE", "false")
    ns8_env.dump_env()
    rc_clone_off, _, err_clone_off = execute_script(
        IMAGEROOT / "actions" / "clone-module" / "50configure",
        payload={"host": "cloned-off.bls-isp.net"},
    )
    assert rc_clone_off == 0, err_clone_off
    assert not prom_file.exists()
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "inactive"


def test_v110_arch02_stopped_rootless_module_rootful_parity_and_destroy_timer(
    ns8_env: FakeNS8Env,
    tmp_path: Path,
) -> None:
    from hub_core.local_ns8_telemetry import collect_hub_ns8_metrics

    cgroup_root = tmp_path / "cgroup"
    passwd_file = tmp_path / "passwd"
    _write_lf(
        passwd_file,
        "\n".join(
            [
                "nextcloud1:x:1012:1012:NS8 Nextcloud:/home/nextcloud1:/bin/bash",
                "",
            ]
        ),
    )

    # Stopped Redis-known rootful module crowdsec1 (no system.slice dir) + multi-unit samba1 + ldapproxy1 + nethvoice-proxy1-haproxy
    ns8_env.redis.hashes["module/crowdsec1/environment"] = {"NODE_ID": "1"}

    samba_dc = cgroup_root / "system.slice" / "samba1-dc.service"
    _write_lf(samba_dc / "memory.current", "268435456\n")
    _write_lf(samba_dc / "memory.max", "536870912\n")
    _write_lf(samba_dc / "pids.current", "10\n")

    samba_wb = cgroup_root / "system.slice" / "samba1-winbind.service"
    _write_lf(samba_wb / "memory.current", "67108864\n")
    _write_lf(samba_wb / "memory.max", "2147483648\n")
    _write_lf(samba_wb / "pids.current", "4\n")

    ldap_svc = cgroup_root / "system.slice" / "ldapproxy1.service"
    _write_lf(ldap_svc / "memory.current", "33554432\n")
    _write_lf(ldap_svc / "pids.current", "2\n")

    nv_svc = cgroup_root / "system.slice" / "nethvoice-proxy1-haproxy.service"
    _write_lf(nv_svc / "memory.current", "67108864\n")
    _write_lf(nv_svc / "pids.current", "3\n")

    out_path = collect_hub_ns8_metrics(
        ns8_env.state_dir,
        proc_root=None,
        cgroup_root=cgroup_root,
        passwd_path=passwd_file,
    )
    prom = out_path.read_text(encoding="utf-8")

    # 1. Stopped /etc/passwd rootless module (no user-1012.slice) emits ns8_module_up=0
    assert 'ns8_module_up{module_id="nextcloud1",module_type="rootless"} 0\n' in prom
    # 2. Stopped Redis-known rootful module emits ns8_module_up=0
    assert 'ns8_module_up{module_id="crowdsec1",module_type="rootful"} 0\n' in prom
    # 3. Rootful multi-unit aggregation uses max(finite_limits) and matches ldapproxy1 + nethvoice-proxy1
    assert 'ns8_module_up{module_id="samba1",module_type="rootful"} 1\n' in prom
    assert 'ns8_module_memory_limit_bytes{module_id="samba1",module_type="rootful"} 2147483648\n' in prom
    assert 'ns8_module_up{module_id="ldapproxy1",module_type="rootful"} 1\n' in prom
    assert 'ns8_module_up{module_id="nethvoice-proxy1",module_type="rootful"} 1\n' in prom

    # 4. destroy-module stops & disables both hub-ns8-metrics.timer and hub-ns8-metrics.service
    ns8_env.systemctl_state["hub-ns8-metrics.timer"] = "active"
    ns8_env.systemctl_state["hub-ns8-metrics.service"] = "active"
    rc_rm, _, err_rm = execute_script(IMAGEROOT / "actions" / "destroy-module" / "20destroy")
    assert rc_rm == 0, err_rm
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.timer") == "inactive"
    assert ns8_env.systemctl_state.get("hub-ns8-metrics.service") == "inactive"
