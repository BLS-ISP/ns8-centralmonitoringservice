"""CLI entrypoint and negative validation edge-case tests for collector/imageroot/bin and actions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.site_collector.conftest import IMAGEROOT
from tests.site_collector.test_actions_and_ns8_rules import _run_action_script, _write_fake_agent_module


def test_bin_collect_ns8_metrics_render_alloy_and_backup_hooks_cli(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = tmp_path / "fake_agent"
    _write_fake_agent_module(agent_dir)

    # Seed backup JSON fixture so bin/collect-ns8-metrics emits backup metrics end-to-end
    backups_json = state_dir / "ns8-backups.json"
    backups_json.write_text(
        json.dumps(
            {
                "backups": [
                    {
                        "module_id": "samba1",
                        "succeeded": True,
                        "last_success_timestamp": 1732050000,
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    env = dict(os.environ)
    env["COLLECTOR_STATE_DIR"] = str(state_dir)
    env["MODULE_ID"] = "central-monitoring-collector1"

    # 1. bin/collect-ns8-metrics
    res_metrics = subprocess.run(
        [sys.executable, str(IMAGEROOT / "bin" / "collect-ns8-metrics")],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert res_metrics.returncode == 0, res_metrics.stderr
    prom_file = state_dir / "textfile" / "ns8.prom"
    assert prom_file.is_file()
    assert 'ns8_backup_status{module_id="samba1"} 1' in prom_file.read_text(encoding="utf-8")

    # 2. bin/module-dump-state and bin/module-cleanup-state
    stale_tmp = state_dir / ".local-targets.json.tmp.99999.deadbeef"
    stale_tmp.write_text("stale\n", encoding="utf-8", newline="\n")

    res_dump = subprocess.run(
        [sys.executable, str(IMAGEROOT / "bin" / "module-dump-state")],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert res_dump.returncode == 0, res_dump.stderr
    assert (state_dir / "secrets.env").is_file()
    assert (state_dir / "local-targets.json").is_file()

    res_cleanup = subprocess.run(
        [sys.executable, str(IMAGEROOT / "bin" / "module-cleanup-state")],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert res_cleanup.returncode == 0, res_cleanup.stderr
    assert not stale_tmp.exists()

    # 3. bin/render-alloy-config
    (state_dir / "environment").write_text(
        "\n".join(
            [
                "CONFIGURED=1",
                "HUB_URL=https://monitoring.msp.example.com",
                "CUSTOMER=acme-corp",
                "SITE=dc1",
                "COLLECTOR_ID=acme-corp-dc1-ns8",
                "COLLECT_LOCAL_NS8=1",
                "ENABLE_SYSLOG_RECEIVER=0",
                "SYSLOG_PORT=5514",
                "WAL_MAX_DISK_MB=2048",
                "TLS_SKIP_VERIFY=0",
            ]
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (state_dir / "secrets.env").write_text(
        "HUB_AUTH_TOKEN=cms_v1_CliRenderToken12345678901234567890\n",
        encoding="utf-8",
        newline="\n",
    )
    res_render = subprocess.run(
        [sys.executable, str(IMAGEROOT / "bin" / "render-alloy-config")],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert res_render.returncode == 0, res_render.stderr
    alloy_cfg = (state_dir / "config.alloy").read_text(encoding="utf-8")
    assert 'customer     = "acme-corp"' in alloy_cfg
    assert 'site         = "dc1"' in alloy_cfg


def test_negative_validation_errors_in_configure_and_save_local_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = tmp_path / "fake_agent"
    _write_fake_agent_module(agent_dir)

    # 1. configure-module with auth_token_unchanged=True when no token is stored -> exit 2
    bad_cfg = _run_action_script(
        "actions/configure-module/20configure",
        state_dir=state_dir,
        agent_dir=agent_dir,
        stdin_payload={
            "hub_url": "https://monitoring.msp.example.com",
            "auth_token": "",
            "auth_token_unchanged": True,
            "customer": "acme-corp",
            "site": "hq",
        },
    )
    assert bad_cfg.returncode == 2
    errs = json.loads(bad_cfg.stdout)
    assert errs[0]["field"] == "auth_token"

    # 2. save-local-target creating a new proxmox target without pve_token_secret -> exit 2
    bad_pve = _run_action_script(
        "actions/save-local-target/20save",
        state_dir=state_dir,
        agent_dir=agent_dir,
        stdin_payload={
            "name": "Missing Secret PVE",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "10.0.0.50",
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "",
        },
    )
    assert bad_pve.returncode == 2
    pve_errs = json.loads(bad_pve.stdout)
    assert pve_errs[0]["field"] == "pve_token_secret"
