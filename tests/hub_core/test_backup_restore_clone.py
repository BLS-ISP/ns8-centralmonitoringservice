"""Tests for Restic backup state-include.conf, online SQLite dump/restore, and clone-module."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from tests.hub_core.conftest import IMAGEROOT, FakeNS8Env, execute_script


def test_state_include_toggles_tsdb_volumes(ns8_env: FakeNS8Env) -> None:
    from hub_core.backup_state import update_state_include

    conf_path = update_state_include(ns8_env.etc_dir, backup_include_tsdb=False)
    text_no_tsdb = conf_path.read_text(encoding="utf-8")
    assert "state/environment" in text_no_tsdb
    assert "state/secrets.env" in text_no_tsdb
    assert "state/tenants.json" in text_no_tsdb
    assert "state/portal-secrets.json" in text_no_tsdb
    assert "state/.portal.key" in text_no_tsdb
    assert "state/targets.json" in text_no_tsdb
    assert "state/alerting.json" in text_no_tsdb
    assert "state/silences.json" in text_no_tsdb
    assert "state/grafana.db.bak" in text_no_tsdb
    assert "config/custom-rules" in text_no_tsdb
    assert "volumes/prometheus-data" not in text_no_tsdb
    assert "volumes/loki-data" not in text_no_tsdb

    static_conf = (IMAGEROOT / "etc" / "state-include.conf").read_text(encoding="utf-8")
    assert "state/portal-secrets.json" in static_conf
    assert "state/.portal.key" in static_conf

    update_state_include(ns8_env.etc_dir, backup_include_tsdb=True)
    text_with_tsdb = conf_path.read_text(encoding="utf-8")
    assert "volumes/prometheus-data" in text_with_tsdb
    assert "volumes/loki-data" in text_with_tsdb


def test_online_sqlite_backup_cleanup_and_restore_roundtrip(
    ns8_env: FakeNS8Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_dir = ns8_env.install_dir / "grafana-live"
    live_dir.mkdir(parents=True)
    live_db = live_dir / "grafana.db"

    am_dir = ns8_env.install_dir / "am-live"
    am_dir.mkdir(parents=True)
    (am_dir / "nflog").write_bytes(b"nflog-snapshot-bytes")
    (am_dir / "silences").write_bytes(b"silences-snapshot-bytes")

    # Create WAL-enabled SQLite database simulating active Grafana runtime
    conn = sqlite3.connect(str(live_db))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE org (id INTEGER PRIMARY KEY, name TEXT NOT NULL);")
    conn.execute("INSERT INTO org (id, name) VALUES (1, 'MSP Main Org'), (2, 'Customer: Acme');")
    conn.commit()

    monkeypatch.setenv("GRAFANA_DB_PATH", str(live_db))
    monkeypatch.setenv("ALERTMANAGER_DATA_DIR", str(am_dir))

    # Run bin/module-dump-state while WAL connection is still open!
    exit_code, _, stderr = execute_script(IMAGEROOT / "bin" / "module-dump-state")
    assert exit_code == 0, stderr
    conn.close()

    bak_path = ns8_env.state_dir / "grafana.db.bak"
    assert bak_path.exists()
    assert (ns8_env.state_dir / "alertmanager-state.tar.gz").exists()

    # Verify backup DB integrity independently
    verify_conn = sqlite3.connect(str(bak_path))
    rows = verify_conn.execute("SELECT id, name FROM org ORDER BY id").fetchall()
    verify_conn.close()
    assert rows == [(1, "MSP Main Org"), (2, "Customer: Acme")]

    # Restore into a fresh target location via restore-module
    restored_dir = ns8_env.install_dir / "grafana-restored"
    restored_db = restored_dir / "grafana.db"
    monkeypatch.setenv("GRAFANA_DB_PATH", str(restored_db))

    exit_code_env, _, err_env = execute_script(
        IMAGEROOT / "actions" / "restore-module" / "06copyenv",
        payload={
            "environment": {
                "TRAEFIK_HOST": "restored.msp.example.com",
                "TRAEFIK_LETS_ENCRYPT": "true",
                "TRAEFIK_HTTP2HTTPS": "true",
                "STORAGE_MODE": "local",
                "CONFIGURED": "true",
            }
        },
    )
    assert exit_code_env == 0, err_env
    assert ns8_env.persisted_env["TRAEFIK_HOST"] == "restored.msp.example.com"

    exit_code_cfg, _, err_cfg = execute_script(IMAGEROOT / "actions" / "restore-module" / "50configure")
    assert exit_code_cfg == 0, err_cfg
    assert restored_db.exists()

    restored_conn = sqlite3.connect(str(restored_db))
    restored_rows = restored_conn.execute("SELECT id, name FROM org ORDER BY id").fetchall()
    restored_conn.close()
    assert restored_rows == [(1, "MSP Main Org"), (2, "Customer: Acme")]

    # Verify Traefik route re-registered during restore
    route_calls = [c for c in ns8_env.task_calls if c["action"] == "set-route"]
    assert len(route_calls) == 1
    assert route_calls[0]["data"]["host"] == "restored.msp.example.com"
    assert route_calls[0]["data"]["url"] == "http://127.0.0.1:20080"

    # Now run bin/module-cleanup-state and confirm temporary dump files are removed
    (ns8_env.state_dir / "tenants.json").write_text('{"tenants": []}\n', encoding="utf-8")
    exit_cleanup, _, err_cleanup = execute_script(IMAGEROOT / "bin" / "module-cleanup-state")
    assert exit_cleanup == 0, err_cleanup
    assert not bak_path.exists()
    assert not (ns8_env.state_dir / "alertmanager-state.tar.gz").exists()
    assert (ns8_env.state_dir / "tenants.json").exists()


def test_clone_module_regenerates_internal_secrets_and_avoids_route_collision(
    ns8_env: FakeNS8Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hub_core.env_store import apply_configuration, ensure_initial_secrets, read_secrets

    orig_secrets = ensure_initial_secrets(ns8_env.state_dir)
    apply_configuration(
        ns8_env.state_dir,
        {
            "host": "prod-hub.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
        },
    )

    # Simulate NS8 cloning into central-monitoring-hub2 where prod-hub.msp.example.com is in use by hub1
    ns8_env.set_env("MODULE_ID", "central-monitoring-hub2")
    ns8_env.dump_env()
    ns8_env.routes_in_use.add("prod-hub.msp.example.com")
    ns8_env.task_calls.clear()

    exit_code, _, stderr = execute_script(
        IMAGEROOT / "actions" / "clone-module" / "50configure",
        payload={},
    )
    assert exit_code == 0, stderr

    cloned_secrets = read_secrets(ns8_env.state_dir)
    assert cloned_secrets["GRAFANA_SECRET_KEY"] != orig_secrets["GRAFANA_SECRET_KEY"]
    assert cloned_secrets["HUB_INTERNAL_SECRET"] != orig_secrets["HUB_INTERNAL_SECRET"]
    # Cloned instance clears colliding FQDN rather than stealing prod route
    assert ns8_env.persisted_env["TRAEFIK_HOST"] == ""
    assert ns8_env.persisted_env["CONFIGURED"] == "false"
    assert not [c for c in ns8_env.task_calls if c["action"] == "set-route"]


def test_dump_state_podman_exec_avoids_world_readable_tmp_and_clone_syncs_orgs(
    ns8_env: FakeNS8Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil
    import subprocess
    import sys
    import types

    from hub_core.backup_state import dump_state

    recorded_cmds: list[list[str]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        recorded_cmds.append(list(cmd))
        if cmd[:3] == ["podman", "cp", "grafana:/var/lib/grafana/.grafana.db.bak"]:
            Path(cmd[3]).write_bytes(b"sqlite-dump-bytes")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/podman" if name == "podman" else None)
    res = dump_state(ns8_env.state_dir, runner=fake_runner)
    assert res["grafana_db_dumped"] is True
    for cmd in recorded_cmds:
        assert not any("/tmp/" in part for part in cmd), f"Forbidden /tmp path in podman backup cmd: {cmd}"
    assert any("/var/lib/grafana/.grafana.db.bak" in part for cmd in recorded_cmds for part in cmd)

    # Verify clone-module/50configure invokes sync_all_orgs_if_running after rotating GRAFANA_SECRET_KEY
    synced: list[str] = []
    tenancy_pkg = types.ModuleType("hub_tenancy")
    graf_mod = types.ModuleType("hub_tenancy.grafana_sync")
    graf_mod.sync_all_orgs_if_running = lambda s, e=None: synced.append("synced")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hub_tenancy", tenancy_pkg)
    monkeypatch.setitem(sys.modules, "hub_tenancy.grafana_sync", graf_mod)

    rc, _, stderr = execute_script(
        IMAGEROOT / "actions" / "clone-module" / "50configure",
        payload={"host": "cloned-hub.msp.example.com"},
    )
    assert rc == 0, stderr
    assert synced, "clone-module/50configure must invoke sync_all_orgs_if_running after rotating GRAFANA_SECRET_KEY"
