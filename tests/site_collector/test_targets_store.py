"""Unit and schema tests for collector_lib.targets_store."""

from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest


def test_save_and_list_proxmox_target_redacts_secret_and_defaults_port(
    state_dir: Path, load_schema
) -> None:
    from collector_lib.targets_store import TargetsStore

    store = TargetsStore(state_dir)
    saved, created = store.save_target(
        {
            "name": "PVE Cluster HQ",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "192.168.10.20",
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "super-secret-pve-uuid",
            "tls_skip_verify": True,
        }
    )

    assert created is True
    assert saved["id"].startswith("tgt_")
    assert saved["port"] == 8006
    assert saved["scheme"] == "https"

    save_out = {"status": "ok", "id": saved["id"], "created": created}
    jsonschema.validate(save_out, load_schema("collector-save-local-target-output.json"))

    public_list = store.list_public_targets()
    assert len(public_list) == 1
    item = public_list[0]
    assert item["has_pve_token_secret"] is True
    assert "pve_token_secret" not in item
    assert "snmp_community" not in item
    assert "snmp_v3" not in item

    list_out = {"targets": public_list}
    jsonschema.validate(list_out, load_schema("collector-list-local-targets-output.json"))


def test_secret_unchanged_preserves_existing_proxmox_and_snmp_secrets(
    state_dir: Path, load_schema
) -> None:
    from collector_lib.targets_store import TargetsStore

    store = TargetsStore(state_dir)
    created_pve, _ = store.save_target(
        {
            "name": "PVE Node 1",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "10.0.0.10",
            "port": 8006,
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "initial-pve-secret",
        }
    )
    updated_pve, created_flag = store.save_target(
        {
            "id": created_pve["id"],
            "name": "PVE Node 1 Renamed",
            "enabled": True,
            "target_type": "proxmox",
            "device_role": "proxmox",
            "host": "10.0.0.11",
            "port": 8006,
            "pve_token_id": "monitoring@pve!alloy",
            "pve_token_secret": "",
            "secret_unchanged": True,
        }
    )
    assert created_flag is False
    assert updated_pve["host"] == "10.0.0.11"
    assert updated_pve["pve_token_secret"] == "initial-pve-secret"

    created_snmp, _ = store.save_target(
        {
            "name": "Core Firewall",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-firewall",
            "host": "10.0.0.1",
            "snmp_module": "if_mib",
            "snmp_version": "v3",
            "snmp_v3": {
                "username": "mspmonitor",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "auth_password": "auth-secret-password",
                "priv_protocol": "AES256",
                "priv_password": "priv-secret-password",
            },
        }
    )
    assert created_snmp["port"] == 161

    updated_snmp, _ = store.save_target(
        {
            "id": created_snmp["id"],
            "name": "Core Firewall HA",
            "enabled": True,
            "target_type": "snmp",
            "device_role": "snmp-firewall",
            "host": "10.0.0.2",
            "snmp_module": "if_mib",
            "snmp_version": "v3",
            "secret_unchanged": True,
            "snmp_v3": {
                "username": "mspmonitor",
                "security_level": "authPriv",
                "auth_protocol": "SHA256",
                "priv_protocol": "AES256",
            },
        }
    )
    assert updated_snmp["snmp_v3"]["auth_password"] == "auth-secret-password"
    assert updated_snmp["snmp_v3"]["priv_password"] == "priv-secret-password"

    filtered_snmp = store.list_public_targets(target_type="snmp")
    assert len(filtered_snmp) == 1
    assert filtered_snmp[0]["has_snmp_secret"] is True
    jsonschema.validate(
        {"targets": filtered_snmp}, load_schema("collector-list-local-targets-output.json")
    )


def test_default_ports_for_windows_linux_and_delete_target(
    state_dir: Path, load_schema
) -> None:
    from collector_lib.targets_store import TargetsStore

    store = TargetsStore(state_dir)
    win, _ = store.save_target(
        {
            "name": "DC01",
            "enabled": True,
            "target_type": "windows",
            "device_role": "windows",
            "host": "192.168.1.50",
        }
    )
    lin, _ = store.save_target(
        {
            "name": "App01",
            "enabled": True,
            "target_type": "linux",
            "device_role": "linux",
            "host": "192.168.1.51",
        }
    )
    assert win["port"] == 9182
    assert lin["port"] == 9100

    deleted = store.delete_target(win["id"])
    assert deleted is True
    del_out = {"status": "ok", "id": win["id"], "deleted": deleted}
    jsonschema.validate(del_out, load_schema("collector-delete-local-target-output.json"))

    deleted_again = store.delete_target(win["id"])
    assert deleted_again is False
    assert [t["id"] for t in store.list_public_targets()] == [lin["id"]]

    raw_bytes = (state_dir / "local-targets.json").read_bytes()
    assert b"\r\n" not in raw_bytes
    if os.name != "nt":
        assert (state_dir / "local-targets.json").stat().st_mode & 0o777 == 0o600
