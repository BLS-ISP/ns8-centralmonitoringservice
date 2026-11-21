from __future__ import annotations

from pathlib import Path
from typing import Any

from hub_alerting.silences_manager import restore_silences_to_alertmanager
from tests.hub_probes_alerting.conftest import ACTIONS_DIR, PYPKG_DIR, REPO_ROOT, SCHEMAS_DIR

OWNED_ACTIONS = (
    "list-targets",
    "save-target",
    "delete-target",
    "get-alerting",
    "configure-alerting",
    "test-alert",
    "list-silences",
    "create-silence",
    "delete-silence",
)


def test_silences_crud_global_wildcard_validation_and_offline_fallback(
    hub_env: dict[str, Any],
) -> None:
    run_action = hub_env["run_action"]
    state_dir: Path = hub_env["state_dir"]

    # 1. Create scoped customer/site/role silence with extra_matchers
    created_scoped = run_action(
        "create-silence",
        "20create",
        {
            "customer": "acme-corp",
            "site": "hq",
            "device_role": "windows",
            "extra_matchers": [
                {"name": "alertname", "value": "WindowsHostRebooted", "is_regex": False, "is_equal": True}
            ],
            "starts_at": "2026-11-20T00:00:00Z",
            "ends_at": "2099-12-31T23:59:59Z",
            "created_by": "admin@msp.example.com",
            "comment": "Patch Tuesday Windows maintenance window",
        },
    )
    assert created_scoped["status"] == "ok"
    scoped_id = created_scoped["silence_id"]

    # 2. Create global maintenance window (customer="*") -> must omit customer matcher!
    created_global = run_action(
        "create-silence",
        "20create",
        {
            "customer": "*",
            "starts_at": "2026-11-20T00:00:00Z",
            "ends_at": "2099-12-31T23:59:59Z",
            "created_by": "noc@msp.example.com",
            "comment": "Global core router upgrade",
        },
    )
    global_id = created_global["silence_id"]

    # 3. Verify ends_at <= starts_at fails validation with exit code 2
    bad_proc = run_action(
        "create-silence",
        "20create",
        {
            "customer": "acme-corp",
            "starts_at": "2026-11-25T04:00:00Z",
            "ends_at": "2026-11-25T02:00:00Z",
            "created_by": "admin",
            "comment": "Inverted timestamps must fail",
        },
        expect_success=False,
    )
    assert bad_proc.returncode == 2

    # 4. List silences & check matcher translation
    all_silences = run_action("list-silences", "20read", {"include_expired": False})
    by_id = {s["id"]: s for s in all_silences["silences"]}
    assert scoped_id in by_id
    assert global_id in by_id

    scoped_matchers = {m["name"]: m["value"] for m in by_id[scoped_id]["matchers"]}
    assert scoped_matchers["customer"] == "acme-corp"
    assert scoped_matchers["site"] == "hq"
    assert scoped_matchers["device_role"] == "windows"
    assert scoped_matchers["alertname"] == "WindowsHostRebooted"

    global_matcher_names = [m["name"] for m in by_id[global_id]["matchers"]]
    assert "customer" not in global_matcher_names
    assert len(global_matcher_names) >= 1

    # Filter by customer="acme-corp"
    acme_only = run_action("list-silences", "20read", {"customer": "acme-corp", "include_expired": False})
    acme_ids = [s["id"] for s in acme_only["silences"]]
    assert scoped_id in acme_ids
    assert global_id not in acme_ids

    # 5. Delete silence -> excluded when include_expired=False, included when include_expired=True
    del_res = run_action("delete-silence", "20delete", {"silence_id": scoped_id})
    assert del_res == {"status": "ok", "silence_id": scoped_id, "deleted": True}

    active_after_del = run_action("list-silences", "20read", {"include_expired": False})
    assert scoped_id not in {s["id"] for s in active_after_del["silences"]}

    with_expired = run_action("list-silences", "20read", {"include_expired": True})
    by_id_exp = {s["id"]: s for s in with_expired["silences"]}
    assert by_id_exp[scoped_id]["state"] == "expired"

    # 6. Offline fallback when Alertmanager container is unreachable
    offline_env = {"ALERTMANAGER_URL": "http://127.0.0.1:1"}
    offline_created = run_action(
        "create-silence",
        "20create",
        {
            "customer": "beta-gmbh",
            "site": "berlin",
            "starts_at": "2026-11-20T00:00:00Z",
            "ends_at": "2099-12-31T23:59:59Z",
            "created_by": "offline-admin",
            "comment": "Offline silence persistence check",
        },
        extra_env=offline_env,
    )
    offline_id = offline_created["silence_id"]
    assert (state_dir / "silences.json").is_file()

    offline_list = run_action(
        "list-silences",
        "20read",
        {"customer": "beta-gmbh", "include_expired": False},
        extra_env=offline_env,
    )
    assert any(s["id"] == offline_id for s in offline_list["silences"])

    # 7. Restore persisted silences into online Alertmanager after Restic restore
    restored_count = restore_silences_to_alertmanager(state_dir)
    assert restored_count >= 2


def test_action_schema_byte_parity_and_zero_crlf_line_endings() -> None:
    for action in OWNED_ACTIONS:
        for direction in ("input", "output"):
            shared_bytes = (SCHEMAS_DIR / f"hub-{action}-{direction}.json").read_bytes()
            action_bytes = (ACTIONS_DIR / action / f"validate-{direction}.json").read_bytes()
            assert action_bytes == shared_bytes, f"Schema drift in {action}/validate-{direction}.json"

    # Check LF line endings and absence of pypkg/__init__.py
    assert not (PYPKG_DIR / "__init__.py").exists()

    owned_paths: list[Path] = []
    owned_paths.extend((PYPKG_DIR / "hub_alerting").rglob("*"))
    for action in OWNED_ACTIONS:
        owned_paths.extend((ACTIONS_DIR / action).rglob("*"))
    owned_paths.extend((REPO_ROOT / "tests" / "hub_probes_alerting").rglob("*"))

    bad_crlf = [
        str(p)
        for p in owned_paths
        if p.is_file() and "__pycache__" not in p.parts and b"\r\n" in p.read_bytes()
    ]
    assert not bad_crlf, f"CRLF bytes found in owned files: {bad_crlf}"
