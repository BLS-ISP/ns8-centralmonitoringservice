"""Restic backup state-include management and online SQLite / Alertmanager dump & restore."""

from __future__ import annotations

import io
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Callable

from hub_core import atomic_write_text, resolve_state_dir

BASE_STATE_INCLUDE_ENTRIES: tuple[str, ...] = (
    "state/environment",
    "state/secrets.env",
    "state/smarthost.env",
    "state/tenants.json",
    "state/portal-secrets.json",
    "state/.portal.key",
    "state/targets.json",
    "state/alerting.json",
    "state/alerting-secrets.json",
    "state/silences.json",
    "state/grafana.db.bak",
    "state/alertmanager-state.tar.gz",
    "config/custom-rules",
)

TSDB_VOLUME_ENTRIES: tuple[str, ...] = (
    "volumes/prometheus-data",
    "volumes/loki-data",
)


def render_state_include_content(backup_include_tsdb: bool) -> str:
    lines = [
        "# NS8 Restic backup state-include list for central-monitoring-hub",
        *BASE_STATE_INCLUDE_ENTRIES,
    ]
    if backup_include_tsdb:
        lines.extend(TSDB_VOLUME_ENTRIES)
    return "\n".join(lines) + "\n"


def update_state_include(etc_dir: Path, *, backup_include_tsdb: bool) -> Path:
    """Write etc/state-include.conf atomically with optional TSDB volume inclusion."""
    target = etc_dir / "state-include.conf"
    atomic_write_text(target, render_state_include_content(backup_include_tsdb), mode=0o644)
    return target


def _online_sqlite_backup(source_db: Path, dest_db: Path) -> None:
    """Perform an online WAL-safe SQLite .backup into dest_db atomically."""
    dest_db.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(dest_db.parent), prefix=f".{dest_db.name}.")
    os.close(fd)
    try:
        src_conn = sqlite3.connect(f"file:{source_db.as_posix()}?mode=ro", uri=True, timeout=30.0)
        try:
            dst_conn = sqlite3.connect(tmp_name, timeout=30.0)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, dest_db)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def _archive_alertmanager_dir(source_dir: Path, archive_path: Path) -> bool:
    """Snapshot Alertmanager nflog and silences files into a compact tar.gz archive."""
    candidates = [p for name in ("nflog", "silences") if (p := source_dir / name).is_file()]
    if not candidates:
        return False
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for item in candidates:
            tar.add(str(item), arcname=item.name)
    fd, tmp_name = tempfile.mkstemp(dir=str(archive_path.parent), prefix=".am-state.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(buf.getvalue())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, archive_path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
    return True


def _safe_run(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    cmd: list[str],
) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(cmd, capture_output=True, text=True, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _resolve_podman_volume_mount(volume_name: str, runner: Callable[..., subprocess.CompletedProcess[str]]) -> Path | None:
    if shutil.which("podman") is None:
        return None
    proc = _safe_run(
        runner,
        ["podman", "volume", "inspect", "--format", "{{.Mountpoint}}", volume_name],
    )
    if proc is not None and proc.returncode == 0 and proc.stdout.strip():
        mp = Path(proc.stdout.strip())
        if mp.exists():
            return mp
    return None


def dump_state(
    state_dir: str | Path | None = None,
    *,
    grafana_db_path: Path | None = None,
    alertmanager_data_dir: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, bool]:
    """Create online SQLite backup of grafana.db and Alertmanager runtime state snapshot."""
    sdir = resolve_state_dir(state_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    bak_target = sdir / "grafana.db.bak"
    am_archive = sdir / "alertmanager-state.tar.gz"

    db_dumped = False
    explicit_db = grafana_db_path or (
        Path(env_db) if (env_db := os.environ.get("GRAFANA_DB_PATH")) else None
    )

    if explicit_db and explicit_db.is_file():
        _online_sqlite_backup(explicit_db, bak_target)
        db_dumped = True
    else:
        # Try running container sqlite3 .backup first, then rootless volume mountpoint fallback
        if shutil.which("podman") is not None:
            exec_proc = _safe_run(
                runner,
                [
                    "podman",
                    "exec",
                    "grafana",
                    "sqlite3",
                    "/var/lib/grafana/grafana.db",
                    ".backup '/var/lib/grafana/.grafana.db.bak'",
                ],
            )
            if exec_proc is not None and exec_proc.returncode == 0:
                cp_proc = _safe_run(
                    runner,
                    ["podman", "cp", "grafana:/var/lib/grafana/.grafana.db.bak", str(bak_target)],
                )
                _safe_run(
                    runner,
                    ["podman", "exec", "grafana", "rm", "-f", "/var/lib/grafana/.grafana.db.bak"],
                )
                if cp_proc is not None and cp_proc.returncode == 0 and bak_target.is_file():
                    os.chmod(bak_target, 0o600)
                    db_dumped = True

        if not db_dumped:
            vol_mp = _resolve_podman_volume_mount("grafana-data", runner)
            if vol_mp and (vol_mp / "grafana.db").is_file():
                _online_sqlite_backup(vol_mp / "grafana.db", bak_target)
                db_dumped = True

    am_dumped = False
    explicit_am = alertmanager_data_dir or (
        Path(env_am) if (env_am := os.environ.get("ALERTMANAGER_DATA_DIR")) else None
    )
    if explicit_am and explicit_am.is_dir():
        am_dumped = _archive_alertmanager_dir(explicit_am, am_archive)
    else:
        vol_am = _resolve_podman_volume_mount("alertmanager-data", runner)
        if vol_am and vol_am.is_dir():
            am_dumped = _archive_alertmanager_dir(vol_am, am_archive)

    return {"grafana_db_dumped": db_dumped, "alertmanager_state_dumped": am_dumped}


def cleanup_state(state_dir: str | Path | None = None) -> None:
    """Remove temporary dump artifacts after Restic finishes snapshotting."""
    sdir = resolve_state_dir(state_dir)
    for temp_name in ("grafana.db.bak", "alertmanager-state.tar.gz"):
        candidate = sdir / temp_name
        if candidate.exists():
            candidate.unlink()


def restore_state(
    state_dir: str | Path | None = None,
    *,
    grafana_db_path: Path | None = None,
    alertmanager_data_dir: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, bool]:
    """Restore grafana.db.bak and Alertmanager state snapshot into target volumes before start."""
    sdir = resolve_state_dir(state_dir)
    bak_source = sdir / "grafana.db.bak"
    am_archive = sdir / "alertmanager-state.tar.gz"

    db_restored = False
    if bak_source.is_file():
        target_db = grafana_db_path or (
            Path(env_db) if (env_db := os.environ.get("GRAFANA_DB_PATH")) else None
        )
        if target_db is None and shutil.which("podman") is not None:
            _safe_run(runner, ["podman", "volume", "create", "--ignore", "grafana-data"])
            vol_mp = _resolve_podman_volume_mount("grafana-data", runner)
            if vol_mp is not None:
                target_db = vol_mp / "grafana.db"

        if target_db is not None:
            target_db.parent.mkdir(parents=True, exist_ok=True)
            for suffix in ("-wal", "-shm"):
                stale = Path(f"{target_db}{suffix}")
                if stale.exists():
                    stale.unlink()
            _online_sqlite_backup(bak_source, target_db)
            db_restored = True

    am_restored = False
    if am_archive.is_file():
        target_am = alertmanager_data_dir or (
            Path(env_am) if (env_am := os.environ.get("ALERTMANAGER_DATA_DIR")) else None
        )
        if target_am is None and shutil.which("podman") is not None:
            _safe_run(
                runner,
                ["podman", "volume", "create", "--ignore", "alertmanager-data"],
            )
            target_am = _resolve_podman_volume_mount("alertmanager-data", runner)

        if target_am is not None:
            target_am.mkdir(parents=True, exist_ok=True)
            with tarfile.open(am_archive, mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.name in ("nflog", "silences") and member.isfile():
                        extracted = tar.extractfile(member)
                        if extracted is not None:
                            dest = target_am / member.name
                            dest.write_bytes(extracted.read())
                            os.chmod(dest, 0o600)
                            am_restored = True

    return {"grafana_db_restored": db_restored, "alertmanager_state_restored": am_restored}
