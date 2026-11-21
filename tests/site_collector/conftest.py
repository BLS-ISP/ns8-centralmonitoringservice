"""Shared pytest fixtures for central-monitoring-collector (site-collector) tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COLLECTOR_ROOT = REPO_ROOT / "collector"
IMAGEROOT = COLLECTOR_ROOT / "imageroot"
PYPKG_DIR = IMAGEROOT / "pypkg"
SCHEMAS_DIR = REPO_ROOT / "shared" / "schemas"

if str(PYPKG_DIR) not in sys.path:
    sys.path.insert(0, str(PYPKG_DIR))


@pytest.fixture
def schemas_dir() -> Path:
    return SCHEMAS_DIR


@pytest.fixture
def load_schema(schemas_dir: Path):
    def _load(name: str) -> dict[str, Any]:
        schema_path = schemas_dir / name
        return json.loads(schema_path.read_text(encoding="utf-8"))

    return _load


@pytest.fixture
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    sdir = tmp_path / "state"
    sdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("COLLECTOR_STATE_DIR", str(sdir))
    return sdir
