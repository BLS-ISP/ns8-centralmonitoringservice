"""Test package bridge keeping `tests/hub_core` and `hub/imageroot/pypkg/hub_core` unified."""

from __future__ import annotations

from pathlib import Path as _Path

_TEST_INIT_FILE = __file__
_PROD_HUB_CORE = _Path(__file__).resolve().parents[2] / "hub" / "imageroot" / "pypkg" / "hub_core"
_PROD_INIT = _PROD_HUB_CORE / "__init__.py"

if str(_PROD_HUB_CORE) not in __path__:
    __path__.insert(0, str(_PROD_HUB_CORE))

if _PROD_INIT.is_file():
    __file__ = str(_PROD_INIT)
    try:
        exec(compile(_PROD_INIT.read_text(encoding="utf-8"), str(_PROD_INIT), "exec"), globals())
    finally:
        __file__ = _TEST_INIT_FILE
