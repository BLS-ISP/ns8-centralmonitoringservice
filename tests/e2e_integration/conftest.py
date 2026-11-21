"""Pytest fixtures for NS8-CentralMonitoringService E2E cross-module integration tests."""

from __future__ import annotations

import pytest_asyncio

from tests.e2e_integration.harness import LiveObservabilityBackends


@pytest_asyncio.fixture
async def live_backends():
    """Spin up real localhost aiohttp servers for Prometheus, Loki, Grafana, Alertmanager, Push & Alloy."""
    backends = LiveObservabilityBackends()
    await backends.start_all()
    try:
        yield backends
    finally:
        await backends.close_all()
