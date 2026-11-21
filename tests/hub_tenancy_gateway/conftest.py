import sys
from pathlib import Path
from aiohttp.test_utils import TestClient, TestServer
import pytest_asyncio

REPO_ROOT = Path(__file__).resolve().parents[2]
GATEWAY_PKG_ROOT = REPO_ROOT / "hub" / "gateway"
IMAGEROOT_PYPKG = REPO_ROOT / "hub" / "imageroot" / "pypkg"

for p in (GATEWAY_PKG_ROOT, IMAGEROOT_PYPKG):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)


@pytest_asyncio.fixture
async def aiohttp_server():
    servers: list[TestServer] = []

    async def _start(app):
        srv = TestServer(app, host="127.0.0.1")
        await srv.start_server()
        servers.append(srv)
        return srv

    yield _start

    for srv in reversed(servers):
        await srv.close()


@pytest_asyncio.fixture
async def aiohttp_client():
    clients: list[TestClient] = []

    async def _start(app):
        srv = TestServer(app, host="127.0.0.1")
        cli = TestClient(srv)
        await cli.start_server()
        clients.append(cli)
        return cli

    yield _start

    for cli in reversed(clients):
        await cli.close()
