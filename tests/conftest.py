from __future__ import annotations

import os
import socket
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from atalaia.api.app import create_app
from atalaia.config import Settings
from tests.vulnapp import make_secure_app, make_vulnerable_app


class Served:
    def __init__(self, factory, host="127.0.0.1"):
        self.state: dict = {}
        sock = socket.socket()
        sock.bind((host, 0))
        self.port = sock.getsockname()[1]
        sock.close()
        self.url = f"http://{host}:{self.port}"
        self.server = uvicorn.Server(uvicorn.Config(factory(self.state), host=host, port=self.port,
                                                    log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started and time.time() < deadline:
            time.sleep(0.02)

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture(scope="session")
def vuln():
    served = Served(make_vulnerable_app)
    yield served
    served.stop()


@pytest.fixture(scope="session")
def secure():
    served = Served(make_secure_app)
    yield served
    served.stop()


@pytest.fixture(autouse=True)
def _reset(request):
    for name in ("vuln", "secure"):
        if name in request.fixturenames:
            served = request.getfixturevalue(name)
            served.state.pop("token", None)
            served.state.pop("third_party", None)
            served.state.get("hits", {}).clear()
            served.state.get("comments", []).clear()
    yield


# Set ATALAIA_TEST_DATABASE_URL (for example postgresql+psycopg://user:pass@localhost/atalaia_test)
# to run the whole suite against another database. The schema "public" is wiped for every test.
TEST_DATABASE_URL = os.environ.get("ATALAIA_TEST_DATABASE_URL", "")
_wiped: set[str] = set()


def _database_url(tmp_path) -> str:
    if not TEST_DATABASE_URL:
        return f"sqlite:///{tmp_path}/test.db"
    if str(tmp_path) not in _wiped:                      # one fresh database per test, like the SQLite file
        _wiped.add(str(tmp_path))
        engine = create_engine(TEST_DATABASE_URL)
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        engine.dispose()
    return TEST_DATABASE_URL


def make_settings(tmp_path, **over) -> Settings:
    base = dict(database_url=_database_url(tmp_path), secret_key="k" * 48, allow_private_targets=True,
                enable_scheduler=False, default_rps=400, max_rps=400, max_pages=60, browser="off")
    base.update(over)
    return Settings(**base)


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


PASSWORD = "Correta-Bateria-Cavalo-42"


def register(client, email="ana@acme.test", org="ACME"):
    r = client.post("/api/v1/auth/register", json={"organization": org, "name": "Ana", "email": email,
                                                   "password": PASSWORD})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture
def auth(client):
    return register(client)


def verified_target(client, auth, served, name="Loja"):
    r = client.post("/api/v1/targets", json={"name": name, "base_url": served.url}, headers=auth)
    assert r.status_code == 201, r.text
    target = r.json()
    served.state["token"] = target["verification"]["http_file"]["content"]
    r = client.post(f"/api/v1/targets/{target['id']}/verify", json={"method": "http_file"}, headers=auth)
    assert r.json()["verified"] is True, r.text
    return target


def run_scan_and_wait(client, auth, target_id, profile="standard"):
    r = client.post("/api/v1/scans", json={"target_id": target_id, "profile": profile}, headers=auth)
    assert r.status_code == 202, r.text
    scan_id = r.json()["id"]
    deadline = time.time() + 60
    while time.time() < deadline:
        scan = client.get(f"/api/v1/scans/{scan_id}", headers=auth).json()
        if scan["status"] not in ("queued", "running"):
            return scan
        time.sleep(0.1)
    raise AssertionError("scan did not finish")
