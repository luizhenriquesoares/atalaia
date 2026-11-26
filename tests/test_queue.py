"""The scan queue lives in the database, so several worker processes can share it safely."""
import threading
import time
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from atalaia.api.app import create_app
from atalaia.models import AuditLog, Scan, Target, utcnow
from atalaia.scans import ScanManager
from atalaia.security import SecretBox
from tests.conftest import make_settings, register, verified_target

API = "/api/v1"


def api_only(tmp_path, **over):
    """An API process that only queues scans, as in a deployment with dedicated workers."""
    settings = make_settings(tmp_path, embedded_worker=False, worker_poll_seconds=0.1, **over)
    return settings, TestClient(create_app(settings))


def worker(settings, client) -> ScanManager:
    return ScanManager(settings, client.app.state.session_factory, SecretBox(settings.secret_key))


def wait_status(client, auth, scan_id, wanted, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        scan = client.get(f"{API}/scans/{scan_id}", headers=auth).json()
        if scan["status"] in wanted:
            return scan
        time.sleep(0.05)
    raise AssertionError(f"scan stayed {scan['status']}")


def test_scans_wait_in_the_queue_until_a_worker_exists(tmp_path, vuln):
    settings, ctx = api_only(tmp_path)
    with ctx as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        scan = client.post(f"{API}/scans", json={"target_id": target["id"], "profile": "passive"}, headers=auth).json()
        time.sleep(0.4)
        assert client.get(f"{API}/scans/{scan['id']}", headers=auth).json()["status"] == "queued"
        w = worker(settings, client)
        w.start()
        try:
            done = wait_status(client, auth, scan["id"], ("completed", "failed"))
        finally:
            w.shutdown()
        assert done["status"] == "completed"


def test_two_workers_run_each_scan_exactly_once(tmp_path, vuln, secure):
    settings, ctx = api_only(tmp_path)
    with ctx as client:
        auth = register(client)
        ids = []
        for served, name in ((vuln, "a"), (secure, "b")):
            target = verified_target(client, auth, served, name)
            ids.append(client.post(f"{API}/scans", json={"target_id": target["id"], "profile": "passive"},
                                   headers=auth).json()["id"])
        w1, w2 = worker(settings, client), worker(settings, client)
        # Both workers race for the same queue at the same instant.
        barrier = threading.Barrier(2)
        threads = [threading.Thread(target=lambda w=w: (barrier.wait(), w.tick())) for w in (w1, w2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        w1.start(), w2.start()
        try:
            for scan_id in ids:
                assert wait_status(client, auth, scan_id, ("completed", "failed"))["status"] == "completed"
        finally:
            w1.shutdown(), w2.shutdown()
        with client.app.state.session_factory() as db:
            completed = db.execute(select(AuditLog).where(AuditLog.action == "scan.completed")).scalars().all()
            owners = {s.id: s.worker_id for s in db.execute(select(Scan)).scalars()}
        assert sorted(a.resource_id for a in completed) == sorted(ids)       # one completion per scan
        assert set(owners.values()) <= {w1.worker_id, w2.worker_id}
        assert client.get(f"{API}/audit-logs/verify", headers=auth).json()["valid"] is True


def test_claim_is_atomic(tmp_path, vuln):
    """Only one of many concurrent claim attempts on the same scan may win."""
    settings, ctx = api_only(tmp_path)
    with ctx as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        scan_id = client.post(f"{API}/scans", json={"target_id": target["id"]}, headers=auth).json()["id"]
        factory = client.app.state.session_factory
        wins = []
        barrier = threading.Barrier(8)

        def attempt(n):
            barrier.wait()
            with factory() as db:
                res = db.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "queued")
                                 .values(status="running", worker_id=f"w{n}", heartbeat_at=utcnow()))
                db.commit()
                if res.rowcount == 1:
                    wins.append(n)

        threads = [threading.Thread(target=attempt, args=(n,)) for n in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert len(wins) == 1


def test_cancellation_reaches_a_scan_owned_by_another_process(tmp_path, vuln):
    settings, ctx = api_only(tmp_path, default_rps=5, max_rps=5)
    with ctx as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        w = worker(settings, client)
        w.start()
        try:
            scan_id = client.post(f"{API}/scans", json={"target_id": target["id"], "profile": "full"},
                                  headers=auth).json()["id"]
            wait_status(client, auth, scan_id, ("running",))
            # The API process holds no reference to the running scan: it only sets a flag.
            assert client.post(f"{API}/scans/{scan_id}/cancel", headers=auth).status_code == 200
            assert wait_status(client, auth, scan_id, ("canceled", "completed"))["status"] == "canceled"
        finally:
            w.shutdown()


def test_queued_scan_is_canceled_immediately(tmp_path, vuln):
    settings, ctx = api_only(tmp_path)
    with ctx as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        scan_id = client.post(f"{API}/scans", json={"target_id": target["id"]}, headers=auth).json()["id"]
        assert client.post(f"{API}/scans/{scan_id}/cancel", headers=auth).status_code == 200
        assert client.get(f"{API}/scans/{scan_id}", headers=auth).json()["status"] == "canceled"
        assert vuln.state.get("hits", {}).get("index", 0) <= 1     # only the ownership check touched the target


def test_scan_of_a_dead_worker_is_failed_but_live_ones_are_kept(tmp_path, vuln, secure):
    settings, ctx = api_only(tmp_path)
    with ctx as client:
        auth = register(client)
        t1, t2 = verified_target(client, auth, vuln, "a"), verified_target(client, auth, secure, "b")
        with client.app.state.session_factory() as db:
            org = db.get(Target, t1["id"]).org_id
            dead = Scan(org_id=org, target_id=t1["id"], status="running", worker_id="w-morto",
                        heartbeat_at=utcnow() - timedelta(minutes=10))
            alive = Scan(org_id=org, target_id=t2["id"], status="running", worker_id="w-vivo",
                         heartbeat_at=utcnow())
            db.add_all([dead, alive])
            db.commit()
            dead_id, alive_id = dead.id, alive.id
        worker(settings, client).tick()
        assert client.get(f"{API}/scans/{dead_id}", headers=auth).json()["status"] == "failed"
        assert client.get(f"{API}/scans/{alive_id}", headers=auth).json()["status"] == "running"
        # The target of the dead scan is free again.
        assert client.post(f"{API}/scans", json={"target_id": t1["id"]}, headers=auth).status_code == 202


def test_maximum_scan_duration(tmp_path, vuln):
    settings, ctx = api_only(tmp_path, default_rps=5, max_rps=5, max_scan_seconds=0)
    with ctx as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        w = worker(settings, client)
        w.start()
        try:
            scan_id = client.post(f"{API}/scans", json={"target_id": target["id"], "profile": "full"},
                                  headers=auth).json()["id"]
            done = wait_status(client, auth, scan_id, ("canceled", "completed", "failed"))
        finally:
            w.shutdown()
        assert done["status"] == "canceled" and "Tempo máximo" in done["error"]
