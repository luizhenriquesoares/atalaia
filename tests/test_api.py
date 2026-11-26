import json
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, text

from atalaia.api.app import create_app
from atalaia.models import AuditLog, Finding, Scan, Target, utcnow
from atalaia.scanner.engine import ScanFinding, ScanResult
from atalaia.scans import persist_result
from tests.conftest import PASSWORD, make_settings, register, run_scan_and_wait, verified_target

API = "/api/v1"


# ------------------------------------------------------------------ authorization gate
def test_scan_is_refused_until_ownership_is_verified(client, auth, vuln):
    target = client.post(f"{API}/targets", json={"name": "Loja", "base_url": vuln.url}, headers=auth).json()
    assert target["verified"] is False
    r = client.post(f"{API}/scans", json={"target_id": target["id"]}, headers=auth)
    assert r.status_code == 403
    assert vuln.state.get("hits", {}) == {}          # not a single request reached the target

    # Wrong / missing proof does not verify.
    r = client.post(f"{API}/targets/{target['id']}/verify", json={"method": "http_file"}, headers=auth)
    assert r.json()["verified"] is False
    vuln.state["token"] = "atalaia-verify-" + "0" * 40
    r = client.post(f"{API}/targets/{target['id']}/verify", json={"method": "http_file"}, headers=auth)
    assert r.json()["verified"] is False
    assert client.post(f"{API}/scans", json={"target_id": target["id"]}, headers=auth).status_code == 403

    vuln.state["token"] = target["verification"]["http_file"]["content"]
    r = client.post(f"{API}/targets/{target['id']}/verify", json={"method": "http_file"}, headers=auth)
    assert r.json()["verified"] is True
    actions = [a["action"] for a in client.get(f"{API}/audit-logs", headers=auth).json()]
    assert "scan.refused" in actions and "target.verify_failed" in actions and "target.verify" in actions


def test_verification_token_of_another_org_does_not_work(client, vuln):
    a = register(client, "a@a.test", "Org A")
    b = register(client, "b@b.test", "Org B")
    ta = client.post(f"{API}/targets", json={"name": "x", "base_url": vuln.url}, headers=a).json()
    tb = client.post(f"{API}/targets", json={"name": "x", "base_url": vuln.url}, headers=b).json()
    assert ta["verification"]["http_file"]["content"] != tb["verification"]["http_file"]["content"]
    vuln.state["token"] = ta["verification"]["http_file"]["content"]
    r = client.post(f"{API}/targets/{tb['id']}/verify", json={"method": "http_file"}, headers=b)
    assert r.json()["verified"] is False


def test_verification_expires(client, auth, vuln, settings):
    target = verified_target(client, auth, vuln)
    with client.app.state.session_factory() as db:
        t = db.get(Target, target["id"])
        t.verified_at = utcnow() - timedelta(days=settings.verification_ttl_days + 1)
        db.commit()
    r = client.post(f"{API}/scans", json={"target_id": target["id"]}, headers=auth)
    assert r.status_code == 403 and "expirou" in r.json()["detail"]
    assert client.get(f"{API}/targets/{target['id']}", headers=auth).json()["verification_expired"] is True


def test_dns_txt_verification():
    from atalaia import ownership
    token = ownership.new_token()
    ok, _ = ownership.verify("https://loja.example", token, "dns_txt", allow_private=False,
                             dns_lookup=lambda host: ["v=spf1 -all", token])
    assert ok
    ok, _ = ownership.verify("https://loja.example", token, "dns_txt", allow_private=False,
                             dns_lookup=lambda host: ["outro"])
    assert not ok
    ok, _ = ownership.verify("https://203.0.113.9", token, "dns_txt", allow_private=False,
                             dns_lookup=lambda host: [token])
    assert not ok


# ------------------------------------------------------------------ end-to-end
def test_end_to_end_scan_triage_and_reports(client, auth, vuln):
    target = verified_target(client, auth, vuln)
    scan = run_scan_and_wait(client, auth, target["id"], "standard")
    assert scan["status"] == "completed", scan
    assert scan["summary"]["critical"] >= 3 and scan["summary"]["new"] > 20
    assert scan["requests_sent"] > 0 and scan["progress"] == 100

    listing = client.get(f"{API}/findings", params={"severity": "critical,high", "status": "open"},
                         headers=auth).json()
    assert listing["total"] == len(listing["items"]) > 5
    checks = {f["check_id"] for f in listing["items"]}
    assert {"sqli-error", "xss-reflected", "exposed-env"} <= checks
    assert all(f["remediation"] and f["evidence"] for f in listing["items"])

    # Search and scan filter.
    r = client.get(f"{API}/findings", params={"q": "SQL", "scan_id": scan["id"]}, headers=auth).json()
    assert r["total"] >= 2

    # Triage requires a justification, and is audited.
    fid = next(f["id"] for f in listing["items"] if f["check_id"] == "exposed-env")
    assert client.patch(f"{API}/findings/{fid}", json={"status": "accepted_risk"}, headers=auth).status_code == 422
    r = client.patch(f"{API}/findings/{fid}", json={"status": "accepted_risk", "note": "ambiente de teste"},
                     headers=auth)
    assert r.json()["status"] == "accepted_risk"

    # Re-scan: same findings, nothing new, accepted risk is preserved.
    again = run_scan_and_wait(client, auth, target["id"], "standard")
    assert again["summary"]["new"] == 0 and again["summary"]["fixed"] == 0
    assert client.get(f"{API}/findings/{fid}", headers=auth).json()["status"] == "accepted_risk"

    # Reports.
    rep = client.get(f"{API}/scans/{scan['id']}/report", headers=auth).json()
    assert rep["target"]["base_url"] == vuln.url and len(rep["findings"]) == sum(
        1 for _ in rep["findings"])
    html_report = client.get(f"{API}/scans/{scan['id']}/report?format=html", headers=auth)
    assert html_report.status_code == 200 and "Relatório de avaliação" in html_report.text
    assert "<atl" not in html_report.text            # XSS evidence is escaped in the report
    sarif = client.get(f"{API}/scans/{scan['id']}/report?format=sarif", headers=auth).json()
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert all(res["ruleId"] in rule_ids for res in sarif["runs"][0]["results"])
    csv_report = client.get(f"{API}/scans/{scan['id']}/report?format=csv", headers=auth)
    assert csv_report.text.startswith("severity,cvss,title")

    dash = client.get(f"{API}/dashboard", headers=auth).json()
    assert dash["targets"] == 1 and dash["verified_targets"] == 1
    assert dash["open_by_severity"]["critical"] >= 3 and dash["security_score"] == 0
    assert len(dash["recent_scans"]) == 2

    # Audit trail is complete and intact.
    actions = [a["action"] for a in client.get(f"{API}/audit-logs", headers=auth).json()]
    for needed in ("org.create", "target.create", "target.verify", "scan.start", "scan.completed",
                   "finding.triage", "report.export"):
        assert needed in actions, needed
    assert client.get(f"{API}/audit-logs/verify", headers=auth).json()["valid"] is True


def test_one_active_scan_per_target_and_cancel(client, auth, vuln, settings):
    target = verified_target(client, auth, vuln)
    settings.default_rps = 5
    with client.app.state.session_factory() as db:
        db.get(Target, target["id"]).max_rps = 5
        db.commit()
    r = client.post(f"{API}/scans", json={"target_id": target["id"], "profile": "full"}, headers=auth)
    assert r.status_code == 202
    scan_id = r.json()["id"]
    assert client.post(f"{API}/scans", json={"target_id": target["id"]}, headers=auth).status_code == 409
    assert client.delete(f"{API}/targets/{target['id']}", headers=auth).status_code == 409
    assert client.post(f"{API}/scans/{scan_id}/cancel", headers=auth).status_code == 200
    assert client.app.state.manager.wait_idle(30)
    scan = client.get(f"{API}/scans/{scan_id}", headers=auth).json()
    assert scan["status"] == "canceled"
    assert client.delete(f"{API}/targets/{target['id']}", headers=auth).status_code == 204
    assert client.get(f"{API}/scans/{scan_id}", headers=auth).status_code == 404
    assert client.get(f"{API}/findings", headers=auth).json()["total"] == 0


def test_org_concurrency_limit(tmp_path, vuln, secure):
    settings = make_settings(tmp_path, max_concurrent_scans_per_org=1, default_rps=5, max_rps=5)
    with TestClient(create_app(settings)) as client:
        auth = register(client)
        t1 = verified_target(client, auth, vuln, "a")
        t2 = verified_target(client, auth, secure, "b")
        r1 = client.post(f"{API}/scans", json={"target_id": t1["id"]}, headers=auth)
        assert r1.status_code == 202
        assert client.post(f"{API}/scans", json={"target_id": t2["id"]}, headers=auth).status_code == 429
        client.post(f"{API}/scans/{r1.json()['id']}/cancel", headers=auth)
        assert client.app.state.manager.wait_idle(30)


def _sf(fp, check="xss-reflected", method="GET"):
    return ScanFinding(fp, check, "t", "high", "high", 79, "A03", 7.0, "http://x/a", method, "q", "e", "d", "r", [])


def test_finding_lifecycle_fixed_and_reopened(client, auth, vuln):
    target = verified_target(client, auth, vuln)
    sf = client.app.state.session_factory

    def run(findings, profile="standard", **kw):
        with sf() as db:
            scan = Scan(org_id=db.get(Target, target["id"]).org_id, target_id=target["id"], profile=profile)
            db.add(scan)
            db.flush()
            kw.setdefault("paths_requested", {"/a"})
            summary = persist_result(db, scan, ScanResult(findings, kw.pop("pages", 5), 10, **kw))
            db.commit()
            return summary

    def status(fp):
        with sf() as db:
            return db.execute(select(Finding.status).where(Finding.fingerprint == fp)).scalar_one()

    s = run([_sf("a" * 32), _sf("b" * 32, method="POST"), _sf("c" * 32, check="missing-csp")])
    assert s["new"] == 3
    # Canceled / partial / empty scans never close findings.
    assert run([], canceled=True)["fixed"] == 0
    assert run([], budget_exhausted=True)["fixed"] == 0
    assert run([], pages=0)["fixed"] == 0
    # A passive scan cannot prove an injection flaw is gone, only passive findings.
    assert run([], profile="passive")["fixed"] == 1 and status("c" * 32) == "fixed"
    # A standard scan re-tests GET inputs but not POST forms.
    assert run([], profile="standard")["fixed"] == 1
    assert status("a" * 32) == "fixed" and status("b" * 32) == "open"
    assert run([], profile="full")["fixed"] == 1 and status("b" * 32) == "fixed"
    # A finding whose page was not reached again stays open; so does a browser-only finding
    # when the scan ran without the browser.
    run([_sf("d" * 32), _sf("e" * 32, check="xss-dom")], profile="full")
    assert run([], profile="full", paths_requested={"/outra"})["fixed"] == 0 and status("d" * 32) == "open"
    assert run([], profile="full", browser_used=False)["fixed"] == 1
    assert status("d" * 32) == "fixed" and status("e" * 32) == "open"
    assert run([], profile="full", browser_used=True)["fixed"] == 1 and status("e" * 32) == "fixed"
    # Regression: the issue comes back.
    s = run([_sf("a" * 32)])
    assert s["reopened"] == 1 and s["new"] == 0 and status("a" * 32) == "open"


# ------------------------------------------------------------------ tenant isolation / RBAC
def test_tenant_isolation(client, vuln):
    a = register(client, "a@a.test", "Org A")
    b = register(client, "b@b.test", "Org B")
    target = verified_target(client, a, vuln)
    scan = run_scan_and_wait(client, a, target["id"], "passive")
    finding = client.get(f"{API}/findings", headers=a).json()["items"][0]

    assert client.get(f"{API}/targets", headers=b).json() == []
    assert client.get(f"{API}/scans", headers=b).json() == []
    assert client.get(f"{API}/findings", headers=b).json()["total"] == 0
    assert client.get(f"{API}/findings", params={"scan_id": scan["id"]}, headers=b).json()["total"] == 0
    assert client.get(f"{API}/findings", params={"target_id": target["id"]}, headers=b).json()["total"] == 0
    assert client.get(f"{API}/dashboard", headers=b).json()["targets"] == 0
    for method, path, body in [
        ("get", f"/targets/{target['id']}", None), ("patch", f"/targets/{target['id']}", {"name": "x"}),
        ("delete", f"/targets/{target['id']}", None),
        ("post", f"/targets/{target['id']}/verify", {"method": "http_file"}),
        ("post", "/scans", {"target_id": target["id"]}), ("get", f"/scans/{scan['id']}", None),
        ("get", f"/scans/{scan['id']}/report", None), ("post", f"/scans/{scan['id']}/cancel", None),
        ("get", f"/findings/{finding['id']}", None),
        ("patch", f"/findings/{finding['id']}", {"status": "fixed"}),
    ]:
        r = client.request(method, API + path, json=body, headers=b)
        assert r.status_code == 404, (method, path, r.status_code)
    users_a = client.get(f"{API}/users", headers=a).json()
    assert client.patch(f"{API}/users/{users_a[0]['id']}", json={"is_active": False}, headers=b).status_code == 404
    assert all(x["actor"] != "a@a.test" for x in client.get(f"{API}/audit-logs", headers=b).json())


def _member(client, owner_auth, email, role):
    r = client.post(f"{API}/users", json={"name": role, "email": email, "password": PASSWORD, "role": role},
                    headers=owner_auth)
    assert r.status_code == 201, r.text
    tok = client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD}).json()["token"]
    return r.json(), {"Authorization": f"Bearer {tok}"}


def test_rbac(client, auth, vuln):
    viewer_u, viewer = _member(client, auth, "v@acme.test", "viewer")
    analyst_u, analyst = _member(client, auth, "an@acme.test", "analyst")
    admin_u, admin = _member(client, auth, "ad@acme.test", "admin")
    owner_id = client.get(f"{API}/me", headers=auth).json()["user"]["id"]

    assert client.post(f"{API}/targets", json={"name": "x", "base_url": vuln.url}, headers=viewer).status_code == 403
    assert client.get(f"{API}/users", headers=viewer).status_code == 403
    assert client.get(f"{API}/audit-logs", headers=analyst).status_code == 403
    assert client.post(f"{API}/api-keys", json={"name": "ci"}, headers=analyst).status_code == 403
    target = verified_target(client, analyst, vuln)
    assert client.get(f"{API}/targets", headers=viewer).status_code == 200
    assert client.post(f"{API}/scans", json={"target_id": target["id"]}, headers=viewer).status_code == 403
    assert client.delete(f"{API}/targets/{target['id']}", headers=analyst).status_code == 403
    assert client.patch(f"{API}/targets/{target['id']}", json={"auth_headers": {"Cookie": "s=1"}},
                        headers=analyst).status_code == 403

    # Privilege escalation attempts.
    assert client.post(f"{API}/users", json={"name": "x", "email": "o@acme.test", "password": PASSWORD,
                                             "role": "owner"}, headers=admin).status_code == 422
    assert client.patch(f"{API}/users/{admin_u['id']}", json={"role": "owner"}, headers=admin).status_code in (400, 403)
    assert client.patch(f"{API}/users/{viewer_u['id']}", json={"role": "owner"}, headers=admin).status_code == 403
    assert client.patch(f"{API}/users/{owner_id}", json={"is_active": False}, headers=admin).status_code == 403
    assert client.patch(f"{API}/users/{owner_id}", json={"role": "viewer"}, headers=auth).status_code == 400
    assert client.patch(f"{API}/users/{viewer_u['id']}", json={"role": "analyst"}, headers=admin).status_code == 200

    # Deactivation kills existing sessions immediately.
    assert client.patch(f"{API}/users/{analyst_u['id']}", json={"is_active": False}, headers=admin).status_code == 200
    assert client.get(f"{API}/me", headers=analyst).status_code == 401
    assert client.post(f"{API}/auth/login", json={"email": "an@acme.test", "password": PASSWORD}).status_code == 401


# ------------------------------------------------------------------ platform security
def test_internal_targets_are_blocked_by_default(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, allow_private_targets=False))) as client:
        auth = register(client)
        for url in ("http://127.0.0.1:8080", "http://localhost", "http://169.254.169.254", "http://10.0.0.5",
                    "http://192.168.1.1", "http://[::1]", "http://0.0.0.0", "http://[::ffff:127.0.0.1]",
                    "http://2130706433", "ftp://example.com", "http://user:pw@example.com", "file:///etc/passwd"):
            r = client.post("/api/v1/targets", json={"name": "x", "base_url": url}, headers=auth)
            assert r.status_code == 422, (url, r.status_code, r.text)


def test_scan_time_recheck_blocks_rebinding(tmp_path, vuln):
    """A target that was acceptable when registered but now resolves to an internal address
    must be refused when the scan is requested."""
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings)) as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        settings.allow_private_targets = False
        r = client.post("/api/v1/scans", json={"target_id": target["id"]}, headers=auth)
        assert r.status_code == 403


def test_authentication(client):
    assert client.get(f"{API}/me").status_code == 401
    assert client.get(f"{API}/targets", headers={"Authorization": "Bearer nope"}).status_code == 401
    auth = register(client)
    token = auth["Authorization"][7:]
    h, p, s = token.split(".")
    forged = {"Authorization": f"Bearer {h}.{p}.{s[:-2]}AA"}
    assert client.get(f"{API}/me", headers=forged).status_code == 401
    import base64
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    assert client.get(f"{API}/me", headers={"Authorization": f"Bearer {none_header}.{p}."}).status_code == 401
    assert client.get(f"{API}/me", headers=auth).status_code == 200

    # Weak passwords and duplicate e-mails are rejected.
    weak = client.post(f"{API}/auth/register", json={"organization": "Org X", "name": "x", "email": "x@x.test",
                                                     "password": "curta"})
    assert weak.status_code == 422
    dup = client.post(f"{API}/auth/register", json={"organization": "Org X", "name": "x", "email": "ANA@acme.test",
                                                    "password": PASSWORD})
    assert dup.status_code == 409

    # Changing the password invalidates older tokens.
    r = client.post(f"{API}/auth/change-password", headers=auth,
                    json={"current_password": PASSWORD, "new_password": PASSWORD + "!"})
    assert r.status_code == 200
    assert client.get(f"{API}/me", headers=auth).status_code == 401
    assert client.get(f"{API}/me", headers={"Authorization": f"Bearer {r.json()['token']}"}).status_code == 200


def test_login_lockout(client):
    register(client)
    for _ in range(5):
        assert client.post(f"{API}/auth/login", json={"email": "ana@acme.test", "password": "errada"}).status_code == 401
    r = client.post(f"{API}/auth/login", json={"email": "ana@acme.test", "password": PASSWORD})
    assert r.status_code == 429
    # Unknown accounts get the same answer as wrong passwords.
    r = client.post(f"{API}/auth/login", json={"email": "ninguem@acme.test", "password": "x"})
    assert r.status_code == 401 and r.json()["detail"] == "E-mail ou senha incorretos"


def test_api_keys(client, auth, vuln):
    created = client.post(f"{API}/api-keys", json={"name": "ci", "role": "analyst"}, headers=auth).json()
    key = created["key"]
    assert key.startswith("atl_")
    listed = client.get(f"{API}/api-keys", headers=auth).json()
    assert "key" not in listed[0] and key not in json.dumps(listed)
    with client.app.state.engine.connect() as conn:
        stored = conn.execute(text("select key_hash from api_keys")).scalar_one()
    assert stored != key and key not in stored
    kh = {"X-API-Key": key}
    assert client.get(f"{API}/targets", headers=kh).status_code == 200
    assert client.get(f"{API}/targets", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    assert client.get(f"{API}/users", headers=kh).status_code == 403           # role is enforced
    assert client.post(f"{API}/api-keys", json={"name": "x"}, headers=kh).status_code == 403
    assert client.delete(f"{API}/api-keys/{created['id']}", headers=auth).status_code == 204
    assert client.get(f"{API}/targets", headers=kh).status_code == 401


def test_scan_credentials_are_encrypted_and_never_returned(client, auth, vuln):
    target = verified_target(client, auth, vuln)
    r = client.patch(f"{API}/targets/{target['id']}", headers=auth,
                     json={"auth_headers": {"Authorization": "Bearer token-do-cliente-123"}})
    assert r.status_code == 200 and r.json()["has_auth_headers"] is True
    assert "token-do-cliente-123" not in r.text
    assert "token-do-cliente-123" not in client.get(f"{API}/targets", headers=auth).text
    with client.app.state.engine.connect() as conn:
        raw = conn.execute(text("select auth_headers_enc from targets")).scalar_one()
    assert "token-do-cliente-123" not in raw
    assert "token-do-cliente-123" not in client.get(f"{API}/audit-logs", headers=auth).text
    for bad in ({"Host": "evil"}, {"X-A": "a\r\nX-B: b"}, {"bad name": "x"}):
        assert client.patch(f"{API}/targets/{target['id']}", headers=auth,
                            json={"auth_headers": bad}).status_code == 422
    r = client.patch(f"{API}/targets/{target['id']}", headers=auth, json={"auth_headers": {}})
    assert r.json()["has_auth_headers"] is False


def test_audit_chain_detects_tampering(client, auth, vuln):
    verified_target(client, auth, vuln)
    assert client.get(f"{API}/audit-logs/verify", headers=auth).json()["valid"] is True
    with client.app.state.session_factory() as db:
        entry = db.execute(select(AuditLog).order_by(AuditLog.id).limit(1).offset(1)).scalar_one()
        entry.actor = "outra-pessoa@acme.test"
        db.commit()
    result = client.get(f"{API}/audit-logs/verify", headers=auth).json()
    assert result["valid"] is False and result["broken_at"] is not None


def test_security_headers_and_dashboard_assets(client):
    r = client.get("/")
    assert r.status_code == 200 and "Atalaia" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/v1/me").headers["cache-control"] == "no-store"
    assert client.get("/healthz").json()["status"] == "ok"
    assert "<script>" not in r.text and "onclick=" not in r.text      # CSP-compatible: no inline script


def test_scheduled_scans(client, auth, vuln):
    target = verified_target(client, auth, vuln)
    r = client.patch(f"{API}/targets/{target['id']}", json={"schedule": "daily", "schedule_profile": "passive"},
                     headers=auth)
    assert r.json()["next_scan_at"]
    manager = client.app.state.manager
    assert manager.run_due() == []
    with client.app.state.session_factory() as db:
        db.get(Target, target["id"]).next_scan_at = utcnow() - timedelta(minutes=1)
        db.commit()
    started = manager.run_due()
    assert len(started) == 1 and manager.wait_idle(30)
    scan = client.get(f"{API}/scans/{started[0]}", headers=auth).json()
    assert scan["status"] == "completed" and scan["triggered_by"] == "scheduler" and scan["profile"] == "passive"
    assert manager.run_due() == []


def test_interrupted_scans_are_recovered_on_startup(tmp_path, vuln):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings)) as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        with client.app.state.session_factory() as db:
            t = db.get(Target, target["id"])
            db.add(Scan(org_id=t.org_id, target_id=t.id, status="running"))
            db.commit()
    with TestClient(create_app(settings)) as client:
        tok = client.post(f"{API}/auth/login", json={"email": "ana@acme.test", "password": PASSWORD}).json()["token"]
        scans = client.get(f"{API}/scans", headers={"Authorization": f"Bearer {tok}"}).json()
        assert scans[0]["status"] == "failed"
