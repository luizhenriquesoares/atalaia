"""Second factor (TOTP), recovery codes, organization policy and additive schema upgrade."""
import time

from sqlalchemy import create_engine, inspect, text

from atalaia import mfa
from atalaia.db import ensure_schema
from tests.conftest import PASSWORD, register

API = "/api/v1"


def login(client, email="ana@acme.test", code=None):
    body = {"email": email, "password": PASSWORD}
    if code is not None:
        body["code"] = code
    return client.post(f"{API}/auth/login", json=body)


def enroll(client, headers):
    setup = client.post(f"{API}/auth/mfa/setup", json={"password": PASSWORD}, headers=headers).json()
    done = client.post(f"{API}/auth/mfa/enable", headers=headers,
                       json={"code": mfa.code_at(setup["secret"], mfa.current_step())})
    assert done.status_code == 200, done.text
    return setup["secret"], done.json()["recovery_codes"], {"Authorization": "Bearer " + done.json()["token"]}


def next_code(secret):
    # The enrollment consumed the current step; the next step is still inside the accepted window.
    return mfa.code_at(secret, mfa.current_step() + 1)


# ------------------------------------------------------------------ algorithm
def test_totp_matches_rfc6238_vectors():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                # ASCII "12345678901234567890"
    for t, expected in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (20000000000, "353130")):
        assert mfa.code_at(secret, t // 30) == expected          # RFC 6238 appendix B, truncated to 6 digits
        assert mfa.verify(secret, expected, now=t) == t // 30


def test_totp_window_and_replay():
    secret, now = mfa.new_secret(), 1_800_000_000
    step = mfa.current_step(now)
    assert mfa.verify(secret, mfa.code_at(secret, step - 1), now=now) == step - 1     # clock drift tolerated
    assert mfa.verify(secret, mfa.code_at(secret, step - 2), now=now) is None
    assert mfa.verify(secret, mfa.code_at(secret, step), now=now, last_step=step) is None   # replay refused
    assert mfa.verify(secret, "12345", now=now) is None
    assert mfa.verify(secret, "abcdef", now=now) is None


def test_qr_matrix_is_square():
    rows = mfa.qr_matrix(mfa.provisioning_uri(mfa.new_secret(), "ana@acme.test"))
    assert rows and all(len(r) == len(rows) and set(r) <= {"0", "1"} for r in rows)


# ------------------------------------------------------------------ enrollment and login
def test_enrollment_needs_password_and_a_valid_code(client, auth):
    assert client.post(f"{API}/auth/mfa/setup", json={"password": "errada-errada-12"}, headers=auth).status_code == 403
    assert client.post(f"{API}/auth/mfa/enable", json={"code": "123456"}, headers=auth).status_code == 400
    setup = client.post(f"{API}/auth/mfa/setup", json={"password": PASSWORD}, headers=auth).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/Atalaia%3Aana%40acme.test?secret=" + setup["secret"])
    wrong = "000000" if mfa.code_at(setup["secret"], mfa.current_step()) != "000000" else "111111"
    assert client.post(f"{API}/auth/mfa/enable", json={"code": wrong}, headers=auth).status_code == 400
    # A pending (unconfirmed) secret does not change the login.
    assert login(client).status_code == 200
    assert client.get(f"{API}/me", headers=auth).json()["user"]["mfa_enabled"] is False


def test_login_requires_second_factor_and_refuses_replay(client, auth):
    secret, _, fresh = enroll(client, auth)
    assert client.get(f"{API}/me", headers=auth).status_code == 401            # older sessions were revoked
    assert client.get(f"{API}/me", headers=fresh).json()["user"]["mfa_enabled"] is True

    r = login(client)
    assert r.status_code == 401 and r.json()["mfa_required"] is True and "token" not in r.json()
    r = login(client, code="000000" if next_code(secret) != "000000" else "111111")
    assert r.status_code == 401 and r.json()["mfa_required"] is True
    # The code used at enrollment cannot be replayed.
    assert login(client, code=mfa.code_at(secret, mfa.current_step())).status_code in (401,)
    code = next_code(secret)
    ok = login(client, code=code)
    assert ok.status_code == 200 and ok.json()["token"]
    assert login(client, code=code).status_code == 401                          # same code twice
    actions = [a["action"] for a in client.get(f"{API}/audit-logs", headers=fresh).json()]
    assert "auth.mfa_enable" in actions and "auth.mfa_failed" in actions


def test_wrong_password_never_reveals_that_mfa_is_on(client, auth):
    enroll(client, auth)
    r = client.post(f"{API}/auth/login", json={"email": "ana@acme.test", "password": "errada-errada-12", "code": "123456"})
    assert r.status_code == 401 and "mfa_required" not in r.json()


def test_recovery_code_works_once(client, auth):
    _, codes, _ = enroll(client, auth)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert login(client, code=codes[0].upper().replace("-", " ")).status_code == 200    # tolerant to formatting
    assert login(client, code=codes[0]).status_code == 401
    assert login(client, code=codes[1]).status_code == 200


def test_second_factor_guessing_is_throttled(client, auth, settings):
    enroll(client, auth)
    for _ in range(settings.login_max_failures):
        assert login(client, code="000001").status_code == 401
    assert login(client, code="000001").status_code == 429


def test_disable_needs_password_and_code(client, auth):
    secret, _, fresh = enroll(client, auth)
    bad = client.post(f"{API}/auth/mfa/disable", json={"password": PASSWORD, "code": "000001"}, headers=fresh)
    assert bad.status_code == 403
    bad = client.post(f"{API}/auth/mfa/disable", json={"password": "errada-errada-12", "code": next_code(secret)},
                      headers=fresh)
    assert bad.status_code == 403
    ok = client.post(f"{API}/auth/mfa/disable", json={"password": PASSWORD, "code": next_code(secret)}, headers=fresh)
    assert ok.status_code == 200
    assert login(client).status_code == 200


# ------------------------------------------------------------------ organization policy and admin reset
def test_org_policy_forces_enrollment(client, auth):
    # The owner must have a second factor before requiring it from everybody.
    assert client.patch(f"{API}/organization", json={"require_mfa": True}, headers=auth).status_code == 400
    _, _, owner = enroll(client, auth)
    client.post(f"{API}/users", headers=owner, json={"name": "Bia", "email": "bia@acme.test", "password": PASSWORD,
                                                     "role": "analyst"})
    assert client.patch(f"{API}/organization", json={"require_mfa": True}, headers=owner).json()["require_mfa"] is True

    bia = {"Authorization": "Bearer " + login(client, "bia@acme.test").json()["token"]}
    me = client.get(f"{API}/me", headers=bia).json()
    assert me["mfa_setup_required"] is True
    assert client.get(f"{API}/targets", headers=bia).status_code == 403
    assert client.get(f"{API}/findings", headers=bia).status_code == 403
    _, _, bia = enroll(client, bia)
    assert client.get(f"{API}/targets", headers=bia).status_code == 200
    assert client.get(f"{API}/me", headers=bia).json()["mfa_setup_required"] is False


def test_admin_can_reset_a_colleague(client, auth):
    _, _, owner = enroll(client, auth)
    bia_id = client.post(f"{API}/users", headers=owner, json={"name": "Bia", "email": "bia@acme.test",
                                                              "password": PASSWORD, "role": "viewer"}).json()["id"]
    bia = {"Authorization": "Bearer " + login(client, "bia@acme.test").json()["token"]}
    _, _, bia = enroll(client, bia)
    assert login(client, "bia@acme.test").status_code == 401
    assert client.post(f"{API}/users/{bia_id}/mfa/reset", headers=bia).status_code == 403      # not an admin
    me = client.get(f"{API}/me", headers=owner).json()["user"]["id"]
    assert client.post(f"{API}/users/{me}/mfa/reset", headers=owner).status_code == 400        # not for yourself
    assert client.post(f"{API}/users/{bia_id}/mfa/reset", headers=owner).json()["mfa_enabled"] is False
    assert client.get(f"{API}/me", headers=bia).status_code == 401                             # sessions revoked
    assert login(client, "bia@acme.test").status_code == 200

    other = register(client, "x@other.test", "Org X")
    assert client.post(f"{API}/users/{bia_id}/mfa/reset", headers=other).status_code == 404    # tenant isolation


def test_api_keys_are_not_blocked_by_the_policy(client, auth):
    _, _, owner = enroll(client, auth)
    key = client.post(f"{API}/api-keys", json={"name": "CI", "role": "analyst"}, headers=owner).json()["key"]
    client.patch(f"{API}/organization", json={"require_mfa": True}, headers=owner)
    assert client.get(f"{API}/targets", headers={"X-API-Key": key}).status_code == 200


# ------------------------------------------------------------------ upgrade of an existing database
def test_ensure_schema_adds_new_columns_to_an_old_database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/old.db")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE organizations (id VARCHAR(32) PRIMARY KEY, name VARCHAR(200), created_at DATETIME)"))
        conn.execute(text("INSERT INTO organizations (id, name) VALUES ('o1', 'Antiga')"))
    ensure_schema(engine)
    ensure_schema(engine)                                        # idempotent
    assert "require_mfa" in {c["name"] for c in inspect(engine).get_columns("organizations")}
    with engine.connect() as conn:
        assert conn.execute(text("SELECT require_mfa FROM organizations")).scalar() == 0
    assert "mfa_enabled" in {c["name"] for c in inspect(engine).get_columns("users")}
    engine.dispose()
