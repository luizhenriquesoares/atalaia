"""OAuth 2.1 do conector MCP: o fluxo que o claude.ai executa, do 401 até a chamada de ferramenta."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import secrets
from html import unescape
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from atalaia import mfa
from atalaia.api.app import create_app
from tests.conftest import PASSWORD, Served, make_settings

REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def atalaia(tmp_path):
    served = Served(lambda _state: create_app(make_settings(tmp_path)))
    yield served
    served.stop()


def register_user(base, email="ana@acme.test", org="ACME"):
    r = httpx.post(f"{base}/api/v1/auth/register", json={"organization": org, "name": "Ana", "email": email,
                                                          "password": PASSWORD})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def discover(base):
    """Como um cliente MCP: 401 -> metadados do recurso -> metadados do servidor de autorização."""
    r = httpx.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                   headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401
    meta_url = re.search(r'resource_metadata="([^"]+)"', r.headers["www-authenticate"]).group(1)
    pr = httpx.get(meta_url).json()
    assert pr["resource"] == f"{base}/mcp"
    return pr, httpx.get(f"{pr['authorization_servers'][0]}/.well-known/oauth-authorization-server").json()


def hidden_fields(html: str) -> dict:
    return {m.group(1): unescape(m.group(2)) for m in re.finditer(r'type="hidden" name="([^"]+)" value="([^"]*)"', html)}


def authorize(base, asm, client_id, challenge, *, email="ana@acme.test", password=PASSWORD, code="",
              access="write", action="approve", state="xyz", scope=None):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256", "resource": f"{base}/mcp"}
    if scope:
        params["scope"] = scope
    page = httpx.get(asm["authorization_endpoint"], params=params)
    assert page.status_code == 200, page.text
    form = {**hidden_fields(page.text), "email": email, "password": password, "code": code, "access": access,
            "action": action}
    return page, httpx.post(asm["authorization_endpoint"], data=form)


def connect(base, **kw):
    pr, asm = discover(base)
    reg = httpx.post(asm["registration_endpoint"], json={"client_name": "Claude", "redirect_uris": [REDIRECT],
                                                         "token_endpoint_auth_method": "none"}).json()
    verifier, challenge = pkce()
    _, r = authorize(base, asm, reg["client_id"], challenge, **kw)
    assert r.status_code == 302, r.text
    q = parse_qs(urlsplit(r.headers["location"]).query)
    tok = httpx.post(asm["token_endpoint"], data={
        "grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
        "client_id": reg["client_id"], "code_verifier": verifier, "resource": f"{base}/mcp"})
    assert tok.status_code == 200, tok.text
    return asm, reg, tok.json(), q


async def mcp_call(base, token, tool, args=None):
    from tests.test_mcp import call, connect_http
    async with connect_http(f"{base}/mcp", token) as c:
        return await call(c, tool, args or {})


def test_metadata_documents(atalaia):
    pr, asm = discover(atalaia.url)
    assert asm["issuer"] == atalaia.url
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert "none" in asm["token_endpoint_auth_methods_supported"]
    assert set(pr["scopes_supported"]) == {"atalaia:read", "atalaia:write"}
    assert httpx.get(f"{atalaia.url}/.well-known/oauth-protected-resource").json()["resource"] == f"{atalaia.url}/mcp"


def test_full_claude_flow_with_rotation_and_revocation(atalaia):
    auth = register_user(atalaia.url)
    asm, reg, tok, q = connect(atalaia.url)
    assert q["state"] == ["xyz"] and q["iss"] == [atalaia.url]
    assert tok["access_token"].startswith("atm_") and tok["refresh_token"].startswith("atr_")
    assert tok["scope"] == "atalaia:read atalaia:write" and tok["expires_in"] == 3600

    me = asyncio.run(mcp_call(atalaia.url, tok["access_token"], "whoami"))
    assert me["role"] == "analyst" and me["actor"] == "ana@acme.test via Claude"

    # Renovação troca os dois tokens; o token de acesso antigo deixa de valer.
    r = httpx.post(asm["token_endpoint"], data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                                 "client_id": reg["client_id"]})
    assert r.status_code == 200
    new = r.json()
    assert new["refresh_token"] != tok["refresh_token"]
    assert httpx.get(f"{atalaia.url}/api/v1/me", headers={"Authorization": f"Bearer {tok['access_token']}"}).status_code == 401
    assert httpx.get(f"{atalaia.url}/api/v1/me", headers={"Authorization": f"Bearer {new['access_token']}"}).status_code == 200

    # O usuário vê o aplicativo conectado e pode desconectar.
    grants = httpx.get(f"{atalaia.url}/api/v1/oauth/grants", headers=auth).json()
    assert [g["client_name"] for g in grants] == ["Claude"] and grants[0]["role"] == "analyst"
    assert httpx.delete(f"{atalaia.url}/api/v1/oauth/grants/{grants[0]['id']}", headers=auth).status_code == 204
    assert httpx.get(f"{atalaia.url}/api/v1/me", headers={"Authorization": f"Bearer {new['access_token']}"}).status_code == 401
    r = httpx.post(asm["token_endpoint"], data={"grant_type": "refresh_token", "refresh_token": new["refresh_token"],
                                                 "client_id": reg["client_id"]})
    assert r.json()["error"] == "invalid_grant"

    actions = [a["action"] for a in httpx.get(f"{atalaia.url}/api/v1/audit-logs", headers=auth).json()]
    assert {"oauth.authorize", "oauth.token", "oauth.revoke"} <= set(actions)


def test_refresh_token_reuse_revokes_everything(atalaia):
    register_user(atalaia.url)
    asm, reg, tok, _ = connect(atalaia.url)
    refresh = lambda t: httpx.post(asm["token_endpoint"], data={  # noqa: E731
        "grant_type": "refresh_token", "refresh_token": t, "client_id": reg["client_id"]})
    second = refresh(tok["refresh_token"]).json()
    assert refresh(tok["refresh_token"]).json()["error"] == "invalid_grant"          # reuso detectado
    assert refresh(second["refresh_token"]).json()["error"] == "invalid_grant"       # família revogada
    assert httpx.get(f"{atalaia.url}/api/v1/me",
                     headers={"Authorization": f"Bearer {second['access_token']}"}).status_code == 401


def test_code_is_single_use_and_bound_to_pkce_and_client(atalaia):
    register_user(atalaia.url)
    _, asm = discover(atalaia.url)
    reg = httpx.post(asm["registration_endpoint"], json={"client_name": "Claude", "redirect_uris": [REDIRECT]}).json()
    other = httpx.post(asm["registration_endpoint"], json={"client_name": "Outro", "redirect_uris": [REDIRECT]}).json()
    verifier, challenge = pkce()
    _, r = authorize(atalaia.url, asm, reg["client_id"], challenge)
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    exchange = lambda **kw: httpx.post(asm["token_endpoint"], data={  # noqa: E731
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, **kw})
    assert exchange(client_id=reg["client_id"], code_verifier="x" * 50).json()["error"] == "invalid_grant"
    assert exchange(client_id=other["client_id"], code_verifier=verifier).json()["error"] == "invalid_grant"
    ok = exchange(client_id=reg["client_id"], code_verifier=verifier)
    assert ok.status_code == 200
    again = exchange(client_id=reg["client_id"], code_verifier=verifier)
    assert again.json()["error"] == "invalid_grant"
    # Reapresentar o código revoga os tokens emitidos com ele.
    assert httpx.get(f"{atalaia.url}/api/v1/me",
                     headers={"Authorization": f"Bearer {ok.json()['access_token']}"}).status_code == 401


def test_authorize_rejects_bad_requests(atalaia):
    register_user(atalaia.url)
    _, asm = discover(atalaia.url)
    reg = httpx.post(asm["registration_endpoint"], json={"client_name": "Claude", "redirect_uris": [REDIRECT]}).json()
    _, challenge = pkce()
    base = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": "s"}
    ep = asm["authorization_endpoint"]
    # Retorno não registrado: página de erro, nunca redireciona para o atacante.
    r = httpx.get(ep, params={**base, "redirect_uri": "https://evil.example/cb"})
    assert r.status_code == 400 and "location" not in r.headers
    r = httpx.get(ep, params={**base, "client_id": "atc_desconhecido"})
    assert r.status_code == 400
    # Sem PKCE, com escopo ou recurso inválidos: erro devolvido ao cliente.
    for bad, err in (({"code_challenge_method": "plain"}, "invalid_request"),
                     ({"scope": "admin"}, "invalid_scope"),
                     ({"resource": "https://outro.example/mcp"}, "invalid_target")):
        r = httpx.get(ep, params={**base, **bad})
        assert r.status_code == 302 and parse_qs(urlsplit(r.headers["location"]).query)["error"] == [err]
    # Registro: só https ou loopback.
    for uri in ("http://evil.example/cb", "javascript:alert(1)", "https://x.example/cb#frag"):
        r = httpx.post(asm["registration_endpoint"], json={"redirect_uris": [uri]})
        assert r.json()["error"] == "invalid_redirect_uri", uri
    assert httpx.post(asm["registration_endpoint"], json={"redirect_uris": ["http://127.0.0.1:33418/cb"]}).status_code == 201


def test_consent_page_is_hardened(atalaia):
    _, asm = discover(atalaia.url)
    reg = httpx.post(asm["registration_endpoint"], json={"client_name": "<script>x</script>",
                                                         "redirect_uris": [REDIRECT]}).json()
    _, challenge = pkce()
    r = httpx.get(asm["authorization_endpoint"], params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": '"><script>alert(1)</script>'})
    assert "<script>" not in r.text
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "form-action 'self' https://claude.ai" in csp
    assert r.headers["x-frame-options"] == "DENY"


def test_wrong_password_deny_and_viewer_limits(atalaia):
    auth = register_user(atalaia.url)
    _, asm = discover(atalaia.url)
    reg = httpx.post(asm["registration_endpoint"], json={"client_name": "Claude", "redirect_uris": [REDIRECT]}).json()
    _, challenge = pkce()
    _, r = authorize(atalaia.url, asm, reg["client_id"], challenge, password="errada-errada-1")
    assert r.status_code == 401 and "incorretos" in r.text
    _, r = authorize(atalaia.url, asm, reg["client_id"], challenge, action="deny")
    assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["access_denied"]
    # Um leitor só consegue conceder leitura.
    httpx.post(f"{atalaia.url}/api/v1/users", headers=auth, json={"name": "Leo", "email": "leo@acme.test",
                                                                   "password": PASSWORD, "role": "viewer"})
    _, r = authorize(atalaia.url, asm, reg["client_id"], challenge, email="leo@acme.test")
    assert r.status_code == 403
    _, _, tok, _ = connect(atalaia.url, email="leo@acme.test", access="read")
    assert tok["scope"] == "atalaia:read"
    me = asyncio.run(mcp_call(atalaia.url, tok["access_token"], "whoami"))
    assert me["role"] == "viewer"
    # Mesmo um administrador conecta no máximo como analista (sem gestão de usuários e chaves).
    _, _, owner_tok, _ = connect(atalaia.url)
    r = httpx.post(f"{atalaia.url}/api/v1/api-keys", json={"name": "x"},
                   headers={"Authorization": f"Bearer {owner_tok['access_token']}"})
    assert r.status_code == 403


def test_second_factor_is_required_when_enabled(atalaia):
    auth = register_user(atalaia.url)
    setup = httpx.post(f"{atalaia.url}/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=auth).json()
    secret = setup["secret"]
    step = mfa.current_step()
    r = httpx.post(f"{atalaia.url}/api/v1/auth/mfa/enable", json={"code": mfa.code_at(secret, step)}, headers=auth)
    assert r.status_code == 200, r.text
    _, asm = discover(atalaia.url)
    reg = httpx.post(asm["registration_endpoint"], json={"client_name": "Claude", "redirect_uris": [REDIRECT]}).json()
    _, challenge = pkce()
    _, r = authorize(atalaia.url, asm, reg["client_id"], challenge)
    assert r.status_code == 401 and 'name="code"' in r.text
    step_code = mfa.code_at(secret, step + 1)       # o código da ativação não pode ser reaproveitado
    _, r = authorize(atalaia.url, asm, reg["client_id"], challenge, code=step_code)
    assert r.status_code == 302, r.text


def test_password_change_disconnects_apps(atalaia):
    auth = register_user(atalaia.url)
    asm, reg, tok, _ = connect(atalaia.url)
    r = httpx.post(f"{atalaia.url}/api/v1/auth/change-password", headers=auth,
                   json={"current_password": PASSWORD, "new_password": "Outra-Senha-Bem-Longa-77"})
    assert r.status_code == 200
    assert httpx.get(f"{atalaia.url}/api/v1/me",
                     headers={"Authorization": f"Bearer {tok['access_token']}"}).status_code == 401
    r = httpx.post(asm["token_endpoint"], data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                                 "client_id": reg["client_id"]})
    assert r.json()["error"] == "invalid_grant"


def test_confidential_client_needs_its_secret(atalaia):
    register_user(atalaia.url)
    _, asm = discover(atalaia.url)
    reg = httpx.post(asm["registration_endpoint"], json={"client_name": "Servidor", "redirect_uris": [REDIRECT],
                                                         "token_endpoint_auth_method": "client_secret_basic"}).json()
    assert reg["client_secret"].startswith("ats_")
    verifier, challenge = pkce()
    _, r = authorize(atalaia.url, asm, reg["client_id"], challenge)
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier}
    assert httpx.post(asm["token_endpoint"], data={**data, "client_id": reg["client_id"]}).status_code == 401
    ok = httpx.post(asm["token_endpoint"], data=data, auth=(reg["client_id"], reg["client_secret"]))
    assert ok.status_code == 200, ok.text


def test_revocation_accepts_a_rotated_refresh_token(atalaia):
    """RFC 7009: revogar com o token antigo (já rotacionado) tem de derrubar a conexão inteira."""
    register_user(atalaia.url)
    asm, reg, tok, _ = connect(atalaia.url)
    new = httpx.post(asm["token_endpoint"], data={"grant_type": "refresh_token",
                                                  "refresh_token": tok["refresh_token"],
                                                  "client_id": reg["client_id"]}).json()
    assert httpx.get(f"{atalaia.url}/api/v1/me",
                     headers={"Authorization": f"Bearer {new['access_token']}"}).status_code == 200
    rev = httpx.post(asm["revocation_endpoint"], data={"token": tok["refresh_token"],
                                                       "client_id": reg["client_id"]})
    assert rev.status_code == 200
    assert httpx.get(f"{atalaia.url}/api/v1/me",
                     headers={"Authorization": f"Bearer {new['access_token']}"}).status_code == 401
