"""Servidor MCP: ferramentas de ponta a ponta contra uma instância real do Atalaia."""
from __future__ import annotations

import asyncio
import contextlib
import json

import httpx
import pytest

mcp = pytest.importorskip("mcp")

from atalaia.api.app import create_app  # noqa: E402
from atalaia.mcp_server import AtalaiaClient, build_server, check_base_url  # noqa: E402
from tests.conftest import PASSWORD, Served, make_settings  # noqa: E402

try:
    from mcp import Client                            # SDK 2.x
except ImportError:                                   # SDK 1.x
    Client = None


def field(obj, snake: str, camel: str):
    """Os modelos do SDK 2.x usam snake_case; os do 1.x, camelCase."""
    return getattr(obj, snake) if hasattr(obj, snake) else getattr(obj, camel)


@contextlib.asynccontextmanager
async def connect(server, elicitation_callback=None):
    """Sessão de cliente MCP com o servidor (objeto em memória ou parâmetros de stdio)."""
    from mcp import StdioServerParameters
    if Client is not None:
        async with Client(server, elicitation_callback=elicitation_callback) as c:
            yield c
    elif isinstance(server, StdioServerParameters):
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client
        async with stdio_client(server) as (r, w), ClientSession(r, w) as c:
            await c.initialize()
            yield c
    else:
        from mcp.shared.memory import create_connected_server_and_client_session
        async with create_connected_server_and_client_session(
                server._mcp_server, elicitation_callback=elicitation_callback) as c:
            yield c


@pytest.fixture
def atalaia(tmp_path):
    served = Served(lambda _state: create_app(make_settings(tmp_path)))
    yield served
    served.stop()


def owner_headers(base: str) -> dict:
    r = httpx.post(f"{base}/api/v1/auth/register", json={"organization": "ACME", "name": "Ana",
                                                          "email": "ana@acme.test", "password": PASSWORD})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def api_key(base: str, auth: dict, role: str = "analyst") -> str:
    r = httpx.post(f"{base}/api/v1/api-keys", json={"name": f"mcp-{role}", "role": role}, headers=auth)
    assert r.status_code == 201, r.text
    return r.json()["key"]


async def call(client, name: str, args: dict | None = None):
    res = await client.call_tool(name, args or {})
    if field(res, "is_error", "isError"):
        return {"error": " ".join(getattr(c, "text", "") for c in res.content)}
    sc = field(res, "structured_content", "structuredContent")
    if sc is not None:
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return res.content[0].text


def run(coro_fn, server):
    async def main():
        async with connect(server) as c:
            return await coro_fn(c)
    return asyncio.run(main())


def test_full_flow_through_mcp(atalaia, vuln):
    auth = owner_headers(atalaia.url)
    server = build_server(AtalaiaClient(atalaia.url, api_key(atalaia.url, auth)))

    async def flow(c):
        out = {}
        tools = {t.name: t for t in (await c.list_tools()).tools}
        out["tools"] = tools
        target = await call(c, "create_target", {"name": "Loja", "base_url": vuln.url})
        out["target"] = target
        # Antes da prova de propriedade a varredura é recusada pelo servidor.
        out["refused"] = await call(c, "start_scan", {"target_id": target["id"]})
        vuln.state["token"] = target["verification"]["http_file"]["content"]
        out["verify"] = await call(c, "verify_target_ownership", {"target_id": target["id"],
                                                                  "method": "http_file"})
        scan = await call(c, "start_scan", {"target_id": target["id"], "profile": "standard"})
        progress: list = []

        async def on_progress(p, total, msg):
            progress.append((p, total, msg))
        res = await c.call_tool("wait_for_scan", {"scan_id": scan["id"], "timeout_seconds": 120},
                                progress_callback=on_progress)
        out["done"] = field(res, "structured_content", "structuredContent")
        out["progress"] = progress
        out["findings"] = await call(c, "list_findings", {"scan_id": scan["id"], "severity": ["high", "critical"],
                                                          "status": ["open"]})
        fid = out["findings"]["items"][0]["id"]
        out["finding"] = await call(c, "get_finding", {"finding_id": fid})
        out["triage_no_note"] = await call(c, "triage_finding", {"finding_id": fid, "status": "false_positive"})
        out["triage"] = await call(c, "triage_finding", {"finding_id": fid, "status": "accepted_risk",
                                                         "note": "compensado pelo WAF"})
        out["report"] = await call(c, "get_scan_report", {"scan_id": scan["id"]})
        out["sarif"] = await call(c, "get_scan_report", {"scan_id": scan["id"], "format": "sarif"})
        out["dash"] = await call(c, "get_dashboard")
        out["whoami"] = await call(c, "whoami")
        scan2 = await call(c, "start_scan", {"target_id": target["id"], "profile": "passive"})
        await call(c, "wait_for_scan", {"scan_id": scan2["id"], "timeout_seconds": 120})
        out["diff"] = await call(c, "compare_scans", {"base_scan_id": scan["id"], "new_scan_id": scan2["id"]})
        out["prompts"] = [p.name for p in (await c.list_prompts()).prompts]
        return out

    out = run(flow, server)
    assert {"start_scan", "wait_for_scan", "list_findings", "triage_finding", "compare_scans"} <= set(out["tools"])
    assert field(out["tools"]["get_finding"].annotations, "read_only_hint", "readOnlyHint") is True
    assert field(out["tools"]["start_scan"].annotations, "read_only_hint", "readOnlyHint") is False
    assert out["target"]["verified"] is False
    assert "[403]" in out["refused"]["error"] and "verifica" in out["refused"]["error"].lower()
    assert out["verify"]["verified"] is True
    assert out["done"]["finished"] is True and out["done"]["scan"]["status"] == "completed"
    assert out["done"]["open_findings_total"] > 0
    assert out["progress"] and out["progress"][-1][1] == 100.0
    assert out["findings"]["total"] > 0
    assert set(out["finding"]["evidence"] or {"untrusted_content_from_target": 1}) == {"untrusted_content_from_target"}
    assert "justificativa" in out["triage_no_note"]["error"]
    assert out["triage"]["applied"] is True and out["triage"]["finding"]["status"] == "accepted_risk"
    # Cliente de teste sem elicitation: nada foi confirmado, e a resposta não pode dizer o contrário.
    assert out["triage"]["confirmed_by"] is None and out["triage"]["confirmation"] == "unavailable"
    assert out["report"].startswith("# Relatório Atalaia: Loja")
    assert json.loads(out["sarif"])["version"] == "2.1.0"
    assert out["dash"]["verified_targets"] == 1
    assert out["whoami"]["role"] == "analyst"
    assert out["diff"]["counts"]["no_longer_detected"] > 0      # o perfil passivo não repete os testes ativos
    assert {"assess_site", "executive_summary", "validate_fix"} <= set(out["prompts"])

    # Tudo o que o assistente fez ficou na trilha de auditoria, atribuído à chave.
    logs = httpx.get(f"{atalaia.url}/api/v1/audit-logs", params={"limit": 200}, headers=auth).json()
    actions = {a["action"] for a in logs if a["actor"].startswith("apikey")}
    assert {"target.create", "scan.refused", "target.verify", "scan.start", "finding.triage",
            "report.export"} <= actions, actions


def test_viewer_key_and_read_only_mode(atalaia, vuln):
    auth = owner_headers(atalaia.url)
    viewer = build_server(AtalaiaClient(atalaia.url, api_key(atalaia.url, auth, "viewer")))
    read_only = build_server(AtalaiaClient(atalaia.url, api_key(atalaia.url, auth)), read_only=True)

    async def as_viewer(c):
        return await call(c, "create_target", {"name": "x", "base_url": vuln.url})
    assert "[403]" in run(as_viewer, viewer)["error"]

    async def names(c):
        return {t.name for t in (await c.list_tools()).tools}
    tools = run(names, read_only)
    assert "list_findings" in tools and "get_dashboard" in tools
    assert not tools & {"start_scan", "create_target", "triage_finding", "cancel_scan", "verify_target_ownership"}


def test_bad_key_and_unreachable_server(atalaia):
    async def dash(c):
        return await call(c, "get_dashboard")
    assert "[401]" in run(dash, build_server(AtalaiaClient(atalaia.url, "atl_invalida")))["error"]
    assert "Não foi possível falar" in run(dash, build_server(AtalaiaClient("http://127.0.0.1:1", "x")))["error"]


def test_api_key_is_never_sent_over_plain_http_to_remote_hosts():
    assert check_base_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    assert check_base_url("http://localhost:8000") == "http://localhost:8000"
    assert check_base_url("https://atalaia.acme.com") == "https://atalaia.acme.com"
    with pytest.raises(ValueError):
        check_base_url("http://atalaia.acme.com")
    with pytest.raises(ValueError):
        check_base_url("ftp://x")
    assert check_base_url("http://atalaia.acme.com", allow_insecure=True)


def test_stdio_subprocess(atalaia, tmp_path):
    """O executável real, falando JSON-RPC por stdin/stdout, como o Claude Desktop faz."""
    import os
    import sys

    from mcp import StdioServerParameters

    auth = owner_headers(atalaia.url)
    params = StdioServerParameters(command=sys.executable, args=["-m", "atalaia.mcp_server"],
                                   env={**os.environ, "ATALAIA_URL": atalaia.url,
                                        "ATALAIA_API_KEY": api_key(atalaia.url, auth, "viewer")})

    async def main():
        async with connect(params) as c:
            tools = {t.name for t in (await c.list_tools()).tools}
            return tools, await call(c, "whoami")
    tools, me = asyncio.run(main())
    assert "start_scan" in tools and me["role"] == "viewer"


def test_ids_cannot_escape_into_other_routes(atalaia):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={})
    server = build_server(AtalaiaClient("http://atalaia.test", "k", transport=httpx.MockTransport(handler)))

    async def go(c):
        return [await call(c, "get_target", {"target_id": "../api-keys"}),
                await call(c, "get_finding", {"finding_id": "x?y=1"}),
                await call(c, "cancel_scan", {"scan_id": "a/b"}),
                await call(c, "start_scan", {"target_id": "../api-keys"}),
                await call(c, "list_findings", {"scan_id": "a/b"}),
                await call(c, "compare_scans", {"base_scan_id": "a/b", "new_scan_id": "ok"})]
    results = run(go, server)
    assert all("inválido" in r["error"] for r in results)
    assert seen == []


# ------------------------------------------------------------------ modo HTTP (uso remoto)
@contextlib.asynccontextmanager
async def connect_http(url: str, key: str | None, elicitation_callback=None):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    if Client is not None:
        import httpx2
        from mcp.client.streamable_http import streamable_http_client
        async with httpx2.AsyncClient(headers=headers, timeout=60) as http, \
                Client(streamable_http_client(url, http_client=http), elicitation_callback=elicitation_callback) as c:
            yield c
    else:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
        async with streamablehttp_client(url, headers=headers) as (r, w, _), \
                ClientSession(r, w, elicitation_callback=elicitation_callback) as c:
            await c.initialize()
            yield c


def test_embedded_mcp_requires_a_valid_api_key(atalaia):
    url = f"{atalaia.url}/mcp"
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}}
    accept = {"Accept": "application/json, text/event-stream"}
    r = httpx.post(url, json=init, headers=accept)
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
    r = httpx.post(url, json=init, headers={**accept, "Authorization": "Bearer atl_x_falsa"})
    assert r.status_code == 401
    # Um token de sessão de usuário não serve: o MCP só aceita chaves de API.
    session = owner_headers(atalaia.url)
    assert httpx.post(url, json=init, headers={**accept, **session}).status_code == 401
    key = api_key(atalaia.url, session, "viewer")
    r = httpx.post(url, json=init, headers={**accept, "Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text


def test_embedded_mcp_each_client_acts_as_its_own_key(atalaia, vuln, secure):
    """Duas organizações no mesmo endpoint /mcp: cada uma só vê o que é seu, e a auditoria registra a
    chave de quem chamou."""
    acme = owner_headers(atalaia.url)
    r = httpx.post(f"{atalaia.url}/api/v1/auth/register", json={"organization": "Globex", "name": "Bia",
                                                                 "email": "bia@globex.test", "password": PASSWORD})
    globex = {"Authorization": f"Bearer {r.json()['token']}"}
    k_acme, k_globex = api_key(atalaia.url, acme), api_key(atalaia.url, globex, "viewer")

    async def go():
        async with connect_http(f"{atalaia.url}/mcp", k_acme) as c:
            created = await call(c, "create_target", {"name": "Loja ACME", "base_url": vuln.url})
            mine = await call(c, "list_targets")
        async with connect_http(f"{atalaia.url}/mcp", k_globex) as c:
            theirs = await call(c, "list_targets")
            peek = await call(c, "get_target", {"target_id": created["id"]})
            write = await call(c, "create_target", {"name": "x", "base_url": secure.url})
            me = await call(c, "whoami")
        return created, mine, theirs, peek, write, me
    created, mine, theirs, peek, write, me = asyncio.run(go())
    assert mine["total"] == 1 and theirs["total"] == 0
    assert "[404]" in peek["error"]                     # isolamento entre organizações
    assert "[403]" in write["error"]                    # chave de leitor não cadastra alvo
    assert me["organization"]["name"] == "Globex" and me["role"] == "viewer"
    logs = httpx.get(f"{atalaia.url}/api/v1/audit-logs", headers=acme).json()
    create = next(a for a in logs if a["action"] == "target.create")
    assert create["actor"] == "apikey:mcp-analyst" and create["ip"] == "127.0.0.1"


def test_embedded_mcp_reports_scan_progress(atalaia, vuln):
    auth = owner_headers(atalaia.url)
    key = api_key(atalaia.url, auth)

    async def go():
        async with connect_http(f"{atalaia.url}/mcp", key) as c:
            target = await call(c, "create_target", {"name": "Loja", "base_url": vuln.url})
            vuln.state["token"] = target["verification"]["http_file"]["content"]
            await call(c, "verify_target_ownership", {"target_id": target["id"], "method": "http_file"})
            scan = await call(c, "start_scan", {"target_id": target["id"], "profile": "passive"})
            seen = []

            async def on_progress(p, total, msg):
                seen.append(p)
            res = await c.call_tool("wait_for_scan", {"scan_id": scan["id"], "timeout_seconds": 120},
                                    progress_callback=on_progress)
            return field(res, "structured_content", "structuredContent"), seen
    done, seen = asyncio.run(go())
    assert done["finished"] is True and done["scan"]["status"] == "completed"
    assert seen


def test_standalone_http_server_against_remote_atalaia(atalaia):
    """atalaia-mcp --transport streamable-http: o servidor não tem chave própria; usa a de cada cliente."""
    from atalaia.mcp_server import http_app
    client = AtalaiaClient(atalaia.url)
    proxy = Served(lambda _state: http_app(build_server(client), client)[1])
    try:
        key = api_key(atalaia.url, owner_headers(atalaia.url), "viewer")
        assert httpx.post(f"{proxy.url}/mcp", json={}).status_code == 401

        async def go():
            async with connect_http(f"{proxy.url}/mcp", key) as c:
                return await call(c, "whoami")
        assert asyncio.run(go())["role"] == "viewer"
    finally:
        proxy.stop()


def test_mcp_can_be_disabled(tmp_path):
    from fastapi.testclient import TestClient
    with TestClient(create_app(make_settings(tmp_path, mcp_enabled=False))) as c:
        assert c.post("/mcp", json={}).status_code in (404, 405)



# ------------------------------------------------------------------ confirmação e catálogo
def _scanned_finding(atalaia, vuln):
    """Organização com um alvo verificado e uma varredura concluída; devolve (chave, id de um achado)."""
    auth = owner_headers(atalaia.url)
    t = httpx.post(f"{atalaia.url}/api/v1/targets", json={"name": "Loja", "base_url": vuln.url}, headers=auth).json()
    vuln.state["token"] = t["verification"]["http_file"]["content"]
    httpx.post(f"{atalaia.url}/api/v1/targets/{t['id']}/verify", json={"method": "http_file"}, headers=auth)
    scan = httpx.post(f"{atalaia.url}/api/v1/scans", json={"target_id": t["id"], "profile": "passive"},
                      headers=auth).json()
    import time
    for _ in range(600):
        if httpx.get(f"{atalaia.url}/api/v1/scans/{scan['id']}", headers=auth).json()["status"] not in ("queued", "running"):
            break
        time.sleep(0.1)
    items = httpx.get(f"{atalaia.url}/api/v1/findings", params={"scan_id": scan["id"]}, headers=auth).json()["items"]
    return api_key(atalaia.url, auth), items[0]["id"], auth


def test_triage_asks_the_user_first(atalaia, vuln):
    import mcp.types as types
    key, fid, auth = _scanned_finding(atalaia, vuln)
    server = build_server(AtalaiaClient(atalaia.url, key))
    asked = []

    def answer(action, content=None):
        async def cb(context, params):
            asked.append(params)
            return types.ElicitResult(action=action, content=content)
        return cb

    async def triage(c, cb, **args):
        holder["cb"] = cb
        return await call(c, "triage_finding", {"finding_id": fid, **args})

    holder = {}

    async def dispatch(context, params):
        return await holder["cb"](context, params)

    async def flow():
        async with connect(server, elicitation_callback=dispatch) as c:
            declined = await triage(c, answer("decline"), status="false_positive", note="teste")
            asked_msg = asked[-1].message
            not_ticked = await triage(c, answer("accept", {"approve": False, "note": "x"}), status="fixed")
            still = httpx.get(f"{atalaia.url}/api/v1/findings/{fid}", headers=auth).json()["status"]
            ok = await triage(c, answer("accept", {"approve": True, "note": "Coberto pelo WAF, ticket SEC-12"}),
                              status="accepted_risk", note="waf")
            return declined, asked_msg, not_ticked, still, ok

    declined, asked_msg, not_ticked, still, ok = asyncio.run(flow())
    assert declined["applied"] is False, declined
    assert "FALSO POSITIVO" in asked_msg
    assert not_ticked["applied"] is False and still == "open"
    # O usuário aprova e corrige a justificativa: vale o texto dele.
    assert ok["applied"] is True and ok["confirmed_by"] == "user"
    f = httpx.get(f"{atalaia.url}/api/v1/findings/{fid}", headers=auth).json()
    assert f["status"] == "accepted_risk" and f["status_note"] == "Coberto pelo WAF, ticket SEC-12"
    schema = field(asked[-1], "requested_schema", "requestedSchema")
    assert schema["properties"]["note"]["default"] == "waf"


def test_check_catalog_tools_and_resources(atalaia):
    server = build_server(AtalaiaClient(atalaia.url, "atl_qualquer"))

    async def go(c):
        allc = await call(c, "list_checks")
        xss = await call(c, "list_checks", {"search": "CWE-79"})
        crit = await call(c, "list_checks", {"severity": ["critical"]})
        one = await call(c, "get_check", {"check_id": "xss-dom"})
        bad = await call(c, "get_check", {"check_id": "nao-existe"})
        res = await c.read_resource("atalaia://checks")
        tpl = await c.read_resource("atalaia://checks/sqli-error")
        listed = await c.list_resources()
        templates = await c.list_resource_templates()
        return allc, xss, crit, one, bad, res, tpl, listed, templates
    allc, xss, crit, one, bad, res, tpl, listed, templates = run(go, server)
    assert allc["total"] == 52 and set(allc["profiles"]) == {"passive", "standard", "full"}
    assert {i["id"] for i in xss["items"]} >= {"xss-reflected", "xss-dom", "xss-stored"}
    assert crit["total"] > 0 and all(i["severity"] == "critical" for i in crit["items"])
    assert one["requires_browser"] is True and one["profiles"] == ["standard", "full"] and one["remediation"]
    assert "desconhecida" in bad["error"]
    assert len(json.loads(res.contents[0].text)["items"]) == 52
    assert json.loads(tpl.contents[0].text)["cwe"] == "CWE-89"
    assert "atalaia://checks" in {str(r.uri) for r in listed.resources}
    assert any("checks/{check_id}" in field(t, "uri_template", "uriTemplate") for t in templates.resource_templates
               ) if hasattr(templates, "resource_templates") else True



def test_triage_confirmation_over_remote_http(atalaia, vuln):
    """No /mcp embutido (HTTP sem estado), a confirmação também chega ao usuário."""
    import mcp.types as types
    key, fid, auth = _scanned_finding(atalaia, vuln)
    asked = []

    async def cb(context, params):
        asked.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": True, "note": "aceito pelo time"})

    async def go():
        async with connect_http(f"{atalaia.url}/mcp", key, elicitation_callback=cb) as c:
            return await call(c, "triage_finding", {"finding_id": fid, "status": "accepted_risk", "note": "x"})
    out = asyncio.run(go())
    assert asked, out
    assert out["applied"] is True and out["confirmed_by"] == "user"
    assert httpx.get(f"{atalaia.url}/api/v1/findings/{fid}", headers=auth).json()["status_note"] == "aceito pelo time"


def test_error_messages_are_actionable():
    from atalaia.mcp_server import _error_message
    assert "Muitas requisições" in _error_message(httpx.Response(429))
    assert "falhou" in _error_message(httpx.Response(500))
    assert "Chave de API inválida" in _error_message(httpx.Response(401))
    detail = [{"loc": ["body", "name"], "msg": "obrigatório"}]
    assert _error_message(httpx.Response(422, json={"detail": detail})) == "[422] name: obrigatório"
