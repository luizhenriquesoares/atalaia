"""Headless-browser features: JavaScript rendering, API discovery, proof-based XSS, isolation."""
import asyncio
import threading
import urllib.parse

import pytest
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route

from atalaia.scanner import browser as browser_mod
from atalaia.scanner import passive
from atalaia.scanner.browser import BrowserSession, BrowserUnavailable, ThirdPartyFetcher
from atalaia.scanner.engine import ScanConfig, run_scan
from atalaia.scanner.http import ScanHttp
from tests.conftest import Served, make_settings, register, run_scan_and_wait, verified_target
from tests.vulnapp import make_jwt

pytest.importorskip("playwright")


def scan(url, **kw):
    kw.setdefault("rps", 500)
    kw.setdefault("browser", True)
    kw.setdefault("browser_allow_private_third_party", True)
    return asyncio.run(run_scan(ScanConfig(url, **kw)))


def index(result):
    return {(f.check_id, f.url.rsplit("/", 1)[-1], f.parameter): f for f in result.findings}


def make_asset_app(state: dict) -> Starlette:
    """A second origin: counts every request it receives."""
    async def anything(request):
        state["hits"] = state.get("hits", 0) + 1
        script = "document.body.insertAdjacentHTML('beforeend', '<a href=/from-lib?z=1>lib</a>');"
        return Response(script, media_type="application/javascript")
    return Starlette(routes=[Route("/{path:path}", anything)])


@pytest.fixture(scope="module")
def other_origin():
    served = Served(make_asset_app, host="127.0.0.2")
    yield served
    served.stop()


@pytest.fixture(autouse=True)
def _reset_other(request):
    if "other_origin" in request.fixturenames:
        request.getfixturevalue("other_origin").state.clear()
    yield


def with_session(url, coro_factory, **session_kw):
    async def go():
        http = ScanHttp(url, rps=500)
        session = BrowserSession(http, **session_kw)
        await session.start()
        try:
            return await coro_factory(session, http)
        finally:
            await session.close()
            await http.aclose()
    return asyncio.run(go())


# ------------------------------------------------------------------ detection
def test_browser_scan_finds_what_only_javascript_reveals(vuln):
    result = scan(vuln.url, profile="full")
    assert result.browser_used and result.pages_rendered > 5
    found = index(result)

    # API calls made by the page while rendering become test targets.
    assert ("sqli-error", "products", "category") in found
    assert found[("sqli-error", "search", "term")].method == "POST"          # JSON body
    # A link that only exists after JavaScript runs leads to a page with reflected XSS.
    assert found[("xss-reflected", "hidden", "q")].confidence == "confirmed"
    # DOM-based XSS: the server never reflects the value; execution is proven in the browser.
    assert found[("xss-dom", "spa", "msg")].confidence == "confirmed"
    assert found[("xss-dom", "spa", "(fragmento da URL)")].confidence == "confirmed"
    # Reflected XSS found over HTTP is upgraded to confirmed, including the attribute context.
    assert found[("xss-reflected", "search", "q")].confidence == "confirmed"
    assert found[("xss-reflected", "attr", "name")].confidence == "confirmed"
    assert "__atlp(" in found[("xss-reflected", "attr", "name")].evidence
    # Stored XSS: marker posted to /comment shows up unencoded on /comments.
    stored = found[("xss-stored", "comments", "text")]
    assert stored.method == "POST" and "/comment" in stored.evidence
    for check in ("jwt-insecure", "host-header-injection", "session-in-url"):
        assert any(f.check_id == check for f in result.findings), check

    hits = vuln.state["hits"]
    for forbidden in ("logout", "account_delete", "delete_account_post", "login_post"):
        assert forbidden not in hits


def test_without_browser_those_findings_are_missed(vuln):
    result = scan(vuln.url, profile="full", browser=False)
    found = index(result)
    assert not result.browser_used and result.pages_rendered == 0
    assert ("xss-dom", "spa", "msg") not in found
    assert ("xss-reflected", "hidden", "q") not in found
    assert ("sqli-error", "products", "category") not in found
    assert found[("xss-reflected", "search", "q")].confidence == "high"       # inferred, not proven


def test_standard_profile_does_not_inject_into_post_apis(vuln):
    result = scan(vuln.url, profile="standard")
    found = index(result)
    assert ("sqli-error", "products", "category") in found
    assert ("sqli-error", "search", "term") not in found
    assert not any(f.check_id == "xss-stored" for f in result.findings)
    assert "comment_post" not in vuln.state["hits"]


def test_passive_profile_renders_but_sends_no_payloads(vuln):
    result = scan(vuln.url, profile="passive")
    assert result.browser_used and result.pages_rendered > 0
    assert {f.check_id for f in result.findings}.isdisjoint(
        {"xss-dom", "xss-reflected", "xss-stored", "sqli-error", "ssti", "host-header-injection"})
    assert any(f.check_id == "jwt-insecure" for f in result.findings)


def test_hardened_spa_has_no_false_positives(secure):
    result = scan(secure.url, profile="full")
    assert result.browser_used and result.pages_rendered > 5
    unexpected = [f for f in result.findings if f.check_id != "no-https"]
    assert unexpected == [], [(f.check_id, f.url, f.parameter, f.evidence) for f in unexpected]


def test_scan_continues_when_the_browser_cannot_start(vuln, monkeypatch):
    async def boom(self):
        raise BrowserUnavailable("chromium ausente")
    monkeypatch.setattr(BrowserSession, "start", boom)
    result = scan(vuln.url, profile="standard")
    assert not result.browser_used
    assert any("Navegador indisponível" in n for n in result.notes)
    assert any(f.check_id == "sqli-error" for f in result.findings)


def test_budget_and_cancellation_apply_to_browser_traffic(vuln):
    result = scan(vuln.url, profile="full", max_requests=40)
    assert result.budget_exhausted and result.requests_sent <= 40
    ev = threading.Event()
    ev.set()
    result = asyncio.run(run_scan(ScanConfig(vuln.url, rps=500, browser=True), cancel_event=ev))
    assert result.canceled and result.requests_sent == 0


# ------------------------------------------------------------------ isolation of the browser
def test_page_cannot_make_the_browser_reach_other_origins(vuln, other_origin):
    """A hostile page (here: our own DOM-XSS sink) asks for resources on another origin. Nothing
    may reach it: not images, not fetch(), not WebSockets, not a redirect."""
    other = other_origin.url
    probes = (f'<img src="{other}/pixel.png"><img src=x onerror="fetch(\'{other}/fetch\');'
              f'new WebSocket(\'ws://127.0.0.2:{other_origin.port}/ws\');'
              f'var s=document.createElement(\'script\');s.src=\'{other}/dyn.js\';document.body.append(s)">')

    async def go(session, http):
        await session.visit(f"{vuln.url}/spa#{urllib.parse.quote(probes)}")
        await session.visit(f"{vuln.url}/redirect?next={urllib.parse.quote(other + '/redirected')}")
        return await session.visit(f"{other}/direct")

    assert with_session(vuln.url, go) is None           # out-of-scope navigation is refused outright
    assert other_origin.state.get("hits", 0) == 0


def test_third_party_scripts_only_from_public_addresses(vuln, other_origin):
    vuln.state["third_party"] = other_origin.url + "/lib.js"

    async def go(session, http):
        return await session.visit(vuln.url + "/spa")

    # Default policy: the asset host resolves to a non-public address, so it is never contacted.
    rendered = with_session(vuln.url, go, third_party=ThirdPartyFetcher(allow_private=False))
    assert other_origin.state.get("hits", 0) == 0
    assert not any("/from-lib" in link for link in rendered.links)

    # On-premises mode: the script is fetched by the guarded fetcher and runs.
    rendered = with_session(vuln.url, go, third_party=ThirdPartyFetcher(allow_private=True))
    assert other_origin.state["hits"] == 1
    assert any("/from-lib" in link for link in rendered.links)


def test_in_scope_redirects_are_followed_and_dom_is_extracted(vuln):
    async def go(session, http):
        a = await session.visit(f"{vuln.url}/redirect?next={urllib.parse.quote('/safe?q=1')}")
        b = await session.visit(vuln.url + "/spa?msg=oi")
        c = await session.visit(vuln.url + "/logout")
        return a, b, c, list(session.captured)

    a, b, c, captured = with_session(vuln.url, go)
    assert a.url.endswith("/safe?q=1")
    assert any(link.endswith("/hidden?q=ola") for link in b.links)       # link created by JavaScript
    calls = {(cap.method, urllib.parse.urlsplit(cap.url).path) for cap in captured}
    assert ("GET", "/api/products") in calls and ("POST", "/api/search") in calls
    assert c is None and "logout" not in vuln.state["hits"]              # session-ending URLs are never opened


def test_dead_proxy_blocks_unintercepted_traffic(vuln):
    """Belt and braces: even a context without our interception cannot reach the network."""
    async def go(session, http):
        ctx = await session._browser.new_context()
        page = await ctx.new_page()
        try:
            await page.goto(vuln.url + "/", timeout=5000)
            return "loaded"
        except Exception as exc:
            return str(exc)
        finally:
            await ctx.close()

    before = vuln.state.get("hits", {}).get("index", 0)
    assert "ERR_PROXY_CONNECTION_FAILED" in with_session(vuln.url, go)
    assert vuln.state.get("hits", {}).get("index", 0) == before


def test_render_key_treats_client_routes_as_pages():
    key = browser_mod.render_key
    assert key("http://x/a?id=1") == key("http://x/a?id=2")
    assert key("http://x/#/produtos") != key("http://x/#/carrinho")
    assert key("http://x/a#secao") == key("http://x/a")


# ------------------------------------------------------------------ new non-browser checks
def test_jwt_weakness_detection():
    assert "segredo trivial" in passive.jwt_weakness(make_jwt("secret"))
    assert passive.jwt_weakness(make_jwt("b7f1c0d9-nao-esta-na-lista-e-e-longo-4411")) is None
    unsigned = make_jwt("x").rsplit(".", 1)[0].replace(
        "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9", "eyJhbGciOiJub25lIn0") + "."
    assert "alg none" in passive.jwt_weakness(unsigned)
    assert passive.jwt_weakness("isto.nao.ejwt") is None
    assert "secret" not in passive.jwt_weakness(make_jwt("secret"))        # the secret itself is masked


def test_crlf_injection_is_detected():
    """uvicorn refuses to emit CR/LF in headers, so the vulnerable server is a raw socket."""
    async def handle(reader, writer):
        try:
            line = (await reader.readline()).decode("latin-1")
            while (await reader.readline()).strip():
                pass
            target = line.split(" ")[1] if " " in line else "/"
            parts = urllib.parse.urlsplit(target)
            if parts.path == "/go":
                nxt = urllib.parse.parse_qs(parts.query).get("next", ["/"])[0]
                writer.write(f"HTTP/1.1 302 Found\r\nLocation: {nxt}\r\nContent-Length: 0\r\n"
                             "Connection: close\r\n\r\n".encode("latin-1", "replace"))
            else:
                body = b'<html><body><a href="/go?next=/inicio">ir</a></body></html>' if parts.path == "/" else b"ok"
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        finally:
            writer.close()

    async def go():
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await run_scan(ScanConfig(f"http://127.0.0.1:{port}", rps=500))

    result = asyncio.run(go())
    crlf = [f for f in result.findings if f.check_id == "crlf-injection"]
    assert len(crlf) == 1 and crlf[0].parameter == "next" and crlf[0].url.endswith("/go")


# ------------------------------------------------------------------ through the API
def test_api_scan_uses_the_browser_and_reports_confirmed_findings(tmp_path, vuln):
    from fastapi.testclient import TestClient
    from atalaia.api.app import create_app
    with TestClient(create_app(make_settings(tmp_path, browser="auto"))) as client:
        auth = register(client)
        target = verified_target(client, auth, vuln)
        done = run_scan_and_wait(client, auth, target["id"], "standard")
        assert done["status"] == "completed" and done["summary"]["rendered"] > 0
        items = client.get("/api/v1/findings", params={"q": "DOM"}, headers=auth).json()["items"]
        assert items and all(i["confidence"] == "confirmed" and i["check_id"] == "xss-dom" for i in items)
        html_report = client.get(f"/api/v1/scans/{done['id']}/report?format=html", headers=auth).text
        assert "confirmada por execução no navegador" in html_report
        assert "<img src=x onerror" not in html_report          # proof payloads are escaped in the report
