"""Headless-browser support: JavaScript rendering, API discovery and proof-based XSS.

Security model
--------------
Chromium is used purely as a renderer. It is launched behind a dead proxy, so it cannot open
any network connection by itself (pages, WebSockets, prefetches, IP literals: all fail).
Every request a page makes is intercepted and then either

  * served through ScanHttp when it targets the scanned origin, so it obeys the same scope,
    rate limit, request budget, pinned address and credentials as the rest of the scan;
  * fetched by ThirdPartyFetcher when it is a plain GET for a script or stylesheet on another
    host, which must resolve to public addresses only (what any visitor's browser would load);
  * aborted.

A page under test therefore cannot use our browser to reach internal services.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from ..netguard import TargetNotAllowed, assert_allowed_host, is_ip_literal, pick_ip, pin_url
from .crawler import UNSAFE_LINK, Crawler, Form
from .http import USER_AGENT, BudgetExceeded, Resp, ScanCanceled, ScanHttp

BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/130.0.0.0 Safari/537.36 " + USER_AGENT)
DEAD_PROXY = {"server": "http://127.0.0.1:9", "bypass": "<-loopback>"}
BROWSER_MAX_BODY = 8_000_000
NAV_TIMEOUT_MS = 20_000
SETTLE_MAX_S = 6.0
SETTLE_QUIET_S = 0.4
REDIRECTS = (301, 302, 303, 307, 308)
SKIPPED_RESOURCES = ("image", "media", "font")
DROPPED_REQUEST_HEADERS = {"host", "connection", "content-length", "accept-encoding", "proxy-connection",
                           "proxy-authorization"}
DROPPED_RESPONSE_HEADERS = {"content-encoding", "content-length", "transfer-encoding", "connection",
                            "keep-alive", "set-cookie"}

EXTRACT_JS = """() => ({
  url: location.href,
  links: Array.from(document.querySelectorAll('a[href], area[href]')).map(a => a.href).slice(0, 500),
  forms: Array.from(document.forms).slice(0, 50).map(f => ({
    action: f.action || location.href,
    method: (f.getAttribute('method') || 'GET').toUpperCase(),
    inputs: Array.from(f.elements).filter(e => e.name).slice(0, 60).map(e => ({
      name: String(e.name), type: String(e.type || 'text').toLowerCase(), value: String(e.value || '')}))
  }))
})"""


class BrowserUnavailable(Exception):
    pass


@dataclass
class Captured:
    """A request the page made by itself while being rendered."""
    method: str
    url: str
    resource_type: str
    body: bytes | None
    content_type: str
    resp: Resp


@dataclass
class Rendered:
    url: str
    links: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)


class ThirdPartyFetcher:
    """Loads public script/style assets hosted outside the target, with SSRF protection:
    each host is resolved once, must be entirely public, and the connection is pinned to it."""

    def __init__(self, *, allow_private: bool = False, max_fetches: int = 80, timeout: float = 10):
        self.allow_private = allow_private
        self.remaining = max_fetches
        self._ips: dict[str, str | None] = {}
        self._cache: dict[str, tuple[int, dict[str, str], bytes] | None] = {}
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                         headers={"User-Agent": BROWSER_UA, "Accept": "*/*"})

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _ip_for(self, host: str) -> str | None:
        if host not in self._ips:
            try:
                ips = await asyncio.to_thread(assert_allowed_host, host, allow_private=self.allow_private)
                self._ips[host] = pick_ip(ips)
            except TargetNotAllowed:
                self._ips[host] = None
        return self._ips[host]

    async def fetch(self, url: str) -> tuple[int, dict[str, str], bytes] | None:
        if url in self._cache:
            return self._cache[url]
        result = None
        if self.remaining > 0:
            self.remaining -= 1
            try:
                result = await self._fetch(url)
            except (httpx.HTTPError, OSError, ValueError):
                result = None
        self._cache[url] = result
        return result

    async def _fetch(self, url: str):
        for _ in range(4):
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            if parts.scheme not in ("http", "https") or not host:
                return None
            ip = await self._ip_for(host)
            if ip is None:
                return None
            target, headers, extensions = url, {}, {}
            if not is_ip_literal(host):
                target, headers["Host"], sni = pin_url(url, ip)
                extensions = {"sni_hostname": sni}
            async with self._client.stream("GET", target, headers=headers, extensions=extensions) as r:
                if r.status_code in REDIRECTS and r.headers.get("location"):
                    url = urljoin(url, r.headers["location"])
                    continue
                chunks, size = [], 0
                async for chunk in r.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > BROWSER_MAX_BODY:
                        return None
                out = {k: v for k, v in r.headers.items() if k.lower() in (
                    "content-type", "access-control-allow-origin", "cache-control")}
                return r.status_code, out, b"".join(chunks)
        return None


class BrowserSession:
    def __init__(self, http: ScanHttp, *, third_party: ThirdPartyFetcher | None = None,
                 excludes: list[str] | None = None, sandbox: bool = False):
        self.http = http
        self.third_party = third_party
        self.excludes = [e for e in (excludes or []) if e]
        self.sandbox = sandbox
        self.captured: list[Captured] = []
        self.proofs: set[int] = set()
        self.pages_rendered = 0
        self._fatal: Exception | None = None
        self._static: dict[str, Resp] = {}
        self._activity: dict = {}                 # page -> [requests in flight, time of last activity]
        self._slots = asyncio.Semaphore(4)        # pages rendered at the same time
        self._pw = self._browser = self._ctx = None
        self._next_proof = 1000

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserUnavailable("o pacote playwright não está instalado") from exc
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                proxy=DEAD_PROXY, chromium_sandbox=self.sandbox,
                args=["--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-background-networking",
                      "--disable-component-update", "--disable-sync", "--no-first-run"])
            self._ctx = await self._browser.new_context(
                service_workers="block", user_agent=BROWSER_UA, ignore_https_errors=True,
                accept_downloads=False, viewport={"width": 1280, "height": 900})
            self._ctx.set_default_timeout(NAV_TIMEOUT_MS)
            await self._ctx.expose_binding("__atlp", self._on_proof)
            await self._ctx.route("**/*", self._route)
        except Exception as exc:
            await self.close()
            reason = str(exc).splitlines()[0][:200]
            if "Executable doesn't exist" in reason:
                reason = "o Chromium não está instalado; rode: python -m playwright install chromium"
            raise BrowserUnavailable(reason) from exc

    async def close(self) -> None:
        for closer in (getattr(self._ctx, "close", None), getattr(self._browser, "close", None),
                       getattr(self._pw, "stop", None)):
            if closer:
                try:
                    await closer()
                except Exception:
                    pass
        self._ctx = self._browser = self._pw = None
        if self.third_party:
            await self.third_party.aclose()

    def new_proof_id(self) -> int:
        self._next_proof += 1
        return self._next_proof

    def _on_proof(self, source, ident=None) -> None:
        if isinstance(ident, int):
            self.proofs.add(ident)

    # ------------------------------------------------------------------ request interception
    async def _route(self, route) -> None:
        try:
            tracker = self._activity.get(route.request.frame.page)
        except Exception:
            tracker = None
        if tracker:
            tracker[0] += 1
        try:
            req = route.request
            url = req.url
            if not url.startswith(("http://", "https://")):
                await route.abort("blockedbyclient")
            elif self.http.in_scope(url):
                await self._serve_target(route, req)
            elif self.third_party and req.method == "GET" and req.resource_type in ("script", "stylesheet"):
                result = await self.third_party.fetch(url)
                if result:
                    status, headers, body = result
                    await route.fulfill(status=status, headers=headers, body=body)
                else:
                    await route.abort("blockedbyclient")
            else:
                await route.abort("blockedbyclient")
        except (ScanCanceled, BudgetExceeded) as exc:
            self._fatal = exc
            await self._abort(route)
        except Exception:
            await self._abort(route)      # page closed mid-flight, malformed response, ...
        finally:
            if tracker:
                tracker[0] -= 1
                tracker[1] = time.monotonic()

    @staticmethod
    async def _abort(route) -> None:
        try:
            await route.abort("failed")
        except Exception:
            pass

    def _blocked(self, url: str) -> bool:
        return bool(UNSAFE_LINK.search(url)) or any(e in url for e in self.excludes)

    async def _serve_target(self, route, req) -> None:
        method, rtype, url = req.method, req.resource_type, req.url
        if method not in ("GET", "POST", "HEAD", "OPTIONS") or rtype in SKIPPED_RESOURCES or self._blocked(url):
            await route.abort("blockedbyclient")
            return
        cacheable = method == "GET" and rtype in ("script", "stylesheet")
        if cacheable and url in self._static:
            await self._fulfill(route, self._static[url], [])
            return
        headers = {k: v for k, v in req.headers.items()
                   if k.lower() not in DROPPED_REQUEST_HEADERS and not k.startswith(":")}
        base_cookie = self.http.client.headers.get("cookie")
        if base_cookie:     # scan credentials supplied as a Cookie header must survive the browser's own jar
            headers["cookie"] = f"{base_cookie}; {headers['cookie']}" if headers.get("cookie") else base_cookie
        body = req.post_data_buffer
        carried: list[str] = []
        for _ in range(6):
            resp = await self.http.request(method, url, content=body, headers=headers, max_body=BROWSER_MAX_BODY)
            if resp is None:
                await route.abort("failed")
                return
            if rtype in ("document", "xhr", "fetch"):
                self.captured.append(Captured(method, url, rtype, body, req.headers.get("content-type", ""), resp))
            location = resp.headers.get("location")
            if resp.status not in REDIRECTS or not location:
                break
            nxt = urljoin(url, location)
            if not self.http.in_scope(nxt) or self._blocked(nxt):
                await route.abort("blockedbyclient")     # the scan never leaves the target origin
                return
            cookies = resp.headers.get_list("set-cookie")
            if rtype == "document" and req.is_navigation_request():
                # Interception does not see browser-followed redirects, so the hop is replayed as a
                # fresh navigation: address bar, base URL and cookie jar stay consistent.
                out = {"content-type": "text/html; charset=utf-8"}
                if cookies:
                    out["set-cookie"] = "\n".join(cookies)
                await route.fulfill(status=200, headers=out,
                                    body=f"<script>location.replace({json.dumps(nxt)})</script>")
                return
            carried += cookies
            pairs = [c.split(";", 1)[0].strip() for c in cookies]
            if pairs:
                headers["cookie"] = "; ".join(([headers["cookie"]] if headers.get("cookie") else []) + pairs)
            if resp.status in (301, 302, 303):
                method, body = "GET", None
                headers.pop("content-type", None)
            url = nxt
        else:
            await route.abort("failed")
            return
        if cacheable and resp.status == 200:
            self._static[url] = resp
        await self._fulfill(route, resp, carried)

    @staticmethod
    async def _fulfill(route, resp: Resp, carried_cookies: list[str]) -> None:
        headers = {k: v for k, v in resp.headers.items() if k.lower() not in DROPPED_RESPONSE_HEADERS}
        cookies = carried_cookies + resp.headers.get_list("set-cookie")
        if cookies:
            headers["set-cookie"] = "\n".join(cookies)
        await route.fulfill(status=resp.status, headers=headers, body=resp.content)

    # ------------------------------------------------------------------ rendering
    async def visit(self, url: str) -> Rendered | None:
        """Render *url* and return what the live DOM exposes. Raises ScanCanceled/BudgetExceeded."""
        if self._fatal:
            raise self._fatal
        if not self.http.in_scope(urldefrag(url)[0]) or self._blocked(url):
            return None
        async with self._slots:
            rendered = await self._render(url)
        if self._fatal:
            raise self._fatal
        return rendered

    async def _render(self, url: str) -> Rendered | None:
        page = await self._ctx.new_page()
        self._activity[page] = [0, time.monotonic()]
        page.on("dialog", lambda d: asyncio.ensure_future(self._dismiss(d)))
        rendered = None
        try:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            except Exception:
                pass                      # timeouts and aborted navigations still leave a DOM worth reading
            await self._settle(page)
            try:
                data = await page.evaluate(EXTRACT_JS)
            except Exception:
                data = None
            if data and str(data.get("url", "")).startswith(("http://", "https://")):
                self.pages_rendered += 1
                rendered = Rendered(url=data["url"], links=[str(x) for x in data.get("links", [])])
                for f in data.get("forms", []):
                    method = f.get("method") if f.get("method") in ("GET", "POST") else "GET"
                    rendered.forms.append(Form(
                        page_url=data["url"], action=urldefrag(str(f.get("action") or data["url"]))[0],
                        method=method,
                        inputs=[(i["name"], i["type"], i["value"]) for i in f.get("inputs", [])]))
        finally:
            self._activity.pop(page, None)
            try:
                await page.close()
            except Exception:
                pass
        return rendered

    @staticmethod
    async def _dismiss(dialog) -> None:
        try:
            await dialog.dismiss()
        except Exception:
            pass

    async def _settle(self, page) -> None:
        """Wait until the page stops making requests (bounded)."""
        tracker = self._activity[page]
        deadline = time.monotonic() + SETTLE_MAX_S
        await asyncio.sleep(0.1)
        while time.monotonic() < deadline and not self._fatal:
            if tracker[0] == 0 and time.monotonic() - tracker[1] >= SETTLE_QUIET_S:
                return
            await asyncio.sleep(0.05)

    async def proves(self, url: str, ident: int) -> bool:
        """Render *url* and report whether the proof function was called with *ident*."""
        await self.visit(url)
        return ident in self.proofs


def render_key(url: str) -> tuple:
    """Pages that differ only by parameter values are one page; client-side routes are distinct."""
    parts = urlsplit(url)
    from urllib.parse import parse_qsl
    names = tuple(sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)}))
    route = parts.fragment if parts.fragment.startswith(("/", "!/")) else ""
    return (parts.path or "/", names, route.split("?")[0])


async def browser_crawl(session: BrowserSession, crawler: Crawler, seeds: list[str], *, max_pages: int,
                        on_page=None) -> list[Rendered]:
    """Breadth-first rendering of the application, following links that only exist in the live DOM."""
    queue: list[str] = []
    seen: set[tuple] = set()

    def push(link: str) -> None:
        bare = urldefrag(link)[0]
        if not crawler.allowed(bare) or UNSAFE_LINK.search(link):
            return
        key = render_key(link)
        if key not in seen:
            seen.add(key)
            queue.append(link if key[2] else bare)

    for seed in seeds:
        push(seed)
    rendered: list[Rendered] = []
    while queue and len(rendered) < max_pages:
        batch = [queue.pop(0) for _ in range(min(4, len(queue), max_pages - len(rendered)))]
        results = await asyncio.gather(*(session.visit(u) for u in batch), return_exceptions=True)
        for page in results:
            if isinstance(page, (ScanCanceled, BudgetExceeded)):
                raise page
            if page is None or isinstance(page, Exception):
                continue
            rendered.append(page)
            if on_page:
                on_page(len(rendered))
            for link in page.links:
                push(link)
    return rendered


def proof_payloads(ident: int) -> dict[str, str]:
    call = f"__atlp({ident})"
    return {
        "html": f"\"'><img src=x onerror={call}>",
        "attr_dq": f"\" autofocus onfocus={call} x=\"",
        "attr_sq": f"' autofocus onfocus={call} x='",
        "js": f"'-{call}-'\"-{call}-\"",
    }
