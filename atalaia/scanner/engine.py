"""Scan orchestration: crawl, run passive checks, run active probes, de-duplicate."""
from __future__ import annotations

import asyncio
import hashlib
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from . import active, knowledge, passive
from .browser import (BrowserSession, BrowserUnavailable, ThirdPartyFetcher, browser_crawl, proof_payloads,
                      render_key)
from .crawler import Crawler, Page, _shape, api_injection_points, injection_points, parse_page
from .http import BudgetExceeded, Resp, ScanCanceled, ScanHttp
from .passive import FindingData

PROFILES = {
    # passive: only observes responses of a normal crawl; no probe payloads at all.
    "passive": {"host_probes": False, "input_probes": False, "post_forms": False},
    # standard: host probes + injection probes on GET inputs.
    "standard": {"host_probes": True, "input_probes": True, "post_forms": False},
    # full: also probes POST forms that do not look state-changing.
    "full": {"host_probes": True, "input_probes": True, "post_forms": True},
}


@dataclass
class ScanConfig:
    base_url: str
    profile: str = "standard"
    max_pages: int = 100
    max_depth: int = 5
    rps: float = 10
    timeout: float = 10
    max_requests: int = 5000
    headers: dict[str, str] = field(default_factory=dict)
    excludes: list[str] = field(default_factory=list)
    pinned_ip: str | None = None
    # Headless browser: renders JavaScript, discovers API calls and proves XSS by execution.
    browser: bool = False
    browser_max_pages: int = 25
    browser_third_party: bool = True
    browser_allow_private_third_party: bool = False
    browser_sandbox: bool = False


@dataclass
class ScanFinding:
    fingerprint: str
    check_id: str
    title: str
    severity: str
    confidence: str
    cwe: int | None
    owasp: str
    cvss: float
    url: str
    method: str
    parameter: str
    evidence: str
    description: str
    remediation: str
    references: list[str]


@dataclass
class ScanResult:
    findings: list[ScanFinding]
    pages_crawled: int
    requests_sent: int
    canceled: bool = False
    budget_exhausted: bool = False
    notes: list[str] = field(default_factory=list)
    # URL paths this scan actually requested: a finding is only considered re-tested (and thus
    # eligible to be closed as fixed) when its path is in this set.
    paths_requested: set[str] = field(default_factory=set)
    browser_used: bool = False
    pages_rendered: int = 0


def materialize(fd: FindingData, base_url: str) -> ScanFinding:
    vuln = knowledge.get(fd.check_id)
    path = "" if fd.host_level else urlsplit(fd.url).path
    raw = "|".join([urlsplit(base_url).netloc, fd.check_id, path, fd.method if not fd.host_level else "",
                    fd.parameter, fd.key])
    severity = fd.severity or vuln.severity
    cvss = vuln.cvss
    if fd.severity and fd.severity != vuln.severity:
        cvss = min(cvss, {"critical": 10.0, "high": 8.9, "medium": 6.9, "low": 3.9, "info": 0.0}[fd.severity])
    return ScanFinding(
        fingerprint=hashlib.sha256(raw.encode()).hexdigest()[:32],
        check_id=fd.check_id, title=vuln.title + fd.title_suffix, severity=severity,
        confidence=fd.confidence, cwe=vuln.cwe, owasp=vuln.owasp, cvss=cvss, url=fd.url,
        method=fd.method, parameter=fd.parameter, evidence=fd.evidence[:2000],
        description=vuln.description, remediation=vuln.remediation, references=list(vuln.references),
    )


async def run_scan(config: ScanConfig, *, cancel_event: threading.Event | None = None,
                   progress=None) -> ScanResult:
    """Run a scan against config.base_url. The caller is responsible for authorization
    (ownership verification) and for the network guard; see atalaia.scans."""
    profile = PROFILES[config.profile]
    http = ScanHttp(config.base_url, rps=config.rps, timeout=config.timeout, headers=config.headers,
                    max_requests=config.max_requests, cancel_event=cancel_event,
                    pinned_ip=config.pinned_ip)
    raw: list[FindingData] = []
    notes: list[str] = []
    canceled = exhausted = False
    pages: list[Page] = []
    session: BrowserSession | None = None
    rendered = []

    def report(stage: str, pct: int):
        if progress:
            progress(stage, pct, http.requests_sent, len(pages))

    try:
        # ---------------------------------------------------------------- 1. HTTP crawl
        report("crawling", 2)
        crawler = Crawler(http, max_pages=config.max_pages, max_depth=config.max_depth,
                          excludes=config.excludes,
                          on_page=lambda n: progress and progress(
                              "crawling", min(30, 2 + int(28 * n / config.max_pages)), http.requests_sent, n))
        try:
            await crawler.crawl()
        except BudgetExceeded:
            exhausted = True
        finally:
            pages = crawler.pages
        if not pages:
            notes.append("Não foi possível obter nenhuma página do alvo.")

        # ---------------------------------------------------------------- 2. browser rendering
        api_calls: list[tuple[str, str, bytes | None, str]] = []
        rendered_pages: list[Page] = []
        if config.browser and pages and not exhausted:
            report("browser", 31)
            third_party = ThirdPartyFetcher(allow_private=config.browser_allow_private_third_party) \
                if config.browser_third_party else None
            candidate = BrowserSession(http, third_party=third_party, excludes=config.excludes,
                                       sandbox=config.browser_sandbox)
            try:
                await candidate.start()
                session = candidate
            except BrowserUnavailable as exc:
                notes.append(f"Navegador indisponível ({exc}); a varredura seguiu sem renderizar JavaScript.")
        if session:
            seeds = [http.base_url + "/"] + [p.url for p in pages if p.resp.is_html and p.resp.status == 200]
            try:
                rendered = await browser_crawl(
                    session, crawler, seeds, max_pages=config.browser_max_pages,
                    on_page=lambda n: report("browser", min(41, 31 + int(10 * n / config.browser_max_pages))))
            except BudgetExceeded:
                exhausted = True
            known = {("GET", _shape(p.url)) for p in pages}
            for cap in session.captured:
                if cap.resp.status in (301, 302, 303, 307, 308):
                    continue
                if cap.resource_type in ("xhr", "fetch"):
                    api_calls.append((cap.method, cap.url, cap.body, cap.content_type))
                key = (cap.method, _shape(cap.url))
                if key not in known and len(pages) < config.max_pages * 2:
                    known.add(key)
                    pages.append(parse_page(cap.url, cap.resp, 0))     # also runs passive checks on API responses
            stub = Resp("", 200, httpx.Headers(), b"", 0.0)
            rendered_pages = [Page(url=r.url, resp=stub, depth=0, links=r.links, forms=r.forms) for r in rendered]

        # ---------------------------------------------------------------- 3. passive analysis
        report("passive", 42)
        main = next((p for p in pages if p.resp.is_html and p.resp.status == 200), pages[0] if pages else None)
        if main:
            raw.extend(passive.check_security_headers(main.resp))
        for page in pages:
            raw.extend(passive.check_cookies(page.resp))
            raw.extend(passive.check_jwt(page.resp))
            raw.extend(passive.check_page(page))

        if exhausted:
            raise BudgetExceeded()

        # ---------------------------------------------------------------- 4. host probes
        if profile["host_probes"]:
            report("host-probes", 50)
            for probe in active.HOST_PROBES:
                raw.extend(await probe(http))

        # ---------------------------------------------------------------- 5. input probes
        if profile["input_probes"]:
            merged = {}
            for ip in (injection_points(pages + rendered_pages, include_post=profile["post_forms"],
                                        excludes=config.excludes)
                       + api_injection_points(api_calls, include_post=profile["post_forms"],
                                              excludes=config.excludes)):
                merged.setdefault(ip.key, ip)
            points = list(merged.values())[:250]
            total = max(len(points), 1)
            done = 0
            html_points = []
            xss_found: dict[tuple, FindingData] = {}

            async def test_point(ip):
                nonlocal done
                baseline = await active.send(http, ip, ip.original)
                if baseline is not None:
                    if baseline.is_html and ip.method == "GET" and ip.json_body is None:
                        html_points.append(ip)
                    for probe in active.INPUT_PROBES:
                        found = await probe(http, ip, baseline)
                        if probe is active.probe_xss and found:
                            xss_found[ip.key] = found[0]
                        raw.extend(found)
                done += 1
                report("input-probes", 55 + int(30 * done / total))

            results = await asyncio.gather(*(test_point(ip) for ip in points), return_exceptions=True)
            for r in results:
                if isinstance(r, (ScanCanceled, BudgetExceeded)):
                    raise r
                if isinstance(r, Exception):
                    notes.append(f"Erro em verificação: {type(r).__name__}: {r}")

            report("stored-xss", 86)
            html_urls = list(dict.fromkeys(p.url for p in pages if p.resp.is_html and p.resp.status == 200))
            raw.extend(await active.probe_stored_xss(http, html_urls))

            if session:
                report("browser-proof", 90)
                raw.extend(await _prove_xss(session, html_points[:40], xss_found, rendered))
    except ScanCanceled:
        canceled = True
    except BudgetExceeded:
        exhausted = True
        notes.append(f"Orçamento de {config.max_requests} requisições atingido; varredura parcial.")
    finally:
        if session:
            await session.close()
        await http.aclose()

    findings: dict[str, ScanFinding] = {}
    for fd in raw:
        f = materialize(fd, config.base_url)
        findings.setdefault(f.fingerprint, f)
    ordered = sorted(findings.values(), key=lambda f: (knowledge.SEVERITY_ORDER[f.severity], f.title, f.url))
    return ScanResult(ordered, len(pages), http.requests_sent, canceled, exhausted, notes,
                      paths_requested=set(http.paths_requested), browser_used=session is not None,
                      pages_rendered=session.pages_rendered if session else 0)


def _with_param(ip, value: str) -> str:
    from urllib.parse import urlencode
    return ip.url + "?" + urlencode([(k, value if k == ip.param else v) for k, v in ip.params])


async def _prove_xss(session: BrowserSession, html_points, xss_found: dict, rendered) -> list[FindingData]:
    """Proof-based XSS: load the page in a real browser with a payload that calls a function only
    the scanner defines. If the function runs, the vulnerability is confirmed, not inferred."""
    out: list[FindingData] = []

    async def prove_point(ip) -> None:
        existing = xss_found.get(ip.key)
        ident = session.new_proof_id()
        payloads = proof_payloads(ident)
        if existing is None:
            order = ["html"]                               # hunting for DOM sinks: one navigation
        elif "atributo" in existing.title_suffix:
            order = ["attr_dq", "attr_sq", "html"]
        else:
            order = ["html", "js"]
        for name in order:
            if await session.proves(_with_param(ip, payloads[name]), ident):
                proof = (f" Execução comprovada em navegador real com {ip.param}={payloads[name]} "
                         "(a função de prova do scanner foi chamada pela página).")
                if existing is not None:
                    existing.confidence = "confirmed"
                    existing.evidence += proof
                else:
                    out.append(FindingData("xss-dom", ip.url, "GET", ip.param, confidence="confirmed",
                                           evidence="O servidor não reflete o valor, mas o JavaScript da "
                                                    "página o insere no DOM." + proof))
                return

    async def prove_fragment(bare: str) -> None:
        ident = session.new_proof_id()
        payload = proof_payloads(ident)["html"]
        if await session.proves(f"{bare}#{payload}", ident):
            out.append(FindingData("xss-dom", bare.split("?", 1)[0], "GET", "(fragmento da URL)", key="fragment",
                                   confidence="confirmed",
                                   evidence=f"Ao abrir {bare}#{payload} em um navegador real, a página leu "
                                            "location.hash e executou o conteúdo (a função de prova do "
                                            "scanner foi chamada)."))

    fragments: dict[str, str] = {}
    for page in rendered:
        bare = page.url.split("#", 1)[0]
        fragments.setdefault(render_key(bare)[0], bare)
    jobs = [prove_point(ip) for ip in html_points] + [prove_fragment(b) for b in list(fragments.values())[:15]]
    for result in await asyncio.gather(*jobs, return_exceptions=True):
        if isinstance(result, (ScanCanceled, BudgetExceeded)):
            raise result
    return out
