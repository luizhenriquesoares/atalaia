"""Breadth-first, same-origin crawler that discovers pages, forms and input points."""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from .http import Resp, ScanHttp

# Links that end sessions or change state must never be followed by an automated crawler.
UNSAFE_LINK = re.compile(r"(log|sign)[-_]?(out|off)|sair|logoff|delete|remove|excluir|apagar|destroy|unsubscribe",
                         re.I)
STATIC_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|mp4|mp3|avi|mov|pdf|zip|gz|tar|"
                        r"rar|7z|exe|dmg|iso|docx?|xlsx?|pptx?)$", re.I)


@dataclass
class Form:
    page_url: str
    action: str
    method: str
    inputs: list[tuple[str, str, str]]  # (name, type, value)

    def has_password(self) -> bool:
        return any(t == "password" for _, t, _ in self.inputs)


@dataclass
class Page:
    url: str
    resp: Resp
    depth: int
    forms: list[Form] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[tuple[str, bool]] = field(default_factory=list)  # (src, has_integrity)
    soup: BeautifulSoup | None = None


@dataclass(frozen=True)
class InjectionPoint:
    url: str          # URL without query string
    method: str       # GET | POST
    param: str
    params: tuple[tuple[str, str], ...]
    # For JSON APIs: the original request body (serialized); *params* then lists its scalar fields.
    json_body: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (urlsplit(self.url).path, self.method, self.param)

    @property
    def original(self) -> str:
        return dict(self.params).get(self.param, "")


def strip_query(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))


def _shape(url: str) -> tuple[str, tuple[str, ...]]:
    """Two URLs with the same path and parameter names are the same page for crawling purposes."""
    p = urlsplit(url)
    return (p.path or "/", tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})))


def parse_page(url: str, resp: Resp, depth: int) -> Page:
    page = Page(url=url, resp=resp, depth=depth)
    if not resp.is_html or not resp.content:
        return page
    soup = BeautifulSoup(resp.text, "html.parser")
    page.soup = soup
    base = url
    base_tag = soup.find("base", href=True)
    if base_tag:
        base = urljoin(url, base_tag["href"])
    for a in soup.find_all(["a", "area", "link", "iframe", "frame"]):
        href = a.get("href") or a.get("src")
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        page.links.append(urldefrag(urljoin(base, href.strip()))[0])
    for s in soup.find_all("script", src=True):
        page.scripts.append((urljoin(base, s["src"].strip()), bool(s.get("integrity"))))
    for f in soup.find_all("form"):
        action = urldefrag(urljoin(base, (f.get("action") or "").strip() or url))[0]
        method = (f.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        inputs = []
        for el in f.find_all(["input", "textarea", "select"]):
            name = el.get("name")
            if not name:
                continue
            itype = (el.get("type") or ("textarea" if el.name == "textarea" else "text")).lower()
            value = el.get("value") or ""
            if el.name == "select":
                opt = el.find("option", selected=True) or el.find("option")
                value = (opt.get("value") or opt.get_text(strip=True)) if opt else ""
            inputs.append((name, itype, value))
        page.forms.append(Form(page_url=url, action=action, method=method, inputs=inputs))
    return page


class Crawler:
    def __init__(self, http: ScanHttp, *, max_pages: int = 100, max_depth: int = 5,
                 excludes: list[str] | None = None, on_page=None):
        self.http = http
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.excludes = [e for e in (excludes or []) if e]   # plain substrings, not regexes
        self.on_page = on_page
        self.pages: list[Page] = []
        self._seen_shapes: set = set()

    def allowed(self, url: str) -> bool:
        if not self.http.in_scope(url):
            return False
        path = urlsplit(url).path
        if STATIC_EXT.search(path) or UNSAFE_LINK.search(url):
            return False
        return not any(e in url for e in self.excludes)

    async def _seeds(self) -> list[str]:
        seeds = [self.http.base_url + "/"]
        robots = await self.http.get(self.http.base_url + "/robots.txt")
        if robots and robots.status == 200 and "html" not in robots.content_type:
            for line in robots.text.splitlines()[:300]:
                m = re.match(r"\s*(?:allow|disallow|sitemap)\s*:\s*(\S+)", line, re.I)
                if m and "*" not in m.group(1):
                    seeds.append(urljoin(self.http.base_url + "/", m.group(1)))
        sitemap = await self.http.get(self.http.base_url + "/sitemap.xml")
        if sitemap and sitemap.status == 200:
            seeds.extend(re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap.text)[:200])
        return seeds

    async def crawl(self) -> list[Page]:
        queue: deque[tuple[str, int]] = deque()
        for seed in await self._seeds():
            self._enqueue(queue, seed, 0)
        while queue and len(self.pages) < self.max_pages:
            url, depth = queue.popleft()
            resp = await self.http.get(url)
            if resp is None:
                continue
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location")
                if loc:
                    self._enqueue(queue, urldefrag(urljoin(url, loc))[0], depth)
                page = Page(url=url, resp=resp, depth=depth)
            else:
                page = parse_page(url, resp, depth)
            self.pages.append(page)
            if self.on_page:
                self.on_page(len(self.pages))
            if depth < self.max_depth:
                for link in page.links:
                    self._enqueue(queue, link, depth + 1)
                for form in page.forms:
                    if form.method == "GET" and not form.has_password():
                        self._enqueue(queue, self._form_url(form), depth + 1)
        return self.pages

    @staticmethod
    def _form_url(form: Form) -> str:
        from urllib.parse import urlencode
        params = [(n, v or default_value(n, t)) for n, t, v in form.inputs if t not in ("submit", "button", "file")]
        return strip_query(form.action) + ("?" + urlencode(params) if params else "")

    def _enqueue(self, queue, url: str, depth: int) -> None:
        if not self.allowed(url):
            return
        shape = _shape(url)
        if shape in self._seen_shapes:
            return
        self._seen_shapes.add(shape)
        queue.append((url, depth))


def default_value(name: str, itype: str) -> str:
    n = name.lower()
    if itype == "email" or "mail" in n:
        return "scanner@example.com"
    if itype in ("number", "range") or n in ("id", "page", "qty", "quantity", "limit", "offset"):
        return "1"
    if itype == "url":
        return "https://example.com/"
    return "atalaia"


DESTRUCTIVE_FORM = re.compile(
    r"delete|remove|excluir|apagar|destroy|cancel|logout|sair|password|senha|payment|pagamento|checkout|"
    r"transfer|purchase|comprar|upload|register|signup|cadastro|unsubscribe|reset", re.I)


def injection_points(pages: list[Page], *, include_post: bool, limit: int = 200,
                     excludes: list[str] | None = None) -> list[InjectionPoint]:
    """Collect the distinct (path, method, parameter) inputs worth probing.

    POST forms are only included when *include_post* is set, and forms that look like they
    change important state (deletes, payments, password changes, uploads) are always skipped.
    """
    points: dict[tuple[str, str, str], InjectionPoint] = {}

    def add(url: str, method: str, params: list[tuple[str, str]]):
        params_t = tuple(params)
        for name, _ in params:
            ip = InjectionPoint(strip_query(url), method, name, params_t)
            points.setdefault(ip.key, ip)

    for page in pages:
        for link in [page.url, *page.links]:
            q = parse_qsl(urlsplit(link).query, keep_blank_values=True)
            if q and not UNSAFE_LINK.search(link):
                add(link, "GET", q)
        for form in page.forms:
            if form.method == "POST" and not include_post:
                continue
            blob = form.action + " " + " ".join(n for n, _, _ in form.inputs)
            if form.method == "POST" and (DESTRUCTIVE_FORM.search(blob) or form.has_password()):
                continue
            if UNSAFE_LINK.search(form.action):
                continue
            fields = [(n, t, v or default_value(n, t)) for n, t, v in form.inputs if t != "file"]
            params_t = tuple((n, v) for n, _, v in fields)
            base = strip_query(form.action)
            for name, itype, _ in fields:
                if itype in ("submit", "button", "hidden", "checkbox", "radio", "password"):
                    continue
                ip = InjectionPoint(base, form.method, name, params_t)
                points.setdefault(ip.key, ip)
    kept = [ip for ip in points.values() if not any(e in ip.url for e in (excludes or []) if e)]
    return kept[:limit]


def api_injection_points(calls, *, include_post: bool, excludes: list[str] | None = None,
                         limit: int = 100) -> list[InjectionPoint]:
    """Inputs of the API calls a page made by itself while rendered in the browser.

    *calls* is an iterable of (method, url, body bytes | None, request content type).
    """
    import json as _json
    points: dict[tuple[str, str, str], InjectionPoint] = {}
    for method, url, body, ctype in calls:
        if UNSAFE_LINK.search(url) or any(e in url for e in (excludes or []) if e):
            continue
        base = strip_query(url)
        if method == "GET":
            q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            for name, _ in q:
                ip = InjectionPoint(base, "GET", name, tuple(q))
                points.setdefault(ip.key, ip)
            continue
        if method != "POST" or not include_post or not body or len(body) > 20_000:
            continue
        text = body.decode("utf-8", "replace")
        if "json" in ctype:
            try:
                data = _json.loads(text)
            except ValueError:
                continue
            if not isinstance(data, dict) or ("query" in data and "graphql" in url.lower()):
                continue
            scalars = [(k, "" if v is None else str(v)) for k, v in data.items()
                       if isinstance(k, str) and isinstance(v, (str, int, float)) and not isinstance(v, bool)]
            if DESTRUCTIVE_FORM.search(url + " " + " ".join(k for k, _ in scalars)):
                continue
            for name, _ in scalars:
                ip = InjectionPoint(base, "POST", name, tuple(scalars), json_body=_json.dumps(data))
                points.setdefault(ip.key, ip)
        elif "x-www-form-urlencoded" in ctype:
            fields = parse_qsl(text, keep_blank_values=True)
            if DESTRUCTIVE_FORM.search(url + " " + " ".join(k for k, _ in fields)):
                continue
            for name, _ in fields:
                ip = InjectionPoint(base, "POST", name, tuple(fields))
                points.setdefault(ip.key, ip)
    return list(points.values())[:limit]
