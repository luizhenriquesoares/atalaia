"""Scoped, rate-limited HTTP client used by every scanner component."""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from ..netguard import host_of, is_ip_literal, pin_url, port_of

USER_AGENT = "Atalaia-Scanner/1.0 (authorized security assessment)"
MAX_BODY = 1_500_000


class OutOfScope(Exception):
    pass


class ScanCanceled(Exception):
    pass


class BudgetExceeded(Exception):
    pass


@dataclass
class Resp:
    url: str
    status: int
    headers: httpx.Headers
    content: bytes
    elapsed: float

    @property
    def text(self) -> str:
        if not hasattr(self, "_text"):
            self._text = self.content.decode("utf-8", errors="replace")
        return self._text

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in ("text/html", "application/xhtml+xml")


class RateLimiter:
    """Spaces requests evenly so that at most *rps* are sent per second."""

    def __init__(self, rps: float):
        self.interval = 1.0 / max(rps, 0.1)
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            await asyncio.sleep(delay)


class ScanHttp:
    def __init__(self, base_url: str, *, rps: float = 10, timeout: float = 10,
                 headers: dict[str, str] | None = None, max_requests: int = 5000,
                 cancel_event: threading.Event | None = None, concurrency: int = 6,
                 pinned_ip: str | None = None):
        self.base_url = base_url
        # When set, every connection goes to this pre-validated address (anti DNS rebinding).
        self.pinned_ip = pinned_ip
        self.host = host_of(base_url)
        self.port = port_of(base_url)
        self.scheme = urlsplit(base_url).scheme
        self.limiter = RateLimiter(rps)
        self.max_requests = max_requests
        self.requests_sent = 0
        self.paths_requested: set[str] = set()   # which URL paths this scan actually exercised
        self.canaries: dict = {}                 # XSS marker -> injection point that submitted it
        self.cancel_event = cancel_event
        self._sem = asyncio.Semaphore(concurrency)
        base_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        base_headers.update(headers or {})
        # Certificate problems are reported by the TLS check; the crawler must still be able
        # to assess sites with broken certificates, so verification is off for scan traffic.
        self.client = httpx.AsyncClient(
            headers=base_headers, timeout=timeout, verify=False, follow_redirects=False,
            limits=httpx.Limits(max_connections=concurrency + 2),
        )

        # Probes outside the exact origin (e.g. the plain-HTTP twin of an HTTPS target) must not
        # carry the customer's scan credentials.
        self.bare = httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, timeout=timeout, verify=False,
                                      follow_redirects=False)

    async def aclose(self) -> None:
        await self.client.aclose()
        await self.bare.aclose()

    def in_scope(self, url: str, *, any_port: bool = False) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or host_of(url) != self.host:
            return False
        if any_port:
            return True
        return port_of(url) == self.port and parts.scheme == self.scheme

    async def request(self, method: str, url: str, *, params=None, data=None, json=None,
                      content: bytes | None = None, headers: dict[str, str] | None = None,
                      any_port: bool = False, max_body: int = MAX_BODY) -> Resp | None:
        """Send one request. Returns None on network errors; raises on scope/budget/cancel."""
        if not self.in_scope(url, any_port=any_port):
            raise OutOfScope(url)
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ScanCanceled()
        if self.requests_sent >= self.max_requests:
            raise BudgetExceeded()
        self.requests_sent += 1
        self.paths_requested.add(urlsplit(url).path or "/")
        async with self._sem:
            await self.limiter.wait()
            started = time.monotonic()
            try:
                client = self.client if self.in_scope(url) else self.bare
                target_url, extensions = url, {}
                if self.pinned_ip and not is_ip_literal(self.host):
                    target_url, host_header, sni = pin_url(url, self.pinned_ip)
                    headers = {**(headers or {}), "Host": host_header}
                    extensions = {"sni_hostname": sni}
                async with client.stream(method, target_url, params=params, data=data, json=json,
                                         content=content, headers=headers, extensions=extensions) as r:
                    chunks, size = [], 0
                    async for chunk in r.aiter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= max_body:
                            break
                    final_url = str(r.url)
                    if target_url is not url:
                        final_url = str(httpx.URL(url).copy_merge_params(params)) if params else url
                    return Resp(final_url, r.status_code, r.headers, b"".join(chunks)[:max_body],
                                time.monotonic() - started)
            except (httpx.HTTPError, OSError, ValueError):
                return None

    async def get(self, url: str, **kw) -> Resp | None:
        return await self.request("GET", url, **kw)
