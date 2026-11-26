"""Target ownership verification. No active scan runs against an unverified target.

Three methods, all proving control over the host being scanned:
  * dns_txt   - TXT record at _atalaia-challenge.<host> (or on the host itself)
  * http_file - file at <base_url>/.well-known/atalaia-verification.txt
  * meta_tag  - <meta name="atalaia-verification" content="..."> on the home page
"""
from __future__ import annotations

import secrets

import httpx
from bs4 import BeautifulSoup

from .netguard import TargetNotAllowed, assert_allowed_host, host_of, is_ip_literal, pick_ip, pin_url
from .scanner.http import USER_AGENT

METHODS = ("dns_txt", "http_file", "meta_tag")
TOKEN_PREFIX = "atalaia-verify-"
WELL_KNOWN_PATH = "/.well-known/atalaia-verification.txt"
DNS_LABEL = "_atalaia-challenge"


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_hex(20)


def instructions(base_url: str, token: str) -> dict:
    host = host_of(base_url)
    return {
        "dns_txt": {"record": f"{DNS_LABEL}.{host}", "type": "TXT", "value": token},
        "http_file": {"url": base_url + WELL_KNOWN_PATH, "content": token},
        "meta_tag": {"url": base_url + "/", "html": f'<meta name="atalaia-verification" content="{token}">'},
    }


def _dns_txt(host: str) -> list[str]:
    import dns.exception
    import dns.resolver
    values: list[str] = []
    for name in (f"{DNS_LABEL}.{host}", host):
        try:
            for rdata in dns.resolver.resolve(name, "TXT", lifetime=8):
                values.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        except (dns.exception.DNSException, OSError):
            continue
    return values


class _Fetched:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


def _fetch(url: str, host: str, allow_private: bool) -> _Fetched | None:
    # Redirects are not followed: the proof must be served by the verified host itself.
    ip = pick_ip(assert_allowed_host(host, allow_private=allow_private))
    headers, extensions = {"User-Agent": USER_AGENT}, {}
    if not is_ip_literal(host):
        url, headers["Host"], sni = pin_url(url, ip)   # connect to the address that was just validated
        extensions = {"sni_hostname": sni}
    try:
        # Certificate validation is off because the connection is made by IP; the token itself is
        # the proof, and it is a per-target random secret.
        with httpx.Client(timeout=10, follow_redirects=False, verify=False) as client:
            with client.stream("GET", url, headers=headers, extensions=extensions) as resp:
                body = b""
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > 1_000_000:
                        break
                return _Fetched(resp.status_code, body.decode("utf-8", "replace"))
    except (httpx.HTTPError, OSError):
        return None


def verify(base_url: str, token: str, method: str, *, allow_private: bool, dns_lookup=_dns_txt) -> tuple[bool, str]:
    """Returns (verified, human-readable detail)."""
    host = host_of(base_url)
    if method not in METHODS:
        return False, "Método de verificação desconhecido"
    try:
        if method == "dns_txt":
            if is_ip_literal(host):
                return False, "Verificação por DNS não se aplica a endereços IP"
            values = dns_lookup(host)
            if any(v.strip() == token for v in values):
                return True, "Registro TXT encontrado"
            return False, f"Registro TXT com o token não encontrado em {DNS_LABEL}.{host}"
        if method == "http_file":
            resp = _fetch(base_url + WELL_KNOWN_PATH, host, allow_private)
            if resp is None:
                return False, "Não foi possível acessar o arquivo de verificação"
            if resp.status_code == 200 and resp.text.strip() == token:
                return True, "Arquivo de verificação encontrado"
            return False, f"Arquivo ausente ou com conteúdo diferente (HTTP {resp.status_code})"
        resp = _fetch(base_url + "/", host, allow_private)
        if resp is None:
            return False, "Não foi possível acessar a página inicial"
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            head = soup.find("head")
            for meta in (head.find_all("meta") if head else []):
                if (meta.get("name") or "").lower() == "atalaia-verification" and \
                        (meta.get("content") or "").strip() == token:
                    return True, "Meta tag encontrada"
        return False, "Meta tag com o token não encontrada no <head> da página inicial"
    except TargetNotAllowed as exc:
        return False, str(exc)
