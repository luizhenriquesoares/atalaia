"""Network guard: keeps the scanner from being used against internal infrastructure (SSRF)."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


class TargetNotAllowed(ValueError):
    pass


def normalize_base_url(url: str) -> str:
    """Validate and canonicalise a target base URL (scheme://host[:port])."""
    url = (url or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise TargetNotAllowed("A URL deve começar com http:// ou https://")
    if not parts.hostname:
        raise TargetNotAllowed("URL sem host")
    if parts.username or parts.password:
        raise TargetNotAllowed("A URL não pode conter credenciais")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetNotAllowed("Porta inválida") from exc
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    default = 443 if parts.scheme == "https" else 80
    netloc = host if port in (None, default) else f"{host}:{port}"
    return f"{parts.scheme}://{netloc}"


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def port_of(url: str) -> int:
    parts = urlsplit(url)
    return parts.port or (443 if parts.scheme == "https" else 80)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def resolve(host: str) -> list[str]:
    host = host.strip("[]")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"Não foi possível resolver o host {host}") from exc
    return sorted({info[4][0] for info in infos})


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def assert_allowed_host(host: str, *, allow_private: bool) -> list[str]:
    """Resolve *host* and refuse loopback, private, link-local and metadata addresses.

    Every resolved address must be public: a hostname that resolves to a mix of public and
    internal addresses is rejected.
    """
    ips = resolve(host)
    if not ips:
        raise TargetNotAllowed(f"Host {host} não resolve para nenhum endereço")
    if allow_private:
        return ips
    for ip in ips:
        if not _is_public(ip):
            raise TargetNotAllowed(
                f"O host {host} resolve para um endereço não público ({ip}); "
                "alvos internos não são permitidos nesta instalação"
            )
    return ips


def pick_ip(ips: list[str]) -> str:
    """Prefer IPv4 for the pinned connection address."""
    for ip in ips:
        if ":" not in ip:
            return ip
    return ips[0]


def pin_url(url: str, ip: str) -> tuple[str, str, str]:
    """Rewrite *url* to connect to *ip* directly.

    Returns (url_with_ip, host_header, sni_hostname). Connecting to the address that passed
    assert_allowed_host - instead of letting the HTTP client resolve the name again - closes
    the DNS-rebinding window between the check and the request.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    literal = f"[{ip}]" if ":" in ip else ip
    netloc = literal if parts.port is None else f"{literal}:{parts.port}"
    host_header = parts.netloc.rsplit("@", 1)[-1]
    return parts._replace(netloc=netloc).geturl(), host_header, host.strip("[]")
