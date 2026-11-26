"""Active checks: send extra, non-destructive probe requests to detect vulnerabilities.

Design rules for every probe in this module:
  * detection only: payloads are inert markers, arithmetic or read-only conditions;
  * never stacked queries, writes, command execution, time-delay/DoS or data extraction;
  * every request goes through ScanHttp, which enforces scope, rate limit and budget.
"""
from __future__ import annotations

import asyncio
import base64
import difflib
import json
import re
import secrets
import socket
import ssl
import time
import warnings
from urllib.parse import urlsplit

from .crawler import InjectionPoint
from .http import Resp, ScanHttp
from .passive import SQL_ERRORS, FindingData, around, clip

CANARY_HOST = "atalaia-canary.example"   # reserved TLD: never resolves, never contacted


# =========================================================================== host probes
def _looks_env(body: str) -> bool:
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    hits = sum(1 for ln in lines if re.match(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=", ln))
    return hits >= 2 and hits >= len(lines) * 0.6


SENSITIVE_PATHS: list[tuple[str, str, callable, str]] = [
    ("/.git/HEAD", "exposed-git", lambda b: bool(re.match(r"^(ref: refs/|[0-9a-f]{40}\s*$)", b)), ""),
    ("/.git/config", "exposed-git", lambda b: "[core]" in b and "repositoryformatversion" in b, ""),
    ("/.svn/entries", "exposed-git", lambda b: bool(re.match(r"^\d+\s*\n", b)) and "dir" in b[:200],
     " (Subversion)"),
    ("/.env", "exposed-env", _looks_env, ""),
    ("/.env.local", "exposed-env", _looks_env, ""),
    ("/.env.production", "exposed-env", _looks_env, ""),
    ("/.env.backup", "exposed-env", _looks_env, ""),
    ("/backup.sql", "exposed-backup", lambda b: bool(re.search(r"CREATE TABLE|INSERT INTO", b)), ""),
    ("/dump.sql", "exposed-backup", lambda b: bool(re.search(r"CREATE TABLE|INSERT INTO", b)), ""),
    ("/database.sql", "exposed-backup", lambda b: bool(re.search(r"CREATE TABLE|INSERT INTO", b)), ""),
    ("/db.sql", "exposed-backup", lambda b: bool(re.search(r"CREATE TABLE|INSERT INTO", b)), ""),
    ("/wp-config.php.bak", "exposed-backup", lambda b: "DB_PASSWORD" in b, ""),
    ("/wp-config.php~", "exposed-backup", lambda b: "DB_PASSWORD" in b, ""),
    ("/config.php.bak", "exposed-backup", lambda b: "<?php" in b, ""),
    ("/web.config.bak", "exposed-backup", lambda b: "<configuration" in b, ""),
    ("/.htpasswd", "exposed-backup",
     lambda b: bool(re.match(r"^[\w.@-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}\s*$)", b)), " (.htpasswd)"),
    ("/id_rsa", "exposed-private-key", lambda b: "PRIVATE KEY-----" in b, ""),
    ("/.ssh/id_rsa", "exposed-private-key", lambda b: "PRIVATE KEY-----" in b, ""),
    ("/server.key", "exposed-private-key", lambda b: "PRIVATE KEY-----" in b, ""),
    ("/phpinfo.php", "exposed-debug", lambda b: "phpinfo()" in b and "PHP Version" in b, " (phpinfo)"),
    ("/info.php", "exposed-debug", lambda b: "phpinfo()" in b and "PHP Version" in b, " (phpinfo)"),
    ("/server-status", "exposed-debug", lambda b: "Apache Server Status" in b, " (Apache server-status)"),
    ("/actuator/env", "exposed-debug", lambda b: '"propertySources"' in b, " (Spring Actuator)"),
    ("/actuator", "exposed-debug", lambda b: '"_links"' in b and "actuator" in b, " (Spring Actuator)"),
    ("/debug/pprof/", "exposed-debug", lambda b: "Types of profiles available" in b, " (Go pprof)"),
    ("/elmah.axd", "exposed-debug", lambda b: "Error Log for" in b, " (ELMAH)"),
    ("/_profiler/phpinfo", "exposed-debug", lambda b: "PHP Version" in b, " (Symfony profiler)"),
    ("/telescope/requests", "exposed-debug", lambda b: "Laravel Telescope" in b, " (Laravel Telescope)"),
    ("/swagger.json", "exposed-api-docs", lambda b: '"swagger"' in b or '"openapi"' in b, ""),
    ("/openapi.json", "exposed-api-docs", lambda b: '"openapi"' in b, ""),
    ("/v2/api-docs", "exposed-api-docs", lambda b: '"swagger"' in b, ""),
    ("/v3/api-docs", "exposed-api-docs", lambda b: '"openapi"' in b, ""),
]


async def probe_sensitive_files(http: ScanHttp) -> list[FindingData]:
    out: list[FindingData] = []
    base = http.base_url
    soft = await http.get(f"{base}/atl-{secrets.token_hex(6)}")
    soft_body = soft.text if soft and soft.status == 200 else ""
    seen: set[str] = set()
    for path, check_id, validator, suffix in SENSITIVE_PATHS:
        resp = await http.get(base + path)
        if not resp or resp.status != 200 or not resp.content:
            continue
        body = resp.text
        try:
            ok = validator(body) and not (soft_body and validator(soft_body))
        except Exception:
            ok = False
        if not ok or (check_id, suffix) in seen and check_id != "exposed-backup":
            continue
        seen.add((check_id, suffix))
        out.append(FindingData(check_id, base + path, key=path, title_suffix=suffix,
                               evidence=f"GET {path} → 200 ({len(resp.content)} bytes). "
                                        f"Início do conteúdo: {clip(_redact(body), 120)}"))
    sec = await http.get(base + "/.well-known/security.txt")
    if not (sec and sec.status == 200 and re.search(r"^contact:", sec.text, re.I | re.M)):
        alt = await http.get(base + "/security.txt")
        if not (alt and alt.status == 200 and re.search(r"^contact:", alt.text, re.I | re.M)):
            out.append(FindingData("security-txt-missing", base + "/.well-known/security.txt", host_level=True,
                                   evidence="Nenhum security.txt válido encontrado."))
    return out


def _redact(body: str) -> str:
    """Never store secret values found in exposed files: keep names, mask values."""
    body = re.sub(r"(?m)^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*).+$", r"\1***", body)
    body = re.sub(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*", r"\1 ***", body, flags=re.S)
    body = re.sub(r"(?m)^([\w.@-]+:)\S+$", r"\1***", body)
    return body


async def probe_cors(http: ScanHttp) -> list[FindingData]:
    url = http.base_url + "/"
    origin = f"https://{CANARY_HOST}"
    resp = await http.get(url, headers={"Origin": origin})
    out = []
    if resp:
        acao = resp.headers.get("access-control-allow-origin", "")
        creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
        if acao == origin:
            ev = f"Origin: {origin} → Access-Control-Allow-Origin: {acao}"
            if creds:
                out.append(FindingData("cors-reflect-credentials", url, host_level=True,
                                       evidence=ev + "; Access-Control-Allow-Credentials: true"))
            else:
                out.append(FindingData("cors-reflect", url, host_level=True, evidence=ev))
    if not out:
        resp = await http.get(url, headers={"Origin": "null"})
        if resp and resp.headers.get("access-control-allow-origin") == "null" and \
                resp.headers.get("access-control-allow-credentials", "").lower() == "true":
            out.append(FindingData("cors-null-origin", url, host_level=True,
                                   evidence="Origin: null → Access-Control-Allow-Origin: null; "
                                            "Access-Control-Allow-Credentials: true"))
    return out


async def probe_trace(http: ScanHttp) -> list[FindingData]:
    marker = "atl" + secrets.token_hex(4)
    resp = await http.request("TRACE", http.base_url + "/", headers={"X-Atalaia-Probe": marker})
    if resp and resp.status == 200 and marker in resp.text:
        return [FindingData("trace-enabled", http.base_url + "/", method="TRACE", host_level=True,
                            evidence="TRACE / → 200 com o cabeçalho de teste ecoado no corpo.")]
    return []


async def probe_graphql(http: ScanHttp) -> list[FindingData]:
    query = {"query": "{__schema{queryType{name}}}"}
    for path in ("/graphql", "/api/graphql"):
        resp = await http.request("POST", http.base_url + path, json=query)
        if not resp or resp.status != 200:
            continue
        try:
            data = json.loads(resp.text)
        except ValueError:
            continue
        if isinstance(data, dict) and isinstance(data.get("data"), dict) and data["data"].get("__schema"):
            return [FindingData("graphql-introspection", http.base_url + path, method="POST",
                                evidence="Consulta {__schema{queryType{name}}} respondida com o esquema.")]
    return []


def _tls_probe(host: str, port: int, connect_to: str | None = None) -> dict:
    result: dict = {}
    host = host.strip("[]")
    address = connect_to or host
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((address, port), timeout=8) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            result["version"] = tls.version()
            if cert and cert.get("notAfter"):
                result["days_left"] = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
                result["not_after"] = cert["notAfter"]
    except ssl.SSLCertVerificationError as exc:
        result["verify_error"] = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        result["error"] = str(exc)
        return result
    try:
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.check_hostname = False
        legacy.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)   # probing obsolete versions on purpose
            legacy.minimum_version = ssl.TLSVersion.TLSv1
            legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        legacy.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((address, port), timeout=8) as sock, \
                legacy.wrap_socket(sock, server_hostname=host) as tls:
            result["legacy"] = tls.version()
    except Exception:
        pass
    return result


async def probe_transport(http: ScanHttp) -> list[FindingData]:
    base = http.base_url
    if http.scheme == "http":
        return [FindingData("no-https", base + "/", host_level=True,
                            evidence=f"O alvo cadastrado usa HTTP sem criptografia: {base}")]
    out = []
    info = await asyncio.to_thread(_tls_probe, http.host, http.port, http.pinned_ip)
    if "verify_error" in info:
        expired = "expired" in info["verify_error"].lower()
        out.append(FindingData("tls-cert-expired" if expired else "tls-cert-invalid", base + "/",
                               host_level=True, evidence=f"Falha na validação: {info['verify_error']}"))
    elif "days_left" in info:
        if info["days_left"] < 0:
            out.append(FindingData("tls-cert-expired", base + "/", host_level=True,
                                   evidence=f"Válido até {info['not_after']}"))
        elif info["days_left"] < 30:
            out.append(FindingData("tls-cert-expiring", base + "/", host_level=True,
                                   evidence=f"Válido até {info['not_after']} "
                                            f"({int(info['days_left'])} dias restantes)"))
    if info.get("legacy"):
        out.append(FindingData("tls-legacy-protocol", base + "/", host_level=True,
                               evidence=f"Handshake concluído com {info['legacy']}"))
    if http.port == 443:
        plain = await http.get(f"http://{http.host}/", any_port=True)
        if plain is not None:
            loc = plain.headers.get("location", "")
            if not (plain.status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://")):
                out.append(FindingData("no-https-redirect", f"http://{http.host}/", host_level=True,
                                       evidence=f"GET http://{http.host}/ → {plain.status} "
                                                f"(Location: {loc or 'ausente'})"))
    return out


async def probe_host_header(http: ScanHttp) -> list[FindingData]:
    """Only the forwarding headers are altered. The real Host header is never changed, so the
    request cannot be routed to another site sharing the same address."""
    url = http.base_url + "/"
    resp = await http.get(url, headers={"X-Forwarded-Host": CANARY_HOST})
    if not resp:
        return []
    location = resp.headers.get("location", "")
    pos = resp.text.find(CANARY_HOST) if resp.content else -1
    if CANARY_HOST in location:
        evidence = f"X-Forwarded-Host: {CANARY_HOST} → Location: {location}"
    elif pos >= 0:
        evidence = (f"X-Forwarded-Host: {CANARY_HOST} → o host aparece no corpo da resposta: "
                    f"{around(resp.text, pos, pos + len(CANARY_HOST), 60)}")
    else:
        return []
    return [FindingData("host-header-injection", url, host_level=True, confidence="medium", evidence=evidence)]




# ===========================================================================
# Windows file-read API (CWE-22) — trailing-dot blocklist bypass
# ===========================================================================

# Regex matching IIS/ASP.NET server headers; presence gates all probes below.
_IIS_SERVER_RE = re.compile(r"IIS|Microsoft-HTTPAPI|ASP\.NET", re.I)

# (api_path, method_query_param, json_body_key)
# method_query_param: appended as ?metodosApis=<value>; empty string if not used.
_WIN_READ_CANDIDATES: list[tuple[str, str, str]] = [
    # Generic IIS/.NET file-read patterns
    ("/api/file/read",                           "", "path"),
    ("/api/files/read",                          "", "path"),
    ("/api/file/content",                        "", "path"),
    ("/FileService/read",                        "", "filePath"),
    ("/api/ServidorArquivo/ObterBytesPorCaminho", "", "caminho"),
    ("/api/documento/obter",                     "", "caminho"),
    # Proxy pass-through pattern: method selector in query, path in JSON body
    ("/api/Proxy/RequestHandler",                "ServidorArquivo_ObterBytesPorCaminhoPost", "caminho"),
    ("/DetranProxy/api/Proxy/RequestHandler",    "ServidorArquivo_ObterBytesPorCaminhoPost", "caminho"),
]

# win.ini always exists on every Windows version — read it first to confirm the capability.
_WIN_SANITY_PATH = r"C:\Windows\win.ini"
_WIN_SANITY_SIG = re.compile(r"\[(?:fonts|extensions|files|mail|mci extensions)\]", re.I)

# Config files to test with trailing-dot bypass.
# The bypass works because Win32 CreateFile() strips trailing dots; a blocklist
# matching 'web.config' does not match 'web.config.' and allows the request through.
_WIN_CRED_CANDIDATES: list[str] = [
    r"C:\inetpub\wwwroot\web.config.",
    r"C:\inetpub\wwwroot\Web.config.",
    r"C:\inetpub\wwwroot\appsettings.json.",
    r"C:\inetpub\wwwroot\appsettings.Production.json.",
    r"C:\inetpub\wwwroot\appsettings.Development.json.",
    r"C:\inetpub\wwwroot\DetranProxy\appsettings.json.",
    r"C:\inetpub\wwwroot\DetranProxy\appsettings.Production.json.",
    r"C:\inetpub\wwwroot\DetranProxy\web.config.",
    r"C:\inetpub\wwwroot\APX\DetranProxy\appsettings.json.",
    r"C:\inetpub\wwwroot\APX\DetranProxy\web.config.",
    r"C:\inetpub\wwwroot\api\web.config.",
    r"C:\inetpub\wwwroot\api\appsettings.json.",
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\web.config.",
    r"C:\Sybase\ini\sql.ini",
]


def _decode_b64_api_response(text: str) -> bytes | None:
    """Extract and Base64-decode the payload from a Windows file-read API response."""
    try:
        j = json.loads(text)
        raw = j if isinstance(j, str) else None
        if not raw:
            for k in ("Bytes", "bytes", "Conteudo", "conteudo", "content", "Data", "data"):
                if isinstance(j, dict) and k in j:
                    raw = j[k]
                    break
        if raw and isinstance(raw, str):
            padding = (4 - len(raw) % 4) % 4
            return base64.b64decode(raw + "=" * padding)
    except Exception:
        pass
    return None


async def probe_windows_api_file_read(http: ScanHttp) -> list[FindingData]:
    """Detect Windows arbitrary-file-read via authenticated JSON APIs (CWE-22).

    Sub-techniques:
      * Direct read: endpoint returns any file's content as Base64 for a given absolute path.
      * Trailing-dot bypass: a blocklist checking exact filename (e.g. 'web.config') is bypassed
        by appending a trailing dot ('web.config.').  Win32 CreateFile() strips trailing dots and
        opens the real file; the application's filter sees a different name and allows the request.
    """
    base = http.base_url
    for api_path, method_param, body_key in _WIN_READ_CANDIDATES:
        check_url = (f"{base}{api_path}?metodosApis={method_param}"
                     if method_param else f"{base}{api_path}")
        if not http.in_scope(check_url):
            continue

        # 1. Sanity: can we read win.ini? Retry once — some proxies drop the first connection.
        raw_bytes = None
        for _attempt in range(2):
            resp = await http.request("POST", check_url, json={body_key: _WIN_SANITY_PATH})
            if resp is None or resp.status != 200:
                continue
            raw_bytes = _decode_b64_api_response(resp.text)
            if raw_bytes is not None:
                break
            await asyncio.sleep(2)
        if raw_bytes is None or not _WIN_SANITY_SIG.search(raw_bytes.decode("utf-8", errors="replace")):
            continue

        # 2. Trailing-dot bypass: attempt to read credential/config files.
        # Evidence records only file names and byte counts — never actual content.
        bypass_hits: list[tuple[str, int]] = []
        for cred_path in _WIN_CRED_CANDIDATES:
            cr = await http.request("POST", check_url, json={body_key: cred_path})
            if cr is None or cr.status != 200:
                continue
            cred_bytes = _decode_b64_api_response(cr.text)
            if cred_bytes is not None:
                bypass_hits.append((cred_path.rstrip("."), len(cred_bytes)))

        bypass_note = ""
        if bypass_hits:
            names = ", ".join(h[0].split("\\")[-1] for h in bypass_hits[:3])
            bypass_note = (f" Bypass por trailing-dot confirmado: {len(bypass_hits)} arquivo(s) de "
                           f"configuração lidos ({names}).")

        evidence = (
            f"POST {check_url} com {body_key}={_WIN_SANITY_PATH!r} → conteúdo retornado em Base64 "
            f"({len(raw_bytes)} bytes; assinatura win.ini presente).{bypass_note} "
            f"Padrão de bypass: nome_arquivo + '.' contorna blocklist por nome exato; Win32 "
            f"CreateFile() ignora pontos finais ao abrir o arquivo."
        )
        return [FindingData("windows-api-arbitrary-file-read", check_url,
                            method="POST", host_level=True, evidence=evidence)]
    return []


HOST_PROBES = [probe_transport, probe_sensitive_files, probe_cors, probe_trace, probe_graphql,
               probe_host_header, probe_windows_api_file_read]


# =========================================================================== input probes
async def send(http: ScanHttp, ip: InjectionPoint, value: str) -> Resp | None:
    if ip.json_body is not None:
        body = json.loads(ip.json_body)
        body[ip.param] = value
        return await http.request("POST", ip.url, json=body)
    params = [(k, value if k == ip.param else v) for k, v in ip.params]
    if ip.method == "POST":
        return await http.request("POST", ip.url, data=dict(params))
    return await http.request("GET", ip.url, params=params)


def _shown(ip: InjectionPoint, value: str) -> str:
    return f"{ip.method} {ip.url} com {ip.param}={value}"


async def probe_xss(http: ScanHttp, ip: InjectionPoint, baseline: Resp) -> list[FindingData]:
    c = "atl" + secrets.token_hex(4)
    payload = f"{c}\"'<{c}>"
    http.canaries[c] = ip          # lets the stored-XSS pass trace where a marker was submitted
    resp = await send(http, ip, payload)
    if not resp or not resp.is_html:
        return []
    body = resp.text
    tag = f"<{c}>"
    pos = body.find(tag)
    if pos >= 0:
        return [FindingData("xss-reflected", ip.url, ip.method, ip.param,
                            evidence=f"{_shown(ip, payload)} → a marcação <{c}> foi refletida sem "
                                     f"codificação: {around(body, pos, pos + len(tag), 60)}")]
    # Attribute context: the quote that delimits the attribute came back unencoded.
    for quote in ('"', "'"):
        m = re.search(rf"<[^<>]*=\s*{quote}[^{quote}<>]*{c}{quote}", body)
        if m:
            return [FindingData("xss-reflected", ip.url, ip.method, ip.param, confidence="medium",
                                title_suffix=" (contexto de atributo)",
                                evidence=f"{_shown(ip, payload)} → aspas refletidas sem codificação dentro "
                                         f"de um atributo: {clip(m.group(0)[-160:], 200)}")]
    return []


def _similar(a: Resp, b: Resp) -> float:
    if a.status != b.status:
        return 0.0
    ta, tb = a.text[:6000], b.text[:6000]
    if ta == tb:
        return 1.0
    return difflib.SequenceMatcher(None, ta, tb, autojunk=False).ratio()


async def probe_sqli(http: ScanHttp, ip: InjectionPoint, baseline: Resp) -> list[FindingData]:
    base_text = baseline.text
    for payload in (ip.original + "'", ip.original + '"'):
        resp = await send(http, ip, payload)
        if not resp:
            continue
        for dbms, pat in SQL_ERRORS:
            m = pat.search(resp.text)
            if m and not pat.search(base_text):
                return [FindingData("sqli-error", ip.url, ip.method, ip.param, title_suffix=f" — {dbms}",
                                    evidence=f"{_shown(ip, payload)} → erro de banco de dados ({dbms}): "
                                             f"{around(resp.text, m.start(), m.end(), 60)}")]

    # Boolean-based: read-only tautology/contradiction pair, confirmed twice.
    v = ip.original
    if re.fullmatch(r"\d+", v):
        pairs = [(f"{v} AND 1=1", f"{v} AND 1=2")]
    else:
        pairs = [(f"{v}' AND '1'='1", f"{v}' AND '1'='2")]
    stable = await send(http, ip, v)
    if not stable or _similar(baseline, stable) < 0.98:
        return []  # page is dynamic; differential analysis would be unreliable
    for true_p, false_p in pairs:
        t1 = await send(http, ip, true_p)
        if not t1 or _similar(baseline, t1) < 0.97:
            continue
        f1 = await send(http, ip, false_p)
        if not f1 or _similar(baseline, f1) > 0.90:
            continue
        t2, f2 = await send(http, ip, true_p), await send(http, ip, false_p)
        if t2 and f2 and _similar(baseline, t2) >= 0.97 and _similar(baseline, f2) <= 0.90 \
                and _similar(f1, f2) >= 0.97:
            return [FindingData("sqli-boolean", ip.url, ip.method, ip.param, confidence="medium",
                                evidence=f"{_shown(ip, true_p)} devolve a página original, enquanto "
                                         f"{ip.param}={false_p} devolve resposta diferente "
                                         f"(status {f1.status}, {len(f1.content)} bytes contra "
                                         f"{len(baseline.content)}); comportamento confirmado em duas "
                                         "repetições.")]
    return []


REDIRECT_PARAM = re.compile(r"url|uri|next|redirect|redir|return|dest|destination|continue|goto|target|"
                            r"forward|callback|back|rurl|out|link|voltar|retorno", re.I)


async def probe_open_redirect(http: ScanHttp, ip: InjectionPoint, baseline: Resp) -> list[FindingData]:
    v = ip.original
    if ip.method != "GET" or not (REDIRECT_PARAM.search(ip.param) or v.startswith(("http://", "https://", "/"))):
        return []
    for payload in (f"https://{CANARY_HOST}/", f"//{CANARY_HOST}/"):
        resp = await send(http, ip, payload)
        if not resp or resp.status not in (301, 302, 303, 307, 308):
            continue
        loc = resp.headers.get("location", "")
        if re.match(rf"^(?:https?:)?//{re.escape(CANARY_HOST)}(?:[/?#]|$)", loc, re.I):
            return [FindingData("open-redirect", ip.url, ip.method, ip.param,
                                evidence=f"{_shown(ip, payload)} → {resp.status} Location: {loc}")]
    return []


FILE_PARAM = re.compile(r"file|path|page|doc|template|include|dir|folder|load|read|download|view|lang|"
                        r"arquivo|pagina|caminho|img|image|name", re.I)
TRAVERSAL = [
    ("../../../../../../../../etc/passwd", re.compile(r"root:[^:\n]*:0:0:")),
    ("/etc/passwd", re.compile(r"root:[^:\n]*:0:0:")),
    ("....//....//....//....//....//....//etc/passwd", re.compile(r"root:[^:\n]*:0:0:")),
    ("..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[fonts\]|for 16-bit app support", re.I)),
]


async def probe_path_traversal(http: ScanHttp, ip: InjectionPoint, baseline: Resp) -> list[FindingData]:
    v = ip.original
    if not (FILE_PARAM.search(ip.param) or "/" in v or re.search(r"\.\w{2,5}$", v)):
        return []
    for payload, signature in TRAVERSAL:
        resp = await send(http, ip, payload)
        if not resp:
            continue
        m = signature.search(resp.text)
        if m and not signature.search(baseline.text):
            return [FindingData("path-traversal", ip.url, ip.method, ip.param,
                                evidence=f"{_shown(ip, payload)} → a resposta contém conteúdo de arquivo do "
                                         f"sistema: {clip(m.group(0), 40)}…")]
    return []


async def probe_ssti(http: ScanHttp, ip: InjectionPoint, baseline: Resp) -> list[FindingData]:
    a, b = 1337 + secrets.randbelow(500), 7331 + secrets.randbelow(500)
    expected = str(a * b)
    payload = f"{{{{{a}*{b}}}}}${{{a}*{b}}}<%= {a}*{b} %>#{{{a}*{b}}}"
    resp = await send(http, ip, payload)
    if resp and expected in resp.text and expected not in baseline.text:
        pos = resp.text.find(expected)
        return [FindingData("ssti", ip.url, ip.method, ip.param,
                            evidence=f"{_shown(ip, payload)} → a expressão {a}*{b} foi avaliada no servidor "
                                     f"({expected}): {around(resp.text, pos, pos + len(expected), 40)}")]
    return []


async def probe_crlf(http: ScanHttp, ip: InjectionPoint, baseline: Resp) -> list[FindingData]:
    v = ip.original
    in_header = len(v) >= 3 and any(v in value for value in baseline.headers.values())
    if ip.json_body is not None or not (in_header or REDIRECT_PARAM.search(ip.param)):
        return []
    marker = "x-atl-" + secrets.token_hex(4)
    payload = f"{v}\r\n{marker}: 1"
    resp = await send(http, ip, payload)
    if resp and resp.headers.get(marker) is not None and baseline.headers.get(marker) is None:
        return [FindingData("crlf-injection", ip.url, ip.method, ip.param,
                            evidence=f"{ip.method} {ip.url} com {ip.param}={v}%0d%0a{marker}: 1 → a resposta "
                                     f"passou a conter o cabeçalho {marker}.")]
    return []


INPUT_PROBES = [probe_xss, probe_sqli, probe_ssti, probe_path_traversal, probe_open_redirect, probe_crlf]

STORED_MARKER = re.compile(r"<(atl[0-9a-f]{8})>")


async def probe_stored_xss(http: ScanHttp, page_urls: list[str]) -> list[FindingData]:
    """Re-reads the crawled pages looking for markers that earlier probes submitted elsewhere."""
    out: list[FindingData] = []
    if not http.canaries:
        return out
    seen: set[tuple[str, str]] = set()
    for url in page_urls:
        resp = await http.get(url)
        if not resp or not resp.is_html:
            continue
        for match in STORED_MARKER.finditer(resp.text):
            ip = http.canaries.get(match.group(1))
            if ip is None or match.group(1) in url:
                continue
            source = urlsplit(ip.url).path
            if (url, source + ip.param) in seen:
                continue
            seen.add((url, source + ip.param))
            out.append(FindingData(
                "xss-stored", url, ip.method, ip.param, key=source,
                evidence=f"Marcador enviado em {ip.method} {ip.url} ({ip.param}) aparece sem codificação em "
                         f"{url}: {around(resp.text, match.start(), match.end(), 60)}"))
    return out
