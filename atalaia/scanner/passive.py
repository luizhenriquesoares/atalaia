"""Passive checks: analyse responses the crawler already fetched, sending nothing extra."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .crawler import Page
from .http import Resp


@dataclass
class FindingData:
    check_id: str
    url: str
    method: str = "GET"
    parameter: str = ""
    evidence: str = ""
    # Distinguishes findings of the same check on the same URL (cookie name, library, ...).
    key: str = ""
    confidence: str = "high"      # high | medium | low
    severity: str | None = None   # overrides the catalogue default
    title_suffix: str = ""
    # Site-wide findings (headers, TLS) are fingerprinted without the URL path.
    host_level: bool = False
    extra: dict = field(default_factory=dict)


def clip(text: str, n: int = 300) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n] + "…"


def around(text: str, start: int, end: int, pad: int = 80) -> str:
    return clip(text[max(0, start - pad): end + pad], 2 * pad + (end - start) + 5)


# --------------------------------------------------------------------------- headers
def check_security_headers(resp: Resp) -> list[FindingData]:
    """Run once against the main HTML response of the site."""
    out: list[FindingData] = []
    h = resp.headers
    url = resp.url
    https = url.startswith("https://")

    def add(check_id, evidence, **kw):
        out.append(FindingData(check_id, url, evidence=evidence, host_level=True, **kw))

    if https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            add("missing-hsts", "Cabeçalho Strict-Transport-Security não presente na resposta.")
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                add("weak-hsts", f"Strict-Transport-Security: {hsts}")

    csp = h.get("content-security-policy")
    if not csp:
        add("missing-csp", "Cabeçalho Content-Security-Policy não presente na resposta.")
    else:
        weak = _csp_weaknesses(csp)
        if weak:
            add("weak-csp", f"Problemas: {', '.join(weak)}. Política: {clip(csp, 400)}")

    has_frame_ancestors = bool(csp and re.search(r"frame-ancestors", csp, re.I))
    if not h.get("x-frame-options") and not has_frame_ancestors:
        add("missing-frame-protection",
            "Nem X-Frame-Options nem a diretiva CSP frame-ancestors estão presentes.")
    if (h.get("x-content-type-options") or "").strip().lower() != "nosniff":
        add("missing-xcto", "Cabeçalho X-Content-Type-Options: nosniff não presente.")
    if not h.get("referrer-policy"):
        add("missing-referrer-policy", "Cabeçalho Referrer-Policy não presente.")
    if not h.get("permissions-policy"):
        add("missing-permissions-policy", "Cabeçalho Permissions-Policy não presente.")

    disclosed = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        value = h.get(name)
        if value and re.search(r"\d+\.\d+", value):
            disclosed.append(f"{name}: {value}")
    if disclosed:
        add("version-disclosure", "; ".join(disclosed))
    return out


def _csp_weaknesses(csp: str) -> list[str]:
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    script = directives.get("script-src", directives.get("default-src"))
    weak = []
    if script is None:
        weak.append("sem script-src/default-src")
        return weak
    has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
    if "'unsafe-inline'" in script and not has_nonce_or_hash:
        weak.append("script-src permite 'unsafe-inline'")
    if "'unsafe-eval'" in script:
        weak.append("script-src permite 'unsafe-eval'")
    if any(t in ("*", "http:", "https:", "data:") for t in script) and "'strict-dynamic'" not in script:
        weak.append("script-src permite origens curinga")
    return weak


# --------------------------------------------------------------------------- cookies
SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|login|user|remember|csrf|xsrf", re.I)


def check_cookies(resp: Resp) -> list[FindingData]:
    out = []
    https = resp.url.startswith("https://")
    for raw in resp.headers.get_list("set-cookie"):
        first, *attrs = raw.split(";")
        name = first.split("=", 1)[0].strip()
        if not name:
            continue
        flags = {a.strip().split("=", 1)[0].lower() for a in attrs}
        sensitive = bool(SESSION_COOKIE.search(name))
        shown = f"Set-Cookie: {name}=…; {'; '.join(a.strip() for a in attrs)}".rstrip("; ")

        def add(check_id):
            out.append(FindingData(check_id, resp.url, parameter=name, key=name, evidence=shown,
                                   host_level=True, title_suffix=f" ({name})",
                                   severity=None if sensitive else "low",
                                   confidence="high" if sensitive else "medium"))
        if https and "secure" not in flags:
            add("cookie-no-secure")
        if "httponly" not in flags and sensitive and not re.search(r"csrf|xsrf", name, re.I):
            add("cookie-no-httponly")
        if "samesite" not in flags:
            add("cookie-no-samesite")
    return out


# --------------------------------------------------------------------------- content
SECRET_PATTERNS = [
    ("Chave de acesso AWS", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("Chave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Chave de API Google", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("Token Slack", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,72})\b")),
    ("Token GitHub", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("Chave secreta Stripe", re.compile(r"\b(sk_live_[0-9A-Za-z]{20,})\b")),
    ("Webhook Slack", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),
]

ERROR_PATTERNS = [
    ("Python", re.compile(r"Traceback \(most recent call last\):")),
    ("Java", re.compile(r"(?:Exception|Error)[^\n<]{0,200}\n?\s+at [\w.$]+\([\w.]+\.java:\d+\)")),
    ("PHP", re.compile(r"<b>(?:Fatal error|Warning|Parse error|Notice)</b>:\s.+? on line <b>\d+</b>", re.S)),
    ("ASP.NET", re.compile(r"Server Error in '.*?' Application|\[\w+Exception: [^\]]+\]")),
    ("Ruby on Rails", re.compile(r"<h1>\s*(?:ActionController|ActiveRecord|NoMethodError)[\w:]*")),
    ("Node.js", re.compile(r"\bat [\w.<>$]+ \((?:/|[A-Z]:\\)[^)]+\.js:\d+:\d+\)")),
    ("Django (DEBUG)", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>")),
    ("Laravel (debug)", re.compile(r"Whoops, looks like something went wrong|Illuminate\\\\")),
]

SQL_ERRORS = [
    ("MySQL", re.compile(r"You have an error in your SQL syntax|Warning: mysqli?_|MySqlException|"
                         r"com\.mysql\.jdbc|Unknown column '[^']+' in", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.{0,20}ERROR|pg_query\(\)|PSQLException|"
                              r"unterminated quoted string at or near|syntax error at or near", re.I)),
    ("SQL Server", re.compile(r"Unclosed quotation mark after the character string|"
                              r"Microsoft OLE DB Provider for SQL Server|SqlException|"
                              r"Incorrect syntax near", re.I)),
    ("Oracle", re.compile(r"\bORA-\d{5}\b|quoted string not properly terminated", re.I)),
    ("SQLite", re.compile(r"SQLite3?::|sqlite3\.OperationalError|SQLITE_ERROR|unrecognized token: \"|"
                          r"near \"[^\"]*\": syntax error", re.I)),
    ("Genérico", re.compile(r"SQLSTATE\[\w+\]|ODBC SQL|JDBC.{0,30}SQLException", re.I)),
]

PRIVATE_IP = re.compile(r"(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")

# (library, version regexes, [(fixed_in, advisories)])
JS_LIBS = [
    ("jquery", [("3.5.0", "CVE-2020-11022, CVE-2020-11023 (XSS)"), ("3.0.0", "CVE-2015-9251 (XSS)"),
                ("1.9.0", "CVE-2012-6708 (XSS)")]),
    ("bootstrap", [("3.4.1", "CVE-2019-8331 (XSS)"), ("4.3.1", "CVE-2019-8331 (XSS)")]),
    ("lodash", [("4.17.21", "CVE-2021-23337 (injeção de comando), CVE-2020-8203 (prototype pollution)")]),
    ("moment", [("2.29.4", "CVE-2022-31129 (ReDoS), CVE-2022-24785 (path traversal)")]),
    ("handlebars", [("4.7.7", "CVE-2021-23369 (execução remota de código)")]),
    ("angular", [("2.0.0", "AngularJS 1.x está sem suporte desde 2022 e tem falhas de XSS sem correção")]),
]
_VER = r"(\d+\.\d+(?:\.\d+)?)"


def _vt(v: str) -> tuple[int, ...]:
    parts = [int(x) for x in v.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def detect_js_library(src: str) -> tuple[str, str] | None:
    path = urlsplit(src).path.lower()
    for lib, _ in JS_LIBS:
        names = [lib] + (["angular.js", "angularjs"] if lib == "angular" else [])
        for name in names:
            n = re.escape(name)
            for pat in (rf"(?:^|/){n}(?:\.js)?[-@/]v?{_VER}", rf"(?:^|/){n}[-.]{_VER}(?:\.slim)?(?:\.min)?\.js",
                        rf"/{n}/{_VER}/"):
                m = re.search(pat, path)
                if m:
                    return lib, m.group(1)
    return None


def vulnerable_library(lib: str, version: str) -> str | None:
    table = dict(JS_LIBS)[lib]
    v = _vt(version)
    hits = []
    if lib == "bootstrap":
        if v < _vt("3.4.1") or (_vt("4.0.0") <= v < _vt("4.3.1")):
            hits.append(table[0][1])
    else:
        hits = [adv for fixed, adv in table if v < _vt(fixed)]
    return "; ".join(hits) if hits else None


JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
# Secrets copied from tutorials and framework defaults. Checked offline against tokens the target
# itself handed to the scanner.
WEAK_JWT_SECRETS = ["secret", "secretkey", "secret-key", "secret_key", "mysecret", "my-secret", "changeme",
                    "change-me", "password", "123456", "12345678", "jwt", "jwtsecret", "jwt-secret",
                    "jwt_secret", "your-256-bit-secret", "your_jwt_secret", "supersecret", "key", "test",
                    "admin", "default", "s3cr3t", "private", "token", "qwerty", "shhhhh", "keyboard cat",
                    "development", "dev"]
SESSION_PARAM = re.compile(r"^(?:jsessionid|phpsessid|aspsessionid\w*|sessionid|session_id|sid|sessid|"
                           r"access_token|auth_token|authtoken)$", re.I)


def _b64url(data: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def jwt_weakness(token: str) -> str | None:
    """Returns a description when *token* is unsigned or signed with a guessable secret."""
    import hashlib
    import hmac
    import json
    try:
        head_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url(head_b64))
        json.loads(_b64url(payload_b64))
    except (ValueError, TypeError):
        return None
    if not isinstance(header, dict):
        return None
    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        return "token sem assinatura (alg none)"
    digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}.get(alg)
    if digest:
        try:
            signature = _b64url(sig_b64)
        except (ValueError, TypeError):
            return None
        signed = f"{head_b64}.{payload_b64}".encode()
        for secret in WEAK_JWT_SECRETS:
            if hmac.compare_digest(hmac.new(secret.encode(), signed, digest).digest(), signature):
                return (f"assinado com {alg.upper()} usando um segredo trivial "
                        f"({secret[0]}{'*' * (len(secret) - 1)}, {len(secret)} caracteres)")
    return None


def check_jwt(resp: Resp) -> list[FindingData]:
    sources = [("cookie " + raw.split("=", 1)[0].strip(), raw) for raw in resp.headers.get_list("set-cookie")]
    if resp.content and resp.content_type in ("application/json", "text/html", "text/plain", "application/javascript"):
        sources.append(("corpo da resposta", resp.text[:200_000]))
    out, seen = [], set()
    for where, text in sources:
        for token in JWT_RE.findall(text)[:5]:
            if token in seen:
                continue
            seen.add(token)
            weakness = jwt_weakness(token)
            if weakness:
                out.append(FindingData("jwt-insecure", resp.url, key=weakness.split(" (")[0], host_level=True,
                                       evidence=f"JWT em {where}: {token[:16]}… — {weakness}"))
    return out


CSRF_FIELD = re.compile(r"csrf|xsrf|token|authenticity|nonce|__requestverification|_wpnonce", re.I)


def check_page(page: Page) -> list[FindingData]:
    out: list[FindingData] = []
    resp = page.resp
    url = page.url
    body = resp.text if resp.content and (resp.is_html or resp.content_type.startswith(
        ("text/", "application/json", "application/javascript", "application/xml"))) else ""
    https = url.startswith("https://")
    host = urlsplit(url).hostname

    if body:
        for label, pat in SECRET_PATTERNS:
            m = pat.search(body)
            if m:
                value = m.group(0)
                redacted = value[:6] + "…" + value[-2:] if len(value) > 12 else value[:4] + "…"
                out.append(FindingData("secret-in-response", url, key=label, title_suffix=f": {label}",
                                       evidence=f"{label} encontrada na resposta: {redacted}",
                                       severity="critical" if label == "Chave privada" else None))
        for label, pat in ERROR_PATTERNS + SQL_ERRORS:
            m = pat.search(body)
            if m:
                out.append(FindingData("error-disclosure", url, key=label, title_suffix=f" ({label})",
                                       evidence=around(body, m.start(), m.end())))
                break
        ips = sorted(set(PRIVATE_IP.findall(body)))
        if ips and host not in ips:
            out.append(FindingData("internal-ip-disclosure", url, evidence="Endereços: " + ", ".join(ips[:5]),
                                   confidence="medium"))

    if resp.is_html and resp.status == 200 and re.search(
            r"<title>\s*(?:Index of /|Directory listing for )", body, re.I):
        out.append(FindingData("directory-listing", url, evidence=clip(body, 200)))

    for src, has_integrity in page.scripts:
        src_host = urlsplit(src).hostname
        if https and src.startswith("http://"):
            out.append(FindingData("mixed-content", url, key=src, evidence=f"<script src=\"{src}\">"))
        if src_host and src_host != host and not has_integrity:
            out.append(FindingData("sri-missing", url, key=src_host, host_level=True,
                                   title_suffix=f" ({src_host})", evidence=f"<script src=\"{src}\">"))
        detected = detect_js_library(src)
        if detected:
            lib, version = detected
            advisories = vulnerable_library(lib, version)
            if advisories:
                out.append(FindingData("vulnerable-js-library", url, key=f"{lib}@{version}", host_level=True,
                                       title_suffix=f": {lib} {version}",
                                       evidence=f"{src} — {advisories}"))

    from urllib.parse import parse_qsl
    for link in page.links[:300]:
        parts = urlsplit(link)
        if parts.hostname != host:
            continue
        leaked = [k for k, v in parse_qsl(parts.query) if SESSION_PARAM.match(k) and len(v) >= 12]
        if ";jsessionid=" in parts.path.lower():
            leaked.append("jsessionid")
        if leaked:
            out.append(FindingData("session-in-url", url, key=leaked[0], confidence="medium", host_level=True,
                                   parameter=leaked[0],
                                   evidence=f"Link com {leaked[0]} na URL: {parts.path}?{leaked[0]}=…"))
            break

    for form in page.forms:
        names = " ".join(n for n, _, _ in form.inputs)
        path = urlsplit(form.action).path
        if form.has_password() and (not https or form.action.startswith("http://")):
            out.append(FindingData("password-over-http", url, key=path,
                                   evidence=f"Formulário com campo de senha enviado para {form.action}"))
        if form.method == "POST":
            hidden = [n for n, t, _ in form.inputs if t == "hidden"]
            if not any(CSRF_FIELD.search(n) for n in hidden):
                out.append(FindingData("csrf-token-missing", form.action, method="POST", key=path,
                                       confidence="low",
                                       evidence=f"Formulário em {url} com campos: {clip(names, 150)}"))
    return out
