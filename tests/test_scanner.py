import asyncio
import threading
import time

import pytest

from atalaia.scanner import passive
from atalaia.scanner.engine import ScanConfig, run_scan
from atalaia.scanner.http import BudgetExceeded, OutOfScope, RateLimiter, ScanHttp
from atalaia.scanner.knowledge import CATALOG, SEVERITIES


def scan(url, **kw):
    kw.setdefault("rps", 500)
    return asyncio.run(run_scan(ScanConfig(url, **kw)))


def ids(result):
    return {f.check_id for f in result.findings}


def test_full_scan_detects_planted_vulnerabilities(vuln):
    result = scan(vuln.url, profile="full")
    found = ids(result)
    expected = {
        "xss-reflected", "sqli-error", "sqli-boolean", "ssti", "path-traversal", "open-redirect",
        "exposed-git", "exposed-env", "exposed-backup", "cors-reflect-credentials", "graphql-introspection",
        "directory-listing", "secret-in-response", "error-disclosure", "internal-ip-disclosure",
        "version-disclosure", "missing-csp", "missing-frame-protection", "missing-xcto",
        "cookie-no-httponly", "password-over-http", "csrf-token-missing", "vulnerable-js-library",
        "sri-missing", "no-https", "security-txt-missing",
    }
    assert expected <= found, f"missing: {expected - found}"
    by = {(f.check_id, f.url.rsplit('/', 1)[-1], f.parameter) for f in result.findings}
    assert ("xss-reflected", "search", "q") in by
    assert ("xss-reflected", "attr", "name") in by          # attribute-context XSS
    assert ("sqli-error", "product", "id") in by
    assert ("sqli-boolean", "item", "id") in by
    assert ("path-traversal", "download", "file") in by
    assert ("xss-reflected", "comment", "text") in by       # POST form, full profile only
    # The properly escaped endpoint must not be reported.
    assert not any(f.url.endswith("/safe") for f in result.findings if f.check_id == "xss-reflected")


def test_scanner_never_triggers_destructive_actions(vuln):
    scan(vuln.url, profile="full")
    hits = vuln.state["hits"]
    assert "logout" not in hits
    assert "account_delete" not in hits
    assert "delete_account_post" not in hits
    assert "login_post" not in hits       # forms with password fields are never submitted


def test_standard_profile_does_not_submit_post_forms(vuln):
    result = scan(vuln.url, profile="standard")
    assert "comment_post" not in vuln.state["hits"]
    assert "sqli-error" in ids(result)
    assert not any(f.method == "POST" and f.check_id == "xss-reflected" for f in result.findings)


def test_passive_profile_sends_no_probes(vuln):
    result = scan(vuln.url, profile="passive")
    found = ids(result)
    assert found.isdisjoint({"xss-reflected", "sqli-error", "sqli-boolean", "ssti", "path-traversal",
                             "open-redirect", "exposed-git", "exposed-env", "cors-reflect-credentials"})
    assert "missing-csp" in found
    assert result.requests_sent <= result.pages_crawled + 5


def test_hardened_app_has_no_false_positives(secure):
    result = scan(secure.url, profile="full")
    unexpected = [f for f in result.findings if f.check_id != "no-https"]
    assert unexpected == [], [(f.check_id, f.url, f.parameter, f.evidence) for f in unexpected]


def test_findings_are_deduplicated_and_stable(vuln):
    a, b = scan(vuln.url), scan(vuln.url)
    fa, fb = [f.fingerprint for f in a.findings], [f.fingerprint for f in b.findings]
    assert len(fa) == len(set(fa))
    assert set(fa) == set(fb)


def test_evidence_never_contains_secret_values(vuln):
    result = scan(vuln.url)
    blob = " ".join(f.evidence for f in result.findings)
    assert "supersecreta123" not in blob
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_request_budget_is_enforced(vuln):
    result = scan(vuln.url, profile="full", max_requests=20)
    assert result.requests_sent <= 20
    assert result.budget_exhausted


def test_cancellation_stops_the_scan(vuln):
    ev = threading.Event()
    ev.set()
    result = asyncio.run(run_scan(ScanConfig(vuln.url, rps=500), cancel_event=ev))
    assert result.canceled and result.requests_sent == 0


def test_excludes_are_respected(vuln):
    result = scan(vuln.url, excludes=["/search", "/product"])
    assert not any("/search" in f.url or "/product" in f.url for f in result.findings)


def test_out_of_scope_requests_are_refused(vuln):
    async def go():
        http = ScanHttp(vuln.url)
        try:
            for url in ("http://example.com/", "http://127.0.0.2:%d/" % vuln.port,
                        "http://127.0.0.1:1/", "https://127.0.0.1:%d/" % vuln.port, "file:///etc/passwd"):
                with pytest.raises(OutOfScope):
                    await http.get(url)
            assert http.requests_sent == 0
        finally:
            await http.aclose()
    asyncio.run(go())


def test_auth_headers_are_not_sent_to_other_ports(vuln):
    """Scan credentials go only to the exact origin; the any-port probe uses a bare client."""
    async def go():
        http = ScanHttp("http://127.0.0.1:9", headers={"Authorization": "Bearer segredo"})
        try:
            resp = await http.request("TRACE", vuln.url + "/", any_port=True)
            assert resp is not None and "segredo" not in resp.text
        finally:
            await http.aclose()
    asyncio.run(go())


def test_rate_limiter_spaces_requests():
    async def go():
        limiter = RateLimiter(20)
        start = time.monotonic()
        await asyncio.gather(*(limiter.wait() for _ in range(11)))
        return time.monotonic() - start
    assert asyncio.run(go()) >= 0.45


def test_budget_exception_type(vuln):
    async def go():
        http = ScanHttp(vuln.url, max_requests=1, rps=100)
        try:
            await http.get(vuln.url + "/")
            with pytest.raises(BudgetExceeded):
                await http.get(vuln.url + "/")
        finally:
            await http.aclose()
    asyncio.run(go())


def test_catalog_is_complete():
    for v in CATALOG.values():
        assert v.severity in SEVERITIES and v.description and v.remediation and 0 <= v.cvss <= 10


@pytest.mark.parametrize("src,expected", [
    ("https://code.jquery.com/jquery-1.12.4.min.js", ("jquery", "1.12.4")),
    ("https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js", ("jquery", "3.4.1")),
    ("https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js", ("lodash", "4.17.15")),
    ("/static/bootstrap-4.1.0.min.js", ("bootstrap", "4.1.0")),
    ("/static/app.js", None),
])
def test_js_library_detection(src, expected):
    assert passive.detect_js_library(src) == expected


def test_js_library_vulnerability_ranges():
    assert passive.vulnerable_library("jquery", "3.4.1")
    assert passive.vulnerable_library("jquery", "3.7.1") is None
    assert passive.vulnerable_library("bootstrap", "4.1.0")
    assert passive.vulnerable_library("bootstrap", "3.4.1") is None
    assert passive.vulnerable_library("bootstrap", "5.3.0") is None
    assert passive.vulnerable_library("lodash", "4.17.21") is None


def test_csp_analysis():
    assert passive._csp_weaknesses("default-src 'self'") == []
    assert passive._csp_weaknesses("script-src 'self' 'unsafe-inline'")
    assert passive._csp_weaknesses("script-src 'nonce-abc' 'unsafe-inline'") == []
    assert passive._csp_weaknesses("script-src *")
    assert passive._csp_weaknesses("img-src 'self'")


def test_connections_are_pinned_to_the_validated_address(vuln):
    """The hostname is never resolved again by the HTTP client: requests go to the pinned IP
    with the right Host header, so DNS rebinding after the guard check has no effect."""
    async def go():
        http = ScanHttp(f"http://nao-resolve.invalid:{vuln.port}", pinned_ip="127.0.0.1", rps=100)
        try:
            resp = await http.get(f"http://nao-resolve.invalid:{vuln.port}/search", params={"q": "abc"})
            assert resp is not None and resp.status == 200 and "abc" in resp.text
            assert resp.url.startswith("http://nao-resolve.invalid:")
            echoed = await http.request("TRACE", f"http://nao-resolve.invalid:{vuln.port}/")
            return echoed
        finally:
            await http.aclose()
    asyncio.run(go())
    result = asyncio.run(run_scan(ScanConfig(f"http://nao-resolve.invalid:{vuln.port}", rps=500,
                                             pinned_ip="127.0.0.1")))
    assert "sqli-error" in ids(result) and "xss-reflected" in ids(result)
    assert all("nao-resolve.invalid" in f.url for f in result.findings)


def _self_signed(tmp_path):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "loja.invalid")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=10)).sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


def test_https_target_with_untrusted_certificate(tmp_path):
    import socket
    import uvicorn
    from tests.vulnapp import make_secure_app
    cert, key = _self_signed(tmp_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(make_secure_app({}), host="127.0.0.1", port=port, log_level="critical",
                                           ssl_certfile=cert, ssl_keyfile=key))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.02)
    try:
        result = asyncio.run(run_scan(ScanConfig(f"https://loja.invalid:{port}", rps=500, pinned_ip="127.0.0.1")))
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    found = ids(result)
    assert result.pages_crawled > 0
    assert "tls-cert-invalid" in found and "missing-hsts" in found and "cookie-no-secure" in found
    assert "no-https" not in found and "tls-legacy-protocol" not in found
