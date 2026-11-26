import pytest

from atalaia import netguard, reports, security
from atalaia.netguard import TargetNotAllowed


@pytest.mark.parametrize("raw,expected", [
    ("https://Exemplo.com.br/", "https://exemplo.com.br"),
    ("https://exemplo.com.br:443/caminho?x=1", "https://exemplo.com.br"),
    ("http://exemplo.com.br:8080", "http://exemplo.com.br:8080"),
    ("  http://exemplo.com.br.  ", "http://exemplo.com.br"),
])
def test_normalize_base_url(raw, expected):
    assert netguard.normalize_base_url(raw) == expected


@pytest.mark.parametrize("raw", ["exemplo.com.br", "ftp://x.com", "http://", "http://u:p@x.com", "javascript:alert(1)",
                                 "http://x.com:99999"])
def test_normalize_rejects(raw):
    with pytest.raises(TargetNotAllowed):
        netguard.normalize_base_url(raw)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "0.0.0.0",
                                "100.64.0.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "224.0.0.1"])
def test_non_public_addresses(ip):
    assert not netguard._is_public(ip)


def test_public_address():
    assert netguard._is_public("8.8.8.8") and netguard._is_public("2606:4700:4700::1111")


def test_mixed_resolution_is_rejected(monkeypatch):
    monkeypatch.setattr(netguard, "resolve", lambda host: ["8.8.8.8", "10.0.0.1"])
    with pytest.raises(TargetNotAllowed):
        netguard.assert_allowed_host("misto.example", allow_private=False)
    monkeypatch.setattr(netguard, "resolve", lambda host: ["8.8.8.8"])
    assert netguard.assert_allowed_host("ok.example", allow_private=False) == ["8.8.8.8"]


def test_pin_url():
    assert netguard.pin_url("https://loja.example/a?b=1", "203.0.113.7") == (
        "https://203.0.113.7/a?b=1", "loja.example", "loja.example")
    assert netguard.pin_url("http://loja.example:8080/", "2001:db8::1")[0] == "http://[2001:db8::1]:8080/"


def test_password_hashing():
    h = security.hash_password("Correta-Bateria-Cavalo-42")
    assert h.startswith("scrypt$") and "Correta" not in h
    assert security.verify_password("Correta-Bateria-Cavalo-42", h)
    assert not security.verify_password("errada", h)
    assert not security.verify_password("x", "lixo")
    assert h != security.hash_password("Correta-Bateria-Cavalo-42")


def test_tokens():
    t = security.make_token("s" * 40, "u1", 1, 60)
    assert security.read_token("s" * 40, t)["sub"] == "u1"
    assert security.read_token("outra" * 10, t) is None
    assert security.read_token("s" * 40, security.make_token("s" * 40, "u1", 1, -5)) is None
    assert security.read_token("s" * 40, "a.b") is None


def test_secret_box():
    box = security.SecretBox("s" * 40)
    enc = box.encrypt_json({"Authorization": "Bearer x"})
    assert "Bearer" not in enc and box.decrypt_json(enc) == {"Authorization": "Bearer x"}
    assert security.SecretBox("t" * 40).decrypt_json(enc) is None


def test_csv_formula_injection_is_neutralised():
    assert reports._csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert reports._csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert reports._csv_safe("normal") == "normal"


def test_short_secret_key_is_refused():
    from atalaia.config import Settings
    with pytest.raises(RuntimeError):
        Settings(secret_key="curta")
