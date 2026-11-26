"""Runtime configuration, read from environment variables (12-factor)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.environ.get("ATALAIA_DATABASE_URL", "sqlite:///./atalaia.db"))
    # Signs session tokens and derives the key that encrypts stored scan credentials.
    secret_key: str = field(default_factory=lambda: os.environ.get("ATALAIA_SECRET_KEY", ""))
    token_ttl_seconds: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_TOKEN_TTL", "28800")))
    allow_registration: bool = field(default_factory=lambda: _bool("ATALAIA_ALLOW_REGISTRATION", True))
    # Only for on-premises installs that scan their own internal network. Never enable in SaaS.
    allow_private_targets: bool = field(default_factory=lambda: _bool("ATALAIA_ALLOW_PRIVATE_TARGETS", False))
    verification_ttl_days: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_VERIFICATION_TTL_DAYS", "90")))
    max_concurrent_scans_per_org: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_MAX_SCANS_PER_ORG", "3")))
    scan_workers: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_SCAN_WORKERS", "4")))
    max_rps: float = field(default_factory=lambda: float(os.environ.get("ATALAIA_MAX_RPS", "20")))
    default_rps: float = field(default_factory=lambda: float(os.environ.get("ATALAIA_DEFAULT_RPS", "8")))
    max_pages: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_MAX_PAGES", "150")))
    max_requests: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_MAX_REQUESTS", "6000")))
    # Headless browser for JavaScript rendering and proof-based XSS: "auto" uses it when available.
    browser: str = field(default_factory=lambda: os.environ.get("ATALAIA_BROWSER", "auto").lower())
    browser_max_pages: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_BROWSER_MAX_PAGES", "25")))
    browser_third_party: bool = field(default_factory=lambda: _bool("ATALAIA_BROWSER_THIRD_PARTY", True))
    browser_sandbox: bool = field(default_factory=lambda: _bool("ATALAIA_BROWSER_SANDBOX", False))
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    enable_scheduler: bool = field(default_factory=lambda: _bool("ATALAIA_ENABLE_SCHEDULER", True))
    # True: the API process also executes scans. False: run `python -m atalaia.worker` separately.
    embedded_worker: bool = field(default_factory=lambda: _bool("ATALAIA_EMBEDDED_WORKER", True))
    worker_poll_seconds: float = field(default_factory=lambda: float(os.environ.get("ATALAIA_WORKER_POLL", "1")))
    max_scan_seconds: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_MAX_SCAN_SECONDS", "7200")))
    # A running scan whose worker has not sent a heartbeat for this long is considered dead.
    worker_stale_seconds: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_WORKER_STALE", "90")))

    # Servidor MCP embutido em /mcp (exige o extra [mcp]); clientes se autenticam com chave de API.
    mcp_enabled: bool = field(default_factory=lambda: _bool("ATALAIA_MCP", True))
    # Endereço público (https://atalaia.suaempresa.com). Usado como emissor OAuth e nos metadados do MCP;
    # sem ele o endereço é deduzido de cada requisição (defina em produção, atrás de proxy reverso).
    public_url: str = field(default_factory=lambda: os.environ.get("ATALAIA_PUBLIC_URL", "").strip().rstrip("/"))
    oauth_access_ttl: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_OAUTH_ACCESS_TTL", "3600")))
    oauth_refresh_ttl_days: int = field(default_factory=lambda: int(os.environ.get("ATALAIA_OAUTH_REFRESH_DAYS", "30")))

    def __post_init__(self):
        if not self.secret_key:
            if _bool("ATALAIA_REQUIRE_SECRET", False):
                raise RuntimeError("ATALAIA_SECRET_KEY must be set")
            # Development fallback: random per process (tokens do not survive a restart).
            self.secret_key = secrets.token_urlsafe(48)
        elif len(self.secret_key) < 32:
            raise RuntimeError("ATALAIA_SECRET_KEY must have at least 32 characters")
