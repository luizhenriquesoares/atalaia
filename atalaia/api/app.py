"""HTTP API and dashboard host."""
from __future__ import annotations

import hmac
import re
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__, audit, mfa, oauth, ownership, reports
from ..config import Settings
from ..db import ensure_schema, make_engine, make_session_factory
from ..models import (FINDING_STATUSES, ROLES, ApiKey, AuditLog, Finding, OAuthGrant, Organization, Scan,
                      ScanFindingLink, Target, User, utcnow)
from ..netguard import TargetNotAllowed, assert_allowed_host, host_of, normalize_base_url
from ..scanner.knowledge import SEVERITIES
from ..scans import ACTIVE, ScanManager, ScanRefused, create_scan, next_run, verification_valid
from ..security import (API_KEY_PREFIX, DUMMY_HASH, LoginThrottle, SecretBox, hash_api_key, hash_password,
                        make_token, new_api_key, password_problem, read_token, verify_password)

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s.]{2,}$")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer"}


# ------------------------------------------------------------------------- schemas
class RegisterIn(BaseModel):
    organization: str = Field(min_length=2, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


class LoginIn(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)
    code: str = Field(default="", max_length=32)        # TOTP or recovery code, when MFA is on


class MfaSetupIn(BaseModel):
    password: str = Field(max_length=256)


class MfaCodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class MfaDisableIn(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(min_length=6, max_length=32)


class OrgPatch(BaseModel):
    require_mfa: bool


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class UserIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)
    role: Literal["viewer", "analyst", "admin"] = "viewer"


class UserPatch(BaseModel):
    role: Literal["viewer", "analyst", "admin", "owner"] | None = None
    is_active: bool | None = None


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    role: Literal["viewer", "analyst", "admin"] = "analyst"


class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(max_length=500)
    max_rps: float | None = Field(default=None, gt=0, le=100)
    excludes: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("excludes")
    @classmethod
    def _excludes(cls, v):
        if any(len(e) > 200 for e in v):
            raise ValueError("exclusão muito longa")
        return [e for e in v if e.strip()]


class TargetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    max_rps: float | None = Field(default=None, gt=0, le=100)
    excludes: list[str] | None = Field(default=None, max_length=50)
    schedule: Literal["none", "daily", "weekly"] | None = None
    schedule_profile: Literal["passive", "standard", "full"] | None = None
    # {} clears stored credentials; omit to keep them.
    auth_headers: dict[str, str] | None = None


class VerifyIn(BaseModel):
    method: Literal["dns_txt", "http_file", "meta_tag"]


class ScanIn(BaseModel):
    target_id: str = Field(max_length=32)
    profile: Literal["passive", "standard", "full"] = "standard"


class FindingPatch(BaseModel):
    status: Literal["open", "fixed", "false_positive", "accepted_risk"]
    note: str = Field(default="", max_length=2000)


# ------------------------------------------------------------------------- auth
@dataclass
class Principal:
    org_id: str
    actor: str
    role: str
    user_id: str | None
    ip: str

    def require(self, role: str) -> None:
        if ROLE_RANK[self.role] < ROLE_RANK[role]:
            raise HTTPException(403, "Permissão insuficiente para esta operação")


def get_db(request: Request):
    with request.app.state.session_factory() as db:
        yield db


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    settings: Settings = request.app.state.settings
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    api_key = request.headers.get("x-api-key") or (token if token.startswith(API_KEY_PREFIX) else "")
    ip = client_ip(request)
    if api_key:
        key = db.execute(select(ApiKey).where(ApiKey.key_hash == hash_api_key(api_key))).scalar_one_or_none()
        if not key or key.revoked_at:
            raise HTTPException(401, "Chave de API inválida")
        if not key.last_used_at or (utcnow() - key.last_used_at).total_seconds() > 60:
            key.last_used_at = utcnow()
            db.commit()
        return Principal(key.org_id, f"apikey:{key.name}", key.role, None, ip)
    if token.startswith(oauth.ACCESS_PREFIX):
        found = oauth.principal_for_access_token(db, token)
        if not found:
            raise HTTPException(401, "Token de acesso inválido ou expirado")
        grant, user = found
        org = db.get(Organization, user.org_id)
        if org and org.require_mfa and not user.mfa_enabled:
            raise HTTPException(403, "Sua organização exige verificação em duas etapas.")
        if not grant.last_used_at or (utcnow() - grant.last_used_at).total_seconds() > 60:
            grant.last_used_at = utcnow()
            db.commit()
        role = min(grant.role, user.role, key=ROLE_RANK.__getitem__)
        return Principal(user.org_id, f"{user.email} via {grant.client_name}", role, user.id, ip)
    data = read_token(settings.secret_key, token) if token else None
    if not data:
        raise HTTPException(401, "Autenticação necessária")
    user = db.get(User, str(data.get("sub")))
    if not user or not user.is_active or data.get("ver") != user.token_version:
        raise HTTPException(401, "Sessão inválida ou expirada")
    if not user.mfa_enabled and request.url.path not in MFA_ENROLL_PATHS:
        org = db.get(Organization, user.org_id)
        if org and org.require_mfa:
            raise HTTPException(403, "Sua organização exige verificação em duas etapas. "
                                     "Ative-a em Minha conta para continuar.")
    return Principal(user.org_id, user.email, user.role, user.id, ip)


# What a user without a second factor may still call when the organization requires one.
MFA_ENROLL_PATHS = {"/api/v1/me", "/api/v1/auth/mfa/setup", "/api/v1/auth/mfa/enable",
                    "/api/v1/auth/change-password"}


# ------------------------------------------------------------------------- helpers
def user_dict(u: User) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "is_active": u.is_active,
            "mfa_enabled": bool(u.mfa_enabled), "created_at": reports.iso(u.created_at)}


def target_dict(t: Target, settings: Settings, include_instructions: bool = False) -> dict:
    d = {
        "id": t.id, "name": t.name, "base_url": t.base_url, "host": t.host,
        "verified": verification_valid(t, settings), "verified_at": reports.iso(t.verified_at),
        "verification_method": t.verification_method, "verification_expired": bool(
            t.verified_at and not verification_valid(t, settings)),
        "max_rps": t.max_rps, "excludes": t.excludes or [], "schedule": t.schedule,
        "schedule_profile": t.schedule_profile, "next_scan_at": reports.iso(t.next_scan_at),
        "has_auth_headers": bool(t.auth_headers_enc), "created_at": reports.iso(t.created_at),
    }
    if include_instructions:
        d["verification"] = ownership.instructions(t.base_url, t.verification_token)
    return d


def own(db: Session, model, obj_id: str, org_id: str):
    obj = db.get(model, obj_id)
    if obj is None or obj.org_id != org_id:
        raise HTTPException(404, "Recurso não encontrado")
    return obj


def clean_email(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "E-mail inválido")
    return email


def check_password(password: str) -> None:
    problem = password_problem(password)
    if problem:
        raise HTTPException(422, problem)


# ------------------------------------------------------------------------- app
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)
    box = SecretBox(settings.secret_key)
    manager = ScanManager(settings, session_factory, box)

    mcp_asgi = None                       # (app do SDK, app com autenticação), quando o MCP está ativo

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ensure_schema(engine)
        if settings.embedded_worker:
            manager.start()
        async with AsyncExitStack() as stack:
            if mcp_asgi:
                await stack.enter_async_context(mcp_asgi[0].router.lifespan_context(mcp_asgi[0]))
            yield
        manager.shutdown()
        engine.dispose()

    app = FastAPI(title="Atalaia", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.manager = manager
    app.state.engine = engine
    login_throttle = LoginThrottle(settings.login_max_failures, settings.login_lockout_seconds)
    account_throttle = LoginThrottle(settings.login_max_failures * 5, settings.login_lockout_seconds)
    register_throttle = LoginThrottle(10, 3600)
    # Only reachable with the right password, so it cannot be used by strangers to lock someone
    # out, and it keeps guessing of 6-digit codes far from feasible.
    mfa_throttle = LoginThrottle(settings.login_max_failures, settings.login_lockout_seconds)

    def second_factor_ok(db: Session, user: User, code: str) -> str | None:
        """Checks a TOTP or recovery code and consumes it. Returns the kind that matched."""
        secret = box.decrypt_json(user.mfa_secret_enc) if user.mfa_secret_enc else None
        if not secret:
            return None
        step = mfa.verify(secret, code, last_step=user.mfa_last_step or 0)
        if step is not None:
            user.mfa_last_step = step
            return "totp"
        if mfa.looks_like_recovery(code):
            digest = mfa.hash_recovery(code)
            stored = list(user.mfa_recovery or [])
            match = next((h for h in stored if hmac.compare_digest(h, digest)), None)
            if match:
                stored.remove(match)
                user.mfa_recovery = stored
                return "recovery"
        return None

    def clear_mfa(user: User) -> None:
        user.mfa_secret_enc = None
        user.mfa_enabled = False
        user.mfa_last_step = 0
        user.mfa_recovery = None
        user.token_version += 1

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        if "content-security-policy" not in h:          # a tela OAuth define a própria política
            h["Content-Security-Policy"] = ("default-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                                            "form-action 'self'; object-src 'none'")
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ScanRefused)
    async def scan_refused(_, exc: ScanRefused):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    api = "/api/v1"

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    # ---------------------------------------------------------------- auth
    @app.post(f"{api}/auth/register", status_code=201)
    def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
        if not settings.allow_registration:
            raise HTTPException(403, "O cadastro está desabilitado nesta instalação")
        ip = client_ip(request)
        if register_throttle.blocked(f"ip:{ip}"):
            raise HTTPException(429, "Muitos cadastros a partir deste endereço. Tente mais tarde.")
        register_throttle.fail(f"ip:{ip}")
        email = clean_email(body.email)
        check_password(body.password)
        if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
            raise HTTPException(409, "Não foi possível concluir o cadastro com este e-mail")
        org = Organization(name=body.organization.strip())
        db.add(org)
        db.flush()
        user = User(org_id=org.id, email=email, name=body.name.strip(), role="owner",
                    password_hash=hash_password(body.password))
        db.add(user)
        db.flush()
        audit.record(db, org_id=org.id, actor=email, action="org.create", resource_type="organization",
                     resource_id=org.id, ip=ip)
        db.commit()
        return {"token": make_token(settings.secret_key, user.id, user.token_version, settings.token_ttl_seconds),
                "user": user_dict(user), "organization": {"id": org.id, "name": org.name}}

    class AuthFailure(Exception):
        def __init__(self, status: int, message: str, mfa_required: bool = False):
            super().__init__(message)
            self.status, self.message, self.mfa_required = status, message, mfa_required

    def authenticate(db: Session, email: str, password: str, code: str, ip: str, via: str = "") -> User:
        """Senha + segundo fator, com os mesmos limites de tentativa para o painel e para o OAuth."""
        email = email.strip().lower()
        pair, account = f"{ip}|{email}", email
        if login_throttle.blocked(pair) or account_throttle.blocked(account):
            raise AuthFailure(429, "Muitas tentativas. Aguarde alguns minutos e tente novamente.")
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        ok = verify_password(password, user.password_hash if user else DUMMY_HASH)
        if not user or not ok or not user.is_active:
            login_throttle.fail(pair)
            # The per-account limit is higher, so a single client cannot cheaply lock a victim out,
            # while distributed guessing against one account is still bounded.
            account_throttle.fail(account)
            if user:
                audit.record(db, org_id=user.org_id, actor=email, action="auth.login_failed", ip=ip,
                             details={"via": via} if via else None)
                db.commit()
            raise AuthFailure(401, "E-mail ou senha incorretos")
        factor = None
        if user.mfa_enabled:
            if mfa_throttle.blocked(user.id):
                raise AuthFailure(429, "Muitas tentativas. Aguarde alguns minutos e tente novamente.")
            if not code.strip():
                raise AuthFailure(401, "Informe o código de verificação do seu aplicativo autenticador.", True)
            factor = second_factor_ok(db, user, code)
            if not factor:
                mfa_throttle.fail(user.id)
                audit.record(db, org_id=user.org_id, actor=email, action="auth.mfa_failed", ip=ip)
                db.commit()
                raise AuthFailure(401, "Código de verificação incorreto ou já utilizado.", True)
            mfa_throttle.reset(user.id)
        login_throttle.reset(pair)
        details = {k: v for k, v in (("second_factor", factor), ("via", via)) if v}
        audit.record(db, org_id=user.org_id, actor=email, action="auth.login", ip=ip, details=details or None)
        return user

    @app.post(f"{api}/auth/login")
    def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
        try:
            user = authenticate(db, body.email, body.password, body.code, client_ip(request))
        except AuthFailure as exc:
            if exc.mfa_required:
                return JSONResponse({"detail": exc.message, "mfa_required": True}, status_code=exc.status)
            raise HTTPException(exc.status, exc.message) from None
        db.commit()
        return {"token": make_token(settings.secret_key, user.id, user.token_version, settings.token_ttl_seconds),
                "user": user_dict(user)}

    @app.get(f"{api}/me")
    def me(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        org = db.get(Organization, p.org_id)
        user = db.get(User, p.user_id) if p.user_id else None
        return {"actor": p.actor, "role": p.role, "user": user_dict(user) if user else None,
                "organization": {"id": org.id, "name": org.name, "require_mfa": bool(org.require_mfa)},
                "mfa_setup_required": bool(user and org.require_mfa and not user.mfa_enabled)}

    @app.patch(f"{api}/organization")
    def patch_organization(body: OrgPatch, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("owner")
        org = db.get(Organization, p.org_id)
        user = db.get(User, p.user_id) if p.user_id else None
        if body.require_mfa and not (user and user.mfa_enabled):
            raise HTTPException(400, "Ative a verificação em duas etapas na sua própria conta antes de exigi-la "
                                     "de toda a organização")
        if body.require_mfa != bool(org.require_mfa):
            org.require_mfa = body.require_mfa
            audit.record(db, org_id=p.org_id, actor=p.actor, action="org.update", resource_type="organization",
                         resource_id=org.id, ip=p.ip, details={"require_mfa": body.require_mfa})
            db.commit()
        return {"id": org.id, "name": org.name, "require_mfa": bool(org.require_mfa)}

    # ---------------------------------------------------------------- second factor
    def session_user(p: Principal, db: Session) -> User:
        if not p.user_id:
            raise HTTPException(403, "Disponível apenas para usuários")
        return db.get(User, p.user_id)

    @app.post(f"{api}/auth/mfa/setup")
    def mfa_setup(body: MfaSetupIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        user = session_user(p, db)
        if user.mfa_enabled:
            raise HTTPException(409, "A verificação em duas etapas já está ativa")
        if not verify_password(body.password, user.password_hash):
            raise HTTPException(403, "Senha incorreta")
        secret = mfa.new_secret()
        user.mfa_secret_enc = box.encrypt_json(secret)      # pending until a code proves possession
        db.commit()
        uri = mfa.provisioning_uri(secret, user.email)
        return {"secret": secret, "otpauth_uri": uri, "qr": mfa.qr_matrix(uri)}

    @app.post(f"{api}/auth/mfa/enable")
    def mfa_enable(body: MfaCodeIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        user = session_user(p, db)
        if user.mfa_enabled:
            raise HTTPException(409, "A verificação em duas etapas já está ativa")
        secret = box.decrypt_json(user.mfa_secret_enc) if user.mfa_secret_enc else None
        if not secret:
            raise HTTPException(400, "Inicie a configuração antes de confirmar o código")
        if mfa_throttle.blocked(user.id):
            raise HTTPException(429, "Muitas tentativas. Aguarde alguns minutos e tente novamente.")
        step = mfa.verify(secret, body.code)
        if step is None:
            mfa_throttle.fail(user.id)
            raise HTTPException(400, "Código incorreto. Confira o relógio do aparelho e tente de novo.")
        codes = mfa.new_recovery_codes()
        user.mfa_enabled = True
        user.mfa_last_step = step
        user.mfa_recovery = [mfa.hash_recovery(c) for c in codes]
        user.token_version += 1                              # other sessions must log in again
        audit.record(db, org_id=p.org_id, actor=p.actor, action="auth.mfa_enable", ip=p.ip)
        db.commit()
        return {"recovery_codes": codes,
                "token": make_token(settings.secret_key, user.id, user.token_version, settings.token_ttl_seconds)}

    @app.post(f"{api}/auth/mfa/disable")
    def mfa_disable(body: MfaDisableIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        user = session_user(p, db)
        if not user.mfa_enabled:
            raise HTTPException(409, "A verificação em duas etapas não está ativa")
        if mfa_throttle.blocked(user.id):
            raise HTTPException(429, "Muitas tentativas. Aguarde alguns minutos e tente novamente.")
        if not verify_password(body.password, user.password_hash) or not second_factor_ok(db, user, body.code):
            mfa_throttle.fail(user.id)
            db.rollback()
            raise HTTPException(403, "Senha ou código incorretos")
        clear_mfa(user)
        audit.record(db, org_id=p.org_id, actor=p.actor, action="auth.mfa_disable", ip=p.ip)
        db.commit()
        return {"token": make_token(settings.secret_key, user.id, user.token_version, settings.token_ttl_seconds)}

    @app.post(f"{api}/auth/change-password")
    def change_password(body: PasswordIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        if not p.user_id:
            raise HTTPException(403, "Disponível apenas para usuários")
        user = db.get(User, p.user_id)
        if not verify_password(body.current_password, user.password_hash):
            raise HTTPException(403, "Senha atual incorreta")
        check_password(body.new_password)
        user.password_hash = hash_password(body.new_password)
        user.token_version += 1
        audit.record(db, org_id=p.org_id, actor=p.actor, action="auth.password_change", ip=p.ip)
        db.commit()
        return {"token": make_token(settings.secret_key, user.id, user.token_version, settings.token_ttl_seconds)}

    # ---------------------------------------------------------------- users
    @app.get(f"{api}/users")
    def list_users(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        rows = db.execute(select(User).where(User.org_id == p.org_id).order_by(User.created_at)).scalars()
        return [user_dict(u) for u in rows]

    @app.post(f"{api}/users", status_code=201)
    def create_user(body: UserIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        email = clean_email(body.email)
        check_password(body.password)
        if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
            raise HTTPException(409, "Já existe um usuário com este e-mail")
        user = User(org_id=p.org_id, email=email, name=body.name.strip(), role=body.role,
                    password_hash=hash_password(body.password))
        db.add(user)
        db.flush()
        audit.record(db, org_id=p.org_id, actor=p.actor, action="user.create", resource_type="user",
                     resource_id=user.id, ip=p.ip, details={"email": email, "role": body.role})
        db.commit()
        return user_dict(user)

    @app.patch(f"{api}/users/{{user_id}}")
    def patch_user(user_id: str, body: UserPatch, p: Principal = Depends(get_principal),
                   db: Session = Depends(get_db)):
        p.require("admin")
        user = own(db, User, user_id, p.org_id)
        if (user.role == "owner" or body.role == "owner") and p.role != "owner":
            raise HTTPException(403, "Apenas o proprietário pode alterar ou conceder o papel de proprietário")
        if user.id == p.user_id and (body.is_active is False or (body.role and body.role != user.role)):
            raise HTTPException(400, "Você não pode alterar o próprio papel ou desativar a própria conta")
        demoting_owner = user.role == "owner" and (body.is_active is False or (body.role and body.role != "owner"))
        if demoting_owner:
            owners = db.scalar(select(func.count()).select_from(User).where(
                User.org_id == p.org_id, User.role == "owner", User.is_active.is_(True)))
            if owners <= 1:
                raise HTTPException(400, "A organização precisa de pelo menos um proprietário ativo")
        changes = {}
        if body.role and body.role != user.role:
            changes["role"] = [user.role, body.role]
            user.role = body.role
        if body.is_active is not None and body.is_active != user.is_active:
            changes["is_active"] = [user.is_active, body.is_active]
            user.is_active = body.is_active
        if changes:
            user.token_version += 1
            audit.record(db, org_id=p.org_id, actor=p.actor, action="user.update", resource_type="user",
                         resource_id=user.id, ip=p.ip, details=changes)
            db.commit()
        return user_dict(user)

    @app.post(f"{api}/users/{{user_id}}/mfa/reset")
    def reset_user_mfa(user_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        """For a colleague who lost the phone and the recovery codes: they enroll again at next login."""
        p.require("admin")
        user = own(db, User, user_id, p.org_id)
        if user.role == "owner" and p.role != "owner":
            raise HTTPException(403, "Apenas o proprietário pode redefinir o segundo fator de um proprietário")
        if user.id == p.user_id:
            raise HTTPException(400, "Para a própria conta, desative em Minha conta com senha e código")
        if user.mfa_enabled or user.mfa_secret_enc:
            clear_mfa(user)
            audit.record(db, org_id=p.org_id, actor=p.actor, action="user.mfa_reset", resource_type="user",
                         resource_id=user.id, ip=p.ip, details={"email": user.email})
            db.commit()
        return user_dict(user)

    # ---------------------------------------------------------------- api keys
    def key_dict(k: ApiKey) -> dict:
        return {"id": k.id, "name": k.name, "prefix": f"{API_KEY_PREFIX}{k.prefix}", "role": k.role,
                "created_at": reports.iso(k.created_at), "last_used_at": reports.iso(k.last_used_at),
                "revoked": bool(k.revoked_at)}

    @app.get(f"{api}/api-keys")
    def list_keys(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        rows = db.execute(select(ApiKey).where(ApiKey.org_id == p.org_id).order_by(ApiKey.created_at.desc()))
        return [key_dict(k) for k in rows.scalars()]

    @app.post(f"{api}/api-keys", status_code=201)
    def create_key(body: ApiKeyIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        if not p.user_id:
            raise HTTPException(403, "Chaves de API só podem ser criadas por usuários")
        key, prefix, digest = new_api_key()
        row = ApiKey(org_id=p.org_id, created_by=p.user_id, name=body.name.strip(), prefix=prefix,
                     key_hash=digest, role=body.role)
        db.add(row)
        db.flush()
        audit.record(db, org_id=p.org_id, actor=p.actor, action="apikey.create", resource_type="api_key",
                     resource_id=row.id, ip=p.ip, details={"name": row.name, "role": row.role})
        db.commit()
        return {**key_dict(row), "key": key}

    @app.delete(f"{api}/api-keys/{{key_id}}", status_code=204)
    def revoke_key(key_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        row = own(db, ApiKey, key_id, p.org_id)
        if not row.revoked_at:
            row.revoked_at = utcnow()
            audit.record(db, org_id=p.org_id, actor=p.actor, action="apikey.revoke", resource_type="api_key",
                         resource_id=row.id, ip=p.ip)
            db.commit()
        return Response(status_code=204)

    # ---------------------------------------------------------------- targets
    @app.get(f"{api}/targets")
    def list_targets(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        rows = db.execute(select(Target).where(Target.org_id == p.org_id).order_by(Target.created_at.desc()))
        targets = rows.scalars().all()
        counts: dict[str, dict] = {}
        for tid, sev, n in db.execute(
                select(Finding.target_id, Finding.severity, func.count()).where(
                    Finding.org_id == p.org_id, Finding.status == "open")
                .group_by(Finding.target_id, Finding.severity)):
            counts.setdefault(tid, {})[sev] = n
        out = []
        for t in targets:
            d = target_dict(t, settings)
            d["open_findings"] = {s: counts.get(t.id, {}).get(s, 0) for s in SEVERITIES}
            out.append(d)
        return out

    @app.post(f"{api}/targets", status_code=201)
    def create_target(body: TargetIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("analyst")
        try:
            base_url = normalize_base_url(body.base_url)
            assert_allowed_host(host_of(base_url), allow_private=settings.allow_private_targets)
        except TargetNotAllowed as exc:
            raise HTTPException(422, str(exc)) from exc
        if db.execute(select(Target).where(Target.org_id == p.org_id, Target.base_url == base_url)).first():
            raise HTTPException(409, "Este alvo já está cadastrado")
        target = Target(org_id=p.org_id, name=body.name.strip(), base_url=base_url, host=host_of(base_url),
                        verification_token=ownership.new_token(), excludes=body.excludes,
                        max_rps=min(body.max_rps or settings.default_rps, settings.max_rps),
                        created_by=p.actor)
        db.add(target)
        db.flush()
        audit.record(db, org_id=p.org_id, actor=p.actor, action="target.create", resource_type="target",
                     resource_id=target.id, ip=p.ip, details={"base_url": base_url})
        db.commit()
        return target_dict(target, settings, include_instructions=True)

    @app.get(f"{api}/targets/{{target_id}}")
    def get_target(target_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        return target_dict(own(db, Target, target_id, p.org_id), settings, include_instructions=True)

    @app.patch(f"{api}/targets/{{target_id}}")
    def patch_target(target_id: str, body: TargetPatch, p: Principal = Depends(get_principal),
                     db: Session = Depends(get_db)):
        p.require("analyst")
        target = own(db, Target, target_id, p.org_id)
        changed = []
        if body.name is not None:
            target.name = body.name.strip()
            changed.append("name")
        if body.max_rps is not None:
            target.max_rps = min(body.max_rps, settings.max_rps)
            changed.append("max_rps")
        if body.excludes is not None:
            if any(len(e) > 200 for e in body.excludes):
                raise HTTPException(422, "Exclusão muito longa")
            target.excludes = [e for e in body.excludes if e.strip()]
            changed.append("excludes")
        if body.schedule is not None or body.schedule_profile is not None:
            target.schedule = body.schedule or target.schedule
            target.schedule_profile = body.schedule_profile or target.schedule_profile
            target.next_scan_at = next_run(target.schedule)
            changed.append("schedule")
        if body.auth_headers is not None:
            p.require("admin")
            if len(body.auth_headers) > 10:
                raise HTTPException(422, "No máximo 10 cabeçalhos")
            for name, value in body.auth_headers.items():
                if not HEADER_NAME_RE.match(name) or name.lower() in FORBIDDEN_HEADERS:
                    raise HTTPException(422, f"Cabeçalho não permitido: {name[:40]}")
                if len(value) > 4000 or re.search(r"[\r\n\x00]", value):
                    raise HTTPException(422, f"Valor inválido para o cabeçalho {name}")
            target.auth_headers_enc = box.encrypt_json(body.auth_headers) if body.auth_headers else None
            changed.append("auth_headers")
        if changed:
            audit.record(db, org_id=p.org_id, actor=p.actor, action="target.update", resource_type="target",
                         resource_id=target.id, ip=p.ip, details={"fields": changed})
            db.commit()
        return target_dict(target, settings, include_instructions=True)

    @app.delete(f"{api}/targets/{{target_id}}", status_code=204)
    def delete_target(target_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        target = own(db, Target, target_id, p.org_id)
        if db.scalar(select(func.count()).select_from(Scan).where(
                Scan.target_id == target.id, Scan.status.in_(ACTIVE))):
            raise HTTPException(409, "Cancele a varredura em andamento antes de excluir o alvo")
        scan_ids = select(Scan.id).where(Scan.target_id == target.id)
        db.query(ScanFindingLink).filter(ScanFindingLink.scan_id.in_(scan_ids)).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.target_id == target.id).delete(synchronize_session=False)
        db.query(Scan).filter(Scan.target_id == target.id).delete(synchronize_session=False)
        audit.record(db, org_id=p.org_id, actor=p.actor, action="target.delete", resource_type="target",
                     resource_id=target.id, ip=p.ip, details={"base_url": target.base_url})
        db.delete(target)
        db.commit()
        return Response(status_code=204)

    @app.post(f"{api}/targets/{{target_id}}/verify")
    def verify_target(target_id: str, body: VerifyIn, p: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)):
        p.require("analyst")
        target = own(db, Target, target_id, p.org_id)
        ok, detail = ownership.verify(target.base_url, target.verification_token, body.method,
                                      allow_private=settings.allow_private_targets)
        if ok:
            target.verified_at = utcnow()
            target.verification_method = body.method
            target.verified_by = p.actor
        audit.record(db, org_id=p.org_id, actor=p.actor,
                     action="target.verify" if ok else "target.verify_failed", resource_type="target",
                     resource_id=target.id, ip=p.ip, details={"method": body.method, "detail": detail})
        db.commit()
        return {"verified": ok, "detail": detail, "target": target_dict(target, settings, True)}

    # ---------------------------------------------------------------- scans
    @app.post(f"{api}/scans", status_code=202)
    def start_scan(body: ScanIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("analyst")
        target = own(db, Target, body.target_id, p.org_id)
        try:
            scan = create_scan(db, settings, target, body.profile, p.actor, p.ip)
        except ScanRefused as exc:
            db.rollback()
            audit.record(db, org_id=p.org_id, actor=p.actor, action="scan.refused", resource_type="target",
                         resource_id=target.id, ip=p.ip, details={"reason": str(exc)})
            db.commit()
            raise
        db.commit()
        manager.submit(scan.id)
        return reports.scan_dict(scan)

    @app.get(f"{api}/scans")
    def list_scans(target_id: str | None = None, limit: int = Query(50, ge=1, le=200),
                   offset: int = Query(0, ge=0), p: Principal = Depends(get_principal),
                   db: Session = Depends(get_db)):
        q = select(Scan).where(Scan.org_id == p.org_id)
        if target_id:
            q = q.where(Scan.target_id == target_id)
        rows = db.execute(q.order_by(Scan.created_at.desc()).limit(limit).offset(offset)).scalars()
        return [reports.scan_dict(s) for s in rows]

    @app.get(f"{api}/scans/{{scan_id}}")
    def get_scan(scan_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        return reports.scan_dict(own(db, Scan, scan_id, p.org_id))

    @app.post(f"{api}/scans/{{scan_id}}/cancel")
    def cancel_scan(scan_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("analyst")
        scan = own(db, Scan, scan_id, p.org_id)
        if scan.status not in ACTIVE:
            raise HTTPException(409, "A varredura já foi finalizada")
        audit.record(db, org_id=p.org_id, actor=p.actor, action="scan.cancel", resource_type="scan",
                     resource_id=scan.id, ip=p.ip)
        db.commit()
        manager.cancel(scan.id)
        return {"status": "canceling"}

    def scan_findings(db: Session, scan: Scan) -> list[Finding]:
        return list(db.execute(select(Finding).join(ScanFindingLink, ScanFindingLink.finding_id == Finding.id)
                               .where(ScanFindingLink.scan_id == scan.id)).scalars())

    @app.get(f"{api}/scans/{{scan_id}}/report")
    def scan_report(scan_id: str, format: Literal["json", "html", "csv", "sarif"] = "json",
                    p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        scan = own(db, Scan, scan_id, p.org_id)
        target = db.get(Target, scan.target_id)
        findings = scan_findings(db, scan)
        audit.record(db, org_id=p.org_id, actor=p.actor, action="report.export", resource_type="scan",
                     resource_id=scan.id, ip=p.ip, details={"format": format})
        db.commit()
        name = f"atalaia-{scan.id[:8]}"
        if format == "html":
            return HTMLResponse(reports.as_html(scan, target, findings), headers={
                "Content-Disposition": f'attachment; filename="{name}.html"'})
        if format == "csv":
            return PlainTextResponse(reports.as_csv(findings), media_type="text/csv", headers={
                "Content-Disposition": f'attachment; filename="{name}.csv"'})
        if format == "sarif":
            return JSONResponse(reports.as_sarif(scan, target, findings), headers={
                "Content-Disposition": f'attachment; filename="{name}.sarif"'})
        return reports.as_json(scan, target, findings)

    # ---------------------------------------------------------------- findings
    @app.get(f"{api}/findings")
    def list_findings(target_id: str | None = None, scan_id: str | None = None,
                      severity: str | None = None, status: str | None = None, q: str | None = Query(None, max_length=100),
                      limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                      p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        query = select(Finding).where(Finding.org_id == p.org_id)
        if target_id:
            query = query.where(Finding.target_id == target_id)
        if scan_id:
            query = query.join(ScanFindingLink, ScanFindingLink.finding_id == Finding.id).where(
                ScanFindingLink.scan_id == scan_id)
        if severity:
            query = query.where(Finding.severity.in_([s for s in severity.split(",") if s in SEVERITIES]))
        if status:
            query = query.where(Finding.status.in_([s for s in status.split(",") if s in FINDING_STATUSES]))
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%"
            query = query.where(Finding.title.ilike(like, escape="\\") | Finding.url.ilike(like, escape="\\"))
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        rows = db.execute(query.order_by(Finding.cvss.desc(), Finding.last_seen.desc())
                          .limit(limit).offset(offset)).scalars().all()
        names = dict(db.execute(select(Target.id, Target.name).where(Target.org_id == p.org_id)).all())
        items = []
        for f in rows:
            d = reports.finding_dict(f)
            d["target_name"] = names.get(f.target_id)
            items.append(d)
        return {"total": total, "items": items}

    @app.get(f"{api}/findings/{{finding_id}}")
    def get_finding(finding_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        f = own(db, Finding, finding_id, p.org_id)
        d = reports.finding_dict(f)
        d["target_name"] = f.target.name if f.target else None
        return d

    @app.patch(f"{api}/findings/{{finding_id}}")
    def patch_finding(finding_id: str, body: FindingPatch, p: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)):
        p.require("analyst")
        f = own(db, Finding, finding_id, p.org_id)
        if body.status in ("false_positive", "accepted_risk") and not body.note.strip():
            raise HTTPException(422, "Informe uma justificativa para esta classificação")
        old = f.status
        f.status = body.status
        f.status_note = body.note.strip()
        f.resolved_at = None if body.status == "open" else utcnow()
        audit.record(db, org_id=p.org_id, actor=p.actor, action="finding.triage", resource_type="finding",
                     resource_id=f.id, ip=p.ip, details={"from": old, "to": body.status, "note": f.status_note})
        db.commit()
        return reports.finding_dict(f)

    # ---------------------------------------------------------------- dashboard
    @app.get(f"{api}/dashboard")
    def dashboard(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        by_sev = {s: 0 for s in SEVERITIES}
        for sev, n in db.execute(select(Finding.severity, func.count()).where(
                Finding.org_id == p.org_id, Finding.status == "open").group_by(Finding.severity)):
            by_sev[sev] = n
        by_owasp = [{"category": c, "count": n} for c, n in db.execute(
            select(Finding.owasp, func.count()).where(Finding.org_id == p.org_id, Finding.status == "open",
                                                      Finding.severity != "info")
            .group_by(Finding.owasp).order_by(func.count().desc()))]
        by_status = dict(db.execute(select(Finding.status, func.count()).where(
            Finding.org_id == p.org_id).group_by(Finding.status)).all())
        targets = db.execute(select(Target).where(Target.org_id == p.org_id)).scalars().all()
        recent = db.execute(select(Scan).where(Scan.org_id == p.org_id)
                            .order_by(Scan.created_at.desc()).limit(8)).scalars()
        penalty = by_sev["critical"] * 25 + by_sev["high"] * 10 + by_sev["medium"] * 3 + by_sev["low"]
        return {
            "open_by_severity": by_sev, "open_by_owasp": by_owasp, "findings_by_status": by_status,
            "targets": len(targets), "verified_targets": sum(1 for t in targets if verification_valid(t, settings)),
            "security_score": max(0, 100 - penalty) if targets else None,
            "recent_scans": [reports.scan_dict(s) for s in recent],
        }

    # ---------------------------------------------------------------- audit
    @app.get(f"{api}/audit-logs")
    def audit_logs(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                   action: str | None = Query(None, max_length=60),
                   p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        q = select(AuditLog).where(AuditLog.org_id == p.org_id)
        if action:
            q = q.where(AuditLog.action == action)
        rows = db.execute(q.order_by(AuditLog.id.desc()).limit(limit).offset(offset)).scalars()
        return [{"id": a.id, "actor": a.actor, "action": a.action, "resource_type": a.resource_type,
                 "resource_id": a.resource_id, "ip": a.ip, "details": a.details,
                 "created_at": reports.iso(a.created_at), "hash": a.hash} for a in rows]

    @app.get(f"{api}/audit-logs/verify")
    def audit_verify(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        p.require("admin")
        return audit.verify_chain(db, p.org_id)

    # ---------------------------------------------------------------- aplicativos conectados (OAuth)
    oauth.install(app, settings=settings, get_db=get_db, authenticate=authenticate, auth_failure=AuthFailure,
                  client_ip=client_ip, register_throttle=register_throttle)

    def grant_dict(g: OAuthGrant, emails: dict) -> dict:
        return {"id": g.id, "client_name": g.client_name, "role": g.role, "scope": g.scope,
                "user_email": emails.get(g.user_id), "created_at": reports.iso(g.created_at),
                "last_used_at": reports.iso(g.last_used_at), "revoked": bool(g.revoked_at)}

    @app.get(f"{api}/oauth/grants")
    def list_grants(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        """Aplicativos conectados: o usuário vê os seus; administradores veem os da organização."""
        q = select(OAuthGrant).where(OAuthGrant.org_id == p.org_id, OAuthGrant.revoked_at.is_(None))
        if ROLE_RANK[p.role] < ROLE_RANK["admin"]:
            q = q.where(OAuthGrant.user_id == (p.user_id or ""))
        rows = db.execute(q.order_by(OAuthGrant.created_at.desc())).scalars().all()
        emails = dict(db.execute(select(User.id, User.email).where(User.org_id == p.org_id)).all())
        return [grant_dict(g, emails) for g in rows]

    @app.delete(f"{api}/oauth/grants/{{grant_id}}", status_code=204)
    def delete_grant(grant_id: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
        g = own(db, OAuthGrant, grant_id, p.org_id)
        if g.user_id != p.user_id:
            p.require("admin")
        app.state.oauth_revoke_grant(db, g, p.ip, f"revoked by {p.actor}")
        db.commit()
        return Response(status_code=204)

    # ---------------------------------------------------------------- web
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

    if settings.mcp_enabled:
        mcp_asgi = embedded_mcp(app)
        if mcp_asgi:
            mcp_asgi[1].metadata_url = lambda scope: oauth.resource_metadata_url(
                settings.public_url or _scope_base(scope))
            app.add_middleware(McpRoute, mcp_app=mcp_asgi[1])
    return app


def _scope_base(scope) -> str:
    headers = dict(scope.get("headers") or [])
    host = headers.get(b"host", b"").decode("latin-1") or "localhost"
    return f"{scope.get('scheme', 'http')}://{host}"


class McpRoute:
    """Entrega /mcp ao servidor MCP embutido; o resto segue para a API."""

    def __init__(self, app, mcp_app):
        self.app, self.mcp_app = app, mcp_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") in ("/mcp", "/mcp/"):
            return await self.mcp_app(scope, receive, send)
        return await self.app(scope, receive, send)


def embedded_mcp(api_app: FastAPI):
    """O MCP embutido fala com esta mesma API dentro do processo (sem rede) e com a chave do cliente,
    então passa pelas mesmas regras, papéis e auditoria de qualquer outro cliente."""
    try:
        from ..mcp_server import AtalaiaClient, InProcessTransport, build_server, http_app
    except ImportError:                    # extra [mcp] não instalado
        return None
    client = AtalaiaClient("http://atalaia.internal", transport=InProcessTransport(api_app))
    return http_app(build_server(client), client)
