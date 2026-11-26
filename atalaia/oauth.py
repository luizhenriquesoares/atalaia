"""Servidor de autorização OAuth 2.1 para o conector MCP (claude.ai e outros clientes remotos).

Segue a especificação de autorização do MCP:

- metadados do recurso protegido (RFC 9728) e do servidor de autorização (RFC 8414);
- registro dinâmico de cliente (RFC 7591), público (PKCE) ou confidencial;
- código de autorização com PKCE S256 obrigatório, uso único e validade curta;
- indicador de recurso (RFC 8707) e parâmetro ``iss`` na resposta (RFC 9207);
- tokens opacos guardados só como hash, token de renovação com rotação e detecção de reuso;
- revogação (RFC 7009).

O usuário entra com e-mail, senha e segundo fator (com os mesmos limites de tentativa do painel) e escolhe
o nível de acesso: leitura (papel leitor) ou leitura e ação (papel analista, se ele tiver esse papel).
Nunca mais do que analista: administração de usuários e chaves fica fora do alcance do conector.
Não há cookie de sessão nesta tela, então não existe autoridade ambiente para um site forjar o consentimento.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import ROLES, OAuthClient, OAuthCode, OAuthGrant, Organization, User, utcnow

ACCESS_PREFIX = "atm_"
REFRESH_PREFIX = "atr_"
SCOPES = {"atalaia:read": "viewer", "atalaia:write": "analyst"}
CODE_TTL = 120
MAX_REDIRECT_URIS = 10
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(default=True, default_for_string=True))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def public_base(settings, request: Request) -> str:
    if settings.public_url:
        return settings.public_url
    return f"{request.url.scheme}://{request.headers.get('host') or request.url.netloc}"


def resource_metadata_url(base: str) -> str:
    return f"{base}/.well-known/oauth-protected-resource/mcp"


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def valid_redirect_uri(uri: str) -> bool:
    """https em qualquer lugar; http só em loopback (aplicativos nativos); nada de fragmento."""
    if not isinstance(uri, str) or len(uri) > 2000 or any(c in uri for c in "\r\n\x00 "):
        return False
    parts = urlsplit(uri)
    if parts.fragment or not parts.hostname or parts.username or parts.password:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and _loopback(parts.hostname))


def _origin(uri: str) -> str:
    p = urlsplit(uri)
    return f"{p.scheme}://{p.netloc}"


def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    if status == 401:
        headers["WWW-Authenticate"] = 'Basic realm="atalaia"'
    return JSONResponse({"error": error, "error_description": description}, status_code=status, headers=headers)


async def _form(request: Request) -> dict[str, str]:
    """Corpo application/x-www-form-urlencoded sem depender de python-multipart. Parâmetro repetido é
    erro (RFC 6749 3.1), então devolvemos None nesse caso."""
    body = await request.body()
    if len(body) > 16_384:
        return {"__error__": "corpo muito grande"}
    try:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
    except UnicodeDecodeError:
        return {"__error__": "codificação inválida"}
    out = {}
    for k, v in parsed.items():
        if len(v) > 1:
            return {"__error__": f"parâmetro repetido: {k}"}
        out[k] = v[0]
    return out


def install(app: FastAPI, *, settings, get_db: Callable, authenticate: Callable, auth_failure: type,
            client_ip: Callable, register_throttle) -> None:
    """Registra as rotas OAuth no app da API."""

    # ------------------------------------------------------------ metadados
    def as_metadata(base: str) -> dict:
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "revocation_endpoint": f"{base}/oauth/revoke",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "scopes_supported": list(SCOPES),
            "authorization_response_iss_parameter_supported": True,
            "service_documentation": f"{base}/",
        }

    def pr_metadata(base: str) -> dict:
        return {"resource": f"{base}/mcp", "authorization_servers": [base], "scopes_supported": list(SCOPES),
                "bearer_methods_supported": ["header"], "resource_name": "Atalaia"}

    @app.get("/.well-known/oauth-authorization-server", include_in_schema=False)
    @app.get("/.well-known/oauth-authorization-server/{_rest:path}", include_in_schema=False)
    @app.get("/.well-known/openid-configuration", include_in_schema=False)
    def as_meta(request: Request, _rest: str = ""):
        return JSONResponse(as_metadata(public_base(settings, request)), headers={"Cache-Control": "max-age=300"})

    @app.get("/.well-known/oauth-protected-resource", include_in_schema=False)
    @app.get("/.well-known/oauth-protected-resource/{_rest:path}", include_in_schema=False)
    def pr_meta(request: Request, _rest: str = ""):
        return JSONResponse(pr_metadata(public_base(settings, request)), headers={"Cache-Control": "max-age=300"})

    # ------------------------------------------------------------ registro dinâmico
    @app.post("/oauth/register", include_in_schema=False)
    async def register(request: Request):
        ip = client_ip(request)
        if register_throttle.blocked(f"oauth:{ip}"):
            return _oauth_error("slow_down", "Muitos registros a partir deste endereço. Tente mais tarde.", 429)
        try:
            meta = await request.json()
        except ValueError:
            return _oauth_error("invalid_client_metadata", "Envie os metadados do cliente em JSON.")
        if not isinstance(meta, dict):
            return _oauth_error("invalid_client_metadata", "Metadados inválidos.")
        uris = meta.get("redirect_uris")
        if not isinstance(uris, list) or not uris or len(uris) > MAX_REDIRECT_URIS:
            return _oauth_error("invalid_redirect_uri", f"Informe de 1 a {MAX_REDIRECT_URIS} redirect_uris.")
        if not all(valid_redirect_uri(u) for u in uris):
            return _oauth_error("invalid_redirect_uri", "redirect_uri precisa ser https (ou http em loopback) "
                                                        "e não pode ter fragmento.")
        grants = meta.get("grant_types") or ["authorization_code", "refresh_token"]
        if not isinstance(grants, list) or not set(grants) <= {"authorization_code", "refresh_token"}:
            return _oauth_error("invalid_client_metadata", "grant_types suportados: authorization_code, refresh_token.")
        if (meta.get("response_types") or ["code"]) != ["code"]:
            return _oauth_error("invalid_client_metadata", "response_types suportado: code.")
        method = meta.get("token_endpoint_auth_method") or "none"
        if method not in ("none", "client_secret_post", "client_secret_basic"):
            return _oauth_error("invalid_client_metadata", "token_endpoint_auth_method não suportado.")
        name = str(meta.get("client_name") or "Aplicativo sem nome").strip()[:100] or "Aplicativo sem nome"
        register_throttle.fail(f"oauth:{ip}")
        client_id = "atc_" + secrets.token_urlsafe(24)
        secret = "ats_" + secrets.token_urlsafe(32) if method != "none" else None
        with app.state.session_factory() as db:
            db.add(OAuthClient(id=client_id, name=name, redirect_uris=list(uris), created_ip=ip[:64],
                               secret_hash=token_hash(secret) if secret else None))
            db.commit()
        out = {"client_id": client_id, "client_id_issued_at": int(utcnow().timestamp()), "client_name": name,
               "redirect_uris": uris, "grant_types": grants, "response_types": ["code"],
               "token_endpoint_auth_method": method}
        if secret:
            out.update(client_secret=secret, client_secret_expires_at=0)
        return JSONResponse(out, status_code=201, headers={"Cache-Control": "no-store"})

    # ------------------------------------------------------------ autorização
    class BadRequest(Exception):
        """Erro que não pode voltar ao cliente por redirecionamento (cliente ou redirect_uri inválidos)."""

    def load_request(db: Session, params: dict, base: str) -> tuple[OAuthClient, dict]:
        client = db.get(OAuthClient, params.get("client_id", "")[:64]) if params.get("client_id") else None
        if client is None:
            raise BadRequest("Aplicativo desconhecido. Remova o conector e adicione-o de novo.")
        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri not in client.redirect_uris:
            raise BadRequest("O endereço de retorno não corresponde ao que o aplicativo registrou.")
        req = {"client_id": client.id, "redirect_uri": redirect_uri, "state": params.get("state", "")[:2000],
               "code_challenge": params.get("code_challenge", ""),
               "code_challenge_method": params.get("code_challenge_method", ""),
               "scope": params.get("scope", ""), "resource": params.get("resource", ""),
               "response_type": params.get("response_type", "")}
        return client, req

    def redirect_error(req: dict, base: str, error: str, description: str) -> RedirectResponse:
        q = {"error": error, "error_description": description, "iss": base}
        if req["state"]:
            q["state"] = req["state"]
        return RedirectResponse(f"{req['redirect_uri']}{'&' if '?' in req['redirect_uri'] else '?'}{urlencode(q)}",
                                status_code=302)

    def validate(req: dict, base: str) -> tuple[str, str] | None:
        """Erros devolvidos ao cliente pelo redirect_uri (já validado)."""
        if req["response_type"] != "code":
            return "unsupported_response_type", "Apenas response_type=code."
        if req["code_challenge_method"] != "S256" or not (43 <= len(req["code_challenge"]) <= 128):
            return "invalid_request", "PKCE com code_challenge_method=S256 é obrigatório."
        scopes = req["scope"].split() if req["scope"] else list(SCOPES)
        if not set(scopes) <= set(SCOPES):
            return "invalid_scope", f"Escopos suportados: {', '.join(SCOPES)}."
        if req["resource"] and req["resource"].rstrip("/") not in (f"{base}/mcp", base):
            return "invalid_target", "Este servidor só emite tokens para o próprio MCP."
        return None

    def page(client: OAuthClient, req: dict, base: str, *, error: str = "", email: str = "",
             need_code: bool = False, status: int = 200) -> HTMLResponse:
        scopes = req["scope"].split() if req["scope"] else list(SCOPES)
        html = _env.get_template("oauth_authorize.html").render(
            client_name=client.name, redirect_host=urlsplit(req["redirect_uri"]).netloc, req=req, error=error,
            email=email, need_code=need_code, can_write="atalaia:write" in scopes, base=base)
        resp = HTMLResponse(html, status_code=status)
        # form-action precisa incluir a origem do retorno: o navegador aplica a diretiva ao
        # redirecionamento que segue o envio do formulário.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
            f"form-action 'self' {_origin(req['redirect_uri'])}")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def error_page(message: str) -> HTMLResponse:
        html = _env.get_template("oauth_authorize.html").render(fatal=message)
        return HTMLResponse(html, status_code=400, headers={"Cache-Control": "no-store"})

    @app.get("/oauth/authorize", include_in_schema=False)
    def authorize_get(request: Request):
        base = public_base(settings, request)
        params = {k: v for k, v in request.query_params.items()}
        with app.state.session_factory() as db:
            try:
                client, req = load_request(db, params, base)
            except BadRequest as exc:
                return error_page(str(exc))
        problem = validate(req, base)
        if problem:
            return redirect_error(req, base, *problem)
        return page(client, req, base)

    @app.post("/oauth/authorize", include_in_schema=False)
    async def authorize_post(request: Request):
        base = public_base(settings, request)
        form = await _form(request)
        if "__error__" in form:
            return error_page("Requisição inválida.")
        ip = client_ip(request)
        with app.state.session_factory() as db:
            try:
                client, req = load_request(db, form, base)
            except BadRequest as exc:
                return error_page(str(exc))
            problem = validate(req, base)
            if problem:
                return redirect_error(req, base, *problem)
            if form.get("action") == "deny":
                return redirect_error(req, base, "access_denied", "O usuário recusou o acesso.")
            email = form.get("email", "")[:320]
            try:
                user = authenticate(db, email, form.get("password", "")[:256], form.get("code", "")[:32], ip,
                                    via=f"oauth:{client.name}")
            except auth_failure as exc:
                return page(client, req, base, error=exc.message, email=email,
                            need_code=exc.mfa_required or bool(form.get("code")), status=exc.status)
            org = db.get(Organization, user.org_id)
            if org.require_mfa and not user.mfa_enabled:
                db.commit()
                return page(client, req, base, email=email, status=403,
                            error="Sua organização exige verificação em duas etapas. Ative-a no painel antes de "
                                  "conectar aplicativos.")
            requested = req["scope"].split() if req["scope"] else list(SCOPES)
            want_write = form.get("access") == "write" and "atalaia:write" in requested
            if want_write and ROLE_RANK[user.role] < ROLE_RANK["analyst"]:
                db.commit()
                return page(client, req, base, email=email, status=403,
                            error="Seu papel é leitor: escolha o acesso somente leitura.")
            role = "analyst" if want_write else "viewer"
            scope = "atalaia:read atalaia:write" if want_write else "atalaia:read"
            code = secrets.token_urlsafe(32)
            db.query(OAuthCode).filter(OAuthCode.expires_at < utcnow() - timedelta(days=1)).delete(
                synchronize_session=False)                         # limpeza de códigos antigos
            db.add(OAuthCode(code_hash=token_hash(code), client_id=client.id, user_id=user.id, org_id=user.org_id,
                             role=role, scope=scope, redirect_uri=req["redirect_uri"],
                             code_challenge=req["code_challenge"], resource=req["resource"],
                             expires_at=utcnow() + timedelta(seconds=CODE_TTL)))
            audit.record(db, org_id=user.org_id, actor=user.email, action="oauth.authorize",
                         resource_type="oauth_client", resource_id=client.id, ip=ip,
                         details={"client": client.name, "role": role, "redirect": urlsplit(req["redirect_uri"]).netloc})
            db.commit()
        q = {"code": code, "iss": base}
        if req["state"]:
            q["state"] = req["state"]
        sep = "&" if "?" in req["redirect_uri"] else "?"
        return RedirectResponse(f"{req['redirect_uri']}{sep}{urlencode(q)}", status_code=302)

    # ------------------------------------------------------------ token
    def client_auth(db: Session, request: Request, form: dict) -> OAuthClient | None:
        client_id, secret = form.get("client_id", ""), form.get("client_secret", "")
        auth = request.headers.get("authorization", "")
        if auth[:6].lower() == "basic ":
            try:
                from urllib.parse import unquote
                cid, _, sec = base64.b64decode(auth[6:]).decode().partition(":")
                client_id, secret = unquote(cid), unquote(sec)
            except (ValueError, UnicodeDecodeError):
                return None
        client = db.get(OAuthClient, client_id[:64]) if client_id else None
        if client is None:
            return None
        if client.secret_hash:
            if not secret or not hmac.compare_digest(client.secret_hash, token_hash(secret)):
                return None
        return client

    def issue(db: Session, grant: OAuthGrant) -> dict:
        access, refresh = ACCESS_PREFIX + secrets.token_urlsafe(32), REFRESH_PREFIX + secrets.token_urlsafe(32)
        now = utcnow()
        grant.access_hash, grant.access_expires_at = token_hash(access), now + timedelta(seconds=settings.oauth_access_ttl)
        grant.prev_refresh_hash = grant.refresh_hash
        grant.refresh_hash = token_hash(refresh)
        grant.refresh_expires_at = now + timedelta(days=settings.oauth_refresh_ttl_days)
        grant.last_used_at = now
        return {"access_token": access, "token_type": "Bearer", "expires_in": settings.oauth_access_ttl,
                "refresh_token": refresh, "scope": grant.scope}

    def revoke_grant(db: Session, grant: OAuthGrant, ip: str, reason: str) -> None:
        if not grant.revoked_at:
            grant.revoked_at = utcnow()
            grant.access_hash = grant.refresh_hash = None
            audit.record(db, org_id=grant.org_id, actor=f"oauth:{grant.client_name}", action="oauth.revoke",
                         resource_type="oauth_grant", resource_id=grant.id, ip=ip, details={"reason": reason})

    @app.post("/oauth/token", include_in_schema=False)
    async def token(request: Request):
        form = await _form(request)
        if "__error__" in form:
            return _oauth_error("invalid_request", form["__error__"])
        ip = client_ip(request)
        no_store = {"Cache-Control": "no-store", "Pragma": "no-cache"}
        with app.state.session_factory() as db:
            client = client_auth(db, request, form)
            if client is None:
                return _oauth_error("invalid_client", "Cliente desconhecido ou credencial incorreta.", 401)
            gt = form.get("grant_type")
            if gt == "authorization_code":
                row = db.get(OAuthCode, token_hash(form.get("code", ""))) if form.get("code") else None
                if row is None or row.client_id != client.id:
                    return _oauth_error("invalid_grant", "Código inválido.")
                if row.used_at:
                    # Código reapresentado: alguém pode tê-lo interceptado. Revoga o que foi emitido com ele.
                    grant = db.get(OAuthGrant, row.grant_id) if row.grant_id else None
                    if grant:
                        revoke_grant(db, grant, ip, "authorization code reused")
                    db.commit()
                    return _oauth_error("invalid_grant", "Código já utilizado.")
                if row.expires_at < utcnow():
                    return _oauth_error("invalid_grant", "Código expirado.")
                if form.get("redirect_uri", row.redirect_uri) != row.redirect_uri:
                    return _oauth_error("invalid_grant", "redirect_uri diferente do usado na autorização.")
                verifier = form.get("code_verifier", "")
                if not (43 <= len(verifier) <= 128) or not hmac.compare_digest(_s256(verifier), row.code_challenge):
                    return _oauth_error("invalid_grant", "code_verifier não confere (PKCE).")
                resource = form.get("resource", "")
                if resource and row.resource and resource.rstrip("/") != row.resource.rstrip("/"):
                    return _oauth_error("invalid_target", "resource diferente do autorizado.")
                user = db.get(User, row.user_id)
                if not user or not user.is_active:
                    return _oauth_error("invalid_grant", "Usuário inativo.")
                row.used_at = utcnow()
                grant = OAuthGrant(org_id=row.org_id, user_id=row.user_id, client_id=client.id,
                                   client_name=client.name, role=row.role, scope=row.scope,
                                   resource=row.resource or resource, user_token_version=user.token_version)
                db.add(grant)
                db.flush()
                row.grant_id = grant.id
                out = issue(db, grant)
                audit.record(db, org_id=grant.org_id, actor=user.email, action="oauth.token",
                             resource_type="oauth_grant", resource_id=grant.id, ip=ip,
                             details={"client": client.name, "role": grant.role})
                db.commit()
                return JSONResponse(out, headers=no_store)
            if gt == "refresh_token":
                presented = token_hash(form.get("refresh_token", "")) if form.get("refresh_token") else ""
                grant = db.execute(select(OAuthGrant).where(OAuthGrant.refresh_hash == presented)).scalar_one_or_none() \
                    if presented else None
                if grant is None and presented:
                    old = db.execute(select(OAuthGrant).where(OAuthGrant.prev_refresh_hash == presented)
                                     ).scalar_one_or_none()
                    if old:                                     # token de renovação antigo: possível roubo
                        revoke_grant(db, old, ip, "refresh token reused")
                        db.commit()
                    return _oauth_error("invalid_grant", "Token de renovação inválido.")
                if grant is None or grant.client_id != client.id or grant.revoked_at:
                    return _oauth_error("invalid_grant", "Token de renovação inválido.")
                if grant.refresh_expires_at < utcnow():
                    return _oauth_error("invalid_grant", "Token de renovação expirado. Conecte de novo.")
                user = db.get(User, grant.user_id)
                if not user or not user.is_active or user.token_version != grant.user_token_version:
                    revoke_grant(db, grant, ip, "user changed")
                    db.commit()
                    return _oauth_error("invalid_grant", "A conta mudou (senha, papel ou acesso). Conecte de novo.")
                if ROLE_RANK[user.role] < ROLE_RANK[grant.role]:
                    grant.role, grant.scope = "viewer", "atalaia:read"
                out = issue(db, grant)
                db.commit()
                return JSONResponse(out, headers=no_store)
            return _oauth_error("unsupported_grant_type", "grant_type suportados: authorization_code, refresh_token.")

    @app.post("/oauth/revoke", include_in_schema=False)
    async def revoke(request: Request):
        form = await _form(request)
        tok = form.get("token", "")
        with app.state.session_factory() as db:
            client = client_auth(db, request, form)
            if client is None:
                return _oauth_error("invalid_client", "Cliente desconhecido ou credencial incorreta.", 401)
            if tok:
                h = token_hash(tok)
                grant = db.execute(select(OAuthGrant).where(
                    (OAuthGrant.access_hash == h) | (OAuthGrant.refresh_hash == h)
                    | (OAuthGrant.prev_refresh_hash == h))).scalar_one_or_none()
                if grant and grant.client_id == client.id:
                    revoke_grant(db, grant, client_ip(request), "revoked by client")
                    db.commit()
        return Response(status_code=200, headers={"Cache-Control": "no-store"})

    app.state.oauth_revoke_grant = revoke_grant


def principal_for_access_token(db: Session, token: str):
    """Valida um token de acesso OAuth. Devolve (grant, user) ou None."""
    grant = db.execute(select(OAuthGrant).where(OAuthGrant.access_hash == token_hash(token))).scalar_one_or_none()
    if grant is None or grant.revoked_at or not grant.access_expires_at or grant.access_expires_at < utcnow():
        return None
    user = db.get(User, grant.user_id)
    if not user or not user.is_active or user.token_version != grant.user_token_version:
        return None
    return grant, user
