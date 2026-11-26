"""Deliberately vulnerable and deliberately hardened apps used as scan targets in tests.

They only ever listen on 127.0.0.1 during the test run.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import tempfile

from jinja2 import Template
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route


def _db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT)")
    db.executemany("INSERT INTO products VALUES (?, ?, ?)",
                   [(1, "Teclado", "hardware"), (2, "Mouse", "hardware"), (3, "Monitor", "telas")])
    return db


def make_jwt(secret: str, claims: dict | None = None) -> str:
    def enc(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    head = enc(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = enc(json.dumps(claims or {"sub": "42", "role": "user"}).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{enc(sig)}"


def make_vulnerable_app(state: dict) -> Starlette:
    """state: {'token': verification token, 'hits': {...counters...}}"""
    db = _db()
    hits = state.setdefault("hits", {})
    docs = tempfile.mkdtemp(prefix="atl-docs-")
    with open(os.path.join(docs, "readme.txt"), "w") as fh:
        fh.write("Manual do produto")

    def count(name):
        hits[name] = hits.get(name, 0) + 1

    def page(body: str, status=200, headers=None) -> HTMLResponse:
        h = {"X-Powered-By": "PHP/5.6.40"}
        h.update(headers or {})
        return HTMLResponse(f"<html><head><title>Loja</title></head><body>{body}</body></html>",
                            status_code=status, headers=h)

    async def index(request):
        count("index")
        origin = request.headers.get("origin")
        headers = {}
        if origin:
            headers = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
        public_host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        resp = page(f'<link rel="canonical" href="http://{public_host}/">' + """
            <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
            <h1>Loja</h1>
            <a href="/spa?msg=oi">Novidades</a> <a href="/comments">Comentários</a>
            <a href="/account?sessionid=abcdef1234567890abcd">Minha conta</a>
            <a href="/search?q=teclado">Busca</a> <a href="/attr?name=ana">Perfil</a>
            <a href="/product?id=1">Produto</a> <a href="/item?id=1">Item</a>
            <a href="/redirect?next=/">Voltar</a> <a href="/download?file=readme.txt">Manual</a>
            <a href="/greet?name=ana">Saudação</a> <a href="/safe?q=ola">Seguro</a>
            <a href="/files/">Arquivos</a> <a href="/debug">Debug</a> <a href="/aws">Config</a>
            <a href="/logout">Sair</a> <a href="/account/delete?id=7">Excluir conta</a>
            <a href="https://outro-site.example/pagina">Externo</a>
            <form method="post" action="/login"><input name="user"><input type="password" name="pass">
              <input type="submit"></form>
            <form method="post" action="/comment"><textarea name="text"></textarea>
              <input type="submit"></form>
            <form method="post" action="/delete-account"><input name="reason"><input type="submit"></form>
        """, headers=headers)
        resp.set_cookie("sessionid", "abc123")
        resp.set_cookie("auth_token", make_jwt("secret"), httponly=True)
        return resp

    async def spa(request):
        return page("""<h1>Novidades</h1><div id="m"></div><div id="h"></div><ul id="list"></ul><div id="nav"></div>
            <script>
              const p = new URLSearchParams(location.search);
              document.getElementById('m').innerHTML = p.get('msg') || '';
              if (location.hash.length > 1)
                document.getElementById('h').innerHTML = decodeURIComponent(location.hash.slice(1));
              fetch('/api/products?category=hardware').then(r => r.json()).then(items => {
                document.getElementById('list').innerHTML = items.map(i => '<li>' + i.name + '</li>').join('');
              });
              fetch('/api/search', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({term: 'teclado', limit: 5})});
              document.getElementById('nav').innerHTML = '<a href="/hidden?q=ola">Oculto</a>';
            </script>""" + (f'<script src="{state["third_party"]}"></script>' if state.get("third_party") else ""))

    async def api_products(request):
        category = request.query_params.get("category", "")
        try:
            rows = db.execute(f"SELECT id, name FROM products WHERE category = '{category}'").fetchall()
        except sqlite3.Error as exc:
            return JSONResponse({"error": f"sqlite3.OperationalError: {exc}"}, status_code=500)
        return JSONResponse([{"id": r[0], "name": r[1]} for r in rows])

    async def api_search(request):
        count("api_search_post")
        try:
            term = (await request.json()).get("term", "")
            rows = db.execute(f"SELECT id, name FROM products WHERE name LIKE '%{term}%'").fetchall()
        except sqlite3.Error as exc:
            return JSONResponse({"error": f"sqlite3.OperationalError: {exc}"}, status_code=500)
        except Exception:
            return JSONResponse({"error": "bad request"}, status_code=400)
        return JSONResponse([{"id": r[0], "name": r[1]} for r in rows])

    async def hidden(request):
        return page(f"<p>Área oculta: {request.query_params.get('q', '')}</p>")

    async def comments(request):
        items = "".join(f"<li>{c}</li>" for c in state.setdefault("comments", [])[-50:])
        return page(f"<h2>Comentários</h2><ul>{items}</ul>")

    async def account(request):
        return page("<h2>Minha conta</h2>")

    async def search(request):
        q = request.query_params.get("q", "")
        return page(f"<p>Resultados para: {q}</p>")

    async def attr(request):
        name = request.query_params.get("name", "").replace("<", "&lt;").replace(">", "&gt;")
        return page(f'<input type="text" value="{name}">')

    async def product(request):
        pid = request.query_params.get("id", "")
        try:
            row = db.execute(f"SELECT name FROM products WHERE id = '{pid}'").fetchone()
        except sqlite3.Error as exc:
            return page(f"<pre>sqlite3.OperationalError: {html.escape(str(exc))}</pre>", status=500)
        return page(f"<h2>{row[0] if row else 'Produto não encontrado'}</h2>")

    async def item(request):
        iid = request.query_params.get("id", "")
        try:
            row = db.execute(f"SELECT name FROM products WHERE id = {iid}").fetchone()
        except sqlite3.Error:
            return page("<h2>Erro</h2>")
        if not row:
            return page("<h2>Item inexistente</h2><p>Nada encontrado, tente outra busca no catálogo.</p>")
        return page(f"<h2>{row[0]}</h2><p>Em estoque, envio imediato para todo o Brasil com garantia.</p>")

    async def redirect(request):
        return RedirectResponse(request.query_params.get("next", "/"), status_code=302)

    async def download(request):
        name = request.query_params.get("file", "")
        try:
            with open(os.path.join(docs, name)) as fh:
                return PlainTextResponse(fh.read())
        except OSError:
            return PlainTextResponse("arquivo não encontrado", status_code=404)

    async def greet(request):
        name = request.query_params.get("name", "")
        try:
            return page(Template(f"<p>Olá {name}!</p>").render())
        except Exception:
            return page("<p>erro</p>", status=500)

    async def safe(request):
        return page(f"<p>Você buscou: {html.escape(request.query_params.get('q', ''))}</p>")

    async def files(request):
        return HTMLResponse("<html><head><title>Index of /files/</title></head><body>"
                            "<a href='notas.txt'>notas.txt</a></body></html>")

    async def debug(request):
        return page("<pre>Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 10\n"
                    "KeyError: 'user' on host 10.1.2.3</pre>", status=500)

    async def aws(request):
        return page("<script>var cfg = {key: 'AKIAIOSFODNN7EXAMPLE'};</script>")

    async def logout(request):
        count("logout")
        return page("bye")

    async def account_delete(request):
        count("account_delete")
        return page("deleted")

    async def delete_account(request):
        count("delete_account_post")
        return page("deleted")

    async def comment(request):
        count("comment_post")
        form = await request.form()
        state.setdefault("comments", []).append(str(form.get("text", "")))
        return page(f"<p>Comentário: {form.get('text', '')}</p>")

    async def login(request):
        count("login_post")
        return page("login")

    async def git_head(request):
        return PlainTextResponse("ref: refs/heads/main\n")

    async def env(request):
        return PlainTextResponse("DB_PASSWORD=supersecreta123\nSECRET_KEY=chave-muito-secreta\nDEBUG=true\n")

    async def backup(request):
        return PlainTextResponse("CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n")

    async def graphql(request):
        return JSONResponse({"data": {"__schema": {"queryType": {"name": "Query"}}}})

    async def verification(request):
        if not state.get("token"):
            return PlainTextResponse("not found", status_code=404)
        return PlainTextResponse(state["token"])

    async def trace(request):
        if request.method == "TRACE":
            return PlainTextResponse("\n".join(f"{k}: {v}" for k, v in request.headers.items()))
        return Response(status_code=405)

    return Starlette(routes=[
        Route("/", index), Route("/search", search), Route("/attr", attr), Route("/product", product),
        Route("/item", item), Route("/redirect", redirect), Route("/download", download),
        Route("/greet", greet), Route("/safe", safe), Route("/files/", files), Route("/debug", debug),
        Route("/aws", aws), Route("/logout", logout), Route("/account/delete", account_delete),
        Route("/delete-account", delete_account, methods=["POST"]),
        Route("/comment", comment, methods=["POST"]), Route("/login", login, methods=["POST"]),
        Route("/.git/HEAD", git_head), Route("/.env", env), Route("/backup.sql", backup),
        Route("/graphql", graphql, methods=["POST"]),
        Route("/.well-known/atalaia-verification.txt", verification),
        Route("/spa", spa), Route("/api/products", api_products),
        Route("/api/search", api_search, methods=["POST"]), Route("/hidden", hidden),
        Route("/comments", comments), Route("/account", account),
    ])


SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def make_secure_app(state: dict) -> Starlette:
    db = _db()
    jwt_secret = secrets.token_urlsafe(48)
    stored: list[str] = []

    def page(body: str, status=200) -> HTMLResponse:
        return HTMLResponse(f"<html><head><title>Loja</title></head><body>{body}</body></html>",
                            status_code=status, headers=SECURE_HEADERS)

    async def index(request):
        resp = page("""<h1>Loja segura</h1><link rel="canonical" href="/">
            <a href="/spa?msg=oi">Novidades</a> <a href="/comments">Comentários</a>
            <a href="/search?q=teclado">Busca</a> <a href="/product?id=1">Produto</a>
            <a href="/redirect?next=/search">Ir</a> <a href="/download?file=readme.txt">Manual</a>
            <a href="/greet?name=ana">Saudação</a> <a href="/attr?name=ana">Perfil</a>
            <form method="post" action="/comment"><input type="hidden" name="csrf_token" value="x1">
              <textarea name="text"></textarea><input type="submit"></form>""")
        resp.set_cookie("sessionid", "abc", httponly=True, samesite="lax")
        resp.set_cookie("auth_token", make_jwt(jwt_secret), httponly=True, samesite="lax")
        return resp

    async def spa(request):
        return page('<h1>Novidades</h1><div id="m"></div><div id="h"></div><ul id="list"></ul>'
                    '<div id="nav"></div><script src="/static/app.js"></script>')

    async def app_js(request):
        return Response("""
            const p = new URLSearchParams(location.search);
            document.getElementById('m').textContent = p.get('msg') || '';
            if (location.hash.length > 1)
              document.getElementById('h').textContent = decodeURIComponent(location.hash.slice(1));
            fetch('/api/products?category=hardware').then(r => r.json()).then(items => {
              const list = document.getElementById('list');
              for (const i of items) { const li = document.createElement('li'); li.textContent = i.name; list.append(li); }
            });
            fetch('/api/search', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                  body: JSON.stringify({term: 'teclado', limit: 5})});
            const a = document.createElement('a'); a.href = '/hidden?q=ola'; a.textContent = 'Oculto';
            document.getElementById('nav').append(a);
        """, media_type="application/javascript", headers=SECURE_HEADERS)

    async def api_products(request):
        rows = db.execute("SELECT id, name FROM products WHERE category = ?",
                          (request.query_params.get("category", ""),)).fetchall()
        return JSONResponse([{"id": r[0], "name": r[1]} for r in rows], headers=SECURE_HEADERS)

    async def api_search(request):
        try:
            term = str((await request.json()).get("term", ""))
        except Exception:
            return JSONResponse({"error": "bad request"}, status_code=400, headers=SECURE_HEADERS)
        rows = db.execute("SELECT id, name FROM products WHERE name LIKE ?", (f"%{term}%",)).fetchall()
        return JSONResponse([{"id": r[0], "name": r[1]} for r in rows], headers=SECURE_HEADERS)

    async def hidden(request):
        return page(f"<p>Área oculta: {html.escape(request.query_params.get('q', ''))}</p>")

    async def comments(request):
        items = "".join(f"<li>{html.escape(c)}</li>" for c in stored[-50:])
        return page(f"<h2>Comentários</h2><ul>{items}</ul>")

    async def search(request):
        return page(f"<p>Resultados para: {html.escape(request.query_params.get('q', ''))}</p>")

    async def attr(request):
        return page(f'<input value="{html.escape(request.query_params.get("name", ""), quote=True)}">')

    async def product(request):
        row = db.execute("SELECT name FROM products WHERE id = ?", (request.query_params.get("id", ""),)).fetchone()
        return page(f"<h2>{html.escape(row[0]) if row else 'Produto não encontrado'}</h2>",
                    status=200 if row else 404)

    async def redirect(request):
        nxt = request.query_params.get("next", "/")
        if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
            nxt = "/"
        return RedirectResponse(nxt, status_code=302, headers=SECURE_HEADERS)

    async def download(request):
        if request.query_params.get("file") == "readme.txt":
            return PlainTextResponse("Manual do produto", headers=SECURE_HEADERS)
        return PlainTextResponse("arquivo não encontrado", status_code=404, headers=SECURE_HEADERS)

    async def greet(request):
        return page(Template("<p>Olá {{ name }}!</p>", autoescape=True).render(
            name=request.query_params.get("name", "")))

    async def comment(request):
        form = await request.form()
        stored.append(str(form.get("text", "")))
        return page(f"<p>{html.escape(str(form.get('text', '')))}</p>")

    async def security_txt(request):
        return PlainTextResponse("Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n")

    async def verification(request):
        return PlainTextResponse(state.get("token") or "", status_code=200 if state.get("token") else 404)

    return Starlette(routes=[
        Route("/", index), Route("/search", search), Route("/attr", attr), Route("/product", product),
        Route("/redirect", redirect), Route("/download", download), Route("/greet", greet),
        Route("/comment", comment, methods=["POST"]),
        Route("/.well-known/security.txt", security_txt),
        Route("/.well-known/atalaia-verification.txt", verification),
        Route("/spa", spa), Route("/static/app.js", app_js), Route("/api/products", api_products),
        Route("/api/search", api_search, methods=["POST"]), Route("/hidden", hidden),
        Route("/comments", comments),
    ])
