"""Demonstração local: sobe o Atalaia e um alvo deliberadamente vulnerável, tudo em 127.0.0.1.

    python demo.py

Cria uma organização de demonstração, cadastra o alvo local, comprova a propriedade
(o próprio script publica o arquivo de verificação no alvo) e dispara a primeira varredura.
Nada sai da sua máquina: os dois servidores escutam apenas em 127.0.0.1.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from atalaia.api.app import create_app
from atalaia.config import Settings
from tests.vulnapp import make_vulnerable_app

HOST = "127.0.0.1"
PORT = int(os.environ.get("ATALAIA_DEMO_PORT", "8000"))
TARGET_PORT = int(os.environ.get("ATALAIA_DEMO_TARGET_PORT", "8901"))
EMAIL = "demo@atalaia.local"
PASSWORD = "Atalaia-Demo-Local-2026"
DB = Path(__file__).resolve().parent / "demo.db"


def serve_target(state: dict) -> None:
    server = uvicorn.Server(uvicorn.Config(make_vulnerable_app(state), host=HOST, port=TARGET_PORT,
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True, name="demo-target").start()


def bootstrap(state: dict) -> None:
    base = f"http://{HOST}:{PORT}"
    api = base + "/api/v1"
    with httpx.Client(timeout=30, trust_env=False) as http:
        for _ in range(100):
            try:
                if http.get(base + "/healthz").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        r = http.post(api + "/auth/register", json={"organization": "Empresa Demo", "name": "Demo",
                                                    "email": EMAIL, "password": PASSWORD})
        if r.status_code != 201:
            print("Não foi possível criar a conta de demonstração:", r.text)
            return
        auth = {"Authorization": "Bearer " + r.json()["token"]}
        target = http.post(api + "/targets", headers=auth, json={
            "name": "Loja de demonstração (vulnerável)", "base_url": f"http://{HOST}:{TARGET_PORT}"}).json()
        state["token"] = target["verification"]["http_file"]["content"]
        http.post(f"{api}/targets/{target['id']}/verify", headers=auth, json={"method": "http_file"})
        http.post(api + "/scans", headers=auth, json={"target_id": target["id"], "profile": "full"})
    print("\n" + "=" * 64)
    print(f"  Atalaia rodando em   {base}")
    print(f"  E-mail               {EMAIL}")
    print(f"  Senha                {PASSWORD}")
    print(f"  Alvo de demonstração http://{HOST}:{TARGET_PORT} (varredura já iniciada)")
    print("  Ctrl+C para encerrar")
    print("=" * 64 + "\n")


def main() -> None:
    for leftover in DB.parent.glob("demo.db*"):
        leftover.unlink()
    settings = Settings(database_url=f"sqlite:///{DB}", secret_key=secrets.token_urlsafe(48),
                        allow_private_targets=True, default_rps=50, max_rps=50)
    state: dict = {}
    serve_target(state)
    threading.Thread(target=bootstrap, args=(state,), daemon=True, name="demo-bootstrap").start()
    uvicorn.run(create_app(settings), host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
