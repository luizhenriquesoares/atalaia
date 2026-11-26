#!/usr/bin/env bash
# Sobe a demonstração local do Atalaia em http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")/.."

PY=""
for candidate in python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && \
     "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    PY="$candidate"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "Python 3.11 ou mais novo não encontrado. No macOS: brew install python@3.13" >&2
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv
fi
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet ".[demo]"

# Navegador real (Chromium) para renderizar JavaScript e comprovar XSS por execução.
# Para pular: ATALAIA_DEMO_BROWSER=off ./scripts/run-demo.sh
if [ "${ATALAIA_DEMO_BROWSER:-on}" != "off" ]; then
  echo "Preparando o Chromium (na primeira vez baixa cerca de 150 MB)..."
  if ! { .venv/bin/python -m pip install --quiet ".[browser]" && .venv/bin/python -m playwright install chromium; }; then
    echo "Não foi possível preparar o navegador. A demonstração segue sem ele." >&2
  fi
fi
exec .venv/bin/python demo.py
