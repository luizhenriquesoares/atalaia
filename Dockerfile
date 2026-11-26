FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
WORKDIR /app
COPY pyproject.toml ./
COPY atalaia ./atalaia
# Chromium (with its system libraries) renders JavaScript and proves XSS by execution. To build a
# smaller image without it, drop ",browser" and the "playwright install" line: scans still run and
# report that the browser was unavailable.
# libatomic1: needed by the Node runtime bundled with Playwright, absent from the slim image.
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
    && pip install --no-cache-dir ".[postgres,browser,mcp]" \
    && python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home atalaia && mkdir /data && chown atalaia /data
USER atalaia
ENV ATALAIA_DATABASE_URL=sqlite:////data/atalaia.db ATALAIA_REQUIRE_SECRET=true
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
# By default this process serves the API and also executes scans. To scale out, set
# ATALAIA_EMBEDDED_WORKER=false here and run "python -m atalaia.worker" in other containers.
CMD ["uvicorn", "atalaia.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
