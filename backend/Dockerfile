# Build context is the repo root so the scanner package can be installed alongside.
FROM python:3.12-slim
WORKDIR /srv
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY scanner/ scanner/
RUN pip install --no-cache-dir ./scanner
COPY backend/app/ backend/app/
COPY sample-repos/ sample-repos/
# Non-root runtime user; /data (scan workspaces + SQLite) must be writable by it.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin qmc \
    && mkdir /data && chown 10001:10001 /data
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 QMC_DATA_DIR=/data PORT=8000
USER 10001
WORKDIR /srv/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000'), timeout=4)"
# PORT is honoured so platforms that inject it (e.g. Render) work unchanged; defaults to 8000.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
