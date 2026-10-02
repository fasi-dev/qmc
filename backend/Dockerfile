# Build context is the repo root so the scanner package can be installed alongside.
FROM python:3.12-slim
WORKDIR /srv
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY scanner/ scanner/
RUN pip install --no-cache-dir ./scanner
COPY backend/ backend/
# liboqs / liboqs-python are added in Phase 8 (PQC Lab).
# Non-root runtime user; /data (scan workspaces) must be writable by it.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin qmc \
    && mkdir /data && chown 10001:10001 /data
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
WORKDIR /srv/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
