# Deployment

QMC is two services: the FastAPI backend (`backend/Dockerfile`, build context = repo root) and the static React
frontend (`frontend/Dockerfile`, build context = `frontend/`). Local stack: `docker compose up --build`
(UI http://localhost:5173, API http://localhost:8000).

## Backend environment variables

| Variable | Default | Purpose |
|---|---|---|
| `QMC_DATA_DIR` | `./data` (`/data` in the image) | SQLite file + scan workspaces. Must be persistent if scans should survive restarts. |
| `QMC_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,https://qmc-frontend.onrender.com` | Comma-separated browser origins allowed to call the API. |
| `QMC_TRUST_PROXY` | off | **Set to `1` behind a reverse proxy (Render, Fly, a load balancer).** Rate limits then use the first `X-Forwarded-For` hop. If it stays off behind a proxy, every visitor shares the proxy's address and therefore one rate-limit bucket. Never enable it when the API is reachable directly (the header is spoofable). |
| `QMC_RATE_LIMIT` / `QMC_RATE_WINDOW_SECONDS` | `20` / `3600` | New scans (uploads + demo) per client per window. `0` disables. |
| `QMC_MAX_CONCURRENT_ANALYSES` | `2` | Extra analyze requests get HTTP 503 instead of tying up worker threads. |
| `QMC_RETENTION_HOURS` | `24` | Scans older than this are deleted (checked at most every 5 minutes when a scan is created). `0` keeps scans forever. |
| `QMC_MAX_SCANS` | `500` | Hard cap on stored scans; new scans get 503 when reached (after a forced retention pass). |
| `QMC_SCAN_TIMEOUT_SECONDS` | `300` | Scanner deadline; a timed-out scan is marked partial and the UI/report say so. |
| `QMC_ADMIN_TOKEN` | empty | Optional operator token. With it, `GET /api/scans` (header `X-QMC-Admin-Token`) lists scans and any scan can be opened. Empty = listing disabled. Use a long random value (`python -c "import secrets; print(secrets.token_urlsafe(32))"`). |
| `PORT` | `8000` | Listening port (platforms that inject `PORT` work unchanged). |

## Frontend build arguments

| Build arg | Purpose |
|---|---|
| `VITE_API_URL` | Backend base URL, **compiled into the bundle at build time** (default `http://localhost:8000`). |

The frontend image serves the built files with nginx on `$PORT` (default 8080).

## Render checklist (existing deployment)

Behaviour changes in this release that need a deliberate step:

1. **Backend service** - add `QMC_TRUST_PROXY=1`. Optionally set `QMC_ADMIN_TOKEN`. If the service has no persistent
   disk, the SQLite database and scans are lost on every restart/redeploy (that was already true before).
2. **Frontend service**
   * If it is a Render *Static Site* (`npm run build`, publish `dist/`), nothing changes except that `VITE_API_URL`
     must still be set as an environment variable, as before.
   * If it is a *Docker* web service, the container now serves a production build with nginx instead of running
     `npm run dev`. `VITE_API_URL` must be available **at build time** (as a Docker build argument); if it is not,
     the bundle falls back to `http://localhost:8000` and the deployed UI cannot reach the API. Render injects
     `PORT`, which nginx uses.
3. **API contract** - every `/api/scans/{id}/...` request now needs `X-QMC-Scan-Token`. The frontend in this
   release handles it. Scans created before the upgrade have no token and are reachable only with the admin token
   (they will also be removed by retention after 24 h). Browsers that still remember an old scan id simply show
   "No scan yet".
4. CORS now only allows the headers the app uses (`Content-Type`, `X-QMC-Scan-Token`, `X-QMC-Admin-Token`).

## Health

`GET /api/health` -> `{"status": "ok", "engine_version": "..."}`. The backend image has a Docker `HEALTHCHECK`;
Compose waits for it before starting the frontend.
