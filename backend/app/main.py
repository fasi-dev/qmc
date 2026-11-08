"""Quantum Migration Copilot - backend entrypoint (FastAPI monolith; modules, not services)."""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from qmc_scanner import ENGINE_VERSION

from .config import get_settings
from .ingestion import IngestionError
from .routes_analysis import router as analysis_router
from .routes_scans import router as scans_router

app = FastAPI(title="Quantum Migration Copilot", version="0.4.0")

# Allowed browser origins: QMC_CORS_ORIGINS (comma-separated); defaults to local dev + the deployed frontend.
# No cookies are used (access is by per-scan header token), so credentials stay disabled.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(get_settings().cors_origins),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-QMC-Scan-Token", "X-QMC-Admin-Token"],
)


@app.exception_handler(IngestionError)
async def ingestion_error_handler(_: Request, exc: IngestionError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code,
                        content={"error": {"code": exc.code, "message": exc.message}})


app.include_router(scans_router)
app.include_router(analysis_router)


@app.get("/api/health")
def health() -> dict:
    # No Copilot exists yet, so health no longer advertises a copilot mode.
    return {"status": "ok", "engine_version": ENGINE_VERSION}
