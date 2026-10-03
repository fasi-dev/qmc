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

# Single-tenant local demo: allow the Vite dev server only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "https://qmc-frontend.onrender.com"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.exception_handler(IngestionError)
async def ingestion_error_handler(_: Request, exc: IngestionError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code,
                        content={"error": {"code": exc.code, "message": exc.message}})


app.include_router(scans_router)
app.include_router(analysis_router)


@app.get("/api/health")
def health() -> dict:
    s = get_settings()
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "copilot_mode": "template" if s.llm_backend == "none" else "llm",
    }
