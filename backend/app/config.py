"""Central configuration. Limits mirror 04_THREAT_MODEL.md section 4; everything operational is env-configurable."""
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CORS_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173", "https://qmc-frontend.onrender.com")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return default if not raw else raw in ("1", "true", "yes", "on")


def _env_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name, "").strip()
    return tuple(x.strip() for x in raw.split(",") if x.strip()) if raw else default


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("QMC_DATA_DIR", "./data")))
    llm_backend: str = field(default_factory=lambda: os.environ.get("QMC_LLM_BACKEND", "none"))
    # --- Ingestion limits (defaults from 04 section 4; configurable) ---
    max_archive_bytes: int = 100 * 1024 * 1024
    max_file_bytes: int = 5 * 1024 * 1024
    max_extracted_bytes: int = 300 * 1024 * 1024
    max_file_count: int = 50_000
    max_compression_ratio: int = 100          # 04: "e.g., <= 100:1"
    ratio_floor_bytes: int = 1024 * 1024      # ratio only enforced above this output size (avoids tiny-file false positives)
    max_path_length: int = 1024
    max_metadata_bytes: int = 64 * 1024       # service.yaml size cap
    scan_timeout_seconds: int = field(default_factory=lambda: _env_int("QMC_SCAN_TIMEOUT_SECONDS", 300))
    # --- Access control ---
    # Optional operator token: lists all scans and can open any scan. Empty = listing disabled.
    admin_token: str = field(default_factory=lambda: os.environ.get("QMC_ADMIN_TOKEN", ""))
    # --- Abuse / resource limits (public demo) ---
    retention_hours: int = field(default_factory=lambda: _env_int("QMC_RETENTION_HOURS", 24))   # 0 = keep forever
    max_scans: int = field(default_factory=lambda: _env_int("QMC_MAX_SCANS", 500))
    scans_per_window: int = field(default_factory=lambda: _env_int("QMC_RATE_LIMIT", 20))     # new scans per client
    rate_window_seconds: int = field(default_factory=lambda: _env_int("QMC_RATE_WINDOW_SECONDS", 3600))
    max_concurrent_analyses: int = field(default_factory=lambda: _env_int("QMC_MAX_CONCURRENT_ANALYSES", 2))
    # Use the first X-Forwarded-For hop as the client address. Only enable behind a proxy that sets it (e.g. Render).
    trust_proxy: bool = field(default_factory=lambda: _env_bool("QMC_TRUST_PROXY"))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: _env_list("QMC_CORS_ORIGINS", DEFAULT_CORS_ORIGINS))

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"


def get_settings() -> Settings:
    return Settings()
