"""Central configuration. Limits mirror 04_THREAT_MODEL.md section 4."""
import os
from dataclasses import dataclass, field
from pathlib import Path


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
    scan_timeout_seconds: int = 300

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"


def get_settings() -> Settings:
    return Settings()
