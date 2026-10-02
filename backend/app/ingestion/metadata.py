"""Parse `service.yaml` metadata (09 section 3) consumed later by the risk engine (06).

Uses yaml.safe_load ONLY (never yaml.load): no object construction, no code execution.
Missing/invalid fields are recorded, not guessed: the risk engine applies the documented
midpoint default with a "metadata missing" badge (06 section 6).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from qmc_scanner.services import service_for_path  # noqa: F401  (re-exported; single implementation)

from ..config import Settings

DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "sensitive", "highly-sensitive", "regulated"}
CRITICALITIES = {"low", "medium", "high", "critical"}
FIELDS = ("service", "owner", "data_classification", "business_criticality",
          "internet_exposed", "data_lifetime_years")


def _validate(field: str, v: Any) -> tuple[Any, bool]:
    """Return (normalized_value, is_valid)."""
    if field in ("service", "owner"):
        return (v.strip(), True) if isinstance(v, str) and v.strip() else (None, False)
    if field == "data_classification":
        n = v.strip().lower() if isinstance(v, str) else None
        return (n, True) if n in DATA_CLASSIFICATIONS else (None, False)
    if field == "business_criticality":
        n = v.strip().lower() if isinstance(v, str) else None
        return (n, True) if n in CRITICALITIES else (None, False)
    if field == "internet_exposed":
        return (v, True) if isinstance(v, bool) else (None, False)
    if field == "data_lifetime_years":
        return (v, True) if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 200 else (None, False)
    return None, False


def parse_service_metadata(tree_root: Path, file_paths: list[str], s: Settings) -> tuple[list[dict], list[str]]:
    services: list[dict] = []
    warnings: list[str] = []
    for rel in sorted(p for p in file_paths if p.rsplit("/", 1)[-1] == "service.yaml"):
        full = tree_root / rel
        try:
            if full.stat().st_size > s.max_metadata_bytes:
                warnings.append(f"{rel}: ignored (larger than {s.max_metadata_bytes} bytes)")
                continue
            doc = yaml.safe_load(full.read_text(encoding="utf-8", errors="replace"))
        except (yaml.YAMLError, RecursionError, ValueError, OSError) as e:
            warnings.append(f"{rel}: could not be parsed as safe YAML ({type(e).__name__})")
            continue
        if not isinstance(doc, dict):
            warnings.append(f"{rel}: expected a mapping of fields")
            continue
        entry: dict[str, Any] = {"metadata_file": rel, "root": rel.rsplit("/", 1)[0] if "/" in rel else "",
                                 "missing_fields": [], "invalid_fields": []}
        for f in FIELDS:
            if f not in doc:
                entry[f] = None
                entry["missing_fields"].append(f)
                continue
            val, ok = _validate(f, doc[f])
            entry[f] = val
            if not ok:
                entry["invalid_fields"].append(f)
        services.append(entry)
    return services, warnings
