"""File -> service mapping from service.yaml metadata (09_SAMPLE_REPOSITORY_SPEC.md section 3)."""
from __future__ import annotations


def service_for_path(path: str, services: list[dict]) -> str | None:
    """Nearest-ancestor service.yaml wins. `services` items need 'service' and 'root' keys."""
    best: dict | None = None
    for svc in services:
        root = svc["root"]
        if root == "" or path == root or path.startswith(root + "/"):
            if best is None or len(root) > len(best["root"]):
                best = svc
    return best["service"] if best else None
