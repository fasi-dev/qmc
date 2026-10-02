import json
from pathlib import Path

import pytest

from qmc_scanner import scan_tree


def write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return root


@pytest.fixture
def scan(tmp_path):
    counter = iter(range(10_000))

    def _scan(files: dict[str, str | bytes], **kw):
        root = write_tree(tmp_path / f"t{next(counter)}", files)
        return scan_tree(root, scan_id="11111111-1111-4111-8111-111111111111", **kw)
    return _scan


def sig(f: dict) -> tuple:
    """(rule_id, algorithm, operation, key_size) for executable (non-comment) findings."""
    return (f["rule_id"], f["algorithm"], f["operation"], f["metadata"]["key_size"])


def code_findings(res) -> list[dict]:
    return [f for f in res.findings if not f["metadata"]["comment_only"]]
