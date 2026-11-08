"""CSV export must neutralise spreadsheet formula injection (OWASP CSV injection)."""
import csv
import io

import pytest

from app.analysis import export_csv

COLS = ["id", "algorithm", "primitive", "operation", "service", "file", "line_start", "confidence_level", "band", "qmp",
        "quantum_vulnerable", "already_pqc", "hndl", "rule_id", "evidence"]


@pytest.mark.parametrize("payload", ["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\t=1+1", "\r=1+1"])
def test_formula_like_cells_are_prefixed(payload):
    row = {c: "x" for c in COLS} | {"line_start": 3, "qmp": 20, "quantum_vulnerable": True, "already_pqc": False,
                                    "hndl": False, "evidence": payload}
    out = list(csv.DictReader(io.StringIO(export_csv([row]))))[0]
    assert out["evidence"] == "'" + payload
    assert out["line_start"] == "3" and out["algorithm"] == "x"
