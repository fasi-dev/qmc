"""Regression guard for the evaluation set in eval/ (see eval/README.md). Not an accuracy claim."""
from eval.evaluate import evaluate


def test_evaluation_set_has_no_false_positives_and_no_realistic_misses():
    r = evaluate()
    assert r["overall"]["fp"] == 0, [c for c in r["cases"] if c["fp"]]
    assert r["by_kind"]["realistic"]["fn"] == 0, [c for c in r["cases"] if c["kind"] == "realistic" and c["fn"]]


def test_known_limitations_are_still_reported_as_misses():
    """If a limitation gets fixed, move the case to kind='realistic' and update docs/SCANNER_EVALUATION numbers."""
    r = evaluate()
    assert r["by_kind"]["limitation"]["tp"] == 0 and r["by_kind"]["limitation"]["fn"] == 6
