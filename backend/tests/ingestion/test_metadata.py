import dataclasses

from app.ingestion.metadata import parse_service_metadata, service_for_path
from tests.conftest import make_zip
from tests.ingestion.test_archive_adversarial import run

GOOD = """service: payment-api
owner: payments-team
data_classification: highly-sensitive
business_criticality: critical
internet_exposed: true
data_lifetime_years: 10
"""


def test_service_yaml_parsed_and_validated(tmp_path, settings):
    m, _ = run(tmp_path, settings, make_zip({"acme/service.yaml": GOOD, "acme/src/a.py": "1"}))
    (svc,) = m["services"]
    assert svc["service"] == "payment-api" and svc["root"] == ""
    assert svc["data_classification"] == "highly-sensitive" and svc["internet_exposed"] is True
    assert svc["data_lifetime_years"] == 10 and svc["missing_fields"] == [] and svc["invalid_fields"] == []


def test_missing_and_invalid_fields_recorded_not_guessed(tmp_path, settings):
    bad = "service: s\ndata_classification: top-secret\ninternet_exposed: 'yes'\ndata_lifetime_years: -3\n"
    m, _ = run(tmp_path, settings, make_zip({"service.yaml": bad}))
    (svc,) = m["services"]
    assert svc["data_classification"] is None and svc["internet_exposed"] is None and svc["data_lifetime_years"] is None
    assert set(svc["invalid_fields"]) == {"data_classification", "internet_exposed", "data_lifetime_years"}
    assert set(svc["missing_fields"]) == {"owner", "business_criticality"}


def test_malicious_yaml_tag_is_not_executed(tmp_path, settings):
    marker = tmp_path / "PWNED"
    evil = f"!!python/object/apply:os.system ['touch {marker}']\n"
    m, _ = run(tmp_path, settings, make_zip({"service.yaml": evil}))
    assert not marker.exists() and m["services"] == [] and m["warnings"]


def test_oversized_service_yaml_ignored(tmp_path, settings):
    big = "service: s\n# " + "x" * (settings.max_metadata_bytes + 10) + "\n"
    m, _ = run(tmp_path, settings, make_zip({"service.yaml": big}, compress=0))
    assert m["services"] == [] and "larger than" in m["warnings"][0]


def test_non_mapping_yaml_warns(tmp_path, settings):
    m, _ = run(tmp_path, settings, make_zip({"service.yaml": "- a\n- b\n"}))
    assert m["services"] == [] and m["warnings"]


def test_nearest_service_yaml_wins():
    svcs = [{"service": "root", "root": ""}, {"service": "settle", "root": "services/settle"}]
    assert service_for_path("src/a.py", svcs) == "root"
    assert service_for_path("services/settle/x/y.py", svcs) == "settle"
    assert service_for_path("services/settlement/y.py", svcs) == "root"   # prefix must match a whole dir
    assert service_for_path("a.py", []) is None
