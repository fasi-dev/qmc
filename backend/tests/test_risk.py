"""06_RISK_SCORING.md worked examples and guard rules."""
import pytest

from app.risk import band_for, priority_key, role_of, round_half_up, score

PAYMENT = {"service": "payment-api", "data_classification": "highly-sensitive", "business_criticality": "critical",
           "internet_exposed": True, "data_lifetime_years": 10}
DEV = {"service": "dev-scripts", "data_classification": "internal", "business_criticality": "low",
       "internet_exposed": False, "data_lifetime_years": 1}


def F(**kw):
    base = {"id": "CRYPTO-001", "rule_id": "PY-X", "algorithm": "ECDH", "primitive": "public-key", "operation": "key_agreement",
            "context": "key-establishment", "confidence_level": "high", "quantum_vulnerable": True, "already_pqc": False,
            "metadata": {"key_size": None, "comment_only": False, "in_dead_code": False, "test_path": False}}
    base.update(kw)
    return base


def test_example_a_payment_api_ecdh_is_critical_with_elevated_hndl():
    r = score(F(), PAYMENT)
    assert [r["factors"][k]["value"] for k in ("QE", "DS", "IE", "BC", "MC")] == [4, 4, 3, 3, 2]
    assert r["raw"] == 22.0 and r["qmp"] == 20 and r["band"] == "Critical"
    assert r["hndl"]["flag"] is True and r["hndl"]["severity"] == "elevated" and "10-year" in r["hndl"]["text"]


def test_example_b_dev_script_rsa_keygen_is_review_not_critical():
    r = score(F(algorithm="RSA", operation="key_generation", context="unknown"), DEV)
    assert [r["factors"][k]["value"] for k in ("QE", "DS", "IE", "BC", "MC")] == [4, 1, 0, 0, 1]
    assert r["raw"] == 8.5 and r["qmp"] == 9 and r["band"] == "Review"      # 8.5 rounds half UP (not banker's)
    assert r["hndl"]["flag"] is False and "test/dev path" not in r["badges"]


def test_example_d_aes_gcm_is_informational_by_guard_rule():
    r = score(F(algorithm="AES", primitive="symmetric", operation="encryption", context="data-protection", quantum_vulnerable=False), PAYMENT)
    assert r["factors"]["QE"]["value"] == 0 and r["band"] == "Informational" and "Guard rule" in r["cap_reason"]
    assert r["qmp"] > 3          # arithmetic would be higher: the guard rule, not the number, decides the band


def test_contrast_sensitive_service_far_above_dev_script():
    a = score(F(), PAYMENT)["qmp"]
    b = score(F(algorithm="RSA", operation="key_generation", context="unknown"), DEV)["qmp"]
    assert a - b >= 10


@pytest.mark.parametrize("x,exp", [(8.5, 9), (9.5, 10), (0.5, 1), (-0.5, 0), (14.49, 14), (22, 22)])
def test_round_half_up(x, exp):
    assert round_half_up(x) == exp


@pytest.mark.parametrize("q,b", [(0, "Informational"), (3, "Informational"), (4, "Review"), (9, "Review"), (10, "High"), (14, "High"), (15, "Critical"), (20, "Critical")])
def test_bands(q, b):
    assert band_for(q) == b


def test_qmp_is_clamped_to_20_and_never_negative():
    assert score(F(), PAYMENT)["qmp"] == 20
    low = score(F(algorithm="AES", primitive="symmetric", operation="encryption", quantum_vulnerable=False), {"data_classification": "public", "business_criticality": "low", "internet_exposed": False})
    assert low["qmp"] >= 0


def test_missing_metadata_uses_midpoint_with_badge_never_zero():
    r = score(F(), None)
    assert [r["factors"][k]["value"] for k in ("DS", "IE", "BC")] == [2, 1.5, 1.5]
    assert {"metadata missing: data_classification", "metadata missing: business_criticality", "metadata missing: internet_exposed"} <= set(r["badges"])
    assert r["factors"]["DS"]["source"].startswith("default midpoint")


def test_invalid_metadata_value_treated_as_missing():
    r = score(F(), {**PAYMENT, "data_classification": None})
    assert r["factors"]["DS"]["value"] == 2 and "metadata missing: data_classification" in r["badges"]


def test_low_or_medium_confidence_caps_band_at_review():
    r = score(F(confidence_level="medium"), PAYMENT)
    assert r["factors"]["QE"]["value"] == 2 and r["band_uncapped"] in ("High", "Critical") and r["band"] == "Review"
    assert "confidence" in r["cap_reason"]


def test_hndl_requires_key_establishment_sensitivity_exposure_and_lifetime():
    assert score(F(algorithm="ECDSA", operation="signature", context="authentication"), PAYMENT)["hndl"]["flag"] is False   # signature
    assert score(F(), {**PAYMENT, "data_lifetime_years": 3})["hndl"]["flag"] is False
    assert score(F(), {**PAYMENT, "internet_exposed": False})["hndl"]["flag"] is False
    assert score(F(), {**PAYMENT, "data_classification": "internal"})["hndl"]["flag"] is False
    assert score(F(), {**PAYMENT, "data_lifetime_years": 7})["hndl"]["severity"] == "noted"
    assert score(F(confidence_level="medium"), PAYMENT)["hndl"]["flag"] is True        # TLS ECDHE named in config still HNDL-relevant


def test_hndl_is_separate_from_qmp_number():
    a, b = score(F(), PAYMENT), score(F(), {**PAYMENT, "data_lifetime_years": 1})
    assert a["qmp"] == b["qmp"] and a["hndl"]["flag"] != b["hndl"]["flag"]


def test_sha1_is_classical_hygiene_capped_at_review_even_in_sensitive_service():
    r = score(F(algorithm="SHA-1", primitive="hash", operation="hashing", context="integrity", quantum_vulnerable=False), PAYMENT)
    assert r["factors"]["QE"]["value"] == 1 and r["band"] == "Review" and "classical hygiene" in r["badges"] and r["band_uncapped"] != "Review"


def test_pqc_and_comment_findings():
    r = score(F(algorithm="ML-KEM", primitive="pqc-kem", operation="key_generation", already_pqc=True, quantum_vulnerable=False), PAYMENT)
    assert r["band"] == "Informational" and r["factors"]["MC"]["value"] == 0
    c = F(); c["metadata"] = {**c["metadata"], "comment_only": True}
    assert score(c, PAYMENT) is None


@pytest.mark.parametrize("alg,op,ctx,role", [
    ("ECDH", "key_generation", "unknown", "key-establishment"), ("DH", "key_agreement", "unknown", "key-establishment"),
    ("RSA", "encryption", "unknown", "key-establishment"), ("RSA", "signature", "unknown", "signature"),
    ("RSA", "key_generation", "authentication", "signature"), ("RSA", "key_generation", "unknown", "unclear"),
    ("ECDSA", "key_generation", "unknown", "signature"), ("EdDSA", "signature", "unknown", "signature"), ("EC", "key_generation", "unknown", "unclear")])
def test_role_derivation(alg, op, ctx, role):
    assert role_of(F(algorithm=alg, operation=op, context=ctx)) == role


def test_aes128_has_qe1_aes256_zero():
    a = score(F(algorithm="AES", primitive="symmetric", operation="encryption", quantum_vulnerable=False, metadata={"key_size": 128, "comment_only": False, "in_dead_code": False, "test_path": False}), PAYMENT)
    b = score(F(algorithm="AES", primitive="symmetric", operation="encryption", quantum_vulnerable=False, metadata={"key_size": 256, "comment_only": False, "in_dead_code": False, "test_path": False}), PAYMENT)
    assert (a["factors"]["QE"]["value"], b["factors"]["QE"]["value"]) == (1, 0)


def test_scoring_is_deterministic_and_labelled_as_prototype():
    assert score(F(), PAYMENT) == score(F(), PAYMENT)
    lab = score(F(), PAYMENT)["label"]
    assert "not an official NIST score" in lab and "not a security certification" in lab


def test_priority_ordering_puts_hndl_critical_first():
    hi, lo = F(id="CRYPTO-002"), F(id="CRYPTO-001", algorithm="ECDSA", operation="signature", context="authentication")
    order = sorted([(lo, score(lo, PAYMENT)), (hi, score(hi, PAYMENT))], key=lambda p: priority_key(*p))
    assert order[0][0]["id"] == "CRYPTO-002"


def test_ranking_follows_displayed_band_before_number():
    capped = F(id="CRYPTO-001", confidence_level="medium")             # QMP 20 but capped to Review
    crit = F(id="CRYPTO-002", algorithm="ECDSA", operation="signature", context="authentication")   # QMP 20, Critical
    order = sorted([(capped, score(capped, PAYMENT)), (crit, score(crit, PAYMENT))], key=lambda p: priority_key(*p))
    assert [o[0]["id"] for o in order] == ["CRYPTO-002", "CRYPTO-001"]
