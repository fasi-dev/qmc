"""Pure-logic tests for access tokens, rate limiting, the analysis gate, retention and scan warnings (no FastAPI)."""
from datetime import datetime, timedelta, timezone

import pytest

from app.access import can_access, hash_token, is_admin, new_token
from app.ingestion.errors import IngestionError
from app.limits import AnalysisGate, RateLimiter, client_key
from app.scan_notes import is_expired, scan_warnings


def test_tokens_are_random_and_only_the_hash_is_needed():
    t1, h1 = new_token()
    t2, h2 = new_token()
    assert t1 != t2 and len(t1) >= 43 and h1 == hash_token(t1) and len(h1) == 64 and t1 not in h1
    assert can_access(h1, t1) and not can_access(h1, t2) and not can_access(h1, None) and not can_access(h1, "")


def test_legacy_rows_without_hash_are_admin_only():
    assert not can_access(None, "anything") and can_access(None, None, admin=True)


def test_admin_requires_a_configured_token():
    assert not is_admin("x", "") and not is_admin(None, "secret") and not is_admin("wrong", "secret")
    assert is_admin("secret", "secret")


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_rate_limiter_sliding_window():
    c = Clock()
    rl = RateLimiter(3, 60, clock=c)
    assert [rl.hit("a") for _ in range(4)] == [True, True, True, False]
    assert rl.hit("b") is True                      # per client
    assert 1 <= rl.retry_after("a") <= 61
    c.t += 61
    assert rl.hit("a") is True


def test_rate_limiter_disabled_and_bounded_memory(monkeypatch):
    assert all(RateLimiter(0, 60).hit("a") for _ in range(100))
    monkeypatch.setattr("app.limits.MAX_TRACKED_CLIENTS", 50)
    rl = RateLimiter(5, 60, clock=Clock())
    for i in range(500):
        rl.hit(f"c{i}")
    assert len(rl._events) <= 50


def test_analysis_gate_rejects_instead_of_queueing():
    g = AnalysisGate(1)
    with g.slot():
        with pytest.raises(IngestionError) as e:
            with g.slot():
                pass
        assert e.value.status_code == 503
    with g.slot():           # released again
        pass


def test_client_key_trusts_forwarded_for_only_when_configured():
    h = {"x-forwarded-for": "203.0.113.7, 10.0.0.1"}
    assert client_key(h, "10.0.0.1", trust_proxy=False) == "10.0.0.1"
    assert client_key(h, "10.0.0.1", trust_proxy=True) == "203.0.113.7"
    assert client_key({}, None, trust_proxy=True) == "unknown"


def test_retention_expiry():
    now = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
    assert is_expired((now - timedelta(hours=25)).isoformat(), now, 24)
    assert not is_expired((now - timedelta(hours=23)).isoformat(), now, 24)
    assert not is_expired((now - timedelta(days=999)).isoformat(), now, 0)       # 0 = keep forever
    assert is_expired("garbage", now, 24)


def test_scan_warnings_surface_partial_and_skipped_files():
    assert scan_warnings(None) == [] and scan_warnings({"scan_status": "complete", "files_skipped": []}) == []
    w = scan_warnings({"scan_status": "partial", "files_skipped": [
        {"file": "a.py", "reason": "parse_error"}, {"file": "b.py", "reason": "parse_error"}, {"file": "m.js", "reason": "skipped_minified"}]})
    assert "PARTIAL" in w[0] and any(x.startswith("2 file(s) could not be parsed") for x in w) and len(w) == 3
