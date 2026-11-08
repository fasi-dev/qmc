from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_ok():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["engine_version"] == "0.4.0"
    assert "copilot_mode" not in body          # no Copilot exists yet; health must not advertise one
