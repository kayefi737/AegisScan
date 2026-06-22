"""API-surface tests. The one scan success path monkeypatches the engine so the
suite never touches the network (and stays green in CI)."""
import app.routers.scans as scans_router


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_meta_exposes_rubric(client):
    r = client.get("/api/meta")
    body = r.json()
    assert r.status_code == 200
    assert "category_weights" in body
    assert any(c["key"] == "tls" for c in body["categories"])


def test_register_and_login(client):
    email = "newuser@example.com"
    assert client.post("/api/auth/register", json={"email": email, "password": "supersecret"}).status_code == 201
    login = client.post("/api/auth/login", data={"username": email, "password": "supersecret"})
    assert login.status_code == 200
    assert "access_token" in login.json()


def test_scan_rejects_invalid_host(client):
    r = client.post("/api/scans", json={"hostname": "not a hostname"})
    assert r.status_code == 400


def test_scan_success_path_monkeypatched(client, monkeypatch):
    async def fake_scan(hostname):
        return {
            "hostname": "example.com", "grade": "B", "score": 84.0, "max_score": 100.0,
            "summary": {"pass": 5, "warn": 1, "fail": 1, "info": 0},
            "engine_version": "test", "duration_ms": 12,
            "categories": [{"key": "tls", "label": "TLS", "score": 1.0, "max_score": 1.0,
                            "findings": [{"id": "x", "title": "Site reachable over HTTPS",
                                          "status": "pass", "severity": "high", "detail": "ok",
                                          "fix": None, "owasp": [], "weight": 1.0}]}],
        }

    monkeypatch.setattr(scans_router, "run_scan", fake_scan)
    r = client.post("/api/scans", json={"hostname": "example.com"})
    assert r.status_code == 201
    body = r.json()
    assert body["grade"] == "B"
    assert body["result"]["hostname"] == "example.com"

    # fetch it back
    got = client.get(f"/api/scans/{body['id']}")
    assert got.status_code == 200

    # it should now appear (masked) on the public dashboard
    dash = client.get("/api/dashboard").json()
    assert dash["total_scans"] >= 1


def test_history_requires_auth(client):
    assert client.get("/api/scans").status_code == 401


def test_domain_tracking_flow(auth_client):
    created = auth_client.post("/api/domains", json={"hostname": "example.com", "note": "prod"})
    assert created.status_code == 201
    listed = auth_client.get("/api/domains").json()
    assert any(d["hostname"] == "example.com" for d in listed)
