import importlib
import json
import os
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def create_client(tmp_path):
    db_path = tmp_path / "honeykey.db"
    if db_path.exists():
        db_path.unlink()
    os.environ["DATABASE_PATH"] = str(db_path)
    os.environ["HONEYPOT_KEY"] = "acme_live_f93k2jf92jf0s9df"
    os.environ["INCIDENT_WINDOW_MINUTES"] = "30"
    os.environ["CORS_ORIGINS"] = "http://localhost:5173,http://localhost:3000"
    os.environ.pop("GEMINI_API_KEY", None)
    os.environ.pop("GEMINI_MODEL", None)

    if "app.main" in sys.modules:
        del sys.modules["app.main"]
    module = importlib.import_module("app.main")
    module.settings = module.load_settings()
    module.app.state.settings = module.settings
    module.init_db()
    client = TestClient(module.app)
    client.__enter__()
    return client, db_path, module


def get_latest_incident_id(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    incident = conn.execute(
        "SELECT id FROM incidents ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not incident:
        return None
    return incident["id"]


def test_health_endpoint(tmp_path):
    client, _, _ = create_client(tmp_path)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_honeypot_detection_logs_incident(tmp_path):
    client, db_path, _ = create_client(tmp_path)
    response = client.get(
        "/v1/projects",
        headers={"Authorization": "Bearer acme_live_f93k2jf92jf0s9df"},
    )
    # New behavior: honeypot key returns 200 with fake data to keep attacker engaged
    assert response.status_code == 200
    data = response.json()
    assert "data" in data  # Fake project list
    assert "meta" in data

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    event = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert event is not None
    assert event["auth_present"] == 1
    assert event["honeypot_key_used"] == 1
    assert event["incident_id"] is not None

    incident = conn.execute(
        "SELECT * FROM incidents WHERE id = ?",
        (event["incident_id"],),
    ).fetchone()
    conn.close()
    assert incident is not None
    assert incident["key_id"] == "honeypot"
    assert incident["event_count"] == 1


def test_wrong_token_does_not_create_incident(tmp_path):
    client, db_path, _ = create_client(tmp_path)
    response = client.get(
        "/v1/projects",
        headers={"Authorization": "Bearer not_the_key"},
    )
    assert response.status_code == 401

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    incident = conn.execute("SELECT * FROM incidents").fetchone()
    conn.close()
    assert incident is None


def test_ai_report_clean_json(tmp_path, monkeypatch):
    client, db_path, module = create_client(tmp_path)
    os.environ["GEMINI_API_KEY"] = "test_key"
    os.environ["GEMINI_MODEL"] = "gemini-1.5-pro"
    module.app.state.settings = module.load_settings()

    client.get(
        "/v1/projects",
        headers={"Authorization": "Bearer acme_live_f93k2jf92jf0s9df"},
    )
    incident_id = get_latest_incident_id(db_path)
    assert incident_id is not None

    response_payload = {
        "incident_id": incident_id,
        "severity": "medium",
        "summary": "Honeypot token used.",
        "evidence": ["Bearer token matched honeypot"],
        "recommended_actions": ["HoneyKey: Export JSON report", "You: Review source IP"],
    }

    def fake_generate(prompt, api_key, model):
        return json.dumps(response_payload)

    monkeypatch.setattr(module, "generate_gemini_report", fake_generate)

    response = client.post(f"/incidents/{incident_id}/analyze")
    assert response.status_code == 200
    result = response.json()
    assert result["incident_id"] == response_payload["incident_id"]
    assert result["severity"] == response_payload["severity"]
    assert result["summary"] == response_payload["summary"]

    fetch = client.get(f"/incidents/{incident_id}/ai-report")
    assert fetch.status_code == 200
    fetch_result = fetch.json()
    assert fetch_result["incident_id"] == response_payload["incident_id"]


def test_ai_report_parse_failure(tmp_path, monkeypatch):
    client, db_path, module = create_client(tmp_path)
    os.environ["GEMINI_API_KEY"] = "test_key"
    module.app.state.settings = module.load_settings()

    client.get(
        "/v1/projects",
        headers={"Authorization": "Bearer acme_live_f93k2jf92jf0s9df"},
    )
    incident_id = get_latest_incident_id(db_path)
    assert incident_id is not None

    def fake_generate(prompt, api_key, model):
        return "not json"

    monkeypatch.setattr(module, "generate_gemini_report", fake_generate)

    response = client.post(f"/incidents/{incident_id}/analyze")
    assert response.status_code == 502

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    report = conn.execute(
        "SELECT * FROM ai_reports WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()
    conn.close()
    assert report is not None
    assert report["parse_ok"] == 0


def test_ai_report_fenced_json(tmp_path, monkeypatch):
    client, db_path, module = create_client(tmp_path)
    os.environ["GEMINI_API_KEY"] = "test_key"
    module.app.state.settings = module.load_settings()

    client.get(
        "/v1/projects",
        headers={"Authorization": "Bearer acme_live_f93k2jf92jf0s9df"},
    )
    incident_id = get_latest_incident_id(db_path)
    assert incident_id is not None

    response_payload = {
        "incident_id": incident_id,
        "severity": "low",
        "summary": "Fenced JSON response handled.",
        "evidence": ["Fenced output"],
        "recommended_actions": ["HoneyKey: Preserve evidence", "You: Monitor for repeats"],
    }

    def fake_generate(prompt, api_key, model):
        return f"```json\n{json.dumps(response_payload)}\n```"

    monkeypatch.setattr(module, "generate_gemini_report", fake_generate)

    response = client.post(f"/incidents/{incident_id}/analyze")
    assert response.status_code == 200
    result = response.json()
    assert result["incident_id"] == response_payload["incident_id"]
    assert result["severity"] == response_payload["severity"]
