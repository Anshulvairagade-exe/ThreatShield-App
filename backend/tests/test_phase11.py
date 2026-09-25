"""Phase 11 tests — simulator, scenarios, WebSocket stream."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase11.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.repositories.ioc_repository import PostgresIOCRepository
from app.simulator.generator import SCENARIOS, baseline_events
from app.ws import bus

ENG = create_engine("sqlite:///./test_phase11.db", connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=ENG)


def _client():
    Base.metadata.drop_all(ENG)
    Base.metadata.create_all(ENG)

    def _override():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    return TestClient(app)


def test_four_scenarios_defined_with_pipeline_ready_steps():
    assert set(SCENARIOS) == {"SCN-APT-01", "SCN-ZERODAY-01", "SCN-BRUTE-01", "SCN-DNS-01"}
    for sid, scen in SCENARIOS.items():
        assert scen["steps"], sid
        for step in scen["steps"]:
            assert {"step", "title", "phase", "mitre", "raw"} <= set(step), (sid, step)
            assert step["raw"].get("event_type"), (sid, step)


def test_baseline_generator_deterministic_and_benign_shaped():
    first, second = baseline_events(20, seed=7), baseline_events(20, seed=7)
    assert first == second and len(first) == 20
    types = {e["event_type"] for e in first}
    assert {"PROCESS", "AUTH", "DNS", "NETWORK"} <= types


def test_scenario_start_runs_full_pipeline_to_incident():
    c = _client()
    with TestingSession() as db:
        PostgresIOCRepository(db).upsert(
            {"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["C2"],
             "reputation": 92, "confidence": 0.91, "mitre": ["T1071.001"],
             "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    bus.clear()
    r = c.post("/api/v1/scenarios/SCN-APT-01/start", json={"actor": "test"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incident_id"] and body["total_detections"] >= 3 and len(body["steps"]) == 5
    detail = c.get(f"/api/v1/incidents/{body['incident_id']}").json()
    assert detail["risk_score"] >= 61
    assert c.post("/api/v1/scenarios/NOPE/start", json={}).status_code == 404
    listed = c.get("/api/v1/scenarios").json()
    assert listed["count"] == 4


def test_websocket_streams_pipeline_messages():
    c = _client()
    bus.clear()
    with c.websocket_connect("/api/v1/ws/events") as ws:
        assert ws.receive_json()["type"] == "connected"
        bus.publish_sync("event_ingested", {"event_id": "E-WS"})
        got = [ws.receive_json()]
        # drain any further queued messages shortly after
        ws.close()
    types = [m["type"] for m in got]
    assert "event_ingested" in types


def test_brute_force_scenario_correlates():
    c = _client()
    r = c.post("/api/v1/scenarios/SCN-BRUTE-01/start", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["incident_id"] and body["total_detections"] >= 2
