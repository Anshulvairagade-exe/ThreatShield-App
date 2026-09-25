"""Phase 7 tests — lifecycle, assignment, investigation composition."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase7.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models import AuditLog, Incident
from app.repositories.ioc_repository import PostgresIOCRepository
from app.services import incidents as incident_service

ENG = create_engine("sqlite:///./test_phase7.db", connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=ENG)


def _client():
    Base.metadata.create_all(ENG)

    def _override():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    return TestClient(app)


def _make_incident(client):
    with TestingSession() as db:
        db.query(Incident).delete()
        db.commit()
        PostgresIOCRepository(db).upsert(
            {"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["C2"],
             "reputation": 92, "confidence": 0.91, "mitre": ["T1071.001"],
             "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    r = client.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": {
        "event_id": "E-P7", "event_type": "NETWORK", "hostname": "WIN-01", "user": "victim",
        "dest_ip": "185.220.101.5", "dest_port": 443, "host_criticality": "HIGH"}})
    assert r.status_code == 200, r.text
    return r.json()["incident"]["id"]


def test_lifecycle_valid_path_and_audit():
    c = _client()
    inc_id = _make_incident(c)
    for nxt in ("TRIAGED", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY", "CLOSED"):
        r = c.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": nxt, "actor": "soc-01"})
        assert r.status_code == 200, (nxt, r.text)
        assert r.json()["status"] == nxt
    with TestingSession() as db:
        actions = [a.action for a in db.query(AuditLog).filter(AuditLog.incident_id == inc_id).all()]
        assert actions.count("incident.status_changed") == 6


def test_lifecycle_rejects_skip_and_unknown():
    c = _client()
    inc_id = _make_incident(c)
    bad = c.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "ERADICATION"})
    assert bad.status_code == 422
    unknown = c.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "BOGUS"})
    assert unknown.status_code == 422
    alias = c.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGED"})
    assert alias.status_code == 200


def test_assign_analyst_and_audit():
    c = _client()
    inc_id = _make_incident(c)
    r = c.patch(f"/api/v1/incidents/{inc_id}/assign", json={"analyst": "soc-01", "actor": "lead"})
    assert r.json()["assigned_analyst"] == "soc-01"
    with TestingSession() as db:
        assert db.query(AuditLog).filter(AuditLog.incident_id == inc_id,
                                         AuditLog.action == "incident.assigned").count() == 1


def test_investigation_composition():
    c = _client()
    inc_id = _make_incident(c)
    inv = c.get(f"/api/v1/incidents/{inc_id}/investigation").json()
    for field in ("summary", "risk_explanation", "affected_hosts", "users", "iocs", "detections",
                  "timeline", "related_events", "mitre_techniques", "evidence", "response_options",
                  "response_actions", "primary_asset", "assigned_analyst"):
        assert field in inv, f"missing {field}"
    assert inv["iocs"] and inv["iocs"][0]["ioc"] == "185.220.101.5"
    assert inv["affected_hosts"] and inv["affected_hosts"][0]["hostname"] == "WIN-01"
    assert inv["primary_asset"]["hostname"] == "WIN-01"
    assert any(t["technique_id"] == "T1071.001" for t in inv["mitre_techniques"])
    assert inv["related_events"] and inv["timeline"]
    assert {o["action"] for o in inv["response_options"]} == {"ISOLATE_HOST", "BLOCK_IOC", "DISABLE_USER"}
    assert c.get("/api/v1/incidents/NOPE/investigation").status_code == 404


def test_timeline_and_events_endpoints():
    c = _client()
    inc_id = _make_incident(c)
    tl = c.get(f"/api/v1/incidents/{inc_id}/timeline").json()
    assert tl["timeline"] and tl["timeline"][0]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    ev = c.get(f"/api/v1/incidents/{inc_id}/events").json()
    assert ev["count"] >= 1 and ev["events"][0]["event_id"] == "E-P7"
    assert c.get("/api/v1/incidents/NOPE/timeline").status_code == 404
