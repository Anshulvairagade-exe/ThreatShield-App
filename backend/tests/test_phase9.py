"""Phase 9 tests — response policy, simulation, approval, audit trail."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase9.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models import Asset, AuditLog
from app.repositories.ioc_repository import PostgresIOCRepository

ENG = create_engine("sqlite:///./test_phase9.db", connect_args={"check_same_thread": False})
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


def _critical_incident(client):
    with TestingSession() as db:
        PostgresIOCRepository(db).upsert(
            {"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["C2"],
             "reputation": 92, "confidence": 0.91, "mitre": ["T1071.001"],
             "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    raws = ({"event_id": "E-P9", "event_type": "PROCESS", "hostname": "WIN-01", "user": "victim",
             "image": "powershell.exe", "parent_image": "excel.exe",
             "command_line": "powershell -enc ZZZ -w hidden", "host_criticality": "HIGH"},
            {"event_id": "E-P9B", "event_type": "NETWORK", "hostname": "WIN-01", "user": "victim",
             "dest_ip": "185.220.101.5", "dest_port": 443, "host_criticality": "HIGH"})
    inc_id = None
    for raw in raws:
        r = client.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": raw})
        assert r.status_code == 200, r.text
        inc_id = r.json()["incident"]["id"]
    return inc_id


def test_isolate_auto_approves_on_critical_and_audits():
    c = _client()
    inc_id = _critical_incident(c)
    det = c.get(f"/api/v1/incidents/{inc_id}").json()
    assert det["severity"] == "CRITICAL"
    r = c.post(f"/api/v1/incidents/{inc_id}/actions/isolate",
               json={"target": "WIN-01", "actor": "soc-01"})
    assert r.json()["status"] == "SUCCESS" and r.json()["mode"] == "SIMULATION"
    with TestingSession() as db:
        asset = db.query(Asset).filter(Asset.hostname == "WIN-01").first()
        assert asset.status == "isolated"
        actions = [a.action for a in db.query(AuditLog).filter(AuditLog.incident_id == inc_id).all()]
        assert "response.isolate_host.requested" in actions and "response.isolate_host.success" in actions


def test_block_needs_approval_on_medium_then_succeeds():
    c = _client()
    r = c.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": {
        "event_id": "E-P9M", "event_type": "DNS", "hostname": "WS-M",
        "query_name": "evil.cc", "query_type": "TXT"}})
    inc_id = r.json()["incident"]["id"]
    sev = r.json()["incident"]["severity"]
    assert sev in ("LOW", "MEDIUM"), sev
    req = c.post(f"/api/v1/incidents/{inc_id}/actions/block",
                 json={"target": "evil.cc", "actor": "soc-01"}).json()
    assert req["status"] == "REQUESTED", req
    ap = c.post(f"/api/v1/incidents/{inc_id}/actions/{req['id']}/approve",
                json={"actor": "lead"}).json()
    assert ap["status"] == "SUCCESS"
    again = c.post(f"/api/v1/incidents/{inc_id}/actions/{req['id']}/approve",
                   json={"actor": "lead"})
    assert again.status_code == 422


def test_reject_and_live_fails_safe():
    c = _client()
    inc_id = _critical_incident(c)
    req = c.post(f"/api/v1/incidents/{inc_id}/actions/disable-user",
                 json={"target": "victim", "actor": "soc-01"}).json()
    assert req["status"] == "REQUESTED"
    rej = c.post(f"/api/v1/incidents/{inc_id}/actions/{req['id']}/reject",
                 json={"actor": "lead", "reason": "business hours user"}).json()
    assert rej["status"] == "REJECTED"
    live = c.post(f"/api/v1/incidents/{inc_id}/actions/block",
                  json={"target": "1.2.3.4", "actor": "soc-01", "mode": "LIVE"}).json()
    assert live["status"] == "FAILED" and "disabled" in live["result"]
    assert c.post("/api/v1/incidents/NOPE/actions/isolate",
                  json={"target": "H"}).status_code == 404


def test_audit_listing_and_action_history():
    c = _client()
    inc_id = _critical_incident(c)
    c.post(f"/api/v1/incidents/{inc_id}/actions/notify", json={"target": "siem", "actor": "soc-01"})
    logs = c.get("/api/v1/audit", params={"incident_id": inc_id}).json()
    assert logs["count"] >= 2 and all("timestamp" in l and "actor" in l for l in logs["logs"])
    hist = c.get(f"/api/v1/incidents/{inc_id}/actions").json()
    assert hist["count"] >= 1
    inv = c.get(f"/api/v1/incidents/{inc_id}/investigation").json()
    assert inv["response_actions"]
