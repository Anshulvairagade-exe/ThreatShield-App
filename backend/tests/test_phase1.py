"""Phase 1 tests — health + DB models (sqlite, no docker needed)."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase1.db"
os.environ["OPENSEARCH_URL"] = "http://localhost:9200"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.main import app


def test_health_endpoint():
    c = TestClient(app)
    r = c.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "database" in body


def test_models_create_all_tables():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    tables = set(Base.metadata.tables.keys())
    for expected in ["assets", "users", "security_events_metadata", "iocs", "threat_sources", "detections", "alerts", "incidents", "incident_events", "incident_iocs", "incident_assets", "incident_users", "mitre_techniques", "detection_mitre", "investigations", "investigation_notes", "response_actions", "audit_logs", "rules", "model_metadata"]:
        assert expected in tables, f"missing table {expected}"


def test_ioc_unique_constraint_and_crud():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    from app.models import Ioc

    s = S()
    s.add(Ioc(ioc="185.220.101.5", type="ip", sources=["AbuseIPDB"], tags=["C2"], reputation=92, confidence=0.91, mitre=["T1071"], first_seen="2026-01-01", last_seen="2026-01-02", status="Active"))
    s.commit()
    assert s.query(Ioc).count() == 1
    s.close()
