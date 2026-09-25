"""Phase 8 tests — catalogue seed, matrix coverage, technique detail."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase8.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models import MitreTechnique
from app.repositories.ioc_repository import PostgresIOCRepository
from app.services.mitre_catalog import CATALOG, seed_catalog

ENG = create_engine("sqlite:///./test_phase8.db", connect_args={"check_same_thread": False})
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


def test_catalog_covers_all_emitted_techniques():
    with TestingSession() as db:
        Base.metadata.create_all(ENG)
        n = seed_catalog(db)
        assert n == len(CATALOG) >= 25
        for tid in ("T1059.001", "T1027", "T1110", "T1071.001", "T1071.004", "T1055",
                    "T1078", "T1021.004", "T1566.001", "T1486", "T1204", "T1041"):
            row = db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first()
            assert row is not None and row.tactic and row.name, tid


def test_matrix_reflects_live_detections():
    c = _client()
    with TestingSession() as db:
        PostgresIOCRepository(db).upsert(
            {"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["C2"],
             "reputation": 92, "confidence": 0.91, "mitre": ["T1071.001"],
             "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    r = c.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": {
        "event_id": "E-M8", "event_type": "PROCESS", "hostname": "WIN-01",
        "image": "powershell.exe", "parent_image": "excel.exe",
        "command_line": "powershell -enc ZZZ -w hidden"}})
    assert r.status_code == 200
    inc_id = r.json()["incident"]["id"]
    matrix = c.get("/api/v1/mitre").json()
    assert len(matrix["tactics"]) == 12
    execution = next(t for t in matrix["tactics"] if t["tactic"] == "Execution")
    ps = next(t for t in execution["techniques"] if t["technique_id"] == "T1059.001")
    assert ps["observed_count"] >= 1 and inc_id in ps["incidents"]
    assert matrix["overall_coverage_pct"] > 0


def test_technique_detail_links_rules_and_incidents():
    c = _client()
    c.post("/api/v1/detections/evaluate", json={"event": {
        "event_id": "E-M8B", "event_type": "PROCESS", "asset": {"hostname": "H"},
        "process": {"image": "powershell.exe", "parent_image": "excel.exe",
                    "command_line": "powershell -enc ZZZ -w hidden"}}})
    detail = c.get("/api/v1/mitre/T1059.001").json()
    assert detail["tactic"] == "Execution" and detail["technique_name"] == "PowerShell"
    assert detail["observed_count"] >= 1
    assert any(r["rule_id"] == "suspicious_powershell" for r in detail["rules"])
    assert c.get("/api/v1/mitre/T9999.999").status_code == 404
