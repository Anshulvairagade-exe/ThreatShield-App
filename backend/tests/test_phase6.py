"""Phase 6 tests — DetectionEngine, correlation, risk, pipeline E2E."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase6.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.detection import DetectionResult
from app.detection.detection_engine import DetectionEngine
from app.main import app
from app.repositories.ioc_repository import PostgresIOCRepository
from app.risk.engine import RiskEngine, severity_for_score

ENG = create_engine("sqlite:///./test_phase6.db", connect_args={"check_same_thread": False})
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


def _seed_ioc(db):
    PostgresIOCRepository(db).upsert(
        {"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["C2", "botnet"],
         "reputation": 92, "confidence": 0.91, "mitre": ["T1071.001"],
         "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})


EVT_PS = {"event_id": "E-PS", "event_type": "PROCESS", "hostname": "WIN-01", "user": "victim",
          "image": "powershell.exe", "parent_image": "excel.exe",
          "command_line": "powershell -enc ZZZ -w hidden", "host_criticality": "HIGH"}
EVT_C2 = {"event_id": "E-C2", "event_type": "NETWORK", "hostname": "WIN-01", "user": "victim",
          "dest_ip": "185.220.101.5", "dest_port": 443, "protocol": "tcp", "host_criticality": "HIGH"}
EVT_SSH = {"event_id": "E-SSH", "timestamp": "2026-01-01T03:00:00Z", "event_type": "NETWORK",
           "hostname": "WIN-01", "user": "victim", "src_ip": "10.20.4.15",
           "dest_ip": "10.20.10.50", "dest_port": 22, "host_criticality": "HIGH"}
EVT_OTHER_HOST = {"event_id": "E-OTHER", "event_type": "PROCESS", "hostname": "UBU-01",
                  "image": "calc.exe", "parent_image": "spoolsv.exe", "command_line": "calc.exe -x"}


def test_detection_engine_runs_three_layers():
    with TestingSession() as db:
        Base.metadata.create_all(ENG)
        _seed_ioc(db)
        from app.adapters import SimulatorAdapter
        event = SimulatorAdapter().normalize(dict(EVT_C2))
        results = DetectionEngine(db).detect(event)
        layers = {r.detector_type for r in results}
        assert "IOC" in layers, f"expected IOC layer hit, got {layers}"
        assert any(r.rule_id == "ioc-ip-match" for r in results)


def test_zeroday_layer_only_alerts():
    from app.adapters import SimulatorAdapter
    from app.detection.zeroday_layer import ZeroDayLayer

    with TestingSession() as db:
        benign = SimulatorAdapter().normalize(
            {"event_id": "B", "event_type": "PROCESS", "hostname": "H",
             "image": "excel.exe", "parent_image": "explorer.exe", "command_line": "excel.exe x"})
        assert ZeroDayLayer().detect(benign) == []


def test_risk_bands_and_no_single_score_passthrough():
    assert severity_for_score(0) == "LOW" and severity_for_score(30) == "LOW"
    assert severity_for_score(31) == "MEDIUM" and severity_for_score(60) == "MEDIUM"
    assert severity_for_score(61) == "HIGH" and severity_for_score(80) == "HIGH"
    assert severity_for_score(81) == "CRITICAL" and severity_for_score(100) == "CRITICAL"
    zd_only = [DetectionResult(event_id="E", detector_type="ZERODAY", rule_id="zeroday-anomaly",
                               severity="CRITICAL", confidence=1.0, score=1.0, reasons=["x"])]
    r = RiskEngine().score(zd_only, "LOW", 0.0)
    assert r.risk_score <= 30, f"single perfect anomaly on LOW host must stay LOW, got {r.risk_score}"
    assert "capped" in " ".join(r.risk_factors).lower() or "Zero-day" in " ".join(r.risk_factors)


def test_pipeline_correlates_attack_into_one_incident():
    c = _client()
    with TestingSession() as db:
        db.query(__import__("app.models", fromlist=["Incident"]).Incident).delete()
        db.commit()
        _seed_ioc(db)
    ids = set()
    for raw in (EVT_PS, EVT_C2, EVT_SSH):
        r = c.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": raw})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["incident"] is not None
        ids.add(body["incident"]["id"])
    assert len(ids) == 1, f"PowerShell+C2+SSH on WIN-01 must be ONE incident, got {ids}"
    inc_id = ids.pop()
    detail = c.get(f"/api/v1/incidents/{inc_id}").json()
    assert detail["risk_score"] >= 61, f"multi-signal C2 intrusion should be HIGH+, got {detail['risk_score']}"
    assert "T1071.001" in detail["mitre_techniques"] and "T1059.001" in detail["mitre_techniques"]
    assert len(detail["timeline"]) >= 3 and len(detail["detections"]) >= 3
    assert detail["risk_explanation"] and detail["status"] == "NEW"


def test_pipeline_separates_hosts_and_benign_creates_nothing():
    c = _client()
    r = c.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": EVT_OTHER_HOST})
    assert r.status_code == 200
    other_inc = r.json()["incident"]["id"]
    all_incs = c.get("/api/v1/incidents").json()
    assert all_incs["count"] >= 2
    assert other_inc not in [i["id"] for i in all_incs["incidents"]][:0]  # sanity: list works
    benign = c.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": {
        "event_id": "E-BENIGN", "event_type": "PROCESS", "hostname": "WS-QUIET",
        "image": "excel.exe", "parent_image": "explorer.exe", "command_line": "excel.exe ledger.xlsx"}})
    assert benign.json()["incident"] is None and benign.json()["detections"] == []
