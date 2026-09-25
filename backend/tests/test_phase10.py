"""Phase 10 tests — alerts stream, dashboard, assets/topology."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase10.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models import Asset

ENG = create_engine("sqlite:///./test_phase10.db", connect_args={"check_same_thread": False})
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


def _attack(client):
    raws = ({"event_id": "E-P10A", "event_type": "PROCESS", "hostname": "WIN-01", "user": "u",
             "image": "powershell.exe", "parent_image": "excel.exe",
             "command_line": "powershell -enc ZZZ -w hidden", "host_criticality": "HIGH"},
            {"event_id": "E-P10B", "event_type": "NETWORK", "hostname": "WIN-01", "user": "u",
             "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dest_port": 443, "host_criticality": "HIGH"})
    with TestingSession() as db:
        if not db.query(Asset).filter(Asset.hostname == "WIN-01").first():
            db.add(Asset(hostname="WIN-01", ip="10.0.0.1", criticality="HIGH"))
        if not db.query(Asset).filter(Asset.hostname == "SRV-01").first():
            db.add(Asset(hostname="SRV-01", ip="10.0.0.2", criticality="MEDIUM"))
        db.commit()
    for raw in raws:
        r = client.post("/api/v1/pipeline/ingest", json={"source": "simulator", "raw": raw})
        assert r.status_code == 200, r.text


def test_alerts_created_and_triaged():
    c = _client()
    _attack(c)
    alerts = c.get("/api/v1/alerts").json()
    assert alerts["count"] >= 2 and all(a["status"] == "OPEN" for a in alerts["alerts"])
    rule_only = c.get("/api/v1/alerts", params={"detector_type": "RULE"}).json()
    assert rule_only["count"] >= 1
    aid = alerts["alerts"][0]["id"]
    upd = c.patch(f"/api/v1/alerts/{aid}", json={"status": "ACKED"}).json()
    assert upd["status"] == "ACKED"
    assert c.patch(f"/api/v1/alerts/{aid}", json={"status": "BOGUS"}).status_code == 422
    assert c.patch("/api/v1/alerts/NOPE", json={"status": "CLOSED"}).status_code == 404


def test_dashboard_shape():
    c = _client()
    _attack(c)
    dash = c.get("/api/v1/dashboard").json()
    assert dash["kpis"]["active_incidents"] >= 1
    assert dash["kpis"]["monitored_assets"] >= 2
    assert dash["kpis"]["open_alerts"] >= 2
    assert dash["recent_incidents"]


def test_assets_and_topology():
    c = _client()
    _attack(c)
    assets = c.get("/api/v1/assets").json()
    assert assets["count"] >= 2
    one = c.get("/api/v1/assets/WIN-01").json()
    assert one["ip"] == "10.0.0.1"
    assert c.get("/api/v1/assets/NOPE").status_code == 404
    topo = c.get("/api/v1/twin/topology").json()
    assert len(topo["nodes"]) >= 2 and all("x" in n and "hostname" in n for n in topo["nodes"])
    edge = next((e for e in topo["edges"] if e["source"] == "WIN-01" and e["target"] == "SRV-01"), None)
    assert edge is not None, f"expected WIN-01->SRV-01 edge, got {topo['edges']}"
