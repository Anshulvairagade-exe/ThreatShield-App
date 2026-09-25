"""Phase 13 tests — Zeek adapter mapping + intake pipeline."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase13.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.adapters import get_adapter
from app.db import Base, get_db
from app.main import app
from app.repositories.ioc_repository import PostgresIOCRepository

ENG = create_engine("sqlite:///./test_phase13.db", connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=ENG)

# Keep all sensor timestamps inside one correlation window (2026-09-25 10:00Z).
from datetime import datetime, timezone

TS = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc).timestamp()


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


CONN = {"ts": TS, "uid": "C1", "id.orig_h": "10.20.4.15", "id.orig_p": 52341,
        "id.resp_h": "185.220.101.5", "id.resp_p": 4444, "proto": "tcp",
        "orig_bytes": 512, "resp_bytes": 128, "hostname": "WIN-WORKSTATION-01"}
DNS = {"ts": TS + 1, "uid": "D1", "id.orig_h": "10.20.4.15",
       "query": "malicious-c2-tunnel.cc", "qtype_name": "TXT", "answers": [],
       "hostname": "WIN-WORKSTATION-01"}
HTTP = {"ts": TS + 2, "uid": "H1", "id.orig_h": "10.20.4.15",
        "id.resp_h": "93.184.216.34", "method": "GET", "host": "example.com",
        "uri": "/x", "status_code": 200, "hostname": "WIN-WORKSTATION-01"}
FILES = {"ts": TS + 3, "fuid": "F1", "source": "HTTP", "mime_type": "application/x-dosexec",
         "filename": "payload.exe", "sha256": "abc123", "hostname": "WIN-WORKSTATION-01"}


def test_zeek_log_type_mapping():
    conn = get_adapter("zeek").normalize(dict(CONN))
    assert conn.source == "zeek" and conn.event_type == "NETWORK"
    assert conn.event_id == "C1" and conn.network.dest_port == 4444
    assert conn.network.bytes_sent == 512 and conn.asset.hostname == "WIN-WORKSTATION-01"
    dns = get_adapter("zeek").normalize(dict(DNS))
    assert dns.event_type == "DNS" and dns.dns.query_type == "TXT"
    assert get_adapter("zeek").normalize(dict(HTTP)).event_type == "WEB"
    assert get_adapter("zeek").normalize(dict(FILES)).event_type == "FILE"


def test_zeek_intake_detects_and_correlates():
    c = _client()
    with TestingSession() as db:
        PostgresIOCRepository(db).upsert(
            {"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["C2"],
             "reputation": 92, "confidence": 0.91, "mitre": ["T1071.001"],
             "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    r = c.post("/api/v1/intake/zeek", json={"record": CONN})
    assert r.status_code == 200, r.text
    rules = {d["rule_id"] for d in r.json()["detections"]}
    assert "unusual_external_connection" in rules and "ioc-ip-match" in rules
    assert r.json()["incident"] is not None
    d = c.post("/api/v1/intake/zeek", json={"record": DNS})
    assert any(x["rule_id"] == "suspicious_dns" for x in d.json()["detections"])
    assert c.post("/api/v1/intake/zeek", json={}).status_code == 422


def test_zeek_wazuh_cross_source_correlation():
    c = _client()
    z = c.post("/api/v1/intake/zeek", json={"record": CONN}).json()
    w = c.post("/api/v1/intake/wazuh", json={"alert": {
        "timestamp": "2026-09-25T10:05:00Z",
        "agent": {"id": "001", "name": "WIN-WORKSTATION-01", "ip": "10.20.4.15"},
        "rule": {"id": "61603", "description": "Sysmon process",
                 "groups": ["windows", "sysmon"], "mitre": {"id": ["T1059.001"]}},
        "data": {"win": {"eventdata": {"Image": "powershell.exe", "ParentImage": "excel.exe",
                 "CommandLine": "powershell -enc ZZZ -w hidden"}}}}}).json()
    assert z["incident"] and w["incident"]
    assert z["incident"]["id"] == w["incident"]["id"], "same host+IP must correlate across sensors"
