"""Phase 12 tests — Wazuh adapter mapping + intake pipeline."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase12.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.adapters import get_adapter
from app.db import Base, get_db
from app.main import app

ENG = create_engine("sqlite:///./test_phase12.db", connect_args={"check_same_thread": False})
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


WIN_4625 = {
    "timestamp": "2026-09-25T10:00:00Z",
    "agent": {"id": "001", "name": "WIN-WORKSTATION-01", "ip": "10.20.4.15"},
    "rule": {"id": "60122", "description": "Failed logon attempt",
             "groups": ["windows", "authentication_failed"],
             "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
    "data": {"win": {"system": {"eventID": "4625"},
             "eventdata": {"TargetUserName": "victim.user", "LogonType": "3"}}},
}

SYSMON_PS = {
    "timestamp": "2026-09-25T10:01:00Z",
    "agent": {"id": "001", "name": "WIN-WORKSTATION-01", "ip": "10.20.4.15"},
    "rule": {"id": "61603", "description": "Sysmon process creation",
             "groups": ["windows", "sysmon"],
             "mitre": {"id": ["T1059.001"]}},
    "data": {"win": {"eventdata": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "ParentImage": "C:\\Windows\\explorer.exe",
             "CommandLine": "powershell -enc aGVsbG8= -w hidden"}}},
}

SYSCHECK = {
    "timestamp": "2026-09-25T10:02:00Z",
    "agent": {"id": "002", "name": "UBUNTU-SERVER-01", "ip": "10.20.10.50"},
    "rule": {"id": "550", "description": "File modified", "groups": ["syscheck"]},
    "data": {"syscheck": {"path": "/etc/passwd", "event": "modified"}},
}


def test_wazuh_auth_alert_mapping():
    e = get_adapter("wazuh").normalize(dict(WIN_4625))
    assert e.source == "wazuh" and e.event_type == "AUTH"
    assert e.asset.hostname == "WIN-WORKSTATION-01" and e.asset.ip == "10.20.4.15"
    assert e.user.name == "victim.user"
    assert e.authentication.event_code == "4625" and e.authentication.status == "FAILURE"
    assert e.mitre_hint == "T1110" and e.raw["rule"]["id"] == "60122"


def test_wazuh_process_and_file_mapping():
    ps = get_adapter("wazuh").normalize(dict(SYSMON_PS))
    assert ps.event_type == "PROCESS" and "powershell" in ps.process.image.lower()
    assert ps.mitre_hint == "T1059.001"
    f = get_adapter("wazuh").normalize(dict(SYSCHECK))
    assert f.event_type == "FILE" and f.asset.hostname == "UBUNTU-SERVER-01"


def test_wazuh_intake_runs_pipeline():
    c = _client()
    r = c.post("/api/v1/intake/wazuh", json={"alert": WIN_4625})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["event_id"]
    # 5 more failures → repeated_failed_logins fires and correlates
    for i in range(5):
        alert = dict(WIN_4625)
        r = c.post("/api/v1/intake/wazuh", json={"alert": alert})
    body = r.json()
    assert any(d["rule_id"] == "repeated_failed_logins" for d in body["detections"])
    assert body["incident"] is not None
    assert c.post("/api/v1/intake/wazuh", json={}).status_code == 422


def test_unknown_source_still_rejected():
    try:
        get_adapter("nope")
        assert False, "expected ValueError"
    except ValueError:
        pass
