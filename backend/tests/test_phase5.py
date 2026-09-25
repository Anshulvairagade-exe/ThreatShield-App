"""Phase 5 tests — one test per rule + engine + API persistence."""
import base64
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase5.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.detection.engine import RuleEngine, get_rule_engine
from app.detection.rules import BaseRule
from app.main import app
from app.schemas.events import CanonicalSecurityEvent

ENG = create_engine("sqlite:///./test_phase5.db", connect_args={"check_same_thread": False})
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


def _ev(**kw):
    base = {"event_id": "E", "event_type": "PROCESS", "asset": {"hostname": "H"},
            "process": {"image": "x.exe", "parent_image": "explorer.exe"}}
    base.update(kw)
    return CanonicalSecurityEvent.model_validate(base)


BENIGN_PROCESS = _ev()


def test_suspicious_powershell():
    (eng,) = [r for r in get_rule_engine().rules if r.rule_id == "suspicious_powershell"]
    hit = eng.evaluate(_ev(process={"image": "powershell.exe", "parent_image": "explorer.exe",
                                    "command_line": "powershell -enc abc -w hidden"}))
    assert hit and hit.mitre_techniques == ["T1059.001"] and hit.severity == "HIGH"
    assert eng.evaluate(BENIGN_PROCESS) is None


def test_encoded_powershell():
    blob = base64.b64encode("Write-Host hello world from encoded payload".encode("utf-16-le")).decode()
    (eng,) = [r for r in get_rule_engine().rules if r.rule_id == "encoded_powershell"]
    hit = eng.evaluate(_ev(process={"image": "powershell.exe", "parent_image": "explorer.exe",
                                    "command_line": f"powershell -EncodedCommand {blob}"}))
    assert hit and hit.mitre_techniques == ["T1027"]


def test_repeated_failed_logins_threshold():
    eng = RuleEngine()
    rule = [r for r in eng.rules if r.rule_id == "repeated_failed_logins"][0]
    rule.reset()
    auth = {"event_type": "AUTH", "asset": {"hostname": "H"}, "user": {"name": "bob"},
            "authentication": {"event_code": "4625", "status": "FAILURE"}}
    for i in range(4):
        assert rule.evaluate(CanonicalSecurityEvent.model_validate({**auth, "event_id": f"F{i}"})) is None
    hit = rule.evaluate(CanonicalSecurityEvent.model_validate({**auth, "event_id": "F4"}))
    assert hit and hit.mitre_techniques == ["T1110"] and "5 failed" in hit.reason


def test_suspicious_dns_txt_and_benign():
    (rule,) = [r for r in get_rule_engine().rules if r.rule_id == "suspicious_dns"]
    hit = rule.evaluate(_ev(event_type="DNS", dns={"query_name": "evil.cc", "query_type": "TXT"}))
    assert hit and "T1071.004" in hit.mitre_techniques
    assert rule.evaluate(_ev(event_type="DNS", dns={"query_name": "mail.example.com", "query_type": "A"})) is None


def test_unusual_external_connection():
    (rule,) = [r for r in get_rule_engine().rules if r.rule_id == "unusual_external_connection"]
    hit = rule.evaluate(_ev(event_type="NETWORK", network={"dest_ip": "1.2.3.4", "dest_port": 4444}))
    assert hit and hit.severity == "HIGH"
    assert rule.evaluate(_ev(event_type="NETWORK", network={"dest_ip": "1.2.3.4", "dest_port": 443})) is None


def test_rare_process_parent_child():
    (rule,) = [r for r in get_rule_engine().rules if r.rule_id == "rare_process_parent_child"]
    hit = rule.evaluate(_ev(process={"image": "calc.exe", "parent_image": "spoolsv.exe"}))
    assert hit and hit.mitre_techniques == ["T1055"]
    assert rule.evaluate(_ev(process={"image": "excel.exe", "parent_image": "explorer.exe"})) is None


def test_privileged_account_anomaly():
    (rule,) = [r for r in get_rule_engine().rules if r.rule_id == "privileged_account_anomaly"]
    hit = rule.evaluate(CanonicalSecurityEvent.model_validate(
        {"event_id": "P", "timestamp": "2026-01-01T02:00:00Z", "event_type": "AUTH",
         "asset": {"hostname": "H"}, "user": {"name": "root"}}))
    assert hit and hit.mitre_techniques == ["T1078"]


def test_suspicious_ssh_activity():
    (rule,) = [r for r in get_rule_engine().rules if r.rule_id == "suspicious_ssh_activity"]
    hit = rule.evaluate(CanonicalSecurityEvent.model_validate(
        {"event_id": "S", "timestamp": "2026-01-01T03:00:00Z", "event_type": "NETWORK",
         "asset": {"hostname": "H"}, "network": {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dest_port": 22}}))
    assert hit and "T1021.004" in hit.mitre_techniques


def test_engine_extension_without_modification():
    class MyRule(BaseRule):
        rule_id = "custom_demo"
        version = "9.9.9"
        severity = "LOW"
        confidence = 0.1
        mitre = ["T1005"]
        description = "demo"

        def evaluate(self, event):
            from app.detection.rules import RuleHit
            return RuleHit(rule_id=self.rule_id, severity="LOW", confidence=0.1,
                           reason="always", mitre_techniques=["T1005"])

    eng = RuleEngine()
    n = len(eng.evaluate(BENIGN_PROCESS))
    eng.register(MyRule())
    assert len(eng.evaluate(BENIGN_PROCESS)) == n + 1


def test_rules_and_evaluate_api_persist():
    c = _client()
    rules = c.get("/api/v1/rules").json()
    assert rules["count"] == 8 and {r["rule_id"] for r in rules["rules"]} == {
        "suspicious_powershell", "encoded_powershell", "repeated_failed_logins", "suspicious_dns",
        "unusual_external_connection", "rare_process_parent_child", "privileged_account_anomaly",
        "suspicious_ssh_activity"}
    r = c.post("/api/v1/detections/evaluate", json={"event": {
        "event_id": "EVT-API-1", "event_type": "PROCESS", "asset": {"hostname": "WS-01"},
        "process": {"image": "calc.exe", "parent_image": "spoolsv.exe", "command_line": "calc.exe -x"}}})
    assert r.status_code == 200 and r.json()["count"] >= 1
    det_id = r.json()["detections"][0]["detection_id"]
    assert det_id
    lst = c.get("/api/v1/detections", params={"event_id": "EVT-API-1"}).json()
    assert lst["count"] >= 1
    raw = c.post("/api/v1/detections/evaluate", json={"source": "simulator", "raw": {
        "event_id": "EVT-API-2", "event_type": "DNS", "hostname": "H",
        "query_name": "evil.cc", "query_type": "TXT"}})
    assert raw.json()["count"] >= 1
