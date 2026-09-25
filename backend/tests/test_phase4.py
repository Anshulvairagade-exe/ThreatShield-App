"""Phase 4 tests — zero-day adapter (pretrained pickle, never retrained)."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase4.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient

from app.ml.zeroday_adapter import flatten_for_model, get_adapter, to_detection_fields
from app.schemas.events import CanonicalSecurityEvent

NORMAL = {
    "event_id": "EVT-NORM-001", "timestamp": "2026-09-11T10:15:30Z", "event_type": "PROCESS",
    "hostname": "WS-FIN-02", "user": "bob.fin", "image": "excel.exe",
    "parent_image": "explorer.exe", "command_line": "excel.exe ledger.xlsx",
    "details": "User opened Excel sheet",
}
ZERODAY = {
    "event_id": "EVT-ZERODAY-001", "timestamp": "2026-09-11T02:45:10Z", "event_type": "PROCESS",
    "hostname": "WS-EXEC-01", "user": "alice.exec", "image": "calc.exe",
    "parent_image": "spoolsv.exe",
    "command_line": "calc.exe -d 7b8a9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f -mem_sync 0x00400000",
    "details": "calc.exe spawned with abnormal memory parameter under spoolsv.exe",
}


def test_adapter_loads_once_singleton():
    a1, a2 = get_adapter(), get_adapter()
    assert a1 is a2
    assert a1.load() is True and a1.loaded
    assert a1.status()["version"] == "2.0.0-zeroday-ensemble"


def test_normal_event_benign_and_output_shape_preserved():
    res = get_adapter().evaluate_event(NORMAL, host_criticality="HIGH")
    for field in ("anomaly_score", "risk_score", "severity", "decision", "top_reasons",
                  "top_attributions", "model_diagnostics"):
        assert field in res, f"missing preserved field {field}"
    assert res["decision"] == "BENIGN"
    assert res["model_diagnostics"]["model_version"] == "2.0.0-zeroday-ensemble"


def test_zeroday_event_alert_triggered():
    res = get_adapter().evaluate_event(ZERODAY, host_criticality="HIGH")
    assert res["decision"] == "ALERT_TRIGGERED" and res["is_anomaly"] is True
    assert res["anomaly_score"] > 0.8


def test_canonical_event_flattening_and_storage_mapping():
    canon = CanonicalSecurityEvent.model_validate({
        "event_id": "EVT-C", "event_type": "PROCESS",
        "asset": {"hostname": "WS-01", "criticality": "HIGH"},
        "user": {"name": "alice"}, "process": {"image": "calc.exe", "parent_image": "spoolsv.exe"},
    })
    flat = flatten_for_model(canon)
    assert flat["hostname"] == "WS-01" and flat["image"] == "calc.exe"
    res = get_adapter().evaluate_event(canon)
    stored = to_detection_fields(res)
    for field in ("anomaly_score", "model_risk_score", "severity", "decision",
                  "top_reasons", "top_attributions", "model_version", "model_diagnostics"):
        assert field in stored, f"missing stored field {field}"


def test_model_api_status_and_analyze():
    from app.main import app

    with TestClient(app) as c:
        st = c.get("/api/v1/model/zeroday/status")
        assert st.status_code == 200 and st.json()["loaded"] is True
        an = c.post("/api/v1/model/zeroday/analyze", json={"event": ZERODAY, "host_criticality": "HIGH"})
        assert an.status_code == 200 and an.json()["decision"] == "ALERT_TRIGGERED"
        health = c.get("/api/v1/health")
        assert "loaded" in health.json()["zeroday_model"]
