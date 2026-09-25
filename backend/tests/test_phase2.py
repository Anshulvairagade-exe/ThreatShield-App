"""Phase 2 tests — canonical schema, adapters, ingest→search roundtrip."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase2.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.adapters import SimulatorAdapter, get_adapter
from app.db import Base, get_db
from app.main import app
from app.models import SecurityEventMeta
from app.schemas.events import CanonicalSecurityEvent
from app.store import EVENT_MAPPING, daily_index, get_memory_store

ENG = create_engine("sqlite:///./test_phase2.db", connect_args={"check_same_thread": False})
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


def test_canonical_schema_defaults_and_extensible():
    e = CanonicalSecurityEvent()
    assert e.event_id and e.source == "simulator" and e.event_type == "PROCESS"
    e2 = CanonicalSecurityEvent.model_validate({**e.model_dump(), "custom_future_field": "kept"})
    assert e2.model_extra["custom_future_field"] == "kept"


def test_simulator_adapter_process_event():
    raw = {
        "event_id": "EVT-1", "timestamp": "2026-09-11T02:45:10Z", "event_type": "PROCESS",
        "hostname": "WS-01", "user": "alice", "image": "calc.exe", "parent_image": "spoolsv.exe",
        "command_line": "calc.exe -x", "host_criticality": "HIGH",
    }
    e = SimulatorAdapter().normalize(raw)
    assert e.source == "simulator" and e.asset.hostname == "WS-01"
    assert e.process.image == "calc.exe" and e.asset.criticality == "HIGH"
    assert e.raw["parent_image"] == "spoolsv.exe"


def test_simulator_adapter_dns_and_auth():
    dns = SimulatorAdapter().normalize({"event_type": "DNS", "hostname": "H", "query_name": "evil.cc", "query_type": "TXT"})
    assert dns.dns.query_name == "evil.cc"
    auth = SimulatorAdapter().normalize({"event_type": "AUTH", "hostname": "H", "event_code": "4625", "status": "FAIL"})
    assert auth.authentication.event_code == "4625"


def test_adapters_registered_and_unknown_rejected():
    # All three adapters are real since Phases 12 (wazuh) and 13 (zeek).
    for src in ("simulator", "wazuh", "zeek"):
        assert get_adapter(src).source == src
    try:
        get_adapter("nope")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_ingest_search_roundtrip():
    get_memory_store().clear()
    c = _client()
    r = c.post("/api/v1/events/ingest", json={"source": "simulator", "raw": {
        "event_id": "EVT-RT-1", "event_type": "DNS", "hostname": "UBU-01",
        "query_name": "evil.cc", "query_type": "TXT"}})
    assert r.status_code == 201, r.text
    assert r.json()["event_id"] == "EVT-RT-1"

    s = c.get("/api/v1/events/search", params={"domain": "evil.cc"})
    assert s.status_code == 200 and any(d["event_id"] == "EVT-RT-1" for d in s.json()["results"])

    g = c.get("/api/v1/events/EVT-RT-1")
    assert g.status_code == 200 and g.json()["event_id"] == "EVT-RT-1"

    assert c.get("/api/v1/events/NOPE").status_code == 404
    # PG metadata pointer row exists
    with TestingSession() as db:
        assert db.query(SecurityEventMeta).filter_by(event_id="EVT-RT-1").count() == 1


def test_opensearch_mapping_and_index_docs():
    assert EVENT_MAPPING["mappings"]["properties"]["event_id"]["type"] == "keyword"
    assert daily_index().__len__() > len("threatshield-events-")
