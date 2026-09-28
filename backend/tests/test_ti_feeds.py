"""TI feed integrations — OTX/AbuseIPDB/AbuseCH wiring + VirusTotal enrichment."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_ti_feeds.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import ti as ti_logic
from app.db import Base, get_db
from app.main import app
from app.models import ThreatSource
from app.repositories.ioc_repository import PostgresIOCRepository

ENG = create_engine("sqlite:///./test_ti_feeds.db", connect_args={"check_same_thread": False})
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


def test_feed_status_lists_all_five_sources():
    feeds = ti_logic.feed_status()
    assert {f["source"] for f in feeds} == {"AbuseIPDB", "URLhaus", "MalwareBazaar", "OTX", "VirusTotal"}
    vt = next(f for f in feeds if f["source"] == "VirusTotal")
    assert vt["mode"] == "enrichment"
    assert next(f for f in feeds if f["source"] == "URLhaus")["configured"] is True


def test_collect_all_status_shape():
    import app.services.threat_intel as svc

    orig = ti_logic.collect_all_status
    ti_logic.collect_all_status = lambda: {"records": [], "feeds": [
        {"source": "URLhaus", "status": "ok", "records": 0}]}
    svc.ti_logic.collect_all_status = ti_logic.collect_all_status
    try:
        out = ti_logic.collect_all_status()
        assert out["records"] == [] and out["feeds"][0]["source"] == "URLhaus"
    finally:
        ti_logic.collect_all_status = orig
        svc.ti_logic.collect_all_status = orig


def test_virustotal_skipped_without_key(monkeypatch):
    import collectors

    monkeypatch.setattr(collectors, "VT_API_KEY", "")
    assert ti_logic.lookup_virustotal("8.8.8.8", "ip") is None
    assert ti_logic.lookup_virustotal("", "ip") is None


def test_virustotal_parses_malicious_response(monkeypatch):
    import collectors

    monkeypatch.setattr(collectors, "VT_API_KEY", "TESTKEY")

    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 70},
                "reputation": -10, "country": "NL", "tags": ["cobalt-strike"]}}}

    monkeypatch.setattr(collectors.requests, "get", lambda *a, **k: Resp())
    rec = ti_logic.lookup_virustotal("185.220.101.5", "ip")
    assert rec["source"] == "VirusTotal" and rec["reputation_hint"] == 91
    assert "cobalt-strike" in rec["tags"] and rec["vt_malicious_votes"] == 12


def test_virustotal_404_means_clean(monkeypatch):
    import collectors

    monkeypatch.setattr(collectors, "VT_API_KEY", "TESTKEY")

    class Resp404:
        status_code = 404

    monkeypatch.setattr(collectors.requests, "get", lambda *a, **k: Resp404())
    assert ti_logic.lookup_virustotal("9.9.9.9", "ip") is None


def test_refresh_records_feed_runs_and_enrich_vt_skips_without_key():
    import app.services.threat_intel as svc

    c = _client()
    orig = ti_logic.collect_all_status
    ti_logic.collect_all_status = lambda: {"records": [], "feeds": [
        {"source": "URLhaus", "status": "ok", "records": 5}]}
    svc.ti_logic.collect_all_status = ti_logic.collect_all_status
    try:
        body = c.post("/api/v1/ti/refresh").json()
        assert body["feeds"][0] == {"source": "URLhaus", "status": "ok", "records": 5}
        with TestingSession() as db:
            row = db.query(ThreatSource).filter(ThreatSource.name == "URLhaus").first()
            assert row is not None and row.record_count == 5 and row.last_run
    finally:
        ti_logic.collect_all_status = orig
        svc.ti_logic.collect_all_status = orig

    feeds = c.get("/api/v1/ti/feeds").json()["feeds"]
    assert len(feeds) == 5 and all("configured" in f and "last_run" in f for f in feeds)

    r = c.post("/api/v1/ti/enrich-vt", json={"limit": 2}).json()
    assert r["skipped_no_key"] is True
    bad = c.post("/api/v1/ti/enrich-vt", json={"limit": 99})
    assert bad.status_code == 422


def test_lookup_query_form_handles_slashes():
    c = _client()
    with TestingSession() as db:
        PostgresIOCRepository(db).upsert(
            {"ioc": "http://evil.example/x", "type": "url", "sources": ["URLhaus"], "tags": [],
             "reputation": None, "confidence": 0.6, "mitre": ["T1071"],
             "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    r = c.get("/api/v1/ti/lookup", params={"value": "http://evil.example/x", "type": "url"})
    assert r.status_code == 200 and r.json()["found"] is True


def test_enrich_vt_backfills_reputation(monkeypatch):
    import collectors

    c = _client()
    with TestingSession() as db:
        PostgresIOCRepository(db).upsert(
            {"ioc": "1.2.3.9", "type": "ip", "sources": ["URLhaus"], "tags": [],
             "reputation": None, "confidence": 0.5, "mitre": ["T1071"],
             "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    monkeypatch.setattr(collectors, "VT_API_KEY", "TESTKEY")

    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 80}, "tags": []}}}

    monkeypatch.setattr(collectors.requests, "get", lambda *a, **k: Resp())
    body = c.post("/api/v1/ti/enrich-vt", json={"limit": 4}).json()
    assert body == {"checked": 1, "enriched": 1, "skipped_no_key": False}
    with TestingSession() as db:
        got = PostgresIOCRepository(db).get("1.2.3.9", "ip")
        assert got["reputation"] == 70 and "VirusTotal" in got["sources"] and "virustotal" in got["tags"]
