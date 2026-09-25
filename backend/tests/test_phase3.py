"""Phase 3 tests — TI reuse, repository, lookup API."""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phase3.db"
os.environ["THREATSHIELD_EVENT_STORE"] = "memory"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import ti as ti_logic
from app.db import Base, get_db
from app.main import app
from app.repositories.ioc_repository import PostgresIOCRepository

ENG = create_engine("sqlite:///./test_phase3.db", connect_args={"check_same_thread": False})
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


def test_reused_normalization_and_dedup():
    """Original validator/normalizer/dedup behavior preserved via shim."""
    raw = [
        {"raw_value": "EVIL.com", "type_hint": "domain", "source": "URLhaus", "reputation_hint": None, "tags": ["c2"], "seen_at": "2026-01-01T00:00:00"},
        {"raw_value": "evil.com", "type_hint": "domain", "source": "OTX", "reputation_hint": None, "tags": ["botnet"], "seen_at": "2026-01-02T00:00:00"},
        {"raw_value": "10.0.0.5", "type_hint": "ip", "source": "AbuseIPDB", "reputation_hint": 90, "tags": [], "seen_at": "2026-01-01T00:00:00"},
    ]
    valid = ti_logic.filter_valid(raw)
    assert len(valid) == 2, "private IP must be rejected by original validator"
    normed = ti_logic.normalize_all(valid)
    assert normed[0]["ioc"] == "evil.com"
    deduped = ti_logic.deduplicate(normed)
    assert len(deduped) == 1 and sorted(deduped[0]["sources"]) == ["OTX", "URLhaus"]


def test_reused_confidence_and_mitre():
    assert ti_logic.calculate_confidence(3, "2099-01-01T00:00:00", [90, 85]) == 1.0
    assert ti_logic.confidence_label(0.8) == "High"
    assert "T1071" in ti_logic.map_to_mitre("ip", ["c2"])
    assert ti_logic.compute_status("2026-01-01", "2099-01-01", is_new_record=True) == "New"


def test_repository_upsert_merges_second_pass():
    with TestingSession() as db:
        Base.metadata.create_all(ENG)
        db.query(__import__("app.models", fromlist=["Ioc"]).Ioc).delete()
        db.commit()
        repo = PostgresIOCRepository(db)
        enriched = {"ioc": "1.2.3.4", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["c2"],
                    "reputation": 90, "confidence": 0.8, "mitre": ["T1071"],
                    "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "New"}
        assert repo.upsert(enriched) is True
        enriched2 = dict(enriched, sources=["OTX"], tags=["botnet"], last_seen="2026-01-03", status="Active")
        assert repo.upsert(enriched2) is False  # merged, not duplicated
        got = repo.get("1.2.3.4", "ip")
        assert sorted(got["sources"]) == ["AbuseIPDB", "OTX"] and repo.count() == 1


def test_lookup_api_hit_and_miss():
    c = _client()
    with TestingSession() as db:
        repo = PostgresIOCRepository(db)
        repo.upsert({"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB"], "tags": ["C2"],
                     "reputation": 92, "confidence": 0.91, "mitre": ["T1071"],
                     "first_seen": "2026-01-01", "last_seen": "2026-01-02", "status": "Active"})
    hit = c.get("/api/v1/ti/ioc/185.220.101.5", params={"type": "ip"})
    assert hit.status_code == 200
    body = hit.json()
    assert body["found"] is True and body["reputation"] == 92 and body["mitre"] == ["T1071"]
    miss = c.get("/api/v1/ti/ioc/9.9.9.9", params={"type": "ip"})
    assert miss.json() == {"found": False, "ioc": "9.9.9.9"}
    stats = c.get("/api/v1/ti/stats")
    assert stats.json()["total_iocs"] >= 1


def test_refresh_with_empty_feeds():
    import app.services.threat_intel as svc

    c = _client()
    orig = ti_logic.collect_all
    ti_logic.collect_all = lambda: []
    svc.ti_logic.collect_all = lambda: []
    try:
        r = c.post("/api/v1/ti/refresh")
        assert r.status_code == 200 and r.json()["raw"] == 0
    finally:
        ti_logic.collect_all = orig
        svc.ti_logic.collect_all = orig
