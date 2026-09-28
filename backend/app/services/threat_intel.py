"""Threat-intel service — orchestrates existing pipeline onto Postgres repo.

Same response shape as the standalone threat_intel/api.py lookup_ioc.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import ti as ti_logic
from app.models import ThreatSource
from app.repositories.ioc_repository import PostgresIOCRepository


def lookup_ioc(db: Session, value: str, ioc_type: str | None = None) -> dict:
    repo = PostgresIOCRepository(db)
    result = repo.get(value, ioc_type)
    if not result:
        return {"found": False, "ioc": value}
    return {
        "found": True,
        "ioc": result["ioc"],
        "type": result["type"],
        "reputation": result["reputation"],
        "confidence": result["confidence"],
        "sources": result["sources"],
        "tags": result["tags"],
        "mitre": result["mitre"],
        "status": result["status"],
        "first_seen": result["first_seen"],
        "last_seen": result["last_seen"],
    }


def _record_feed_runs(db: Session, feeds: list[dict]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for f in feeds:
        row = db.query(ThreatSource).filter(ThreatSource.name == f["source"]).first()
        if row is None:
            db.add(ThreatSource(name=f["source"], last_run=now, record_count=f.get("records", 0)))
        else:
            row.last_run, row.record_count = now, f.get("records", 0)
    db.commit()


def run_refresh(db: Session) -> dict:
    """Full pipeline: collect → validate → normalize → dedup → enrich → store."""
    collected = ti_logic.collect_all_status()
    raw_records = collected["records"]
    valid_records = ti_logic.filter_valid(raw_records)
    normalized = ti_logic.normalize_all(valid_records)
    deduped = ti_logic.deduplicate(normalized)

    repo = PostgresIOCRepository(db)
    new_count = 0
    updated_count = 0
    for item in deduped:
        existing = repo.get(item["ioc"], item["type"])
        enriched = ti_logic.enrich(item, existing_db_row=existing)
        if repo.upsert(enriched):
            new_count += 1
        else:
            updated_count += 1
    _record_feed_runs(db, collected["feeds"])
    return {
        "raw": len(raw_records),
        "valid": len(valid_records),
        "unique": len(deduped),
        "new": new_count,
        "updated": updated_count,
        "total": repo.count(),
        "feeds": collected["feeds"],
    }


def enrich_with_virustotal(db: Session, limit: int = 4) -> dict:
    """Backfill VirusTotal reputation onto stored IOCs missing it.

    Bounded on purpose: the VT free tier allows ~4 lookups/min, so callers
    (scheduler, analyst) should use small limits on a slow cadence.
    Returns {"checked": n, "enriched": m, "skipped_no_key": bool}.
    """
    from app.models import Ioc

    configured = any(f["source"] == "VirusTotal" and f["configured"]
                       for f in ti_logic.feed_status())
    if not configured:
        return {"checked": 0, "enriched": 0, "skipped_no_key": True}
    rows = db.query(Ioc).filter(Ioc.reputation.is_(None)).limit(max(1, min(limit, 25))).all()
    enriched = 0
    for row in rows:
        vt = ti_logic.lookup_virustotal(row.ioc, row.type)
        if not vt or not vt.get("reputation_hint"):
            continue  # clean/unknown in VT — leave the record as-is
        row.reputation = vt["reputation_hint"]
        row.tags = sorted(set(row.tags or []) | set(vt.get("tags", [])) | {"virustotal"})
        row.sources = sorted(set(row.sources or []) | {"VirusTotal"})
        enriched += 1
    db.commit()
    return {"checked": len(rows), "enriched": enriched, "skipped_no_key": False}
