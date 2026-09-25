"""Threat-intel service — orchestrates existing pipeline onto Postgres repo.

Same response shape as the standalone threat_intel/api.py lookup_ioc.
"""
from sqlalchemy.orm import Session

from app import ti as ti_logic
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


def run_refresh(db: Session) -> dict:
    """Full pipeline: collect → validate → normalize → dedup → enrich → store."""
    raw_records = ti_logic.collect_all()
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
    return {
        "raw": len(raw_records),
        "valid": len(valid_records),
        "unique": len(deduped),
        "new": new_count,
        "updated": updated_count,
        "total": repo.count(),
    }
