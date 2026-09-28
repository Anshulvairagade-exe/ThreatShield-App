"""Threat-intel endpoints — standalone IOC API folded into the main app."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import ThreatSource
from app.repositories.ioc_repository import PostgresIOCRepository
from app.services import threat_intel as ti_service
from app.services.threat_intel import ti_logic

router = APIRouter()


@router.get("/ti/ioc/{value}")
def get_ioc(value: str, type: str | None = Query(default=None), db: Session = Depends(get_db)):
    """GET /api/v1/ti/ioc/{value}?type=ip — same contract as :8001 /ioc/{value}."""
    return ti_service.lookup_ioc(db, value, type)


@router.get("/ti/stats")
def ti_stats(db: Session = Depends(get_db)):
    return {"total_iocs": PostgresIOCRepository(db).count()}


@router.post("/ti/refresh")
def ti_refresh(db: Session = Depends(get_db)):
    """Run the feed pipeline on demand (scheduler wiring comes later)."""
    return ti_service.run_refresh(db)


@router.get("/ti/feeds")
def ti_feeds(db: Session = Depends(get_db)):
    """Per-feed wiring + last-run state for all five sources."""
    runs = {r.name: {"last_run": r.last_run, "record_count": r.record_count}
            for r in db.query(ThreatSource).all()}
    return {"feeds": [{**f, **runs.get(f["source"], {"last_run": "", "record_count": 0})}
                      for f in ti_logic.feed_status()]}


class EnrichVtRequest(BaseModel):
    limit: int = 4

    model_config = {"extra": "forbid"}


@router.post("/ti/enrich-vt")
def ti_enrich_vt(body: EnrichVtRequest, db: Session = Depends(get_db)):
    """Backfill VirusTotal reputation onto stored IOCs (free-tier paced)."""
    if body.limit < 1 or body.limit > 25:
        raise HTTPException(status_code=422, detail="limit must be 1-25 (VT free tier: ~4 lookups/min)")
    return ti_service.enrich_with_virustotal(db, limit=body.limit)
