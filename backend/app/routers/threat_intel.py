"""Threat-intel endpoints — standalone IOC API folded into the main app."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.repositories.ioc_repository import PostgresIOCRepository
from app.services import threat_intel as ti_service

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
