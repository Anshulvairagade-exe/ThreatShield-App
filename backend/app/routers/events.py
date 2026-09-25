"""Event ingestion + search API (Phase 2)."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.schemas.events import CanonicalSecurityEvent
from app.services import ingest_raw
from app.store import get_event_store

router = APIRouter()


class IngestRequest(BaseModel):
    source: str = "simulator"
    raw: dict[str, Any]

    model_config = {"extra": "forbid"}


@router.post("/events/ingest", response_model=CanonicalSecurityEvent, status_code=201)
def ingest_event(body: IngestRequest, db: Session = Depends(get_db)):
    try:
        return ingest_raw(body.source, body.raw, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))


@router.get("/events/search")
def search_events(
    limit: int = Query(50, ge=1, le=500),
    event_id: str = "", asset: str = "", hostname: str = "", user: str = "",
    ip: str = "", domain: str = "", event_type: str = "", incident_id: str = "",
    source: str = "", from_ts: str = "", to_ts: str = "",
):
    store = get_event_store()
    return {
        "count": None,  # OpenSearch-backed; len(results) is authoritative for memory
        "results": store.search(
            limit=limit, event_id=event_id, asset=asset or hostname, hostname=hostname,
            user=user, ip=ip, domain=domain, event_type=event_type,
            incident_id=incident_id, source=source, from_ts=from_ts, to_ts=to_ts,
        ),
    }


@router.get("/events/{event_id}")
def get_event(event_id: str):
    doc = get_event_store().get(event_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return doc
