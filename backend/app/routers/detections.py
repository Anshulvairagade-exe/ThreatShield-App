"""Rules + detections endpoints (Phase 5 behavioral layer)."""
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.adapters import get_adapter
from app.db import get_db
from app.detection.engine import get_rule_engine
from app.models import Detection
from app.schemas.events import CanonicalSecurityEvent
from app.services.behavioral import evaluate_and_persist

router = APIRouter()


class EvaluateRequest(BaseModel):
    source: str = "simulator"
    raw: dict[str, Any] | None = None
    event: dict[str, Any] | None = None

    model_config = {"extra": "forbid"}


@router.get("/rules")
def list_rules():
    return {"count": len(get_rule_engine().rules), "rules": [
        {"rule_id": r.rule_id, "version": r.version, "enabled": r.enabled,
         "severity": r.severity, "confidence": r.confidence,
         "mitre": list(r.mitre), "description": r.description}
        for r in get_rule_engine().rules]}


@router.post("/detections/evaluate")
def evaluate(body: EvaluateRequest, db: Session = Depends(get_db)):
    if body.event is not None:
        event = CanonicalSecurityEvent.model_validate(body.event)
    elif body.raw is not None:
        event = get_adapter(body.source).normalize(body.raw)
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail="Provide either 'event' (canonical) or 'raw' + 'source'")
    results = evaluate_and_persist(event, db)
    return {"event_id": event.event_id, "count": len(results),
            "detections": [r.model_dump() for r in results]}


@router.get("/detections")
def list_detections(limit: int = Query(50, ge=1, le=500), event_id: str = "",
                    rule_id: str = "", detector_type: str = "", db: Session = Depends(get_db)):
    q = db.query(Detection).order_by(Detection.created_at.desc())
    if event_id:
        q = q.filter(Detection.event_id == event_id)
    if rule_id:
        q = q.filter(Detection.rule_id == rule_id)
    if detector_type:
        q = q.filter(Detection.detector_type == detector_type)
    rows = q.limit(limit).all()
    return {"count": len(rows), "detections": [
        {"detection_id": r.id, "event_id": r.event_id, "detector_type": r.detector_type,
         "rule_id": r.rule_id, "severity": r.severity, "confidence": r.confidence,
         "score": r.score, "reasons": r.reasons, "evidence": r.evidence} for r in rows]}
