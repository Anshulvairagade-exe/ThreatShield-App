"""Incident lifecycle + investigation reads (Phase 7)."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Detection, Incident, IncidentEvent, SecurityEventMeta
from app.services import incidents as incident_service
from app.services import investigation as investigation_service
from app.services.investigation import compose
from app.services.pipeline import _full_incident_detections

router = APIRouter()


def _timeline(db: Session, incident_id: str) -> list[dict]:
    event_ids = [r.event_id for r in db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == incident_id).all()]
    if not event_ids:
        return []
    metas = db.query(SecurityEventMeta).filter(
        SecurityEventMeta.event_id.in_(event_ids)).order_by(SecurityEventMeta.timestamp).all()
    dets = db.query(Detection).filter(Detection.event_id.in_(event_ids)).all()
    by_event: dict[str, list] = {}
    for d in dets:
        by_event.setdefault(d.event_id, []).append(d)
    sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    timeline = []
    for m in metas:
        ds = by_event.get(m.event_id, [])
        top = max(ds, key=lambda d: sev_rank.get(d.severity, 0)) if ds else None
        timeline.append({"time": m.timestamp.isoformat() if m.timestamp else "",
                         "event": f"{m.event_type} event on {m.hostname or 'unknown host'}",
                         "source": m.source, "severity": top.severity if top else "LOW",
                         "technique": (top.rule_id if top else "")})
    return timeline


@router.get("/incidents")
def list_incidents(limit: int = Query(50, ge=1, le=500), severity: str = "",
                   status: str = "", db: Session = Depends(get_db)):
    q = db.query(Incident).order_by(Incident.created_at.desc())
    if severity:
        q = q.filter(Incident.severity == severity.upper())
    if status:
        q = q.filter(Incident.status == status.upper())
    rows = q.limit(limit).all()
    return {"count": len(rows), "incidents": [
        {"id": r.id, "title": r.title, "severity": r.severity, "risk_score": r.risk_score,
         "status": r.status, "created_at": r.created_at.isoformat() if r.created_at else "",
         "updated_at": r.updated_at.isoformat() if r.updated_at else ""} for r in rows]}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    dets = _full_incident_detections(db, inc.id)
    mitre = sorted({t for d in dets for t in d.mitre_techniques})
    return {
        "id": inc.id, "title": inc.title, "severity": inc.severity, "risk_score": inc.risk_score,
        "status": inc.status, "created_at": inc.created_at.isoformat() if inc.created_at else "",
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else "",
        "primary_asset_id": inc.primary_asset_id, "assigned_analyst": inc.assigned_analyst,
        "summary": inc.summary, "risk_explanation": inc.risk_explanation,
        "mitre_techniques": mitre,
        "detections": [d.model_dump() for d in dets],
        "timeline": _timeline(db, inc.id),
    }


class StatusUpdate(BaseModel):
    status: str
    actor: str = "analyst"

    model_config = {"extra": "forbid"}


class AssignUpdate(BaseModel):
    analyst: str
    actor: str = "analyst"

    model_config = {"extra": "forbid"}


@router.patch("/incidents/{incident_id}/status")
def update_status(incident_id: str, body: StatusUpdate, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    try:
        incident_service.transition(inc, body.status, body.actor, db)
    except incident_service.InvalidTransitionError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"id": inc.id, "status": inc.status}


@router.patch("/incidents/{incident_id}/assign")
def assign_analyst(incident_id: str, body: AssignUpdate, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    incident_service.assign(inc, body.analyst, body.actor, db)
    return {"id": inc.id, "assigned_analyst": inc.assigned_analyst}


@router.get("/incidents/{incident_id}/events")
def incident_events(incident_id: str, db: Session = Depends(get_db)):
    try:
        inv = compose(incident_id, db)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return {"incident_id": incident_id, "count": len(inv["related_events"]), "events": inv["related_events"]}


@router.get("/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return {"incident_id": incident_id, "timeline": _timeline(db, inc.id)}


@router.get("/incidents/{incident_id}/investigation")
def incident_investigation(incident_id: str, db: Session = Depends(get_db)):
    try:
        return compose(incident_id, db)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
