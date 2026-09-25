"""Response action + audit endpoints (Phase 9)."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import AuditLog, Incident, ResponseAction
from app.services import response as response_service

router = APIRouter()


class ActionRequest(BaseModel):
    target: str = ""
    actor: str = "analyst"
    mode: str = "SIMULATION"

    model_config = {"extra": "forbid"}


class ReviewRequest(BaseModel):
    actor: str = "analyst"
    reason: str = ""

    model_config = {"extra": "forbid"}


def _incident_or_404(db: Session, incident_id: str) -> Incident:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return inc


def _serialize(action: ResponseAction) -> dict:
    return {"id": action.id, "incident_id": action.incident_id, "type": action.type,
            "mode": action.mode, "status": action.status, "actor": action.actor,
            "target": action.target, "result": action.result,
            "created_at": action.created_at.isoformat() if action.created_at else ""}


def _request(db: Session, incident_id: str, action_type: str, body: ActionRequest) -> dict:
    inc = _incident_or_404(db, incident_id)
    try:
        action = response_service.request_action(db, inc, action_type, body.target, body.actor, body.mode)
    except response_service.InvalidActionError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _serialize(action)


@router.post("/incidents/{incident_id}/actions/isolate")
def isolate_host(incident_id: str, body: ActionRequest, db: Session = Depends(get_db)):
    return _request(db, incident_id, "ISOLATE_HOST", body)


@router.post("/incidents/{incident_id}/actions/block")
def block_ioc(incident_id: str, body: ActionRequest, db: Session = Depends(get_db)):
    return _request(db, incident_id, "BLOCK_IOC", body)


@router.post("/incidents/{incident_id}/actions/disable-user")
def disable_user(incident_id: str, body: ActionRequest, db: Session = Depends(get_db)):
    return _request(db, incident_id, "DISABLE_USER", body)


@router.post("/incidents/{incident_id}/actions/notify")
def notify_analyst(incident_id: str, body: ActionRequest, db: Session = Depends(get_db)):
    return _request(db, incident_id, "NOTIFY_ANALYST", body)


@router.get("/incidents/{incident_id}/actions")
def list_actions(incident_id: str, db: Session = Depends(get_db)):
    _incident_or_404(db, incident_id)
    rows = db.query(ResponseAction).filter(ResponseAction.incident_id == incident_id).all()
    return {"count": len(rows), "actions": [_serialize(a) for a in rows]}


@router.post("/incidents/{incident_id}/actions/{action_id}/approve")
def approve_action(incident_id: str, action_id: str, body: ReviewRequest, db: Session = Depends(get_db)):
    action = db.query(ResponseAction).filter(
        ResponseAction.id == action_id, ResponseAction.incident_id == incident_id).first()
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    try:
        response_service.approve(db, action, body.actor)
    except response_service.InvalidActionError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _serialize(action)


@router.post("/incidents/{incident_id}/actions/{action_id}/reject")
def reject_action(incident_id: str, action_id: str, body: ReviewRequest, db: Session = Depends(get_db)):
    action = db.query(ResponseAction).filter(
        ResponseAction.id == action_id, ResponseAction.incident_id == incident_id).first()
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    try:
        response_service.reject(db, action, body.actor, body.reason)
    except response_service.InvalidActionError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _serialize(action)


@router.get("/audit")
def list_audit(limit: int = Query(50, ge=1, le=500), incident_id: str = "",
               action: str = "", db: Session = Depends(get_db)):
    q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    if incident_id:
        q = q.filter(AuditLog.incident_id == incident_id)
    if action:
        q = q.filter(AuditLog.action.contains(action))
    rows = q.limit(limit).all()
    return {"count": len(rows), "logs": [
        {"id": r.id, "timestamp": r.timestamp.isoformat() if r.timestamp else "", "actor": r.actor,
         "action": r.action, "target": r.target, "incident_id": r.incident_id,
         "result": r.result, "metadata": r.log_metadata} for r in rows]}
