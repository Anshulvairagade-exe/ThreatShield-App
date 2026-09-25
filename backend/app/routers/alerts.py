"""Alert stream endpoints — de-duplicated detections surfaced for triage."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Alert, Detection, DetectionMitre, IncidentEvent, MitreTechnique, SecurityEventMeta
from app.services.audit import log

router = APIRouter()

VALID_STATUSES = ("OPEN", "ACKED", "CLOSED")


class AlertStatusUpdate(BaseModel):
    status: str
    actor: str = "analyst"

    model_config = {"extra": "forbid"}


@router.get("/alerts")
def list_alerts(limit: int = Query(50, ge=1, le=500), status: str = "",
                detector_type: str = "", db: Session = Depends(get_db)):
    q = db.query(Alert, Detection, SecurityEventMeta).join(Detection, Alert.detection_id == Detection.id).outerjoin(
        SecurityEventMeta, Detection.event_id == SecurityEventMeta.event_id).order_by(Alert.id.desc())
    if status:
        q = q.filter(Alert.status == status.upper())
    if detector_type:
        q = q.filter(Detection.detector_type == detector_type.upper())
    rows = q.limit(limit).all()
    return {"count": len(rows), "alerts": [
        {"id": a.id, "status": a.status, "detection_id": d.id, "event_id": d.event_id,
         "hostname": m.hostname if m else "", "detector_type": d.detector_type, "rule_id": d.rule_id,
         "severity": d.severity, "confidence": d.confidence, "score": d.score, "reasons": d.reasons,
         "created_at": a.created_at.isoformat() if a.created_at else ""}
        for a, d, m in rows]}


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str, db: Session = Depends(get_db)):
    row = db.query(Alert, Detection).join(Detection, Alert.detection_id == Detection.id).filter(
        Alert.id == alert_id).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    alert, det = row
    tech_ids = [l.technique_id for l in db.query(DetectionMitre).filter(
        DetectionMitre.detection_id == det.id).all()]
    tech_rows = db.query(MitreTechnique).filter(MitreTechnique.technique_id.in_(tech_ids)).all() if tech_ids else []
    meta = db.query(SecurityEventMeta).filter(SecurityEventMeta.event_id == det.event_id).first()
    inc_ids = [r.incident_id for r in db.query(IncidentEvent).filter(
        IncidentEvent.event_id == det.event_id).all()]
    return {
        "id": alert.id, "status": alert.status,
        "detection": {"id": det.id, "event_id": det.event_id, "detector_type": det.detector_type,
                      "rule_id": det.rule_id, "severity": det.severity, "confidence": det.confidence,
                      "score": det.score, "reasons": det.reasons or [], "evidence": det.evidence or {}},
        "mitre": [{"technique_id": t.technique_id, "tactic": t.tactic, "name": t.name} for t in tech_rows],
        "event": ({"event_id": meta.event_id, "timestamp": meta.timestamp.isoformat() if meta.timestamp else "",
                   "source": meta.source, "event_type": meta.event_type, "hostname": meta.hostname,
                   "user": meta.user, "src_ip": meta.src_ip, "dest_ip": meta.dest_ip,
                   "domain": meta.domain} if meta else None),
        "incident_ids": inc_ids,
    }


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: str, body: AlertStatusUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    target = body.status.upper()
    if target not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Unknown alert status '{body.status}'")
    alert.status = target
    log(db, body.actor, "alert.status_changed", target=alert.id, result=target,
        metadata={"detection_id": alert.detection_id})
    db.commit()
    return {"id": alert.id, "status": alert.status}
