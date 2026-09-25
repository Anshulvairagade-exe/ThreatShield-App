"""Full pipeline — one entry point for ingest → detect → correlate → risk → incident.

Used by the pipeline API, the simulator/scenario engine (Phase 11) and the
end-to-end test. Wazuh/Zeek later flow through this exact function.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.adapters import get_adapter
from app.correlation.engine import CorrelationEngine
from app.detection import DetectionResult
from app.detection.detection_engine import DetectionEngine
from app.models import (AppUser, Asset, Detection, Incident, IncidentAsset, IncidentEvent,
                        IncidentIoc, IncidentUser, Ioc, SecurityEventMeta)
from app.risk.engine import RiskEngine, RiskAssessment
from app.schemas.events import CanonicalSecurityEvent
from app.services import ingest_raw


def _ensure_asset(db: Session, event: CanonicalSecurityEvent) -> Asset:
    asset = db.query(Asset).filter(Asset.hostname == event.asset.hostname).first() if event.asset.hostname else None
    if asset is None and event.asset.hostname:
        asset = Asset(hostname=event.asset.hostname, ip=event.asset.ip, os=event.asset.os,
                      criticality=event.asset.criticality or "MEDIUM")
        db.add(asset)
        db.flush()
    if asset and event.asset.ip:
        asset.ip, asset.last_seen = event.asset.ip, datetime.utcnow()
    return asset


def _ensure_user(db: Session, name: str) -> AppUser | None:
    if not name:
        return None
    user = db.query(AppUser).filter(AppUser.name == name).first()
    if user is None:
        user = AppUser(name=name)
        db.add(user)
        db.flush()
    return user


def _refresh_incident(db: Session, incident: Incident, event: CanonicalSecurityEvent,
                      detections: list[DetectionResult], risk: RiskAssessment) -> None:
    asset = _ensure_asset(db, event)
    if asset and not db.query(IncidentAsset).filter(
            IncidentAsset.incident_id == incident.id, IncidentAsset.asset_id == asset.id).first():
        db.add(IncidentAsset(incident_id=incident.id, asset_id=asset.id))
    if event.user and event.user.name:
        user = _ensure_user(db, event.user.name)
        if user and not db.query(IncidentUser).filter(
                IncidentUser.incident_id == incident.id, IncidentUser.user_id == user.id).first():
            db.add(IncidentUser(incident_id=incident.id, user_id=user.id))
    for d in detections:
        if d.detector_type == "IOC" and d.evidence.get("ioc"):
            row = db.query(Ioc).filter(Ioc.ioc == d.evidence["ioc"]).first()
            if row and not db.query(IncidentIoc).filter(
                    IncidentIoc.incident_id == incident.id, IncidentIoc.ioc_id == row.id).first():
                db.add(IncidentIoc(incident_id=incident.id, ioc_id=row.id))
    if not db.query(IncidentEvent).filter(
            IncidentEvent.incident_id == incident.id, IncidentEvent.event_id == event.event_id).first():
        db.add(IncidentEvent(incident_id=incident.id, event_id=event.event_id))
    meta = db.query(SecurityEventMeta).filter(SecurityEventMeta.event_id == event.event_id).first()
    if meta:
        meta.incident_id = incident.id
    incident.risk_score, incident.severity = risk.risk_score, risk.severity
    incident.risk_explanation = risk.explanation
    if asset:
        incident.primary_asset_id = incident.primary_asset_id or asset.id
    incident.updated_at = datetime.utcnow()
    db.commit()


def _new_incident(db: Session, event: CanonicalSecurityEvent,
                  detections: list[DetectionResult], risk: RiskAssessment) -> Incident:
    top = max(detections, key=lambda d: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(d.severity, 0))
    layers = sorted({d.detector_type for d in detections})
    if len(detections) > 1:
        title = f"Correlated multi-signal intrusion on {event.asset.hostname} ({len(detections)} signals)"
    else:
        title = f"{top.severity} {top.rule_id} on {event.asset.hostname or 'unknown host'}"
    incident = Incident(title=title, severity=risk.severity, risk_score=risk.risk_score, status="NEW",
                        summary=f"Opened by correlation over {'+'.join(layers)} detections; strongest: {top.rule_id}.",
                        risk_explanation=risk.explanation)
    db.add(incident)
    db.flush()
    _refresh_incident(db, incident, event, detections, risk)
    return incident


def run_event(event: CanonicalSecurityEvent, db: Session) -> dict:
    from app.ws import bus

    bus.publish_sync("event_ingested", {"event_id": event.event_id, "event_type": event.event_type,
                                        "hostname": event.asset.hostname, "source": event.source})
    detections = DetectionEngine(db).detect(event)
    if not detections:
        return {"event": event, "detections": [], "incident": None, "risk": None, "cluster": None}
    bus.publish_sync("detection_fired", {"event_id": event.event_id, "count": len(detections),
                                         "detections": [d.model_dump() for d in detections]})
    cluster = CorrelationEngine(db).correlate(event, detections)
    if cluster.incident_id is None:
        risk = RiskEngine().score(detections, event.asset.criticality, cluster.correlation_strength)
        incident = _new_incident(db, event, detections, risk)
        cluster.incident_id = incident.id
        bus.publish_sync("incident_created", {"incident_id": incident.id, "title": incident.title,
                                              "severity": incident.severity, "risk_score": incident.risk_score})
    else:
        incident = db.query(Incident).filter(Incident.id == cluster.incident_id).first()
        combined = _full_incident_detections(db, incident.id) + detections
        risk = RiskEngine().score(combined, event.asset.criticality, cluster.correlation_strength)
        _refresh_incident(db, incident, event, detections, risk)
        bus.publish_sync("incident_updated", {"incident_id": incident.id, "severity": incident.severity,
                                              "risk_score": incident.risk_score})
    bus.publish_sync("risk_changed", {"incident_id": incident.id, "risk_score": risk.risk_score,
                                      "severity": risk.severity})
    return {"event": event, "detections": detections, "incident": incident, "risk": risk, "cluster": cluster}


def _full_incident_detections(db: Session, incident_id: str) -> list[DetectionResult]:
    from app.models import DetectionMitre
    event_ids = [r.event_id for r in db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id).all()]
    if not event_ids:
        return []
    dets = db.query(Detection).filter(Detection.event_id.in_(event_ids)).all()
    links = db.query(DetectionMitre).filter(DetectionMitre.detection_id.in_([d.id for d in dets])).all() if dets else []
    by_det: dict[str, list] = {}
    for l in links:
        by_det.setdefault(l.detection_id, []).append(l.technique_id)
    return [DetectionResult(detection_id=d.id, event_id=d.event_id, detector_type=d.detector_type,
                            rule_id=d.rule_id, severity=d.severity, confidence=d.confidence,
                            score=d.score, reasons=list(d.reasons or []),
                            mitre_techniques=list(by_det.get(d.id, [])), evidence=dict(d.evidence or {}))
            for d in dets]


def run_raw(source: str, raw: dict, db: Session) -> dict:
    event = ingest_raw(source, raw, db)
    return run_event(event, db)
