"""Investigation composer — everything the Investigation page needs, from live data.

No mocks: summary, risk explanation, hosts, users, IOCs, detections,
timeline, related events, MITRE techniques, evidence and response options
are all read from PostgreSQL (+ EventStore for full event docs).
"""
from sqlalchemy.orm import Session

from app.models import (AppUser, Asset, Incident, IncidentAsset, IncidentEvent, IncidentIoc,
                        IncidentUser, Ioc, MitreTechnique, ResponseAction, SecurityEventMeta)
from app.services.pipeline import _full_incident_detections
from app.store import get_event_store

RESPONSE_OPTIONS = [
    {"action": "ISOLATE_HOST", "mode": "SIMULATION", "requires_approval": False},
    {"action": "BLOCK_IOC", "mode": "SIMULATION", "requires_approval": False},
    {"action": "DISABLE_USER", "mode": "SIMULATION", "requires_approval": True},
]


def compose(incident_id: str, db: Session) -> dict:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise KeyError(incident_id)
    dets = _full_incident_detections(db, inc.id)
    mitre_ids = sorted({t for d in dets for t in d.mitre_techniques})
    tech_rows = db.query(MitreTechnique).filter(MitreTechnique.technique_id.in_(mitre_ids)).all() if mitre_ids else []
    mitre = [{"tactic": t.tactic, "technique_id": t.technique_id, "technique_name": t.name,
              "subtechnique": t.subtechnique or ""} for t in tech_rows]
    for tid in mitre_ids:
        if tid not in {m["technique_id"] for m in mitre}:
            mitre.append({"tactic": "Unknown", "technique_id": tid, "technique_name": tid, "subtechnique": ""})

    asset_ids = [r.asset_id for r in db.query(IncidentAsset).filter(IncidentAsset.incident_id == inc.id).all()]
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all() if asset_ids else []
    primary = next((a for a in assets if a.id == inc.primary_asset_id), assets[0] if assets else None)
    user_ids = [r.user_id for r in db.query(IncidentUser).filter(IncidentUser.incident_id == inc.id).all()]
    users = db.query(AppUser).filter(AppUser.id.in_(user_ids)).all() if user_ids else []
    ioc_ids = [r.ioc_id for r in db.query(IncidentIoc).filter(IncidentIoc.incident_id == inc.id).all()]
    iocs = db.query(Ioc).filter(Ioc.id.in_(ioc_ids)).all() if ioc_ids else []

    event_ids = [r.event_id for r in db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).all()]
    metas = db.query(SecurityEventMeta).filter(SecurityEventMeta.event_id.in_(event_ids)).order_by(
        SecurityEventMeta.timestamp).all() if event_ids else []
    store = get_event_store()
    related_events, timeline = [], []
    sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for m in metas:
        ds = [d for d in dets if d.event_id == m.event_id]
        top = max(ds, key=lambda d: sev_rank.get(d.severity, 0)) if ds else None
        doc = None
        try:
            doc = store.get(m.event_id)
        except Exception:
            doc = None
        related_events.append({"event_id": m.event_id, "timestamp": m.timestamp.isoformat() if m.timestamp else "",
                               "source": m.source, "event_type": m.event_type, "hostname": m.hostname,
                               "user": m.user, "src_ip": m.src_ip, "dest_ip": m.dest_ip, "domain": m.domain,
                               "detections": [d.model_dump() for d in ds],
                               "full": (doc or {}).get("full", doc)})
        timeline.append({"time": m.timestamp.isoformat() if m.timestamp else "",
                         "event": f"{m.event_type} event on {m.hostname or 'unknown host'}",
                         "source": m.source, "severity": top.severity if top else "LOW",
                         "technique": (top.rule_id if top else "")})

    evidence = {"reasons": [r for d in dets for r in d.reasons],
                "detection_evidence": [d.evidence for d in dets]}
    actions = db.query(ResponseAction).filter(ResponseAction.incident_id == inc.id).all()
    return {
        "id": inc.id, "title": inc.title, "severity": inc.severity, "risk_score": inc.risk_score,
        "status": inc.status, "created_at": inc.created_at.isoformat() if inc.created_at else "",
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else "",
        "summary": inc.summary, "risk_explanation": inc.risk_explanation,
        "assigned_analyst": inc.assigned_analyst,
        "primary_asset": ({"id": primary.id, "hostname": primary.hostname, "ip": primary.ip,
                            "os": primary.os, "criticality": primary.criticality,
                            "status": primary.status, "risk_score": primary.risk_score} if primary else None),
        "affected_hosts": [{"id": a.id, "hostname": a.hostname, "ip": a.ip, "criticality": a.criticality} for a in assets],
        "users": [{"id": u.id, "name": u.name} for u in users],
        "iocs": [{"id": o.id, "ioc": o.ioc, "type": o.type, "reputation": o.reputation,
                  "confidence": o.confidence, "sources": o.sources, "mitre": o.mitre} for o in iocs],
        "detections": [d.model_dump() for d in dets],
        "mitre_techniques": mitre,
        "timeline": timeline,
        "related_events": related_events,
        "evidence": evidence,
        "response_actions": [{"id": a.id, "type": a.type, "mode": a.mode, "status": a.status,
                              "actor": a.actor, "target": a.target, "result": a.result} for a in actions],
        "response_options": RESPONSE_OPTIONS,
    }
