"""Dashboard aggregation — SOC KPIs from live backend state."""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Alert, Asset, Incident
from app.services.mitre_catalog import CATALOG

router = APIRouter()


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    open_incs = db.query(Incident).filter(Incident.status != "CLOSED").all()
    critical = sum(1 for i in open_incs if i.severity == "CRITICAL")
    assets = db.query(Asset).all()
    compromised = sum(1 for a in assets if a.status == "compromised")
    open_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "OPEN").scalar() or 0
    from app.models import DetectionMitre
    observed = {r[0] for r in db.query(DetectionMitre.technique_id).distinct().all()}
    tactics_covered = len({CATALOG[t][0] for t in observed if t in CATALOG}) if observed else 0
    recent = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()
    return {
        "kpis": {"active_incidents": len(open_incs), "critical": critical,
                 "compromised_assets": compromised, "monitored_assets": len(assets),
                 "open_alerts": open_alerts,
                 "mitre_tactics_covered": tactics_covered, "mitre_tactics_total": 12,
                 "mitre_techniques_observed": len(observed)},
        "recent_incidents": [{"id": i.id, "title": i.title, "severity": i.severity,
                              "risk_score": i.risk_score, "status": i.status} for i in recent],
    }
