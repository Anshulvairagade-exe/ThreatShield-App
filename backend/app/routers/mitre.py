"""MITRE matrix endpoints — backend truth replacing frontend hardcoding."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Detection, DetectionMitre, IncidentEvent, MitreTechnique, Rule
from app.services.mitre_catalog import CATALOG, TACTIC_ORDER, seed_catalog

router = APIRouter()


def _observed(db: Session) -> dict[str, dict]:
    """technique_id -> {count, detection_ids} from live detection_mitre rows."""
    out: dict[str, dict] = {}
    for link in db.query(DetectionMitre).all():
        entry = out.setdefault(link.technique_id, {"count": 0, "detection_ids": []})
        entry["count"] += 1
        entry["detection_ids"].append(link.detection_id)
    return out


def _incidents_for(db: Session, detection_ids: list[str]) -> list[str]:
    if not detection_ids:
        return []
    dets = db.query(Detection).filter(Detection.id.in_(detection_ids)).all()
    event_ids = list({d.event_id for d in dets})
    if not event_ids:
        return []
    rows = db.query(IncidentEvent).filter(IncidentEvent.event_id.in_(event_ids)).all()
    return sorted({r.incident_id for r in rows})


@router.get("/mitre")
def mitre_matrix(db: Session = Depends(get_db)):
    seed_catalog(db)
    observed = _observed(db)
    tactics = []
    total, covered = 0, 0
    for tactic in TACTIC_ORDER:
        tids = sorted(tid for tid, meta in CATALOG.items() if meta[0] == tactic)
        total += len(tids)
        techs = []
        for tid in tids:
            obs = observed.get(tid, {"count": 0, "detection_ids": []})
            if obs["count"]:
                covered += 1
            techs.append({"technique_id": tid, "name": CATALOG[tid][2],
                          "observed_count": obs["count"],
                          "incidents": _incidents_for(db, obs["detection_ids"])})
        tactics.append({"tactic": tactic, "tactic_id": CATALOG[tids[0]][1] if tids else "",
                        "coverage_pct": round(100 * sum(1 for t in techs if t["observed_count"]) / len(techs)) if techs else 0,
                        "techniques": techs})
    return {"tactics": tactics,
            "overall_coverage_pct": round(100 * covered / total) if total else 0}


@router.get("/mitre/{technique_id}")
def mitre_detail(technique_id: str, db: Session = Depends(get_db)):
    seed_catalog(db)
    row = db.query(MitreTechnique).filter(MitreTechnique.technique_id == technique_id).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Unknown technique {technique_id}")
    observed = _observed(db).get(technique_id, {"count": 0, "detection_ids": []})
    rules = [{"rule_id": r.rule_id, "version": r.version}
             for r in db.query(Rule).all() if technique_id in (r.mitre or [])]
    return {"technique_id": row.technique_id, "tactic": row.tactic, "technique_name": row.name,
            "subtechnique": row.subtechnique or "", "description": row.description or "",
            "observed_count": observed["count"], "incidents": _incidents_for(db, observed["detection_ids"]),
            "rules": rules}
