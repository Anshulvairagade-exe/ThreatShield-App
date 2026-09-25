"""Pipeline endpoint — ingest → detect (3 layers) → correlate → risk → incident."""
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.services import pipeline as pipeline_service

router = APIRouter()


class PipelineIngestRequest(BaseModel):
    source: str = "simulator"
    raw: dict[str, Any]

    model_config = {"extra": "forbid"}


@router.post("/pipeline/ingest")
def pipeline_ingest(body: PipelineIngestRequest, db: Session = Depends(get_db)):
    out = pipeline_service.run_raw(body.source, body.raw, db)
    incident = out["incident"]
    risk = out["risk"]
    cluster = out["cluster"]
    return {
        "event_id": out["event"].event_id,
        "detections": [d.model_dump() for d in out["detections"]],
        "incident": ({
            "id": incident.id, "title": incident.title, "severity": incident.severity,
            "risk_score": incident.risk_score, "status": incident.status,
        } if incident else None),
        "risk": ({"risk_score": risk.risk_score, "severity": risk.severity,
                  "risk_factors": risk.risk_factors, "explanation": risk.explanation} if risk else None),
        "correlation": ({"incident_id": cluster.incident_id, "is_new": cluster.is_new,
                         "strength": cluster.correlation_strength,
                         "mitre_techniques": cluster.mitre_techniques} if cluster else None),
    }
