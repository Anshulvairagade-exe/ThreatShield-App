"""External sensor intake — Wazuh + Zeek enter the same pipeline as simulation.

POST /api/v1/intake/wazuh accepts one Wazuh manager alert JSON object.
POST /api/v1/intake/zeek accepts one Zeek JSON log record (conn/dns/http/files).
Both run ingest → detect → correlate → risk → incident.
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.services import pipeline as pipeline_service

router = APIRouter()


class WazuhIntakeRequest(BaseModel):
    alert: dict[str, Any]

    model_config = {"extra": "forbid"}


class ZeekIntakeRequest(BaseModel):
    record: dict[str, Any]

    model_config = {"extra": "forbid"}


def _outcome(out: dict) -> dict:
    incident = out["incident"]
    return {
        "event_id": out["event"].event_id,
        "detections": [d.model_dump() for d in out["detections"]],
        "incident": ({"id": incident.id, "severity": incident.severity,
                      "risk_score": incident.risk_score} if incident else None),
    }


@router.post("/intake/wazuh")
def intake_wazuh(body: WazuhIntakeRequest, db: Session = Depends(get_db)):
    try:
        return _outcome(pipeline_service.run_raw("wazuh", body.alert, db))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Wazuh alert rejected: {e}")


@router.post("/intake/zeek")
def intake_zeek(body: ZeekIntakeRequest, db: Session = Depends(get_db)):
    try:
        return _outcome(pipeline_service.run_raw("zeek", body.record, db))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Zeek record rejected: {e}")
