"""Zero-day model endpoints — analyst/debug signal access.

The model NEVER creates incidents here; it returns a detection signal for
the correlation/risk pipeline (Phase 6) to consume.
"""
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.ml.zeroday_adapter import get_adapter

router = APIRouter()


class AnalyzeRequest(BaseModel):
    event: dict[str, Any]
    host_criticality: str = "MEDIUM"

    model_config = {"extra": "forbid"}


@router.get("/model/zeroday/status")
def model_status():
    return get_adapter().status()


@router.post("/model/zeroday/analyze")
def model_analyze(body: AnalyzeRequest):
    try:
        return get_adapter().evaluate_event(body.event, host_criticality=body.host_criticality)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
