"""Attack replay endpoints — backend scenario engine (Phase 11)."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.services import scenarios as scenario_service

router = APIRouter()


class StartRequest(BaseModel):
    actor: str = "analyst"

    model_config = {"extra": "forbid"}


@router.get("/scenarios")
def list_scenarios():
    scenes = scenario_service.list_scenarios()
    return {"count": len(scenes), "scenarios": scenes}


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    try:
        s = scenario_service.get_scenario(scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown scenario {scenario_id}")
    return {"id": s["id"], "name": s["name"], "description": s["description"],
            "total_steps": len(s["steps"]),
            "steps": [{k: step[k] for k in ("step", "title", "phase", "mitre", "target", "description")}
                      for step in s["steps"]]}


@router.post("/scenarios/{scenario_id}/start")
def start_scenario(scenario_id: str, body: StartRequest, db: Session = Depends(get_db)):
    try:
        return scenario_service.start_scenario(scenario_id, db, actor=body.actor)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown scenario {scenario_id}")
