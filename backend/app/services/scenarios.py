"""Scenario engine — replays simulator attack chains through the real pipeline.

POST /scenarios/{id}/start ingests every step via run_raw (same path as
Wazuh/Zeek later), publishing scenario_step + pipeline messages to the WS bus
so the SOC dashboard behaves live. Synchronous: returns the full outcome.
"""
from sqlalchemy.orm import Session

from app.services.pipeline import run_raw
from app.simulator.generator import SCENARIOS, get_scenario
from app.ws import bus


def list_scenarios() -> list[dict]:
    return [{"id": s["id"], "name": s["name"], "description": s["description"],
             "total_steps": len(s["steps"])} for s in SCENARIOS.values()]


def start_scenario(scenario_id: str, db: Session, actor: str = "analyst") -> dict:
    scenario = get_scenario(scenario_id)
    bus.publish_sync("scenario_started", {"scenario_id": scenario_id, "actor": actor,
                                          "total_steps": len(scenario["steps"])})
    incident_id, total_detections = None, 0
    steps_out = []
    for step in scenario["steps"]:
        out = run_raw("simulator", dict(step["raw"]), db)
        n = len(out["detections"])
        total_detections += n
        if out["incident"] is not None:
            incident_id = out["incident"].id
        bus.publish_sync("scenario_step", {"scenario_id": scenario_id, "step": step["step"],
                                           "title": step["title"], "phase": step["phase"],
                                           "mitre": step["mitre"], "detections": n,
                                           "incident_id": incident_id})
        steps_out.append({"step": step["step"], "title": step["title"], "detections": n})
    bus.publish_sync("scenario_finished", {"scenario_id": scenario_id, "incident_id": incident_id,
                                           "total_detections": total_detections})
    return {"scenario_id": scenario_id, "steps": steps_out, "total_detections": total_detections,
            "incident_id": incident_id}
