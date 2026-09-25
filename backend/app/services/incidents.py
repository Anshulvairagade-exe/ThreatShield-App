"""Incident lifecycle — validated status transitions + analyst assignment.

Lifecycle: NEW → TRIAGED → INVESTIGATING → CONTAINMENT → ERADICATION →
RECOVERY → CLOSED. Every change is audit-logged.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import Incident
from app.services.audit import log

TRANSITIONS: dict[str, tuple[str, ...]] = {
    "NEW": ("TRIAGED", "CLOSED"),
    "TRIAGED": ("INVESTIGATING", "NEW", "CLOSED"),
    "INVESTIGATING": ("CONTAINMENT", "TRIAGED", "CLOSED"),
    "CONTAINMENT": ("ERADICATION", "INVESTIGATING"),
    "ERADICATION": ("RECOVERY", "CONTAINMENT"),
    "RECOVERY": ("CLOSED", "ERADICATION"),
    "CLOSED": (),
}

# Frontend legacy alias (mock used CONTAINED) — normalize on input.
ALIASES = {"CONTAINED": "CONTAINMENT"}


class InvalidTransitionError(ValueError):
    pass


def transition(incident: Incident, new_status: str, actor: str, db: Session) -> Incident:
    target = ALIASES.get((new_status or "").upper(), (new_status or "").upper())
    if target not in TRANSITIONS:
        raise InvalidTransitionError(f"Unknown status '{new_status}'")
    if target not in TRANSITIONS.get(incident.status, ()):
        raise InvalidTransitionError(f"Cannot move incident {incident.id} from {incident.status} to {target}")
    old = incident.status
    incident.status, incident.updated_at = target, datetime.utcnow()
    log(db, actor, "incident.status_changed", target=incident.id, incident_id=incident.id,
        result="SUCCESS", metadata={"from": old, "to": target})
    db.commit()
    return incident


def assign(incident: Incident, analyst: str, actor: str, db: Session) -> Incident:
    incident.assigned_analyst = analyst or ""
    incident.updated_at = datetime.utcnow()
    log(db, actor, "incident.assigned", target=incident.id, incident_id=incident.id,
        result="SUCCESS", metadata={"analyst": analyst or ""})
    db.commit()
    return incident
