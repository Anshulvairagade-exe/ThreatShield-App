"""ResponseEngine — controlled response abstraction.

Actions: BLOCK_IOC, ISOLATE_HOST, DISABLE_USER, CREATE_INCIDENT, NOTIFY_ANALYST,
plus reverts RESTORE_HOST, UNBLOCK_IOC, ENABLE_USER.
States: REQUESTED → APPROVED → EXECUTING → SUCCESS | FAILED, or REJECTED.

Safety:
- mode defaults to SIMULATION; LIVE execution is disabled by policy and
  fails safe (FAILED + audit) unless explicitly enabled.
- High-severity incidents auto-approve per ACTION_POLICY; anything else
  waits for analyst approval via approve()/reject(). Reverts are safe
  operations and auto-approve.
- Every state change writes an audit row.
- A revert requires a matching SUCCESS action on the same target+incident.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import AppUser, Asset, Incident, IocBlock, ResponseAction
from app.services import incidents as incident_service
from app.services.audit import log

ACTION_TYPES = ("BLOCK_IOC", "ISOLATE_HOST", "DISABLE_USER", "CREATE_INCIDENT", "NOTIFY_ANALYST",
                "RESTORE_HOST", "UNBLOCK_IOC", "ENABLE_USER")

# revert action -> the action type it reverses
REVERTS = {"RESTORE_HOST": "ISOLATE_HOST", "UNBLOCK_IOC": "BLOCK_IOC", "ENABLE_USER": "DISABLE_USER"}

# action -> minimum incident severity that auto-approves (None = always needs approval)
ACTION_POLICY: dict[str, str | None] = {
    "BLOCK_IOC": "HIGH",
    "ISOLATE_HOST": "CRITICAL",
    "DISABLE_USER": None,
    "CREATE_INCIDENT": "LOW",
    "NOTIFY_ANALYST": "LOW",
    "RESTORE_HOST": "LOW",
    "UNBLOCK_IOC": "LOW",
    "ENABLE_USER": "LOW",
}

_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
LIVE_ENABLED = False  # flip only with explicit operator opt-in + real connectors


class InvalidActionError(ValueError):
    pass


def _audit(db, action: ResponseAction, result: str, actor: str):
    log(db, actor, f"response.{action.type.lower()}.{action.status.lower()}",
        target=action.target, incident_id=action.incident_id, result=result,
        metadata={"action_id": action.id, "mode": action.mode})
    try:
        from app.ws import bus
        bus.publish_sync("response_transition", {"action_id": action.id, "type": action.type,
                                                 "status": action.status, "incident_id": action.incident_id})
    except Exception:
        pass


def _auto_approved(action_type: str, severity: str) -> bool:
    floor = ACTION_POLICY.get(action_type)
    if floor is None:
        return False
    return _SEV_RANK.get((severity or "LOW").upper(), 0) >= _SEV_RANK.get(floor, 99)


def _simulated_effect(db: Session, action: ResponseAction) -> str:
    """Apply the reversible twin-state effect of a SIMULATION-mode action."""
    if action.type == "ISOLATE_HOST":
        asset = db.query(Asset).filter(Asset.hostname == action.target).first()
        if asset:
            asset.status, asset.risk_score = "isolated", min(asset.risk_score, 20)
            return f"SIMULATED: {action.target} marked isolated in twin state"
        return f"SIMULATED: isolate recorded for unknown host {action.target}"
    if action.type == "BLOCK_IOC":
        block = db.query(IocBlock).filter(IocBlock.ioc == action.target).first()
        if block is None:
            db.add(IocBlock(ioc=action.target, status="BLOCKED", updated_at=datetime.utcnow()))
        else:
            block.status, block.updated_at = "BLOCKED", datetime.utcnow()
        return f"SIMULATED: perimeter block recorded for {action.target}"
    if action.type == "UNBLOCK_IOC":
        block = db.query(IocBlock).filter(IocBlock.ioc == action.target).first()
        if block is None or block.status != "BLOCKED":
            return f"SIMULATED: {action.target} was not blocked — nothing to remove"
        block.status, block.updated_at = "ALLOWED", datetime.utcnow()
        return f"SIMULATED: perimeter block removed for {action.target}"
    if action.type == "RESTORE_HOST":
        asset = db.query(Asset).filter(Asset.hostname == action.target).first()
        if asset and asset.status == "isolated":
            asset.status = "healthy"
            return f"SIMULATED: {action.target} restored to service in twin state"
        return f"SIMULATED: {action.target} was not isolated — nothing to restore"
    if action.type == "ENABLE_USER":
        user = db.query(AppUser).filter(AppUser.name == action.target).first()
        if user and user.disabled:
            user.disabled = 0
            return f"SIMULATED: {action.target} re-enabled"
        return f"SIMULATED: {action.target} was not disabled — nothing to restore"
    if action.type == "DISABLE_USER":
        user = db.query(AppUser).filter(AppUser.name == action.target).first()
        if user:
            user.disabled = 1
            return f"SIMULATED: {action.target} disabled"
        return f"SIMULATED: disable recorded for unknown user {action.target}"
    if action.type == "CREATE_INCIDENT":
        return f"SIMULATED: triage incident noted ({action.target})"
    return f"SIMULATED: analyst notified re {action.target}"


def request_action(db: Session, incident: Incident, action_type: str, target: str,
                   actor: str, mode: str = "SIMULATION") -> ResponseAction:
    action_type = (action_type or "").upper()
    mode = (mode or "SIMULATION").upper()
    if action_type not in ACTION_TYPES:
        raise InvalidActionError(f"Unknown action '{action_type}'")
    if mode not in ("SIMULATION", "LIVE"):
        raise InvalidActionError(f"Unknown mode '{mode}'")
    action = ResponseAction(incident_id=incident.id, type=action_type, mode=mode,
                            status="REQUESTED", actor=actor or "", target=target or "")
    if action_type in REVERTS:
        original = REVERTS[action_type]
        prior = db.query(ResponseAction).filter(
            ResponseAction.incident_id == incident.id, ResponseAction.target == (target or ""),
            ResponseAction.type == original, ResponseAction.status == "SUCCESS").first()
        if not prior:
            raise InvalidActionError(
                f"Cannot {action_type}: no successful {original} on '{target}' in this incident")
    db.add(action)
    db.flush()
    _audit(db, action, "REQUESTED", actor)
    if _auto_approved(action_type, incident.severity):
        return _execute(db, action, actor, auto=True)
    db.commit()
    return action


def _execute(db: Session, action: ResponseAction, actor: str, auto: bool = False) -> ResponseAction:
    action.status = "APPROVED"
    _audit(db, action, "AUTO_APPROVED" if auto else "APPROVED", actor)
    action.status = "EXECUTING"
    db.flush()
    if action.mode == "LIVE" and not LIVE_ENABLED:
        action.status, action.result = "FAILED", "LIVE execution disabled by policy"
        _audit(db, action, "FAILED: live disabled", actor)
        db.commit()
        return action
    action.result = _simulated_effect(db, action)
    action.status = "SUCCESS"
    _audit(db, action, "SUCCESS", actor)
    # Best-effort: successful isolation moves an INVESTIGATING incident to CONTAINMENT.
    if action.type == "ISOLATE_HOST":
        try:
            incident = db.query(Incident).filter(Incident.id == action.incident_id).first()
            if incident and incident.status == "INVESTIGATING":
                incident_service.transition(incident, "CONTAINMENT", actor, db)
        except Exception:
            pass
    db.commit()
    return action


def approve(db: Session, action: ResponseAction, actor: str) -> ResponseAction:
    if action.status != "REQUESTED":
        raise InvalidActionError(f"Cannot approve action in status {action.status}")
    return _execute(db, action, actor)


def reject(db: Session, action: ResponseAction, actor: str, reason: str = "") -> ResponseAction:
    if action.status != "REQUESTED":
        raise InvalidActionError(f"Cannot reject action in status {action.status}")
    action.status = "REJECTED"
    action.result = reason or "Rejected by analyst"
    _audit(db, action, "REJECTED", actor)
    db.commit()
    return action
