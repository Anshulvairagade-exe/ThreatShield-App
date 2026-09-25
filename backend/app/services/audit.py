"""Audit helper — every important operation writes a row here."""
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import AuditLog


def log(db: Session, actor: str, action: str, target: str = "",
        incident_id: str | None = None, result: str = "", metadata: dict | None = None) -> AuditLog:
    entry = AuditLog(timestamp=datetime.utcnow(), actor=actor or "", action=action,
                     target=target or "", incident_id=incident_id, result=result or "",
                     log_metadata=metadata or {})
    db.add(entry)
    db.flush()
    return entry
