"""Behavioral detection service — evaluate canonical events, persist hits."""
from sqlalchemy.orm import Session

from app.detection import DetectionResult
from app.detection.engine import get_rule_engine
from app.models import Rule
from app.schemas.events import CanonicalSecurityEvent
from app.services.detection_store import persist_results


def _ensure_rule_row(db: Session, rule) -> None:
    row = db.query(Rule).filter(Rule.rule_id == rule.rule_id).first()
    if row is None:
        db.add(Rule(rule_id=rule.rule_id, version=rule.version, enabled=1 if rule.enabled else 0,
                    severity=rule.severity, confidence=rule.confidence,
                    mitre=list(rule.mitre), description=rule.description))
    else:
        row.version, row.severity, row.confidence = rule.version, rule.severity, rule.confidence
        row.mitre, row.description = list(rule.mitre), rule.description


def evaluate_and_persist(event: CanonicalSecurityEvent, db: Session) -> list[DetectionResult]:
    engine = get_rule_engine()
    results = engine.evaluate(event)
    for rule in engine.rules:
        _ensure_rule_row(db, rule)
    db.flush()
    return persist_results(results, db)
