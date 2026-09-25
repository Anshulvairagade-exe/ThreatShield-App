"""RuleEngine — runs registered rules over a canonical event.

Extension point: RuleEngine.register(my_rule) — no engine changes needed.
Each hit becomes a DetectionResult with detector_type=RULE.
"""
from uuid import uuid4

from app.detection import DetectionResult
from app.detection.rules import BUILTIN_RULES, BaseRule
from app.schemas.events import CanonicalSecurityEvent


class RuleEngine:
    def __init__(self, rules: list[BaseRule] | None = None):
        self._rules: list[BaseRule] = list(rules) if rules is not None else list(BUILTIN_RULES)

    def register(self, rule: BaseRule) -> None:
        self._rules = [r for r in self._rules if r.rule_id != rule.rule_id] + [rule]

    @property
    def rules(self) -> list[BaseRule]:
        return list(self._rules)

    def evaluate(self, event: CanonicalSecurityEvent) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                hit = rule.evaluate(event)
            except Exception:
                continue  # a broken rule must never kill the pipeline
            if hit is None:
                continue
            results.append(DetectionResult(
                detection_id=str(uuid4()), event_id=event.event_id, detector_type="RULE",
                rule_id=hit.rule_id, severity=hit.severity, confidence=hit.confidence,
                score=hit.confidence, reasons=[hit.reason],
                mitre_techniques=list(hit.mitre_techniques), evidence=dict(hit.evidence),
            ))
        return results


_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine
