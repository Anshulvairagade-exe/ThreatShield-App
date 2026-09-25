"""Zero-day detection layer — model signal wrapped as DetectionResult.

Produces a result ONLY on ALERT_TRIGGERED. BENIGN model output is not a
detection. Never creates incidents — correlation decides that downstream.
"""
from uuid import uuid4

from app.core import logger
from app.detection import DetectionResult
from app.schemas.events import CanonicalSecurityEvent

_SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


class ZeroDayLayer:
    def detect(self, event: CanonicalSecurityEvent) -> list[DetectionResult]:
        try:
            from app.ml.zeroday_adapter import get_adapter, to_detection_fields
        except Exception as e:
            logger.warning("zeroday layer unavailable: %s", e)
            return []
        adapter = get_adapter()
        try:
            result = adapter.evaluate_event(event)
        except Exception as e:
            logger.warning("zeroday evaluate failed for %s: %s", event.event_id, e)
            return []
        if result.get("decision") != "ALERT_TRIGGERED":
            return []
        stored = to_detection_fields(result)
        mitre = [event.mitre_hint] if event.mitre_hint else []
        return [DetectionResult(
            detection_id=str(uuid4()), event_id=event.event_id, detector_type="ZERODAY",
            rule_id="zeroday-anomaly", severity=_SEV_MAP.get(stored["severity"], "MEDIUM"),
            confidence=float(stored["anomaly_score"] or 0.0), score=float(stored["anomaly_score"] or 0.0),
            reasons=list(stored["top_reasons"]), mitre_techniques=mitre,
            evidence={"model_risk_score": stored["model_risk_score"], "decision": stored["decision"],
                      "top_attributions": stored["top_attributions"], "model_version": stored["model_version"],
                      "model_diagnostics": stored["model_diagnostics"]},
        )]
