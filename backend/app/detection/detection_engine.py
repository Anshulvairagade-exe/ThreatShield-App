"""DetectionEngine — runs the three independent layers over one event.

IOC + RULE + ZERODAY layers share the DetectionResult contract and are
persisted together. The engine never creates incidents.
"""
from sqlalchemy.orm import Session

from app.core import logger
from app.detection import DetectionResult
from app.detection.engine import get_rule_engine
from app.detection.ioc_detector import IOCDetector
from app.detection.zeroday_layer import ZeroDayLayer
from app.schemas.events import CanonicalSecurityEvent
from app.services.detection_store import persist_results


class DetectionEngine:
    def __init__(self, db: Session):
        self.db = db
        self.ioc = IOCDetector(db)
        self.zeroday = ZeroDayLayer()

    def detect(self, event: CanonicalSecurityEvent) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        try:
            results.extend(self.ioc.detect(event))
        except Exception as e:
            logger.warning("ioc layer failed for %s: %s", event.event_id, e)
        try:
            results.extend(get_rule_engine().evaluate(event))
        except Exception as e:
            logger.warning("rule layer failed for %s: %s", event.event_id, e)
        results.extend(self.zeroday.detect(event))
        if results:
            persist_results(results, self.db)
        return results
