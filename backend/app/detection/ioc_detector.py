"""IOC detection layer — TI repository lookups over event observables."""
from uuid import uuid4

from sqlalchemy.orm import Session

from app.detection import DetectionResult
from app.repositories.ioc_repository import PostgresIOCRepository
from app.schemas.events import CanonicalSecurityEvent


def _observables(event: CanonicalSecurityEvent) -> list[tuple[str, str]]:
    obs: list[tuple[str, str]] = []
    if event.network:
        if event.network.src_ip:
            obs.append((event.network.src_ip, "ip"))
        if event.network.dest_ip and event.network.dest_ip != event.network.src_ip:
            obs.append((event.network.dest_ip, "ip"))
    if event.dns and event.dns.query_name:
        obs.append((event.dns.query_name, "domain"))
    return obs


def _severity(reputation: int | None, confidence: float | None) -> str:
    rep, conf = reputation or 0, confidence or 0.0
    if rep >= 80 or conf >= 0.8:
        return "HIGH"
    if rep >= 50 or conf >= 0.5:
        return "MEDIUM"
    return "LOW"


class IOCDetector:
    def __init__(self, db: Session):
        self.repo = PostgresIOCRepository(db)

    def detect(self, event: CanonicalSecurityEvent) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for value, ioc_type in _observables(event):
            record = self.repo.get(value, ioc_type)
            if not record:
                continue
            conf = record.get("confidence") or 0.0
            results.append(DetectionResult(
                detection_id=str(uuid4()), event_id=event.event_id, detector_type="IOC",
                rule_id=f"ioc-{ioc_type}-match", severity=_severity(record.get("reputation"), conf),
                confidence=float(conf), score=float(conf),
                reasons=[f"IOC matched: {value} ({ioc_type}) via {', '.join(record.get('sources', []))}"],
                mitre_techniques=list(record.get("mitre", [])),
                evidence={"ioc": value, "ioc_type": ioc_type, "reputation": record.get("reputation"),
                          "sources": record.get("sources", []), "tags": record.get("tags", []),
                          "status": record.get("status", "")},
            ))
        return results
