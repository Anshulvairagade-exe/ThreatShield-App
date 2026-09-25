"""Detection layer contracts — shared by rule, IOC and zero-day detectors.

DetectionResult is the common output of all three detection layers
(Phase 5 implements the RULE layer; IOC + zero-day plug in during Phase 6
without changing this schema).
"""
from uuid import uuid4

from pydantic import BaseModel, Field


class DetectionResult(BaseModel):
    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str = ""
    detector_type: str = "RULE"  # IOC | RULE | ZERODAY
    rule_id: str = ""
    severity: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float = 0.0
    score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
