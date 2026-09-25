"""RiskEngine — final 0-100 score from ALL signals combined.

No single score (including the zero-day anomaly_score) can become the final
risk on its own: the model contributes at most 15 points out of 100.
"""
from dataclasses import dataclass, field

from app.detection import DetectionResult

_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_SEV_WEIGHT = {"LOW": 0.4, "MEDIUM": 0.7, "HIGH": 1.0, "CRITICAL": 1.2}
_ASSET_POINTS = {"LOW": 0, "MEDIUM": 5, "HIGH": 10, "CROWN_JEWEL": 15, "CRITICAL": 15}


def severity_for_score(score: int) -> str:
    if score >= 81:
        return "CRITICAL"
    if score >= 61:
        return "HIGH"
    if score >= 31:
        return "MEDIUM"
    return "LOW"


@dataclass
class RiskAssessment:
    risk_score: int
    severity: str
    risk_factors: list[str] = field(default_factory=list)
    explanation: str = ""


class RiskEngine:
    def score(self, detections: list[DetectionResult], asset_criticality: str = "MEDIUM",
              correlation_strength: float = 0.0) -> RiskAssessment:
        factors: list[str] = []
        total = 0.0

        ioc_pts = 0.0
        for d in detections:
            if d.detector_type == "IOC":
                rep = (d.evidence.get("reputation") or 0) / 100.0
                pts = rep * (d.confidence or 0.0) * 25.0
                ioc_pts = max(ioc_pts, pts)
        if ioc_pts > 0:
            total += ioc_pts
            factors.append(f"IOC reputation signal +{ioc_pts:.1f}")

        beh_pts = 0.0
        for d in detections:
            if d.detector_type == "RULE":
                pts = (d.confidence or 0.0) * _SEV_WEIGHT.get(d.severity, 0.7) * 20.0
                beh_pts = max(beh_pts, pts)
        if beh_pts > 0:
            total += beh_pts
            factors.append(f"Behavioral rule signal +{beh_pts:.1f}")

        zd_pts = 0.0
        for d in detections:
            if d.detector_type == "ZERODAY":
                zd_pts = max(zd_pts, (d.score or 0.0) * 15.0)
        if zd_pts > 0:
            total += zd_pts
            factors.append(f"Zero-day anomaly signal +{zd_pts:.1f} (capped at 15)")

        asset_pts = float(_ASSET_POINTS.get((asset_criticality or "MEDIUM").upper(), 5))
        total += asset_pts
        factors.append(f"Asset criticality {asset_criticality} +{asset_pts:.0f}")

        if len(detections) > 1:
            rep_pts = min(10.0, 2.5 * (len(detections) - 1))
            total += rep_pts
            factors.append(f"Repeated activity ({len(detections)} signals) +{rep_pts:.1f}")

        if correlation_strength > 0:
            corr_pts = correlation_strength * 10.0
            total += corr_pts
            factors.append(f"Correlation strength {correlation_strength:.2f} +{corr_pts:.1f}")

        mitre = sorted({t for d in detections for t in d.mitre_techniques})
        c2 = any(t.startswith("T1071") for t in mitre) or any(
            "c2" in str((d.evidence.get("tags") or [])).lower()
            for d in detections if d.detector_type == "IOC")
        if c2:
            total += 10.0
            factors.append("C2 indicator present +10")
        if mitre:
            m_pts = min(6.0, 2.0 * len(mitre))
            total += m_pts
            factors.append(f"MITRE relevance ({len(mitre)} techniques) +{m_pts:.0f}")

        score = max(0, min(100, int(round(total))))
        severity = severity_for_score(score)
        top = max(detections, key=lambda d: _SEV_ORDER.get(d.severity, 0)) if detections else None
        explanation = (f"{len(detections)} detection signal(s) combined into risk {score}/100 ({severity})"
                       + (f"; strongest: {top.rule_id} [{top.detector_type}/{top.severity}]" if top else "")
                       + ". No single model score determines this value.")
        return RiskAssessment(risk_score=score, severity=severity, risk_factors=factors, explanation=explanation)
