"""Shared detection persistence — all layers write Detection rows here."""
from sqlalchemy.orm import Session

from app.detection import DetectionResult
from app.models import Alert, Detection, DetectionMitre, MitreTechnique
from app.services.mitre_catalog import technique_meta

# Backwards-compat alias (canonical data now lives in mitre_catalog.CATALOG).
TECHNIQUE_META = {
    "T1059.001": ("Execution", "PowerShell"),
    "T1027": ("Defense Evasion", "Obfuscated Files or Information"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1071": ("Command and Control", "Command and Control"),
    "T1071.001": ("Command and Control", "Web Protocols"),
    "T1071.004": ("Command and Control", "DNS"),
    "T1055": ("Privilege Escalation", "Process Injection"),
    "T1078": ("Defense Evasion", "Valid Accounts"),
    "T1021.004": ("Lateral Movement", "SSH"),
    "T1021.002": ("Lateral Movement", "SMB/Windows Admin Shares"),
    "T1566.001": ("Initial Access", "Spearphishing Attachment"),
}


def ensure_technique_rows(db: Session, technique_ids: list[str]) -> None:
    for tid in technique_ids:
        if db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first() is None:
            tactic, name = technique_meta(tid)
            db.add(MitreTechnique(technique_id=tid, tactic=tactic, name=name))
    db.flush()


def persist_results(results: list[DetectionResult], db: Session) -> list[DetectionResult]:
    for res in results:
        ensure_technique_rows(db, res.mitre_techniques)
        db.add(Detection(id=res.detection_id, event_id=res.event_id, detector_type=res.detector_type,
                         rule_id=res.rule_id, severity=res.severity, confidence=res.confidence,
                         score=res.score, reasons=list(res.reasons), evidence=dict(res.evidence)))
        for tid in res.mitre_techniques:
            db.add(DetectionMitre(detection_id=res.detection_id, technique_id=tid))
        db.add(Alert(detection_id=res.detection_id, status="OPEN"))
    db.commit()
    return results
