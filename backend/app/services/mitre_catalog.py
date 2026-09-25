"""MITRE catalogue — stored technique metadata, seeded into PostgreSQL.

Covers every technique the platform can emit (behavioral rules + TI mapper)
plus the tactics matrix the frontend currently hardcodes, so MITRE stops
being frontend mock data and becomes backend truth.
"""
from sqlalchemy.orm import Session

from app.models import MitreTechnique

# technique_id -> (tactic, tactic_id, technique_name, subtechnique)
CATALOG: dict[str, tuple[str, str, str, str]] = {
    # Initial Access
    "T1566.001": ("Initial Access", "TA0001", "Spearphishing Attachment", ""),
    "T1190": ("Initial Access", "TA0001", "Exploit Public-Facing Application", ""),
    # Execution
    "T1059.001": ("Execution", "TA0002", "PowerShell", ""),
    "T1059.003": ("Execution", "TA0002", "Windows Command Shell", ""),
    "T1204": ("Execution", "TA0002", "User Execution", ""),
    # Persistence
    "T1547": ("Persistence", "TA0003", "Boot or Logon Autostart Execution", ""),
    "T1053": ("Persistence", "TA0003", "Scheduled Task/Job", ""),
    "T1505": ("Persistence", "TA0003", "Server Software Component", ""),
    # Privilege Escalation
    "T1055": ("Privilege Escalation", "TA0004", "Process Injection", ""),
    "T1068": ("Privilege Escalation", "TA0004", "Exploitation for Privilege Escalation", ""),
    # Defense Evasion
    "T1027": ("Defense Evasion", "TA0005", "Obfuscated Files or Information", ""),
    "T1070": ("Defense Evasion", "TA0005", "Indicator Removal", ""),
    "T1078": ("Defense Evasion", "TA0005", "Valid Accounts", ""),
    # Credential Access
    "T1110": ("Credential Access", "TA0006", "Brute Force", ""),
    "T1003": ("Credential Access", "TA0006", "OS Credential Dumping", ""),
    "T1056.001": ("Credential Access", "TA0006", "Keylogging", ""),
    # Discovery
    "T1087": ("Discovery", "TA0007", "Account Discovery", ""),
    "T1046": ("Discovery", "TA0007", "Network Service Discovery", ""),
    # Lateral Movement
    "T1021.001": ("Lateral Movement", "TA0008", "Remote Desktop Protocol", ""),
    "T1021.002": ("Lateral Movement", "TA0008", "SMB/Windows Admin Shares", ""),
    "T1021.004": ("Lateral Movement", "TA0008", "SSH", ""),
    # Collection
    "T1005": ("Collection", "TA0009", "Data from Local System", ""),
    "T1560": ("Collection", "TA0009", "Archive Collected Data", ""),
    # Command and Control
    "T1071": ("Command and Control", "TA0011", "Application Layer Protocol", ""),
    "T1071.001": ("Command and Control", "TA0011", "Web Protocols", ""),
    "T1071.004": ("Command and Control", "TA0011", "DNS", ""),
    "T1573": ("Command and Control", "TA0011", "Encrypted Channel", ""),
    "T1584": ("Command and Control", "TA0011", "Compromise Infrastructure", ""),
    # Exfiltration
    "T1048": ("Exfiltration", "TA0010", "Exfiltration Over Alternative Protocol", ""),
    "T1041": ("Exfiltration", "TA0010", "Exfiltration Over C2 Channel", ""),
    # Impact
    "T1486": ("Impact", "TA0040", "Data Encrypted for Impact", ""),
}

TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
                "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Command and Control", "Exfiltration", "Impact"]


def technique_meta(technique_id: str) -> tuple[str, str]:
    """(tactic, name) for any technique — replaces ad-hoc maps elsewhere."""
    entry = CATALOG.get(technique_id)
    if entry:
        return entry[0], entry[2]
    return "Unknown", technique_id


def seed_catalog(db: Session) -> int:
    """Upsert the full catalogue. Returns number of techniques ensured."""
    for tid, (tactic, _tactic_id, name, sub) in CATALOG.items():
        row = db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first()
        if row is None:
            db.add(MitreTechnique(technique_id=tid, tactic=tactic, name=name, subtechnique=sub))
        else:
            row.tactic, row.name, row.subtechnique = tactic, name, sub
    db.commit()
    return len(CATALOG)
