"""Seed realistic local data: assets, users, IOCs, MITRE catalog + attack chain.

Usage:
    cd backend
    DATABASE_URL="postgresql+psycopg2://.../threatshield" python seed.py
    DATABASE_URL="sqlite:///./local.db" python seed.py   # local smoke

Idempotent: skips rows that already exist. The attack chain runs through the
real pipeline (ingest → detect → correlate → risk → incident), so the sample
incident is computed, not hardcoded.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings

DATABASE_URL = os.getenv("DATABASE_URL", get_settings().DATABASE_URL)
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

ASSETS = [
    {"hostname": "WIN-WORKSTATION-01", "ip": "10.20.4.15", "os": "Windows 11 Enterprise",
     "type": "workstation", "subnet": "WINDOWS-ENDPOINT-ZONE", "user": "victim.user",
     "criticality": "HIGH"},
    {"hostname": "UBUNTU-SERVER-01", "ip": "10.20.10.50", "os": "Ubuntu 22.04 LTS",
     "type": "server", "subnet": "UBUNTU-SERVER-ZONE", "user": "ubuntu-admin",
     "criticality": "CROWN_JEWEL"},
]

USERS = ["victim.user", "ubuntu-admin"]

IOCS = [
    {"ioc": "185.220.101.5", "type": "ip", "sources": ["AbuseIPDB", "AlienVault OTX"],
     "tags": ["C2", "botnet", "CobaltStrike"], "reputation": 92, "confidence": 0.91,
     "mitre": ["T1071.001"], "first_seen": "2026-08-21T09:12:00Z",
     "last_seen": "2026-09-19T22:45:00Z", "status": "Active"},
    {"ioc": "malicious-c2-tunnel.cc", "type": "domain", "sources": ["URLhaus"],
     "tags": ["phishing", "malware-download"], "reputation": 88, "confidence": 0.85,
     "mitre": ["T1566.002"], "first_seen": "2026-09-01T00:00:00Z",
     "last_seen": "2026-09-19T00:00:00Z", "status": "Active"},
]

# Scenario 1 (PS + malicious IP) + Scenario 3 (brute-force → success → lateral)
CHAIN = [
    {"event_id": "SEED-01", "event_type": "PROCESS", "hostname": "WIN-WORKSTATION-01",
     "user": "victim.user", "image": "powershell.exe", "parent_image": "excel.exe",
     "command_line": "powershell -enc aGVsbG8gd29ybGQgdGVzdA== -w hidden", "host_criticality": "HIGH"},
    {"event_id": "SEED-02", "event_type": "NETWORK", "hostname": "WIN-WORKSTATION-01",
     "user": "victim.user", "src_ip": "10.20.4.15", "dest_ip": "185.220.101.5",
     "dest_port": 443, "protocol": "tcp", "host_criticality": "HIGH"},
    {"event_id": "SEED-03", "timestamp": "2026-09-20T03:00:00Z", "event_type": "NETWORK",
     "hostname": "WIN-WORKSTATION-01", "user": "victim.user", "src_ip": "10.20.4.15",
     "dest_ip": "10.20.10.50", "dest_port": 22, "host_criticality": "HIGH"},
]


def main() -> None:
    from app.models import AppUser, Asset
    from app.repositories.ioc_repository import PostgresIOCRepository
    from app.services.mitre_catalog import seed_catalog
    from app.services.pipeline import run_raw

    db = Session()
    for spec in ASSETS:
        if not db.query(Asset).filter(Asset.hostname == spec["hostname"]).first():
            db.add(Asset(status="healthy", risk_score=10, **spec))
            print("asset+", spec["hostname"])
    for name in USERS:
        if not db.query(AppUser).filter(AppUser.name == name).first():
            db.add(AppUser(name=name))
            print("user+", name)
    db.commit()

    repo = PostgresIOCRepository(db)
    for ioc in IOCS:
        print(("ioc+" if repo.upsert(dict(ioc)) else "ioc="), ioc["ioc"])
    print("mitre catalog:", seed_catalog(db))

    incident_id = None
    for raw in CHAIN:
        out = run_raw("simulator", dict(raw), db)
        inc = out["incident"]
        print(raw["event_id"], "->", len(out["detections"]), "detections",
              ("incident " + inc.id[:8] + f" risk {inc.risk_score}" if inc else "no incident"))
        incident_id = (inc.id if inc else incident_id)

    if incident_id:
        win = db.query(Asset).filter(Asset.hostname == "WIN-WORKSTATION-01").first()
        win.status, win.risk_score = "compromised", 94
        db.commit()
        print("WIN-WORKSTATION-01 marked compromised (seed attack outcome)")
    db.close()
    print("seed done.")


if __name__ == "__main__":
    main()
