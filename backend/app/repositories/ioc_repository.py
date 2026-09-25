"""IOCRepository — storage interface; PostgreSQL is the target store.

The existing threat_intel/database.py (SQLite) is retired after migration;
all backend code talks to this interface. Second-pass dedup semantics
(merge sources/tags on conflict) are preserved from the original upsert.
"""
from abc import ABC, abstractmethod

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Ioc


class IOCRepository(ABC):
    @abstractmethod
    def get(self, ioc_value: str, ioc_type: str | None = None) -> dict | None:
        ...

    @abstractmethod
    def upsert(self, enriched: dict) -> bool:
        """Store enriched IOC. Returns True if brand-new, False if merged."""

    @abstractmethod
    def count(self) -> int:
        ...


def _row_to_dict(row: Ioc) -> dict:
    return {
        "ioc": row.ioc,
        "type": row.type,
        "sources": list(row.sources or []),
        "tags": list(row.tags or []),
        "reputation": row.reputation,
        "confidence": row.confidence,
        "mitre": list(row.mitre or []),
        "country": row.country or "",
        "asn": row.asn or "",
        "first_seen": row.first_seen or "",
        "last_seen": row.last_seen or "",
        "status": row.status or "",
    }


class PostgresIOCRepository(IOCRepository):
    def __init__(self, db: Session):
        self.db = db

    def get(self, ioc_value: str, ioc_type: str | None = None) -> dict | None:
        q = self.db.query(Ioc).filter(Ioc.ioc == ioc_value)
        if ioc_type:
            q = q.filter(Ioc.type == ioc_type)
        row = q.first()
        return _row_to_dict(row) if row else None

    def upsert(self, enriched: dict) -> bool:
        row = (
            self.db.query(Ioc)
            .filter(Ioc.ioc == enriched["ioc"], Ioc.type == enriched["type"])
            .first()
        )
        if row is None:
            self.db.add(
                Ioc(
                    ioc=enriched["ioc"],
                    type=enriched["type"],
                    sources=list(enriched.get("sources", [])),
                    tags=list(enriched.get("tags", [])),
                    reputation=enriched.get("reputation"),
                    confidence=enriched.get("confidence"),
                    mitre=list(enriched.get("mitre", [])),
                    country=enriched.get("country", ""),
                    asn=enriched.get("asn", ""),
                    first_seen=enriched.get("first_seen", ""),
                    last_seen=enriched.get("last_seen", ""),
                    status=enriched.get("status", "New"),
                )
            )
            self.db.commit()
            return True
        row.sources = sorted(set(row.sources or []) | set(enriched.get("sources", [])))
        row.tags = sorted(set(row.tags or []) | set(enriched.get("tags", [])))
        row.reputation = enriched.get("reputation")
        row.confidence = enriched.get("confidence")
        row.mitre = list(enriched.get("mitre", []))
        row.last_seen = enriched.get("last_seen", row.last_seen)
        row.status = enriched.get("status", row.status)
        self.db.commit()
        return False

    def count(self) -> int:
        return self.db.query(func.count(Ioc.id)).scalar() or 0
