"""Ingestion service — the ONLY path events take into the platform.

Adapter → PostgreSQL metadata pointer → OpenSearch full doc.
Raw high-volume payloads stay in OpenSearch; Postgres keeps the pointer row.
"""
from sqlalchemy.orm import Session

from app.adapters import get_adapter
from app.core import logger
from app.models import SecurityEventMeta
from app.schemas.events import CanonicalSecurityEvent
from app.store import get_event_store


def ingest_raw(source: str, raw: dict, db: Session) -> CanonicalSecurityEvent:
    adapter = get_adapter(source)
    event = adapter.normalize(raw)
    return persist_event(event, db)


def persist_event(event: CanonicalSecurityEvent, db: Session) -> CanonicalSecurityEvent:
    meta = SecurityEventMeta(
        event_id=event.event_id,
        timestamp=event.timestamp.replace(tzinfo=None),
        source=event.source,
        event_type=event.event_type,
        hostname=event.asset.hostname,
        user=event.user.name if event.user else "",
        src_ip=event.network.src_ip if event.network else "",
        dest_ip=event.network.dest_ip if event.network else "",
        domain=event.dns.query_name if event.dns else "",
        incident_id=event.incident_id,
    )
    db.merge(meta)
    db.commit()
    try:
        get_event_store().index(event)
    except Exception as e:
        logger.warning("event store index failed for %s: %s", event.event_id, e)
    return event
