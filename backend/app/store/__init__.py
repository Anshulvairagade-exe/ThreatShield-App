"""EventStore abstraction — hot telemetry lives in OpenSearch, not Postgres.

Index strategy (documented):
  - Daily indexes: threatshield-events-YYYY.MM.DD (timezone UTC)
  - Alias for reads: threatshield-events (all daily indexes)
  - Mapping: event_id/hostname/user/IP/domain keyword|ip, timestamp date,
    event_type/source/incident_id keyword, raw object with index:false,
    full flattened canonical stored for investigation replay.
  - ILM expectation (ops): rollover daily, delete after 30-90d.

Phase 2 ships OpenSearchEventStore (real) + InMemoryEventStore (local/tests
fallback when OpenSearch is unreachable). Factory prefers OpenSearch and
degrades gracefully — ingestion never fails just because search is down.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from app.core import logger
from app.schemas.events import CanonicalSecurityEvent

INDEX_ALIAS = "threatshield-events"

EVENT_MAPPING = {
    "mappings": {
        "properties": {
            "event_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "source": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "asset": {"properties": {"hostname": {"type": "keyword"}, "ip": {"type": "ip", "ignore_malformed": True}}},
            "user": {"type": "keyword"},
            "src_ip": {"type": "ip", "ignore_malformed": True},
            "dest_ip": {"type": "ip", "ignore_malformed": True},
            "ip": {"type": "ip", "ignore_malformed": True},
            "domain": {"type": "keyword"},
            "incident_id": {"type": "keyword"},
            "mitre_hint": {"type": "keyword"},
            "raw": {"type": "object", "enabled": False},
            "full": {"type": "object", "enabled": False},
        }
    }
}


def daily_index(ts: datetime | None = None) -> str:
    ts = ts or datetime.now(timezone.utc)
    return f"threatshield-events-{ts.strftime('%Y.%m.%d')}"


class EventStore(ABC):
    @abstractmethod
    def index(self, event: CanonicalSecurityEvent) -> str:
        """Store event, return index/doc id."""

    @abstractmethod
    def get(self, event_id: str) -> dict | None:
        ...

    @abstractmethod
    def search(self, limit: int = 50, **filters: str) -> list[dict]:
        """Supported filters: event_id, asset/hostname, user, ip, domain,
        event_type, incident_id, source, from_ts, to_ts."""


class InMemoryEventStore(EventStore):
    def __init__(self) -> None:
        self._docs: dict[str, dict] = {}

    def index(self, event: CanonicalSecurityEvent) -> str:
        doc = event.search_doc()
        self._docs[event.event_id] = doc
        return "memory"

    def get(self, event_id: str) -> dict | None:
        return self._docs.get(event_id)

    def search(self, limit: int = 50, **filters: str) -> list[dict]:
        out: list[dict] = []
        for doc in self._docs.values():
            if _matches(doc, filters):
                out.append(doc)
            if len(out) >= limit:
                break
        return out

    def clear(self) -> None:
        self._docs.clear()


def _matches(doc: dict, filters: dict) -> bool:
    full = doc.get("full", doc)
    asset = full.get("asset", {}) if isinstance(full, dict) else {}
    network = full.get("network") or {}
    dns = full.get("dns") or {}
    for key, val in filters.items():
        if not val:
            continue
        if key == "event_id" and doc.get("event_id") != val:
            return False
        elif key in ("asset", "hostname") and (asset.get("hostname") or doc.get("hostname")) != val:
            return False
        elif key == "user":
            u = full.get("user") if isinstance(full.get("user"), str) else (full.get("user") or {}).get("name", "")
            if (u or doc.get("user")) != val:
                return False
        elif key == "ip":
            ips = {network.get("src_ip", ""), network.get("dest_ip", ""), doc.get("src_ip", ""), doc.get("dest_ip", "")}
            if val not in ips:
                return False
        elif key == "domain" and (dns.get("query_name", "") or doc.get("domain", "")) != val:
            return False
        elif key == "event_type" and doc.get("event_type") != val:
            return False
        elif key == "incident_id" and doc.get("incident_id") != val:
            return False
        elif key == "source" and doc.get("source") != val:
            return False
        elif key == "from_ts" and doc.get("timestamp", "") < val:
            return False
        elif key == "to_ts" and doc.get("timestamp", "") > val:
            return False
    return True


class OpenSearchEventStore(EventStore):
    def __init__(self, url: str):
        from opensearchpy import OpenSearch

        self.client = OpenSearch(hosts=[url], timeout=5)
        self.url = url

    def index(self, event: CanonicalSecurityEvent) -> str:
        idx = daily_index(event.timestamp)
        try:
            if not self.client.indices.exists(index=idx):
                self.client.indices.create(index=idx, body=EVENT_MAPPING)
        except Exception as e:
            logger.warning("opensearch index-create skipped: %s", e)
        self.client.index(index=idx, id=event.event_id, body=event.search_doc(), refresh=False)
        return idx

    def get(self, event_id: str) -> dict | None:
        try:
            res = self.client.search(index=f"{INDEX_ALIAS}*", body={"query": {"term": {"event_id": event_id}}, "size": 1})
            hits = res.get("hits", {}).get("hits", [])
            return hits[0]["_source"] if hits else None
        except Exception as e:
            logger.warning("opensearch get failed: %s", e)
            return None

    def search(self, limit: int = 50, **filters: str) -> list[dict]:
        must: list[dict] = []
        for key, val in filters.items():
            if not val:
                continue
            if key in ("from_ts", "to_ts"):
                continue
            field = {"asset": "hostname", "hostname": "hostname"}.get(key, key)
            must.append({"term": {field: val}})
        rng: dict = {}
        if filters.get("from_ts"):
            rng["gte"] = filters["from_ts"]
        if filters.get("to_ts"):
            rng["lte"] = filters["to_ts"]
        if rng:
            must.append({"range": {"timestamp": rng}})
        body = {"query": {"bool": {"filter": must}} if must else {"match_all": {}}, "size": min(limit, 500), "sort": [{"timestamp": "desc"}]}
        try:
            res = self.client.search(index=f"{INDEX_ALIAS}*", body=body)
            return [h["_source"] for h in res.get("hits", {}).get("hits", [])]
        except Exception as e:
            logger.warning("opensearch search failed: %s", e)
            return []


_memory = InMemoryEventStore()


def get_event_store() -> EventStore:
    """Prefer OpenSearch when reachable, else in-memory. Never raises."""
    import os

    if os.getenv("THREATSHIELD_EVENT_STORE", "") == "memory":
        return _memory
    from app.config import get_settings

    url = get_settings().OPENSEARCH_URL
    try:
        from opensearchpy import OpenSearch

        client = OpenSearch(hosts=[url], timeout=2)
        if client.ping():
            return OpenSearchEventStore(url)
    except Exception as e:
        logger.info("opensearch unreachable (%s) — using in-memory store", e)
    return _memory


def get_memory_store() -> InMemoryEventStore:
    return _memory
