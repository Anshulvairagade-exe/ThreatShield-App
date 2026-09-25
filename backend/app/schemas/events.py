"""Canonical security event schema — the single contract for all ingestion.

Everything entering ThreatShield (simulator now, Wazuh/Zeek later) MUST be
converted into CanonicalSecurityEvent. Extensible via extra="allow".
"""
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

EventType = Literal["AUTH", "PROCESS", "NETWORK", "DNS", "FILE", "WEB", "FIREWALL", "ENDPOINT"]
SourceType = Literal["simulator", "wazuh", "zeek"]


class AssetInfo(BaseModel):
    hostname: str = ""
    ip: str = ""
    os: str = ""
    criticality: str = "MEDIUM"

    model_config = {"extra": "allow"}


class UserInfo(BaseModel):
    name: str = ""
    domain: str = ""
    privileged: bool = False

    model_config = {"extra": "allow"}


class ProcessInfo(BaseModel):
    image: str = ""
    parent_image: str = ""
    command_line: str = ""
    pid: int | None = None
    ppid: int | None = None

    model_config = {"extra": "allow"}


class NetworkInfo(BaseModel):
    src_ip: str = ""
    src_port: int | None = None
    dest_ip: str = ""
    dest_port: int | None = None
    protocol: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0

    model_config = {"extra": "allow"}


class DnsInfo(BaseModel):
    query_name: str = ""
    query_type: str = ""
    answers: list[str] = Field(default_factory=list)

    model_config = {"extra": "allow"}


class AuthInfo(BaseModel):
    event_code: str = ""
    status: str = ""
    logon_type: str = ""
    failure_count: int = 0

    model_config = {"extra": "allow"}


class CanonicalSecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: SourceType = "simulator"
    event_type: EventType = "PROCESS"
    asset: AssetInfo = Field(default_factory=AssetInfo)
    user: UserInfo | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    dns: DnsInfo | None = None
    authentication: AuthInfo | None = None
    mitre_hint: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
    incident_id: str | None = None

    model_config = {"extra": "allow"}

    def search_doc(self) -> dict[str, Any]:
        """Flattened doc for OpenSearch indexing."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "asset": {"hostname": self.asset.hostname, "ip": self.asset.ip},
            "hostname": self.asset.hostname,
            "user": self.user.name if self.user else "",
            "src_ip": self.network.src_ip if self.network else "",
            "dest_ip": self.network.dest_ip if self.network else "",
            "ip": self.network.dest_ip if self.network else "",
            "domain": self.dns.query_name if self.dns else "",
            "incident_id": self.incident_id or "",
            "mitre_hint": self.mitre_hint,
            "raw": self.raw,
            "full": self.model_dump(mode="json"),
        }
