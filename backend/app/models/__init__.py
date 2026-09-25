"""Phase 1 ORM models — full table skeleton so Alembic has a stable target.

Later phases add columns/indexes via new migrations; never edit this
initial migration after it is applied.
"""
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    os: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    type: Mapped[str] = mapped_column(String(64), nullable=False, default="workstation")
    subnet: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    user: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    criticality: Mapped[str] = mapped_column(String(32), nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="healthy")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)


class AppUser(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    privileged: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disabled: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SecurityEventMeta(Base):
    __tablename__ = "security_events_metadata"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="simulator")
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, default="PROCESS")
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    user: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    dest_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    incident_id: Mapped[str] = mapped_column(String(36), nullable=True)


class Ioc(Base):
    __tablename__ = "iocs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ioc: Mapped[str] = mapped_column(String(1024), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reputation: Mapped[int] = mapped_column(Integer, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=True)
    mitre: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    country: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    asn: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    first_seen: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    last_seen: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="New")
    __table_args__ = (UniqueConstraint("ioc", "type", name="uq_ioc_type"),)


class ThreatSource(Base):
    __tablename__ = "threat_sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    last_run: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Detection(Base):
    __tablename__ = "detections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    detector_type: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="LOW")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    detection_id: Mapped[str] = mapped_column(String(36), ForeignKey("detections.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="MEDIUM")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)
    primary_asset_id: Mapped[str] = mapped_column(String(36), nullable=True)
    assigned_analyst: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    risk_explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)


class IncidentIoc(Base):
    __tablename__ = "incident_iocs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    ioc_id: Mapped[str] = mapped_column(String(36), ForeignKey("iocs.id"), nullable=False)


class IncidentAsset(Base):
    __tablename__ = "incident_assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)


class IncidentUser(Base):
    __tablename__ = "incident_users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"
    technique_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tactic: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    subtechnique: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class DetectionMitre(Base):
    __tablename__ = "detection_mitre"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    detection_id: Mapped[str] = mapped_column(String(36), ForeignKey("detections.id"), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(32), ForeignKey("mitre_techniques.technique_id"), nullable=False)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(String(36), ForeignKey("investigations.id"), nullable=False)
    author: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="SIMULATION")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="REQUESTED")
    actor: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    result: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    action_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)
    actor: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    incident_id: Mapped[str] = mapped_column(String(36), nullable=True)
    result: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    log_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    enabled: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="MEDIUM")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    mitre: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ModelMetadata(Base):
    __tablename__ = "model_metadata"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    trained_at: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    thresholds: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    loaded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)
