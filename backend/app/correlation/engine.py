"""CorrelationEngine — many detections, one incident.

Matches a new event's detections against OPEN incidents (NEW/TRIAGED/
INVESTIGATING) using shared entities inside a time window:
asset/hostname, user, source/destination IP, domain, IOC value,
process lineage, MITRE technique. Emits a cluster with related events,
timeline, entities and MITRE coverage; creates or attaches the incident.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.detection import DetectionResult
from app.models import Asset, Detection, DetectionMitre, Incident, IncidentEvent, SecurityEventMeta
from app.schemas.events import CanonicalSecurityEvent

OPEN_STATUSES = ("NEW", "TRIAGED", "INVESTIGATING")
ATTACH_THRESHOLD = 2.0


@dataclass
class IncidentCluster:
    incident_id: str | None
    is_new: bool
    correlation_strength: float
    related_event_ids: list[str] = field(default_factory=list)
    entities: dict = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)


def event_entities(event: CanonicalSecurityEvent, detections: list[DetectionResult]) -> dict:
    return {
        "hostname": event.asset.hostname,
        "host_ip": event.asset.ip,
        "user": event.user.name if event.user else "",
        "src_ip": event.network.src_ip if event.network else "",
        "dest_ip": event.network.dest_ip if event.network else "",
        "domain": event.dns.query_name if event.dns else "",
        "iocs": sorted({str(d.evidence.get("ioc")) for d in detections if d.detector_type == "IOC" and d.evidence.get("ioc")}),
        "process": f"{event.process.parent_image}->{event.process.image}" if event.process and event.process.parent_image else "",
        "mitre": sorted({t for d in detections for t in d.mitre_techniques}),
    }


def overlap_score(a: dict, b: dict) -> float:
    score = 0.0
    if a.get("hostname") and a["hostname"] == b.get("hostname"):
        score += 3
    if a.get("user") and a["user"] == b.get("user"):
        score += 2
    for key, pts in (("src_ip", 2), ("dest_ip", 2), ("domain", 2)):
        if a.get(key) and a[key] == b.get(key):
            score += pts
    # Lateral-movement chain: event host IP equals the other's src/dest IP.
    for host_key, ip_keys in (("host_ip", ("src_ip", "dest_ip")),):
        a_ips = {a.get(host_key), a.get("src_ip"), a.get("dest_ip")} - {""}
        b_ips = {b.get(host_key), b.get("src_ip"), b.get("dest_ip")} - {""}
        if a_ips & b_ips and (a.get(host_key) or b.get(host_key)):
            score += 2
    shared_iocs = set(a.get("iocs", [])) & set(b.get("iocs", []))
    score += 3 * len(shared_iocs)
    if a.get("process") and a["process"] == b.get("process"):
        score += 2
    shared_mitre = set(a.get("mitre", [])) & set(b.get("mitre", []))
    score += min(3.0, float(len(shared_mitre)))
    return score


class CorrelationEngine:
    def __init__(self, db: Session, window_minutes: int = 60):
        self.db = db
        self.window = timedelta(minutes=window_minutes)

    def correlate(self, event: CanonicalSecurityEvent, detections: list[DetectionResult]) -> IncidentCluster:
        entities = event_entities(event, detections)
        now = event.timestamp.replace(tzinfo=None) if isinstance(event.timestamp, datetime) else datetime.utcnow()
        best_id, best_strength, best_related = None, 0.0, []

        for inc in self.db.query(Incident).filter(Incident.status.in_(OPEN_STATUSES)).all():
            rows = self.db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).all()
            if not rows:
                continue
            metas = self.db.query(SecurityEventMeta).filter(
                SecurityEventMeta.event_id.in_([r.event_id for r in rows])).all()
            if not metas:
                continue
            # Window is satisfied by EITHER clock: event-time proximity (replayed
            # or backfilled sensors) or recency of incident activity (live stream
            # with skewed device timestamps). Both far apart → new incident.
            latest = max((m.timestamp for m in metas if m.timestamp), default=None)
            wall_now = datetime.utcnow()
            event_far = latest is not None and abs(now - latest) > self.window
            wall_far = inc.updated_at is not None and abs(wall_now - inc.updated_at) > self.window
            if event_far and wall_far:
                continue
            host_ips = {a.hostname: a.ip for a in
                        self.db.query(Asset).filter(Asset.hostname.in_([m.hostname for m in metas])).all()}
            prior_dets = self.db.query(Detection).filter(
                Detection.event_id.in_([m.event_id for m in metas])).all() if metas else []
            by_event: dict[str, list] = {}
            for d in prior_dets:
                by_event.setdefault(d.event_id, []).append(d)
            link_rows = self.db.query(DetectionMitre).filter(
                DetectionMitre.detection_id.in_([d.id for d in prior_dets])).all() if prior_dets else []
            mitre_by_det: dict[str, list] = {}
            for l in link_rows:
                mitre_by_det.setdefault(l.detection_id, []).append(l.technique_id)
            for m in metas:
                pseudo = [DetectionResult(detection_id=d.id, event_id=d.event_id, detector_type=d.detector_type,
                                          rule_id=d.rule_id, severity=d.severity, confidence=d.confidence,
                                          score=d.score, reasons=list(d.reasons or []),
                                          mitre_techniques=list(mitre_by_det.get(d.id, [])),
                                          evidence=dict(d.evidence or {}))
                          for d in by_event.get(m.event_id, [])]
                other = {"hostname": m.hostname, "host_ip": host_ips.get(m.hostname, ""),
                         "user": m.user, "src_ip": m.src_ip,
                         "dest_ip": m.dest_ip, "domain": m.domain,
                         "iocs": sorted({str(d.evidence.get("ioc")) for d in pseudo if d.detector_type == "IOC" and d.evidence.get("ioc")}),
                         "process": "", "mitre": sorted({t for d in pseudo for t in d.mitre_techniques})}
                s = overlap_score(entities, other)
                if s > best_strength:
                    best_strength, best_id = s, inc.id
                    best_related = [r.event_id for r in rows]

        mitre = sorted({t for d in detections for t in d.mitre_techniques})
        if best_id is not None and best_strength >= ATTACH_THRESHOLD:
            return IncidentCluster(incident_id=best_id, is_new=False,
                                   correlation_strength=min(1.0, best_strength / 8.0),
                                   related_event_ids=best_related, entities=entities,
                                   mitre_techniques=mitre)
        return IncidentCluster(incident_id=None, is_new=True, correlation_strength=0.0,
                               related_event_ids=[], entities=entities, mitre_techniques=mitre)
