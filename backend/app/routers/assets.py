"""Assets + digital-twin topology — backend asset state, not hardcoded UI.

Topology edges are derived from real NETWORK event metadata: an edge links
a known host to the asset whose IP matches the event's dest_ip. When the DB
is empty the topology is empty and the frontend keeps its mock fallback.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Asset, Detection, IncidentEvent, SecurityEventMeta

router = APIRouter()


def _serialize(a: Asset) -> dict:
    return {"id": a.hostname, "asset_id": a.id, "name": a.hostname, "hostname": a.hostname,
            "ip": a.ip, "os": a.os, "type": a.type, "subnet": a.subnet, "user": a.user,
            "criticality": a.criticality, "status": a.status, "risk_score": a.risk_score,
            "last_seen": a.last_seen.isoformat() if a.last_seen else ""}


@router.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    rows = db.query(Asset).all()
    return {"count": len(rows), "assets": [_serialize(a) for a in rows]}


@router.get("/assets/{hostname}")
def get_asset(hostname: str, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.hostname == hostname).first()
    if not a:
        raise HTTPException(status_code=404, detail=f"Asset {hostname} not found")
    return _serialize(a)


@router.get("/twin/topology")
def twin_topology(db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.hostname).all()
    by_ip = {a.ip: a for a in assets if a.ip}
    nodes = []
    for i, a in enumerate(assets):
        node = _serialize(a)
        node.update({"x": 200 + (i % 3) * 320, "y": 120 + (i // 3) * 220})
        nodes.append(node)
    edges = []
    seen: set[tuple[str, str]] = set()
    metas = db.query(SecurityEventMeta).filter(SecurityEventMeta.event_type == "NETWORK").all()
    for m in metas:
        target = by_ip.get(m.dest_ip or "")
        if not target or not m.hostname or target.hostname == m.hostname:
            continue
        key = (m.hostname, target.hostname)
        if key in seen:
            continue
        seen.add(key)
        dets = db.query(Detection).filter(Detection.event_id == m.event_id).all()
        sev = max([d.severity for d in dets], default="LOW",
                  key=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index)
        edges.append({"id": f"{m.hostname}->{target.hostname}", "source": m.hostname,
                      "target": target.hostname, "label": f"NET {m.dest_ip}",
                      "severity": sev, "status": "active" if sev in ("HIGH", "CRITICAL") else "dormant"})
    return {"nodes": nodes, "edges": edges}
