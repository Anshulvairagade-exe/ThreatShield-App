"""
Step 6 - Enrichment

Takes a deduplicated IOC (from dedup.py) plus what's already in the DB
(if anything), and produces the final, fully-enriched record ready for
storage: reputation, confidence, MITRE mapping, lifecycle status.
"""

import datetime
from confidence import calculate_confidence
from lifecycle import compute_status
from mitre_mapper import map_to_mitre


def enrich(deduped_ioc, existing_db_row=None):
    """
    deduped_ioc: output of dedup.deduplicate() - one merged IOC
    existing_db_row: result of database.get_ioc() if this IOC already
                      exists, else None
    """
    now = datetime.datetime.utcnow().isoformat()

    last_seen = max(deduped_ioc["seen_at_values"], default=now)
    first_seen = existing_db_row["first_seen"] if existing_db_row else now
    is_new = existing_db_row is None

    reputation = None
    if deduped_ioc["reputation_hints"]:
        reputation = round(sum(deduped_ioc["reputation_hints"]) / len(deduped_ioc["reputation_hints"]))

    all_sources = deduped_ioc["sources"]
    if existing_db_row:
        all_sources = sorted(set(all_sources) | set(existing_db_row["sources"]))

    confidence = calculate_confidence(
        num_sources=len(all_sources),
        last_seen_iso=last_seen,
        reputation_hints=deduped_ioc["reputation_hints"],
    )

    status = compute_status(first_seen, last_seen, is_new_record=is_new)

    all_tags = deduped_ioc["tags"]
    if existing_db_row:
        all_tags = sorted(set(all_tags) | set(existing_db_row["tags"]))

    mitre = map_to_mitre(deduped_ioc["type"], all_tags)

    return {
        "ioc": deduped_ioc["ioc"],
        "type": deduped_ioc["type"],
        "sources": all_sources,
        "tags": all_tags,
        "reputation": reputation,
        "confidence": confidence,
        "mitre": mitre,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "status": status,
    }
