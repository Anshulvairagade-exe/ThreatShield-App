"""
Step 5 - Deduplication

Multiple feeds often report the same indicator. Instead of storing
"evil.com" three times, merge into ONE IOC entry with sources=[...].

This runs in-memory, on the batch you just normalized, BEFORE it ever
touches the database. The database layer (Step 10) does a second layer
of dedup against what's already stored, via upsert.
"""

from collections import defaultdict


def deduplicate(records):
    """
    Input: list of normalized records (each has 'ioc' and 'type').
    Output: list of merged IOC dicts:
        {
            "ioc": ...,
            "type": ...,
            "sources": [...],
            "tags": [...],
            "seen_at_values": [...],   # every timestamp seen this batch
        }
    """
    grouped = defaultdict(lambda: {
        "sources": set(),
        "tags": set(),
        "seen_at_values": [],
        "reputation_hints": [],
    })

    for r in records:
        key = (r["type"], r["ioc"])
        bucket = grouped[key]
        bucket["sources"].add(r["source"])
        for t in r.get("tags", []) or []:
            bucket["tags"].add(t)
        if r.get("seen_at"):
            bucket["seen_at_values"].append(r["seen_at"])
        if r.get("reputation_hint") is not None:
            bucket["reputation_hints"].append(r["reputation_hint"])

    merged = []
    for (ioc_type, ioc_value), bucket in grouped.items():
        merged.append({
            "ioc": ioc_value,
            "type": ioc_type,
            "sources": sorted(bucket["sources"]),
            "tags": sorted(bucket["tags"]),
            "seen_at_values": bucket["seen_at_values"],
            "reputation_hints": bucket["reputation_hints"],
        })

    print(f"[dedup] {len(records)} records -> {len(merged)} unique IOCs")
    return merged


if __name__ == "__main__":
    sample = [
        {"ioc": "evil.com", "type": "domain", "source": "OTX", "tags": ["c2"], "seen_at": "2026-01-01"},
        {"ioc": "evil.com", "type": "domain", "source": "URLhaus", "tags": [], "seen_at": "2026-01-02"},
    ]
    print(deduplicate(sample))
