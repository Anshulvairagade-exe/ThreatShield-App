"""
pipeline.py - runs the full Member 2 pipeline end to end:

  collect -> validate -> normalize -> dedup -> enrich -> store

Run this on a schedule (cron / APScheduler / systemd timer) to keep the
IOC database fresh.
"""

from collectors import collect_all
from validator import filter_valid
from normalizer import normalize_all
from dedup import deduplicate
from enrichment import enrich
from database import get_connection, get_ioc, upsert_ioc, count_iocs


def run_pipeline():
    print("=" * 50)
    print("STEP 1-2: Collecting from feeds...")
    raw_records = collect_all()

    print("STEP 3: Validating...")
    valid_records = filter_valid(raw_records)

    print("STEP 4: Normalizing...")
    normalized = normalize_all(valid_records)

    print("STEP 5: Deduplicating (batch)...")
    deduped = deduplicate(normalized)

    print("STEP 6-9: Enriching, scoring, mapping to MITRE...")
    conn = get_connection()
    new_count = 0
    updated_count = 0

    for item in deduped:
        existing = get_ioc(conn, item["ioc"], item["type"])
        enriched = enrich(item, existing_db_row=existing)

        print("STEP 10: Storing...")
        was_new = upsert_ioc(conn, enriched)
        if was_new:
            new_count += 1
        else:
            updated_count += 1

    conn.close()
    print("=" * 50)
    print(f"Pipeline complete. New IOCs: {new_count} | Updated IOCs: {updated_count}")
    print(f"Total IOCs in DB: {count_iocs(get_connection())}")


if __name__ == "__main__":
    run_pipeline()
