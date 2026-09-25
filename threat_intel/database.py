"""
Step 10 - IOC Database (storage layer)

Using SQLite here so the whole pipeline runs standalone with zero setup.
Swap get_connection() for a psycopg2/SQLAlchemy Postgres connection once
Member 8 hands you the shared schema - the rest of this file barely
has to change.

Also does the SECOND pass of dedup: if an IOC already exists, we UPDATE
it (merge sources, bump last_seen, recompute confidence) instead of
inserting a duplicate row.
"""

import sqlite3
import json
import datetime
import os
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc TEXT NOT NULL,
    type TEXT NOT NULL,
    sources TEXT NOT NULL,        -- JSON list
    tags TEXT NOT NULL,           -- JSON list
    reputation INTEGER,
    confidence REAL,
    mitre TEXT NOT NULL,          -- JSON list
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL,
    UNIQUE(ioc, type)
);
"""


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(SCHEMA)
    return conn


def upsert_ioc(conn, enriched):
    """
    enriched is a fully-processed IOC dict (post enrichment/confidence/mitre):
    {
      "ioc", "type", "sources": [...], "tags": [...], "reputation": int,
      "confidence": float, "mitre": [...], "last_seen": iso str, "status": str
    }
    Returns True if this was a brand-new IOC, False if it merged into an existing one.
    """
    cur = conn.cursor()
    cur.execute("SELECT sources, tags, first_seen FROM iocs WHERE ioc=? AND type=?",
                (enriched["ioc"], enriched["type"]))
    row = cur.fetchone()
    now = datetime.datetime.utcnow().isoformat()

    if row is None:
        cur.execute("""
            INSERT INTO iocs (ioc, type, sources, tags, reputation, confidence,
                               mitre, first_seen, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            enriched["ioc"], enriched["type"],
            json.dumps(enriched["sources"]), json.dumps(enriched["tags"]),
            enriched.get("reputation"), enriched["confidence"],
            json.dumps(enriched["mitre"]),
            enriched.get("first_seen", now), enriched.get("last_seen", now),
            enriched["status"],
        ))
        conn.commit()
        return True
    else:
        existing_sources = set(json.loads(row[0]))
        existing_tags = set(json.loads(row[1]))
        first_seen = row[2]
        merged_sources = sorted(existing_sources | set(enriched["sources"]))
        merged_tags = sorted(existing_tags | set(enriched["tags"]))

        cur.execute("""
            UPDATE iocs SET sources=?, tags=?, reputation=?, confidence=?,
                             mitre=?, last_seen=?, status=?
            WHERE ioc=? AND type=?
        """, (
            json.dumps(merged_sources), json.dumps(merged_tags),
            enriched.get("reputation"), enriched["confidence"],
            json.dumps(enriched["mitre"]), enriched.get("last_seen", now),
            enriched["status"], enriched["ioc"], enriched["type"],
        ))
        conn.commit()
        return False


def get_ioc(conn, ioc_value, ioc_type=None):
    cur = conn.cursor()
    if ioc_type:
        cur.execute("SELECT * FROM iocs WHERE ioc=? AND type=?", (ioc_value, ioc_type))
    else:
        cur.execute("SELECT * FROM iocs WHERE ioc=?", (ioc_value,))
    row = cur.fetchone()
    if not row:
        return None
    cols = [d[0] for d in cur.description]
    result = dict(zip(cols, row))
    result["sources"] = json.loads(result["sources"])
    result["tags"] = json.loads(result["tags"])
    result["mitre"] = json.loads(result["mitre"])
    return result


def count_iocs(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM iocs")
    return cur.fetchone()[0]


if __name__ == "__main__":
    conn = get_connection()
    print("Current IOC count:", count_iocs(conn))
