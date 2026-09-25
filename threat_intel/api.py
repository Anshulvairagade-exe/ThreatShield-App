"""
Step 11 - Query API for Member 5 (Detection) / Member 8 (Backend)

A minimal FastAPI service exposing IOC lookups. Coordinate with Member 8
before deploying this standalone - they may want you to expose these as
functions they import into their FastAPI app instead of running a
second separate server. This file works either way:

  - Run standalone:  uvicorn api:app --reload --port 8001
  - Or import `lookup_ioc()` directly into Member 8's FastAPI app.
"""

from fastapi import FastAPI, HTTPException
from database import get_connection, get_ioc

app = FastAPI(title="Threat Intel IOC Lookup API")


def lookup_ioc(value: str, ioc_type: str = None):
    conn = get_connection()
    result = get_ioc(conn, value, ioc_type)
    conn.close()

    if not result:
        return {"found": False, "ioc": value}

    return {
        "found": True,
        "ioc": result["ioc"],
        "type": result["type"],
        "reputation": result["reputation"],
        "confidence": result["confidence"],
        "sources": result["sources"],
        "tags": result["tags"],
        "mitre": result["mitre"],
        "status": result["status"],
        "first_seen": result["first_seen"],
        "last_seen": result["last_seen"],
    }


@app.get("/ioc/{value}")
def get_ioc_endpoint(value: str, type: str = None):
    """
    Example: GET /ioc/185.220.101.5?type=ip
    Returns found=false if it's not in the threat-intel DB (i.e. clean).
    """
    result = lookup_ioc(value, type)
    return result


@app.get("/health")
def health():
    return {"status": "ok"}


# Example of the exact response shape Member 5 / Member 8 should expect:
#
# {
#   "found": true,
#   "ioc": "185.x.x.x",
#   "type": "ip",
#   "reputation": 92,
#   "confidence": 0.91,
#   "sources": ["AbuseIPDB", "OTX"],
#   "tags": ["C2", "botnet"],
#   "mitre": ["T1071"],
#   "status": "Active",
#   "first_seen": "...",
#   "last_seen": "..."
# }
