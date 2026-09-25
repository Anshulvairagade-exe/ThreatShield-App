"""
Step 2 - Feed Collectors

Each collector hits one public threat-intel source and returns a list of
raw records in ONE common shape, so nothing downstream needs to know
which feed a record came from:

{
    "raw_value": str,      # the indicator exactly as the feed gave it
    "type_hint": str,      # feed's own guess at type: "ip"/"domain"/"url"/"hash"
    "source": str,         # feed name
    "reputation_hint": int or None,
    "tags": list[str],
    "seen_at": str (ISO8601)
}
"""

import requests
import datetime
from config import ABUSEIPDB_API_KEY, OTX_API_KEY, ABUSECH_AUTH_KEY, REQUEST_TIMEOUT


def _now_iso():
    return datetime.datetime.utcnow().isoformat()


def collect_abuseipdb(limit=100):
    """Malicious IPs from AbuseIPDB's blacklist endpoint."""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"limit": limit, "confidenceMinimum": 50}
    out = []
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        for entry in data:
            out.append({
                "raw_value": entry.get("ipAddress"),
                "type_hint": "ip",
                "source": "AbuseIPDB",
                "reputation_hint": entry.get("abuseConfidenceScore"),
                "tags": [],
                "seen_at": entry.get("lastReportedAt", _now_iso()),
            })
    except requests.RequestException as e:
        print(f"[AbuseIPDB] collection failed: {e}")
    return out


def collect_urlhaus(limit=100):
    """Recent malicious URLs from URLhaus. No API key required."""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    out = []
    try:
        resp = requests.post(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return out
        for entry in data.get("urls", [])[:limit]:
            out.append({
                "raw_value": entry.get("url"),
                "type_hint": "url",
                "source": "URLhaus",
                "reputation_hint": None,
                "tags": entry.get("tags") or [],
                "seen_at": entry.get("dateadded", _now_iso()),
            })
    except requests.RequestException as e:
        print(f"[URLhaus] collection failed: {e}")
    return out


def collect_malwarebazaar(limit=100):
    """Recent malware file hashes from MalwareBazaar.
    abuse.ch now requires a free Auth-Key: https://auth.abuse.ch/"""
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    out = []
    try:
        resp = requests.post(url, headers=headers,
                              data={"query": "get_recent", "selector": "time"},
                              timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return out
        for entry in data.get("data", [])[:limit]:
            out.append({
                "raw_value": entry.get("sha256_hash"),
                "type_hint": "hash",
                "source": "MalwareBazaar",
                "reputation_hint": None,
                "tags": entry.get("tags") or [],
                "seen_at": entry.get("first_seen", _now_iso()),
            })
    except requests.RequestException as e:
        print(f"[MalwareBazaar] collection failed: {e}")
    return out


def collect_otx(limit=50):
    """IOCs pulled from pulses you're subscribed to on AlienVault OTX."""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    out = []
    try:
        resp = requests.get(url, headers=headers, params={"limit": limit}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        pulses = resp.json().get("results", [])
        for pulse in pulses:
            tags = pulse.get("tags", [])
            for indicator in pulse.get("indicators", []):
                itype_raw = indicator.get("type", "").lower()
                type_hint = {
                    "ipv4": "ip", "ipv6": "ip",
                    "domain": "domain", "hostname": "domain",
                    "url": "url",
                    "filehash-md5": "hash", "filehash-sha1": "hash", "filehash-sha256": "hash",
                }.get(itype_raw, "unknown")
                out.append({
                    "raw_value": indicator.get("indicator"),
                    "type_hint": type_hint,
                    "source": "OTX",
                    "reputation_hint": None,
                    "tags": tags,
                    "seen_at": indicator.get("created", _now_iso()),
                })
    except requests.RequestException as e:
        print(f"[OTX] collection failed: {e}")
    return out


def collect_all():
    """Run every collector and merge the raw record lists."""
    records = []
    records += collect_abuseipdb()
    records += collect_urlhaus()
    records += collect_malwarebazaar()
    records += collect_otx()
    print(f"[collect_all] pulled {len(records)} raw records")
    return records


if __name__ == "__main__":
    recs = collect_all()
    for r in recs[:5]:
        print(r)
