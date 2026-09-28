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
import base64
import datetime
from config import ABUSEIPDB_API_KEY, OTX_API_KEY, ABUSECH_AUTH_KEY, VT_API_KEY, REQUEST_TIMEOUT


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


def feed_status():
    """Static per-feed wiring state: is this source configured right now?"""
    return [
        {"source": "AbuseIPDB", "configured": bool(ABUSEIPDB_API_KEY),
         "mode": "feed", "needs_key": True, "key_url": "https://www.abuseipdb.com/register"},
        {"source": "URLhaus", "configured": True,
         "mode": "feed", "needs_key": False,
         "note": "works keyless; abuse.ch Auth-Key raises rate limits (https://auth.abuse.ch/)"},
        {"source": "MalwareBazaar", "configured": bool(ABUSECH_AUTH_KEY),
         "mode": "feed", "needs_key": True, "key_url": "https://auth.abuse.ch/"},
        {"source": "OTX", "configured": bool(OTX_API_KEY),
         "mode": "feed", "needs_key": True, "key_url": "https://otx.alienvault.com/"},
        {"source": "VirusTotal", "configured": bool(VT_API_KEY),
         "mode": "enrichment", "needs_key": True, "key_url": "https://www.virustotal.com/gui/join-us",
         "note": "free tier is query-based (4 lookups/min), not a bulk feed"},
    ]


def collect_all_status():
    """Same as collect_all() but also reports per-feed outcome.

    Returns {"records": [...], "feeds": [{"source", "status", "records", ...}]}.
    collect_all() is unchanged for backwards compatibility.
    """
    merged = []
    feeds = []
    for name, fn in [("AbuseIPDB", collect_abuseipdb), ("URLhaus", collect_urlhaus),
                     ("MalwareBazaar", collect_malwarebazaar), ("OTX", collect_otx)]:
        try:
            recs = fn()
            merged += recs
            feeds.append({"source": name, "status": "ok", "records": len(recs)})
        except Exception as e:
            feeds.append({"source": name, "status": "error", "records": 0, "error": str(e)})
    print(f"[collect_all_status] pulled {len(merged)} raw records")
    return {"records": merged, "feeds": feeds}


def live_lookup(value, ioc_type=None):
    """Query a repo-miss indicator LIVE across configured sources.

    Display-only (nothing is stored): the verdict answers "what do our
    integrated APIs say about this value right now".
    Returns {"value", "type", "verdict": malicious|clean|unknown,
             "checked": [...], "flagged_by": [...], "details": {...}}.
    verdict = malicious if ANY source flags it; clean if at least one source
    was checked and none flagged; unknown if nothing could be checked.
    """
    from validator import detect_type

    value = (value or "").strip()
    ioc_type = ioc_type or detect_type(value)
    checked, flagged, details = [], [], {}

    def _get(url, headers=None, params=None, timeout=REQUEST_TIMEOUT):
        resp = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    # 1. URLhaus — exact-URL lookup, no key needed.
    if ioc_type == "url":
        try:
            resp = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                                 data={"url": value}, timeout=REQUEST_TIMEOUT)
            data = resp.json()
            checked.append("URLhaus")
            if data.get("query_status") == "ok":
                flagged.append("URLhaus")
                details["URLhaus"] = {"threat": data.get("threat"),
                                      "tags": data.get("tags"),
                                      "reporter": data.get("reporter")}
            else:
                details["URLhaus"] = {"result": data.get("query_status")}
        except requests.RequestException as e:
            details["URLhaus"] = {"error": str(e)}

    # 2. AbuseIPDB — reputation check, needs key.
    if ioc_type == "ip" and ABUSEIPDB_API_KEY:
        try:
            data = _get("https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                        params={"ipAddress": value, "maxAgeInDays": 90})
            score = int((data.get("data") or {}).get("abuseConfidenceScore", 0) or 0)
            checked.append("AbuseIPDB")
            details["AbuseIPDB"] = {"abuseConfidenceScore": score}
            if score >= 50:
                flagged.append("AbuseIPDB")
        except requests.RequestException as e:
            details["AbuseIPDB"] = {"error": str(e)}

    # 3. OTX — pulse membership, needs key.
    if OTX_API_KEY and ioc_type in ("ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"):
        otype = {"ip": "IPv4", "domain": "domain", "url": "URL"}.get(
            ioc_type, "FileHash")
        try:
            data = _get(f"https://otx.alienvault.com/api/v1/indicators/{otype}/{value}/general",
                        headers={"X-OTX-API-KEY": OTX_API_KEY})
            pulses = int((data.get("pulse_info") or {}).get("count", 0) or 0)
            checked.append("OTX")
            details["OTX"] = {"pulses": pulses}
            if pulses > 0:
                flagged.append("OTX")
        except requests.RequestException as e:
            details["OTX"] = {"error": str(e)}

    # 4. VirusTotal — vendor votes, needs key.
    if VT_API_KEY:
        vt = lookup_virustotal(value, ioc_type)
        if vt is not None:
            checked.append("VirusTotal")
            details["VirusTotal"] = {"malicious_votes": vt.get("vt_malicious_votes", 0),
                                     "tags": vt.get("tags", [])}
            if vt.get("vt_malicious_votes", 0) > 0:
                flagged.append("VirusTotal")

    verdict = "malicious" if flagged else ("clean" if checked else "unknown")
    return {"value": value, "type": ioc_type, "verdict": verdict,
            "checked": checked, "flagged_by": flagged, "details": details}


def lookup_virustotal(value, ioc_type=None):
    """Live VirusTotal v3 lookup for one indicator (enrichment, not a feed).

    Returns a raw-record-shaped dict, or None when: no API key configured,
    VT has never seen the value (HTTP 404 = clean/unknown), or the type is
    unsupported. reputation_hint scales with vendor detections:
    min(99, 55 + 3 * malicious_votes) when malicious > 0, else None.
    """
    import urllib.parse

    if not VT_API_KEY:
        return None
    value = (value or "").strip()
    if not value:
        return None
    if not ioc_type:
        from validator import detect_type
        ioc_type = detect_type(value)
    if ioc_type == "ip":
        endpoint = f"ip_addresses/{value}"
    elif ioc_type == "domain":
        endpoint = f"domains/{value}"
    elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        endpoint = f"files/{value.lower()}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        endpoint = f"urls/{urllib.parse.quote(url_id, safe='')}"
    else:
        return None

    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}",
                            headers={"x-apikey": VT_API_KEY}, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
    except requests.RequestException as e:
        print(f"[VirusTotal] lookup failed for {value}: {e}")
        return None

    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    tags = set()
    for cat in (attrs.get("categories") or {}).values():
        if cat:
            tags.add(str(cat).lower())
    for t in attrs.get("tags") or []:
        tags.add(str(t).lower())
    if attrs.get("country"):
        tags.add(f"country:{attrs['country']}")
    reputation = min(99, 55 + 3 * malicious) if malicious > 0 else None
    return {
        "raw_value": value,
        "type_hint": {"ip": "ip", "domain": "domain", "url": "url"}.get(ioc_type, "hash"),
        "source": "VirusTotal",
        "reputation_hint": reputation,
        "tags": sorted(tags),
        "seen_at": _now_iso(),
        "vt_malicious_votes": malicious,
    }


if __name__ == "__main__":
    recs = collect_all()
    for r in recs[:5]:
        print(r)
