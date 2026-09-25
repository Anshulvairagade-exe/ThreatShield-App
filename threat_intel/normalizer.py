"""
Step 4 - IOC Normalizer

Takes validated records and forces every field into one consistent shape,
regardless of which feed it came from. This is what makes deduplication
in Step 5 actually work.
"""

from urllib.parse import urlparse, urlunparse


def normalize_domain(value):
    v = value.strip().lower()
    if v.startswith("www."):
        v = v[4:]
    return v.rstrip(".")


def normalize_ip(value):
    return value.strip()


def normalize_url(value):
    v = value.strip()
    parsed = urlparse(v)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    path = parsed.path or ""
    # drop trailing slash on bare paths, keep query string as-is
    if path == "/":
        path = ""
    normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return normalized


def normalize_hash(value):
    return value.strip().lower()


_NORMALIZERS = {
    "domain": normalize_domain,
    "ip": normalize_ip,
    "url": normalize_url,
    "hash_md5": normalize_hash,
    "hash_sha1": normalize_hash,
    "hash_sha256": normalize_hash,
}


def normalize_record(record):
    """record must already have 'confirmed_type' from the validator step."""
    ctype = record["confirmed_type"]
    fn = _NORMALIZERS.get(ctype)
    normalized_value = fn(record["raw_value"]) if fn else record["raw_value"].strip()

    out = dict(record)
    out["ioc"] = normalized_value
    out["type"] = ctype
    return out


def normalize_all(records):
    normalized = [normalize_record(r) for r in records]
    print(f"[normalizer] normalized {len(normalized)} records")
    return normalized


if __name__ == "__main__":
    sample = {"raw_value": "HTTP://EVIL.COM/", "confirmed_type": "url"}
    print(normalize_record(sample))
    sample2 = {"raw_value": "Evil.com", "confirmed_type": "domain"}
    print(normalize_record(sample2))
