"""
Step 3 - IOC Validator

Confirms a raw_value is actually a well-formed indicator of its claimed
type, and rejects junk. Returns the CONFIRMED type (never trust type_hint
blindly - e.g. a feed might mislabel a URL as a domain).
"""

import re
import ipaddress

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
)
URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# Local/reserved ranges we don't want polluting the intel DB
_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "0.0.0.0/8"]
]


def _is_private_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def detect_type(value):
    """Figure out the real type of a raw indicator string. Returns None if invalid."""
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None

    if URL_RE.match(value):
        return "url"
    if IPV4_RE.match(value):
        try:
            ipaddress.ip_address(value)
            if _is_private_ip(value):
                return None
            return "ip"
        except ValueError:
            return None
    if SHA256_RE.match(value):
        return "hash_sha256"
    if SHA1_RE.match(value):
        return "hash_sha1"
    if MD5_RE.match(value):
        return "hash_md5"
    if DOMAIN_RE.match(value):
        return "domain"
    return None


def validate_record(record):
    """
    Takes a raw collector record, returns (is_valid, confirmed_type).
    Does NOT mutate the record.
    """
    value = (record.get("raw_value") or "").strip()
    confirmed_type = detect_type(value)
    return (confirmed_type is not None, confirmed_type)


def filter_valid(records):
    """Given a list of raw records, return only the valid ones, each tagged
    with its confirmed_type."""
    valid = []
    for r in records:
        ok, ctype = validate_record(r)
        if ok:
            r = dict(r)
            r["confirmed_type"] = ctype
            valid.append(r)
    print(f"[validator] {len(valid)}/{len(records)} records valid")
    return valid


if __name__ == "__main__":
    tests = ["192.168.1.10", "8.8.8.8", "evil-example.com", "https://evil.com/x",
              "random text", "d41d8cd98f00b204e9800998ecf8427e"]
    for t in tests:
        print(t, "->", detect_type(t))
