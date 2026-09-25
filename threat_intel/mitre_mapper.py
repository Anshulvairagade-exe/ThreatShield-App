"""
Step 9 - MITRE ATT&CK Mapping

Simple, explainable keyword-based mapping from an IOC's tags/type to
ATT&CK technique IDs. Not exhaustive - extend this table as your team's
attack scenarios (Member 4) grow.
"""

# tag keyword (lowercase, substring match) -> list of technique IDs
_TAG_RULES = {
    "c2":            ["T1071"],          # Application Layer Protocol
    "botnet":        ["T1071", "T1584"],
    "phishing":      ["T1566"],          # Phishing
    "powershell":    ["T1059.001"],      # Command and Scripting Interpreter: PowerShell
    "trojan":        ["T1204"],          # User Execution
    "ransomware":    ["T1486"],          # Data Encrypted for Impact
    "exploit":       ["T1190"],          # Exploit Public-Facing Application
    "backdoor":      ["T1505"],          # Server Software Component
    "keylogger":     ["T1056.001"],      # Input Capture: Keylogging
    "loader":        ["T1027"],          # Obfuscated Files or Information
    "malware":       ["T1204"],
    "brute":         ["T1110"],          # Brute Force
    "exfil":         ["T1041"],          # Exfiltration Over C2 Channel
}

# fallback mapping purely by IOC type, used when no tag matches
_TYPE_FALLBACK = {
    "url": ["T1071"],
    "domain": ["T1071"],
    "ip": ["T1071"],
    "hash_md5": ["T1204"],
    "hash_sha1": ["T1204"],
    "hash_sha256": ["T1204"],
}


def map_to_mitre(ioc_type, tags):
    techniques = set()
    for tag in tags or []:
        tag_l = tag.lower()
        for keyword, techs in _TAG_RULES.items():
            if keyword in tag_l:
                techniques.update(techs)

    if not techniques:
        techniques.update(_TYPE_FALLBACK.get(ioc_type, []))

    return sorted(techniques)


if __name__ == "__main__":
    print(map_to_mitre("domain", ["c2", "botnet"]))
    print(map_to_mitre("hash_sha256", []))
