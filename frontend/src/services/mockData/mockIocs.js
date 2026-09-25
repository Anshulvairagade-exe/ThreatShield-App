export const MOCK_IOC_DATABASE = {
  "185.220.101.5": {
    found: true,
    ioc: "185.220.101.5",
    type: "ip",
    reputation: 92,
    confidence: 0.91,
    sources: ["AbuseIPDB", "AlienVault OTX", "URLhaus"],
    tags: ["C2", "botnet", "CobaltStrike", "Tor Exit"],
    mitre: ["T1071.001", "T1059.001"],
    status: "Active",
    country: "Netherlands",
    asn: "AS205100",
    first_seen: "2026-08-21T09:12:00Z",
    last_seen: "2026-09-19T22:45:00Z",
    associatedIncidents: ["INC-842", "INC-811"]
  },
  "malicious-c2-tunnel.cc": {
    found: true,
    ioc: "malicious-c2-tunnel.cc",
    type: "domain",
    reputation: 88,
    confidence: 0.85,
    sources: ["URLhaus", "MalwareBazaar"],
    tags: ["phishing", "dynamic-dns", "malware-download"],
    mitre: ["T1566.002"],
    status: "Active",
    country: "Russian Federation",
    asn: "AS48282",
    first_seen: "2026-09-02T14:20:00Z",
    last_seen: "2026-09-19T18:10:00Z",
    associatedIncidents: ["INC-842"]
  },
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
    found: true,
    ioc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    type: "hash",
    reputation: 99,
    confidence: 0.98,
    sources: ["MalwareBazaar", "AlienVault OTX"],
    tags: ["trojan", "stealer", "cobalt-beacon"],
    mitre: ["T1059.001", "T1055"],
    status: "Active",
    country: "Global",
    first_seen: "2026-09-10T11:00:00Z",
    last_seen: "2026-09-19T21:00:00Z",
    associatedIncidents: ["INC-839"]
  }
};
