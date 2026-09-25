export const INITIAL_TWIN_NODES = [
  {
    id: "ATTACKER-EXT",
    name: "EXTERNAL C2 ATTACKER",
    ip: "185.220.101.5",
    type: "attacker",
    subnet: "UNTRUSTED-INTERNET",
    os: "Kali Linux / C2 Proxy",
    user: "threat-actor-APT",
    criticality: "CRITICAL_THREAT",
    status: "active_threat",
    riskScore: 98,
    x: 460,
    y: 45
  },
  {
    id: "WIN-ENDPOINT-01",
    name: "WIN-WORKSTATION-01",
    ip: "10.20.4.15",
    type: "workstation",
    subnet: "WINDOWS-ENDPOINT-ZONE",
    os: "Windows 11 Enterprise (x64)",
    user: "victim.user (Finance Analyst)",
    criticality: "HIGH",
    status: "healthy",
    riskScore: 12,
    x: 280,
    y: 250
  },
  {
    id: "UBUNTU-SRV-01",
    name: "UBUNTU-SERVER-01",
    ip: "10.20.10.50",
    type: "server",
    subnet: "UBUNTU-SERVER-ZONE",
    os: "Ubuntu 22.04 LTS (Linux)",
    user: "ubuntu-admin (Sudoer)",
    criticality: "CROWN_JEWEL",
    status: "healthy",
    riskScore: 8,
    x: 640,
    y: 390
  }
];

export const INITIAL_TWIN_EDGES = [
  {
    id: "e1",
    source: "ATTACKER-EXT",
    target: "WIN-ENDPOINT-01",
    label: "T1071 C2 Beacon",
    technique: "T1071.001",
    protocol: "HTTPS (443)",
    status: "dormant",
  },
  {
    id: "e2",
    source: "WIN-ENDPOINT-01",
    target: "UBUNTU-SRV-01",
    label: "T1021.004 SSH Lateral Pivot",
    technique: "T1021.004",
    protocol: "SSH / TCP (22)",
    status: "dormant",
  }
];

