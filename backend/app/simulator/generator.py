"""Local event simulator — realistic baseline + attack scenarios.

Every scenario step is a flat simulator-format raw dict that flows through
the EXACT SAME pipeline as Wazuh/Zeek later will (adapters → DetectionEngine
→ CorrelationEngine → RiskEngine → incident). No parallel fake pipeline.
"""
import random

WIN_HOST = {"hostname": "WIN-WORKSTATION-01", "host_ip": "10.20.4.15",
            "os": "Windows 11 Enterprise", "host_criticality": "HIGH"}
UBU_HOST = {"hostname": "UBUNTU-SERVER-01", "host_ip": "10.20.10.50",
            "os": "Ubuntu 22.04 LTS", "host_criticality": "CROWN_JEWEL"}


def _base(host, **kw):
    evt = dict(host)
    evt.update(kw)
    return evt


def baseline_events(n: int = 20, seed: int = 42) -> list[dict]:
    """Benign Windows/Linux traffic: process, auth, DNS, network."""
    rng = random.Random(seed)
    templates = [
        lambda i: _base(WIN_HOST, event_id=f"BASE-{i:03d}", event_type="PROCESS",
                        user="victim.user", image="excel.exe", parent_image="explorer.exe",
                        command_line="excel.exe ledger.xlsx"),
        lambda i: _base(UBU_HOST, event_id=f"BASE-{i:03d}", event_type="PROCESS",
                        user="ubuntu-admin", image="bash", parent_image="sshd",
                        command_line="bash -c ls"),
        lambda i: _base(WIN_HOST, event_id=f"BASE-{i:03d}", event_type="AUTH",
                        user="victim.user", event_code="4624", status="SUCCESS", logon_type="2"),
        lambda i: _base(UBU_HOST, event_id=f"BASE-{i:03d}", event_type="DNS",
                        query_name=rng.choice(["mail.example.com", "updates.ubuntu.com"]),
                        query_type="A"),
        lambda i: _base(WIN_HOST, event_id=f"BASE-{i:03d}", event_type="NETWORK",
                        src_ip="10.20.4.15", dest_ip=rng.choice(["93.184.216.34", "142.250.1.1"]),
                        dest_port=443, protocol="tcp", bytes_sent=1200, bytes_recv=5400),
    ]
    return [templates[i % len(templates)](i) for i in range(n)]


def _step(step: int, title: str, phase: str, mitre: str, target: str, raw: dict, description: str = "") -> dict:
    return {"step": step, "title": title, "phase": phase, "mitre": mitre,
            "target": target, "raw": raw, "description": description}


SCENARIOS: dict[str, dict] = {
    "SCN-APT-01": {
        "id": "SCN-APT-01",
        "name": "Windows Ingress → C2 Beacon → Ubuntu Lateral Movement",
        "description": "Spearphish → encoded PowerShell → C2 → SSH pivot → privesc.",
        "steps": [
            _step(1, "Spearphishing Attachment Opened", "Initial Access", "T1566.001",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, event_id="SCN1-01", event_type="PROCESS",
                        user="victim.user", image="excel.exe", parent_image="explorer.exe",
                        command_line="excel.exe invoice.xlsx"),
                  "Phishing invoice opened on Windows workstation"),
            _step(2, "Encoded PowerShell Execution", "Execution", "T1059.001",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, event_id="SCN1-02", event_type="PROCESS",
                        user="victim.user", image="powershell.exe", parent_image="excel.exe",
                        command_line="powershell -enc aGVsbG8gd29ybGQgdGVzdA== -w hidden"),
                  "Encoded PowerShell with bypass-style flags"),
            _step(3, "C2 Beacon to Malicious IP", "Command and Control", "T1071.001",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, event_id="SCN1-03", event_type="NETWORK",
                        user="victim.user", src_ip="10.20.4.15", dest_ip="185.220.101.5",
                        dest_port=443, protocol="tcp"),
                  "HTTPS beacon to known C2 infrastructure"),
            _step(4, "SSH Lateral Movement to Ubuntu", "Lateral Movement", "T1021.004",
                  "UBUNTU-SERVER-01", _base(WIN_HOST, timestamp="2026-09-20T03:00:00Z",
                        event_id="SCN1-04", event_type="NETWORK", user="victim.user",
                        src_ip="10.20.4.15", dest_ip="10.20.10.50", dest_port=22),
                  "Off-hours SSH pivot Windows → Ubuntu"),
            _step(5, "Privilege Escalation on Ubuntu", "Persistence", "T1548.003",
                  "UBUNTU-SERVER-01", _base(UBU_HOST, event_id="SCN1-05", event_type="PROCESS",
                        user="ubuntu-admin", image="sudo", parent_image="bash",
                        command_line="sudo -u root /tmp/.hidden"),
                  "Sudo abuse from remote SSH session"),
        ],
    },
    "SCN-ZERODAY-01": {
        "id": "SCN-ZERODAY-01",
        "name": "Zero-Day Process Anomaly",
        "description": "Unprecedented parent-child lineage with obfuscated arguments.",
        "steps": [
            _step(1, "Anomalous Process Lineage", "Execution", "T1055",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, timestamp="2026-09-11T02:45:10Z",
                        event_id="SCN2-01", event_type="PROCESS", user="alice.exec",
                        image="calc.exe", parent_image="spoolsv.exe",
                        command_line="calc.exe -d 7b8a9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f -mem_sync 0x00400000"),
                  "calc.exe spawned with memory params under spoolsv.exe"),
        ],
    },
    "SCN-BRUTE-01": {
        "id": "SCN-BRUTE-01",
        "name": "Brute Force → Success → Lateral Movement",
        "description": "Repeated failed logins, successful logon, SSH pivot.",
        "steps": [
            _step(i + 1, f"Failed Login Attempt {i + 1}", "Credential Access", "T1110",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, event_id=f"SCN3-0{i + 1}",
                        event_type="AUTH", user="victim.user", event_code="4625",
                        status="FAILURE", logon_type="3"))
            for i in range(5)
        ] + [
            _step(6, "Successful Logon After Burst", "Credential Access", "T1078",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, event_id="SCN3-06",
                        event_type="AUTH", user="victim.user", event_code="4624",
                        status="SUCCESS", logon_type="3"),
                  "Logon success immediately after failure burst"),
            _step(7, "SSH Pivot After Compromise", "Lateral Movement", "T1021.004",
                  "UBUNTU-SERVER-01", _base(WIN_HOST, timestamp="2026-09-20T03:10:00Z",
                        event_id="SCN3-07", event_type="NETWORK", user="victim.user",
                        src_ip="10.20.4.15", dest_ip="10.20.10.50", dest_port=22),
                  "Off-hours SSH following brute-force success"),
        ],
    },
    "SCN-DNS-01": {
        "id": "SCN-DNS-01",
        "name": "Suspicious DNS → External Connection",
        "description": "TXT query to dynamic-DNS domain followed by rare-port egress.",
        "steps": [
            _step(1, "Suspicious TXT Query", "Command and Control", "T1071.004",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, event_id="SCN4-01", event_type="DNS",
                        query_name="malicious-c2-tunnel.cc", query_type="TXT"),
                  "TXT query to dynamic-DNS C2 domain"),
            _step(2, "Egress to Rare External Port", "Command and Control", "T1071.001",
                  "WIN-WORKSTATION-01", _base(WIN_HOST, event_id="SCN4-02", event_type="NETWORK",
                        src_ip="10.20.4.15", dest_ip="185.220.101.5", dest_port=4444),
                  "Outbound connection to uncommon C2 port"),
        ],
    },
}


def get_scenario(scenario_id: str) -> dict:
    try:
        return SCENARIOS[scenario_id]
    except KeyError:
        raise KeyError(f"Unknown scenario {scenario_id}. Available: {sorted(SCENARIOS)}")
