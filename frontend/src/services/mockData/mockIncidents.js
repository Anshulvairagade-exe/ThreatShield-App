export const INITIAL_INCIDENTS = [
  {
    id: "INC-842",
    title: "C2 Beacon & Multi-Stage Cross-Platform Pivot",
    severity: "CRITICAL",
    riskScore: 94,
    status: "INVESTIGATING",
    targetHost: "WIN-ENDPOINT-01",
    targetIp: "10.20.4.15",
    user: "victim.user",
    criticality: "HIGH",
    detectedAt: "10:16:48",
    mitreTechniques: ["T1059.001", "T1071.001", "T1021.004"],
    ioc: "185.220.101.5",
    containmentActions: {
      hostIsolated: false,
      iocBlocked: false,
      userDisabled: false
    },
    zeroDayAnomaly: {
      detected: true,
      anomalyScore: 0.94,
      decision: "ANOMALOUS",
      severity: "CRITICAL",
      modelSource: "Member 5 Zero-Day Anomaly Detector",
      topReasons: [
        "Unprecedented parent-child execution lineage: excel.exe -> powershell.exe",
        "Off-hours credential query on restricted RPC ports",
        "Command line contains unquoted obfuscated memory injection arguments"
      ]
    },
    timeline: [
      {
        time: "10:14:02",
        event: "Phishing invoice opened on Windows workstation",
        source: "Endpoint Monitor",
        severity: "LOW",
        technique: "T1566.001"
      },
      {
        time: "10:15:33",
        event: "Encoded PowerShell executed with bypass flag",
        source: "Member 5 Anomaly Engine",
        severity: "HIGH",
        technique: "T1059.001"
      },
      {
        time: "10:16:48",
        event: "C2 beacon session initiated to 185.220.101.5:443 (Matched AbuseIPDB feed)",
        source: "Member 2 Threat Intel",
        severity: "CRITICAL",
        technique: "T1071.001"
      },
      {
        time: "10:18:15",
        event: "SSH lateral movement from Windows endpoint to UBUNTU-SERVER-01",
        source: "Member 7 SIEM Correlation",
        severity: "HIGH",
        technique: "T1021.004"
      }
    ]
  },
  {
    id: "INC-839",
    title: "Zero-Day Process Injection under Spoolsv",
    severity: "HIGH",
    riskScore: 82,
    status: "TRIAGED",
    targetHost: "WIN-ENDPOINT-01",
    targetIp: "10.20.4.15",
    user: "victim.user",
    criticality: "HIGH",
    detectedAt: "09:45:10",
    mitreTechniques: ["T1055", "T1059"],
    ioc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    containmentActions: {
      hostIsolated: false,
      iocBlocked: false,
      userDisabled: false
    },
    zeroDayAnomaly: {
      detected: true,
      anomalyScore: 0.89,
      decision: "ANOMALOUS",
      severity: "HIGH",
      modelSource: "Member 5 Zero-Day Anomaly Detector",
      topReasons: [
        "spoolsv.exe spawned calc.exe with -mem_sync 0x00400000",
        "0 occurrences of this binary relationship in 30-day baseline"
      ]
    },
    timeline: [
      {
        time: "09:45:10",
        event: "spoolsv.exe spawned child process with suspicious memory pointer",
        source: "Member 5 Anomaly Engine",
        severity: "HIGH",
        technique: "T1055"
      }
    ]
  },
  {
    id: "INC-831",
    title: "Unauthorized Sudo Escalation Attempt",
    severity: "MEDIUM",
    riskScore: 68,
    status: "NEW",
    targetHost: "UBUNTU-SRV-01",
    targetIp: "10.20.10.50",
    user: "ubuntu-admin",
    criticality: "CROWN_JEWEL",
    detectedAt: "08:12:00",
    mitreTechniques: ["T1548.003"],
    ioc: "185.220.101.5",
    containmentActions: {
      hostIsolated: false,
      iocBlocked: false,
      userDisabled: false
    },
    zeroDayAnomaly: {
      detected: false,
      anomalyScore: 0.42,
      decision: "ANOMALOUS",
      severity: "MEDIUM",
      modelSource: "Linux Auditd SIEM",
      topReasons: ["Non-interactive sudo root invocation from remote SSH session"]
    },
    timeline: [
      {
        time: "08:12:00",
        event: "Sudo invocation logged with unexpected parent process",
        source: "Member 6 Network / Host Monitor",
        severity: "MEDIUM",
        technique: "T1548.003"
      }
    ]
  }
];
