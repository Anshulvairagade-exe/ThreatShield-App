// Frontend-only demo backend — used ONLY when VITE_API_BASE_URL is unset
// (Vercel / Netlify portfolio deploy). No backend code is touched.
// Every shape matches the real FastAPI contract so pages render fully.
const now = Date.now();
const iso = (hrsAgo) => new Date(now - hrsAgo * 3600 * 1000).toISOString();

const DEMO_HOSTS = [
  { hostname: 'WIN-ENDPOINT-01', ip: '10.20.4.15', os: 'Windows 11 Enterprise (x64)', type: 'workstation', subnet: 'WINDOWS-ENDPOINT-ZONE', user: 'victim.user', criticality: 'HIGH' },
  { hostname: 'UBUNTU-SRV-01', ip: '10.20.10.50', os: 'Ubuntu 22.04 LTS', type: 'server', subnet: 'UBUNTU-SERVER-ZONE', user: 'ubuntu-admin', criticality: 'CROWN_JEWEL' },
  { hostname: 'WIN-DC-01', ip: '10.20.4.10', os: 'Windows Server 2022', type: 'server', subnet: 'AD-CORE', user: 'svc-ad', criticality: 'CROWN_JEWEL' },
  { hostname: 'UBUNTU-WEB-02', ip: '10.20.10.62', os: 'Ubuntu 22.04 LTS', type: 'server', subnet: 'DMZ-WEB', user: 'www-data', criticality: 'MEDIUM' },
  { hostname: 'ANALYST-LAPTOP-03', ip: '10.20.6.21', os: 'Windows 11 Enterprise (x64)', type: 'workstation', subnet: 'SOC-ZONE', user: 'soc.analyst', criticality: 'MEDIUM' },
];

const DEMO_ASSETS = [
  { hostname: 'WIN-ENDPOINT-01', ip: '10.20.4.15', os: 'Windows 11 Enterprise (x64)', type: 'workstation', subnet: 'WINDOWS-ENDPOINT-ZONE', user: 'victim.user', criticality: 'HIGH', status: 'compromised', risk_score: 94, last_seen: iso(0.2) },
  { hostname: 'UBUNTU-SRV-01', ip: '10.20.10.50', os: 'Ubuntu 22.04 LTS', type: 'server', subnet: 'UBUNTU-SERVER-ZONE', user: 'ubuntu-admin', criticality: 'CROWN_JEWEL', status: 'suspicious', risk_score: 68, last_seen: iso(0.5) },
  { hostname: 'WIN-DC-01', ip: '10.20.4.10', os: 'Windows Server 2022', type: 'server', subnet: 'AD-CORE', user: 'svc-ad', criticality: 'CROWN_JEWEL', status: 'healthy', risk_score: 22, last_seen: iso(0.1) },
  { hostname: 'UBUNTU-WEB-02', ip: '10.20.10.62', os: 'Ubuntu 22.04 LTS', type: 'server', subnet: 'DMZ-WEB', user: 'www-data', criticality: 'MEDIUM', status: 'healthy', risk_score: 18, last_seen: iso(1) },
  { hostname: 'ANALYST-LAPTOP-03', ip: '10.20.6.21', os: 'Windows 11 Enterprise (x64)', type: 'workstation', subnet: 'SOC-ZONE', user: 'soc.analyst', criticality: 'MEDIUM', status: 'healthy', risk_score: 9, last_seen: iso(0.3) },
];

const DEMO_ALERTS = [
  { id: 'al-1001', rule_id: 'RULE-C2-BEACON', severity: 'CRITICAL', detector_type: 'IOC', score: 0.94, status: 'OPEN', hostname: 'WIN-ENDPOINT-01', event_id: 'ev-9001', created_at: iso(1.5), reasons: ['C2 beacon to 185.220.101.5:443 matched AbuseIPDB feed'] },
  { id: 'al-1002', rule_id: 'RULE-PS-ENCODED', severity: 'HIGH', detector_type: 'RULE', score: 0.87, status: 'OPEN', hostname: 'WIN-ENDPOINT-01', event_id: 'ev-9002', created_at: iso(2), reasons: ['Encoded PowerShell with -bypass flag from excel.exe'] },
  { id: 'al-1003', rule_id: 'ZD-PROC-INJECT', severity: 'HIGH', detector_type: 'ZERODAY', score: 0.89, status: 'ACKED', hostname: 'WIN-ENDPOINT-01', event_id: 'ev-9003', created_at: iso(3), reasons: ['spoolsv.exe spawned calc.exe with suspicious memory args', '0 occurrences in 30-day baseline'] },
  { id: 'al-1004', rule_id: 'RULE-SUDO-ABUSE', severity: 'MEDIUM', detector_type: 'RULE', score: 0.66, status: 'OPEN', hostname: 'UBUNTU-SRV-01', event_id: 'ev-9004', created_at: iso(5), reasons: ['Non-interactive sudo root invocation from remote SSH session'] },
  { id: 'al-1005', rule_id: 'RULE-DNS-TUNNEL', severity: 'MEDIUM', detector_type: 'IOC', score: 0.71, status: 'OPEN', hostname: 'UBUNTU-WEB-02', event_id: 'ev-9005', created_at: iso(7), reasons: ['DNS queries to malicious-c2-tunnel.cc at 40 q/min'] },
  { id: 'al-1006', rule_id: 'RULE-BRUTEFORCE', severity: 'LOW', detector_type: 'RULE', score: 0.42, status: 'CLOSED', hostname: 'WIN-DC-01', event_id: 'ev-9006', created_at: iso(12), reasons: ['12 failed logins for svc-ad in 5 minutes'] },
  { id: 'al-1007', rule_id: 'ZD-LATERAL-SSH', severity: 'CRITICAL', detector_type: 'ZERODAY', score: 0.92, status: 'OPEN', hostname: 'UBUNTU-SRV-01', event_id: 'ev-9007', created_at: iso(1), reasons: ['SSH lateral movement WIN-ENDPOINT-01 -> UBUNTU-SRV-01 off-hours'] },
  { id: 'al-1008', rule_id: 'RULE-PHISH-CLICK', severity: 'LOW', detector_type: 'RULE', score: 0.35, status: 'CLOSED', hostname: 'ANALYST-LAPTOP-03', event_id: 'ev-9008', created_at: iso(20), reasons: ['Phishing invoice attachment opened, no payload'] },
];

const DEMO_EVENTS = [
  { event_id: 'ev-9001', timestamp: iso(1.5), hostname: 'WIN-ENDPOINT-01', event_type: 'NETWORK', source: 'zeek', user: 'victim.user', src_ip: '10.20.4.15', dest_ip: '185.220.101.5', domain: 'malicious-c2-tunnel.cc', raw: { proto: 'tcp', dest_port: 443, bytes: 184320 } },
  { event_id: 'ev-9002', timestamp: iso(2), hostname: 'WIN-ENDPOINT-01', event_type: 'PROCESS', source: 'wazuh', user: 'victim.user', src_ip: '10.20.4.15', dest_ip: null, domain: null, raw: { parent: 'excel.exe', child: 'powershell.exe -enc aQBmACgA... -bypass' } },
  { event_id: 'ev-9003', timestamp: iso(3), hostname: 'WIN-ENDPOINT-01', event_type: 'PROCESS', source: 'wazuh', user: 'victim.user', src_ip: '10.20.4.15', dest_ip: null, domain: null, raw: { parent: 'spoolsv.exe', child: 'calc.exe -mem_sync 0x00400000' } },
  { event_id: 'ev-9004', timestamp: iso(5), hostname: 'UBUNTU-SRV-01', event_type: 'AUTH', source: 'wazuh', user: 'ubuntu-admin', src_ip: '10.20.4.15', dest_ip: '10.20.10.50', domain: null, raw: { auth: 'sudo su -', tty: 'ssh' } },
  { event_id: 'ev-9005', timestamp: iso(7), hostname: 'UBUNTU-WEB-02', event_type: 'DNS', source: 'zeek', user: null, src_ip: '10.20.10.62', dest_ip: '8.8.8.8', domain: 'malicious-c2-tunnel.cc', raw: { qtype: 'A', rate_per_min: 40 } },
  { event_id: 'ev-9006', timestamp: iso(12), hostname: 'WIN-DC-01', event_type: 'AUTH', source: 'wazuh', user: 'svc-ad', src_ip: '10.20.6.21', dest_ip: '10.20.4.10', domain: null, raw: { failures: 12, window: '5m' } },
  { event_id: 'ev-9007', timestamp: iso(1), hostname: 'UBUNTU-SRV-01', event_type: 'NETWORK', source: 'zeek', user: 'ubuntu-admin', src_ip: '10.20.4.15', dest_ip: '10.20.10.50', domain: null, raw: { proto: 'tcp', dest_port: 22 } },
  { event_id: 'ev-9008', timestamp: iso(20), hostname: 'ANALYST-LAPTOP-03', event_type: 'FILE', source: 'simulator', user: 'soc.analyst', src_ip: '10.20.6.21', dest_ip: null, domain: null, raw: { file: 'invoice_Q3.xlsm', action: 'opened' } },
];

const DEMO_INCIDENTS = [
  { id: 'INC-842', title: 'C2 Beacon & Multi-Stage Cross-Platform Pivot', severity: 'CRITICAL', risk_score: 94, status: 'INVESTIGATING', created_at: iso(1.5) },
  { id: 'INC-839', title: 'Zero-Day Process Injection under Spoolsv', severity: 'HIGH', risk_score: 82, status: 'TRIAGED', created_at: iso(3) },
  { id: 'INC-831', title: 'Unauthorized Sudo Escalation Attempt', severity: 'MEDIUM', risk_score: 68, status: 'NEW', created_at: iso(5) },
];

function investigationFor(id) {
  const inc = DEMO_INCIDENTS.find((i) => i.id === id) || DEMO_INCIDENTS[0];
  const related = DEMO_EVENTS.slice(0, 4).map((e) => ({ ...e, detections: DEMO_ALERTS.filter((a) => a.event_id === e.event_id).length ? [{ rule_id: 'RULE-C2-BEACON' }] : [] }));
  return {
    id: inc.id, title: inc.title, severity: inc.severity, risk_score: inc.risk_score,
    status: inc.status, created_at: inc.created_at,
    summary: 'Correlated C2 beacon, encoded execution and lateral pivot across Windows + Linux assets.',
    risk_explanation: 'Crown-jewel Linux server reachable from compromised finance workstation; C2 IOC has 0.91 confidence.',
    assigned_analyst: 'analyst',
    primary_asset: { hostname: 'WIN-ENDPOINT-01' },
    affected_hosts: [
      { id: 'h1', hostname: 'WIN-ENDPOINT-01', ip: '10.20.4.15', criticality: 'HIGH' },
      { id: 'h2', hostname: 'UBUNTU-SRV-01', ip: '10.20.10.50', criticality: 'CROWN_JEWEL' },
    ],
    users: [{ id: 'u1', name: 'victim.user' }],
    iocs: [
      { id: 'ioc1', ioc: '185.220.101.5', reputation: 92, confidence: 0.91 },
      { id: 'ioc2', ioc: 'malicious-c2-tunnel.cc', reputation: 88, confidence: 0.85 },
    ],
    detections: [
      { detection_id: 'd1', rule_id: 'RULE-C2-BEACON', detector_type: 'IOC', score: 0.94, reasons: ['C2 beacon matched AbuseIPDB feed'], evidence: { ioc: '185.220.101.5' } },
      { detection_id: 'd2', rule_id: 'ZD-PROC-INJECT', detector_type: 'ZERODAY', score: 0.89, reasons: ['Unprecedented parent-child lineage excel.exe -> powershell.exe', 'Off-hours RPC credential query'], evidence: { decision: 'ANOMALOUS', model_risk_score: 0.89 } },
    ],
    timeline: [
      { time: iso(2.2), event: 'Phishing invoice opened on Windows workstation', source: 'Endpoint Monitor', severity: 'LOW', technique: 'T1566.001' },
      { time: iso(2), event: 'Encoded PowerShell executed with bypass flag', source: 'Anomaly Engine', severity: 'HIGH', technique: 'T1059.001' },
      { time: iso(1.5), event: 'C2 beacon session initiated to 185.220.101.5:443', source: 'Threat Intel', severity: 'CRITICAL', technique: 'T1071.001' },
      { time: iso(1), event: 'SSH lateral movement to UBUNTU-SRV-01', source: 'SIEM Correlation', severity: 'HIGH', technique: 'T1021.004' },
    ],
    mitre_techniques: [
      { technique_id: 'T1059.001', technique_name: 'PowerShell', tactic: 'Execution' },
      { technique_id: 'T1071.001', technique_name: 'Web Protocols', tactic: 'Command and Control' },
      { technique_id: 'T1021.004', technique_name: 'SSH', tactic: 'Lateral Movement' },
    ],
    related_events: related,
    response_actions: [
      { id: 'ra-1', incident_id: inc.id, type: 'ISOLATE_HOST', target: 'WIN-ENDPOINT-01', mode: 'SIMULATION', actor: 'analyst', status: 'SUCCESS', created_at: iso(0.8) },
      { id: 'ra-2', incident_id: inc.id, type: 'BLOCK_IOC', target: '185.220.101.5', mode: 'SIMULATION', actor: 'analyst', status: 'REQUESTED', created_at: iso(0.5) },
    ],
  };
}

const DEMO_MITRE = {
  overall_coverage_pct: 34,
  tactics: [
    { tactic: 'Initial Access', coverage_pct: 40, techniques: [{ technique_id: 'T1566.001', name: 'Spearphishing Attachment', observed_count: 2 }, { technique_id: 'T1566.002', name: 'Spearphishing Link', observed_count: 0 }] },
    { tactic: 'Execution', coverage_pct: 60, techniques: [{ technique_id: 'T1059.001', name: 'PowerShell', observed_count: 3 }, { technique_id: 'T1059.003', name: 'Windows Command Shell', observed_count: 1 }] },
    { tactic: 'Persistence', coverage_pct: 20, techniques: [{ technique_id: 'T1055', name: 'Process Injection', observed_count: 2 }] },
    { tactic: 'Privilege Escalation', coverage_pct: 25, techniques: [{ technique_id: 'T1548.003', name: 'Sudo', observed_count: 1 }] },
    { tactic: 'Command and Control', coverage_pct: 50, techniques: [{ technique_id: 'T1071.001', name: 'Web Protocols', observed_count: 4 }, { technique_id: 'T1071.004', name: 'DNS', observed_count: 1 }] },
    { tactic: 'Lateral Movement', coverage_pct: 30, techniques: [{ technique_id: 'T1021.004', name: 'SSH', observed_count: 2 }] },
  ],
};

const DEMO_IOCS = {
  '185.220.101.5': { found: true, ioc: '185.220.101.5', type: 'ip', reputation: 92, confidence: 0.91, sources: ['AbuseIPDB', 'AlienVault OTX', 'URLhaus'], tags: ['C2', 'botnet', 'CobaltStrike'], mitre: ['T1071.001'], status: 'Active', first_seen: iso(24 * 30), last_seen: iso(1) },
  'malicious-c2-tunnel.cc': { found: true, ioc: 'malicious-c2-tunnel.cc', type: 'domain', reputation: 88, confidence: 0.85, sources: ['URLhaus', 'MalwareBazaar'], tags: ['phishing', 'dynamic-dns'], mitre: ['T1566.002'], status: 'Active', first_seen: iso(24 * 17), last_seen: iso(2) },
};

// Tiny in-memory mutations so demo actions feel alive (Approve/Close/Ack)
const demoState = { alerts: JSON.parse(JSON.stringify(DEMO_ALERTS)), incidents: JSON.parse(JSON.stringify(DEMO_INCIDENTS)) };

export function mockApiResponse(path, { method = 'GET', body = null } = {}) {
  const [cleanPath, qs] = path.split('?');
  const params = new URLSearchParams(qs || '');

  if (cleanPath === '/api/v1/health') {
    return { status: 'ok (demo)', version: 'demo-frontend-only', database: 'demo', opensearch: 'demo', zeroday_model: 'loaded:demo-v1' };
  }
  if (cleanPath === '/api/v1/dashboard') {
    return {
      kpis: { active_incidents: 3, critical: 1, compromised_assets: 1, risky_assets: 2, monitored_assets: 5, open_alerts: 5, mitre_tactics_covered: 6, mitre_tactics_total: 12, mitre_techniques_observed: 8 },
      recent_incidents: demoState.incidents,
    };
  }
  if (cleanPath === '/api/v1/alerts') {
    return { alerts: demoState.alerts };
  }
  if (cleanPath.startsWith('/api/v1/alerts/')) {
    const id = decodeURIComponent(cleanPath.split('/').pop());
    const a = demoState.alerts.find((x) => x.id === id) || demoState.alerts[0];
    if (method === 'PATCH' && body?.status) a.status = body.status;
    const ev = DEMO_EVENTS.find((e) => e.event_id === a.event_id) || DEMO_EVENTS[0];
    return { detection: { rule_id: a.rule_id, severity: a.severity, detector_type: a.detector_type, score: a.score, reasons: a.reasons, evidence: { ioc: '185.220.101.5', model_risk_score: a.score, decision: 'ANOMALOUS' } }, status: a.status, event: ev, incident_ids: ['INC-842'], mitre: [{ technique_id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control' }] };
  }
  if (cleanPath === '/api/v1/detections') return { detections: [] };
  if (cleanPath === '/api/v1/rules') return { rules: demoState.alerts.map((a) => ({ rule_id: a.rule_id, severity: a.severity })) };
  if (cleanPath === '/api/v1/events/search') return { results: DEMO_EVENTS, count: DEMO_EVENTS.length };
  if (cleanPath.startsWith('/api/v1/events/')) {
    const id = decodeURIComponent(cleanPath.split('/').pop());
    const ev = DEMO_EVENTS.find((e) => e.event_id === id) || DEMO_EVENTS[0];
    return { ...ev, full: ev };
  }
  if (cleanPath === '/api/v1/incidents') return { incidents: demoState.incidents };
  const invMatch = cleanPath.match(/^\/api\/v1\/incidents\/([^/]+)\/(investigation|timeline|events|actions)$/);
  if (invMatch) {
    const [, id, kind] = invMatch;
    const inv = investigationFor(id);
    if (kind === 'investigation') return inv;
    if (kind === 'timeline') return { timeline: inv.timeline };
    if (kind === 'events') return { events: inv.related_events };
    if (kind === 'actions') return { actions: inv.response_actions };
  }
  if (cleanPath.startsWith('/api/v1/incidents/') && cleanPath.endsWith('/status') && method === 'PATCH') return { ok: true };
  if (cleanPath.startsWith('/api/v1/incidents/') && cleanPath.endsWith('/assign') && method === 'PATCH') return { ok: true };
  if (cleanPath.includes('/actions/') && method === 'POST') return { ok: true, status: 'REQUESTED (demo)' };
  if (cleanPath.startsWith('/api/v1/incidents/')) {
    const id = decodeURIComponent(cleanPath.split('/').pop().split('?')[0]);
    const inv = investigationFor(id);
    return { id: inv.id, title: inv.title, severity: inv.severity, risk_score: inv.risk_score, status: inv.status, created_at: inv.created_at };
  }
  if (cleanPath === '/api/v1/assets') return { assets: DEMO_ASSETS };
  if (cleanPath.startsWith('/api/v1/assets/')) {
    const hn = decodeURIComponent(cleanPath.split('/').pop());
    return DEMO_ASSETS.find((a) => a.hostname === hn) || DEMO_ASSETS[0];
  }
  if (cleanPath === '/api/v1/twin/topology') {
    return {
      nodes: DEMO_ASSETS.map((a, i) => ({ id: a.hostname, hostname: a.hostname, ip: a.ip, os: a.os, type: a.type, subnet: a.subnet, user: a.user, criticality: a.criticality, status: a.status, risk_score: a.risk_score, last_seen: a.last_seen, x: 150 + i * 160, y: 120 + (i % 2) * 160 })),
      edges: [{ id: 'e1', source: 'WIN-ENDPOINT-01', target: 'UBUNTU-SRV-01', severity: 'CRITICAL', status: 'active' }],
    };
  }
  if (cleanPath === '/api/v1/mitre') return DEMO_MITRE;
  if (cleanPath.startsWith('/api/v1/mitre/')) {
    const id = decodeURIComponent(cleanPath.split('/').pop());
    return { technique_id: id, technique_name: 'Web Protocols', tactic: 'Command and Control', description: 'Demo technique detail — adversaries communicate via application-layer protocols to avoid detection.', observed_count: 4, incidents: ['INC-842'], rules: [{ rule_id: 'RULE-C2-BEACON' }] };
  }
  if (cleanPath.startsWith('/api/v1/ti/lookup')) {
    const v = params.get('value') || '';
    const hit = DEMO_IOCS[v] || Object.values(DEMO_IOCS).find((d) => v.includes(d.ioc));
    if (hit) return hit;
    return { found: false, ioc: v, type: params.get('type') || 'ip' };
  }
  if (cleanPath === '/api/v1/ti/stats') return { total_iocs: 128, sources: ['AbuseIPDB', 'OTX', 'URLhaus', 'MalwareBazaar'], last_refresh: iso(2) };
  if (cleanPath === '/api/v1/ti/refresh' || cleanPath === '/api/v1/ti/live-lookup') return { verdict: 'clean', checked: ['demo-feed'], flagged_by: [], details: {}, ioc: params.get('value') || '' };
  if (cleanPath.startsWith('/api/v1/audit')) {
    return { logs: [
      { id: 'log1', timestamp: iso(0.5), actor: 'analyst', action: 'INCIDENT_STATUS', target: 'INC-842', result: 'INVESTIGATING', incident_id: 'INC-842' },
      { id: 'log2', timestamp: iso(0.8), actor: 'analyst', action: 'ISOLATE_HOST', target: 'WIN-ENDPOINT-01', result: 'SUCCESS', incident_id: 'INC-842' },
      { id: 'log3', timestamp: iso(1.2), actor: 'system', action: 'DETECTION_CORRELATE', target: 'RULE-C2-BEACON', result: 'INCIDENT_OPENED', incident_id: 'INC-842' },
      { id: 'log4', timestamp: iso(3), actor: 'analyst', action: 'ALERT_ACK', target: 'al-1003', result: 'ACKED', incident_id: null },
    ]};
  }
  if (cleanPath === '/api/v1/scenarios') return { scenarios: [{ id: 'SCN-APT-01', name: 'APT C2 + Lateral Pivot (demo)' }] };
  if (cleanPath.includes('/scenarios/') && cleanPath.endsWith('/start')) return { total_detections: 7, incident_id: 'INC-842', note: 'demo run — no backend required' };
  if (cleanPath === '/api/v1/pipeline/ingest') return { ok: true, demo: true };
  return { demo: true, path, note: 'Demo mode — connect backend for live data' };
}
