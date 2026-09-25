# Wazuh Integration — Manager 3.104.196.100

Live manager (provided by operator):

- Manager IP: `3.104.196.100`
- Dashboard: `https://3.104.196.100` (port 443, accept the self-signed cert)
- Agent enrollment: `3.104.196.100:1515` (TCP)
- Agent events: `3.104.196.100:1514` (TCP)

ThreatShield side is ready: `WazuhAdapter` maps manager alert JSON to
`CanonicalSecurityEvent`, and `POST /api/v1/intake/wazuh` runs each alert
through the full pipeline. No detection-engine changes were needed.

## 1. Enroll the endpoints

Windows (PowerShell, admin) — Windows 11 workstation:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="3.104.196.100" WAZUH_AGENT_GROUP="windows"
"C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 3.104.196.100 -p 1515
net start wazuh-agent
```

Ubuntu 22.04 server:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install -y wazuh-agent
sudo sed -i 's/<address>.*<\/address>/<address>3.104.196.100<\/address>/' /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/agent-auth -m 3.104.196.100 -p 1515
sudo systemctl enable --now wazuh-agent
```

Verify on the dashboard (`https://3.104.196.100`): Agents page shows
`WIN-WORKSTATION-01` and `UBUNTU-SERVER-01` as Active.

## 2. Forward alerts into ThreatShield (pick one)

A. Direct POST per alert (simplest, no extra infra):

```bash
tail -F /var/ossec/logs/alerts/alerts.json | while read -r line; do
  curl -s -X POST http://localhost:8000/api/v1/intake/wazuh \
    -H 'Content-Type: application/json' -d "{\"alert\": $line}"
done
```

B. Manager API poll (add `WAZUH_API_USER/PASS` env, extend
`routers/intake.py` with a poll loop — adapter already handles the shape).

C. Syslog: point manager `<syslog_output>` at ThreatShield and parse to
the same alert dict before POSTing.

## 3. Smoke test

```bash
# Windows failed logon → AUTH event, rule T1110 may fire after 5 in 10 min
# Sysmon/Syscheck file change → FILE event
curl -X POST http://localhost:8000/api/v1/intake/wazuh \
  -H 'Content-Type: application/json' -d '{"alert": {
    "timestamp": "2026-09-25T10:00:00Z",
    "agent": {"id": "001", "name": "WIN-WORKSTATION-01", "ip": "10.20.4.15"},
    "rule": {"id": "60122", "description": "Failed logon",
             "groups": ["windows", "authentication_failed"],
             "mitre": {"id": ["T1110"]}},
    "data": {"win": {"system": {"eventID": "4625"},
             "eventdata": {"TargetUserName": "victim.user", "LogonType": "3"}}}}}'
```

Expect `event_type: AUTH`, `mitre_hint: T1110`, and (after 5 failures)
a `repeated_failed_logins` detection correlated into an incident.

## 4. Notes

- Agent `os` is not in alert JSON; asset OS comes from the seeded
  `assets` table (seed.py) or the twin topology.
- Private IPs pass through untouched; TI lookup misses them (clean).
- High-volume: alerts.json tail is fine for SOC scale; move to API
  cursor polling if EPS exceeds single POST throughput.
