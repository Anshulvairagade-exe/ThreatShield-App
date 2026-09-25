# Zeek Integration — Network Sensor for ThreatShield

Zeek runs on the Ubuntu sensor (same VM family as the Wazuh agent host) and
its JSON logs flow into ThreatShield via `POST /api/v1/intake/zeek`, through
the same pipeline as simulation and Wazuh. No detection-engine changes needed.

## 1. Install Zeek on the Ubuntu sensor

```bash
# Zeek 7.x on Ubuntu 22.04
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | sudo tee /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null
sudo apt update && sudo apt install -y zeek
```

Capture interface = the one facing the monitored network (e.g. `eth0`):

```bash
sudo /opt/zeek/bin/zeekctl install
# in /opt/zeek/etc/node.cfg set interface=eth0
sudo /opt/zeek/bin/zeekctl start
```

Enable JSON logs in `/opt/zeek/share/zeek/site/local.zeek`:

```zeek
@load policy/tuning/json-logs
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
```

Logs land in `/opt/zeek/logs/current/{conn,dns,http,files}.log` (one JSON
object per line with `ts` epoch, `uid`, dotted keys like `id.orig_h`).

## 2. Forward logs into ThreatShield

Filebeat (or a one-liner tail) POSTs each line. Inject the sensor hostname
so Zeek records map to the right asset:

```bash
tail -F /opt/zeek/logs/current/conn.log /opt/zeek/logs/current/dns.log | while read -r line; do
  host=$(hostname)
  curl -s -X POST http://localhost:8000/api/v1/intake/zeek \
    -H 'Content-Type: application/json' \
    -d "{\"record\": $(echo "$line" | jq --arg h "$host" '. + {hostname: $h}'))}"
done
```

## 3. Field contract (what the adapter reads)

| Zeek log | Keys → canonical |
|---|---|
| conn.log | `id.orig_h/resp_h/resp_p/proto/orig_bytes/resp_bytes` → network (NETWORK) |
| dns.log | `query/qtype_name/answers` → dns (DNS) |
| http.log | `method/host/uri/status_code/user_agent` → raw (WEB) |
| files.log | `filename/mime_type/sha256` → raw (FILE) |
| all | `ts` → timestamp, `uid/fuid` → event_id, `hostname` → asset |

Detection notes:

- DNS TXT / high-entropy queries fire `suspicious_dns` (T1071.004).
- Rare-port egress fires `unusual_external_connection` (T1071.001).
- Dest IPs hitting the TI repo fire `ioc-ip-match` — Zeek is the main
  source of C2-confirming evidence for Wazuh endpoint alerts.
- Correlate a Zeek `conn` (src = workstation IP) with a Wazuh 4625 on the
  same host and they land in one incident via the host_ip chain rule.

## 4. Smoke test

```bash
curl -X POST http://localhost:8000/api/v1/intake/zeek \
  -H 'Content-Type: application/json' -d '{"record": {
    "ts": 1788000000, "uid": "Csmoke1", "id.orig_h": "10.20.4.15",
    "id.resp_h": "185.220.101.5", "id.resp_p": 4444, "proto": "tcp",
    "orig_bytes": 512, "resp_bytes": 128, "hostname": "WIN-WORKSTATION-01"}}'
```

Expect `event_type: NETWORK`, an `unusual_external_connection` detection
(+ `ioc-ip-match` if the IP is in the TI repo), and an incident.
