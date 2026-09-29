"""Ingestion adapters — one interface, three sources.

SimulatorAdapter: fully implemented (Phase 2).
WazuhAdapter / ZeekAdapter: clean stubs with documented field maps (Phase 12/13).
The detection engine only ever sees CanonicalSecurityEvent.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from app.schemas.events import (
    AssetInfo,
    AuthInfo,
    CanonicalSecurityEvent,
    DnsInfo,
    NetworkInfo,
    ProcessInfo,
    UserInfo,
)


class BaseAdapter(ABC):
    source: str = "unknown"

    @abstractmethod
    def normalize(self, raw: dict) -> CanonicalSecurityEvent:
        raise NotImplementedError


def _parse_ts(value: object) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            v = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


class SimulatorAdapter(BaseAdapter):
    """Accepts flat simulator dicts (same keys the zero-day model uses)."""

    source = "simulator"

    def normalize(self, raw: dict) -> CanonicalSecurityEvent:
        raw = dict(raw or {})
        event_type = str(raw.get("event_type", "PROCESS")).upper()
        if event_type not in ("AUTH", "PROCESS", "NETWORK", "DNS", "FILE", "WEB", "FIREWALL", "ENDPOINT"):
            event_type = "PROCESS"  # type: ignore[assignment]

        network = None
        if any(k in raw for k in ("src_ip", "dest_ip", "dest_port", "bytes_sent", "bytes_recv", "protocol")):
            network = NetworkInfo(
                src_ip=str(raw.get("src_ip", "")),
                src_port=raw.get("src_port"),
                dest_ip=str(raw.get("dest_ip", "")),
                dest_port=raw.get("dest_port"),
                protocol=str(raw.get("protocol", "")),
                bytes_sent=int(raw.get("bytes_sent", 0) or 0),
                bytes_recv=int(raw.get("bytes_recv", 0) or 0),
            )
        dns = None
        if any(k in raw for k in ("query_name", "query_type", "answers")):
            answers = raw.get("answers", []) or []
            dns = DnsInfo(query_name=str(raw.get("query_name", "")), query_type=str(raw.get("query_type", "")), answers=list(answers))
        auth = None
        if event_type == "AUTH" or any(k in raw for k in ("event_code", "status", "logon_type")):
            auth = AuthInfo(
                event_code=str(raw.get("event_code", "")),
                status=str(raw.get("status", "")),
                logon_type=str(raw.get("logon_type", "")),
                failure_count=int(raw.get("failure_count", 0) or 0),
            )
        process = None
        if any(k in raw for k in ("image", "parent_image", "command_line", "pid", "ppid")) or event_type == "PROCESS":
            process = ProcessInfo(
                image=str(raw.get("image", "")),
                parent_image=str(raw.get("parent_image", "")),
                command_line=str(raw.get("command_line", "")),
                pid=raw.get("pid"),
                ppid=raw.get("ppid"),
            )
        user = None
        if "user" in raw and raw.get("user") not in (None, ""):
            user = UserInfo(name=str(raw.get("user", "")), privileged=bool(raw.get("privileged", False)))

        return CanonicalSecurityEvent(
            event_id=str(raw.get("event_id", "") or CanonicalSecurityEvent.model_fields["event_id"].default_factory()),
            timestamp=_parse_ts(raw.get("timestamp")),
            source="simulator",
            event_type=event_type,  # type: ignore[arg-type]
            asset=AssetInfo(
                hostname=str(raw.get("hostname", "")),
                ip=str(raw.get("host_ip", raw.get("src_ip", ""))),
                os=str(raw.get("os", "")),
                criticality=str(raw.get("host_criticality", raw.get("criticality", "MEDIUM"))).upper(),
            ),
            user=user,
            process=process,
            network=network,
            dns=dns,
            authentication=auth,
            mitre_hint=str(raw.get("mitre_hint", "")),
            raw=raw,
        )


class WazuhAdapter(BaseAdapter):
    """Wazuh manager alert JSON (alerts.json / API / syslog) → canonical.

    Field map (implemented):
      timestamp -> timestamp | agent.name -> asset.hostname
      agent.ip -> asset.ip | rule.mitre.id[0] -> mitre_hint
      rule.groups -> event_type (authentication→AUTH, syscheck→FILE,
        web→WEB, ids→NETWORK, windows+process fields→PROCESS)
      data.win.eventdata.{TargetUserName,SubjectUserName} -> user.name
      data.win.eventdata.{Image,ParentImage,CommandLine} -> process
      srcip/dstip (+data.win.eventdata.{SourceIp,DestinationIp}) -> network
      data.win.system.eventID -> authentication.event_code
      data.syscheck.{path} -> raw.file_path (FILE events)
    Intake: POST /api/v1/intake/wazuh, alerts.json tail, or manager API
    poll — see docs/wazuh.md. DetectionEngine is untouched.
    """

    source = "wazuh"

    def normalize(self, raw: dict) -> CanonicalSecurityEvent:
        raw = dict(raw or {})
        agent = raw.get("agent") or {}
        rule = raw.get("rule") or {}
        data = raw.get("data") or {}
        groups = [str(g).lower() for g in (rule.get("groups") or [])]
        win = data.get("win") or {}
        eventdata = win.get("eventdata") or {}
        system = win.get("system") or {}
        syscheck = data.get("syscheck") or {}

        mitre_ids = ((rule.get("mitre") or {}).get("id")) or []
        mitre_hint = str(mitre_ids[0]) if mitre_ids else ""

        event_type = "ENDPOINT"
        if "authentication" in groups or "authentication_failed" in groups:
            event_type = "AUTH"
        elif "syscheck" in groups:
            event_type = "FILE"
        elif "web" in groups:
            event_type = "WEB"
        elif "ids" in groups or "suricata" in groups:
            event_type = "NETWORK"
        elif any(k in eventdata for k in ("Image", "ParentImage", "CommandLine", "ProcessName")):
            event_type = "PROCESS"
        elif "srcip" in raw or "dstip" in raw:
            event_type = "NETWORK"

        user = None
        username = (eventdata.get("TargetUserName") or eventdata.get("SubjectUserName")
                    or eventdata.get("AccountName") or data.get("user") or "")
        if username:
            user = UserInfo(name=str(username))

        process = None
        if any(k in eventdata for k in ("Image", "ParentImage", "CommandLine", "ProcessName", "ParentProcessName")):
            process = ProcessInfo(
                image=str(eventdata.get("Image") or eventdata.get("ProcessName") or ""),
                parent_image=str(eventdata.get("ParentImage") or eventdata.get("ParentProcessName") or ""),
                command_line=str(eventdata.get("CommandLine") or ""),
            )

        network = None
        src_ip = str(raw.get("srcip") or eventdata.get("SourceIp") or data.get("srcip") or "")
        dest_ip = str(raw.get("dstip") or eventdata.get("DestinationIp") or data.get("dstip") or "")
        dest_port = raw.get("dstport") or eventdata.get("DestinationPort") or data.get("dstport")
        if src_ip or dest_ip or dest_port:
            try:
                dest_port = int(dest_port) if dest_port is not None else None
            except (TypeError, ValueError):
                dest_port = None
            network = NetworkInfo(src_ip=src_ip, dest_ip=dest_ip, dest_port=dest_port)

        auth = None
        event_code = str(system.get("eventID") or eventdata.get("EventID") or data.get("event_code") or "")
        if event_type == "AUTH" or event_code:
            status = "FAILURE" if ("authentication_failed" in groups or "failed" in str(rule.get("description", "")).lower()) else ""
            auth = AuthInfo(event_code=event_code, status=status,
                            logon_type=str(eventdata.get("LogonType") or ""))

        hostname = str(agent.get("name") or data.get("hostname") or "")
        return CanonicalSecurityEvent(
            event_id=str(raw.get("id") or CanonicalSecurityEvent.model_fields["event_id"].default_factory()),
            timestamp=_parse_ts(raw.get("timestamp")),
            source="wazuh",
            event_type=event_type,  # type: ignore[arg-type]
            asset=AssetInfo(hostname=hostname, ip=str(agent.get("ip") or "")),
            user=user,
            process=process,
            network=network,
            authentication=auth,
            mitre_hint=mitre_hint,
            raw=raw,
        )


class ZeekAdapter(BaseAdapter):
    """Zeek JSON logs (conn/dns/http/files) → canonical.

    Field map (implemented, keys are Zeek's dotted JSON names):
      ts (epoch) -> timestamp | uid/fuid -> raw (correlation)
      conn.log id.orig_h/resp_h/resp_p/proto/orig_bytes/resp_bytes -> network (NETWORK)
      dns.log query/qtype_name/answers -> dns (DNS)
      http.log method/host/uri/status_code/user_agent -> raw (WEB)
      files.log filename/mime_type/sha256/tx_hosts/rx_hosts -> raw (FILE)
      hostname/sensor/agent.hostname (forwarder-injected) -> asset.hostname
      mitre_hint (optional forwarder annotation) -> mitre_hint
    Intake: POST /api/v1/intake/zeek — see docs/zeek.md.
    """

    source = "zeek"

    @staticmethod
    def _ts(raw: dict):
        ts = raw.get("ts")
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        return _parse_ts(raw.get("timestamp"))

    def normalize(self, raw: dict) -> CanonicalSecurityEvent:
        raw = dict(raw or {})
        if "query" in raw or "qtype_name" in raw:
            log_type = "dns"
        elif "method" in raw or "uri" in raw or "host" in raw:
            log_type = "http"
        elif "filename" in raw or "sha256" in raw or "mime_type" in raw:
            log_type = "files"
        else:
            log_type = raw.get("_log_type") or "conn"

        event_type = {"dns": "DNS", "http": "WEB", "files": "FILE"}.get(log_type, "NETWORK")
        hostname = str(raw.get("hostname") or raw.get("sensor")
                       or ((raw.get("agent") or {}) if isinstance(raw.get("agent"), dict) else {}).get("hostname")
                       or raw.get("id.orig_h") or "")

        network = None
        if log_type in ("conn", "http"):
            try:
                dest_port = raw.get("id.resp_p")
                dest_port = int(dest_port) if dest_port is not None else None
            except (TypeError, ValueError):
                dest_port = None
            src_ip = str(raw.get("id.orig_h") or "")
            dest_ip = str(raw.get("id.resp_h") or "")
            if src_ip or dest_ip or dest_port:
                network = NetworkInfo(
                    src_ip=src_ip, src_port=raw.get("id.orig_p"), dest_ip=dest_ip,
                    dest_port=dest_port, protocol=str(raw.get("proto") or ""),
                    bytes_sent=int(raw.get("orig_bytes") or 0),
                    bytes_recv=int(raw.get("resp_bytes") or 0))

        dns = None
        if log_type == "dns":
            answers = raw.get("answers") or []
            dns = DnsInfo(query_name=str(raw.get("query") or ""),
                          query_type=str(raw.get("qtype_name") or raw.get("qtype") or ""),
                          answers=list(answers) if isinstance(answers, list) else [str(answers)])

        return CanonicalSecurityEvent(
            event_id=str(raw.get("uid") or raw.get("fuid") or
                         CanonicalSecurityEvent.model_fields["event_id"].default_factory()),
            timestamp=self._ts(raw),
            source="zeek",
            event_type=event_type,  # type: ignore[arg-type]
            asset=AssetInfo(hostname=hostname),
            network=network,
            dns=dns,
            mitre_hint=str(raw.get("mitre_hint") or ""),
            raw=raw,
        )


ADAPTERS: dict[str, BaseAdapter] = {
    "simulator": SimulatorAdapter(),
    "wazuh": WazuhAdapter(),
    "zeek": ZeekAdapter(),
}


def get_adapter(source: str) -> BaseAdapter:
    try:
        return ADAPTERS[source]
    except KeyError:
        raise ValueError(f"Unknown event source: {source}. Expected one of {sorted(ADAPTERS)}")
