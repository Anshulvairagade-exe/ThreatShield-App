"""Versioned behavioral rules — data/config driven where practical.

Each rule is a self-contained BaseRule subclass exposing:
  rule_id, version, severity, confidence, mitre[], description
  evaluate(event) -> RuleHit | None

RuleHit carries rule_id, severity, confidence, reason, mitre_techniques,
evidence. New rules are added via RuleEngine.register() — the engine
itself never changes.

Stateful note: repeated_failed_logins keeps an in-memory burst counter
keyed by (user, host). Production hardening (Phase 6+) should back this
with an OpenSearch range query over AUTH failures instead.
"""
import base64
import math
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.schemas.events import CanonicalSecurityEvent


@dataclass
class RuleHit:
    rule_id: str
    severity: str
    confidence: float
    reason: str
    mitre_techniques: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


class BaseRule(ABC):
    rule_id: str = "base"
    version: str = "1.0.0"
    severity: str = "MEDIUM"
    confidence: float = 0.5
    mitre: list[str] = field(default_factory=list)  # type: ignore[assignment]
    description: str = ""
    enabled: bool = True

    @abstractmethod
    def evaluate(self, event: CanonicalSecurityEvent) -> RuleHit | None:
        ...

    def _hit(self, reason: str, evidence: dict | None = None, severity: str | None = None,
             confidence: float | None = None) -> RuleHit:
        return RuleHit(rule_id=self.rule_id, severity=severity or self.severity,
                       confidence=confidence if confidence is not None else self.confidence,
                       reason=reason, mitre_techniques=list(self.mitre), evidence=evidence or {})


def _cmd(event: CanonicalSecurityEvent) -> str:
    return (event.process.command_line if event.process else "") or ""


def _img(event: CanonicalSecurityEvent) -> str:
    return ((event.process.image if event.process else "") or "").lower()


# ---------------------------------------------------------------- rules

class SuspiciousPowershellRule(BaseRule):
    rule_id = "suspicious_powershell"
    version = "1.0.0"
    severity = "HIGH"
    confidence = 0.8
    mitre = ["T1059.001"]
    description = "PowerShell with obfuscation/bypass flags or hidden execution"
    _FLAGS = ("-enc", "-encodedcommand", "bypass", "-w hidden", "-windowstyle hidden", "iex", "invoke-expression", "downloadstring")

    def evaluate(self, event):
        if event.event_type != "PROCESS" or "powershell" not in _img(event):
            return None
        cmd = _cmd(event).lower()
        matched = [f for f in self._FLAGS if f in cmd]
        if not matched:
            return None
        return self._hit(f"PowerShell invoked with suspicious flags: {', '.join(matched)}",
                         {"image": event.process.image, "command_line": _cmd(event), "matched_flags": matched})


class EncodedPowershellRule(BaseRule):
    rule_id = "encoded_powershell"
    version = "1.0.0"
    severity = "HIGH"
    confidence = 0.85
    mitre = ["T1027"]
    description = "Base64-encoded PowerShell payload (-EncodedCommand with decodable blob)"

    def evaluate(self, event):
        if event.event_type != "PROCESS" or "powershell" not in _img(event):
            return None
        cmd = _cmd(event)
        m = re.search(r"-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]{40,})", cmd, re.IGNORECASE)
        if not m:
            return None
        blob = m.group(1)
        try:
            decoded = base64.b64decode(blob).decode("utf-16-le", errors="ignore") or base64.b64decode(blob).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        if decoded and len(decoded.strip()) < 3:
            return None
        return self._hit("Base64-encoded PowerShell command payload detected",
                         {"blob_prefix": blob[:32] + "...", "decoded_prefix": decoded[:120]})


class RepeatedFailedLoginsRule(BaseRule):
    rule_id = "repeated_failed_logins"
    version = "1.0.0"
    severity = "MEDIUM"
    confidence = 0.75
    mitre = ["T1110"]
    description = "N failed AUTH logins for same user/host inside a sliding window"
    THRESHOLD = 5
    WINDOW = timedelta(minutes=10)

    def __init__(self):
        self._failures: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    def _is_failure(self, event):
        if event.event_type != "AUTH":
            return False
        a = event.authentication
        if not a:
            return False
        return "fail" in (a.status or "").lower() or a.event_code in ("4625", "4771")

    def evaluate(self, event):
        if not self._is_failure(event):
            return None
        user = event.user.name if event.user else ""
        host = event.asset.hostname
        now = event.timestamp if isinstance(event.timestamp, datetime) else datetime.now(timezone.utc)
        key = (user, host)
        self._failures[key] = [t for t in self._failures[key] if now - t <= self.WINDOW] + [now]
        count = len(self._failures[key])
        if count < self.THRESHOLD:
            return None
        return self._hit(f"{count} failed logins for '{user}' on '{host}' within 10 minutes",
                         {"user": user, "hostname": host, "failure_count": count})

    def reset(self):
        self._failures.clear()


class SuspiciousDnsRule(BaseRule):
    rule_id = "suspicious_dns"
    version = "1.0.0"
    severity = "MEDIUM"
    confidence = 0.7
    mitre = ["T1071.004"]
    description = "TXT queries, high-entropy/long/DGA-like domains"
    _SUSPicious_TLDS = (".tk", ".top", ".xyz", ".cc", ".ru", ".onion")

    def evaluate(self, event):
        if event.event_type != "DNS" or not event.dns:
            return None
        q = event.dns.query_name or ""
        qtype = (event.dns.query_type or "").upper()
        reasons, evidence = [], {"query_name": q, "query_type": qtype}
        if qtype == "TXT":
            reasons.append("TXT query (possible DNS tunneling/C2)")
        labels = q.split(".")
        entropy = self._entropy(q)
        if len(q) > 40:
            reasons.append(f"unusually long domain ({len(q)} chars)")
        if entropy > 4.2:
            reasons.append(f"high domain entropy ({entropy:.2f})")
        if any(q.lower().endswith(t) for t in self._SUSPicious_TLDS):
            reasons.append("suspicious TLD")
        if len(labels) > 4:
            reasons.append("excessive subdomain depth")
        evidence.update({"domain_length": len(q), "entropy": round(entropy, 2), "labels": len(labels)})
        if not reasons:
            return None
        return self._hit("Suspicious DNS: " + "; ".join(reasons), evidence)

    @staticmethod
    def _entropy(s: str) -> float:
        s = re.sub(r"[.]", "", s.lower())
        if not s:
            return 0.0
        from collections import Counter
        freq = Counter(s)
        return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())


class UnusualExternalConnectionRule(BaseRule):
    rule_id = "unusual_external_connection"
    version = "1.0.0"
    severity = "MEDIUM"
    confidence = 0.65
    mitre = ["T1071.001"]
    description = "Outbound connection to rare external port or non-standard C2 port"
    _COMMON_PORTS = {80, 443, 53, 88, 135, 389, 445, 636, 3128, 5432, 22, 25, 587, 993}

    def evaluate(self, event):
        if event.event_type not in ("NETWORK", "WEB", "FIREWALL") or not event.network:
            return None
        port = event.network.dest_port
        if port is None or port in self._COMMON_PORTS:
            return None
        return self._hit(f"Outbound connection to uncommon external port {port}",
                         {"dest_ip": event.network.dest_ip, "dest_port": port,
                          "protocol": event.network.protocol}, severity="HIGH" if port in (4444, 8443, 8080) else None)


class RareProcessParentChildRule(BaseRule):
    rule_id = "rare_process_parent_child"
    version = "1.0.0"
    severity = "HIGH"
    confidence = 0.8
    mitre = ["T1055"]
    description = "Process spawned by an unprecedented parent (not in known-good baseline)"
    _KNOWN_GOOD = {("explorer.exe", "excel.exe"), ("explorer.exe", "winword.exe"), ("explorer.exe", "chrome.exe"),
                   ("services.exe", "svchost.exe"), ("svchost.exe", "dllhost.exe"), ("systemd", "sshd"),
                   ("sshd", "bash"), ("bash", "ls"), ("explorer.exe", "powershell.exe")}

    def evaluate(self, event):
        if event.event_type != "PROCESS" or not event.process:
            return None
        parent = (event.process.parent_image or "").lower()
        image = (event.process.image or "").lower()
        if not parent or not image or (parent, image) in self._KNOWN_GOOD:
            return None
        lolbas = {"powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe", "certutil.exe"}
        sev = "CRITICAL" if image in lolbas else None
        return self._hit(f"Rare parent-child lineage: '{parent}' spawned '{image}'",
                         {"parent_image": event.process.parent_image, "image": event.process.image},
                         severity=sev)


class PrivilegedAccountAnomalyRule(BaseRule):
    rule_id = "privileged_account_anomaly"
    version = "1.0.0"
    severity = "HIGH"
    confidence = 0.75
    mitre = ["T1078"]
    description = "Privileged account active off-hours or on an unusual host"
    _PRIVILEGED = {"administrator", "root", "system", "adm.josh", "svc_backup", "domain admins"}

    def evaluate(self, event):
        user = (event.user.name if event.user else "").lower()
        if not user or (user not in self._PRIVILEGED and not (event.user and event.user.privileged)):
            return None
        ts = event.timestamp if isinstance(event.timestamp, datetime) else None
        hour = ts.hour if ts else -1
        off_hours = hour != -1 and (hour < 6 or hour >= 22)
        network_logon = bool(event.authentication and str(event.authentication.logon_type) == "3")
        if not off_hours and not network_logon:
            return None
        why = "off-hours activity" if off_hours else "network logon"
        return self._hit(f"Privileged account '{user}' {why} on '{event.asset.hostname}'",
                         {"user": user, "hostname": event.asset.hostname, "hour": hour})


class SuspiciousSshActivityRule(BaseRule):
    rule_id = "suspicious_ssh_activity"
    version = "1.0.0"
    severity = "HIGH"
    confidence = 0.8
    mitre = ["T1021.004"]
    description = "SSH to a new host, off-hours SSH, or SSH pivot chain indicator"

    def evaluate(self, event):
        is_ssh = (event.network and event.network.dest_port == 22) or (
            event.event_type == "NETWORK" and "ssh" in (event.network.protocol if event.network else "").lower())
        if not is_ssh:
            if event.event_type == "AUTH" and event.authentication and "ssh" not in str(event.raw.get("protocol", "")).lower():
                return None
            if event.event_type == "AUTH" and "ssh" not in str(event.raw.get("service", event.raw.get("protocol", ""))).lower():
                return None
        ts = event.timestamp if isinstance(event.timestamp, datetime) else None
        hour = ts.hour if ts else -1
        dest = event.network.dest_ip if event.network else event.raw.get("dest_ip", "")
        if hour != -1 and (hour < 6 or hour >= 22):
            return self._hit(f"Off-hours SSH activity to '{dest}' (possible lateral movement)",
                             {"dest_ip": dest, "hour": hour, "src_ip": event.network.src_ip if event.network else ""})
        if event.event_type == "AUTH" and event.authentication and "success" in (event.authentication.status or "").lower():
            return self._hit(f"Successful SSH logon to '{dest}' after authentication events (possible pivot)",
                             {"dest_ip": dest, "user": event.user.name if event.user else ""})
        return None


BUILTIN_RULES: list[BaseRule] = [
    SuspiciousPowershellRule(),
    EncodedPowershellRule(),
    RepeatedFailedLoginsRule(),
    SuspiciousDnsRule(),
    UnusualExternalConnectionRule(),
    RareProcessParentChildRule(),
    PrivilegedAccountAnomalyRule(),
    SuspiciousSshActivityRule(),
]
