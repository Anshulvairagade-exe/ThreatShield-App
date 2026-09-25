"""
Security Telemetry Feature Preprocessor.
Extracts normalized numerical features from multi-modal security events (Auth, Process, Network, DNS).
Maintains baseline statistical profiles and sliding UEBA state to quantify deviations.
"""

import math
import ipaddress
import datetime
from typing import List, Dict, Any, Tuple
import numpy as np

LOLBAS_BINARIES = {
    "powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe",
    "cscript.exe", "wscript.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe",
    "schtasks.exe", "vssadmin.exe", "psexec.exe"
}

COMMON_PORTS = {80, 443, 53, 88, 135, 389, 445, 636, 3128, 5432, 22, 25}

PRIVILEGED_USERS = {"adm.josh", "svc_backup", "SYSTEM", "root", "Administrator"}

FEATURE_NAMES = [
    "hour_sin",
    "hour_cos",
    "is_weekend",
    "is_event_auth",
    "is_event_process",
    "is_event_network",
    "is_event_dns",
    "is_auth_failure",
    "is_network_logon",
    "auth_failure_burst",
    "is_privileged_user",
    "cmd_length",
    "cmd_entropy",
    "is_lolbas_process",
    "parent_child_rarity",
    "is_external_dest_ip",
    "bytes_sent_log",
    "bytes_ratio",
    "dest_port_rarity",
    "domain_entropy",
    "domain_length",
    "domain_subdomain_depth",
    "is_txt_dns_query",
    "user_host_mismatch"
]

def shannon_entropy(s: str) -> float:
    """Computes Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return float(ent)

def is_private_ip(ip_str: str) -> bool:
    """Returns True if IP is in private/loopback RFC1918 range."""
    if not ip_str:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return True

class SecurityTelemetryPreprocessor:
    """
    Transforms heterogeneous security events into normalized numerical feature vectors.
    Computes baseline distributions for categorical frequencies and scalar scalers.
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES
        self.baseline_parent_child: Dict[str, int] = {}
        self.baseline_user_hosts: Dict[str, set] = {}
        self.total_baseline_processes: int = 0
        self.scaler_mean: np.ndarray = np.zeros(len(FEATURE_NAMES))
        self.scaler_scale: np.ndarray = np.ones(len(FEATURE_NAMES))
        self._failure_history: Dict[str, List[datetime.datetime]] = {}
        self.is_fitted: bool = False

    def reset_state(self):
        """Resets dynamic sliding window state."""
        self._failure_history = {}

    def _get_auth_failure_burst(self, evt: Dict[str, Any]) -> float:
        """Tracks rolling window failure bursts per source IP."""
        src = evt.get("src_ip") or evt.get("hostname", "default")
        code = evt.get("event_code", 0)
        status = evt.get("status", "")
        is_fail = (status == "FAILURE_BAD_PASSWORD" or code == 4625)

        now = datetime.datetime.now(datetime.timezone.utc)
        ts_str = evt.get("timestamp")
        if ts_str:
            try:
                now = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                pass

        history = self._failure_history.get(src, [])
        cutoff = now - datetime.timedelta(seconds=90)
        history = [t for t in history if t >= cutoff]

        if is_fail:
            history.append(now)

        self._failure_history[src] = history
        return float(min(len(history), 20))

    def fit(self, baseline_events: List[Dict[str, Any]]):
        """Learns baseline distributions and normalization parameters."""
        self.reset_state()
        raw_features = []

        # 1. Accumulate categorical relationships
        for evt in baseline_events:
            user = evt.get("user", "")
            host = evt.get("hostname", "")
            if user and host:
                if user not in self.baseline_user_hosts:
                    self.baseline_user_hosts[user] = set()
                self.baseline_user_hosts[user].add(host)

            if evt.get("event_type") == "PROCESS":
                p_img = evt.get("parent_image", "").lower()
                c_img = evt.get("image", "").lower()
                pair = f"{p_img}->{c_img}"
                self.baseline_parent_child[pair] = self.baseline_parent_child.get(pair, 0) + 1
                self.total_baseline_processes += 1

        # 2. Extract raw feature vectors for normalization
        for evt in baseline_events:
            vec = self._extract_raw_vector(evt)
            raw_features.append(vec)

        X = np.array(raw_features, dtype=np.float32)

        # 3. Compute mean and standard deviation for Z-score scaling
        self.scaler_mean = np.mean(X, axis=0)
        self.scaler_scale = np.std(X, axis=0)
        # Avoid zero division on constant features
        self.scaler_scale[self.scaler_scale < 1e-4] = 1.0

        self.is_fitted = True
        self.reset_state()

    def _extract_raw_vector(self, evt: Dict[str, Any]) -> List[float]:
        """Converts a single event into unscaled numerical feature values."""
        # 1. Temporal
        ts_str = evt.get("timestamp")
        hour = 12
        weekday = 1
        if ts_str:
            try:
                dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                hour = dt.hour + dt.minute / 60.0
                weekday = dt.weekday()
            except Exception:
                pass

        hour_rad = (hour / 24.0) * 2.0 * math.pi
        hour_sin = math.sin(hour_rad)
        hour_cos = math.cos(hour_rad)
        is_weekend = 1.0 if weekday in [5, 6] else 0.0

        # 2. Event Types
        etype = evt.get("event_type", "").upper()
        is_event_auth = 1.0 if etype == "AUTH" else 0.0
        is_event_process = 1.0 if etype == "PROCESS" else 0.0
        is_event_network = 1.0 if etype == "NETWORK" else 0.0
        is_event_dns = 1.0 if etype == "DNS" else 0.0

        # 3. Auth specifics
        status = evt.get("status", "")
        code = evt.get("event_code", 0)
        is_auth_failure = 1.0 if (status == "FAILURE_BAD_PASSWORD" or code == 4625) else 0.0
        logon_type = float(evt.get("logon_type", 0))
        is_network_logon = 1.0 if logon_type == 3 else 0.0
        auth_failure_burst = self._get_auth_failure_burst(evt)

        user = evt.get("user", "")
        is_privileged = 1.0 if user in PRIVILEGED_USERS else 0.0

        # 4. Process specifics
        cmd = evt.get("command_line", "")
        cmd_length = float(len(cmd))
        cmd_ent = shannon_entropy(cmd)

        img = evt.get("image", "").lower()
        is_lolbas = 1.0 if img in LOLBAS_BINARIES else 0.0

        p_img = evt.get("parent_image", "").lower()
        pair = f"{p_img}->{img}"
        if self.total_baseline_processes > 0 and is_event_process:
            pair_count = self.baseline_parent_child.get(pair, 0)
            pair_freq = pair_count / self.total_baseline_processes
            parent_child_rarity = max(0.0, 1.0 - (pair_freq * 10.0))
        else:
            parent_child_rarity = 0.0

        # 5. Network specifics
        dest_ip = evt.get("dest_ip", "")
        is_external = 0.0 if is_private_ip(dest_ip) else 1.0

        bytes_sent = float(evt.get("bytes_sent", 0))
        bytes_recv = float(evt.get("bytes_recv", 0))
        bytes_sent_log = math.log10(bytes_sent + 1.0)
        bytes_ratio = (bytes_sent + 1.0) / (bytes_sent + bytes_recv + 2.0)

        dest_port = evt.get("dest_port", 0)
        dest_port_rarity = 0.0 if (dest_port in COMMON_PORTS or not is_event_network) else 1.0

        # 6. DNS specifics
        domain = evt.get("query_name", "")
        domain_ent = shannon_entropy(domain)
        domain_len = float(len(domain))
        domain_depth = float(domain.count("."))
        is_txt_query = 1.0 if evt.get("query_type") == "TXT" else 0.0

        # 7. Identity & Host Mismatch
        host = evt.get("hostname", "")
        allowed_hosts = self.baseline_user_hosts.get(user, set())
        user_host_mismatch = 1.0 if (allowed_hosts and host not in allowed_hosts and user not in PRIVILEGED_USERS) else 0.0

        return [
            hour_sin,
            hour_cos,
            is_weekend,
            is_event_auth,
            is_event_process,
            is_event_network,
            is_event_dns,
            is_auth_failure,
            is_network_logon,
            auth_failure_burst,
            is_privileged,
            cmd_length,
            cmd_ent,
            is_lolbas,
            parent_child_rarity,
            is_external,
            bytes_sent_log,
            bytes_ratio,
            dest_port_rarity,
            domain_ent,
            domain_len,
            domain_depth,
            is_txt_query,
            user_host_mismatch
        ]

    def transform(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Transforms events to standardized feature matrix."""
        if not self.is_fitted:
            raise ValueError("Preprocessor has not been fitted on baseline data yet.")

        raw = [self._extract_raw_vector(e) for e in events]
        X = np.array(raw, dtype=np.float32)
        X_scaled = (X - self.scaler_mean) / self.scaler_scale
        return X_scaled

    def transform_single(self, event: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray]:
        """Transforms a single event. Returns (scaled_vector, raw_vector)."""
        raw = np.array(self._extract_raw_vector(event), dtype=np.float32)
        scaled = (raw - self.scaler_mean) / self.scaler_scale
        return scaled.reshape(1, -1), raw.reshape(1, -1)
