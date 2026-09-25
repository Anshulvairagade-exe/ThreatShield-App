"""ZeroDayDetectorAdapter — singleton over the supplied pretrained pickle.

Rules (frozen):
- Never retrain, never replace the model.
- Pickle loads ONCE at application startup (FastAPI lifespan), never per event.
- Original model output is preserved verbatim and returned as-is.
- The model is a DETECTION SIGNAL only — it never creates incidents directly
  (correlation/risk in later phases decide that).

Storage contract (no schema change needed — Detection row carries it):
  score = anomaly_score | reasons = top_reasons
  evidence = {model_risk_score, severity, decision, top_attributions,
              model_version, model_diagnostics}
"""
import os
import pickle
import sys
import threading
import warnings
from typing import Any

from app.core import logger
from app.schemas.events import CanonicalSecurityEvent

_PKG_CANDIDATES = [
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "zero_day_model_package"),
    os.path.join(os.getcwd(), "zero_day_model_package"),
    "/code/zero_day_model_package",
]

for _cand in _PKG_CANDIDATES:
    _abs = os.path.abspath(_cand)
    if os.path.isdir(_abs) and _abs not in sys.path:
        sys.path.insert(0, _abs)
        break

_MODEL_CANDIDATES = [
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "zero_day_model_package", "zero_day_anomaly_detector.pkl"),
    os.path.join(os.getcwd(), "zero_day_model_package", "zero_day_anomaly_detector.pkl"),
    "/code/zero_day_model_package/zero_day_anomaly_detector.pkl",
    os.getenv("ZERODAY_MODEL_PATH", ""),
]


def _resolve_model_path() -> str | None:
    for cand in _MODEL_CANDIDATES:
        if cand and os.path.isfile(os.path.abspath(cand)):
            return os.path.abspath(cand)
    return None


def flatten_for_model(event: CanonicalSecurityEvent | dict) -> dict[str, Any]:
    """Canonical (or already-flat dict) → the flat dict the pickle expects."""
    if isinstance(event, dict) and "asset" not in event:
        return dict(event)
    if isinstance(event, dict):
        event = CanonicalSecurityEvent.model_validate(event)
    flat: dict[str, Any] = {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat() if hasattr(event.timestamp, "isoformat") else event.timestamp,
        "event_type": event.event_type,
        "hostname": event.asset.hostname,
        "host_ip": event.asset.ip,
        "host_criticality": event.asset.criticality,
        "os": event.asset.os,
        "mitre_hint": event.mitre_hint,
        "details": "",
    }
    if event.user:
        flat["user"] = event.user.name
    if event.process:
        flat.update({"image": event.process.image, "parent_image": event.process.parent_image,
                     "command_line": event.process.command_line, "pid": event.process.pid, "ppid": event.process.ppid})
    if event.network:
        flat.update({"src_ip": event.network.src_ip, "src_port": event.network.src_port,
                     "dest_ip": event.network.dest_ip, "dest_port": event.network.dest_port,
                     "protocol": event.network.protocol, "bytes_sent": event.network.bytes_sent,
                     "bytes_recv": event.network.bytes_recv})
    if event.dns:
        flat.update({"query_name": event.dns.query_name, "query_type": event.dns.query_type, "answers": event.dns.answers})
    if event.authentication:
        flat.update({"event_code": event.authentication.event_code, "status": event.authentication.status,
                     "logon_type": event.authentication.logon_type, "failure_count": event.authentication.failure_count})
    if isinstance(event.raw, dict):
        flat.setdefault("details", event.raw.get("details", ""))
        for k in ("image", "parent_image", "command_line", "details", "src_ip", "dest_ip", "dest_port",
                  "bytes_sent", "bytes_recv", "query_name", "query_type", "event_code", "status", "logon_type"):
            if k not in flat or flat[k] in ("", None, 0):
                if k in event.raw and event.raw[k] not in ("", None):
                    flat[k] = event.raw[k]
    return flat


def to_detection_fields(result: dict[str, Any]) -> dict[str, Any]:
    """Map a model result onto Detection persistence fields (Phase 6 uses this)."""
    diag = result.get("model_diagnostics", {}) or {}
    return {
        "anomaly_score": result.get("anomaly_score"),
        "model_risk_score": result.get("risk_score"),
        "severity": result.get("severity"),
        "decision": result.get("decision"),
        "top_reasons": list(result.get("top_reasons", [])),
        "top_attributions": list(result.get("top_attributions", [])),
        "model_version": diag.get("model_version", ""),
        "model_diagnostics": dict(diag),
    }


class ZeroDayDetectorAdapter:
    """Load-once wrapper. Use get_adapter() — never instantiate per request."""

    def __init__(self, model_path: str | None = None):
        self.model_path = model_path or _resolve_model_path()
        self._detector: Any = None
        self._lock = threading.Lock()
        self.load_error: str = ""

    def load(self) -> bool:
        if self._detector is not None:
            return True
        if not self.model_path:
            self.load_error = "pickle not found (checked zero_day_model_package/)"
            logger.warning("zeroday %s", self.load_error)
            return False
        with self._lock:
            if self._detector is not None:
                return True
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore")
                    with open(self.model_path, "rb") as f:
                        self._detector = pickle.load(f)
                logger.info("zeroday model loaded: version=%s trained_at=%s",
                            getattr(self._detector, "version", "?"), getattr(self._detector, "trained_at", "?"))
                return True
            except Exception as e:
                self.load_error = str(e)
                logger.warning("zeroday load failed: %s", e)
                return False

    @property
    def loaded(self) -> bool:
        return self._detector is not None

    def status(self) -> dict[str, Any]:
        if not self.loaded:
            return {"loaded": False, "model_path_found": bool(self.model_path), "error": self.load_error}
        d = self._detector
        return {"loaded": True, "version": getattr(d, "version", "?"),
                "trained_at": str(getattr(d, "trained_at", "")), 
                "training_sample_count": getattr(d, "training_sample_count", 0),
                "thresholds": {"low": getattr(d, "threshold_low", None), "medium": getattr(d, "threshold_medium", None),
                               "high": getattr(d, "threshold_high", None), "critical": getattr(d, "threshold_critical", None)}}

    def evaluate_event(self, event: CanonicalSecurityEvent | dict, host_criticality: str = "MEDIUM") -> dict[str, Any]:
        """Core Python API. Returns the model's ORIGINAL output dict verbatim."""
        if not self.loaded and not self.load():
            raise RuntimeError(f"Zero-day model not loaded: {self.load_error or self.model_path}")
        flat = flatten_for_model(event)
        crit = (flat.get("host_criticality") or host_criticality or "MEDIUM").upper()
        if crit not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            crit = "MEDIUM"
        return self._detector.evaluate_event(flat, host_criticality=crit)


_adapter: ZeroDayDetectorAdapter | None = None


def get_adapter() -> ZeroDayDetectorAdapter:
    global _adapter
    if _adapter is None:
        _adapter = ZeroDayDetectorAdapter()
    return _adapter
