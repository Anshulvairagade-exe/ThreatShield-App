"""
Master Zero-Day Behavioral Anomaly Detector.
Combines Deep Reconstruction Autoencoder and Isolation Forest with calibrated percentile thresholding,
explainable feature attribution, and asset-criticality risk scoring.
"""

import datetime
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from .preprocessor import SecurityTelemetryPreprocessor
from .autoencoder_model import ReconstructionAutoencoder

CRITICALITY_WEIGHTS = {
    "CRITICAL": 1.40,
    "HIGH": 1.20,
    "MEDIUM": 1.00,
    "LOW": 0.85
}

class ZeroDayAnomalyDetector:
    """
    Production-grade behavioral anomaly detector trained strictly on normal enterprise activity.
    Identifies zero-day / unknown threats via reconstruction loss and tree isolation depth.
    Provides plain-English feature attribution for every triggered alert.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.preprocessor = SecurityTelemetryPreprocessor()
        self.autoencoder = ReconstructionAutoencoder(random_state=random_state)
        self.isolation_forest = IsolationForest(
            n_estimators=150,
            contamination=0.01,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1
        )

        # Baseline calibration statistics
        self.threshold_low: float = 0.35
        self.threshold_medium: float = 0.45
        self.threshold_high: float = 0.55
        self.threshold_critical: float = 0.65

        self.ae_min_score: float = 0.0
        self.ae_max_score: float = 1.0
        self.if_min_score: float = 0.0
        self.if_max_score: float = 1.0

        self.baseline_feature_means: Dict[str, float] = {}
        self.trained_at: Optional[str] = None
        self.training_sample_count: int = 0
        self.version: str = "2.0.0-zeroday-ensemble"

    def fit(self, baseline_events: List[Dict[str, Any]]):
        """
        Trains the anomaly detection model strictly on normal baseline events.
        Calibrates anomaly score thresholds on the baseline empirical distribution.
        """
        self.training_sample_count = len(baseline_events)
        self.trained_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Feature Preprocessing
        self.preprocessor.fit(baseline_events)
        X_scaled = self.preprocessor.transform(baseline_events)

        # Store baseline feature averages for attribution explanations
        for idx, feat_name in enumerate(self.preprocessor.feature_names):
            self.baseline_feature_means[feat_name] = float(np.mean(X_scaled[:, idx]))

        # 2. Train Autoencoder
        self.autoencoder.fit(X_scaled)
        ae_errors = self.autoencoder.compute_reconstruction_error(X_scaled)

        # 3. Train Isolation Forest
        self.isolation_forest.fit(X_scaled)
        if_scores = -self.isolation_forest.score_samples(X_scaled)

        # 4. Calibrate normalization ranges based on baseline percentiles
        self.ae_min_score = float(np.percentile(ae_errors, 1))
        self.ae_max_score = float(max(np.percentile(ae_errors, 99.8), self.ae_min_score + 1e-4))

        self.if_min_score = float(np.percentile(if_scores, 1))
        self.if_max_score = float(max(np.percentile(if_scores, 99.8), self.if_min_score + 1e-4))

        # 5. Compute combined baseline scores to establish dynamic thresholds
        norm_ae = np.clip((ae_errors - self.ae_min_score) / (self.ae_max_score - self.ae_min_score), 0.0, 1.0)
        norm_if = np.clip((if_scores - self.if_min_score) / (self.if_max_score - self.if_min_score), 0.0, 1.0)
        baseline_combined = 0.55 * norm_ae + 0.45 * norm_if

        # Threshold calibration: strict percentiles for false positive suppression
        self.threshold_low = float(np.percentile(baseline_combined, 94.0))
        self.threshold_medium = float(np.percentile(baseline_combined, 98.0))
        self.threshold_high = float(np.percentile(baseline_combined, 99.2))
        self.threshold_critical = float(np.percentile(baseline_combined, 99.7))

    def _score_vectors(self, X_scaled: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Calculates normalized ensemble scores and per-feature attribution errors."""
        ae_errors, feat_sq_errors = self.autoencoder.compute_feature_attribution(X_scaled)
        if_scores = -self.isolation_forest.score_samples(X_scaled)

        norm_ae = np.clip((ae_errors - self.ae_min_score) / (self.ae_max_score - self.ae_min_score), 0.0, 3.0)
        norm_if = np.clip((if_scores - self.if_min_score) / (self.if_max_score - self.if_min_score), 0.0, 3.0)

        combined = 0.55 * norm_ae + 0.45 * norm_if

        # Piecewise quantile-calibrated mapping to [0.0, 1.0]
        anomaly_scores = np.zeros(len(combined), dtype=np.float32)
        for i, val in enumerate(combined):
            if val <= self.threshold_low:
                anomaly_scores[i] = (val / max(self.threshold_low, 1e-4)) * 0.40
            elif val <= self.threshold_medium:
                frac = (val - self.threshold_low) / max(self.threshold_medium - self.threshold_low, 1e-4)
                anomaly_scores[i] = 0.40 + frac * 0.25
            elif val <= self.threshold_high:
                frac = (val - self.threshold_medium) / max(self.threshold_high - self.threshold_medium, 1e-4)
                anomaly_scores[i] = 0.65 + frac * 0.15
            elif val <= self.threshold_critical:
                frac = (val - self.threshold_high) / max(self.threshold_critical - self.threshold_high, 1e-4)
                anomaly_scores[i] = 0.80 + frac * 0.12
            else:
                excess = val - self.threshold_critical
                anomaly_scores[i] = min(1.0, 0.92 + 0.08 * (1.0 - np.exp(-1.5 * excess)))

        return anomaly_scores, feat_sq_errors, ae_errors, if_scores

    def evaluate_event(self, event: Dict[str, Any], host_criticality: str = "MEDIUM") -> Dict[str, Any]:
        """
        Evaluates a single security log event for zero-day / novel threat anomalies.
        Returns full alert analysis with severity, confidence, risk score, and plain-English attribution.
        """
        X_scaled, X_raw = self.preprocessor.transform_single(event)
        scores, feat_sq_errors, ae_errors, if_scores = self._score_vectors(X_scaled)

        anomaly_score = float(scores[0])
        ae_err = float(ae_errors[0])
        if_score = float(if_scores[0])

        # Severity Determination
        if anomaly_score >= 0.92:
            severity = "CRITICAL"
            is_anomaly = True
        elif anomaly_score >= 0.80:
            severity = "HIGH"
            is_anomaly = True
        elif anomaly_score >= 0.65:
            severity = "MEDIUM"
            is_anomaly = True
        elif anomaly_score >= 0.40:
            severity = "LOW"
            is_anomaly = False  # Logged for telemetry correlation, not alert
        else:
            severity = "BENIGN"
            is_anomaly = False

        # Asset-criticality risk adjustment
        crit_weight = CRITICALITY_WEIGHTS.get(host_criticality.upper(), 1.0)
        risk_score = round(min(1.0, anomaly_score * crit_weight), 4)

        # Explainability: Feature Attribution
        sample_feat_err = feat_sq_errors[0]
        total_err = float(np.sum(sample_feat_err)) + 1e-6
        contributions = (sample_feat_err / total_err) * 100.0

        # Sort features by error contribution descending
        top_indices = np.argsort(contributions)[::-1][:4]
        top_attributions = []

        for idx in top_indices:
            feat_name = self.preprocessor.feature_names[idx]
            contrib_pct = round(float(contributions[idx]), 1)
            explanation = self._generate_explanation(feat_name, event)
            top_attributions.append({
                "feature": feat_name,
                "contribution_pct": contrib_pct,
                "explanation": explanation
            })

        return {
            "event_id": event.get("event_id", "UNKNOWN"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "hostname": event.get("hostname"),
            "user": event.get("user"),
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "risk_score": risk_score,
            "severity": severity,
            "decision": "ALERT_TRIGGERED" if is_anomaly else "BENIGN",
            "top_reasons": [a["explanation"] for a in top_attributions if a["contribution_pct"] > 10.0],
            "top_attributions": top_attributions,
            "details": event.get("details", ""),
            "model_diagnostics": {
                "autoencoder_reconstruction_mse": round(ae_err, 4),
                "isolation_forest_depth_score": round(if_score, 4),
                "model_version": self.version
            }
        }

    def evaluate_batch(self, events: List[Dict[str, Any]], host_criticality_map: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Evaluates a batch of security log events."""
        if not events:
            return []
        if host_criticality_map is None:
            host_criticality_map = {}

        results = []
        for evt in events:
            host = evt.get("hostname", "")
            crit = host_criticality_map.get(host, "MEDIUM")
            results.append(self.evaluate_event(evt, host_criticality=crit))
        return results

    def _generate_explanation(self, feat_name: str, evt: Dict[str, Any]) -> str:
        """Generates plain-English explanation for why a specific feature contributed to the anomaly."""
        if feat_name == "parent_child_rarity":
            p = evt.get("parent_image", "unknown")
            c = evt.get("image", "unknown")
            return f"Unprecedented process execution lineage: parent '{p}' spawned '{c}'"

        elif feat_name == "cmd_entropy":
            cmd = evt.get("command_line", "")
            return f"Anomalously high command-line randomness/obfuscation (length {len(cmd)})"

        elif feat_name == "is_lolbas_process":
            img = evt.get("image", "binary")
            return f"Living-Off-The-Land system binary execution: '{img}'"

        elif feat_name == "dest_port_rarity":
            port = evt.get("dest_port", "unknown")
            ip = evt.get("dest_ip", "unknown")
            return f"Atypical destination egress port {port} to external IP {ip}"

        elif feat_name == "bytes_sent_log":
            b = evt.get("bytes_sent", 0)
            return f"Excessive outbound transmission volume ({b:,} bytes)"

        elif feat_name == "bytes_ratio":
            return "Anomalous outbound to inbound data volume ratio"

        elif feat_name == "domain_entropy":
            dom = evt.get("query_name", "domain")
            return f"High-entropy / algorithmic domain query: '{dom}'"

        elif feat_name == "is_auth_failure":
            return "Repeated authentication failure burst indicating credential guessing"

        elif feat_name == "is_txt_dns_query":
            dom = evt.get("query_name", "domain")
            return f"Unusual DNS TXT query structure for '{dom}' (indicative of covert tunneling)"

        elif feat_name == "hour_sin" or feat_name == "hour_cos":
            return "Off-hours behavioral execution outside standard user operational profile"

        elif feat_name == "user_host_mismatch":
            u = evt.get("user", "unknown")
            h = evt.get("hostname", "unknown")
            return f"User '{u}' executing actions on unassigned workstation '{h}'"

        return f"Statistical divergence detected in {feat_name}"
