"""DeepLog-style LSTM anomaly detection for alert sequences.

Based on DeepLog (Du et al., CCS 2017). Detects anomalous events
in sequential log/alert data by predicting next events and flagging
those with low predicted probability.

Model loads from DEEPLOG_MODEL_PATH env var or defaults to
/models/deeplog.pt. If model not found, runs in feature-extraction
mode only (no anomaly scoring).
"""
import os
import logging
import json
from typing import List, Tuple, Dict, Optional

logger = logging.getLogger(__name__)

DEEPLOG_MODEL_PATH = os.environ.get("DEEPLOG_MODEL_PATH", "/models/deeplog.pt")

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available — DeepLog runs in feature-extraction mode only")


if TORCH_AVAILABLE:
    class DeepLogModel(nn.Module):
        """LSTM-based next-event predictor."""

        def __init__(self, input_size: int = 50, hidden_size: int = 128,
                     num_layers: int = 2, num_classes: int = 50):
            super().__init__()
            self.hidden_size = hidden_size
            self.num_layers = num_layers
            self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
            self.fc = nn.Linear(hidden_size, num_classes)

        def forward(self, x):
            h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
            c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
            out, _ = self.lstm(x, (h0, c0))
            out = self.fc(out[:, -1, :])
            return out


class DeepLogAnalyzer:
    """Anomaly detection in alert sequences using LSTM prediction."""

    def __init__(self, model_path: str = None, window_size: int = 10):
        self.window_size = window_size
        self.model = None
        self.model_loaded = False

        if TORCH_AVAILABLE:
            self.model = DeepLogModel()
            path = model_path or DEEPLOG_MODEL_PATH
            if os.path.exists(path):
                try:
                    self.model.load_state_dict(torch.load(path, map_location="cpu"))
                    self.model.eval()
                    self.model_loaded = True
                    logger.info(f"DeepLog model loaded from {path}")
                except Exception as e:
                    logger.warning(f"Failed to load DeepLog model: {e}")
            else:
                logger.info(f"DeepLog model not found at {path} — feature-extraction mode")

    def detect_anomalies(self, alert_sequence: List[Dict],
                         threshold: float = 0.01) -> List[Dict]:
        """Detect anomalous events in an alert sequence.

        Args:
            alert_sequence: List of alert dicts with at least {id, embedding/features}
            threshold: Probability threshold below which an event is anomalous

        Returns:
            List of {index, alert_id, anomaly_score, reason} for anomalous events
        """
        if not alert_sequence:
            return []

        # Extract feature vectors from alerts
        features = self._extract_features(alert_sequence)

        if not self.model_loaded or not TORCH_AVAILABLE:
            # Feature-extraction mode: use statistical anomaly detection
            return self._statistical_anomaly_detection(alert_sequence, features)

        anomalies = []
        with torch.no_grad():
            for i in range(self.window_size, len(features)):
                window = features[i - self.window_size:i]
                input_tensor = torch.FloatTensor([window])
                output = self.model(input_tensor)
                probs = torch.softmax(output, dim=1)[0]

                # Get the actual event class
                actual_class = self._event_to_class(alert_sequence[i])
                if actual_class < len(probs):
                    event_prob = probs[actual_class].item()
                    if event_prob < threshold:
                        anomalies.append({
                            "index": i,
                            "alert_id": alert_sequence[i].get("id", f"idx-{i}"),
                            "anomaly_score": 1.0 - event_prob,
                            "predicted_prob": event_prob,
                            "reason": f"Event probability {event_prob:.4f} below threshold {threshold}",
                        })

        return anomalies

    def _extract_features(self, alerts: List[Dict]) -> List[List[float]]:
        """Extract feature vectors from alert dicts."""
        features = []
        for alert in alerts:
            # Use embedding if available, otherwise create basic feature vector
            if "embedding" in alert and alert["embedding"]:
                vec = alert["embedding"][:50]  # Truncate/pad to input_size
                vec = vec + [0.0] * (50 - len(vec))
            else:
                vec = self._basic_features(alert)
            features.append(vec)
        return features

    def _basic_features(self, alert: Dict) -> List[float]:
        """Create a basic 50-dim feature vector from alert fields."""
        features = [0.0] * 50
        # Severity encoding
        sev_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "informational": 0.1}
        features[0] = sev_map.get(str(alert.get("severity", "")).lower(), 0.3)
        # Alert type hash (deterministic numeric encoding)
        alert_name = str(alert.get("alert_name", alert.get("type", "")))
        features[1] = (hash(alert_name) % 1000) / 1000.0
        # Source IP hash
        features[2] = (hash(str(alert.get("source_ip", ""))) % 1000) / 1000.0
        # Dest IP hash
        features[3] = (hash(str(alert.get("dest_ip", ""))) % 1000) / 1000.0
        # Rule name hash
        features[4] = (hash(str(alert.get("rule_name", ""))) % 1000) / 1000.0
        return features

    def _event_to_class(self, alert: Dict) -> int:
        """Map alert to a class index for prediction."""
        alert_name = str(alert.get("alert_name", alert.get("type", "")))
        return hash(alert_name) % 50

    def _statistical_anomaly_detection(self, alerts: List[Dict],
                                        features: List[List[float]]) -> List[Dict]:
        """Fallback: statistical anomaly detection without model."""
        if len(features) < 3:
            return []

        anomalies = []
        # Compute feature means and stds
        import statistics
        for dim in range(min(5, len(features[0]))):
            values = [f[dim] for f in features]
            if len(set(values)) <= 1:
                continue
            mean = statistics.mean(values)
            stdev = statistics.stdev(values)
            if stdev == 0:
                continue
            for i, val in enumerate(values):
                z_score = abs(val - mean) / stdev
                if z_score > 3.0:  # 3-sigma outlier
                    anomalies.append({
                        "index": i,
                        "alert_id": alerts[i].get("id", f"idx-{i}"),
                        "anomaly_score": min(z_score / 5.0, 1.0),
                        "reason": f"Statistical outlier: z-score={z_score:.2f} on feature {dim}",
                    })

        # Deduplicate by index (keep highest score)
        seen = {}
        for a in anomalies:
            idx = a["index"]
            if idx not in seen or a["anomaly_score"] > seen[idx]["anomaly_score"]:
                seen[idx] = a
        return sorted(seen.values(), key=lambda x: x["anomaly_score"], reverse=True)


from temporalio import activity


@activity.defn
async def analyze_alert_sequence(params: dict) -> dict:
    """Temporal activity: run DeepLog analysis on alert sequence.

    Args: {alert_ids: List[str], tenant_id: str}
    Returns: {anomalies: List, total_alerts: int, model_loaded: bool}
    """
    alert_ids = params.get("alert_ids", [])
    tenant_id = params.get("tenant_id")

    # Fetch alerts from DB
    import psycopg2
    from psycopg2.extras import RealDictCursor
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    conn = psycopg2.connect(db_url)
    alerts = []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if alert_ids:
                placeholders = ",".join(["%s"] * len(alert_ids))
                cur.execute(
                    f"SELECT id, alert_name, severity, source_ip, dest_ip, rule_name, created_at "
                    f"FROM siem_alerts WHERE id IN ({placeholders}) AND tenant_id = %s "
                    f"ORDER BY created_at",
                    (*alert_ids, tenant_id)
                )
            else:
                cur.execute(
                    "SELECT id, alert_name, severity, source_ip, dest_ip, rule_name, created_at "
                    "FROM siem_alerts WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 100",
                    (tenant_id,)
                )
            alerts = [dict(row) for row in cur.fetchall()]
            for a in alerts:
                a["id"] = str(a["id"])
    finally:
        conn.close()

    analyzer = DeepLogAnalyzer()
    anomalies = analyzer.detect_anomalies(alerts)

    return {
        "anomalies": anomalies,
        "total_alerts": len(alerts),
        "anomalies_found": len(anomalies),
        "model_loaded": analyzer.model_loaded,
    }
