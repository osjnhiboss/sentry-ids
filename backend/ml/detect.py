"""
Hybrid detection engine: signature-based rules (fast, deterministic,
zero false negatives on known bad patterns) layered with the ML model
(catches novel/unseen patterns the rules don't cover). This matches
the proposal's "combines machine learning-based anomaly detection with
traditional signature-based methods".
"""
import joblib
from .train_model import FEATURES, MODEL_PATH

_model = None


def _get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


# --- Signature-based rules: obvious, known-bad patterns caught instantly,
# without waiting on model probability thresholds. ---
SIGNATURE_RULES = [
    ("brute_force_auth", lambda f: f["failed_auth_attempts_10min"] >= 5),
    ("mass_enumeration", lambda f: f["unique_records_accessed_5min"] >= 40),
    ("bulk_exfiltration", lambda f: f["bytes_transferred_5min"] >= 60000),
]


def check_signatures(features: dict):
    hits = [name for name, rule in SIGNATURE_RULES if rule(features)]
    return hits


def score(features: dict):
    """
    Returns a dict: {is_alert, source, ml_probability, signature_hits, reason}
    features must contain all keys in FEATURES.
    """
    signature_hits = check_signatures(features)

    model = _get_model()
    import pandas as pd
    X = pd.DataFrame([[features[f] for f in FEATURES]], columns=FEATURES)
    ml_probability = float(model.predict_proba(X)[0][1])  # P(malicious)

    ML_THRESHOLD = 0.6
    is_ml_alert = ml_probability >= ML_THRESHOLD
    is_alert = bool(signature_hits) or is_ml_alert

    if signature_hits and is_ml_alert:
        source = "signature+ml"
    elif signature_hits:
        source = "signature"
    elif is_ml_alert:
        source = "ml"
    else:
        source = "none"

    reason_parts = []
    if signature_hits:
        reason_parts.append("Matched rule(s): " + ", ".join(signature_hits))
    if is_ml_alert:
        reason_parts.append(f"ML anomaly probability {ml_probability:.2f} >= {ML_THRESHOLD}")

    return {
        "is_alert": is_alert,
        "source": source,
        "ml_probability": round(ml_probability, 4),
        "signature_hits": signature_hits,
        "reason": "; ".join(reason_parts) if reason_parts else "Normal activity",
    }
