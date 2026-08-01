"""
Trains the core "classification model for distinguishing normal from
intrusive activity" called for in the proposal, and reports the
evaluation metrics the proposal names: accuracy, precision, recall,
false-positive rate.

Model choice: RandomForestClassifier.
- Handles the mixed/overlapping feature distributions well.
- Gives feature_importances_, which is useful evidence in your report
  for *why* the model flags what it flags (explainability matters for
  a security tool an admin has to trust).
- Fast enough to retrain from scratch every run; no GPU needed.
"""
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

FEATURES = [
    "requests_per_minute",
    "unique_records_accessed_5min",
    "off_hours",
    "failed_auth_attempts_10min",
    "bytes_transferred_5min",
    "is_confidential_endpoint",
]

DATA_PATH = "backend/data/access_logs.csv"
MODEL_PATH = "backend/ml/model.joblib"
METRICS_PATH = "backend/ml/metrics.json"


def train():
    df = pd.read_csv(DATA_PATH)
    X = df[FEATURES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight="balanced",  # malicious class is the minority
        random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "feature_importances": dict(zip(FEATURES, [round(v, 4) for v in model.feature_importances_])),
    }

    joblib.dump(model, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(json.dumps(metrics, indent=2))
    print(f"\nModel saved to {MODEL_PATH}")
    return metrics


if __name__ == "__main__":
    train()
