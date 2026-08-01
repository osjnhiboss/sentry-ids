"""
IDS Application backend.

Three roles in one Flask app, deliberately kept together for a
prototype (a real deployment would split the "target" system from the
IDS, since in reality the IDS watches *someone else's* app):

1. A mock "confidential data" API — the thing being protected. Stands
   in for whatever real system (HR records, financial DB, customer
   PII store) an org wants monitored.
2. A logging + hybrid detection layer — every request to the
   confidential API is turned into a feature vector (rolling counts
   per user) and scored by backend/ml/detect.py in real time.
3. An alerts/admin API — what the React-less dashboard (frontend/dashboard.html)
   polls to show live alerts, logs, and system status.

Run with: python backend/app.py  (from the ids-project/ root)
"""
import time
import collections
from flask import Flask, request, jsonify, g
from functools import wraps

from backend.security.auth import hash_password, verify_password, issue_token, decode_token
from backend.security.crypto import encrypt, decrypt
from backend.blockchain.audit_chain import append_event, verify_chain, read_all
from backend.ml.detect import score

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    # Dashboard is served from a different origin (file:// or a static
    # server) than the API, so we allow cross-origin requests here.
    # In production, restrict this to the dashboard's real origin.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return "", 204

# ---------------------------------------------------------------------------
# In-memory "database" (swap for Postgres/Mongo in production; kept simple
# here so the whole prototype runs with zero external services).
# ---------------------------------------------------------------------------
USERS = {
    "admin": {"password_hash": hash_password("AdminPass123!"), "role": "admin"},
    "alice": {"password_hash": hash_password("AlicePass123!"), "role": "user"},
    "bob":   {"password_hash": hash_password("BobPass123!"), "role": "user"},
}

CONFIDENTIAL_RECORDS = {
    str(i): encrypt(f"Confidential record #{i}: SSN-{1000+i}, Salary=${40000 + i*137}")
    for i in range(1, 201)
}

ALERTS = []             # list of alert dicts, newest first
ACCESS_LOG = []         # list of raw access events, newest first

# Rolling per-user activity windows, used to compute features live.
# Each entry: deque of (timestamp, event_dict)
_user_windows = collections.defaultdict(lambda: collections.deque(maxlen=500))
FAILED_AUTH = collections.defaultdict(lambda: collections.deque(maxlen=500))

WINDOW_5MIN = 300
WINDOW_10MIN = 600


def _now():
    return time.time()


def _prune(dq, window_seconds):
    cutoff = _now() - window_seconds
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def compute_features(user_id: str, is_confidential_endpoint: bool, bytes_size: int, hour: int):
    dq = _user_windows[user_id]
    _prune(dq, WINDOW_10MIN)

    one_min_ago = _now() - 60
    requests_last_min = sum(1 for ts, _ in dq if ts >= one_min_ago)

    five_min_ago = _now() - WINDOW_5MIN
    recent5 = [ev for ts, ev in dq if ts >= five_min_ago]
    unique_records = len({ev["record_id"] for ev in recent5 if ev.get("record_id")})
    bytes_5min = sum(ev.get("bytes_size", 0) for ev in recent5) + bytes_size

    fdq = FAILED_AUTH[user_id]
    _prune_failed(fdq)

    return {
        "requests_per_minute": requests_last_min,
        "unique_records_accessed_5min": unique_records,
        "off_hours": 1 if (hour < 8 or hour >= 20) else 0,
        "failed_auth_attempts_10min": len(fdq),
        "bytes_transferred_5min": bytes_5min,
        "is_confidential_endpoint": 1 if is_confidential_endpoint else 0,
    }


def _prune_failed(dq):
    cutoff = _now() - WINDOW_10MIN
    while dq and dq[0] < cutoff:
        dq.popleft()


def log_and_score(user_id, endpoint, record_id, bytes_size, is_confidential_endpoint, ip):
    ts = _now()
    hour = time.localtime(ts).tm_hour
    event = {"record_id": record_id, "bytes_size": bytes_size, "endpoint": endpoint}
    _user_windows[user_id].append((ts, event))

    features = compute_features(user_id, is_confidential_endpoint, bytes_size, hour)
    result = score(features)

    log_entry = {
        "timestamp": ts,
        "user_id": user_id,
        "ip": ip,
        "endpoint": endpoint,
        "record_id": record_id,
        "features": features,
        "detection": result,
    }
    ACCESS_LOG.insert(0, log_entry)
    del ACCESS_LOG[500:]  # cap in-memory log size

    if result["is_alert"]:
        ALERTS.insert(0, log_entry)
        del ALERTS[200:]
        append_event({
            "type": "ALERT",
            "user_id": user_id,
            "ip": ip,
            "endpoint": endpoint,
            "reason": result["reason"],
            "source": result["source"],
        })

    return result


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------
def require_auth(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or malformed Authorization header"}), 401
            token = auth_header.split(" ", 1)[1]
            payload = decode_token(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            if role and payload.get("role") != role:
                return jsonify({"error": "Insufficient permissions"}), 403
            g.user = payload
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    ip = request.remote_addr or "unknown"

    user = USERS.get(username)
    ok = user and verify_password(password, user["password_hash"])

    if not ok:
        FAILED_AUTH[username].append(_now())
        # Failed logins are themselves security-relevant events; score them too.
        log_and_score(username or "unknown", "/api/login", None, 0, False, ip)
        return jsonify({"error": "Invalid credentials"}), 401

    token = issue_token(username, role=user["role"])
    return jsonify({"token": token, "role": user["role"]})


# ---------------------------------------------------------------------------
# The protected target: confidential data endpoints
# ---------------------------------------------------------------------------
@app.route("/api/confidential/<record_id>", methods=["GET"])
@require_auth()
def get_confidential_record(record_id):
    user_id = g.user["sub"]
    ip = request.remote_addr or "unknown"
    ciphertext = CONFIDENTIAL_RECORDS.get(record_id)

    if not ciphertext:
        log_and_score(user_id, "/api/confidential/<id>", record_id, 0, True, ip)
        return jsonify({"error": "Not found"}), 404

    plaintext = decrypt(ciphertext)
    result = log_and_score(user_id, "/api/confidential/<id>", record_id, len(plaintext), True, ip)

    return jsonify({"record": plaintext, "_detection": result})


@app.route("/api/confidential", methods=["GET"])
@require_auth()
def list_confidential():
    """Bulk listing endpoint — a prime exfiltration vector, watched closely."""
    user_id = g.user["sub"]
    ip = request.remote_addr or "unknown"
    limit = min(int(request.args.get("limit", 10)), 200)

    ids = list(CONFIDENTIAL_RECORDS.keys())[:limit]
    records = [decrypt(CONFIDENTIAL_RECORDS[i]) for i in ids]
    total_bytes = sum(len(r) for r in records)

    result = log_and_score(user_id, "/api/confidential", f"bulk:{limit}", total_bytes, True, ip)

    return jsonify({"records": records, "_detection": result})


# ---------------------------------------------------------------------------
# Admin / dashboard endpoints
# ---------------------------------------------------------------------------
@app.route("/api/alerts", methods=["GET"])
@require_auth(role="admin")
def get_alerts():
    return jsonify({"alerts": ALERTS[:100]})


@app.route("/api/logs", methods=["GET"])
@require_auth(role="admin")
def get_logs():
    return jsonify({"logs": ACCESS_LOG[:100]})


@app.route("/api/status", methods=["GET"])
@require_auth(role="admin")
def get_status():
    chain_status = verify_chain()
    return jsonify({
        "total_events_logged": len(ACCESS_LOG),
        "total_alerts": len(ALERTS),
        "active_users_tracked": len(_user_windows),
        "audit_chain": chain_status,
    })


@app.route("/api/audit-log", methods=["GET"])
@require_auth(role="admin")
def get_audit_log():
    return jsonify({"chain": read_all()[-100:], "verification": verify_chain()})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
