# Sentry — AI-Powered Intrusion Detection System

A working prototype for the proposal *"Development of an AI-Powered
Intrusion Detection System (IDS) Application for Detecting
Unauthorized Access trying to Generate Confidential Information and
Data."*

It watches access to a confidential-data API in real time, scores every
request with a hybrid signature + machine-learning engine, raises
alerts to an admin dashboard, and writes every alert to a
tamper-evident hash-chained audit log.

## Why this architecture

The proposal targets something more specific than generic network
intrusion detection: unauthorized attempts to **reach, generate, or
exfiltrate confidential data**. That's an application-layer access
pattern problem (who's touching what, how often, how much, when),
not a raw-packet problem. So instead of sniffing network traffic, the
system:

1. Runs a small "target" API serving mock confidential records —
   stands in for whatever real system (HR database, financial
   records, customer PII store) an organization wants protected.
2. Logs every request into rolling per-user windows and turns them
   into behavioral features (request rate, unique records touched,
   off-hours activity, failed logins, bytes transferred).
3. Scores each event with **signature rules** (catches known-bad
   patterns instantly: brute force, mass enumeration, bulk transfer)
   **and** a **trained ML classifier** (catches patterns that don't
   match a hard-coded rule but still look anomalous) — this is the
   "hybrid" approach the proposal calls for.
4. Surfaces alerts, logs, and system status on a live dashboard.
5. Chains every alert into a hash-linked audit log so tampering with
   history is detectable — the optional blockchain-style deliverable.

## Project structure

```
ids-project/
├── backend/
│   ├── app.py                 Flask API: target endpoints, auth, logging, alerts
│   ├── security/
│   │   ├── auth.py            password hashing + JWT issue/verify
│   │   └── crypto.py          AES (Fernet) encryption of stored records
│   ├── blockchain/
│   │   └── audit_chain.py     hash-chained tamper-evident audit log
│   ├── ml/
│   │   ├── generate_data.py   builds the labeled training dataset
│   │   ├── train_model.py     trains + evaluates the classifier
│   │   ├── detect.py          hybrid signature+ML scoring used live
│   │   └── model.joblib       trained model (generated)
│   ├── data/                  generated CSV, model, audit log, keys
│   └── requirements.txt
├── frontend/
│   └── dashboard.html         single-file live console (no build step)
├── tests/
│   └── simulate_traffic.py    fires normal + attack traffic for a demo
└── README.md
```

## Setup

```bash
cd ids-project
pip install -r backend/requirements.txt

# 1. Generate the training dataset
python -m backend.ml.generate_data

# 2. Train the detection model
python -m backend.ml.train_model

# 3. Run the API
python -m backend.app
# -> serving on http://localhost:5001
```

Then open `frontend/dashboard.html` directly in a browser (no server
needed for it — it's a static file that calls the API at
`http://localhost:5001`). Log in with:

- **admin / AdminPass123!** (full dashboard access)
- **alice / AlicePass123!**, **bob / BobPass123!** (regular users, for
  generating traffic)

To see it detect something, run the demo attack script in another
terminal while the server is running:

```bash
python tests/simulate_traffic.py
```

Watch the dashboard's alert panel populate live as it simulates a
brute-force login attempt, a record-scraping run, and a bulk-download
exfiltration attempt.

## Detection logic

**Signature rules** (`backend/ml/detect.py`) — deterministic, instant:
- `brute_force_auth`: ≥5 failed logins from one actor in 10 minutes
- `mass_enumeration`: ≥40 unique confidential records touched in 5 minutes
- `bulk_exfiltration`: ≥60KB transferred to one actor in 5 minutes

**ML model** — `RandomForestClassifier` trained on the six behavioral
features, flags anything scoring ≥0.6 probability of being intrusive,
catching patterns that don't cross a hard rule threshold but still
look statistically abnormal.

An event is alerted if *either* layer fires. Every alert records which
layer(s) caught it — useful evidence in your report for why hybrid
beats either approach alone.

## Evaluation

Run `python -m backend.ml.train_model` to reproduce the held-out test
metrics (accuracy, precision, recall, false-positive rate — the exact
metrics named in the proposal). Results are written to
`backend/ml/metrics.json`.

**Be upfront about this in your report:** the current run scores
100% on all four metrics. That's not evidence of a great model — it's
because the synthetic training data has cleanly separated classes
(normal vs. attack behavior don't overlap much by construction). A
real evaluation needs messier, more realistic data. Two ways to
strengthen this before you present:

1. Edit `backend/ml/generate_data.py` to add more overlap between
   normal and malicious distributions (e.g. a normal power-user with
   a naturally high request rate), so the model has to work harder.
2. Better: capture *real* access logs from your home/school lab
   environment (even a few days of legitimate use plus a few staged
   "attacks" you run yourself) and retrain on that. This is also what
   turns this from a coursework demo into something you can honestly
   call tested against a live environment, which matches your "real
   network I control" setup.

## Mapping to the proposal's deliverables

| Proposal deliverable | Where it lives |
|---|---|
| Trained classification model | `backend/ml/train_model.py`, `model.joblib` |
| Web-based admin dashboard | `frontend/dashboard.html` |
| Secure app design (auth, access control, encryption) | `backend/security/` |
| Optional blockchain audit trail | `backend/blockchain/audit_chain.py` |
| Evaluation (accuracy/precision/recall/FPR) | `backend/ml/metrics.json` |

## Known limitations / honest next steps

- **In-memory storage.** Users, records, logs, and alerts live in
  Python dicts/lists, reset on restart. Fine for a prototype; swap for
  Postgres/SQLite before anything resembling production use.
- **Single-process Flask dev server.** Not for production traffic —
  the code says as much when it boots. Use gunicorn/uwsgi behind a
  reverse proxy for anything real.
- **JWT secret is hard-coded** in `security/auth.py` for convenience.
  Move it to an environment variable before deploying anywhere.
- **Blockchain component is a hash chain, not a distributed ledger.**
  It gives tamper-evidence (the property the proposal actually needs)
  without the complexity of a real blockchain. If your blockchain
  teammate wants to go further, the natural extension is periodically
  anchoring batches of `entry_hash` values to a testnet.
- **Synthetic training data**, discussed above under Evaluation.

## Suggested next milestones for the team

1. Cybersecurity: design more attack scenarios (IDOR-style ID
   tampering, session hijacking) and encode them as new signature
   rules or features.
2. Full-stack: move storage to a real database, add rate limiting to
   the auth endpoint itself.
3. Data analysis: replace/augment synthetic data with real captured
   logs; try a second model (e.g. Isolation Forest for unsupervised
   anomaly detection) and compare.
4. Blockchain: extend `audit_chain.py` toward a real distributed
   ledger if scope allows.
