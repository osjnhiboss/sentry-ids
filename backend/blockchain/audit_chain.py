"""
Lightweight hash-chained audit log ("blockchain-lite").

This is not a distributed blockchain — it's the minimal mechanism that
gives you the *tamper-evidence* property the proposal asks for:
each entry stores the SHA-256 hash of the previous entry plus its own
data, so any retroactive edit to an earlier entry breaks every hash
after it. That's enough to satisfy "tamper-evident logging of security
events" for a prototype, and the README explains how to extend it to a
real distributed ledger if the blockchain specialist on the team wants
to take it further (e.g. anchoring batches to a testnet).
"""
import hashlib
import json
import time
import os

CHAIN_FILE = "backend/data/audit_chain.jsonl"
GENESIS_HASH = "0" * 64


def _last_hash() -> str:
    if not os.path.exists(CHAIN_FILE):
        return GENESIS_HASH
    with open(CHAIN_FILE, "rb") as f:
        lines = f.readlines()
        if not lines:
            return GENESIS_HASH
        last_entry = json.loads(lines[-1])
        return last_entry["entry_hash"]


def _hash_entry(prev_hash: str, timestamp: float, event: dict) -> str:
    payload = json.dumps({"prev_hash": prev_hash, "timestamp": timestamp, "event": event}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def append_event(event: dict) -> dict:
    """Append a security event to the tamper-evident chain. Returns the stored entry."""
    os.makedirs(os.path.dirname(CHAIN_FILE), exist_ok=True)
    prev_hash = _last_hash()
    timestamp = time.time()
    entry_hash = _hash_entry(prev_hash, timestamp, event)
    entry = {
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "event": event,
        "entry_hash": entry_hash,
    }
    with open(CHAIN_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def verify_chain() -> dict:
    """Walk the whole chain and confirm no entry has been tampered with."""
    if not os.path.exists(CHAIN_FILE):
        return {"valid": True, "entries": 0}

    prev_hash = GENESIS_HASH
    count = 0
    with open(CHAIN_FILE, "r") as f:
        for line in f:
            entry = json.loads(line)
            expected_hash = _hash_entry(prev_hash, entry["timestamp"], entry["event"])
            if entry["prev_hash"] != prev_hash or entry["entry_hash"] != expected_hash:
                return {"valid": False, "broken_at_entry": count}
            prev_hash = entry["entry_hash"]
            count += 1
    return {"valid": True, "entries": count}


def read_all():
    if not os.path.exists(CHAIN_FILE):
        return []
    with open(CHAIN_FILE, "r") as f:
        return [json.loads(line) for line in f]
