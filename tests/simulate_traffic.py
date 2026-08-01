"""
Demo/test script: fires normal traffic, then three attack scenarios,
at a running instance of the backend, so you can watch the dashboard
light up in real time.

Usage:
    1. In one terminal: python backend/app.py   (from ids-project/ root)
    2. In another:       python tests/simulate_traffic.py
    3. Open frontend/dashboard.html in a browser, log in as
       admin / AdminPass123!, and watch the alerts panel.
"""
import time
import requests

BASE = "http://localhost:5001"


def login(username, password):
    r = requests.post(f"{BASE}/api/login", json={"username": username, "password": password})
    r.raise_for_status()
    return r.json()["token"]


def normal_traffic():
    print("\n[*] Simulating normal user behavior (alice browsing a few records)...")
    token = login("alice", "AlicePass123!")
    headers = {"Authorization": f"Bearer {token}"}
    for record_id in [3, 17, 42]:
        r = requests.get(f"{BASE}/api/confidential/{record_id}", headers=headers)
        print(f"    GET /api/confidential/{record_id} -> {r.status_code}, alert={r.json().get('_detection', {}).get('is_alert')}")
        time.sleep(0.5)


def brute_force_attack():
    print("\n[*] Simulating brute-force login attack against 'bob'...")
    for i in range(7):
        r = requests.post(f"{BASE}/api/login", json={"username": "bob", "password": f"wrong{i}"})
        print(f"    attempt {i+1}: {r.status_code}")


def mass_enumeration_attack():
    print("\n[*] Simulating mass record enumeration (scraping) as 'alice'...")
    token = login("alice", "AlicePass123!")
    headers = {"Authorization": f"Bearer {token}"}
    for record_id in range(1, 51):
        r = requests.get(f"{BASE}/api/confidential/{record_id}", headers=headers)
        if r.json().get("_detection", {}).get("is_alert"):
            print(f"    record {record_id}: ALERT -> {r.json()['_detection']['reason']}")
            break


def bulk_exfiltration_attack():
    print("\n[*] Simulating bulk exfiltration via list endpoint...")
    token = login("alice", "AlicePass123!")
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE}/api/confidential?limit=200", headers=headers)
    print(f"    GET /api/confidential?limit=200 -> alert={r.json().get('_detection', {}).get('is_alert')}, "
          f"reason={r.json().get('_detection', {}).get('reason')}")


if __name__ == "__main__":
    normal_traffic()
    brute_force_attack()
    mass_enumeration_attack()
    bulk_exfiltration_attack()

    admin_token = login("admin", "AdminPass123!")
    alerts = requests.get(f"{BASE}/api/alerts", headers={"Authorization": f"Bearer {admin_token}"}).json()
    print(f"\n[*] Total alerts raised: {len(alerts['alerts'])}")
