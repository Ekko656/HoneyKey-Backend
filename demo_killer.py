import requests
import time
import json
import os
import subprocess
import signal
import sys

# Config
BASE_URL = "http://127.0.0.1:8000"
KEY = "acme_client_m5n6o7p8q9r0s1t2"
HEADERS = {"Authorization": f"Bearer {KEY}"}

def wait_for_server():
    print("Waiting for server to be up...")
    for _ in range(10):
        try:
            requests.get(f"{BASE_URL}/health")
            print("Server is up.")
            return True
        except:
            time.sleep(1)
    return False

def print_report_summary(phase_name, report):
    print(f"\n[{phase_name}] Report Summary:")
    print(f"Severity: {report.get('severity')}")
    print(f"Confidence: {report.get('confidence_score')}")
    print(f"Techniques: {len(report.get('techniques', []))}")
    for t in report.get('techniques', []):
        print(f"  - {t}")
    print(f"Evidence Count: {len(report.get('evidence', []))}")
    print("-" * 40)

def main():
    # 0. Start Server (assuming it's handled externally or running already? 
    # The user asked to "Run this twice", implying manual steps, but I will automate it.)
    # Since I don't control the external terminal easily, I'll assume the server needs to be started.
    # But for a robust tool usage, I should probably rely on `run_in_terminal` to run the server in background.
    pass

if __name__ == "__main__":
    if not wait_for_server():
        print("Server not running. Please start it with 'uvicorn app.main:app --host 127.0.0.1 --port 8000'")
        sys.exit(1)

    print("\n=== PHASE 1: Low & Slow (Few Requests) ===")
    # 1. Few requests
    requests.get(f"{BASE_URL}/v1/projects", headers=HEADERS)
    requests.get(f"{BASE_URL}/v1/users", headers=HEADERS)
    
    # 2. Analyze
    incidents = requests.get(f"{BASE_URL}/incidents").json()
    if not incidents:
        print("No incidents found!")
        sys.exit(1)
    
    incident_id = incidents[0]['id']
    print(f"Analyzing Incident {incident_id}...")
    resp = requests.post(f"{BASE_URL}/incidents/{incident_id}/analyze")
    if resp.status_code == 200:
        print_report_summary("Phase 1", resp.json())
    else:
        print(f"Phase 1 Analysis Failed: {resp.text}")

    print("\n=== PHASE 2: Noisy Attacker (Enumeration) ===")
    # 3. Simulated attacker (many requests)
    for _ in range(40):
        requests.get(f"{BASE_URL}/v1/projects", headers=HEADERS)
    
    # Allow DB to catch up slightly?
    time.sleep(1)

    # 4. Analyze again
    print(f"Re-analyzing Incident {incident_id}...")
    resp = requests.post(f"{BASE_URL}/incidents/{incident_id}/analyze")
    if resp.status_code == 200:
        print_report_summary("Phase 2", resp.json())
    else:
        print(f"Phase 2 Analysis Failed: {resp.text}")

