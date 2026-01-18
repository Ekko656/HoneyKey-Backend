import requests
import time
import os
import json
import subprocess
import signal
import sys

# Configuration
env = os.environ.copy()
env["GEMINI_API_KEY"] = "AIzaSyBpGrgDFRgT8iDpDyXjLHZa0fshBayIvNo"
env["GEMINI_MODEL"] = "gemini-flash-latest"
env["HONEYPOT_KEY"] = "acme_client_m5n6o7p8q9r0s1t2"
env["PYTHONUNBUFFERED"] = "1"
BASE = "http://127.0.0.1:8000"

def start_server():
    print("Starting server...")
    return subprocess.Popen(
        [r".\.venv\Scripts\uvicorn.exe", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def wait_for_server():
    for _ in range(10):
        try:
            requests.get(f"{BASE}/health")
            print("Server ready.")
            return True
        except:
            time.sleep(1)
    return False

def run_scenario(name, requests_func):
    print(f"\n=== Scenario: {name} ===")
    headers = {"Authorization": f"Bearer {env['HONEYPOT_KEY']}"}
    requests_func(headers)
    
    # Get latest incident
    incidents = requests.get(f"{BASE}/incidents").json()
    if not incidents:
        print("No incident found!")
        return None
        
    incident_id = incidents[0]['id'] # Assuming ordered desc
    print(f"Incident ID: {incident_id}")
    
    # Analyze
    print("Generating SOC report...")
    resp = requests.post(f"{BASE}/incidents/{incident_id}/analyze")
    if resp.status_code != 200:
        print(f"Analysis failed: {resp.text}")
        return None
        
    report = resp.json()
    print(f"Severity: {report.get('severity')}")
    print(f"Summary: {report.get('summary')}")
    return report

def scenario_small(headers):
    print("Sending 3 requests...")
    requests.get(f"{BASE}/v1/projects", headers=headers)
    requests.get(f"{BASE}/v1/users", headers=headers)
    requests.get(f"{BASE}/admin", headers=headers)

def scenario_attacker(headers):
    print("Simulating specific attack patterns (40 requests)...")
    for _ in range(10):
        requests.get(f"{BASE}/v1/projects", headers=headers)
    for _ in range(5):
        requests.post(f"{BASE}/v1/projects", headers=headers) # Injection/Modification
    for _ in range(25):
        requests.get(f"{BASE}/v1/users", headers=headers) # Enum

# Main
server = start_server()
try:
    if wait_for_server():
        # Clean DB first? No, let's just rely on incident windows. 
        # Actually to prove delta we need fresh incidents or ensure they are treated separately.
        # But the backend groups by window. So we should sleep 2 seconds between maybe?
        
        print("\n--- 1️⃣ Few Requests ---")
        report1 = run_scenario("Small Recon", scenario_small)
        
        print("\nWaiting 5s before next wave...")
        time.sleep(5)
        
        print("\n--- 2️⃣ Simulated Attacker ---")
        report2 = run_scenario("Heavy Attack", scenario_attacker)

        if report1 and report2:
            print("\n\n=== KILLER DEMO PROOF ===")
            print("Report 1 Severity:", report1.get("severity"))
            print("Report 2 Severity:", report2.get("severity"))
            print("Delta confirmed." if report1.get("severity") != report2.get("severity") or len(report2.get("evidence", [])) > len(report1.get("evidence", [])) else "Delta unclear.")
finally:
    server.terminate()
