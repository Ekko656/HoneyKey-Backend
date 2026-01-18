import subprocess
import time
import requests
import os
import signal
import sys
import json

# Configuration
env = os.environ.copy()
# env["GEMINI_API_KEY"] = "..." # Set this in your environment or .env file
# env["GEMINI_MODEL"] = "gemini-flash-latest" 
env["HONEYPOT_KEY"] = "acme_client_m5n6o7p8q9r0s1t2"
env["PYTHONUNBUFFERED"] = "1"

print("Starting server...")
# Start server as a subprocess
server_process = subprocess.Popen(
    [r".\.venv\Scripts\uvicorn.exe", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

try:
    # Wait for server to be ready
    base_url = "http://127.0.0.1:8000"
    server_ready = False
    for _ in range(10):
        try:
            requests.get(f"{base_url}/health")
            server_ready = True
            print("Server is ready.")
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            
    if not server_ready:
        print("Server failed to start.")
        stdout, stderr = server_process.communicate(timeout=1)
        print("Server STDOUT:", stdout.decode())
        print("Server STDERR:", stderr.decode())
        sys.exit(1)

    # 1. Simulate Hacker Activity
    print("\n[Action] Simulating Hacker Activity...")
    headers = {"Authorization": f"Bearer {env['HONEYPOT_KEY']}"}
    
    # Intentionally causing 401/404/405 errors (this is the hacker activity)
    requests.get(f"{base_url}/v1/projects", headers=headers)
    requests.get(f"{base_url}/v1/users", headers=headers)
    requests.get(f"{base_url}/admin", headers=headers)
    requests.post(f"{base_url}/v1/projects", headers=headers)
    print("Hacker activity complete.")

    # 2. Get Incident ID
    print("\n[Action] Fetching Incident ID...")
    resp = requests.get(f"{base_url}/incidents")
    incidents = resp.json()
    if not incidents:
        print("No incidents found!")
        sys.exit(1)
        
    incident_id = incidents[0]['id']
    print(f"Latest Incident ID: {incident_id}")

    # 3. Analyze Incident
    print(f"\n[Action] Analyzing Incident {incident_id} (Generating Report)...")
    analyze_resp = requests.post(f"{base_url}/incidents/{incident_id}/analyze")
    
    if analyze_resp.status_code == 200:
        print("\n[SUCCESS] Report Generated!")
        report = analyze_resp.json()
        print(json.dumps(report, indent=2))
        
        # Save to file for user convenience
        with open("latest_soc_report.json", "w") as f:
            json.dump(report, f, indent=2)
    else:
        print(f"\n[ERROR] Analysis failed with status {analyze_resp.status_code}")
        print("Response:", analyze_resp.text)
        
        # Check DB for details if 502
        if analyze_resp.status_code == 502:
            print("Checking server logs provided in error...")

finally:
    print("\nStopping server...")
    server_process.terminate()
    try:
        server_process.wait(timeout=5)
    except:
        server_process.kill()
    print("Done.")
