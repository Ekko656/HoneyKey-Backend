import time
import requests
import sys
import json
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.theme import Theme
from rich.prompt import Prompt
import demo_reset

# Configuration
BASE_URL = "http://127.0.0.1:8000"
HONEYPOT_KEY = "acme_live_f93k2jf92jf0s9df"

# Rich Console Setup
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "success": "green", 
    "header": "bold magenta"
})
console = Console(theme=custom_theme)

def check_server():
    try:
        requests.get(f"{BASE_URL}/health", timeout=1)
        return True
    except:
        console.print("[error]Backend server is NOT reachable at http://127.0.0.1:8000 ![/error]")
        console.print("Please run: [bold]uvicorn app.main:app --host 127.0.0.1 --port 8000[/bold] in a separate terminal.")
        return False

def get_latest_incident():
    """Fetches the most recent incident from the API."""
    try:
        resp = requests.get(f"{BASE_URL}/incidents")
        resp.raise_for_status()
        incidents = resp.json()
        if incidents:
            return incidents[0] # List is ordered by last_seen DESC
        return None
    except Exception as e:
        console.print(f"[error]Failed to fetch incidents: {e}[/error]")
        return None

def run_analysis(incident_id):
    """Triggers the AI analysis for the given incident."""
    console.print(f"[info]Triggering AI Analysis for Incident {incident_id}...[/info]")
    try:
        resp = requests.post(f"{BASE_URL}/incidents/{incident_id}/analyze")
        if resp.status_code == 200:
            console.print(f"[success]Analysis Complete for Incident {incident_id}![/success]")
            data = resp.json()
            summary = data.get("summary", "No summary provided.")
            console.print(Panel(summary, title=f"Report for Incident {incident_id}", border_style="green"))
            return True
        else:
            console.print(f"[error]Analysis Failed: {resp.status_code} - {resp.text}[/error]")
            return False
    except Exception as e:
        console.print(f"[error]Error triggering analysis: {str(e)}[/error]")
        return False

def scenario_script_kiddie():
    console.print(Panel("Simulating: Script Kiddie (High Noise, Basic curl)", style="bold red"))
    headers = {
        "User-Agent": "curl/7.81.0",
        "Authorization": f"Bearer {HONEYPOT_KEY}"
    }
    steps = [
        ("GET", "/v1/projects"),
        ("GET", "/v1/projects"),
        ("GET", "/v1/secrets"),
        ("GET", "/admin"),
        ("POST", "/v1/projects")
    ]
    with Progress() as progress:
        task = progress.add_task("[red]Firing requests...", total=len(steps))
        for method, path in steps:
            try:
                if method == "GET":
                    requests.get(f"{BASE_URL}{path}", headers=headers)
                elif method == "POST":
                    requests.post(f"{BASE_URL}{path}", headers=headers)
            except: pass
            progress.advance(task)
            time.sleep(0.1)

def scenario_sql_injection():
    console.print(Panel("Simulating: SQL Injection (Malicious Payloads)", style="bold yellow"))
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
        "Authorization": f"Bearer {HONEYPOT_KEY}"
    }
    payloads = ["' OR '1'='1", "admin' --", "UNION SELECT 1, version(), 3"]
    path = "/v1/projects"
    with Progress() as progress:
        task = progress.add_task("[yellow]Injecting payloads...", total=len(payloads))
        for payload in payloads:
            try:
                requests.get(f"{BASE_URL}{path}?id={payload}", headers=headers)
            except: pass
            progress.advance(task)
            time.sleep(0.5)

def scenario_slow_recon():
    console.print(Panel("Simulating: Low & Slow Recon (Stealthy)", style="bold blue"))
    headers = {
        "User-Agent": "python-requests/2.26.0",
        "Authorization": f"Bearer {HONEYPOT_KEY}"
    }
    steps = ["/health", "/v1/projects", "/v1/invalid", "/v1/secrets"]
    with Progress() as progress:
        task = progress.add_task("[blue]Probing slowly...", total=len(steps))
        for path in steps:
            try:
                requests.get(f"{BASE_URL}{path}", headers=headers)
            except: pass
            progress.advance(task)
            time.sleep(1.0) # Faster than 1.5s for demo patience

def main():
    if not check_server():
        sys.exit(1)

    while True:
        console.clear()
        console.print("[header]HoneyKey Attack Simulation Suite[/header]")
        console.print("1. [Script Kiddie]   Fast, Noisy (Current Demo)")
        console.print("2. [SQL Injection]   Malicious Payloads")
        console.print("3. [Low & Slow]      Stealthy Recon")
        console.print("4. Exit")
        
        choice = Prompt.ask("\nSelect Option", choices=["1", "2", "3", "4"], default="1")
        
        if choice == '4': sys.exit(0)
        
        # 1. Reset
        console.print("\n[info]Step 1: Forcing NEW Incident (Moving old ones to archive)...[/info]")
        demo_reset.close_active_incidents()
        time.sleep(0.5)

        # 2. Attack
        if choice == '1': scenario_script_kiddie()
        elif choice == '2': scenario_sql_injection()
        elif choice == '3': scenario_slow_recon()

        # 3. Verify & Analyze
        time.sleep(1.5) # Wait for processing
        console.print("\n[info]Step 2: Detecting New Incident...[/info]")
        latest = get_latest_incident()
        
        if not latest:
            console.print("[error]No incidents found![/error]")
            input("Press Enter...")
            continue
            
        new_id = latest['id']
        console.print(f"[success]detected new Incident {new_id}[/success]")
        
        # 4. Generate Report AUTOMATICALLY
        run_analysis(new_id)

        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    main()
