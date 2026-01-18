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

# Different keys for different attack scenarios
KEYS = {
    "script_kiddie": "acme_docker_j4k5l6m7n8o9p0q1",   # GitHub dorking (novice)
    "sql_injection": "acme_client_m5n6o7p8q9r0s1t2",   # JS source map (intermediate)
    "slow_recon": "acme_debug_a1b2c3d4e5f6g7h8",       # Log file access (advanced)
}

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
    key = KEYS["script_kiddie"]
    console.print(Panel(f"Simulating: Script Kiddie (GitHub Dorking)\nKey: {key[:20]}...", style="bold red"))
    console.print("[dim]Attacker found key in docker-compose.yml on public GitHub repo[/dim]")
    headers = {
        "User-Agent": "curl/7.81.0",
        "Authorization": f"Bearer {key}"
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
    key = KEYS["sql_injection"]
    console.print(Panel(f"Simulating: SQL Injection (JS Source Map Attack)\nKey: {key[:20]}...", style="bold yellow"))
    console.print("[dim]Attacker extracted key from minified JS bundle via source map[/dim]")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
        "Authorization": f"Bearer {key}"
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
    key = KEYS["slow_recon"]
    console.print(Panel(f"Simulating: Advanced Recon (Debug Log Compromise)\nKey: {key[:20]}...", style="bold blue"))
    console.print("[dim]Attacker has server access - extracted key from debug logs[/dim]")
    headers = {
        "User-Agent": "python-requests/2.26.0",
        "Authorization": f"Bearer {key}"
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
        console.print("Each attack uses a DIFFERENT honeypot key from a different leak source:\n")
        console.print("1. [Script Kiddie]   GitHub Dorking      - docker-compose.yml leak (NOVICE)")
        console.print("2. [SQL Injection]   Source Map Attack   - JS bundle extraction (INTERMEDIATE)")
        console.print("3. [Advanced Recon]  Log File Compromise - server debug logs (ADVANCED)")
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
