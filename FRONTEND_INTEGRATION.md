# HoneyKey Frontend Integration Guide

## Base URL
```
http://localhost:8000
```

---

## Incidents API

### List All Incidents
```http
GET /incidents
```
**Response:**
```json
[
  {
    "id": 1,
    "key_id": "honeypot",
    "source_ip": "192.168.1.100",
    "first_seen": "2024-01-15T10:00:00Z",
    "last_seen": "2024-01-15T10:30:00Z",
    "event_count": 50
  }
]
```

### Get Single Incident
```http
GET /incidents/{incident_id}
```

### Get Incident Events
```http
GET /incidents/{incident_id}/events
```

### Analyze Incident (Generate AI Report)
```http
POST /incidents/{incident_id}/analyze
```
**Response:**
```json
{
  "incident_id": 1,
  "severity": "Medium",
  "summary": "...",
  "evidence": ["..."],
  "recommended_actions": ["..."],
  "techniques": ["T1595: Active Scanning"],
  "confidence_score": 0.85
}
```

### Get Existing AI Report
```http
GET /incidents/{incident_id}/ai-report
```

---

## IP Blocking API

### Check Block Status (call when loading incident)
```http
GET /incidents/{incident_id}/block-status
```
**Response:**
```json
{
  "incident_id": 1,
  "source_ip": "192.168.1.100",
  "is_blocked": true
}
```

### Block IP from Incident
```http
POST /incidents/{incident_id}/block-ip
Content-Type: application/json

{
  "duration_hours": 24,    // null = permanent
  "notes": "Blocked by analyst"
}
```
**Response:**
```json
{
  "success": true,
  "message": "Successfully blocked IP 192.168.1.100",
  "block": {
    "id": 1,
    "ip_address": "192.168.1.100",
    "incident_id": 1,
    "reason": "honeypot_abuse",
    "blocked_at": "2024-01-15T10:00:00Z",
    "expires_at": "2024-01-16T10:00:00Z",
    "status": "active"
  }
}
```

### Unblock IP from Incident
```http
DELETE /incidents/{incident_id}/unblock-ip
```
**Response:**
```json
{
  "success": true,
  "message": "Successfully unblocked IP 192.168.1.100"
}
```

### List All Blocked IPs
```http
GET /blocklist?status=active&limit=100
```

### Manually Block Any IP
```http
POST /blocklist
Content-Type: application/json

{
  "ip_address": "10.0.0.1",
  "reason": "manual",
  "duration_hours": 48,
  "notes": "Suspicious activity"
}
```

### Manually Unblock Any IP
```http
DELETE /blocklist/{ip_address}
```

### Export Blocklist for Firewall
```http
GET /blocklist/export?format=plain|nginx|iptables|json
```

---

## Dual Reports API (Executive + Engineer)

### Get Both Report Types
Use the integration module to generate dual reports:

```python
from app.integration import generate_dual_report, build_dual_report_prompt

# Build prompt for LLM
prompt = build_dual_report_prompt(incident_dict, events_list)

# Generate reports
dual = generate_dual_report(incident_dict, events_list, llm_response)

# Access reports
executive = dual.executive.to_dict()  # For non-technical users
engineer = dual.engineer.to_dict()    # For SOC analysts
```

**Executive Report Structure:**
```json
{
  "incident_id": 1,
  "severity": "Medium",
  "risk_level": "Moderate",
  "what_happened": "Plain English explanation...",
  "business_impact": "How this affects the organization...",
  "threat_contained": true,
  "key_findings": ["Finding 1", "Finding 2"],
  "recommended_decisions": ["Decision 1", "Decision 2"]
}
```

**Engineer Report Structure:**
```json
{
  "incident_id": 1,
  "severity": "Medium",
  "confidence_score": 0.85,
  "summary": "Technical summary...",
  "techniques": ["T1595: Active Scanning"],
  "kill_chain_phase": "Reconnaissance",
  "attacker_sophistication": "Medium",
  "event_count": 50,
  "time_window_minutes": 30.0,
  "request_rate_per_minute": 1.67,
  "source_ip": "192.168.1.100",
  "user_agents": ["python-requests/2.28.0"],
  "targeted_endpoints": ["/v1/projects", "/v1/secrets"],
  "behavioral_indicators": ["Endpoint enumeration", "Automated timing"],
  "recommended_actions": ["Block IP", "Rotate credentials"],
  "ioc_list": ["IP: 192.168.1.100"]
}
```

---

## Frontend Component Flow

### Incident Report Page
```
1. Load incident: GET /incidents/{id}
2. Load events: GET /incidents/{id}/events
3. Check block status: GET /incidents/{id}/block-status
4. Load AI report: GET /incidents/{id}/ai-report (or POST /analyze if none)

5. Display:
   - Toggle: "Executive View" | "Technical View"
   - Button: "Block IP" or "Unblock IP" (based on status)
   - Export options: PDF, JSON
```

### Block/Unblock Button Logic
```typescript
// On page load
const { is_blocked } = await fetch(`/incidents/${id}/block-status`).then(r => r.json());

// Button click handler
async function toggleBlock() {
  if (is_blocked) {
    await fetch(`/incidents/${id}/unblock-ip`, { method: 'DELETE' });
  } else {
    await fetch(`/incidents/${id}/block-ip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ duration_hours: 24 })
    });
  }
  // Refresh status
}
```

---

## Testing Commands

```bash
# Start server
uvicorn app.main:app --reload

# Test block IP
curl -X POST http://localhost:8000/incidents/1/block-ip \
  -H "Content-Type: application/json" \
  -d '{"duration_hours": 24}'

# Check status
curl http://localhost:8000/incidents/1/block-status

# Unblock IP
curl -X DELETE http://localhost:8000/incidents/1/unblock-ip

# List blocklist
curl http://localhost:8000/blocklist
```
