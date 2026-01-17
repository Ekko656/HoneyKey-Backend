# HoneyKey Backend

Minimal FastAPI backend for the HoneyKey hackathon demo. It logs suspicious traffic and groups honeypot key usage into incidents.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

The service will auto-create the SQLite database at `./data/honeykey.db`.

## Endpoints

### Health
- `GET /health` → `{ "status": "ok" }`

### Trap endpoints (always fail)
- `GET /v1/projects`
- `GET /v1/secrets`
- `POST /v1/auth/verify`

### Analyst endpoints
- `GET /incidents`
- `GET /incidents/{id}`
- `GET /incidents/{id}/events`
- `POST /incidents/{id}/analyze`
- `GET /incidents/{id}/ai-report`

## Configuration

Set values via environment variables or `.env`:

```
DATABASE_PATH=./data/honeykey.db
HONEYPOT_KEY=acme_live_f93k2jf92jf0s9df
INCIDENT_WINDOW_MINUTES=30
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-pro
```

## Testing

```bash
pytest
```
