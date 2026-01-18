from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Generator, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DEFAULT_DB_PATH = "./data/honeykey.db"
DEFAULT_INCIDENT_WINDOW_MINUTES = 30
DEFAULT_GEMINI_MODEL = "gemini-1.5-pro"


class Settings(BaseModel):
    database_path: str = DEFAULT_DB_PATH
    honeypot_key: str = ""
    incident_window_minutes: int = DEFAULT_INCIDENT_WINDOW_MINUTES
    cors_origins: List[str] = []
    gemini_api_key: Optional[str] = None
    gemini_model: str = DEFAULT_GEMINI_MODEL


def load_settings() -> Settings:
    load_dotenv()
    cors_origins = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    return Settings(
        database_path=os.getenv("DATABASE_PATH", DEFAULT_DB_PATH),
        honeypot_key=os.getenv("HONEYPOT_KEY", ""),
        incident_window_minutes=int(
            os.getenv("INCIDENT_WINDOW_MINUTES", str(DEFAULT_INCIDENT_WINDOW_MINUTES))
        ),
        cors_origins=cors_origins,
        gemini_api_key=os.getenv("GEMINI_API_KEY"),
        gemini_model=os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
    )


settings = load_settings()

app = FastAPI(title="HoneyKey Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_settings() -> Settings:
    return getattr(app.state, "settings", settings)


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    database_path = get_settings().database_path
    os.makedirs(os.path.dirname(database_path), exist_ok=True)
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT,
                method TEXT,
                path TEXT,
                user_agent TEXT,
                correlation_id TEXT,
                auth_present INTEGER,
                honeypot_key_used INTEGER,
                incident_id INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                report_json TEXT,
                parse_ok INTEGER NOT NULL,
                error TEXT
            )
            """
        )


@app.on_event("startup")
def on_startup() -> None:
    app.state.settings = load_settings()
    init_db()


class Incident(BaseModel):
    id: int
    key_id: str
    source_ip: str
    first_seen: str
    last_seen: str
    event_count: int


class Event(BaseModel):
    id: int
    ts: str
    ip: Optional[str]
    method: Optional[str]
    path: Optional[str]
    user_agent: Optional[str]
    correlation_id: Optional[str]
    auth_present: bool
    honeypot_key_used: bool
    incident_id: Optional[int]


class HealthResponse(BaseModel):
    status: str


class AIReportResponse(BaseModel):
    incident_id: int
    severity: str
    summary: str
    evidence: List[str]
    recommended_actions: List[str]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def extract_json_payload(text: str) -> dict:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        cleaned = "\n".join(
            line for line in lines if not line.strip().startswith("```")
        ).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found")
    return json.loads(cleaned[start : end + 1])


def validate_report_payload(payload: dict, incident_id: int) -> AIReportResponse:
    expected_keys = {
        "incident_id",
        "severity",
        "summary",
        "evidence",
        "recommended_actions",
    }
    if set(payload.keys()) != expected_keys:
        raise ValueError("Unexpected JSON keys in report")
    if not isinstance(payload["incident_id"], int):
        raise ValueError("incident_id must be int")
    if payload["incident_id"] != incident_id:
        raise ValueError("incident_id does not match")
    if not isinstance(payload["severity"], str):
        raise ValueError("severity must be string")
    if not isinstance(payload["summary"], str):
        raise ValueError("summary must be string")
    if not isinstance(payload["evidence"], list) or not all(
        isinstance(item, str) for item in payload["evidence"]
    ):
        raise ValueError("evidence must be list of strings")
    if not isinstance(payload["recommended_actions"], list) or not all(
        isinstance(item, str) for item in payload["recommended_actions"]
    ):
        raise ValueError("recommended_actions must be list of strings")
    return AIReportResponse(**payload)


def generate_gemini_report(prompt: str, api_key: str, model: str) -> str:
    from google import genai

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(model=model, contents=prompt)
    return response.text or ""


def store_ai_report(
    conn: sqlite3.Connection,
    incident_id: int,
    provider: str,
    model: str,
    report_json: Optional[str],
    parse_ok: bool,
    error: Optional[str],
) -> None:
    conn.execute(
        """
        INSERT INTO ai_reports (
            incident_id, created_at, provider, model, report_json, parse_ok, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            utc_now().isoformat(),
            provider,
            model,
            report_json,
            int(parse_ok),
            error,
        ),
    )


def build_prompt(incident: sqlite3.Row, events: list[sqlite3.Row]) -> str:
    incident_payload = dict(incident)
    event_payloads = [
        {
            "ts": row["ts"],
            "ip": row["ip"],
            "method": row["method"],
            "path": row["path"],
            "user_agent": row["user_agent"],
            "correlation_id": row["correlation_id"],
            "auth_present": bool(row["auth_present"]),
            "honeypot_key_used": bool(row["honeypot_key_used"]),
        }
        for row in events
    ]
    return (
        "You are a SOC analyst. Summarize this incident for a report. "
        "Return ONLY valid JSON. No markdown. No code fences. "
        "Required keys: incident_id (int), severity (string), summary (string), "
        "evidence (list of strings), recommended_actions (list of strings). "
        f"Incident: {json.dumps(incident_payload)}. "
        f"Recent events: {json.dumps(event_payloads)}."
    )


def parse_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


def find_or_create_incident(conn: sqlite3.Connection, source_ip: str, key_id: str) -> int:
    window_start = utc_now() - timedelta(
        minutes=get_settings().incident_window_minutes
    )
    window_start_iso = window_start.isoformat()
    existing = conn.execute(
        """
        SELECT id, event_count
        FROM incidents
        WHERE source_ip = ?
          AND key_id = ?
          AND last_seen >= ?
        ORDER BY last_seen DESC
        LIMIT 1
        """,
        (source_ip, key_id, window_start_iso),
    ).fetchone()
    now_iso = utc_now().isoformat()
    if existing:
        conn.execute(
            """
            UPDATE incidents
            SET last_seen = ?, event_count = ?
            WHERE id = ?
            """,
            (now_iso, existing["event_count"] + 1, existing["id"]),
        )
        return int(existing["id"])

    cursor = conn.execute(
        """
        INSERT INTO incidents (key_id, source_ip, first_seen, last_seen, event_count)
        VALUES (?, ?, ?, ?, ?)
        """,
        (key_id, source_ip, now_iso, now_iso, 1),
    )
    return int(cursor.lastrowid)


@app.middleware("http")
async def logging_middleware(request: Request, call_next) -> Any:
    correlation_id = request.headers.get("x-correlation-id") or str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    auth_header = request.headers.get("authorization")
    auth_present = bool(auth_header)
    token = parse_bearer_token(auth_header)
    honeypot_key = get_settings().honeypot_key
    honeypot_key_used = bool(token and honeypot_key and token == honeypot_key)

    response = await call_next(request)
    response.headers["x-correlation-id"] = correlation_id

    now_iso = utc_now().isoformat()
    client_ip = request.client.host if request.client else None
    key_id = "honeypot" if honeypot_key_used else None
    with get_db() as conn:
        incident_id = None
        if honeypot_key_used and client_ip:
            incident_id = find_or_create_incident(conn, client_ip, key_id)

        conn.execute(
            """
            INSERT INTO events (
                ts, ip, method, path, user_agent,
                correlation_id, auth_present, honeypot_key_used, incident_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso,
                client_ip,
                request.method,
                request.url.path,
                request.headers.get("user-agent"),
                correlation_id,
                int(auth_present),
                int(honeypot_key_used),
                incident_id,
            ),
        )

    return response


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/v1/projects")
async def trap_projects() -> None:
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/v1/secrets")
async def trap_secrets() -> None:
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/v1/auth/verify")
async def trap_verify() -> None:
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/incidents", response_model=List[Incident])
async def list_incidents() -> List[Incident]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, key_id, source_ip, first_seen, last_seen, event_count
            FROM incidents
            ORDER BY last_seen DESC
            """
        ).fetchall()
    return [Incident(**dict(row)) for row in rows]


@app.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: int) -> Incident:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, key_id, source_ip, first_seen, last_seen, event_count
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return Incident(**dict(row))


@app.get("/incidents/{incident_id}/events", response_model=List[Event])
async def get_incident_events(incident_id: int) -> List[Event]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, ts, ip, method, path, user_agent, correlation_id,
                   auth_present, honeypot_key_used, incident_id
            FROM events
            WHERE incident_id = ?
            ORDER BY ts DESC
            """,
            (incident_id,),
        ).fetchall()
    return [
        Event(
            **{
                **dict(row),
                "auth_present": bool(row["auth_present"]),
                "honeypot_key_used": bool(row["honeypot_key_used"]),
            }
        )
        for row in rows
    ]


@app.post("/incidents/{incident_id}/analyze", response_model=AIReportResponse)
async def analyze_incident(incident_id: int, request: Request) -> AIReportResponse:
    settings_value = get_settings()
    if not settings_value.gemini_api_key:
        raise HTTPException(
            status_code=400,
            detail="GEMINI_API_KEY is required to analyze incidents.",
        )
    with get_db() as conn:
        incident = conn.execute(
            """
            SELECT id, key_id, source_ip, first_seen, last_seen, event_count
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        events = conn.execute(
            """
            SELECT ts, ip, method, path, user_agent, correlation_id,
                   auth_present, honeypot_key_used
            FROM events
            WHERE incident_id = ?
            ORDER BY ts DESC
            LIMIT 25
            """,
            (incident_id,),
        ).fetchall()

    prompt = build_prompt(incident, events)
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    response_text = ""
    provider = "gemini"
    try:
        response_text = generate_gemini_report(
            prompt,
            settings_value.gemini_api_key,
            settings_value.gemini_model,
        )
        payload = extract_json_payload(response_text)
        report = validate_report_payload(payload, incident_id)
    except Exception as exc:
        with get_db() as conn:
            store_ai_report(
                conn,
                incident_id,
                provider,
                settings_value.gemini_model,
                response_text or None,
                False,
                str(exc),
            )
        raise HTTPException(
            status_code=502,
            detail=(
                "Failed to parse AI report. "
                f"correlation_id={correlation_id}"
            ),
        ) from exc

    with get_db() as conn:
        store_ai_report(
            conn,
            incident_id,
            provider,
            settings_value.gemini_model,
            report.model_dump_json(),
            True,
            None,
        )
    return report


@app.get("/incidents/{incident_id}/ai-report", response_model=AIReportResponse)
async def get_ai_report(incident_id: int) -> AIReportResponse:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT report_json, parse_ok
            FROM ai_reports
            WHERE incident_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (incident_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="AI report not found")
    if not row["parse_ok"]:
        raise HTTPException(
            status_code=409, detail="Latest AI report failed to parse"
        )
    payload = json.loads(row["report_json"])
    return AIReportResponse(**payload)
