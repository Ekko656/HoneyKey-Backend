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
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.integration.enhanced_prompt import build_enhanced_prompt_from_rows
from app.features.attacker_responses import (
    get_fake_project_list,
    get_fake_secret_list,
    generate_request_id,
    utc_now_iso,
)

from app.features.attacker_responses import (
    generate_request_id,
    get_fake_project_list,
    get_fake_secret_list,
    utc_now_iso,
)
from app.features.key_metadata import HONEYPOT_KEYS
from app.features.ip_blocking import (
    init_blocklist_table,
    add_ip_block,
    remove_ip_block,
    is_ip_blocked,
    get_blocked_ips,
    block_ip_from_incident,
    export_blocklist,
    BlockReason,
    BlockStatus,
)
from app.integration.enhanced_prompt import build_enhanced_prompt_from_rows

DEFAULT_DB_PATH = "./data/honeykey.db"
DEFAULT_INCIDENT_WINDOW_MINUTES = 30
DEFAULT_GEMINI_MODEL = "gemini-flash-latest"


class Settings(BaseModel):
    database_path: str = DEFAULT_DB_PATH
    honeypot_key: str = ""
    incident_window_minutes: int = DEFAULT_INCIDENT_WINDOW_MINUTES
    cors_origins: List[str] = []
    gemini_api_key: Optional[str] = None
    gemini_model: str = DEFAULT_GEMINI_MODEL


def load_settings() -> Settings:
    load_dotenv()
    # Default CORS origins for local development and production
    default_origins = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "https://honeykey.tech",
        "https://www.honeykey.tech",
    ]
    env_origins = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    # Combine default and env origins, remove duplicates
    cors_origins = list(set(default_origins + env_origins))
    settings = Settings(
        database_path=os.getenv("DATABASE_PATH", DEFAULT_DB_PATH),
        honeypot_key=os.getenv("HONEYPOT_KEY", ""),
        incident_window_minutes=int(
            os.getenv("INCIDENT_WINDOW_MINUTES", str(DEFAULT_INCIDENT_WINDOW_MINUTES))
        ),
        cors_origins=cors_origins,
        gemini_api_key=os.getenv("GEMINI_API_KEY"),
        gemini_model=os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
    )
    print(f"DEBUG: Loaded Key: {(settings.gemini_api_key or '')[:10]}... Model: {settings.gemini_model}")
    print(f"DEBUG: CORS Origins: {cors_origins}")
    return settings


settings = load_settings()

app = FastAPI(title="HoneyKey Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or [],
    allow_origin_regex=r"https://.*\.vercel\.app",  # Allow Vercel preview deployments
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
        # Initialize IP blocklist table (enhanced version)
        init_blocklist_table(conn)


@app.middleware("http")
async def block_ip_middleware(request: Request, call_next):
    """Block requests from IPs in the blocklist. Returns ambiguous error."""
    client_ip = request.client.host if request.client else None
    if client_ip:
        with get_db() as conn:
            if is_ip_blocked(conn, client_ip):
                # Ambiguous error - looks like a normal auth failure
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized"}
                )
    return await call_next(request)


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
    confidence_score: float
    summary: str
    evidence: List[str]
    techniques: List[str]
    recommended_actions: List[str]
    report: Optional[str] = None
    techniques: Optional[List[str]] = None
    confidence_score: Optional[float] = None


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
    required_keys = {
        "incident_id",
        "severity",
        "summary",
        "evidence",
        "recommended_actions",
    }
    if not required_keys.issubset(set(payload.keys())):
        missing = required_keys - set(payload.keys())
        raise ValueError(f"Missing required JSON keys in report: {missing}")
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
    # Optional fields with defaults
    if "confidence_score" not in payload:
        payload["confidence_score"] = 0.8
    if "techniques" not in payload:
        payload["techniques"] = []
    if "report" in payload and payload["report"] is not None:
        if not isinstance(payload["report"], str):
            raise ValueError("report must be string")
    return AIReportResponse(**payload)


def generate_gemini_report(prompt: str, api_key: str, model: str) -> str:
    from google import genai

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(model=model, contents=prompt)
    return response.text or ""


def normalize_recommended_actions(actions: List[str]) -> List[str]:
    normalized = []
    for action in actions:
        if action.startswith("HoneyKey:") or action.startswith("You:"):
            normalized.append(action)
        elif action.startswith("User:"):
            normalized.append(action.replace("User:", "You:", 1))
        else:
            normalized.append(f"You: {action}")
    return normalized


def build_report_fallback(incident: sqlite3.Row, events: list[sqlite3.Row]) -> str:
    event_count = len(events)
    first_ts = events[-1]["ts"] if events else "unknown"
    last_ts = events[0]["ts"] if events else "unknown"
    paths = sorted({row["path"] for row in events if row["path"]})[:5]
    user_agents = sorted({row["user_agent"] for row in events if row["user_agent"]})[:3]
    return (
        "Executive Summary: HoneyKey detected use of a honeypot credential tied to this "
        f"incident. Activity was observed between {first_ts} and {last_ts} with "
        f"{event_count} related events. Impact appears contained to the honeypot "
        "environment; HoneyKey did not change external systems. Risk is moderate because "
        "leaked credentials can signal broader exposure. Next steps require organizational "
        "review of credential hygiene and access policies.\n\n"
        "Technical Details: Telemetry shows honeypot key usage with "
        f"{event_count} events from a single source. Observed window: {first_ts} → {last_ts}. "
        f"Affected endpoints: {', '.join(paths) if paths else 'unknown'}. "
        f"User-Agent samples: {', '.join(user_agents) if user_agents else 'unknown'}. "
        "Likely techniques include credential abuse against protected endpoints; validate "
        "authorization boundaries and audit related systems outside HoneyKey."
    )


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
        "Return ONLY valid JSON (no markdown, no code fences, no extra text). "
        "Required keys: incident_id (int), severity (string), summary (string), "
        "evidence (list of strings), recommended_actions (list of strings). "
        "Additive keys allowed: report (string), techniques (list of strings), "
        "confidence_score (number). "
        "The report must be a single layered narrative with two sections. "
        "Start with 'Executive Summary:' in plain English (no jargon or raw metrics) "
        "explaining what happened, impact, whether activity stayed in the honeypot "
        "environment, why it matters, and what decision-makers should know. "
        "Then include 'Technical Details:' with concrete evidence and metrics (event counts, "
        "timing window, burstiness, enumeration patterns, user-agent observations), "
        "explain attacker behaviors in human-readable terms before optional technique IDs, "
        "and provide a short timeline. "
        "Clearly distinguish HoneyKey capabilities (telemetry, grouping, analysis, reports) "
        "from user actions (blocking IPs, revoking creds, firewall/WAF changes, external SIEMs). "
        "Never claim HoneyKey performed external actions. "
        "Each recommended_actions item must be prefixed with 'HoneyKey:' or 'You:'. "
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

    # Check against all honeypot keys (from registry + env)
    honeypot_key_used = False
    key_id = None
    env_key = get_settings().honeypot_key

    if token:
        # Check env key first
        if env_key and token == env_key:
            honeypot_key_used = True
            key_id = "honeypot"
        # Check all registered honeypot keys
        elif token in HONEYPOT_KEYS:
            honeypot_key_used = True
            key_id = token  # Use the actual key as ID for tracking

    request.state.honeypot_key_used = honeypot_key_used
    request.state.key_id = key_id

    client_ip = request.client.host if request.client else None

    response = await call_next(request)
    response.headers["x-correlation-id"] = correlation_id

    now_iso = utc_now().isoformat()
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
async def trap_projects(request: Request) -> Any:
    # If the honeypot key was used, provide realistic fake data to keep them hooked
    # Middleware already validated the key if request.state.auth_present is True
    if getattr(request.state, "honeypot_key_used", False):
        return {
            "data": get_fake_project_list(),
            "meta": {
                "total": 4,
                "request_id": generate_request_id(),
                "timestamp": utc_now_iso(),
            }
        }
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/v1/secrets")
async def trap_secrets(request: Request) -> Any:
    if getattr(request.state, "honeypot_key_used", False):
         return {
            "data": get_fake_secret_list(),
            "meta": {
                "total": 5,
                "request_id": generate_request_id(),
                "timestamp": utc_now_iso(),
            }
        }
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/v1/auth/verify")
async def trap_verify(request: Request) -> Any:
    if getattr(request.state, "honeypot_key_used", False):
        return {
            "valid": True,
            "scopes": ["read", "write", "admin"],
            "expires_in": 3600,
            "meta": {"request_id": generate_request_id()}
        }
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

    # Use the actual key_id from the incident (which is the full key value for registered keys)
    incident_key = incident["key_id"]
    prompt = build_enhanced_prompt_from_rows(incident, events, key_value=incident_key)
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    response_text = ""
    provider = "gemini"
    try:
        try:
            response_text = generate_gemini_report(
                prompt,
                settings_value.gemini_api_key,
                settings_value.gemini_model,
            )
            payload = extract_json_payload(response_text)
            report = validate_report_payload(payload, incident_id)
            report = report.model_copy(
                update={
                    "recommended_actions": normalize_recommended_actions(
                        report.recommended_actions
                    )
                }
            )
        except Exception as ai_exc:
            # Fallback to deterministic report if AI fails (Rate limits, etc)
            print(f"WARNING: AI Generation failed ({ai_exc}). Using fallback report.")
            response_text = f"FALLBACK: {str(ai_exc)}"
            fallback_text = build_report_fallback(incident, events)
            report = AIReportResponse(
                incident_id=incident_id,
                severity="Medium",
                confidence_score=1.0,
                summary="AI generation unavailable (Rate Limit/Error). Showing telemetry summary.",
                evidence=["Deterministic fallback triggered"],
                techniques=["T1000: Fallback Technique"],
                recommended_actions=["Check API Quota"],
                report=fallback_text
            )

        if not report.report:
            report_text = build_report_fallback(incident, events)
            report = report.model_copy(update={"report": report_text})

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
        # If even fallback fails, then raise error
        raise HTTPException(
            status_code=502,
            detail=(
                f"Reporting failed: {str(exc)}. "
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


# =============================================================================
# IP BLOCKING ENDPOINTS
# =============================================================================

class BlockIPRequestModel(BaseModel):
    """Request model for blocking an IP."""
    ip_address: Optional[str] = None  # If None, use incident's source_ip
    reason: str = "honeypot_abuse"
    duration_hours: Optional[int] = 24  # None = permanent
    notes: str = ""


class BlockIPResponseModel(BaseModel):
    """Response model for IP block operations."""
    success: bool
    message: str
    block: Optional[dict] = None


class BlocklistResponseModel(BaseModel):
    """Response model for blocklist queries."""
    total: int
    blocks: List[dict]


@app.post("/incidents/{incident_id}/block-ip", response_model=BlockIPResponseModel)
async def block_incident_ip(incident_id: int, request: BlockIPRequestModel) -> BlockIPResponseModel:
    """
    Block the source IP from an incident.

    This endpoint is called from the frontend when a user clicks
    "Block IP" on an incident report.
    """
    with get_db() as conn:
        result = block_ip_from_incident(
            conn,
            incident_id=incident_id,
            blocked_by="analyst",
            duration_hours=request.duration_hours,
            notes=request.notes,
        )
        return BlockIPResponseModel(
            success=result.success,
            message=result.message,
            block=result.block.to_dict() if result.block else None,
        )


@app.delete("/incidents/{incident_id}/unblock-ip", response_model=BlockIPResponseModel)
async def unblock_incident_ip(incident_id: int) -> BlockIPResponseModel:
    """
    Unblock the source IP from an incident.

    Called when user clicks "Unblock IP" on an incident report.
    """
    with get_db() as conn:
        incident = conn.execute(
            "SELECT source_ip FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        if not incident:
            return BlockIPResponseModel(success=False, message=f"Incident {incident_id} not found")

        source_ip = incident["source_ip"]
        success = remove_ip_block(conn, ip_address=source_ip, removed_by="analyst")

        if success:
            return BlockIPResponseModel(success=True, message=f"Successfully unblocked IP {source_ip}")
        return BlockIPResponseModel(success=False, message=f"IP {source_ip} is not currently blocked")


@app.get("/incidents/{incident_id}/block-status")
async def get_incident_block_status(incident_id: int) -> dict:
    """Check if the incident's source IP is currently blocked."""
    with get_db() as conn:
        incident = conn.execute(
            "SELECT source_ip FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        source_ip = incident["source_ip"]
        blocked = is_ip_blocked(conn, source_ip)

        return {"incident_id": incident_id, "source_ip": source_ip, "is_blocked": blocked}


@app.post("/blocklist", response_model=BlockIPResponseModel)
async def add_to_blocklist(request: BlockIPRequestModel) -> BlockIPResponseModel:
    """
    Manually add an IP to the blocklist.

    Used for blocking IPs that aren't associated with a specific incident.
    """
    if not request.ip_address:
        raise HTTPException(status_code=400, detail="ip_address is required")

    try:
        reason = BlockReason(request.reason)
    except ValueError:
        reason = BlockReason.MANUAL

    with get_db() as conn:
        try:
            block = add_ip_block(
                conn,
                ip_address=request.ip_address,
                reason=reason,
                blocked_by="analyst",
                duration_hours=request.duration_hours,
                notes=request.notes,
            )
            return BlockIPResponseModel(
                success=True,
                message=f"Successfully blocked IP {request.ip_address}",
                block=block.to_dict(),
            )
        except ValueError as e:
            return BlockIPResponseModel(
                success=False,
                message=str(e),
            )


@app.delete("/blocklist/{ip_address}", response_model=BlockIPResponseModel)
async def remove_from_blocklist(ip_address: str) -> BlockIPResponseModel:
    """Remove an IP from the blocklist."""
    with get_db() as conn:
        success = remove_ip_block(conn, ip_address=ip_address, removed_by="analyst")
        if success:
            return BlockIPResponseModel(
                success=True,
                message=f"Successfully unblocked IP {ip_address}",
            )
        return BlockIPResponseModel(
            success=False,
            message=f"IP {ip_address} is not currently blocked",
        )


@app.get("/blocklist", response_model=BlocklistResponseModel)
async def list_blocklist(
    status: Optional[str] = "active",
    incident_id: Optional[int] = None,
    limit: int = 100,
) -> BlocklistResponseModel:
    """
    Get the current IP blocklist.

    Query params:
        status: Filter by status ('active', 'expired', 'removed', or None for all)
        incident_id: Filter by incident
        limit: Max results (default 100)
    """
    try:
        block_status = BlockStatus(status) if status else None
    except ValueError:
        block_status = BlockStatus.ACTIVE

    with get_db() as conn:
        blocks = get_blocked_ips(conn, status=block_status, incident_id=incident_id, limit=limit)
        return BlocklistResponseModel(
            total=len(blocks),
            blocks=[b.to_dict() for b in blocks],
        )


@app.get("/blocklist/check/{ip_address}")
async def check_ip_blocked(ip_address: str) -> dict:
    """Check if an IP is currently blocked."""
    with get_db() as conn:
        blocked = is_ip_blocked(conn, ip_address)
        return {
            "ip_address": ip_address,
            "is_blocked": blocked,
        }


@app.get("/blocklist/export")
async def export_blocklist_endpoint(format: str = "plain") -> Any:
    """
    Export the blocklist in various formats for firewall/WAF integration.

    Formats:
        plain: One IP per line
        nginx: nginx deny directives
        iptables: iptables DROP commands
        json: JSON array of block objects
    """
    with get_db() as conn:
        try:
            content = export_blocklist(conn, format=format)
            if format == "json":
                return JSONResponse(content=json.loads(content))
            return JSONResponse(
                content={"format": format, "content": content},
                media_type="application/json",
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# FRONTEND API COMPATIBILITY ROUTES (/api/*)
# These routes provide a clean /api/* prefix for frontend integration
# =============================================================================

class DashboardStats(BaseModel):
    """Dashboard statistics for the frontend."""
    active_incidents: int
    total_incidents: int
    honeypot_keys_active: int
    blocked_ips: int
    last_incident_time: Optional[str]


class ReportListItem(BaseModel):
    """Report list item for frontend."""
    id: str
    incident_id: int
    title: str
    generated_date: str
    incident_date: str
    severity: str
    status: str
    event_count: int
    source_ip: str
    summary: str


@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def api_dashboard_stats() -> DashboardStats:
    """Get dashboard statistics for the frontend."""
    with get_db() as conn:
        # Count total incidents
        total = conn.execute("SELECT COUNT(*) as cnt FROM incidents").fetchone()["cnt"]

        # Get most recent incident
        last_incident = conn.execute(
            "SELECT last_seen FROM incidents ORDER BY last_seen DESC LIMIT 1"
        ).fetchone()

        # Count active blocked IPs
        blocked = conn.execute(
            "SELECT COUNT(*) as cnt FROM ip_blocklist WHERE status = 'active'"
        ).fetchone()["cnt"]

        # Count incidents in last 24 hours as "active"
        yesterday = (utc_now() - timedelta(hours=24)).isoformat()
        active = conn.execute(
            "SELECT COUNT(*) as cnt FROM incidents WHERE last_seen >= ?",
            (yesterday,)
        ).fetchone()["cnt"]

        return DashboardStats(
            active_incidents=active,
            total_incidents=total,
            honeypot_keys_active=12,  # Configurable in production
            blocked_ips=blocked,
            last_incident_time=last_incident["last_seen"] if last_incident else None,
        )


@app.get("/api/reports", response_model=List[ReportListItem])
async def api_list_reports() -> List[ReportListItem]:
    """
    List all incidents as reports for the frontend.
    Maps incidents to the report format expected by the frontend.
    """
    with get_db() as conn:
        incidents = conn.execute(
            """
            SELECT i.id, i.key_id, i.source_ip, i.first_seen, i.last_seen, i.event_count,
                   ar.report_json, ar.created_at as report_date
            FROM incidents i
            LEFT JOIN (
                SELECT incident_id, report_json, created_at,
                       ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY created_at DESC) as rn
                FROM ai_reports
                WHERE parse_ok = 1
            ) ar ON ar.incident_id = i.id AND ar.rn = 1
            ORDER BY i.last_seen DESC
            """
        ).fetchall()

        def get_attack_title(key_id: str, source_ip: str) -> str:
            """Generate descriptive title based on the honeypot key used."""
            if key_id.startswith("acme_docker"):
                return f"GitHub Credential Leak - {source_ip}"
            elif key_id.startswith("acme_client"):
                return f"Source Map Extraction Attack - {source_ip}"
            elif key_id.startswith("acme_debug"):
                return f"Debug Log Compromise - {source_ip}"
            else:
                return f"API Key Abuse Detected - {source_ip}"

        reports = []
        for inc in incidents:
            # Parse AI report if available
            severity = "medium"
            summary = f"Honeypot key usage detected from {inc['source_ip']}"
            status = "new"

            if inc["report_json"]:
                try:
                    report_data = json.loads(inc["report_json"])
                    severity = report_data.get("severity", "medium").lower()
                    summary = report_data.get("summary", summary)
                    status = "reviewed"
                except:
                    pass

            reports.append(ReportListItem(
                id=f"INC-{inc['id']:04d}",
                incident_id=inc["id"],
                title=get_attack_title(inc["key_id"], inc["source_ip"]),
                generated_date=inc["report_date"] or inc["last_seen"],
                incident_date=inc["first_seen"],
                severity=severity,
                status=status,
                event_count=inc["event_count"],
                source_ip=inc["source_ip"],
                summary=summary,
            ))

        return reports


@app.get("/api/reports/{report_id}")
async def api_get_report(report_id: str) -> dict:
    """
    Get a specific report by ID (format: INC-XXXX).
    Returns full report details including AI analysis.
    """
    # Parse incident ID from report ID
    try:
        incident_id = int(report_id.replace("INC-", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    with get_db() as conn:
        # Get incident
        incident = conn.execute(
            """
            SELECT id, key_id, source_ip, first_seen, last_seen, event_count
            FROM incidents WHERE id = ?
            """,
            (incident_id,)
        ).fetchone()

        if not incident:
            raise HTTPException(status_code=404, detail="Report not found")

        # Get AI report if available
        ai_report = conn.execute(
            """
            SELECT report_json, created_at, parse_ok
            FROM ai_reports
            WHERE incident_id = ? AND parse_ok = 1
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (incident_id,)
        ).fetchone()

        # Get events
        events = conn.execute(
            """
            SELECT id, ts, ip, method, path, user_agent, correlation_id,
                   auth_present, honeypot_key_used
            FROM events
            WHERE incident_id = ?
            ORDER BY ts DESC
            LIMIT 50
            """,
            (incident_id,)
        ).fetchall()

        # Get block status
        blocked = is_ip_blocked(conn, incident["source_ip"])

        # Build response
        report_data = None
        if ai_report and ai_report["report_json"]:
            try:
                report_data = json.loads(ai_report["report_json"])
            except:
                pass

        return {
            "id": f"INC-{incident['id']:04d}",
            "incident_id": incident["id"],
            "source_ip": incident["source_ip"],
            "key_id": incident["key_id"],
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
            "event_count": incident["event_count"],
            "is_blocked": blocked,
            "has_ai_report": report_data is not None,
            "ai_report": report_data,
            "events": [
                {
                    "id": e["id"],
                    "timestamp": e["ts"],
                    "ip": e["ip"],
                    "method": e["method"],
                    "path": e["path"],
                    "user_agent": e["user_agent"],
                    "correlation_id": e["correlation_id"],
                }
                for e in events
            ],
        }


@app.get("/api/reports/{report_id}/events")
async def api_get_report_events(report_id: str, limit: int = 50) -> List[dict]:
    """Get events for a specific report."""
    try:
        incident_id = int(report_id.replace("INC-", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    with get_db() as conn:
        events = conn.execute(
            """
            SELECT id, ts, ip, method, path, user_agent, correlation_id,
                   auth_present, honeypot_key_used
            FROM events
            WHERE incident_id = ?
            ORDER BY ts DESC
            LIMIT ?
            """,
            (incident_id, limit),
        ).fetchall()

        return [
            {
                "id": e["id"],
                "timestamp": e["ts"],
                "ip": e["ip"],
                "method": e["method"],
                "path": e["path"],
                "user_agent": e["user_agent"],
                "correlation_id": e["correlation_id"],
                "auth_present": bool(e["auth_present"]),
                "honeypot_key_used": bool(e["honeypot_key_used"]),
            }
            for e in events
        ]


@app.post("/api/reports/{report_id}/analyze")
async def api_analyze_report(report_id: str, request: Request) -> dict:
    """
    Trigger AI analysis for a report.
    This is an alias to the existing /incidents/{id}/analyze endpoint.
    """
    try:
        incident_id = int(report_id.replace("INC-", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    # Use existing analyze function
    result = await analyze_incident(incident_id, request)
    return result.model_dump()


@app.post("/api/reports/{report_id}/block-ip")
async def api_block_report_ip(report_id: str, request: BlockIPRequestModel) -> BlockIPResponseModel:
    """Block the IP associated with a report."""
    try:
        incident_id = int(report_id.replace("INC-", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    return await block_incident_ip(incident_id, request)


@app.delete("/api/reports/{report_id}/unblock-ip")
async def api_unblock_report_ip(report_id: str) -> BlockIPResponseModel:
    """Unblock the IP associated with a report."""
    try:
        incident_id = int(report_id.replace("INC-", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    return await unblock_incident_ip(incident_id)
