"""
Telemetry capture module for API instrumentation.

Captures request/response metadata for analysis and SOC reporting.
All data structures are designed to be JSON-serializable.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class RequestTelemetry:
    """
    Captured telemetry for a single API request.

    Attributes:
        request_id: Unique identifier for this request
        timestamp: ISO-8601 timestamp when request was received
        source_ip: Client IP address
        user_agent: User-Agent header value
        method: HTTP method (GET, POST, etc.)
        path: Request path (e.g., /v1/charges)
        query_params: Query string parameters (redacted values)
        headers: Request headers (sensitive values redacted)
        body_size: Size of request body in bytes
        body_hash: SHA-256 hash of request body (for deduplication)
        api_key_prefix: First 8 chars of API key (for identification)
        api_key_hash: SHA-256 hash of full API key
    """
    request_id: str
    timestamp: str
    source_ip: str
    user_agent: Optional[str]
    method: str
    path: str
    query_params: dict[str, str]
    headers: dict[str, str]
    body_size: int
    body_hash: Optional[str]
    api_key_prefix: Optional[str]
    api_key_hash: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "method": self.method,
            "path": self.path,
            "query_params": self.query_params,
            "headers": self.headers,
            "body_size": self.body_size,
            "body_hash": self.body_hash,
            "api_key_prefix": self.api_key_prefix,
            "api_key_hash": self.api_key_hash,
        }


@dataclass
class ResponseTelemetry:
    """
    Captured telemetry for an API response.

    Attributes:
        request_id: Matches the corresponding RequestTelemetry
        status_code: HTTP status code
        latency_ms: Time to receive response in milliseconds
        body_size: Size of response body in bytes
        error_type: Extracted error type if status >= 400
        error_message: Extracted error message (truncated)
        is_auth_error: True if 401/403 response
        is_rate_limited: True if 429 response
    """
    request_id: str
    status_code: int
    latency_ms: float
    body_size: int
    error_type: Optional[str]
    error_message: Optional[str]
    is_auth_error: bool
    is_rate_limited: bool

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "request_id": self.request_id,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "body_size": self.body_size,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "is_auth_error": self.is_auth_error,
            "is_rate_limited": self.is_rate_limited,
        }


@dataclass
class TelemetryRecord:
    """
    Complete telemetry record combining request and response data.

    This is the primary unit of data for behavior analysis.
    """
    request: RequestTelemetry
    response: ResponseTelemetry
    target_api: str  # e.g., "stripe", "openai", "github"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "target_api": self.target_api,
        }


# =============================================================================
# TELEMETRY CAPTURE FUNCTIONS
# =============================================================================

# Headers that should have their values redacted
SENSITIVE_HEADERS = {
    "authorization",
    "x-api-key",
    "api-key",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "x-access-token",
}

# Headers to completely exclude from telemetry
EXCLUDED_HEADERS = {
    "proxy-authorization",
    "www-authenticate",
}


def generate_request_id() -> str:
    """Generate a unique request ID using timestamp and random component."""
    import uuid
    ts = int(time.time() * 1000)
    rand = uuid.uuid4().hex[:8]
    return f"req_{ts}_{rand}"


def utc_now_iso() -> str:
    """Get current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def hash_value(value: str) -> str:
    """Compute SHA-256 hash of a string value."""
    return hashlib.sha256(value.encode()).hexdigest()


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Redact sensitive header values while preserving keys.

    Args:
        headers: Original headers dict

    Returns:
        Headers dict with sensitive values replaced by "[REDACTED]"
    """
    redacted = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in EXCLUDED_HEADERS:
            continue
        if key_lower in SENSITIVE_HEADERS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def extract_api_key(headers: dict[str, str]) -> tuple[Optional[str], Optional[str]]:
    """
    Extract API key prefix and hash from headers.

    Looks for common API key header patterns:
    - Authorization: Bearer <key>
    - X-API-Key: <key>
    - Api-Key: <key>

    Returns:
        Tuple of (key_prefix, key_hash) or (None, None) if not found
    """
    # Check Authorization header
    auth = headers.get("Authorization") or headers.get("authorization")
    if auth:
        parts = auth.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            key = parts[1]
            return key[:8] if len(key) >= 8 else key, hash_value(key)

    # Check X-API-Key
    for header_name in ["X-API-Key", "x-api-key", "Api-Key", "api-key"]:
        if header_name in headers:
            key = headers[header_name]
            return key[:8] if len(key) >= 8 else key, hash_value(key)

    return None, None


def redact_query_params(params: dict[str, str]) -> dict[str, str]:
    """
    Redact potentially sensitive query parameters.

    Preserves parameter names but redacts values for sensitive keys.
    """
    sensitive_params = {"key", "api_key", "apikey", "token", "secret", "password"}
    redacted = {}
    for key, value in params.items():
        if key.lower() in sensitive_params:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def capture_request(
    request_id: str,
    source_ip: str,
    method: str,
    path: str,
    headers: dict[str, str],
    query_params: Optional[dict[str, str]] = None,
    body: Optional[bytes] = None,
) -> RequestTelemetry:
    """
    Capture telemetry from an incoming request.

    Args:
        request_id: Unique request identifier
        source_ip: Client IP address
        method: HTTP method
        path: Request path
        headers: Request headers
        query_params: URL query parameters
        body: Request body bytes

    Returns:
        RequestTelemetry object with captured data
    """
    key_prefix, key_hash = extract_api_key(headers)

    return RequestTelemetry(
        request_id=request_id,
        timestamp=utc_now_iso(),
        source_ip=source_ip,
        user_agent=headers.get("User-Agent") or headers.get("user-agent"),
        method=method.upper(),
        path=path,
        query_params=redact_query_params(query_params or {}),
        headers=redact_headers(headers),
        body_size=len(body) if body else 0,
        body_hash=hash_value(body.decode("utf-8", errors="replace")) if body else None,
        api_key_prefix=key_prefix,
        api_key_hash=key_hash,
    )


def extract_error_info(status_code: int, body: bytes) -> tuple[Optional[str], Optional[str]]:
    """
    Extract error type and message from response body.

    Handles common API error formats (JSON with "error" key).

    Returns:
        Tuple of (error_type, error_message) or (None, None)
    """
    if status_code < 400:
        return None, None

    try:
        import json
        data = json.loads(body.decode("utf-8"))

        # Handle {"error": {"type": "...", "message": "..."}} format
        if isinstance(data.get("error"), dict):
            error = data["error"]
            return error.get("type"), _truncate(error.get("message"), 200)

        # Handle {"error": "message"} format
        if isinstance(data.get("error"), str):
            return None, _truncate(data["error"], 200)

        # Handle {"message": "..."} format
        if "message" in data:
            return data.get("code"), _truncate(data["message"], 200)

    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    return None, None


def _truncate(s: Optional[str], max_len: int) -> Optional[str]:
    """Truncate string to max length."""
    if s is None:
        return None
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


def capture_response(
    request_id: str,
    status_code: int,
    latency_ms: float,
    body: Optional[bytes] = None,
) -> ResponseTelemetry:
    """
    Capture telemetry from an API response.

    Args:
        request_id: Matches the corresponding request
        status_code: HTTP status code
        latency_ms: Request latency in milliseconds
        body: Response body bytes

    Returns:
        ResponseTelemetry object with captured data
    """
    error_type, error_message = extract_error_info(status_code, body or b"")

    return ResponseTelemetry(
        request_id=request_id,
        status_code=status_code,
        latency_ms=round(latency_ms, 2),
        body_size=len(body) if body else 0,
        error_type=error_type,
        error_message=error_message,
        is_auth_error=status_code in (401, 403),
        is_rate_limited=status_code == 429,
    )


def create_telemetry_record(
    request: RequestTelemetry,
    response: ResponseTelemetry,
    target_api: str,
) -> TelemetryRecord:
    """
    Create a complete telemetry record from request and response.

    Args:
        request: Captured request telemetry
        response: Captured response telemetry
        target_api: Identifier for the target API (e.g., "stripe")

    Returns:
        Complete TelemetryRecord
    """
    return TelemetryRecord(
        request=request,
        response=response,
        target_api=target_api,
    )
