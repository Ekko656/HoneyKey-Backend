"""
Behavioral classification module for API request analysis.

Implements stateless scoring to classify requests as normal, suspicious, or malicious
based on observable request patterns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .telemetry import TelemetryRecord


class Classification(str, Enum):
    """Request behavior classification levels."""
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Signal(str, Enum):
    """
    Detectable behavioral signals.

    Each signal represents an observable pattern that may indicate
    malicious or suspicious activity.
    """
    # Enumeration patterns
    ENDPOINT_ENUMERATION = "endpoint_enumeration"
    PARAMETER_FUZZING = "parameter_fuzzing"
    VERSION_PROBING = "version_probing"

    # Authentication patterns
    AUTH_ERROR_PERSISTENCE = "auth_error_persistence"
    CREDENTIAL_STUFFING = "credential_stuffing"
    KEY_ROTATION_ATTEMPT = "key_rotation_attempt"

    # Rate patterns
    RAPID_RETRIES = "rapid_retries"
    BURST_REQUESTS = "burst_requests"
    SLOW_SCAN = "slow_scan"

    # Header anomalies
    NON_SDK_HEADERS = "non_sdk_headers"
    MISSING_USER_AGENT = "missing_user_agent"
    SPOOFED_USER_AGENT = "spoofed_user_agent"
    UNUSUAL_CONTENT_TYPE = "unusual_content_type"

    # Request anomalies
    OVERSIZED_PAYLOAD = "oversized_payload"
    MALFORMED_JSON = "malformed_json"
    INJECTION_ATTEMPT = "injection_attempt"

    # Response patterns
    ERROR_HARVESTING = "error_harvesting"
    RATE_LIMIT_PROBING = "rate_limit_probing"


@dataclass
class ClassificationResult:
    """
    Result of behavioral classification.

    Attributes:
        classification: Overall classification (normal/suspicious/malicious)
        confidence: Confidence score from 0.0 to 1.0
        signals: List of detected behavioral signals
        signal_details: Additional context for each signal
        risk_score: Numeric risk score (0-100)
    """
    classification: Classification
    confidence: float
    signals: list[Signal]
    signal_details: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "classification": self.classification.value,
            "confidence": round(self.confidence, 2),
            "signals": [s.value for s in self.signals],
            "signal_details": self.signal_details,
            "risk_score": self.risk_score,
        }


# =============================================================================
# SIGNAL DETECTION FUNCTIONS
# =============================================================================

# Known SDK User-Agent patterns for common APIs
SDK_USER_AGENTS = {
    "stripe": ["Stripe/v1", "stripe-python", "stripe-node", "stripe-ruby", "stripe-go"],
    "openai": ["OpenAI/Python", "openai-python", "openai-node"],
    "github": ["PyGithub", "octokit", "GitHub-Hookshot"],
}

# Suspicious User-Agent patterns
SUSPICIOUS_USER_AGENTS = [
    "curl",
    "wget",
    "python-requests",
    "httpie",
    "postman",
    "insomnia",
    "burp",
    "sqlmap",
    "nikto",
    "scanner",
    "bot",
    "crawler",
]

# Common enumeration paths
ENUMERATION_PATHS = [
    "/.env",
    "/.git",
    "/config",
    "/admin",
    "/debug",
    "/swagger",
    "/api-docs",
    "/graphql",
    "/actuator",
    "/.well-known",
]


def detect_non_sdk_headers(
    record: TelemetryRecord,
) -> tuple[bool, dict[str, Any]]:
    """
    Detect if request headers don't match expected SDK patterns.

    Returns:
        Tuple of (is_detected, details)
    """
    user_agent = record.request.user_agent or ""
    target_api = record.target_api.lower()

    # Check if UA matches known SDK patterns
    if target_api in SDK_USER_AGENTS:
        sdk_patterns = SDK_USER_AGENTS[target_api]
        matches_sdk = any(pattern.lower() in user_agent.lower() for pattern in sdk_patterns)
        if not matches_sdk and user_agent:
            return True, {"user_agent": user_agent, "expected_sdk": sdk_patterns}

    return False, {}


def detect_missing_user_agent(record: TelemetryRecord) -> tuple[bool, dict[str, Any]]:
    """Detect missing User-Agent header."""
    if not record.request.user_agent:
        return True, {"reason": "No User-Agent header provided"}
    return False, {}


def detect_spoofed_user_agent(record: TelemetryRecord) -> tuple[bool, dict[str, Any]]:
    """Detect potentially spoofed or suspicious User-Agent."""
    ua = (record.request.user_agent or "").lower()

    for suspicious in SUSPICIOUS_USER_AGENTS:
        if suspicious in ua:
            return True, {"user_agent": record.request.user_agent, "matched": suspicious}

    return False, {}


def detect_endpoint_enumeration(
    record: TelemetryRecord,
    recent_paths: Optional[list[str]] = None,
) -> tuple[bool, dict[str, Any]]:
    """
    Detect endpoint enumeration patterns.

    Args:
        record: Current telemetry record
        recent_paths: List of recently requested paths from same source

    Returns:
        Tuple of (is_detected, details)
    """
    path = record.request.path.lower()

    # Check for known enumeration paths
    for enum_path in ENUMERATION_PATHS:
        if enum_path in path:
            return True, {"path": record.request.path, "matched_pattern": enum_path}

    # Check for sequential pattern probing (if history provided)
    if recent_paths and len(recent_paths) >= 3:
        unique_paths = set(recent_paths[-10:])
        if len(unique_paths) >= 5:
            return True, {
                "unique_paths_count": len(unique_paths),
                "recent_paths": list(unique_paths)[:5],
            }

    return False, {}


def detect_auth_error_persistence(
    record: TelemetryRecord,
    recent_auth_errors: int = 0,
) -> tuple[bool, dict[str, Any]]:
    """
    Detect persistent authentication errors.

    Args:
        record: Current telemetry record
        recent_auth_errors: Count of recent auth errors from same source

    Returns:
        Tuple of (is_detected, details)
    """
    if record.response.is_auth_error:
        if recent_auth_errors >= 3:
            return True, {
                "current_error": record.response.status_code,
                "recent_auth_errors": recent_auth_errors + 1,
            }
    return False, {}


def detect_rapid_retries(
    record: TelemetryRecord,
    requests_last_minute: int = 0,
) -> tuple[bool, dict[str, Any]]:
    """
    Detect rapid retry patterns.

    Args:
        record: Current telemetry record
        requests_last_minute: Request count in last 60 seconds from same source

    Returns:
        Tuple of (is_detected, details)
    """
    # Threshold: more than 30 requests per minute is suspicious
    if requests_last_minute >= 30:
        return True, {"requests_per_minute": requests_last_minute}
    return False, {}


def detect_burst_requests(
    requests_last_second: int = 0,
) -> tuple[bool, dict[str, Any]]:
    """
    Detect burst request patterns.

    Args:
        requests_last_second: Request count in last second from same source

    Returns:
        Tuple of (is_detected, details)
    """
    # More than 10 requests per second is a burst
    if requests_last_second >= 10:
        return True, {"requests_per_second": requests_last_second}
    return False, {}


def detect_rate_limit_probing(
    record: TelemetryRecord,
    recent_429_count: int = 0,
) -> tuple[bool, dict[str, Any]]:
    """
    Detect rate limit probing behavior.

    Args:
        record: Current telemetry record
        recent_429_count: Count of recent 429 responses

    Returns:
        Tuple of (is_detected, details)
    """
    if record.response.is_rate_limited and recent_429_count >= 2:
        return True, {"rate_limit_hits": recent_429_count + 1}
    return False, {}


def detect_injection_attempt(record: TelemetryRecord) -> tuple[bool, dict[str, Any]]:
    """
    Detect potential injection attempts in path or parameters.

    Returns:
        Tuple of (is_detected, details)
    """
    injection_patterns = [
        "../",
        "..\\",
        "<script",
        "javascript:",
        "' OR ",
        "\" OR ",
        "1=1",
        "UNION SELECT",
        "${",
        "{{",
        "%00",
    ]

    path = record.request.path
    params = str(record.request.query_params)

    for pattern in injection_patterns:
        if pattern.lower() in path.lower() or pattern.lower() in params.lower():
            return True, {"pattern": pattern, "location": "path" if pattern in path else "params"}

    return False, {}


def detect_error_harvesting(
    record: TelemetryRecord,
    recent_error_count: int = 0,
) -> tuple[bool, dict[str, Any]]:
    """
    Detect error message harvesting behavior.

    Attackers may intentionally trigger errors to gather information.

    Returns:
        Tuple of (is_detected, details)
    """
    if record.response.status_code >= 400 and recent_error_count >= 5:
        return True, {
            "error_count": recent_error_count + 1,
            "current_status": record.response.status_code,
        }
    return False, {}


# =============================================================================
# CLASSIFICATION FUNCTIONS
# =============================================================================

# Signal weights for risk scoring
SIGNAL_WEIGHTS: dict[Signal, int] = {
    Signal.ENDPOINT_ENUMERATION: 25,
    Signal.PARAMETER_FUZZING: 20,
    Signal.VERSION_PROBING: 15,
    Signal.AUTH_ERROR_PERSISTENCE: 30,
    Signal.CREDENTIAL_STUFFING: 40,
    Signal.KEY_ROTATION_ATTEMPT: 20,
    Signal.RAPID_RETRIES: 15,
    Signal.BURST_REQUESTS: 20,
    Signal.SLOW_SCAN: 10,
    Signal.NON_SDK_HEADERS: 10,
    Signal.MISSING_USER_AGENT: 15,
    Signal.SPOOFED_USER_AGENT: 20,
    Signal.UNUSUAL_CONTENT_TYPE: 10,
    Signal.OVERSIZED_PAYLOAD: 15,
    Signal.MALFORMED_JSON: 10,
    Signal.INJECTION_ATTEMPT: 50,
    Signal.ERROR_HARVESTING: 20,
    Signal.RATE_LIMIT_PROBING: 25,
}


@dataclass
class RequestContext:
    """
    Additional context for classification from request history.

    This allows stateless classification with externally-provided context.
    """
    recent_paths: list[str] = field(default_factory=list)
    recent_auth_errors: int = 0
    requests_last_minute: int = 0
    requests_last_second: int = 0
    recent_429_count: int = 0
    recent_error_count: int = 0


def classify_request(
    record: TelemetryRecord,
    context: Optional[RequestContext] = None,
) -> ClassificationResult:
    """
    Classify a request based on telemetry and context.

    This is the main classification function. It analyzes the telemetry record
    and optional historical context to determine if behavior is normal,
    suspicious, or malicious.

    Args:
        record: Complete telemetry record for the request
        context: Optional historical context from same source

    Returns:
        ClassificationResult with classification, confidence, and signals
    """
    ctx = context or RequestContext()
    detected_signals: list[Signal] = []
    signal_details: dict[str, Any] = {}

    # Run all detectors
    detectors = [
        (Signal.NON_SDK_HEADERS, detect_non_sdk_headers(record)),
        (Signal.MISSING_USER_AGENT, detect_missing_user_agent(record)),
        (Signal.SPOOFED_USER_AGENT, detect_spoofed_user_agent(record)),
        (Signal.ENDPOINT_ENUMERATION, detect_endpoint_enumeration(record, ctx.recent_paths)),
        (Signal.AUTH_ERROR_PERSISTENCE, detect_auth_error_persistence(record, ctx.recent_auth_errors)),
        (Signal.RAPID_RETRIES, detect_rapid_retries(record, ctx.requests_last_minute)),
        (Signal.BURST_REQUESTS, detect_burst_requests(ctx.requests_last_second)),
        (Signal.RATE_LIMIT_PROBING, detect_rate_limit_probing(record, ctx.recent_429_count)),
        (Signal.INJECTION_ATTEMPT, detect_injection_attempt(record)),
        (Signal.ERROR_HARVESTING, detect_error_harvesting(record, ctx.recent_error_count)),
    ]

    for signal, (detected, details) in detectors:
        if detected:
            detected_signals.append(signal)
            signal_details[signal.value] = details

    # Calculate risk score
    risk_score = sum(SIGNAL_WEIGHTS.get(s, 10) for s in detected_signals)
    risk_score = min(100, risk_score)  # Cap at 100

    # Determine classification based on risk score
    if risk_score >= 60:
        classification = Classification.MALICIOUS
    elif risk_score >= 25:
        classification = Classification.SUSPICIOUS
    else:
        classification = Classification.NORMAL

    # Calculate confidence based on signal count and weight distribution
    if not detected_signals:
        confidence = 0.95  # High confidence it's normal
    else:
        # Confidence increases with more signals and higher weights
        weight_sum = sum(SIGNAL_WEIGHTS.get(s, 10) for s in detected_signals)
        signal_count_factor = min(1.0, len(detected_signals) / 5)
        weight_factor = min(1.0, weight_sum / 80)
        confidence = 0.5 + (signal_count_factor + weight_factor) / 4

    return ClassificationResult(
        classification=classification,
        confidence=round(confidence, 2),
        signals=detected_signals,
        signal_details=signal_details,
        risk_score=risk_score,
    )


def classify_request_simple(
    record: TelemetryRecord,
) -> ClassificationResult:
    """
    Simplified classification without historical context.

    Use this for stateless, single-request classification.

    Args:
        record: Telemetry record to classify

    Returns:
        ClassificationResult based only on current request
    """
    return classify_request(record, context=None)


def get_classification_summary(result: ClassificationResult) -> str:
    """
    Generate a human-readable summary of the classification.

    Args:
        result: Classification result

    Returns:
        Summary string for logging or display
    """
    if result.classification == Classification.NORMAL:
        return f"Normal request (confidence: {result.confidence:.0%})"

    signals_str = ", ".join(s.value for s in result.signals)
    return (
        f"{result.classification.value.upper()} request detected "
        f"(risk: {result.risk_score}/100, confidence: {result.confidence:.0%}). "
        f"Signals: {signals_str}"
    )
