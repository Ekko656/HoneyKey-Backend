"""
Behavioral Feature Extraction Module.

Extracts quantitative behavioral signals from HTTP event sequences.
These features are used for technique inference WITHOUT relying on
key identity or hardcoded mappings.

All extraction is deterministic and explainable.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class HTTPEvent:
    """
    Single HTTP event for analysis.

    This is the input format expected by the feature extractor.
    """
    timestamp: str  # ISO-8601
    ip: str
    method: str
    path: str
    status_code: int
    user_agent: Optional[str] = None
    response_time_ms: Optional[float] = None
    headers: Optional[dict[str, str]] = None
    body_size: Optional[int] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HTTPEvent":
        """Create from dictionary."""
        return cls(
            timestamp=d["timestamp"],
            ip=d["ip"],
            method=d["method"],
            path=d["path"],
            status_code=d["status_code"],
            user_agent=d.get("user_agent"),
            response_time_ms=d.get("response_time_ms"),
            headers=d.get("headers"),
            body_size=d.get("body_size"),
        )


@dataclass
class ContextualHints:
    """
    Optional contextual hints about the environment.

    These provide context but are NOT used for hardcoded technique mapping.
    """
    key_scope: Optional[str] = None  # "read-only", "admin", "unknown"
    deployment_surface: Optional[str] = None  # "frontend", "logs", "git", "docker"
    is_production: Optional[bool] = None
    api_type: Optional[str] = None  # "stripe", "openai", "internal"


@dataclass
class BehavioralFeatures:
    """
    Extracted behavioral features from an event sequence.

    All features are numeric or categorical - no key identity information.
    """
    # Temporal patterns
    burst_score: float  # 0-1, how bursty the request pattern is
    request_rate_per_minute: float
    time_span_seconds: float
    temporal_regularity: float  # 0-1, how regular/automated the timing is

    # Endpoint patterns
    enum_score: float  # 0-1, likelihood of endpoint enumeration
    unique_paths_ratio: float  # unique_paths / total_requests
    path_depth_variance: float  # variance in URL path depth
    sensitive_path_hits: int  # count of sensitive-looking paths

    # Authentication patterns
    auth_failure_rate: float  # 0-1, ratio of 401/403 responses
    auth_retry_count: int  # consecutive auth failures
    auth_failure_persistence: float  # 0-1, how persistent auth failures are

    # Response patterns
    error_rate: float  # 0-1, ratio of 4xx/5xx responses
    rate_limit_hits: int  # count of 429 responses
    server_error_count: int  # count of 5xx responses

    # Client patterns
    sdk_likelihood: float  # 0-1, how likely client is legitimate SDK
    user_agent_entropy: float  # entropy of user agent strings
    unique_user_agents: int
    header_anomaly_score: float  # 0-1, how anomalous headers are

    # Method patterns
    method_distribution: dict[str, float]  # GET: 0.8, POST: 0.2, etc.
    write_method_ratio: float  # ratio of POST/PUT/DELETE

    # Sequence patterns
    path_transition_entropy: float  # entropy of path-to-path transitions
    sequential_probe_score: float  # 0-1, sequential path probing
    backtrack_count: int  # times attacker revisited paths

    # Injection indicators
    injection_pattern_count: int  # count of injection-like patterns
    payload_anomaly_score: float  # 0-1, how anomalous payloads are

    # Summary
    total_events: int
    distinct_ips: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization or LLM input."""
        return {
            "temporal": {
                "burst_score": round(self.burst_score, 3),
                "request_rate_per_minute": round(self.request_rate_per_minute, 2),
                "time_span_seconds": round(self.time_span_seconds, 1),
                "temporal_regularity": round(self.temporal_regularity, 3),
            },
            "endpoint": {
                "enum_score": round(self.enum_score, 3),
                "unique_paths_ratio": round(self.unique_paths_ratio, 3),
                "path_depth_variance": round(self.path_depth_variance, 3),
                "sensitive_path_hits": self.sensitive_path_hits,
            },
            "authentication": {
                "auth_failure_rate": round(self.auth_failure_rate, 3),
                "auth_retry_count": self.auth_retry_count,
                "auth_failure_persistence": round(self.auth_failure_persistence, 3),
            },
            "response": {
                "error_rate": round(self.error_rate, 3),
                "rate_limit_hits": self.rate_limit_hits,
                "server_error_count": self.server_error_count,
            },
            "client": {
                "sdk_likelihood": round(self.sdk_likelihood, 3),
                "user_agent_entropy": round(self.user_agent_entropy, 3),
                "unique_user_agents": self.unique_user_agents,
                "header_anomaly_score": round(self.header_anomaly_score, 3),
            },
            "method": {
                "distribution": {k: round(v, 3) for k, v in self.method_distribution.items()},
                "write_method_ratio": round(self.write_method_ratio, 3),
            },
            "sequence": {
                "path_transition_entropy": round(self.path_transition_entropy, 3),
                "sequential_probe_score": round(self.sequential_probe_score, 3),
                "backtrack_count": self.backtrack_count,
            },
            "injection": {
                "injection_pattern_count": self.injection_pattern_count,
                "payload_anomaly_score": round(self.payload_anomaly_score, 3),
            },
            "summary": {
                "total_events": self.total_events,
                "distinct_ips": self.distinct_ips,
            },
        }


# =============================================================================
# FEATURE EXTRACTION FUNCTIONS
# =============================================================================

def _parse_timestamp(ts: str) -> datetime:
    """Parse ISO-8601 timestamp."""
    # Handle various ISO formats
    ts = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        # Fallback for edge cases
        return datetime.now()


def _calculate_entropy(values: list[str]) -> float:
    """Calculate Shannon entropy of a list of values."""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _normalize_entropy(entropy: float, n_unique: int) -> float:
    """Normalize entropy to 0-1 range."""
    if n_unique <= 1:
        return 0.0
    max_entropy = math.log2(n_unique)
    return entropy / max_entropy if max_entropy > 0 else 0.0


# Sensitive path patterns (common targets for enumeration)
SENSITIVE_PATTERNS = [
    r"\.env",
    r"\.git",
    r"config",
    r"admin",
    r"debug",
    r"swagger",
    r"api-docs",
    r"graphql",
    r"actuator",
    r"health",
    r"metrics",
    r"\.well-known",
    r"backup",
    r"dump",
    r"export",
    r"internal",
    r"private",
    r"secret",
    r"token",
    r"key",
    r"password",
    r"credential",
]

# Injection patterns
INJECTION_PATTERNS = [
    r"\.\./",  # Path traversal
    r"\.\.\\",
    r"<script",  # XSS
    r"javascript:",
    r"'.*OR.*'",  # SQL injection
    r'".*OR.*"',
    r"UNION\s+SELECT",
    r"\$\{",  # Template injection
    r"\{\{",
    r"%00",  # Null byte
    r"%0[aAdD]",  # CRLF
    r"cmd=",  # Command injection indicators
    r"exec=",
    r"system\(",
]

# Known SDK user agent patterns
SDK_PATTERNS = [
    r"stripe",
    r"openai",
    r"github",
    r"octokit",
    r"aws-sdk",
    r"google-api",
    r"azure",
    r"twilio",
    r"sendgrid",
]

# Suspicious user agent patterns
SUSPICIOUS_UA_PATTERNS = [
    r"curl",
    r"wget",
    r"python-requests",
    r"httpie",
    r"postman",
    r"insomnia",
    r"burp",
    r"sqlmap",
    r"nikto",
    r"nmap",
    r"scanner",
    r"bot",
    r"crawler",
    r"scraper",
]


def extract_temporal_features(events: list[HTTPEvent]) -> dict[str, float]:
    """
    Extract temporal/timing features from events.

    Returns:
        burst_score: How bursty the pattern is (1.0 = very bursty)
        request_rate_per_minute: Average requests per minute
        time_span_seconds: Total time span of events
        temporal_regularity: How regular the timing is (1.0 = very regular/automated)
    """
    if len(events) < 2:
        return {
            "burst_score": 0.0,
            "request_rate_per_minute": 0.0,
            "time_span_seconds": 0.0,
            "temporal_regularity": 0.0,
        }

    timestamps = sorted(_parse_timestamp(e.timestamp) for e in events)
    time_span = (timestamps[-1] - timestamps[0]).total_seconds()

    if time_span == 0:
        return {
            "burst_score": 1.0,  # All requests at same time = max burst
            "request_rate_per_minute": float(len(events)),
            "time_span_seconds": 0.0,
            "temporal_regularity": 1.0,
        }

    # Calculate inter-arrival times
    intervals = []
    for i in range(1, len(timestamps)):
        interval = (timestamps[i] - timestamps[i - 1]).total_seconds()
        intervals.append(interval)

    # Burst score: based on how many requests happen in short windows
    short_intervals = sum(1 for i in intervals if i < 1.0)  # < 1 second
    burst_score = short_intervals / len(intervals) if intervals else 0.0

    # Request rate
    request_rate = (len(events) / time_span) * 60 if time_span > 0 else 0.0

    # Temporal regularity: low variance in intervals = automated
    if intervals:
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        # Coefficient of variation (lower = more regular)
        cv = std_dev / mean_interval if mean_interval > 0 else 0.0
        regularity = max(0.0, 1.0 - min(cv, 1.0))
    else:
        regularity = 0.0

    return {
        "burst_score": min(1.0, burst_score),
        "request_rate_per_minute": request_rate,
        "time_span_seconds": time_span,
        "temporal_regularity": regularity,
    }


def extract_endpoint_features(events: list[HTTPEvent]) -> dict[str, Any]:
    """
    Extract endpoint/path-related features.

    Returns:
        enum_score: Likelihood of enumeration behavior
        unique_paths_ratio: Ratio of unique paths to total requests
        path_depth_variance: Variance in URL depth
        sensitive_path_hits: Count of sensitive path accesses
    """
    if not events:
        return {
            "enum_score": 0.0,
            "unique_paths_ratio": 0.0,
            "path_depth_variance": 0.0,
            "sensitive_path_hits": 0,
        }

    paths = [e.path for e in events]
    unique_paths = set(paths)
    unique_ratio = len(unique_paths) / len(paths)

    # Path depth analysis
    depths = [len(p.strip("/").split("/")) for p in paths]
    mean_depth = sum(depths) / len(depths)
    depth_variance = sum((d - mean_depth) ** 2 for d in depths) / len(depths)

    # Sensitive path detection
    sensitive_hits = 0
    for path in paths:
        path_lower = path.lower()
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, path_lower):
                sensitive_hits += 1
                break

    # Enumeration score based on:
    # - High unique path ratio
    # - Sensitive path hits
    # - Path depth variance (trying different depths)
    enum_indicators = [
        unique_ratio > 0.5,
        sensitive_hits > 2,
        depth_variance > 1.0,
        len(unique_paths) > 5,
    ]
    enum_score = sum(enum_indicators) / len(enum_indicators)

    # Boost enum score if hitting many unique paths rapidly
    if unique_ratio > 0.8 and len(unique_paths) > 10:
        enum_score = min(1.0, enum_score + 0.3)

    return {
        "enum_score": enum_score,
        "unique_paths_ratio": unique_ratio,
        "path_depth_variance": depth_variance,
        "sensitive_path_hits": sensitive_hits,
    }


def extract_auth_features(events: list[HTTPEvent]) -> dict[str, Any]:
    """
    Extract authentication-related features.

    Returns:
        auth_failure_rate: Ratio of 401/403 responses
        auth_retry_count: Max consecutive auth failures
        auth_failure_persistence: How persistent failures are over time
    """
    if not events:
        return {
            "auth_failure_rate": 0.0,
            "auth_retry_count": 0,
            "auth_failure_persistence": 0.0,
        }

    auth_failures = [e for e in events if e.status_code in (401, 403)]
    failure_rate = len(auth_failures) / len(events)

    # Count max consecutive auth failures
    max_consecutive = 0
    current_consecutive = 0
    for event in events:
        if event.status_code in (401, 403):
            current_consecutive += 1
            max_consecutive = max(max_consecutive, current_consecutive)
        else:
            current_consecutive = 0

    # Persistence: failures spread over time vs clustered
    if len(auth_failures) >= 2:
        failure_times = sorted(_parse_timestamp(e.timestamp) for e in auth_failures)
        time_span = (failure_times[-1] - failure_times[0]).total_seconds()
        total_span = extract_temporal_features(events)["time_span_seconds"]
        persistence = time_span / total_span if total_span > 0 else 1.0
    else:
        persistence = 0.0

    return {
        "auth_failure_rate": failure_rate,
        "auth_retry_count": max_consecutive,
        "auth_failure_persistence": min(1.0, persistence),
    }


def extract_response_features(events: list[HTTPEvent]) -> dict[str, Any]:
    """
    Extract response pattern features.

    Returns:
        error_rate: Ratio of error responses
        rate_limit_hits: Count of 429 responses
        server_error_count: Count of 5xx responses
    """
    if not events:
        return {
            "error_rate": 0.0,
            "rate_limit_hits": 0,
            "server_error_count": 0,
        }

    errors = [e for e in events if e.status_code >= 400]
    rate_limits = [e for e in events if e.status_code == 429]
    server_errors = [e for e in events if 500 <= e.status_code < 600]

    return {
        "error_rate": len(errors) / len(events),
        "rate_limit_hits": len(rate_limits),
        "server_error_count": len(server_errors),
    }


def extract_client_features(events: list[HTTPEvent]) -> dict[str, Any]:
    """
    Extract client/user-agent features.

    Returns:
        sdk_likelihood: How likely the client is a legitimate SDK
        user_agent_entropy: Entropy of user agent strings
        unique_user_agents: Count of unique user agents
        header_anomaly_score: How anomalous the headers are
    """
    user_agents = [e.user_agent or "" for e in events]
    unique_uas = set(ua for ua in user_agents if ua)

    # SDK likelihood based on UA patterns
    sdk_matches = 0
    suspicious_matches = 0
    for ua in user_agents:
        ua_lower = ua.lower()
        if any(re.search(p, ua_lower) for p in SDK_PATTERNS):
            sdk_matches += 1
        if any(re.search(p, ua_lower) for p in SUSPICIOUS_UA_PATTERNS):
            suspicious_matches += 1

    if user_agents:
        sdk_ratio = sdk_matches / len(user_agents)
        suspicious_ratio = suspicious_matches / len(user_agents)
        # SDK likelihood decreases with suspicious tools
        sdk_likelihood = max(0.0, sdk_ratio - suspicious_ratio)
    else:
        sdk_likelihood = 0.0

    # User agent entropy (multiple different UAs = suspicious)
    ua_entropy = _calculate_entropy(user_agents)
    normalized_ua_entropy = _normalize_entropy(ua_entropy, len(unique_uas)) if unique_uas else 0.0

    # Header anomaly score
    header_anomaly = 0.0
    missing_ua_count = sum(1 for ua in user_agents if not ua)
    if events:
        header_anomaly = missing_ua_count / len(events)

    return {
        "sdk_likelihood": sdk_likelihood,
        "user_agent_entropy": normalized_ua_entropy,
        "unique_user_agents": len(unique_uas),
        "header_anomaly_score": header_anomaly,
    }


def extract_method_features(events: list[HTTPEvent]) -> dict[str, Any]:
    """
    Extract HTTP method distribution features.

    Returns:
        distribution: Method frequency distribution
        write_method_ratio: Ratio of write methods (POST/PUT/DELETE/PATCH)
    """
    if not events:
        return {
            "distribution": {},
            "write_method_ratio": 0.0,
        }

    methods = [e.method.upper() for e in events]
    counter = Counter(methods)
    total = len(methods)

    distribution = {method: count / total for method, count in counter.items()}

    write_methods = {"POST", "PUT", "DELETE", "PATCH"}
    write_count = sum(1 for m in methods if m in write_methods)
    write_ratio = write_count / total

    return {
        "distribution": distribution,
        "write_method_ratio": write_ratio,
    }


def extract_sequence_features(events: list[HTTPEvent]) -> dict[str, Any]:
    """
    Extract sequential pattern features.

    Returns:
        path_transition_entropy: Entropy of path transitions
        sequential_probe_score: Score for sequential probing behavior
        backtrack_count: Number of times paths were revisited
    """
    if len(events) < 2:
        return {
            "path_transition_entropy": 0.0,
            "sequential_probe_score": 0.0,
            "backtrack_count": 0,
        }

    paths = [e.path for e in events]

    # Path transitions (path_i -> path_i+1)
    transitions = []
    for i in range(len(paths) - 1):
        transitions.append(f"{paths[i]}|{paths[i + 1]}")

    transition_entropy = _calculate_entropy(transitions)
    unique_transitions = len(set(transitions))
    normalized_entropy = _normalize_entropy(transition_entropy, unique_transitions)

    # Sequential probe detection (incrementing paths like /1, /2, /3)
    sequential_count = 0
    for i in range(len(paths) - 1):
        # Check for numeric increment patterns
        match1 = re.search(r"/(\d+)$", paths[i])
        match2 = re.search(r"/(\d+)$", paths[i + 1])
        if match1 and match2:
            if int(match2.group(1)) == int(match1.group(1)) + 1:
                sequential_count += 1

    sequential_score = sequential_count / (len(paths) - 1) if len(paths) > 1 else 0.0

    # Backtrack count (revisiting same path)
    seen_paths = set()
    backtrack = 0
    for path in paths:
        if path in seen_paths:
            backtrack += 1
        seen_paths.add(path)

    return {
        "path_transition_entropy": normalized_entropy,
        "sequential_probe_score": sequential_score,
        "backtrack_count": backtrack,
    }


def extract_injection_features(events: list[HTTPEvent]) -> dict[str, Any]:
    """
    Extract injection attempt indicators.

    Returns:
        injection_pattern_count: Count of injection-like patterns
        payload_anomaly_score: How anomalous payloads appear
    """
    injection_count = 0
    anomaly_indicators = 0

    for event in events:
        path = event.path
        # Check path for injection patterns
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                injection_count += 1
                break

        # Check for anomalous characters in path
        if re.search(r"[<>'\";`|&$]", path):
            anomaly_indicators += 1

    anomaly_score = anomaly_indicators / len(events) if events else 0.0

    return {
        "injection_pattern_count": injection_count,
        "payload_anomaly_score": min(1.0, anomaly_score),
    }


# =============================================================================
# MAIN EXTRACTION FUNCTION
# =============================================================================

def extract_behavioral_features(
    events: list[HTTPEvent],
    context: Optional[ContextualHints] = None,
) -> BehavioralFeatures:
    """
    Extract all behavioral features from an event sequence.

    This is the main entry point for feature extraction. It analyzes
    raw HTTP events and produces quantitative behavioral signals that
    can be used for technique inference.

    Args:
        events: List of HTTP events to analyze
        context: Optional contextual hints (NOT used for technique mapping)

    Returns:
        BehavioralFeatures containing all extracted signals
    """
    if not events:
        # Return zeroed features for empty input
        return BehavioralFeatures(
            burst_score=0.0,
            request_rate_per_minute=0.0,
            time_span_seconds=0.0,
            temporal_regularity=0.0,
            enum_score=0.0,
            unique_paths_ratio=0.0,
            path_depth_variance=0.0,
            sensitive_path_hits=0,
            auth_failure_rate=0.0,
            auth_retry_count=0,
            auth_failure_persistence=0.0,
            error_rate=0.0,
            rate_limit_hits=0,
            server_error_count=0,
            sdk_likelihood=0.0,
            user_agent_entropy=0.0,
            unique_user_agents=0,
            header_anomaly_score=0.0,
            method_distribution={},
            write_method_ratio=0.0,
            path_transition_entropy=0.0,
            sequential_probe_score=0.0,
            backtrack_count=0,
            injection_pattern_count=0,
            payload_anomaly_score=0.0,
            total_events=0,
            distinct_ips=0,
        )

    # Extract all feature categories
    temporal = extract_temporal_features(events)
    endpoint = extract_endpoint_features(events)
    auth = extract_auth_features(events)
    response = extract_response_features(events)
    client = extract_client_features(events)
    method = extract_method_features(events)
    sequence = extract_sequence_features(events)
    injection = extract_injection_features(events)

    return BehavioralFeatures(
        # Temporal
        burst_score=temporal["burst_score"],
        request_rate_per_minute=temporal["request_rate_per_minute"],
        time_span_seconds=temporal["time_span_seconds"],
        temporal_regularity=temporal["temporal_regularity"],
        # Endpoint
        enum_score=endpoint["enum_score"],
        unique_paths_ratio=endpoint["unique_paths_ratio"],
        path_depth_variance=endpoint["path_depth_variance"],
        sensitive_path_hits=endpoint["sensitive_path_hits"],
        # Auth
        auth_failure_rate=auth["auth_failure_rate"],
        auth_retry_count=auth["auth_retry_count"],
        auth_failure_persistence=auth["auth_failure_persistence"],
        # Response
        error_rate=response["error_rate"],
        rate_limit_hits=response["rate_limit_hits"],
        server_error_count=response["server_error_count"],
        # Client
        sdk_likelihood=client["sdk_likelihood"],
        user_agent_entropy=client["user_agent_entropy"],
        unique_user_agents=client["unique_user_agents"],
        header_anomaly_score=client["header_anomaly_score"],
        # Method
        method_distribution=method["distribution"],
        write_method_ratio=method["write_method_ratio"],
        # Sequence
        path_transition_entropy=sequence["path_transition_entropy"],
        sequential_probe_score=sequence["sequential_probe_score"],
        backtrack_count=sequence["backtrack_count"],
        # Injection
        injection_pattern_count=injection["injection_pattern_count"],
        payload_anomaly_score=injection["payload_anomaly_score"],
        # Summary
        total_events=len(events),
        distinct_ips=len(set(e.ip for e in events)),
    )


def extract_features_from_dicts(
    event_dicts: list[dict[str, Any]],
    context: Optional[dict[str, Any]] = None,
) -> BehavioralFeatures:
    """
    Convenience function to extract features from raw dictionaries.

    Args:
        event_dicts: List of event dictionaries
        context: Optional context dictionary

    Returns:
        BehavioralFeatures
    """
    events = [HTTPEvent.from_dict(d) for d in event_dicts]
    hints = None
    if context:
        hints = ContextualHints(
            key_scope=context.get("key_scope"),
            deployment_surface=context.get("deployment_surface"),
            is_production=context.get("is_production"),
            api_type=context.get("api_type"),
        )
    return extract_behavioral_features(events, hints)
