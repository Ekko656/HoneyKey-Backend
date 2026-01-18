"""
SOC Event Generator for HoneyKey integration.

Converts instrumentation telemetry and classifications into SOC-ready event
objects compatible with HoneyKey's existing incident model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .classifier import Classification, ClassificationResult, Signal
from .telemetry import TelemetryRecord


# =============================================================================
# MITRE ATT&CK MAPPINGS
# =============================================================================

@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique reference."""
    technique_id: str
    technique_name: str
    tactic: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.technique_id,
            "name": self.technique_name,
            "tactic": self.tactic,
            "url": self.url,
        }


# Map behavioral signals to MITRE techniques
SIGNAL_TO_MITRE: dict[Signal, MitreTechnique] = {
    Signal.ENDPOINT_ENUMERATION: MitreTechnique(
        technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1083/",
    ),
    Signal.AUTH_ERROR_PERSISTENCE: MitreTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/",
    ),
    Signal.CREDENTIAL_STUFFING: MitreTechnique(
        technique_id="T1110.004",
        technique_name="Brute Force: Credential Stuffing",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/004/",
    ),
    Signal.RAPID_RETRIES: MitreTechnique(
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    Signal.INJECTION_ATTEMPT: MitreTechnique(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1190/",
    ),
    Signal.NON_SDK_HEADERS: MitreTechnique(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/",
    ),
    Signal.SPOOFED_USER_AGENT: MitreTechnique(
        technique_id="T1036",
        technique_name="Masquerading",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1036/",
    ),
    Signal.ERROR_HARVESTING: MitreTechnique(
        technique_id="T1580",
        technique_name="Cloud Infrastructure Discovery",
        tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1580/",
    ),
    Signal.RATE_LIMIT_PROBING: MitreTechnique(
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1595/",
    ),
    Signal.BURST_REQUESTS: MitreTechnique(
        technique_id="T1498",
        technique_name="Network Denial of Service",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1498/",
    ),
}

# Default technique for unmapped signals
DEFAULT_MITRE = MitreTechnique(
    technique_id="T1595.002",
    technique_name="Active Scanning: Vulnerability Scanning",
    tactic="Reconnaissance",
    url="https://attack.mitre.org/techniques/T1595/002/",
)


def get_mitre_techniques(signals: list[Signal]) -> list[MitreTechnique]:
    """
    Get MITRE techniques for a list of signals.

    Returns unique techniques mapped from the detected signals.
    """
    techniques = []
    seen_ids = set()

    for signal in signals:
        technique = SIGNAL_TO_MITRE.get(signal, DEFAULT_MITRE)
        if technique.technique_id not in seen_ids:
            techniques.append(technique)
            seen_ids.add(technique.technique_id)

    return techniques if techniques else [DEFAULT_MITRE]


# =============================================================================
# SOC EVENT DATA STRUCTURES
# =============================================================================

@dataclass
class EvidenceItem:
    """A single piece of evidence for the SOC report."""
    category: str
    description: str
    raw_value: Optional[str] = None
    severity: str = "info"  # info, low, medium, high, critical

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "description": self.description,
            "raw_value": self.raw_value,
            "severity": self.severity,
        }


@dataclass
class SOCEvent:
    """
    SOC-ready event object compatible with HoneyKey's incident model.

    This is the primary output structure for integration with HoneyKey.
    """
    # Identification
    event_id: str
    timestamp: str
    target_api: str

    # Source information
    source_ip: str
    user_agent: Optional[str]
    api_key_prefix: Optional[str]

    # Request details
    method: str
    path: str
    status_code: int
    latency_ms: float

    # Classification
    classification: str
    confidence: float
    risk_score: int
    signals: list[str]

    # Threat intelligence
    mitre_techniques: list[dict[str, str]]
    primary_tactic: str

    # Evidence
    evidence: list[dict[str, Any]]

    # Analyst explanation
    summary: str
    analyst_notes: str
    recommended_actions: list[str]

    # Metadata
    is_auth_error: bool
    is_rate_limited: bool

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "target_api": self.target_api,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "api_key_prefix": self.api_key_prefix,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "classification": self.classification,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "signals": self.signals,
            "mitre_techniques": self.mitre_techniques,
            "primary_tactic": self.primary_tactic,
            "evidence": self.evidence,
            "summary": self.summary,
            "analyst_notes": self.analyst_notes,
            "recommended_actions": self.recommended_actions,
            "is_auth_error": self.is_auth_error,
            "is_rate_limited": self.is_rate_limited,
        }


# =============================================================================
# EVIDENCE GENERATION
# =============================================================================

def generate_evidence(
    telemetry: TelemetryRecord,
    classification: ClassificationResult,
) -> list[EvidenceItem]:
    """
    Generate evidence items from telemetry and classification.

    Returns a list of evidence items suitable for SOC review.
    """
    evidence = []

    # Source identification
    evidence.append(EvidenceItem(
        category="source",
        description=f"Request originated from IP {telemetry.request.source_ip}",
        raw_value=telemetry.request.source_ip,
        severity="info",
    ))

    # User agent analysis
    if telemetry.request.user_agent:
        evidence.append(EvidenceItem(
            category="client",
            description=f"User-Agent: {telemetry.request.user_agent}",
            raw_value=telemetry.request.user_agent,
            severity="low" if Signal.SPOOFED_USER_AGENT in classification.signals else "info",
        ))
    else:
        evidence.append(EvidenceItem(
            category="client",
            description="No User-Agent header provided (potential automated tool)",
            severity="medium",
        ))

    # API key usage
    if telemetry.request.api_key_prefix:
        evidence.append(EvidenceItem(
            category="authentication",
            description=f"API key prefix: {telemetry.request.api_key_prefix}...",
            raw_value=telemetry.request.api_key_prefix,
            severity="info",
        ))

    # Request details
    evidence.append(EvidenceItem(
        category="request",
        description=f"{telemetry.request.method} {telemetry.request.path}",
        raw_value=telemetry.request.path,
        severity="info",
    ))

    # Response analysis
    if telemetry.response.is_auth_error:
        evidence.append(EvidenceItem(
            category="response",
            description=f"Authentication error ({telemetry.response.status_code})",
            raw_value=str(telemetry.response.status_code),
            severity="medium",
        ))

    if telemetry.response.is_rate_limited:
        evidence.append(EvidenceItem(
            category="response",
            description="Rate limit triggered (429)",
            severity="medium",
        ))

    if telemetry.response.error_message:
        evidence.append(EvidenceItem(
            category="response",
            description=f"Error: {telemetry.response.error_message}",
            raw_value=telemetry.response.error_message,
            severity="low",
        ))

    # Signal-specific evidence
    for signal in classification.signals:
        details = classification.signal_details.get(signal.value, {})

        if signal == Signal.ENDPOINT_ENUMERATION:
            evidence.append(EvidenceItem(
                category="behavior",
                description="Endpoint enumeration pattern detected",
                raw_value=str(details.get("matched_pattern") or details.get("unique_paths_count")),
                severity="high",
            ))

        elif signal == Signal.INJECTION_ATTEMPT:
            evidence.append(EvidenceItem(
                category="attack",
                description=f"Injection attempt detected: {details.get('pattern')}",
                raw_value=details.get("pattern"),
                severity="critical",
            ))

        elif signal == Signal.AUTH_ERROR_PERSISTENCE:
            evidence.append(EvidenceItem(
                category="behavior",
                description=f"Persistent auth failures: {details.get('recent_auth_errors')} attempts",
                raw_value=str(details.get("recent_auth_errors")),
                severity="high",
            ))

        elif signal == Signal.RAPID_RETRIES:
            evidence.append(EvidenceItem(
                category="behavior",
                description=f"Rapid requests: {details.get('requests_per_minute')}/min",
                raw_value=str(details.get("requests_per_minute")),
                severity="medium",
            ))

    return evidence


# =============================================================================
# ANALYST EXPLANATION GENERATION
# =============================================================================

def generate_summary(
    telemetry: TelemetryRecord,
    classification: ClassificationResult,
) -> str:
    """
    Generate a concise summary of the event for analysts.

    Returns a 1-2 sentence summary suitable for alert triage.
    """
    if classification.classification == Classification.NORMAL:
        return (
            f"Normal API request to {telemetry.target_api} "
            f"from {telemetry.request.source_ip}."
        )

    signal_names = [s.value.replace("_", " ") for s in classification.signals[:3]]
    signals_str = ", ".join(signal_names)

    if classification.classification == Classification.MALICIOUS:
        return (
            f"MALICIOUS activity detected from {telemetry.request.source_ip} "
            f"targeting {telemetry.target_api} API. "
            f"Detected signals: {signals_str}. "
            f"Risk score: {classification.risk_score}/100."
        )
    else:
        return (
            f"Suspicious activity from {telemetry.request.source_ip} "
            f"on {telemetry.target_api} API. "
            f"Signals: {signals_str}."
        )


def generate_analyst_notes(
    telemetry: TelemetryRecord,
    classification: ClassificationResult,
) -> str:
    """
    Generate detailed analyst notes explaining the classification.

    Returns a multi-sentence explanation for SOC analysts.
    """
    notes = []

    # Classification explanation
    if classification.classification == Classification.MALICIOUS:
        notes.append(
            f"This request has been classified as MALICIOUS with "
            f"{classification.confidence:.0%} confidence based on "
            f"{len(classification.signals)} behavioral signals."
        )
    elif classification.classification == Classification.SUSPICIOUS:
        notes.append(
            f"This request exhibits SUSPICIOUS behavior patterns. "
            f"Confidence: {classification.confidence:.0%}."
        )
    else:
        notes.append("This request appears to be normal API usage.")
        return " ".join(notes)

    # Signal explanations
    if Signal.ENDPOINT_ENUMERATION in classification.signals:
        notes.append(
            "The client is probing multiple endpoints, consistent with "
            "reconnaissance or API discovery behavior."
        )

    if Signal.AUTH_ERROR_PERSISTENCE in classification.signals:
        notes.append(
            "Multiple authentication failures from this source suggest "
            "credential testing or brute force activity."
        )

    if Signal.INJECTION_ATTEMPT in classification.signals:
        notes.append(
            "CRITICAL: Injection patterns detected in request. "
            "This indicates active exploitation attempts."
        )

    if Signal.NON_SDK_HEADERS in classification.signals:
        notes.append(
            "Request headers don't match expected SDK patterns, suggesting "
            "manual or custom tooling rather than legitimate integration."
        )

    if Signal.RAPID_RETRIES in classification.signals or Signal.BURST_REQUESTS in classification.signals:
        notes.append(
            "Request rate exceeds normal patterns. This could indicate "
            "automated scanning or denial-of-service behavior."
        )

    # MITRE context
    techniques = get_mitre_techniques(classification.signals)
    if techniques:
        primary = techniques[0]
        notes.append(
            f"Primary MITRE ATT&CK mapping: {primary.technique_id} "
            f"({primary.technique_name}) - {primary.tactic} tactic."
        )

    return " ".join(notes)


def generate_recommended_actions(
    classification: ClassificationResult,
    source_ip: str,
) -> list[str]:
    """
    Generate recommended response actions based on classification.

    Returns a prioritized list of actions for SOC response.
    """
    actions = []

    if classification.classification == Classification.NORMAL:
        return ["No action required - normal traffic"]

    # Always recommend for suspicious/malicious
    actions.append(f"Monitor source IP {source_ip} for continued activity")

    if classification.classification == Classification.MALICIOUS:
        actions.insert(0, f"IMMEDIATE: Consider blocking IP {source_ip}")

    if Signal.INJECTION_ATTEMPT in classification.signals:
        actions.insert(0, "CRITICAL: Investigate injection attempt - potential active attack")
        actions.append("Review WAF rules for injection pattern coverage")

    if Signal.AUTH_ERROR_PERSISTENCE in classification.signals:
        actions.append("Review API key validity and rotation status")
        actions.append("Check for credential exposure in logs or repositories")

    if Signal.ENDPOINT_ENUMERATION in classification.signals:
        actions.append("Review API documentation exposure")
        actions.append("Verify rate limiting is properly configured")

    if Signal.RAPID_RETRIES in classification.signals or Signal.BURST_REQUESTS in classification.signals:
        actions.append("Review and tighten rate limiting thresholds")

    if classification.risk_score >= 60:
        actions.append("Escalate to security team for investigation")
        actions.append("Preserve logs for forensic analysis")

    return actions


# =============================================================================
# MAIN EVENT GENERATOR
# =============================================================================

def create_soc_event(
    telemetry: TelemetryRecord,
    classification: ClassificationResult,
) -> SOCEvent:
    """
    Create a complete SOC event from telemetry and classification.

    This is the main entry point for generating SOC-compatible events
    that can be integrated with HoneyKey's incident model.

    Args:
        telemetry: Complete telemetry record from the proxy
        classification: Behavioral classification result

    Returns:
        SOCEvent ready for storage or alerting
    """
    # Get MITRE techniques
    techniques = get_mitre_techniques(classification.signals)
    primary_tactic = techniques[0].tactic if techniques else "Unknown"

    # Generate evidence
    evidence = generate_evidence(telemetry, classification)

    # Generate explanations
    summary = generate_summary(telemetry, classification)
    analyst_notes = generate_analyst_notes(telemetry, classification)
    recommended_actions = generate_recommended_actions(
        classification,
        telemetry.request.source_ip,
    )

    return SOCEvent(
        event_id=telemetry.request.request_id,
        timestamp=telemetry.request.timestamp,
        target_api=telemetry.target_api,
        source_ip=telemetry.request.source_ip,
        user_agent=telemetry.request.user_agent,
        api_key_prefix=telemetry.request.api_key_prefix,
        method=telemetry.request.method,
        path=telemetry.request.path,
        status_code=telemetry.response.status_code,
        latency_ms=telemetry.response.latency_ms,
        classification=classification.classification.value,
        confidence=classification.confidence,
        risk_score=classification.risk_score,
        signals=[s.value for s in classification.signals],
        mitre_techniques=[t.to_dict() for t in techniques],
        primary_tactic=primary_tactic,
        evidence=[e.to_dict() for e in evidence],
        summary=summary,
        analyst_notes=analyst_notes,
        recommended_actions=recommended_actions,
        is_auth_error=telemetry.response.is_auth_error,
        is_rate_limited=telemetry.response.is_rate_limited,
    )


def format_soc_event_for_logging(event: SOCEvent) -> str:
    """
    Format a SOC event for structured logging.

    Returns a single-line JSON string suitable for log aggregation.
    """
    import json
    return json.dumps(event.to_dict(), separators=(",", ":"))
