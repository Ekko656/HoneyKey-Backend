"""
Dual Report Generator for HoneyKey SOC Reports.

Generates two types of reports from the same incident:
1. Executive Report - For non-technical stakeholders (managers, executives)
2. Engineer Report - For technical SOC analysts and security engineers

Both reports are generated from a single LLM call for efficiency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional, List

from app.detection import (
    BehavioralFeatures,
    HTTPEvent,
    extract_behavioral_features,
    infer_techniques_heuristic,
    TechniqueInferenceResult,
)
from app.integration.enhanced_prompt import get_key_hint, KeyHint


# =============================================================================
# RESPONSE MODELS
# =============================================================================

@dataclass
class ExecutiveReport:
    """
    Executive-friendly report for non-technical stakeholders.

    Uses plain English, avoids jargon, focuses on business impact.
    """
    incident_id: int
    severity: str  # Low, Medium, High, Critical
    risk_level: str  # Minimal, Moderate, Significant, Severe
    what_happened: str  # 2-3 sentences, plain English
    business_impact: str  # How this affects the organization
    threat_contained: bool  # Was the threat contained?
    key_findings: List[str]  # Bullet points, no jargon
    recommended_decisions: List[str]  # What executives should decide

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "risk_level": self.risk_level,
            "what_happened": self.what_happened,
            "business_impact": self.business_impact,
            "threat_contained": self.threat_contained,
            "key_findings": self.key_findings,
            "recommended_decisions": self.recommended_decisions,
        }


@dataclass
class EngineerReport:
    """
    Technical report for SOC analysts and security engineers.

    Includes MITRE ATT&CK techniques, metrics, and technical details.
    """
    incident_id: int
    severity: str  # Low, Medium, High, Critical
    confidence_score: float  # 0.0 - 1.0
    summary: str  # Technical summary

    # MITRE ATT&CK
    techniques: List[str]  # e.g., ["T1595: Active Scanning", "T1078: Valid Accounts"]
    kill_chain_phase: str  # Reconnaissance, Initial Access, etc.
    attacker_sophistication: str  # Low, Medium, High

    # Metrics
    event_count: int
    time_window_minutes: float
    request_rate_per_minute: float
    unique_endpoints: int

    # Evidence
    source_ip: str
    user_agents: List[str]
    targeted_endpoints: List[str]
    behavioral_indicators: List[str]

    # Technical recommendations
    recommended_actions: List[str]
    ioc_list: List[str] = field(default_factory=list)  # Indicators of Compromise

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "confidence_score": self.confidence_score,
            "summary": self.summary,
            "techniques": self.techniques,
            "kill_chain_phase": self.kill_chain_phase,
            "attacker_sophistication": self.attacker_sophistication,
            "event_count": self.event_count,
            "time_window_minutes": self.time_window_minutes,
            "request_rate_per_minute": self.request_rate_per_minute,
            "unique_endpoints": self.unique_endpoints,
            "source_ip": self.source_ip,
            "user_agents": self.user_agents,
            "targeted_endpoints": self.targeted_endpoints,
            "behavioral_indicators": self.behavioral_indicators,
            "recommended_actions": self.recommended_actions,
            "ioc_list": self.ioc_list,
        }


@dataclass
class DualReport:
    """Combined report containing both executive and engineer versions."""
    executive: ExecutiveReport
    engineer: EngineerReport

    def to_dict(self) -> dict[str, Any]:
        return {
            "executive_report": self.executive.to_dict(),
            "engineer_report": self.engineer.to_dict(),
        }


# =============================================================================
# DUAL REPORT PROMPT
# =============================================================================

DUAL_REPORT_PROMPT = """You are a senior SOC analyst generating TWO incident reports for a honeypot detection system.
Generate BOTH an Executive Report (for non-technical stakeholders) AND an Engineer Report (for technical SOC analysts).

=== INCIDENT DATA ===
{incident_json}

=== RECENT EVENTS ===
{events_json}

=== BEHAVIORAL ANALYSIS (Pre-computed) ===
{behavioral_summary}

=== TECHNIQUE INFERENCE ===
{technique_summary}

=== KEY CONTEXT ===
{key_hint_section}

=== REPORT REQUIREMENTS ===

Generate a JSON object with TWO reports:

{{
    "executive_report": {{
        "incident_id": {incident_id},
        "severity": "Low|Medium|High|Critical",
        "risk_level": "Minimal|Moderate|Significant|Severe",
        "what_happened": "Plain English explanation (2-3 sentences). NO technical jargon. Explain like you're telling a manager.",
        "business_impact": "How this affects the organization in business terms.",
        "threat_contained": true|false,
        "key_findings": [
            "Finding 1 in plain English",
            "Finding 2 in plain English"
        ],
        "recommended_decisions": [
            "Decision 1 for leadership",
            "Decision 2 for leadership"
        ]
    }},
    "engineer_report": {{
        "incident_id": {incident_id},
        "severity": "Low|Medium|High|Critical",
        "confidence_score": 0.0-1.0,
        "summary": "Technical summary with specifics.",
        "techniques": ["T1595: Active Scanning", "T1078: Valid Accounts"],
        "kill_chain_phase": "Reconnaissance|Initial Access|Execution|...",
        "attacker_sophistication": "Low|Medium|High",
        "event_count": <number>,
        "time_window_minutes": <float>,
        "request_rate_per_minute": <float>,
        "unique_endpoints": <number>,
        "source_ip": "<ip address>",
        "user_agents": ["User-Agent 1", "User-Agent 2"],
        "targeted_endpoints": ["/endpoint1", "/endpoint2"],
        "behavioral_indicators": [
            "Technical indicator 1",
            "Technical indicator 2"
        ],
        "recommended_actions": [
            "Technical action 1",
            "Technical action 2"
        ],
        "ioc_list": ["IOC 1", "IOC 2"]
    }}
}}

=== EXECUTIVE REPORT RULES ===
- NO technical jargon (no "enumeration", "injection", "MITRE", "T1xxx")
- NO IP addresses, user agents, or technical metrics
- Explain like you're talking to a business executive
- Focus on IMPACT and DECISIONS needed
- Use phrases like "unauthorized access attempt" instead of "credential abuse"

=== ENGINEER REPORT RULES ===
- Include ALL technical details
- List specific MITRE ATT&CK technique IDs
- Include metrics (event counts, timing, rates)
- List specific endpoints, IPs, user agents
- Provide actionable technical recommendations

Return ONLY valid JSON. No markdown, no code fences, no extra text."""


# =============================================================================
# BEHAVIORAL CONTEXT
# =============================================================================

def extract_context(
    events: list[dict[str, Any]],
) -> tuple[BehavioralFeatures, TechniqueInferenceResult, dict[str, Any]]:
    """
    Extract behavioral features, techniques, and metrics from events.

    Returns:
        Tuple of (features, inference, metrics_dict)
    """
    # Convert to HTTPEvent format
    http_events = []
    for e in events:
        http_events.append(HTTPEvent(
            timestamp=e.get("ts", ""),
            ip=e.get("ip", "unknown"),
            method=e.get("method", "GET"),
            path=e.get("path", "/"),
            status_code=401,
            user_agent=e.get("user_agent"),
        ))

    # Extract features
    features = extract_behavioral_features(http_events)
    inference = infer_techniques_heuristic(features)

    # Calculate metrics
    unique_paths = set(e.get("path", "/") for e in events)
    unique_agents = set(e.get("user_agent", "") for e in events if e.get("user_agent"))
    unique_ips = set(e.get("ip", "") for e in events if e.get("ip"))

    metrics = {
        "event_count": len(events),
        "unique_endpoints": len(unique_paths),
        "unique_user_agents": list(unique_agents)[:5],
        "unique_ips": list(unique_ips),
        "paths": list(unique_paths)[:10],
    }

    return features, inference, metrics


def format_behavioral_for_dual(features: BehavioralFeatures) -> str:
    """Format behavioral features for the dual report prompt."""
    lines = []

    if features.burst_score > 0.5:
        lines.append(f"• Bursty traffic pattern (score: {features.burst_score:.2f})")
    if features.request_rate_per_minute > 30:
        lines.append(f"• High request rate: {features.request_rate_per_minute:.1f}/min")
    if features.temporal_regularity > 0.7:
        lines.append(f"• Automated timing (regularity: {features.temporal_regularity:.2f})")
    if features.enum_score > 0.5:
        lines.append(f"• Endpoint enumeration (score: {features.enum_score:.2f})")
    if features.sensitive_path_hits > 0:
        lines.append(f"• Sensitive paths probed: {features.sensitive_path_hits}")
    if features.auth_failure_rate > 0.3:
        lines.append(f"• Auth failure rate: {features.auth_failure_rate:.0%}")
    if features.injection_pattern_count > 0:
        lines.append(f"• CRITICAL: {features.injection_pattern_count} injection patterns")

    if not lines:
        lines.append("• No significant anomalies detected")

    return "\n".join(lines)


def format_techniques_for_dual(inference: TechniqueInferenceResult) -> str:
    """Format technique inference for the dual report prompt."""
    if not inference.techniques:
        return "No specific techniques identified."

    lines = []
    for t in inference.techniques[:4]:
        lines.append(f"• {t.technique_id}: {t.technique_name} (confidence: {t.confidence:.0%})")

    lines.append(f"\nSophistication: {inference.attacker_sophistication}")
    lines.append(f"Kill chain phase: {inference.kill_chain_phase}")

    return "\n".join(lines)


# =============================================================================
# PROMPT BUILDER
# =============================================================================

def build_dual_report_prompt(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
    key_value: Optional[str] = None,
) -> str:
    """
    Build prompt for generating both executive and engineer reports.

    Args:
        incident: Incident data from database
        events: List of event dicts
        key_value: Optional key value for hint lookup

    Returns:
        Prompt string for LLM
    """
    features, inference, metrics = extract_context(events)

    key_id = incident.get("key_id", "unknown")
    key_hint = get_key_hint(key_value) or get_key_hint(key_id)

    if key_hint:
        key_section = f"Key: {key_id}\nPossible source: {key_hint.likely_leak_source}"
    else:
        key_section = f"Key: {key_id}\nNo specific source information."

    return DUAL_REPORT_PROMPT.format(
        incident_json=json.dumps(incident, indent=2),
        events_json=json.dumps(events[:15], indent=2),  # Limit events
        behavioral_summary=format_behavioral_for_dual(features),
        technique_summary=format_techniques_for_dual(inference),
        key_hint_section=key_section,
        incident_id=incident.get("id", 0),
    )


# =============================================================================
# RESPONSE PARSING
# =============================================================================

def parse_dual_report_response(response_text: str, incident_id: int) -> DualReport:
    """
    Parse LLM response into DualReport.

    Args:
        response_text: Raw LLM response
        incident_id: Expected incident ID

    Returns:
        DualReport with both executive and engineer reports

    Raises:
        ValueError: If response cannot be parsed
    """
    # Clean response
    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        cleaned = "\n".join(
            line for line in lines if not line.strip().startswith("```")
        ).strip()

    # Find JSON
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON found in response")

    payload = json.loads(cleaned[start:end + 1])

    # Extract reports
    exec_data = payload.get("executive_report", {})
    eng_data = payload.get("engineer_report", {})

    if not exec_data or not eng_data:
        raise ValueError("Missing executive_report or engineer_report")

    # Build ExecutiveReport
    executive = ExecutiveReport(
        incident_id=exec_data.get("incident_id", incident_id),
        severity=exec_data.get("severity", "Medium"),
        risk_level=exec_data.get("risk_level", "Moderate"),
        what_happened=exec_data.get("what_happened", ""),
        business_impact=exec_data.get("business_impact", ""),
        threat_contained=exec_data.get("threat_contained", True),
        key_findings=exec_data.get("key_findings", []),
        recommended_decisions=exec_data.get("recommended_decisions", []),
    )

    # Build EngineerReport
    engineer = EngineerReport(
        incident_id=eng_data.get("incident_id", incident_id),
        severity=eng_data.get("severity", "Medium"),
        confidence_score=float(eng_data.get("confidence_score", 0.7)),
        summary=eng_data.get("summary", ""),
        techniques=eng_data.get("techniques", []),
        kill_chain_phase=eng_data.get("kill_chain_phase", "Reconnaissance"),
        attacker_sophistication=eng_data.get("attacker_sophistication", "Medium"),
        event_count=int(eng_data.get("event_count", 0)),
        time_window_minutes=float(eng_data.get("time_window_minutes", 0)),
        request_rate_per_minute=float(eng_data.get("request_rate_per_minute", 0)),
        unique_endpoints=int(eng_data.get("unique_endpoints", 0)),
        source_ip=eng_data.get("source_ip", "unknown"),
        user_agents=eng_data.get("user_agents", []),
        targeted_endpoints=eng_data.get("targeted_endpoints", []),
        behavioral_indicators=eng_data.get("behavioral_indicators", []),
        recommended_actions=eng_data.get("recommended_actions", []),
        ioc_list=eng_data.get("ioc_list", []),
    )

    return DualReport(executive=executive, engineer=engineer)


# =============================================================================
# FALLBACK GENERATION (No LLM)
# =============================================================================

def generate_fallback_dual_report(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
) -> DualReport:
    """
    Generate a fallback dual report without LLM.

    Uses heuristic analysis to create both reports.
    """
    features, inference, metrics = extract_context(events)

    # Determine severity from features
    if features.injection_pattern_count > 0:
        severity = "Critical"
        risk_level = "Severe"
    elif features.sensitive_path_hits > 5 or features.enum_score > 0.8:
        severity = "High"
        risk_level = "Significant"
    elif features.enum_score > 0.5 or features.auth_failure_rate > 0.5:
        severity = "Medium"
        risk_level = "Moderate"
    else:
        severity = "Low"
        risk_level = "Minimal"

    incident_id = incident.get("id", 0)
    source_ip = incident.get("source_ip", "unknown")
    event_count = len(events)

    # Executive report
    executive = ExecutiveReport(
        incident_id=incident_id,
        severity=severity,
        risk_level=risk_level,
        what_happened=(
            f"Someone used a leaked credential to probe our systems. "
            f"We detected {event_count} unauthorized access attempts from a single source. "
            f"All activity was contained within our security monitoring environment."
        ),
        business_impact=(
            "The credential exposure indicates a potential security gap in how we store "
            "or share access keys. No production systems were affected."
        ),
        threat_contained=True,
        key_findings=[
            f"Detected {event_count} unauthorized access attempts",
            "Attacker used automated tools to probe multiple endpoints",
            "All attempts were blocked and logged",
            "No data was accessed or exfiltrated",
        ],
        recommended_decisions=[
            "Review how API credentials are stored and shared",
            "Consider rotating potentially exposed credentials",
            "Evaluate if additional security monitoring is needed",
        ],
    )

    # Engineer report
    techniques = [
        f"{t.technique_id}: {t.technique_name}"
        for t in inference.techniques[:4]
    ] if inference.techniques else ["T1595: Active Scanning"]

    engineer = EngineerReport(
        incident_id=incident_id,
        severity=severity,
        confidence_score=inference.confidence_overall,
        summary=(
            f"Honeypot key abuse detected from {source_ip}. "
            f"{event_count} events over {features.time_span_seconds/60:.1f} minutes. "
            f"Automated scanning behavior with {features.enum_score:.0%} enumeration score."
        ),
        techniques=techniques,
        kill_chain_phase=inference.kill_chain_phase,
        attacker_sophistication=inference.attacker_sophistication,
        event_count=event_count,
        time_window_minutes=features.time_span_seconds / 60,
        request_rate_per_minute=features.request_rate_per_minute,
        unique_endpoints=metrics["unique_endpoints"],
        source_ip=source_ip,
        user_agents=metrics["unique_user_agents"],
        targeted_endpoints=metrics["paths"][:5],
        behavioral_indicators=[
            f"Burst score: {features.burst_score:.2f}",
            f"Enumeration score: {features.enum_score:.2f}",
            f"Auth failure rate: {features.auth_failure_rate:.0%}",
            f"Temporal regularity: {features.temporal_regularity:.2f}",
        ],
        recommended_actions=[
            f"Block source IP {source_ip} at WAF/firewall",
            "Rotate the compromised honeypot key",
            "Review access logs for related activity",
            "Update threat intelligence feeds with IOCs",
        ],
        ioc_list=[
            f"IP: {source_ip}",
            f"Key: {incident.get('key_id', 'unknown')}",
        ] + [f"UA: {ua}" for ua in metrics["unique_user_agents"][:3]],
    )

    return DualReport(executive=executive, engineer=engineer)


# =============================================================================
# MAIN API
# =============================================================================

def generate_dual_report(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
    llm_response: Optional[str] = None,
    key_value: Optional[str] = None,
) -> DualReport:
    """
    Generate dual report from incident data.

    If llm_response is provided, parse it. Otherwise generate fallback.

    Args:
        incident: Incident data
        events: Event list
        llm_response: Optional LLM response to parse
        key_value: Optional key for hint lookup

    Returns:
        DualReport with executive and engineer versions
    """
    if llm_response:
        try:
            return parse_dual_report_response(
                llm_response,
                incident.get("id", 0)
            )
        except (ValueError, json.JSONDecodeError):
            # Fall through to fallback
            pass

    return generate_fallback_dual_report(incident, events)


def build_prompt_for_dual_report(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
    key_value: Optional[str] = None,
) -> str:
    """Convenience function to build the prompt."""
    return build_dual_report_prompt(incident, events, key_value)
