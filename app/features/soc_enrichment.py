"""
SOC Report Enrichment Module.

Enhances LLM prompts with honeypot key metadata to generate more accurate,
contextual, and actionable SOC reports.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from .key_metadata import (
    HONEYPOT_KEYS,
    HoneypotKeyMetadata,
    Severity,
    Sophistication,
    get_confidence_label,
    get_key_metadata,
    get_severity_level,
)


# =============================================================================
# EVIDENCE GENERATION
# =============================================================================

def format_evidence_from_metadata(
    key: str,
    source_ip: str,
    endpoint: str,
    user_agent: Optional[str] = None,
    event_count: int = 1,
    timestamp: Optional[str] = None,
) -> list[str]:
    """
    Generate evidence bullet points based on key metadata.

    Returns structured evidence that the LLM can incorporate directly.
    """
    metadata = get_key_metadata(key)
    if not metadata:
        return [f"Unknown key '{key[:20]}...' used from IP {source_ip}"]

    evidence = []

    # Key identification
    evidence.append(
        f"Honeypot key `{metadata.key_id}` ({key[:12]}...) was used - "
        f"designated for {metadata.leak_source.type.value.replace('_', ' ')} exposure"
    )

    # Leak source context
    evidence.append(
        f"Key was planted at: {metadata.leak_source.location}"
    )

    # Discovery method implication
    evidence.append(
        f"Usage implies attacker performed: {metadata.leak_source.discovery_method.replace('_', ' ')}"
    )

    # Source IP
    evidence.append(f"Source IP: {source_ip}")

    # Target endpoint
    evidence.append(f"Targeted endpoint: {endpoint}")

    # User agent if available
    if user_agent:
        if "python" in user_agent.lower() or "curl" in user_agent.lower():
            evidence.append(
                f"User-Agent '{user_agent}' suggests scripted/automated attack"
            )
        elif "scanner" in user_agent.lower():
            evidence.append(
                f"User-Agent '{user_agent}' indicates security scanning tool"
            )
        else:
            evidence.append(f"User-Agent: {user_agent}")

    # Event count
    if event_count > 1:
        evidence.append(f"Attacker made {event_count} requests in this incident window")

    # Timestamp
    if timestamp:
        evidence.append(f"First detected: {timestamp}")

    # Confidence statement
    evidence.append(
        f"Confidence: {get_confidence_label(metadata.confidence_score)} "
        f"({int(metadata.confidence_score * 100)}%) - {metadata.confidence_reasoning}"
    )

    return evidence


def generate_recommendations_from_metadata(
    key: str,
    source_ip: str,
    event_count: int = 1,
) -> list[str]:
    """
    Generate actionable recommendations based on key metadata.

    Recommendations are tailored to the leak source and attacker sophistication.
    """
    metadata = get_key_metadata(key)
    if not metadata:
        return [
            f"Block source IP {source_ip}",
            "Investigate unknown key usage",
            "Review authentication logs",
        ]

    recommendations = []
    leak_type = metadata.leak_source.type.value
    sophistication = metadata.attacker_profile.sophistication

    # Immediate actions (always included)
    recommendations.append(f"IMMEDIATE: Block source IP {source_ip} at perimeter firewall")

    # Leak-source-specific remediation
    if leak_type == "client_side_js":
        recommendations.append(
            "IMMEDIATE: Review and rotate any API keys in client-side JavaScript"
        )
        recommendations.append(
            "24 HOURS: Audit build pipeline for source map exposure"
        )
        recommendations.append(
            "ONGOING: Implement client-side key obfuscation or proxy pattern"
        )

    elif leak_type == "application_logs":
        recommendations.append(
            "IMMEDIATE: Rotate all credentials that may appear in logs"
        )
        recommendations.append(
            "IMMEDIATE: Isolate and investigate log aggregation infrastructure"
        )
        recommendations.append(
            "24 HOURS: Implement credential scrubbing in logging pipeline"
        )
        recommendations.append(
            "72 HOURS: Audit log access permissions and retention policies"
        )

    elif leak_type == "infrastructure_config":
        recommendations.append(
            "IMMEDIATE: Rotate all credentials in configuration files"
        )
        recommendations.append(
            "24 HOURS: Scan git history for committed secrets (use truffleHog/gitleaks)"
        )
        recommendations.append(
            "24 HOURS: Enable GitHub secret scanning alerts"
        )
        recommendations.append(
            "ONGOING: Implement pre-commit hooks to prevent secret commits"
        )

    elif leak_type == "git_history":
        recommendations.append(
            "IMMEDIATE: Rotate all credentials found in git history"
        )
        recommendations.append(
            "24 HOURS: Consider repository history rewrite if highly sensitive"
        )
        recommendations.append(
            "ONGOING: Implement BFG Repo-Cleaner for secret removal"
        )

    # Sophistication-based recommendations
    if sophistication in (Sophistication.ADVANCED, Sophistication.EXPERT):
        recommendations.append(
            "ESCALATE: Advanced attacker detected - engage incident response team"
        )
        recommendations.append(
            "72 HOURS: Conduct full compromise assessment of related systems"
        )

    # Event-count-based recommendations
    if event_count >= 10:
        recommendations.append(
            "HIGH PRIORITY: Persistent attacker - consider active threat hunting"
        )

    return recommendations


# =============================================================================
# PROMPT ENRICHMENT
# =============================================================================

def enrich_prompt_with_metadata(key: str) -> str:
    """
    Generate metadata context block for LLM prompt injection.

    Returns a formatted string to prepend to the incident prompt.
    """
    metadata = get_key_metadata(key)
    if not metadata:
        return "No metadata available for this key."

    return f"""
=== HONEYPOT KEY INTELLIGENCE ===
Key ID: {metadata.key_id}
Leak Source Type: {metadata.leak_source.type.value}
Leak Location: {metadata.leak_source.location}
Discovery Method: {metadata.leak_source.discovery_method}
Exposure Context: {metadata.leak_source.exposure_context}

MITRE ATT&CK Mapping:
- Primary: {metadata.mitre_technique.technique_id} - {metadata.mitre_technique.technique_name}
- Tactic: {metadata.mitre_technique.tactic}
{f"- Secondary: {metadata.mitre_technique.secondary_id} - {metadata.mitre_technique.secondary_name}" if metadata.mitre_technique.secondary_id else ""}

Attacker Profile:
- Sophistication: {metadata.attacker_profile.sophistication.value} ({metadata.attacker_profile.sophistication_score}/10)
- Assessment: {metadata.attacker_profile.reasoning}

Confidence Assessment:
- Score: {int(metadata.confidence_score * 100)}% ({get_confidence_label(metadata.confidence_score)})
- Basis: {metadata.confidence_reasoning}

Base Severity: {metadata.base_severity.value.upper()}
=================================
"""


def build_enriched_soc_prompt(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
    key_used: Optional[str] = None,
) -> str:
    """
    Build a complete enriched prompt for SOC report generation.

    This replaces the basic prompt builder with metadata-enriched context.

    Args:
        incident: Incident data from database
        events: List of event data from database
        key_used: The honeypot key used (extracted from events if not provided)

    Returns:
        Complete prompt string for LLM
    """
    # Extract key from events if not provided
    if not key_used:
        for event in events:
            if event.get("honeypot_key_used"):
                # Try to find the actual key value from the incident
                break

    # Get metadata enrichment
    metadata_context = ""
    metadata = None
    if key_used:
        metadata = get_key_metadata(key_used)
        metadata_context = enrich_prompt_with_metadata(key_used)

    # Calculate severity
    severity = get_severity_level(key_used, incident.get("event_count", 1)) if key_used else Severity.MEDIUM

    # Build event summaries
    event_summaries = []
    for event in events[:25]:  # Limit to 25 events
        event_summaries.append({
            "ts": event.get("ts"),
            "ip": event.get("ip"),
            "method": event.get("method"),
            "path": event.get("path"),
            "user_agent": event.get("user_agent"),
        })

    # Generate pre-computed evidence and recommendations
    source_ip = incident.get("source_ip", "unknown")
    first_event = events[0] if events else {}

    pre_evidence = []
    pre_recommendations = []
    if key_used and metadata:
        pre_evidence = format_evidence_from_metadata(
            key=key_used,
            source_ip=source_ip,
            endpoint=first_event.get("path", "/unknown"),
            user_agent=first_event.get("user_agent"),
            event_count=incident.get("event_count", 1),
            timestamp=incident.get("first_seen"),
        )
        pre_recommendations = generate_recommendations_from_metadata(
            key=key_used,
            source_ip=source_ip,
            event_count=incident.get("event_count", 1),
        )

    prompt = f"""You are a senior SOC analyst generating an incident report for a honeypot detection system.

{metadata_context}

=== INCIDENT DATA ===
Incident ID: {incident.get("id")}
Source IP: {source_ip}
First Seen: {incident.get("first_seen")}
Last Seen: {incident.get("last_seen")}
Event Count: {incident.get("event_count")}
Calculated Severity: {severity.value.upper()}

=== RECENT EVENTS ===
{json.dumps(event_summaries, indent=2)}

=== PRE-COMPUTED EVIDENCE ===
{json.dumps(pre_evidence, indent=2)}

=== PRE-COMPUTED RECOMMENDATIONS ===
{json.dumps(pre_recommendations, indent=2)}

=== INSTRUCTIONS ===
Generate a SOC incident report in JSON format with these exact keys:
- incident_id (int): {incident.get("id")}
- severity (string): Use "{severity.value}" based on the analysis
- summary (string): 2-3 sentence executive summary explaining what happened and why it matters
- evidence (list of strings): Use and expand on the pre-computed evidence above
- recommended_actions (list of strings): Use and expand on the pre-computed recommendations above

IMPORTANT:
- Return ONLY valid JSON. No markdown. No code fences.
- Use the MITRE ATT&CK mapping in your analysis
- Reference the leak source to explain how the attacker likely found the key
- Tailor severity and urgency to the attacker sophistication level
- Make recommendations specific and actionable

Generate the report now:"""

    return prompt


def get_severity_from_metadata(
    key: str,
    event_count: int = 1,
    is_repeat_offender: bool = False,
) -> dict[str, Any]:
    """
    Get comprehensive severity assessment for an incident.

    Returns a dict with severity level, score, and justification.
    """
    metadata = get_key_metadata(key)
    if not metadata:
        return {
            "level": "medium",
            "score": 5,
            "justification": "Unknown key - defaulting to medium severity",
        }

    base_severity = metadata.base_severity
    sophistication = metadata.attacker_profile.sophistication_score
    confidence = metadata.confidence_score

    # Calculate numeric score (1-10)
    score = 5  # Base

    # Adjust for base severity
    if base_severity == Severity.LOW:
        score = 3
    elif base_severity == Severity.MEDIUM:
        score = 5
    elif base_severity == Severity.HIGH:
        score = 7
    elif base_severity == Severity.CRITICAL:
        score = 9

    # Adjust for sophistication
    if sophistication >= 8:
        score += 1
    elif sophistication >= 6:
        score += 0.5

    # Adjust for event count
    if event_count >= 10:
        score += 1
    elif event_count >= 5:
        score += 0.5

    # Adjust for repeat offender
    if is_repeat_offender:
        score += 1

    # Adjust for confidence
    score *= confidence

    # Clamp to 1-10
    score = max(1, min(10, round(score)))

    # Determine final level
    if score >= 9:
        level = "critical"
    elif score >= 7:
        level = "high"
    elif score >= 4:
        level = "medium"
    else:
        level = "low"

    # Build justification
    factors = []
    factors.append(f"Base severity from leak source: {base_severity.value}")
    factors.append(f"Attacker sophistication: {metadata.attacker_profile.sophistication.value}")
    factors.append(f"Event count: {event_count}")
    if is_repeat_offender:
        factors.append("Repeat offender IP detected")
    factors.append(f"Confidence: {get_confidence_label(confidence)}")

    return {
        "level": level,
        "score": score,
        "justification": "; ".join(factors),
    }
