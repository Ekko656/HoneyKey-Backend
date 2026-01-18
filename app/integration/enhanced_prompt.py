"""
Enhanced Prompt Builder for HoneyKey SOC Reports.

Combines:
1. Raw incident/event data (from backend)
2. Behavioral feature extraction (from detection module)
3. Key hints (suggestive, NOT definitive)

Key Principle: The honeypot key provides contextual hints about HOW the
attacker likely discovered the key, but actual techniques are inferred
from OBSERVED BEHAVIOR. The key hint increases/decreases confidence
but never overrides behavioral evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from app.detection import (
    BehavioralFeatures,
    HTTPEvent,
    extract_behavioral_features,
    infer_techniques_heuristic,
    TechniqueInferenceResult,
)


@dataclass
class KeyHint:
    """
    Contextual hint based on which honeypot key was used.

    This is NOT definitive - it's a probabilistic hint that adjusts
    confidence but doesn't determine the technique.

    Attributes:
        key_prefix: First part of the key (for identification)
        likely_leak_source: Where the key was probably found
        suggested_discovery_method: How attacker likely found it
        confidence_modifier: Adjustment to behavioral confidence (-0.2 to +0.2)
        hint_text: Human-readable hint for LLM context
    """
    key_prefix: str
    likely_leak_source: str
    suggested_discovery_method: str
    confidence_modifier: float  # -0.2 to +0.2
    hint_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_prefix": self.key_prefix,
            "likely_leak_source": self.likely_leak_source,
            "suggested_discovery_method": self.suggested_discovery_method,
            "confidence_modifier": self.confidence_modifier,
            "hint_text": self.hint_text,
        }


# =============================================================================
# KEY HINT REGISTRY
# These are HINTS, not certainties. Confidence modifiers are small.
# =============================================================================

KEY_HINTS: dict[str, KeyHint] = {
    # Client-side JS exposure (full key and prefix)
    "acme_client_m5n6o7p8q9r0s1t2": KeyHint(
        key_prefix="acme_client_",
        likely_leak_source="client-side JavaScript bundle with source maps",
        suggested_discovery_method="source map extraction or JS analysis",
        confidence_modifier=0.1,  # Slight boost if behavior matches
        hint_text=(
            "This key was planted in client-side JavaScript (dist/app.min.js with source map). "
            "If the attacker found it there, they likely have intermediate technical skills "
            "(source map parsing, understanding of JS build tooling). MITRE: T1552.001 "
            "(Unsecured Credentials: Credentials In Files)."
        ),
    ),
    "acme_client_": KeyHint(
        key_prefix="acme_client_",
        likely_leak_source="client-side JavaScript",
        suggested_discovery_method="source map extraction or JS analysis",
        confidence_modifier=0.1,
        hint_text=(
            "This key was planted in client-side JavaScript. Indicates intermediate "
            "technical skills if found via source map parsing."
        ),
    ),
    # Debug log exposure (full key and prefix)
    "acme_debug_a1b2c3d4e5f6g7h8": KeyHint(
        key_prefix="acme_debug_",
        likely_leak_source="application debug logs (/var/log/acme/debug.log)",
        suggested_discovery_method="log file access or log aggregation compromise",
        confidence_modifier=0.15,  # Higher modifier - log access is significant
        hint_text=(
            "This key was planted in application debug logs. If found there, it suggests "
            "the attacker has SYSTEM ACCESS (serious security breach). This is HIGH severity "
            "as it indicates prior foothold. MITRE: T1552.001 + T1083 (File Discovery)."
        ),
    ),
    "acme_debug_": KeyHint(
        key_prefix="acme_debug_",
        likely_leak_source="application debug logs",
        suggested_discovery_method="log file access or log aggregation compromise",
        confidence_modifier=0.15,
        hint_text=(
            "This key was planted in debug logs. Suggests system access if found there."
        ),
    ),
    # Docker/infrastructure exposure (full key and prefix)
    "acme_docker_j4k5l6m7n8o9p0q1": KeyHint(
        key_prefix="acme_docker_",
        likely_leak_source="docker-compose.yml in public GitHub repository",
        suggested_discovery_method="GitHub dorking or automated repository scanning",
        confidence_modifier=0.05,  # Low modifier - very common attack vector
        hint_text=(
            "This key was planted in docker-compose.yml committed to a public repo. "
            "GitHub dorking is a NOVICE-level technique with automated tools (truffleHog). "
            "Low sophistication but still indicates active reconnaissance. "
            "MITRE: T1552.004 + T1593.003 (Search Code Repositories)."
        ),
    ),
    "acme_docker_": KeyHint(
        key_prefix="acme_docker_",
        likely_leak_source="infrastructure config (docker-compose, env files)",
        suggested_discovery_method="GitHub dorking or repository scanning",
        confidence_modifier=0.05,
        hint_text=(
            "This key was planted in infrastructure config files. Common, low-skill technique."
        ),
    ),
}


def get_key_hint(key_value: Optional[str]) -> Optional[KeyHint]:
    """
    Get the hint associated with a honeypot key.

    Returns None if the key is unknown or doesn't match any pattern.
    The hint is SUGGESTIVE, not definitive.

    Args:
        key_value: The full key value or key_id

    Returns:
        KeyHint if matched, None otherwise
    """
    if not key_value:
        return None

    # Check for exact match first (full key values)
    if key_value in KEY_HINTS:
        return KEY_HINTS[key_value]

    # Then match by prefix
    for prefix, hint in KEY_HINTS.items():
        if key_value.startswith(prefix):
            return hint

    # Also check for key_id values like "honeypot"
    if key_value == "honeypot":
        # Generic honeypot - no specific hint
        return None

    return None


def register_key_hint(
    key_prefix: str,
    likely_leak_source: str,
    suggested_discovery_method: str,
    confidence_modifier: float = 0.1,
    hint_text: str = "",
) -> None:
    """
    Register a new key hint at runtime.

    Args:
        key_prefix: Prefix to match (e.g., "acme_prod_")
        likely_leak_source: Where the key was probably exposed
        suggested_discovery_method: How attacker likely found it
        confidence_modifier: Adjustment (-0.2 to 0.2)
        hint_text: Human-readable context for LLM
    """
    # Clamp confidence modifier
    confidence_modifier = max(-0.2, min(0.2, confidence_modifier))

    KEY_HINTS[key_prefix] = KeyHint(
        key_prefix=key_prefix,
        likely_leak_source=likely_leak_source,
        suggested_discovery_method=suggested_discovery_method,
        confidence_modifier=confidence_modifier,
        hint_text=hint_text or f"Key planted in {likely_leak_source}.",
    )


# =============================================================================
# BEHAVIORAL CONTEXT CREATION
# =============================================================================

def create_behavioral_context(
    events: list[dict[str, Any]],
) -> tuple[BehavioralFeatures, TechniqueInferenceResult]:
    """
    Extract behavioral features and infer techniques from events.

    Args:
        events: List of event dictionaries from the database

    Returns:
        Tuple of (BehavioralFeatures, TechniqueInferenceResult)
    """
    # Convert database events to HTTPEvent format
    http_events = []
    for e in events:
        http_events.append(HTTPEvent(
            timestamp=e.get("ts", ""),
            ip=e.get("ip", "unknown"),
            method=e.get("method", "GET"),
            path=e.get("path", "/"),
            status_code=401,  # Honeypot always returns 401
            user_agent=e.get("user_agent"),
        ))

    # Extract features
    features = extract_behavioral_features(http_events)

    # Infer techniques (heuristic - no LLM needed here)
    inference = infer_techniques_heuristic(features)

    return features, inference


# =============================================================================
# ENHANCED PROMPT BUILDER
# =============================================================================

ENHANCED_PROMPT_TEMPLATE = """You are a senior SOC analyst generating an incident report for a honeypot detection system.

=== INCIDENT DATA ===
{incident_json}

=== RECENT EVENTS ===
{events_json}

=== BEHAVIORAL ANALYSIS ===
The following behavioral patterns were extracted from the request sequence:

{behavioral_summary}

=== TECHNIQUE INFERENCE (Pre-computed) ===
Based on OBSERVED BEHAVIOR (not key identity), the following MITRE ATT&CK techniques are likely:

{technique_summary}

=== KEY CONTEXT HINT ===
{key_hint_section}

=== IMPORTANT INSTRUCTIONS ===
1. Base your analysis PRIMARILY on the behavioral evidence above
2. The key hint provides CONTEXT but is NOT definitive proof of technique
3. If behavioral evidence contradicts the key hint, trust the behavior
4. Assign confidence scores realistically (most should be 0.5-0.85)

Generate a JSON report with this exact structure:
{{
    "incident_id": {incident_id},
    "severity": "Low|Medium|High|Critical",
    "confidence_score": 0.0-1.0,
    "summary": "2-3 sentence executive summary",
    "evidence": ["evidence point 1", "evidence point 2", ...],
    "techniques": ["Technique ID: Name", ...],
    "recommended_actions": ["action 1", "action 2", ...]
}}

Rules:
- severity should match the behavioral risk level
- confidence_score should reflect certainty in the attribution (float)
- evidence should cite SPECIFIC behavioral observations
- techniques should list MITRE ATT&CK techniques inferred from behavior (e.g. "T1595: Active Scanning")
- recommended_actions should be actionable and specific
- Return ONLY valid JSON, no markdown or code fences

Generate the report now:"""


def format_behavioral_summary(features: BehavioralFeatures) -> str:
    """Format behavioral features for the prompt."""
    lines = []

    # Temporal
    if features.burst_score > 0.5:
        lines.append(f"• Bursty request pattern (score: {features.burst_score:.2f})")
    if features.request_rate_per_minute > 30:
        lines.append(f"• High request rate: {features.request_rate_per_minute:.1f}/minute")
    if features.temporal_regularity > 0.7:
        lines.append(f"• Automated/scripted timing detected (regularity: {features.temporal_regularity:.2f})")

    # Endpoint
    if features.enum_score > 0.5:
        lines.append(f"• Endpoint enumeration behavior (score: {features.enum_score:.2f})")
    if features.sensitive_path_hits > 0:
        lines.append(f"• Sensitive paths probed: {features.sensitive_path_hits} hits")
    if features.unique_paths_ratio > 0.7:
        lines.append(f"• High path diversity: {features.unique_paths_ratio:.0%} unique paths")

    # Auth
    if features.auth_failure_rate > 0.3:
        lines.append(f"• Authentication failure rate: {features.auth_failure_rate:.0%}")
    if features.auth_retry_count > 3:
        lines.append(f"• Consecutive auth failures: {features.auth_retry_count}")

    # Client
    if features.sdk_likelihood < 0.2:
        lines.append(f"• Non-SDK client suspected (SDK likelihood: {features.sdk_likelihood:.2f})")
    if features.header_anomaly_score > 0.3:
        lines.append(f"• Header anomalies detected")

    # Injection
    if features.injection_pattern_count > 0:
        lines.append(f"• CRITICAL: {features.injection_pattern_count} injection pattern(s) detected")

    # Rate limiting
    if features.rate_limit_hits > 0:
        lines.append(f"• Rate limiting triggered: {features.rate_limit_hits} times")

    if not lines:
        lines.append("• No significant anomalies detected in behavioral patterns")

    return "\n".join(lines)


def format_technique_summary(inference: TechniqueInferenceResult) -> str:
    """Format technique inference for the prompt."""
    if not inference.techniques:
        return "No specific techniques identified from behavior alone."

    lines = []
    for t in inference.techniques[:4]:
        lines.append(
            f"• {t.technique_id} ({t.technique_name}) - "
            f"Confidence: {t.confidence:.0%}\n"
            f"  Evidence: {', '.join(t.evidence[:2])}"
        )

    lines.append(f"\nOverall assessment:")
    lines.append(f"• Attacker sophistication: {inference.attacker_sophistication}")
    lines.append(f"• Kill chain phase: {inference.kill_chain_phase}")
    lines.append(f"• Analysis confidence: {inference.confidence_overall:.0%}")

    return "\n".join(lines)


def format_key_hint_section(key_hint: Optional[KeyHint], key_id: str) -> str:
    """Format the key hint section for the prompt."""
    if not key_hint:
        return (
            f"Key identifier: {key_id}\n"
            "No specific leak source information available for this key.\n"
            "Base your analysis entirely on observed behavior."
        )

    return f"""Key identifier: {key_id}
Possible leak source: {key_hint.likely_leak_source}
Suggested discovery method: {key_hint.suggested_discovery_method}

IMPORTANT: {key_hint.hint_text}

This hint adjusts confidence by {key_hint.confidence_modifier:+.0%} IF behavioral evidence supports it.
Do NOT assume this is how the attacker found the key - verify with behavioral evidence."""


def build_enhanced_prompt(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
    key_value: Optional[str] = None,
) -> str:
    """
    Build an enhanced prompt combining incident data, behavioral analysis, and key hints.

    This is the main function to replace/augment the backend's build_prompt().

    Args:
        incident: Incident data from database (dict with id, key_id, source_ip, etc.)
        events: List of event dicts from database
        key_value: Optional full key value (for hint lookup)

    Returns:
        Enhanced prompt string for LLM
    """
    # Extract behavioral context
    features, inference = create_behavioral_context(events)

    # Get key hint (if available)
    key_id = incident.get("key_id", "unknown")
    key_hint = get_key_hint(key_value) or get_key_hint(key_id)

    # Build prompt
    return ENHANCED_PROMPT_TEMPLATE.format(
        incident_json=json.dumps(incident, indent=2),
        events_json=json.dumps(events, indent=2),
        behavioral_summary=format_behavioral_summary(features),
        technique_summary=format_technique_summary(inference),
        key_hint_section=format_key_hint_section(key_hint, key_id),
        incident_id=incident.get("id", 0),
    )


def build_enhanced_prompt_from_rows(
    incident_row,
    event_rows: list,
    key_value: Optional[str] = None,
) -> str:
    """
    Build enhanced prompt from SQLite Row objects.

    Convenience function for direct integration with backend.

    Args:
        incident_row: sqlite3.Row for incident
        event_rows: List of sqlite3.Row for events
        key_value: Optional full key value

    Returns:
        Enhanced prompt string
    """
    incident = dict(incident_row)
    events = [
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
        for row in event_rows
    ]
    return build_enhanced_prompt(incident, events, key_value)
