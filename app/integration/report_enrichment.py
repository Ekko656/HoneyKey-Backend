"""
SOC Report Enrichment Module.

Merges behavioral analysis with LLM-generated reports to produce
comprehensive, evidence-based SOC reports.

The key principle: LLM provides narrative and recommendations,
behavioral analysis provides quantitative evidence and technique mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from app.detection import (
    BehavioralFeatures,
    TechniqueInferenceResult,
    extract_behavioral_features,
    infer_techniques_heuristic,
    HTTPEvent,
)
from .enhanced_prompt import get_key_hint, KeyHint


@dataclass
class EnrichedSOCReport:
    """
    SOC report enriched with behavioral analysis.

    This extends the base AIReportResponse with additional
    behavioral and technique data.
    """
    # Base fields (from AIReportResponse)
    incident_id: int
    severity: str
    summary: str
    evidence: list[str]
    recommended_actions: list[str]

    # Enrichment fields
    behavioral_features: Optional[dict[str, Any]] = None
    inferred_techniques: Optional[list[dict[str, Any]]] = None
    key_hint: Optional[dict[str, Any]] = None
    confidence_score: float = 0.0
    attacker_sophistication: Optional[str] = None
    kill_chain_phase: Optional[str] = None

    def to_base_format(self) -> dict[str, Any]:
        """Return only base AIReportResponse fields."""
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence,
            "recommended_actions": self.recommended_actions,
        }

    def to_full_format(self) -> dict[str, Any]:
        """Return all fields including enrichments."""
        result = self.to_base_format()
        result.update({
            "behavioral_features": self.behavioral_features,
            "inferred_techniques": self.inferred_techniques,
            "key_hint": self.key_hint,
            "confidence_score": round(self.confidence_score, 2),
            "attacker_sophistication": self.attacker_sophistication,
            "kill_chain_phase": self.kill_chain_phase,
        })
        return result


def enrich_soc_report(
    base_report: dict[str, Any],
    events: list[dict[str, Any]],
    key_value: Optional[str] = None,
) -> EnrichedSOCReport:
    """
    Enrich an LLM-generated SOC report with behavioral analysis.

    Takes the base report from Gemini and adds:
    - Quantitative behavioral features
    - MITRE technique mappings based on behavior
    - Key hint context (if available)
    - Confidence scoring

    Args:
        base_report: The AIReportResponse dict from LLM
        events: List of event dicts from database
        key_value: Optional full key value for hint lookup

    Returns:
        EnrichedSOCReport with all enrichments
    """
    # Convert events to HTTPEvent format
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

    # Extract behavioral features
    features = extract_behavioral_features(http_events)

    # Infer techniques
    inference = infer_techniques_heuristic(features)

    # Get key hint
    key_hint = get_key_hint(key_value)

    # Calculate confidence score
    confidence = inference.confidence_overall
    if key_hint:
        # Adjust confidence based on key hint
        confidence = min(1.0, max(0.0, confidence + key_hint.confidence_modifier))

    return EnrichedSOCReport(
        incident_id=base_report.get("incident_id", 0),
        severity=base_report.get("severity", "Medium"),
        summary=base_report.get("summary", ""),
        evidence=base_report.get("evidence", []),
        recommended_actions=base_report.get("recommended_actions", []),
        behavioral_features=features.to_dict(),
        inferred_techniques=[t.to_dict() for t in inference.techniques],
        key_hint=key_hint.to_dict() if key_hint else None,
        confidence_score=confidence,
        attacker_sophistication=inference.attacker_sophistication,
        kill_chain_phase=inference.kill_chain_phase,
    )


def merge_behavioral_analysis(
    base_report: dict[str, Any],
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
    key_hint: Optional[KeyHint] = None,
) -> dict[str, Any]:
    """
    Merge behavioral analysis into an existing report.

    This can enhance the evidence and recommendations sections
    with behavioral data.

    Args:
        base_report: Original report dict
        features: Extracted behavioral features
        inference: Technique inference results
        key_hint: Optional key hint

    Returns:
        Enhanced report dict
    """
    enhanced = dict(base_report)

    # Enhance evidence with behavioral observations
    behavioral_evidence = []

    if features.burst_score > 0.5:
        behavioral_evidence.append(
            f"Behavioral: Bursty request pattern detected (score: {features.burst_score:.2f})"
        )
    if features.enum_score > 0.5:
        behavioral_evidence.append(
            f"Behavioral: Endpoint enumeration behavior (score: {features.enum_score:.2f})"
        )
    if features.auth_failure_rate > 0.5:
        behavioral_evidence.append(
            f"Behavioral: High auth failure rate ({features.auth_failure_rate:.0%})"
        )
    if features.injection_pattern_count > 0:
        behavioral_evidence.append(
            f"Behavioral: {features.injection_pattern_count} injection pattern(s) in requests"
        )
    if features.sdk_likelihood < 0.2:
        behavioral_evidence.append(
            f"Behavioral: Non-SDK client detected (custom tooling likely)"
        )

    # Add technique evidence
    for technique in inference.techniques[:2]:
        if technique.confidence > 0.6:
            behavioral_evidence.append(
                f"MITRE {technique.technique_id}: {technique.technique_name} "
                f"(confidence: {technique.confidence:.0%})"
            )

    # Add key hint context if available
    if key_hint:
        behavioral_evidence.append(
            f"Key context hint: Possible leak via {key_hint.likely_leak_source} "
            f"(unverified)"
        )

    # Merge evidence (behavioral first, then LLM evidence)
    original_evidence = enhanced.get("evidence", [])
    enhanced["evidence"] = behavioral_evidence + original_evidence

    # Add behavioral metadata
    enhanced["_behavioral_analysis"] = {
        "features_summary": {
            "burst_score": round(features.burst_score, 2),
            "enum_score": round(features.enum_score, 2),
            "auth_failure_rate": round(features.auth_failure_rate, 2),
            "sdk_likelihood": round(features.sdk_likelihood, 2),
            "injection_count": features.injection_pattern_count,
        },
        "techniques": [t.to_dict() for t in inference.techniques],
        "sophistication": inference.attacker_sophistication,
        "kill_chain_phase": inference.kill_chain_phase,
        "confidence": round(inference.confidence_overall, 2),
    }

    if key_hint:
        enhanced["_key_hint"] = {
            "likely_source": key_hint.likely_leak_source,
            "discovery_method": key_hint.suggested_discovery_method,
            "note": "This is a HINT, not definitive. Verify with behavioral evidence.",
        }

    return enhanced


def validate_severity_with_behavior(
    llm_severity: str,
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
) -> tuple[str, str]:
    """
    Validate and potentially adjust LLM severity based on behavior.

    Returns tuple of (final_severity, adjustment_reason).
    If no adjustment needed, reason will be empty.

    Args:
        llm_severity: Severity from LLM report
        features: Behavioral features
        inference: Technique inference

    Returns:
        (final_severity, adjustment_reason)
    """
    severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    llm_level = severity_levels.get(llm_severity.lower(), 2)

    # Calculate behavioral severity
    behavioral_level = 2  # Default medium

    if features.injection_pattern_count > 0:
        behavioral_level = 4  # Injection = critical
    elif features.auth_failure_rate > 0.7 and features.auth_retry_count > 10:
        behavioral_level = 3  # Heavy auth attack = high
    elif features.enum_score > 0.8 and features.sensitive_path_hits > 5:
        behavioral_level = 3  # Heavy enumeration = high
    elif features.burst_score > 0.9 and features.rate_limit_hits > 5:
        behavioral_level = 3  # Possible DoS = high

    # Adjust based on sophistication
    if inference.attacker_sophistication in ("Advanced", "Expert"):
        behavioral_level = min(4, behavioral_level + 1)

    # Compare and decide
    if behavioral_level > llm_level + 1:
        # Behavioral suggests much higher severity
        final_severity = list(severity_levels.keys())[behavioral_level - 1]
        reason = (
            f"Severity upgraded from {llm_severity} to {final_severity} "
            f"based on behavioral evidence"
        )
        return final_severity, reason
    elif llm_level > behavioral_level + 1:
        # LLM might be overreacting - note but don't downgrade
        reason = (
            f"Note: LLM severity ({llm_severity}) may be elevated. "
            f"Behavioral analysis suggests {list(severity_levels.keys())[behavioral_level - 1]}."
        )
        return llm_severity, reason

    return llm_severity, ""


def generate_confidence_explanation(
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
    key_hint: Optional[KeyHint],
) -> str:
    """
    Generate a human-readable explanation of confidence scoring.

    Args:
        features: Behavioral features
        inference: Technique inference
        key_hint: Optional key hint

    Returns:
        Explanation string
    """
    parts = []

    # Base confidence from behavior
    parts.append(
        f"Base confidence from behavioral analysis: {inference.confidence_overall:.0%}"
    )

    # Key factors
    factors = []
    if inference.techniques:
        primary = inference.techniques[0]
        factors.append(f"Primary technique ({primary.technique_id}) confidence: {primary.confidence:.0%}")

    if features.injection_pattern_count > 0:
        factors.append("Injection patterns detected (high confidence indicator)")
    if features.auth_retry_count > 5:
        factors.append(f"Persistent auth failures ({features.auth_retry_count} consecutive)")
    if features.sdk_likelihood < 0.2:
        factors.append("Non-SDK client behavior (likely custom tooling)")

    if factors:
        parts.append("Key factors: " + "; ".join(factors))

    # Key hint adjustment
    if key_hint:
        parts.append(
            f"Key hint adjustment: {key_hint.confidence_modifier:+.0%} "
            f"(if behavior matches {key_hint.likely_leak_source} exposure)"
        )
        parts.append(
            "Note: Key hint is contextual, not definitive. "
            "Behavioral evidence takes precedence."
        )

    return "\n".join(parts)
