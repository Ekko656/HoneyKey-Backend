"""
Behavioral SOC Report Generator.

Produces SOC-ready output from behavioral analysis that integrates
with HoneyKey's existing incident model and report generator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .behavior_features import BehavioralFeatures, ContextualHints, HTTPEvent
from .technique_inference import (
    InferredTechnique,
    TechniqueInferenceResult,
    infer_techniques_heuristic,
)


@dataclass
class RiskAssessment:
    """
    Risk assessment based on behavioral analysis.

    Attributes:
        level: Risk level (low, medium, high, critical)
        score: Numeric risk score 0-100
        factors: Contributing risk factors
        trend: Risk trend if historical data available
    """
    level: str
    score: int
    factors: list[str]
    trend: Optional[str] = None  # "increasing", "stable", "decreasing"

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "score": self.score,
            "factors": self.factors,
            "trend": self.trend,
        }


@dataclass
class RecommendedResponse:
    """
    Recommended response actions based on analysis.

    Attributes:
        priority: Response priority (immediate, high, medium, low)
        actions: List of recommended actions
        automation_hints: Actions suitable for automation
    """
    priority: str
    actions: list[str]
    automation_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "actions": self.actions,
            "automation_hints": self.automation_hints,
        }


@dataclass
class BehavioralSOCReport:
    """
    Complete SOC-ready report from behavioral analysis.

    This is the primary output format for integration with HoneyKey's
    existing SOC report generator.

    Compatible with HoneyKey's AIReportResponse structure.
    """
    # Core identification
    incident_id: Optional[int]
    analysis_timestamp: str
    source_ip: str

    # Severity (matches HoneyKey's format)
    severity: str  # "low", "medium", "high", "critical"

    # Summary (matches HoneyKey's format)
    summary: str

    # Evidence (matches HoneyKey's format - list of strings)
    evidence: list[str]

    # Recommended actions (matches HoneyKey's format - list of strings)
    recommended_actions: list[str]

    # Extended behavioral analysis
    techniques: list[dict[str, Any]]  # MITRE techniques
    attacker_sophistication: str
    kill_chain_phase: str
    confidence: float

    # Detailed assessments
    risk_assessment: dict[str, Any]
    behavioral_features: dict[str, Any]

    # Metadata
    analysis_method: str  # "llm", "heuristic"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary matching HoneyKey's expected format."""
        return {
            # Core HoneyKey AIReportResponse fields
            "incident_id": self.incident_id,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence,
            "recommended_actions": self.recommended_actions,
            # Extended fields
            "analysis_timestamp": self.analysis_timestamp,
            "source_ip": self.source_ip,
            "techniques": self.techniques,
            "attacker_sophistication": self.attacker_sophistication,
            "kill_chain_phase": self.kill_chain_phase,
            "confidence": round(self.confidence, 2),
            "risk_assessment": self.risk_assessment,
            "behavioral_features": self.behavioral_features,
            "analysis_method": self.analysis_method,
        }

    def to_honeykey_format(self) -> dict[str, Any]:
        """
        Convert to HoneyKey's AIReportResponse-compatible format.

        This returns only the fields expected by the existing HoneyKey
        SOC report structure.
        """
        return {
            "incident_id": self.incident_id or 0,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence,
            "recommended_actions": self.recommended_actions,
        }


# =============================================================================
# RISK ASSESSMENT
# =============================================================================

def assess_risk(
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
) -> RiskAssessment:
    """
    Assess risk level from behavioral features and technique inference.

    Args:
        features: Extracted behavioral features
        inference: Technique inference results

    Returns:
        RiskAssessment with level, score, and factors
    """
    score = 0
    factors = []

    # Factor 1: Injection attempts (highest weight)
    if features.injection_pattern_count > 0:
        score += 35
        factors.append(f"Injection patterns detected ({features.injection_pattern_count})")

    # Factor 2: Authentication attacks
    if features.auth_failure_rate > 0.5:
        score += 25
        factors.append(f"High auth failure rate ({features.auth_failure_rate:.0%})")
    elif features.auth_retry_count > 5:
        score += 15
        factors.append(f"Persistent auth failures ({features.auth_retry_count} consecutive)")

    # Factor 3: Enumeration behavior
    if features.enum_score > 0.7:
        score += 20
        factors.append(f"Active enumeration detected (score: {features.enum_score:.2f})")
    elif features.sensitive_path_hits > 3:
        score += 15
        factors.append(f"Sensitive paths probed ({features.sensitive_path_hits})")

    # Factor 4: Request rate/burst
    if features.request_rate_per_minute > 100:
        score += 15
        factors.append(f"High request rate ({features.request_rate_per_minute:.0f}/min)")
    elif features.burst_score > 0.8:
        score += 10
        factors.append(f"Bursty request pattern (score: {features.burst_score:.2f})")

    # Factor 5: Attacker sophistication
    if inference.attacker_sophistication in ("Advanced", "Expert"):
        score += 10
        factors.append(f"Sophisticated attacker ({inference.attacker_sophistication})")

    # Factor 6: Technique confidence
    if inference.techniques and inference.techniques[0].confidence > 0.8:
        score += 5
        factors.append("High-confidence technique identification")

    # Factor 7: Non-SDK tooling
    if features.sdk_likelihood < 0.1 and features.header_anomaly_score > 0.3:
        score += 10
        factors.append("Custom/malicious tooling suspected")

    # Cap at 100
    score = min(100, score)

    # Determine level
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return RiskAssessment(
        level=level,
        score=score,
        factors=factors,
    )


# =============================================================================
# EVIDENCE GENERATION
# =============================================================================

def generate_evidence_summary(
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
    events: Optional[list[HTTPEvent]] = None,
) -> list[str]:
    """
    Generate evidence summary as list of strings.

    This matches HoneyKey's expected evidence format.

    Args:
        features: Behavioral features
        inference: Technique inference
        events: Optional raw events for additional context

    Returns:
        List of evidence strings
    """
    evidence = []

    # Temporal evidence
    if features.burst_score > 0.5:
        evidence.append(
            f"Bursty request pattern detected (burst score: {features.burst_score:.2f})"
        )
    if features.request_rate_per_minute > 30:
        evidence.append(
            f"Elevated request rate: {features.request_rate_per_minute:.1f} requests/minute"
        )
    if features.temporal_regularity > 0.7:
        evidence.append(
            f"Automated/scripted timing pattern (regularity: {features.temporal_regularity:.2f})"
        )

    # Endpoint evidence
    if features.enum_score > 0.5:
        evidence.append(
            f"Endpoint enumeration behavior (score: {features.enum_score:.2f}, "
            f"unique path ratio: {features.unique_paths_ratio:.2f})"
        )
    if features.sensitive_path_hits > 0:
        evidence.append(
            f"Sensitive paths accessed: {features.sensitive_path_hits} hits on "
            f"paths like /admin, /.env, /config"
        )

    # Authentication evidence
    if features.auth_failure_rate > 0.3:
        evidence.append(
            f"Authentication failures: {features.auth_failure_rate:.0%} of requests "
            f"returned 401/403"
        )
    if features.auth_retry_count > 3:
        evidence.append(
            f"Credential testing: {features.auth_retry_count} consecutive "
            f"authentication failures"
        )

    # Client evidence
    if features.sdk_likelihood < 0.2:
        evidence.append(
            f"Non-SDK client detected (SDK likelihood: {features.sdk_likelihood:.2f})"
        )
    if features.header_anomaly_score > 0.3:
        evidence.append(
            f"Header anomalies detected (missing User-Agent, unusual patterns)"
        )

    # Injection evidence
    if features.injection_pattern_count > 0:
        evidence.append(
            f"CRITICAL: {features.injection_pattern_count} injection pattern(s) "
            f"detected in request paths"
        )

    # Rate limiting evidence
    if features.rate_limit_hits > 0:
        evidence.append(
            f"Rate limiting triggered: {features.rate_limit_hits} requests "
            f"received 429 responses"
        )

    # Technique-specific evidence
    for technique in inference.techniques[:3]:
        if technique.confidence > 0.6:
            evidence.append(
                f"MITRE {technique.technique_id}: {technique.technique_name} - "
                f"{technique.reasoning[:100]}..."
                if len(technique.reasoning) > 100 else
                f"MITRE {technique.technique_id}: {technique.technique_name} - "
                f"{technique.reasoning}"
            )

    return evidence


# =============================================================================
# RECOMMENDATION GENERATION
# =============================================================================

def generate_recommendations(
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
    risk: RiskAssessment,
    source_ip: str,
) -> RecommendedResponse:
    """
    Generate recommended response actions.

    Args:
        features: Behavioral features
        inference: Technique inference
        risk: Risk assessment
        source_ip: Source IP for recommendations

    Returns:
        RecommendedResponse with prioritized actions
    """
    actions = []
    automation_hints = []

    # Priority based on risk level
    if risk.level == "critical":
        priority = "immediate"
        actions.append(f"IMMEDIATE: Block source IP {source_ip} at perimeter firewall")
        automation_hints.append(f"block_ip:{source_ip}")
    elif risk.level == "high":
        priority = "high"
        actions.append(f"HIGH: Consider blocking IP {source_ip}")
        automation_hints.append(f"alert:high:{source_ip}")
    elif risk.level == "medium":
        priority = "medium"
        actions.append(f"Monitor source IP {source_ip} for continued activity")
    else:
        priority = "low"
        actions.append(f"Log activity from {source_ip} for baseline tracking")

    # Injection-specific recommendations
    if features.injection_pattern_count > 0:
        actions.insert(0, "CRITICAL: Investigate injection attempts - active exploitation likely")
        actions.append("Review and enhance WAF rules for injection patterns")
        actions.append("Audit application input validation")
        automation_hints.append("escalate:security_team")

    # Auth attack recommendations
    if features.auth_failure_rate > 0.5 or features.auth_retry_count > 5:
        actions.append("Review API key rotation and validity")
        actions.append("Check for credential exposure in logs/repositories")
        actions.append("Consider implementing progressive rate limiting on auth failures")
        automation_hints.append("check:credential_exposure")

    # Enumeration recommendations
    if features.enum_score > 0.6:
        actions.append("Audit API documentation and endpoint exposure")
        actions.append("Review rate limiting configuration")
        actions.append("Consider implementing path-based anomaly detection")

    # Rate limit recommendations
    if features.rate_limit_hits > 3:
        actions.append("Review and potentially tighten rate limit thresholds")
        automation_hints.append("adjust:rate_limits")

    # Sophistication-based recommendations
    if inference.attacker_sophistication in ("Advanced", "Expert"):
        actions.append("ESCALATE: Advanced threat actor - engage incident response team")
        actions.append("Preserve all logs for forensic analysis")
        actions.append("Review for potential lateral movement indicators")
        automation_hints.append("escalate:ir_team")

    # Kill chain phase recommendations
    if inference.kill_chain_phase == "Initial Access":
        actions.append("Immediate application security review required")
        actions.append("Validate all authentication mechanisms")
    elif inference.kill_chain_phase == "Credential Access":
        actions.append("Rotate potentially compromised credentials")
        actions.append("Enable enhanced authentication logging")

    return RecommendedResponse(
        priority=priority,
        actions=actions,
        automation_hints=automation_hints,
    )


# =============================================================================
# SUMMARY GENERATION
# =============================================================================

def generate_summary(
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
    risk: RiskAssessment,
    source_ip: str,
) -> str:
    """
    Generate executive summary for SOC report.

    Args:
        features: Behavioral features
        inference: Technique inference
        risk: Risk assessment
        source_ip: Source IP

    Returns:
        Summary string (2-3 sentences)
    """
    # Build summary based on most significant findings
    parts = []

    # Opening with severity
    severity_desc = {
        "critical": "CRITICAL threat activity",
        "high": "High-risk activity",
        "medium": "Suspicious activity",
        "low": "Low-risk activity",
    }
    parts.append(f"{severity_desc[risk.level]} detected from {source_ip}.")

    # Primary technique
    if inference.techniques:
        primary = inference.techniques[0]
        parts.append(
            f"Behavioral analysis indicates {primary.technique_name} "
            f"({primary.technique_id}) with {primary.confidence:.0%} confidence."
        )

    # Key behavioral indicator
    if features.injection_pattern_count > 0:
        parts.append(
            f"Active exploitation detected with {features.injection_pattern_count} "
            f"injection patterns in requests."
        )
    elif features.auth_failure_rate > 0.5:
        parts.append(
            f"Credential attack in progress with {features.auth_failure_rate:.0%} "
            f"authentication failure rate."
        )
    elif features.enum_score > 0.6:
        parts.append(
            f"Reconnaissance activity with {int(features.unique_paths_ratio * 100)}% "
            f"unique endpoint requests."
        )
    else:
        parts.append(
            f"Attacker sophistication assessed as {inference.attacker_sophistication} "
            f"in {inference.kill_chain_phase} phase."
        )

    return " ".join(parts)


# =============================================================================
# MAIN REPORT GENERATOR
# =============================================================================

def generate_behavioral_soc_report(
    events: list[HTTPEvent],
    features: BehavioralFeatures,
    inference: TechniqueInferenceResult,
    incident_id: Optional[int] = None,
    source_ip: Optional[str] = None,
) -> BehavioralSOCReport:
    """
    Generate a complete SOC report from behavioral analysis.

    This is the main entry point for producing HoneyKey-compatible
    SOC reports from behavioral detection.

    Args:
        events: Raw HTTP events
        features: Extracted behavioral features
        inference: Technique inference results
        incident_id: Optional HoneyKey incident ID
        source_ip: Override source IP (auto-detected if not provided)

    Returns:
        BehavioralSOCReport ready for integration
    """
    # Determine source IP
    if not source_ip and events:
        # Use most common IP from events
        from collections import Counter
        ip_counts = Counter(e.ip for e in events)
        source_ip = ip_counts.most_common(1)[0][0]
    source_ip = source_ip or "unknown"

    # Assess risk
    risk = assess_risk(features, inference)

    # Generate components
    evidence = generate_evidence_summary(features, inference, events)
    recommendations = generate_recommendations(features, inference, risk, source_ip)
    summary = generate_summary(features, inference, risk, source_ip)

    # Map severity
    severity = risk.level

    return BehavioralSOCReport(
        incident_id=incident_id,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip=source_ip,
        severity=severity,
        summary=summary,
        evidence=evidence,
        recommended_actions=recommendations.actions,
        techniques=[t.to_dict() for t in inference.techniques],
        attacker_sophistication=inference.attacker_sophistication,
        kill_chain_phase=inference.kill_chain_phase,
        confidence=inference.confidence_overall,
        risk_assessment=risk.to_dict(),
        behavioral_features=features.to_dict(),
        analysis_method="llm" if "Heuristic" not in inference.raw_reasoning else "heuristic",
    )


def analyze_and_report(
    event_dicts: list[dict[str, Any]],
    incident_id: Optional[int] = None,
    context: Optional[dict[str, Any]] = None,
    use_llm: bool = False,
    llm_api_key: Optional[str] = None,
    llm_model: str = "gemini-1.5-pro",
) -> BehavioralSOCReport:
    """
    Complete analysis pipeline: events -> features -> inference -> SOC report.

    This is the convenience function for full end-to-end analysis.

    Args:
        event_dicts: List of event dictionaries
        incident_id: Optional HoneyKey incident ID
        context: Optional context hints
        use_llm: Whether to use LLM for inference (requires api_key)
        llm_api_key: API key for LLM service
        llm_model: LLM model name

    Returns:
        BehavioralSOCReport

    Example:
        events = [
            {"timestamp": "2025-01-18T00:00:00Z", "ip": "1.2.3.4", ...},
            ...
        ]
        report = analyze_and_report(events, incident_id=42)
        print(report.to_honeykey_format())
    """
    from .behavior_features import extract_features_from_dicts

    # Extract features
    features = extract_features_from_dicts(event_dicts, context)

    # Build context hints
    hints = None
    if context:
        hints = ContextualHints(
            key_scope=context.get("key_scope"),
            deployment_surface=context.get("deployment_surface"),
            is_production=context.get("is_production"),
            api_type=context.get("api_type"),
        )

    # Infer techniques
    if use_llm and llm_api_key:
        from .technique_inference import infer_techniques_with_gemini
        inference = infer_techniques_with_gemini(
            features, llm_api_key, llm_model, hints
        )
    else:
        inference = infer_techniques_heuristic(features, hints)

    # Convert event dicts to objects
    events = [HTTPEvent.from_dict(d) for d in event_dicts]

    # Generate report
    return generate_behavioral_soc_report(
        events=events,
        features=features,
        inference=inference,
        incident_id=incident_id,
    )
