"""Tests for the HoneyKey integration module."""

import json
import pytest

from app.integration.enhanced_prompt import (
    KeyHint,
    build_enhanced_prompt,
    create_behavioral_context,
    get_key_hint,
    register_key_hint,
    format_behavioral_summary,
    format_technique_summary,
)
from app.integration.report_enrichment import (
    EnrichedSOCReport,
    enrich_soc_report,
    merge_behavioral_analysis,
    validate_severity_with_behavior,
    generate_confidence_explanation,
)
from app.detection import extract_behavioral_features, infer_techniques_heuristic, HTTPEvent


# =============================================================================
# Test Fixtures
# =============================================================================

def make_event_dict(
    path: str = "/v1/test",
    method: str = "GET",
    ip: str = "192.168.1.100",
    user_agent: str = "test-client/1.0",
    ts: str = "2025-01-18T00:00:00Z",
) -> dict:
    """Create test event dict."""
    return {
        "ts": ts,
        "ip": ip,
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "correlation_id": "test-123",
        "auth_present": True,
        "honeypot_key_used": True,
    }


def make_incident_dict(
    incident_id: int = 1,
    key_id: str = "honeypot",
    source_ip: str = "192.168.1.100",
) -> dict:
    """Create test incident dict."""
    return {
        "id": incident_id,
        "key_id": key_id,
        "source_ip": source_ip,
        "first_seen": "2025-01-18T00:00:00Z",
        "last_seen": "2025-01-18T00:01:00Z",
        "event_count": 5,
    }


# =============================================================================
# Key Hint Tests
# =============================================================================

class TestKeyHints:
    def test_get_key_hint_client(self):
        """Client key hint is returned."""
        hint = get_key_hint("acme_client_m5n6o7p8q9r0s1t2")
        assert hint is not None
        assert "JavaScript" in hint.likely_leak_source
        assert hint.confidence_modifier == 0.1

    def test_get_key_hint_debug(self):
        """Debug key hint is returned."""
        hint = get_key_hint("acme_debug_a1b2c3d4e5f6g7h8")
        assert hint is not None
        assert "log" in hint.likely_leak_source.lower()
        assert hint.confidence_modifier == 0.15

    def test_get_key_hint_docker(self):
        """Docker key hint is returned."""
        hint = get_key_hint("acme_docker_j4k5l6m7n8o9p0q1")
        assert hint is not None
        assert "docker" in hint.likely_leak_source.lower() or "config" in hint.likely_leak_source.lower()
        assert hint.confidence_modifier == 0.05

    def test_get_key_hint_unknown(self):
        """Unknown key returns None."""
        hint = get_key_hint("unknown_key_12345")
        assert hint is None

    def test_get_key_hint_none(self):
        """None key returns None."""
        hint = get_key_hint(None)
        assert hint is None

    def test_register_key_hint(self):
        """Custom key hint can be registered."""
        register_key_hint(
            key_prefix="test_custom_",
            likely_leak_source="test source",
            suggested_discovery_method="test method",
            confidence_modifier=0.12,
            hint_text="Test hint text",
        )
        hint = get_key_hint("test_custom_key123")
        assert hint is not None
        assert hint.likely_leak_source == "test source"
        assert hint.confidence_modifier == 0.12

    def test_key_hint_to_dict(self):
        """KeyHint serializes to dict."""
        hint = get_key_hint("acme_client_test")
        assert hint is not None
        d = hint.to_dict()
        assert "key_prefix" in d
        assert "likely_leak_source" in d
        assert "confidence_modifier" in d

    def test_confidence_modifier_clamping(self):
        """Confidence modifier is clamped to valid range."""
        register_key_hint(
            key_prefix="test_clamp_",
            likely_leak_source="test",
            suggested_discovery_method="test",
            confidence_modifier=0.5,  # Should be clamped to 0.2
        )
        hint = get_key_hint("test_clamp_key")
        assert hint.confidence_modifier == 0.2


# =============================================================================
# Enhanced Prompt Tests
# =============================================================================

class TestEnhancedPrompt:
    def test_create_behavioral_context(self):
        """Behavioral context is created from events."""
        events = [
            make_event_dict(path="/v1/secrets"),
            make_event_dict(path="/v1/projects"),
            make_event_dict(path="/v1/admin"),
        ]
        features, inference = create_behavioral_context(events)

        assert features.total_events == 3
        assert inference is not None
        assert inference.attacker_sophistication in ("Novice", "Intermediate", "Advanced", "Expert")

    def test_build_enhanced_prompt_basic(self):
        """Enhanced prompt is built."""
        incident = make_incident_dict()
        events = [make_event_dict() for _ in range(3)]

        prompt = build_enhanced_prompt(incident, events)

        assert "INCIDENT DATA" in prompt
        assert "BEHAVIORAL ANALYSIS" in prompt
        assert "TECHNIQUE INFERENCE" in prompt
        assert "KEY CONTEXT HINT" in prompt
        assert "incident_id" in prompt

    def test_build_enhanced_prompt_with_key(self):
        """Enhanced prompt includes key hint."""
        incident = make_incident_dict()
        events = [make_event_dict() for _ in range(3)]

        prompt = build_enhanced_prompt(
            incident, events,
            key_value="acme_debug_a1b2c3d4e5f6g7h8"
        )

        assert "log" in prompt.lower()  # Debug key mentions logs

    def test_build_enhanced_prompt_no_key(self):
        """Enhanced prompt handles unknown key."""
        incident = make_incident_dict(key_id="unknown")
        events = [make_event_dict() for _ in range(3)]

        prompt = build_enhanced_prompt(incident, events, key_value="random_key")

        assert "No specific leak source" in prompt

    def test_format_behavioral_summary_with_issues(self):
        """Behavioral summary formats detected issues."""
        events = [
            HTTPEvent(
                timestamp="2025-01-18T00:00:00Z",
                ip="1.2.3.4",
                method="GET",
                path=f"/v1/endpoint{i}",
                status_code=401,
                user_agent="curl/7.88",
            )
            for i in range(20)
        ]
        features = extract_behavioral_features(events)
        summary = format_behavioral_summary(features)

        # Should mention enumeration due to high unique path ratio
        assert len(summary) > 0

    def test_format_technique_summary(self):
        """Technique summary formats inference."""
        events = [
            HTTPEvent(
                timestamp="2025-01-18T00:00:00Z",
                ip="1.2.3.4",
                method="GET",
                path="/.env",
                status_code=401,
                user_agent="curl",
            )
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        summary = format_technique_summary(inference)

        assert "sophistication" in summary.lower()
        assert "T1" in summary or "No specific" in summary


# =============================================================================
# Report Enrichment Tests
# =============================================================================

class TestReportEnrichment:
    def test_enrich_soc_report(self):
        """SOC report is enriched with behavioral data."""
        base_report = {
            "incident_id": 1,
            "severity": "Medium",
            "summary": "Test summary",
            "evidence": ["Evidence 1"],
            "recommended_actions": ["Action 1"],
        }
        events = [make_event_dict() for _ in range(5)]

        enriched = enrich_soc_report(base_report, events)

        assert enriched.incident_id == 1
        assert enriched.behavioral_features is not None
        assert enriched.inferred_techniques is not None
        assert enriched.confidence_score > 0

    def test_enrich_soc_report_with_key(self):
        """Enrichment includes key hint when available."""
        base_report = {
            "incident_id": 2,
            "severity": "High",
            "summary": "Test",
            "evidence": [],
            "recommended_actions": [],
        }
        events = [make_event_dict() for _ in range(3)]

        enriched = enrich_soc_report(
            base_report, events,
            key_value="acme_client_m5n6o7p8q9r0s1t2"
        )

        assert enriched.key_hint is not None
        assert "JavaScript" in enriched.key_hint["likely_leak_source"]

    def test_enriched_report_formats(self):
        """Enriched report has both format methods."""
        base_report = {
            "incident_id": 3,
            "severity": "Low",
            "summary": "Test",
            "evidence": ["E1"],
            "recommended_actions": ["A1"],
        }
        events = [make_event_dict()]

        enriched = enrich_soc_report(base_report, events)

        base_format = enriched.to_base_format()
        full_format = enriched.to_full_format()

        # Base format has only AIReportResponse fields
        assert "behavioral_features" not in base_format
        assert "incident_id" in base_format

        # Full format has everything
        assert "behavioral_features" in full_format
        assert "inferred_techniques" in full_format

    def test_merge_behavioral_analysis(self):
        """Behavioral analysis merges into report."""
        base_report = {
            "incident_id": 4,
            "severity": "Medium",
            "summary": "Test",
            "evidence": ["Original evidence"],
            "recommended_actions": [],
        }

        events = [
            HTTPEvent(
                timestamp="2025-01-18T00:00:00Z",
                ip="10.0.0.1",
                method="GET",
                path="/.env",
                status_code=401,
                user_agent="curl",
            )
            for _ in range(5)
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        key_hint = get_key_hint("acme_debug_test")

        merged = merge_behavioral_analysis(base_report, features, inference, key_hint)

        # Original evidence should still be there
        assert "Original evidence" in merged["evidence"]
        # Behavioral metadata added
        assert "_behavioral_analysis" in merged
        # Key hint added
        assert "_key_hint" in merged

    def test_validate_severity_no_change(self):
        """Severity unchanged when behavior matches."""
        events = [
            HTTPEvent(
                timestamp="2025-01-18T00:00:00Z",
                ip="1.2.3.4",
                method="GET",
                path="/v1/test",
                status_code=200,
                user_agent="sdk/1.0",
            )
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)

        final, reason = validate_severity_with_behavior("Low", features, inference)
        # Should stay low for benign traffic
        assert final.lower() in ("low", "medium")

    def test_validate_severity_upgrade_injection(self):
        """Severity upgraded for injection attacks."""
        events = [
            HTTPEvent(
                timestamp="2025-01-18T00:00:00Z",
                ip="1.2.3.4",
                method="GET",
                path="/v1/users?id=' OR '1'='1",
                status_code=500,
                user_agent="sqlmap",
            )
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)

        final, reason = validate_severity_with_behavior("Low", features, inference)

        # Should be upgraded due to injection
        assert final.lower() in ("high", "critical")
        assert "upgraded" in reason.lower() or "behavioral" in reason.lower()

    def test_generate_confidence_explanation(self):
        """Confidence explanation is generated."""
        events = [
            HTTPEvent(
                timestamp="2025-01-18T00:00:00Z",
                ip="1.2.3.4",
                method="GET",
                path="/admin",
                status_code=401,
                user_agent="curl",
            )
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        key_hint = get_key_hint("acme_client_test")

        explanation = generate_confidence_explanation(features, inference, key_hint)

        assert "confidence" in explanation.lower()
        assert "behavioral" in explanation.lower()


# =============================================================================
# Integration Tests
# =============================================================================

class TestFullIntegration:
    def test_full_flow_enumeration_attack(self):
        """Full flow for enumeration attack with key hint."""
        incident = make_incident_dict(key_id="honeypot")
        events = [
            make_event_dict(path=f"/v1/endpoint{i}", ts=f"2025-01-18T00:00:{i:02d}Z")
            for i in range(15)
        ]

        # Build prompt
        prompt = build_enhanced_prompt(
            incident, events,
            key_value="acme_docker_j4k5l6m7n8o9p0q1"
        )

        assert "enumeration" in prompt.lower() or "unique" in prompt.lower()
        assert "docker" in prompt.lower() or "config" in prompt.lower()

        # Simulate LLM response and enrich
        base_report = {
            "incident_id": 1,
            "severity": "Medium",
            "summary": "Enumeration detected",
            "evidence": ["Multiple endpoints probed"],
            "recommended_actions": ["Monitor IP"],
        }

        enriched = enrich_soc_report(base_report, events, "acme_docker_j4k5l6m7n8o9p0q1")

        assert enriched.attacker_sophistication is not None
        assert enriched.inferred_techniques is not None
        assert enriched.key_hint is not None

    def test_full_flow_auth_attack(self):
        """Full flow for auth attack."""
        incident = make_incident_dict()
        events = [
            make_event_dict(path="/v1/auth/login", ts=f"2025-01-18T00:00:{i:02d}Z")
            for i in range(20)
        ]

        prompt = build_enhanced_prompt(incident, events)

        # Should mention auth failures (all return 401)
        assert "auth" in prompt.lower() or "failure" in prompt.lower()

    def test_key_hint_not_override_behavior(self):
        """Key hint doesn't override behavioral evidence."""
        # Create events that look like injection attack
        events = [
            make_event_dict(path="/v1/users?id=' OR '1'='1"),
            make_event_dict(path="/v1/data/../../../etc/passwd"),
        ]

        # Use a key that suggests low sophistication (docker)
        incident = make_incident_dict()
        prompt = build_enhanced_prompt(
            incident, events,
            key_value="acme_docker_j4k5l6m7n8o9p0q1"
        )

        # The prompt should still mention injection behavior
        # (not just assume it's GitHub dorking because of key)
        assert "injection" in prompt.lower() or "pattern" in prompt.lower()

        # Enrich and check
        base_report = {
            "incident_id": 1,
            "severity": "Low",  # LLM underestimates
            "summary": "Test",
            "evidence": [],
            "recommended_actions": [],
        }

        enriched = enrich_soc_report(base_report, events, "acme_docker_j4k5l6m7n8o9p0q1")

        # Behavioral analysis should detect injection
        techniques = enriched.inferred_techniques
        technique_ids = [t["id"] for t in techniques] if techniques else []
        assert "T1190" in technique_ids  # Exploit Public-Facing Application

    def test_output_matches_backend_format(self):
        """Output matches AIReportResponse structure."""
        base_report = {
            "incident_id": 42,
            "severity": "High",
            "summary": "Test summary",
            "evidence": ["E1", "E2"],
            "recommended_actions": ["A1", "A2"],
        }
        events = [make_event_dict()]

        enriched = enrich_soc_report(base_report, events)

        # Base format should be exactly what backend expects
        base = enriched.to_base_format()
        required_keys = {"incident_id", "severity", "summary", "evidence", "recommended_actions"}
        assert set(base.keys()) == required_keys

        # Types should match
        assert isinstance(base["incident_id"], int)
        assert isinstance(base["severity"], str)
        assert isinstance(base["summary"], str)
        assert isinstance(base["evidence"], list)
        assert isinstance(base["recommended_actions"], list)
