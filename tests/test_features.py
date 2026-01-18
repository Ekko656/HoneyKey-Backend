"""Tests for the HoneyKey feature modules."""

import json

import pytest

from app.features.key_metadata import (
    HONEYPOT_KEYS,
    LeakSourceType,
    Severity,
    Sophistication,
    get_confidence_label,
    get_key_metadata,
    get_leak_source,
    get_mitre_technique,
    get_severity_level,
    get_sophistication,
    is_honeypot_key,
    register_honeypot_key,
    LeakSource,
    MitreTechnique,
    AttackerProfile,
)
from app.features.attacker_responses import (
    generate_attacker_response,
    generate_request_id,
    generate_trap_response,
    get_auth_error,
    get_fake_project_list,
    get_fake_secret_list,
    get_permission_error,
)
from app.features.soc_enrichment import (
    build_enriched_soc_prompt,
    enrich_prompt_with_metadata,
    format_evidence_from_metadata,
    generate_recommendations_from_metadata,
    get_severity_from_metadata,
)


# =============================================================================
# Key Metadata Tests
# =============================================================================

class TestKeyMetadata:
    def test_all_honeypot_keys_registered(self):
        """All three honeypot keys should be in the registry."""
        assert "acme_client_m5n6o7p8q9r0s1t2" in HONEYPOT_KEYS
        assert "acme_debug_a1b2c3d4e5f6g7h8" in HONEYPOT_KEYS
        assert "acme_docker_j4k5l6m7n8o9p0q1" in HONEYPOT_KEYS

    def test_get_key_metadata_valid(self):
        """get_key_metadata returns metadata for valid keys."""
        metadata = get_key_metadata("acme_client_m5n6o7p8q9r0s1t2")
        assert metadata is not None
        assert metadata.key_id == "client_js_key"
        assert metadata.leak_source.type == LeakSourceType.CLIENT_SIDE_JS

    def test_get_key_metadata_invalid(self):
        """get_key_metadata returns None for unknown keys."""
        assert get_key_metadata("invalid_key") is None

    def test_is_honeypot_key(self):
        """is_honeypot_key correctly identifies honeypot keys."""
        assert is_honeypot_key("acme_debug_a1b2c3d4e5f6g7h8") is True
        assert is_honeypot_key("random_key") is False

    def test_get_leak_source(self):
        """get_leak_source returns leak info for valid keys."""
        leak = get_leak_source("acme_docker_j4k5l6m7n8o9p0q1")
        assert leak is not None
        assert leak.type == LeakSourceType.INFRASTRUCTURE_CONFIG
        assert "docker-compose" in leak.location

    def test_get_mitre_technique(self):
        """get_mitre_technique returns MITRE mapping."""
        mitre = get_mitre_technique("acme_debug_a1b2c3d4e5f6g7h8")
        assert mitre is not None
        assert mitre.technique_id == "T1552.001"
        assert mitre.secondary_id == "T1083"

    def test_get_sophistication(self):
        """get_sophistication returns attacker profile."""
        profile = get_sophistication("acme_client_m5n6o7p8q9r0s1t2")
        assert profile is not None
        assert profile.sophistication == Sophistication.INTERMEDIATE
        assert profile.sophistication_score == 6

    def test_severity_escalation(self):
        """Severity escalates with event count."""
        # Base severity for docker key is MEDIUM
        assert get_severity_level("acme_docker_j4k5l6m7n8o9p0q1", 1) == Severity.MEDIUM
        assert get_severity_level("acme_docker_j4k5l6m7n8o9p0q1", 5) == Severity.HIGH
        assert get_severity_level("acme_docker_j4k5l6m7n8o9p0q1", 10) == Severity.HIGH

        # Base severity for debug key is HIGH
        assert get_severity_level("acme_debug_a1b2c3d4e5f6g7h8", 1) == Severity.HIGH
        assert get_severity_level("acme_debug_a1b2c3d4e5f6g7h8", 10) == Severity.CRITICAL

    def test_confidence_labels(self):
        """Confidence scores map to correct labels."""
        assert get_confidence_label(0.99) == "Very High"
        assert get_confidence_label(0.90) == "High"
        assert get_confidence_label(0.75) == "Medium"
        assert get_confidence_label(0.55) == "Low"
        assert get_confidence_label(0.30) == "Very Low"

    def test_metadata_to_dict(self):
        """Metadata can be serialized to dict."""
        metadata = get_key_metadata("acme_client_m5n6o7p8q9r0s1t2")
        d = metadata.to_dict()
        assert d["key_id"] == "client_js_key"
        assert d["leak_source"]["type"] == "client_side_js"
        assert d["mitre_technique"]["id"] == "T1552.001"


# =============================================================================
# Attacker Response Tests
# =============================================================================

class TestAttackerResponses:
    def test_request_id_format(self):
        """Request IDs have correct format."""
        req_id = generate_request_id()
        assert req_id.startswith("req_")
        assert len(req_id) == 20  # "req_" + 16 hex chars

    def test_fake_project_list(self):
        """Fake project list is populated."""
        projects = get_fake_project_list()
        assert len(projects) >= 3
        assert all("id" in p and "name" in p for p in projects)
        assert any("payment" in p["name"] for p in projects)

    def test_fake_secret_list(self):
        """Fake secret list looks enticing."""
        secrets = get_fake_secret_list()
        assert len(secrets) >= 3
        names = [s["name"] for s in secrets]
        assert "DATABASE_PASSWORD" in names
        assert "STRIPE_SECRET_KEY" in names

    def test_auth_error_format(self):
        """Auth error has correct structure."""
        error = get_auth_error("Test message", 401)
        assert error["error"]["code"] == 401
        assert error["error"]["message"] == "Test message"
        assert "request_id" in error["error"]
        assert "timestamp" in error["error"]

    def test_permission_error_format(self):
        """Permission error includes resource info."""
        error = get_permission_error("secrets")
        assert error["error"]["code"] == 403
        assert "secrets" in error["error"]["message"]
        assert "required_permission" in error["error"]

    def test_attacker_response_unknown_key(self):
        """Unknown keys get 401."""
        status, response = generate_attacker_response("fake_key", "/v1/projects")
        assert status == 401
        assert "error" in response

    def test_attacker_response_docker_key_partial_data(self):
        """Docker key (novice) returns partial data to bait."""
        status, response = generate_attacker_response(
            "acme_docker_j4k5l6m7n8o9p0q1", "/v1/projects"
        )
        assert status == 200
        assert "projects" in response
        assert len(response["projects"]) > 0

    def test_attacker_response_debug_key_immediate_deny(self):
        """Debug key (advanced) gets immediate deny."""
        status, response = generate_attacker_response(
            "acme_debug_a1b2c3d4e5f6g7h8", "/v1/secrets"
        )
        assert status == 401
        assert "error" in response

    def test_attacker_response_client_key_permission_bait(self):
        """Client JS key gets 403 permission bait."""
        status, response = generate_attacker_response(
            "acme_client_m5n6o7p8q9r0s1t2", "/v1/projects"
        )
        assert status == 403
        assert "error" in response
        assert response["error"]["code"] == 403

    def test_trap_response_no_key(self):
        """Trap endpoints require auth."""
        status, response = generate_trap_response("/v1/projects")
        assert status == 401


# =============================================================================
# SOC Enrichment Tests
# =============================================================================

class TestSOCEnrichment:
    def test_evidence_generation(self):
        """Evidence is generated from metadata."""
        evidence = format_evidence_from_metadata(
            key="acme_debug_a1b2c3d4e5f6g7h8",
            source_ip="10.0.0.1",
            endpoint="/v1/secrets",
            user_agent="curl/7.88.1",
            event_count=5,
        )
        assert len(evidence) >= 5
        assert any("debug_log_key" in e for e in evidence)
        assert any("10.0.0.1" in e for e in evidence)
        assert any("/v1/secrets" in e for e in evidence)
        assert any("curl" in e.lower() for e in evidence)

    def test_evidence_unknown_key(self):
        """Unknown keys still generate basic evidence."""
        evidence = format_evidence_from_metadata(
            key="unknown_key",
            source_ip="192.168.1.1",
            endpoint="/test",
        )
        assert len(evidence) >= 1
        assert any("192.168.1.1" in e for e in evidence)

    def test_recommendations_generation(self):
        """Recommendations are tailored to leak source."""
        recs = generate_recommendations_from_metadata(
            key="acme_docker_j4k5l6m7n8o9p0q1",
            source_ip="1.2.3.4",
        )
        assert len(recs) >= 3
        assert any("1.2.3.4" in r for r in recs)
        # Docker-specific recommendations
        assert any("git" in r.lower() or "config" in r.lower() for r in recs)

    def test_recommendations_log_leak(self):
        """Log leak recommendations include log-specific actions."""
        recs = generate_recommendations_from_metadata(
            key="acme_debug_a1b2c3d4e5f6g7h8",
            source_ip="5.6.7.8",
        )
        assert any("log" in r.lower() for r in recs)
        assert any("scrub" in r.lower() or "aggregation" in r.lower() for r in recs)

    def test_metadata_prompt_enrichment(self):
        """Prompt enrichment includes key metadata."""
        enrichment = enrich_prompt_with_metadata("acme_client_m5n6o7p8q9r0s1t2")
        assert "client_js_key" in enrichment
        assert "T1552.001" in enrichment
        assert "source_map" in enrichment.lower()
        assert "intermediate" in enrichment.lower()

    def test_enriched_soc_prompt_complete(self):
        """Full SOC prompt includes all required sections."""
        prompt = build_enriched_soc_prompt(
            incident={
                "id": 42,
                "source_ip": "192.168.1.100",
                "first_seen": "2025-01-18T00:00:00Z",
                "last_seen": "2025-01-18T01:00:00Z",
                "event_count": 10,
            },
            events=[
                {
                    "ts": "2025-01-18T00:00:00Z",
                    "ip": "192.168.1.100",
                    "method": "GET",
                    "path": "/v1/projects",
                    "user_agent": "python-requests/2.28",
                    "honeypot_key_used": True,
                }
            ],
            key_used="acme_debug_a1b2c3d4e5f6g7h8",
        )
        # Check all required sections
        assert "HONEYPOT KEY INTELLIGENCE" in prompt
        assert "INCIDENT DATA" in prompt
        assert "RECENT EVENTS" in prompt
        assert "PRE-COMPUTED EVIDENCE" in prompt
        assert "PRE-COMPUTED RECOMMENDATIONS" in prompt
        assert "INSTRUCTIONS" in prompt
        # Check metadata is included
        assert "T1552.001" in prompt
        assert "HIGH" in prompt  # severity
        assert "192.168.1.100" in prompt

    def test_severity_from_metadata(self):
        """Severity calculation includes all factors."""
        result = get_severity_from_metadata(
            key="acme_debug_a1b2c3d4e5f6g7h8",
            event_count=15,
            is_repeat_offender=True,
        )
        assert result["level"] in ("high", "critical")
        assert result["score"] >= 7
        assert "Repeat offender" in result["justification"]
        assert "advanced" in result["justification"].lower()


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    def test_full_flow_docker_key(self):
        """Full flow: docker key detection to SOC prompt."""
        key = "acme_docker_j4k5l6m7n8o9p0q1"

        # 1. Key is recognized
        assert is_honeypot_key(key)

        # 2. Attacker response is generated
        status, response = generate_attacker_response(key, "/v1/projects")
        assert status == 200  # Partial data strategy

        # 3. Evidence is generated
        evidence = format_evidence_from_metadata(
            key=key,
            source_ip="45.33.32.1",
            endpoint="/v1/projects",
        )
        assert len(evidence) >= 5

        # 4. SOC prompt is built
        prompt = build_enriched_soc_prompt(
            incident={"id": 1, "source_ip": "45.33.32.1", "first_seen": "2025-01-18T00:00:00Z", "last_seen": "2025-01-18T00:00:00Z", "event_count": 1},
            events=[{"ts": "2025-01-18T00:00:00Z", "ip": "45.33.32.1", "method": "GET", "path": "/v1/projects", "user_agent": "curl", "honeypot_key_used": True}],
            key_used=key,
        )
        assert "docker-compose" in prompt
        assert "github_dorking" in prompt
        assert "novice" in prompt.lower()

    def test_full_flow_debug_key(self):
        """Full flow: debug key (high severity) detection."""
        key = "acme_debug_a1b2c3d4e5f6g7h8"

        # 1. High severity key
        metadata = get_key_metadata(key)
        assert metadata.base_severity == Severity.HIGH

        # 2. Immediate deny response
        status, _ = generate_attacker_response(key, "/v1/secrets")
        assert status == 401

        # 3. Recommendations include escalation
        recs = generate_recommendations_from_metadata(key, "1.1.1.1", event_count=1)
        assert any("ESCALATE" in r or "incident response" in r.lower() for r in recs)
