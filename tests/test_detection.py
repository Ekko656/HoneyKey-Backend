"""Tests for the HoneyKey behavioral detection module."""

import json
from datetime import datetime, timezone, timedelta

import pytest

from app.detection.behavior_features import (
    BehavioralFeatures,
    ContextualHints,
    HTTPEvent,
    extract_behavioral_features,
    extract_features_from_dicts,
    extract_temporal_features,
    extract_endpoint_features,
    extract_auth_features,
    extract_client_features,
    extract_injection_features,
    extract_sequence_features,
)
from app.detection.technique_inference import (
    InferredTechnique,
    TechniqueInferenceResult,
    build_inference_prompt,
    infer_techniques_heuristic,
    parse_inference_response,
)
from app.detection.behavioral_soc import (
    BehavioralSOCReport,
    analyze_and_report,
    assess_risk,
    generate_evidence_summary,
    generate_recommendations,
    generate_summary,
)


# =============================================================================
# Test Fixtures
# =============================================================================

def make_event(
    path: str = "/v1/test",
    method: str = "GET",
    status_code: int = 200,
    ip: str = "192.168.1.100",
    user_agent: str = "test-client/1.0",
    timestamp: str = None,
) -> HTTPEvent:
    """Helper to create test events."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return HTTPEvent(
        timestamp=timestamp,
        ip=ip,
        method=method,
        path=path,
        status_code=status_code,
        user_agent=user_agent,
    )


def make_events_sequence(n: int, base_time: datetime = None, interval_seconds: float = 1.0) -> list[HTTPEvent]:
    """Create a sequence of events with regular timing."""
    if base_time is None:
        base_time = datetime.now(timezone.utc)
    events = []
    for i in range(n):
        ts = (base_time + timedelta(seconds=i * interval_seconds)).isoformat()
        events.append(make_event(
            path=f"/v1/resource/{i}",
            timestamp=ts,
        ))
    return events


# =============================================================================
# Feature Extraction Tests
# =============================================================================

class TestBehaviorFeatures:
    def test_empty_events(self):
        """Empty event list returns zeroed features."""
        features = extract_behavioral_features([])
        assert features.total_events == 0
        assert features.burst_score == 0.0
        assert features.enum_score == 0.0

    def test_single_event(self):
        """Single event extracts basic features."""
        events = [make_event()]
        features = extract_behavioral_features(events)
        assert features.total_events == 1
        assert features.distinct_ips == 1

    def test_temporal_burst_detection(self):
        """Bursty requests are detected."""
        # Create 10 events in 1 second (very bursty)
        base_time = datetime.now(timezone.utc)
        events = make_events_sequence(10, base_time, interval_seconds=0.1)
        features = extract_behavioral_features(events)
        assert features.burst_score > 0.5

    def test_temporal_regularity(self):
        """Regular timing is detected."""
        # Regular 1-second intervals
        events = make_events_sequence(20, interval_seconds=1.0)
        features = extract_behavioral_features(events)
        # Regular timing should have high regularity
        assert features.temporal_regularity > 0.5

    def test_endpoint_enumeration(self):
        """High unique path ratio indicates enumeration."""
        events = [
            make_event(path=f"/v1/path{i}")
            for i in range(20)
        ]
        features = extract_behavioral_features(events)
        assert features.unique_paths_ratio > 0.9
        assert features.enum_score > 0.5

    def test_sensitive_path_detection(self):
        """Sensitive paths are counted."""
        events = [
            make_event(path="/.env"),
            make_event(path="/.git/config"),
            make_event(path="/admin/settings"),
            make_event(path="/v1/normal"),
        ]
        features = extract_behavioral_features(events)
        assert features.sensitive_path_hits >= 3

    def test_auth_failure_rate(self):
        """Auth failures are tracked."""
        events = [
            make_event(status_code=401),
            make_event(status_code=403),
            make_event(status_code=401),
            make_event(status_code=200),
        ]
        features = extract_behavioral_features(events)
        assert features.auth_failure_rate == 0.75

    def test_auth_consecutive_failures(self):
        """Consecutive auth failures are counted."""
        events = [
            make_event(status_code=401),
            make_event(status_code=401),
            make_event(status_code=401),
            make_event(status_code=200),
            make_event(status_code=401),
        ]
        features = extract_behavioral_features(events)
        assert features.auth_retry_count == 3

    def test_sdk_detection(self):
        """SDK user agents are detected."""
        events = [
            make_event(user_agent="Stripe/v1 python"),
            make_event(user_agent="stripe-python/5.0.0"),
        ]
        features = extract_behavioral_features(events)
        assert features.sdk_likelihood > 0.5

    def test_suspicious_ua_detection(self):
        """Suspicious user agents lower SDK likelihood."""
        events = [
            make_event(user_agent="curl/7.88.1"),
            make_event(user_agent="sqlmap/1.4"),
        ]
        features = extract_behavioral_features(events)
        assert features.sdk_likelihood < 0.2

    def test_injection_detection(self):
        """Injection patterns are detected."""
        events = [
            make_event(path="/v1/users?id=1' OR '1'='1"),
            make_event(path="/v1/data/../../../etc/passwd"),
            make_event(path="/v1/search?q=<script>alert(1)</script>"),
        ]
        features = extract_behavioral_features(events)
        assert features.injection_pattern_count >= 3

    def test_rate_limit_tracking(self):
        """Rate limit responses are tracked."""
        events = [
            make_event(status_code=429),
            make_event(status_code=429),
            make_event(status_code=200),
        ]
        features = extract_behavioral_features(events)
        assert features.rate_limit_hits == 2

    def test_method_distribution(self):
        """Method distribution is calculated."""
        events = [
            make_event(method="GET"),
            make_event(method="GET"),
            make_event(method="POST"),
            make_event(method="DELETE"),
        ]
        features = extract_behavioral_features(events)
        assert features.method_distribution["GET"] == 0.5
        assert features.method_distribution["POST"] == 0.25
        assert features.write_method_ratio == 0.5

    def test_features_to_dict(self):
        """Features serialize to dict."""
        events = make_events_sequence(5)
        features = extract_behavioral_features(events)
        d = features.to_dict()
        assert "temporal" in d
        assert "endpoint" in d
        assert "authentication" in d
        assert "injection" in d


class TestFeatureExtraction:
    def test_extract_from_dicts(self):
        """Can extract features from raw dictionaries."""
        event_dicts = [
            {
                "timestamp": "2025-01-18T00:00:00Z",
                "ip": "10.0.0.1",
                "method": "GET",
                "path": "/v1/test",
                "status_code": 200,
                "user_agent": "test",
            }
        ]
        features = extract_features_from_dicts(event_dicts)
        assert features.total_events == 1

    def test_extract_with_context(self):
        """Context hints are accepted."""
        event_dicts = [
            {
                "timestamp": "2025-01-18T00:00:00Z",
                "ip": "10.0.0.1",
                "method": "GET",
                "path": "/v1/test",
                "status_code": 200,
            }
        ]
        context = {"key_scope": "read-only", "deployment_surface": "frontend"}
        features = extract_features_from_dicts(event_dicts, context)
        assert features.total_events == 1


# =============================================================================
# Technique Inference Tests
# =============================================================================

class TestTechniqueInference:
    def test_heuristic_enumeration(self):
        """Heuristic detects enumeration."""
        events = [make_event(path=f"/v1/p{i}") for i in range(20)]
        features = extract_behavioral_features(events)
        result = infer_techniques_heuristic(features)

        assert len(result.techniques) > 0
        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1595" in technique_ids  # Active Scanning

    def test_heuristic_auth_attack(self):
        """Heuristic detects auth attacks."""
        events = [make_event(status_code=401) for _ in range(15)]
        features = extract_behavioral_features(events)
        result = infer_techniques_heuristic(features)

        technique_ids = [t.technique_id for t in result.techniques]
        assert any(t.startswith("T1110") for t in technique_ids)  # Brute Force

    def test_heuristic_injection(self):
        """Heuristic detects injection."""
        events = [
            make_event(path="/v1/users?id=' OR '1'='1"),
            make_event(path="/v1/data/../secret"),
        ]
        features = extract_behavioral_features(events)
        result = infer_techniques_heuristic(features)

        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1190" in technique_ids  # Exploit Public-Facing Application

    def test_heuristic_sophistication(self):
        """Heuristic assesses sophistication."""
        # Simple curl requests
        simple_events = [make_event(user_agent="curl/7.88") for _ in range(5)]
        simple_features = extract_behavioral_features(simple_events)
        simple_result = infer_techniques_heuristic(simple_features)

        # Complex injection with regular timing
        complex_events = [
            make_event(
                path=f"/v1/test{i}?q=' UNION SELECT * FROM users",
                user_agent="custom-scanner/1.0",
            )
            for i in range(10)
        ]
        complex_features = extract_behavioral_features(complex_events)
        complex_result = infer_techniques_heuristic(complex_features)

        # Complex should be rated higher
        soph_levels = {"Novice": 1, "Intermediate": 2, "Advanced": 3, "Expert": 4}
        assert soph_levels.get(complex_result.attacker_sophistication, 0) >= \
               soph_levels.get(simple_result.attacker_sophistication, 0)

    def test_inference_result_to_dict(self):
        """Inference result serializes."""
        events = make_events_sequence(5)
        features = extract_behavioral_features(events)
        result = infer_techniques_heuristic(features)
        d = result.to_dict()

        assert "techniques" in d
        assert "attacker_sophistication" in d
        assert "confidence_overall" in d

    def test_build_prompt(self):
        """Prompt builder includes features."""
        events = make_events_sequence(5)
        features = extract_behavioral_features(events)
        prompt = build_inference_prompt(features)

        assert "MITRE" in prompt
        assert "burst_score" in prompt.lower() or "burst" in prompt.lower()
        assert "JSON" in prompt

    def test_parse_valid_response(self):
        """Valid LLM response parses correctly."""
        response = '''
        {
            "techniques": [
                {
                    "id": "T1595",
                    "name": "Active Scanning",
                    "tactic": "Reconnaissance",
                    "confidence": 0.82,
                    "evidence": ["High enumeration"],
                    "reasoning": "Test reasoning"
                }
            ],
            "attacker_sophistication": "Intermediate",
            "confidence_overall": 0.78,
            "kill_chain_phase": "Reconnaissance",
            "summary_reasoning": "Test summary"
        }
        '''
        result = parse_inference_response(response)

        assert len(result.techniques) == 1
        assert result.techniques[0].technique_id == "T1595"
        assert result.attacker_sophistication == "Intermediate"

    def test_parse_markdown_response(self):
        """Handles markdown-wrapped JSON."""
        response = '''```json
        {
            "techniques": [],
            "attacker_sophistication": "Novice",
            "confidence_overall": 0.5,
            "kill_chain_phase": "Reconnaissance",
            "summary_reasoning": "Test"
        }
        ```'''
        result = parse_inference_response(response)
        assert result.attacker_sophistication == "Novice"


# =============================================================================
# SOC Report Tests
# =============================================================================

class TestBehavioralSOC:
    def test_risk_assessment_low(self):
        """Low risk for benign traffic."""
        events = [make_event(status_code=200) for _ in range(5)]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        risk = assess_risk(features, inference)

        assert risk.level in ("low", "medium")
        assert risk.score < 50

    def test_risk_assessment_critical(self):
        """Critical risk for injection attacks."""
        events = [
            make_event(path="/v1/test?q=' OR '1'='1", status_code=500),
            make_event(path="/v1/data/../../../etc/passwd", status_code=403),
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        risk = assess_risk(features, inference)

        assert risk.level in ("high", "critical")
        assert risk.score >= 35

    def test_evidence_generation(self):
        """Evidence is generated from features."""
        events = [
            make_event(path="/.env", status_code=401),
            make_event(path="/admin", status_code=401),
            make_event(user_agent="curl/7.88"),
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        evidence = generate_evidence_summary(features, inference, events)

        assert len(evidence) > 0
        assert any("401" in e or "auth" in e.lower() for e in evidence)

    def test_recommendations_generation(self):
        """Recommendations are generated."""
        events = [make_event(status_code=401) for _ in range(10)]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        risk = assess_risk(features, inference)
        recs = generate_recommendations(features, inference, risk, "10.0.0.1")

        assert len(recs.actions) > 0
        assert any("10.0.0.1" in a for a in recs.actions)

    def test_recommendations_critical(self):
        """Critical risk gets immediate action."""
        events = [
            make_event(path="/v1/test?q=<script>", status_code=500)
            for _ in range(5)
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        risk = assess_risk(features, inference)
        recs = generate_recommendations(features, inference, risk, "1.2.3.4")

        if risk.level == "critical":
            assert recs.priority == "immediate"
            assert any("IMMEDIATE" in a or "block" in a.lower() for a in recs.actions)

    def test_summary_generation(self):
        """Summary is generated."""
        events = make_events_sequence(10)
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)
        risk = assess_risk(features, inference)
        summary = generate_summary(features, inference, risk, "192.168.1.1")

        assert len(summary) > 0
        assert "192.168.1.1" in summary

    def test_full_report_generation(self):
        """Full SOC report is generated."""
        events = [
            make_event(path="/v1/secrets", status_code=401, user_agent="curl"),
            make_event(path="/v1/admin", status_code=403, user_agent="curl"),
        ]
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)

        from app.detection.behavioral_soc import generate_behavioral_soc_report
        report = generate_behavioral_soc_report(
            events=events,
            features=features,
            inference=inference,
            incident_id=42,
        )

        assert report.incident_id == 42
        assert report.severity in ("low", "medium", "high", "critical")
        assert len(report.summary) > 0
        assert len(report.evidence) > 0
        assert len(report.recommended_actions) > 0

    def test_report_honeykey_format(self):
        """Report converts to HoneyKey format."""
        events = make_events_sequence(5)
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)

        from app.detection.behavioral_soc import generate_behavioral_soc_report
        report = generate_behavioral_soc_report(
            events=events,
            features=features,
            inference=inference,
            incident_id=100,
        )

        hk_format = report.to_honeykey_format()

        # Must match HoneyKey's AIReportResponse structure
        assert "incident_id" in hk_format
        assert "severity" in hk_format
        assert "summary" in hk_format
        assert "evidence" in hk_format
        assert "recommended_actions" in hk_format
        assert isinstance(hk_format["evidence"], list)
        assert isinstance(hk_format["recommended_actions"], list)

    def test_report_json_serializable(self):
        """Report serializes to JSON."""
        events = make_events_sequence(5)
        features = extract_behavioral_features(events)
        inference = infer_techniques_heuristic(features)

        from app.detection.behavioral_soc import generate_behavioral_soc_report
        report = generate_behavioral_soc_report(
            events=events,
            features=features,
            inference=inference,
        )

        # Should not raise
        json_str = json.dumps(report.to_dict())
        assert len(json_str) > 0


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    def test_full_pipeline_enumeration(self):
        """Full pipeline for enumeration attack."""
        event_dicts = [
            {
                "timestamp": f"2025-01-18T00:00:{i:02d}Z",
                "ip": "45.33.32.1",
                "method": "GET",
                "path": f"/v1/endpoint{i}",
                "status_code": 404 if i % 2 == 0 else 401,
                "user_agent": "python-requests/2.28.0",
            }
            for i in range(20)
        ]

        report = analyze_and_report(event_dicts, incident_id=1)

        assert report.incident_id == 1
        assert report.source_ip == "45.33.32.1"
        assert len(report.techniques) > 0
        # Should detect scanning/enumeration
        technique_ids = [t["id"] for t in report.techniques]
        assert any("T1595" in tid or "T1083" in tid for tid in technique_ids)

    def test_full_pipeline_credential_attack(self):
        """Full pipeline for credential attack."""
        event_dicts = [
            {
                "timestamp": f"2025-01-18T00:00:{i:02d}Z",
                "ip": "10.0.0.50",
                "method": "POST",
                "path": "/v1/auth/login",
                "status_code": 401,
                "user_agent": "curl/7.88.1",
            }
            for i in range(15)
        ]

        report = analyze_and_report(event_dicts, incident_id=2)

        assert report.severity in ("medium", "high", "critical")
        technique_ids = [t["id"] for t in report.techniques]
        # Should detect brute force
        assert any("T1110" in tid for tid in technique_ids)

    def test_full_pipeline_injection_attack(self):
        """Full pipeline for injection attack."""
        event_dicts = [
            {
                "timestamp": "2025-01-18T00:00:00Z",
                "ip": "192.168.1.200",
                "method": "GET",
                "path": "/v1/users?id=1' OR '1'='1",
                "status_code": 500,
                "user_agent": "sqlmap/1.4.7",
            },
            {
                "timestamp": "2025-01-18T00:00:01Z",
                "ip": "192.168.1.200",
                "method": "GET",
                "path": "/v1/data/../../../etc/passwd",
                "status_code": 403,
                "user_agent": "sqlmap/1.4.7",
            },
        ]

        report = analyze_and_report(event_dicts, incident_id=3)

        assert report.severity in ("high", "critical")
        # Should detect exploitation
        technique_ids = [t["id"] for t in report.techniques]
        assert "T1190" in technique_ids

    def test_full_pipeline_benign_traffic(self):
        """Full pipeline for benign traffic."""
        event_dicts = [
            {
                "timestamp": f"2025-01-18T00:00:{i:02d}Z",
                "ip": "10.0.0.1",
                "method": "GET",
                "path": "/v1/charges",
                "status_code": 200,
                "user_agent": "Stripe/v1 python",
            }
            for i in range(5)
        ]

        report = analyze_and_report(event_dicts, incident_id=4)

        assert report.severity in ("low", "medium")
        assert report.confidence < 0.7  # Lower confidence for benign

    def test_no_hardcoded_key_mapping(self):
        """Verify no key-based technique mapping."""
        # Same behavior with different "key hints" should produce same result
        events_base = [
            {
                "timestamp": "2025-01-18T00:00:00Z",
                "ip": "1.2.3.4",
                "method": "GET",
                "path": "/.env",
                "status_code": 404,
                "user_agent": "curl",
            },
            {
                "timestamp": "2025-01-18T00:00:01Z",
                "ip": "1.2.3.4",
                "method": "GET",
                "path": "/.git/config",
                "status_code": 403,
                "user_agent": "curl",
            },
        ]

        # With different context hints
        report1 = analyze_and_report(
            events_base,
            context={"key_scope": "admin", "deployment_surface": "docker"},
        )
        report2 = analyze_and_report(
            events_base,
            context={"key_scope": "read-only", "deployment_surface": "frontend"},
        )

        # Techniques should be the same (based on behavior, not context)
        assert report1.techniques == report2.techniques
        assert report1.attacker_sophistication == report2.attacker_sophistication
