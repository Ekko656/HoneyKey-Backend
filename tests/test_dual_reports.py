"""Tests for the dual reports module."""

import json
import pytest
from datetime import datetime, timedelta

from app.integration.dual_reports import (
    ExecutiveReport,
    EngineerReport,
    DualReport,
    build_dual_report_prompt,
    parse_dual_report_response,
    generate_fallback_dual_report,
    generate_dual_report,
    extract_context,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def sample_incident():
    """Sample incident data."""
    return {
        "id": 1,
        "key_id": "honeypot",
        "source_ip": "192.168.1.100",
        "first_seen": "2024-01-15T10:00:00Z",
        "last_seen": "2024-01-15T10:30:00Z",
        "event_count": 50,
    }


@pytest.fixture
def sample_events():
    """Sample event list."""
    base_time = datetime(2024, 1, 15, 10, 0, 0)
    events = []
    paths = ["/v1/users", "/v1/projects", "/admin", "/v1/secrets", "/api/keys"]

    for i in range(50):
        events.append({
            "ts": (base_time + timedelta(seconds=i * 30)).isoformat(),
            "ip": "192.168.1.100",
            "method": "GET" if i % 3 != 0 else "POST",
            "path": paths[i % len(paths)],
            "user_agent": "python-requests/2.28.0",
            "correlation_id": f"corr-{i}",
            "auth_present": True,
            "honeypot_key_used": True,
        })
    return events


@pytest.fixture
def sample_llm_response():
    """Sample valid LLM response."""
    return json.dumps({
        "executive_report": {
            "incident_id": 1,
            "severity": "Medium",
            "risk_level": "Moderate",
            "what_happened": "Someone with a leaked credential attempted to access our systems. They made 50 requests over 30 minutes but all were blocked.",
            "business_impact": "No data was compromised. However, a credential leak indicates a potential process gap.",
            "threat_contained": True,
            "key_findings": [
                "50 unauthorized access attempts detected",
                "Automated tools were used",
                "All attempts were blocked"
            ],
            "recommended_decisions": [
                "Review credential management processes",
                "Consider additional monitoring"
            ]
        },
        "engineer_report": {
            "incident_id": 1,
            "severity": "Medium",
            "confidence_score": 0.75,
            "summary": "Honeypot abuse from 192.168.1.100 with automated scanning behavior.",
            "techniques": ["T1595: Active Scanning", "T1078: Valid Accounts"],
            "kill_chain_phase": "Reconnaissance",
            "attacker_sophistication": "Medium",
            "event_count": 50,
            "time_window_minutes": 30.0,
            "request_rate_per_minute": 1.67,
            "unique_endpoints": 5,
            "source_ip": "192.168.1.100",
            "user_agents": ["python-requests/2.28.0"],
            "targeted_endpoints": ["/v1/users", "/v1/projects", "/admin"],
            "behavioral_indicators": [
                "Automated timing patterns",
                "Endpoint enumeration behavior"
            ],
            "recommended_actions": [
                "Block IP at firewall",
                "Rotate honeypot key"
            ],
            "ioc_list": ["IP: 192.168.1.100", "Key: honeypot"]
        }
    })


# =============================================================================
# EXECUTIVE REPORT TESTS
# =============================================================================

class TestExecutiveReport:
    """Tests for ExecutiveReport dataclass."""

    def test_create_executive_report(self):
        """Test creating an executive report."""
        report = ExecutiveReport(
            incident_id=1,
            severity="Medium",
            risk_level="Moderate",
            what_happened="Someone tried to access our systems.",
            business_impact="No data was compromised.",
            threat_contained=True,
            key_findings=["Finding 1", "Finding 2"],
            recommended_decisions=["Decision 1"],
        )
        assert report.incident_id == 1
        assert report.severity == "Medium"
        assert report.threat_contained is True

    def test_executive_report_to_dict(self):
        """Test converting executive report to dict."""
        report = ExecutiveReport(
            incident_id=1,
            severity="High",
            risk_level="Significant",
            what_happened="Test",
            business_impact="Impact",
            threat_contained=False,
            key_findings=["F1"],
            recommended_decisions=["D1"],
        )
        d = report.to_dict()
        assert d["incident_id"] == 1
        assert d["severity"] == "High"
        assert d["threat_contained"] is False
        assert isinstance(d["key_findings"], list)


# =============================================================================
# ENGINEER REPORT TESTS
# =============================================================================

class TestEngineerReport:
    """Tests for EngineerReport dataclass."""

    def test_create_engineer_report(self):
        """Test creating an engineer report."""
        report = EngineerReport(
            incident_id=1,
            severity="High",
            confidence_score=0.85,
            summary="Technical summary",
            techniques=["T1595: Active Scanning"],
            kill_chain_phase="Reconnaissance",
            attacker_sophistication="Medium",
            event_count=100,
            time_window_minutes=60.0,
            request_rate_per_minute=1.67,
            unique_endpoints=10,
            source_ip="10.0.0.1",
            user_agents=["curl/7.68"],
            targeted_endpoints=["/api/v1"],
            behavioral_indicators=["Indicator 1"],
            recommended_actions=["Action 1"],
            ioc_list=["IOC 1"],
        )
        assert report.incident_id == 1
        assert report.confidence_score == 0.85
        assert len(report.techniques) == 1

    def test_engineer_report_to_dict(self):
        """Test converting engineer report to dict."""
        report = EngineerReport(
            incident_id=2,
            severity="Critical",
            confidence_score=0.95,
            summary="Summary",
            techniques=["T1078", "T1595"],
            kill_chain_phase="Initial Access",
            attacker_sophistication="High",
            event_count=500,
            time_window_minutes=10.0,
            request_rate_per_minute=50.0,
            unique_endpoints=20,
            source_ip="1.2.3.4",
            user_agents=["UA1", "UA2"],
            targeted_endpoints=["/admin", "/api"],
            behavioral_indicators=["I1", "I2"],
            recommended_actions=["A1"],
            ioc_list=["IP: 1.2.3.4"],
        )
        d = report.to_dict()
        assert d["incident_id"] == 2
        assert d["confidence_score"] == 0.95
        assert d["event_count"] == 500


# =============================================================================
# DUAL REPORT TESTS
# =============================================================================

class TestDualReport:
    """Tests for DualReport dataclass."""

    def test_create_dual_report(self):
        """Test creating a dual report."""
        exec_report = ExecutiveReport(
            incident_id=1,
            severity="Medium",
            risk_level="Moderate",
            what_happened="Test",
            business_impact="Impact",
            threat_contained=True,
            key_findings=[],
            recommended_decisions=[],
        )
        eng_report = EngineerReport(
            incident_id=1,
            severity="Medium",
            confidence_score=0.7,
            summary="Summary",
            techniques=[],
            kill_chain_phase="Recon",
            attacker_sophistication="Low",
            event_count=10,
            time_window_minutes=5.0,
            request_rate_per_minute=2.0,
            unique_endpoints=3,
            source_ip="127.0.0.1",
            user_agents=[],
            targeted_endpoints=[],
            behavioral_indicators=[],
            recommended_actions=[],
        )
        dual = DualReport(executive=exec_report, engineer=eng_report)
        assert dual.executive.incident_id == 1
        assert dual.engineer.incident_id == 1

    def test_dual_report_to_dict(self):
        """Test converting dual report to dict."""
        exec_report = ExecutiveReport(
            incident_id=1, severity="Low", risk_level="Minimal",
            what_happened="W", business_impact="B", threat_contained=True,
            key_findings=[], recommended_decisions=[],
        )
        eng_report = EngineerReport(
            incident_id=1, severity="Low", confidence_score=0.5, summary="S",
            techniques=[], kill_chain_phase="Recon", attacker_sophistication="Low",
            event_count=5, time_window_minutes=1.0, request_rate_per_minute=5.0,
            unique_endpoints=1, source_ip="127.0.0.1", user_agents=[],
            targeted_endpoints=[], behavioral_indicators=[], recommended_actions=[],
        )
        dual = DualReport(executive=exec_report, engineer=eng_report)
        d = dual.to_dict()
        assert "executive_report" in d
        assert "engineer_report" in d


# =============================================================================
# PROMPT BUILDER TESTS
# =============================================================================

class TestBuildDualReportPrompt:
    """Tests for build_dual_report_prompt function."""

    def test_build_prompt_basic(self, sample_incident, sample_events):
        """Test building a basic prompt."""
        prompt = build_dual_report_prompt(sample_incident, sample_events)
        assert "executive_report" in prompt
        assert "engineer_report" in prompt
        assert "192.168.1.100" in prompt

    def test_build_prompt_includes_incident_id(self, sample_incident, sample_events):
        """Test that prompt includes incident ID."""
        prompt = build_dual_report_prompt(sample_incident, sample_events)
        assert '"incident_id": 1' in prompt or "'incident_id': 1" in prompt

    def test_build_prompt_includes_behavioral_analysis(self, sample_incident, sample_events):
        """Test that prompt includes behavioral analysis."""
        prompt = build_dual_report_prompt(sample_incident, sample_events)
        assert "BEHAVIORAL ANALYSIS" in prompt

    def test_build_prompt_includes_technique_inference(self, sample_incident, sample_events):
        """Test that prompt includes technique inference."""
        prompt = build_dual_report_prompt(sample_incident, sample_events)
        assert "TECHNIQUE INFERENCE" in prompt

    def test_build_prompt_with_key_hint(self, sample_events):
        """Test building prompt with key hint."""
        incident = {
            "id": 1,
            "key_id": "acme_client_xyz",
            "source_ip": "10.0.0.1",
            "first_seen": "2024-01-15T10:00:00Z",
            "last_seen": "2024-01-15T10:30:00Z",
            "event_count": 20,
        }
        prompt = build_dual_report_prompt(incident, sample_events, key_value="acme_client_xyz")
        assert "client-side JavaScript" in prompt or "acme_client" in prompt


# =============================================================================
# RESPONSE PARSING TESTS
# =============================================================================

class TestParseDualReportResponse:
    """Tests for parse_dual_report_response function."""

    def test_parse_valid_response(self, sample_llm_response):
        """Test parsing a valid LLM response."""
        result = parse_dual_report_response(sample_llm_response, 1)
        assert isinstance(result, DualReport)
        assert result.executive.incident_id == 1
        assert result.engineer.incident_id == 1

    def test_parse_response_with_code_fences(self, sample_llm_response):
        """Test parsing response wrapped in code fences."""
        wrapped = f"```json\n{sample_llm_response}\n```"
        result = parse_dual_report_response(wrapped, 1)
        assert isinstance(result, DualReport)

    def test_parse_response_extracts_severity(self, sample_llm_response):
        """Test that severity is correctly extracted."""
        result = parse_dual_report_response(sample_llm_response, 1)
        assert result.executive.severity == "Medium"
        assert result.engineer.severity == "Medium"

    def test_parse_response_extracts_findings(self, sample_llm_response):
        """Test that findings are correctly extracted."""
        result = parse_dual_report_response(sample_llm_response, 1)
        assert len(result.executive.key_findings) == 3
        assert "blocked" in result.executive.key_findings[2].lower()

    def test_parse_response_extracts_techniques(self, sample_llm_response):
        """Test that techniques are correctly extracted."""
        result = parse_dual_report_response(sample_llm_response, 1)
        assert len(result.engineer.techniques) == 2
        assert "T1595" in result.engineer.techniques[0]

    def test_parse_invalid_json_raises(self):
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError):
            parse_dual_report_response("not json", 1)

    def test_parse_missing_reports_raises(self):
        """Test that missing reports raises ValueError."""
        with pytest.raises(ValueError):
            parse_dual_report_response('{"executive_report": {}}', 1)


# =============================================================================
# FALLBACK GENERATION TESTS
# =============================================================================

class TestGenerateFallbackDualReport:
    """Tests for generate_fallback_dual_report function."""

    def test_fallback_generates_both_reports(self, sample_incident, sample_events):
        """Test that fallback generates both reports."""
        result = generate_fallback_dual_report(sample_incident, sample_events)
        assert isinstance(result, DualReport)
        assert result.executive is not None
        assert result.engineer is not None

    def test_fallback_executive_is_non_technical(self, sample_incident, sample_events):
        """Test that executive report avoids technical jargon."""
        result = generate_fallback_dual_report(sample_incident, sample_events)
        # Should not contain MITRE IDs
        what_happened = result.executive.what_happened.lower()
        assert "t1595" not in what_happened
        assert "t1078" not in what_happened

    def test_fallback_engineer_has_techniques(self, sample_incident, sample_events):
        """Test that engineer report has techniques."""
        result = generate_fallback_dual_report(sample_incident, sample_events)
        assert len(result.engineer.techniques) > 0

    def test_fallback_calculates_metrics(self, sample_incident, sample_events):
        """Test that fallback calculates metrics."""
        result = generate_fallback_dual_report(sample_incident, sample_events)
        assert result.engineer.event_count == 50
        assert result.engineer.source_ip == "192.168.1.100"

    def test_fallback_severity_based_on_behavior(self, sample_incident):
        """Test that severity is based on behavioral analysis."""
        # Events with injection patterns should be Critical
        events_with_injection = [
            {
                "ts": "2024-01-15T10:00:00Z",
                "ip": "10.0.0.1",
                "method": "GET",
                "path": "/api?id=1' OR '1'='1",
                "user_agent": "curl",
                "auth_present": True,
                "honeypot_key_used": True,
            }
        ]
        result = generate_fallback_dual_report(sample_incident, events_with_injection)
        # Should detect injection patterns
        assert result.executive.severity in ["High", "Critical", "Medium"]


# =============================================================================
# GENERATE DUAL REPORT TESTS
# =============================================================================

class TestGenerateDualReport:
    """Tests for generate_dual_report main function."""

    def test_generate_with_llm_response(self, sample_incident, sample_events, sample_llm_response):
        """Test generating with LLM response."""
        result = generate_dual_report(
            sample_incident,
            sample_events,
            llm_response=sample_llm_response,
        )
        assert result.executive.incident_id == 1

    def test_generate_fallback_on_invalid_llm(self, sample_incident, sample_events):
        """Test that fallback is used when LLM response is invalid."""
        result = generate_dual_report(
            sample_incident,
            sample_events,
            llm_response="invalid json",
        )
        # Should still return a valid DualReport (from fallback)
        assert isinstance(result, DualReport)
        assert result.executive.incident_id == 1

    def test_generate_without_llm_response(self, sample_incident, sample_events):
        """Test generating without LLM response (fallback)."""
        result = generate_dual_report(sample_incident, sample_events)
        assert isinstance(result, DualReport)


# =============================================================================
# EXTRACT CONTEXT TESTS
# =============================================================================

class TestExtractContext:
    """Tests for extract_context function."""

    def test_extract_context_returns_tuple(self, sample_events):
        """Test that extract_context returns correct tuple."""
        features, inference, metrics = extract_context(sample_events)
        assert features is not None
        assert inference is not None
        assert isinstance(metrics, dict)

    def test_extract_context_calculates_metrics(self, sample_events):
        """Test that metrics are calculated correctly."""
        _, _, metrics = extract_context(sample_events)
        assert metrics["event_count"] == 50
        assert metrics["unique_endpoints"] == 5

    def test_extract_context_extracts_user_agents(self, sample_events):
        """Test that user agents are extracted."""
        _, _, metrics = extract_context(sample_events)
        assert "python-requests/2.28.0" in metrics["unique_user_agents"]
