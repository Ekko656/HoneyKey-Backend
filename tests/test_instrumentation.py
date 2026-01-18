"""Tests for the HoneyKey API instrumentation layer."""

import json

import pytest

from app.instrumentation.telemetry import (
    capture_request,
    capture_response,
    create_telemetry_record,
    extract_api_key,
    extract_error_info,
    generate_request_id,
    redact_headers,
    redact_query_params,
)
from app.instrumentation.classifier import (
    Classification,
    ClassificationResult,
    RequestContext,
    Signal,
    classify_request,
    classify_request_simple,
    detect_endpoint_enumeration,
    detect_injection_attempt,
    detect_non_sdk_headers,
    detect_spoofed_user_agent,
    get_classification_summary,
)
from app.instrumentation.soc_events import (
    SOCEvent,
    create_soc_event,
    generate_analyst_notes,
    generate_evidence,
    generate_recommended_actions,
    generate_summary,
    get_mitre_techniques,
)


# =============================================================================
# Telemetry Tests
# =============================================================================

class TestTelemetry:
    def test_generate_request_id_format(self):
        """Request IDs have expected format."""
        req_id = generate_request_id()
        assert req_id.startswith("req_")
        parts = req_id.split("_")
        assert len(parts) == 3
        assert parts[1].isdigit()  # timestamp

    def test_generate_request_id_unique(self):
        """Request IDs are unique."""
        ids = [generate_request_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_redact_headers_sensitive(self):
        """Sensitive headers are redacted."""
        headers = {
            "Authorization": "Bearer sk_test_secret",
            "X-API-Key": "secret_key",
            "Content-Type": "application/json",
            "User-Agent": "test-client/1.0",
        }
        redacted = redact_headers(headers)
        assert redacted["Authorization"] == "[REDACTED]"
        assert redacted["X-API-Key"] == "[REDACTED]"
        assert redacted["Content-Type"] == "application/json"
        assert redacted["User-Agent"] == "test-client/1.0"

    def test_redact_headers_excludes(self):
        """Excluded headers are removed entirely."""
        headers = {
            "Proxy-Authorization": "secret",
            "Content-Type": "application/json",
        }
        redacted = redact_headers(headers)
        assert "Proxy-Authorization" not in redacted
        assert "Content-Type" in redacted

    def test_extract_api_key_bearer(self):
        """API key extracted from Bearer token."""
        headers = {"Authorization": "Bearer sk_test_1234567890abcdef"}
        prefix, hash_val = extract_api_key(headers)
        assert prefix == "sk_test_"
        assert hash_val is not None
        assert len(hash_val) == 64  # SHA-256 hex

    def test_extract_api_key_x_api_key(self):
        """API key extracted from X-API-Key header."""
        headers = {"X-API-Key": "key_abcd1234efgh5678"}
        prefix, hash_val = extract_api_key(headers)
        assert prefix == "key_abcd"
        assert hash_val is not None

    def test_extract_api_key_none(self):
        """Returns None when no API key present."""
        headers = {"Content-Type": "application/json"}
        prefix, hash_val = extract_api_key(headers)
        assert prefix is None
        assert hash_val is None

    def test_redact_query_params(self):
        """Sensitive query params are redacted."""
        params = {
            "api_key": "secret123",
            "page": "1",
            "token": "abc123",
        }
        redacted = redact_query_params(params)
        assert redacted["api_key"] == "[REDACTED]"
        assert redacted["page"] == "1"
        assert redacted["token"] == "[REDACTED]"

    def test_capture_request(self):
        """Request telemetry is captured correctly."""
        telemetry = capture_request(
            request_id="req_test_123",
            source_ip="192.168.1.100",
            method="POST",
            path="/v1/charges",
            headers={
                "Authorization": "Bearer sk_test_key",
                "Content-Type": "application/json",
            },
            query_params={"expand[]": "customer"},
            body=b'{"amount": 1000}',
        )
        assert telemetry.request_id == "req_test_123"
        assert telemetry.source_ip == "192.168.1.100"
        assert telemetry.method == "POST"
        assert telemetry.path == "/v1/charges"
        assert telemetry.api_key_prefix == "sk_test_"
        assert telemetry.body_size == 16
        assert telemetry.body_hash is not None

    def test_extract_error_info_json(self):
        """Error info extracted from JSON response."""
        body = b'{"error": {"type": "invalid_request_error", "message": "Invalid API key"}}'
        error_type, error_msg = extract_error_info(401, body)
        assert error_type == "invalid_request_error"
        assert error_msg == "Invalid API key"

    def test_extract_error_info_simple(self):
        """Error info extracted from simple error format."""
        body = b'{"error": "Something went wrong"}'
        error_type, error_msg = extract_error_info(500, body)
        assert error_type is None
        assert error_msg == "Something went wrong"

    def test_extract_error_info_success(self):
        """No error info for success responses."""
        body = b'{"data": "success"}'
        error_type, error_msg = extract_error_info(200, body)
        assert error_type is None
        assert error_msg is None

    def test_capture_response(self):
        """Response telemetry is captured correctly."""
        telemetry = capture_response(
            request_id="req_test_123",
            status_code=401,
            latency_ms=150.5,
            body=b'{"error": {"message": "Unauthorized"}}',
        )
        assert telemetry.request_id == "req_test_123"
        assert telemetry.status_code == 401
        assert telemetry.latency_ms == 150.5
        assert telemetry.is_auth_error is True
        assert telemetry.is_rate_limited is False
        assert telemetry.error_message == "Unauthorized"

    def test_capture_response_rate_limited(self):
        """Rate limited responses are flagged."""
        telemetry = capture_response(
            request_id="req_test_123",
            status_code=429,
            latency_ms=50.0,
        )
        assert telemetry.is_rate_limited is True
        assert telemetry.is_auth_error is False


# =============================================================================
# Classifier Tests
# =============================================================================

class TestClassifier:
    def _make_telemetry(
        self,
        user_agent: str = "test-client/1.0",
        path: str = "/v1/test",
        status_code: int = 200,
        target_api: str = "stripe",
    ):
        """Helper to create telemetry record for testing."""
        req = capture_request(
            request_id="req_test",
            source_ip="192.168.1.1",
            method="GET",
            path=path,
            headers={"User-Agent": user_agent, "Authorization": "Bearer sk_test"},
        )
        resp = capture_response(
            request_id="req_test",
            status_code=status_code,
            latency_ms=100.0,
        )
        return create_telemetry_record(req, resp, target_api)

    def test_detect_non_sdk_headers(self):
        """Non-SDK user agents are detected."""
        record = self._make_telemetry(user_agent="curl/7.88.1", target_api="stripe")
        detected, details = detect_non_sdk_headers(record)
        assert detected is True
        assert "curl" in details["user_agent"]

    def test_detect_sdk_headers_valid(self):
        """Valid SDK user agents pass."""
        record = self._make_telemetry(user_agent="Stripe/v1 python", target_api="stripe")
        detected, _ = detect_non_sdk_headers(record)
        assert detected is False

    def test_detect_spoofed_user_agent(self):
        """Suspicious user agents are detected."""
        suspicious_agents = ["curl/7.88", "python-requests/2.28", "sqlmap/1.0"]
        for ua in suspicious_agents:
            record = self._make_telemetry(user_agent=ua)
            detected, details = detect_spoofed_user_agent(record)
            assert detected is True, f"Should detect {ua}"

    def test_detect_endpoint_enumeration_known_paths(self):
        """Known enumeration paths are detected."""
        enum_paths = ["/.env", "/.git/config", "/admin/config", "/swagger.json"]
        for path in enum_paths:
            record = self._make_telemetry(path=path)
            detected, details = detect_endpoint_enumeration(record)
            assert detected is True, f"Should detect enumeration in {path}"

    def test_detect_endpoint_enumeration_history(self):
        """Enumeration detected from request history."""
        record = self._make_telemetry(path="/v1/normal")
        recent = ["/v1/a", "/v1/b", "/v1/c", "/v1/d", "/v1/e", "/v1/f"]
        detected, details = detect_endpoint_enumeration(record, recent)
        assert detected is True
        assert details["unique_paths_count"] >= 5

    def test_detect_injection_attempt(self):
        """Injection patterns are detected."""
        injection_paths = [
            "/v1/users/../admin",
            "/v1/search?q=<script>alert(1)</script>",
            "/v1/data?id=1' OR '1'='1",
        ]
        for path in injection_paths:
            record = self._make_telemetry(path=path)
            detected, details = detect_injection_attempt(record)
            assert detected is True, f"Should detect injection in {path}"

    def test_classify_normal_request(self):
        """Normal requests are classified correctly."""
        record = self._make_telemetry(
            user_agent="Stripe/v1 python",
            path="/v1/charges",
            status_code=200,
            target_api="stripe",
        )
        result = classify_request_simple(record)
        assert result.classification == Classification.NORMAL
        assert result.confidence >= 0.9
        assert result.risk_score < 25

    def test_classify_suspicious_request(self):
        """Suspicious requests are classified correctly."""
        record = self._make_telemetry(
            user_agent="curl/7.88.1",
            path="/v1/charges",
            status_code=401,
        )
        context = RequestContext(recent_auth_errors=3)
        result = classify_request(record, context)
        assert result.classification in (Classification.SUSPICIOUS, Classification.MALICIOUS)
        assert result.risk_score >= 25

    def test_classify_malicious_request(self):
        """Malicious requests are classified correctly."""
        record = self._make_telemetry(
            user_agent="sqlmap/1.4",
            path="/v1/users?id=1' OR '1'='1",
            status_code=500,
        )
        result = classify_request_simple(record)
        assert result.classification == Classification.MALICIOUS
        assert result.risk_score >= 60
        assert Signal.INJECTION_ATTEMPT in result.signals

    def test_classification_result_to_dict(self):
        """Classification result serializes correctly."""
        result = ClassificationResult(
            classification=Classification.SUSPICIOUS,
            confidence=0.82,
            signals=[Signal.ENDPOINT_ENUMERATION, Signal.RAPID_RETRIES],
            signal_details={"endpoint_enumeration": {"path": "/test"}},
            risk_score=45,
        )
        d = result.to_dict()
        assert d["classification"] == "suspicious"
        assert d["confidence"] == 0.82
        assert "endpoint_enumeration" in d["signals"]
        assert d["risk_score"] == 45

    def test_get_classification_summary_normal(self):
        """Summary for normal request."""
        result = ClassificationResult(
            classification=Classification.NORMAL,
            confidence=0.95,
            signals=[],
            risk_score=0,
        )
        summary = get_classification_summary(result)
        assert "Normal" in summary
        assert "95%" in summary

    def test_get_classification_summary_malicious(self):
        """Summary for malicious request."""
        result = ClassificationResult(
            classification=Classification.MALICIOUS,
            confidence=0.88,
            signals=[Signal.INJECTION_ATTEMPT, Signal.SPOOFED_USER_AGENT],
            risk_score=75,
        )
        summary = get_classification_summary(result)
        assert "MALICIOUS" in summary
        assert "75/100" in summary


# =============================================================================
# SOC Events Tests
# =============================================================================

class TestSOCEvents:
    def _make_telemetry_and_classification(
        self,
        classification: Classification = Classification.SUSPICIOUS,
        signals: list = None,
    ):
        """Helper to create test data."""
        from app.instrumentation.telemetry import (
            capture_request,
            capture_response,
            create_telemetry_record,
        )

        req = capture_request(
            request_id="req_test_soc",
            source_ip="10.0.0.50",
            method="GET",
            path="/v1/secrets",
            headers={
                "User-Agent": "curl/7.88.1",
                "Authorization": "Bearer sk_test_123",
            },
        )
        resp = capture_response(
            request_id="req_test_soc",
            status_code=401,
            latency_ms=85.5,
            body=b'{"error": {"message": "Invalid API key"}}',
        )
        telemetry = create_telemetry_record(req, resp, "stripe")

        result = ClassificationResult(
            classification=classification,
            confidence=0.85,
            signals=signals or [Signal.NON_SDK_HEADERS, Signal.AUTH_ERROR_PERSISTENCE],
            signal_details={},
            risk_score=45,
        )

        return telemetry, result

    def test_get_mitre_techniques(self):
        """MITRE techniques are mapped from signals."""
        signals = [Signal.AUTH_ERROR_PERSISTENCE, Signal.INJECTION_ATTEMPT]
        techniques = get_mitre_techniques(signals)
        assert len(techniques) >= 2
        technique_ids = [t.technique_id for t in techniques]
        assert "T1110" in technique_ids  # Brute Force
        assert "T1190" in technique_ids  # Exploit Public-Facing Application

    def test_get_mitre_techniques_empty(self):
        """Default technique returned for empty signals."""
        techniques = get_mitre_techniques([])
        assert len(techniques) == 1
        assert techniques[0].technique_id == "T1595.002"

    def test_generate_evidence(self):
        """Evidence is generated from telemetry."""
        telemetry, classification = self._make_telemetry_and_classification()
        evidence = generate_evidence(telemetry, classification)
        assert len(evidence) >= 4
        categories = [e.category for e in evidence]
        assert "source" in categories
        assert "client" in categories
        assert "request" in categories

    def test_generate_summary_suspicious(self):
        """Summary generated for suspicious request."""
        telemetry, classification = self._make_telemetry_and_classification(
            classification=Classification.SUSPICIOUS,
        )
        summary = generate_summary(telemetry, classification)
        assert "Suspicious" in summary
        assert "10.0.0.50" in summary
        assert "stripe" in summary

    def test_generate_summary_malicious(self):
        """Summary generated for malicious request."""
        telemetry, classification = self._make_telemetry_and_classification(
            classification=Classification.MALICIOUS,
            signals=[Signal.INJECTION_ATTEMPT],
        )
        classification.risk_score = 75
        summary = generate_summary(telemetry, classification)
        assert "MALICIOUS" in summary
        assert "75/100" in summary

    def test_generate_analyst_notes(self):
        """Analyst notes explain classification."""
        telemetry, classification = self._make_telemetry_and_classification(
            signals=[Signal.AUTH_ERROR_PERSISTENCE, Signal.NON_SDK_HEADERS],
        )
        notes = generate_analyst_notes(telemetry, classification)
        assert "SUSPICIOUS" in notes or "classified" in notes
        assert "authentication" in notes.lower() or "auth" in notes.lower()

    def test_generate_recommended_actions_malicious(self):
        """Recommendations for malicious include blocking."""
        telemetry, classification = self._make_telemetry_and_classification(
            classification=Classification.MALICIOUS,
            signals=[Signal.INJECTION_ATTEMPT],
        )
        classification.risk_score = 75
        actions = generate_recommended_actions(classification, "10.0.0.50")
        assert any("block" in a.lower() for a in actions)
        assert any("10.0.0.50" in a for a in actions)

    def test_generate_recommended_actions_injection(self):
        """Injection attempts get critical recommendations."""
        classification = ClassificationResult(
            classification=Classification.MALICIOUS,
            confidence=0.95,
            signals=[Signal.INJECTION_ATTEMPT],
            risk_score=80,
        )
        actions = generate_recommended_actions(classification, "1.2.3.4")
        assert any("CRITICAL" in a for a in actions)
        assert any("injection" in a.lower() for a in actions)

    def test_create_soc_event_complete(self):
        """Complete SOC event is created."""
        telemetry, classification = self._make_telemetry_and_classification()
        event = create_soc_event(telemetry, classification)

        assert event.event_id == "req_test_soc"
        assert event.source_ip == "10.0.0.50"
        assert event.target_api == "stripe"
        assert event.method == "GET"
        assert event.path == "/v1/secrets"
        assert event.status_code == 401
        assert event.classification == "suspicious"
        assert event.confidence == 0.85
        assert len(event.mitre_techniques) > 0
        assert len(event.evidence) > 0
        assert len(event.recommended_actions) > 0
        assert event.summary != ""
        assert event.analyst_notes != ""

    def test_soc_event_to_dict(self):
        """SOC event serializes to dict."""
        telemetry, classification = self._make_telemetry_and_classification()
        event = create_soc_event(telemetry, classification)
        d = event.to_dict()

        assert "event_id" in d
        assert "mitre_techniques" in d
        assert "evidence" in d
        assert "recommended_actions" in d
        assert isinstance(d["mitre_techniques"], list)
        assert isinstance(d["evidence"], list)

    def test_soc_event_json_serializable(self):
        """SOC event can be serialized to JSON."""
        telemetry, classification = self._make_telemetry_and_classification()
        event = create_soc_event(telemetry, classification)

        # Should not raise
        json_str = json.dumps(event.to_dict())
        assert len(json_str) > 0

        # Should be parseable
        parsed = json.loads(json_str)
        assert parsed["event_id"] == event.event_id


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    def test_full_pipeline_normal_request(self):
        """Full pipeline for normal request."""
        from app.instrumentation import (
            capture_request,
            capture_response,
            create_telemetry_record,
            classify_request_simple,
            create_soc_event,
        )

        # Simulate normal SDK request
        req = capture_request(
            request_id="req_normal",
            source_ip="192.168.1.1",
            method="POST",
            path="/v1/charges",
            headers={
                "User-Agent": "Stripe/v1 python",
                "Authorization": "Bearer sk_live_real",
                "Content-Type": "application/json",
            },
            body=b'{"amount": 1000, "currency": "usd"}',
        )
        resp = capture_response(
            request_id="req_normal",
            status_code=200,
            latency_ms=250.0,
            body=b'{"id": "ch_123", "amount": 1000}',
        )
        telemetry = create_telemetry_record(req, resp, "stripe")

        classification = classify_request_simple(telemetry)
        assert classification.classification == Classification.NORMAL

        event = create_soc_event(telemetry, classification)
        assert "Normal" in event.summary
        assert event.risk_score < 25

    def test_full_pipeline_attack_request(self):
        """Full pipeline for attack request."""
        from app.instrumentation import (
            capture_request,
            capture_response,
            create_telemetry_record,
            classify_request,
            create_soc_event,
            RequestContext,
        )

        # Simulate malicious request
        req = capture_request(
            request_id="req_attack",
            source_ip="45.33.32.1",
            method="GET",
            path="/v1/customers?email=' OR '1'='1",
            headers={
                "User-Agent": "sqlmap/1.4.7",
                "Authorization": "Bearer stolen_key_123",
            },
        )
        resp = capture_response(
            request_id="req_attack",
            status_code=401,
            latency_ms=50.0,
            body=b'{"error": {"type": "authentication_error"}}',
        )
        telemetry = create_telemetry_record(req, resp, "stripe")

        # Add context of previous failures
        context = RequestContext(
            recent_auth_errors=5,
            requests_last_minute=45,
        )

        classification = classify_request(telemetry, context)
        assert classification.classification == Classification.MALICIOUS
        assert Signal.INJECTION_ATTEMPT in classification.signals

        event = create_soc_event(telemetry, classification)
        assert "MALICIOUS" in event.summary
        assert any("T1190" in t["id"] for t in event.mitre_techniques)
        assert any("block" in a.lower() for a in event.recommended_actions)

    def test_telemetry_callback_integration(self):
        """Telemetry callback receives data."""
        from app.instrumentation import (
            capture_request,
            capture_response,
            create_telemetry_record,
            classify_request_simple,
            TelemetryRecord,
            ClassificationResult,
        )

        captured = []

        def callback(telemetry: TelemetryRecord, classification: ClassificationResult):
            captured.append((telemetry, classification))

        # Simulate the callback being invoked (as proxy would do)
        req = capture_request(
            request_id="req_cb",
            source_ip="10.0.0.1",
            method="GET",
            path="/test",
            headers={"User-Agent": "test"},
        )
        resp = capture_response("req_cb", 200, 100.0)
        telemetry = create_telemetry_record(req, resp, "test")
        classification = classify_request_simple(telemetry)

        callback(telemetry, classification)

        assert len(captured) == 1
        assert captured[0][0].request.request_id == "req_cb"
