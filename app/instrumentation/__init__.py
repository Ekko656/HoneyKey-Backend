"""
HoneyKey API Instrumentation Layer.

This module provides transparent API proxying with:
- Comprehensive telemetry capture
- Behavioral classification (normal/suspicious/malicious)
- SOC-ready event generation with MITRE ATT&CK mapping

Example Usage:

    from app.instrumentation import (
        APIProxy,
        ProxyConfig,
        create_soc_event,
    )

    # Create a proxy for Stripe API
    proxy = APIProxy(ProxyConfig(
        name="stripe",
        target_base_url="https://api.stripe.com",
    ))

    # Forward a request
    async with proxy:
        response = await proxy.forward(
            method="GET",
            path="/v1/charges",
            headers={"Authorization": "Bearer sk_test_..."},
            source_ip="192.168.1.1",
        )

    # Generate SOC event
    soc_event = create_soc_event(response.telemetry, response.classification)
    print(soc_event.to_dict())

Module Components:
    - telemetry: Request/response capture and formatting
    - classifier: Behavioral analysis and scoring
    - proxy: HTTP forwarding layer
    - soc_events: SOC-compatible event generation
"""

from .telemetry import (
    RequestTelemetry,
    ResponseTelemetry,
    TelemetryRecord,
    capture_request,
    capture_response,
    create_telemetry_record,
    generate_request_id,
)

from .classifier import (
    Classification,
    ClassificationResult,
    RequestContext,
    Signal,
    classify_request,
    classify_request_simple,
    get_classification_summary,
)

from .proxy import (
    APIProxy,
    ProxyConfig,
    ProxyResponse,
    SyncAPIProxy,
    TelemetryCallback,
    create_github_proxy,
    create_openai_proxy,
    create_stripe_proxy,
)

from .soc_events import (
    EvidenceItem,
    MitreTechnique,
    SOCEvent,
    create_soc_event,
    format_soc_event_for_logging,
    generate_analyst_notes,
    generate_evidence,
    generate_recommended_actions,
    generate_summary,
    get_mitre_techniques,
)

__all__ = [
    # Telemetry
    "RequestTelemetry",
    "ResponseTelemetry",
    "TelemetryRecord",
    "capture_request",
    "capture_response",
    "create_telemetry_record",
    "generate_request_id",
    # Classifier
    "Classification",
    "ClassificationResult",
    "RequestContext",
    "Signal",
    "classify_request",
    "classify_request_simple",
    "get_classification_summary",
    # Proxy
    "APIProxy",
    "ProxyConfig",
    "ProxyResponse",
    "SyncAPIProxy",
    "TelemetryCallback",
    "create_github_proxy",
    "create_openai_proxy",
    "create_stripe_proxy",
    # SOC Events
    "EvidenceItem",
    "MitreTechnique",
    "SOCEvent",
    "create_soc_event",
    "format_soc_event_for_logging",
    "generate_analyst_notes",
    "generate_evidence",
    "generate_recommended_actions",
    "generate_summary",
    "get_mitre_techniques",
]
