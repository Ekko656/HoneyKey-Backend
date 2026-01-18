"""
HoneyKey Behavioral Detection Module.

This module provides behavior-driven attack detection that infers
MITRE ATT&CK techniques from observed patterns WITHOUT relying on
key identity or hardcoded mappings.

The detection pipeline:
1. Feature Extraction: Extract behavioral signals from HTTP events
2. Technique Inference: Map behaviors to MITRE techniques (LLM or heuristic)
3. SOC Report Generation: Produce HoneyKey-compatible reports

Example Usage:

    from app.detection import analyze_and_report

    # Analyze events and generate SOC report
    events = [
        {
            "timestamp": "2025-01-18T00:00:00Z",
            "ip": "192.168.1.100",
            "method": "GET",
            "path": "/v1/secrets",
            "status_code": 401,
            "user_agent": "curl/7.88.1"
        },
        # ... more events
    ]

    report = analyze_and_report(events, incident_id=42)

    # Get HoneyKey-compatible format
    print(report.to_honeykey_format())
    # {"incident_id": 42, "severity": "high", "summary": "...", ...}

    # Or get full behavioral analysis
    print(report.to_dict())

Module Components:
    - behavior_features: Extract behavioral signals from events
    - technique_inference: Map behaviors to MITRE ATT&CK
    - behavioral_soc: Generate SOC-compatible reports
"""

from .behavior_features import (
    BehavioralFeatures,
    ContextualHints,
    HTTPEvent,
    extract_behavioral_features,
    extract_features_from_dicts,
    extract_temporal_features,
    extract_endpoint_features,
    extract_auth_features,
    extract_response_features,
    extract_client_features,
    extract_method_features,
    extract_sequence_features,
    extract_injection_features,
)

from .technique_inference import (
    InferredTechnique,
    TechniqueInferenceResult,
    build_inference_prompt,
    infer_techniques,
    infer_techniques_heuristic,
    infer_techniques_with_gemini,
    parse_inference_response,
)

from .behavioral_soc import (
    BehavioralSOCReport,
    RecommendedResponse,
    RiskAssessment,
    analyze_and_report,
    assess_risk,
    generate_behavioral_soc_report,
    generate_evidence_summary,
    generate_recommendations,
    generate_summary,
)

__all__ = [
    # Feature Extraction
    "BehavioralFeatures",
    "ContextualHints",
    "HTTPEvent",
    "extract_behavioral_features",
    "extract_features_from_dicts",
    "extract_temporal_features",
    "extract_endpoint_features",
    "extract_auth_features",
    "extract_response_features",
    "extract_client_features",
    "extract_method_features",
    "extract_sequence_features",
    "extract_injection_features",
    # Technique Inference
    "InferredTechnique",
    "TechniqueInferenceResult",
    "build_inference_prompt",
    "infer_techniques",
    "infer_techniques_heuristic",
    "infer_techniques_with_gemini",
    "parse_inference_response",
    # SOC Reports
    "BehavioralSOCReport",
    "RecommendedResponse",
    "RiskAssessment",
    "analyze_and_report",
    "assess_risk",
    "generate_behavioral_soc_report",
    "generate_evidence_summary",
    "generate_recommendations",
    "generate_summary",
]
