"""
LLM-Based MITRE ATT&CK Technique Inference.

Maps observed behavioral features to MITRE ATT&CK techniques using
LLM reasoning. NO hardcoded mappings based on key identity.

The LLM receives ONLY behavioral evidence and must reason about
which techniques explain the observed patterns.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .behavior_features import BehavioralFeatures, ContextualHints


@dataclass
class InferredTechnique:
    """
    A single inferred MITRE ATT&CK technique.

    Attributes:
        technique_id: MITRE technique ID (e.g., "T1595")
        technique_name: Human-readable name
        tactic: MITRE tactic (e.g., "Reconnaissance")
        confidence: Confidence score 0.0-1.0
        evidence: Behavioral evidence supporting this inference
        reasoning: LLM's explanation for this inference
    """
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: list[str]
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.technique_id,
            "name": self.technique_name,
            "tactic": self.tactic,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "reasoning": self.reasoning,
        }


@dataclass
class TechniqueInferenceResult:
    """
    Complete result from technique inference.

    Attributes:
        techniques: List of inferred techniques, ordered by confidence
        attacker_sophistication: Assessed sophistication level
        confidence_overall: Overall confidence in the assessment
        kill_chain_phase: Estimated kill chain phase
        raw_reasoning: Full LLM reasoning text
    """
    techniques: list[InferredTechnique]
    attacker_sophistication: str  # "Novice", "Intermediate", "Advanced", "Expert"
    confidence_overall: float
    kill_chain_phase: str  # "Reconnaissance", "Initial Access", etc.
    raw_reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "attacker_sophistication": self.attacker_sophistication,
            "confidence_overall": round(self.confidence_overall, 2),
            "kill_chain_phase": self.kill_chain_phase,
            "raw_reasoning": self.raw_reasoning,
        }


# =============================================================================
# LLM PROMPT TEMPLATES
# =============================================================================

TECHNIQUE_INFERENCE_PROMPT = """You are a senior threat intelligence analyst. Your task is to analyze behavioral patterns from API request logs and infer which MITRE ATT&CK techniques the attacker is likely using.

CRITICAL RULES:
1. Base ALL inferences on the behavioral evidence provided
2. DO NOT assume anything about the API key identity
3. DO NOT make inferences based on key names or prefixes
4. Only infer techniques that are DIRECTLY supported by the behavioral patterns
5. Assign realistic confidence scores (most should be 0.5-0.85, not 0.95+)

=== BEHAVIORAL EVIDENCE ===

{behavioral_features}

=== CONTEXTUAL HINTS (Optional, treat as unverified) ===

{context_hints}

=== MITRE ATT&CK REFERENCE ===

Consider these relevant techniques based on API/web attack patterns:

RECONNAISSANCE:
- T1595: Active Scanning (probing endpoints, testing responses)
- T1595.001: Scanning IP Blocks
- T1595.002: Vulnerability Scanning
- T1592: Gather Victim Host Information
- T1589: Gather Victim Identity Information

RESOURCE DEVELOPMENT:
- T1586: Compromise Accounts (using stolen credentials)
- T1588.002: Obtain Capabilities: Tool

INITIAL ACCESS:
- T1190: Exploit Public-Facing Application
- T1078: Valid Accounts (using stolen/leaked credentials)
- T1078.004: Cloud Accounts

CREDENTIAL ACCESS:
- T1110: Brute Force
- T1110.001: Password Guessing
- T1110.003: Password Spraying
- T1110.004: Credential Stuffing
- T1552: Unsecured Credentials
- T1552.001: Credentials In Files

DISCOVERY:
- T1083: File and Directory Discovery
- T1087: Account Discovery
- T1580: Cloud Infrastructure Discovery
- T1526: Cloud Service Discovery

COLLECTION:
- T1530: Data from Cloud Storage
- T1213: Data from Information Repositories

DEFENSE EVASION:
- T1036: Masquerading (spoofing user agents)
- T1070: Indicator Removal

=== YOUR ANALYSIS ===

Analyze the behavioral evidence and output a JSON object with this exact structure:

{{
  "techniques": [
    {{
      "id": "T1595",
      "name": "Active Scanning",
      "tactic": "Reconnaissance",
      "confidence": 0.82,
      "evidence": ["High endpoint enumeration score (0.85)", "Probed 15 unique paths in 30 seconds"],
      "reasoning": "The high unique path ratio and rapid request pattern indicates systematic endpoint discovery..."
    }}
  ],
  "attacker_sophistication": "Intermediate",
  "confidence_overall": 0.78,
  "kill_chain_phase": "Reconnaissance",
  "summary_reasoning": "The behavioral pattern suggests an attacker in the reconnaissance phase..."
}}

Rules for your response:
- List 1-4 techniques maximum, ordered by confidence
- Each technique must have specific behavioral evidence
- Confidence scores should reflect actual certainty
- sophistication: "Novice" (script kiddie), "Intermediate" (some skill), "Advanced" (experienced), "Expert" (APT-level)
- kill_chain_phase: The PRIMARY phase based on observed behavior

Return ONLY the JSON object, no other text."""


FEATURE_SUMMARY_TEMPLATE = """TEMPORAL PATTERNS:
- Burst Score: {burst_score} (0=steady, 1=very bursty)
- Request Rate: {request_rate_per_minute:.1f} requests/minute
- Time Span: {time_span_seconds:.1f} seconds
- Temporal Regularity: {temporal_regularity} (0=random, 1=automated/regular)

ENDPOINT PATTERNS:
- Enumeration Score: {enum_score} (0=normal, 1=definite enumeration)
- Unique Paths Ratio: {unique_paths_ratio} ({unique_paths} unique of {total_events} requests)
- Path Depth Variance: {path_depth_variance}
- Sensitive Path Hits: {sensitive_path_hits} (paths like /admin, /.env, /config)

AUTHENTICATION PATTERNS:
- Auth Failure Rate: {auth_failure_rate} (ratio of 401/403 responses)
- Max Consecutive Auth Failures: {auth_retry_count}
- Auth Failure Persistence: {auth_failure_persistence} (0=clustered, 1=spread over time)

RESPONSE PATTERNS:
- Overall Error Rate: {error_rate}
- Rate Limit Hits (429): {rate_limit_hits}
- Server Errors (5xx): {server_error_count}

CLIENT PATTERNS:
- SDK Likelihood: {sdk_likelihood} (0=not SDK, 1=legitimate SDK)
- User Agent Entropy: {user_agent_entropy} (high=multiple UAs)
- Unique User Agents: {unique_user_agents}
- Header Anomaly Score: {header_anomaly_score}

METHOD PATTERNS:
- Distribution: {method_distribution}
- Write Method Ratio: {write_method_ratio} (POST/PUT/DELETE/PATCH)

SEQUENCE PATTERNS:
- Path Transition Entropy: {path_transition_entropy}
- Sequential Probe Score: {sequential_probe_score} (e.g., /1, /2, /3 pattern)
- Path Revisit Count: {backtrack_count}

INJECTION INDICATORS:
- Injection Pattern Count: {injection_pattern_count}
- Payload Anomaly Score: {payload_anomaly_score}

SUMMARY:
- Total Events: {total_events}
- Distinct Source IPs: {distinct_ips}"""


def format_features_for_prompt(features: BehavioralFeatures) -> str:
    """Format behavioral features as human-readable text for the LLM."""
    # Calculate unique paths for display
    unique_paths = int(features.unique_paths_ratio * features.total_events)

    return FEATURE_SUMMARY_TEMPLATE.format(
        burst_score=features.burst_score,
        request_rate_per_minute=features.request_rate_per_minute,
        time_span_seconds=features.time_span_seconds,
        temporal_regularity=features.temporal_regularity,
        enum_score=features.enum_score,
        unique_paths_ratio=features.unique_paths_ratio,
        unique_paths=unique_paths,
        total_events=features.total_events,
        path_depth_variance=features.path_depth_variance,
        sensitive_path_hits=features.sensitive_path_hits,
        auth_failure_rate=features.auth_failure_rate,
        auth_retry_count=features.auth_retry_count,
        auth_failure_persistence=features.auth_failure_persistence,
        error_rate=features.error_rate,
        rate_limit_hits=features.rate_limit_hits,
        server_error_count=features.server_error_count,
        sdk_likelihood=features.sdk_likelihood,
        user_agent_entropy=features.user_agent_entropy,
        unique_user_agents=features.unique_user_agents,
        header_anomaly_score=features.header_anomaly_score,
        method_distribution=features.method_distribution,
        write_method_ratio=features.write_method_ratio,
        path_transition_entropy=features.path_transition_entropy,
        sequential_probe_score=features.sequential_probe_score,
        backtrack_count=features.backtrack_count,
        injection_pattern_count=features.injection_pattern_count,
        payload_anomaly_score=features.payload_anomaly_score,
        distinct_ips=features.distinct_ips,
    )


def format_context_hints(context: Optional[ContextualHints]) -> str:
    """Format contextual hints for the prompt."""
    if not context:
        return "No contextual hints provided."

    hints = []
    if context.key_scope:
        hints.append(f"- Key scope hint: {context.key_scope}")
    if context.deployment_surface:
        hints.append(f"- Deployment surface hint: {context.deployment_surface}")
    if context.is_production is not None:
        hints.append(f"- Production environment: {context.is_production}")
    if context.api_type:
        hints.append(f"- API type hint: {context.api_type}")

    return "\n".join(hints) if hints else "No contextual hints provided."


def build_inference_prompt(
    features: BehavioralFeatures,
    context: Optional[ContextualHints] = None,
) -> str:
    """
    Build the complete LLM prompt for technique inference.

    Args:
        features: Extracted behavioral features
        context: Optional contextual hints

    Returns:
        Complete prompt string
    """
    feature_text = format_features_for_prompt(features)
    context_text = format_context_hints(context)

    return TECHNIQUE_INFERENCE_PROMPT.format(
        behavioral_features=feature_text,
        context_hints=context_text,
    )


# =============================================================================
# RESPONSE PARSING
# =============================================================================

def parse_inference_response(response_text: str) -> TechniqueInferenceResult:
    """
    Parse the LLM response into structured result.

    Args:
        response_text: Raw LLM response text

    Returns:
        TechniqueInferenceResult

    Raises:
        ValueError: If response cannot be parsed
    """
    # Clean up response - handle markdown code blocks
    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        ).strip()

    # Find JSON object
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object found in response")

    json_str = cleaned[start:end + 1]

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in response: {e}")

    # Parse techniques
    techniques = []
    for t in data.get("techniques", []):
        techniques.append(InferredTechnique(
            technique_id=t.get("id", "T0000"),
            technique_name=t.get("name", "Unknown"),
            tactic=t.get("tactic", "Unknown"),
            confidence=float(t.get("confidence", 0.5)),
            evidence=t.get("evidence", []),
            reasoning=t.get("reasoning", ""),
        ))

    return TechniqueInferenceResult(
        techniques=techniques,
        attacker_sophistication=data.get("attacker_sophistication", "Unknown"),
        confidence_overall=float(data.get("confidence_overall", 0.5)),
        kill_chain_phase=data.get("kill_chain_phase", "Unknown"),
        raw_reasoning=data.get("summary_reasoning", ""),
    )


# =============================================================================
# INFERENCE FUNCTIONS
# =============================================================================

# Type alias for LLM call function
LLMCallFunction = Callable[[str], str]


def infer_techniques(
    features: BehavioralFeatures,
    llm_call: LLMCallFunction,
    context: Optional[ContextualHints] = None,
) -> TechniqueInferenceResult:
    """
    Infer MITRE ATT&CK techniques from behavioral features.

    This is the main entry point for technique inference. It:
    1. Builds a prompt from behavioral features
    2. Calls the LLM to reason about techniques
    3. Parses and returns structured results

    Args:
        features: Extracted behavioral features
        llm_call: Function that takes prompt string and returns LLM response
        context: Optional contextual hints

    Returns:
        TechniqueInferenceResult with inferred techniques
    """
    prompt = build_inference_prompt(features, context)
    response = llm_call(prompt)
    return parse_inference_response(response)


def infer_techniques_with_gemini(
    features: BehavioralFeatures,
    api_key: str,
    model: str = "gemini-1.5-pro",
    context: Optional[ContextualHints] = None,
) -> TechniqueInferenceResult:
    """
    Infer techniques using Google Gemini API.

    Args:
        features: Extracted behavioral features
        api_key: Gemini API key
        model: Model name (default: gemini-1.5-pro)
        context: Optional contextual hints

    Returns:
        TechniqueInferenceResult
    """
    from google import genai

    def gemini_call(prompt: str) -> str:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=model, contents=prompt)
        return response.text or ""

    return infer_techniques(features, gemini_call, context)


# =============================================================================
# FALLBACK HEURISTIC INFERENCE
# =============================================================================

def infer_techniques_heuristic(
    features: BehavioralFeatures,
    context: Optional[ContextualHints] = None,
) -> TechniqueInferenceResult:
    """
    Fallback heuristic-based technique inference (no LLM required).

    This provides basic inference when LLM is unavailable. Results are
    less nuanced but still useful for basic detection.

    Args:
        features: Extracted behavioral features
        context: Optional contextual hints

    Returns:
        TechniqueInferenceResult based on heuristic rules
    """
    techniques = []
    reasoning_parts = []

    # Rule 1: High enumeration score -> Active Scanning
    if features.enum_score > 0.6 or features.sensitive_path_hits > 3:
        confidence = min(0.9, 0.5 + features.enum_score * 0.4)
        techniques.append(InferredTechnique(
            technique_id="T1595",
            technique_name="Active Scanning",
            tactic="Reconnaissance",
            confidence=confidence,
            evidence=[
                f"Enumeration score: {features.enum_score:.2f}",
                f"Sensitive path hits: {features.sensitive_path_hits}",
                f"Unique paths ratio: {features.unique_paths_ratio:.2f}",
            ],
            reasoning="High endpoint diversity and sensitive path access indicates active scanning behavior.",
        ))
        reasoning_parts.append("endpoint enumeration detected")

    # Rule 2: Auth failures -> Brute Force / Credential Stuffing
    if features.auth_failure_rate > 0.5 or features.auth_retry_count > 5:
        confidence = min(0.85, 0.5 + features.auth_failure_rate * 0.35)
        technique_id = "T1110.004" if features.auth_retry_count > 10 else "T1110"
        technique_name = "Credential Stuffing" if features.auth_retry_count > 10 else "Brute Force"
        techniques.append(InferredTechnique(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic="Credential Access",
            confidence=confidence,
            evidence=[
                f"Auth failure rate: {features.auth_failure_rate:.2f}",
                f"Consecutive auth failures: {features.auth_retry_count}",
                f"Auth failure persistence: {features.auth_failure_persistence:.2f}",
            ],
            reasoning="Repeated authentication failures suggest credential testing or brute force attempt.",
        ))
        reasoning_parts.append("authentication attacks detected")

    # Rule 3: Injection patterns -> Exploit Public-Facing Application
    if features.injection_pattern_count > 0:
        confidence = min(0.9, 0.6 + features.injection_pattern_count * 0.1)
        techniques.append(InferredTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            confidence=confidence,
            evidence=[
                f"Injection patterns detected: {features.injection_pattern_count}",
                f"Payload anomaly score: {features.payload_anomaly_score:.2f}",
            ],
            reasoning="Injection patterns in requests indicate active exploitation attempts.",
        ))
        reasoning_parts.append("injection attacks detected")

    # Rule 4: Low SDK likelihood + suspicious UA -> Masquerading or custom tooling
    if features.sdk_likelihood < 0.2 and features.header_anomaly_score > 0.3:
        techniques.append(InferredTechnique(
            technique_id="T1036",
            technique_name="Masquerading",
            tactic="Defense Evasion",
            confidence=0.6,
            evidence=[
                f"SDK likelihood: {features.sdk_likelihood:.2f}",
                f"Header anomaly score: {features.header_anomaly_score:.2f}",
                f"Unique user agents: {features.unique_user_agents}",
            ],
            reasoning="Non-SDK client patterns suggest custom tooling or masquerading attempts.",
        ))
        reasoning_parts.append("custom tooling detected")

    # Rule 5: Rate limit hits -> Possible DoS or aggressive scanning
    if features.rate_limit_hits > 3:
        techniques.append(InferredTechnique(
            technique_id="T1498",
            technique_name="Network Denial of Service",
            tactic="Impact",
            confidence=0.55,
            evidence=[
                f"Rate limit hits: {features.rate_limit_hits}",
                f"Request rate: {features.request_rate_per_minute:.1f}/min",
                f"Burst score: {features.burst_score:.2f}",
            ],
            reasoning="Repeated rate limit triggers may indicate DoS attempt or overly aggressive scanning.",
        ))
        reasoning_parts.append("rate abuse detected")

    # If no techniques detected, add generic reconnaissance
    if not techniques:
        techniques.append(InferredTechnique(
            technique_id="T1595.002",
            technique_name="Vulnerability Scanning",
            tactic="Reconnaissance",
            confidence=0.4,
            evidence=[
                f"Total events: {features.total_events}",
                f"Error rate: {features.error_rate:.2f}",
            ],
            reasoning="General API probing behavior without specific attack patterns.",
        ))
        reasoning_parts.append("general probing")

    # Determine sophistication
    if features.injection_pattern_count > 0 and features.temporal_regularity > 0.7:
        sophistication = "Advanced"
    elif features.auth_retry_count > 10 or features.enum_score > 0.8:
        sophistication = "Intermediate"
    elif features.sdk_likelihood < 0.1:
        sophistication = "Intermediate"
    else:
        sophistication = "Novice"

    # Determine kill chain phase
    if features.injection_pattern_count > 0:
        phase = "Initial Access"
    elif features.auth_failure_rate > 0.5:
        phase = "Credential Access"
    elif features.enum_score > 0.5:
        phase = "Reconnaissance"
    else:
        phase = "Reconnaissance"

    # Sort by confidence
    techniques.sort(key=lambda t: t.confidence, reverse=True)

    # Overall confidence
    if techniques:
        overall = sum(t.confidence for t in techniques) / len(techniques)
    else:
        overall = 0.4

    return TechniqueInferenceResult(
        techniques=techniques[:4],  # Max 4 techniques
        attacker_sophistication=sophistication,
        confidence_overall=overall,
        kill_chain_phase=phase,
        raw_reasoning=f"Heuristic analysis detected: {', '.join(reasoning_parts)}.",
    )
