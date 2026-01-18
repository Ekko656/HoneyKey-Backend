"""HoneyKey feature modules for attacker response and SOC enrichment."""

from .key_metadata import (
    HONEYPOT_KEYS,
    get_key_metadata,
    get_leak_source,
    get_mitre_technique,
    get_sophistication,
    get_severity_level,
)
from .attacker_responses import (
    generate_attacker_response,
    get_fake_project_list,
    get_fake_secret_list,
    get_auth_error,
)
from .soc_enrichment import (
    enrich_prompt_with_metadata,
    build_enriched_soc_prompt,
    format_evidence_from_metadata,
    generate_recommendations_from_metadata,
)

__all__ = [
    "HONEYPOT_KEYS",
    "get_key_metadata",
    "get_leak_source",
    "get_mitre_technique",
    "get_sophistication",
    "get_severity_level",
    "generate_attacker_response",
    "get_fake_project_list",
    "get_fake_secret_list",
    "get_auth_error",
    "enrich_prompt_with_metadata",
    "build_enriched_soc_prompt",
    "format_evidence_from_metadata",
    "generate_recommendations_from_metadata",
]
