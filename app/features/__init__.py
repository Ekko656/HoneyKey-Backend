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
from .ip_blocking import (
    IPBlock,
    BlockReason,
    BlockStatus,
    BlockIPRequest,
    BlockIPResponse,
    BlocklistResponse,
    init_blocklist_table,
    add_ip_block,
    remove_ip_block,
    is_ip_blocked,
    get_blocked_ips,
    block_ip_from_incident,
    export_blocklist,
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
    # IP Blocking
    "IPBlock",
    "BlockReason",
    "BlockStatus",
    "BlockIPRequest",
    "BlockIPResponse",
    "BlocklistResponse",
    "init_blocklist_table",
    "add_ip_block",
    "remove_ip_block",
    "is_ip_blocked",
    "get_blocked_ips",
    "block_ip_from_incident",
    "export_blocklist",
]
