"""
HoneyKey Integration Module.

Combines behavioral detection, key hints, and SOC report generation
into a unified system that enhances the backend's AI report generation.

Key Principle: The honeypot key used provides a HINT about likely attack
vectors, but behavioral evidence is the PRIMARY basis for conclusions.
"""

from .enhanced_prompt import (
    build_enhanced_prompt,
    create_behavioral_context,
    get_key_hint,
    KeyHint,
)
from .report_enrichment import (
    enrich_soc_report,
    merge_behavioral_analysis,
)

__all__ = [
    "build_enhanced_prompt",
    "create_behavioral_context",
    "get_key_hint",
    "KeyHint",
    "enrich_soc_report",
    "merge_behavioral_analysis",
]
