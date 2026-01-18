"""
Honeypot key metadata registry.

Maps each honeypot key to its leak source, attack technique, attacker profile,
and confidence scoring. Used by both attacker response generation and SOC report enrichment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LeakSourceType(str, Enum):
    CLIENT_SIDE_JS = "client_side_js"
    APPLICATION_LOGS = "application_logs"
    INFRASTRUCTURE_CONFIG = "infrastructure_config"
    GIT_HISTORY = "git_history"
    ENVIRONMENT_VARS = "environment_vars"


class Sophistication(str, Enum):
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LeakSource:
    type: LeakSourceType
    location: str
    discovery_method: str
    exposure_context: str


@dataclass
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    secondary_id: Optional[str] = None
    secondary_name: Optional[str] = None


@dataclass
class AttackerProfile:
    sophistication: Sophistication
    sophistication_score: int  # 1-10
    reasoning: str


@dataclass
class HoneypotKeyMetadata:
    key_id: str
    key_value: str
    leak_source: LeakSource
    mitre_technique: MitreTechnique
    attacker_profile: AttackerProfile
    confidence_score: float  # 0.0-1.0
    confidence_reasoning: str
    base_severity: Severity

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization or LLM prompts."""
        return {
            "key_id": self.key_id,
            "leak_source": {
                "type": self.leak_source.type.value,
                "location": self.leak_source.location,
                "discovery_method": self.leak_source.discovery_method,
                "exposure_context": self.leak_source.exposure_context,
            },
            "mitre_technique": {
                "id": self.mitre_technique.technique_id,
                "name": self.mitre_technique.technique_name,
                "tactic": self.mitre_technique.tactic,
                "description": self.mitre_technique.description,
                "secondary_id": self.mitre_technique.secondary_id,
                "secondary_name": self.mitre_technique.secondary_name,
            },
            "attacker_profile": {
                "sophistication": self.attacker_profile.sophistication.value,
                "sophistication_score": self.attacker_profile.sophistication_score,
                "reasoning": self.attacker_profile.reasoning,
            },
            "confidence_score": self.confidence_score,
            "confidence_reasoning": self.confidence_reasoning,
            "base_severity": self.base_severity.value,
        }


# =============================================================================
# HONEYPOT KEY REGISTRY
# =============================================================================

HONEYPOT_KEYS: dict[str, HoneypotKeyMetadata] = {
    # Key exposed via minified JS bundle + source map
    "acme_client_m5n6o7p8q9r0s1t2": HoneypotKeyMetadata(
        key_id="client_js_key",
        key_value="acme_client_m5n6o7p8q9r0s1t2",
        leak_source=LeakSource(
            type=LeakSourceType.CLIENT_SIDE_JS,
            location="dist/app.min.js + app.min.js.map",
            discovery_method="source_map_extraction",
            exposure_context=(
                "Embedded in minified JavaScript bundle with source map "
                "exposing original variable name `API_KEY`"
            ),
        ),
        mitre_technique=MitreTechnique(
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials In Files",
            tactic="Credential Access",
            description="Attacker extracted API key from client-side JavaScript source maps",
        ),
        attacker_profile=AttackerProfile(
            sophistication=Sophistication.INTERMEDIATE,
            sophistication_score=6,
            reasoning="Required source map parsing and understanding of JS build tooling",
        ),
        confidence_score=0.95,
        confidence_reasoning=(
            "Source maps are not accidentally accessed; indicates intentional reconnaissance"
        ),
        base_severity=Severity.MEDIUM,
    ),

    # Key exposed via application debug logs
    "acme_debug_a1b2c3d4e5f6g7h8": HoneypotKeyMetadata(
        key_id="debug_log_key",
        key_value="acme_debug_a1b2c3d4e5f6g7h8",
        leak_source=LeakSource(
            type=LeakSourceType.APPLICATION_LOGS,
            location="/var/log/acme/debug.log",
            discovery_method="log_file_access",
            exposure_context=(
                "Debug logging accidentally included API key in request headers dump"
            ),
        ),
        mitre_technique=MitreTechnique(
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials In Files",
            tactic="Credential Access",
            description="Attacker gained access to application logs containing sensitive credentials",
            secondary_id="T1083",
            secondary_name="File and Directory Discovery",
        ),
        attacker_profile=AttackerProfile(
            sophistication=Sophistication.ADVANCED,
            sophistication_score=8,
            reasoning="Required server access or log aggregation compromise; suggests prior foothold",
        ),
        confidence_score=0.99,
        confidence_reasoning="Log files require system access; near-certain malicious intent",
        base_severity=Severity.HIGH,
    ),

    # Key exposed via docker-compose.yml in public repo
    "acme_docker_j4k5l6m7n8o9p0q1": HoneypotKeyMetadata(
        key_id="docker_config_key",
        key_value="acme_docker_j4k5l6m7n8o9p0q1",
        leak_source=LeakSource(
            type=LeakSourceType.INFRASTRUCTURE_CONFIG,
            location="docker-compose.yml (public GitHub repo)",
            discovery_method="github_dorking",
            exposure_context=(
                "API key hardcoded in docker-compose.yml environment variables, "
                "committed to public repository"
            ),
        ),
        mitre_technique=MitreTechnique(
            technique_id="T1552.004",
            technique_name="Unsecured Credentials: Private Keys",
            tactic="Credential Access",
            description="Attacker discovered credentials via GitHub repository scanning",
            secondary_id="T1593.003",
            secondary_name="Search Open Websites/Domains: Code Repositories",
        ),
        attacker_profile=AttackerProfile(
            sophistication=Sophistication.NOVICE,
            sophistication_score=3,
            reasoning="GitHub dorking is well-documented; automated tools like truffleHog make this trivial",
        ),
        confidence_score=0.85,
        confidence_reasoning=(
            "Could be automated scanning or manual discovery; still indicates active reconnaissance"
        ),
        base_severity=Severity.MEDIUM,
    ),
}


# =============================================================================
# ACCESSOR FUNCTIONS
# =============================================================================

def get_key_metadata(key: str) -> Optional[HoneypotKeyMetadata]:
    """Get full metadata for a honeypot key, or None if not a known honeypot."""
    return HONEYPOT_KEYS.get(key)


def is_honeypot_key(key: str) -> bool:
    """Check if a key is a registered honeypot key."""
    return key in HONEYPOT_KEYS


def get_leak_source(key: str) -> Optional[LeakSource]:
    """Get the leak source for a honeypot key."""
    metadata = get_key_metadata(key)
    return metadata.leak_source if metadata else None


def get_mitre_technique(key: str) -> Optional[MitreTechnique]:
    """Get the MITRE ATT&CK technique for a honeypot key."""
    metadata = get_key_metadata(key)
    return metadata.mitre_technique if metadata else None


def get_sophistication(key: str) -> Optional[AttackerProfile]:
    """Get the attacker profile for a honeypot key."""
    metadata = get_key_metadata(key)
    return metadata.attacker_profile if metadata else None


def get_severity_level(key: str, event_count: int = 1) -> Severity:
    """
    Calculate severity based on key metadata and event context.

    Severity escalates based on:
    - Base severity from leak source type
    - Number of events (repeated attempts = higher severity)
    - Attacker sophistication
    """
    metadata = get_key_metadata(key)
    if not metadata:
        return Severity.MEDIUM

    base = metadata.base_severity

    # Escalate if multiple attempts
    if event_count >= 10:
        if base == Severity.LOW:
            return Severity.MEDIUM
        elif base == Severity.MEDIUM:
            return Severity.HIGH
        elif base == Severity.HIGH:
            return Severity.CRITICAL
    elif event_count >= 5:
        if base == Severity.LOW:
            return Severity.MEDIUM
        elif base == Severity.MEDIUM:
            return Severity.HIGH

    return base


def get_confidence_label(score: float) -> str:
    """Convert confidence score to human-readable label."""
    if score >= 0.95:
        return "Very High"
    elif score >= 0.85:
        return "High"
    elif score >= 0.70:
        return "Medium"
    elif score >= 0.50:
        return "Low"
    else:
        return "Very Low"


def register_honeypot_key(
    key_value: str,
    key_id: str,
    leak_source: LeakSource,
    mitre_technique: MitreTechnique,
    attacker_profile: AttackerProfile,
    confidence_score: float,
    confidence_reasoning: str,
    base_severity: Severity,
) -> None:
    """
    Register a new honeypot key at runtime.

    Useful for adding keys dynamically without code changes.
    """
    HONEYPOT_KEYS[key_value] = HoneypotKeyMetadata(
        key_id=key_id,
        key_value=key_value,
        leak_source=leak_source,
        mitre_technique=mitre_technique,
        attacker_profile=attacker_profile,
        confidence_score=confidence_score,
        confidence_reasoning=confidence_reasoning,
        base_severity=base_severity,
    )
