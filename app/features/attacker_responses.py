"""
Attacker-facing response generator.

Generates realistic fake API responses that appear legitimate to attackers,
while logging all activity. Responses are designed to:
1. Look like real API responses (realistic error messages, structure)
2. Potentially bait attackers into further enumeration
3. Provide forensic value for the SOC report
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .key_metadata import get_key_metadata, is_honeypot_key


def generate_request_id() -> str:
    """Generate a realistic-looking request ID."""
    return f"req_{uuid.uuid4().hex[:16]}"


def utc_now_iso() -> str:
    """Current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# FAKE DATA GENERATORS
# =============================================================================

def get_fake_project_list() -> list[dict[str, Any]]:
    """
    Generate a list of fake projects that looks enticing to attackers.

    These appear as if the attacker almost has access, encouraging further attempts.
    """
    return [
        {
            "id": "proj_7f8a9b2c3d4e",
            "name": "payment-processing",
            "environment": "production",
            "created_at": "2024-08-15T10:30:00Z",
            "status": "active",
        },
        {
            "id": "proj_1a2b3c4d5e6f",
            "name": "user-authentication",
            "environment": "production",
            "created_at": "2024-06-20T14:22:00Z",
            "status": "active",
        },
        {
            "id": "proj_9x8y7z6w5v4u",
            "name": "internal-admin-tools",
            "environment": "production",
            "created_at": "2024-03-10T08:15:00Z",
            "status": "active",
        },
        {
            "id": "proj_m3n4o5p6q7r8",
            "name": "customer-data-export",
            "environment": "staging",
            "created_at": "2024-11-01T16:45:00Z",
            "status": "active",
        },
    ]


def get_fake_secret_list() -> list[dict[str, Any]]:
    """
    Generate a list of fake secrets that looks like credential storage.

    Values are redacted but names suggest high-value targets.
    """
    return [
        {
            "name": "DATABASE_PASSWORD",
            "created_at": "2024-01-15T09:00:00Z",
            "last_accessed": "2025-01-17T22:30:00Z",
            "version": 3,
        },
        {
            "name": "STRIPE_SECRET_KEY",
            "created_at": "2024-03-20T11:15:00Z",
            "last_accessed": "2025-01-18T01:45:00Z",
            "version": 2,
        },
        {
            "name": "AWS_SECRET_ACCESS_KEY",
            "created_at": "2024-02-10T14:30:00Z",
            "last_accessed": "2025-01-17T18:00:00Z",
            "version": 5,
        },
        {
            "name": "INTERNAL_API_MASTER_KEY",
            "created_at": "2024-05-05T08:00:00Z",
            "last_accessed": "2025-01-18T03:15:00Z",
            "version": 1,
        },
    ]


def get_fake_user_info() -> dict[str, Any]:
    """Generate fake user/service account info."""
    return {
        "id": "svc_acme_readonly_001",
        "type": "service_account",
        "name": "acme-readonly-service",
        "permissions": ["read:projects", "read:secrets"],
        "created_at": "2024-01-10T12:00:00Z",
        "last_active": utc_now_iso(),
    }


# =============================================================================
# ERROR RESPONSE GENERATORS
# =============================================================================

def get_auth_error(
    message: str = "Unauthorized",
    code: int = 401,
    hint: Optional[str] = None,
) -> dict[str, Any]:
    """
    Generate an authentication error response.

    Args:
        message: Error message
        code: HTTP status code
        hint: Optional hint that might encourage further enumeration
    """
    response = {
        "error": {
            "code": code,
            "message": message,
            "request_id": generate_request_id(),
            "timestamp": utc_now_iso(),
        }
    }
    if hint:
        response["error"]["hint"] = hint
    return response


def get_permission_error(resource: str) -> dict[str, Any]:
    """
    Generate a permission denied error.

    Indicates the key is valid but lacks permissions (enticing attackers).
    """
    return {
        "error": {
            "code": 403,
            "message": f"Access denied: insufficient permissions for '{resource}'",
            "request_id": generate_request_id(),
            "timestamp": utc_now_iso(),
            "required_permission": f"admin:{resource}",
        }
    }


def get_rate_limit_error(retry_after: int = 60) -> dict[str, Any]:
    """Generate a rate limit error response."""
    return {
        "error": {
            "code": 429,
            "message": "Rate limit exceeded",
            "request_id": generate_request_id(),
            "timestamp": utc_now_iso(),
            "retry_after": retry_after,
        }
    }


def get_not_found_error(resource: str) -> dict[str, Any]:
    """Generate a not found error response."""
    return {
        "error": {
            "code": 404,
            "message": f"Resource not found: {resource}",
            "request_id": generate_request_id(),
            "timestamp": utc_now_iso(),
        }
    }


# =============================================================================
# MAIN RESPONSE GENERATOR
# =============================================================================

class AttackerResponseStrategy:
    """
    Determines what response to show attackers based on the honeypot key used.

    Different keys can have different response strategies:
    - Some always return 401 (immediate detection)
    - Some return 403 (appear valid but restricted)
    - Some return partial data (high-engagement honeypot)
    """

    # Response modes
    IMMEDIATE_DENY = "immediate_deny"      # Always 401
    PERMISSION_BAIT = "permission_bait"    # 403 with hints
    PARTIAL_DATA = "partial_data"          # Show some fake data, then deny

    # Map key IDs to response strategies
    KEY_STRATEGIES = {
        "client_js_key": PERMISSION_BAIT,      # Encourage enumeration
        "debug_log_key": IMMEDIATE_DENY,       # High severity, block fast
        "docker_config_key": PARTIAL_DATA,     # Low sophistication, bait them
    }

    @classmethod
    def get_strategy(cls, key: str) -> str:
        """Get the response strategy for a given key."""
        metadata = get_key_metadata(key)
        if metadata:
            return cls.KEY_STRATEGIES.get(metadata.key_id, cls.IMMEDIATE_DENY)
        return cls.IMMEDIATE_DENY


def generate_attacker_response(
    key: str,
    endpoint: str,
    method: str = "GET",
) -> tuple[int, dict[str, Any]]:
    """
    Generate an appropriate response for an attacker request.

    Args:
        key: The honeypot key used by the attacker
        endpoint: The API endpoint requested
        method: HTTP method

    Returns:
        Tuple of (status_code, response_body)
    """
    if not is_honeypot_key(key):
        # Unknown key - standard 401
        return 401, get_auth_error("Invalid or expired API key")

    strategy = AttackerResponseStrategy.get_strategy(key)
    metadata = get_key_metadata(key)

    if strategy == AttackerResponseStrategy.IMMEDIATE_DENY:
        # High-risk keys: immediate block
        return 401, get_auth_error(
            message="Unauthorized: Invalid API key",
            hint=None,  # No hints for high-risk
        )

    elif strategy == AttackerResponseStrategy.PERMISSION_BAIT:
        # Medium-risk: appear valid but restricted
        if endpoint == "/v1/projects":
            return 403, get_permission_error("projects:list")
        elif endpoint == "/v1/secrets":
            return 403, get_permission_error("secrets:read")
        elif endpoint == "/v1/auth/verify":
            # Verification endpoint - show partial success
            return 200, {
                "valid": True,
                "type": "service_account",
                "permissions": ["read:limited"],
                "warning": "This key has restricted access",
                "request_id": generate_request_id(),
            }
        else:
            return 403, get_permission_error(endpoint)

    elif strategy == AttackerResponseStrategy.PARTIAL_DATA:
        # Low-risk: show enticing data to gather more intel
        if endpoint == "/v1/projects":
            # Show project list but deny access to details
            projects = get_fake_project_list()
            return 200, {
                "projects": projects,
                "total": len(projects),
                "request_id": generate_request_id(),
                "_warning": "Read-only access. Contact admin for write permissions.",
            }
        elif endpoint == "/v1/secrets":
            # Show secret names but not values
            secrets = get_fake_secret_list()
            return 200, {
                "secrets": [
                    {"name": s["name"], "version": s["version"]}
                    for s in secrets
                ],
                "total": len(secrets),
                "request_id": generate_request_id(),
                "_note": "Values redacted. Use /v1/secrets/{name} to retrieve.",
            }
        elif endpoint == "/v1/auth/verify":
            return 200, {
                "valid": True,
                "account": get_fake_user_info(),
                "request_id": generate_request_id(),
            }
        else:
            return 404, get_not_found_error(endpoint)

    # Default fallback
    return 401, get_auth_error("Unauthorized")


def generate_trap_response(
    endpoint: str,
    key_used: Optional[str] = None,
    include_bait: bool = False,
) -> tuple[int, dict[str, Any]]:
    """
    Generate response for honeypot trap endpoints.

    These endpoints exist solely to attract attackers.

    Args:
        endpoint: The trap endpoint
        key_used: The key used (if any)
        include_bait: Whether to include enticing data
    """
    request_id = generate_request_id()

    if not key_used:
        # No auth - standard 401
        return 401, {
            "error": {
                "code": 401,
                "message": "Authentication required",
                "request_id": request_id,
            }
        }

    if include_bait and is_honeypot_key(key_used):
        return generate_attacker_response(key_used, endpoint)

    # Default: deny with realistic message
    return 401, {
        "error": {
            "code": 401,
            "message": "Unauthorized: Invalid or expired API key",
            "request_id": request_id,
            "timestamp": utc_now_iso(),
        }
    }
