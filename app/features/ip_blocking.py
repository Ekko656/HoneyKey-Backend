"""
IP Blocking Module for HoneyKey.

Allows SOC analysts to block attacker IPs directly from incident reports.
Integrates with the frontend to provide a seamless blocking experience.

Features:
- Block individual IPs or CIDR ranges
- Associate blocks with incidents for audit trail
- Temporary or permanent blocks
- Blocklist export for firewall/WAF integration
"""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Optional, List


class BlockReason(str, Enum):
    """Reason for blocking an IP."""
    HONEYPOT_ABUSE = "honeypot_abuse"
    ENUMERATION = "enumeration"
    INJECTION_ATTEMPT = "injection_attempt"
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MANUAL = "manual"


class BlockStatus(str, Enum):
    """Current status of an IP block."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REMOVED = "removed"


@dataclass
class IPBlock:
    """
    Represents a blocked IP address or CIDR range.

    Attributes:
        id: Database ID
        ip_address: IP address or CIDR (e.g., "192.168.1.100" or "192.168.1.0/24")
        incident_id: Associated incident (for audit trail)
        reason: Why the IP was blocked
        blocked_by: User/system that created the block
        blocked_at: When the block was created
        expires_at: When the block expires (None = permanent)
        status: Current status of the block
        notes: Additional context
    """
    id: Optional[int] = None
    ip_address: str = ""
    incident_id: Optional[int] = None
    reason: BlockReason = BlockReason.HONEYPOT_ABUSE
    blocked_by: str = "system"
    blocked_at: Optional[str] = None
    expires_at: Optional[str] = None
    status: BlockStatus = BlockStatus.ACTIVE
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "incident_id": self.incident_id,
            "reason": self.reason.value,
            "blocked_by": self.blocked_by,
            "blocked_at": self.blocked_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "notes": self.notes,
            "is_cidr": "/" in self.ip_address,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "IPBlock":
        """Create from database row."""
        return cls(
            id=row["id"],
            ip_address=row["ip_address"],
            incident_id=row["incident_id"],
            reason=BlockReason(row["reason"]),
            blocked_by=row["blocked_by"],
            blocked_at=row["blocked_at"],
            expires_at=row["expires_at"],
            status=BlockStatus(row["status"]),
            notes=row["notes"] or "",
        )


# =============================================================================
# DATABASE OPERATIONS
# =============================================================================

def init_blocklist_table(conn: sqlite3.Connection) -> None:
    """Create the IP blocklist table if it doesn't exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            incident_id INTEGER,
            reason TEXT NOT NULL,
            blocked_by TEXT NOT NULL,
            blocked_at TEXT NOT NULL,
            expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            notes TEXT,
            UNIQUE(ip_address, status)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_blocklist_ip ON ip_blocklist(ip_address)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_blocklist_status ON ip_blocklist(status)
    """)


def add_ip_block(
    conn: sqlite3.Connection,
    ip_address: str,
    incident_id: Optional[int] = None,
    reason: BlockReason = BlockReason.HONEYPOT_ABUSE,
    blocked_by: str = "system",
    duration_hours: Optional[int] = None,
    notes: str = "",
) -> IPBlock:
    """
    Add an IP to the blocklist.

    Args:
        conn: Database connection
        ip_address: IP address or CIDR to block
        incident_id: Associated incident ID
        reason: Reason for blocking
        blocked_by: Who/what created the block
        duration_hours: Block duration in hours (None = permanent)
        notes: Additional notes

    Returns:
        Created IPBlock

    Raises:
        ValueError: If IP format is invalid or already blocked
    """
    # Validate IP format
    try:
        if "/" in ip_address:
            ipaddress.ip_network(ip_address, strict=False)
        else:
            ipaddress.ip_address(ip_address)
    except ValueError as e:
        raise ValueError(f"Invalid IP address format: {e}")

    now = datetime.now(timezone.utc)
    expires_at = None
    if duration_hours is not None:
        expires_at = (now + timedelta(hours=duration_hours)).isoformat()

    # Check if already blocked
    existing = conn.execute(
        "SELECT id FROM ip_blocklist WHERE ip_address = ? AND status = 'active'",
        (ip_address,)
    ).fetchone()
    if existing:
        raise ValueError(f"IP {ip_address} is already blocked")

    cursor = conn.execute(
        """
        INSERT INTO ip_blocklist (
            ip_address, incident_id, reason, blocked_by,
            blocked_at, expires_at, status, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ip_address,
            incident_id,
            reason.value,
            blocked_by,
            now.isoformat(),
            expires_at,
            BlockStatus.ACTIVE.value,
            notes,
        ),
    )

    return IPBlock(
        id=cursor.lastrowid,
        ip_address=ip_address,
        incident_id=incident_id,
        reason=reason,
        blocked_by=blocked_by,
        blocked_at=now.isoformat(),
        expires_at=expires_at,
        status=BlockStatus.ACTIVE,
        notes=notes,
    )


def remove_ip_block(
    conn: sqlite3.Connection,
    ip_address: Optional[str] = None,
    block_id: Optional[int] = None,
    removed_by: str = "system",
) -> bool:
    """
    Remove an IP from the blocklist.

    Args:
        conn: Database connection
        ip_address: IP to unblock (either this or block_id required)
        block_id: Block ID to remove
        removed_by: Who removed the block

    Returns:
        True if block was removed, False if not found
    """
    removal_note = f"\nRemoved by {removed_by} at {datetime.now(timezone.utc).isoformat()}"

    if block_id:
        result = conn.execute(
            """
            UPDATE ip_blocklist
            SET status = ?, notes = COALESCE(notes, '') || ?
            WHERE id = ? AND status = 'active'
            """,
            (BlockStatus.REMOVED.value, removal_note, block_id),
        )
    elif ip_address:
        result = conn.execute(
            """
            UPDATE ip_blocklist
            SET status = ?, notes = COALESCE(notes, '') || ?
            WHERE ip_address = ? AND status = 'active'
            """,
            (BlockStatus.REMOVED.value, removal_note, ip_address),
        )
    else:
        raise ValueError("Either ip_address or block_id required")

    return result.rowcount > 0


def is_ip_blocked(conn: sqlite3.Connection, ip_address: str) -> bool:
    """
    Check if an IP is currently blocked.

    Also checks CIDR ranges that contain the IP.
    """
    # Direct match
    row = conn.execute(
        "SELECT id FROM ip_blocklist WHERE ip_address = ? AND status = 'active'",
        (ip_address,)
    ).fetchone()
    if row:
        return True

    # Check CIDR ranges
    try:
        ip = ipaddress.ip_address(ip_address)
        cidrs = conn.execute(
            "SELECT ip_address FROM ip_blocklist WHERE ip_address LIKE '%/%' AND status = 'active'"
        ).fetchall()
        for cidr_row in cidrs:
            try:
                network = ipaddress.ip_network(cidr_row["ip_address"], strict=False)
                if ip in network:
                    return True
            except ValueError:
                continue
    except ValueError:
        pass

    return False


def get_blocked_ips(
    conn: sqlite3.Connection,
    status: Optional[BlockStatus] = BlockStatus.ACTIVE,
    incident_id: Optional[int] = None,
    limit: int = 100,
) -> List[IPBlock]:
    """
    Get list of blocked IPs.

    Args:
        conn: Database connection
        status: Filter by status (None = all)
        incident_id: Filter by incident
        limit: Maximum results

    Returns:
        List of IPBlock objects
    """
    query = "SELECT * FROM ip_blocklist WHERE 1=1"
    params: list[Any] = []

    if status:
        query += " AND status = ?"
        params.append(status.value)

    if incident_id:
        query += " AND incident_id = ?"
        params.append(incident_id)

    query += " ORDER BY blocked_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    return [IPBlock.from_row(row) for row in rows]


def expire_old_blocks(conn: sqlite3.Connection) -> int:
    """
    Mark expired blocks as expired.

    Returns:
        Number of blocks expired
    """
    now = datetime.now(timezone.utc).isoformat()
    result = conn.execute(
        """
        UPDATE ip_blocklist
        SET status = ?
        WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?
        """,
        (BlockStatus.EXPIRED.value, now),
    )
    return result.rowcount


def export_blocklist(
    conn: sqlite3.Connection,
    format: str = "plain",
) -> str:
    """
    Export active blocklist for firewall/WAF integration.

    Args:
        conn: Database connection
        format: Output format ('plain', 'nginx', 'iptables', 'json')

    Returns:
        Formatted blocklist string
    """
    blocks = get_blocked_ips(conn, status=BlockStatus.ACTIVE, limit=10000)

    if format == "plain":
        return "\n".join(b.ip_address for b in blocks)

    elif format == "nginx":
        lines = ["# HoneyKey IP Blocklist for nginx"]
        for b in blocks:
            lines.append(f"deny {b.ip_address};")
        return "\n".join(lines)

    elif format == "iptables":
        lines = ["# HoneyKey IP Blocklist for iptables"]
        for b in blocks:
            if "/" in b.ip_address:
                lines.append(f"iptables -A INPUT -s {b.ip_address} -j DROP")
            else:
                lines.append(f"iptables -A INPUT -s {b.ip_address}/32 -j DROP")
        return "\n".join(lines)

    elif format == "json":
        import json
        return json.dumps([b.to_dict() for b in blocks], indent=2)

    else:
        raise ValueError(f"Unknown format: {format}")


# =============================================================================
# FRONTEND INTEGRATION MODELS
# =============================================================================

@dataclass
class BlockIPRequest:
    """Request model for blocking an IP from frontend."""
    ip_address: str
    incident_id: Optional[int] = None
    reason: str = "honeypot_abuse"
    duration_hours: Optional[int] = None  # None = permanent
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BlockIPRequest":
        return cls(
            ip_address=data["ip_address"],
            incident_id=data.get("incident_id"),
            reason=data.get("reason", "honeypot_abuse"),
            duration_hours=data.get("duration_hours"),
            notes=data.get("notes", ""),
        )


@dataclass
class BlockIPResponse:
    """Response model for IP block operations."""
    success: bool
    message: str
    block: Optional[IPBlock] = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "success": self.success,
            "message": self.message,
        }
        if self.block:
            result["block"] = self.block.to_dict()
        return result


@dataclass
class BlocklistResponse:
    """Response model for blocklist queries."""
    total: int
    blocks: List[IPBlock]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "blocks": [b.to_dict() for b in self.blocks],
        }


# =============================================================================
# CONVENIENCE FUNCTIONS FOR INCIDENT INTEGRATION
# =============================================================================

def block_ip_from_incident(
    conn: sqlite3.Connection,
    incident_id: int,
    blocked_by: str = "analyst",
    duration_hours: Optional[int] = 24,
    notes: str = "",
) -> BlockIPResponse:
    """
    Block the source IP associated with an incident.

    This is the main function called from the frontend when a user
    clicks "Block IP" on an incident report.

    Args:
        conn: Database connection
        incident_id: Incident to get IP from
        blocked_by: User who initiated the block
        duration_hours: Block duration (default 24h, None = permanent)
        notes: Additional notes

    Returns:
        BlockIPResponse with success/failure info
    """
    # Get incident to find source IP
    incident = conn.execute(
        "SELECT source_ip FROM incidents WHERE id = ?",
        (incident_id,)
    ).fetchone()

    if not incident:
        return BlockIPResponse(
            success=False,
            message=f"Incident {incident_id} not found",
        )

    source_ip = incident["source_ip"]

    # Check if already blocked
    if is_ip_blocked(conn, source_ip):
        return BlockIPResponse(
            success=False,
            message=f"IP {source_ip} is already blocked",
        )

    try:
        block = add_ip_block(
            conn,
            ip_address=source_ip,
            incident_id=incident_id,
            reason=BlockReason.HONEYPOT_ABUSE,
            blocked_by=blocked_by,
            duration_hours=duration_hours,
            notes=notes or f"Blocked from incident #{incident_id}",
        )
        return BlockIPResponse(
            success=True,
            message=f"Successfully blocked IP {source_ip}",
            block=block,
        )
    except ValueError as e:
        return BlockIPResponse(
            success=False,
            message=str(e),
        )
