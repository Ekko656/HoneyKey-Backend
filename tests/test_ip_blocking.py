"""Tests for IP blocking module."""

import json
import os
import sqlite3
import pytest

from app.features.ip_blocking import (
    IPBlock,
    BlockReason,
    BlockStatus,
    init_blocklist_table,
    add_ip_block,
    remove_ip_block,
    is_ip_blocked,
    get_blocked_ips,
    block_ip_from_incident,
    export_blocklist,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def db_conn(tmp_path):
    """Create a test database connection."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Create incidents table for testing
    conn.execute("""
        CREATE TABLE incidents (
            id INTEGER PRIMARY KEY,
            source_ip TEXT NOT NULL,
            key_id TEXT,
            first_seen TEXT,
            last_seen TEXT,
            event_count INTEGER
        )
    """)

    # Add test incident
    conn.execute("""
        INSERT INTO incidents (id, source_ip, key_id, first_seen, last_seen, event_count)
        VALUES (1, '192.168.1.100', 'honeypot', '2024-01-01T00:00:00Z', '2024-01-01T01:00:00Z', 10)
    """)

    # Initialize blocklist table
    init_blocklist_table(conn)
    conn.commit()

    yield conn
    conn.close()


# =============================================================================
# UNIT TESTS - IPBlock
# =============================================================================

class TestIPBlock:
    """Tests for IPBlock dataclass."""

    def test_create_ip_block(self):
        """Test creating an IPBlock."""
        block = IPBlock(
            id=1,
            ip_address="192.168.1.100",
            incident_id=1,
            reason=BlockReason.HONEYPOT_ABUSE,
            blocked_by="analyst",
            blocked_at="2024-01-01T00:00:00Z",
            status=BlockStatus.ACTIVE,
        )
        assert block.ip_address == "192.168.1.100"
        assert block.reason == BlockReason.HONEYPOT_ABUSE

    def test_ip_block_to_dict(self):
        """Test converting IPBlock to dict."""
        block = IPBlock(
            id=1,
            ip_address="10.0.0.1",
            reason=BlockReason.ENUMERATION,
            status=BlockStatus.ACTIVE,
        )
        d = block.to_dict()
        assert d["ip_address"] == "10.0.0.1"
        assert d["reason"] == "enumeration"
        assert d["is_cidr"] is False

    def test_ip_block_cidr_detection(self):
        """Test CIDR detection in to_dict."""
        block = IPBlock(ip_address="192.168.0.0/24")
        d = block.to_dict()
        assert d["is_cidr"] is True


# =============================================================================
# UNIT TESTS - Database Operations
# =============================================================================

class TestAddIPBlock:
    """Tests for add_ip_block function."""

    def test_add_valid_ip(self, db_conn):
        """Test adding a valid IP."""
        block = add_ip_block(db_conn, "10.0.0.1")
        assert block.ip_address == "10.0.0.1"
        assert block.status == BlockStatus.ACTIVE
        assert block.id is not None

    def test_add_ip_with_details(self, db_conn):
        """Test adding IP with all details."""
        block = add_ip_block(
            db_conn,
            ip_address="10.0.0.2",
            incident_id=1,
            reason=BlockReason.BRUTE_FORCE,
            blocked_by="admin",
            duration_hours=48,
            notes="Test block",
        )
        assert block.incident_id == 1
        assert block.reason == BlockReason.BRUTE_FORCE
        assert block.notes == "Test block"
        assert block.expires_at is not None

    def test_add_cidr(self, db_conn):
        """Test adding a CIDR range."""
        block = add_ip_block(db_conn, "192.168.0.0/24")
        assert block.ip_address == "192.168.0.0/24"

    def test_add_invalid_ip_raises(self, db_conn):
        """Test that invalid IP raises ValueError."""
        with pytest.raises(ValueError):
            add_ip_block(db_conn, "not-an-ip")

    def test_add_duplicate_ip_raises(self, db_conn):
        """Test that duplicate IP raises ValueError."""
        add_ip_block(db_conn, "10.0.0.5")
        with pytest.raises(ValueError):
            add_ip_block(db_conn, "10.0.0.5")

    def test_add_permanent_block(self, db_conn):
        """Test adding permanent block (no expiry)."""
        block = add_ip_block(db_conn, "10.0.0.6", duration_hours=None)
        assert block.expires_at is None


class TestRemoveIPBlock:
    """Tests for remove_ip_block function."""

    def test_remove_by_ip(self, db_conn):
        """Test removing block by IP address."""
        add_ip_block(db_conn, "10.0.0.10")
        result = remove_ip_block(db_conn, ip_address="10.0.0.10")
        assert result is True

    def test_remove_by_id(self, db_conn):
        """Test removing block by ID."""
        block = add_ip_block(db_conn, "10.0.0.11")
        result = remove_ip_block(db_conn, block_id=block.id)
        assert result is True

    def test_remove_nonexistent_returns_false(self, db_conn):
        """Test removing nonexistent IP returns False."""
        result = remove_ip_block(db_conn, ip_address="1.2.3.4")
        assert result is False

    def test_remove_requires_ip_or_id(self, db_conn):
        """Test that either ip_address or block_id is required."""
        with pytest.raises(ValueError):
            remove_ip_block(db_conn)


class TestIsIPBlocked:
    """Tests for is_ip_blocked function."""

    def test_blocked_ip_returns_true(self, db_conn):
        """Test that blocked IP returns True."""
        add_ip_block(db_conn, "10.0.0.20")
        assert is_ip_blocked(db_conn, "10.0.0.20") is True

    def test_unblocked_ip_returns_false(self, db_conn):
        """Test that unblocked IP returns False."""
        assert is_ip_blocked(db_conn, "10.0.0.21") is False

    def test_ip_in_blocked_cidr_returns_true(self, db_conn):
        """Test that IP in blocked CIDR returns True."""
        add_ip_block(db_conn, "192.168.1.0/24")
        assert is_ip_blocked(db_conn, "192.168.1.50") is True
        assert is_ip_blocked(db_conn, "192.168.2.50") is False


class TestGetBlockedIPs:
    """Tests for get_blocked_ips function."""

    def test_get_all_active(self, db_conn):
        """Test getting all active blocks."""
        add_ip_block(db_conn, "10.0.0.30")
        add_ip_block(db_conn, "10.0.0.31")
        blocks = get_blocked_ips(db_conn, status=BlockStatus.ACTIVE)
        assert len(blocks) == 2

    def test_get_by_incident(self, db_conn):
        """Test filtering by incident."""
        add_ip_block(db_conn, "10.0.0.40", incident_id=1)
        add_ip_block(db_conn, "10.0.0.41", incident_id=2)
        blocks = get_blocked_ips(db_conn, incident_id=1)
        assert len(blocks) == 1
        assert blocks[0].ip_address == "10.0.0.40"

    def test_limit_results(self, db_conn):
        """Test limiting results."""
        for i in range(10):
            add_ip_block(db_conn, f"10.0.1.{i}")
        blocks = get_blocked_ips(db_conn, limit=5)
        assert len(blocks) == 5


class TestBlockIPFromIncident:
    """Tests for block_ip_from_incident function."""

    def test_block_incident_ip(self, db_conn):
        """Test blocking IP from incident."""
        result = block_ip_from_incident(db_conn, incident_id=1)
        assert result.success is True
        assert "192.168.1.100" in result.message
        assert result.block is not None

    def test_block_nonexistent_incident(self, db_conn):
        """Test blocking from nonexistent incident."""
        result = block_ip_from_incident(db_conn, incident_id=999)
        assert result.success is False
        assert "not found" in result.message.lower()

    def test_block_already_blocked_ip(self, db_conn):
        """Test blocking already blocked IP."""
        block_ip_from_incident(db_conn, incident_id=1)
        result = block_ip_from_incident(db_conn, incident_id=1)
        assert result.success is False
        assert "already blocked" in result.message.lower()


class TestExportBlocklist:
    """Tests for export_blocklist function."""

    def test_export_plain(self, db_conn):
        """Test plain text export."""
        add_ip_block(db_conn, "10.0.2.1")
        add_ip_block(db_conn, "10.0.2.2")
        content = export_blocklist(db_conn, format="plain")
        assert "10.0.2.1" in content
        assert "10.0.2.2" in content

    def test_export_nginx(self, db_conn):
        """Test nginx format export."""
        add_ip_block(db_conn, "10.0.3.1")
        content = export_blocklist(db_conn, format="nginx")
        assert "deny 10.0.3.1;" in content

    def test_export_iptables(self, db_conn):
        """Test iptables format export."""
        add_ip_block(db_conn, "10.0.4.1")
        content = export_blocklist(db_conn, format="iptables")
        assert "iptables -A INPUT -s 10.0.4.1/32 -j DROP" in content

    def test_export_json(self, db_conn):
        """Test JSON format export."""
        add_ip_block(db_conn, "10.0.5.1")
        content = export_blocklist(db_conn, format="json")
        data = json.loads(content)
        assert len(data) == 1
        assert data[0]["ip_address"] == "10.0.5.1"

    def test_export_invalid_format_raises(self, db_conn):
        """Test invalid format raises ValueError."""
        with pytest.raises(ValueError):
            export_blocklist(db_conn, format="invalid")


# =============================================================================
# INTEGRATION TESTS - API Endpoints
# =============================================================================

class TestAPIEndpoints:
    """Tests for API endpoints."""

    @pytest.fixture
    def client(self, tmp_path):
        """Create test client."""
        import importlib
        import sys

        db_path = tmp_path / "honeykey.db"
        os.environ["DATABASE_PATH"] = str(db_path)
        os.environ["HONEYPOT_KEY"] = "test_key"
        os.environ.pop("GEMINI_API_KEY", None)

        if "app.main" in sys.modules:
            del sys.modules["app.main"]

        from fastapi.testclient import TestClient

        module = importlib.import_module("app.main")
        module.settings = module.load_settings()
        module.app.state.settings = module.settings
        module.init_db()

        # Add test incident
        with module.get_db() as conn:
            conn.execute("""
                INSERT INTO incidents (key_id, source_ip, first_seen, last_seen, event_count)
                VALUES ('honeypot', '192.168.1.100', '2024-01-01T00:00:00Z', '2024-01-01T01:00:00Z', 10)
            """)

        client = TestClient(module.app)
        client.__enter__()
        return client

    def test_block_incident_ip(self, client):
        """Test POST /incidents/{id}/block-ip."""
        response = client.post(
            "/incidents/1/block-ip",
            json={"duration_hours": 24, "notes": "Test block"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "192.168.1.100" in data["message"]

    def test_add_to_blocklist(self, client):
        """Test POST /blocklist."""
        response = client.post(
            "/blocklist",
            json={"ip_address": "10.0.0.1", "reason": "manual"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_remove_from_blocklist(self, client):
        """Test DELETE /blocklist/{ip}."""
        # First add
        client.post("/blocklist", json={"ip_address": "10.0.0.2"})
        # Then remove
        response = client.delete("/blocklist/10.0.0.2")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_list_blocklist(self, client):
        """Test GET /blocklist."""
        client.post("/blocklist", json={"ip_address": "10.0.0.3"})
        response = client.get("/blocklist")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1

    def test_check_ip_blocked(self, client):
        """Test GET /blocklist/check/{ip}."""
        client.post("/blocklist", json={"ip_address": "10.0.0.4"})
        response = client.get("/blocklist/check/10.0.0.4")
        assert response.status_code == 200
        data = response.json()
        assert data["is_blocked"] is True

    def test_export_blocklist(self, client):
        """Test GET /blocklist/export."""
        client.post("/blocklist", json={"ip_address": "10.0.0.5"})
        response = client.get("/blocklist/export?format=plain")
        assert response.status_code == 200
        data = response.json()
        assert "10.0.0.5" in data["content"]
