"""Sprint 1E integration tests.

Run inside worker container:
  docker compose exec worker python -m pytest /app/../tests/test_sprint1e.py -v

Or mount tests dir and run:
  docker compose exec worker python -m pytest tests/test_sprint1e.py -v
"""

import os
import sys
import json
import psycopg2
import pytest

# Add worker dir to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

DB_URL = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@localhost:5432/zovarc")


@pytest.fixture
def db():
    conn = psycopg2.connect(DB_URL)
    yield conn
    conn.rollback()
    conn.close()


class TestSCRAMAuth:
    """1E-3: Verify SCRAM-SHA-256 password encryption."""

    def test_password_encryption_setting(self, db):
        with db.cursor() as cur:
            cur.execute("SHOW password_encryption;")
            result = cur.fetchone()[0]
            assert result == "scram-sha-256", f"Expected scram-sha-256, got {result}"

    def test_zovarc_user_has_scram_hash(self, db):
        with db.cursor() as cur:
            cur.execute(
                "SELECT rolpassword LIKE 'SCRAM-SHA-256$%%' FROM pg_authid WHERE rolname = 'zovarc';"
            )
            row = cur.fetchone()
            if row:
                assert row[0] is True, "zovarc user password is not SCRAM-SHA-256"


class TestAuditEventsTable:
    """1E-4: Verify audit_events table exists and is partitioned."""

    def test_audit_events_exists(self, db):
        with db.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_events';"
            )
            assert cur.fetchone() is not None, "audit_events table does not exist"

    def test_audit_events_is_partitioned(self, db):
        with db.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM pg_inherits WHERE inhparent = 'audit_events'::regclass;"
            )
            count = cur.fetchone()[0]
            assert count >= 12, f"Expected >=12 partitions, got {count}"

    def test_audit_events_insert(self, db):
        with db.cursor() as cur:
            # Get a tenant_id
            cur.execute("SELECT id FROM tenants LIMIT 1;")
            tenant_row = cur.fetchone()
            if not tenant_row:
                pytest.skip("No tenants in DB")
            tenant_id = tenant_row[0]

            cur.execute("""
                INSERT INTO audit_events (tenant_id, event_type, actor_type, resource_type, metadata)
                VALUES (%s, 'investigation_started', 'system', 'task', '{}')
                RETURNING id
            """, (tenant_id,))
            row = cur.fetchone()
            assert row is not None, "Failed to insert audit event"

    def test_audit_events_check_constraint(self, db):
        with db.cursor() as cur:
            cur.execute("SELECT id FROM tenants LIMIT 1;")
            tenant_row = cur.fetchone()
            if not tenant_row:
                pytest.skip("No tenants in DB")
            tenant_id = tenant_row[0]

            with pytest.raises(psycopg2.errors.CheckViolation):
                cur.execute("""
                    INSERT INTO audit_events (tenant_id, event_type, actor_type)
                    VALUES (%s, 'invalid_event_type', 'system')
                """, (tenant_id,))


class TestSyncCommit:
    """1E-2: Verify synchronous_commit is off globally (per-transaction override in code)."""

    def test_global_sync_commit_off(self, db):
        with db.cursor() as cur:
            cur.execute("SHOW synchronous_commit;")
            result = cur.fetchone()[0]
            assert result == "off", f"Expected global sync_commit=off, got {result}"

    def test_local_sync_commit_on(self, db):
        """Verify SET LOCAL synchronous_commit = on works within a transaction."""
        with db.cursor() as cur:
            cur.execute("SET LOCAL synchronous_commit = on;")
            cur.execute("SHOW synchronous_commit;")
            result = cur.fetchone()[0]
            assert result == "on", f"Expected local sync_commit=on, got {result}"


class TestEntityNormalize:
    """Verify entity_normalize module can be imported and works."""

    def test_import(self):
        from entity_normalize import normalize_entity, compute_entity_hash
        assert callable(normalize_entity)
        assert callable(compute_entity_hash)

    def test_ip_normalize(self):
        from entity_normalize import normalize_entity
        assert normalize_entity("ip", "192.168.1.1") == "192.168.1.1"
        assert normalize_entity("ip", "192[.]168[.]1[.]1") == "192.168.1.1"

    def test_domain_normalize(self):
        from entity_normalize import normalize_entity
        assert normalize_entity("domain", "www.Example.COM") == "example.com"

    def test_hash_deterministic(self):
        from entity_normalize import compute_entity_hash
        h1 = compute_entity_hash("ip", "192.168.1.1")
        h2 = compute_entity_hash("ip", "192.168.1.1")
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex
