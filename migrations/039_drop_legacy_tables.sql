-- Migration 039: Drop confirmed-unused legacy tables
-- Sprint v0.16.0 — Legacy table cleanup
--
-- Verified unused by:
--   grep -r "agent_personas\|agent_memory_episodic\|working_memory_snapshots\|object_refs" api/ worker/
-- All returned zero matches.
--
-- NOTE: playbooks and agent_audit_log are still referenced by active code.
-- They are NOT dropped here.

BEGIN;

DROP TABLE IF EXISTS agent_personas CASCADE;
DROP TABLE IF EXISTS agent_memory_episodic CASCADE;
DROP TABLE IF EXISTS working_memory_snapshots CASCADE;
DROP TABLE IF EXISTS object_refs CASCADE;

COMMIT;
