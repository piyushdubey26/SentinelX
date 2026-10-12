-- ========================================================
-- SENTINELX — 003 EVENT CORRELATION & CANDIDATE INCIDENTS (ROLLBACK)
-- Reversible PostgreSQL Schema Down-Migration
-- ========================================================

DROP INDEX IF EXISTS idx_candidates_confidence;
DROP INDEX IF EXISTS idx_candidates_incident_id;
DROP INDEX IF EXISTS idx_candidates_primary_ip;
DROP INDEX IF EXISTS idx_candidates_primary_user;
DROP INDEX IF EXISTS idx_candidates_status_last_seen;
DROP TABLE IF EXISTS candidate_incidents CASCADE;
