-- ========================================================
-- SENTINELX — 002 EVENT STREAMING ROLLBACK (DOWN)
-- ========================================================

DROP TABLE IF EXISTS dead_letter_events CASCADE;
DROP TABLE IF EXISTS idempotency_keys CASCADE;
