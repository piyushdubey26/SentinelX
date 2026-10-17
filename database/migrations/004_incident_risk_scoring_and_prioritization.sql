-- ========================================================
-- SENTINELX — 004 INCIDENT RISK SCORING & PRIORITIZATION
-- Reversible PostgreSQL Schema for Explainable Risk Engine
-- ========================================================

-- UP MIGRATION
BEGIN;

-- 1. Add risk scoring columns to incidents table
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0.00,
    ADD COLUMN IF NOT EXISTS risk_tier VARCHAR(20) NOT NULL DEFAULT 'LOW',
    ADD COLUMN IF NOT EXISTS risk_factors JSONB NOT NULL DEFAULT '{}';

-- 2. Add check constraint for risk_score and risk_tier
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_incidents_risk_score'
    ) THEN
        ALTER TABLE incidents
            ADD CONSTRAINT chk_incidents_risk_score
            CHECK (risk_score >= 0.00 AND risk_score <= 100.00);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_incidents_risk_tier'
    ) THEN
        ALTER TABLE incidents
            ADD CONSTRAINT chk_incidents_risk_tier
            CHECK (risk_tier IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'));
    END IF;
END $$;

-- 3. Indexes for fast priority queue sorting and tier filtering
CREATE INDEX IF NOT EXISTS idx_incidents_risk_score ON incidents(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_risk_tier ON incidents(risk_tier);
CREATE INDEX IF NOT EXISTS idx_incidents_status_risk ON incidents(status, risk_score DESC);

COMMIT;

-- ========================================================
-- DOWN MIGRATION (ROLLBACK INSTRUCTIONS)
-- ========================================================
-- BEGIN;
-- DROP INDEX IF EXISTS idx_incidents_status_risk;
-- DROP INDEX IF EXISTS idx_incidents_risk_tier;
-- DROP INDEX IF EXISTS idx_incidents_risk_score;
-- ALTER TABLE incidents DROP CONSTRAINT IF EXISTS chk_incidents_risk_tier;
-- ALTER TABLE incidents DROP CONSTRAINT IF EXISTS chk_incidents_risk_score;
-- ALTER TABLE incidents DROP COLUMN IF EXISTS risk_factors;
-- ALTER TABLE incidents DROP COLUMN IF EXISTS risk_tier;
-- ALTER TABLE incidents DROP COLUMN IF EXISTS risk_score;
-- COMMIT;
