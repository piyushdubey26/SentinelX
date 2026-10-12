-- ========================================================
-- SENTINELX — 003 EVENT CORRELATION & CANDIDATE INCIDENTS
-- Reversible PostgreSQL Schema for Multi-Attribute Correlation
-- ========================================================

-- 1. Create Candidate Incidents Table
CREATE TABLE IF NOT EXISTS candidate_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,
    confidence_score NUMERIC(4, 3) NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    severity event_severity_enum NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(50) NOT NULL DEFAULT 'CANDIDATE' CHECK (status IN ('CANDIDATE', 'PROMOTED', 'DISMISSED')),
    correlation_factors JSONB NOT NULL DEFAULT '[]',
    explanation TEXT NOT NULL,
    primary_user VARCHAR(100) NULL,
    primary_source_ip VARCHAR(45) NULL,
    primary_asset_id UUID NULL REFERENCES assets(id) ON DELETE SET NULL,
    event_ids UUID[] NOT NULL DEFAULT '{}',
    detection_ids UUID[] NOT NULL DEFAULT '{}',
    incident_id UUID NULL REFERENCES incidents(id) ON DELETE SET NULL,
    dismissed_reason TEXT NULL,
    dismissed_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Indexes for efficient lookup, status filtering, and sliding window query
CREATE INDEX IF NOT EXISTS idx_candidates_status_last_seen ON candidate_incidents(status, last_seen);
CREATE INDEX IF NOT EXISTS idx_candidates_primary_user ON candidate_incidents(primary_user);
CREATE INDEX IF NOT EXISTS idx_candidates_primary_ip ON candidate_incidents(primary_source_ip);
CREATE INDEX IF NOT EXISTS idx_candidates_incident_id ON candidate_incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_candidates_confidence ON candidate_incidents(confidence_score);
