-- ========================================================
-- SENTINELX — 002 EVENT STREAMING, IDEMPOTENCY & DLQ MIGRATION
-- Reversible PostgreSQL Schema for Kafka Event Pipeline
-- ========================================================

-- 1. Create Idempotency Keys Table
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key VARCHAR(255) PRIMARY KEY,
    event_id UUID NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_keys(expires_at);

-- 2. Create Dead Letter Events Table
CREATE TABLE IF NOT EXISTS dead_letter_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    topic VARCHAR(100) NOT NULL,
    error_message TEXT NOT NULL,
    error_stack TEXT NULL,
    retry_count INT NOT NULL DEFAULT 0,
    raw_payload JSONB NOT NULL DEFAULT '{}',
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_dlq_failed_at ON dead_letter_events(failed_at);
CREATE INDEX IF NOT EXISTS idx_dlq_resolved ON dead_letter_events(resolved);
