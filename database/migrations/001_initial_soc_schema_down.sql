-- ========================================================
-- SENTINELX — 001 INITIAL SOC SCHEMA ROLLBACK (DOWN)
-- ========================================================

DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS incidents CASCADE;
DROP TABLE IF EXISTS detections CASCADE;
DROP TABLE IF EXISTS security_events CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS roles CASCADE;

DROP TYPE IF EXISTS incident_status_enum CASCADE;
DROP TYPE IF EXISTS event_severity_enum CASCADE;
DROP TYPE IF EXISTS asset_environment_enum CASCADE;
DROP TYPE IF EXISTS asset_criticality_enum CASCADE;
DROP TYPE IF EXISTS role_type_enum CASCADE;
