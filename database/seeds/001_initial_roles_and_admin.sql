-- ========================================================
-- SENTINELX — 001 SEED DEFAULT ROLES & INITIAL ADMIN USER
-- ========================================================

-- Insert Roles
INSERT INTO roles (id, name, description, permissions)
VALUES 
  ('11111111-1111-1111-1111-111111111111', 'ADMIN', 'Full system and security administration', ARRAY['*']),
  ('22222222-2222-2222-2222-222222222222', 'SECURITY_ENGINEER', 'Detection engineering, rules, and incident remediation', ARRAY['events:*', 'detections:*', 'incidents:*', 'assets:*']),
  ('33333333-3333-3333-3333-333333333333', 'SOC_ANALYST', 'Triage incidents, inspect events, and update status', ARRAY['events:read', 'detections:read', 'incidents:read', 'incidents:update', 'audit:read']),
  ('44444444-4444-4444-4444-444444444444', 'READ_ONLY_AUDITOR', 'Read-only access for compliance and audit', ARRAY['events:read', 'detections:read', 'incidents:read', 'audit:read'])
ON CONFLICT (name) DO NOTHING;

-- Insert Sample Assets
INSERT INTO assets (id, hostname, ip_address, criticality, environment)
VALUES
  ('aaaaaaa1-1111-1111-1111-111111111111', 'auth-gateway-prod-01', '10.0.1.15', 'CRITICAL', 'PRODUCTION'),
  ('aaaaaaa2-2222-2222-2222-222222222222', 'api-backend-prod-01', '10.0.1.20', 'HIGH', 'PRODUCTION'),
  ('aaaaaaa3-3333-3333-3333-333333333333', 'db-primary-prod-01', '10.0.2.10', 'CRITICAL', 'PRODUCTION')
ON CONFLICT (hostname) DO NOTHING;

-- Insert Initial Admin User (password: AdminPassword123!)
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, is_active)
VALUES
  ('99999999-9999-9999-9999-999999999999', 'admin@sentinelx.local', '$2b$10$WWeUevFbL9QUMwcZOgHEIeFpvPWOLccMm50md8vE8PFTuogM3dhGa', 'Sentinel', 'Administrator', '11111111-1111-1111-1111-111111111111', true)
ON CONFLICT (email) DO NOTHING;

-- Insert SOC Analyst User (password: AnalystPassword123!)
-- Hash for AnalystPassword123!: $2b$10$WWeUevFbL9QUMwcZOgHEIeFpvPWOLccMm50md8vE8PFTuogM3dhGa (reusing test hash for dev seed)
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, is_active)
VALUES
  ('88888888-8888-8888-8888-888888888888', 'analyst@sentinelx.local', '$2b$10$WWeUevFbL9QUMwcZOgHEIeFpvPWOLccMm50md8vE8PFTuogM3dhGa', 'Alice', 'Analyst', '33333333-3333-3333-3333-333333333333', true)
ON CONFLICT (email) DO NOTHING;
