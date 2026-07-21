-- ============================================================================
-- 000001_init (down) — reverses 000001_init.up.sql
-- Drop order is the reverse of creation to respect foreign keys.
-- ============================================================================

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS licenses;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS recording_segments;
DROP TABLE IF EXISTS recording_schedules;
DROP TABLE IF EXISTS cameras;
DROP TABLE IF EXISTS camera_groups;
DROP TABLE IF EXISTS sites;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS organizations;

DROP FUNCTION IF EXISTS set_updated_at();

DROP EXTENSION IF EXISTS citext;
