-- ============================================================================
-- 000003_backfill_recording_schedules
--
-- Sprint 3 added auto-creation of a default 'continuous' recording_schedules
-- row when a camera is created via the API, but that only takes effect for
-- new cameras going forward — anything created in Sprint 2, before that
-- code existed, has no schedule row at all and the recording manager's
-- reconcile query (JOIN recording_schedules) silently never picks it up.
-- Backfill one for every camera that's missing one, defaulting to
-- 'continuous' at the standard 30-day retention, matching what a camera
-- created today would get.
-- ============================================================================

INSERT INTO recording_schedules (camera_id, mode, retention_days)
SELECT c.id, 'continuous', 30
FROM cameras c
LEFT JOIN recording_schedules rs ON rs.camera_id = c.id
WHERE rs.camera_id IS NULL;
