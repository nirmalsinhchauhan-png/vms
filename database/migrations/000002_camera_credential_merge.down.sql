-- ============================================================================
-- 000002_camera_credential_merge (down)
--
-- Restores the pre-merge two-column shape. No real camera data exists at
-- this stage of the project, so the restored columns are placeholder-empty
-- rather than reconstructed from credential_enc.
-- ============================================================================

ALTER TABLE cameras
    ADD COLUMN credential_username_enc BYTEA,
    ADD COLUMN credential_password_enc BYTEA;

UPDATE cameras SET
    credential_username_enc = ''::bytea,
    credential_password_enc = ''::bytea
WHERE credential_username_enc IS NULL;

ALTER TABLE cameras
    ALTER COLUMN credential_username_enc SET NOT NULL,
    ALTER COLUMN credential_password_enc SET NOT NULL,
    DROP COLUMN credential_enc;
