-- ============================================================================
-- 000002_camera_credential_merge
--
-- Fixes a nonce-reuse bug in the Sprint 1 schema: cameras had two separate
-- ciphertext columns (credential_username_enc, credential_password_enc) but
-- only ONE shared credential_nonce. Encrypting two different plaintexts
-- under the same AES-256-GCM key with the same nonce is a real
-- cryptographic weakness (nonce reuse under GCM can leak the XOR of the two
-- plaintexts and allow forging authentication tags). No encryption code
-- existed yet to expose this, so it went unnoticed until Sprint 2.
--
-- Fix: merge into a single credential_enc column holding one encrypted JSON
-- payload {"username":"...","password":"..."}, so there's exactly one
-- plaintext, one nonce, one ciphertext — what AES-GCM is designed for.
-- No real camera data exists yet, so no data migration is needed.
-- ============================================================================

ALTER TABLE cameras
    ADD COLUMN credential_enc BYTEA;

UPDATE cameras SET credential_enc = ''::bytea WHERE credential_enc IS NULL;

ALTER TABLE cameras
    ALTER COLUMN credential_enc SET NOT NULL,
    DROP COLUMN credential_username_enc,
    DROP COLUMN credential_password_enc;
