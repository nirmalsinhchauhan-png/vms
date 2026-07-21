-- ============================================================================
-- 000001_init — VMS Platform initial schema
-- PostgreSQL 16
--
-- Covers: organizations, auth (users/roles/refresh tokens), sites, cameras,
-- recording segment metadata, events, licensing, and audit logging.
--
-- No explicit BEGIN/COMMIT here: golang-migrate already runs each migration
-- file inside its own managed transaction. Wrapping it again would commit
-- migrate's transaction early and can leave schema_migrations "dirty".
-- ============================================================================

-- citext: case-insensitive email comparisons/uniqueness without app-side lower().
CREATE EXTENSION IF NOT EXISTS citext;

-- ----------------------------------------------------------------------------
-- Shared trigger: keep updated_at current on every row UPDATE.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Organizations — a single on-prem deployment is normally one row; the table
-- exists so the schema also supports a future hosted/multi-tenant offering
-- without a breaking migration.
-- ============================================================================
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    timezone        TEXT NOT NULL DEFAULT 'Asia/Kolkata',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================================
-- Roles & Users
-- ============================================================================
CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE CHECK (name IN ('admin', 'operator', 'viewer')),
    description     TEXT NOT NULL DEFAULT '',
    permissions     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO roles (name, description, permissions) VALUES
    ('admin',    'Full system access: users, cameras, licensing, settings', '{"*": true}'::jsonb),
    ('operator', 'Manage cameras and view/export recordings',               '{"cameras": ["read","write"], "recordings": ["read","export"], "events": ["read","ack"]}'::jsonb),
    ('viewer',   'Read-only live view and playback',                        '{"cameras": ["read"], "recordings": ["read"]}'::jsonb);

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    email               CITEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    full_name           TEXT NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email)
);

CREATE INDEX idx_users_organization_id ON users(organization_id);
CREATE INDEX idx_users_role_id ON users(role_id);

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Rotating refresh tokens: each row is one issued token in the rotation
-- chain. A reused (already-rotated) token is a theft signal the backend can
-- detect via replaced_by_id and revoke the whole chain.
CREATE TABLE refresh_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL UNIQUE,
    replaced_by_id      UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    ip_address          INET,
    user_agent          TEXT
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- ============================================================================
-- Sites & Camera Groups — physical/logical organization of cameras
-- ============================================================================
CREATE TABLE sites (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    address             TEXT NOT NULL DEFAULT '',
    timezone            TEXT NOT NULL DEFAULT 'Asia/Kolkata',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TRIGGER trg_sites_updated_at
    BEFORE UPDATE ON sites
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE camera_groups (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id             UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, name)
);

-- ============================================================================
-- Cameras
-- Credentials are stored as AES-256-GCM ciphertext (nonce + ciphertext + tag);
-- the application layer holds the key (CAMERA_CREDENTIALS_ENC_KEY), never the
-- database. mainstream_uri feeds FFmpeg recording; substream_uri feeds go2rtc
-- live view — the two pipelines are intentionally decoupled end to end.
-- ============================================================================
CREATE TABLE cameras (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id                 UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    camera_group_id         UUID REFERENCES camera_groups(id) ON DELETE SET NULL,
    name                    TEXT NOT NULL,
    manufacturer            TEXT NOT NULL DEFAULT '',
    model                   TEXT NOT NULL DEFAULT '',
    onvif_endpoint          TEXT,
    ip_address              INET NOT NULL,
    mainstream_uri          TEXT NOT NULL,
    substream_uri           TEXT,
    credential_username_enc BYTEA NOT NULL,
    credential_password_enc BYTEA NOT NULL,
    credential_nonce        BYTEA NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'unknown'
                                CHECK (status IN ('unknown', 'online', 'offline', 'error', 'disabled')),
    ptz_capable             BOOLEAN NOT NULL DEFAULT false,
    last_seen_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, name)
);

CREATE INDEX idx_cameras_organization_id ON cameras(organization_id);
CREATE INDEX idx_cameras_site_id ON cameras(site_id);
CREATE INDEX idx_cameras_status ON cameras(status);

CREATE TRIGGER trg_cameras_updated_at
    BEFORE UPDATE ON cameras
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Per-camera recording behavior: continuous, motion-triggered, or a fixed
-- weekly schedule. One active row per camera.
CREATE TABLE recording_schedules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    camera_id           UUID NOT NULL UNIQUE REFERENCES cameras(id) ON DELETE CASCADE,
    mode                TEXT NOT NULL DEFAULT 'continuous'
                            CHECK (mode IN ('continuous', 'motion', 'scheduled', 'disabled')),
    schedule            JSONB NOT NULL DEFAULT '{}'::jsonb,
    retention_days      INT NOT NULL DEFAULT 30 CHECK (retention_days > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_recording_schedules_updated_at
    BEFORE UPDATE ON recording_schedules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================================
-- Recording segments — one row per 10s HLS (.ts) segment FFmpeg writes to
-- XFS. Indexed for fast time-range playback lookups per camera.
-- ============================================================================
CREATE TABLE recording_segments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    camera_id           UUID NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
    file_path           TEXT NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL,
    duration_ms         INT NOT NULL CHECK (duration_ms > 0),
    size_bytes          BIGINT NOT NULL CHECK (size_bytes >= 0),
    checksum_sha256     TEXT,
    has_motion          BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_recording_segments_camera_time ON recording_segments(camera_id, started_at DESC);

-- ============================================================================
-- Events — motion, tamper, connectivity, storage, and system events.
-- ============================================================================
CREATE TABLE events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    camera_id           UUID REFERENCES cameras(id) ON DELETE CASCADE,
    event_type          TEXT NOT NULL
                            CHECK (event_type IN (
                                'motion_detected', 'camera_online', 'camera_offline',
                                'tamper_detected', 'disk_usage_warning', 'disk_full',
                                'recording_failed', 'license_expiring', 'license_expired'
                            )),
    severity            TEXT NOT NULL DEFAULT 'info'
                            CHECK (severity IN ('info', 'warning', 'critical')),
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    acknowledged_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_organization_created ON events(organization_id, created_at DESC);
CREATE INDEX idx_events_camera_id ON events(camera_id);
CREATE INDEX idx_events_unacknowledged ON events(organization_id) WHERE acknowledged_at IS NULL;

-- ============================================================================
-- Licensing — offline RS256-signed JWT, bound to a hardware fingerprint.
-- The JWT itself is the source of truth; this table caches its parsed claims
-- for fast lookups and lets the backend flag expiry/grace-period state.
-- ============================================================================
CREATE TABLE licenses (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    license_jwt             TEXT NOT NULL,
    hardware_fingerprint    TEXT NOT NULL,
    max_cameras             INT NOT NULL CHECK (max_cameras > 0),
    features                JSONB NOT NULL DEFAULT '{}'::jsonb,
    issued_at               TIMESTAMPTZ NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'expired', 'revoked')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_licenses_organization_id ON licenses(organization_id);

CREATE TRIGGER trg_licenses_updated_at
    BEFORE UPDATE ON licenses
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================================
-- Audit log — append-only record of security-relevant actions.
-- ============================================================================
CREATE TABLE audit_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    action              TEXT NOT NULL,
    resource_type       TEXT NOT NULL,
    resource_id         UUID,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address          INET,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_organization_created ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
