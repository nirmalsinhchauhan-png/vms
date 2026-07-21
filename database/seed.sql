-- ============================================================================
-- seed.sql — development-only sample data.
--
-- NEVER run this against a production database: it creates a known admin
-- login (admin@example.com / ChangeMe123!) purely so a fresh dev environment
-- has something to log into and look at. Applied via `make seed`, not
-- docker-entrypoint-initdb.d — see docker-compose.yml's postgres service.
--
-- Idempotent: safe to run more than once against the same database.
-- ============================================================================

-- pgcrypto's crypt()/gen_salt('bf') produces standard $2a$ bcrypt hashes,
-- the same format golang.org/x/crypto/bcrypt verifies — no need for a
-- separate hashing tool just to seed a login.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

WITH ins AS (
    INSERT INTO organizations (name, slug)
    VALUES ('Silicon Signals Demo', 'demo')
    ON CONFLICT (slug) DO NOTHING
    RETURNING id
)
SELECT id FROM ins
UNION ALL
SELECT id FROM organizations WHERE slug = 'demo'
LIMIT 1 \gset org_

WITH ins AS (
    INSERT INTO sites (organization_id, name, address)
    VALUES (:'org_id', 'HQ', 'Ahmedabad, Gujarat, India')
    ON CONFLICT (organization_id, name) DO NOTHING
    RETURNING id
)
SELECT id FROM ins
UNION ALL
SELECT id FROM sites WHERE organization_id = :'org_id' AND name = 'HQ'
LIMIT 1 \gset site_

INSERT INTO users (organization_id, role_id, email, password_hash, full_name)
SELECT :'org_id', r.id, 'admin@example.com', crypt('ChangeMe123!', gen_salt('bf', 10)), 'Demo Admin'
FROM roles r
WHERE r.name = 'admin'
ON CONFLICT (organization_id, email) DO NOTHING;

\echo 'Seed complete. Login: admin@example.com / ChangeMe123! (dev only — change or remove before production).'
