-- ============================================================
--  007 — Multi-tenant onboarding: classes, and the request/approve gate
--
--  Two changes.
--
--  1. A tenant is no longer always a family. `families.kind` says
--     whether a tenant is a household or a classroom. The roles
--     underneath stay 'parent' and 'learner' — a teacher IS a parent
--     row, a student IS a learner row — so every existing scoping
--     query keeps working untouched. Only the words on screen change.
--
--  2. Registration is still closed, but it is no longer a dead end.
--     A stranger who tries to sign in can now file a request for a new
--     family or class. An admin approves it, which is the ONLY way a
--     new tenant comes into existence.
--
--  Safe to re-run.
-- ============================================================

-- ── Tenant kind ────────────────────────────────────────────────
ALTER TABLE families ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'family';
DO $$ BEGIN
  ALTER TABLE families ADD CONSTRAINT families_kind_check
    CHECK (kind IN ('family','class'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── Access requests ────────────────────────────────────────────
-- A pending row is a stranger asking for a tenant. It is NOT an
-- account: no users row exists until an admin approves, so a pending
-- request cannot request a login code, cannot hold a session, and
-- cannot be referenced by anything family-scoped.
CREATE TABLE IF NOT EXISTS access_requests (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          citext NOT NULL,
  requester_name text NOT NULL,
  group_name     text NOT NULL,
  kind           text NOT NULL DEFAULT 'family' CHECK (kind IN ('family','class')),
  note           text NOT NULL DEFAULT '',
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied')),
  decision_note  text NOT NULL DEFAULT '',
  reviewed_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at    timestamptz,
  family_id      uuid REFERENCES families(id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- At most one open request per address. A denied or approved row stays
-- for the record but no longer blocks a fresh attempt.
CREATE UNIQUE INDEX IF NOT EXISTS access_requests_one_pending
  ON access_requests (email) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS access_requests_status_idx
  ON access_requests (status, created_at DESC);
