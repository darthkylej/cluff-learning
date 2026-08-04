-- ============================================================
--  Cluff Learning Systems — initial schema
--  Target: Neon Postgres
--  Run this once in the Neon SQL Editor (or via psql).
--  Safe to re-run: every statement is IF NOT EXISTS / idempotent.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive email

-- ── Crew ───────────────────────────────────────────────────────
-- One row per person who can sign in. Registration is closed:
-- a row must exist here (created by a parent, or bootstrapped via
-- the BOOTSTRAP_EMAILS secret) before that address can request a
-- login code.
CREATE TABLE IF NOT EXISTS users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          citext UNIQUE NOT NULL,
  display_name   text,
  avatar_key     text NOT NULL DEFAULT 'delta',
  is_admin       boolean NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_login_at  timestamptz
);

-- The reading level that student-facing prose is written at. This is a
-- PRESENTATION setting only — it never changes how work is graded, just
-- how the feedback is worded. A parent sets the starting band; it then
-- ratchets upward on its own as the student's real scores climb, and
-- never moves back down (a demotion after one bad essay would sting
-- more than the score does).
ALTER TABLE users ADD COLUMN IF NOT EXISTS feedback_level text NOT NULL DEFAULT 'upper_elementary';
DO $$ BEGIN
  ALTER TABLE users ADD CONSTRAINT users_feedback_level_check
    CHECK (feedback_level IN ('early_elementary','upper_elementary','middle_school','high_school','college'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── One-time login codes ───────────────────────────────────────
-- Codes are stored as SHA-256 hashes, never in plaintext.
CREATE TABLE IF NOT EXISTS otp_codes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email       citext NOT NULL,
  code_hash   text NOT NULL,
  attempts    int NOT NULL DEFAULT 0,
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS otp_codes_email_idx   ON otp_codes (email);
CREATE INDEX IF NOT EXISTS otp_codes_expires_idx ON otp_codes (expires_at);

-- ── Sessions ───────────────────────────────────────────────────
-- The JWT handed to the browser carries only this row's id.
-- Deleting the row revokes the token immediately.
CREATE TABLE IF NOT EXISTS sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_agent   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

-- ── Families ───────────────────────────────────────────────────
-- The tenancy boundary, equivalent to a "ward" in Condscript.
-- Every learner belongs to exactly one family.
CREATE TABLE IF NOT EXISTS families (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text NOT NULL,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS family_members (
  family_id uuid NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role      text NOT NULL DEFAULT 'learner' CHECK (role IN ('parent','learner')),
  added_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  added_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (family_id, user_id)
);
-- A person belongs to at most one family.
CREATE UNIQUE INDEX IF NOT EXISTS family_members_one_per_user ON family_members (user_id);

-- ── Tool registry ──────────────────────────────────────────────
-- The homepage grid is rendered from this table, so adding a new
-- module later is an INSERT rather than a frontend edit.
CREATE TABLE IF NOT EXISTS tools (
  slug        text PRIMARY KEY,
  name        text NOT NULL,
  tagline     text,
  description text,
  glyph       text NOT NULL DEFAULT '◈',
  accent      text NOT NULL DEFAULT 'cyan'
              CHECK (accent IN ('cyan','amber','violet','green','rose')),
  status      text NOT NULL DEFAULT 'planned'
              CHECK (status IN ('online','beta','planned','offline')),
  url         text,
  sort_order  int NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- ── Per-learner tool access ────────────────────────────────────
-- Absent row = tool is available. A row with enabled=false is an
-- explicit parental block for that learner.
CREATE TABLE IF NOT EXISTS tool_access (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_slug  text NOT NULL REFERENCES tools(slug) ON DELETE CASCADE,
  enabled    boolean NOT NULL DEFAULT true,
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, tool_slug)
);

-- ── Generic per-tool saved state ───────────────────────────────
-- Scaffolding for the modules that come next (Spanish tutor,
-- spelling game, essay coach, typing trainer). Each keeps its own
-- shape inside `state`, so new tools need no new migration.
CREATE TABLE IF NOT EXISTS tool_progress (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_slug  text NOT NULL REFERENCES tools(slug) ON DELETE CASCADE,
  state      jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, tool_slug)
);

-- ── Activity log ───────────────────────────────────────────────
-- Append-only. Feeds the parent dashboard later on.
CREATE TABLE IF NOT EXISTS activity_log (
  id         bigserial PRIMARY KEY,
  user_id    uuid REFERENCES users(id) ON DELETE CASCADE,
  tool_slug  text REFERENCES tools(slug) ON DELETE SET NULL,
  event      text NOT NULL,
  payload    jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS activity_log_user_time_idx ON activity_log (user_id, created_at DESC);

-- ── Seed the tool registry ─────────────────────────────────────
INSERT INTO tools (slug, name, tagline, description, glyph, accent, status, url, sort_order) VALUES
  ('code-lab',       'Code Lab',        'Guided programming with a safe AI mentor',
   'Write real code with an AI mentor that teaches instead of doing the work for you.',
   '⌘', 'cyan',   'online',  'https://darthkylej.github.io/Safe-Coding-Helper-for-Kids/', 10),

  ('spelling-drill', 'Spell Invaders',  'Adaptive spelling practice',
   'Spell your way to credits, then arm your ship and defend Earth. Word mastery is tracked per player.',
   '◆', 'amber',  'online',  'https://darthkylej.github.io/cluff-learning/games/spell-invaders.html', 20),

  ('spanish-tutor',  'Spanish Comms',   'Live conversation practice',
   'Talk with an AI conversation partner in Spanish at your level, with gentle correction.',
   '⌬', 'violet', 'planned', NULL, 30),

  ('essay-coach',    'Essay Coach',     'College-level essay grading and coaching',
   'Write to a prompt your parent sets and get sentence-by-sentence feedback plus honest, college-level grading.',
   '▤', 'green',  'online',  'https://darthkylej.github.io/cluff-learning/essay-coach.html', 40),

  ('typing-trainer', 'Typing Trainer',  'Speed and accuracy drills',
   'Build muscle memory with timed drills and accuracy tracking.',
   '⌨', 'rose',   'planned', NULL, 50)
ON CONFLICT (slug) DO UPDATE SET
  name        = EXCLUDED.name,
  tagline     = EXCLUDED.tagline,
  description = EXCLUDED.description,
  glyph       = EXCLUDED.glyph,
  accent      = EXCLUDED.accent,
  status      = EXCLUDED.status,
  url         = EXCLUDED.url,
  sort_order  = EXCLUDED.sort_order;

-- ── Spell Invaders: shared word bank ────────────────────────────
-- One word bank for the whole platform (not scoped to a family).
-- Only an admin (users.is_admin) may add, edit, or remove words.
-- Case-insensitive on `word` so "Because" and "because" collide.
CREATE TABLE IF NOT EXISTS spelling_words (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  word       citext NOT NULL UNIQUE,
  sentence   text NOT NULL DEFAULT '',
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Per-player mastery score against the shared bank, -10..10,
-- mirroring the old CSV `score` column. Absent row = untried (0).
CREATE TABLE IF NOT EXISTS spelling_word_scores (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  word_id    uuid NOT NULL REFERENCES spelling_words(id) ON DELETE CASCADE,
  score      int NOT NULL DEFAULT 0 CHECK (score BETWEEN -10 AND 10),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, word_id)
);
CREATE INDEX IF NOT EXISTS spelling_word_scores_user_idx ON spelling_word_scores (user_id);

-- ── Essay Coach ──────────────────────────────────────────────────
-- A parent writes a prompt and assigns it to one or more of their
-- own kids. Family-scoped (unlike the platform-wide spelling bank),
-- since a writing prompt is set by and for one family.
CREATE TABLE IF NOT EXISTS essay_assignments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id       uuid NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
  title           text NOT NULL,
  prompt          text NOT NULL,
  length_guidance text NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS essay_assignment_targets (
  assignment_id uuid NOT NULL REFERENCES essay_assignments(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (assignment_id, user_id)
);
CREATE INDEX IF NOT EXISTS essay_assignment_targets_user_idx ON essay_assignment_targets (user_id);

-- One essay per (assignment, student). `original_text` is frozen at
-- the moment the student clicks Grade — that text and the score
-- computed from it never change again. Everything after grading
-- (the 5-issue coaching loop) writes into `coaching` on a practice
-- copy and never touches original_text or score_total.
CREATE TABLE IF NOT EXISTS essays (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assignment_id          uuid NOT NULL REFERENCES essay_assignments(id) ON DELETE CASCADE,
  user_id                uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status                 text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','grading','graded')),
  draft_text             text NOT NULL DEFAULT '',
  draft_updated_at       timestamptz NOT NULL DEFAULT now(),
  original_text          text,          -- frozen at grading time; this is what was scored
  score_total            int,           -- 0..100, the real/objective score — never shown raw to a struggling student
  adaptive_score         int,           -- 0..100, the score actually presented to the student
  feedback               jsonb,         -- rubric breakdown, sentence annotations, top-5 issues, narrative feedback
  coaching                jsonb,         -- post-grade practice state: practice_text + per-issue status/attempts
  graded_at              timestamptz,
  coaching_completed_at  timestamptz,
  UNIQUE (assignment_id, user_id)
);
CREATE INDEX IF NOT EXISTS essays_user_idx ON essays (user_id);

-- Per-student recurring-weakness ledger. Every issue Claude finds
-- (not just the 5 chosen for coaching) updates this, so future
-- grading calls know the difference between "first time seeing
-- this" and "flagged four essays running" — and the adaptive score
-- can dock a student who never fixes something they've been told.
CREATE TABLE IF NOT EXISTS essay_issue_history (
  user_id                       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issue_type                    text NOT NULL,
  tier                          text NOT NULL CHECK (tier IN ('mechanics','clarity','organization','argument','rhetoric')),
  times_flagged                 int NOT NULL DEFAULT 0,
  times_in_top_five             int NOT NULL DEFAULT 0,
  times_recurred_after_flagged  int NOT NULL DEFAULT 0,
  first_seen_essay_id           uuid REFERENCES essays(id) ON DELETE SET NULL,
  last_seen_essay_id            uuid REFERENCES essays(id) ON DELETE SET NULL,
  updated_at                    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, issue_type)
);
