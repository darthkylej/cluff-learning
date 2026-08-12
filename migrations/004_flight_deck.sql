-- ============================================================
--  Cluff Learning Systems — Flight Deck (migration 004)
--
--  Idempotent. Safe to run repeatedly.
--  Adds time-on-task measurement, an audience flag so a module
--  can be hidden from the learners' grid, and the parent-only
--  Flight Deck module itself.
-- ============================================================

-- ── Time on task ───────────────────────────────────────────────
-- One row per stretch of time a person spent inside a module.
--
-- The browser sends a heartbeat every 45 seconds while the tab is
-- visible; the SERVER decides what that beat is worth by looking
-- at the clock, so nothing here depends on a number the client
-- reported. A closed laptop simply stops beating, and the row
-- stops growing — no "end session" call to miss.
--
-- A beat more than 150 seconds after the last one opens a new row
-- rather than extending the old one, so a module left open
-- overnight doesn't read as an all-night study session.
--
-- `seconds` is therefore always an undercount by up to one beat
-- interval per visit. That is the right direction to be wrong in.
CREATE TABLE IF NOT EXISTS module_sessions (
  id           bigserial PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_slug    text NOT NULL REFERENCES tools(slug) ON DELETE CASCADE,
  started_at   timestamptz NOT NULL DEFAULT now(),
  last_beat_at timestamptz NOT NULL DEFAULT now(),
  seconds      integer NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS module_sessions_user_started_idx
  ON module_sessions (user_id, started_at DESC);

-- The lookup every heartbeat makes: "is there an open session for
-- this person in this module?"
CREATE INDEX IF NOT EXISTS module_sessions_open_idx
  ON module_sessions (user_id, tool_slug, last_beat_at DESC);

-- ── Who a module is for ────────────────────────────────────────
-- Everything before now was for the kids. The Flight Deck is for
-- the grown-ups, and a module the learners can see but never open
-- is just a locked door to rattle.
ALTER TABLE tools ADD COLUMN IF NOT EXISTS audience text NOT NULL DEFAULT 'all';
DO $$ BEGIN
  ALTER TABLE tools ADD CONSTRAINT tools_audience_check
    CHECK (audience IN ('all','parents'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── Register the module ────────────────────────────────────────
INSERT INTO tools (slug, name, tagline, description, glyph, accent, status, url, sort_order, audience) VALUES
  ('flight-deck', 'Flight Deck', 'Every learner, every module, at a glance',
   'See where each of your students stands in every module, how long they have spent in each one, and what they worked on most recently.',
   '◎', 'amber', 'online',
   'https://darthkylej.github.io/cluff-learning/flight-deck.html', 5, 'parents')
ON CONFLICT (slug) DO UPDATE SET
  name        = EXCLUDED.name,
  tagline     = EXCLUDED.tagline,
  description = EXCLUDED.description,
  glyph       = EXCLUDED.glyph,
  accent      = EXCLUDED.accent,
  status      = EXCLUDED.status,
  url         = EXCLUDED.url,
  sort_order  = EXCLUDED.sort_order,
  audience    = EXCLUDED.audience;
