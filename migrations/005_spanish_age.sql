-- ============================================================
--  Cluff Learning Systems — Spanish age (migration 005)
--
--  Idempotent. Safe to run repeatedly.
--  Replaces the session arc with a single developmental dial,
--  and records where the parent set it so drift stays legible.
-- ============================================================

-- ── How old this child sounds in Spanish ───────────────────────
-- Not their real age. 1 means they speak Spanish like a one-year-old
-- does: a few words, no sentences, answers that may not follow the
-- question. 3 means a three-year-old. The coach speaks to this number
-- and expects replies at it, which is the whole point — a child asked
-- for a story before they can make a sentence learns that Spanish is
-- a thing they fail at.
--
-- Fractional on purpose. Growth is a drift of a tenth or two per
-- session, not a promotion, so a child crosses from 2 to 3 without a
-- day where the coach suddenly talks over their head.
ALTER TABLE spanish_profiles
  ADD COLUMN IF NOT EXISTS spanish_age numeric(3,1) NOT NULL DEFAULT 2.0;

DO $$ BEGIN
  ALTER TABLE spanish_profiles ADD CONSTRAINT spanish_profiles_age_check
    CHECK (spanish_age BETWEEN 1 AND 12);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- What the parent last set by hand, and when. Kept so the Flight Deck
-- can show "you set 3, it has grown to 3.6" — and so a reset is a real
-- reset: the drift starts again from the new number, not from wherever
-- the old one had wandered to.
ALTER TABLE spanish_profiles
  ADD COLUMN IF NOT EXISTS spanish_age_baseline numeric(3,1);
ALTER TABLE spanish_profiles
  ADD COLUMN IF NOT EXISTS spanish_age_set_at timestamptz;

-- ── Sessions no longer have a target length ────────────────────
-- session_minutes stays on the table because dropping a column is not
-- worth the risk to old rows, but nothing reads it any more. A session
-- lasts exactly as long as the child wants it to.
COMMENT ON COLUMN spanish_profiles.session_minutes IS
  'Unused since migration 005. Sessions are open-ended; the child ends them.';

COMMENT ON COLUMN spanish_sessions.input_audio_seconds IS
  'Seconds the learner actually held the record button on turns that produced words. This is the number the Flight Deck reports as time spoken.';
