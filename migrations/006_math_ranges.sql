-- ============================================================
--  Cluff Learning Systems — Fact Runner number ranges (migration 006)
--
--  Idempotent. Safe to run repeatedly.
--  Lets a parent aim each child's arithmetic practice at the facts
--  that child is actually working on.
-- ============================================================

-- ── Per-learner practice ranges for Fact Runner ────────────────
-- One row per person, holding which operations they practise and the
-- numbers each operation draws from:
--
--   { "mul": { "on": true, "a": {"min":1,"max":8},  "b": {"min":1,"max":12} },
--     "div": { "on": true, "divisor": {...}, "quotient": {...} },
--     "add": { "on": true, "a": {...}, "b": {...} },
--     "sub": { "on": true, "a": {...}, "b": {...}, "negatives": true } }
--
-- Absent row means the ranges the game shipped with (1–12 tables,
-- 1–100 addition and subtraction), so nobody has to be configured
-- before they can play.
--
-- jsonb rather than a column per knob: a fifth operation later is a
-- Worker change, not a migration. The Worker is the authority on
-- shape and limits — everything written here has been through
-- normalizeMathSettings first.
--
-- Only a parent writes this table, and only for someone in their own
-- family. A learner reads their own row and cannot change it; what
-- they still choose for themselves is which of the operations left
-- switched on they want to drill today.
CREATE TABLE IF NOT EXISTS math_fact_settings (
  user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  settings   jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE math_fact_settings IS
  'Fact Runner practice ranges, set by a parent. Absent row = the default 1-12 tables and 1-100 addition/subtraction.';
