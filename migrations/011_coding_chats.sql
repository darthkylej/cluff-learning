-- Run once in the Neon SQL Editor before deploying the updated Worker.
CREATE TABLE IF NOT EXISTS coding_chats (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title text NOT NULL DEFAULT 'New conversation',
  messages jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS coding_chats_user_updated_idx ON coding_chats(user_id, updated_at DESC);
