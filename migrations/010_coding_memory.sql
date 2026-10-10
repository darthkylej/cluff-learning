CREATE TABLE IF NOT EXISTS coding_memory (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 repo text NOT NULL DEFAULT '',
 notes text NOT NULL DEFAULT '',
 summary text NOT NULL DEFAULT '',
 summarized_count integer NOT NULL DEFAULT 0,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (user_id, repo)
);
