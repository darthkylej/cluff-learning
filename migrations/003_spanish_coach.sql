-- ============================================================
--  Cluff Learning Systems — Spanish Coach (migration 003)
--
--  Idempotent. Safe to run repeatedly.
--  Adds voice-conversation tables, the curriculum deck, and
--  per-learner lesson plans. Brings spanish-tutor online.
-- ============================================================

-- ── Learner profile ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_profiles (
  user_id              uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  comprehension_level  text NOT NULL DEFAULT 'novice_low',
  production_level     text NOT NULL DEFAULT 'novice_low',
  correction_intensity text NOT NULL DEFAULT 'balanced'
    CHECK (correction_intensity IN ('gentle','balanced','active')),
  english_support      text NOT NULL DEFAULT 'as_needed'
    CHECK (english_support IN ('immersion','as_needed','bilingual')),
  speech_rate          numeric(3,2) NOT NULL DEFAULT 0.92,
  session_minutes      integer NOT NULL DEFAULT 15
    CHECK (session_minutes BETWEEN 5 AND 60),
  daily_session_cap    integer NOT NULL DEFAULT 4
    CHECK (daily_session_cap BETWEEN 1 AND 10),
  weekly_minutes_goal  integer NOT NULL DEFAULT 105,
  transcript_retention text NOT NULL DEFAULT 'days_30'
    CHECK (transcript_retention IN ('none','days_30','retain')),
  show_direct_button   boolean NOT NULL DEFAULT true,
  interests            jsonb NOT NULL DEFAULT '[]'::jsonb,
  profile_summary      text NOT NULL DEFAULT '',
  total_seconds        integer NOT NULL DEFAULT 0,
  total_sessions       integer NOT NULL DEFAULT 0,
  updated_at           timestamptz NOT NULL DEFAULT now()
);

-- ── Sessions ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_sessions (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scenario_key         text NOT NULL DEFAULT 'free-talk',
  topic_key            text,
  engine               text NOT NULL DEFAULT 'pipeline'
    CHECK (engine IN ('pipeline','realtime')),
  status               text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','completed','abandoned','failed')),
  started_at           timestamptz NOT NULL DEFAULT now(),
  ended_at             timestamptz,
  duration_seconds     integer,
  model_name           text,
  input_audio_seconds  numeric(10,2) NOT NULL DEFAULT 0,
  output_audio_seconds numeric(10,2) NOT NULL DEFAULT 0,
  plan_id              bigint,
  summary              jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS spanish_sessions_user_started_idx
  ON spanish_sessions(user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS spanish_sessions_month_idx
  ON spanish_sessions(started_at);

-- ── Turns ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_turns (
  id                    bigserial PRIMARY KEY,
  session_id            uuid NOT NULL REFERENCES spanish_sessions(id) ON DELETE CASCADE,
  turn_index            integer NOT NULL,
  speaker               text NOT NULL CHECK (speaker IN ('learner','coach')),
  transcript            text NOT NULL,
  transcript_confidence numeric(4,3),
  audio_seconds         numeric(8,2),
  phase                 text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE(session_id, turn_index, speaker)
);

CREATE INDEX IF NOT EXISTS spanish_turns_session_idx
  ON spanish_turns(session_id, turn_index);

-- ── Interventions (the pedagogical event log) ───────────────────
CREATE TABLE IF NOT EXISTS spanish_interventions (
  id                         bigserial PRIMARY KEY,
  session_id                 uuid NOT NULL REFERENCES spanish_sessions(id) ON DELETE CASCADE,
  learner_turn_index         integer NOT NULL,
  intervention_type          text NOT NULL CHECK (intervention_type IN (
    'ignore','recast','expansion','extension',
    'clarification','guided_repair','explicit_correction')),
  intended_meaning           text,
  learner_form               text,
  target_form                text,
  skill_key                  text,
  importance                 smallint NOT NULL DEFAULT 1
    CHECK (importance BETWEEN 1 AND 5),
  recognition_uncertain      boolean NOT NULL DEFAULT false,
  learner_repeated_correctly boolean,
  created_at                 timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS spanish_interventions_session_idx
  ON spanish_interventions(session_id);

-- ── Skill estimates + spaced review ────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_skills (
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  skill_key        text NOT NULL,
  display_name     text NOT NULL,
  skill_type       text NOT NULL DEFAULT 'grammar' CHECK (skill_type IN
    ('grammar','vocabulary','comprehension','fluency','pronunciation')),
  evidence_count   integer NOT NULL DEFAULT 0,
  success_count    integer NOT NULL DEFAULT 0,
  recurrence_count integer NOT NULL DEFAULT 0,
  estimate         numeric(5,4) NOT NULL DEFAULT 0.20,
  last_seen_at     timestamptz,
  next_review_at   timestamptz,
  notes            jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY(user_id, skill_key)
);

CREATE INDEX IF NOT EXISTS spanish_skills_review_idx
  ON spanish_skills(user_id, next_review_at);

-- ── Vocabulary ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_vocabulary (
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  lemma               text NOT NULL,
  english_gloss       text,
  exposures           integer NOT NULL DEFAULT 0,
  produced_correctly  integer NOT NULL DEFAULT 0,
  produced_with_help  integer NOT NULL DEFAULT 0,
  mastery             numeric(5,4) NOT NULL DEFAULT 0.10,
  last_seen_at        timestamptz,
  next_review_at      timestamptz,
  PRIMARY KEY(user_id, lemma)
);

CREATE INDEX IF NOT EXISTS spanish_vocabulary_review_idx
  ON spanish_vocabulary(user_id, next_review_at);

-- ── Scenarios (role-play settings) ─────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_scenarios (
  key                 text PRIMARY KEY,
  title               text NOT NULL,
  description         text NOT NULL,
  opening_instruction text NOT NULL,
  target_domains      jsonb NOT NULL DEFAULT '[]'::jsonb,
  min_level           text NOT NULL DEFAULT 'novice_low',
  enabled             boolean NOT NULL DEFAULT true,
  sort_order          integer NOT NULL DEFAULT 100
);

-- ── Curriculum deck ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_topics (
  key               text PRIMARY KEY,
  title             text NOT NULL,
  unit_order        integer NOT NULL,
  target_words      jsonb NOT NULL DEFAULT '[]'::jsonb,
  target_structures jsonb NOT NULL DEFAULT '[]'::jsonb,
  min_level         text NOT NULL DEFAULT 'novice_low',
  enabled           boolean NOT NULL DEFAULT true
);

-- ── Per-learner lesson plans ───────────────────────────────────
CREATE TABLE IF NOT EXISTS spanish_lesson_plans (
  id              bigserial PRIMARY KEY,
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sequence        integer NOT NULL,
  plan            jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  used_by_session uuid REFERENCES spanish_sessions(id) ON DELETE SET NULL,
  UNIQUE(user_id, sequence)
);

CREATE INDEX IF NOT EXISTS spanish_lesson_plans_pending_idx
  ON spanish_lesson_plans(user_id, sequence DESC)
  WHERE used_by_session IS NULL;

-- ── Seeds: curriculum deck (12 units) ──────────────────────────
INSERT INTO spanish_topics (key, title, unit_order, target_words, target_structures) VALUES
  ('saludos-familia', 'Saludos y familia', 1,
   '["hola","la mamá","el papá","el hermano","la hermana","los años"]'::jsonb,
   '[{"skill_key":"ser_intro","note":"ser + names and ages; quién / cómo"}]'::jsonb),
  ('animales', 'Animales', 2,
   '["el perro","el gato","el pájaro","la tortuga","grande","pequeño"]'::jsonb,
   '[{"skill_key":"gender_agreement_basic","note":"el/la + adjective agreement"},
     {"skill_key":"tener_present","note":"tengo / tienes"}]'::jsonb),
  ('comida', 'Comida', 3,
   '["la manzana","el pan","la leche","el queso","quiero","me gusta"]'::jsonb,
   '[{"skill_key":"gustar_singular","note":"me gusta(n) + noun"},
     {"skill_key":"querer_request","note":"quiero + noun, polite requests"}]'::jsonb),
  ('la-escuela', 'La escuela', 4,
   '["el libro","el maestro","la clase","el lunes","hay"]'::jsonb,
   '[{"skill_key":"ir_a_present","note":"voy a / vas a"},
     {"skill_key":"hay_existential","note":"hay + noun"}]'::jsonb),
  ('mi-casa', 'Mi casa', 5,
   '["la cocina","el cuarto","la mesa","la puerta","debajo","sobre"]'::jsonb,
   '[{"skill_key":"estar_location","note":"está + en/sobre/debajo"}]'::jsonb),
  ('cuerpo-ropa', 'El cuerpo y la ropa', 6,
   '["la cabeza","la mano","la camisa","los zapatos","llevar"]'::jsonb,
   '[{"skill_key":"llevar_present","note":"llevo / llevas + clothing"},
     {"skill_key":"me_duele","note":"me duele + body part"}]'::jsonb),
  ('el-tiempo', 'El tiempo y las estaciones', 7,
   '["el sol","la lluvia","el frío","el calor","el invierno","el verano"]'::jsonb,
   '[{"skill_key":"hace_weather","note":"hace calor / hace frío / llueve"}]'::jsonb),
  ('direcciones', 'El pueblo y direcciones', 8,
   '["la calle","la tienda","el parque","la izquierda","la derecha","cerca"]'::jsonb,
   '[{"skill_key":"direcciones_basic","note":"está a la izquierda / derecha"},
     {"skill_key":"commands_informal","note":"ve, dobla, sigue"}]'::jsonb),
  ('numeros-hora', 'Los números y la hora', 9,
   '["uno","diez","veinte","cien","la hora","cuánto"]'::jsonb,
   '[{"skill_key":"que_hora_es","note":"¿qué hora es? son las..."},
     {"skill_key":"numbers_to_100","note":"counting and quantity"}]'::jsonb),
  ('sentimientos', 'Sentimientos', 10,
   '["feliz","triste","cansado","enojado","porque"]'::jsonb,
   '[{"skill_key":"estar_emotion","note":"estoy / estás + emotion"},
     {"skill_key":"porque_clause","note":"porque + reason"}]'::jsonb),
  ('pasatiempos', 'Pasatiempos y deportes', 11,
   '["el fútbol","jugar","correr","nadar","siempre","nunca"]'::jsonb,
   '[{"skill_key":"jugar_hacer","note":"juego a / hago"},
     {"skill_key":"frequency_adverbs","note":"siempre, a veces, nunca"}]'::jsonb),
  ('cuentos-pasado', 'Cuentos y pasado', 12,
   '["ayer","anoche","fui","comí","jugué","el cuento"]'::jsonb,
   '[{"skill_key":"preterite_ir_first_person","note":"fui / fuiste"},
     {"skill_key":"preterite_ar_regular","note":"-é / -aste endings"}]'::jsonb)
ON CONFLICT (key) DO UPDATE SET
  title             = EXCLUDED.title,
  unit_order        = EXCLUDED.unit_order,
  target_words      = EXCLUDED.target_words,
  target_structures = EXCLUDED.target_structures;

-- ── Seeds: scenarios ───────────────────────────────────────────
INSERT INTO spanish_scenarios
  (key, title, description, opening_instruction, target_domains, sort_order)
VALUES
  ('free-talk', 'Conversación libre',
   'Talk naturally about anything.',
   'Invite the learner to choose a topic, then sustain the conversation.',
   '["conversation","interests"]'::jsonb, 10),
  ('mystery-island', 'La isla misteriosa',
   'Explore an island and solve a story problem through Spanish.',
   'Begin on a beach with a map, a distant light, and two possible paths.',
   '["directions","descriptions","past_tense"]'::jsonb, 20),
  ('restaurant', 'En el restaurante',
   'Order food, ask questions, and solve a small mix-up.',
   'Greet the learner as the server and offer a short menu.',
   '["food","polite_requests","numbers"]'::jsonb, 30),
  ('granja-visita', 'Visita a la granja',
   'Visit a farm and meet the animals.',
   'Greet the learner at the farm gate; animals are waiting to be described.',
   '["animals","descriptions","adjectives"]'::jsonb, 40),
  ('la-tienda', 'En la tienda',
   'Shop for a few things and handle prices.',
   'Greet the learner as the shopkeeper; ask what they are looking for.',
   '["shopping","numbers","polite_requests"]'::jsonb, 50)
ON CONFLICT (key) DO UPDATE SET
  title               = EXCLUDED.title,
  description         = EXCLUDED.description,
  opening_instruction = EXCLUDED.opening_instruction,
  target_domains      = EXCLUDED.target_domains,
  sort_order          = EXCLUDED.sort_order;

-- ── Bring the module online ────────────────────────────────────
-- NOTE: `url` is a full absolute URL (matches every other seeded tool),
-- and `accent` is a named enum, not a hex colour.
UPDATE tools
   SET name        = 'Spanish Coach',
       tagline     = 'Real conversations that teach while you talk',
       description = 'Voice-first Spanish conversation with gentle recasts, daily lessons, and long-term memory.',
       glyph       = '◉',
       accent      = 'amber',
       status      = 'online',
       url         = 'https://darthkylej.github.io/cluff-learning/spanish-coach.html'
 WHERE slug = 'spanish-tutor';
