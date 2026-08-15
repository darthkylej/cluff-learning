# Cluff Learning Systems

A family learning platform. Same stack and sign-in model as
[condscript](https://github.com/darthkylej/condscript): a single static page on
GitHub Pages, a Cloudflare Worker API, Neon Postgres, and email one-time codes
via Resend.

```
Browser  ──▶  index.html         GitHub Pages
                  │
                  ▼  fetch + Bearer JWT
             worker.js           Cloudflare Worker
                  │
                  ▼  Neon HTTP /sql
             Neon Postgres
```

## What's here

| File | Purpose |
| --- | --- |
| `index.html` | Access terminal + bridge homepage. No build step, no dependencies. |
| `flight-deck.html` | Flight Deck — the parent/teacher dashboard. Parents only. |
| `essay-coach.html` | Essay Coach module. |
| `spanish-coach.html` | Spanish Coach module — voice conversation. |
| `games/spell-invaders.html` | Spell Invaders module. |
| `games/fact-runner.html` | Fact Runner module — math facts. |
| `worker.js` | API: auth, family/crew registry, module registry, per-tool saved state. |
| `wrangler.toml` | Worker config and the list of required secrets. |
| `schema.sql` | Postgres schema + seeded module registry. Idempotent. |
| `migrations/` | Incremental schema migrations applied after `schema.sql`. |
| `docs/VOICE_AUDITION.md` | Gate 0 — the Spanish voice check, required before launch. |

Every module is a single self-contained HTML file that signs in against the
same Worker with the JWT already in `localStorage`.

## Sign-in model

Everyone — parents and kids — signs in with their own email address and a
6-digit code. There is no password.

**Registration is closed.** `/auth/send-otp` refuses any address that doesn't
already have a `users` row. Rows are created two ways:

1. A parent adds someone via **+ Add member** on the bridge.
2. The address is listed in the `BOOTSTRAP_EMAILS` secret — that's the escape
   hatch that lets the first parent in.

This keeps strangers from creating accounts on a site the kids use.

Differences from condscript's auth, all deliberate:

- OTP codes are stored as SHA-256 hashes, never plaintext.
- Codes are generated with `crypto.getRandomValues`, not `Math.random`.
- Five wrong attempts burns the code.
- CORS is limited to an origin allowlist instead of `*`.

## Tables

- `users` — one row per person who can sign in
- `otp_codes` — pending login codes (hashed, expiring)
- `sessions` — server-side session rows; the JWT only carries a session id, so
  deleting the row revokes the token immediately
- `families` / `family_members` — the tenancy boundary, with `parent` /
  `learner` roles. One family per person.
- `tools` — the module registry that renders the homepage grid
- `tool_access` — per-learner enable/disable, set by a parent
- `tool_progress` — generic `jsonb` state bucket, one row per (user, tool)
- `math_fact_settings` — Fact Runner number ranges, set per learner by a parent
- `module_sessions` — one row per stretch of time someone spent in a module
- `activity_log` — append-only event stream; still unused

`tool_progress` is what the modules save into — one `jsonb` blob per (user,
tool), so a new module needs no migration. `activity_log` predates
`module_sessions` and nothing writes to it.

## Setup

### 1. Database

Create a Neon project, then paste `schema.sql` into the Neon SQL Editor and run
it, followed by each file in `migrations/` in numerical order. Every one of them
is idempotent, so re-running is safe. Copy the **pooled** connection string.

Run the migrations **before** deploying a Worker that needs them — `/parents/*`
and `/activity/beat` query tables that migration 004 creates, and `/math/settings`
queries one that 006 creates.

### 2. Worker

```bash
npx wrangler secret put DATABASE_URL
```

Then the rest, one at a time:

```bash
npx wrangler secret put JWT_SECRET
```

```bash
npx wrangler secret put RESEND_API_KEY
```

```bash
npx wrangler secret put RESEND_FROM
```

```bash
npx wrangler secret put BOOTSTRAP_EMAILS
```

- `JWT_SECRET` — any long random string
- `RESEND_FROM` — must be on a domain verified in Resend, e.g.
  `Cluff Learning <no-reply@yourdomain.com>`. Until a domain is verified, Resend
  only delivers to your own account address.
- `BOOTSTRAP_EMAILS` — comma-separated, e.g. `kylecluff@protonmail.com`

Deploy:

```bash
npx wrangler deploy
```

### 3. Frontend

Set `API_URL` near the top of the `<script>` block in `index.html` to the
deployed Worker URL, then enable GitHub Pages on `main` / root. Add any extra
origins you serve from to `ALLOWED_ORIGINS` in `worker.js`.

### 4. First run

Sign in with a `BOOTSTRAP_EMAILS` address → create the family → add each kid by
email. They can sign in from that point on.

## API

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/auth/send-otp` | `{email}` — 403 if not registered |
| POST | `/auth/verify-otp` | `{email, code}` → `{token, user}` |
| POST | `/auth/logout` | deletes the session row |
| GET | `/auth/me` | current user + family + role |
| PATCH | `/auth/profile` | `{display_name?, avatar_key?}` |
| GET | `/family` | family + member roster |
| POST | `/family/create` | `{name}` — caller becomes parent |
| POST | `/family/members/add` | `{email, display_name?, role?}` — parent only |
| POST | `/family/members/remove` | `{email}` — parent only |
| POST | `/family/leave` | blocked if you're the last parent |
| GET | `/tools` | registry with this user's access applied |
| PATCH | `/tools/:slug/access` | `{email, enabled}` — parent only |
| GET | `/progress/:slug` | `{state, updated_at}` |
| PUT | `/progress/:slug` | `{state}` — arbitrary JSON object |
| GET | `/math/settings` | your Fact Runner ranges; parents also get the roster |
| PUT | `/math/settings/:studentId` | `{settings}` — parent only, same family |
| POST | `/spanish/session` | starts a session; enforces the budget gates |
| POST | `/spanish/session/:id/turn` | one exchange → reply text + mp3 |
| POST | `/spanish/session/:id/end` | aggregates, summary, next lesson plan |
| GET | `/spanish/profile` | learner profile, streak, today's plan |
| PATCH | `/spanish/profile` | learner-owned preferences |
| GET | `/spanish/reports/:studentId` | parent only, same family |
| PATCH | `/spanish/settings/:studentId` | parent only, same family |
| POST | `/activity/beat` | `{tool}` — time-on-task heartbeat |
| GET | `/parents/overview` | parent only — every learner, every module |
| GET | `/parents/students/:id` | parent only, same family — the drill-down |

## Modules

Seeded in `tools`. The homepage renders whatever is in that table, so bringing a
module online is an `UPDATE`, not a frontend change.

| Slug | Status |
| --- | --- |
| `code-lab` | online — links to [Safe-Coding-Helper-for-Kids](https://darthkylej.github.io/Safe-Coding-Helper-for-Kids/) |
| `spelling-drill` | online — `games/spell-invaders.html` |
| `math-facts` | online — `games/fact-runner.html` |
| `essay-coach` | online — `essay-coach.html` |
| `spanish-tutor` | online — `spanish-coach.html` (after migration 003) |
| `flight-deck` | online — `flight-deck.html`, parents only (after migration 004) |
| `typing-trainer` | standby |

`tools.audience` is `all` or `parents`. `/tools` drops the parent-only rows for
anyone who isn't one, so the Flight Deck never appears on a learner's grid —
a module a kid can see but never open is just a locked door to rattle.

Modules open in the **same tab** as the bridge, and each one carries a
**← Bridge** button back. Nothing opens a new window.

### Flight Deck

The parent/teacher view. One card per learner showing time spent in each module
over today / 7 days / 30 days / all time, plus where they actually stand in each
one; click through for a 30-day chart, per-module detail, and recent visits.

Two rules keep it honest.

**Time is measured by heartbeat, and the server holds the clock.** Each module
posts to `/activity/beat` every 45 seconds while its tab is *visible*, and the
Worker credits the real elapsed gap since the last beat, capped at 75 seconds.
A gap longer than 150 seconds opens a new visit instead of extending the old
one, so a tab left open overnight doesn't read as an all-night study session.
Nothing has to remember to end a session — a closed lid just stops beating.

Consequences worth knowing:

- The number is a slight **undercount**, by up to one beat interval per visit.
  That is the right direction to be wrong in.
- It measures time *with the module in front of them*, not time signed in, and
  not time launched. A background tab counts for nothing.
- **Code Lab** lives on another site and can't beat, so the bridge posts one
  beat when it's launched. Its row shows visits, not minutes.
- Spanish Coach time is **not** the same as the audio minutes the cost gates
  meter — reading the recap is learning time and zero billable speech.

**Progress is read, never re-recorded.** Every module already keeps real state —
spelling scores, essay rows, Spanish sessions — so the dashboard summarises
those tables directly. There is no second copy of the truth to drift out of
step with the first, and no module had to be taught to report in.

`"Today"` means the family's today: the browser sends its IANA timezone and the
Worker buckets days in it. An unrecognised zone falls back to UTC.

Bringing a new module online puts it on this dashboard with no code change — its
time bar works immediately, and it simply carries no progress line until one is
written for it.

### Fact Runner

Arithmetic drill wrapped in a chase. A problem appears, the answer is typed and
submitted with Enter; correct answers bling green and move the runner a step
forward, wrong ones buzz red and cost a step. A missed problem is shown with its
answer and then **repeats until it is answered correctly**. The monster behind
advances continuously and accelerates with both elapsed time and score, so a run
always ends eventually — the score is how long you held it off.

Problem sets, all selectable independently. These are the defaults, and what
anyone with no ranges of their own gets:

| Set | Range |
| --- | --- |
| Multiplication | 1–12 × 1–12 — all 144 facts |
| Division | dividend ÷ 1–12, always exact, dividend ≤ 144 |
| Addition | 1–100 + 1–100 |
| Subtraction | 1–100 − 1–100, answers −99 to 99 |

#### Practice ranges

A parent opening Fact Runner gets a **crew panel** under the practice set: one
tab per learner (and one for themselves), and per operation a switch plus the
numbers it draws from. So one child can grind 1–8 × 1–8 while another does
2–9 + 2–9 and nothing else — the point being that a child drilling the facts
they already own is not practising.

| Operation | What a parent sets | Limits |
| --- | --- | --- |
| Multiplication | both factors' ranges | 0–100 |
| Division | divisor and answer ranges | divisor 1–100, answer 0–100 |
| Addition | both addends' ranges | 0–1000 |
| Subtraction | both numbers' ranges, and whether answers may go below zero | 0–1000 |

Division builds the problem from the answer (`dividend = answer × divisor`), so
it always divides evenly whatever the ranges are. Subtraction with negatives
switched off redraws for a non-negative pair, and if the ranges make that
unlikely — 1–5 minus 10–20 — it puts the larger number first rather than hand
over the thing the setting exists to prevent.

Ranges live in `math_fact_settings` (migration 006), one jsonb row per person,
written only by a parent and only for their own family. **The Worker owns the
limits**: everything is normalised on the way in and again on the way out, so a
stale row can't hand the game a range it cannot draw from.

The learner still chooses which of the operations left switched on they want to
drill today; an operation a parent switched off shows on their menu greyed out
and cannot be switched back on. That choice, along with best score, run count,
furthest distance and mute, stays in `tool_progress` under `math-facts` on the
generic `/progress/:slug` pair.

### Spanish Coach

Voice-first Spanish conversation. The child holds a button, speaks, and the coach
answers aloud — correcting the way a parent does, by **recasting** rather than
lecturing. Say *"Yo fue al parque"* and the coach replies *"Ah, **fuiste** al
parque. ¿Qué hiciste allí?"* — the correction is modelled, stressed in the audio,
highlighted on screen, and logged, without ever stopping the conversation.

**Architecture (Engine P — pipeline).** The browser captures speech and plays
audio back. Everything paid runs through the Worker: Claude drives the
conversation, the Worker records the pedagogy, and OpenAI synthesizes the reply.
No provider key ever reaches the browser, and the module speaks only to the
Worker — no new domains to whitelist.

**Listening works two ways:**

| Mode | When | Notes |
| --- | --- | --- |
| `record` | **Default**, every modern browser | `MediaRecorder` uploads to the Worker, which transcribes via OpenAI. ≈$0.006/min. Deterministic — it either captures bytes or it doesn't. |
| `websr` | Opt in with `?stt=browser` | Web Speech API. Free and instant, but Chrome/Edge/Safari only, and Chrome sends the audio to Google. |

Both hit the same `/turn` endpoint in one round trip — JSON carries a
browser-made transcript, raw audio gets transcribed server-side.

`record` is the default because the Web Speech API ends recognition by itself
after a brief silence, even with `continuous = true`. A child who holds the
button and pauses to think loses the whole turn, and the API reports no error
when it happens — it just returns nothing.

**A live level meter runs while the button is held** — a ring around the mic
and a bar beneath it. If a turn produces no words, the app distinguishes "I
didn't catch that" from "your microphone is silent" and says which. There is
also a **Test microphone** button on the home screen. A dead mic should never
again look like a coach that isn't listening.

Server-side transcription uses `whisper-1` deliberately: its per-segment
logprobs give a confidence score, so the coach still knows when a transcript is
unreliable and must not treat it as a learner error. That protection is worth
more than the ~$2/month a cheaper model would save.

**When a turn fails, the message carries a code**, because "the coach couldn't
hear you" was being shown for three unrelated causes and no tablet could tell
them apart:

| Code | Step | Means | Fix |
| --- | --- | --- | --- |
| `[fmt]` | Listening | The device recorded a container OpenAI won't decode | Read the container off the **Test microphone** line and add it to `spanishAudioExt` in `worker.js` |
| `[cfg]` | Listening | Bad or missing `OPENAI_API_KEY`, or a retired STT model | Check the secret and `SPANISH_STT_MODEL` |
| `[net]` | Listening | Transcription timed out or 5xx'd, twice | Upstream — retry the turn |
| `[brain]` | Answering | Transcription **succeeded**; the Claude call failed | The mic is fine — look at the turn's context size and the logged message |
| `[empty]` | Answering | Claude replied with no usable text | Usually a tool-schema drift; check the logged turn |

The first three mean the coach never heard the child. The last two mean it heard
them fine and fell over afterwards. Those used to be one word apart — "could not
hear that" versus "had trouble hearing that" — which made a failing tablet
impossible to place from the message alone.

The Worker logs the container, byte count, and upstream reply on the listening
failures, and the user, turn index, and transcript length on the answering ones,
so `wrangler tail` names the cause on the first failing turn.

**A session has no length.** No countdown, no target, no phases, no forced end,
no 409. It lasts exactly as long as the child wants to talk and they end it
themselves; the coach picks the conversation up where it left off next time,
which is what the lesson plan and callback hooks were always for.

This replaced two earlier designs in quick succession, and both failures are
worth keeping written down:

1. A **wall clock** counted down while a child stood there working out how to
   say something — punishing the exact moment the learning happens. Sessions
   expired with barely a word spoken in them.
2. A **speech clock** with a one-minute floor fixed the timing but broke the
   pedagogy: to reach the floor the coach asked for stories, reasons, and
   opinions from children who cannot yet build a sentence. A question a child
   cannot answer is not a stretch, it is a wall.

Nothing is timed now, and nothing is encouraged. The month cap and
`daily_session_cap` still bound the spend, checked before a session starts
rather than during one — which makes the month cap the real ceiling.

**Time spoken is still measured, just not enforced.** Every learner turn that
produced words banks its recording seconds in `input_audio_seconds`; holding the
button in silence banks nothing. That figure — not wall-clock duration — is what
the streak, the profile total, and the Flight Deck all report, so a session where
a child sat and listened for ten minutes never reads as ten minutes of Spanish
spoken.

**Level is one dial: the child's Spanish age.** Not their real age — a `1` speaks
Spanish the way a one-year-old does (a few isolated words, no sentences, answers
that may not match the question); a `3` like a three-year-old; a `6` manages full
sentences and reasons. The parent sets it in the Flight Deck.

The number drives both halves of the conversation, and the second half is the one
that matters:

| | What the coach does |
| --- | --- |
| **How it speaks** | Matched to the band — two-word phrases at 2, full sentences at 5, unsimplified Spanish at 9 |
| **What it expects back** | Explicitly capped. At 1, silence or an unrelated word *is* success and is accepted warmly |
| **What it asks** | Yes/no and point-at-it questions low down; opinions and disagreement only high up |

It is never spoken aloud — no mention of the level, the number, or the child's
age, and no comparisons.

**Growth is automatic; the parent's setting is a reset.** At the end of each
session the consolidation call reports `observed_spanish_age` — how old the child
*sounded*, judged only from what they actually produced. `spanishNextAge` decides
what that is worth: no movement at all on a session under four learner turns, and
at most ±0.15 either way, so a full year of growth takes about seven sessions and
one bad microphone cannot undo a month. Setting the dial by hand writes a new
baseline and the drift starts again from there, so a correction sticks. The
Flight Deck shows both: the number you set, and where it has drifted to.

**Memory.** After each session one Claude call writes the parent summary, the
child's summary, and **the next session's lesson plan** — callback hooks drawn
from what the child actually said, target words, and the scenario. That plan is
loaded at the next start, which is how the coach remembers the dog's name.
Skill estimates and review scheduling stay deterministic in SQL; the model
proposes, the database decides.

**Cost controls,** since audio is billed by the minute:

- Session creation is refused past `SPANISH_MONTHLY_AUDIO_MINUTES` (family-wide)
  or the learner's `daily_session_cap` — with a kind message, not an error.
- Sessions are no longer bounded by length, so the month cap is now the real
  ceiling rather than a backstop. Any still-`active` row is abandoned when the
  learner starts their next session.
- Every session accumulates audio seconds; the parent report shows month-to-date
  minutes and an estimated cost.

Nine tables (`spanish_profiles`, `_sessions`, `_turns`, `_interventions`,
`_skills`, `_vocabulary`, `_scenarios`, `_topics`, `_lesson_plans`) come from
`migrations/003_spanish_coach.sql`, which also seeds a 12-unit curriculum and
five role-play scenarios. `migrations/005_spanish_age.sql` adds the level dial.
`session_minutes` survives on the table but nothing reads it.

> **Before enabling this for the kids, complete `docs/VOICE_AUDITION.md`.** The
> coach's voice is the pronunciation curriculum — if it speaks Spanish with an
> American accent, it teaches an American accent. That check takes 20 minutes.
