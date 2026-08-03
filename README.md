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
| `index.html` | Whole frontend — access terminal + bridge homepage. No build step, no dependencies. |
| `worker.js` | API: auth, family/crew registry, module registry, per-tool saved state. |
| `wrangler.toml` | Worker config and the list of required secrets. |
| `schema.sql` | Postgres schema + seeded module registry. Idempotent. |

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
- `activity_log` — append-only event stream for a future parent dashboard

`tool_progress` and `activity_log` are scaffolding for the modules that come
next; nothing writes to `activity_log` yet.

## Setup

### 1. Database

Create a Neon project, then paste `schema.sql` into the Neon SQL Editor and run
it. Copy the **pooled** connection string.

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

## Modules

Seeded in `tools`. The homepage renders whatever is in that table, so bringing a
module online is an `UPDATE`, not a frontend change.

| Slug | Status |
| --- | --- |
| `code-lab` | online — links to [Safe-Coding-Helper-for-Kids](https://darthkylej.github.io/Safe-Coding-Helper-for-Kids/) |
| `spelling-drill` | standby |
| `spanish-tutor` | standby |
| `essay-coach` | standby |
| `typing-trainer` | standby |
