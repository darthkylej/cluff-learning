/* ============================================================
   Cluff Learning Systems API — Cloudflare Worker

   Routes:
     POST   /auth/send-otp
     POST   /auth/verify-otp
     POST   /auth/logout
     GET    /auth/me
     PATCH  /auth/profile

     GET    /family
     POST   /family/create
     POST   /family/members/add
     POST   /family/members/remove
     PATCH  /family/members/feedback-level
     POST   /family/leave

     GET    /tools
     PATCH  /tools/:slug/access

     GET    /progress/:slug
     PUT    /progress/:slug

     GET    /spelling/words
     POST   /spelling/words
     POST   /spelling/words/bulk
     PATCH  /spelling/words/:id
     DELETE /spelling/words/:id
     POST   /spelling/scores/bulk

     POST   /essays/assignments
     GET    /essays/assignments
     PATCH  /essays/assignments/:id
     DELETE /essays/assignments/:id
     GET    /essays/assignments/:id/essay
     PUT    /essays/assignments/:id/essay/draft
     POST   /essays/assignments/:id/essay/grade
     PUT    /essays/assignments/:id/essay/practice
     POST   /essays/assignments/:id/essay/coaching/check
     GET    /essays/assignments/:id/essay/:studentId/results

     POST   /spanish/session
     POST   /spanish/session/:id/turn
     POST   /spanish/session/:id/end
     GET    /spanish/profile
     PATCH  /spanish/profile
     GET    /spanish/reports/:studentId
     PATCH  /spanish/settings/:studentId

     POST   /activity/beat
     GET    /parents/overview
     GET    /parents/students/:id

   Registration is closed. An email can only request a login code
   if a users row already exists for it — created either by a
   parent via /family/members/add, or by listing the address in
   the BOOTSTRAP_EMAILS secret.
============================================================ */

const ALLOWED_ORIGINS = [
  'https://darthkylej.github.io',
  'http://localhost:8788',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

const OTP_TTL_MS      = 10 * 60 * 1000;        // 10 minutes
const OTP_MAX_ATTEMPTS = 5;
const SESSION_TTL_MS  = 30 * 24 * 60 * 60 * 1000; // 30 days

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allow  = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
  };
}

function json(request, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(request), 'Content-Type': 'application/json' },
  });
}
function err(request, msg, status = 400) { return json(request, { error: msg }, status); }

// ── Crypto helpers ─────────────────────────────────────────────
function randomCode() {
  // Uniform 6-digit code from a CSPRNG (rejection-sampled).
  const buf = new Uint32Array(1);
  let n;
  do { crypto.getRandomValues(buf); n = buf[0]; } while (n >= 4294000000);
  return String(100000 + (n % 900000));
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64url(bytes) {
  const bin = typeof bytes === 'string' ? bytes : String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(str) {
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
}

async function signJwt(payload, secret) {
  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = b64url(JSON.stringify(payload));
  const signing = `${header}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signing));
  return `${signing}.${b64url(sig)}`;
}

async function verifyJwt(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    if (!header || !body || !sig) return null;
    const signing = `${header}.${body}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(b64urlDecode(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(signing));
    if (!valid) return null;
    return JSON.parse(b64urlDecode(body));
  } catch { return null; }
}

// ── Database (Neon HTTP endpoint) ──────────────────────────────
async function query(env, sql, params = []) {
  const connStr = env.DATABASE_URL;
  let host;
  try { host = new URL(connStr).host; } catch { throw new Error('Invalid DATABASE_URL'); }
  if (!host) throw new Error('Invalid DATABASE_URL');

  const res = await fetch(`https://${host}/sql`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Neon-Connection-String': connStr,
      'Neon-Pool-Opt-In': 'true',
    },
    body: JSON.stringify({ query: sql, params }),
  });
  if (!res.ok) throw new Error(`DB ${res.status}: ${await res.text()}`);
  return res.json();
}

// ── Session / membership helpers ───────────────────────────────
async function getSession(request, env) {
  const auth  = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  const payload = await verifyJwt(token, env.JWT_SECRET);
  if (!payload?.session_id) return null;
  const r = await query(env,
    `SELECT s.id AS session_id, u.id AS user_id, u.email, u.display_name, u.avatar_key, u.is_admin, u.feedback_level
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.id = $1 AND s.expires_at > NOW()`,
    [payload.session_id]);
  return r.rows?.[0] || null;
}

async function getMembership(env, userId) {
  const r = await query(env,
    `SELECT f.id, f.name, fm.role
       FROM families f
       JOIN family_members fm ON fm.family_id = f.id
      WHERE fm.user_id = $1
      LIMIT 1`,
    [userId]);
  return r.rows?.[0] || null;
}

function bootstrapEmails(env) {
  return (env.BOOTSTRAP_EMAILS || '')
    .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
}

// Wraps a handler that needs an authenticated user.
async function withUser(request, env, fn) {
  const session = await getSession(request, env);
  if (!session) return err(request, 'Unauthorized', 401);
  return fn(session);
}

// ── Email ──────────────────────────────────────────────────────
async function sendOtpEmail(env, email, code) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.RESEND_FROM,
      to: email,
      subject: 'Your Cluff Learning Systems access code',
      html: `<div style="font-family:system-ui,sans-serif;max-width:440px;margin:40px auto;background:#0a1020;border:1px solid #1e3a5f;border-radius:10px;padding:32px;color:#dbe7f5">
        <div style="font-size:.7rem;letter-spacing:.28em;text-transform:uppercase;color:#4fd1e0">Cluff Learning Systems</div>
        <h2 style="color:#eaf3ff;margin:.4em 0 1em;font-weight:600">Access code</h2>
        <div style="font-size:2.4rem;font-weight:700;letter-spacing:.28em;color:#4fd1e0;margin:20px 0">${code}</div>
        <p style="color:#8aa4c2;font-size:.85rem;margin:0">Expires in 10 minutes. If you didn't request this, you can ignore it.</p>
      </div>`,
    }),
  });
  if (!res.ok) {
    const t = await res.text();
    let message = t;
    try { message = JSON.parse(t).message || t; } catch {}
    if (res.status === 403 && message.includes('testing emails')) {
      throw new Error('Resend is still in test mode. Verify a sending domain and set RESEND_FROM to an address on it.');
    }
    throw new Error(`Email error: ${message}`);
  }
}

// ── Auth handlers ──────────────────────────────────────────────
async function handleSendOtp(request, env) {
  const { email: raw } = await request.json();
  const email = String(raw || '').trim().toLowerCase();
  if (!email.includes('@')) return err(request, 'Please enter a valid email address.');

  // Closed registration: the address must already be known.
  const known = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
  if (!known.rows?.length) {
    if (!bootstrapEmails(env).includes(email)) {
      return err(request, 'That address is not registered. Ask a parent to add you to the family first.', 403);
    }
    await query(env, `INSERT INTO users (email, is_admin) VALUES ($1, true) ON CONFLICT (email) DO NOTHING`, [email]);
  }

  const code = randomCode();
  await query(env, `DELETE FROM otp_codes WHERE email = $1 OR expires_at < NOW()`, [email]);
  await query(env,
    `INSERT INTO otp_codes (email, code_hash, expires_at) VALUES ($1, $2, $3)`,
    [email, await sha256Hex(code), new Date(Date.now() + OTP_TTL_MS).toISOString()]);

  try {
    await sendOtpEmail(env, email, code);
  } catch (e) {
    await query(env, `DELETE FROM otp_codes WHERE email = $1`, [email]);
    throw e;
  }
  return json(request, { ok: true });
}

async function handleVerifyOtp(request, env) {
  const body  = await request.json();
  const email = String(body.email || '').trim().toLowerCase();
  const code  = String(body.code || '').trim();
  if (!email || !code) return err(request, 'Email and code are required.');

  const r = await query(env,
    `SELECT id, code_hash, attempts FROM otp_codes
      WHERE email = $1 AND expires_at > NOW()
      ORDER BY created_at DESC LIMIT 1`,
    [email]);
  const row = r.rows?.[0];
  if (!row) return err(request, 'That code has expired. Request a new one.', 401);

  if (row.attempts >= OTP_MAX_ATTEMPTS) {
    await query(env, `DELETE FROM otp_codes WHERE email = $1`, [email]);
    return err(request, 'Too many attempts. Request a new code.', 429);
  }

  if (row.code_hash !== await sha256Hex(code)) {
    await query(env, `UPDATE otp_codes SET attempts = attempts + 1 WHERE id = $1`, [row.id]);
    return err(request, 'That code is not correct.', 401);
  }

  await query(env, `DELETE FROM otp_codes WHERE email = $1`, [email]);

  const ur = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
  if (!ur.rows?.length) return err(request, 'That address is not registered.', 403);
  const userId = ur.rows[0].id;

  await query(env, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, [userId]);
  const sr = await query(env,
    `INSERT INTO sessions (user_id, user_agent, expires_at) VALUES ($1, $2, $3) RETURNING id`,
    [userId, (request.headers.get('User-Agent') || '').slice(0, 300),
     new Date(Date.now() + SESSION_TTL_MS).toISOString()]);

  const token = await signJwt({ session_id: sr.rows[0].id }, env.JWT_SECRET);
  return json(request, { token, user: await mePayload(env, userId) });
}

async function handleLogout(request, env) {
  const auth  = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  const payload = token ? await verifyJwt(token, env.JWT_SECRET) : null;
  if (payload?.session_id) {
    await query(env, `DELETE FROM sessions WHERE id = $1`, [payload.session_id]);
  }
  return json(request, { ok: true });
}

async function mePayload(env, userId) {
  const r = await query(env,
    `SELECT id, email, display_name, avatar_key, is_admin, feedback_level FROM users WHERE id = $1`, [userId]);
  const user = r.rows[0];
  const family = await getMembership(env, userId);
  return {
    id: user.id,
    email: user.email,
    display_name: user.display_name,
    avatar_key: user.avatar_key,
    is_admin: user.is_admin,
    feedback_level: user.feedback_level,
    role: family?.role || null,
    family: family ? { id: family.id, name: family.name } : null,
  };
}

async function handleMe(request, env) {
  return withUser(request, env, async (session) => {
    await query(env, `UPDATE sessions SET last_seen_at = NOW() WHERE id = $1`, [session.session_id]);
    return json(request, { user: await mePayload(env, session.user_id) });
  });
}

async function handleUpdateProfile(request, env) {
  return withUser(request, env, async (session) => {
    const body = await request.json();
    const sets = []; const vals = []; let i = 1;

    if (body.display_name !== undefined) {
      const name = String(body.display_name).trim().slice(0, 60);
      if (!name) return err(request, 'Display name cannot be empty.');
      sets.push(`display_name = $${i++}`); vals.push(name);
    }
    if (body.avatar_key !== undefined) {
      sets.push(`avatar_key = $${i++}`); vals.push(String(body.avatar_key).slice(0, 24));
    }
    if (!sets.length) return json(request, { user: await mePayload(env, session.user_id) });

    vals.push(session.user_id);
    await query(env, `UPDATE users SET ${sets.join(', ')} WHERE id = $${i}`, vals);
    return json(request, { user: await mePayload(env, session.user_id) });
  });
}

// ── Family handlers ────────────────────────────────────────────
async function handleGetFamily(request, env) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    if (!family) return json(request, { family: null });
    const members = await query(env,
      `SELECT u.id, u.email, u.display_name, u.avatar_key, u.feedback_level, fm.role, fm.added_at, u.last_login_at
         FROM family_members fm
         JOIN users u ON u.id = fm.user_id
        WHERE fm.family_id = $1
        ORDER BY fm.role, fm.added_at`,
      [family.id]);
    return json(request, { family: { ...family, members: members.rows || [] } });
  });
}

async function handleCreateFamily(request, env) {
  return withUser(request, env, async (session) => {
    if (await getMembership(env, session.user_id)) {
      return err(request, 'You already belong to a family.');
    }
    const { name } = await request.json();
    const trimmed = String(name || '').trim().slice(0, 80);
    if (!trimmed) return err(request, 'A family name is required.');

    const fr = await query(env,
      `INSERT INTO families (name, created_by) VALUES ($1, $2) RETURNING id`,
      [trimmed, session.user_id]);
    const familyId = fr.rows[0].id;
    await query(env,
      `INSERT INTO family_members (family_id, user_id, role, added_by) VALUES ($1, $2, 'parent', $2)`,
      [familyId, session.user_id]);

    return json(request, { family: { id: familyId, name: trimmed, role: 'parent' } }, 201);
  });
}

async function handleAddMember(request, env) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    if (!family) return err(request, 'You are not in a family yet.');
    if (family.role !== 'parent') return err(request, 'Only a parent can add members.', 403);

    const body  = await request.json();
    const email = String(body.email || '').trim().toLowerCase();
    const role  = body.role === 'parent' ? 'parent' : 'learner';
    const name  = String(body.display_name || '').trim().slice(0, 60) || null;
    if (!email.includes('@')) return err(request, 'Please enter a valid email address.');

    const existing = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
    if (existing.rows?.length) {
      const theirFamily = await getMembership(env, existing.rows[0].id);
      if (theirFamily) {
        return err(request, theirFamily.id === family.id
          ? 'They are already in your family.'
          : `${email} already belongs to another family.`);
      }
    }

    await query(env,
      `INSERT INTO users (email, display_name) VALUES ($1, $2)
       ON CONFLICT (email) DO UPDATE SET display_name = COALESCE(users.display_name, EXCLUDED.display_name)`,
      [email, name]);
    const ur = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
    await query(env,
      `INSERT INTO family_members (family_id, user_id, role, added_by) VALUES ($1, $2, $3, $4)
       ON CONFLICT DO NOTHING`,
      [family.id, ur.rows[0].id, role, session.user_id]);

    return json(request, { ok: true }, 201);
  });
}

async function handleRemoveMember(request, env) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    if (!family) return err(request, 'You are not in a family yet.');
    if (family.role !== 'parent') return err(request, 'Only a parent can remove members.', 403);

    const { email } = await request.json();
    const target = await query(env, `SELECT id FROM users WHERE email = $1`,
      [String(email || '').trim().toLowerCase()]);
    if (!target.rows?.length) return err(request, 'No such member.', 404);
    if (target.rows[0].id === session.user_id) {
      return err(request, 'Use "leave family" to remove yourself.');
    }
    await query(env, `DELETE FROM family_members WHERE family_id = $1 AND user_id = $2`,
      [family.id, target.rows[0].id]);
    return json(request, { ok: true });
  });
}

// A parent sets the starting reading level for a family member's
// feedback. Presentation only — grading is unaffected.
async function handleSetFeedbackLevel(request, env) {
  const session = await getSession(request, env);
  if (!session) return err(request, 'Unauthorized', 401);
  const family = await getMembership(env, session.user_id);
  if (!family) return err(request, 'You are not in a family yet.');
  if (family.role !== 'parent') return err(request, 'Only a parent can change reading level.', 403);

  const { user_id, feedback_level } = await request.json();
  if (!FEEDBACK_BAND_ORDER.includes(feedback_level)) return err(request, 'Unknown reading level.');

  const target = await query(env,
    `SELECT 1 FROM family_members WHERE family_id = $1 AND user_id = $2`, [family.id, user_id]);
  if (!target.rows?.length) return err(request, 'That person is not in your family.', 404);

  await query(env, `UPDATE users SET feedback_level = $1 WHERE id = $2`, [feedback_level, user_id]);
  return json(request, { ok: true });
}

async function handleLeaveFamily(request, env) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    if (!family) return err(request, 'You are not in a family yet.');
    if (family.role === 'parent') {
      const parents = await query(env,
        `SELECT COUNT(*)::int AS n FROM family_members WHERE family_id = $1 AND role = 'parent'`,
        [family.id]);
      if ((parents.rows?.[0]?.n || 0) <= 1) {
        return err(request, 'You are the only parent. Add another parent before leaving.');
      }
    }
    await query(env, `DELETE FROM family_members WHERE family_id = $1 AND user_id = $2`,
      [family.id, session.user_id]);
    return json(request, { ok: true });
  });
}

// ── Tool handlers ──────────────────────────────────────────────
async function handleListTools(request, env) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    const isParent = family?.role === 'parent';
    // `audience` is read through to_jsonb rather than as a plain
    // column so this keeps working if the Worker is deployed before
    // migration 004 runs — a missing column reads as NULL, and NULL
    // means "everyone", which is what every older row is.
    const r = await query(env,
      `SELECT t.slug, t.name, t.tagline, t.description, t.glyph, t.accent, t.status, t.url,
              COALESCE(to_jsonb(t) ->> 'audience', 'all') AS audience,
              COALESCE(ta.enabled, true) AS enabled
         FROM tools t
         LEFT JOIN tool_access ta ON ta.tool_slug = t.slug AND ta.user_id = $1
        ORDER BY t.sort_order, t.name`,
      [session.user_id]);
    const tools = (r.rows || []).filter(t => t.audience !== 'parents' || isParent);
    return json(request, { tools });
  });
}

async function handleSetToolAccess(request, env, slug) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    if (family?.role !== 'parent') return err(request, 'Only a parent can change tool access.', 403);

    const { email, enabled } = await request.json();
    const target = await query(env, `SELECT id FROM users WHERE email = $1`,
      [String(email || '').trim().toLowerCase()]);
    if (!target.rows?.length) return err(request, 'No such member.', 404);

    const sameFamily = await getMembership(env, target.rows[0].id);
    if (sameFamily?.id !== family.id) return err(request, 'That person is not in your family.', 403);

    await query(env,
      `INSERT INTO tool_access (user_id, tool_slug, enabled, updated_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, tool_slug) DO UPDATE
         SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
      [target.rows[0].id, slug, enabled !== false, session.user_id]);
    return json(request, { ok: true });
  });
}

// ── Progress handlers (scaffolding for the modules to come) ────
async function handleGetProgress(request, env, slug) {
  return withUser(request, env, async (session) => {
    const r = await query(env,
      `SELECT state, updated_at FROM tool_progress WHERE user_id = $1 AND tool_slug = $2`,
      [session.user_id, slug]);
    return json(request, { state: r.rows?.[0]?.state || {}, updated_at: r.rows?.[0]?.updated_at || null });
  });
}

async function handlePutProgress(request, env, slug) {
  return withUser(request, env, async (session) => {
    const { state } = await request.json();
    if (state === null || typeof state !== 'object' || Array.isArray(state)) {
      return err(request, 'state must be a JSON object.');
    }
    await query(env,
      `INSERT INTO tool_progress (user_id, tool_slug, state) VALUES ($1, $2, $3::jsonb)
       ON CONFLICT (user_id, tool_slug) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()`,
      [session.user_id, slug, JSON.stringify(state)]);
    return json(request, { ok: true });
  });
}

// ── Spelling (Spell Invaders) handlers ──────────────────────────
// The word bank is shared platform-wide; only an admin may edit it.
// Mastery scores are per-player against that shared bank.
async function requireAdminSession(request, env) {
  const session = await getSession(request, env);
  if (!session) return { error: err(request, 'Unauthorized', 401) };
  if (!session.is_admin) return { error: err(request, 'Admins only.', 403) };
  return { session };
}

async function handleGetSpellingWords(request, env) {
  return withUser(request, env, async (session) => {
    const r = await query(env,
      `SELECT w.id, w.word, w.sentence, COALESCE(s.score, 0) AS score
         FROM spelling_words w
         LEFT JOIN spelling_word_scores s ON s.word_id = w.id AND s.user_id = $1
        ORDER BY w.word`,
      [session.user_id]);
    return json(request, { words: r.rows || [] });
  });
}

async function handleAddSpellingWord(request, env) {
  const gate = await requireAdminSession(request, env);
  if (gate.error) return gate.error;
  const body = await request.json();
  const word = String(body.word || '').trim().slice(0, 80);
  const sentence = String(body.sentence || '').trim().slice(0, 300);
  if (!word) return err(request, 'A word is required.');
  const r = await query(env,
    `INSERT INTO spelling_words (word, sentence, created_by) VALUES ($1, $2, $3)
     ON CONFLICT (word) DO UPDATE SET sentence = EXCLUDED.sentence
     RETURNING id, word, sentence`,
    [word, sentence, gate.session.user_id]);
  return json(request, { word: r.rows[0] }, 201);
}

async function handleBulkAddSpellingWords(request, env) {
  const gate = await requireAdminSession(request, env);
  if (gate.error) return gate.error;
  const { rows } = await request.json();
  if (!Array.isArray(rows) || !rows.length) return err(request, 'rows must be a non-empty array.');

  const clean = []; const seen = new Set();
  for (const r of rows) {
    const word = String(r?.word || '').trim().slice(0, 80);
    if (!word || seen.has(word.toLowerCase())) continue;
    seen.add(word.toLowerCase());
    clean.push({ word, sentence: String(r?.sentence || '').trim().slice(0, 300) });
  }
  if (!clean.length) return err(request, 'No valid words found.');

  const params = [gate.session.user_id];
  const rowsSql = []; let p = 2;
  for (const c of clean) {
    rowsSql.push(`($${p++}, $${p++}, $1)`);
    params.push(c.word, c.sentence);
  }
  const r = await query(env,
    `INSERT INTO spelling_words (word, sentence, created_by)
     VALUES ${rowsSql.join(',')}
     ON CONFLICT (word) DO UPDATE SET sentence = EXCLUDED.sentence
     RETURNING id, word, sentence`,
    params);
  return json(request, { words: r.rows || [], count: r.rows?.length || 0 }, 201);
}

async function handleUpdateSpellingWord(request, env, id) {
  const gate = await requireAdminSession(request, env);
  if (gate.error) return gate.error;
  const body = await request.json();
  const sets = []; const vals = []; let i = 1;
  if (body.word !== undefined) {
    const word = String(body.word).trim().slice(0, 80);
    if (!word) return err(request, 'Word cannot be empty.');
    sets.push(`word = $${i++}`); vals.push(word);
  }
  if (body.sentence !== undefined) {
    sets.push(`sentence = $${i++}`); vals.push(String(body.sentence).trim().slice(0, 300));
  }
  if (!sets.length) return err(request, 'Nothing to update.');
  vals.push(id);
  const r = await query(env,
    `UPDATE spelling_words SET ${sets.join(', ')} WHERE id = $${i} RETURNING id, word, sentence`,
    vals);
  if (!r.rows?.length) return err(request, 'Word not found.', 404);
  return json(request, { word: r.rows[0] });
}

async function handleDeleteSpellingWord(request, env, id) {
  const gate = await requireAdminSession(request, env);
  if (gate.error) return gate.error;
  await query(env, `DELETE FROM spelling_words WHERE id = $1`, [id]);
  return json(request, { ok: true });
}

async function handleBulkScores(request, env) {
  return withUser(request, env, async (session) => {
    const { deltas } = await request.json();
    if (!Array.isArray(deltas) || !deltas.length) return json(request, { ok: true });

    const byWord = new Map();
    for (const d of deltas) {
      const wordId = String(d?.word_id || '');
      const delta = Math.trunc(Number(d?.delta) || 0);
      if (!wordId || !delta) continue;
      byWord.set(wordId, (byWord.get(wordId) || 0) + delta);
    }
    if (!byWord.size) return json(request, { ok: true });

    const params = [session.user_id];
    const rowsSql = []; let p = 2;
    for (const [wordId, delta] of byWord) {
      rowsSql.push(`($1, $${p++}, $${p++})`);
      params.push(wordId, Math.max(-10, Math.min(10, delta)));
    }
    await query(env,
      `INSERT INTO spelling_word_scores (user_id, word_id, score)
       VALUES ${rowsSql.join(',')}
       ON CONFLICT (user_id, word_id) DO UPDATE SET
         score = GREATEST(-10, LEAST(10, spelling_word_scores.score + EXCLUDED.score)),
         updated_at = NOW()`,
      params);
    return json(request, { ok: true });
  });
}

// ── Essay Coach ──────────────────────────────────────────────────
// Assignments are family-scoped (a parent writes a prompt for their
// own kids), unlike the platform-wide spelling word bank.
const CLAUDE_MODEL = 'claude-sonnet-5';

const ESSAY_RUBRIC = {
  mechanics:    { max: 20, label: 'Mechanics (spelling, grammar, punctuation)' },
  word_choice:  { max: 15, label: 'Word choice & voice' },
  organization: { max: 15, label: 'Organization & flow' },
  argument:     { max: 25, label: 'Argument quality (logic, evidence, avoiding fallacies)' },
  persuasion:   { max: 15, label: 'Persuasiveness & rhetorical craft' },
  polish:       { max: 10, label: 'Holistic college-readiness & polish' },
};
const ISSUE_TIERS = ['mechanics', 'clarity', 'organization', 'argument', 'rhetoric'];

// Reading level for student-facing prose. Presentation only — never
// affects grading. Ordered easiest → hardest; the ratchet below only
// ever moves a student up.
const FEEDBACK_BANDS = {
  early_elementary: {
    label: 'a reader in early elementary school (roughly ages 6-8)',
    guidance: 'Use short sentences and everyday words. Do not use grammar terminology at all — say "these two sentences got squished together" instead of "comma splice". Be warm and very encouraging. Explain what to do, not just what went wrong.',
  },
  upper_elementary: {
    label: 'a reader in upper elementary school (roughly ages 9-11)',
    guidance: 'Use plain, direct language. You may name a grammar term but always explain it in the same breath — "this is a run-on sentence, which means two whole sentences joined without a break". Encouraging but straightforward.',
  },
  middle_school: {
    label: 'a middle school reader (roughly ages 12-14)',
    guidance: 'Use normal conversational language. Name grammar and rhetoric terms and give a short plain-English gloss the first time each appears. Treat the student as capable of handling direct criticism.',
  },
  high_school: {
    label: 'a high school reader',
    guidance: 'Write as you would to a capable high school student. Use standard composition vocabulary (thesis, evidence, transition, tone) without glossing it. Gloss only genuinely specialized terms like specific logical fallacies.',
  },
  college: {
    label: 'a college-level reader',
    guidance: 'Write as you would to a first-year college student in office hours. Use precise compositional and rhetorical vocabulary directly, without simplification.',
  },
};
const FEEDBACK_BAND_ORDER = ['early_elementary', 'upper_elementary', 'middle_school', 'high_school', 'college'];
// Average real score required to move up out of band i.
const BAND_PROMOTE_AT = [55, 65, 75, 85];

function feedbackBand(level) {
  return FEEDBACK_BANDS[level] || FEEDBACK_BANDS.upper_elementary;
}

// Monotonic: only ever promotes, and only on a sustained average rather
// than one lucky essay. `recentScores` is newest-first, current included.
function maybePromoteFeedbackLevel(current, recentScores) {
  const i = FEEDBACK_BAND_ORDER.indexOf(current);
  if (i < 0 || i >= FEEDBACK_BAND_ORDER.length - 1) return current;
  const window = (recentScores || []).slice(0, 3);
  if (window.length < 3) return current;
  const avg = window.reduce((a, b) => a + b, 0) / window.length;
  return avg >= BAND_PROMOTE_AT[i] ? FEEDBACK_BAND_ORDER[i + 1] : current;
}

function clampInt(v, lo, hi) {
  const n = Math.round(Number(v) || 0);
  return Math.max(lo, Math.min(hi, n));
}

// `model`, `maxTokens` and `cacheSystem` are optional; omitting them
// preserves the original behaviour used by Essay Coach.
async function callClaude(env, { system, content, tool, model, maxTokens, cacheSystem }) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: model || CLAUDE_MODEL,
      max_tokens: maxTokens || 8000,
      system: cacheSystem
        ? [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }]
        : system,
      messages: [{ role: 'user', content }],
      tools: [tool],
      tool_choice: { type: 'tool', name: tool.name },
    }),
  });
  if (!res.ok) throw new Error(`Claude API ${res.status}: ${(await res.text()).slice(0, 400)}`);
  const data = await res.json();
  const block = (data.content || []).find(c => c.type === 'tool_use' && c.name === tool.name);
  if (!block) throw new Error('Claude did not return the expected result.');
  return block.input;
}

const GRADE_TOOL = {
  name: 'submit_essay_grade',
  description: 'Submit the complete grading result for a student essay.',
  input_schema: {
    type: 'object',
    required: ['sentences', 'rubric', 'strengths', 'overall_feedback', 'issues_catalog'],
    properties: {
      sentences: {
        type: 'array',
        description: 'The essay split into sentences, original order, covering the ENTIRE text with nothing omitted, reworded, or summarized.',
        items: {
          type: 'object',
          required: ['text', 'issues'],
          properties: {
            text: { type: 'string' },
            issues: {
              type: 'array',
              items: {
                type: 'object',
                required: ['type', 'severity', 'note'],
                properties: {
                  type:       { type: 'string', description: 'short slug, e.g. subject_verb_agreement, comma_splice, weak_word_choice' },
                  severity:   { type: 'string', enum: ['minor', 'moderate', 'major'] },
                  note:       { type: 'string' },
                  suggestion: { type: 'string' },
                },
              },
            },
          },
        },
      },
      rubric: {
        type: 'object',
        required: Object.keys(ESSAY_RUBRIC),
        properties: Object.fromEntries(Object.entries(ESSAY_RUBRIC).map(([k, v]) => [k, {
          type: 'object',
          required: ['score', 'notes'],
          properties: {
            score: { type: 'integer', minimum: 0, maximum: v.max },
            notes: { type: 'string' },
          },
        }])),
      },
      strengths:         { type: 'array', items: { type: 'string' }, description: '2-4 specific, genuine things this essay does well.' },
      overall_feedback:  { type: 'string', description: 'A few paragraphs on flow, organization, voice, consistency, persuasiveness, and any logical fallacies.' },
      length_assessment: { type: 'string', description: 'One sentence on whether the length was reasonable for making the point — not a word-count judgment.' },
      issues_catalog: {
        type: 'array',
        description: 'Every distinct issue found anywhere in the essay, deduplicated by type.',
        items: {
          type: 'object',
          required: ['issue_type', 'tier', 'severity', 'description'],
          properties: {
            issue_type:  { type: 'string' },
            tier:        { type: 'string', enum: ISSUE_TIERS },
            severity:    { type: 'string', enum: ['minor', 'moderate', 'major'] },
            description: { type: 'string' },
            quote:       { type: 'string' },
          },
        },
      },
    },
  },
};

const COACHING_CHECK_TOOL = {
  name: 'submit_fix_verdict',
  description: 'Judge whether the student made a genuine, reasonable effort to fix the described issue.',
  input_schema: {
    type: 'object',
    required: ['verdict', 'note'],
    properties: {
      verdict: { type: 'string', enum: ['resolved', 'partial', 'not_addressed'] },
      note:    { type: 'string', description: 'One or two sentences, encouraging but honest, addressed directly to the student.' },
    },
  },
};

function buildGradingSystemPrompt(assignment, issueHistory, feedbackLevel) {
  const band = feedbackBand(feedbackLevel);
  const rubricLines = Object.entries(ESSAY_RUBRIC).map(([, v]) => `- ${v.label}: ${v.max} points`).join('\n');
  const historyLines = (issueHistory || []).length
    ? issueHistory.map(h => `- ${h.issue_type} (${h.tier}): flagged in ${h.times_flagged} previous essay(s), recurred ${h.times_recurred_after_flagged} time(s) after being told about it`).join('\n')
    : '(no prior essays on record for this student)';

  return `You are a rigorous, fair college writing instructor grading a first-year college-level essay. Grade honestly and consistently — do not adjust the rubric for the student's age or grade level; grade the writing itself as if it were submitted to a college composition course.

RUBRIC (100 points total, score each category independently):
${rubricLines}

A 100 means: no spelling or grammar errors, a clear and persuasive message with strong support, eloquent word choice suited to the topic without being pretentious, and writing that would score well in a first-year college writing class.

Do not grade on raw length. The length guidance below is a soft target — judge whether the essay makes its point clearly without belaboring it and without skimping. Reward rich, specific writing: concrete examples, apt literary devices, references, facts, and rhetorical technique used well. Penalize padding, vagueness, and unsupported claims.

ASSIGNMENT PROMPT:
"""
${assignment.prompt}
"""
Length guidance given to the student: ${assignment.length_guidance || '(none specified)'}

THIS STUDENT'S RECURRING ISSUE HISTORY (from past essays):
${historyLines}
If an issue below recurs from this history, say so plainly in your feedback and treat it as more serious than a first-time slip — the student has already been told.

FEEDBACK VOICE:
Write every piece of prose the student will read — sentence notes and suggestions, rubric notes, strengths, overall feedback, and the descriptions in issues_catalog — for ${band.label}. ${band.guidance}

This governs only HOW you word things. It must NOT change what you look for or how you score:
- Score against the fixed college rubric above regardless of this setting. A 74 means the same thing at every level.
- Still find and report every real issue. If a 9-year-old commits a logical fallacy, still flag it — just describe it as "your reason doesn't quite prove your point" rather than naming it a non sequitur.
- The issue_type slug stays a stable, consistent identifier (e.g. comma_splice, unsupported_claim) no matter what reading level the description is written for. Never simplify or rename the slug itself.

Segment the essay into sentences covering the ENTIRE text with nothing omitted or reworded, and call the submit_essay_grade tool with your complete result. Be specific in every note — cite the actual words, not just the category.`;
}

function buildCoachingCheckPrompt(issue, feedbackLevel) {
  const band = feedbackBand(feedbackLevel);
  return `You are coaching a student revising their own essay. Here is one specific issue that was flagged:

Type: ${issue.issue_type}
Original problem: ${issue.description}
${issue.quote ? `Original text: "${issue.quote}"` : ''}

Below is the student's CURRENT full essay text after revision. Judge whether this specific issue has been genuinely, reasonably addressed.
- "resolved": clearly fixed.
- "partial": a real, good-faith attempt that improves things, even if not perfect.
- "not_addressed": the issue is still there, or the student didn't seriously try.
Be encouraging but honest — don't rubber-stamp a fix that isn't there, but don't demand perfection either.

Write your note for ${band.label}. ${band.guidance} This affects only your wording, not how strictly you judge whether the issue was actually fixed. Call submit_fix_verdict with your result.`;
}

function selectTopIssues(catalog, history) {
  const historyByType = new Map((history || []).map(h => [h.issue_type, h]));
  const tierRank = t => { const i = ISSUE_TIERS.indexOf(t); return i >= 0 ? i : 0; };
  const scored = (catalog || []).map(issue => {
    const type = String(issue.issue_type || '').trim();
    const h = historyByType.get(type);
    const recurrence = h ? h.times_recurred_after_flagged : 0;
    // Issues the student has been told about repeatedly jump the queue,
    // regardless of tier — everything else follows foundational-first order.
    const priority = recurrence >= 2 ? -100 : tierRank(issue.tier);
    return { issue, type, priority, recurrence };
  }).sort((a, b) => a.priority - b.priority || b.recurrence - a.recurrence);

  const picked = []; const seen = new Set();
  for (const s of scored) {
    if (!s.type || seen.has(s.type)) continue;
    seen.add(s.type);
    picked.push(s.issue);
    if (picked.length >= 5) break;
  }
  return picked;
}

function computeAdaptiveScore(scoreTotal, priorScores, persistentOffender) {
  let adaptive;
  if (!priorScores.length) {
    // First essay ever: compress upward so a rough first attempt still
    // feels encouraging, while leaving clear room to grow.
    adaptive = 55 + scoreTotal * 0.45;
  } else {
    const baseline = priorScores.reduce((a, b) => a + b, 0) / priorScores.length;
    const delta = scoreTotal - baseline;
    // Reward improvement generously; soften but don't erase a decline.
    adaptive = 78 + delta * (delta >= 0 ? 2.2 : 1.3);
  }
  if (persistentOffender) adaptive -= 9; // told repeatedly, still unresolved
  return clampInt(adaptive, 35, 100);
}

function stripScoresForLearner(feedback) {
  const copy = JSON.parse(JSON.stringify(feedback || {}));
  if (copy.rubric) {
    for (const k of Object.keys(copy.rubric)) {
      if (copy.rubric[k] && typeof copy.rubric[k] === 'object') delete copy.rubric[k].score;
    }
  }
  return copy;
}

async function requireParentSession(request, env) {
  const session = await getSession(request, env);
  if (!session) return { error: err(request, 'Unauthorized', 401) };
  const family = await getMembership(env, session.user_id);
  if (!family) return { error: err(request, 'You are not in a family yet.') };
  if (family.role !== 'parent') return { error: err(request, 'Only a parent can do this.', 403) };
  return { session, family };
}

async function getOrCreateEssay(env, assignmentId, userId) {
  const existing = await query(env, `SELECT * FROM essays WHERE assignment_id = $1 AND user_id = $2`, [assignmentId, userId]);
  if (existing.rows?.length) return existing.rows[0];
  const created = await query(env,
    `INSERT INTO essays (assignment_id, user_id) VALUES ($1, $2)
     ON CONFLICT (assignment_id, user_id) DO NOTHING RETURNING *`,
    [assignmentId, userId]);
  if (created.rows?.length) return created.rows[0];
  const retry = await query(env, `SELECT * FROM essays WHERE assignment_id = $1 AND user_id = $2`, [assignmentId, userId]);
  return retry.rows[0];
}

async function handleCreateAssignment(request, env) {
  const gate = await requireParentSession(request, env);
  if (gate.error) return gate.error;
  const body = await request.json();
  const title = String(body.title || '').trim().slice(0, 120);
  const prompt = String(body.prompt || '').trim();
  const lengthGuidance = String(body.length_guidance || '').trim().slice(0, 300);
  const studentIds = Array.isArray(body.student_ids) ? body.student_ids.filter(Boolean) : [];
  if (!title || !prompt) return err(request, 'Title and prompt are required.');
  if (!studentIds.length) return err(request, 'Pick at least one student.');

  const members = await query(env,
    `SELECT user_id FROM family_members WHERE family_id = $1 AND user_id = ANY($2::uuid[])`,
    [gate.family.id, studentIds]);
  const validIds = new Set((members.rows || []).map(r => r.user_id));
  const targets = studentIds.filter(id => validIds.has(id));
  if (!targets.length) return err(request, 'None of those students are in your family.');

  const ar = await query(env,
    `INSERT INTO essay_assignments (family_id, created_by, title, prompt, length_guidance)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [gate.family.id, gate.session.user_id, title, prompt, lengthGuidance]);
  const assignmentId = ar.rows[0].id;

  const params = [assignmentId]; const rowsSql = []; let p = 2;
  for (const id of targets) { rowsSql.push(`($1, $${p++})`); params.push(id); }
  await query(env, `INSERT INTO essay_assignment_targets (assignment_id, user_id) VALUES ${rowsSql.join(',')}`, params);

  return json(request, { ok: true, assignment_id: assignmentId }, 201);
}

// Title/prompt/length are optional partial updates. student_ids, if given,
// is the FULL desired roster — targets are added/removed to match, but an
// essay a student already wrote is never touched or deleted by this, even
// if they're removed from the roster afterward.
async function handleUpdateAssignment(request, env, assignmentId) {
  const gate = await requireParentSession(request, env);
  if (gate.error) return gate.error;
  const owns = await query(env, `SELECT id FROM essay_assignments WHERE id = $1 AND family_id = $2`,
    [assignmentId, gate.family.id]);
  if (!owns.rows?.length) return err(request, 'Assignment not found.', 404);

  const body = await request.json();
  const sets = []; const vals = []; let i = 1;
  if (body.title !== undefined) {
    const title = String(body.title).trim().slice(0, 120);
    if (!title) return err(request, 'Title cannot be empty.');
    sets.push(`title = $${i++}`); vals.push(title);
  }
  if (body.prompt !== undefined) {
    const prompt = String(body.prompt).trim();
    if (!prompt) return err(request, 'Prompt cannot be empty.');
    sets.push(`prompt = $${i++}`); vals.push(prompt);
  }
  if (body.length_guidance !== undefined) {
    sets.push(`length_guidance = $${i++}`); vals.push(String(body.length_guidance).trim().slice(0, 300));
  }
  if (sets.length) {
    vals.push(assignmentId);
    await query(env, `UPDATE essay_assignments SET ${sets.join(', ')} WHERE id = $${i}`, vals);
  }

  if (Array.isArray(body.student_ids)) {
    const studentIds = body.student_ids.filter(Boolean);
    const members = await query(env,
      `SELECT user_id FROM family_members WHERE family_id = $1 AND user_id = ANY($2::uuid[])`,
      [gate.family.id, studentIds]);
    const validIds = new Set((members.rows || []).map(r => r.user_id));
    const nextIds = new Set(studentIds.filter(id => validIds.has(id)));

    const current = await query(env, `SELECT user_id FROM essay_assignment_targets WHERE assignment_id = $1`, [assignmentId]);
    const currentIds = new Set((current.rows || []).map(r => r.user_id));

    const toRemove = [...currentIds].filter(id => !nextIds.has(id));
    const toAdd = [...nextIds].filter(id => !currentIds.has(id));

    if (toRemove.length) {
      await query(env, `DELETE FROM essay_assignment_targets WHERE assignment_id = $1 AND user_id = ANY($2::uuid[])`,
        [assignmentId, toRemove]);
    }
    if (toAdd.length) {
      const params = [assignmentId]; const rowsSql = []; let p = 2;
      for (const id of toAdd) { rowsSql.push(`($1, $${p++})`); params.push(id); }
      await query(env, `INSERT INTO essay_assignment_targets (assignment_id, user_id) VALUES ${rowsSql.join(',')}`, params);
    }
  }

  return json(request, { ok: true });
}

// Deletes the assignment and — via ON DELETE CASCADE — its targets and
// every essay written against it, including graded ones. The frontend
// confirms before calling this; there's no undo.
async function handleDeleteAssignment(request, env, assignmentId) {
  const gate = await requireParentSession(request, env);
  if (gate.error) return gate.error;
  const owns = await query(env, `SELECT id FROM essay_assignments WHERE id = $1 AND family_id = $2`,
    [assignmentId, gate.family.id]);
  if (!owns.rows?.length) return err(request, 'Assignment not found.', 404);
  await query(env, `DELETE FROM essay_assignments WHERE id = $1`, [assignmentId]);
  return json(request, { ok: true });
}

async function handleListAssignments(request, env) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    if (!family) return json(request, { assignments: [], role: null });

    if (family.role === 'parent') {
      const r = await query(env,
        `SELECT a.id, a.title, a.prompt, a.length_guidance, a.created_at,
                json_agg(json_build_object(
                  'user_id', u.id, 'display_name', u.display_name, 'email', u.email,
                  'status', COALESCE(e.status, 'not_started'),
                  'score_total', e.score_total, 'adaptive_score', e.adaptive_score,
                  'graded_at', e.graded_at
                ) ORDER BY u.display_name) AS targets
           FROM essay_assignments a
           JOIN essay_assignment_targets t ON t.assignment_id = a.id
           JOIN users u ON u.id = t.user_id
           LEFT JOIN essays e ON e.assignment_id = a.id AND e.user_id = u.id
          WHERE a.family_id = $1
          GROUP BY a.id
          ORDER BY a.created_at DESC`,
        [family.id]);
      return json(request, { assignments: r.rows || [], role: 'parent' });
    }

    const r = await query(env,
      `SELECT a.id, a.title, a.prompt, a.length_guidance, a.created_at,
              COALESCE(e.status, 'not_started') AS status, e.adaptive_score, e.graded_at
         FROM essay_assignments a
         JOIN essay_assignment_targets t ON t.assignment_id = a.id AND t.user_id = $1
         LEFT JOIN essays e ON e.assignment_id = a.id AND e.user_id = $1
        ORDER BY a.created_at DESC`,
      [session.user_id]);
    return json(request, { assignments: r.rows || [], role: 'learner' });
  });
}

async function handleGetEssay(request, env, assignmentId) {
  return withUser(request, env, async (session) => {
    const target = await query(env,
      `SELECT 1 FROM essay_assignment_targets WHERE assignment_id = $1 AND user_id = $2`,
      [assignmentId, session.user_id]);
    if (!target.rows?.length) return err(request, 'Not found.', 404);

    const ar = await query(env, `SELECT id, title, prompt, length_guidance FROM essay_assignments WHERE id = $1`, [assignmentId]);
    if (!ar.rows?.length) return err(request, 'Not found.', 404);

    const essay = await getOrCreateEssay(env, assignmentId, session.user_id);
    return json(request, {
      assignment: ar.rows[0],
      essay: { id: essay.id, status: essay.status, draft_text: essay.draft_text, draft_updated_at: essay.draft_updated_at },
    });
  });
}

async function handleSaveDraft(request, env, assignmentId) {
  return withUser(request, env, async (session) => {
    const essay = await getOrCreateEssay(env, assignmentId, session.user_id);
    if (essay.status === 'graded') return err(request, 'This essay has already been graded.', 409);
    const { draft_text } = await request.json();
    await query(env, `UPDATE essays SET draft_text = $1, draft_updated_at = NOW() WHERE id = $2`,
      [String(draft_text ?? ''), essay.id]);
    return json(request, { ok: true });
  });
}

async function handleGradeEssay(request, env, assignmentId) {
  return withUser(request, env, async (session) => {
    const essay = await getOrCreateEssay(env, assignmentId, session.user_id);
    if (essay.status === 'graded') return err(request, 'This essay has already been graded.', 409);
    if (!essay.draft_text || !essay.draft_text.trim()) return err(request, 'Write something before grading.');

    const ar = await query(env, `SELECT * FROM essay_assignments WHERE id = $1`, [assignmentId]);
    const assignment = ar.rows?.[0];
    if (!assignment) return err(request, 'Assignment not found.', 404);

    await query(env, `UPDATE essays SET status = 'grading' WHERE id = $1`, [essay.id]);

    const historyR = await query(env,
      `SELECT issue_type, tier, times_flagged, times_recurred_after_flagged
         FROM essay_issue_history WHERE user_id = $1
        ORDER BY times_recurred_after_flagged DESC, times_flagged DESC LIMIT 20`,
      [session.user_id]);

    let result;
    try {
      result = await callClaude(env, {
        system: buildGradingSystemPrompt(assignment, historyR.rows || [], session.feedback_level),
        content: essay.draft_text,
        tool: GRADE_TOOL,
      });
    } catch (e) {
      await query(env, `UPDATE essays SET status = 'draft' WHERE id = $1`, [essay.id]);
      return err(request, `Grading failed: ${e.message}`, 502);
    }

    const rebuilt = (result.sentences || []).map(s => s.text).join(' ').replace(/\s+/g, ' ').trim();
    const original = essay.draft_text.replace(/\s+/g, ' ').trim();
    if (rebuilt.length < original.length * 0.7) {
      await query(env, `UPDATE essays SET status = 'draft' WHERE id = $1`, [essay.id]);
      return err(request, 'Grading response looked incomplete — please try again.', 502);
    }

    const rubric = result.rubric || {};
    const scoreTotal = clampInt(
      Object.entries(ESSAY_RUBRIC).reduce((sum, [k, v]) => sum + clampInt(rubric[k]?.score, 0, v.max), 0),
      0, 100);

    const catalog = Array.isArray(result.issues_catalog) ? result.issues_catalog : [];
    for (const issue of catalog) {
      const type = String(issue.issue_type || '').trim().slice(0, 60);
      if (!type) continue;
      const tier = ISSUE_TIERS.includes(issue.tier) ? issue.tier : 'mechanics';
      const existing = await query(env,
        `SELECT times_flagged FROM essay_issue_history WHERE user_id = $1 AND issue_type = $2`,
        [session.user_id, type]);
      const recurred = (existing.rows?.[0]?.times_flagged || 0) > 0 ? 1 : 0;
      await query(env,
        `INSERT INTO essay_issue_history (user_id, issue_type, tier, times_flagged, times_recurred_after_flagged, first_seen_essay_id, last_seen_essay_id)
         VALUES ($1, $2, $3, 1, $4, $5, $5)
         ON CONFLICT (user_id, issue_type) DO UPDATE SET
           times_flagged = essay_issue_history.times_flagged + 1,
           times_recurred_after_flagged = essay_issue_history.times_recurred_after_flagged + $4,
           tier = EXCLUDED.tier, last_seen_essay_id = EXCLUDED.last_seen_essay_id, updated_at = NOW()`,
        [session.user_id, type, tier, recurred, essay.id]);
    }

    const topFive = selectTopIssues(catalog, historyR.rows || []);
    for (const issue of topFive) {
      await query(env,
        `UPDATE essay_issue_history SET times_in_top_five = times_in_top_five + 1, updated_at = NOW()
          WHERE user_id = $1 AND issue_type = $2`,
        [session.user_id, String(issue.issue_type || '').trim().slice(0, 60)]);
    }

    const priorR = await query(env,
      `SELECT score_total FROM essays WHERE user_id = $1 AND status = 'graded' AND id != $2
        ORDER BY graded_at DESC LIMIT 5`,
      [session.user_id, essay.id]);
    const priorScores = (priorR.rows || []).map(r => r.score_total).filter(n => n != null);
    const persistentOffender = (historyR.rows || []).some(h =>
      h.times_recurred_after_flagged >= 3 && catalog.some(c => c.issue_type === h.issue_type));
    const adaptiveScore = computeAdaptiveScore(scoreTotal, priorScores, persistentOffender);

    const feedback = {
      sentences: result.sentences || [], rubric, strengths: result.strengths || [],
      overall_feedback: result.overall_feedback || '', issues_catalog: catalog,
      top_issues: topFive, length_assessment: result.length_assessment || '',
    };
    const coaching = {
      practice_text: essay.draft_text,
      issues: topFive.map(issue => ({ ...issue, status: 'open', attempts: 0 })),
      completed: topFive.length === 0,
    };

    await query(env,
      `UPDATE essays SET status = 'graded', original_text = $1, score_total = $2, adaptive_score = $3,
         feedback = $4::jsonb, coaching = $5::jsonb, graded_at = NOW() WHERE id = $6`,
      [essay.draft_text, scoreTotal, adaptiveScore, JSON.stringify(feedback), JSON.stringify(coaching), essay.id]);

    // Ratchet the feedback reading level up if their real scores now
    // sustain it. Applies to the NEXT essay — this one is already worded.
    const promoted = maybePromoteFeedbackLevel(session.feedback_level, [scoreTotal, ...priorScores]);
    if (promoted !== session.feedback_level) {
      await query(env, `UPDATE users SET feedback_level = $1 WHERE id = $2`, [promoted, session.user_id]);
    }

    return json(request, {
      ok: true, adaptive_score: adaptiveScore,
      feedback: stripScoresForLearner(feedback), coaching,
      feedback_level: promoted,
      level_promoted: promoted !== session.feedback_level,
    });
  });
}

async function handleSavePractice(request, env, assignmentId) {
  return withUser(request, env, async (session) => {
    const essay = await getOrCreateEssay(env, assignmentId, session.user_id);
    if (essay.status !== 'graded') return err(request, 'Grade the essay first.', 409);
    const { practice_text } = await request.json();
    const coaching = essay.coaching || {};
    coaching.practice_text = String(practice_text ?? '');
    await query(env, `UPDATE essays SET coaching = $1::jsonb WHERE id = $2`, [JSON.stringify(coaching), essay.id]);
    return json(request, { ok: true });
  });
}

async function handleCoachingCheck(request, env, assignmentId) {
  return withUser(request, env, async (session) => {
    const essay = await getOrCreateEssay(env, assignmentId, session.user_id);
    if (essay.status !== 'graded') return err(request, 'Grade the essay first.', 409);
    const { issue_index } = await request.json();
    const coaching = essay.coaching || { issues: [], practice_text: essay.original_text || '' };
    const issue = coaching.issues?.[issue_index];
    if (!issue) return err(request, 'No such issue.', 404);
    if (issue.status && issue.status !== 'open') return json(request, { coaching });

    let verdict;
    try {
      verdict = await callClaude(env, {
        system: buildCoachingCheckPrompt(issue, session.feedback_level),
        content: coaching.practice_text || '',
        tool: COACHING_CHECK_TOOL,
      });
    } catch (e) {
      return err(request, `Check failed: ${e.message}`, 502);
    }

    issue.attempts = (issue.attempts || 0) + 1;
    issue.last_note = verdict.note || '';
    if (verdict.verdict === 'not_addressed' && issue.attempts < 3) issue.status = 'open';
    else if (verdict.verdict === 'resolved') issue.status = 'resolved';
    else if (verdict.verdict === 'partial') issue.status = 'partial';
    else issue.status = 'accepted'; // hit the attempt cap — accept best effort and move on

    coaching.completed = (coaching.issues || []).every(i => i.status !== 'open');

    await query(env,
      `UPDATE essays SET coaching = $1::jsonb, coaching_completed_at = $2 WHERE id = $3`,
      [JSON.stringify(coaching), coaching.completed ? new Date().toISOString() : null, essay.id]);

    return json(request, { verdict, coaching });
  });
}

async function handleGetEssayResults(request, env, assignmentId, studentId) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    const isSelf = session.user_id === studentId;
    const isParent = !!(family && family.role === 'parent');
    if (!isSelf && !isParent) return err(request, 'Not found.', 404);

    if (isParent && !isSelf) {
      const owns = await query(env, `SELECT 1 FROM essay_assignments WHERE id = $1 AND family_id = $2`,
        [assignmentId, family.id]);
      if (!owns.rows?.length) return err(request, 'Not found.', 404);
    }

    const r = await query(env,
      `SELECT e.*, u.display_name, u.email FROM essays e JOIN users u ON u.id = e.user_id
        WHERE e.assignment_id = $1 AND e.user_id = $2`,
      [assignmentId, studentId]);
    const essay = r.rows?.[0];
    if (!essay || essay.status !== 'graded') return err(request, 'Not graded yet.', 404);

    const payload = {
      student: { id: studentId, display_name: essay.display_name, email: essay.email },
      original_text: essay.original_text,
      adaptive_score: essay.adaptive_score,
      feedback: isParent ? essay.feedback : stripScoresForLearner(essay.feedback),
      coaching: essay.coaching,
      coaching_completed_at: essay.coaching_completed_at,
      graded_at: essay.graded_at,
    };
    if (isParent) payload.score_total = essay.score_total;
    return json(request, payload);
  });
}

/* ============================================================
   Spanish Coach — voice-first conversation (Engine P: pipeline)

   Browser does speech-to-text and playback. The Worker owns the
   conversation brain (Claude), the pedagogical event log, the
   budget gates, and speech synthesis. Nothing paid is reachable
   from the browser without passing through here.
============================================================ */

const SPANISH_TURN_MODEL     = 'claude-sonnet-5';  // latency-sensitive
const SPANISH_CONSOLIDATE_MODEL = 'claude-opus-5'; // quality-sensitive, once per session

// Phase windows are fractions of the session, so they scale with
// a 15 / 20 / 30-minute setting without redefining the arc.
const SPANISH_PHASES = [
  { key: 'saludo',   name: 'Saludo',   until: 0.10,
    brief: 'Greeting ritual. Say hello warmly, ask how they are, ask one easy personal question.' },
  { key: 'recuerdo', name: 'Recuerdo', until: 0.20,
    brief: 'Call back to last time using the plan’s hooks. Reuse a past win; elicit one open target naturally.' },
  { key: 'tema',     name: 'Tema',     until: 0.53,
    brief: 'Today’s topic. Work the target words and structures into genuine conversation — never a drill.' },
  { key: 'escena',   name: 'Escena',   until: 0.77,
    brief: 'Role-play the scenario. Play your character; let the learner act and decide.' },
  { key: 'juego',    name: 'Juego',    until: 0.90,
    brief: 'Play the game from the plan using today’s words. Keep it light and quick.' },
  { key: 'cierre',   name: 'Cierre',   until: 1.01,
    brief: 'Closing. Recap three good words, praise one specific win, preview tomorrow, say goodbye warmly.' },
];

const SPANISH_INTERVENTIONS = [
  'ignore', 'recast', 'expansion', 'extension',
  'clarification', 'guided_repair', 'explicit_correction',
];
const SPANISH_SKILL_TYPES = ['grammar', 'vocabulary', 'comprehension', 'fluency', 'pronunciation'];

function spanishNum(v, lo, hi, dflt) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : dflt;
}
function cleanText(v, max) {
  const s = String(v ?? '').trim();
  return s ? s.slice(0, max) : null;
}
function cleanKey(v) {
  const s = String(v ?? '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '_');
  return s ? s.slice(0, 60) : null;
}

function defaultSpanishProfile() {
  return {
    comprehension_level: 'novice_low', production_level: 'novice_low',
    correction_intensity: 'balanced', english_support: 'as_needed',
    speech_rate: 0.92, session_minutes: 15, daily_session_cap: 4,
    weekly_minutes_goal: 105, transcript_retention: 'days_30',
    show_direct_button: true, interests: [], profile_summary: '',
    total_seconds: 0, total_sessions: 0,
  };
}

async function getSpanishProfile(env, userId) {
  const r = await query(env, `SELECT * FROM spanish_profiles WHERE user_id = $1`, [userId]);
  if (r.rows?.[0]) return r.rows[0];
  await query(env, `INSERT INTO spanish_profiles (user_id) VALUES ($1)
                    ON CONFLICT (user_id) DO NOTHING`, [userId]);
  return { user_id: userId, ...defaultSpanishProfile() };
}

/* ── The session clock counts speech, not wall time ─────────────
   A wall clock punishes the pause before a sentence, which is the
   exact moment a child is assembling one. Sessions were running out
   with barely a word said in them. The clock now advances only while
   the learner is actually recording, so thinking is free.

   There is no cutoff. The clock chooses the phase and tells the coach
   when a session has been worth having; the conversation ends when
   the child ends it, or when it reaches its own natural close.
──────────────────────────────────────────────────────────────── */

// What a session should contain before it counts as one.
const SPANISH_MIN_SPEAKING_SECONDS = 60;

// A learner speaks perhaps a fifth of a conversation — the rest is the coach
// talking, and the child listening, which is not idleness either. This turns
// the parent-facing session_minutes setting into a speech budget, so that knob
// keeps meaning something without anyone having to think in two units.
const SPANISH_SPEAKING_RATIO = 0.2;

function spanishSpeakingTarget(profile) {
  const minutes = spanishNum(profile?.session_minutes, 5, 120, 15);
  return Math.max(SPANISH_MIN_SPEAKING_SECONDS, minutes * 60 * SPANISH_SPEAKING_RATIO);
}

// Which phase are we in, given how much the learner has actually spoken?
function spanishPhase(spokenSeconds, targetSeconds) {
  const frac = targetSeconds > 0 ? spokenSeconds / targetSeconds : 1;
  return SPANISH_PHASES.find(p => frac < p.until) || SPANISH_PHASES[SPANISH_PHASES.length - 1];
}

// The coach cannot keep time; we tell it the time every turn. None of this may
// reach the child — a session that narrates its own budget teaches a child to
// watch the budget instead of the conversation.
function spanishClockLine(spokenSeconds, targetSeconds) {
  const phase  = spanishPhase(spokenSeconds, targetSeconds);
  const spoken = Math.round(spokenSeconds);
  const short  = SPANISH_MIN_SPEAKING_SECONDS - spoken;

  const lines = [
    `[CLOCK] The learner has spoken about ${spoken} seconds so far. Phase: ${phase.name} — ${phase.brief}`,
    '[CLOCK] This budget counts only the learner\'s own speech; their silences cost nothing, so never rush them and never fill a pause for them.',
    '[CLOCK] Say nothing about time, seconds, minutes, length, phases, or progress — not as praise, not as encouragement, not at the close. The learner must never discover that speaking more is what carries the session forward.',
  ];
  lines.push(short > 0
    ? `[CLOCK] This session is not yet worth keeping — roughly ${short} more seconds of their speech would do it. Do not begin closing. Ask what invites a long answer: a story, a reason, a description, an opinion, and then follow the thread they offer.`
    : '[CLOCK] They have spoken enough for this session to count. Follow the conversation while it holds their interest, and close warmly when it reaches its own end.');
  return lines.join('\n');
}

// Estimated seconds of speech for a Spanish utterance (~15 chars/sec).
function spanishSpeechSeconds(text) {
  return Math.max(0.5, Math.round((String(text || '').length / 15) * 10) / 10);
}

function spanishNextReview(estimate, recurrenceCount) {
  let days;
  if (recurrenceCount >= 3)   days = 1;
  else if (estimate < 0.35)   days = 2;
  else if (estimate < 0.55)   days = 5;
  else if (estimate < 0.75)   days = 12;
  else                        days = 30;
  return new Date(Date.now() + days * 86400000).toISOString();
}

// ── Tool contracts ─────────────────────────────────────────────
const SPANISH_TURN_TOOL = {
  name: 'spanish_turn',
  description: 'Reply to the learner and record the pedagogical decision for their turn.',
  input_schema: {
    type: 'object',
    required: ['reply_text'],
    properties: {
      reply_text: {
        type: 'string',
        description: 'What the coach says aloud. One or two short sentences of Spanish, ending with a genuine question or choice.',
      },
      emphasis_word: {
        type: 'string',
        description: 'If this reply recasts a form, the single corrected word or phrase to stress slightly when speaking.',
      },
      intervention: {
        type: 'object',
        required: ['intervention_type'],
        properties: {
          intervention_type: { type: 'string', enum: SPANISH_INTERVENTIONS },
          intended_meaning:  { type: 'string' },
          learner_form:      { type: 'string' },
          target_form:       { type: 'string' },
          skill_key:         { type: 'string', description: 'stable snake_case id, e.g. preterite_ir_first_person' },
          display_name:      { type: 'string' },
          skill_type:        { type: 'string', enum: SPANISH_SKILL_TYPES },
          importance:        { type: 'integer', minimum: 1, maximum: 5 },
          recognition_uncertain:      { type: 'boolean' },
          learner_repeated_correctly: { type: 'boolean' },
        },
      },
      vocabulary: {
        type: 'array',
        description: 'Meaningful vocabulary exposure or production in this exchange.',
        items: {
          type: 'object',
          required: ['lemma', 'evidence'],
          properties: {
            lemma:         { type: 'string' },
            english_gloss: { type: 'string' },
            evidence:      { type: 'string', enum: ['heard', 'produced_correctly', 'produced_with_help'] },
          },
        },
      },
    },
  },
};

const SPANISH_CONSOLIDATE_TOOL = {
  name: 'submit_session_consolidation',
  description: 'Summarize the finished session and plan the next one.',
  input_schema: {
    type: 'object',
    required: ['parent_summary', 'learner_summary', 'next_lesson_plan'],
    properties: {
      parent_summary: {
        type: 'string',
        description: 'Two to four sentences for a parent. Use ONLY the supplied aggregates and transcript. Never invent numbers or diagnoses.',
      },
      learner_summary: {
        type: 'string',
        description: 'One or two simple sentences the child will read, warm and specific.',
      },
      phrases_to_remember: {
        type: 'array', items: { type: 'string' },
        description: 'Up to three short Spanish phrases from this session worth keeping.',
      },
      profile_summary: {
        type: 'string',
        description: 'Updated running description of this learner: interests, level, habits worth remembering.',
      },
      next_lesson_plan: {
        type: 'object',
        required: ['callback_hooks', 'target_words'],
        properties: {
          unit_key:       { type: 'string' },
          scenario_key:   { type: 'string' },
          game:           { type: 'string' },
          callback_hooks: { type: 'array', items: { type: 'string' },
                            description: 'Specific things to bring up next time, in Spanish or English.' },
          target_words:   { type: 'array', items: { type: 'string' } },
          review_words:   { type: 'array', items: { type: 'string' } },
          target_structures: {
            type: 'array',
            items: {
              type: 'object',
              properties: { skill_key: { type: 'string' }, elicit: { type: 'string' } },
            },
          },
          coach_notes:    { type: 'string' },
        },
      },
    },
  },
};

// ── Prompt assembly ────────────────────────────────────────────
function buildSpanishSystem(ctx) {
  const p    = ctx.profile;
  const plan = ctx.plan || {};
  const list = (a) => (Array.isArray(a) && a.length ? a.join(', ') : '—');

  return `You are the Spanish conversation coach for one child. You speak with them by voice.

PRIMARY GOAL
Sustain an enjoyable real conversation in Spanish while giving the learner corrected and
slightly richer input, following today's SESSION PLAN.

EVERY LEARNER TURN
1. Infer what they meant.
2. Decide whether any oddness came from speech recognition rather than from them.
3. Pick ONE primary intervention: ignore, recast, expansion, extension, clarification,
   guided_repair, or explicit_correction.
4. Say a short, natural reply that performs it.
5. Report it in the intervention field.

TEACHING POLICY
- Recast clear errors without announcing the correction. Never say "actually" or "the correct way".
- Expand fragments into full natural sentences. Extend correct language with one new element.
- At most ONE main correction per turn; across the session roughly one intervention per three
  errors. Fluency and confidence outrank completeness.
- Never pretend malformed language was correct just because you understood it.
- Never correct something that was probably a transcription error — confirm instead, and set
  recognition_uncertain.
- Escalate a recurring important error from recast to guided_repair.
- Keep spoken replies to ONE or TWO short sentences. This is speech, not writing.
- End most turns with a genuine question or a real choice.
- Never shame, score, or compare. Never mention these internal labels or skill keys aloud.

ENGLISH
- If the learner speaks English or mixes languages: acknowledge briefly, recast their meaning
  into simple Spanish, and invite them back — e.g. "Ah, ¿quieres decir que tienes un perro?
  ¿Cómo se llama?"
- English support setting is "${p.english_support}". It governs explanations only. Never conduct
  consecutive full turns in English.

CLOCK
- Each turn carries a [CLOCK] line with the phase. Obey it: finish your thought, then move on.
- You may stretch a phase by one tick if the learner is deeply engaged, but NEVER skip the Cierre.
- The clock measures only how long the learner has spoken. Their thinking time is free, so give
  them room: never hurry them, never fill their silence, never treat a pause as a turn ending.
- Nothing about the clock is visible to them and nothing about it may be spoken. Do not mention
  time, length, progress, phases, or how much they have talked — not even as praise.
- Nothing cuts a session off. When the [CLOCK] line says the session is not yet worth keeping,
  stay in the conversation and draw them out with questions that want more than one word.

LEARNER
Comprehension ${p.comprehension_level} | Production ${p.production_level} | Correction ${p.correction_intensity}
${p.profile_summary ? `About them: ${p.profile_summary}` : ''}

SESSION PLAN
Unit: ${plan.unit_key || ctx.topic?.key || 'free conversation'}
Scenario: ${ctx.scenario?.title || 'Conversación libre'} — ${ctx.scenario?.opening_instruction || ''}
Game for the Juego phase: ${plan.game || 'veo-veo'}
Target words: ${list(plan.target_words || ctx.topic?.target_words)}
Review words: ${list(plan.review_words || ctx.review_words?.map(w => w.lemma))}
Callback hooks: ${list(plan.callback_hooks)}
${plan.coach_notes ? `Coach notes: ${plan.coach_notes}` : ''}

OPEN TARGETS (work these in naturally; do not force all of them)
${(ctx.active_skills || []).slice(0, 6).map(s =>
   `- ${s.display_name} (${s.skill_key}) seen ${s.evidence_count}×, recurring ${s.recurrence_count}×`).join('\n') || '- none yet'}

SAFETY
Keep everything age-appropriate. Redirect sexual content, drugs, violence, and self-harm.
Never encourage secrecy from parents. Never claim to be a human friend, and avoid language that
invites emotional dependency. Keep role-play clearly pretend. Never ask for addresses, school
names, passwords, or other identifying details.`;
}

function buildSpanishTurnContent(ctx, transcript, confidence, clockLine) {
  const history = (ctx.history || []).map(t =>
    `${t.speaker === 'coach' ? 'COACH' : 'LEARNER'}: ${t.transcript}`).join('\n');

  if (!transcript) {
    return `${clockLine}\n\n${history ? `CONVERSATION SO FAR\n${history}\n\n` : ''}` +
      `The session is starting and the learner has not spoken yet. Greet them warmly in Spanish ` +
      `and ask one easy opening question. Do not report an intervention.`;
  }

  const conf = confidence == null ? 'unknown'
    : confidence < 0.6 ? `${confidence.toFixed(2)} (LOW — likely a recognition problem, not a learner error)`
    : confidence.toFixed(2);

  return `${clockLine}\n\n${history ? `CONVERSATION SO FAR\n${history}\n\n` : ''}` +
    `LEARNER JUST SAID (speech recognition, confidence ${conf}):\n"${transcript}"\n\n` +
    `Reply as the coach.`;
}

// ── Context loading ────────────────────────────────────────────
async function loadSpanishContext(env, userId, scenarioKey) {
  const profile = await getSpanishProfile(env, userId);

  const [planR, skillsR, vocabR, recentR, scenarioR] = await Promise.all([
    query(env, `SELECT id, sequence, plan FROM spanish_lesson_plans
                 WHERE user_id = $1 AND used_by_session IS NULL
                 ORDER BY sequence DESC LIMIT 1`, [userId]),
    query(env, `SELECT skill_key, display_name, skill_type, estimate,
                       evidence_count, recurrence_count
                  FROM spanish_skills WHERE user_id = $1
                 ORDER BY CASE WHEN next_review_at <= NOW() THEN 0 ELSE 1 END,
                          recurrence_count DESC, estimate ASC
                 LIMIT 12`, [userId]),
    query(env, `SELECT lemma, english_gloss, mastery FROM spanish_vocabulary
                 WHERE user_id = $1
                 ORDER BY CASE WHEN next_review_at <= NOW() THEN 0 ELSE 1 END, mastery ASC
                 LIMIT 20`, [userId]),
    query(env, `SELECT summary FROM spanish_sessions
                 WHERE user_id = $1 AND status = 'completed'
                 ORDER BY started_at DESC LIMIT 3`, [userId]),
    query(env, `SELECT * FROM spanish_scenarios WHERE key = $1 AND enabled`, [scenarioKey]),
  ]);

  const planRow = planR.rows?.[0] || null;
  const plan    = planRow?.plan || null;

  // Scenario: the plan's choice wins, then the request, then free talk.
  let scenario = scenarioR.rows?.[0] || null;
  if (plan?.scenario_key && plan.scenario_key !== scenarioKey) {
    const alt = await query(env, `SELECT * FROM spanish_scenarios WHERE key = $1 AND enabled`,
      [plan.scenario_key]);
    if (alt.rows?.[0]) scenario = alt.rows[0];
  }
  if (!scenario) {
    const fallback = await query(env,
      `SELECT * FROM spanish_scenarios WHERE key = 'free-talk'`, []);
    scenario = fallback.rows?.[0] || {
      key: 'free-talk', title: 'Conversación libre',
      opening_instruction: 'Invite the learner to choose a topic.',
    };
  }

  // Topic: the plan's unit, else the next unit by curriculum order.
  let topic = null;
  if (plan?.unit_key) {
    const t = await query(env, `SELECT * FROM spanish_topics WHERE key = $1 AND enabled`, [plan.unit_key]);
    topic = t.rows?.[0] || null;
  }
  if (!topic) {
    const t = await query(env,
      `SELECT * FROM spanish_topics WHERE enabled ORDER BY unit_order LIMIT 1`, []);
    topic = t.rows?.[0] || null;
  }

  return {
    profile, scenario, topic, plan, plan_id: planRow?.id || null,
    plan_sequence: planRow?.sequence || 0,
    active_skills: skillsR.rows || [],
    review_words:  vocabR.rows || [],
    recent_sessions: recentR.rows || [],
  };
}

// ── Speech synthesis (proxied; the key stays here) ─────────────
async function spanishSynthesize(env, text, emphasisWord) {
  if (!env.OPENAI_API_KEY) return null;   // graceful: caller falls back to text-only

  const instructions =
    'Speak as a warm, patient adult talking with a young child learning Spanish. ' +
    'Natural Latin American Spanish, clear and unhurried, friendly and encouraging. ' +
    (emphasisWord
      ? `Say "${emphasisWord}" slightly slower and with gentle emphasis so it stands out.`
      : '');

  const res = await fetch('https://api.openai.com/v1/audio/speech', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: env.SPANISH_TTS_MODEL || 'gpt-4o-mini-tts',
      voice: env.SPANISH_TTS_VOICE || 'coral',
      input: text,
      instructions,
      response_format: 'mp3',
      speed: spanishNum(env.SPANISH_TTS_SPEED, 0.5, 1.5, 1.0),
    }),
  });
  if (!res.ok) {
    console.error('TTS failed', res.status, (await res.text()).slice(0, 300));
    return null;
  }

  // Chunked base64 so a long clip cannot blow the argument limit.
  const bytes = new Uint8Array(await res.arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

// ── Speech recognition (server-side fallback) ──────────────────
// Browsers without the Web Speech API (Firefox, Brave) record audio and
// upload it here instead. Also the privacy-preferable path in Chrome,
// where Web Speech sends the child's audio to Google.
// OpenAI picks its decoder from the filename, so a wrong extension rejects a
// recording that was perfectly good. Map from the container the browser really
// sent, and refuse to guess: labelling an Ogg file .webm fails as a 400 that
// looks exactly like a broken microphone.
function spanishAudioExt(contentType) {
  const t = String(contentType || '').toLowerCase();
  if (t.includes('webm')) return 'webm';
  if (t.includes('ogg') || t.includes('oga') || t.includes('opus')) return 'ogg';
  if (t.includes('mp4') || t.includes('m4a') || t.includes('aac')) return 'mp4';
  if (t.includes('wav') || t.includes('wave')) return 'wav';
  if (t.includes('flac')) return 'flac';
  if (t.includes('mpeg') || t.includes('mpga') || t.includes('mp3')) return 'mp3';
  return '';
}

// Tagged so the turn handler can tell a child something true about which part
// broke, instead of blaming their microphone for every failure.
function transcribeError(kind, message) {
  const e = new Error(message);
  e.kind = kind;                       // format | config | upstream
  return e;
}

const SPANISH_STT_TIMEOUT_MS = 20000;

async function spanishTranscribe(env, bytes, contentType) {
  if (!env.OPENAI_API_KEY) {
    throw transcribeError('config', 'Speech recognition is not configured.');
  }

  const ext = spanishAudioExt(contentType);
  if (!ext) {
    throw transcribeError('format', `Unsupported recording container: ${contentType}`);
  }

  const model = env.SPANISH_STT_MODEL || 'whisper-1';

  // One retry. This call sits in the middle of a child's turn, so a stalled
  // connection should cost a few seconds, not the turn — and without the
  // timeout a hung upstream just spins until the child gives up.
  let last = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const form = new FormData();
    form.append('file', new Blob([bytes], { type: contentType }), `speech.${ext}`);
    form.append('model', model);
    // Steers proper nouns and register; helps a lot with children's speech.
    form.append('prompt', 'Conversación en español entre un niño y su maestro de español.');
    if (model === 'whisper-1') {
      form.append('language', 'es');
      form.append('response_format', 'verbose_json');   // carries avg_logprob
    } else {
      form.append('languages[]', 'es');
    }

    let res;
    try {
      res = await fetch('https://api.openai.com/v1/audio/transcriptions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${env.OPENAI_API_KEY}` },
        body: form,
        signal: AbortSignal.timeout(SPANISH_STT_TIMEOUT_MS),
      });
    } catch (e) {
      last = transcribeError('upstream', `Transcription request failed: ${e.name}: ${e.message}`);
      continue;
    }

    if (!res.ok) {
      const body = (await res.text().catch(() => '')).slice(0, 300);
      // A 4xx means the key, the model, or the file is wrong, and a second
      // identical request fails identically. Only 5xx and 429 are worth a retry.
      if (res.status >= 500 || res.status === 429) {
        last = transcribeError('upstream', `Transcription ${res.status}: ${body}`);
        continue;
      }
      throw transcribeError(
        res.status === 400 || res.status === 415 ? 'format' : 'config',
        `Transcription ${res.status}: ${body}`);
    }

    return spanishReadTranscription(await res.json());
  }
  throw last;
}

function spanishReadTranscription(data) {
  // Derive a rough confidence so the coach still knows when NOT to treat
  // something as a learner error. verbose_json gives per-segment avg_logprob;
  // models that don't return it yield null, which the prompt reads as "unknown".
  let confidence = null;
  const segs = Array.isArray(data.segments) ? data.segments : [];
  if (segs.length) {
    const lp = segs.reduce((n, s) => n + (Number(s.avg_logprob) || 0), 0) / segs.length;
    const noSpeech = segs.reduce((n, s) => n + (Number(s.no_speech_prob) || 0), 0) / segs.length;
    confidence = Math.max(0, Math.min(1, Math.exp(lp) * (1 - noSpeech)));
  }
  return { text: String(data.text || '').trim(), confidence };
}

// ── Session creation ───────────────────────────────────────────
async function handleCreateSpanishSession(request, env) {
  return withUser(request, env, async (session) => {
    const family = await getMembership(env, session.user_id);
    if (!family) return err(request, 'Join a family before using Spanish Coach.', 403);

    const access = await query(env,
      `SELECT COALESCE(ta.enabled, true) AS enabled
         FROM tools t
         LEFT JOIN tool_access ta ON ta.tool_slug = t.slug AND ta.user_id = $1
        WHERE t.slug = 'spanish-tutor'`, [session.user_id]);
    if (access.rows?.[0]?.enabled === false) {
      return err(request, 'Spanish Coach is not enabled for this account.', 403);
    }

    const body        = await request.json().catch(() => ({}));
    const scenarioKey = cleanKey(body.scenario_key) || 'free-talk';
    const profile     = await getSpanishProfile(env, session.user_id);

    // Close out anything still open before counting. Sessions no longer expire
    // on a clock, so age is no longer evidence that one is stale — but starting
    // a new one is, and a learner only ever has one going.
    await query(env,
      `UPDATE spanish_sessions SET status = 'abandoned', ended_at = NOW()
        WHERE user_id = $1 AND status = 'active'`,
      [session.user_id]);

    // Layer 1 — budget gates, before anything paid happens.
    const usage = await query(env,
      `SELECT
         COALESCE((SELECT SUM(input_audio_seconds + output_audio_seconds)
                     FROM spanish_sessions
                    WHERE started_at >= date_trunc('month', NOW())), 0) AS month_secs,
         (SELECT COUNT(*) FROM spanish_sessions
           WHERE user_id = $1 AND started_at::date = CURRENT_DATE
             AND status <> 'failed') AS today_sessions`,
      [session.user_id]);

    const monthMinutes  = Number(usage.rows?.[0]?.month_secs || 0) / 60;
    const todaySessions = Number(usage.rows?.[0]?.today_sessions || 0);
    const monthCap      = spanishNum(env.SPANISH_MONTHLY_AUDIO_MINUTES, 60, 100000, 2400);
    const dailyCap      = spanishNum(profile.daily_session_cap, 1, 10, 4);

    if (monthMinutes >= monthCap) {
      return err(request, 'Spanish Coach has used up this month’s practice time. It resets on the 1st.', 429);
    }
    if (todaySessions >= dailyCap) {
      return err(request, '¡Ya practicaste mucho hoy! That’s plenty of Spanish for today — ¡hasta mañana!', 429);
    }

    const ctx = await loadSpanishContext(env, session.user_id, scenarioKey);

    const created = await query(env,
      `INSERT INTO spanish_sessions (user_id, scenario_key, topic_key, engine, model_name, plan_id)
       VALUES ($1, $2, $3, 'pipeline', $4, $5)
       RETURNING id, started_at`,
      [session.user_id, ctx.scenario.key, ctx.topic?.key || null,
       SPANISH_TURN_MODEL, ctx.plan_id]);

    const sessionId = created.rows[0].id;
    if (ctx.plan_id) {
      await query(env, `UPDATE spanish_lesson_plans SET used_by_session = $1 WHERE id = $2`,
        [sessionId, ctx.plan_id]);
    }

    return json(request, {
      session_id:      sessionId,
      started_at:      created.rows[0].started_at,
      scenario:        { key: ctx.scenario.key, title: ctx.scenario.title,
                         description: ctx.scenario.description },
      topic:           ctx.topic ? { key: ctx.topic.key, title: ctx.topic.title } : null,
      plan:            ctx.plan,
      phases:          SPANISH_PHASES.map(p => ({ key: p.key, name: p.name, until: p.until })),
      show_direct_button: profile.show_direct_button,
      speech_rate:     Number(profile.speech_rate),
    }, 201);
  });
}

// ── One conversation turn ──────────────────────────────────────
async function handleSpanishTurn(request, env, sessionId) {
  return withUser(request, env, async (session) => {
    const sr = await query(env,
      `SELECT * FROM spanish_sessions WHERE id = $1 AND user_id = $2 AND status = 'active'`,
      [sessionId, session.user_id]);
    const sess = sr.rows?.[0];
    if (!sess) return err(request, 'Active session not found.', 404);

    const profile      = await getSpanishProfile(env, session.user_id);
    const targetSecs   = spanishSpeakingTarget(profile);
    // Speech already banked in this session. No turn is refused on time — a
    // session ends when the child ends it, and the month cap in
    // handleCreateSpanishSession is what keeps the spend bounded.
    const spokenBefore = Number(sess.input_audio_seconds || 0);

    // Two input shapes. Browsers with the Web Speech API send JSON with a
    // transcript they produced; every other browser uploads raw audio and we
    // transcribe it here. Same endpoint either way, so one round trip.
    const contentType = request.headers.get('Content-Type') || '';
    let transcript, confidence, turnIndex, control, learnerSeconds;

    if (contentType.startsWith('audio/')) {
      const params   = new URL(request.url).searchParams;
      turnIndex      = clampInt(params.get('turn_index'), 0, 100000);
      control        = cleanKey(params.get('control'));
      learnerSeconds = spanishNum(params.get('seconds'), 0, 300, 0);

      const bytes = await request.arrayBuffer();
      if (bytes.byteLength > 24 * 1024 * 1024) {
        return err(request, 'That recording is too long.', 413);
      }
      if (bytes.byteLength < 1200) {
        transcript = null; confidence = null;      // effectively silence
      } else {
        try {
          const heard = await spanishTranscribe(env, bytes, contentType);
          transcript  = cleanText(heard.text, 2000);
          confidence  = heard.confidence;
        } catch (e) {
          // Log what a `wrangler tail` needs to settle this in one turn: the
          // container the device sent, how much audio arrived, and the upstream
          // reply. Without these, every cause looks like "bad microphone".
          console.error('Transcription failed', {
            kind: e?.kind || 'unknown',
            content_type: contentType,
            bytes: bytes.byteLength,
            seconds: learnerSeconds,
            message: e?.message,
          });
          // The child gets a plain sentence; the bracketed code tells a parent
          // which of three very different problems they are looking at.
          const kind = e?.kind;
          return err(request,
            kind === 'format'
              ? 'This tablet records audio in a format the coach can’t read yet. [fmt]'
            : kind === 'config'
              ? 'The coach’s listening service isn’t set up right. [cfg]'
              : 'The coach couldn’t reach its listening service — try that again. [net]',
            502);
        }
      }
    } else {
      const body     = await request.json().catch(() => ({}));
      transcript     = cleanText(body.transcript, 2000);
      confidence     = Number.isFinite(Number(body.confidence)) ? Number(body.confidence) : null;
      turnIndex      = clampInt(body.turn_index, 0, 100000);
      control        = cleanKey(body.control);    // slower | repeat | meaning | direct
      learnerSeconds = spanishNum(body.audio_seconds, 0, 300, 0);
    }
    // Only speech that produced words counts. A child who holds the button for
    // thirty seconds and says nothing has recorded silence, and silence is the
    // thing this clock was rebuilt to stop charging them for.
    const learnerSecs = transcript ? (learnerSeconds || spanishSpeechSeconds(transcript)) : 0;
    const spokenSecs  = spokenBefore + learnerSecs;
    const phase       = spanishPhase(spokenSecs, targetSecs);

    // Recent history keeps the prompt bounded on long sessions.
    const histR = await query(env,
      `SELECT speaker, transcript FROM spanish_turns
        WHERE session_id = $1 ORDER BY id DESC LIMIT 16`, [sessionId]);
    const history = (histR.rows || []).reverse();

    if (transcript) {
      await query(env,
        `INSERT INTO spanish_turns
           (session_id, turn_index, speaker, transcript, transcript_confidence, audio_seconds, phase)
         VALUES ($1,$2,'learner',$3,$4,$5,$6)
         ON CONFLICT (session_id, turn_index, speaker) DO NOTHING`,
        [sessionId, turnIndex, transcript, confidence, learnerSecs, phase.key]);
    }

    const ctx = await loadSpanishContext(env, session.user_id, sess.scenario_key);
    ctx.history = history;

    let clockLine = spanishClockLine(spokenSecs, targetSecs);
    if (control) {
      const extra = {
        slower:  'The learner pressed "slower". Speak more simply and slowly for the next few turns.',
        repeat:  'The learner pressed "repeat". Say your last message again in simpler Spanish.',
        meaning: 'The learner pressed "what does that mean". Briefly explain your last message in English, then continue in Spanish.',
        direct:  'The learner pressed "correct me". For their next error, give a brief direct correction and invite them to say it again.',
      }[control];
      if (extra) clockLine += `\n[CONTROL] ${extra}`;
    }

    let result;
    try {
      result = await callClaude(env, {
        system:      buildSpanishSystem(ctx),
        content:     buildSpanishTurnContent(ctx, transcript, confidence, clockLine),
        tool:        SPANISH_TURN_TOOL,
        model:       SPANISH_TURN_MODEL,
        maxTokens:   700,
        cacheSystem: true,
      });
    } catch (e) {
      // This is the reply step, not the listening step. It used to say "had
      // trouble hearing that", one word away from the transcription failure
      // above, which made the two indistinguishable from a tablet.
      console.error('Spanish turn failed', {
        user: session.user_id,
        turn: turnIndex,
        heard_chars: transcript ? transcript.length : 0,
        history: history.length,
        message: e?.message,
      });
      return err(request, 'The coach heard you, but had trouble answering. [brain]', 502);
    }

    const replyText = cleanText(result.reply_text, 1200);
    if (!replyText) {
      console.error('Spanish turn returned no reply text', { user: session.user_id, turn: turnIndex });
      return err(request, 'The coach heard you, but came back with nothing to say. [empty]', 502);
    }

    await query(env,
      `INSERT INTO spanish_turns (session_id, turn_index, speaker, transcript, audio_seconds, phase)
       VALUES ($1,$2,'coach',$3,$4,$5)
       ON CONFLICT (session_id, turn_index, speaker) DO NOTHING`,
      [sessionId, turnIndex, replyText, spanishSpeechSeconds(replyText), phase.key]);

    // Pedagogical event — recorded server-side, never client-trusted.
    const iv = result.intervention;
    if (iv && SPANISH_INTERVENTIONS.includes(iv.intervention_type)) {
      await query(env,
        `INSERT INTO spanish_interventions
           (session_id, learner_turn_index, intervention_type, intended_meaning,
            learner_form, target_form, skill_key, importance,
            recognition_uncertain, learner_repeated_correctly)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [sessionId, turnIndex, iv.intervention_type,
         cleanText(iv.intended_meaning, 500), cleanText(iv.learner_form, 500),
         cleanText(iv.target_form, 500), cleanKey(iv.skill_key),
         clampInt(iv.importance, 1, 5), iv.recognition_uncertain === true,
         typeof iv.learner_repeated_correctly === 'boolean' ? iv.learner_repeated_correctly : null]);

      if (iv.skill_key && !iv.recognition_uncertain) {
        await applySpanishSkillEvidence(env, session.user_id, iv);
      }
    }

    for (const v of (Array.isArray(result.vocabulary) ? result.vocabulary.slice(0, 8) : [])) {
      const lemma = cleanText(v.lemma, 80);
      if (!lemma) continue;
      const correct = v.evidence === 'produced_correctly' ? 1 : 0;
      const helped  = v.evidence === 'produced_with_help' ? 1 : 0;
      await query(env,
        `INSERT INTO spanish_vocabulary
           (user_id, lemma, english_gloss, exposures, produced_correctly,
            produced_with_help, mastery, last_seen_at, next_review_at)
         VALUES ($1,$2,$3,1,$4,$5,$6,NOW(),$7)
         ON CONFLICT (user_id, lemma) DO UPDATE SET
           english_gloss      = COALESCE(EXCLUDED.english_gloss, spanish_vocabulary.english_gloss),
           exposures          = spanish_vocabulary.exposures + 1,
           produced_correctly = spanish_vocabulary.produced_correctly + EXCLUDED.produced_correctly,
           produced_with_help = spanish_vocabulary.produced_with_help + EXCLUDED.produced_with_help,
           mastery            = LEAST(0.99, spanish_vocabulary.mastery + $8),
           last_seen_at       = NOW(),
           next_review_at     = EXCLUDED.next_review_at`,
        [session.user_id, lemma, cleanText(v.english_gloss, 120), correct, helped,
         correct ? 0.25 : 0.12, spanishNextReview(correct ? 0.4 : 0.2, 0),
         correct ? 0.14 : 0.05]);
    }

    const coachSecs = spanishSpeechSeconds(replyText);
    await query(env,
      `UPDATE spanish_sessions
          SET input_audio_seconds  = input_audio_seconds + $2,
              output_audio_seconds = output_audio_seconds + $3
        WHERE id = $1`, [sessionId, learnerSecs, coachSecs]);

    let audio = null;
    try { audio = await spanishSynthesize(env, replyText, cleanText(result.emphasis_word, 60)); }
    catch (e) { console.error('TTS error', e); }

    return json(request, {
      reply_text: replyText,
      audio_b64:  audio,             // null => browser shows text only
      heard:      transcript || null, // what we transcribed, for the UI to echo
      turn_index: turnIndex,
      phase:      phase.key,
      phase_name: phase.name,
      // No clock goes to the browser. The page cannot display what it is
      // never told, which is the only reliable way to keep it invisible.
      corrected:  iv && iv.intervention_type !== 'ignore' ? iv.target_form || null : null,
    });
  });
}

// Deterministic skill EMA — the model proposes, SQL decides.
async function applySpanishSkillEvidence(env, userId, iv) {
  const skillKey = cleanKey(iv.skill_key);
  if (!skillKey) return;

  const success    = iv.learner_repeated_correctly === true ? 1 : 0;
  const recurrence = ['guided_repair', 'explicit_correction'].includes(iv.intervention_type) ? 1 : 0;

  const cur = await query(env,
    `SELECT estimate, recurrence_count FROM spanish_skills WHERE user_id = $1 AND skill_key = $2`,
    [userId, skillKey]);
  const current   = cur.rows?.[0] || { estimate: 0.20, recurrence_count: 0 };
  const weight    = clampInt(iv.importance, 1, 5) / 5;
  const estimate  = Math.max(0.02, Math.min(0.98,
    Number(current.estimate) * 0.88 + success * 0.14 * weight - recurrence * 0.08 * weight));
  const recurrences = Number(current.recurrence_count) + recurrence;

  await query(env,
    `INSERT INTO spanish_skills
       (user_id, skill_key, display_name, skill_type, evidence_count, success_count,
        recurrence_count, estimate, last_seen_at, next_review_at)
     VALUES ($1,$2,$3,$4,1,$5,$6,$7,NOW(),$8)
     ON CONFLICT (user_id, skill_key) DO UPDATE SET
       evidence_count   = spanish_skills.evidence_count + 1,
       success_count    = spanish_skills.success_count + EXCLUDED.success_count,
       recurrence_count = spanish_skills.recurrence_count + EXCLUDED.recurrence_count,
       estimate         = EXCLUDED.estimate,
       last_seen_at     = NOW(),
       next_review_at   = EXCLUDED.next_review_at`,
    [userId, skillKey,
     cleanText(iv.display_name, 120) || skillKey.replace(/_/g, ' '),
     SPANISH_SKILL_TYPES.includes(iv.skill_type) ? iv.skill_type : 'grammar',
     success, recurrence, estimate, spanishNextReview(estimate, recurrences)]);
}

// ── Session end + consolidation ────────────────────────────────
async function handleEndSpanishSession(request, env, sessionId) {
  return withUser(request, env, async (session) => {
    const sr = await query(env,
      `SELECT * FROM spanish_sessions WHERE id = $1 AND user_id = $2`, [sessionId, session.user_id]);
    const sess = sr.rows?.[0];
    if (!sess) return err(request, 'Session not found.', 404);
    if (sess.status === 'completed') {
      return json(request, { ok: true, summary: sess.summary });
    }

    const duration = Math.max(0, Math.round((Date.now() - new Date(sess.started_at).getTime()) / 1000));

    const [turnsR, ivR, profileRow] = await Promise.all([
      query(env, `SELECT speaker, transcript, phase FROM spanish_turns
                   WHERE session_id = $1 ORDER BY id`, [sessionId]),
      query(env, `SELECT intervention_type, learner_form, target_form, skill_key, importance
                    FROM spanish_interventions WHERE session_id = $1 ORDER BY id`, [sessionId]),
      getSpanishProfile(env, session.user_id),
    ]);

    const turns  = turnsR.rows || [];
    const ivs    = ivR.rows || [];
    const learnerTurns = turns.filter(t => t.speaker === 'learner');

    // Too short to be a real session — close it without spending a consolidation call.
    if (learnerTurns.length < 2) {
      await query(env,
        `UPDATE spanish_sessions SET status = 'abandoned', ended_at = NOW(), duration_seconds = $2
          WHERE id = $1`, [sessionId, duration]);
      return json(request, { ok: true, too_short: true });
    }

    const aggregates = {
      duration_seconds: duration,
      learner_turns:    learnerTurns.length,
      coach_turns:      turns.length - learnerTurns.length,
      learner_words:    learnerTurns.reduce((n, t) => n + t.transcript.split(/\s+/).length, 0),
      interventions:    ivs.length,
      by_type:          ivs.reduce((m, i) => (m[i.intervention_type] = (m[i.intervention_type] || 0) + 1, m), {}),
      skills_touched:   [...new Set(ivs.map(i => i.skill_key).filter(Boolean))],
    };

    const transcript = turns.map(t =>
      `${t.speaker === 'coach' ? 'COACH' : 'LEARNER'}: ${t.transcript}`).join('\n').slice(0, 24000);

    const topicsR = await query(env,
      `SELECT key, title, unit_order FROM spanish_topics WHERE enabled ORDER BY unit_order`, []);

    let consolidated = null;
    try {
      consolidated = await callClaude(env, {
        model:     SPANISH_CONSOLIDATE_MODEL,
        maxTokens: 2000,
        system:
`You review a finished Spanish conversation session for one child and plan the next one.

Write the parent summary using ONLY the aggregates and transcript supplied. Never invent numbers,
diagnoses, or proficiency claims. Be concrete and warm; name what actually happened.

The next lesson plan should:
- carry forward specific, personal callback hooks from THIS conversation (things the child said)
- keep working any error that recurred, and interleave due review words with new ones
- advance through the curriculum when the current unit is going well
- stay small: 4-6 target words, 1-2 structures.

Current learner profile summary: ${profileRow.profile_summary || '(none yet)'}
Curriculum units in order: ${(topicsR.rows || []).map(t => `${t.unit_order}. ${t.key}`).join(', ')}
This session used unit: ${sess.topic_key || '(none)'} and scenario: ${sess.scenario_key}`,
        content:
`AGGREGATES (authoritative)\n${JSON.stringify(aggregates, null, 2)}\n\n` +
`INTERVENTIONS\n${ivs.map(i => `${i.intervention_type}: "${i.learner_form || ''}" -> "${i.target_form || ''}" [${i.skill_key || ''}]`).join('\n') || '(none)'}\n\n` +
`TRANSCRIPT\n${transcript}`,
        tool: SPANISH_CONSOLIDATE_TOOL,
      });
    } catch (e) {
      console.error('Consolidation failed', e);
    }

    const summary = {
      aggregates,
      parent_summary:      consolidated?.parent_summary || '',
      learner_summary:     consolidated?.learner_summary || '¡Buen trabajo hoy!',
      phrases_to_remember: (consolidated?.phrases_to_remember || []).slice(0, 3),
    };

    await query(env,
      `UPDATE spanish_sessions
          SET status = 'completed', ended_at = NOW(), duration_seconds = $2, summary = $3
        WHERE id = $1`, [sessionId, duration, JSON.stringify(summary)]);

    await query(env,
      `UPDATE spanish_profiles
          SET total_seconds  = total_seconds + $2,
              total_sessions = total_sessions + 1,
              profile_summary = COALESCE($3, profile_summary),
              updated_at = NOW()
        WHERE user_id = $1`,
      [session.user_id, duration, cleanText(consolidated?.profile_summary, 2000)]);

    if (consolidated?.next_lesson_plan) {
      await query(env,
        `INSERT INTO spanish_lesson_plans (user_id, sequence, plan)
         VALUES ($1, COALESCE((SELECT MAX(sequence) FROM spanish_lesson_plans WHERE user_id = $1), 0) + 1, $2)
         ON CONFLICT (user_id, sequence) DO NOTHING`,
        [session.user_id, JSON.stringify(consolidated.next_lesson_plan)]);
    }

    // Honour transcript retention.
    if (profileRow.transcript_retention === 'none') {
      await query(env, `DELETE FROM spanish_turns WHERE session_id = $1`, [sessionId]);
    }

    return json(request, { ok: true, summary });
  });
}

// ── Profile / streak ───────────────────────────────────────────
async function spanishStreak(env, userId) {
  const r = await query(env,
    `SELECT started_at::date AS d, SUM(duration_seconds) AS secs
       FROM spanish_sessions
      WHERE user_id = $1 AND status = 'completed'
      GROUP BY 1 ORDER BY 1 DESC LIMIT 90`, [userId]);
  const days = (r.rows || []).map(x => ({ d: String(x.d).slice(0, 10), secs: Number(x.secs || 0) }));
  const set  = new Set(days.map(x => x.d));

  let streak = 0;
  const cursor = new Date();
  // Today not yet practised doesn't break a streak until tomorrow.
  if (!set.has(cursor.toISOString().slice(0, 10))) cursor.setDate(cursor.getDate() - 1);
  for (;;) {
    if (!set.has(cursor.toISOString().slice(0, 10))) break;
    streak++;
    cursor.setDate(cursor.getDate() - 1);
  }

  const today = days.find(x => x.d === new Date().toISOString().slice(0, 10));
  const weekAgo = new Date(Date.now() - 6 * 86400000).toISOString().slice(0, 10);
  return {
    streak_days:   streak,
    minutes_today: Math.round((today?.secs || 0) / 60),
    minutes_week:  Math.round(days.filter(x => x.d >= weekAgo).reduce((n, x) => n + x.secs, 0) / 60),
    recent_days:   days.slice(0, 14),
  };
}

async function handleGetSpanishProfile(request, env) {
  return withUser(request, env, async (session) => {
    const [profile, scenariosR, streak, planR] = await Promise.all([
      getSpanishProfile(env, session.user_id),
      query(env, `SELECT key, title, description FROM spanish_scenarios
                   WHERE enabled ORDER BY sort_order`, []),
      spanishStreak(env, session.user_id),
      query(env, `SELECT plan FROM spanish_lesson_plans
                   WHERE user_id = $1 AND used_by_session IS NULL
                   ORDER BY sequence DESC LIMIT 1`, [session.user_id]),
    ]);

    const lastR = await query(env,
      `SELECT summary FROM spanish_sessions
        WHERE user_id = $1 AND status = 'completed'
        ORDER BY started_at DESC LIMIT 1`, [session.user_id]);

    return json(request, {
      profile: {
        comprehension_level: profile.comprehension_level,
        production_level:    profile.production_level,
        correction_intensity: profile.correction_intensity,
        english_support:     profile.english_support,
        session_minutes:     Number(profile.session_minutes),
        weekly_minutes_goal: Number(profile.weekly_minutes_goal),
        show_direct_button:  profile.show_direct_button,
        total_sessions:      Number(profile.total_sessions),
      },
      scenarios: scenariosR.rows || [],
      streak,
      next_plan: planR.rows?.[0]?.plan || null,
      last_summary: lastR.rows?.[0]?.summary || null,
    });
  });
}

async function handlePatchSpanishProfile(request, env) {
  return withUser(request, env, async (session) => {
    const body = await request.json().catch(() => ({}));
    await getSpanishProfile(env, session.user_id);   // ensure the row exists

    const sets = [], params = [session.user_id];
    if (['immersion', 'as_needed', 'bilingual'].includes(body.english_support)) {
      params.push(body.english_support); sets.push(`english_support = $${params.length}`);
    }
    if (Array.isArray(body.interests)) {
      params.push(JSON.stringify(body.interests.slice(0, 20).map(s => String(s).slice(0, 60))));
      sets.push(`interests = $${params.length}::jsonb`);
    }
    if (!sets.length) return json(request, { ok: true });

    await query(env,
      `UPDATE spanish_profiles SET ${sets.join(', ')}, updated_at = NOW() WHERE user_id = $1`, params);
    return json(request, { ok: true });
  });
}

// ── Parent report and settings ─────────────────────────────────
async function spanishAssertSameFamily(env, parentId, studentId) {
  const me = await getMembership(env, parentId);
  if (!me || me.role !== 'parent') return 'Only a parent can do that.';
  const them = await getMembership(env, studentId);
  if (!them || them.id !== me.id) return 'That learner is not in your family.';
  return null;
}

async function handleSpanishReport(request, env, studentId) {
  return withUser(request, env, async (session) => {
    const problem = await spanishAssertSameFamily(env, session.user_id, studentId);
    if (problem) return err(request, problem, 403);

    const [profile, streak, sessionsR, skillsR, vocabR, monthR] = await Promise.all([
      getSpanishProfile(env, studentId),
      spanishStreak(env, studentId),
      query(env, `SELECT id, started_at, duration_seconds, scenario_key, topic_key, summary
                    FROM spanish_sessions
                   WHERE user_id = $1 AND status = 'completed'
                   ORDER BY started_at DESC LIMIT 14`, [studentId]),
      query(env, `SELECT skill_key, display_name, estimate, evidence_count, recurrence_count
                    FROM spanish_skills WHERE user_id = $1
                   ORDER BY recurrence_count DESC, estimate ASC LIMIT 15`, [studentId]),
      query(env, `SELECT COUNT(*) AS total,
                         COUNT(*) FILTER (WHERE produced_correctly > 0) AS produced
                    FROM spanish_vocabulary WHERE user_id = $1`, [studentId]),
      query(env, `SELECT COALESCE(SUM(input_audio_seconds + output_audio_seconds),0) AS secs
                    FROM spanish_sessions
                   WHERE user_id = $1 AND started_at >= date_trunc('month', NOW())`, [studentId]),
    ]);

    const monthMinutes = Number(monthR.rows?.[0]?.secs || 0) / 60;
    return json(request, {
      settings: {
        correction_intensity: profile.correction_intensity,
        english_support:      profile.english_support,
        session_minutes:      Number(profile.session_minutes),
        daily_session_cap:    Number(profile.daily_session_cap),
        weekly_minutes_goal:  Number(profile.weekly_minutes_goal),
        transcript_retention: profile.transcript_retention,
        show_direct_button:   profile.show_direct_button,
      },
      streak,
      totals: {
        sessions: Number(profile.total_sessions),
        minutes:  Math.round(Number(profile.total_seconds) / 60),
        vocabulary_known:    Number(vocabR.rows?.[0]?.total || 0),
        vocabulary_produced: Number(vocabR.rows?.[0]?.produced || 0),
      },
      month_audio_minutes: Math.round(monthMinutes),
      // Rough guide only: Claude turn cost + TTS at ~$0.015/min of coach speech.
      month_cost_estimate: Number((monthMinutes * 0.028).toFixed(2)),
      recent_sessions: sessionsR.rows || [],
      skills: skillsR.rows || [],
    });
  });
}

async function handlePatchSpanishSettings(request, env, studentId) {
  return withUser(request, env, async (session) => {
    const problem = await spanishAssertSameFamily(env, session.user_id, studentId);
    if (problem) return err(request, problem, 403);

    const body = await request.json().catch(() => ({}));
    await getSpanishProfile(env, studentId);

    const sets = [], params = [studentId];
    const push = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };

    if (['gentle', 'balanced', 'active'].includes(body.correction_intensity))
      push('correction_intensity', body.correction_intensity);
    if (['immersion', 'as_needed', 'bilingual'].includes(body.english_support))
      push('english_support', body.english_support);
    if ([15, 20, 30].includes(Number(body.session_minutes)))
      push('session_minutes', Number(body.session_minutes));
    if (Number.isInteger(Number(body.daily_session_cap)))
      push('daily_session_cap', clampInt(body.daily_session_cap, 1, 10));
    if (Number.isInteger(Number(body.weekly_minutes_goal)))
      push('weekly_minutes_goal', clampInt(body.weekly_minutes_goal, 0, 2000));
    if (['none', 'days_30', 'retain'].includes(body.transcript_retention))
      push('transcript_retention', body.transcript_retention);
    if (typeof body.show_direct_button === 'boolean')
      push('show_direct_button', body.show_direct_button);

    if (!sets.length) return json(request, { ok: true });
    await query(env,
      `UPDATE spanish_profiles SET ${sets.join(', ')}, updated_at = NOW() WHERE user_id = $1`, params);
    return json(request, { ok: true });
  });
}

/* ══════════════════════════════════════════════════════════════
   FLIGHT DECK — the parent dashboard
   ──────────────────────────────────────────────────────────────
   Two ideas hold this up.

   1. Time is measured by heartbeat, and the SERVER holds the
      clock. A module beats every 45 seconds while its tab is
      visible; the Worker credits the real elapsed gap, capped, so
      a client that lies (or a laptop lid that closes) can't
      inflate the number. Nothing has to remember to end a session.

   2. Progress is READ, never re-recorded. Every module already
      keeps its own real state — spelling scores, essay rows,
      Spanish sessions — so the dashboard summarises those tables
      instead of asking modules to report into a second one that
      could drift out of step with the first.
══════════════════════════════════════════════════════════════ */

const BEAT_WINDOW_SECONDS = 150; // a longer gap than this starts a new visit
const BEAT_MAX_CREDIT     = 75;  // the most a single beat can be worth

// Builds "$3,$4,$5" for an IN list and appends the ids to `params`.
// The Neon HTTP endpoint takes positional parameters only, so an
// array parameter isn't an option.
function idList(params, ids) {
  const start = params.length;
  for (const id of ids) params.push(id);
  return ids.map((_, i) => `$${start + i + 1}`).join(',');
}

// "Today" has to mean the family's today, not UTC's — a Utah
// evening is already tomorrow in UTC, and a dashboard that resets
// at 6pm is a dashboard nobody trusts. The browser sends its IANA
// zone; anything Postgres doesn't recognise falls back to UTC.
async function resolveTimeZone(env, raw) {
  const tz = String(raw || '').trim();
  if (!/^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$/.test(tz)) return 'UTC';
  try {
    await query(env, `SELECT NOW() AT TIME ZONE $1`, [tz]);
    return tz;
  } catch { return 'UTC'; }
}

async function handleActivityBeat(request, env) {
  return withUser(request, env, async (session) => {
    const body = await request.json().catch(() => ({}));
    const slug = String(body.tool || '').trim();
    if (!/^[a-z0-9-]{1,40}$/.test(slug)) return err(request, 'Unknown module.');

    // One statement: extend the open visit if there is one, open a
    // new one if there isn't. Selecting the slug out of `tools`
    // means an unrecognised module quietly records nothing rather
    // than blowing up on a foreign key.
    const r = await query(env, `
      WITH open_visit AS (
        SELECT id FROM module_sessions
         WHERE user_id = $1 AND tool_slug = $2
           AND last_beat_at > NOW() - make_interval(secs => $3::int)
         ORDER BY last_beat_at DESC
         LIMIT 1
      ), extended AS (
        UPDATE module_sessions m
           SET seconds      = m.seconds + LEAST(EXTRACT(EPOCH FROM (NOW() - m.last_beat_at))::int, $4::int),
               last_beat_at = NOW()
          FROM open_visit o
         WHERE m.id = o.id
        RETURNING m.id, m.seconds
      ), opened AS (
        INSERT INTO module_sessions (user_id, tool_slug)
        SELECT $1, t.slug FROM tools t
         WHERE t.slug = $2 AND NOT EXISTS (SELECT 1 FROM open_visit)
        RETURNING id, seconds
      )
      SELECT id, seconds FROM extended
      UNION ALL
      SELECT id, seconds FROM opened`,
      [session.user_id, slug, BEAT_WINDOW_SECONDS, BEAT_MAX_CREDIT]);

    const row = r.rows?.[0];
    return json(request, { ok: !!row, seconds: Number(row?.seconds || 0) });
  });
}

// Everything the overview needs about one family's learners, in a
// handful of set-based queries rather than a few per child.
async function handleParentsOverview(request, env) {
  const guard = await requireParentSession(request, env);
  if (guard.error) return guard.error;
  const { family } = guard;

  const tz = await resolveTimeZone(env, new URL(request.url).searchParams.get('tz'));

  const learnersR = await query(env,
    `SELECT u.id, u.email, u.display_name, u.avatar_key, u.feedback_level,
            u.last_login_at, fm.added_at
       FROM family_members fm
       JOIN users u ON u.id = fm.user_id
      WHERE fm.family_id = $1 AND fm.role = 'learner'
      ORDER BY fm.added_at`,
    [family.id]);
  const learners = learnersR.rows || [];

  // Whatever the learners can actually reach today. Bringing a new
  // module online puts it on this dashboard with no code change —
  // its time bar works immediately, and it simply has no progress
  // line until one is written for it.
  const toolsR = await query(env,
    `SELECT t.slug, t.name, t.glyph, t.accent, t.status,
            COALESCE(to_jsonb(t) ->> 'audience', 'all') AS audience
       FROM tools t
      WHERE t.status IN ('online', 'beta')
      ORDER BY t.sort_order, t.name`);
  const tools = (toolsR.rows || []).filter(t => t.audience !== 'parents');

  if (!learners.length) {
    return json(request, { family, timezone: tz, tools, students: [] });
  }

  const ids = learners.map(l => l.id);
  const p = [tz];
  const inIds = idList(p, ids);

  const timeSql = `
    WITH b AS (SELECT (date_trunc('day', NOW() AT TIME ZONE $1) AT TIME ZONE $1) AS day_start)
    SELECT m.user_id, m.tool_slug,
           SUM(m.seconds)::int AS total_seconds,
           COALESCE(SUM(m.seconds) FILTER (WHERE m.started_at >= b.day_start), 0)::int              AS today_seconds,
           COALESCE(SUM(m.seconds) FILTER (WHERE m.started_at >= NOW() - INTERVAL '7 days'), 0)::int  AS week_seconds,
           COALESCE(SUM(m.seconds) FILTER (WHERE m.started_at >= NOW() - INTERVAL '30 days'), 0)::int AS month_seconds,
           COUNT(*)::int AS visits,
           MAX(m.last_beat_at) AS last_at
      FROM module_sessions m CROSS JOIN b
     WHERE m.user_id IN (${inIds})
     GROUP BY m.user_id, m.tool_slug`;

  const idOnly = [];
  const inIdsAlone = idList(idOnly, ids);

  const [timeR, bankR, spellR, mathR, essayR, assignedR, spanishR] = await Promise.all([
    query(env, timeSql, p),
    query(env, `SELECT COUNT(*)::int AS n FROM spelling_words`),
    query(env, `
      SELECT user_id,
             COUNT(*)::int                                       AS attempted,
             (COUNT(*) FILTER (WHERE score >= 5))::int            AS mastered,
             (COUNT(*) FILTER (WHERE score BETWEEN 1 AND 4))::int AS learning,
             (COUNT(*) FILTER (WHERE score <= 0))::int            AS shaky,
             MAX(updated_at)                                      AS last_at
        FROM spelling_word_scores
       WHERE user_id IN (${inIdsAlone})
       GROUP BY user_id`, idOnly),
    query(env, `
      SELECT user_id, state, updated_at
        FROM tool_progress
       WHERE tool_slug = 'math-facts' AND user_id IN (${inIdsAlone})`, idOnly),
    query(env, `
      SELECT user_id,
             COUNT(*)::int                                          AS started,
             (COUNT(*) FILTER (WHERE status = 'graded'))::int        AS graded,
             ROUND(AVG(score_total) FILTER (WHERE status = 'graded'))::int AS avg_score,
             MAX(graded_at)                                          AS last_graded_at,
             MAX(GREATEST(draft_updated_at, COALESCE(graded_at, draft_updated_at))) AS last_at
        FROM essays
       WHERE user_id IN (${inIdsAlone})
       GROUP BY user_id`, idOnly),
    query(env, `
      SELECT user_id, COUNT(*)::int AS assigned
        FROM essay_assignment_targets
       WHERE user_id IN (${inIdsAlone})
       GROUP BY user_id`, idOnly),
    query(env, `
      SELECT p.user_id, p.total_sessions, p.total_seconds,
             p.comprehension_level, p.production_level, p.weekly_minutes_goal,
             (SELECT MAX(started_at) FROM spanish_sessions s
               WHERE s.user_id = p.user_id AND s.status = 'completed') AS last_session_at,
             (SELECT COALESCE(SUM(duration_seconds), 0)::int FROM spanish_sessions s
               WHERE s.user_id = p.user_id AND s.status = 'completed'
                 AND s.started_at >= NOW() - INTERVAL '7 days')        AS week_seconds
        FROM spanish_profiles p
       WHERE p.user_id IN (${inIdsAlone})`, idOnly),
  ]);

  const bank = Number(bankR.rows?.[0]?.n || 0);
  const byUser = (rows, key = 'user_id') => {
    const m = new Map();
    for (const row of rows || []) m.set(String(row[key]), row);
    return m;
  };
  const spell = byUser(spellR.rows), math = byUser(mathR.rows);
  const essay = byUser(essayR.rows), assigned = byUser(assignedR.rows);
  const spanish = byUser(spanishR.rows);

  const timeByUser = new Map();
  for (const row of timeR.rows || []) {
    const k = String(row.user_id);
    if (!timeByUser.has(k)) timeByUser.set(k, []);
    timeByUser.get(k).push(row);
  }

  const students = learners.map(l => {
    const k = String(l.id);
    const rows = timeByUser.get(k) || [];
    const sum = (field) => rows.reduce((a, r) => a + Number(r[field] || 0), 0);
    const lastAt = rows.reduce((a, r) => {
      const t = r.last_at ? new Date(r.last_at).getTime() : 0;
      return t > a ? t : a;
    }, 0);

    const sp = spell.get(k), es = essay.get(k), sn = spanish.get(k);
    const mathState = math.get(k)?.state || null;

    return {
      user: {
        id: l.id, email: l.email, display_name: l.display_name,
        avatar_key: l.avatar_key, feedback_level: l.feedback_level,
        last_login_at: l.last_login_at, added_at: l.added_at,
      },
      last_active_at: lastAt ? new Date(lastAt).toISOString() : null,
      time: {
        today: sum('today_seconds'),
        week:  sum('week_seconds'),
        month: sum('month_seconds'),
        total: sum('total_seconds'),
        visits: sum('visits'),
      },
      by_tool: rows.map(r => ({
        slug:   r.tool_slug,
        today:  Number(r.today_seconds || 0),
        week:   Number(r.week_seconds || 0),
        month:  Number(r.month_seconds || 0),
        total:  Number(r.total_seconds || 0),
        visits: Number(r.visits || 0),
        last_at: r.last_at,
      })),
      progress: {
        'spelling-drill': sp ? {
          bank, attempted: Number(sp.attempted), mastered: Number(sp.mastered),
          learning: Number(sp.learning), shaky: Number(sp.shaky), last_at: sp.last_at,
        } : { bank, attempted: 0, mastered: 0, learning: 0, shaky: 0, last_at: null },
        'math-facts': mathState ? {
          best: Number(mathState.best || 0),
          runs: Number(mathState.runs || 0),
          furthest: Number(mathState.furthest || 0),
          ops: mathState.ops || null,
          last_at: math.get(k)?.updated_at || null,
        } : null,
        'essay-coach': {
          assigned: Number(assigned.get(k)?.assigned || 0),
          started:  Number(es?.started || 0),
          graded:   Number(es?.graded || 0),
          avg_score: es?.avg_score == null ? null : Number(es.avg_score),
          last_graded_at: es?.last_graded_at || null,
          last_at: es?.last_at || null,
        },
        'spanish-tutor': sn ? {
          sessions: Number(sn.total_sessions || 0),
          minutes:  Math.round(Number(sn.total_seconds || 0) / 60),
          week_minutes: Math.round(Number(sn.week_seconds || 0) / 60),
          weekly_minutes_goal: Number(sn.weekly_minutes_goal || 0),
          comprehension_level: sn.comprehension_level,
          production_level:    sn.production_level,
          last_session_at:     sn.last_session_at,
        } : null,
        'code-lab': null, // lives on another site; opens are all we can see
      },
    };
  });

  return json(request, { family, timezone: tz, tools, students });
}

// The drill-down for one learner. Same family, parent only.
async function handleParentsStudent(request, env, studentId) {
  const guard = await requireParentSession(request, env);
  if (guard.error) return guard.error;
  const { family } = guard;

  const memberR = await query(env,
    `SELECT u.id, u.email, u.display_name, u.avatar_key, u.feedback_level, u.last_login_at, fm.role
       FROM family_members fm
       JOIN users u ON u.id = fm.user_id
      WHERE fm.family_id = $1 AND fm.user_id = $2`,
    [family.id, studentId]);
  const student = memberR.rows?.[0];
  if (!student) return err(request, 'That learner is not in your family.', 403);

  const tz = await resolveTimeZone(env, new URL(request.url).searchParams.get('tz'));

  const [dailyR, visitsR, spellBandsR, weakR, bankR, mathR, essaysR, spanishR, skillsR, streak] = await Promise.all([
    query(env, `
      SELECT (m.started_at AT TIME ZONE $2)::date AS day, m.tool_slug, SUM(m.seconds)::int AS seconds
        FROM module_sessions m
       WHERE m.user_id = $1 AND m.started_at >= NOW() - INTERVAL '30 days'
       GROUP BY 1, 2
       ORDER BY 1`, [studentId, tz]),
    query(env, `
      SELECT tool_slug, started_at, last_beat_at, seconds
        FROM module_sessions
       WHERE user_id = $1
       ORDER BY started_at DESC
       LIMIT 25`, [studentId]),
    query(env, `
      SELECT COUNT(*)::int                                        AS attempted,
             (COUNT(*) FILTER (WHERE score >= 5))::int             AS mastered,
             (COUNT(*) FILTER (WHERE score BETWEEN 1 AND 4))::int  AS learning,
             (COUNT(*) FILTER (WHERE score <= 0))::int             AS shaky
        FROM spelling_word_scores WHERE user_id = $1`, [studentId]),
    query(env, `
      SELECT w.word, s.score, s.updated_at
        FROM spelling_word_scores s
        JOIN spelling_words w ON w.id = s.word_id
       WHERE s.user_id = $1
       ORDER BY s.score ASC, s.updated_at DESC
       LIMIT 12`, [studentId]),
    query(env, `SELECT COUNT(*)::int AS n FROM spelling_words`),
    query(env, `SELECT state, updated_at FROM tool_progress WHERE user_id = $1 AND tool_slug = 'math-facts'`, [studentId]),
    query(env, `
      SELECT a.id, a.title, a.created_at,
             COALESCE(e.status, 'not_started') AS status,
             e.score_total, e.adaptive_score, e.graded_at, e.draft_updated_at,
             e.coaching_completed_at
        FROM essay_assignment_targets t
        JOIN essay_assignments a ON a.id = t.assignment_id
        LEFT JOIN essays e ON e.assignment_id = a.id AND e.user_id = t.user_id
       WHERE t.user_id = $1
       ORDER BY a.created_at DESC
       LIMIT 20`, [studentId]),
    query(env, `
      SELECT id, started_at, duration_seconds, scenario_key, topic_key, summary
        FROM spanish_sessions
       WHERE user_id = $1 AND status = 'completed'
       ORDER BY started_at DESC
       LIMIT 10`, [studentId]),
    query(env, `
      SELECT skill_key, display_name, estimate, evidence_count, recurrence_count
        FROM spanish_skills WHERE user_id = $1
       ORDER BY recurrence_count DESC, estimate ASC
       LIMIT 10`, [studentId]),
    spanishStreak(env, studentId).catch(() => null),
  ]);

  return json(request, {
    student,
    timezone: tz,
    daily: dailyR.rows || [],
    visits: visitsR.rows || [],
    spelling: {
      bank: Number(bankR.rows?.[0]?.n || 0),
      ...(spellBandsR.rows?.[0] || { attempted: 0, mastered: 0, learning: 0, shaky: 0 }),
      weakest: weakR.rows || [],
    },
    math: mathR.rows?.[0] ? { state: mathR.rows[0].state, updated_at: mathR.rows[0].updated_at } : null,
    essays: essaysR.rows || [],
    spanish: {
      streak,
      recent_sessions: spanishR.rows || [],
      skills: skillsR.rows || [],
    },
  });
}

// ── Router ─────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(request) });
    }

    const path   = new URL(request.url).pathname;
    const method = request.method;

    try {
      if (path === '/auth/send-otp'   && method === 'POST')  return await handleSendOtp(request, env);
      if (path === '/auth/verify-otp' && method === 'POST')  return await handleVerifyOtp(request, env);
      if (path === '/auth/logout'     && method === 'POST')  return await handleLogout(request, env);
      if (path === '/auth/me'         && method === 'GET')   return await handleMe(request, env);
      if (path === '/auth/profile'    && method === 'PATCH') return await handleUpdateProfile(request, env);

      if (path === '/family'                && method === 'GET')  return await handleGetFamily(request, env);
      if (path === '/family/create'         && method === 'POST') return await handleCreateFamily(request, env);
      if (path === '/family/members/add'    && method === 'POST') return await handleAddMember(request, env);
      if (path === '/family/members/remove' && method === 'POST') return await handleRemoveMember(request, env);
      if (path === '/family/members/feedback-level' && method === 'PATCH') return await handleSetFeedbackLevel(request, env);
      if (path === '/family/leave'          && method === 'POST') return await handleLeaveFamily(request, env);

      if (path === '/tools' && method === 'GET') return await handleListTools(request, env);

      const accessMatch = path.match(/^\/tools\/([a-z0-9-]{1,40})\/access$/);
      if (accessMatch && method === 'PATCH') return await handleSetToolAccess(request, env, accessMatch[1]);

      const progressMatch = path.match(/^\/progress\/([a-z0-9-]{1,40})$/);
      if (progressMatch && method === 'GET') return await handleGetProgress(request, env, progressMatch[1]);
      if (progressMatch && method === 'PUT') return await handlePutProgress(request, env, progressMatch[1]);

      if (path === '/spelling/words'      && method === 'GET')  return await handleGetSpellingWords(request, env);
      if (path === '/spelling/words'      && method === 'POST') return await handleAddSpellingWord(request, env);
      if (path === '/spelling/words/bulk' && method === 'POST') return await handleBulkAddSpellingWords(request, env);
      if (path === '/spelling/scores/bulk' && method === 'POST') return await handleBulkScores(request, env);

      const spellingWordMatch = path.match(/^\/spelling\/words\/([0-9a-fA-F-]{36})$/);
      if (spellingWordMatch && method === 'PATCH')  return await handleUpdateSpellingWord(request, env, spellingWordMatch[1]);
      if (spellingWordMatch && method === 'DELETE') return await handleDeleteSpellingWord(request, env, spellingWordMatch[1]);

      if (path === '/essays/assignments' && method === 'POST') return await handleCreateAssignment(request, env);
      if (path === '/essays/assignments' && method === 'GET')  return await handleListAssignments(request, env);

      const assignmentIdMatch = path.match(/^\/essays\/assignments\/([0-9a-fA-F-]{36})$/);
      if (assignmentIdMatch && method === 'PATCH')  return await handleUpdateAssignment(request, env, assignmentIdMatch[1]);
      if (assignmentIdMatch && method === 'DELETE') return await handleDeleteAssignment(request, env, assignmentIdMatch[1]);

      const essayMatch = path.match(/^\/essays\/assignments\/([0-9a-fA-F-]{36})\/essay$/);
      if (essayMatch && method === 'GET') return await handleGetEssay(request, env, essayMatch[1]);

      const draftMatch = path.match(/^\/essays\/assignments\/([0-9a-fA-F-]{36})\/essay\/draft$/);
      if (draftMatch && method === 'PUT') return await handleSaveDraft(request, env, draftMatch[1]);

      const gradeMatch = path.match(/^\/essays\/assignments\/([0-9a-fA-F-]{36})\/essay\/grade$/);
      if (gradeMatch && method === 'POST') return await handleGradeEssay(request, env, gradeMatch[1]);

      const practiceMatch = path.match(/^\/essays\/assignments\/([0-9a-fA-F-]{36})\/essay\/practice$/);
      if (practiceMatch && method === 'PUT') return await handleSavePractice(request, env, practiceMatch[1]);

      const checkMatch = path.match(/^\/essays\/assignments\/([0-9a-fA-F-]{36})\/essay\/coaching\/check$/);
      if (checkMatch && method === 'POST') return await handleCoachingCheck(request, env, checkMatch[1]);

      const resultsMatch = path.match(/^\/essays\/assignments\/([0-9a-fA-F-]{36})\/essay\/([0-9a-fA-F-]{36})\/results$/);
      if (resultsMatch && method === 'GET') return await handleGetEssayResults(request, env, resultsMatch[1], resultsMatch[2]);

      if (path === '/spanish/session' && method === 'POST') return await handleCreateSpanishSession(request, env);
      if (path === '/spanish/profile' && method === 'GET')   return await handleGetSpanishProfile(request, env);
      if (path === '/spanish/profile' && method === 'PATCH') return await handlePatchSpanishProfile(request, env);

      const spTurnMatch = path.match(/^\/spanish\/session\/([0-9a-fA-F-]{36})\/turn$/);
      if (spTurnMatch && method === 'POST') return await handleSpanishTurn(request, env, spTurnMatch[1]);

      const spEndMatch = path.match(/^\/spanish\/session\/([0-9a-fA-F-]{36})\/end$/);
      if (spEndMatch && method === 'POST') return await handleEndSpanishSession(request, env, spEndMatch[1]);

      const spReportMatch = path.match(/^\/spanish\/reports\/([0-9a-fA-F-]{36})$/);
      if (spReportMatch && method === 'GET') return await handleSpanishReport(request, env, spReportMatch[1]);

      const spSettingsMatch = path.match(/^\/spanish\/settings\/([0-9a-fA-F-]{36})$/);
      if (spSettingsMatch && method === 'PATCH') return await handlePatchSpanishSettings(request, env, spSettingsMatch[1]);

      if (path === '/activity/beat'    && method === 'POST') return await handleActivityBeat(request, env);
      if (path === '/parents/overview' && method === 'GET')  return await handleParentsOverview(request, env);

      const parentStudentMatch = path.match(/^\/parents\/students\/([0-9a-fA-F-]{36})$/);
      if (parentStudentMatch && method === 'GET') return await handleParentsStudent(request, env, parentStudentMatch[1]);

      return err(request, 'Not found', 404);
    } catch (e) {
      console.error(e);
      return err(request, `Server error: ${e.message}`, 500);
    }
  },
};
