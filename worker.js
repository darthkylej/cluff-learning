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
     POST   /family/leave

     GET    /tools
     PATCH  /tools/:slug/access

     GET    /progress/:slug
     PUT    /progress/:slug

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
    `SELECT s.id AS session_id, u.id AS user_id, u.email, u.display_name, u.avatar_key, u.is_admin
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
    `SELECT id, email, display_name, avatar_key, is_admin FROM users WHERE id = $1`, [userId]);
  const user = r.rows[0];
  const family = await getMembership(env, userId);
  return {
    id: user.id,
    email: user.email,
    display_name: user.display_name,
    avatar_key: user.avatar_key,
    is_admin: user.is_admin,
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
      `SELECT u.id, u.email, u.display_name, u.avatar_key, fm.role, fm.added_at, u.last_login_at
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
    const r = await query(env,
      `SELECT t.slug, t.name, t.tagline, t.description, t.glyph, t.accent, t.status, t.url,
              COALESCE(ta.enabled, true) AS enabled
         FROM tools t
         LEFT JOIN tool_access ta ON ta.tool_slug = t.slug AND ta.user_id = $1
        ORDER BY t.sort_order, t.name`,
      [session.user_id]);
    return json(request, { tools: r.rows || [] });
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

      return err(request, 'Not found', 404);
    } catch (e) {
      console.error(e);
      return err(request, `Server error: ${e.message}`, 500);
    }
  },
};
