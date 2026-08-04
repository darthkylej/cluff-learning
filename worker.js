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

function clampInt(v, lo, hi) {
  const n = Math.round(Number(v) || 0);
  return Math.max(lo, Math.min(hi, n));
}

async function callClaude(env, { system, content, tool }) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 8000,
      system,
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

function buildGradingSystemPrompt(assignment, issueHistory) {
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

Segment the essay into sentences covering the ENTIRE text with nothing omitted or reworded, and call the submit_essay_grade tool with your complete result. Be specific in every note — cite the actual words, not just the category.`;
}

function buildCoachingCheckPrompt(issue) {
  return `You are coaching a student revising their own essay. Here is one specific issue that was flagged:

Type: ${issue.issue_type}
Original problem: ${issue.description}
${issue.quote ? `Original text: "${issue.quote}"` : ''}

Below is the student's CURRENT full essay text after revision. Judge whether this specific issue has been genuinely, reasonably addressed.
- "resolved": clearly fixed.
- "partial": a real, good-faith attempt that improves things, even if not perfect.
- "not_addressed": the issue is still there, or the student didn't seriously try.
Be encouraging but honest — don't rubber-stamp a fix that isn't there, but don't demand perfection either. Call submit_fix_verdict with your result.`;
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
        system: buildGradingSystemPrompt(assignment, historyR.rows || []),
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

    return json(request, { ok: true, adaptive_score: adaptiveScore, feedback: stripScoresForLearner(feedback), coaching });
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
        system: buildCoachingCheckPrompt(issue),
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

      return err(request, 'Not found', 404);
    } catch (e) {
      console.error(e);
      return err(request, `Server error: ${e.message}`, 500);
    }
  },
};
