// /api/auth  -  server-side accounts (signup / login / session) for Social Services PK
// Storage: Upstash Redis / Vercel KV via REST (no npm packages needed).
// Required env vars (Vercel adds these automatically when you connect a KV / Upstash store):
//   KV_REST_API_URL + KV_REST_API_TOKEN   (or UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN)
const crypto = require('crypto');

const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOK_ = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SESSION_SECONDS = 60 * 60 * 24 * 30; // 30 days

async function rc(cmd) {
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOK_, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

const normEmail = e => String(e || '').trim().toLowerCase();
const validEmail = e => e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const validPw = p => typeof p === 'string' && p.length >= 8 && p.length <= 200 && /[A-Za-z]/.test(p) && /\d/.test(p);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const uKey = e => 'ssp:user:' + e;
const sKey = t => 'ssp:sess:' + sha(t);
const rKey = e => 'ssp:rl:' + e;

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

async function newSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  await rc(['SET', sKey(token), email, 'EX', String(SESSION_SECONDS)]);
  return token;
}

function bearer(req) {
  const h = req.headers['authorization'] || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'method', message: 'Method not allowed.' });
  if (!URL_ || !TOK_) return send(res, 503, { ok: false, error: 'not_configured', message: 'Account server is not configured.' });

  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  b = b || {};
  const action = String(b.action || '');

  try {
    if (action === 'ping') return send(res, 200, { ok: true });

    if (action === 'signup') {
      const email = normEmail(b.email);
      const name = String(b.name || '').trim().replace(/\s+/g, ' ');
      const pw = b.password;
      if (!validEmail(email)) return send(res, 400, { ok: false, error: 'email', message: 'Please enter a valid email address.' });
      if (name.length < 2 || name.length > 80) return send(res, 400, { ok: false, error: 'name', message: 'Please enter your full name.' });
      if (!validPw(pw)) return send(res, 400, { ok: false, error: 'password', message: 'Password must be at least 8 characters and include letters and numbers.' });
      const salt = crypto.randomBytes(16).toString('hex');
      const user = { name, email, salt, hash: hashPw(pw, salt), created: Date.now() };
      // SET ... NX is atomic: only one signup can ever win for an email
      const ok = await rc(['SET', uKey(email), JSON.stringify(user), 'NX']);
      if (ok !== 'OK') return send(res, 409, { ok: false, error: 'exists', message: 'This email is already registered. Please sign in instead.' });
      const token = await newSession(email);
      return send(res, 200, { ok: true, token, user: { name, email } });
    }

    if (action === 'login') {
      const email = normEmail(b.email);
      const pw = String(b.password || '');
      if (!validEmail(email)) return send(res, 400, { ok: false, error: 'email', message: 'Please enter a valid email address.' });
      const fails = parseInt(await rc(['GET', rKey(email)]) || '0', 10);
      if (fails >= 5) {
        const ms = Math.max(1000, parseInt(await rc(['PTTL', rKey(email)]), 10) || 60000);
        return send(res, 429, { ok: false, error: 'locked', message: 'Too many attempts. Please try again in ' + Math.ceil(ms / 1000) + ' seconds.' });
      }
      const raw = await rc(['GET', uKey(email)]);
      let good = false, u = null;
      if (raw) {
        u = JSON.parse(raw);
        const a = Buffer.from(hashPw(pw, u.salt), 'hex'), c = Buffer.from(u.hash, 'hex');
        good = a.length === c.length && crypto.timingSafeEqual(a, c);
      } else {
        hashPw(pw, 'x'.repeat(32)); // keep timing similar when the email does not exist
      }
      if (!good) {
        await rc(['INCR', rKey(email)]);
        await rc(['EXPIRE', rKey(email), '60']);
        return send(res, 401, { ok: false, error: 'invalid', message: 'Incorrect email or password.' });
      }
      await rc(['DEL', rKey(email)]);
      const token = await newSession(email);
      return send(res, 200, { ok: true, token, user: { name: u.name, email: u.email } });
    }

    if (action === 'me') {
      const t = bearer(req);
      if (!t) return send(res, 401, { ok: false, error: 'session', message: 'Please sign in.' });
      const email = await rc(['GET', sKey(t)]);
      const raw = email ? await rc(['GET', uKey(email)]) : null;
      if (!raw) return send(res, 401, { ok: false, error: 'session', message: 'Please sign in.' });
      await rc(['EXPIRE', sKey(t), String(SESSION_SECONDS)]);
      const u = JSON.parse(raw);
      return send(res, 200, { ok: true, user: { name: u.name, email: u.email } });
    }

    if (action === 'logout') {
      const t = bearer(req);
      if (t) await rc(['DEL', sKey(t)]);
      return send(res, 200, { ok: true });
    }

    return send(res, 400, { ok: false, error: 'action', message: 'Unknown action.' });
  } catch (e) {
    console.error('auth error', e && e.message);
    return send(res, 500, { ok: false, error: 'server', message: 'Something went wrong. Please try again.' });
  }
};
