// Vercel serverless function: subscription orders (payment proof + owner approval)
// Uses the same Upstash Redis connection as api/products.js and the same ADMIN_PASSWORD.
const crypto = require('crypto');

const RURL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const RTOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const METHODS = ['Easypaisa', 'Askari Bank', 'NayaPay'];
const STATUSES = ['waiting', 'active', 'rejected'];

async function rc(cmd) {
  if (!RURL || !RTOK) throw new Error('storage-not-connected');
  const r = await fetch(RURL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + RTOK, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || 'storage-error');
  return j.result;
}

function isAdmin(req) {
  const pw = process.env.ADMIN_PASSWORD || '';
  const h = String(req.headers['x-admin-password'] || '');
  if (!pw || !h) return false;
  const a = Buffer.from(h), b = Buffer.from(pw);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const all = async () => ((await rc(['HVALS', 'ssp:orders'])) || []).map(s => { try { return JSON.parse(s); } catch (e) { return null; } }).filter(Boolean);

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, obj) => res.status(code).json(obj);
  try {
    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
    body = body || {};
    const q = req.query || {};

    if (req.method === 'GET') {
      if (q.shot) {
        if (!isAdmin(req)) return send(401, { error: 'Unauthorized' });
        const shot = await rc(['GET', 'ssp:shot:' + clean(q.shot, 40)]);
        return send(200, { shot: shot || '' });
      }
      if (q.all) {
        if (!isAdmin(req)) return send(401, { error: 'Unauthorized' });
        const list = (await all()).sort((a, b) => b.t - a.t);
        return send(200, { orders: list });
      }
      const email = clean(q.email, 120).toLowerCase();
      if (!email) return send(400, { error: 'Email required' });
      const mine = (await all()).filter(o => o.email === email).sort((a, b) => b.t - a.t)
        .map(o => ({ id: o.id, product: o.product, price: o.price, duration: o.duration, status: o.status, t: o.t }));
      return send(200, { orders: mine });
    }

    if (req.method === 'POST' && body.action === 'create') {
      const o = body.order || {};
      const email = clean(o.email, 120).toLowerCase();
      const wa = clean(o.whatsapp, 20).replace(/\D/g, '');
      const txid = clean(o.txid, 40);
      const rec = {
        id: 'SSP-' + Date.now().toString(36).toUpperCase().slice(-5) + crypto.randomBytes(2).toString('hex').toUpperCase(),
        product: clean(o.product, 80), duration: clean(o.duration, 40), price: Number(o.price) || 0,
        name: clean(o.name, 80), email, whatsapp: wa, method: clean(o.method, 30), txid,
        status: 'waiting', t: Date.now()
      };
      const shot = String(o.screenshot || '');
      if (!rec.product) return send(400, { error: 'Product missing.' });
      if (rec.name.length < 2) return send(400, { error: 'Please enter your name.' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return send(400, { error: 'Please enter a valid email.' });
      if (wa.length < 10 || wa.length > 15) return send(400, { error: 'Please enter a valid WhatsApp number.' });
      if (!METHODS.includes(rec.method)) return send(400, { error: 'Please select the payment method you used.' });
      if (txid.length < 6) return send(400, { error: 'Please enter a valid Transaction ID.' });
      if (!/^data:image\/(jpeg|png|webp);base64,/.test(shot) || shot.length > 600000) return send(400, { error: 'Please upload a valid payment screenshot.' });

      const ip = String(req.headers['x-forwarded-for'] || 'x').split(',')[0].trim();
      const rk = 'ssp:rl:' + ip;
      const n = await rc(['INCR', rk]);
      if (n === 1) await rc(['EXPIRE', rk, 3600]);
      if (n > 12) return send(429, { error: 'Too many orders. Please try again later.' });

      const dup = (await all()).find(x => x.txid.toLowerCase() === txid.toLowerCase() && x.status !== 'rejected');
      if (dup) return send(409, { error: 'This Transaction ID was already submitted.' });

      await rc(['SET', 'ssp:shot:' + rec.id, shot]);
      await rc(['HSET', 'ssp:orders', rec.id, JSON.stringify(rec)]);
      return send(200, { ok: true, id: rec.id });
    }

    if (req.method === 'POST' && body.action === 'status') {
      if (!isAdmin(req)) return send(401, { error: 'Unauthorized' });
      const id = clean(body.id, 40);
      if (!STATUSES.includes(body.status)) return send(400, { error: 'Invalid status' });
      const raw = await rc(['HGET', 'ssp:orders', id]);
      if (!raw) return send(404, { error: 'Order not found' });
      const rec = JSON.parse(raw);
      rec.status = body.status; rec.updated = Date.now();
      await rc(['HSET', 'ssp:orders', id, JSON.stringify(rec)]);
      return send(200, { ok: true, order: rec });
    }

    if (req.method === 'DELETE') {
      if (!isAdmin(req)) return send(401, { error: 'Unauthorized' });
      const id = clean(body.id, 40);
      await rc(['HDEL', 'ssp:orders', id]);
      await rc(['DEL', 'ssp:shot:' + id]);
      return send(200, { ok: true });
    }

    return send(405, { error: 'Method not allowed' });
  } catch (e) {
    return send(500, { error: e.message === 'storage-not-connected' ? 'storage-not-connected' : 'Server error' });
  }
};
