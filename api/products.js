// Vercel serverless function: products API (public read, password-protected write)
const crypto = require('crypto');

// ===== OWNER PASSWORD (stays on the server, visitors can never see it) =====
const PASSWORD = 'Sk7#vQ9mLp2!';

const RURL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const RTOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const KEY = 'products';

const sha = s => crypto.createHash('sha256').update(String(s || '')).digest();
const okPass = p => crypto.timingSafeEqual(sha(p), sha(PASSWORD));
const clean = (v, n) => String(v == null ? '' : v).trim().slice(0, n);

async function redis(cmd) {
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

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.method === 'GET') {
      const flat = (await redis(['HGETALL', KEY])) || [];
      const products = [];
      for (let i = 0; i < flat.length; i += 2) {
        try { products.push(JSON.parse(flat[i + 1])); } catch (e) {}
      }
      return res.status(200).json({ products });
    }

    if (req.method === 'POST' || req.method === 'DELETE') {
      if (!okPass(req.headers['x-admin-password'])) {
        await new Promise(r => setTimeout(r, 800));
        return res.status(401).json({ error: 'Incorrect password.' });
      }
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});

      if (req.method === 'DELETE') {
        const id = clean(body.id, 40);
        if (!id) return res.status(400).json({ error: 'Missing product id.' });
        await redis(['HDEL', KEY, id]);
        return res.status(200).json({ ok: true });
      }

      if (body.action === 'login') return res.status(200).json({ ok: true });

      const p = body.product || {};
      const name = clean(p.name, 80);
      const price = Number(p.price);
      if (!name) return res.status(400).json({ error: 'Please enter the product name.' });
      if (!isFinite(price) || price < 0) return res.status(400).json({ error: 'Please enter a valid price.' });
      const old = Number(p.old_price);
      let image = '';
      if (p.image) {
        image = String(p.image);
        if (!/^data:image\/(png|jpe?g|webp|gif);base64,/.test(image) || image.length > 500000)
          return res.status(400).json({ error: 'Image is not valid or too large.' });
      }
      const id = 'p' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
      const item = {
        id, name,
        category: clean(p.category, 40),
        duration: clean(p.duration, 40),
        price,
        old_price: p.old_price !== '' && p.old_price != null && isFinite(old) && old >= 0 ? old : null,
        badge: clean(p.badge, 24),
        features: String(p.features || '').slice(0, 800),
        image,
        in_stock: p.in_stock !== false,
        t: Date.now()
      };
      await redis(['HSET', KEY, id, JSON.stringify(item)]);
      return res.status(200).json({ ok: true, product: item });
    }

    res.setHeader('Allow', 'GET, POST, DELETE');
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    const nc = e.message === 'storage-not-connected';
    return res.status(nc ? 503 : 500).json({ error: nc ? 'storage-not-connected' : 'Server error' });
  }
};
