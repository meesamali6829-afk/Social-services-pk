"""
Social Services PK - Flask backend + Admin Dashboard (Vercel ready)

Public site : /
Admin panel : /admin

Data and images are stored in a Redis database (Upstash), because Vercel
cannot save files. Required environment variables on Vercel:
    KV_REST_API_URL, KV_REST_API_TOKEN   (added automatically when you connect Upstash Redis)
    ADMIN_PASSWORD                       (your admin panel password)
Optional: SECRET_KEY
"""
import os, io, json, uuid, hmac, math, time, base64, hashlib, re, threading
import urllib.request, urllib.error
from datetime import timedelta
from functools import wraps
from flask import (Flask, request, jsonify, session, send_from_directory,
                   render_template_string, redirect, abort, Response)
from werkzeug.middleware.proxy_fix import ProxyFix
from PIL import Image, ImageOps

BASE = os.path.dirname(os.path.abspath(__file__))
ON_VERCEL = bool(os.environ.get("VERCEL"))
KV_URL = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
LOCAL_DIR = os.path.join(BASE, "local_store")  # only used when running on your own computer

# Admin password: set ADMIN_PASSWORD in Vercel > Settings > Environment Variables.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "wteRQChZk9cUkc#14"
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif"}

DEFAULT_SETTINGS = {
    "name": "Social Services PK",
    "tagline": "Premium digital subscriptions and social services",
    "whatsapp": "923005591403",
    "email": "",
    "phone": "03005591403",
    "currency": "Rs.",
    "hero_image": "",
}

app = Flask(__name__, static_folder=None)
# Work correctly behind a hosting proxy / nginx (real client IP + https).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,  # Vercel allows about 4.5 MB per request
    SESSION_COOKIE_SECURE=ON_VERCEL,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="sspk_admin",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


app.secret_key = os.environ.get("SECRET_KEY") or hashlib.sha256(
    ("sspk-session|" + ADMIN_PASSWORD).encode()).hexdigest()
_lock = threading.Lock()


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.path.startswith("/admin"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ----------------------------------------------------------------- storage
class StorageError(Exception):
    pass


def _kv(*cmd):
    """Run one Redis command through the Upstash REST API."""
    req = urllib.request.Request(
        KV_URL, data=json.dumps(list(cmd)).encode(), method="POST",
        headers={"Authorization": "Bearer " + KV_TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            out = json.loads(r.read().decode())
    except Exception as e:
        raise StorageError("Database error: %s" % e)
    if out.get("error"):
        raise StorageError("Database error: %s" % out["error"])
    return out.get("result")


def _local_path(key):
    os.makedirs(LOCAL_DIR, exist_ok=True)
    return os.path.join(LOCAL_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", key))


def store_get(key):
    if KV_URL and KV_TOKEN:
        return _kv("GET", key)
    if ON_VERCEL:
        raise StorageError("Database not connected. Add Upstash Redis in Vercel > Storage.")
    p = _local_path(key)
    return open(p, encoding="utf-8").read() if os.path.exists(p) else None


def store_set(key, value):
    if KV_URL and KV_TOKEN:
        _kv("SET", key, value)
        return
    if ON_VERCEL:
        raise StorageError("Database not connected. Add Upstash Redis in Vercel > Storage.")
    with open(_local_path(key), "w", encoding="utf-8") as f:
        f.write(value)


def store_del(key):
    if KV_URL and KV_TOKEN:
        _kv("DEL", key)
    elif not ON_VERCEL and os.path.exists(_local_path(key)):
        os.remove(_local_path(key))


def load():
    raw = store_get("ssp:data")
    d = json.loads(raw) if raw else {"settings": {}, "products": []}
    d["settings"] = {**DEFAULT_SETTINGS, **d.get("settings", {})}
    d.setdefault("products", [])
    return d


def save(d):
    store_set("ssp:data", json.dumps(d, ensure_ascii=False))


def save_image(file):
    """Validate, shrink and store an uploaded image. Returns the image name or ''."""
    if not file or not file.filename:
        return ""
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_EXT:
        abort(400, "Only PNG, JPG, WEBP or GIF images are allowed.")
    try:
        img = Image.open(file.stream)
        img = ImageOps.exif_transpose(img)
        img.thumbnail((1400, 1400))
        img = img.convert("RGBA" if img.mode in ("RGBA", "LA", "P") else "RGB")
    except Exception:
        abort(400, "File is not a valid image.")
    data = b""
    for q in (82, 70, 55, 40):
        buf = io.BytesIO()
        img.save(buf, "WEBP", quality=q)
        data = buf.getvalue()
        if len(data) < 700_000:
            break
    name = uuid.uuid4().hex + ".webp"
    store_set("ssp:img:" + name, base64.b64encode(data).decode())
    return name


def remove_image(name):
    if name and re.fullmatch(r"[a-f0-9]{32}\.webp", name):
        try:
            store_del("ssp:img:" + name)
        except StorageError:
            pass


# -------------------------------------------------------------------- auth
_fails = {}


def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get("admin"):
            return jsonify(error="Please log in again."), 401
        return fn(*a, **k)
    return w


# ------------------------------------------------------------ public routes
@app.route("/")
def index():
    return send_from_directory(BASE, "index.html")


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\n", mimetype="text/plain")


@app.route("/uploads/<name>")
def uploads(name):
    if not re.fullmatch(r"[a-f0-9]{32}\.webp", name):
        abort(404)
    raw = store_get("ssp:img:" + name)
    if not raw:
        abort(404)
    resp = Response(base64.b64decode(raw), mimetype="image/webp")
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.route("/api/site")
def api_site():
    d = load()
    resp = jsonify(settings=d["settings"], products=d["products"])
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ------------------------------------------------------------- admin pages
@app.route("/admin")
def admin():
    if not session.get("admin"):
        return render_template_string(
            LOGIN_HTML, error=LOGIN_ERRORS.get(request.args.get("e", "")))
    return render_template_string(ADMIN_HTML)


LOGIN_ERRORS = {
    "bad": "Incorrect password.",
    "locked": "Too many attempts. Try again in 5 minutes.",
}


@app.route("/admin/login", methods=["POST"])
def admin_login():
    ip = request.remote_addr or "x"
    now = time.time()
    rec = _fails.get(ip, [0, 0])
    if rec[1] < now:  # previous lock/window expired
        rec = [0, 0]
    if rec[0] >= 5:
        return redirect("/admin?e=locked")
    pw = request.form.get("password", "")
    if hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode()):
        _fails.pop(ip, None)
        session.clear()
        session.permanent = True
        session["admin"] = True
        return redirect("/admin")
    _fails[ip] = [rec[0] + 1, now + 300]
    if len(_fails) > 2000:  # keep memory bounded
        for k in [k for k, v in _fails.items() if v[1] < now]:
            _fails.pop(k, None)
    time.sleep(0.6)
    return redirect("/admin?e=" + ("locked" if rec[0] + 1 >= 5 else "bad"))


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect("/admin")


# --------------------------------------------------------------- admin API
@app.route("/admin/api/product", methods=["POST"])
@login_required
def save_product():
    f = request.form
    name = f.get("name", "").strip()
    try:
        price = float(f.get("price", ""))
        if not math.isfinite(price) or price < 0:
            raise ValueError
    except ValueError:
        return jsonify(error="Please enter a valid price."), 400
    if not name:
        return jsonify(error="Product name is required."), 400
    try:
        old = float(f.get("old_price")) if f.get("old_price") else None
        if old is not None and (not math.isfinite(old) or old < 0):
            old = None
    except ValueError:
        old = None
    pid = f.get("id") or uuid.uuid4().hex[:10]
    with _lock:
        d = load()
        existing = next((p for p in d["products"] if p["id"] == pid), None)
        image = existing["image"] if existing else ""
        new_img = save_image(request.files.get("image"))
        if new_img:
            remove_image(image)
            image = new_img
        prod = {
            "id": pid, "name": name[:80], "category": f.get("category", "").strip()[:40],
            "price": price, "old_price": old, "duration": f.get("duration", "").strip()[:40],
            "badge": f.get("badge", "").strip()[:24], "features": f.get("features", "")[:800],
            "image": image, "in_stock": f.get("in_stock") == "1",
        }
        if existing:
            d["products"] = [prod if p["id"] == pid else p for p in d["products"]]
        else:
            d["products"].append(prod)
        save(d)
    return jsonify(ok=True)


@app.route("/admin/api/product/<pid>", methods=["DELETE"])
@login_required
def delete_product(pid):
    with _lock:
        d = load()
        for p in d["products"]:
            if p["id"] == pid:
                remove_image(p.get("image"))
        d["products"] = [p for p in d["products"] if p["id"] != pid]
        save(d)
    return jsonify(ok=True)


@app.route("/admin/api/settings", methods=["POST"])
@login_required
def save_settings():
    f = request.form
    with _lock:
        d = load()
        s = d["settings"]
        for k in ("name", "tagline", "email", "phone", "currency"):
            s[k] = f.get(k, s[k]).strip()[:120] or DEFAULT_SETTINGS[k]
        digits = "".join(c for c in f.get("whatsapp", "") if c.isdigit())
        if digits.startswith("0"):
            digits = "92" + digits[1:]
        s["whatsapp"] = digits or DEFAULT_SETTINGS["whatsapp"]
        new_img = save_image(request.files.get("hero_image"))  # validates first
        if new_img:
            remove_image(s["hero_image"])
            s["hero_image"] = new_img
        elif f.get("remove_hero") == "1":
            remove_image(s["hero_image"])
            s["hero_image"] = ""
        save(d)
    return jsonify(ok=True)


@app.errorhandler(400)
def bad(e):
    return jsonify(error=getattr(e, "description", "Bad request")), 400


@app.errorhandler(StorageError)
def storage_err(e):
    if request.path.startswith("/admin/api") or request.path == "/api/site":
        return jsonify(error=str(e)), 500
    return str(e), 500


@app.errorhandler(413)
def big(e):
    return jsonify(error="File is too large (max 4 MB)."), 413


# ----------------------------------------------------------------- templates
LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Playfair+Display:wght@600;700&display=swap">
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(160deg,#062217,#14543a);font-family:Inter,sans-serif;padding:20px}
.c{background:#fff;border-radius:16px;padding:40px 34px;width:100%;max-width:400px;box-shadow:0 30px 60px rgba(0,0,0,.35)}
h1{font-family:'Playfair Display',serif;margin:0 0 4px;color:#0f3d2e;font-size:28px}p{color:#5b6e64;margin:0 0 24px;font-size:14px}
label{font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#5b6e64}
input{width:100%;padding:13px;margin:8px 0 18px;border:1px solid #d5e3db;border-radius:8px;font-size:16px}
button{width:100%;padding:14px;border:0;border-radius:8px;background:#14543a;color:#fff;font-weight:600;font-size:15px;cursor:pointer}
button:hover{background:#0f3d2e}.e{background:#fdecea;color:#a93226;padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:16px}</style></head>
<body><form class="c" method="post" action="/admin/login"><h1>Social Services PK</h1><p>Administrator sign in</p>
{% if error %}<div class="e">{{ error }}</div>{% endif %}
<label>Password</label><input type="password" name="password" autofocus required><button>Sign In</button></form></body></html>"""

ADMIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Dashboard - Social Services PK</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Playfair+Display:wght@600;700&display=swap">
<style>
:root{--g9:#0a2e21;--g8:#0f3d2e;--g7:#14543a;--g5:#2e9967;--bd:#dbe7e0;--mut:#5b6e64;--gold:#b8923a}
*{box-sizing:border-box}body{margin:0;background:#f2f7f4;font-family:Inter,sans-serif;color:#14231c}
header{background:var(--g9);color:#fff;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
header b{font-family:'Playfair Display',serif;font-size:20px;letter-spacing:.01em}header div{display:flex;gap:10px}
.wrap{max-width:900px;margin:0 auto;padding:10px 18px 60px}
.card{background:#fff;border:1px solid var(--bd);border-radius:14px;padding:26px;margin:20px 0}
h2{font-family:'Playfair Display',serif;color:var(--g8);margin:0 0 4px;font-size:22px}.hint{color:var(--mut);font-size:14px;margin:0 0 6px}
label{display:block;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin:16px 0 6px}
input,textarea{width:100%;padding:12px;border:1px solid var(--bd);border-radius:8px;font:16px Inter,sans-serif;background:#fff}
input:focus,textarea:focus{outline:2px solid var(--g5);border-color:transparent}textarea{min-height:100px;resize:vertical}
.r{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.btn{border:0;border-radius:8px;padding:12px 22px;font:600 14px Inter,sans-serif;cursor:pointer;background:var(--g7);color:#fff;text-decoration:none;display:inline-block}
.btn:hover{background:var(--g8)}.btn.l{background:transparent;color:inherit;border:1px solid currentColor}header .btn.l{color:#cfe7da}
.btn.s{padding:8px 14px;font-size:13px}.btn.d{background:#b3382c}.btn.o{background:#fff;color:var(--g8);border:1px solid var(--bd)}
.pv{max-width:240px;width:100%;aspect-ratio:16/10;object-fit:cover;border-radius:10px;margin-top:10px;display:block;border:1px solid var(--bd)}
.ck{display:flex;gap:8px;align-items:center;margin-top:16px;font-size:15px}.ck input{width:auto}
.it{display:flex;gap:14px;align-items:center;padding:14px 0;border-top:1px solid var(--bd)}
.it img,.it i{width:76px;height:50px;border-radius:8px;object-fit:cover;background:var(--g7);flex:none}
.it div.t{flex:1;min-width:0}.it b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--g8)}.it span{color:var(--mut);font-size:13px}
.a{display:flex;gap:6px}#t{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--g9);color:#fff;padding:12px 22px;border-radius:99px;font-size:14px;display:none;z-index:9}
@media(max-width:640px){.r{grid-template-columns:1fr}.it{flex-wrap:wrap}.a{width:100%}}
</style></head><body>
<header><b>Social Services PK &nbsp;/&nbsp; Admin</b><div><a class="btn l s" href="/" target="_blank">View website</a>
<form method="post" action="/admin/logout" style="margin:0"><button class="btn l s">Log out</button></form></div></header>
<div class="wrap">
<div class="card"><h2 id="ft">Add new product</h2><p class="hint">Fill in the details and press Publish. It goes live on the website immediately.</p>
<form id="pf"><input type="hidden" name="id" id="pid">
<label>Product / subscription name *</label><input name="name" id="name" required placeholder="e.g. Netflix Premium">
<div class="r"><div><label>Category</label><input name="category" id="category" placeholder="e.g. Streaming"></div><div><label>Duration</label><input name="duration" id="duration" placeholder="e.g. 1 Month"></div></div>
<div class="r"><div><label>Price *</label><input name="price" id="price" type="number" step="any" required></div><div><label>Old price (optional)</label><input name="old_price" id="old_price" type="number" step="any"></div></div>
<label>Badge (optional)</label><input name="badge" id="badge" placeholder="e.g. Best Seller">
<label>Details (one point per line)</label><textarea name="features" id="features" placeholder="4K Ultra HD&#10;Private profile&#10;Full warranty"></textarea>
<label>Product picture</label><input type="file" name="image" id="image" accept="image/*"><img id="pv" class="pv" style="display:none" alt="">
<label class="ck"><input type="checkbox" id="in_stock" checked> Available (in stock)</label>
<p style="margin:20px 0 0;display:flex;gap:8px;flex-wrap:wrap"><button class="btn" id="sb">Publish to website</button><button type="button" class="btn o" id="cn" style="display:none">Cancel edit</button></p></form></div>
<div class="card"><h2>Live products <span id="cnt"></span></h2><p class="hint">Currently visible on your website.</p><div id="list"></div></div>
<div class="card"><h2>Website settings</h2><p class="hint">Business information, WhatsApp number and hero banner image.</p>
<form id="sf"><div class="r"><div><label>Business name</label><input name="name" id="s_name"></div><div><label>Currency</label><input name="currency" id="s_currency"></div></div>
<label>Tagline</label><input name="tagline" id="s_tagline">
<label>WhatsApp number (orders go here)</label><input name="whatsapp" id="s_whatsapp" inputmode="numeric" placeholder="03005591403 or 923005591403">
<div class="r"><div><label>Email</label><input name="email" id="s_email"></div><div><label>Phone</label><input name="phone" id="s_phone"></div></div>
<label>Hero banner image (optional, wide image works best)</label><input type="file" name="hero_image" accept="image/*"><img id="hv" class="pv" style="display:none" alt="">
<label class="ck" id="rh" style="display:none"><input type="checkbox" id="remove_hero"> Remove custom banner (use default artwork)</label>
<p style="margin:20px 0 0"><button class="btn">Save settings</button></p></form></div></div>
<div id="t"></div>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let D={products:[],settings:{}},delId=null;
function toast(m){const t=$('#t');t.textContent=m;t.style.display='block';clearTimeout(t._)&&0;t._=setTimeout(()=>t.style.display='none',2800)}
async function call(url,opt){const r=await fetch(url,opt);let j={};try{j=await r.json()}catch(e){}if(r.status===401){location.reload();throw 0}if(!r.ok)throw new Error(j.error||'Something went wrong');return j}
async function load(){D=await (await fetch('/api/site',{cache:'no-store'})).json();draw()}
function draw(){const s=D.settings;$('#cnt').textContent='('+D.products.length+')';
 $('#list').innerHTML=D.products.length?D.products.map(p=>`<div class="it">${p.image?`<img src="/uploads/${esc(p.image)}" alt="">`:'<i></i>'}<div class="t"><b>${esc(p.name)}</b><span>${esc(s.currency)} ${p.price}${p.duration?' · '+esc(p.duration):''}${p.in_stock?'':' · Out of stock'}</span></div>
 <div class="a"><button class="btn o s" data-e="${p.id}">Edit</button><button class="btn d s" data-d="${p.id}">${delId===p.id?'Confirm delete':'Delete'}</button></div></div>`).join(''):'<p class="hint">No products yet.</p>';
 for(const k of ['name','tagline','whatsapp','email','phone','currency'])$('#s_'+k).value=s[k]||'';
 $('#hv').style.display=s.hero_image?'block':'none';if(s.hero_image)$('#hv').src='/uploads/'+s.hero_image;$('#rh').style.display=s.hero_image?'flex':'none';
 document.querySelectorAll('[data-e]').forEach(b=>b.onclick=()=>edit(b.dataset.e));
 document.querySelectorAll('[data-d]').forEach(b=>b.onclick=async()=>{if(delId!==b.dataset.d){delId=b.dataset.d;return draw()}
  try{await call('/admin/api/product/'+delId,{method:'DELETE'});delId=null;toast('Product deleted');load()}catch(e){toast(e.message)}})}
function reset(){$('#pf').reset();$('#pid').value='';$('#pv').style.display='none';$('#ft').textContent='Add new product';$('#sb').textContent='Publish to website';$('#cn').style.display='none'}
function edit(id){const p=D.products.find(x=>x.id===id);if(!p)return;$('#pid').value=p.id;
 for(const k of ['name','category','duration','price','badge','features'])$('#'+k).value=p[k]||'';$('#old_price').value=p.old_price||'';$('#in_stock').checked=p.in_stock;
 $('#pv').style.display=p.image?'block':'none';if(p.image)$('#pv').src='/uploads/'+p.image;$('#ft').textContent='Edit product';$('#sb').textContent='Update product';$('#cn').style.display='inline-block';scrollTo({top:0,behavior:'smooth'})}
$('#cn').onclick=reset;
$('#image').onchange=e=>{const f=e.target.files[0];if(f){$('#pv').src=URL.createObjectURL(f);$('#pv').style.display='block'}};
$('#pf').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);fd.set('in_stock',$('#in_stock').checked?'1':'0');
 try{await call('/admin/api/product',{method:'POST',body:fd});toast('Published. Your website is updated.');reset();load()}catch(x){toast(x.message)}};
$('#sf').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);fd.set('remove_hero',$('#remove_hero').checked?'1':'0');
 try{await call('/admin/api/settings',{method:'POST',body:fd});toast('Settings saved');e.target.querySelector('[type=file]').value='';$('#remove_hero').checked=false;load()}catch(x){toast(x.message)}};
load();
</script></body></html>"""


if __name__ == "__main__":  # local testing only (Vercel imports `app` directly)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
