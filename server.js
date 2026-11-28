// Fake Famous web server.
// - Serves the public landing page and legal pages.
// - Serves the app (/app/) to signed-in users. Everyone can sign in with an email code.
//   People with an active Paddle subscription get Pro; everyone else gets the Free plan.
// - The server decides the plan and enforces every free limit. The browser is never trusted:
//   free streams are counted here, each stream needs a ticket from here, and the free app is
//   served without the paid-only audience languages.
// - Paddle is the source of truth for Pro. Sessions are re-checked against Paddle every few hours.
//
// Environment variables (Render > service > Environment):
//   PADDLE_API_KEY   Paddle server-side API key. Sandbox keys work with PADDLE_ENV=sandbox.
//   PADDLE_ENV       "sandbox" or "production" (must match the landing page CONFIG.paddle.environment)
//   RESEND_API_KEY   Resend API key used to send sign-in codes
//   MAIL_FROM        Sender, e.g. "Fake Famous <login@fakefamous.online>" (domain verified in Resend)
//   SESSION_SECRET   Long random string used to sign cookies and hash stored identifiers
//   REDIS_URL        Strongly recommended: a Render Key Value (Redis) URL, so free-stream counts
//                    survive restarts and deploys. Without it, counts are kept in memory only.
//   ALLOW_EMAILS     Optional comma-separated emails that always get Pro (owner / testers)
//   FREE_STREAMS_PER_DAY, FREE_SECONDS  Optional: change the free plan without editing code (defaults 2 and 60)

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');

const PORT = process.env.PORT || 10000;
const ROOT = __dirname;
const PADDLE_API = (process.env.PADDLE_ENV || 'sandbox') === 'production' ? 'https://api.paddle.com' : 'https://sandbox-api.paddle.com';
const SECRET = process.env.SESSION_SECRET || '';
const ALLOW = (process.env.ALLOW_EMAILS || '').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);

/* ---------------- plan limits (change these numbers to tune the free plan) ---------------- */
const envInt = (k, d) => { const n = parseInt(process.env[k], 10); return Number.isFinite(n) && n >= 0 ? n : d; };
const FREE = {
  streamsPerDay: envInt('FREE_STREAMS_PER_DAY', 2),  // free streams per account per day (UTC)
  seconds: envInt('FREE_SECONDS', 60),               // length of a free stream
  streamsPerNetworkDay: 6,     // free streams per IP address per day, across all accounts (stops email farming)
  accountsPerNetworkDay: 4,    // different free accounts that may sign in from one IP address per day
  accountsPerDeviceDay: 2,     // different free accounts that may sign in from one browser per day
  codesPerEmailHour: 5,        // sign-in codes one address can receive per hour (stops email bombing)
};
const BEAT_SLACK_S = 12;       // grace on top of FREE.seconds before the server ends a free stream (countdown, slow networks)
const STREAM_TTL_S = 6 * 3600; // how long a stream ticket can live

const SESSION_DAYS = 30;
const RECHECK_MS = 6 * 3600e3;     // re-verify the plan with Paddle this often
const GRACE_MS = 3 * 86400e3;      // if Paddle is unreachable, a verified Pro user keeps Pro this long
const CODE_TTL_MS = 10 * 60e3;
const OK_STATUSES = ['active', 'trialing', 'past_due'];

if (!SECRET) console.warn('WARNING: SESSION_SECRET is not set. Nobody can sign in until it is.');

/* ---------------- storage: Redis (Render Key Value) with an in-memory fallback ---------------- */
function memoryStore() {
  const kv = new Map(); // key -> { v, exp }
  const live = (k) => { const e = kv.get(k); if (!e) return null; if (e.exp && Date.now() > e.exp) { kv.delete(k); return null; } return e; };
  setInterval(() => { for (const k of kv.keys()) live(k); }, 60e3).unref();
  return {
    kind: 'memory',
    async get(k) { const e = live(k); return e ? e.v : null; },
    async set(k, v, ttl) { kv.set(k, { v: String(v), exp: Date.now() + ttl * 1000 }); },
    async incr(k, ttl) { const e = live(k); const n = (e ? parseInt(e.v, 10) || 0 : 0) + 1; kv.set(k, { v: String(n), exp: e ? e.exp : Date.now() + ttl * 1000 }); return n; },
    async decr(k) { const e = live(k); if (e) e.v = String(Math.max(0, (parseInt(e.v, 10) || 0) - 1)); },
    async sadd(k, m, ttl) { let e = live(k); if (!e) { e = { v: new Set(), exp: Date.now() + ttl * 1000 }; kv.set(k, e); } e.v.add(m); return e.v.size; },
    async sismember(k, m) { const e = live(k); return !!(e && e.v.has(m)); },
  };
}

// Minimal Redis client (RESP2) so the server keeps zero dependencies.
function redisStore(urlStr) {
  const u = new URL(urlStr);
  const useTls = u.protocol === 'rediss:';
  let sock = null, buf = Buffer.alloc(0), queue = [], ready = null;

  function parse(b, i) { // returns [value, nextIndex] or null if incomplete
    if (i >= b.length) return null;
    const t = String.fromCharCode(b[i]);
    const nl = b.indexOf('\r\n', i);
    if (nl < 0) return null;
    const line = b.toString('utf8', i + 1, nl);
    if (t === '+') return [line, nl + 2];
    if (t === '-') return [new Error(line), nl + 2];
    if (t === ':') return [parseInt(line, 10), nl + 2];
    if (t === '$') {
      const len = parseInt(line, 10);
      if (len < 0) return [null, nl + 2];
      if (b.length < nl + 2 + len + 2) return null;
      return [b.toString('utf8', nl + 2, nl + 2 + len), nl + 2 + len + 2];
    }
    if (t === '*') {
      const n = parseInt(line, 10); const out = []; let j = nl + 2;
      for (let k = 0; k < n; k++) { const r = parse(b, j); if (!r) return null; out.push(r[0]); j = r[1]; }
      return [out, j];
    }
    throw new Error('Bad Redis reply');
  }
  function connect() {
    if (ready) return ready;
    ready = new Promise((resolve, reject) => {
      const opts = { host: u.hostname, port: parseInt(u.port || '6379', 10) };
      sock = useTls ? tls.connect({ ...opts, servername: u.hostname }) : net.connect(opts);
      sock.setTimeout(10000);
      sock.once(useTls ? 'secureConnect' : 'connect', async () => {
        sock.setTimeout(0);
        try {
          if (u.password) await send(u.username ? ['AUTH', decodeURIComponent(u.username), decodeURIComponent(u.password)] : ['AUTH', decodeURIComponent(u.password)]);
          resolve();
        } catch (e) { reject(e); }
      });
      sock.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        let r;
        while (queue.length && (r = parse(buf, 0))) {
          buf = buf.subarray(r[1]);
          const q = queue.shift();
          r[0] instanceof Error ? q.reject(r[0]) : q.resolve(r[0]);
        }
      });
      const fail = (e) => {
        const err = e instanceof Error ? e : new Error('Redis connection closed');
        queue.forEach((q) => q.reject(err)); queue = []; buf = Buffer.alloc(0);
        sock && sock.destroy(); sock = null; ready = null;
        reject(err);
      };
      sock.on('error', fail); sock.on('close', fail); sock.on('timeout', () => fail(new Error('Redis timeout')));
    });
    return ready;
  }
  function send(args) {
    return new Promise((resolve, reject) => {
      let s = `*${args.length}\r\n`;
      for (const a of args) { const v = String(a); s += `$${Buffer.byteLength(v)}\r\n${v}\r\n`; }
      queue.push({ resolve, reject });
      sock.write(s);
    });
  }
  async function cmd(...args) {
    await connect();
    return Promise.race([send(args), new Promise((_, rej) => setTimeout(() => rej(new Error('Redis command timeout')), 4000))]);
  }
  return {
    kind: 'redis',
    async get(k) { return cmd('GET', k); },
    async set(k, v, ttl) { await cmd('SET', k, v, 'EX', ttl); },
    async incr(k, ttl) { const n = await cmd('INCR', k); if (n === 1) await cmd('EXPIRE', k, ttl); return n; },
    async decr(k) { const n = await cmd('DECR', k); if (n < 0) await cmd('SET', k, 0, 'KEEPTTL'); },
    async sadd(k, m, ttl) { await cmd('SADD', k, m); await cmd('EXPIRE', k, ttl, 'NX').catch(() => cmd('EXPIRE', k, ttl)); return cmd('SCARD', k); },
    async sismember(k, m) { return (await cmd('SISMEMBER', k, m)) === 1; },
  };
}

const memory = memoryStore();
const redis = process.env.REDIS_URL ? redisStore(process.env.REDIS_URL) : null;
// Every call goes to Redis when it is configured; if Redis is down the request uses memory and logs it.
const store = new Proxy({}, {
  get(_, fn) {
    return async (...args) => {
      if (!redis) return memory[fn](...args);
      try { return await redis[fn](...args); } catch (e) { console.error('Redis error, using memory:', e.message); return memory[fn](...args); }
    };
  },
});
if (!redis) console.warn('WARNING: REDIS_URL is not set. Free-stream counts reset whenever the server restarts.');

/* ---------------- helpers ---------------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.mp4': 'video/mp4', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.ico': 'image/x-icon', '.js': 'text/javascript', '.css': 'text/css' };
const PUBLIC = { '/': 'index.html', '/index.html': 'index.html', '/privacy.html': 'privacy.html', '/terms.html': 'terms.html', '/refunds.html': 'refunds.html', '/login': 'login.html' };

function sendFile(req, res, rel, extraHeaders) {
  const file = path.join(ROOT, rel);
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return notFound(res);
    const type = TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream';
    const headers = Object.assign({ 'Content-Type': type, 'Accept-Ranges': 'bytes', 'X-Content-Type-Options': 'nosniff' }, extraHeaders || {});
    const range = req.headers.range && /^bytes=(\d*)-(\d*)$/.exec(req.headers.range);
    if (range && (range[1] || range[2])) {
      let start = range[1] ? parseInt(range[1], 10) : st.size - parseInt(range[2], 10);
      let end = range[1] && range[2] ? parseInt(range[2], 10) : st.size - 1;
      if (start < 0) start = 0;
      if (start >= st.size || end < start) { res.writeHead(416, { 'Content-Range': `bytes */${st.size}` }); return res.end(); }
      end = Math.min(end, st.size - 1);
      headers['Content-Range'] = `bytes ${start}-${end}/${st.size}`;
      headers['Content-Length'] = end - start + 1;
      res.writeHead(206, headers);
      if (req.method === 'HEAD') return res.end();
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
    headers['Content-Length'] = st.size;
    res.writeHead(200, headers);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}
function notFound(res) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); }
function redirect(res, to, headers) { res.writeHead(302, Object.assign({ Location: to, 'Cache-Control': 'no-store' }, headers || {})); res.end(); }
function json(res, code, obj, headers) {
  const h = Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, headers || {});
  res.writeHead(code, h);
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve) => {
    let s = '';
    req.on('data', (c) => { s += c; if (s.length > 4096) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}
// Render appends to X-Forwarded-For without clearing it, so its first entry can be faked by the client.
// Cloudflare (in front of Render) sets True-Client-IP / CF-Connecting-IP itself, so prefer those,
// then the right-most X-Forwarded-For entry (added by the proxy, not the client).
function clientIp(req) {
  const h = req.headers;
  const cf = h['true-client-ip'] || h['cf-connecting-ip'];
  if (cf) return String(cf).trim();
  const xff = String(h['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  return xff.length ? xff[xff.length - 1] : String(req.socket.remoteAddress || '');
}
const day = () => new Date().toISOString().slice(0, 10);
const hash = (s) => crypto.createHmac('sha256', SECRET || 'dev').update(String(s)).digest('base64url').slice(0, 22);
const validEmail = (e) => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
// One person, one identity: ignore +tags everywhere, and dots for Gmail, so aliases can't farm free streams.
function identity(email) {
  let [user, dom] = email.toLowerCase().split('@');
  user = user.split('+')[0];
  if (dom === 'googlemail.com') dom = 'gmail.com';
  if (dom === 'gmail.com') user = user.replace(/\./g, '');
  return `${user}@${dom}`;
}
const DISPOSABLE = new Set(('mailinator.com guerrillamail.com guerrillamail.net guerrillamail.org sharklasers.com grr.la 10minutemail.com 10minutemail.net ' +
  'temp-mail.org tempmail.com tempmail.net tempmailo.com temp-mail.io tempr.email tmpmail.org tmpmail.net yopmail.com yopmail.fr yopmail.net ' +
  'trashmail.com trashmail.de getnada.com nada.email dispostable.com maildrop.cc throwawaymail.com fakeinbox.com emailondeck.com mohmal.com ' +
  'mintemail.com burnermail.io spamgourmet.com mailnesia.com discard.email 1secmail.com 1secmail.org 1secmail.net mailcatch.com moakt.com ' +
  'mail.tm mail.gw emailfake.com fakemail.net inboxkitten.com getairmail.com spambox.us mytemp.email tempinbox.com mailpoof.com ' +
  'minuteinbox.com dropmail.me emltmp.com 33mail.com anonaddy.me spam4.me harakirimail.com mailsac.com tempail.com').split(/\s+/));
const isDisposable = (email) => DISPOSABLE.has(email.split('@')[1]);

// Simple in-memory per-IP rate limiter for login/API abuse (bursts only; the daily limits live in the store).
const ipHits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const list = (ipHits.get(key) || []).filter((t) => now - t < windowMs);
  list.push(now); ipHits.set(key, list);
  return list.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of ipHits) if (!v.some((t) => now - t < 3600e3)) ipHits.delete(k); }, 60e3).unref();

/* ---------------- cookies ---------------- */
const b64 = (s) => Buffer.from(s).toString('base64url');
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeCookie(sess) {
  const body = b64(JSON.stringify(sess));
  return `ff_s=${body}.${sign(body)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}
const clearCookie = 'ff_s=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
function readCookie(req, name) { const m = new RegExp(`(?:^|;\\s*)${name}=([^;]+)`).exec(req.headers.cookie || ''); return m ? m[1] : null; }
function readSession(req) {
  if (!SECRET) return null;
  const v = readCookie(req, 'ff_s');
  if (!v) return null;
  const [body, sig] = v.split('.');
  if (!body || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(sign(body));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const s = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!s.e || !s.x || Date.now() > s.x) return null;
    if (!s.p) s.p = 'pro'; // sessions from before the free plan existed were all paid ones; the recheck corrects them
    return s; // { e: email, c: paddle customer id, p: 'pro'|'free', x: expiry ms, v: last verified ms }
  } catch (e) { return null; }
}
// A random per-browser id, used only to limit how many free accounts one browser can create per day.
function deviceId(req) {
  const v = readCookie(req, 'ff_d');
  if (v && /^[\w-]{16,40}$/.test(v)) return { id: v, cookie: null };
  const id = crypto.randomBytes(16).toString('base64url');
  return { id, cookie: `ff_d=${id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${400 * 86400}` };
}

/* ---------------- Paddle ---------------- */
async function paddle(pathname) {
  const key = process.env.PADDLE_API_KEY;
  if (!key) throw new Error('PADDLE_API_KEY not set');
  const r = await fetch(PADDLE_API + pathname, { headers: { Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`Paddle ${r.status}`);
  return r.json();
}
async function hasActiveSub(customerId) {
  const d = await paddle(`/subscriptions?customer_id=${encodeURIComponent(customerId)}&status=${OK_STATUSES.join(',')}&per_page=5`);
  return Array.isArray(d.data) && d.data.length > 0;
}
// Returns the Paddle customer id if this email has an active subscription, else null.
async function findPaidCustomer(email) {
  const d = await paddle(`/customers?email=${encodeURIComponent(email)}&per_page=5`);
  for (const c of d.data || []) {
    if (c.status && c.status !== 'active') continue;
    if (await hasActiveSub(c.id)) return c.id;
  }
  return null;
}
// Works out the plan for an email: { plan, cust }. Throws if Paddle can't be reached.
async function planFor(email, knownCust) {
  if (ALLOW.includes(email)) return { plan: 'pro', cust: 'allow' };
  if (knownCust && knownCust !== 'allow' && (await hasActiveSub(knownCust))) return { plan: 'pro', cust: knownCust };
  const cust = await findPaidCustomer(email);
  return cust ? { plan: 'pro', cust } : { plan: 'free', cust: null };
}

/* ---------------- sign-in ---------------- */
const codes = new Map(); // email -> { hash, exp, tries, plan, cust }
setInterval(() => { const now = Date.now(); for (const [k, v] of codes) if (now > v.exp) codes.delete(k); }, 60e3).unref();
const hashCode = (email, code) => crypto.createHmac('sha256', SECRET).update(`${email}:${code}`).digest('hex');

async function sendCodeEmail(to, code) {
  const key = process.env.RESEND_API_KEY;
  if (!key) throw new Error('RESEND_API_KEY not set');
  const from = process.env.MAIL_FROM || 'Fake Famous <login@fakefamous.online>';
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#000;color:#fff;padding:32px;border-radius:16px;max-width:420px">
<div style="font-size:22px;font-weight:800;letter-spacing:.5px">FAKE FAMOUS</div>
<p style="color:rgba(255,255,255,.7);font-size:15px">Your sign-in code:</p>
<div style="font-size:36px;font-weight:800;letter-spacing:8px;margin:8px 0 16px">${code}</div>
<p style="color:rgba(255,255,255,.5);font-size:13px">It expires in 10 minutes. If you didn't ask for this, you can ignore this email.</p></div>`;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to: [to], subject: `${code} is your Fake Famous code`, html, text: `Your Fake Famous sign-in code is ${code}. It expires in 10 minutes.` }),
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
}

async function startLogin(req, res, ip) {
  if (limited('login:' + ip, 8, 15 * 60e3)) return json(res, 429, { error: 'Too many attempts. Wait a few minutes and try again.' });
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  if (!validEmail(email)) return json(res, 400, { error: 'Enter a valid email address.' });
  if (!SECRET) return json(res, 503, { error: 'Sign-in is not set up yet. Please try again later.' });
  const id = identity(email);
  if ((await store.incr(`cs:${new Date().toISOString().slice(0, 13)}:${hash(id)}`, 3600)) > FREE.codesPerEmailHour) {
    return json(res, 429, { error: 'Too many codes sent to this email. Wait an hour and try again.' });
  }
  let p;
  try { p = await planFor(email); } catch (e) {
    console.error('Paddle lookup failed:', e.message);
    return json(res, 503, { error: 'We could not check your account right now. Try again in a minute.' });
  }
  const dev = deviceId(req);
  if (p.plan === 'free') {
    if (isDisposable(email)) return json(res, 400, { error: 'Please use your regular email address. Temporary email addresses can\'t be used.' });
    // Limit how many different free accounts one network and one browser can use per day.
    const d = day(), who = hash(id);
    const netKey = `an:${d}:${hash(ip)}`, devKey = `ad:${d}:${hash(dev.id)}`;
    const seenNet = await store.sismember(netKey, who), seenDev = await store.sismember(devKey, who);
    if (!seenNet && (await store.sadd(netKey, who, 2 * 86400)) > FREE.accountsPerNetworkDay) {
      return json(res, 429, { error: 'Too many new free accounts from this network today. Sign in with an account you already use, or try again tomorrow.' });
    }
    if (!seenDev && (await store.sadd(devKey, who, 2 * 86400)) > FREE.accountsPerDeviceDay) {
      return json(res, 429, { error: 'Too many free accounts on this device today. Sign in with an account you already use, or try again tomorrow.' });
    }
  }
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
  codes.set(email, { hash: hashCode(email, code), exp: Date.now() + CODE_TTL_MS, tries: 0, plan: p.plan, cust: p.cust });
  try { await sendCodeEmail(email, code); } catch (e) {
    console.error('Email send failed:', e.message);
    codes.delete(email);
    return json(res, 503, { error: 'We could not send the code email. Try again in a minute.' });
  }
  json(res, 200, { ok: true }, dev.cookie ? { 'Set-Cookie': dev.cookie } : null);
}

async function verifyLogin(req, res, ip) {
  if (limited('verify:' + ip, 20, 15 * 60e3)) return json(res, 429, { error: 'Too many attempts. Wait a few minutes and try again.' });
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const code = String(body.code || '').replace(/\D/g, '');
  const rec = codes.get(email);
  if (!rec || Date.now() > rec.exp) return json(res, 400, { error: 'That code expired. Send a new one.' });
  rec.tries++;
  if (rec.tries > 5) { codes.delete(email); return json(res, 400, { error: 'Too many wrong codes. Send a new one.' }); }
  const a = Buffer.from(hashCode(email, code)), b = Buffer.from(rec.hash);
  if (code.length !== 6 || !crypto.timingSafeEqual(a, b)) return json(res, 400, { error: 'That code is not right. Check the email and try again.' });
  codes.delete(email);
  const now = Date.now();
  json(res, 200, { ok: true, plan: rec.plan }, { 'Set-Cookie': makeCookie({ e: email, c: rec.cust, p: rec.plan, x: now + SESSION_DAYS * 86400e3, v: now }) });
}

/* ---------------- access ---------------- */
// Returns { ok, plan, sess, cookie? }. Re-checks the plan with Paddle when it is due (or when forced).
async function checkAccess(req, force) {
  const s = readSession(req);
  if (!s) return { ok: false };
  if (ALLOW.includes(s.e)) { s.p = 'pro'; return { ok: true, plan: 'pro', sess: s }; }
  const now = Date.now();
  if (!force && now - (s.v || 0) < RECHECK_MS) return { ok: true, plan: s.p, sess: s };
  try {
    const p = await planFor(s.e, s.p === 'pro' ? s.c : null);
    s.p = p.plan; s.c = p.cust; s.v = now;
    return { ok: true, plan: s.p, sess: s, cookie: makeCookie(s) };
  } catch (e) {
    console.error('Paddle recheck failed:', e.message);
    // Paddle unreachable: a verified Pro user keeps Pro for a grace period, then drops to Free until Paddle answers.
    if (s.p === 'pro' && now - (s.v || 0) > GRACE_MS) s.p = 'free';
    return { ok: true, plan: s.p, sess: s };
  }
}

async function freeUsage(sess) {
  const used = parseInt((await store.get(`fq:${day()}:${hash(identity(sess.e))}`)) || '0', 10);
  return { used, left: Math.max(0, FREE.streamsPerDay - used) };
}
async function apiMe(req, res, url, ip) {
  const force = url.searchParams.get('refresh') === '1' && !limited('refresh:' + ip, 8, 60e3);
  const acc = await checkAccess(req, force);
  if (!acc.ok) return json(res, 401, { error: 'signed_out' });
  const out = { email: acc.sess.e, plan: acc.plan };
  if (acc.plan === 'free') Object.assign(out, await freeUsage(acc.sess), { limit: FREE.streamsPerDay, seconds: FREE.seconds });
  json(res, 200, out, acc.cookie ? { 'Set-Cookie': acc.cookie } : null);
}

/* ---------------- streams ---------------- */
// Every stream needs a ticket from here. Free tickets are counted per account AND per network,
// so clearing the browser, private windows or extra accounts don't give extra free streams.
async function streamStart(req, res, ip) {
  if (limited('start:' + ip, 30, 10 * 60e3)) return json(res, 429, { error: 'Too many streams started. Wait a few minutes.' });
  const acc = await checkAccess(req);
  if (!acc.ok) return json(res, 401, { error: 'signed_out' });
  const who = hash(identity(acc.sess.e));
  const id = crypto.randomBytes(12).toString('base64url');
  const headers = acc.cookie ? { 'Set-Cookie': acc.cookie } : null;
  if (acc.plan === 'free') {
    const d = day(), ttl = 2 * 86400;
    const netKey = `fn:${d}:${hash(ip)}`, accKey = `fq:${d}:${who}`;
    const n1 = await store.incr(accKey, ttl);
    if (n1 > FREE.streamsPerDay) { await store.decr(accKey); return json(res, 429, { limit: 'daily', left: 0, error: `You've used your ${FREE.streamsPerDay} free streams for today.` }, headers); }
    const n2 = await store.incr(netKey, ttl);
    if (n2 > FREE.streamsPerNetworkDay) { await store.decr(netKey); await store.decr(accKey); return json(res, 429, { limit: 'network', left: 0, error: 'This network has used all its free streams for today.' }, headers); }
    await store.set(`st:${id}`, JSON.stringify({ w: who, p: 'free', t: Date.now() }), STREAM_TTL_S);
    await store.set(`act:${who}`, id, STREAM_TTL_S);
    return json(res, 200, { ok: true, id, plan: 'free', seconds: FREE.seconds, left: Math.max(0, FREE.streamsPerDay - n1) }, headers);
  }
  // Pro: one live stream per account at a time. Starting a new one ends the old one at its next heartbeat.
  await store.set(`st:${id}`, JSON.stringify({ w: who, p: 'pro', t: Date.now() }), STREAM_TTL_S);
  await store.set(`act:${who}`, id, STREAM_TTL_S);
  json(res, 200, { ok: true, id, plan: 'pro' }, headers);
}

// The app calls this every few seconds while live. It tells the app to stop when the free time is up,
// or when the same account started a stream somewhere else.
async function streamBeat(req, res) {
  const acc = await checkAccess(req);
  if (!acc.ok) return json(res, 401, { end: true, reason: 'signed_out' });
  const body = await readBody(req);
  const id = String(body.id || '');
  const raw = /^[\w-]{10,30}$/.test(id) ? await store.get(`st:${id}`) : null;
  let st = null; try { st = raw && JSON.parse(raw); } catch (e) {}
  const who = hash(identity(acc.sess.e));
  if (!st || st.w !== who) return json(res, 200, { end: true, reason: 'invalid' });
  if ((await store.get(`act:${who}`)) !== id) return json(res, 200, { end: true, reason: 'elsewhere' });
  if (st.p === 'free' && Date.now() - st.t > (FREE.seconds + BEAT_SLACK_S) * 1000) return json(res, 200, { end: true, reason: 'time' });
  json(res, 200, { ok: true });
}

/* ---------------- the app ---------------- */
// The free app is a different file from the Pro app: every audience pack except US English is removed
// before it leaves the server, so they can't be switched on from the browser.
let appCache = null;
function appHtml(plan, email) {
  const file = path.join(ROOT, 'app/index.html');
  const mtime = fs.statSync(file).mtimeMs;
  if (!appCache || appCache.mtime !== mtime) {
    const pro = fs.readFileSync(file, 'utf8');
    const free = pro.replace(/^var AUD=\{"es":.*$/m, 'var AUD={};').replace(/^AUD\["en-[A-Z]+"\]=.*$/gm, '');
    if (free === pro) console.warn('WARNING: could not strip paid languages from the free app build.');
    appCache = { mtime, pro, free };
  }
  const cfg = plan === 'free'
    ? { plan: 'free', seconds: FREE.seconds, limit: FREE.streamsPerDay, email }
    : { plan: 'pro', email };
  const tag = `<script>window.FF_PLAN=${JSON.stringify(cfg).replace(/</g, '\\u003c')};</script>`;
  return (plan === 'free' ? appCache.free : appCache.pro).replace('</head>', tag + '\n</head>');
}
async function serveApp(req, res, url) {
  const acc = await checkAccess(req, url.searchParams.get('welcome') === '1');
  if (!acc.ok) return redirect(res, `/login?next=${encodeURIComponent(url.pathname + url.search)}`);
  const body = appHtml(acc.plan, acc.sess.e);
  const headers = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Length': Buffer.byteLength(body) };
  if (acc.cookie) headers['Set-Cookie'] = acc.cookie;
  res.writeHead(200, headers);
  res.end(req.method === 'HEAD' ? undefined : body);
}

/* ---------------- router ---------------- */
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const ip = clientIp(req);

    if (req.method === 'POST') {
      if (p === '/api/login/start') return await startLogin(req, res, ip);
      if (p === '/api/login/verify') return await verifyLogin(req, res, ip);
      if (p === '/api/stream/start') return await streamStart(req, res, ip);
      if (p === '/api/stream/beat') return await streamBeat(req, res);
      return notFound(res);
    }
    if (p === '/logout') return redirect(res, '/login', { 'Set-Cookie': clearCookie });
    if (req.method !== 'GET' && req.method !== 'HEAD') return notFound(res);

    if (p === '/healthz') { res.writeHead(200); return res.end('ok'); }
    if (p === '/api/me') return await apiMe(req, res, url, ip);
    if (p === '/app') return redirect(res, '/app/' + url.search);
    if (p === '/app/' || p === '/app/index.html') return await serveApp(req, res, url);
    if (p.startsWith('/app/')) return notFound(res);

    if (p === '/login') {
      if ((await checkAccess(req)).ok) return redirect(res, safeNext(url.searchParams.get('next')));
      return sendFile(req, res, 'login.html', { 'Cache-Control': 'no-store' });
    }
    if (PUBLIC[p]) return sendFile(req, res, PUBLIC[p], { 'Cache-Control': 'public, max-age=300' });
    if (/^\/assets\/[\w.-]+$/.test(p)) return sendFile(req, res, p.slice(1), { 'Cache-Control': 'public, max-age=86400' });
    notFound(res);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) { res.writeHead(500); res.end('Server error'); }
  }
});
function safeNext(n) { return n && /^\/app\/?(\?[^#]*)?$/.test(n) ? n : '/app/'; }

server.listen(PORT, () => console.log(`Fake Famous listening on ${PORT} (Paddle: ${PADDLE_API}, store: ${redis ? 'redis' : 'memory'})`));
