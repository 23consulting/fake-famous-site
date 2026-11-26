// Fake Famous web server.
// - Serves the public landing page and legal pages.
// - Serves the app (/app/) only to people with an active Paddle subscription.
// - Sign-in: the buyer enters the email they paid with, gets a 6-digit code by email, and gets a signed session cookie.
// - Paddle is the source of truth. Sessions are re-checked against Paddle every few hours, so a cancelled
//   or expired subscription loses access automatically. No database needed.
//
// Environment variables (set in Render > service > Environment):
//   PADDLE_API_KEY   Paddle server-side API key (Developer tools > Authentication). Sandbox keys work with PADDLE_ENV=sandbox.
//   PADDLE_ENV       "sandbox" or "production" (must match the landing page CONFIG.paddle.environment)
//   RESEND_API_KEY   Resend API key used to send sign-in codes
//   MAIL_FROM        Sender, e.g. "Fake Famous <login@fakefamous.online>" (domain must be verified in Resend)
//   SESSION_SECRET   Long random string used to sign session cookies
//   ALLOW_EMAILS     Optional comma-separated emails that always get access (owner / testers)

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 10000;
const ROOT = __dirname;
const PADDLE_API = (process.env.PADDLE_ENV || 'sandbox') === 'production' ? 'https://api.paddle.com' : 'https://sandbox-api.paddle.com';
const SECRET = process.env.SESSION_SECRET || '';
const ALLOW = (process.env.ALLOW_EMAILS || '').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);

const SESSION_DAYS = 30;           // how long a sign-in lasts
const RECHECK_MS = 6 * 3600e3;     // re-verify the subscription with Paddle this often
const GRACE_MS = 3 * 86400e3;      // if Paddle is unreachable, keep letting a verified user in for this long
const CODE_TTL_MS = 10 * 60e3;
const OK_STATUSES = ['active', 'trialing', 'past_due'];

if (!SECRET) console.warn('WARNING: SESSION_SECRET is not set. Nobody can sign in until it is.');

/* ---------------- public files ---------------- */
const PUBLIC = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/privacy.html': 'privacy.html',
  '/terms.html': 'terms.html',
  '/refunds.html': 'refunds.html',
  '/login': 'login.html',
};
const TYPES = { '.html': 'text/html; charset=utf-8', '.mp4': 'video/mp4', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.ico': 'image/x-icon', '.js': 'text/javascript', '.css': 'text/css' };

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
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, headers || {}));
  res.end(JSON.stringify(obj));
}

/* ---------------- sessions (signed cookie) ---------------- */
const b64 = (s) => Buffer.from(s).toString('base64url');
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');

function makeCookie(sess) {
  const body = b64(JSON.stringify(sess));
  const val = `${body}.${sign(body)}`;
  return `ff_s=${val}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}
const clearCookie = 'ff_s=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

function readSession(req) {
  if (!SECRET) return null;
  const m = /(?:^|;\s*)ff_s=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(sign(body));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const s = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!s.e || !s.x || Date.now() > s.x) return null;
    return s; // { e: email, c: paddle customer id, x: expiry ms, v: last verified ms }
  } catch (e) { return null; }
}

/* ---------------- Paddle ---------------- */
async function paddle(pathname) {
  const key = process.env.PADDLE_API_KEY;
  if (!key) throw new Error('PADDLE_API_KEY not set');
  const r = await fetch(PADDLE_API + pathname, { headers: { Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`Paddle ${r.status}`);
  return r.json();
}
// Returns the Paddle customer id if this customer has a subscription that should have access, else null.
async function hasActiveSub(customerId) {
  const d = await paddle(`/subscriptions?customer_id=${encodeURIComponent(customerId)}&status=${OK_STATUSES.join(',')}&per_page=5`);
  return Array.isArray(d.data) && d.data.length > 0;
}
// Looks up a buyer by email. Returns customer id when they have an active subscription, else null.
async function findPaidCustomer(email) {
  const d = await paddle(`/customers?email=${encodeURIComponent(email)}&per_page=5`);
  for (const c of d.data || []) {
    if (c.status && c.status !== 'active') continue;
    if (await hasActiveSub(c.id)) return c.id;
  }
  return null;
}

/* ---------------- sign-in codes ---------------- */
const codes = new Map();     // email -> { hash, exp, tries, cust }
const ipHits = new Map();    // ip -> [timestamps]
function limited(ip, max, windowMs) {
  const now = Date.now();
  const list = (ipHits.get(ip) || []).filter((t) => now - t < windowMs);
  list.push(now); ipHits.set(ip, list);
  return list.length > max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of codes) if (now > v.exp) codes.delete(k);
  for (const [k, v] of ipHits) if (!v.some((t) => now - t < 3600e3)) ipHits.delete(k);
}, 60e3).unref();

const hashCode = (email, code) => crypto.createHmac('sha256', SECRET).update(`${email}:${code}`).digest('hex');
const validEmail = (e) => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

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

function readBody(req) {
  return new Promise((resolve) => {
    let s = '';
    req.on('data', (c) => { s += c; if (s.length > 4096) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

async function startLogin(req, res, ip) {
  if (limited(ip, 8, 15 * 60e3)) return json(res, 429, { error: 'Too many attempts. Wait a few minutes and try again.' });
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  if (!validEmail(email)) return json(res, 400, { error: 'Enter a valid email address.' });
  if (!SECRET) return json(res, 503, { error: 'Sign-in is not set up yet. Please try again later.' });
  let cust = null;
  try {
    cust = ALLOW.includes(email) ? 'allow' : await findPaidCustomer(email);
  } catch (e) {
    console.error('Paddle lookup failed:', e.message);
    return json(res, 503, { error: 'We could not check your subscription right now. Try again in a minute.' });
  }
  if (!cust) return json(res, 403, { error: 'No active subscription found for that email. Use the email you paid with, or get Pro first.', nosub: true });
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
  codes.set(email, { hash: hashCode(email, code), exp: Date.now() + CODE_TTL_MS, tries: 0, cust });
  try {
    await sendCodeEmail(email, code);
  } catch (e) {
    console.error('Email send failed:', e.message);
    codes.delete(email);
    return json(res, 503, { error: 'We could not send the code email. Try again in a minute.' });
  }
  json(res, 200, { ok: true });
}

async function verifyLogin(req, res, ip) {
  if (limited(ip, 20, 15 * 60e3)) return json(res, 429, { error: 'Too many attempts. Wait a few minutes and try again.' });
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
  json(res, 200, { ok: true }, { 'Set-Cookie': makeCookie({ e: email, c: rec.cust, x: now + SESSION_DAYS * 86400e3, v: now }) });
}

/* ---------------- the gate ---------------- */
// Returns { ok, cookie? } for the current request.
async function checkAccess(req) {
  const s = readSession(req);
  if (!s) return { ok: false };
  if (ALLOW.includes(s.e)) return { ok: true };
  const now = Date.now();
  if (now - (s.v || 0) < RECHECK_MS) return { ok: true };
  try {
    const ok = s.c && s.c !== 'allow' ? await hasActiveSub(s.c) : !!(await findPaidCustomer(s.e));
    if (!ok) return { ok: false, cookie: clearCookie, lapsed: true };
    s.v = now;
    return { ok: true, cookie: makeCookie(s) };
  } catch (e) {
    console.error('Paddle recheck failed:', e.message);
    return { ok: now - (s.v || 0) < GRACE_MS };
  }
}

async function serveApp(req, res, url) {
  const acc = await checkAccess(req);
  if (!acc.ok) {
    const back = encodeURIComponent(url.pathname + url.search);
    return redirect(res, `/login?next=${back}${acc.lapsed ? '&lapsed=1' : ''}`, acc.cookie ? { 'Set-Cookie': acc.cookie } : null);
  }
  const headers = { 'Cache-Control': 'private, no-store' };
  if (acc.cookie) headers['Set-Cookie'] = acc.cookie;
  sendFile(req, res, 'app/index.html', headers);
}

/* ---------------- router ---------------- */
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

    if (req.method === 'POST' && p === '/api/login/start') return await startLogin(req, res, ip);
    if (req.method === 'POST' && p === '/api/login/verify') return await verifyLogin(req, res, ip);
    if (p === '/logout') return redirect(res, '/login', { 'Set-Cookie': clearCookie });
    if (req.method !== 'GET' && req.method !== 'HEAD') return notFound(res);

    if (p === '/healthz') { res.writeHead(200); return res.end('ok'); }
    if (p === '/app') return redirect(res, '/app/' + url.search);
    if (p === '/app/' || p === '/app/index.html') return await serveApp(req, res, url);
    if (p.startsWith('/app/')) return notFound(res);

    if (p === '/login') {
      const s = readSession(req);
      if (s && (await checkAccess(req)).ok) return redirect(res, safeNext(url.searchParams.get('next')));
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

server.listen(PORT, () => console.log(`Fake Famous listening on ${PORT} (Paddle: ${PADDLE_API})`));
