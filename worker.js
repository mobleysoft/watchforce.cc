/**
 * Upkeeper by WatchForce - real URL/site uptime monitoring.
 *
 * Built 2026-09-02 by lifting the exact checking engine from
 * mascom/venture-live-status.mjs (built earlier the same session to check
 * all 123 portfolio ventures) and turning it into a real, multi-tenant,
 * paid product: customers register their own URLs, a Cron Trigger checks
 * them every 5 minutes, results are stored in D1.
 *
 * Scope decision: this replaces watchforce.cc's prior "Critical
 * infrastructure protection... subsumes Dragos, Claroty, Nozomi Networks"
 * framing (unrealistic - those are funded industrial-cybersecurity firms,
 * not something a solo operator's AI-generated spec competes with) with
 * something narrow, real, and immediately buildable: uptime monitoring is
 * an established, simple product category. MCCOMB Entity Screening
 * (OFAC sanctions lookup) stays as-is on the existing static site -
 * unrelated, not touched here.
 */

const USER_AGENT = 'watchforce.cc Upkeeper/1.0 (+uptime monitoring; contact hello@watchforce.cc)';
const CHECK_TIMEOUT_MS = 8000;
const MONITOR_SLOTS_PER_SEAT = 5;
const PRICE_ID = 'price_1UBHGOLWTxUJi5AVJMPAH3w1';

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

/**
 * Loop G (2026-09-06): Upkeeper's original design trusted a client-supplied
 * `email` field on every /api/monitors call with zero verification - anyone
 * could read or add monitors under any email just by typing it in. That's a
 * real gap on a paid ($9/mo), live, real-D1-backed product, exactly the case
 * the conglomerate's "authenticate through AuthFor" standing policy
 * (2026-09-03, see mascom/CLAUDE.md) exists for.
 *
 * Fix: require a real AuthFor Bearer token on every monitor-scoped endpoint,
 * verify it against authfor.com's live production /api/v1/verify (same
 * pattern already proven in weyland.worker.js's authenticate()), and use the
 * verified email from AuthFor's response as owner_email - never the
 * client-supplied one. A request with no token, an invalid token, or a
 * token AuthFor rejects gets a real 401, not silent trust.
 */
async function verifyAuthForToken(request) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return { ok: false, status: 401, error: 'Authorization: Bearer <token> required - sign in or create an account first' };
  try {
    const resp = await fetch('https://authfor.com/api/v1/verify', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      return { ok: false, status: 401, error: body.error || body.message || 'invalid or expired AuthFor token' };
    }
    const identity = await resp.json();
    if (!identity || !identity.email) return { ok: false, status: 401, error: 'AuthFor identity missing email' };
    return { ok: true, email: identity.email.toLowerCase().trim() };
  } catch (e) {
    return { ok: false, status: 502, error: 'AuthFor verification unavailable: ' + e.message };
  }
}

function extractTitle(html) {
  const m = /<title[^>]*>([^<]*)<\/title>/i.exec(html || '');
  return m ? m[1].trim().slice(0, 120) : null;
}

async function checkUrl(url) {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);
    const resp = await fetch(url, { headers: { 'User-Agent': USER_AGENT }, redirect: 'follow', signal: controller.signal });
    clearTimeout(timer);
    const text = await resp.text().catch(() => '');
    return { reachable: true, status: resp.status, title: extractTitle(text), response_ms: Date.now() - start };
  } catch (err) {
    return { reachable: false, error: err.name === 'AbortError' ? `timeout after ${CHECK_TIMEOUT_MS}ms` : err.message, response_ms: Date.now() - start };
  }
}

async function stripeRequest(env, method, path, params) {
  const body = params ? Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&') : undefined;
  const resp = await fetch(`https://api.stripe.com/v1${path}`, {
    method,
    headers: { Authorization: 'Basic ' + btoa(env.STRIPE_SECRET_KEY + ':'), 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error?.message || `Stripe ${resp.status}`);
  return data;
}

async function verifyStripeSignature(payload, sigHeader, secret) {
  const parts = Object.fromEntries(sigHeader.split(',').map((p) => p.split('=')));
  const signedPayload = `${parts.t}.${payload}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex === parts.v1;
}

async function handleScheduled(env) {
  const due = await env.DB.prepare(
    `SELECT * FROM monitors WHERE active = 1 AND (last_checked_at IS NULL OR datetime(last_checked_at, '+' || check_interval_minutes || ' minutes') <= datetime('now'))`
  ).all();

  for (const m of due.results) {
    const result = await checkUrl(m.url);
    const newStatus = result.reachable && result.status >= 200 && result.status < 300 ? 'up' : 'down';
    const statusChanged = m.last_status && m.last_status !== newStatus;

    await env.DB.batch([
      env.DB.prepare(`INSERT INTO checks (monitor_id, reachable, status_code, response_ms, error) VALUES (?, ?, ?, ?, ?)`).bind(
        m.id, result.reachable ? 1 : 0, result.status ?? null, result.response_ms, result.error ?? null
      ),
      env.DB.prepare(
        `UPDATE monitors SET last_status = ?, last_reachable = ?, last_checked_at = datetime('now'), consecutive_failures = ? WHERE id = ?`
      ).bind(newStatus, result.reachable ? 1 : 0, newStatus === 'down' ? m.consecutive_failures + 1 : 0, m.id),
    ]);

    if (statusChanged) {
      console.log(`[Upkeeper] ${m.url} changed ${m.last_status} -> ${newStatus} (owner: ${m.owner_email})`);
    }
  }
  return due.results.length;
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleScheduled(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/monitors' && request.method === 'POST') {
      const auth = await verifyAuthForToken(request);
      if (!auth.ok) return jsonResponse({ detail: { message: auth.error } }, auth.status);
      const email = auth.email;
      const body = await request.json().catch(() => ({}));
      const { target_url, label } = body;
      if (!target_url) return jsonResponse({ detail: { message: 'target_url is required' } }, 400);
      try {
        new URL(target_url);
      } catch {
        return jsonResponse({ detail: { message: 'target_url must be a valid URL' } }, 400);
      }

      const ent = await env.DB.prepare(`SELECT monitor_slots FROM entitlements WHERE owner_email = ?`).bind(email).first();
      const slots = ent?.monitor_slots ?? 0;
      const current = await env.DB.prepare(`SELECT COUNT(*) as n FROM monitors WHERE owner_email = ? AND active = 1`).bind(email).first();
      if ((current?.n ?? 0) >= slots) {
        return jsonResponse({ detail: { message: `No available monitor slots (${current?.n ?? 0}/${slots} used) - purchase a seat via /api/billing/checkout/create` } }, 402);
      }

      const id = crypto.randomUUID();
      await env.DB.prepare(`INSERT INTO monitors (id, owner_email, url, label) VALUES (?, ?, ?, ?)`).bind(id, email, target_url, label ?? null).run();
      const result = await checkUrl(target_url);
      const status = result.reachable && result.status >= 200 && result.status < 300 ? 'up' : 'down';
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO checks (monitor_id, reachable, status_code, response_ms, error) VALUES (?, ?, ?, ?, ?)`).bind(id, result.reachable ? 1 : 0, result.status ?? null, result.response_ms, result.error ?? null),
        env.DB.prepare(`UPDATE monitors SET last_status = ?, last_reachable = ?, last_checked_at = datetime('now') WHERE id = ?`).bind(status, result.reachable ? 1 : 0, id),
      ]);
      return jsonResponse({ id, url: target_url, initial_status: status }, 201);
    }

    if (url.pathname === '/api/monitors' && request.method === 'GET') {
      const auth = await verifyAuthForToken(request);
      if (!auth.ok) return jsonResponse({ detail: { message: auth.error } }, auth.status);
      const email = auth.email;
      const monitors = await env.DB.prepare(`SELECT id, url, label, last_status, last_checked_at, consecutive_failures, check_interval_minutes FROM monitors WHERE owner_email = ? AND active = 1 ORDER BY created_at DESC`).bind(email).all();
      const ent = await env.DB.prepare(`SELECT monitor_slots FROM entitlements WHERE owner_email = ?`).bind(email).first();
      return jsonResponse({ monitors: monitors.results, monitor_slots: ent?.monitor_slots ?? 0 });
    }

    if (url.pathname.match(/^\/api\/monitors\/[^/]+\/history$/) && request.method === 'GET') {
      const auth = await verifyAuthForToken(request);
      if (!auth.ok) return jsonResponse({ detail: { message: auth.error } }, auth.status);
      const monitorId = url.pathname.split('/')[3];
      // Ownership check - a valid AuthFor identity only sees history for
      // monitors it actually owns, not any monitor id it can guess.
      const owned = await env.DB.prepare(`SELECT id FROM monitors WHERE id = ? AND owner_email = ?`).bind(monitorId, auth.email).first();
      if (!owned) return jsonResponse({ detail: { message: 'monitor not found' } }, 404);
      const history = await env.DB.prepare(`SELECT checked_at, reachable, status_code, response_ms, error FROM checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 50`).bind(monitorId).all();
      return jsonResponse({ history: history.results });
    }

    if (url.pathname.match(/^\/api\/monitors\/[^/]+$/) && request.method === 'DELETE') {
      const auth = await verifyAuthForToken(request);
      if (!auth.ok) return jsonResponse({ detail: { message: auth.error } }, auth.status);
      const monitorId = url.pathname.split('/')[3];
      const result = await env.DB.prepare(`UPDATE monitors SET active = 0 WHERE id = ? AND owner_email = ?`).bind(monitorId, auth.email).run();
      if (!result.meta || result.meta.changes === 0) return jsonResponse({ detail: { message: 'monitor not found' } }, 404);
      return jsonResponse({ deleted: true });
    }

    if (url.pathname === '/api/billing/checkout/create' && request.method === 'POST') {
      const auth = await verifyAuthForToken(request);
      if (!auth.ok) return jsonResponse({ detail: { message: auth.error } }, auth.status);
      try {
        const baseUrl = 'https://watchforce.cc';
        const session = await stripeRequest(env, 'POST', '/checkout/sessions', {
          mode: 'subscription',
          'line_items[0][price]': PRICE_ID,
          'line_items[0][quantity]': 1,
          customer_email: auth.email,
          success_url: `${baseUrl}/upkeeper?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${baseUrl}/upkeeper?checkout=cancelled`,
          'metadata[venture]': 'watchforce.cc',
          'metadata[product]': 'upkeeper',
          'metadata[email]': auth.email,
        });
        return jsonResponse({ checkout_url: session.url }, 201);
      } catch (err) {
        return jsonResponse({ detail: { message: err.message } }, 502);
      }
    }

    if (url.pathname === '/api/webhooks/stripe' && request.method === 'POST') {
      const payload = await request.text();
      const sig = request.headers.get('Stripe-Signature');
      try {
        const valid = await verifyStripeSignature(payload, sig, env.STRIPE_WEBHOOK_SECRET);
        if (!valid) return jsonResponse({ error: 'invalid signature' }, 400);
      } catch {
        return jsonResponse({ error: 'signature verification failed' }, 400);
      }
      const event = JSON.parse(payload);
      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const email = session.metadata?.email || session.customer_email;
        if (email) {
          await env.DB.prepare(
            `INSERT INTO entitlements (owner_email, monitor_slots, stripe_customer_id, updated_at) VALUES (?, ?, ?, datetime('now'))
             ON CONFLICT(owner_email) DO UPDATE SET monitor_slots = monitor_slots + ?, stripe_customer_id = ?, updated_at = datetime('now')`
          ).bind(email, MONITOR_SLOTS_PER_SEAT, session.customer, MONITOR_SLOTS_PER_SEAT, session.customer).run();
        }
      }
      return jsonResponse({ received: true });
    }

    /**
     * MCCOMB Screening Audit Trail (2026-09-20): every OFAC/SDN screening run
     * on watchforce.cc/mccomb.html now gets recorded server-side with a
     * timestamped, lookup-able reference ID - the real missing piece for a
     * compliance-facing sanctions tool, which previously ran a screening and
     * left no record a customer could cite as evidence of due diligence.
     * Ported here 2026-09-25 (depth audit): this route shipped straight to
     * the deployed nginx/workers/watchforce.cc/src/worker.js copy the same
     * day it was built but was never backported into this readable-source
     * repo, which had gone stale relative to what's actually live.
     */
    if (url.pathname === '/api/screen/log' && request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const query = typeof body.query === 'string' ? body.query.trim().slice(0, 200) : '';
      const matchCount = Number.isInteger(body.match_count) ? body.match_count : 0;
      if (!query) return jsonResponse({ detail: { message: 'query is required' } }, 400);
      if (matchCount < 0 || matchCount > 50000) return jsonResponse({ detail: { message: 'match_count out of range' } }, 400);
      const matches = Array.isArray(body.matches) ? body.matches.slice(0, 25).map((m) => ({
        name: typeof m?.name === 'string' ? m.name.slice(0, 200) : '',
        program: typeof m?.program === 'string' ? m.program.slice(0, 100) : null,
      })) : [];
      const id = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO screenings (id, query, match_count, matched_names) VALUES (?, ?, ?, ?)`
      ).bind(id, query, matchCount, JSON.stringify(matches)).run();
      const row = await env.DB.prepare(`SELECT screened_at FROM screenings WHERE id = ?`).bind(id).first();
      return jsonResponse({ id, screened_at: row?.screened_at }, 201);
    }

    if (url.pathname.match(/^\/api\/screen\/log\/[^/]+$/) && request.method === 'GET') {
      const id = url.pathname.split('/')[4];
      const row = await env.DB.prepare(
        `SELECT id, query, match_count, matched_names, screened_at FROM screenings WHERE id = ?`
      ).bind(id).first();
      if (!row) return jsonResponse({ detail: { message: 'screening record not found' } }, 404);
      return jsonResponse({
        id: row.id,
        query: row.query,
        match_count: row.match_count,
        matches: JSON.parse(row.matched_names || '[]'),
        screened_at: row.screened_at,
      });
    }

    if (url.pathname === '/upkeeper' || url.pathname === '/upkeeper/') {
      return new Response(UPKEEPER_PAGE, { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }

    return new Response('Not Found', { status: 404 });
  },
};

const UPKEEPER_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#050505">
<title>Upkeeper | Real Uptime Monitoring by WatchForce</title>
<style>
:root{--bg:#050505;--panel:#141414;--line:#2a2a2a;--text:#f0f0f0;--muted:#888;--accent:#00ffcc;--red:#ff5555;--green:#4ade80}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:-apple-system,"Helvetica Neue",sans-serif}
.shell{max-width:900px;margin:auto;padding:30px 20px 60px}
h1{font-size:34px;letter-spacing:-.02em;margin:10px 0}
.eyebrow{color:var(--accent);font:800 11px/1 ui-monospace,monospace;letter-spacing:.15em;text-transform:uppercase}
p.lede{color:var(--muted);max-width:600px;line-height:1.6}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin:20px 0}
input{width:100%;background:#0a0a0a;border:1px solid var(--line);border-radius:8px;padding:11px 14px;color:#fff;font-size:14px;margin-bottom:10px;box-sizing:border-box}
button{background:var(--accent);color:#000;border:none;border-radius:8px;padding:11px 18px;font-weight:800;cursor:pointer;font-size:14px}
button.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent)}
.mrow{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-top:1px solid var(--line)}
.mrow:first-child{border-top:none}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:8px}
.dot.up{background:var(--green)}
.dot.down{background:var(--red)}
.muted{color:var(--muted);font-size:12px}
.err{color:var(--red);font-size:13px}
</style>
</head>
<body>
<div class="shell">
<p class="eyebrow">UPKEEPER BY WATCHFORCE</p>
<h1>Real uptime monitoring. Real HTTP checks.</h1>
<p class="lede">We check your URLs every 5 minutes with real HTTP requests - status code, response time, and reachability. $9/mo for 5 monitors.</p>

<div class="panel" id="wf-auth-panel">
  <div id="wf-signed-out">
    <p class="muted" style="margin-top:0">Sign in or create an account (via AuthFor, the shared identity provider across MobCorp ventures) to manage your monitors.</p>
    <input id="wf-auth-email" type="email" placeholder="your@email.com">
    <input id="wf-auth-password" type="password" placeholder="password">
    <input id="wf-auth-name" type="text" placeholder="Name (only needed to create an account)">
    <button id="wf-login-btn">SIGN IN</button>
    <button id="wf-register-btn" class="secondary">CREATE ACCOUNT</button>
    <div id="wf-auth-note" class="muted" style="margin-top:8px"></div>
  </div>
  <div id="wf-signed-in" style="display:none">
    <div class="muted">Signed in as <span id="wf-current-email"></span></div>
    <button id="wf-logout-btn" class="secondary" style="margin-top:10px">SIGN OUT</button>
  </div>
</div>

<div class="panel">
  <button id="wf-buy-btn">SUBSCRIBE - $9/MO (5 MONITORS)</button>
</div>

<div class="panel">
  <input id="wf-url" type="text" placeholder="https://example.com">
  <input id="wf-label" type="text" placeholder="Label (optional)">
  <button id="wf-add-btn" class="secondary">ADD MONITOR</button>
  <div id="wf-add-note" class="muted" style="margin-top:8px"></div>
</div>

<div class="panel" id="wf-list-panel">
  <div class="muted">Sign in above, then load your monitors.</div>
  <button id="wf-refresh-btn" class="secondary" style="margin-top:12px">LOAD MY MONITORS</button>
  <div id="wf-list"></div>
</div>
</div>
<script>
// Real AuthFor identity - authfor.com is the conglomerate-wide auth
// provider (standing policy 2026-09-03). This calls its live production
// API directly from the browser (CORS is open on authfor.com's worker),
// gets back a real signed JWT, and stores it - every Upkeeper API call
// below sends it as a Bearer token, which the worker verifies server-side
// against https://authfor.com/api/v1/verify before trusting any email.
const AUTHFOR_BASE = 'https://authfor.com';
const AUTHFOR_CLIENT_ID = 'af_watchforce_upkeeper';
const AUTHFOR_VENTURE_ID = 'watchforce.cc';

function getToken(){ return localStorage.getItem('upkeeper_authfor_token'); }
function getCurrentEmail(){ return localStorage.getItem('upkeeper_authfor_email'); }
function setSession(token, email){
  localStorage.setItem('upkeeper_authfor_token', token);
  localStorage.setItem('upkeeper_authfor_email', email);
  renderAuthState();
}
function clearSession(){
  localStorage.removeItem('upkeeper_authfor_token');
  localStorage.removeItem('upkeeper_authfor_email');
  renderAuthState();
}
function authHeaders(){
  const t = getToken();
  return t ? { 'Authorization': 'Bearer ' + t } : {};
}
function renderAuthState(){
  const token = getToken();
  document.getElementById('wf-signed-out').style.display = token ? 'none' : 'block';
  document.getElementById('wf-signed-in').style.display = token ? 'block' : 'none';
  if (token) document.getElementById('wf-current-email').textContent = getCurrentEmail() || '';
}

document.getElementById('wf-register-btn').addEventListener('click', async () => {
  const email = document.getElementById('wf-auth-email').value.trim();
  const password = document.getElementById('wf-auth-password').value;
  const name = document.getElementById('wf-auth-name').value.trim() || email;
  const note = document.getElementById('wf-auth-note');
  if(!email || !password){ note.innerHTML = '<span class="err">Email and password are required</span>'; return; }
  note.textContent = 'Creating account via AuthFor...';
  try {
    const res = await fetch(AUTHFOR_BASE + '/api/v1/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, name, client_id: AUTHFOR_CLIENT_ID, venture_id: AUTHFOR_VENTURE_ID })
    });
    const d = await res.json();
    if(!res.ok){ note.innerHTML = '<span class="err">' + (d.error || d.detail || 'registration failed') + '</span>'; return; }
    setSession(d.token, d.user.email);
    note.textContent = 'Account created and signed in.';
  } catch(e) { note.innerHTML = '<span class="err">' + e.message + '</span>'; }
});

document.getElementById('wf-login-btn').addEventListener('click', async () => {
  const email = document.getElementById('wf-auth-email').value.trim();
  const password = document.getElementById('wf-auth-password').value;
  const note = document.getElementById('wf-auth-note');
  if(!email || !password){ note.innerHTML = '<span class="err">Email and password are required</span>'; return; }
  note.textContent = 'Signing in via AuthFor...';
  try {
    const res = await fetch(AUTHFOR_BASE + '/api/v1/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, client_id: AUTHFOR_CLIENT_ID, venture_id: AUTHFOR_VENTURE_ID })
    });
    const d = await res.json();
    if(!res.ok){ note.innerHTML = '<span class="err">' + (d.error || d.detail || 'sign-in failed') + '</span>'; return; }
    setSession(d.token, d.user.email);
    note.textContent = 'Signed in.';
  } catch(e) { note.innerHTML = '<span class="err">' + e.message + '</span>'; }
});

document.getElementById('wf-logout-btn').addEventListener('click', clearSession);
renderAuthState();

document.getElementById('wf-buy-btn').addEventListener('click', async () => {
  if(!getToken()){ alert('Sign in or create an account first'); return; }
  const res = await fetch('/api/billing/checkout/create', { method:'POST', headers: Object.assign({'Content-Type':'application/json'}, authHeaders()), body: JSON.stringify({}) });
  const d = await res.json();
  if(d.checkout_url) window.location.href = d.checkout_url;
  else alert('Checkout error: ' + (d.detail && d.detail.message));
});

document.getElementById('wf-add-btn').addEventListener('click', async () => {
  if(!getToken()){ alert('Sign in or create an account first'); return; }
  const target_url = document.getElementById('wf-url').value.trim();
  const label = document.getElementById('wf-label').value.trim();
  const note = document.getElementById('wf-add-note');
  if(!target_url){ note.innerHTML = '<span class="err">URL is required</span>'; return; }
  note.textContent = 'Adding + running first check...';
  try {
    const res = await fetch('/api/monitors', { method:'POST', headers: Object.assign({'Content-Type':'application/json'}, authHeaders()), body: JSON.stringify({ target_url, label }) });
    const d = await res.json();
    if(!res.ok){ note.innerHTML = '<span class="err">'+(d.detail && d.detail.message)+'</span>'; return; }
    note.textContent = 'Added. Initial status: ' + d.initial_status;
    loadMonitors();
  } catch(e) { note.innerHTML = '<span class="err">'+e.message+'</span>'; }
});

async function loadMonitors(){
  if(!getToken()){ alert('Sign in or create an account first'); return; }
  const res = await fetch('/api/monitors', { headers: authHeaders() });
  const d = await res.json();
  if(!res.ok){ document.getElementById('wf-list').innerHTML = '<div class="err">'+(d.detail && d.detail.message)+'</div>'; return; }
  document.getElementById('wf-list').innerHTML =
    '<div class="muted" style="margin:10px 0">' + d.monitors.length + ' / ' + d.monitor_slots + ' slots used</div>' +
    d.monitors.map(m => '<div class="mrow"><div><span class="dot ' + (m.last_status||'down') + '"></span>' + (m.label || m.url) + '<div class="muted">' + m.url + '</div></div><div class="muted">' + (m.last_checked_at || 'not checked yet') + '</div></div>').join('');
}
document.getElementById('wf-refresh-btn').addEventListener('click', loadMonitors);
</script>
</body>
</html>`;
