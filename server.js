'use strict';
/**
 * Parley: a private, end-to-end encrypted messenger, in ONE file.
 *
 *   Run it:     npm install ws
 *               node server.js          then open http://localhost:3000
 *   Needs:      Node 18 or newer. Env vars: PORT (default 3000), DATA_FILE (default ./data.json)
 *   HTTPS:      browser crypto only works on https:// or localhost, so put this behind HTTPS
 *               (for example Caddy: `chat.example.com { reverse_proxy localhost:3000 }`).
 *
 * This file is both the relay server and the web app. The browser files (index.html, style.css,
 * app.js) sit at the bottom as comment lines starting with "//| ". The server reads them from
 * itself at start-up and serves them. To edit the web app, change the lines at the bottom and
 * keep the "//| " prefix on each one.
 *
 * Parley relay server.
 *
 * The server never sees message plaintext or private keys. It only:
 *   - stores each user's PUBLIC keys,
 *   - verifies users prove ownership of their signing key (challenge/response),
 *   - relays and temporarily queues opaque encrypted envelopes.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');

// ---------- embedded web app ----------
// Only the files embedded at the bottom of this file are ever served to browsers
// (never this script or data.json). Each embedded line is "//| " followed by the real line.
const CLIENT_FILES = Object.create(null);
(function loadClientFiles() {
  let current = null;
  for (const line of fs.readFileSync(__filename, 'utf8').split(/\r?\n/)) {
    if (line.startsWith('//#### FILE: ')) { current = line.slice(13).trim(); CLIENT_FILES[current] = []; continue; }
    if (line.startsWith('//#### END')) { current = null; continue; }
    if (current && line.startsWith('//|')) CLIENT_FILES[current].push(line.slice(4));
  }
  for (const name of Object.keys(CLIENT_FILES)) CLIENT_FILES[name] = CLIENT_FILES[name].join('\n') + '\n';
})();

const USERNAME_RE = /^[a-z0-9_]{3,24}$/;
const MAX_WS_PAYLOAD = 1024 * 1024;
const MAX_CT_LEN = 700 * 1024;         // base64 chars (~500 KB of ciphertext: room for a compressed photo)
const MAX_QUEUE_BYTES = 25 * 1024 * 1024; // undelivered ciphertext allowed per user
const MAX_QUEUE_PER_USER = 1000;
const MSG_LIMIT = { count: 30, windowMs: 10_000 };
const REGISTER_LIMIT = { count: 5, windowMs: 60 * 60 * 1000 }; // per IP
const LOGIN_FAIL_LIMIT = { perUser: 10, perIp: 40, windowMs: 15 * 60 * 1000 }; // password attempts

// ---------- persistence (small JSON file; swap for a real DB at scale) ----------
let db = { users: {}, queue: {} };
try {
  db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  db.users ||= {};
  db.queue ||= {};
} catch (_) { /* first run */ }

let saveTimer = null;
function saveSoon() {
  if (saveTimer) return;
  saveTimer = setTimeout(saveNow, 200);
}
function saveNow() {
  clearTimeout(saveTimer);
  saveTimer = null;
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}
process.on('SIGINT', () => { saveNow(); process.exit(0); });
process.on('SIGTERM', () => { saveNow(); process.exit(0); });

// ---------- crypto helpers ----------
function cleanJwk(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') return null;
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return null;
  if (jwk.x.length > 64 || jwk.y.length > 64) return null;
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

function verifySig(signPubJwk, message, sigB64) {
  try {
    const key = crypto.createPublicKey({ key: signPubJwk, format: 'jwk' });
    return crypto.verify(
      'sha256',
      Buffer.from(message, 'utf8'),
      { key, dsaEncoding: 'ieee-p1363' }, // WebCrypto's ECDSA signature format
      Buffer.from(sigB64, 'base64')
    );
  } catch (_) {
    return false;
  }
}

const authMessage = (nonce, username) => `pm-auth-v1:${nonce}:${username}`;

// ---------- password login ----------
// The browser stretches the password into (a) a key that locks the user's private keys and
// (b) an "auth" value. We only ever see (b), and only store a salted scrypt hash of it. A
// correct "auth" value is what releases the locked-keys blob to a new device. We never see
// the password or any usable key.
const scryptAsync = promisify(crypto.scrypt);
const AUTH_RE = /^[A-Za-z0-9+/]{43}=$/;      // base64 of a 32-byte value
const DUMMY_SALT = crypto.randomBytes(16);   // keeps unknown-user timing close to a real check
const loginFails = new Map();                // "u:name" / "ip:addr" -> recent attempt times
const logErr = err => console.error('handler error:', err);

function recentFails(key) {
  const now = Date.now();
  const list = (loginFails.get(key) || []).filter(t => now - t < LOGIN_FAIL_LIMIT.windowMs);
  if (list.length) loginFails.set(key, list); else loginFails.delete(key);
  return list;
}
function loginBlocked(username, ip) {
  return recentFails(`u:${username}`).length >= LOGIN_FAIL_LIMIT.perUser ||
         recentFails(`ip:${ip}`).length >= LOGIN_FAIL_LIMIT.perIp;
}
// Every attempt is counted up front (so a burst can't slip through), then forgiven on success.
function noteLoginAttempt(username, ip) {
  for (const key of [`u:${username}`, `ip:${ip}`]) {
    const list = recentFails(key);
    list.push(Date.now());
    loginFails.set(key, list);
  }
}
function forgiveLoginAttempt(username, ip) {
  loginFails.delete(`u:${username}`);
  const list = recentFails(`ip:${ip}`);
  list.pop();
  if (list.length) loginFails.set(`ip:${ip}`, list);
}

function cleanPw(pw) {
  if (!pw || typeof pw.auth !== 'string' || !AUTH_RE.test(pw.auth)) return null;
  const blob = pw.blob;
  if (!blob || typeof blob.iv !== 'string' || typeof blob.ct !== 'string') return null;
  if (blob.iv.length > 32 || blob.ct.length > 4096) return null;
  return { auth: pw.auth, blob: { iv: blob.iv, ct: blob.ct } };
}

// ---------- HTTP (static client) ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
    "connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

const server = http.createServer((req, res) => {
  let urlPath;
  try { urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname); }
  catch (_) { res.writeHead(400); return res.end(); }

  if (urlPath === '/') urlPath = '/index.html';
  const name = urlPath.slice(1);
  const body = CLIENT_FILES[name];
  if (body === undefined) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'Content-Type': MIME[path.extname(name)] || 'application/octet-stream',
  });
  res.end(body);
});

// ---------- WebSocket relay ----------
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: MAX_WS_PAYLOAD });
const online = new Map();        // username -> Set<ws>
const registerHits = new Map();  // ip -> [timestamps]

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function allowed(bucket, limit) {
  const now = Date.now();
  const hits = (bucket.hits ||= []);
  while (hits.length && now - hits[0] > limit.windowMs) hits.shift();
  if (hits.length >= limit.count) return false;
  hits.push(now);
  return true;
}

function registerAllowed(ip) {
  const now = Date.now();
  const hits = (registerHits.get(ip) || []).filter(t => now - t < REGISTER_LIMIT.windowMs);
  if (hits.length >= REGISTER_LIMIT.count) { registerHits.set(ip, hits); return false; }
  hits.push(now);
  registerHits.set(ip, hits);
  return true;
}

function goOnline(ws, username) {
  ws.user = username;
  if (!online.has(username)) online.set(username, new Set());
  online.get(username).add(ws);
  send(ws, { t: 'ready', username });
  for (const env of db.queue[username] || []) send(ws, { t: 'msg', ...env });
}

wss.on('connection', (ws, req) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  ws.nonce = crypto.randomBytes(32).toString('base64');
  ws.user = null;
  ws.alive = true;
  ws.rate = {};
  ws.on('pong', () => { ws.alive = true; });

  send(ws, { t: 'hello', nonce: ws.nonce });

  ws.on('message', raw => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch (_) { return; }
    if (!m || typeof m !== 'object' || typeof m.t !== 'string') return;

    switch (m.t) {
      case 'register': return onRegister(ws, m, ip).catch(logErr);
      case 'pwlogin':  return onPwLogin(ws, m, ip).catch(logErr);
      case 'auth':     return onAuth(ws, m);
      default:
        if (!ws.user) return send(ws, { t: 'error', code: 'unauthenticated' });
        if (m.t === 'lookup') return onLookup(ws, m);
        if (m.t === 'msg')    return onMsg(ws, m);
        if (m.t === 'ack')    return onAck(ws, m);
    }
  });

  ws.on('close', () => {
    if (ws.user && online.has(ws.user)) {
      online.get(ws.user).delete(ws);
      if (!online.get(ws.user).size) online.delete(ws.user);
    }
  });
  ws.on('error', () => {});
});

async function onRegister(ws, m, ip) {
  if (ws.user) return;
  const username = String(m.username || '');
  if (!USERNAME_RE.test(username)) return send(ws, { t: 'error', code: 'bad_username' });
  if (db.users[username]) return send(ws, { t: 'error', code: 'taken' });
  if (!registerAllowed(ip)) return send(ws, { t: 'error', code: 'rate_limited' });

  const signPub = cleanJwk(m.signPub);
  const dhPub = cleanJwk(m.dhPub);
  if (!signPub || !dhPub) return send(ws, { t: 'error', code: 'bad_key' });

  // Proof of possession of the signing key
  if (!verifySig(signPub, authMessage(ws.nonce, username), String(m.sig || ''))) {
    return send(ws, { t: 'error', code: 'auth_failed' });
  }

  // Password material: the locked-keys blob plus a salted hash of the client's "auth" value
  const pw = cleanPw(m.pw);
  if (!pw) return send(ws, { t: 'error', code: 'bad_password' });
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(pw.auth, salt, 32);
  if (ws.user) return;
  if (db.users[username]) return send(ws, { t: 'error', code: 'taken' }); // lost a race while hashing

  db.users[username] = {
    signPub, dhPub, created: Date.now(),
    pw: { salt: salt.toString('base64'), hash: hash.toString('base64'), blob: pw.blob },
  };
  db.queue[username] = [];
  saveSoon();
  goOnline(ws, username);
}

async function onPwLogin(ws, m, ip) {
  if (ws.user) return;
  const username = String(m.username || '');
  const auth = String(m.auth || '');
  if (!USERNAME_RE.test(username) || !AUTH_RE.test(auth)) return send(ws, { t: 'error', code: 'auth_failed' });
  if (loginBlocked(username, ip)) return send(ws, { t: 'error', code: 'too_many_attempts' });
  noteLoginAttempt(username, ip);

  const rec = db.users[username] && db.users[username].pw;
  const hash = await scryptAsync(auth, rec ? Buffer.from(rec.salt, 'base64') : DUMMY_SALT, 32);
  if (!rec || !crypto.timingSafeEqual(hash, Buffer.from(rec.hash, 'base64'))) {
    return send(ws, { t: 'error', code: 'auth_failed' });
  }
  forgiveLoginAttempt(username, ip);
  send(ws, { t: 'blob', blob: rec.blob });
}

function onAuth(ws, m) {
  if (ws.user) return;
  const username = String(m.username || '');
  const user = db.users[username];
  if (!user) return send(ws, { t: 'error', code: 'auth_failed' });
  if (!verifySig(user.signPub, authMessage(ws.nonce, username), String(m.sig || ''))) {
    return send(ws, { t: 'error', code: 'auth_failed' });
  }
  goOnline(ws, username);
}

function onLookup(ws, m) {
  const username = String(m.username || '');
  const user = db.users[username];
  if (!user) return send(ws, { t: 'user', username, missing: true });
  send(ws, { t: 'user', username, dhPub: user.dhPub, signPub: user.signPub });
}

function onMsg(ws, m) {
  if (!allowed(ws.rate, MSG_LIMIT)) return send(ws, { t: 'error', code: 'rate_limited', id: m.id });

  const to = String(m.to || '');
  const id = String(m.id || '');
  const iv = String(m.iv || '');
  const ct = String(m.ct || '');
  if (!db.users[to]) return send(ws, { t: 'error', code: 'no_such_user', id });
  if (!/^[a-f0-9]{32}$/.test(id) || iv.length > 32 || !ct || ct.length > MAX_CT_LEN) {
    return send(ws, { t: 'error', code: 'bad_message', id });
  }

  const queue = (db.queue[to] ||= []);
  if (queue.length >= MAX_QUEUE_PER_USER) return send(ws, { t: 'error', code: 'queue_full', id });
  const queuedBytes = queue.reduce((n, e) => n + e.ct.length, 0);
  if (queuedBytes + ct.length > MAX_QUEUE_BYTES) return send(ws, { t: 'error', code: 'queue_full', id });

  const env = { id, from: ws.user, ts: Date.now(), iv, ct };
  queue.push(env);        // kept until the recipient acknowledges
  saveSoon();

  for (const peer of online.get(to) || []) send(peer, { t: 'msg', ...env });
  send(ws, { t: 'sent', id, ts: env.ts });
}

function onAck(ws, m) {
  if (!Array.isArray(m.ids)) return;
  const ids = new Set(m.ids.slice(0, 200).map(String));
  const queue = db.queue[ws.user] || [];
  db.queue[ws.user] = queue.filter(env => !ids.has(env.id));
  saveSoon();
}

// Drop dead connections
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false;
    ws.ping();
  }
  for (const key of [...loginFails.keys()]) recentFails(key);
}, 30_000).unref();

server.listen(PORT, () => {
  console.log(`Parley is running at http://localhost:${PORT}`);
});

// ======================================================================
// Web app files, served to the browser. Keep the "//| " prefix on every line.
// ======================================================================
//#### FILE: index.html
//| <!doctype html>
//| <html lang="en">
//| <head>
//|   <meta charset="utf-8">
//|   <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
//|   <meta name="color-scheme" content="light dark">
//|   <title>Parley</title>
//|   <link rel="stylesheet" href="/style.css">
//| </head>
//| <body>
//|
//|   <!-- First run: create an identity -->
//|   <main id="onboard" class="onboard" hidden>
//|     <div class="onboard-card">
//|       <h1 class="wordmark">Parley</h1>
//|       <p class="lede">Messages are locked on your device and can only be opened by the person you send them to. The server only ever sees scrambled data.</p>
//|       <form id="onboard-form">
//|         <div class="tabs" role="tablist" aria-label="Account">
//|           <button type="button" id="tab-signup" class="tab" role="tab" aria-selected="true">Create account</button>
//|           <button type="button" id="tab-login" class="tab" role="tab" aria-selected="false">Log in</button>
//|         </div>
//|
//|         <div class="field">
//|           <label for="username">Username</label>
//|           <input id="username" name="username" required minlength="3" maxlength="24"
//|                  pattern="[a-z0-9_]{3,24}" inputmode="latin" autocomplete="username" autocapitalize="none" spellcheck="false">
//|           <p id="username-hint" class="hint">3–24 characters: lowercase letters, numbers, underscore.</p>
//|         </div>
//|
//|         <div class="field">
//|           <label for="password">Password</label>
//|           <input id="password" name="password" type="password" required minlength="8" maxlength="128" autocomplete="new-password">
//|           <p id="password-hint" class="hint">At least 8 characters. A longer phrase is stronger. There is no password reset.</p>
//|         </div>
//|
//|         <div class="field" id="confirm-row">
//|           <label for="password2">Confirm password</label>
//|           <input id="password2" name="password2" type="password" required maxlength="128" autocomplete="new-password">
//|         </div>
//|
//|         <p id="onboard-error" class="error" role="alert" hidden></p>
//|         <button type="submit" id="onboard-submit" class="primary">Create account</button>
//|       </form>
//|       <p class="fine">Your password locks your keys in this browser before a backup copy is stored on the server, so the server can never read your messages or your password. If you forget your password the account cannot be recovered. Message history stays on this device and is erased when you log out.</p>
//|     </div>
//|   </main>
//|
//|   <!-- Main app -->
//|   <div id="app" class="app" hidden>
//|     <aside id="side" class="side">
//|       <header class="side-head">
//|         <div>
//|           <div class="wordmark small">Parley</div>
//|           <div class="me"><span id="me-name"></span> <span id="status" class="status" data-state="connecting" title="Connecting"></span></div>
//|         </div>
//|         <button id="logout" type="button" class="ghost">Log out</button>
//|       </header>
//|
//|       <form id="new-chat" class="new-chat" autocomplete="off">
//|         <label for="peer-input" class="sr">Start a chat</label>
//|         <input id="peer-input" placeholder="Start a chat with a username" maxlength="24"
//|                autocapitalize="none" spellcheck="false">
//|         <button type="submit" class="ghost">Start</button>
//|       </form>
//|       <p id="new-chat-error" class="error pad" role="alert" hidden></p>
//|
//|       <ul id="contacts" class="contacts" aria-label="Conversations"></ul>
//|       <p id="contacts-empty" class="empty pad">No conversations yet. Enter a username above to start one.</p>
//|     </aside>
//|
//|     <section id="thread" class="thread" aria-live="polite">
//|       <div id="thread-empty" class="thread-empty">
//|         <p>Pick a conversation, or start a new one.</p>
//|       </div>
//|
//|       <div id="thread-view" class="thread-view" hidden>
//|         <header class="thread-head">
//|           <button id="back" class="icon-btn back" aria-label="Back to conversations">‹</button>
//|           <div class="peer">
//|             <div id="peer-name" class="peer-name"></div>
//|             <div id="peer-verify" class="peer-verify"></div>
//|           </div>
//|           <button id="safety-btn" class="ghost">Verify</button>
//|         </header>
//|
//|         <div id="key-warning" class="banner" role="alert" hidden>
//|           <p><strong>This person's keys changed.</strong> They may have reinstalled, or someone may be intercepting. Compare safety numbers with them another way before you continue.</p>
//|           <div class="banner-actions">
//|             <button id="key-accept" class="ghost">Trust the new keys</button>
//|           </div>
//|         </div>
//|
//|         <ol id="msgs" class="msgs"></ol>
//|
//|         <div id="attach-preview" class="attach-preview" hidden>
//|           <img id="attach-img" class="attach-img" alt="Photo to send" hidden>
//|           <span id="attach-info" class="attach-info" role="status"></span>
//|           <button type="button" id="attach-remove" class="ghost">Remove</button>
//|         </div>
//|
//|         <form id="composer" class="composer" autocomplete="off">
//|           <input id="photo-input" type="file" accept="image/*" hidden>
//|           <button type="button" id="attach" class="icon-btn attach" aria-label="Add a photo" title="Add a photo">
//|             <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
//|               <rect x="3" y="4" width="18" height="16" rx="3"></rect>
//|               <circle cx="9" cy="10" r="1.8"></circle>
//|               <path d="M21 16l-5.5-5.5L6 20"></path>
//|             </svg>
//|           </button>
//|           <label for="text" class="sr">Message</label>
//|           <textarea id="text" rows="1" maxlength="8000" placeholder="Write a message"></textarea>
//|           <button type="submit" class="primary" id="send">Send</button>
//|         </form>
//|       </div>
//|     </section>
//|   </div>
//|
//|   <dialog id="safety">
//|     <form method="dialog" class="safety-card">
//|       <h2>Safety number</h2>
//|       <p>Compare this with <strong id="safety-peer"></strong> in person or over a call. If both of you see the same number, nobody is sitting between you.</p>
//|       <p id="safety-number" class="safety-number"></p>
//|       <div class="dialog-actions">
//|         <button id="safety-verify" type="button" class="primary">They match</button>
//|         <button value="close" class="ghost">Close</button>
//|       </div>
//|     </form>
//|   </dialog>
//|
//|   <dialog id="photo-view" class="photo-view">
//|     <form method="dialog">
//|       <button class="icon-btn photo-close" aria-label="Close photo">&times;</button>
//|     </form>
//|     <img id="photo-view-img" alt="Photo">
//|   </dialog>
//|
//|   <script src="/app.js"></script>
//| </body>
//| </html>
//#### END
//#### FILE: style.css
//| :root {
//|   --bg: #e8edef;
//|   --panel: #f9fbfb;
//|   --line: #d3dbde;
//|   --ink: #14232b;
//|   --ink-soft: #5b6c74;
//|   --bubble-out: #14232b;
//|   --bubble-out-ink: #f2f6f7;
//|   --bubble-in: #ffffff;
//|   --lock: #b86b00;
//|   --lock-soft: #fbefd9;
//|   --danger: #b3261e;
//|   --focus: #1f6f9a;
//|   --serif: "Iowan Old Style", "Palatino Linotype", Charter, Georgia, serif;
//|   --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
//| }
//|
//| @media (prefers-color-scheme: dark) {
//|   :root {
//|     --bg: #0d1519;
//|     --panel: #121d22;
//|     --line: #243238;
//|     --ink: #e6eef0;
//|     --ink-soft: #8fa2aa;
//|     --bubble-out: #e6eef0;
//|     --bubble-out-ink: #0d1519;
//|     --bubble-in: #1b2a31;
//|     --lock: #e7a23c;
//|     --lock-soft: #2a2213;
//|     --danger: #ff8a80;
//|     --focus: #6cc0ec;
//|   }
//| }
//|
//| * { box-sizing: border-box; }
//| [hidden] { display: none !important; }
//|
//| html, body { height: 100%; margin: 0; }
//| body {
//|   background: var(--bg);
//|   color: var(--ink);
//|   font: 16px/1.45 var(--sans);
//|   -webkit-font-smoothing: antialiased;
//| }
//|
//| button, input, textarea { font: inherit; color: inherit; }
//| :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
//| .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
//|
//| .wordmark { font-family: var(--serif); font-size: 2.6rem; font-weight: 600; letter-spacing: -0.02em; margin: 0; }
//| .wordmark.small { font-size: 1.35rem; }
//|
//| input, textarea {
//|   width: 100%;
//|   background: var(--panel);
//|   border: 1px solid var(--line);
//|   border-radius: 8px;
//|   padding: 0.6rem 0.75rem;
//| }
//| textarea { resize: none; max-height: 9rem; }
//|
//| button { cursor: pointer; border-radius: 8px; border: 1px solid transparent; padding: 0.55rem 1rem; }
//| button.primary { background: var(--ink); color: var(--bg); font-weight: 600; }
//| button.primary:disabled { opacity: 0.4; cursor: default; }
//| button.ghost { background: transparent; border-color: var(--line); }
//| button.ghost:hover { background: var(--lock-soft); }
//| .icon-btn { background: none; border: 0; font-size: 1.8rem; line-height: 1; padding: 0 0.5rem; }
//|
//| .error { color: var(--danger); margin: 0.5rem 0; font-size: 0.92rem; }
//| .hint, .fine, .empty { color: var(--ink-soft); font-size: 0.88rem; }
//| .pad { padding: 0 1rem; }
//|
//| /* ---------- onboarding ---------- */
//| .onboard { min-height: 100%; display: grid; place-items: center; padding: 1.5rem; }
//| .onboard-card { width: min(26rem, 100%); }
//| .lede { font-family: var(--serif); font-size: 1.15rem; line-height: 1.5; margin: 0.75rem 0 1.75rem; }
//| .onboard-card label { display: block; font-weight: 600; margin-bottom: 0.4rem; }
//| .onboard-card button { width: 100%; margin-top: 0.5rem; padding: 0.75rem; }
//|
//| /* ---------- sign-up / log-in ---------- */
//| .tabs { display: flex; gap: 0.25rem; padding: 0.25rem; border: 1px solid var(--line); border-radius: 10px; margin-bottom: 1.25rem; }
//| .onboard-card .tab { flex: 1; width: auto; margin: 0; padding: 0.5rem; background: transparent; border: 0; border-radius: 7px; color: var(--ink-soft); font-weight: 600; }
//| .onboard-card .tab[aria-selected="true"] { background: var(--panel); color: var(--ink); box-shadow: 0 1px 2px rgba(0, 0, 0, 0.15); }
//| .onboard-card .tab:disabled { opacity: 0.6; cursor: default; }
//| .field { margin-bottom: 0.9rem; }
//| .field .hint { margin: 0.3rem 0 0; }
//|
//| /* ---------- app layout ---------- */
//| .app { height: 100%; display: grid; grid-template-columns: 20rem 1fr; }
//| .side { background: var(--panel); border-right: 1px solid var(--line); display: flex; flex-direction: column; min-height: 0; padding-top: env(safe-area-inset-top, 0px); }
//| .side-head { padding: 1rem; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
//| .side-head .ghost { padding: 0.35rem 0.7rem; font-size: 0.88rem; }
//| .me { color: var(--ink-soft); font-size: 0.9rem; display: flex; align-items: center; gap: 0.4rem; margin-top: 0.15rem; }
//| .status { width: 0.6rem; height: 0.6rem; border-radius: 50%; background: var(--ink-soft); display: inline-block; }
//| .status[data-state="online"] { background: #2e9e5b; }
//| .status[data-state="connecting"] { background: var(--lock); }
//|
//| .new-chat { display: flex; gap: 0.5rem; padding: 0.75rem 1rem; }
//| .new-chat button { white-space: nowrap; }
//|
//| .contacts { list-style: none; margin: 0; padding: 0; overflow-y: auto; flex: 1; }
//| .contacts li button {
//|   width: 100%; text-align: left; background: none; border: 0; border-radius: 0;
//|   padding: 0.75rem 1rem; display: grid; grid-template-columns: 1fr auto; gap: 0.1rem 0.5rem;
//|   border-bottom: 1px solid var(--line);
//| }
//| .contacts li button[aria-current="true"] { background: var(--lock-soft); }
//| .contacts .name { font-weight: 600; }
//| .contacts .preview { grid-column: 1; color: var(--ink-soft); font-size: 0.88rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
//| .contacts .badge { grid-row: 1 / span 2; grid-column: 2; align-self: center; min-width: 1.4rem; text-align: center; background: var(--lock); color: #fff; border-radius: 999px; font-size: 0.78rem; padding: 0.1rem 0.4rem; }
//|
//| .thread { display: flex; flex-direction: column; min-width: 0; min-height: 0; }
//| .thread-empty { margin: auto; color: var(--ink-soft); font-family: var(--serif); font-size: 1.1rem; }
//| .thread-view { display: flex; flex-direction: column; height: 100%; min-height: 0; padding-top: env(safe-area-inset-top, 0px); }
//|
//| .thread-head { display: flex; align-items: center; gap: 0.5rem; padding: 0.7rem 1rem; background: var(--panel); border-bottom: 1px solid var(--line); }
//| .back { display: none; }
//| .peer { flex: 1; min-width: 0; }
//| .peer-name { font-family: var(--serif); font-size: 1.2rem; font-weight: 600; }
//| .peer-verify { font-size: 0.82rem; color: var(--ink-soft); }
//| .peer-verify.ok { color: var(--lock); }
//|
//| .banner { background: var(--lock-soft); border-bottom: 1px solid var(--lock); padding: 0.75rem 1rem; font-size: 0.92rem; }
//| .banner p { margin: 0 0 0.5rem; }
//|
//| .msgs { list-style: none; margin: 0; padding: 1rem; flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 0.35rem; }
//| .msg { max-width: min(34rem, 82%); padding: 0.5rem 0.8rem; border-radius: 14px; white-space: pre-wrap; overflow-wrap: anywhere; }
//| .msg.in { align-self: flex-start; background: var(--bubble-in); border: 1px solid var(--line); border-bottom-left-radius: 4px; }
//| .msg.out { align-self: flex-end; background: var(--bubble-out); color: var(--bubble-out-ink); border-bottom-right-radius: 4px; }
//| .msg .meta { display: block; font-size: 0.72rem; opacity: 0.65; margin-top: 0.15rem; text-align: right; }
//| .msg.failed .meta { color: var(--danger); opacity: 1; }
//| .day { align-self: center; color: var(--ink-soft); font-size: 0.8rem; margin: 0.6rem 0 0.2rem; }
//|
//| .composer { display: flex; gap: 0.5rem; align-items: flex-end; padding: 0.75rem 1rem calc(0.75rem + env(safe-area-inset-bottom, 0px)); background: var(--panel); border-top: 1px solid var(--line); }
//|
//| /* ---------- safety dialog ---------- */
//| dialog { background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: 12px; padding: 0; width: min(28rem, calc(100% - 2rem)); }
//| dialog::backdrop { background: rgba(0, 0, 0, 0.5); }
//| .safety-card { padding: 1.25rem; }
//| .safety-card h2 { font-family: var(--serif); margin: 0 0 0.5rem; }
//| .safety-number { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 1.25rem; line-height: 1.9; letter-spacing: 0.04em; background: var(--bg); border-radius: 8px; padding: 0.75rem 1rem; }
//| .dialog-actions { display: flex; gap: 0.5rem; justify-content: flex-end; }
//|
//| /* ---------- photos ---------- */
//| .composer .attach { padding: 0.55rem 0.35rem; color: var(--ink-soft); align-self: flex-end; }
//| .composer .attach:hover { color: var(--ink); }
//| .attach svg { display: block; width: 1.5rem; height: 1.5rem; }
//|
//| .attach-preview { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 1rem; background: var(--panel); border-top: 1px solid var(--line); }
//| .attach-img { width: 3.5rem; height: 3.5rem; object-fit: cover; border-radius: 8px; border: 1px solid var(--line); }
//| .attach-info { flex: 1; min-width: 0; color: var(--ink-soft); font-size: 0.88rem; }
//| .attach-info.error { color: var(--danger); }
//|
//| .msg.has-photo { padding: 0.3rem 0.3rem 0.5rem; }
//| .msg.has-photo > span { padding: 0 0.5rem; }
//| .msg.has-photo .meta { padding: 0 0.5rem; }
//| .photo-btn { display: block; padding: 0; margin: 0 0 0.3rem; background: none; border: 0; border-radius: 10px; cursor: zoom-in; max-width: 100%; }
//| .msg-photo { display: block; max-width: 100%; max-height: 22rem; width: auto; height: auto; border-radius: 10px; }
//|
//| .photo-view { width: min(60rem, calc(100% - 2rem)); background: transparent; border: 0; text-align: center; }
//| .photo-view img { max-width: 100%; max-height: 82vh; border-radius: 10px; }
//| .photo-close { position: absolute; top: 0.25rem; right: 0.5rem; color: #fff; text-shadow: 0 0 6px rgba(0, 0, 0, 0.7); }
//|
//| /* ---------- small screens ---------- */
//| @media (max-width: 720px) {
//|   .app { grid-template-columns: 1fr; }
//|   .app[data-view="list"] .thread { display: none; }
//|   .app[data-view="chat"] .side { display: none; }
//|   .back { display: block; }
//|   .msg { max-width: 88%; }
//| }
//|
//| @media (prefers-reduced-motion: reduce) {
//|   * { transition: none !important; animation: none !important; scroll-behavior: auto !important; }
//| }
//#### END
//#### FILE: app.js
//| 'use strict';
//| /**
//|  * Parley client.
//|  *
//|  * Crypto design
//|  *  - Each device makes two P-256 key pairs: ECDSA (proves who you are to the server)
//|  *    and ECDH (derives a secret shared with each contact). Private keys are stored as
//|  *    NON-EXTRACTABLE CryptoKeys in IndexedDB, so page scripts cannot read them out.
//|  *  - Shared secret = ECDH(my private, their public) -> HKDF-SHA-256 -> AES-256-GCM key.
//|  *  - Every message uses a fresh random 96-bit IV, and binds sender, recipient and message id
//|  *    as AES-GCM additional data, so the server can't redirect or relabel ciphertexts.
//|  *  - Contacts' keys are pinned on first use (TOFU). If they change, you get a warning.
//|  *    Compare the safety number out-of-band to rule out a malicious server.
//|  */
//| (() => {
//|   const $ = sel => document.querySelector(sel);
//|   const subtle = crypto.subtle;
//|   const enc = new TextEncoder();
//|   const dec = new TextDecoder();
//|
//|   // ---------- encoding helpers ----------
//|   function b64(buf) {
//|     const bytes = new Uint8Array(buf);
//|     let s = '';
//|     for (let i = 0; i < bytes.length; i += 0x8000) {
//|       s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
//|     }
//|     return btoa(s);
//|   }
//|   function unb64(str) {
//|     const bin = atob(str);
//|     const out = new Uint8Array(bin.length);
//|     for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
//|     return out;
//|   }
//|   const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
//|   const randomId = () => hex(crypto.getRandomValues(new Uint8Array(16)));
//|   const pubOnly = jwk => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
//|   const sameKey = (a, b) => a && b && a.x === b.x && a.y === b.y;
//|
//|   // ---------- IndexedDB ----------
//|   let db;
//|   function openDB() {
//|     return new Promise((resolve, reject) => {
//|       const req = indexedDB.open('parley', 1);
//|       req.onupgradeneeded = () => {
//|         const d = req.result;
//|         d.createObjectStore('kv');
//|         d.createObjectStore('contacts', { keyPath: 'username' });
//|         d.createObjectStore('messages', { keyPath: 'id' }).createIndex('peer', 'peer');
//|       };
//|       req.onsuccess = () => resolve(req.result);
//|       req.onerror = () => reject(req.error);
//|     });
//|   }
//|   function run(store, mode, fn) {
//|     return new Promise((resolve, reject) => {
//|       const t = db.transaction(store, mode);
//|       const rq = fn(t.objectStore(store));
//|       t.oncomplete = () => resolve(rq ? rq.result : undefined);
//|       t.onerror = () => reject(t.error);
//|       t.onabort = () => reject(t.error);
//|     });
//|   }
//|   const kvGet = k => run('kv', 'readonly', s => s.get(k));
//|   const kvSet = (k, v) => run('kv', 'readwrite', s => s.put(v, k));
//|   const kvDel = k => run('kv', 'readwrite', s => s.delete(k));
//|   const contactsAll = () => run('contacts', 'readonly', s => s.getAll());
//|   const contactPut = c => run('contacts', 'readwrite', s => s.put(c));
//|   const msgPut = m => run('messages', 'readwrite', s => s.put(m));
//|   const msgGet = id => run('messages', 'readonly', s => s.get(id));
//|   const msgsFor = peer => run('messages', 'readonly', s => s.index('peer').getAll(peer))
//|     .then(list => list.sort((a, b) => a.ts - b.ts));
//|
//|   // ---------- state ----------
//|   let me = null;            // { username, sign, dh, registered }
//|   let ws = null;
//|   let backoff = 1000;
//|   let active = null;        // username of open conversation
//|   const contacts = new Map();   // username -> contact record
//|   const lastMsg = new Map();    // username -> latest message record
//|   const unread = new Map();     // username -> count
//|   const sessionKeys = new Map();
//|   const pendingLookups = new Map();
//|
//|   // ---------- account: password + identity ----------
//|   // The password never leaves the browser. PBKDF2 stretches it into 64 bytes:
//|   //   first 32 bytes -> AES key that locks a copy of the private keys. The server keeps that
//|   //                     copy as an opaque blob so you can log in from another browser.
//|   //   last 32 bytes  -> "auth" value. The server stores only a salted hash of it and hands the
//|   //                     blob to whoever presents the matching value.
//|   // So the server never sees the password or any usable key.
//|   const PBKDF2_ROUNDS = 600000;
//|   let authMode = 'signup';   // onboarding screen: 'signup' | 'login'
//|   let busy = false;
//|   let attempt = null;        // sign-up or log-in in progress: { mode, username, auth, blob?, wrap? }
//|   let helloNonce = null;     // challenge from the server on the current connection
//|
//|   async function derivePasswordKeys(username, password) {
//|     const base = await subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
//|     const bits = new Uint8Array(await subtle.deriveBits(
//|       { name: 'PBKDF2', hash: 'SHA-256', iterations: PBKDF2_ROUNDS, salt: enc.encode(`parley-pw-v1:${username}`) },
//|       base,
//|       512
//|     ));
//|     const wrap = await subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
//|     return { wrap, auth: b64(bits.slice(32)) };
//|   }
//|
//|   async function wrapKeys(username, wrapKey, signJwk, dhJwk) {
//|     const iv = crypto.getRandomValues(new Uint8Array(12));
//|     const ct = await subtle.encrypt(
//|       { name: 'AES-GCM', iv, additionalData: enc.encode(`parley-keys-v1:${username}`) },
//|       wrapKey,
//|       enc.encode(JSON.stringify({ sign: signJwk, dh: dhJwk }))
//|     );
//|     return { iv: b64(iv), ct: b64(ct) };
//|   }
//|
//|   async function unwrapKeys(username, wrapKey, blob) {
//|     const plain = await subtle.decrypt(
//|       { name: 'AES-GCM', iv: unb64(blob.iv), additionalData: enc.encode(`parley-keys-v1:${username}`) },
//|       wrapKey,
//|       unb64(blob.ct)
//|     );
//|     const { sign, dh } = JSON.parse(dec.decode(plain));
//|     return { sign, dh };
//|   }
//|
//|   // Turn private-key JWKs into NON-extractable CryptoKeys for everyday use.
//|   async function keysFromJwks(signJwk, dhJwk) {
//|     const signAlg = { name: 'ECDSA', namedCurve: 'P-256' };
//|     const dhAlg = { name: 'ECDH', namedCurve: 'P-256' };
//|     return {
//|       sign: {
//|         privateKey: await subtle.importKey('jwk', signJwk, signAlg, false, ['sign']),
//|         publicKey: await subtle.importKey('jwk', pubOnly(signJwk), signAlg, true, ['verify']),
//|       },
//|       dh: {
//|         privateKey: await subtle.importKey('jwk', dhJwk, dhAlg, false, ['deriveBits']),
//|         publicKey: await subtle.importKey('jwk', pubOnly(dhJwk), dhAlg, true, []),
//|       },
//|     };
//|   }
//|
//|   async function startSignup(username, password) {
//|     // Extractable only for this moment, so a locked copy can be made for the server.
//|     const sign = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
//|     const dh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
//|     const signJwk = await subtle.exportKey('jwk', sign.privateKey);
//|     const dhJwk = await subtle.exportKey('jwk', dh.privateKey);
//|     const { wrap, auth } = await derivePasswordKeys(username, password);
//|     const blob = await wrapKeys(username, wrap, signJwk, dhJwk);
//|     const keys = await keysFromJwks(signJwk, dhJwk);   // from here on, keys cannot be read back out
//|     me = { username, sign: keys.sign, dh: keys.dh, registered: false };
//|     attempt = { mode: 'signup', username, auth, blob };
//|     reconnect();
//|   }
//|
//|   async function startLogin(username, password) {
//|     const { wrap, auth } = await derivePasswordKeys(username, password);
//|     me = null;
//|     attempt = { mode: 'login', username, auth, wrap };
//|     reconnect();
//|   }
//|
//|   function reconnect() {
//|     const old = ws;
//|     ws = null;
//|     if (old) old.close();
//|     connect();
//|   }
//|
//|   function failAttempt(text) {
//|     attempt = null;
//|     me = null;
//|     const old = ws;
//|     ws = null;
//|     if (old) old.close();
//|     showOnboard(text);
//|   }
//|
//|   async function wipeLocal() {
//|     for (const store of ['kv', 'contacts', 'messages']) await run(store, 'readwrite', s => s.clear());
//|   }
//|
//|   // ---------- onboarding ----------
//|   function setBusy(on, label) {
//|     busy = on;
//|     $('#onboard-submit').disabled = on;
//|     $('#tab-signup').disabled = on;
//|     $('#tab-login').disabled = on;
//|     $('#onboard-submit').textContent = on ? (label || 'Working…') : (authMode === 'signup' ? 'Create account' : 'Log in');
//|   }
//|
//|   function showOnboard(errorText) {
//|     $('#app').hidden = true;
//|     $('#onboard').hidden = false;
//|     setBusy(false);
//|     const err = $('#onboard-error');
//|     err.hidden = !errorText;
//|     err.textContent = errorText || '';
//|   }
//|
//|   function setAuthMode(mode) {
//|     authMode = mode;
//|     const signup = mode === 'signup';
//|     $('#tab-signup').setAttribute('aria-selected', String(signup));
//|     $('#tab-login').setAttribute('aria-selected', String(!signup));
//|     $('#confirm-row').hidden = !signup;
//|     $('#password2').required = signup;
//|     $('#password-hint').hidden = !signup;
//|     $('#username-hint').hidden = !signup;
//|     const pw = $('#password');
//|     pw.minLength = signup ? 8 : 1;
//|     pw.autocomplete = signup ? 'new-password' : 'current-password';
//|     $('#onboard-error').hidden = true;
//|     setBusy(false);
//|   }
//|
//|   $('#tab-signup').addEventListener('click', () => setAuthMode('signup'));
//|   $('#tab-login').addEventListener('click', () => setAuthMode('login'));
//|
//|   $('#onboard-form').addEventListener('submit', async e => {
//|     e.preventDefault();
//|     if (busy) return;
//|     const name = $('#username').value.trim().toLowerCase();
//|     const password = $('#password').value;
//|     if (!/^[a-z0-9_]{3,24}$/.test(name)) {
//|       return showOnboard('Usernames are 3–24 characters: lowercase letters, numbers or underscore.');
//|     }
//|     if (authMode === 'signup') {
//|       if (password.length < 8 || password.length > 128) return showOnboard('Use a password of 8 to 128 characters.');
//|       if (password !== $('#password2').value) return showOnboard('The two passwords do not match.');
//|     } else if (!password) {
//|       return showOnboard('Enter your password.');
//|     }
//|     setBusy(true, authMode === 'signup' ? 'Creating your keys…' : 'Logging in…');
//|     try {
//|       await (authMode === 'signup' ? startSignup(name, password) : startLogin(name, password));
//|     } catch (err) {
//|       console.error(err);
//|       failAttempt('Could not set up keys in this browser. Open the page over HTTPS or on localhost.');
//|     }
//|   });
//|
//|   $('#logout').addEventListener('click', async () => {
//|     if (!me) return;
//|     const ok = confirm(
//|       `Log out of ${me.username}?\n\nThe message history stored on this device will be erased. ` +
//|       'You can log back in with your password, but past messages will not come back.'
//|     );
//|     if (!ok) return;
//|     const old = ws;
//|     ws = null;
//|     me = null;
//|     attempt = null;
//|     if (old) old.close();
//|     await wipeLocal();
//|     contacts.clear(); lastMsg.clear(); unread.clear(); sessionKeys.clear(); pendingLookups.clear();
//|     active = null;
//|     lastDay = '';
//|     clearPhoto();
//|     $('#msgs').textContent = '';
//|     $('#contacts').textContent = '';
//|     $('#thread-view').hidden = true;
//|     $('#thread-empty').hidden = false;
//|     $('#app').dataset.view = 'list';
//|     for (const id of ['#username', '#password', '#password2']) $(id).value = '';
//|     setAuthMode('login');
//|     showOnboard();
//|   });
//|
//|   setAuthMode('signup');
//|
//|   // ---------- networking ----------
//|   function setStatus(state) {
//|     const el = $('#status');
//|     el.dataset.state = state;
//|     el.title = { online: 'Connected', connecting: 'Connecting…', offline: 'Offline, retrying…' }[state];
//|   }
//|
//|   function connect() {
//|     setStatus('connecting');
//|     const proto = location.protocol === 'https:' ? 'wss' : 'ws';
//|     const sock = new WebSocket(`${proto}://${location.host}/ws`);
//|     ws = sock;
//|
//|     sock.onmessage = ev => {
//|       if (sock !== ws) return;
//|       let m;
//|       try { m = JSON.parse(ev.data); } catch (_) { return; }
//|       handleServer(m).catch(err => console.error('handler error', err));
//|     };
//|     sock.onclose = () => {
//|       if (sock !== ws) return;           // a newer connection replaced this one
//|       setStatus('offline');
//|       pendingLookups.forEach(p => p.reject(new Error('offline')));
//|       pendingLookups.clear();
//|       if (attempt) return failAttempt('Could not reach the server. Check your connection and try again.');
//|       setTimeout(() => { if (me && sock === ws) connect(); }, backoff);
//|       backoff = Math.min(backoff * 2, 15000);
//|     };
//|   }
//|
//|   // Prove we own the account's signing key (or register it, for a brand-new account).
//|   async function sendAuth() {
//|     const sig = await subtle.sign(
//|       { name: 'ECDSA', hash: 'SHA-256' },
//|       me.sign.privateKey,
//|       enc.encode(`pm-auth-v1:${helloNonce}:${me.username}`)
//|     );
//|     if (me.registered) {
//|       wsSend({ t: 'auth', username: me.username, sig: b64(sig) });
//|       return;
//|     }
//|     const [signPub, dhPub] = await Promise.all([
//|       subtle.exportKey('jwk', me.sign.publicKey),
//|       subtle.exportKey('jwk', me.dh.publicKey),
//|     ]);
//|     wsSend({
//|       t: 'register', username: me.username, sig: b64(sig),
//|       signPub: pubOnly(signPub), dhPub: pubOnly(dhPub),
//|       pw: attempt && attempt.mode === 'signup' ? { auth: attempt.auth, blob: attempt.blob } : undefined,
//|     });
//|   }
//|
//|   const wsSend = obj => ws && ws.readyState === 1 && (ws.send(JSON.stringify(obj)), true);
//|
//|   async function handleServer(m) {
//|     switch (m.t) {
//|       case 'hello':
//|         helloNonce = m.nonce;
//|         if (attempt && attempt.mode === 'login') {
//|           wsSend({ t: 'pwlogin', username: attempt.username, auth: attempt.auth });
//|         } else if (me) {
//|           await sendAuth();
//|         }
//|         break;
//|       case 'blob': {
//|         if (!attempt || attempt.mode !== 'login' || !m.blob) break;
//|         try {
//|           const { sign, dh } = await unwrapKeys(attempt.username, attempt.wrap, m.blob);
//|           const keys = await keysFromJwks(sign, dh);
//|           me = { username: attempt.username, sign: keys.sign, dh: keys.dh, registered: true };
//|         } catch (_) {
//|           return failAttempt('Could not unlock your keys. Check your username and password.');
//|         }
//|         await sendAuth();
//|         break;
//|       }
//|       case 'ready': {
//|         backoff = 1000;
//|         setStatus('online');
//|         const finishing = !!attempt;
//|         attempt = null;
//|         if (finishing || !me.registered) { me.registered = true; await kvSet('identity', me); }
//|         if (finishing) {
//|           $('#password').value = '';
//|           $('#password2').value = '';
//|           showApp();
//|         }
//|         break;
//|       }
//|       case 'user': {
//|         const p = pendingLookups.get(m.username);
//|         if (p) { pendingLookups.delete(m.username); p.resolve(m); }
//|         break;
//|       }
//|       case 'msg':
//|         await onIncoming(m);
//|         break;
//|       case 'sent':
//|         await updateStatus(m.id, 'sent', m.ts);
//|         break;
//|       case 'error':
//|         await onServerError(m);
//|         break;
//|     }
//|   }
//|
//|   async function onServerError(m) {
//|     if (attempt) {
//|       const messages = {
//|         taken: 'That username is taken. Pick another one.',
//|         bad_username: 'That username is not allowed. Use 3–24 lowercase letters, numbers or underscore.',
//|         bad_key: 'The server rejected the keys from this device. Try again.',
//|         bad_password: 'The server rejected that password. Use 8 to 128 characters.',
//|         rate_limited: 'Too many sign-ups from this network. Try again later.',
//|         too_many_attempts: 'Too many failed attempts. Wait a few minutes, then try again.',
//|         auth_failed: attempt.mode === 'login'
//|           ? 'Wrong username or password.'
//|           : 'The server rejected that account. Try a different username.',
//|       };
//|       return failAttempt(messages[m.code] || 'Something went wrong. Try again.');
//|     }
//|     if (m.id) {
//|       await updateStatus(m.id, 'failed');
//|       return;
//|     }
//|     if (m.code === 'bad_password' && me && !me.registered) {
//|       // An identity from before passwords existed that never finished registering.
//|       await wipeLocal();
//|       return failAttempt('Please create an account with a password.');
//|     }
//|     if (m.code === 'auth_failed') {
//|       setStatus('offline');
//|       console.error('Authentication failed for', me && me.username);
//|     }
//|   }
//|
//|   function lookup(username) {
//|     return new Promise((resolve, reject) => {
//|       if (!ws || ws.readyState !== 1) return reject(new Error('offline'));
//|       const timer = setTimeout(() => {
//|         pendingLookups.delete(username);
//|         reject(new Error('timeout'));
//|       }, 8000);
//|       pendingLookups.set(username, {
//|         resolve: v => { clearTimeout(timer); resolve(v); },
//|         reject: e => { clearTimeout(timer); reject(e); },
//|       });
//|       wsSend({ t: 'lookup', username });
//|     });
//|   }
//|
//|   // ---------- contacts & session keys ----------
//|   async function addContact(username) {
//|     const res = await lookup(username);
//|     if (res.missing) return null;
//|     const c = { username, dhPub: res.dhPub, verified: false, changedKey: null, added: Date.now() };
//|     contacts.set(username, c);
//|     await contactPut(c);
//|     return c;
//|   }
//|
//|   // Compare the server's current key for a contact with the one we pinned.
//|   async function checkKeyChange(username) {
//|     const c = contacts.get(username);
//|     if (!c) return;
//|     try {
//|       const res = await lookup(username);
//|       if (res.missing || !res.dhPub) return;
//|       if (!sameKey(res.dhPub, c.dhPub)) {
//|         c.changedKey = res.dhPub;
//|         await contactPut(c);
//|         if (active === username) renderThreadHeader();
//|       }
//|     } catch (_) { /* offline; try again later */ }
//|   }
//|
//|   async function sessionKey(peer) {
//|     if (sessionKeys.has(peer)) return sessionKeys.get(peer);
//|     const c = contacts.get(peer);
//|     if (!c) throw new Error('unknown contact');
//|     const theirs = await subtle.importKey('jwk', c.dhPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
//|     const bits = await subtle.deriveBits({ name: 'ECDH', public: theirs }, me.dh.privateKey, 256);
//|     const hkdfKey = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
//|     const pair = [me.username, peer].sort().join('|');
//|     const key = await subtle.deriveKey(
//|       { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('parley-v1'), info: enc.encode(pair) },
//|       hkdfKey,
//|       { name: 'AES-GCM', length: 256 },
//|       false,
//|       ['encrypt', 'decrypt']
//|     );
//|     sessionKeys.set(peer, key);
//|     return key;
//|   }
//|
//|   // Safety number: hash of both public ECDH keys, shown as six 5-digit groups.
//|   async function safetyNumber(peer) {
//|     const mine = pubOnly(await subtle.exportKey('jwk', me.dh.publicKey));
//|     const theirs = contacts.get(peer).dhPub;
//|     const parts = [`${mine.x}.${mine.y}`, `${theirs.x}.${theirs.y}`].sort();
//|     const digest = new Uint8Array(await subtle.digest('SHA-256', enc.encode(parts.join('|'))));
//|     const view = new DataView(digest.buffer);
//|     const groups = [];
//|     for (let i = 0; i < 6; i++) groups.push(String(view.getUint32(i * 4) % 100000).padStart(5, '0'));
//|     return groups.join(' ');
//|   }
//|
//|   // ---------- photos ----------
//|   // Photos are resized and re-encoded as JPEG in the browser before encryption. That keeps
//|   // them small enough for the relay and strips camera metadata such as GPS location.
//|   const PHOTO_MAX_DIM = 1280;
//|   const PHOTO_MAX_CHARS = 420000;      // data-URL length we are willing to send
//|   const PHOTO_RECV_MAX_CHARS = 600000; // what we accept from others
//|   const PHOTO_RE = /^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/;
//|   let pendingPhoto = null;             // { dataUrl, w, h }
//|   let preparingPhoto = false;
//|
//|   async function loadImage(file) {
//|     if (window.createImageBitmap) {
//|       try { return await createImageBitmap(file); } catch (_) { /* fall back below */ }
//|     }
//|     const url = await new Promise((resolve, reject) => {
//|       const r = new FileReader();
//|       r.onload = () => resolve(r.result);
//|       r.onerror = () => reject(r.error);
//|       r.readAsDataURL(file);
//|     });
//|     return new Promise((resolve, reject) => {
//|       const img = new Image();
//|       img.onload = () => resolve(img);
//|       img.onerror = () => reject(new Error('That file could not be read as an image.'));
//|       img.src = url;
//|     });
//|   }
//|
//|   async function compressPhoto(file) {
//|     if (!file.type.startsWith('image/')) throw new Error('Please choose an image file.');
//|     const src = await loadImage(file);
//|     try {
//|       const w0 = src.naturalWidth || src.width;
//|       const h0 = src.naturalHeight || src.height;
//|       if (!w0 || !h0) throw new Error('That file could not be read as an image.');
//|       let scale = Math.min(1, PHOTO_MAX_DIM / Math.max(w0, h0));
//|       for (let attempt = 0; attempt < 6; attempt++) {
//|         const w = Math.max(1, Math.round(w0 * scale));
//|         const h = Math.max(1, Math.round(h0 * scale));
//|         const canvas = document.createElement('canvas');
//|         canvas.width = w;
//|         canvas.height = h;
//|         const ctx = canvas.getContext('2d');
//|         ctx.fillStyle = '#fff';            // JPEG has no transparency
//|         ctx.fillRect(0, 0, w, h);
//|         ctx.drawImage(src, 0, 0, w, h);
//|         for (const q of [0.82, 0.7, 0.58, 0.46]) {
//|           const dataUrl = canvas.toDataURL('image/jpeg', q);
//|           if (!dataUrl.startsWith('data:image/jpeg')) throw new Error('This browser cannot encode photos.');
//|           if (dataUrl.length <= PHOTO_MAX_CHARS) return { dataUrl, w, h };
//|         }
//|         scale *= 0.75;
//|       }
//|       throw new Error('That photo is too large to send.');
//|     } finally {
//|       if (src.close) src.close();
//|     }
//|   }
//|
//|   // Validate a photo that arrived from another user before we ever put it in the page.
//|   function parsePhoto(p) {
//|     if (!p || typeof p.src !== 'string') return null;
//|     if (p.src.length > PHOTO_RECV_MAX_CHARS || !PHOTO_RE.test(p.src)) return null;
//|     const dim = v => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.min(4096, Math.max(0, n)) : 0; };
//|     return { src: p.src, w: dim(p.w), h: dim(p.h) };
//|   }
//|
//|   const previewText = rec => rec.photo ? (rec.text ? `Photo: ${rec.text}` : 'Photo') : rec.text;
//|
//|   // ---------- sending & receiving ----------
//|   const aad = (from, to, id) => enc.encode(`${from}>${to}:${id}`);
//|
//|   async function sendMessage(peer, text, photo) {
//|     const id = randomId();
//|     const iv = crypto.getRandomValues(new Uint8Array(12));
//|     const key = await sessionKey(peer);
//|     const photoBody = photo ? { src: photo.dataUrl, w: photo.w, h: photo.h } : undefined;
//|     const ct = await subtle.encrypt(
//|       { name: 'AES-GCM', iv, additionalData: aad(me.username, peer, id) },
//|       key,
//|       enc.encode(JSON.stringify({ text, photo: photoBody }))
//|     );
//|     const rec = { id, peer, dir: 'out', text, photo: photo ? photoBody : null, ts: Date.now(), status: 'sending' };
//|     await msgPut(rec);
//|     lastMsg.set(peer, rec);
//|     if (active === peer) appendMessage(rec);
//|     renderContacts();
//|     if (!wsSend({ t: 'msg', to: peer, id, iv: b64(iv), ct: b64(ct) })) {
//|       await updateStatus(id, 'failed');
//|     }
//|   }
//|
//|   async function onIncoming(m) {
//|     const ack = () => wsSend({ t: 'ack', ids: [m.id] });
//|     try {
//|       if (await msgGet(m.id)) return ack();
//|
//|       let c = contacts.get(m.from) || await addContact(m.from);
//|       if (!c) return ack();
//|
//|       let plain;
//|       try {
//|         const key = await sessionKey(m.from);
//|         plain = await subtle.decrypt(
//|           { name: 'AES-GCM', iv: unb64(m.iv), additionalData: aad(m.from, me.username, m.id) },
//|           key,
//|           unb64(m.ct)
//|         );
//|       } catch (err) {
//|         // Most likely the sender has new keys. Flag it, drop the message.
//|         console.warn('Could not decrypt message from', m.from);
//|         await checkKeyChange(m.from);
//|         return ack();
//|       }
//|
//|       const body = JSON.parse(dec.decode(plain));
//|       const text = typeof body.text === 'string' ? body.text : '';
//|       const photo = parsePhoto(body.photo);
//|       if (!text && !photo) return ack();
//|       const rec = { id: m.id, peer: m.from, dir: 'in', text, photo, ts: m.ts, status: 'received' };
//|       await msgPut(rec);
//|       lastMsg.set(m.from, rec);
//|       if (active === m.from && !document.hidden) {
//|         appendMessage(rec);
//|       } else {
//|         unread.set(m.from, (unread.get(m.from) || 0) + 1);
//|         if (active === m.from) appendMessage(rec);
//|       }
//|       renderContacts();
//|       ack();
//|     } catch (err) {
//|       console.error('incoming error', err);
//|     }
//|   }
//|
//|   async function updateStatus(id, status, ts) {
//|     const rec = await msgGet(id);
//|     if (!rec) return;
//|     rec.status = status;
//|     if (ts) rec.ts = ts;
//|     await msgPut(rec);
//|     if (lastMsg.get(rec.peer)?.id === id) lastMsg.set(rec.peer, rec);
//|     if (active === rec.peer) {
//|       const el = document.querySelector(`[data-id="${id}"]`);
//|       if (el) fillMessage(el, rec);
//|     }
//|   }
//|
//|   // ---------- rendering ----------
//|   const timeFmt = new Intl.DateTimeFormat([], { hour: 'numeric', minute: '2-digit' });
//|   const dayFmt = new Intl.DateTimeFormat([], { weekday: 'long', month: 'short', day: 'numeric' });
//|
//|   function renderContacts() {
//|     const list = $('#contacts');
//|     list.textContent = '';
//|     const sorted = [...contacts.values()].sort(
//|       (a, b) => (lastMsg.get(b.username)?.ts || b.added) - (lastMsg.get(a.username)?.ts || a.added)
//|     );
//|     $('#contacts-empty').hidden = sorted.length > 0;
//|
//|     for (const c of sorted) {
//|       const li = document.createElement('li');
//|       const btn = document.createElement('button');
//|       btn.type = 'button';
//|       if (c.username === active) btn.setAttribute('aria-current', 'true');
//|
//|       const name = document.createElement('span');
//|       name.className = 'name';
//|       name.textContent = c.username;
//|
//|       const preview = document.createElement('span');
//|       preview.className = 'preview';
//|       const last = lastMsg.get(c.username);
//|       preview.textContent = last ? previewText(last) : 'No messages yet';
//|
//|       btn.append(name, preview);
//|       const n = unread.get(c.username) || 0;
//|       if (n) {
//|         const badge = document.createElement('span');
//|         badge.className = 'badge';
//|         badge.textContent = String(n);
//|         btn.append(badge);
//|       }
//|       btn.addEventListener('click', () => openChat(c.username));
//|       li.append(btn);
//|       list.append(li);
//|     }
//|   }
//|
//|   function fillMessage(li, rec) {
//|     li.className = `msg ${rec.dir === 'out' ? 'out' : 'in'}${rec.status === 'failed' ? ' failed' : ''}${rec.photo ? ' has-photo' : ''}`;
//|     li.textContent = '';
//|     if (rec.photo) {
//|       const btn = document.createElement('button');
//|       btn.type = 'button';
//|       btn.className = 'photo-btn';
//|       btn.setAttribute('aria-label', 'Open photo');
//|       const img = document.createElement('img');
//|       img.className = 'msg-photo';
//|       img.alt = 'Photo';
//|       if (rec.photo.w && rec.photo.h) { img.width = rec.photo.w; img.height = rec.photo.h; }
//|       img.src = rec.photo.src;
//|       btn.append(img);
//|       btn.addEventListener('click', () => openPhoto(rec.photo.src));
//|       li.append(btn);
//|     }
//|     const body = document.createElement('span');
//|     body.textContent = rec.text;
//|     const meta = document.createElement('span');
//|     meta.className = 'meta';
//|     const label = rec.status === 'failed' ? 'Not sent' : rec.status === 'sending' ? 'Sending…' : timeFmt.format(rec.ts);
//|     meta.textContent = label;
//|     li.append(body, meta);
//|   }
//|
//|   let lastDay = '';
//|   function appendMessage(rec) {
//|     const list = $('#msgs');
//|     const day = dayFmt.format(rec.ts);
//|     if (day !== lastDay) {
//|       const d = document.createElement('li');
//|       d.className = 'day';
//|       d.textContent = day;
//|       list.append(d);
//|       lastDay = day;
//|     }
//|     const li = document.createElement('li');
//|     li.dataset.id = rec.id;
//|     fillMessage(li, rec);
//|     list.append(li);
//|     list.scrollTop = list.scrollHeight;
//|   }
//|
//|   function renderThreadHeader() {
//|     const c = contacts.get(active);
//|     if (!c) return;
//|     $('#peer-name').textContent = c.username;
//|     const v = $('#peer-verify');
//|     v.textContent = c.verified ? 'Verified' : 'Not verified yet';
//|     v.classList.toggle('ok', !!c.verified);
//|     $('#key-warning').hidden = !c.changedKey;
//|   }
//|
//|   async function openChat(username) {
//|     clearPhoto();
//|     active = username;
//|     unread.delete(username);
//|     $('#app').dataset.view = 'chat';
//|     $('#thread-empty').hidden = true;
//|     $('#thread-view').hidden = false;
//|     renderThreadHeader();
//|
//|     const list = $('#msgs');
//|     list.textContent = '';
//|     lastDay = '';
//|     for (const rec of await msgsFor(username)) appendMessage(rec);
//|     renderContacts();
//|     $('#text').focus();
//|     checkKeyChange(username);
//|   }
//|
//|   // ---------- UI events ----------
//|   $('#new-chat').addEventListener('submit', async e => {
//|     e.preventDefault();
//|     const input = $('#peer-input');
//|     const err = $('#new-chat-error');
//|     const name = input.value.trim().toLowerCase();
//|     err.hidden = true;
//|     if (!name) return;
//|     if (name === me.username) { err.textContent = 'That is your own username.'; err.hidden = false; return; }
//|     try {
//|       const c = contacts.get(name) || await addContact(name);
//|       if (!c) { err.textContent = `No one is registered as "${name}".`; err.hidden = false; return; }
//|       input.value = '';
//|       renderContacts();
//|       openChat(name);
//|     } catch (_) {
//|       err.textContent = 'Could not reach the server. Check your connection and try again.';
//|       err.hidden = false;
//|     }
//|   });
//|
//|   $('#composer').addEventListener('submit', async e => {
//|     e.preventDefault();
//|     const box = $('#text');
//|     const text = box.value.trim();
//|     const photo = pendingPhoto;
//|     if ((!text && !photo) || !active || preparingPhoto) return;
//|     box.value = '';
//|     box.style.height = 'auto';
//|     clearPhoto();
//|     try {
//|       await sendMessage(active, text, photo);
//|     } catch (err) {
//|       console.error(err);
//|     }
//|   });
//|
//|   $('#text').addEventListener('keydown', e => {
//|     if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
//|       e.preventDefault();
//|       $('#composer').requestSubmit();
//|     }
//|   });
//|   $('#text').addEventListener('input', e => {
//|     const t = e.target;
//|     t.style.height = 'auto';
//|     t.style.height = Math.min(t.scrollHeight, 144) + 'px';
//|   });
//|
//|   // ---------- photo UI ----------
//|   function clearPhoto() {
//|     pendingPhoto = null;
//|     preparingPhoto = false;
//|     $('#attach-preview').hidden = true;
//|     $('#attach-img').hidden = true;
//|     $('#attach-img').removeAttribute('src');
//|     $('#attach-info').textContent = '';
//|     $('#attach-info').classList.remove('error');
//|   }
//|
//|   async function setPendingPhoto(file) {
//|     if (!file || !active) return;
//|     clearPhoto();
//|     const info = $('#attach-info');
//|     $('#attach-preview').hidden = false;
//|     info.textContent = 'Preparing photo…';
//|     preparingPhoto = true;
//|     try {
//|       const photo = await compressPhoto(file);
//|       if (!preparingPhoto) return;            // removed or chat changed while working
//|       pendingPhoto = photo;
//|       const img = $('#attach-img');
//|       img.src = photo.dataUrl;
//|       img.hidden = false;
//|       info.textContent = `${photo.w} × ${photo.h} · ${Math.round(photo.dataUrl.length * 0.75 / 1024)} KB. Add a caption if you like, then press Send.`;
//|     } catch (err) {
//|       if (!preparingPhoto) return;
//|       info.textContent = err.message || 'Could not prepare that photo.';
//|       info.classList.add('error');
//|     } finally {
//|       preparingPhoto = false;
//|     }
//|   }
//|
//|   function openPhoto(src) {
//|     $('#photo-view-img').src = src;
//|     $('#photo-view').showModal();
//|   }
//|
//|   $('#attach').addEventListener('click', () => $('#photo-input').click());
//|   $('#photo-input').addEventListener('change', e => {
//|     const file = e.target.files && e.target.files[0];
//|     e.target.value = '';
//|     setPendingPhoto(file);
//|   });
//|   $('#attach-remove').addEventListener('click', () => { clearPhoto(); $('#text').focus(); });
//|   $('#text').addEventListener('paste', e => {
//|     const file = [...(e.clipboardData?.files || [])].find(f => f.type.startsWith('image/'));
//|     if (file) { e.preventDefault(); setPendingPhoto(file); }
//|   });
//|   $('#photo-view').addEventListener('click', () => $('#photo-view').close());
//|   $('#photo-view').addEventListener('close', () => $('#photo-view-img').removeAttribute('src'));
//|
//|   $('#back').addEventListener('click', () => {
//|     clearPhoto();
//|     active = null;
//|     $('#app').dataset.view = 'list';
//|     renderContacts();
//|   });
//|
//|   $('#safety-btn').addEventListener('click', async () => {
//|     const c = contacts.get(active);
//|     if (!c) return;
//|     $('#safety-peer').textContent = c.username;
//|     $('#safety-number').textContent = await safetyNumber(active);
//|     $('#safety').showModal();
//|   });
//|
//|   $('#safety-verify').addEventListener('click', async () => {
//|     const c = contacts.get(active);
//|     if (!c) return;
//|     c.verified = true;
//|     await contactPut(c);
//|     renderThreadHeader();
//|     $('#safety').close();
//|   });
//|
//|   $('#key-accept').addEventListener('click', async () => {
//|     const c = contacts.get(active);
//|     if (!c || !c.changedKey) return;
//|     c.dhPub = c.changedKey;
//|     c.changedKey = null;
//|     c.verified = false;
//|     sessionKeys.delete(c.username);
//|     await contactPut(c);
//|     renderThreadHeader();
//|   });
//|
//|   document.addEventListener('visibilitychange', () => {
//|     if (!document.hidden && active && unread.has(active)) { unread.delete(active); renderContacts(); }
//|   });
//|
//|   // ---------- startup ----------
//|   function showApp() {
//|     $('#onboard').hidden = true;
//|     $('#app').hidden = false;
//|     $('#app').dataset.view = 'list';
//|     $('#me-name').textContent = me.username;
//|     renderContacts();
//|   }
//|
//|   async function enterApp() {
//|     showApp();
//|     connect();
//|   }
//|
//|   async function init() {
//|     if (!window.isSecureContext || !crypto.subtle || !window.indexedDB) {
//|       showOnboard('This page needs a secure connection. Open it over HTTPS, or on localhost.');
//|       return;
//|     }
//|     db = await openDB();
//|     me = await kvGet('identity');
//|     if (!me) {
//|       await wipeLocal();   // no identity means nothing left over from another account should survive
//|       showOnboard();
//|       return;
//|     }
//|     for (const c of await contactsAll()) contacts.set(c.username, c);
//|     for (const c of contacts.keys()) {
//|       const list = await msgsFor(c);
//|       if (list.length) lastMsg.set(c, list[list.length - 1]);
//|     }
//|     enterApp();
//|   }
//|
//|   init().catch(err => {
//|     console.error(err);
//|     showOnboard('Something went wrong starting the app. Reload and try again.');
//|   });
//| })();
//#### END
