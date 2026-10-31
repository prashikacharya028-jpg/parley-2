'use strict';
/**
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
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const PUBLIC_DIR = __dirname;
// Only these files are ever served to browsers (never server.js or data.json)
const PUBLIC_FILES = new Set(['index.html', 'style.css', 'app.js']);

const USERNAME_RE = /^[a-z0-9_]{3,24}$/;
const MAX_WS_PAYLOAD = 128 * 1024;
const MAX_CT_LEN = 90 * 1024;          // base64 chars (~64 KB of ciphertext)
const MAX_QUEUE_PER_USER = 1000;
const MSG_LIMIT = { count: 30, windowMs: 10_000 };
const REGISTER_LIMIT = { count: 5, windowMs: 60 * 60 * 1000 }; // per IP

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
  if (!PUBLIC_FILES.has(name)) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
  const filePath = path.join(PUBLIC_DIR, name);

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
    });
    res.end(data);
  });
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
      case 'register': return onRegister(ws, m, ip);
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

function onRegister(ws, m, ip) {
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

  db.users[username] = { signPub, dhPub, created: Date.now() };
  db.queue[username] = [];
  saveSoon();
  goOnline(ws, username);
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
}, 30_000).unref();

server.listen(PORT, () => {
  console.log(`Parley is running at http://localhost:${PORT}`);
});
