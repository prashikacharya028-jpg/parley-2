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

const USERNAME_RE = /^[a-z0-9_]{3,24}$/;
const MAX_WS_PAYLOAD = 512 * 1024;
const MAX_CT_LEN = 400 * 1024;         // base64 chars (fits a 60 s voice note)
const MAX_QUEUE_PER_USER = 1000;
const MAX_QUEUE_BYTES = 25 * 1024 * 1024; // undelivered data kept per user
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
    "connect-src 'self' ws: wss:; media-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

// The web app (HTML, CSS, JS) is embedded below, so this one file is the whole project.
const FILES = {
  "index.html": "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n  <meta name=\"color-scheme\" content=\"light dark\">\n  <title>Parley</title>\n  <link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n<body>\n\n  <!-- First run: create an identity -->\n  <main id=\"onboard\" class=\"onboard\" hidden>\n    <div class=\"onboard-card\">\n      <h1 class=\"wordmark\">Parley</h1>\n      <p class=\"lede\">Messages are locked on your device and can only be opened by the person you send them to. The server only ever sees scrambled data.</p>\n      <form id=\"onboard-form\" autocomplete=\"off\">\n        <label for=\"username\">Pick a username</label>\n        <input id=\"username\" name=\"username\" required minlength=\"3\" maxlength=\"24\"\n               pattern=\"[a-z0-9_]{3,24}\" inputmode=\"latin\" autocapitalize=\"none\" spellcheck=\"false\">\n        <p class=\"hint\">3–24 characters: lowercase letters, numbers, underscore.</p>\n        <p id=\"onboard-error\" class=\"error\" role=\"alert\" hidden></p>\n        <button type=\"submit\" class=\"primary\">Create my keys</button>\n      </form>\n      <p class=\"fine\">Your keys are created in this browser and never leave it. If you clear this browser's site data, you lose this identity.</p>\n    </div>\n  </main>\n\n  <!-- Main app -->\n  <div id=\"app\" class=\"app\" hidden>\n    <aside id=\"side\" class=\"side\">\n      <header class=\"side-head\">\n        <div>\n          <div class=\"wordmark small\">Parley</div>\n          <div class=\"me\"><span id=\"me-name\"></span> <span id=\"status\" class=\"status\" data-state=\"connecting\" title=\"Connecting\"></span></div>\n        </div>\n      </header>\n\n      <form id=\"new-chat\" class=\"new-chat\" autocomplete=\"off\">\n        <label for=\"peer-input\" class=\"sr\">Start a chat</label>\n        <input id=\"peer-input\" placeholder=\"Start a chat with a username\" maxlength=\"24\"\n               autocapitalize=\"none\" spellcheck=\"false\">\n        <button type=\"submit\" class=\"ghost\">Start</button>\n      </form>\n      <p id=\"new-chat-error\" class=\"error pad\" role=\"alert\" hidden></p>\n\n      <ul id=\"contacts\" class=\"contacts\" aria-label=\"Conversations\"></ul>\n      <p id=\"contacts-empty\" class=\"empty pad\">No conversations yet. Enter a username above to start one.</p>\n    </aside>\n\n    <section id=\"thread\" class=\"thread\" aria-live=\"polite\">\n      <div id=\"thread-empty\" class=\"thread-empty\">\n        <p>Pick a conversation, or start a new one.</p>\n      </div>\n\n      <div id=\"thread-view\" class=\"thread-view\" hidden>\n        <header class=\"thread-head\">\n          <button id=\"back\" class=\"icon-btn back\" aria-label=\"Back to conversations\">‹</button>\n          <div class=\"peer\">\n            <div id=\"peer-name\" class=\"peer-name\"></div>\n            <div id=\"peer-verify\" class=\"peer-verify\"></div>\n          </div>\n          <button id=\"safety-btn\" class=\"ghost\">Verify</button>\n        </header>\n\n        <div id=\"key-warning\" class=\"banner\" role=\"alert\" hidden>\n          <p><strong>This person's keys changed.</strong> They may have reinstalled, or someone may be intercepting. Compare safety numbers with them another way before you continue.</p>\n          <div class=\"banner-actions\">\n            <button id=\"key-accept\" class=\"ghost\">Trust the new keys</button>\n          </div>\n        </div>\n\n        <ol id=\"msgs\" class=\"msgs\"></ol>\n\n        <p id=\"composer-error\" class=\"error pad\" role=\"alert\" hidden></p>\n        <form id=\"composer\" class=\"composer\" autocomplete=\"off\">\n          <label for=\"text\" class=\"sr\">Message</label>\n          <textarea id=\"text\" rows=\"1\" maxlength=\"8000\" placeholder=\"Write a message\"></textarea>\n          <button type=\"button\" class=\"ghost\" id=\"mic\" aria-label=\"Record a voice note\">Voice</button>\n          <button type=\"submit\" class=\"primary\" id=\"send\">Send</button>\n          <div id=\"rec-bar\" class=\"rec-bar\" hidden>\n            <span class=\"rec-dot\" aria-hidden=\"true\"></span>\n            <span id=\"rec-time\" class=\"rec-time\" role=\"timer\">0:00</span>\n            <button type=\"button\" id=\"rec-cancel\" class=\"ghost\">Cancel</button>\n            <button type=\"button\" id=\"rec-send\" class=\"primary\">Send</button>\n          </div>\n        </form>\n      </div>\n    </section>\n  </div>\n\n  <dialog id=\"safety\">\n    <form method=\"dialog\" class=\"safety-card\">\n      <h2>Safety number</h2>\n      <p>Compare this with <strong id=\"safety-peer\"></strong> in person or over a call. If both of you see the same number, nobody is sitting between you.</p>\n      <p id=\"safety-number\" class=\"safety-number\"></p>\n      <div class=\"dialog-actions\">\n        <button id=\"safety-verify\" type=\"button\" class=\"primary\">They match</button>\n        <button value=\"close\" class=\"ghost\">Close</button>\n      </div>\n    </form>\n  </dialog>\n\n  <script src=\"/app.js\"></script>\n</body>\n</html>\n",
  "style.css": ":root {\n  --bg: #e8edef;\n  --panel: #f9fbfb;\n  --line: #d3dbde;\n  --ink: #14232b;\n  --ink-soft: #5b6c74;\n  --bubble-out: #14232b;\n  --bubble-out-ink: #f2f6f7;\n  --bubble-in: #ffffff;\n  --lock: #b86b00;\n  --lock-soft: #fbefd9;\n  --danger: #b3261e;\n  --focus: #1f6f9a;\n  --serif: \"Iowan Old Style\", \"Palatino Linotype\", Charter, Georgia, serif;\n  --sans: ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif;\n}\n\n@media (prefers-color-scheme: dark) {\n  :root {\n    --bg: #0d1519;\n    --panel: #121d22;\n    --line: #243238;\n    --ink: #e6eef0;\n    --ink-soft: #8fa2aa;\n    --bubble-out: #e6eef0;\n    --bubble-out-ink: #0d1519;\n    --bubble-in: #1b2a31;\n    --lock: #e7a23c;\n    --lock-soft: #2a2213;\n    --danger: #ff8a80;\n    --focus: #6cc0ec;\n  }\n}\n\n* { box-sizing: border-box; }\n[hidden] { display: none !important; }\n\nhtml, body { height: 100%; margin: 0; }\nbody {\n  background: var(--bg);\n  color: var(--ink);\n  font: 16px/1.45 var(--sans);\n  -webkit-font-smoothing: antialiased;\n}\n\nbutton, input, textarea { font: inherit; color: inherit; }\n:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }\n.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }\n\n.wordmark { font-family: var(--serif); font-size: 2.6rem; font-weight: 600; letter-spacing: -0.02em; margin: 0; }\n.wordmark.small { font-size: 1.35rem; }\n\ninput, textarea {\n  width: 100%;\n  background: var(--panel);\n  border: 1px solid var(--line);\n  border-radius: 8px;\n  padding: 0.6rem 0.75rem;\n}\ntextarea { resize: none; max-height: 9rem; }\n\nbutton { cursor: pointer; border-radius: 8px; border: 1px solid transparent; padding: 0.55rem 1rem; }\nbutton.primary { background: var(--ink); color: var(--bg); font-weight: 600; }\nbutton.primary:disabled { opacity: 0.4; cursor: default; }\nbutton.ghost { background: transparent; border-color: var(--line); }\nbutton.ghost:hover { background: var(--lock-soft); }\n.icon-btn { background: none; border: 0; font-size: 1.8rem; line-height: 1; padding: 0 0.5rem; }\n\n.error { color: var(--danger); margin: 0.5rem 0; font-size: 0.92rem; }\n.hint, .fine, .empty { color: var(--ink-soft); font-size: 0.88rem; }\n.pad { padding: 0 1rem; }\n\n/* ---------- onboarding ---------- */\n.onboard { min-height: 100%; display: grid; place-items: center; padding: 1.5rem; }\n.onboard-card { width: min(26rem, 100%); }\n.lede { font-family: var(--serif); font-size: 1.15rem; line-height: 1.5; margin: 0.75rem 0 1.75rem; }\n.onboard-card label { display: block; font-weight: 600; margin-bottom: 0.4rem; }\n.onboard-card button { width: 100%; margin-top: 0.5rem; padding: 0.75rem; }\n\n/* ---------- app layout ---------- */\n.app { height: 100%; display: grid; grid-template-columns: 20rem 1fr; }\n.side { background: var(--panel); border-right: 1px solid var(--line); display: flex; flex-direction: column; min-height: 0; padding-top: env(safe-area-inset-top, 0px); }\n.side-head { padding: 1rem; border-bottom: 1px solid var(--line); }\n.me { color: var(--ink-soft); font-size: 0.9rem; display: flex; align-items: center; gap: 0.4rem; margin-top: 0.15rem; }\n.status { width: 0.6rem; height: 0.6rem; border-radius: 50%; background: var(--ink-soft); display: inline-block; }\n.status[data-state=\"online\"] { background: #2e9e5b; }\n.status[data-state=\"connecting\"] { background: var(--lock); }\n\n.new-chat { display: flex; gap: 0.5rem; padding: 0.75rem 1rem; }\n.new-chat button { white-space: nowrap; }\n\n.contacts { list-style: none; margin: 0; padding: 0; overflow-y: auto; flex: 1; }\n.contacts li button {\n  width: 100%; text-align: left; background: none; border: 0; border-radius: 0;\n  padding: 0.75rem 1rem; display: grid; grid-template-columns: 1fr auto; gap: 0.1rem 0.5rem;\n  border-bottom: 1px solid var(--line);\n}\n.contacts li button[aria-current=\"true\"] { background: var(--lock-soft); }\n.contacts .name { font-weight: 600; }\n.contacts .preview { grid-column: 1; color: var(--ink-soft); font-size: 0.88rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n.contacts .badge { grid-row: 1 / span 2; grid-column: 2; align-self: center; min-width: 1.4rem; text-align: center; background: var(--lock); color: #fff; border-radius: 999px; font-size: 0.78rem; padding: 0.1rem 0.4rem; }\n\n.thread { display: flex; flex-direction: column; min-width: 0; min-height: 0; }\n.thread-empty { margin: auto; color: var(--ink-soft); font-family: var(--serif); font-size: 1.1rem; }\n.thread-view { display: flex; flex-direction: column; height: 100%; min-height: 0; padding-top: env(safe-area-inset-top, 0px); }\n\n.thread-head { display: flex; align-items: center; gap: 0.5rem; padding: 0.7rem 1rem; background: var(--panel); border-bottom: 1px solid var(--line); }\n.back { display: none; }\n.peer { flex: 1; min-width: 0; }\n.peer-name { font-family: var(--serif); font-size: 1.2rem; font-weight: 600; }\n.peer-verify { font-size: 0.82rem; color: var(--ink-soft); }\n.peer-verify.ok { color: var(--lock); }\n\n.banner { background: var(--lock-soft); border-bottom: 1px solid var(--lock); padding: 0.75rem 1rem; font-size: 0.92rem; }\n.banner p { margin: 0 0 0.5rem; }\n\n.msgs { list-style: none; margin: 0; padding: 1rem; flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 0.35rem; }\n.msg { max-width: min(34rem, 82%); padding: 0.5rem 0.8rem; border-radius: 14px; white-space: pre-wrap; overflow-wrap: anywhere; }\n.msg.in { align-self: flex-start; background: var(--bubble-in); border: 1px solid var(--line); border-bottom-left-radius: 4px; }\n.msg.out { align-self: flex-end; background: var(--bubble-out); color: var(--bubble-out-ink); border-bottom-right-radius: 4px; }\n.msg .meta { display: block; font-size: 0.72rem; opacity: 0.65; margin-top: 0.15rem; text-align: right; }\n.msg.failed .meta { color: var(--danger); opacity: 1; }\n.day { align-self: center; color: var(--ink-soft); font-size: 0.8rem; margin: 0.6rem 0 0.2rem; }\n\n.composer { display: flex; gap: 0.5rem; align-items: flex-end; padding: 0.75rem 1rem calc(0.75rem + env(safe-area-inset-bottom, 0px)); background: var(--panel); border-top: 1px solid var(--line); }\n\n/* ---------- safety dialog ---------- */\ndialog { background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: 12px; padding: 0; width: min(28rem, calc(100% - 2rem)); }\ndialog::backdrop { background: rgba(0, 0, 0, 0.5); }\n.safety-card { padding: 1.25rem; }\n.safety-card h2 { font-family: var(--serif); margin: 0 0 0.5rem; }\n.safety-number { font-family: ui-monospace, \"SF Mono\", Menlo, Consolas, monospace; font-size: 1.25rem; line-height: 1.9; letter-spacing: 0.04em; background: var(--bg); border-radius: 8px; padding: 0.75rem 1rem; }\n.dialog-actions { display: flex; gap: 0.5rem; justify-content: flex-end; }\n\n/* ---------- small screens ---------- */\n@media (max-width: 720px) {\n  .app { grid-template-columns: 1fr; }\n  .app[data-view=\"list\"] .thread { display: none; }\n  .app[data-view=\"chat\"] .side { display: none; }\n  .back { display: block; }\n  .msg { max-width: 88%; }\n}\n\n@media (prefers-reduced-motion: reduce) {\n  * { transition: none !important; animation: none !important; scroll-behavior: auto !important; }\n}\n\n/* ---------- voice notes ---------- */\n.msg audio { display: block; width: 15rem; max-width: 100%; height: 2.4rem; }\n.rec-bar { display: flex; flex: 1; align-items: center; gap: 0.75rem; }\n.rec-bar[hidden] { display: none; }\n.rec-dot { width: 0.7rem; height: 0.7rem; border-radius: 50%; background: var(--danger); animation: rec-pulse 1.2s ease-in-out infinite; }\n.rec-time { flex: 1; font-variant-numeric: tabular-nums; font-weight: 600; }\n@keyframes rec-pulse { 50% { opacity: 0.25; } }\n",
  "app.js": "'use strict';\n/**\n * Parley client.\n *\n * Crypto design\n *  - Each device makes two P-256 key pairs: ECDSA (proves who you are to the server)\n *    and ECDH (derives a secret shared with each contact). Private keys are stored as\n *    NON-EXTRACTABLE CryptoKeys in IndexedDB, so page scripts cannot read them out.\n *  - Shared secret = ECDH(my private, their public) -> HKDF-SHA-256 -> AES-256-GCM key.\n *  - Every message uses a fresh random 96-bit IV, and binds sender, recipient and message id\n *    as AES-GCM additional data, so the server can't redirect or relabel ciphertexts.\n *  - Contacts' keys are pinned on first use (TOFU). If they change, you get a warning.\n *    Compare the safety number out-of-band to rule out a malicious server.\n */\n(() => {\n  const $ = sel => document.querySelector(sel);\n  const subtle = crypto.subtle;\n  const enc = new TextEncoder();\n  const dec = new TextDecoder();\n\n  // ---------- encoding helpers ----------\n  function b64(buf) {\n    const bytes = new Uint8Array(buf);\n    let s = '';\n    for (let i = 0; i < bytes.length; i += 0x8000) {\n      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));\n    }\n    return btoa(s);\n  }\n  function unb64(str) {\n    const bin = atob(str);\n    const out = new Uint8Array(bin.length);\n    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);\n    return out;\n  }\n  const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');\n  const randomId = () => hex(crypto.getRandomValues(new Uint8Array(16)));\n  const pubOnly = jwk => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });\n  const sameKey = (a, b) => a && b && a.x === b.x && a.y === b.y;\n\n  // ---------- IndexedDB ----------\n  let db;\n  function openDB() {\n    return new Promise((resolve, reject) => {\n      const req = indexedDB.open('parley', 1);\n      req.onupgradeneeded = () => {\n        const d = req.result;\n        d.createObjectStore('kv');\n        d.createObjectStore('contacts', { keyPath: 'username' });\n        d.createObjectStore('messages', { keyPath: 'id' }).createIndex('peer', 'peer');\n      };\n      req.onsuccess = () => resolve(req.result);\n      req.onerror = () => reject(req.error);\n    });\n  }\n  function run(store, mode, fn) {\n    return new Promise((resolve, reject) => {\n      const t = db.transaction(store, mode);\n      const rq = fn(t.objectStore(store));\n      t.oncomplete = () => resolve(rq ? rq.result : undefined);\n      t.onerror = () => reject(t.error);\n      t.onabort = () => reject(t.error);\n    });\n  }\n  const kvGet = k => run('kv', 'readonly', s => s.get(k));\n  const kvSet = (k, v) => run('kv', 'readwrite', s => s.put(v, k));\n  const kvDel = k => run('kv', 'readwrite', s => s.delete(k));\n  const contactsAll = () => run('contacts', 'readonly', s => s.getAll());\n  const contactPut = c => run('contacts', 'readwrite', s => s.put(c));\n  const msgPut = m => run('messages', 'readwrite', s => s.put(m));\n  const msgGet = id => run('messages', 'readonly', s => s.get(id));\n  const msgsFor = peer => run('messages', 'readonly', s => s.index('peer').getAll(peer))\n    .then(list => list.sort((a, b) => a.ts - b.ts));\n\n  // ---------- state ----------\n  let me = null;            // { username, sign, dh, registered }\n  let ws = null;\n  let backoff = 1000;\n  let active = null;        // username of open conversation\n  const contacts = new Map();   // username -> contact record\n  const lastMsg = new Map();    // username -> latest message record\n  const unread = new Map();     // username -> count\n  const sessionKeys = new Map();\n  const pendingLookups = new Map();\n\n  // ---------- identity ----------\n  async function createIdentity(username) {\n    const sign = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);\n    const dh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);\n    me = { username, sign, dh, registered: false };\n    await kvSet('identity', me);\n  }\n\n  // ---------- onboarding ----------\n  function showOnboard(errorText) {\n    $('#app').hidden = true;\n    $('#onboard').hidden = false;\n    const err = $('#onboard-error');\n    err.hidden = !errorText;\n    err.textContent = errorText || '';\n  }\n\n  $('#onboard-form').addEventListener('submit', async e => {\n    e.preventDefault();\n    const name = $('#username').value.trim().toLowerCase();\n    if (!/^[a-z0-9_]{3,24}$/.test(name)) {\n      return showOnboard('Usernames are 3–24 characters: lowercase letters, numbers or underscore.');\n    }\n    try {\n      await createIdentity(name);\n      $('#onboard').hidden = true;\n      enterApp();\n    } catch (err) {\n      console.error(err);\n      showOnboard('Could not create keys in this browser. Open the page over HTTPS or on localhost.');\n    }\n  });\n\n  // ---------- networking ----------\n  function setStatus(state) {\n    const el = $('#status');\n    el.dataset.state = state;\n    el.title = { online: 'Connected', connecting: 'Connecting…', offline: 'Offline, retrying…' }[state];\n  }\n\n  function connect() {\n    setStatus('connecting');\n    const proto = location.protocol === 'https:' ? 'wss' : 'ws';\n    ws = new WebSocket(`${proto}://${location.host}/ws`);\n\n    ws.onmessage = ev => {\n      let m;\n      try { m = JSON.parse(ev.data); } catch (_) { return; }\n      handleServer(m).catch(err => console.error('handler error', err));\n    };\n    ws.onclose = () => {\n      setStatus('offline');\n      pendingLookups.forEach(p => p.reject(new Error('offline')));\n      pendingLookups.clear();\n      setTimeout(() => { if (me) connect(); }, backoff);\n      backoff = Math.min(backoff * 2, 15000);\n    };\n  }\n\n  const wsSend = obj => ws && ws.readyState === 1 && (ws.send(JSON.stringify(obj)), true);\n\n  async function handleServer(m) {\n    switch (m.t) {\n      case 'hello': {\n        const sig = await subtle.sign(\n          { name: 'ECDSA', hash: 'SHA-256' },\n          me.sign.privateKey,\n          enc.encode(`pm-auth-v1:${m.nonce}:${me.username}`)\n        );\n        if (me.registered) {\n          wsSend({ t: 'auth', username: me.username, sig: b64(sig) });\n        } else {\n          const [signPub, dhPub] = await Promise.all([\n            subtle.exportKey('jwk', me.sign.publicKey),\n            subtle.exportKey('jwk', me.dh.publicKey),\n          ]);\n          wsSend({\n            t: 'register', username: me.username, sig: b64(sig),\n            signPub: pubOnly(signPub), dhPub: pubOnly(dhPub),\n          });\n        }\n        break;\n      }\n      case 'ready':\n        backoff = 1000;\n        setStatus('online');\n        if (!me.registered) { me.registered = true; await kvSet('identity', me); }\n        break;\n      case 'user': {\n        const p = pendingLookups.get(m.username);\n        if (p) { pendingLookups.delete(m.username); p.resolve(m); }\n        break;\n      }\n      case 'msg':\n        await onIncoming(m);\n        break;\n      case 'sent':\n        await updateStatus(m.id, 'sent', m.ts);\n        break;\n      case 'error':\n        await onServerError(m);\n        break;\n    }\n  }\n\n  async function onServerError(m) {\n    if (m.id) {\n      await updateStatus(m.id, 'failed');\n      return;\n    }\n    if (m.code === 'taken') {\n      await kvDel('identity');\n      me = null;\n      if (ws) ws.close();\n      showOnboard('That username is taken. Pick another one.');\n    } else if (m.code === 'auth_failed' || m.code === 'bad_username' || m.code === 'bad_key') {\n      if (!me.registered) {\n        await kvDel('identity');\n        me = null;\n        if (ws) ws.close();\n        showOnboard('The server rejected that identity. Try a different username.');\n      } else {\n        setStatus('offline');\n        console.error('Authentication failed for', me.username);\n      }\n    } else if (m.code === 'rate_limited') {\n      showOnboard('Too many sign-ups from this network. Try again later.');\n    }\n  }\n\n  function lookup(username) {\n    return new Promise((resolve, reject) => {\n      if (!ws || ws.readyState !== 1) return reject(new Error('offline'));\n      const timer = setTimeout(() => {\n        pendingLookups.delete(username);\n        reject(new Error('timeout'));\n      }, 8000);\n      pendingLookups.set(username, {\n        resolve: v => { clearTimeout(timer); resolve(v); },\n        reject: e => { clearTimeout(timer); reject(e); },\n      });\n      wsSend({ t: 'lookup', username });\n    });\n  }\n\n  // ---------- contacts & session keys ----------\n  async function addContact(username) {\n    const res = await lookup(username);\n    if (res.missing) return null;\n    const c = { username, dhPub: res.dhPub, verified: false, changedKey: null, added: Date.now() };\n    contacts.set(username, c);\n    await contactPut(c);\n    return c;\n  }\n\n  // Compare the server's current key for a contact with the one we pinned.\n  async function checkKeyChange(username) {\n    const c = contacts.get(username);\n    if (!c) return;\n    try {\n      const res = await lookup(username);\n      if (res.missing || !res.dhPub) return;\n      if (!sameKey(res.dhPub, c.dhPub)) {\n        c.changedKey = res.dhPub;\n        await contactPut(c);\n        if (active === username) renderThreadHeader();\n      }\n    } catch (_) { /* offline; try again later */ }\n  }\n\n  async function sessionKey(peer) {\n    if (sessionKeys.has(peer)) return sessionKeys.get(peer);\n    const c = contacts.get(peer);\n    if (!c) throw new Error('unknown contact');\n    const theirs = await subtle.importKey('jwk', c.dhPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);\n    const bits = await subtle.deriveBits({ name: 'ECDH', public: theirs }, me.dh.privateKey, 256);\n    const hkdfKey = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);\n    const pair = [me.username, peer].sort().join('|');\n    const key = await subtle.deriveKey(\n      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('parley-v1'), info: enc.encode(pair) },\n      hkdfKey,\n      { name: 'AES-GCM', length: 256 },\n      false,\n      ['encrypt', 'decrypt']\n    );\n    sessionKeys.set(peer, key);\n    return key;\n  }\n\n  // Safety number: hash of both public ECDH keys, shown as six 5-digit groups.\n  async function safetyNumber(peer) {\n    const mine = pubOnly(await subtle.exportKey('jwk', me.dh.publicKey));\n    const theirs = contacts.get(peer).dhPub;\n    const parts = [`${mine.x}.${mine.y}`, `${theirs.x}.${theirs.y}`].sort();\n    const digest = new Uint8Array(await subtle.digest('SHA-256', enc.encode(parts.join('|'))));\n    const view = new DataView(digest.buffer);\n    const groups = [];\n    for (let i = 0; i < 6; i++) groups.push(String(view.getUint32(i * 4) % 100000).padStart(5, '0'));\n    return groups.join(' ');\n  }\n\n  // ---------- sending & receiving ----------\n  const aad = (from, to, id) => enc.encode(`${from}>${to}:${id}`);\n\n  // Plaintext formats (always encrypted before leaving the device):\n  //   text:  UTF-8 JSON {\"text\": \"...\"}\n  //   voice: 0x01 | 4-byte header length | JSON header {mime, dur} | raw audio bytes\n  function packVoice(audioBytes, mime, dur) {\n    const header = enc.encode(JSON.stringify({ mime, dur }));\n    const out = new Uint8Array(5 + header.length + audioBytes.length);\n    out[0] = 1;\n    new DataView(out.buffer).setUint32(1, header.length);\n    out.set(header, 5);\n    out.set(audioBytes, 5 + header.length);\n    return out;\n  }\n\n  function parsePlain(buf) {\n    const bytes = new Uint8Array(buf);\n    if (bytes[0] === 1) {\n      const headerLen = new DataView(bytes.buffer, bytes.byteOffset).getUint32(1);\n      const header = JSON.parse(dec.decode(bytes.subarray(5, 5 + headerLen)));\n      const mime = String(header.mime || '');\n      return {\n        kind: 'voice',\n        mime: mime.startsWith('audio/') ? mime : 'audio/webm',\n        dur: Math.max(0, Math.min(Number(header.dur) || 0, 3600)),\n        audio: bytes.slice(5 + headerLen).buffer,\n        text: '',\n      };\n    }\n    return { kind: 'text', text: String(JSON.parse(dec.decode(bytes)).text) };\n  }\n\n  async function deliver(peer, plain, fields) {\n    const id = randomId();\n    const iv = crypto.getRandomValues(new Uint8Array(12));\n    const key = await sessionKey(peer);\n    const ct = await subtle.encrypt(\n      { name: 'AES-GCM', iv, additionalData: aad(me.username, peer, id) },\n      key,\n      plain\n    );\n    const rec = { id, peer, dir: 'out', ts: Date.now(), status: 'sending', ...fields };\n    await msgPut(rec);\n    lastMsg.set(peer, rec);\n    if (active === peer) appendMessage(rec);\n    renderContacts();\n    if (!wsSend({ t: 'msg', to: peer, id, iv: b64(iv), ct: b64(ct) })) {\n      await updateStatus(id, 'failed');\n    }\n  }\n\n  const sendMessage = (peer, text) =>\n    deliver(peer, enc.encode(JSON.stringify({ text })), { kind: 'text', text });\n\n  async function sendVoice(peer, blob, dur) {\n    const audio = await blob.arrayBuffer();\n    const mime = blob.type && blob.type.startsWith('audio/') ? blob.type : 'audio/webm';\n    return deliver(peer, packVoice(new Uint8Array(audio), mime, dur),\n      { kind: 'voice', audio, mime, dur, text: '' });\n  }\n\n  async function onIncoming(m) {\n    const ack = () => wsSend({ t: 'ack', ids: [m.id] });\n    try {\n      if (await msgGet(m.id)) return ack();\n\n      let c = contacts.get(m.from) || await addContact(m.from);\n      if (!c) return ack();\n\n      let plain;\n      try {\n        const key = await sessionKey(m.from);\n        plain = await subtle.decrypt(\n          { name: 'AES-GCM', iv: unb64(m.iv), additionalData: aad(m.from, me.username, m.id) },\n          key,\n          unb64(m.ct)\n        );\n      } catch (err) {\n        // Most likely the sender has new keys. Flag it, drop the message.\n        console.warn('Could not decrypt message from', m.from);\n        await checkKeyChange(m.from);\n        return ack();\n      }\n\n      const rec = { id: m.id, peer: m.from, dir: 'in', ts: m.ts, status: 'received', ...parsePlain(plain) };\n      await msgPut(rec);\n      lastMsg.set(m.from, rec);\n      if (active === m.from && !document.hidden) {\n        appendMessage(rec);\n      } else {\n        unread.set(m.from, (unread.get(m.from) || 0) + 1);\n        if (active === m.from) appendMessage(rec);\n      }\n      renderContacts();\n      ack();\n    } catch (err) {\n      console.error('incoming error', err);\n    }\n  }\n\n  async function updateStatus(id, status, ts) {\n    const rec = await msgGet(id);\n    if (!rec) return;\n    rec.status = status;\n    if (ts) rec.ts = ts;\n    await msgPut(rec);\n    if (lastMsg.get(rec.peer)?.id === id) lastMsg.set(rec.peer, rec);\n    if (active === rec.peer) {\n      const el = document.querySelector(`[data-id=\"${id}\"]`);\n      if (el) fillMessage(el, rec);\n    }\n  }\n\n  // ---------- rendering ----------\n  const timeFmt = new Intl.DateTimeFormat([], { hour: 'numeric', minute: '2-digit' });\n  const dayFmt = new Intl.DateTimeFormat([], { weekday: 'long', month: 'short', day: 'numeric' });\n\n  function renderContacts() {\n    const list = $('#contacts');\n    list.textContent = '';\n    const sorted = [...contacts.values()].sort(\n      (a, b) => (lastMsg.get(b.username)?.ts || b.added) - (lastMsg.get(a.username)?.ts || a.added)\n    );\n    $('#contacts-empty').hidden = sorted.length > 0;\n\n    for (const c of sorted) {\n      const li = document.createElement('li');\n      const btn = document.createElement('button');\n      btn.type = 'button';\n      if (c.username === active) btn.setAttribute('aria-current', 'true');\n\n      const name = document.createElement('span');\n      name.className = 'name';\n      name.textContent = c.username;\n\n      const preview = document.createElement('span');\n      preview.className = 'preview';\n      const last = lastMsg.get(c.username);\n      preview.textContent = !last ? 'No messages yet' : last.kind === 'voice' ? 'Voice note' : last.text;\n\n      btn.append(name, preview);\n      const n = unread.get(c.username) || 0;\n      if (n) {\n        const badge = document.createElement('span');\n        badge.className = 'badge';\n        badge.textContent = String(n);\n        btn.append(badge);\n      }\n      btn.addEventListener('click', () => openChat(c.username));\n      li.append(btn);\n      list.append(li);\n    }\n  }\n\n  const fmtDur = s => `${Math.floor(s / 60)}:${String(Math.round(s % 60)).padStart(2, '0')}`;\n\n  function fillMessage(li, rec) {\n    li.className = `msg ${rec.dir === 'out' ? 'out' : 'in'}${rec.status === 'failed' ? ' failed' : ''}`;\n    let meta = li.querySelector('.meta');\n    if (!meta) {\n      // Build the body once, so a status update never interrupts audio that is playing.\n      li.textContent = '';\n      const body = document.createElement('span');\n      if (rec.kind === 'voice') {\n        const audio = document.createElement('audio');\n        audio.controls = true;\n        audio.preload = 'metadata';\n        audio.setAttribute('aria-label', `Voice note, ${fmtDur(rec.dur)}`);\n        audio.src = URL.createObjectURL(new Blob([rec.audio], { type: rec.mime }));\n        body.append(audio);\n      } else {\n        body.textContent = rec.text;\n      }\n      meta = document.createElement('span');\n      meta.className = 'meta';\n      li.append(body, meta);\n    }\n    const when = rec.status === 'failed' ? 'Not sent' : rec.status === 'sending' ? 'Sending…' : timeFmt.format(rec.ts);\n    meta.textContent = rec.kind === 'voice' ? `${fmtDur(rec.dur)}, ${when}` : when;\n  }\n\n  let lastDay = '';\n  function appendMessage(rec) {\n    const list = $('#msgs');\n    const day = dayFmt.format(rec.ts);\n    if (day !== lastDay) {\n      const d = document.createElement('li');\n      d.className = 'day';\n      d.textContent = day;\n      list.append(d);\n      lastDay = day;\n    }\n    const li = document.createElement('li');\n    li.dataset.id = rec.id;\n    fillMessage(li, rec);\n    list.append(li);\n    list.scrollTop = list.scrollHeight;\n  }\n\n  function renderThreadHeader() {\n    const c = contacts.get(active);\n    if (!c) return;\n    $('#peer-name').textContent = c.username;\n    const v = $('#peer-verify');\n    v.textContent = c.verified ? 'Verified' : 'Not verified yet';\n    v.classList.toggle('ok', !!c.verified);\n    $('#key-warning').hidden = !c.changedKey;\n  }\n\n  async function openChat(username) {\n    cancelRecording();\n    active = username;\n    unread.delete(username);\n    $('#app').dataset.view = 'chat';\n    $('#thread-empty').hidden = true;\n    $('#thread-view').hidden = false;\n    renderThreadHeader();\n\n    const list = $('#msgs');\n    list.textContent = '';\n    lastDay = '';\n    for (const rec of await msgsFor(username)) appendMessage(rec);\n    renderContacts();\n    $('#text').focus();\n    checkKeyChange(username);\n  }\n\n  // ---------- UI events ----------\n  $('#new-chat').addEventListener('submit', async e => {\n    e.preventDefault();\n    const input = $('#peer-input');\n    const err = $('#new-chat-error');\n    const name = input.value.trim().toLowerCase();\n    err.hidden = true;\n    if (!name) return;\n    if (name === me.username) { err.textContent = 'That is your own username.'; err.hidden = false; return; }\n    try {\n      const c = contacts.get(name) || await addContact(name);\n      if (!c) { err.textContent = `No one is registered as \"${name}\".`; err.hidden = false; return; }\n      input.value = '';\n      renderContacts();\n      openChat(name);\n    } catch (_) {\n      err.textContent = 'Could not reach the server. Check your connection and try again.';\n      err.hidden = false;\n    }\n  });\n\n  $('#composer').addEventListener('submit', async e => {\n    e.preventDefault();\n    const box = $('#text');\n    const text = box.value.trim();\n    if (!text || !active) return;\n    box.value = '';\n    box.style.height = 'auto';\n    try {\n      await sendMessage(active, text);\n    } catch (err) {\n      console.error(err);\n    }\n  });\n\n  $('#text').addEventListener('keydown', e => {\n    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {\n      e.preventDefault();\n      $('#composer').requestSubmit();\n    }\n  });\n  $('#text').addEventListener('input', e => {\n    const t = e.target;\n    t.style.height = 'auto';\n    t.style.height = Math.min(t.scrollHeight, 144) + 'px';\n  });\n\n  $('#back').addEventListener('click', () => {\n    cancelRecording();\n    active = null;\n    $('#app').dataset.view = 'list';\n    renderContacts();\n  });\n\n  $('#safety-btn').addEventListener('click', async () => {\n    const c = contacts.get(active);\n    if (!c) return;\n    $('#safety-peer').textContent = c.username;\n    $('#safety-number').textContent = await safetyNumber(active);\n    $('#safety').showModal();\n  });\n\n  $('#safety-verify').addEventListener('click', async () => {\n    const c = contacts.get(active);\n    if (!c) return;\n    c.verified = true;\n    await contactPut(c);\n    renderThreadHeader();\n    $('#safety').close();\n  });\n\n  $('#key-accept').addEventListener('click', async () => {\n    const c = contacts.get(active);\n    if (!c || !c.changedKey) return;\n    c.dhPub = c.changedKey;\n    c.changedKey = null;\n    c.verified = false;\n    sessionKeys.delete(c.username);\n    await contactPut(c);\n    renderThreadHeader();\n  });\n\n  document.addEventListener('visibilitychange', () => {\n    if (!document.hidden && active && unread.has(active)) { unread.delete(active); renderContacts(); }\n  });\n\n  // ---------- voice recording ----------\n  const MAX_VOICE_SECONDS = 60;\n  let recorder = null;\n  let recStream = null;\n  let recChunks = [];\n  let recStart = 0;\n  let recTimer = null;\n  let recCancelled = false;\n\n  function composerError(text) {\n    const el = $('#composer-error');\n    el.textContent = text || '';\n    el.hidden = !text;\n  }\n\n  function setRecordingUI(on) {\n    $('#rec-bar').hidden = !on;\n    $('#text').hidden = on;\n    $('#mic').hidden = on;\n    $('#send').hidden = on;\n    if (!on) $('#rec-time').textContent = '0:00';\n  }\n\n  async function startRecording() {\n    if (!active || recorder) return;\n    composerError('');\n    if (!navigator.mediaDevices || !window.MediaRecorder) {\n      return composerError('This browser cannot record audio. Try a recent Chrome, Edge, Firefox or Safari.');\n    }\n    try {\n      recStream = await navigator.mediaDevices.getUserMedia({ audio: true });\n    } catch (_) {\n      return composerError('Microphone access is blocked. Allow it in your browser settings, then try again.');\n    }\n\n    const mime = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/webm'].find(t => MediaRecorder.isTypeSupported(t)) || '';\n    const rec = new MediaRecorder(recStream, mime ? { mimeType: mime, audioBitsPerSecond: 24000 } : { audioBitsPerSecond: 24000 });\n    const peer = active;\n    recorder = rec;\n    recChunks = [];\n    recCancelled = false;\n\n    rec.ondataavailable = e => { if (e.data && e.data.size) recChunks.push(e.data); };\n    rec.onstop = async () => {\n      clearInterval(recTimer);\n      recStream.getTracks().forEach(t => t.stop());\n      recStream = null;\n      recorder = null;\n      setRecordingUI(false);\n      const dur = Math.round((Date.now() - recStart) / 1000);\n      if (recCancelled || dur < 1 || !recChunks.length) return;\n      const blob = new Blob(recChunks, { type: rec.mimeType || mime || 'audio/webm' });\n      try {\n        await sendVoice(peer, blob, dur);\n      } catch (err) {\n        console.error(err);\n        composerError('Could not send the voice note.');\n      }\n    };\n\n    recStart = Date.now();\n    rec.start();\n    setRecordingUI(true);\n    recTimer = setInterval(() => {\n      const secs = (Date.now() - recStart) / 1000;\n      $('#rec-time').textContent = fmtDur(secs);\n      if (secs >= MAX_VOICE_SECONDS) stopRecording(false);\n    }, 250);\n  }\n\n  function stopRecording(cancel) {\n    if (!recorder || recorder.state === 'inactive') return;\n    recCancelled = !!cancel;\n    recorder.stop();\n  }\n  function cancelRecording() { stopRecording(true); }\n\n  $('#mic').addEventListener('click', startRecording);\n  $('#rec-send').addEventListener('click', () => stopRecording(false));\n  $('#rec-cancel').addEventListener('click', () => stopRecording(true));\n\n  // ---------- startup ----------\n  async function enterApp() {\n    $('#onboard').hidden = true;\n    $('#app').hidden = false;\n    $('#app').dataset.view = 'list';\n    $('#me-name').textContent = me.username;\n    renderContacts();\n    connect();\n  }\n\n  async function init() {\n    if (!window.isSecureContext || !crypto.subtle || !window.indexedDB) {\n      showOnboard('This page needs a secure connection. Open it over HTTPS, or on localhost.');\n      return;\n    }\n    db = await openDB();\n    for (const c of await contactsAll()) contacts.set(c.username, c);\n    for (const c of contacts.keys()) {\n      const list = await msgsFor(c);\n      if (list.length) lastMsg.set(c, list[list.length - 1]);\n    }\n    me = await kvGet('identity');\n    if (me) enterApp(); else showOnboard();\n  }\n\n  init().catch(err => {\n    console.error(err);\n    showOnboard('Something went wrong starting the app. Reload and try again.');\n  });\n})();\n"
};

const server = http.createServer((req, res) => {
  let urlPath;
  try { urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname); }
  catch (_) { res.writeHead(400); return res.end(); }

  if (urlPath === '/') urlPath = '/index.html';
  const name = urlPath.slice(1);
  if (!Object.prototype.hasOwnProperty.call(FILES, name)) {
    res.writeHead(404, SECURITY_HEADERS);
    return res.end('Not found');
  }
  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'Content-Type': MIME[path.extname(name)] || 'application/octet-stream',
  });
  res.end(FILES[name]);
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
  const queuedBytes = queue.reduce((n, e) => n + e.ct.length, 0);
  if (queue.length >= MAX_QUEUE_PER_USER || queuedBytes + ct.length > MAX_QUEUE_BYTES) {
    return send(ws, { t: 'error', code: 'queue_full', id });
  }

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
