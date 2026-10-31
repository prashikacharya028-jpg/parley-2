'use strict';
/**
 * Parley client.
 *
 * Crypto design
 *  - Each device makes two P-256 key pairs: ECDSA (proves who you are to the server)
 *    and ECDH (derives a secret shared with each contact). Private keys are stored as
 *    NON-EXTRACTABLE CryptoKeys in IndexedDB, so page scripts cannot read them out.
 *  - Shared secret = ECDH(my private, their public) -> HKDF-SHA-256 -> AES-256-GCM key.
 *  - Every message uses a fresh random 96-bit IV, and binds sender, recipient and message id
 *    as AES-GCM additional data, so the server can't redirect or relabel ciphertexts.
 *  - Contacts' keys are pinned on first use (TOFU). If they change, you get a warning.
 *    Compare the safety number out-of-band to rule out a malicious server.
 */
(() => {
  const $ = sel => document.querySelector(sel);
  const subtle = crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------- encoding helpers ----------
  function b64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }
  function unb64(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const randomId = () => hex(crypto.getRandomValues(new Uint8Array(16)));
  const pubOnly = jwk => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
  const sameKey = (a, b) => a && b && a.x === b.x && a.y === b.y;

  // ---------- IndexedDB ----------
  let db;
  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('parley', 1);
      req.onupgradeneeded = () => {
        const d = req.result;
        d.createObjectStore('kv');
        d.createObjectStore('contacts', { keyPath: 'username' });
        d.createObjectStore('messages', { keyPath: 'id' }).createIndex('peer', 'peer');
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  function run(store, mode, fn) {
    return new Promise((resolve, reject) => {
      const t = db.transaction(store, mode);
      const rq = fn(t.objectStore(store));
      t.oncomplete = () => resolve(rq ? rq.result : undefined);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  }
  const kvGet = k => run('kv', 'readonly', s => s.get(k));
  const kvSet = (k, v) => run('kv', 'readwrite', s => s.put(v, k));
  const kvDel = k => run('kv', 'readwrite', s => s.delete(k));
  const contactsAll = () => run('contacts', 'readonly', s => s.getAll());
  const contactPut = c => run('contacts', 'readwrite', s => s.put(c));
  const msgPut = m => run('messages', 'readwrite', s => s.put(m));
  const msgGet = id => run('messages', 'readonly', s => s.get(id));
  const msgsFor = peer => run('messages', 'readonly', s => s.index('peer').getAll(peer))
    .then(list => list.sort((a, b) => a.ts - b.ts));

  // ---------- state ----------
  let me = null;            // { username, sign, dh, registered }
  let ws = null;
  let backoff = 1000;
  let active = null;        // username of open conversation
  const contacts = new Map();   // username -> contact record
  const lastMsg = new Map();    // username -> latest message record
  const unread = new Map();     // username -> count
  const sessionKeys = new Map();
  const pendingLookups = new Map();

  // ---------- identity ----------
  async function createIdentity(username) {
    const sign = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const dh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    me = { username, sign, dh, registered: false };
    await kvSet('identity', me);
  }

  // ---------- onboarding ----------
  function showOnboard(errorText) {
    $('#app').hidden = true;
    $('#onboard').hidden = false;
    const err = $('#onboard-error');
    err.hidden = !errorText;
    err.textContent = errorText || '';
  }

  $('#onboard-form').addEventListener('submit', async e => {
    e.preventDefault();
    const name = $('#username').value.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,24}$/.test(name)) {
      return showOnboard('Usernames are 3–24 characters: lowercase letters, numbers or underscore.');
    }
    try {
      await createIdentity(name);
      $('#onboard').hidden = true;
      enterApp();
    } catch (err) {
      console.error(err);
      showOnboard('Could not create keys in this browser. Open the page over HTTPS or on localhost.');
    }
  });

  // ---------- networking ----------
  function setStatus(state) {
    const el = $('#status');
    el.dataset.state = state;
    el.title = { online: 'Connected', connecting: 'Connecting…', offline: 'Offline, retrying…' }[state];
  }

  function connect() {
    setStatus('connecting');
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onmessage = ev => {
      let m;
      try { m = JSON.parse(ev.data); } catch (_) { return; }
      handleServer(m).catch(err => console.error('handler error', err));
    };
    ws.onclose = () => {
      setStatus('offline');
      pendingLookups.forEach(p => p.reject(new Error('offline')));
      pendingLookups.clear();
      setTimeout(() => { if (me) connect(); }, backoff);
      backoff = Math.min(backoff * 2, 15000);
    };
  }

  const wsSend = obj => ws && ws.readyState === 1 && (ws.send(JSON.stringify(obj)), true);

  async function handleServer(m) {
    switch (m.t) {
      case 'hello': {
        const sig = await subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          me.sign.privateKey,
          enc.encode(`pm-auth-v1:${m.nonce}:${me.username}`)
        );
        if (me.registered) {
          wsSend({ t: 'auth', username: me.username, sig: b64(sig) });
        } else {
          const [signPub, dhPub] = await Promise.all([
            subtle.exportKey('jwk', me.sign.publicKey),
            subtle.exportKey('jwk', me.dh.publicKey),
          ]);
          wsSend({
            t: 'register', username: me.username, sig: b64(sig),
            signPub: pubOnly(signPub), dhPub: pubOnly(dhPub),
          });
        }
        break;
      }
      case 'ready':
        backoff = 1000;
        setStatus('online');
        if (!me.registered) { me.registered = true; await kvSet('identity', me); }
        break;
      case 'user': {
        const p = pendingLookups.get(m.username);
        if (p) { pendingLookups.delete(m.username); p.resolve(m); }
        break;
      }
      case 'msg':
        await onIncoming(m);
        break;
      case 'sent':
        await updateStatus(m.id, 'sent', m.ts);
        break;
      case 'error':
        await onServerError(m);
        break;
    }
  }

  async function onServerError(m) {
    if (m.id) {
      await updateStatus(m.id, 'failed');
      return;
    }
    if (m.code === 'taken') {
      await kvDel('identity');
      me = null;
      if (ws) ws.close();
      showOnboard('That username is taken. Pick another one.');
    } else if (m.code === 'auth_failed' || m.code === 'bad_username' || m.code === 'bad_key') {
      if (!me.registered) {
        await kvDel('identity');
        me = null;
        if (ws) ws.close();
        showOnboard('The server rejected that identity. Try a different username.');
      } else {
        setStatus('offline');
        console.error('Authentication failed for', me.username);
      }
    } else if (m.code === 'rate_limited') {
      showOnboard('Too many sign-ups from this network. Try again later.');
    }
  }

  function lookup(username) {
    return new Promise((resolve, reject) => {
      if (!ws || ws.readyState !== 1) return reject(new Error('offline'));
      const timer = setTimeout(() => {
        pendingLookups.delete(username);
        reject(new Error('timeout'));
      }, 8000);
      pendingLookups.set(username, {
        resolve: v => { clearTimeout(timer); resolve(v); },
        reject: e => { clearTimeout(timer); reject(e); },
      });
      wsSend({ t: 'lookup', username });
    });
  }

  // ---------- contacts & session keys ----------
  async function addContact(username) {
    const res = await lookup(username);
    if (res.missing) return null;
    const c = { username, dhPub: res.dhPub, verified: false, changedKey: null, added: Date.now() };
    contacts.set(username, c);
    await contactPut(c);
    return c;
  }

  // Compare the server's current key for a contact with the one we pinned.
  async function checkKeyChange(username) {
    const c = contacts.get(username);
    if (!c) return;
    try {
      const res = await lookup(username);
      if (res.missing || !res.dhPub) return;
      if (!sameKey(res.dhPub, c.dhPub)) {
        c.changedKey = res.dhPub;
        await contactPut(c);
        if (active === username) renderThreadHeader();
      }
    } catch (_) { /* offline; try again later */ }
  }

  async function sessionKey(peer) {
    if (sessionKeys.has(peer)) return sessionKeys.get(peer);
    const c = contacts.get(peer);
    if (!c) throw new Error('unknown contact');
    const theirs = await subtle.importKey('jwk', c.dhPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const bits = await subtle.deriveBits({ name: 'ECDH', public: theirs }, me.dh.privateKey, 256);
    const hkdfKey = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    const pair = [me.username, peer].sort().join('|');
    const key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('parley-v1'), info: enc.encode(pair) },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    sessionKeys.set(peer, key);
    return key;
  }

  // Safety number: hash of both public ECDH keys, shown as six 5-digit groups.
  async function safetyNumber(peer) {
    const mine = pubOnly(await subtle.exportKey('jwk', me.dh.publicKey));
    const theirs = contacts.get(peer).dhPub;
    const parts = [`${mine.x}.${mine.y}`, `${theirs.x}.${theirs.y}`].sort();
    const digest = new Uint8Array(await subtle.digest('SHA-256', enc.encode(parts.join('|'))));
    const view = new DataView(digest.buffer);
    const groups = [];
    for (let i = 0; i < 6; i++) groups.push(String(view.getUint32(i * 4) % 100000).padStart(5, '0'));
    return groups.join(' ');
  }

  // ---------- sending & receiving ----------
  const aad = (from, to, id) => enc.encode(`${from}>${to}:${id}`);

  async function sendMessage(peer, text) {
    const id = randomId();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await sessionKey(peer);
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad(me.username, peer, id) },
      key,
      enc.encode(JSON.stringify({ text }))
    );
    const rec = { id, peer, dir: 'out', text, ts: Date.now(), status: 'sending' };
    await msgPut(rec);
    lastMsg.set(peer, rec);
    if (active === peer) appendMessage(rec);
    renderContacts();
    if (!wsSend({ t: 'msg', to: peer, id, iv: b64(iv), ct: b64(ct) })) {
      await updateStatus(id, 'failed');
    }
  }

  async function onIncoming(m) {
    const ack = () => wsSend({ t: 'ack', ids: [m.id] });
    try {
      if (await msgGet(m.id)) return ack();

      let c = contacts.get(m.from) || await addContact(m.from);
      if (!c) return ack();

      let plain;
      try {
        const key = await sessionKey(m.from);
        plain = await subtle.decrypt(
          { name: 'AES-GCM', iv: unb64(m.iv), additionalData: aad(m.from, me.username, m.id) },
          key,
          unb64(m.ct)
        );
      } catch (err) {
        // Most likely the sender has new keys. Flag it, drop the message.
        console.warn('Could not decrypt message from', m.from);
        await checkKeyChange(m.from);
        return ack();
      }

      const { text } = JSON.parse(dec.decode(plain));
      const rec = { id: m.id, peer: m.from, dir: 'in', text: String(text), ts: m.ts, status: 'received' };
      await msgPut(rec);
      lastMsg.set(m.from, rec);
      if (active === m.from && !document.hidden) {
        appendMessage(rec);
      } else {
        unread.set(m.from, (unread.get(m.from) || 0) + 1);
        if (active === m.from) appendMessage(rec);
      }
      renderContacts();
      ack();
    } catch (err) {
      console.error('incoming error', err);
    }
  }

  async function updateStatus(id, status, ts) {
    const rec = await msgGet(id);
    if (!rec) return;
    rec.status = status;
    if (ts) rec.ts = ts;
    await msgPut(rec);
    if (lastMsg.get(rec.peer)?.id === id) lastMsg.set(rec.peer, rec);
    if (active === rec.peer) {
      const el = document.querySelector(`[data-id="${id}"]`);
      if (el) fillMessage(el, rec);
    }
  }

  // ---------- rendering ----------
  const timeFmt = new Intl.DateTimeFormat([], { hour: 'numeric', minute: '2-digit' });
  const dayFmt = new Intl.DateTimeFormat([], { weekday: 'long', month: 'short', day: 'numeric' });

  function renderContacts() {
    const list = $('#contacts');
    list.textContent = '';
    const sorted = [...contacts.values()].sort(
      (a, b) => (lastMsg.get(b.username)?.ts || b.added) - (lastMsg.get(a.username)?.ts || a.added)
    );
    $('#contacts-empty').hidden = sorted.length > 0;

    for (const c of sorted) {
      const li = document.createElement('li');
      const btn = document.createElement('button');
      btn.type = 'button';
      if (c.username === active) btn.setAttribute('aria-current', 'true');

      const name = document.createElement('span');
      name.className = 'name';
      name.textContent = c.username;

      const preview = document.createElement('span');
      preview.className = 'preview';
      preview.textContent = lastMsg.get(c.username)?.text || 'No messages yet';

      btn.append(name, preview);
      const n = unread.get(c.username) || 0;
      if (n) {
        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = String(n);
        btn.append(badge);
      }
      btn.addEventListener('click', () => openChat(c.username));
      li.append(btn);
      list.append(li);
    }
  }

  function fillMessage(li, rec) {
    li.className = `msg ${rec.dir === 'out' ? 'out' : 'in'}${rec.status === 'failed' ? ' failed' : ''}`;
    li.textContent = '';
    const body = document.createElement('span');
    body.textContent = rec.text;
    const meta = document.createElement('span');
    meta.className = 'meta';
    const label = rec.status === 'failed' ? 'Not sent' : rec.status === 'sending' ? 'Sending…' : timeFmt.format(rec.ts);
    meta.textContent = label;
    li.append(body, meta);
  }

  let lastDay = '';
  function appendMessage(rec) {
    const list = $('#msgs');
    const day = dayFmt.format(rec.ts);
    if (day !== lastDay) {
      const d = document.createElement('li');
      d.className = 'day';
      d.textContent = day;
      list.append(d);
      lastDay = day;
    }
    const li = document.createElement('li');
    li.dataset.id = rec.id;
    fillMessage(li, rec);
    list.append(li);
    list.scrollTop = list.scrollHeight;
  }

  function renderThreadHeader() {
    const c = contacts.get(active);
    if (!c) return;
    $('#peer-name').textContent = c.username;
    const v = $('#peer-verify');
    v.textContent = c.verified ? 'Verified' : 'Not verified yet';
    v.classList.toggle('ok', !!c.verified);
    $('#key-warning').hidden = !c.changedKey;
  }

  async function openChat(username) {
    active = username;
    unread.delete(username);
    $('#app').dataset.view = 'chat';
    $('#thread-empty').hidden = true;
    $('#thread-view').hidden = false;
    renderThreadHeader();

    const list = $('#msgs');
    list.textContent = '';
    lastDay = '';
    for (const rec of await msgsFor(username)) appendMessage(rec);
    renderContacts();
    $('#text').focus();
    checkKeyChange(username);
  }

  // ---------- UI events ----------
  $('#new-chat').addEventListener('submit', async e => {
    e.preventDefault();
    const input = $('#peer-input');
    const err = $('#new-chat-error');
    const name = input.value.trim().toLowerCase();
    err.hidden = true;
    if (!name) return;
    if (name === me.username) { err.textContent = 'That is your own username.'; err.hidden = false; return; }
    try {
      const c = contacts.get(name) || await addContact(name);
      if (!c) { err.textContent = `No one is registered as "${name}".`; err.hidden = false; return; }
      input.value = '';
      renderContacts();
      openChat(name);
    } catch (_) {
      err.textContent = 'Could not reach the server. Check your connection and try again.';
      err.hidden = false;
    }
  });

  $('#composer').addEventListener('submit', async e => {
    e.preventDefault();
    const box = $('#text');
    const text = box.value.trim();
    if (!text || !active) return;
    box.value = '';
    box.style.height = 'auto';
    try {
      await sendMessage(active, text);
    } catch (err) {
      console.error(err);
    }
  });

  $('#text').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      $('#composer').requestSubmit();
    }
  });
  $('#text').addEventListener('input', e => {
    const t = e.target;
    t.style.height = 'auto';
    t.style.height = Math.min(t.scrollHeight, 144) + 'px';
  });

  $('#back').addEventListener('click', () => {
    active = null;
    $('#app').dataset.view = 'list';
    renderContacts();
  });

  $('#safety-btn').addEventListener('click', async () => {
    const c = contacts.get(active);
    if (!c) return;
    $('#safety-peer').textContent = c.username;
    $('#safety-number').textContent = await safetyNumber(active);
    $('#safety').showModal();
  });

  $('#safety-verify').addEventListener('click', async () => {
    const c = contacts.get(active);
    if (!c) return;
    c.verified = true;
    await contactPut(c);
    renderThreadHeader();
    $('#safety').close();
  });

  $('#key-accept').addEventListener('click', async () => {
    const c = contacts.get(active);
    if (!c || !c.changedKey) return;
    c.dhPub = c.changedKey;
    c.changedKey = null;
    c.verified = false;
    sessionKeys.delete(c.username);
    await contactPut(c);
    renderThreadHeader();
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && active && unread.has(active)) { unread.delete(active); renderContacts(); }
  });

  // ---------- startup ----------
  async function enterApp() {
    $('#onboard').hidden = true;
    $('#app').hidden = false;
    $('#app').dataset.view = 'list';
    $('#me-name').textContent = me.username;
    renderContacts();
    connect();
  }

  async function init() {
    if (!window.isSecureContext || !crypto.subtle || !window.indexedDB) {
      showOnboard('This page needs a secure connection. Open it over HTTPS, or on localhost.');
      return;
    }
    db = await openDB();
    for (const c of await contactsAll()) contacts.set(c.username, c);
    for (const c of contacts.keys()) {
      const list = await msgsFor(c);
      if (list.length) lastMsg.set(c, list[list.length - 1]);
    }
    me = await kvGet('identity');
    if (me) enterApp(); else showOnboard();
  }

  init().catch(err => {
    console.error(err);
    showOnboard('Something went wrong starting the app. Reload and try again.');
  });
})();
