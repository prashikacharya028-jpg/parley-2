# Parley: a private, end-to-end encrypted messenger

A small relay server (Node.js) and a browser client. Messages are encrypted on the sender's device and decrypted on the recipient's. The server only stores public keys and scrambled data.

## Run it

```bash
npm install
npm start
# open http://localhost:3000 in two different browsers (or one normal + one private window)
```

Create two usernames (for example `alice` and `bob`), then start a chat from one to the other.

The browser's crypto APIs only work on `https://` or `localhost`. To use it with other people, put it behind HTTPS, for example with Caddy:

```
chat.example.com {
    reverse_proxy localhost:3000
}
```

Environment variables: `PORT` (default 3000), `DATA_FILE` (default `./data.json`).

## How it works

| Piece | What it does |
| --- | --- |
| Identity | Each device generates an ECDSA P-256 key (proves who you are) and an ECDH P-256 key (encryption). Private keys are stored non-extractable in IndexedDB. |
| Login | No passwords. The server sends a random challenge; the client signs it. |
| Encryption | ECDH shared secret, then HKDF-SHA-256, then AES-256-GCM with a fresh random IV per message. Sender, recipient and message id are bound in as authenticated data. |
| Server | Verifies signatures, relays envelopes, keeps undelivered ones until the recipient acknowledges, rate-limits. It cannot read messages. |
| Trust | Contact keys are pinned on first use. A changed key triggers a warning. Compare the safety number with your contact over a call to rule out a malicious server. |

## Known limits (be honest with your users)

- **No forward secrecy.** The keys are long-lived, so if a device's private key were ever compromised, past captured traffic could be decrypted. For stronger guarantees, add a Double Ratchet (the Signal protocol) or use a library such as libsignal.
- **One device per account.** The identity lives in one browser profile. Clearing site data loses it, and there is no recovery by design.
- **Metadata is visible to the server:** who talks to whom, when, and message sizes.
- **Message history is stored in plaintext in the browser's IndexedDB** on your own device. Use full-disk encryption, or add a passphrase-wrapped store.
- **Web clients must trust the server to deliver honest JavaScript.** For the highest security, ship it as an installed app (Electron, mobile) rather than a page served by the same server you want to distrust.
- Storage is a JSON file, which is fine for a small group. Swap in SQLite or Postgres for more users.
- No push notifications, attachments or group chats yet.

## Files

```
server.js          relay server, static file host
index.html         client shell
style.css         styles (light and dark)
app.js            keys, encryption, networking, UI
```
