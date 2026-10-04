// The reader's vault and the keeper of its code.
//
// The key: opened by one touch of the passkey, kept in this worker's memory
// for a while, so that every encrypted message opens at once instead of
// asking for Touch ID each time. Nothing is written anywhere: the browser
// ends this worker, and the key with it, once no page of the reader has been
// open for about half a minute, and the rules below end it sooner. Pages
// never get the key back. They hand it over once (its PKCS #8 bytes, wiped on
// both sides), and then ask for the one shared secret a message needs
// (X25519 with the sender's ephemeral key, RFC 6637).
//
// The code: this worker carries the SHA-256 of every file of the reader
// (PINS, written by make-pins.py when the reader is published). It installs
// only if what the site serves matches, keeps those files, and serves the
// reader's pages from them; only a page it served may use the key. Someone
// who made GitHub or the names' DNS serve other code would have to serve
// another sw.js, and a new worker starts with an empty vault: the old one,
// and the key in it, are gone, and nothing opens without a new touch.

// PINS-BEGIN (make-pins.py)
const PINS = {
 "compose.html": "da65e60dbc342373b5f802c64f77d42552e5b36bdef0d83ef750e78110924377",
 "compose.mjs": "d10a484e43aa9938ac74c82d889849e9c43281d0265e77062499f472fb9ebb87",
 "decrypt.mjs": "9f226a49614f42b22e76b92f6dfa3e233f0569d0cfd2ec441cde1323f9167df0",
 "embed.mjs": "b4ddcf6cf33bcad25cd275ab1f26a036a7805fb626dcab16405e5d0563ec20fd",
 "frame.css": "c7111bb8d616141397b3ad6584ce8e8212911546b6cb4f73e2fca989dea72a49",
 "hub.html": "c70d16f0b7c3f93df8bf681560a0448eba840bb408c5ee2a5f5220d772ee4186",
 "hub.mjs": "40de18a28649e25f911b5ed7f37ff27d69862671a1574dcba070b3c447fdeb73",
 "icons.mjs": "602dc1b8685dbc1cc70c7d308ac38f0c57cacaa7dca98a1ee8f72c2ff8cc4359",
 "index.html": "823f140a5b266888319a20ef954c66632a12d2fec59f91d948e153a019cb7644",
 "keys.mjs": "1cda93435823cde27d3ccae2babc935c01057f2086855c3994e86e7997ea4611",
 "letter.mjs": "55acd0e58bfd2612c957eb0b011f291b955ead584136f12304d9aa94ded4d84c",
 "mail.css": "a0ccbe1e5d5f5cf058f7160e313fd227d907a94610f6d9b24d8ece8dd04303fb",
 "mark.mjs": "e9dee155a0f2ce8aca5aebeef793de6f3badfb529447615529825a8b0b60ea97",
 "mime.mjs": "c0c133806f84670aba345f14310ff9930782d0ec0b9d16656bb2f7dd873ecd3d",
 "openpgp.min.mjs": "7d3285efa6dfedbb34a136d8b5ad21c28fb973269df0b2818dcb74dfb40b59d9",
 "reader.css": "ec51f0be3ea8fc620ff83c909ad24967ab395ce7bf8de8123af589aaa78ae7bb",
 "row.css": "f372764933bb9c7d8f7ac92a624ee2849397429d4c4b1eab07b94a12ef70b2a2",
 "row.html": "1c20365a92f3e856c687e50b661088b1dcde1ff6d4662bed28c5a6b6938e4865",
 "row.mjs": "e2b9ae228a936ed0a4c1e7ba1120a8e0c8f405a13d9936f66d6554ec8e7c9f6a",
 "seal.mjs": "ade8321d2e225fa6ca71ed3552a4edcee37c9a1ed05dfb36bb4b1d6f870ac2b8",
 "sealed-core.mjs": "751cda0c898ab62b88e8d907c6e8431222084656a3ec1e7c474f0a8092a92c52",
 "send.html": "c675174a48ac3062ea557a8ef99f1b4ba33b3cf5f8a627ff6bca9c26e2a80aac",
 "send.mjs": "d56a1a77f4578959512b9e498399696dbdd24fea9e695041c51f39c2bf3168e6",
 "setup.html": "df55285b44830f1338568580ca9e92819c66bba77b8344ca22da79d519a84656",
 "setup.mjs": "57e3dc467b4631accfc6cd6a3951545369462aa866f72ef53183e63885e9d7f1",
 "sites.mjs": "da735072fc0ca68478199a4a477358f6283792952d8d435f91e33b268d91c7ce",
 "store.mjs": "b8f920eb2e07abf8ed706d50ab8e8955cc6a23eae60e2d8bf19a8378b7e837c4",
 "title.html": "d86d47b2f8c4e4265fd4bc42354e542e6b65b914653cc1c851255385c31412c8",
 "title.mjs": "f1fa9f8cdefa820c69d69461e0f8d5594fd81de03d02b2d452641e1d23243556",
 "vault.mjs": "6e444ce02df36f9eddf313cbabdcebc9fd5a3595661f4e5e5342159d979b9c03",
 "width.mjs": "3f46932569c028cb5815c12c59abf01858e10817dce65d384d4ce43ce29aede8"
};
// PINS-END
const CACHE = 'reader-' + Object.values(PINS).map(v => v.slice(0, 4)).join('').slice(0, 48);
const TYPES = {html: 'text/html; charset=utf-8', mjs: 'text/javascript; charset=utf-8', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8'};

const HOUR = 3600e3, MINUTE = 60e3;
const LONGEST = 12 * HOUR;       // however it is used, a day's work at most
const HIDDEN = 5 * MINUTE;       // no page of Mail in view for this long (the reader's own pages tell)
const INNER = HOUR;              // nothing done in the reader's own frames for this long, whatever Mail says
const CHOICES = [5, 15, 30, 60]; // minutes without use; anything else is 15

// The point a key's mark is made with (mark.mjs): SHA-256 of a fixed text,
// so nobody knows its discrete logarithm and only the key's owner can compute
// X25519(key, point). The mark shows that the reader on screen holds the key.
const MARK_TEXT = 'Mail Reader mark, version 1';

let vault = null;  // {keys: Map(keyId -> {key, mark, info}), since, used, inner, seen, idle}
let timer = 0, epoch = 0;  // epoch: a lock while a key is being put in wins

const tellAll = async message => {
  for (const c of await self.clients.matchAll({includeUncontrolled: true, type: 'window'})) c.postMessage(message);
};

function lock(why) {
  epoch++;
  if (!vault) return;
  vault = null;
  clearTimeout(timer);
  tellAll({type: 'vault-locked', why});
}

// Whether the time is up: too long without use, without a page in view, or at all.
function expired(now = Date.now()) {
  return now - vault.since > LONGEST || now - vault.used > vault.idle || now - vault.inner > INNER || now - vault.seen > HIDDEN;
}
function check() {
  if (vault && expired()) lock('time');
}
function plan() {
  clearTimeout(timer);
  if (!vault) return;
  const next = Math.min(vault.since + LONGEST, vault.used + vault.idle, vault.inner + INNER, vault.seen + HIDDEN) - Date.now();
  timer = setTimeout(() => { check(); plan(); }, Math.max(1000, next + 100));
}

const state = () => vault
  ? {unlocked: true, keyIds: [...vault.keys.keys()], marks: Object.fromEntries([...vault.keys].map(([id, k]) => [id, k.mark])),
     infos: Object.fromEntries([...vault.keys].map(([id, k]) => [id, k.info])),
     until: Math.min(vault.since + LONGEST, vault.used + vault.idle, vault.inner + INNER), idle: vault.idle}
  : {unlocked: false, keyIds: [], marks: {}, infos: {}};

let fixedPoint = null;
async function markPoint() {
  if (!fixedPoint) {
    fixedPoint = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(MARK_TEXT)));
    fixedPoint[31] &= 0x7f;
  }
  return fixedPoint;
}
async function markOf(key) {
  const point = await markPoint();
  const peer = await crypto.subtle.importKey('raw', point, {name: 'X25519'}, false, []);
  const shared = await crypto.subtle.deriveBits({name: 'X25519', public: peer}, key, 256);
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(MARK_TEXT)}, base, 32));
  return [bits[0] >> 2, ((bits[0] & 3) << 4) | (bits[1] >> 4), ((bits[1] & 15) << 2) | (bits[2] >> 6), bits[2] & 63];
}

async function handle(d, from) {
  if (vault) check();
  switch (d.type) {
    case 'state':
      return {...state(), served: await served(from)};
    case 'hold': {
      if (!await served(from)) return {...state(), served: false};  // a page from the network may not put a key in
      // From a page that has just unsealed the key with the passkey.
      const idle = CHOICES.includes(d.minutes) ? d.minutes * MINUTE : 15 * MINUTE;
      const started = epoch, keys = new Map(vault ? vault.keys : []);
      for (const k of Array.isArray(d.keys) ? d.keys.slice(0, 8) : []) {
        const info = k.info || {};
        if (!/^[0-9a-f]{16}$/.test(k.keyId) || !(k.pkcs8 instanceof ArrayBuffer) || info.keyId !== k.keyId || !/^[0-9a-f]{40}$/.test(info.fingerprint) ||
            !Number.isInteger(info.hash) || !Number.isInteger(info.cipher)) continue;
        try {
          const key = await crypto.subtle.importKey('pkcs8', k.pkcs8, {name: 'X25519'}, false, ['deriveBits']);
          keys.set(k.keyId, {key, mark: await markOf(key), info: {fingerprint: info.fingerprint, keyId: info.keyId, hash: info.hash, cipher: info.cipher}});
        } finally {
          new Uint8Array(k.pkcs8).fill(0);
        }
      }
      if (!keys.size || epoch !== started) return state();  // locked meanwhile: the lock stands
      const now = Date.now();
      vault = {keys, since: vault?.since || now, used: now, inner: now, seen: now, idle};
      plan();
      tellAll({type: 'vault-unlocked'});
      return state();
    }
    case 'derive': {
      if (!await served(from)) return {foreign: true};  // a page from the network, not from the checked copy
      const held = vault?.keys.get(d.keyId);
      if (!held || !(d.ephemeral instanceof Uint8Array) || d.ephemeral.length !== 32) return {locked: !held};
      const p = await markPoint();
      if (d.ephemeral.every((b, i) => (i === 31 ? b & 0x7f : b) === p[i])) return {};  // that secret is the mark's (X25519 ignores the top bit)
      const peer = await crypto.subtle.importKey('raw', d.ephemeral, {name: 'X25519'}, false, []);
      return {bits: await crypto.subtle.deriveBits({name: 'X25519', public: peer}, held.key, 256)};
    }
    case 'use':  // someone used Mail (a click, a key, a scroll); inner: in the reader's own frames
      if (vault && await served(from)) { vault.used = Date.now(); if (d.inner === true) vault.inner = vault.used; plan(); }
      return state();
    case 'seen':  // a page of Mail is in view
      if (vault && await served(from)) { vault.seen = Date.now(); plan(); }
      return state();
    case 'lock':
      lock('asked');
      return state();
  }
  return state();
}

const hex = buffer => [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');

// Installing: every file, fetched past the browser's cache and checked; one
// that differs and the install fails, so the worker before stays.
self.addEventListener('install', e => e.waitUntil((async () => {
  const cache = await caches.open(CACHE);
  for (const [name, sum] of Object.entries(PINS)) {
    const r = await fetch(name, {cache: 'no-cache'});
    if (!r.ok) throw new Error('missing ' + name);
    const body = await r.arrayBuffer();
    if (hex(await crypto.subtle.digest('SHA-256', body)) !== sum) throw new Error('changed ' + name);
    await cache.put(name, new Response(body, {headers: {'Content-Type': TYPES[name.split('.').pop()] || 'application/octet-stream'}}));
  }
  await self.skipWaiting();
})()));
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const name of await caches.keys()) if (name.startsWith('reader-') && name !== CACHE) await caches.delete(name);
})()));
// Every request to this site is answered here: a file of the reader from
// the checked copy, checked again as it is served (anything on this site
// could write to the browser's cache), and anything else not found. So a
// page this worker controls has only the reader's own code in it.
const checked = new Map();  // name -> verified bytes, while this worker runs
async function pinned(name) {
  if (checked.has(name)) return checked.get(name);
  const r = await (await caches.open(CACHE)).match(name);
  if (!r) return null;
  const body = await r.arrayBuffer();
  if (hex(await crypto.subtle.digest('SHA-256', body)) !== PINS[name]) return null;
  checked.set(name, body);
  return body;
}
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  if (!Object.hasOwn(PINS, name)) { e.respondWith(new Response('Not found', {status: 404})); return; }
  e.respondWith(pinned(name).then(body => body
    ? new Response(body.slice(0), {headers: {'Content-Type': TYPES[name.split('.').pop()] || 'application/octet-stream'}})
    : new Response('', {status: 503})));
});
// A page this worker served (its document came from the checked copy).
const served = async id => !!id && (await self.clients.matchAll({type: 'window'})).some(c => c.id === id);
self.addEventListener('message', e => {
  const reply = e.ports[0];
  e.waitUntil(handle(e.data || {}, e.source?.id).then(r => reply?.postMessage(r), err => reply?.postMessage({error: String(err?.message || err)})));
});
