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
 "alarm.mjs": "2e924e862b89c8961ddac0dca7fd7522097a5c1a93b259cf816adb0212756854",
 "compose.html": "af86e0834cee3319214b6c2bafd530da6e2ee243b0f4b98f7a4f68aba993661c",
 "compose.mjs": "62ebf28f51517709674a46c2ca798f7d5b26ae1fd25328542cb5fa368dfb59d7",
 "contacts.mjs": "232dc076e82248fbbeca6e1bff54cffb834d2df4b24a4bdaa62937d8135661ab",
 "decrypt.mjs": "9dfb11b5b6a1788fdadde12b2d668d7b954cc291ed0c4f4e0d7922ba61de5203",
 "dkim.mjs": "98b8bfd8d23f2cd940e76a6de8f98a069d8d00e43eee94e211025b9b80f7d269",
 "embed.mjs": "3d5bf2c4471a0278856eeedfaf8a18183c38c56ce63e97a40e9ec638587e8a50",
 "frame.css": "95f5021cdf3ae30b5e472da3c781fc9c4e1b1b4ec6955920e680ae837ffa71c1",
 "hub.html": "105fd268b4f176946950ebd03d2defad76ccf911e10d885b5caac5f5223b249f",
 "hub.mjs": "86c66d8655f115ee11d5e968be91d2861a2b677830b683d275aa6e46af4d3a28",
 "icons.mjs": "58b17ff7905e30859040cc0b77b6c2fa02eb7a9a1c4e7ae5882cf44865428961",
 "index.html": "1bee2962d0b099b2cc1d452de250002b99e310c836078c07d291e24d1fd6aeb8",
 "keys.html": "1939c572fc96989f0d85dab9495ab58e03e1f7d4279bf2b8b8329a10ccd33cb8",
 "keys.mjs": "70c3801c51e67427dbea852f7686d6b9e074e9fb3c0054135934ec9c6564fdd7",
 "letter.mjs": "269f3868371ec27c485bff8a389b0e9d42b5e8aef59b7d8a5c89bc1fe3622f9c",
 "mail.css": "4ecb4ba14c8c93206d29867f325a3a74be39b1a198d51901cdb5040dd50caf5c",
 "mark.mjs": "4ba98ea35bc9eb30f2e1a75a2f93c7fba305d77ceec42bcf3ec150efba719151",
 "marks.mjs": "54fc92d4e354f04ea0b3f406141d6a0d28cec93626d3e65aafc90069db6624ca",
 "mime.mjs": "2669eb9343775add28dda1101cc4ec2d7e6c238bae33c9ea8ef87fd53b7f5835",
 "notices.mjs": "f65d87fe45605a7d16710964003f36cd571f5686b0c9149054aa672b57ce0783",
 "openpgp.min.mjs": "7d3285efa6dfedbb34a136d8b5ad21c28fb973269df0b2818dcb74dfb40b59d9",
 "reader.css": "814529f1db866ecf1b590fce1a4f61db5b4083badd8da9c4dbd511f80e723618",
 "row.css": "f372764933bb9c7d8f7ac92a624ee2849397429d4c4b1eab07b94a12ef70b2a2",
 "row.html": "1c20365a92f3e856c687e50b661088b1dcde1ff6d4662bed28c5a6b6938e4865",
 "row.mjs": "c51ace7c4a897a7a950ade899ed491f073c678c9ddcc69f8c9725a50caab9439",
 "seal.mjs": "0bb9af11c36e33d8cf9a8689e32e1c974629b770d0a85c569bc39ce8613cf3c1",
 "sealed-core.mjs": "f5a3b762ff41cfffe0c409018ea390b6f551829feee17802d1ed60452891374d",
 "send.html": "7f91f2cae14487f1a45c23c38d868f57766682f719312952c0992f96e428f5ce",
 "send.mjs": "aceb11eca13fc7c321e29a6e7cf80855439492210f2721cf5e756a637667e045",
 "setup.html": "b04f9e9e80fdea989fd15bc12b7e45165baf9834b5cd1c98eeadc097e0b31d06",
 "setup.mjs": "4902f12b8b32cd3bbe88c70059dd4cbc0446760dce0012f7aa46f33bc8b558d4",
 "sites.mjs": "da735072fc0ca68478199a4a477358f6283792952d8d435f91e33b268d91c7ce",
 "store.mjs": "e0a92fa31f985df8f6d2bdcef017a4fbcc1344e05146db6820c9127cb7a9e940",
 "tab.mjs": "6cb9413d6a36c53e8a50cb2332fb484fb8c84e2e66b79743510b4c8a253a4757",
 "title.html": "d86d47b2f8c4e4265fd4bc42354e542e6b65b914653cc1c851255385c31412c8",
 "title.mjs": "f1fa9f8cdefa820c69d69461e0f8d5594fd81de03d02b2d452641e1d23243556",
 "vault.mjs": "d1bb5d1a8edc4fc1955623fd225d16ce70fca30ee62a527ef7f805a0eedeabe2",
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
const MARK_TEXT = 'Mail Reader mark, version 1';  // a protocol label, kept from the old name (mark.mjs)

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
// X25519 of a key with the mark's point: the secret the mark comes from,
// which derive never hands out, whatever point a page sends to reach it.
async function markSecret(key) {
  const peer = await crypto.subtle.importKey('raw', await markPoint(), {name: 'X25519'}, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: peer}, key, 256));
}
async function markOf(key) {
  const shared = await markSecret(key);
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(MARK_TEXT)}, base, 32));
  return [bits[0] >> 2, ((bits[0] & 3) << 4) | (bits[1] >> 4), ((bits[1] & 15) << 2) | (bits[2] >> 6), bits[2] & 63];
}

async function handle(d, from) {
  if (vault) check();
  switch (d.type) {
    case 'state': {
      // The mark proves a page is the reader's own: a page from the network
      // gets the state without it.
      const ok = await served(from);
      return ok ? {...state(), served: true} : {...state(), marks: {}, served: false};
    }
    case 'hold': {
      if (!await served(from)) return {...state(), served: false};  // a page from the network may not put a key in
      if (await alarmRaised()) return {...state(), alarm: true};    // you reported a problem (alarm.mjs): no key until you clear it
      // From a page that has just unsealed the key with the passkey.
      const idle = CHOICES.includes(d.minutes) ? d.minutes * MINUTE : 15 * MINUTE;
      const started = epoch, keys = new Map(vault ? vault.keys : []);
      for (const k of Array.isArray(d.keys) ? d.keys.slice(0, 8) : []) {
        const info = k.info || {};
        if (!/^[0-9a-f]{16}$/.test(k.keyId) || !(k.pkcs8 instanceof ArrayBuffer) || info.keyId !== k.keyId || !/^[0-9a-f]{40}$/.test(info.fingerprint) ||
            !Number.isInteger(info.hash) || !Number.isInteger(info.cipher)) continue;
        try {
          const key = await crypto.subtle.importKey('pkcs8', k.pkcs8, {name: 'X25519'}, false, ['deriveBits']);
          keys.set(k.keyId, {key, mark: await markOf(key), markSecret: await markSecret(key), info: {fingerprint: info.fingerprint, keyId: info.keyId, hash: info.hash, cipher: info.cipher}});
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
      const bits = await crypto.subtle.deriveBits({name: 'X25519', public: peer}, held.key, 256), out = new Uint8Array(bits);
      if (held.markSecret && out.every((b, i) => b === held.markSecret[i])) return {};  // another point to the same secret
      return {bits};
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
    // Origin-Agent-Cluster: a hint to keep the reader's pages in a process of
    // their own, apart from the mail page that frames them (same site).
    ? new Response(body.slice(0), {headers: {'Content-Type': TYPES[name.split('.').pop()] || 'application/octet-stream', 'Origin-Agent-Cluster': '?1'}})
    : new Response('', {status: 503})));
});
// Whether you raised the alarm on setup.html (alarm.mjs keeps it).
function alarmRaised() {
  return new Promise(resolve => {
    const r = indexedDB.open('reader-alarm', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('alarm');
    r.onerror = () => resolve(false);
    r.onsuccess = () => {
      try {
        const g = r.result.transaction('alarm').objectStore('alarm').get('raised');
        g.onsuccess = () => { resolve(!!g.result); r.result.close(); };
        g.onerror = () => { resolve(false); r.result.close(); };
      } catch (e) { resolve(false); r.result.close(); }
    };
  });
}

// A page this worker served (its document came from the checked copy).
const served = async id => !!id && (await self.clients.matchAll({type: 'window'})).some(c => c.id === id);
self.addEventListener('message', e => {
  const reply = e.ports[0];
  e.waitUntil(handle(e.data || {}, e.source?.id).then(r => reply?.postMessage(r), err => reply?.postMessage({error: String(err?.message || err)})));
});
