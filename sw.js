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
 "compose.html": "75fa0d025ba3a705e93df7222fe67ad2f8e9b199c745cc89a7dc0ed95cf54b12",
 "compose.mjs": "991b403eca0994f14f761c69074572dc295070ca1908eae048bb46ebbf419563",
 "decrypt.mjs": "7b280f474ebbd0bb017123020767d7dc14e906c890a1a054862379db3409ac6d",
 "embed.mjs": "c26d0e40f42d53a51c116c9047d960e82da6fe6beb5eeb566711364972154d83",
 "frame.css": "27983b10f48e57d049be702814ae7cc47cea5c7e687c8b185f18257e4c1d8a38",
 "hub.html": "c70d16f0b7c3f93df8bf681560a0448eba840bb408c5ee2a5f5220d772ee4186",
 "hub.mjs": "03a1450de11d2528b5652215d90863037745c77be4218c2f37f0193218d7d102",
 "icons.mjs": "7e060128f35ead471be6a1940dc92ff551c52f181b551d7eb4f49e73777f460b",
 "index.html": "782470d3a270ca082e703c6e9846b9fab88a13866b53615b7d4ce3296c229d1a",
 "keys.html": "1939c572fc96989f0d85dab9495ab58e03e1f7d4279bf2b8b8329a10ccd33cb8",
 "keys.mjs": "70c3801c51e67427dbea852f7686d6b9e074e9fb3c0054135934ec9c6564fdd7",
 "letter.mjs": "55acd0e58bfd2612c957eb0b011f291b955ead584136f12304d9aa94ded4d84c",
 "mail.css": "1e9061777422a66403a60d011ce49fea01103b7bf9f22e8ae4676b6fa9f89a27",
 "mark.mjs": "e9dee155a0f2ce8aca5aebeef793de6f3badfb529447615529825a8b0b60ea97",
 "mime.mjs": "2669eb9343775add28dda1101cc4ec2d7e6c238bae33c9ea8ef87fd53b7f5835",
 "notices.mjs": "f65d87fe45605a7d16710964003f36cd571f5686b0c9149054aa672b57ce0783",
 "openpgp.min.mjs": "7d3285efa6dfedbb34a136d8b5ad21c28fb973269df0b2818dcb74dfb40b59d9",
 "reader.css": "97c0047b5d3ebab584181b9a756c1c231aa39dbacfd5d139e0fe5e81a898e7b7",
 "row.css": "f372764933bb9c7d8f7ac92a624ee2849397429d4c4b1eab07b94a12ef70b2a2",
 "row.html": "1c20365a92f3e856c687e50b661088b1dcde1ff6d4662bed28c5a6b6938e4865",
 "row.mjs": "c51ace7c4a897a7a950ade899ed491f073c678c9ddcc69f8c9725a50caab9439",
 "seal.mjs": "e4a07ce6c23006c791cd55b4626e117df06683a963eab1239dfd475645b983bf",
 "sealed-core.mjs": "751cda0c898ab62b88e8d907c6e8431222084656a3ec1e7c474f0a8092a92c52",
 "send.html": "7f91f2cae14487f1a45c23c38d868f57766682f719312952c0992f96e428f5ce",
 "send.mjs": "12fc6789cfcd7fa782ab642ab7acc7658454252c96e75342d50965dfff205087",
 "setup.html": "7035ac578ef7397e89cb6e827acc448a477981c9caa097b724a8291f4135f387",
 "setup.mjs": "c54c9e1700608f717b273aeb235d876ddeb7e861e7114d9345ea584bbac70393",
 "sites.mjs": "da735072fc0ca68478199a4a477358f6283792952d8d435f91e33b268d91c7ce",
 "store.mjs": "b8f920eb2e07abf8ed706d50ab8e8955cc6a23eae60e2d8bf19a8378b7e837c4",
 "tab.mjs": "6cb9413d6a36c53e8a50cb2332fb484fb8c84e2e66b79743510b4c8a253a4757",
 "title.html": "d86d47b2f8c4e4265fd4bc42354e542e6b65b914653cc1c851255385c31412c8",
 "title.mjs": "f1fa9f8cdefa820c69d69461e0f8d5594fd81de03d02b2d452641e1d23243556",
 "vault.mjs": "ada2cbf0d75d12c7caead15d6785c948ab3b38d65f5393814316458dbca74aed",
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
