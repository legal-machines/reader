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
 "check.html": "7400dac7b364ccb9af054f71aec7abdec3dc1d731eba3303db76121e3e2e4525",
 "check.mjs": "c581bdf6a7fa24adace6e7713b3c0582070be91fabf35ffbf031efab00f03adb",
 "clock.mjs": "021d30ce152e6b64264ba59c0a126b42550c2640f2b823fecb8a9c9928644623",
 "compose.html": "af86e0834cee3319214b6c2bafd530da6e2ee243b0f4b98f7a4f68aba993661c",
 "compose.mjs": "62ebf28f51517709674a46c2ca798f7d5b26ae1fd25328542cb5fa368dfb59d7",
 "contacts.mjs": "009a50c543d8c2faa672d2d09ab10185cb116869e9ff6dfb591da2900f0b463e",
 "decrypt.mjs": "c14ecce18662c71fab10b96a0207a8c5579ac9d84da0256e31f8898bb8659e3d",
 "dkim.mjs": "73795ba28249d7a16ff91ea8582f86260088bbd45ec43c2beabb5232a25d3296",
 "dns.html": "f27a9bd26722cf61cb005e25ae821f4084d9139a9d48f386e31e0ed945e468db",
 "dns.mjs": "76eace4737be7affc11d0fbd672090b2c78180d448887104b6accac9b07f2691",
 "embed.mjs": "c3a22673978b337cc1fe97984ad457c4d92fcb6fd3ea5fcef68809a4c0146390",
 "frame.css": "95f5021cdf3ae30b5e472da3c781fc9c4e1b1b4ec6955920e680ae837ffa71c1",
 "hub.html": "c3b901d2a13752d85d327c3e3599aaca0cc801d307e634626a1eb0c3ef3af857",
 "hub.mjs": "efdac07644c6b1fd74e43ea9944e6fdbf3dee4e39ebf75e38c2bf07330ba740f",
 "icons.mjs": "58b17ff7905e30859040cc0b77b6c2fa02eb7a9a1c4e7ae5882cf44865428961",
 "index.html": "44c66a63f204f2116bf6dcbe5105462ae50ed5abf592b6c2772d3d31111e0326",
 "keys.html": "c5665954faf900dfee71861eb0dd4ca6584d9057bcc5cfc68af6e03d56cb787d",
 "keys.mjs": "6c80de78fb6e27f60c15ef6dd9cf29a28d58d8c07c13775d7d14a0a9c35400ea",
 "letter.mjs": "269f3868371ec27c485bff8a389b0e9d42b5e8aef59b7d8a5c89bc1fe3622f9c",
 "mail.css": "01869d3c2d4837a2c004948a01f4d25d320f05ee40b05e2a5a72342ce78139de",
 "mark.mjs": "4ba98ea35bc9eb30f2e1a75a2f93c7fba305d77ceec42bcf3ec150efba719151",
 "marks.mjs": "54fc92d4e354f04ea0b3f406141d6a0d28cec93626d3e65aafc90069db6624ca",
 "mime.mjs": "b9e2d609aa6d81c5e127cd6c42e417e3582f65a126ba14b0a440f479fc022185",
 "notices.mjs": "f65d87fe45605a7d16710964003f36cd571f5686b0c9149054aa672b57ce0783",
 "openpgp.min.mjs": "7d3285efa6dfedbb34a136d8b5ad21c28fb973269df0b2818dcb74dfb40b59d9",
 "people.html": "a522def3eff493bee85e36ea4ee64c7d2ad434d87f0cf903aa49f9d68857544f",
 "people.mjs": "1c6d190ee531a3caf35f9bd8710f8913a9361cf39d8bd4b2946614ba37550cd3",
 "reader.css": "fe70e1f06aac2b4cd73fbc8d01a866fa58dc02e2ecec405c2b2aeea7e23776ca",
 "row.css": "f372764933bb9c7d8f7ac92a624ee2849397429d4c4b1eab07b94a12ef70b2a2",
 "row.html": "1c20365a92f3e856c687e50b661088b1dcde1ff6d4662bed28c5a6b6938e4865",
 "row.mjs": "c51ace7c4a897a7a950ade899ed491f073c678c9ddcc69f8c9725a50caab9439",
 "seal.mjs": "899767c2277b4e3441bf43b54d1df97b0da4ce8ca14afe051b158144bf8e4f60",
 "sealed-core.mjs": "d69446a3d69df9f2cc2a0fab3e774213497d61ab3a84abbce84e33273f1a5dd1",
 "send.html": "5855758efa4d1366293e71b8e99db05657a0465d1388a8ddb7af477a688bd740",
 "send.mjs": "2f70de82594c8bbb8f7629faf2fc22b5866982b477ccecd2bc806b0f13a1095c",
 "setup.html": "60d8e89082e079c7a4bbcc92763d7a479ea52b96eff450446f9f517d1ca5a9b1",
 "setup.mjs": "44cef3bd1da8634f3c4d7129f4d5df6da21bc261b0c2c9ab8b23da62b67b4c0c",
 "sign.mjs": "aad05ddc4d2559811fd3e17ef34fdad3fe1f9dd5abc2d08786ed2f0b58bbf146",
 "sites.mjs": "da735072fc0ca68478199a4a477358f6283792952d8d435f91e33b268d91c7ce",
 "store.mjs": "6855c1b44e73d736ddac6753d4baf73973911adb20122292d9959342a4f90c1e",
 "tab.mjs": "6cb9413d6a36c53e8a50cb2332fb484fb8c84e2e66b79743510b4c8a253a4757",
 "title.html": "d86d47b2f8c4e4265fd4bc42354e542e6b65b914653cc1c851255385c31412c8",
 "title.mjs": "f1fa9f8cdefa820c69d69461e0f8d5594fd81de03d02b2d452641e1d23243556",
 "vault.mjs": "8e43f034a77f40b643ce41af3ca7c607f3733c16e6a7e4ce97d9381f03a5add1",
 "width.mjs": "3f46932569c028cb5815c12c59abf01858e10817dce65d384d4ce43ce29aede8",
 "wkd-frame.mjs": "dc314f95d044e365c0a4b8caa1924401cbea220703963442b36db94a3cc09bee",
 "wkd.html": "7f08d88a5e1bad9907f44e8c3883e9eddc01e68b986d8cc4b0c5804e7fa7d862",
 "wkd.mjs": "8226d3c8b1cf23c7cb5c34a30f6e7e9b6bc9a0d7a65da308f3871d0dc4790a8d"
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

let vault = null;  // {keys: Map(keyId -> {key, mark, info, signKey, signer}), since, used, inner, seen, idle}
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
     signers: Object.fromEntries([...vault.keys].filter(([, k]) => k.signer).map(([id, k]) => [id, k.signer])),
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
// The key the list of people you write to is sealed with: X25519 of your
// key with a point of its own (as the mark's), through HKDF, so every device
// with your key makes the same, and no message can lead derive to it (derive
// refuses nothing else, but the secret it gives never leaves sealed-core).
const PEOPLE_TEXT = 'Seal people, version 1';
async function peopleSecret(key) {
  const point = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(PEOPLE_TEXT)));
  point[31] &= 0x7f;
  const peer = await crypto.subtle.importKey('raw', point, {name: 'X25519'}, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: peer}, key, 256));
}
async function peopleKey(shared, keyId) {
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(PEOPLE_TEXT + '|' + keyId)},
                                 base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
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
        const s = k.sign;
        try {
          const key = await crypto.subtle.importKey('pkcs8', k.pkcs8, {name: 'X25519'}, false, ['deriveBits']);
          // The key that signs, where there is one: only Send may use it.
          let signKey = null, signer = null;
          if (s && s.pkcs8 instanceof ArrayBuffer && /^[0-9a-f]{16}$/.test(s.keyId) && /^[0-9a-f]{40}$/.test(s.fingerprint) && s.fingerprint.endsWith(s.keyId)) {
            signKey = await crypto.subtle.importKey('pkcs8', s.pkcs8, {name: 'Ed25519'}, false, ['sign']).catch(() => null);
            if (signKey) signer = {keyId: s.keyId, fingerprint: s.fingerprint};
          }
          // A key that signs held already stays when this record brings none.
          const before = keys.get(k.keyId);
          keys.set(k.keyId, {key, mark: await markOf(key), markSecret: await markSecret(key), peopleSecret: await peopleSecret(key), info: {fingerprint: info.fingerprint, keyId: info.keyId, hash: info.hash, cipher: info.cipher},
                             ...(signKey ? {signKey, signer} : before?.signKey ? {signKey: before.signKey, signer: before.signer} : {})});
        } finally {
          new Uint8Array(k.pkcs8).fill(0);
          if (s?.pkcs8 instanceof ArrayBuffer) new Uint8Array(s.pkcs8).fill(0);
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
      if (held.peopleSecret && out.every((b, i) => b === held.peopleSecret[i])) return {};  // nor the people list's
      return {bits};
    }
    case 'sign': {
      // Your signature on a message, for Send alone (send.html, a page this
      // worker served): no other page of the reader signs anything.
      if (!await served(from) || !await isPage(from, 'send.html')) return {foreign: true};
      // Only a signature on a message (type 0x00, EdDSA, SHA-512): the digest
      // is made here from what is signed, so nothing else (a certification,
      // a revocation) can be had from this key.
      const held = vault?.keys.get(d.keyId);
      if (!held?.signKey) return {locked: !held};
      const digest = await messageDigest(d.data, d.hashed);
      if (!digest) return {};
      return {signature: new Uint8Array(await crypto.subtle.sign('Ed25519', held.signKey, digest))};
    }
    case 'people-seal': case 'people-open': {
      // The list of people you write to (contacts.mjs), sealed for Mail to
      // keep for your other devices, under a key made from yours: Mail and
      // its server cannot read it nor change it. For the reader's own pages.
      if (!await served(from)) return {foreign: true};
      const held = vault?.keys.get(d.keyId);
      if (!held || !(d.data instanceof Uint8Array) || d.data.length > 4e6) return {locked: !held};
      held.peopleKey ||= await peopleKey(held.peopleSecret, d.keyId);
      try {
        if (d.type === 'people-seal') {
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const sealed = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(PEOPLE_TEXT + '|' + d.keyId)}, held.peopleKey, d.data));
          const out = new Uint8Array(12 + sealed.length);
          out.set(iv);
          out.set(sealed, 12);
          return {data: out};
        }
        return {data: new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: d.data.subarray(0, 12), additionalData: new TextEncoder().encode(PEOPLE_TEXT + '|' + d.keyId)}, held.peopleKey, d.data.subarray(12)))};
      } catch (e) {
        return {bad: true};
      }
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
    case 'time': {
      // GitHub's clock (clock.mjs): the Date of a response fetched past every
      // cache, against this device's clock halfway through the fetch.
      try {
        const t0 = Date.now();
        const r = await fetch('/CNAME?time=' + Math.random().toString(36).slice(2), {cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout(3000)});
        const t1 = Date.now(), at = Date.parse(r.headers.get('Date') || '');
        return {offset: Number.isFinite(at) ? at + 500 - (t0 + t1) / 2 : null};
      } catch (e) {
        return {offset: null};
      }
    }
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
// The digest of a binary-document signature (RFC 9580, 5.2.4) over data,
// with its hashed part (version 4, type 0x00, EdDSA, SHA-512), or null.
async function messageDigest(data, hashed) {
  if (!(data instanceof Uint8Array) || !(hashed instanceof Uint8Array) || data.length > 40e6 || hashed.length < 6 || hashed.length > 1024 ||
      hashed[0] !== 4 || hashed[1] !== 0x00 || hashed[2] !== 22 || hashed[3] !== 10 || hashed.length !== 6 + (hashed[4] << 8 | hashed[5])) return null;
  const n = hashed.length, all = new Uint8Array(data.length + n + 6);
  all.set(data);
  all.set(hashed, data.length);
  all.set([4, 0xff, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255], data.length + n);
  return new Uint8Array(await crypto.subtle.digest('SHA-512', all));
}
const served = async id => !!id && (await self.clients.matchAll({type: 'window'})).some(c => c.id === id);
const isPage = async (id, name) => (await self.clients.matchAll({type: 'window'})).some(c => c.id === id && new URL(c.url).pathname.endsWith('/' + name));
self.addEventListener('message', e => {
  const reply = e.ports[0];
  e.waitUntil(handle(e.data || {}, e.source?.id).then(r => reply?.postMessage(r), err => reply?.postMessage({error: String(err?.message || err)})));
});
