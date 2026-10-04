// The reader's vault: a decryption key, opened by one touch of the passkey,
// kept in this worker's memory for a while, so that every encrypted message
// opens at once instead of asking for Touch ID each time. Nothing is written
// anywhere: the browser ends this worker, and the key with it, once no page
// of the reader has been open for about half a minute, and the rules below
// end it sooner. Only pages of this site can talk to it (the browser lets no
// other site reach it), and it has no fetch handler: it serves nothing.
//
// Pages never get the key back. They hand it over once (its PKCS #8 bytes,
// wiped on both sides), and then ask for the one shared secret a message
// needs (X25519 with the sender's ephemeral key, RFC 6637).

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

async function handle(d) {
  if (vault) check();
  switch (d.type) {
    case 'state':
      return state();
    case 'hold': {
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
      const held = vault?.keys.get(d.keyId);
      if (!held || !(d.ephemeral instanceof Uint8Array) || d.ephemeral.length !== 32) return {locked: !held};
      const p = await markPoint();
      if (d.ephemeral.every((b, i) => b === p[i])) return {};  // that secret is the mark's, not a message's
      const peer = await crypto.subtle.importKey('raw', d.ephemeral, {name: 'X25519'}, false, []);
      return {bits: await crypto.subtle.deriveBits({name: 'X25519', public: peer}, held.key, 256)};
    }
    case 'use':  // someone used Mail (a click, a key, a scroll); inner: in the reader's own frames
      if (vault) { vault.used = Date.now(); if (d.inner === true) vault.inner = vault.used; plan(); }
      return state();
    case 'seen':  // a page of Mail is in view
      if (vault) { vault.seen = Date.now(); plan(); }
      return state();
    case 'lock':
      lock('asked');
      return state();
  }
  return state();
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('message', e => {
  const reply = e.ports[0];
  e.waitUntil(handle(e.data || {}).then(r => reply?.postMessage(r), err => reply?.postMessage({error: String(err?.message || err)})));
});
