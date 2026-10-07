// The page's side of the vault (sw.js): asking whether the key is open,
// opening it with the passkey, the one secret a message needs, locking.
// Where a browser runs no service worker here (a private window of Firefox,
// say), or "Each time" is chosen, the key stays in this page alone, and
// another page asks for the passkey again.

import {unseal} from './store.mjs';
import {markOf, markSecret, remember} from './mark.mjs';
import {alarmText, raised} from './alarm.mjs';

let worker = null, ready = null;
const page = new Map();  // keyId -> {key, info, signKey, signer}, when the vault is not used
const listeners = new Set();

// A newer Seal taking over (its service worker, after a publish) leaves the
// worker this page talked to gone, and the new one holds no key: the page
// starts over with it, and hears the vault is locked.
if ('serviceWorker' in navigator) navigator.serviceWorker.addEventListener('controllerchange', () => {
  worker = null;
  ready = null;
  for (const f of listeners) f(false);
});

function start() {
  return ready ||= (async () => {
    if (!('serviceWorker' in navigator)) return null;
    try {
      const reg = await navigator.serviceWorker.register('sw.js', {scope: './'});
      // A newly published reader (and its new pins) reaches this browser on
      // the next page, not a day later; the browser fetches sw.js past its cache.
      reg.update().catch(() => {});
      const active = reg.active || await new Promise((resolve, reject) => {
        const w = reg.installing || reg.waiting;
        if (!w) return reject(new Error('no worker'));
        w.addEventListener('statechange', () => { if (w.state === 'activated') resolve(reg.active || w); else if (w.state === 'redundant') reject(new Error('redundant')); });
        setTimeout(() => reject(new Error('slow')), 4000);
      });
      navigator.serviceWorker.addEventListener('message', e => {
        if (e.data?.type === 'vault-locked' || e.data?.type === 'vault-unlocked') for (const f of listeners) f(e.data.type === 'vault-unlocked');
      });
      navigator.serviceWorker.startMessages?.();
      return (worker = active);
    } catch (e) {
      return null;
    }
  })();
}

async function ask(message, transfer = []) {
  const w = worker || await start();
  if (!w) return null;
  return new Promise(resolve => {
    const channel = new MessageChannel();
    const late = setTimeout(() => resolve(null), 4000);
    channel.port1.onmessage = e => { clearTimeout(late); resolve(e.data); };
    try { w.postMessage(message, [channel.port2, ...transfer]); } catch (e) { clearTimeout(late); resolve(null); }
  });
}

// {unlocked, keyIds, marks}: what is open, in the vault or in this page.
export async function state() {
  let s = await ask({type: 'state'}) || {unlocked: false, keyIds: [], marks: {}, infos: {}};
  if (s.marks) remember(s.marks);
  // A page the worker did not serve from its checked copy may not use its
  // key (sw.js): for such a page only a key opened in it counts.
  if (s.served === false) s = {...s, unlocked: false, keyIds: [], infos: {}};
  const infos = {...(s.infos || {})}, signers = {...(s.signers || {})};
  for (const [id, k] of page) { infos[id] = k.info; if (k.signer) signers[id] = k.signer; }
  const keyIds = Object.keys(infos);
  return {...s, unlocked: keyIds.length > 0, keyIds, infos, signers, kept: !!s.unlocked};
}

// One touch of the passkey (and the PIN, if the key has one): the key goes
// into the vault for `minutes` without use (0: into this page only).
export async function unlock(records, pin, minutes) {
  if (await raised()) throw new Error(alarmText());  // before any passkey is asked
  const {record, pkcs8, signPkcs8} = await unseal(records, pin);
  await hold(record, pkcs8, minutes, signPkcs8);
  return record;
}

// A key just unsealed (its PKCS #8 bytes, wiped here) into the vault, or
// into this page; its mark is remembered in this browser.
// signPkcs8: the key that signs, where the record holds one (its signer
// names it); kept beside the key, and used only by Send (sw.js).
export async function hold(record, pkcs8, minutes, signPkcs8 = null) {
  const wipe = () => { new Uint8Array(pkcs8).fill(0); if (signPkcs8) new Uint8Array(signPkcs8).fill(0); };
  if (await raised()) { wipe(); throw new Error(alarmText()); }
  const signer = signPkcs8 && record.signer ? {keyId: record.signer.keyId, fingerprint: record.signer.fingerprint} : null;
  let keep = null;
  if (minutes > 0) {
    const copy = pkcs8.slice(0), signCopy = signer ? signPkcs8.slice(0) : null;  // moved to the vault, or wiped here
    keep = await ask({type: 'hold', minutes, keys: [{keyId: record.keyId, info: record.info, pkcs8: copy, ...(signer ? {sign: {...signer, pkcs8: signCopy}} : {})}]},
                     signCopy ? [copy, signCopy] : [copy]);
    if (copy.byteLength) new Uint8Array(copy).fill(0);
    if (signCopy?.byteLength) new Uint8Array(signCopy).fill(0);
  }
  try {
    // Kept in this page as well where the worker did not serve it.
    if (!keep?.keyIds?.includes(record.keyId) || keep.served === false || !navigator.serviceWorker?.controller) {
      const key = await crypto.subtle.importKey('pkcs8', pkcs8, {name: 'X25519'}, false, ['deriveBits']);
      const signKey = signer ? await crypto.subtle.importKey('pkcs8', signPkcs8, {name: 'Ed25519'}, false, ['sign']).catch(() => null) : null;
      const before = page.get(record.keyId);  // a key that signs held already stays when this record brings none
      page.set(record.keyId, {key, info: record.info, markSecret: await markSecret(key), peopleSecret: await peopleSecret(key),
                              ...(signKey ? {signKey, signer} : before?.signKey ? {signKey: before.signKey, signer: before.signer} : {})});
      remember({[record.keyId]: await markOf(key)});
    } else remember(keep.marks);
  } finally {
    wipe();
  }
  for (const f of listeners) f(true);
}

// The list of people you write to (contacts.mjs), sealed and opened under a
// key made from yours (sw.js, peopleKey), for Mail to keep for your other
// devices: {seal(bytes), open(bytes)} -> bytes, or null where that key is
// not open (or the bytes were not sealed with it).
const PEOPLE_TEXT = 'Seal people, version 1';
async function peopleSecret(key) {
  const point = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(PEOPLE_TEXT)));
  point[31] &= 0x7f;
  const peer = await crypto.subtle.importKey('raw', point, {name: 'X25519'}, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: peer}, key, 256));
}
export function peopleBox(keyId) {
  const ad = new TextEncoder().encode(PEOPLE_TEXT + '|' + keyId);
  const local = async () => {
    const here = page.get(keyId);
    if (!here) return null;
    if (!here.peopleKey) {
      const base = await crypto.subtle.importKey('raw', here.peopleSecret, 'HKDF', false, ['deriveKey']);
      here.peopleKey = await crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: ad}, base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
    }
    return here.peopleKey;
  };
  return {
    async seal(data) {
      const key = await local();
      if (!key) { const r = await ask({type: 'people-seal', keyId, data}); return r?.data instanceof Uint8Array ? r.data : null; }
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const sealed = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: ad}, key, data));
      const out = new Uint8Array(12 + sealed.length);
      out.set(iv);
      out.set(sealed, 12);
      return out;
    },
    async open(data) {
      const key = await local();
      if (!key) { const r = await ask({type: 'people-open', keyId, data}); return r?.data instanceof Uint8Array ? r.data : null; }
      try { return new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: data.subarray(0, 12), additionalData: ad}, key, data.subarray(12))); }
      catch (e) { return null; }
    },
  };
}

// Your signature on a message (sign.mjs: the data and the signature's
// hashed part), with the key that signs for the key keyId: the 64 bytes, or
// null. Only a signature on a message is made (as the worker makes it, for
// Send alone), never a certification.
async function messageDigest(data, hashed) {
  if (!(data instanceof Uint8Array) || !(hashed instanceof Uint8Array) || hashed.length < 6 || hashed.length > 1024 ||
      hashed[0] !== 4 || hashed[1] !== 0x00 || hashed[2] !== 22 || hashed[3] !== 10 || hashed.length !== 6 + (hashed[4] << 8 | hashed[5])) return null;
  const n = hashed.length, all = new Uint8Array(data.length + n + 6);
  all.set(data);
  all.set(hashed, data.length);
  all.set([4, 0xff, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255], data.length + n);
  return new Uint8Array(await crypto.subtle.digest('SHA-512', all));
}
export function signer(keyId) {
  return async (data, hashed) => {
    const here = page.get(keyId);
    if (here?.signKey) {
      const digest = await messageDigest(data, hashed);
      return digest ? new Uint8Array(await crypto.subtle.sign('Ed25519', here.signKey, digest)) : null;
    }
    const r = await ask({type: 'sign', keyId, data, hashed});
    return r?.signature instanceof Uint8Array ? r.signature : null;
  };
}

// The secret of one message for a key that is open: X25519 with the
// sender's ephemeral key. Null when that key is locked.
export function deriver(keyId) {
  return async ephemeral => {
    const here = page.get(keyId);
    if (here) {
      const peer = await crypto.subtle.importKey('raw', ephemeral, {name: 'X25519'}, false, []);
      const out = new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: peer}, here.key, 256));
      return out.every((b, i) => b === here.markSecret[i]) || out.every((b, i) => b === here.peopleSecret[i]) ? null : out;  // never the mark's secret, nor the people list's
    }
    const r = await ask({type: 'derive', keyId, ephemeral});
    return r?.bits ? new Uint8Array(r.bits) : null;
  };
}

export async function lock() {
  page.clear();
  await ask({type: 'lock'});
  for (const f of listeners) f(false);
}
// inner: done in the reader's own frames (Mail's own word counts for less, see sw.js).
export const used = (inner = false) => ask({type: 'use', inner});
// How far GitHub's clock is from this device's, in ms, or null (clock.mjs).
export const timeOffset = async () => { const r = await ask({type: 'time'}); return Number.isFinite(r?.offset) ? r.offset : null; };
export const seen = () => ask({type: 'seen'});
// Told when the key is locked or opened, here or in another page of the reader.
export const watch = f => { listeners.add(f); };
export const warm = () => start();
