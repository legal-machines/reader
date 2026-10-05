// The page's side of the vault (sw.js): asking whether the key is open,
// opening it with the passkey, the one secret a message needs, locking.
// Where a browser runs no service worker here (a private window of Firefox,
// say), or "Each time" is chosen, the key stays in this page alone, and
// another page asks for the passkey again.

import {unseal} from './store.mjs';
import {markOf, markSecret, remember} from './mark.mjs';
import {alarmText, raised} from './alarm.mjs';

let worker = null, ready = null;
const page = new Map();  // keyId -> {key, info}, when the vault is not used
const listeners = new Set();

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
  const infos = {...(s.infos || {})};
  for (const [id, k] of page) infos[id] = k.info;
  const keyIds = Object.keys(infos);
  return {...s, unlocked: keyIds.length > 0, keyIds, infos, kept: !!s.unlocked};
}

// One touch of the passkey (and the PIN, if the key has one): the key goes
// into the vault for `minutes` without use (0: into this page only).
export async function unlock(records, pin, minutes) {
  if (await raised()) throw new Error(alarmText());  // before any passkey is asked
  const {record, pkcs8} = await unseal(records, pin);
  await hold(record, pkcs8, minutes);
  return record;
}

// A key just unsealed (its PKCS #8 bytes, wiped here) into the vault, or
// into this page; its mark is remembered in this browser.
export async function hold(record, pkcs8, minutes) {
  if (await raised()) { new Uint8Array(pkcs8).fill(0); throw new Error(alarmText()); }
  let keep = null;
  if (minutes > 0) {
    const copy = pkcs8.slice(0);  // moved to the vault, or wiped here
    keep = await ask({type: 'hold', minutes, keys: [{keyId: record.keyId, info: record.info, pkcs8: copy}]}, [copy]);
    if (copy.byteLength) new Uint8Array(copy).fill(0);
  }
  try {
    // Kept in this page as well where the worker did not serve it.
    if (!keep?.keyIds?.includes(record.keyId) || keep.served === false || !navigator.serviceWorker?.controller) {
      const key = await crypto.subtle.importKey('pkcs8', pkcs8, {name: 'X25519'}, false, ['deriveBits']);
      page.set(record.keyId, {key, info: record.info, markSecret: await markSecret(key)});
      remember({[record.keyId]: await markOf(key)});
    } else remember(keep.marks);
  } finally {
    new Uint8Array(pkcs8).fill(0);
  }
  for (const f of listeners) f(true);
}

// The secret of one message for a key that is open: X25519 with the
// sender's ephemeral key. Null when that key is locked.
export function deriver(keyId) {
  return async ephemeral => {
    const here = page.get(keyId);
    if (here) {
      const peer = await crypto.subtle.importKey('raw', ephemeral, {name: 'X25519'}, false, []);
      const out = new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: peer}, here.key, 256));
      return out.every((b, i) => b === here.markSecret[i]) ? null : out;  // never the mark's secret
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
export const seen = () => ask({type: 'seen'});
// Told when the key is locked or opened, here or in another page of the reader.
export const watch = f => { listeners.add(f); };
export const warm = () => start();
