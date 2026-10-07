// The key to encrypt to for one of our addresses whose key keys.mjs lists
// without the key itself (wkd: one person's key, whose address that file does
// not name): fetched from the Web Key Directory through wkd.html, the only
// page that reaches it, and taken only when it is that entry's key, by its
// fingerprint, with that address's user ID. Armored, or an error.
import {now} from './clock.mjs';

let ready = null, n = 0;
const pending = new Map(), cache = new Map();
function frame() {
  return ready ||= new Promise((ok, no) => {
    const f = document.createElement('iframe');
    f.src = 'wkd.html';
    f.hidden = true;
    f.tabIndex = -1;
    f.setAttribute('aria-hidden', 'true');
    addEventListener('message', e => {
      if (e.source !== f.contentWindow || e.origin !== location.origin) return;
      if (e.data?.type === 'wkd-ready') ok(f.contentWindow);
      else if (e.data?.type === 'wkd-answer') {
        const p = pending.get(e.data.id);
        if (!p) return;
        pending.delete(e.data.id);
        if (e.data.bytes instanceof Uint8Array) p.ok(e.data.bytes); else p.no(new Error('The key of one of our addresses could not be fetched: nothing was sent.'));
      }
    });
    document.body.append(f);
    setTimeout(() => no(new Error('The key of one of our addresses could not be fetched: nothing was sent.')), 10000);
  }).catch(e => { ready = null; throw e; });  // the next try makes the frame again
}
export async function armoredFor(openpgp, address, entry) {
  if (entry.armored) return entry.armored;
  address = String(address).toLowerCase();
  if (cache.has(entry.fingerprint + '|' + address)) return cache.get(entry.fingerprint + '|' + address);
  const w = await frame();
  const bytes = await new Promise((ok, no) => {
    const id = ++n;
    pending.set(id, {ok, no});
    w.postMessage({type: 'wkd-ask', id, address}, location.origin);
    setTimeout(() => { if (pending.delete(id)) no(new Error('The key of one of our addresses could not be fetched: nothing was sent.')); }, 15000);
  });
  const key = await openpgp.readKey({binaryKey: bytes});
  // Its encryption subkey, too: the one keys.mjs names (subkeys), so a key
  // with the right primary but another subkey bound to it is not taken.
  const sub = await key.getEncryptionKey(undefined, new Date(now())).catch(() => null);
  if (key.getFingerprint().toUpperCase() !== entry.fingerprint || !key.users.some(u => (u.userID?.email || '').toLowerCase() === address) ||
      !sub || !(entry.subkeys || []).includes(sub.getKeyID().toHex()))
    throw new Error('The key the directory gave for ' + address + ' is not the one published with Seal: nothing was sent.');
  const armored = key.armor();
  cache.set(entry.fingerprint + '|' + address, armored);
  return armored;
}
