// The keys of people outside our mailboxes, learned from mail they send
// with them (the Autocrypt header, or a key attached): Seal keeps the first
// key it sees for an address and encrypts to it from then on. A different
// key later is kept beside it as a change and used only once you accept it
// (setup.html), so a mail server that slips in a key of its own after the
// first message is caught. Checked: you compared the fingerprint with the
// person through a channel other than this mail. Our own addresses never come
// from here, only from keys.mjs. Kept in this site's IndexedDB, in this browser.
import {keyOf} from './seal.mjs';

const DB = 'seal-contacts', STORE = 'keys', CHECKED = 'checked';
const OURS = /@(?:[a-z0-9-]+\.)*(?:legalmachines\.org|dzyza\.com)$/;  // our domains and any name under them

function db() {
  return new Promise((ok, no) => {
    const r = indexedDB.open(DB, 2);
    r.onupgradeneeded = () => {
      if (!r.result.objectStoreNames.contains(STORE)) r.result.createObjectStore(STORE, {keyPath: 'address'});
      if (!r.result.objectStoreNames.contains(CHECKED)) r.result.createObjectStore(CHECKED, {keyPath: 'hash'});
    };
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });
}
async function run(mode, work, store = STORE) {
  const d = await db();
  return new Promise((ok, no) => {
    const t = d.transaction(store, mode), result = work(t.objectStore(store));
    t.oncomplete = () => { d.close(); ok(result.result); };
    t.onerror = () => { d.close(); no(t.error); };
  });
}
const get = address => run('readonly', s => s.get(address));
const put = record => run('readwrite', s => s.put(record));
export const all = () => run('readonly', s => s.getAll());
// A message whose domain's signature held when it was first opened stays
// checked (by the SHA-256 of the whole message): a domain withdraws old keys
// from DNS, and its older mail would otherwise fail later.
export const checkedOf = hash => run('readonly', s => s.get(hash), CHECKED).catch(() => undefined);
export const keepChecked = (hash, result) => run('readwrite', s => s.put({hash, ...result, at: new Date().toISOString()}), CHECKED).catch(() => {});
export const recordOf = address => get(String(address || '').toLowerCase()).catch(() => undefined);
export const remove = address => run('readwrite', s => s.delete(String(address).toLowerCase()));

// A key from a message of this address, as bytes or armored text. Returns
// 'new', 'same', 'changed' or '' (not a usable key of that address).
export async function learn(openpgp, address, data) {
  address = String(address || '').toLowerCase();
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(address) || OURS.test(address) || await keyOf(address)) return '';
  let key;
  try {
    key = typeof data === 'string' ? await openpgp.readKey({armoredKey: data}) : await openpgp.readKey({binaryKey: data});
    if (key.isPrivate()) return '';
    if (!key.users.some(u => (u.userID?.email || '').toLowerCase() === address)) return '';
    await key.getEncryptionKey();  // throws when it has none that works (expired, revoked)
  } catch (e) {
    return '';
  }
  const fingerprint = key.getFingerprint().toUpperCase(), armored = key.armor(), now = new Date().toISOString();
  const old = await get(address);
  if (!old) { await put({address, fingerprint, armored, first: now, seen: now, checked: '', change: null}); return 'new'; }
  if (old.fingerprint === fingerprint) { old.seen = now; await put(old); return 'same'; }
  // The first new key waits, and no later one takes its place: the one you
  // check with them is the one you accept.
  if (!old.change) { old.change = {fingerprint, armored, seen: now}; await put(old); }
  return 'changed';
}

// The key to encrypt to for an address: ours (keys.mjs) or a contact's.
// {armored, internal, subkeys} | {armored, contact} | {changed: record} | null
export async function keyFor(address) {
  address = String(address || '').toLowerCase();
  const ours = await keyOf(address);
  if (ours) return {armored: ours.armored, internal: true, subkeys: ours.subkeys};
  if (OURS.test(address)) return null;
  const c = await get(address).catch(() => null);
  if (!c) return null;
  if (c.change) return {changed: c};
  return {armored: c.armored, contact: c};
}

// You accept a changed key (after making sure it is theirs), by the
// fingerprint you were shown; or mark the current one checked.
export async function acceptChange(address, fingerprint) {
  const c = await get(String(address).toLowerCase());
  if (!c?.change || c.change.fingerprint !== String(fingerprint || '').toUpperCase()) return false;
  Object.assign(c, {fingerprint: c.change.fingerprint, armored: c.change.armored, seen: c.change.seen, checked: '', change: null});
  await put(c);
  return true;
}
// You decline a new key: the one Seal knew stays.
export async function declineChange(address) {
  const c = await get(String(address).toLowerCase());
  if (!c?.change) return;
  c.change = null;
  await put(c);
}
export async function check(address, on = true) {
  const c = await get(String(address).toLowerCase());
  if (!c) return;
  c.checked = on ? new Date().toISOString() : '';
  await put(c);
}
