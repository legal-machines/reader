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
// Every change is dated, and a key forgotten stays as a dated mark, so the
// list merges with the copy your other devices keep (sync, in the hub). A
// change here tells the hub. Dates only move forward, whatever the clock.
const DAY = 86400e3;
const changes = typeof BroadcastChannel === 'function' ? new BroadcastChannel('seal-people') : null;
const raw = address => run('readonly', s => s.get(address));
const get = async address => { const r = await raw(address); return r?.deleted ? undefined : r; };
const write = record => run('readwrite', s => s.put(record));
const put = async record => {
  const before = await raw(record.address);
  record.updated = Math.max(Date.now(), (before?.updated || 0) + 1);
  await write(record);
  changes?.postMessage({type: 'changed'});
};
export const all = async () => (await run('readonly', s => s.getAll())).filter(r => !r.deleted);
// A message whose domain's signature held when it was first opened stays
// checked (by the SHA-256 of the whole message): a domain withdraws old keys
// from DNS, and its older mail would otherwise fail later.
export const checkedOf = hash => run('readonly', s => s.get(hash), CHECKED).catch(() => undefined);
export const keepChecked = (hash, result) => run('readwrite', s => s.put({hash, ...result, at: new Date().toISOString()}), CHECKED).catch(() => {});
export const recordOf = address => get(String(address || '').toLowerCase()).catch(() => undefined);
export const remove = address => put({address: String(address).toLowerCase(), deleted: true});

// The whole list as it stands here, forgotten keys included, to seal for
// your other devices; and a list from them, merged in. Mail cannot read or
// change that list, but it can hand an older copy to a device that knows
// nothing yet, which would then pass it on as its own. So a key never
// takes another's place by a merge: only your own Use the new key does that,
// on any of your devices (accepted.by 'you', and the latest such choice
// stands). Any other key a merge brings waits beside the one known, as a
// new key from their mail would, for you to accept or decline. What else
// merges (checked, forgotten, a waiting key) goes by the newer record.
// Returns how many changed here.
export const snapshot = () => run('readonly', s => s.getAll());
const FPR = /^[0-9A-F]{40}$/;
const shaped = r => r && typeof r === 'object' && typeof r.address === 'string' && /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(r.address) && !OURS.test(r.address) &&
  Number.isFinite(r.updated) && r.updated > 0 && r.updated < Date.now() + DAY &&
  (r.deleted === true || (FPR.test(r.fingerprint) && typeof r.armored === 'string' && r.armored.length < 40000 &&
  (r.change == null || (FPR.test(r.change.fingerprint) && typeof r.change.armored === 'string' && r.change.armored.length < 40000)) &&
  (r.retired == null || Array.isArray(r.retired))));
// When the key became the one in use: learned first, or chosen by you.
const since = r => Number.isFinite(r.accepted?.at) ? r.accepted.at : 0;
const yours = r => r.accepted?.by === 'you' ? since(r) : 0;
// The keys you replaced with another (Use the new key): never offered again,
// by a merge or by an old message that carries one.
const retiredOf = r => Array.isArray(r?.retired) ? r.retired.filter(f => FPR.test(f)).slice(-20) : [];
const union = (a, b) => [...new Set([...retiredOf(a), ...retiredOf(b)])].slice(-20);
const live = r => ({address: r.address, fingerprint: r.fingerprint, armored: r.armored, first: String(r.first || ''), seen: String(r.seen || ''), retired: retiredOf(r),
                    checked: String(r.checked || ''), change: r.change ? {fingerprint: r.change.fingerprint, armored: r.change.armored, seen: String(r.change.seen || '')} : null,
                    accepted: {by: r.accepted?.by === 'you' ? 'you' : 'first', at: since(r)}, updated: r.updated});
export async function merge(list) {
  let changed = 0;
  for (const r of Array.isArray(list) ? list.slice(0, 2000) : []) {
    if (!shaped(r)) continue;
    const here = await raw(r.address);
    let next = null;
    if (!here) next = r.deleted ? {address: r.address, deleted: true, updated: r.updated} : live(r);
    else if (r.deleted || here.deleted) {
      // Forgotten, or known again: the newer stands, but a key comes back
      // only as it was (or as a key waiting, below, when another is known).
      if (r.updated > (here.updated || 0)) next = r.deleted ? {address: r.address, deleted: true, updated: r.updated} : live(r);
    } else if (retiredOf(here).includes(r.fingerprint)) {
      // A key you replaced here: it stays replaced; what you replaced
      // elsewhere is remembered too.
      const retired = union(here, r);
      if (retired.length !== retiredOf(here).length) next = {...here, retired, updated: Math.max(here.updated || 0, r.updated)};
    } else if (r.fingerprint === here.fingerprint) {
      // The same key: checked as the newer record says; a key waiting
      // beside it taken where none waits here.
      const t = {...here, retired: union(here, r)};
      if (r.updated > (here.updated || 0)) t.checked = String(r.checked || '');
      if (!t.change && r.change && r.change.fingerprint !== here.fingerprint && !t.retired.includes(r.change.fingerprint)) t.change = live(r).change;
      if (yours(r) > since(here)) t.accepted = {by: 'you', at: yours(r)};
      if (JSON.stringify(t) !== JSON.stringify(here)) next = {...t, updated: Math.max(here.updated || 0, r.updated)};
    } else if (yours(r) > since(here)) {
      // You chose that key on another device, after the key here came into
      // use (learned or chosen).
      const retired = [...new Set([...union(here, r), here.fingerprint])].filter(f => f !== r.fingerprint).slice(-20);
      next = {...live(r), first: here.first || String(r.first || ''), retired,
              change: r.change && r.change.fingerprint !== r.fingerprint && !retired.includes(r.change.fingerprint) ? live(r).change : null};
    } else if (retiredOf(r).includes(here.fingerprint)) {
      // You replaced the key here with another elsewhere, but chose it before
      // this key came into use here: it waits, as a new key would.
      if (!here.change) next = {...here, change: {fingerprint: r.fingerprint, armored: r.armored, seen: String(r.seen || '')}, updated: Math.max(here.updated || 0, r.updated)};
    } else if (!here.change) {
      // Another key, which you did not choose: it waits, as a new key would.
      next = {...here, change: {fingerprint: r.fingerprint, armored: r.armored, seen: String(r.seen || '')}, updated: Math.max(here.updated || 0, r.updated)};
    }
    if (next) { await write(next); changed++; }
  }
  if (changed) changes?.postMessage({type: 'merged'});  // for the list on screen; nothing to hand back
  return changed;
}

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
  if (!old) { await put({address, fingerprint, armored, first: now, seen: now, checked: '', change: null, accepted: {by: 'first', at: Date.now()}}); return 'new'; }
  if (old.fingerprint === fingerprint) { old.seen = now; await write(old); return 'same'; }  // seen again: no change to share
  if (retiredOf(old).includes(fingerprint)) return 'same';  // a key you replaced, in an old message: not offered again
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
  const retired = [...new Set([...retiredOf(c), c.fingerprint])].filter(f => f !== c.change.fingerprint).slice(-20);
  Object.assign(c, {fingerprint: c.change.fingerprint, armored: c.change.armored, seen: c.change.seen, checked: '', change: null, accepted: {by: 'you', at: Date.now()}, retired});
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
// Checked: only the key whose fingerprint you were shown (fingerprint), so
// a merge that lands meanwhile does not get the mark instead.
export async function check(address, on = true, fingerprint = '') {
  const c = await get(String(address).toLowerCase());
  if (!c || (on && c.fingerprint !== String(fingerprint).toUpperCase())) return false;
  c.checked = on ? new Date().toISOString() : '';
  await put(c);
  return true;
}
