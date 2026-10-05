// Your mark: four pictures that only the real reader can show. They are made
// from your key (X25519 of the key with a fixed point, see sw.js), so they
// are the same on every device that holds it, and neither Mail nor its
// server, which have only the public key, can work them out. The reader shows
// them with every message it opens and while you write end to end; a page
// that only looks like the reader cannot.
//
// A browser keeps the marks it has seen (this site's storage, which Mail
// cannot read), so the mark can show before the key is opened.

export const PICTURES = [
  '🐶', '🐱', '🦊', '🐻', '🐼', '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🐧', '🦉', '🐝', '🦋',
  '🐌', '🐞', '🐢', '🐙', '🐬', '🐳', '🦀', '🐘', '🐫', '🦄', '🐰', '🐭', '🌵', '🌻', '🌲', '🍄',
  '🍎', '🍋', '🍉', '🍇', '🍓', '🍒', '🍌', '🥕', '🌽', '🍕', '🍩', '🍪', '⚓', '🎈', '🎸', '🎻',
  '🥁', '⏰', '🚲', '🚀', '⛵', '🏠', '🎩', '👑', '💎', '🔔', '📚', '🎲', '🌙', '⭐', '🌈', '⚡'];

const TEXT = 'Mail Reader mark, version 1';  // a protocol label, kept from the old name: the marks come from it
const STORE = 'mail-reader-marks', SEEN = 'mail-reader-mark-explained';

const load = name => { try { return JSON.parse(localStorage.getItem(name) || '{}') || {}; } catch (e) { return {}; } };
const save = (name, value) => { try { localStorage.setItem(name, JSON.stringify(value)); } catch (e) {} };

const valid = m => Array.isArray(m) && m.length === 4 && m.every(n => Number.isInteger(n) && n >= 0 && n < 64);

// The mark as text, or '' for none.
export const text = indices => valid(indices) ? indices.map(i => PICTURES[i]).join(' ') : '';
// Its four pictures, one box each: the gaps between them are the chip's own,
// whatever width the emoji font gives a space.
export const pictures = indices => valid(indices) ? indices.map(i => `<span>${PICTURES[i]}</span>`).join('') : '';

// The marks this browser knows, by key ID.
export const known = () => load(STORE);
export function remember(marks) {
  const all = load(STORE);
  let changed = false;
  for (const [id, m] of Object.entries(marks || {})) {
    if (/^[0-9a-f]{16}$/.test(id) && valid(m) && String(all[id]) !== String(m)) { all[id] = m; changed = true; }
  }
  if (changed) save(STORE, all);
}
// The mark of the first of these keys that has one here.
export function markFor(keyIds) {
  const all = load(STORE);
  for (const id of keyIds || []) if (valid(all[id])) return {keyId: id, mark: all[id]};
  return null;
}
// Whether the reader has explained the mark in this browser.
export const explained = keyId => !!load(SEEN)[keyId];
export const setExplained = keyId => { const all = load(SEEN); all[keyId] = 1; save(SEEN, all); };

// X25519 of a key held in this page with the mark's point: the secret the
// mark comes from, which no derive may hand out (vault.mjs; sw.js the same).
export async function markSecret(privateKey) {
  const point = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(TEXT)));
  point[31] &= 0x7f;
  const peer = await crypto.subtle.importKey('raw', point, {name: 'X25519'}, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: peer}, privateKey, 256));
}

// The mark of a key held in this page (see sw.js for the same in the vault).
export async function markOf(privateKey) {
  const enc = new TextEncoder();
  const point = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(TEXT)));
  point[31] &= 0x7f;
  const peer = await crypto.subtle.importKey('raw', point, {name: 'X25519'}, false, []);
  const shared = await crypto.subtle.deriveBits({name: 'X25519', public: peer}, privateKey, 256);
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(TEXT)}, base, 32));
  return [bits[0] >> 2, ((bits[0] & 3) << 4) | (bits[1] >> 4), ((bits[1] & 15) << 2) | (bits[2] >> 6), bits[2] & 63];
}

// The square that shows it: the four pictures in two rows.
export const tile = (indices, extra = '') => valid(indices)
  ? `<span class="mark-tile"${extra} role="img" aria-label="Your Seal mark: ${text(indices)}">${pictures(indices)}</span>` : '';
