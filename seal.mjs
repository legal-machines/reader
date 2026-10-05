// The sender's seal: proof, to each recipient, that a message was written
// with the sender's key. Encryption alone proves nothing about the sender
// (anyone can encrypt to a public key, the mail server too); the seal can be
// made only with the sender's private key and checked only with the
// recipient's: X25519 of the one's private key with the other's public key
// is the same secret on both sides (no one else can compute it), and an HMAC
// under it covers the whole message. It goes as one header line per
// recipient at the very start of the encrypted message:
//   X-Reader-Seal: v1; from=<sender's key ID>; to=<recipient's key ID>; tag=<HMAC>
// Other mail programs ignore it. Both keys are among those this reader
// carries (keys.mjs).

import {KEYS} from './keys.mjs';

const TEXT = 'Mail Reader seal, version 1', enc = new TextEncoder();  // a protocol label, kept from the old name: every seal is made with it

// keys.mjs knows our addresses only by their SHA-256 (lower case, hex): an
// address is hashed and looked up, never listed.
const hashed = new Map();
export function addressHash(address) {
  const a = String(address).toLowerCase();
  if (!hashed.has(a)) hashed.set(a, crypto.subtle.digest('SHA-256', enc.encode(a)).then(d => [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('')));
  return hashed.get(a);
}
// The key of one of our addresses, or undefined.
export async function keyOf(address) {
  const hash = await addressHash(address);
  return KEYS.find(k => k.hashes.includes(hash));
}
const b64u = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

// Key ID of an encryption subkey -> its X25519 public key, and the hashes of
// the addresses it serves and their domain.
let known = null;
export async function directory(openpgp) {
  if (known) return known;
  const out = {};
  for (const k of KEYS) {
    const key = await openpgp.readKey({armoredKey: k.armored});
    for (const sub of key.subkeys) {
      const p = sub.keyPacket;
      if (p.algorithm !== openpgp.enums.publicKey.ecdh || p.publicParams?.oid?.getName?.() !== 'curve25519Legacy') continue;
      const id = p.getKeyID().toHex();
      (out[id] ||= {pub: p.publicParams.Q.slice(1), hashes: [], domain: k.domain}).hashes.push(...k.hashes);
    }
  }
  return (known = out);
}

async function tagOf(shared, fromId, toId, digest) {
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const mac = await crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(`${TEXT}|${fromId}|${toId}`)},
                                            base, {name: 'HMAC', hash: 'SHA-256', length: 256}, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', mac, digest));
}

// The message (MIME text) with its seal lines in front. derive: X25519 of
// the sender's key with a public key (vault.mjs); toIds: the recipients' keys.
export async function seal(openpgp, inner, fromId, derive, toIds) {
  const dir = await directory(openpgp);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(inner)));
  let lines = '';
  for (const toId of [...new Set(toIds)]) {
    if (!dir[toId]) throw new Error('No key for one of the recipients.');
    const shared = await derive(dir[toId].pub);
    if (!shared) throw new Error('locked');
    lines += `X-Reader-Seal: v1; from=${fromId}; to=${toId}; tag=${b64u(await tagOf(shared, fromId, toId, digest))}\r\n`;
    shared.fill(0);
  }
  return lines + inner;
}

// The seal of an opened message, for the key that opened it (myId):
// {state: 'ok', hashes, domain} (written with the key of the addresses with
// those hashes, at that domain), 'bad' (a seal that does not hold), or
// 'none'; and the message without it.
export async function check(openpgp, bytes, myId, derive) {
  let at = 0, mine = null;
  const latin = n => String.fromCharCode(...bytes.subarray(at, Math.min(at + n, bytes.length)));
  while (latin(14) === 'X-Reader-Seal:') {
    let end = at;
    while (end < bytes.length && bytes[end] !== 10) end++;
    const line = String.fromCharCode(...bytes.subarray(at, end)).replace(/\r$/, '');
    const m = /^X-Reader-Seal: v1; from=([0-9a-f]{16}); to=([0-9a-f]{16}); tag=([A-Za-z0-9_-]{43})$/.exec(line);
    if (m && m[2] === myId) mine = {fromId: m[1], tag: unb64u(m[3])};
    at = end + 1;
  }
  const rest = bytes.subarray(at);
  if (!at) return {state: 'none', rest};
  if (!mine) return {state: 'none', rest};
  const sender = (await directory(openpgp))[mine.fromId];
  if (!sender) return {state: 'bad', rest};
  const shared = await derive(sender.pub);
  if (!shared) return {state: 'none', rest};
  const tag = await tagOf(shared, mine.fromId, myId, new Uint8Array(await crypto.subtle.digest('SHA-256', rest)));
  shared.fill(0);
  let same = tag.length === mine.tag.length ? 0 : 1;
  for (let i = 0; i < tag.length && i < mine.tag.length; i++) same |= tag[i] ^ mine.tag[i];
  return {state: same ? 'bad' : 'ok', hashes: sender.hashes, domain: sender.domain, rest};
}
