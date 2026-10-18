// Link a device: your key, from a device that holds it (a trusted phone) to
// a new one of yours, with no code to type. The new device's Seal makes a
// key pair for this once (X25519, held in its tab's memory, never stored)
// and shows its public half in a QR code with a channel name; the trusted
// device reads the code with its camera, opens your key with a touch of its
// passkey and encrypts it to that public half (X25519, HKDF-SHA-256,
// AES-GCM, bound to the channel and both public halves). The Mail app
// carries what comes out, for that mailbox alone, and cannot open it: the
// public half it would need travelled only through the camera.
//
// What the new device takes from it, it checks: only a key published for
// one of our mailboxes (keys.mjs), the private half matching the public one
// there (setup.mjs, fromLink).

const enc = new TextEncoder();
const INFO = 'seal-link v1';
export const b64u = bytes => { let t = ''; for (let i = 0; i < bytes.length; i += 0x8000) t += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(t).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
export const unb64u = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

// The new device's side: a key pair and a channel, and the code's text.
export async function newOffer() {
  const pair = await crypto.subtle.generateKey({name: 'X25519'}, false, ['deriveBits']);
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const channel = b64u(crypto.getRandomValues(new Uint8Array(16)));
  return {channel, pub, priv: pair.privateKey, text: `SEAL1.${channel}.${b64u(pub)}`};
}

// The code as a new device shows it: an address of this site's link page with
// the offer after the #, so that a phone's own camera opens Seal there by
// itself (the fragment reaches no server).
export const offerUrl = (offer, origin) => `${origin}/link.html#${offer.text}`;

// A code's text as the trusted device reads it, or null for anything else:
// the offer itself, or an address of a link page that carries it.
export function readOffer(text) {
  let t = String(text).trim();
  if (/^https?:\/\//i.test(t)) {
    try {
      const u = new URL(t);
      if (u.pathname !== '/link.html') return null;
      t = u.hash.slice(1);
    } catch (e) {
      return null;
    }
  }
  const m = /^SEAL1\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/.exec(t);
  if (!m) return null;
  const pub = unb64u(m[2]);
  return unb64u(m[1]).length === 16 && pub.length === 32 ? {channel: m[1], pub} : null;
}

async function boxKey(shared, channel, newPub, oldPub) {
  // A shared secret of all zeros means a public half of low order: refused.
  if (shared.every(b => b === 0)) throw new Error('That code cannot be used.');
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  shared.fill(0);
  return crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: unb64u(channel), info: concat(enc.encode(INFO), newPub, oldPub)},
                                 base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
}
const aad = channel => ({additionalData: enc.encode(`${INFO}|${channel}`)});

// The trusted device's side: what it sends for the offer read from the code.
export async function sealFor(offer, plain) {
  const mine = await crypto.subtle.generateKey({name: 'X25519'}, false, ['deriveBits']);
  const myPub = new Uint8Array(await crypto.subtle.exportKey('raw', mine.publicKey));
  const theirs = await crypto.subtle.importKey('raw', offer.pub, {name: 'X25519'}, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: theirs}, mine.privateKey, 256));
  const key = await boxKey(shared, offer.channel, offer.pub, myPub);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv, ...aad(offer.channel)}, key, plain));
  return JSON.stringify({v: 1, pub: b64u(myPub), iv: b64u(iv), sealed: b64u(sealed)});
}

// The new device's side: what came back over its channel, opened, or an error.
export async function openFrom(offer, text) {
  let d;
  try { d = JSON.parse(text); } catch (e) { d = null; }
  if (!(d?.v === 1 && typeof d.pub === 'string' && typeof d.iv === 'string' && typeof d.sealed === 'string' && d.sealed.length < 20000))
    throw new Error('What came is not a key from your other device.');
  const theirPub = unb64u(d.pub), iv = unb64u(d.iv);
  if (theirPub.length !== 32 || iv.length !== 12) throw new Error('What came is not a key from your other device.');
  const theirs = await crypto.subtle.importKey('raw', theirPub, {name: 'X25519'}, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: theirs}, offer.priv, 256));
  const key = await boxKey(shared, offer.channel, offer.pub, theirPub);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv, ...aad(offer.channel)}, key, unb64u(d.sealed)));
  } catch (e) {
    throw new Error('What came does not open with this code: scan the code shown here again.');
  }
}

// What travels: the key's two private parts as their 32 bytes, and what
// describes them (the record's info, key ID, addresses and key that signs).
export function packKey(record, pkcs8, signPkcs8) {
  const scalar = new Uint8Array(pkcs8).slice(-32), seed = signPkcs8 ? new Uint8Array(signPkcs8).slice(-32) : null;
  const plain = enc.encode(JSON.stringify({v: 1, keyId: record.keyId, info: record.info, addresses: record.addresses,
    scalar: b64u(scalar), signer: seed && record.signer ? record.signer : null, seed: seed && record.signer ? b64u(seed) : null}));
  scalar.fill(0);
  seed?.fill(0);
  return plain;
}
export function unpackKey(plain) {
  let d;
  try { d = JSON.parse(new TextDecoder().decode(plain)); } catch (e) { d = null; }
  plain.fill(0);
  const ok = d?.v === 1 && /^[0-9a-f]{16}$/.test(d.keyId) && d.info && d.info.keyId === d.keyId && /^[0-9a-f]{40}$/.test(d.info.fingerprint) &&
    Number.isInteger(d.info.hash) && Number.isInteger(d.info.cipher) && Array.isArray(d.addresses) && d.addresses.length >= 1 && d.addresses.length <= 8 &&
    d.addresses.every(a => typeof a === 'string' && a.length <= 254) && typeof d.scalar === 'string' &&
    (d.seed === null || (typeof d.seed === 'string' && d.signer && /^[0-9a-f]{16}$/.test(d.signer.keyId) && /^[0-9a-f]{40}$/.test(d.signer.fingerprint)));
  if (!ok) throw new Error('What came is not a key from your other device.');
  const scalar = unb64u(d.scalar), seed = d.seed ? unb64u(d.seed) : null;
  if (scalar.length !== 32 || (seed && seed.length !== 32)) throw new Error('What came is not a key from your other device.');
  return {keyId: d.keyId, info: d.info, addresses: d.addresses.map(a => a.toLowerCase()), scalar, signer: seed ? d.signer : null, seed};
}
