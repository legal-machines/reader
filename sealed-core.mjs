// The cryptography of the Sealed Reader: opening an OpenPGP message with a
// Curve25519 (cv25519) decryption key that lives in WebCrypto as a
// non-extractable X25519 key. Nothing here can read the key back out: the
// browser only lets it compute a shared secret. The rest of OpenPGP (packet
// parsing, AES, the integrity check) is OpenPGP.js, given the session key.
//
// RFC 6637 (ECDH in OpenPGP) and RFC 9580, section 11.5: the sender's
// ephemeral key and ours give a shared secret Z; SHA-256(00000001 || Z ||
// params) is the key that wraps the session key (AES Key Wrap, RFC 3394).

const CURVE25519_OID = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);
const ANONYMOUS_SENDER = new TextEncoder().encode('Anonymous Sender    ');
const KEY_BYTES = {7: 16, 8: 24, 9: 32};  // AES-128, AES-192, AES-256
const PKCS8_X25519 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const PKCS8_ED25519 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

// The private key as WebCrypto wants it (PKCS #8), from the 32-byte scalar in
// RFC 7748 order.
export const pkcs8Of = scalar => concat(PKCS8_X25519, scalar);

// What is kept of a decryption key: everything needed to rebuild the wrapping
// key's parameters, but no secret.
export const describe = (fingerprint, keyId, hash, cipher) => ({fingerprint: hex(fingerprint), keyId, hash, cipher});

// The session key of a message encrypted to this key, or null. derive gives
// X25519 of the key with a sender's ephemeral key (vault.mjs): the key itself
// never comes here.
export async function sessionKey(openpgp, message, derive, info) {
  const fingerprint = Uint8Array.from(info.fingerprint.match(/../g).map(h => parseInt(h, 16)));
  const params = concat(new Uint8Array([CURVE25519_OID.length]), CURVE25519_OID, new Uint8Array([18, 3, 1, info.hash, info.cipher]), ANONYMOUS_SENDER, fingerprint);
  for (const p of message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey)) {
    if (p.publicKeyAlgorithm !== openpgp.enums.publicKey.ecdh) continue;
    const id = p.publicKeyID.toHex();
    if (id !== '0000000000000000' && id !== info.keyId) continue;
    const ephemeral = p.encrypted.V;
    if (!ephemeral || ephemeral.length !== 33 || ephemeral[0] !== 0x40) continue;
    const shared = await derive(ephemeral.slice(1));
    if (!shared) throw new Error('locked');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', concat(new Uint8Array([0, 0, 0, 1]), shared, params)));
    shared.fill(0);
    const length = KEY_BYTES[info.cipher];
    if (!length) continue;
    const kek = await crypto.subtle.importKey('raw', digest.slice(0, length), 'AES-KW', false, ['unwrapKey']);
    digest.fill(0);
    const wrapped = p.encrypted.C.data;
    let m;
    try {
      // AES-KW can only unwrap into a key: an HMAC key of the right length
      // carries the bytes out (they are the session key, for this message only).
      const holder = await crypto.subtle.unwrapKey('raw', wrapped, kek, 'AES-KW', {name: 'HMAC', hash: 'SHA-256', length: (wrapped.length - 8) * 8}, true, ['sign']);
      m = new Uint8Array(await crypto.subtle.exportKey('raw', holder));
    } catch (e) {
      continue;  // not for this key
    }
    const pad = m[m.length - 1];
    if (pad < 1 || pad > 8) continue;
    const body = m.slice(0, m.length - pad);
    const algorithm = body[0], key = body.slice(1, body.length - 2);
    const sum = key.reduce((s, b) => (s + b) & 0xffff, 0);
    if (sum !== ((body[body.length - 2] << 8) | body[body.length - 1])) continue;
    m.fill(0);
    return {data: key, algorithm: openpgp.enums.read(openpgp.enums.symmetric, algorithm)};
  }
  return null;
}

// The message's content (the MIME entity inside), opened with that key, and
// the sender's OpenPGP signature in it, if any: verifier(content, key IDs
// that signed) gives the public keys to check it with, once the content is
// read (a key can come in the message itself). {data, signed: null |
// {state: 'ok' | 'bad' | 'unknown', ids, by}}. date: now, by a clock to trust
// (clock.mjs): a signature is not from the future only by this device's.
export async function open(openpgp, armored, derive, info, verifier, date = new Date()) {
  const key = await sessionKey(openpgp, await openpgp.readMessage({armoredMessage: armored}), derive, info);
  if (!key) throw new Error('This message is not encrypted to the key on this device.');
  try {
    const first = await openpgp.decrypt({message: await openpgp.readMessage({armoredMessage: armored}), sessionKeys: key, format: 'binary', expectSigned: false});
    const ids = first.signatures.map(s => s.keyID.toHex());
    if (!ids.length || !verifier) return {data: first.data, signed: null};
    const keys = await verifier(first.data, ids);
    if (!keys?.length) return {data: first.data, signed: {state: 'unknown', ids, by: null}};
    first.data.fill(0);
    const again = await openpgp.decrypt({message: await openpgp.readMessage({armoredMessage: armored}), sessionKeys: key, verificationKeys: keys, format: 'binary', expectSigned: false, date});
    for (const s of again.signatures) {
      if (!keys.some(k => k.getKeys(s.keyID).length)) continue;
      try { await s.verified; return {data: again.data, signed: {state: 'ok', ids, by: s.keyID.toHex()}}; } catch (e) {}
      return {data: again.data, signed: {state: 'bad', ids, by: s.keyID.toHex()}};
    }
    return {data: again.data, signed: {state: 'unknown', ids, by: null}};
  } finally {
    key.data.fill(0);
  }
}

// From a secret key file and its passphrase: the decryption subkey's scalar
// (RFC 7748 order) and its description. Used once, when a device is set up.
export async function extract(openpgp, armoredSecretKey, passphrase) {
  const key = await openpgp.decryptKey({privateKey: await openpgp.readPrivateKey({armoredKey: armoredSecretKey}), passphrase});
  for (const sub of key.subkeys) {
    const packet = sub.keyPacket;
    if (packet.algorithm !== openpgp.enums.publicKey.ecdh || packet.publicParams?.oid?.getName?.() !== 'curve25519Legacy') continue;
    const d = packet.privateParams.d, Q = packet.publicParams.Q;
    // The OpenPGP encoding of a Curve25519 secret is big-endian; WebCrypto
    // wants RFC 7748 order. Which one this is, the public key tells.
    for (const scalar of [d.slice().reverse(), d.slice()]) {
      const probe = await crypto.subtle.importKey('pkcs8', pkcs8Of(scalar), {name: 'X25519'}, true, ['deriveBits']);
      const jwk = await crypto.subtle.exportKey('jwk', probe);
      const x = Uint8Array.from(atob(jwk.x.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      if (hex(x) === hex(Q.slice(1))) {
        const kdf = packet.publicParams.kdfParams;
        return {scalar, info: describe(packet.getFingerprintBytes(), packet.getKeyID().toHex(), kdf.hash, kdf.cipher),
                userIds: key.getUserIDs(), primary: key.getFingerprint(), sign: await signingKey(openpgp, key)};
      }
    }
  }
  throw new Error('This key has no Curve25519 encryption subkey.');
}

// The key that signs: a signing subkey, or the primary key where it signs
// (Ed25519, as OpenPGP v4 writes it, EdDSALegacy): its seed as PKCS #8 for
// WebCrypto, its key ID and fingerprint. null where the file holds none
// (a key exported without its signing secret).
async function signingKey(openpgp, key) {
  try {
    const p = (await key.getSigningKey()).keyPacket;
    const seed = p.privateParams?.seed;
    if (p.algorithm !== openpgp.enums.publicKey.eddsaLegacy || p.publicParams?.oid?.getName?.() !== 'ed25519Legacy' || seed?.length !== 32) return null;
    return {pkcs8: concat(PKCS8_ED25519, seed), keyId: p.getKeyID().toHex(), fingerprint: hex(p.getFingerprintBytes())};
  } catch (e) {
    return null;
  }
}
