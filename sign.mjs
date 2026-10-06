// Your OpenPGP signature on a message you send (RFC 9580: a one-pass
// signature, the literal data, the signature), which the recipient's mail
// app checks with your published key: a message the mail server encrypts to
// them in your name carries none. The key stays in the vault (vault.mjs,
// sw.js); this builds the packets around the 64 bytes it returns for the
// digest. Ed25519 as OpenPGP v4 writes it (EdDSALegacy, algorithm 22), with
// SHA-512.

const EDDSA_LEGACY = 22, SHA512 = 10, BINARY = 0x00;

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const be32 = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const unhex = h => Uint8Array.from(h.match(/../g).map(b => parseInt(b, 16)));

// A packet with a new-format header (section 4.2.1).
function packet(tag, body) {
  const n = body.length;
  const length = n < 192 ? [n] : n < 8384 ? [((n - 192) >> 8) + 192, (n - 192) & 255] : [255, ...be32(n)];
  return concat(new Uint8Array([0xc0 | tag, ...length]), body);
}
// A subpacket (section 5.2.3.7): its length, type and body.
function subpacket(type, body) {
  const n = body.length + 1;
  const length = n < 192 ? [n] : [((n - 192) >> 8) + 192, (n - 192) & 255];
  return [...length, type, ...body];
}
// A multiprecision integer (section 3.2): its bit length, then its bytes
// without leading zeros.
function mpi(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const v = bytes.subarray(i), bits = (v.length - 1) * 8 + (32 - Math.clz32(v[0]));
  return [bits >> 8, bits & 255, ...v];
}

// The signed message (the bytes OpenPGP.js reads with readMessage), for
// data, signed by signer {keyId, fingerprint} through sign(data, hashed) ->
// 64 bytes (R and S of Ed25519): the vault makes the digest itself, and only
// for this kind of signature. at: the time it is signed, in ms (clock.mjs).
export async function signedMessage(data, signer, sign, at = Date.now()) {
  if (!/^[0-9a-f]{16}$/.test(signer?.keyId) || !/^[0-9a-f]{40}$/.test(signer?.fingerprint)) throw new Error('No key to sign with.');
  const keyId = unhex(signer.keyId), fingerprint = unhex(signer.fingerprint);
  const now = Math.floor(at / 1000);
  // Hashed: when it was signed, and by which key (its fingerprint).
  const subs = [...subpacket(2, be32(now)), ...subpacket(33, [4, ...fingerprint])];
  const hashed = new Uint8Array([4, BINARY, EDDSA_LEGACY, SHA512, subs.length >> 8, subs.length & 255, ...subs]);
  const trailer = new Uint8Array([4, 0xff, ...be32(hashed.length)]);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', concat(data, hashed, trailer)));
  const signature = await sign(data, hashed);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new Error('locked');
  const unhashed = subpacket(16, [...keyId]);
  const body = concat(hashed, new Uint8Array([unhashed.length >> 8, unhashed.length & 255, ...unhashed, digest[0], digest[1]]),
                      new Uint8Array(mpi(signature.subarray(0, 32))), new Uint8Array(mpi(signature.subarray(32))));
  const onePass = packet(4, new Uint8Array([3, BINARY, SHA512, EDDSA_LEGACY, ...keyId, 1]));
  const literal = packet(11, concat(new Uint8Array([0x62, 0, ...be32(now)]), data));  // binary, no file name
  return concat(onePass, literal, packet(2, body));
}

// The same as an OpenPGP.js message, ready for openpgp.encrypt. Built from
// its packets: reading the bytes back would tie the signature to the
// one-pass packet, and encrypting would then leave it out.
export async function signedPackets(openpgp, data, signer, sign, at = Date.now()) {
  const bytes = await signedMessage(data, signer, sign, at), parts = [];
  for (let at = 0; at < bytes.length;) {
    at++;  // the header byte: our own, new format
    let n = bytes[at++];
    if (n >= 192 && n < 224) n = ((n - 192) << 8) + bytes[at++] + 192;
    else if (n === 255) { n = (bytes[at] << 24 | bytes[at + 1] << 16 | bytes[at + 2] << 8 | bytes[at + 3]) >>> 0; at += 4; }
    parts.push(bytes.subarray(at, at + n));
    at += n;
  }
  const list = new openpgp.PacketList();
  const onePass = new openpgp.OnePassSignaturePacket(), literal = new openpgp.LiteralDataPacket(), signature = new openpgp.SignaturePacket();
  await onePass.read(parts[0]);
  await literal.read(parts[1]);
  await signature.read(parts[2]);
  list.push(onePass, literal, signature);
  return new openpgp.Message(list);
}
