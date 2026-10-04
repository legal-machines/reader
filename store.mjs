// Where this browser keeps a decryption key: only sealed (AES-GCM) under a
// key made from the passkey's PRF output (Touch ID, a fingerprint, a security
// key) and the device PIN. The sealed key sits in this site's IndexedDB,
// which no other site can open, the mail page included; opened, it becomes
// a non-extractable WebCrypto key that lives in one page's memory.

const DB = 'sealed-reader', STORE = 'keys', PBKDF2_ROUNDS = 600000;
const enc = new TextEncoder();

export const b64u = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64u = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const random = n => crypto.getRandomValues(new Uint8Array(n));

function open() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE, {keyPath: 'keyId'});
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function run(mode, work) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode), result = work(t.objectStore(STORE));
    t.oncomplete = () => { db.close(); resolve(result.result); };
    t.onerror = () => { db.close(); reject(t.error); };
  });
}
export const all = () => run('readonly', s => s.getAll());
export const put = record => run('readwrite', s => s.put(record));
export const remove = keyId => run('readwrite', s => s.delete(keyId));

// The PRF output of the passkey for this record (a touch of Touch ID).
async function prf(credentialId, salt) {
  const got = await navigator.credentials.get({publicKey: {
    challenge: random(32), rpId: location.hostname, userVerification: 'required', timeout: 120000,
    allowCredentials: [{type: 'public-key', id: unb64u(credentialId)}],
    extensions: {prf: {eval: {first: unb64u(salt)}}},
  }});
  const out = got.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error('This browser cannot unlock the key with a passkey.');
  return new Uint8Array(out);
}

async function sealingKey(prfOut, pin, pinSalt) {
  let pinBits = new Uint8Array(0);
  if (pin) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pin.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    pinBits = new Uint8Array(await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: unb64u(pinSalt), iterations: PBKDF2_ROUNDS}, base, 256));
  }
  const material = new Uint8Array(prfOut.length + pinBits.length);
  material.set(prfOut);
  material.set(pinBits, prfOut.length);
  const base = await crypto.subtle.importKey('raw', material, 'HKDF', false, ['deriveKey']);
  material.fill(0);
  pinBits.fill(0);
  return crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('sealed-reader key v1')},
                                 base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
}

// A new passkey for this browser, with its PRF output.
export async function newPasskey(label) {
  const salt = random(32);
  const made = await navigator.credentials.create({publicKey: {
    challenge: random(32), rp: {id: location.hostname, name: 'Mail Reader'},
    user: {id: random(16), name: label, displayName: label},
    pubKeyCredParams: [{type: 'public-key', alg: -7}, {type: 'public-key', alg: -257}],
    authenticatorSelection: {residentKey: 'preferred', userVerification: 'required'}, timeout: 120000,
    extensions: {prf: {eval: {first: salt}}},
  }});
  const result = made.getClientExtensionResults().prf;
  if (result?.enabled === false) throw new Error('This browser or device cannot lock a key with a passkey (Safari 18, Chrome or Edge can).');
  const credentialId = b64u(made.rawId);
  // Some browsers give the PRF output only when the passkey is used.
  const out = result?.results?.first ? new Uint8Array(result.results.first) : await prf(credentialId, b64u(salt));
  return {credentialId, salt: b64u(salt), out};
}

// Seals the key's PKCS #8 bytes and stores the record; the bytes are wiped.
export async function keep(passkey, pin, pkcs8, info, addresses) {
  const pinSalt = b64u(random(16)), iv = random(12);
  const key = await sealingKey(passkey.out, pin, pinSalt);
  passkey.out.fill(0);
  const sealed = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, pkcs8);
  pkcs8.fill(0);
  await put({keyId: info.keyId, info, addresses, credentialId: passkey.credentialId, salt: passkey.salt, pinSalt: pin ? pinSalt : null,
             iv: b64u(iv), sealed: b64u(sealed), created: new Date().toISOString()});
}

// The record's key, opened as a non-extractable X25519 key.
export async function unlock(record, pin) {
  const out = await prf(record.credentialId, record.salt);
  const key = await sealingKey(out, record.pinSalt ? pin : '', record.pinSalt);
  out.fill(0);
  let pkcs8;
  try {
    pkcs8 = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64u(record.iv)}, key, unb64u(record.sealed)));
  } catch (e) {
    throw new Error(record.pinSalt ? 'Wrong PIN.' : 'This passkey does not open the key.');
  }
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, {name: 'X25519'}, false, ['deriveBits']);
  pkcs8.fill(0);
  return privateKey;
}
