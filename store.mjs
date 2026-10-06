// A decryption key exists outside one page's memory only sealed (AES-GCM)
// under a key made from a passkey's PRF output (Touch ID, a fingerprint, a
// security key) and the optional PIN. Only this site can ask the passkey
// for that output (its RP ID is this exact host name), so the sealed key is
// kept by the Mail app, in the owner's mailbox settings, and handed to the
// reader with each message: Safari gives a frame storage of its own, apart
// from this site's tab, and a synced passkey opens the same sealed key on the
// owner's other devices. A copy also stays in this tab's IndexedDB. Opened,
// the key becomes a non-extractable WebCrypto key in one page's memory.

const DB = 'sealed-reader', STORE = 'keys', PBKDF2_ROUNDS = 600000;
const enc = new TextEncoder();

export const b64u = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64u = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const random = n => crypto.getRandomValues(new Uint8Array(n));

// Records by passkey (one key may be sealed under several); version 1 kept
// them by key ID, and its records move over as they are.
function open() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 2);
    r.onupgradeneeded = e => {
      const db = r.result;
      if (e.oldVersion < 1) { db.createObjectStore(STORE, {keyPath: 'credentialId'}); return; }
      const rows = r.transaction.objectStore(STORE).getAll();
      rows.onsuccess = () => {
        db.deleteObjectStore(STORE);
        const store = db.createObjectStore(STORE, {keyPath: 'credentialId'});
        for (const row of rows.result) store.put({...row, rp: row.rp || location.hostname, v: row.v || 1});
      };
    };
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
export const remove = credentialId => run('readwrite', s => s.delete(credentialId));

// One touch of a passkey that one of these records was sealed under: its
// record and PRF output.
async function prf(records) {
  const one = records.length === 1;
  const got = await navigator.credentials.get({publicKey: {
    challenge: random(32), rpId: location.hostname, userVerification: 'required', timeout: 120000,
    allowCredentials: records.map(r => ({type: 'public-key', id: unb64u(r.credentialId)})),
    extensions: {prf: one ? {eval: {first: unb64u(records[0].salt)}}
                          : {evalByCredential: Object.fromEntries(records.map(r => [r.credentialId, {first: unb64u(r.salt)}]))}},
  }});
  const out = got.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error('This browser cannot unlock the key with a passkey.');
  const record = records.find(r => r.credentialId === b64u(got.rawId));
  if (!record) throw new Error('That passkey belongs to another key.');
  return {record, out: new Uint8Array(out)};
}

// What binds the sealed bytes to their record (AES-GCM associated data), so
// a sealed key cannot be passed off under another record's name.
const bound = r => r.v === 2 ? {additionalData: enc.encode(`${r.rp}|${r.keyId}|${r.credentialId}|v2`)} : {};
// The same for the key that signs, with which key it is, so Mail cannot
// hand over a record that names another signing key than the one sealed.
const boundSign = r => ({additionalData: enc.encode(`${r.rp}|${r.keyId}|${r.credentialId}|v2|sign|${r.signer.keyId}|${r.signer.fingerprint}`)});

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
    challenge: random(32), rp: {id: location.hostname, name: 'Seal'},
    user: {id: random(16), name: label, displayName: label},
    pubKeyCredParams: [{type: 'public-key', alg: -7}, {type: 'public-key', alg: -257}],
    authenticatorSelection: {residentKey: 'preferred', userVerification: 'required'}, timeout: 120000,
    extensions: {prf: {eval: {first: salt}}},
  }});
  const result = made.getClientExtensionResults().prf;
  if (result?.enabled === false) throw new Error('This browser or device cannot lock a key with a passkey (Safari 18, Chrome or Edge can).');
  const credentialId = b64u(made.rawId);
  // Some browsers give the PRF output only when the passkey is used.
  const out = result?.results?.first ? new Uint8Array(result.results.first) : (await prf([{credentialId, salt: b64u(salt)}])).out;
  return {credentialId, salt: b64u(salt), out};
}

// Seals the key's PKCS #8 bytes, and those of the key that signs (sign:
// {pkcs8, keyId, fingerprint}, seal.mjs extract), keeps the record here and
// returns it; the bytes are wiped.
export async function keep(passkey, pin, pkcs8, info, addresses, sign) {
  const pinSalt = b64u(random(16)), iv = random(12);
  const record = {v: 2, rp: location.hostname, keyId: info.keyId, info, addresses, credentialId: passkey.credentialId, salt: passkey.salt,
                  pinSalt: pin ? pinSalt : null, iv: b64u(iv), created: new Date().toISOString()};
  const key = await sealingKey(passkey.out, pin, pinSalt);
  passkey.out.fill(0);
  record.sealed = b64u(await crypto.subtle.encrypt({name: 'AES-GCM', iv, ...bound(record)}, key, pkcs8));
  pkcs8.fill(0);
  if (sign) {
    const signIv = random(12);
    record.signer = {keyId: sign.keyId, fingerprint: sign.fingerprint};
    record.signIv = b64u(signIv);
    record.signSealed = b64u(await crypto.subtle.encrypt({name: 'AES-GCM', iv: signIv, ...boundSign(record)}, key, sign.pkcs8));
    sign.pkcs8.fill(0);
  }
  await put(record);
  return record;
}

// The key of whichever of these records the touched passkey opens, as its
// PKCS #8 bytes (an ArrayBuffer the caller wipes or hands on), the key that
// signs where the record holds one (signPkcs8, likewise), and the record.
export async function unseal(records, pin) {
  const {record, out} = await prf(records);
  const key = await sealingKey(out, record.pinSalt ? pin : '', record.pinSalt);
  out.fill(0);
  let pkcs8;
  try {
    pkcs8 = await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64u(record.iv), ...bound(record)}, key, unb64u(record.sealed));
  } catch (e) {
    throw new Error(record.pinSalt ? 'Wrong PIN.' : 'This passkey does not open the key.');
  }
  let signPkcs8 = null;
  if (record.signSealed) {
    try { signPkcs8 = await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64u(record.signIv), ...boundSign(record)}, key, unb64u(record.signSealed)); }
    catch (e) { signPkcs8 = null; }  // a signing part that does not open: the key still decrypts, and nothing signs
  }
  return {record, pkcs8, signPkcs8};
}

// A record handed over by the Mail app, checked for shape: anything else is ignored.
export function valid(r) {
  // Version 2 only: its sealed bytes are bound to the record (bound above),
  // so Mail cannot pass one key's seal off under another record.
  return r && typeof r === 'object' && r.v === 2 && r.rp === location.hostname && /^[0-9a-f]{16}$/.test(r.keyId) && typeof r.credentialId === 'string' &&
    typeof r.salt === 'string' && typeof r.iv === 'string' && typeof r.sealed === 'string' && r.info && /^[0-9a-f]{40}$/.test(r.info.fingerprint) &&
    r.info.keyId === r.keyId && Number.isInteger(r.info.hash) && Number.isInteger(r.info.cipher) && Array.isArray(r.addresses) &&
    (r.signSealed === undefined || (typeof r.signSealed === 'string' && typeof r.signIv === 'string' && r.signer &&
      /^[0-9a-f]{16}$/.test(r.signer.keyId) && /^[0-9a-f]{40}$/.test(r.signer.fingerprint) && r.signer.fingerprint.endsWith(r.signer.keyId)));
}
