// Seal learns the key of a sender outside only from what their domain
// signed as their whole message, and keeps a first key only from a message
// signed with it (decrypt.mjs, dkim.mjs, contacts.mjs). The audit's recipe
// (B03): the same body under a DKIM signature of From alone reads as quoted
// with Content-Type text/plain, and as the whole message with Content-Type
// multipart/encrypted; the signature passes both ways, and neither may
// teach Seal a key. Run with plain node from the repository: node tests/learning.mjs
// Everything is made here (OpenPGP keys, an RSA DKIM key, the messages) and
// kept in memory: no network, no files.
import assert from 'node:assert/strict';
import {createHash, createSign, generateKeyPairSync} from 'node:crypto';

// IndexedDB as contacts.mjs and alarm.mjs use it, in memory.
const databases = new Map();
globalThis.indexedDB = {
  open(name, version) {
    const request = {};
    setTimeout(() => {
      let db = databases.get(name);
      const upgrade = !db || db.version < version;
      if (!db) databases.set(name, db = {version, stores: new Map()});
      const done = f => { const r = {}; try { r.result = f(); } catch (e) { r.error = e; } return r; };
      const copy = v => v === undefined ? v : structuredClone(v);
      request.result = {
        objectStoreNames: {contains: n => db.stores.has(n)},
        createObjectStore: (n, options = {}) => db.stores.set(n, {keyPath: options.keyPath, rows: new Map()}),
        transaction(n) {
          const store = db.stores.get(n), t = {};
          t.objectStore = () => ({
            get: k => done(() => copy(store.rows.get(k))),
            getAll: () => done(() => [...store.rows.values()].map(copy)),
            put: (v, k) => done(() => { const key = store.keyPath ? v[store.keyPath] : k; store.rows.set(key, copy(v)); return key; }),
            delete: k => done(() => { store.rows.delete(k); }),
          });
          setTimeout(() => t.oncomplete?.());
          return t;
        },
        close() {},
      };
      if (upgrade) { db.version = version; request.onupgradeneeded?.({oldVersion: 0}); }
      request.onsuccess?.();
    });
    return request;
  },
};
const forget = () => databases.delete('seal-contacts');

const openpgp = await import('../openpgp.min.mjs');
const {openWith} = await import('../decrypt.mjs');
const {dkim, mimeSigned, useResolver} = await import('../dkim.mjs');
const contacts = await import('../contacts.mjs');
const {hold} = await import('../vault.mjs');
const {extract, pkcs8Of} = await import('../sealed-core.mjs');

let passed = 0;
const it = async (name, f) => { await f(); passed++; console.log(`ok ${passed} - ${name}`); };

// ---- DKIM, signed here as a sender's domain would (RFC 6376, relaxed/relaxed),
// with a key of its own; dkim.mjs gets the key's record from a fake DNS.
const DOMAIN = 'example.org', SELECTOR = 'sel';
const rsa = generateKeyPairSync('rsa', {modulusLength: 2048});
const record = `v=DKIM1; k=rsa; p=${rsa.publicKey.export({type: 'spki', format: 'der'}).toString('base64')}`;
useResolver(name => name === `${SELECTOR}._domainkey.${DOMAIN}` ? Promise.resolve([record]) : Promise.reject(new Error('unreachable')));

const nameOf = field => field.slice(0, field.indexOf(':')).trim().toLowerCase();
const relaxedField = field => nameOf(field) + ':' + field.slice(field.indexOf(':') + 1).replace(/\r\n/g, '').replace(/[ \t]+/g, ' ').trim();
const relaxedBody = body => {
  const lines = body.split('\r\n').map(l => l.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines.length ? lines.join('\r\n') + '\r\n' : '';
};
// The message with a DKIM-Signature over the fields named in h (each taken
// from the bottom up, as the RFC has it) and the whole body.
function signed(fields, body, h) {
  const bh = createHash('sha256').update(relaxedBody(body), 'latin1').digest('base64');
  const field = `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${DOMAIN}; s=${SELECTOR}; h=${h.join(':')}; bh=${bh}; b=`;
  const taken = new Map();
  let data = '';
  for (const name of h) {
    const all = fields.filter(f => nameOf(f) === name), k = taken.get(name) || 0;
    if (k < all.length) { data += relaxedField(all[all.length - 1 - k]) + '\r\n'; taken.set(name, k + 1); }
  }
  data += relaxedField(field);
  return [field + createSign('RSA-SHA256').update(data, 'latin1').sign(rsa.privateKey, 'base64'), ...fields];
}
const message = (fields, body) => new TextEncoder().encode(fields.join('\r\n') + '\r\n\r\n' + body);

// ---- OpenPGP: our key (opened as Seal opens it, in this page's vault), and
// two keys of a sender outside.
const ME = 'me@legalmachines.org', ALICE = `alice@${DOMAIN}`;
const mine = await openpgp.generateKey({type: 'ecc', curve: 'curve25519Legacy', userIDs: [{email: ME}], passphrase: 'test', format: 'armored'});
const found = await extract(openpgp, mine.privateKey, 'test');
await hold({keyId: found.info.keyId, info: found.info}, pkcs8Of(found.scalar), 0);
const myPublic = await openpgp.readKey({armoredKey: mine.publicKey});
const alice = await openpgp.generateKey({type: 'ecc', curve: 'curve25519Legacy', userIDs: [{name: 'Alice', email: ALICE}], format: 'object'});
const alice2 = await openpgp.generateKey({type: 'ecc', curve: 'curve25519Legacy', userIDs: [{name: 'Alice', email: ALICE}], format: 'object'});
const fpr = k => k.getFingerprint().toUpperCase();

// What Alice encrypts to us: a text and her key attached, signed with the
// key `signer` or not signed.
async function encrypted(key, signer) {
  const inner = ['From: Alice <' + ALICE + '>', 'To: ' + ME, 'Subject: Hello', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="inner"', '',
    '--inner', 'Content-Type: text/plain; charset=utf-8', '', 'Hello.', '--inner',
    'Content-Type: application/pgp-keys; name="alice.asc"', 'Content-Disposition: attachment; filename="alice.asc"', '',
    key.publicKey.armor().trim(), '--inner--', ''].join('\r\n');
  return openpgp.encrypt({message: await openpgp.createMessage({binary: new TextEncoder().encode(inner)}), encryptionKeys: myPublic,
                          ...(signer ? {signingKeys: signer.privateKey} : {}), format: 'armored'});
}
// PGP/MIME (RFC 3156) around it: the body every case below shares.
const pgpMime = armored => ['--outer', 'Content-Type: application/pgp-encrypted', '', 'Version: 1', '',
  '--outer', 'Content-Type: application/octet-stream; name="encrypted.asc"', '', armored.trim().replace(/\r?\n/g, '\r\n'), '', '--outer--', ''].join('\r\n');
const HEAD = ['From: Alice <' + ALICE + '>', 'To: ' + ME, 'Subject: Encrypted', 'Date: Tue, 06 Oct 2026 10:00:00 +0000', 'Message-ID: <1@example.org>', 'MIME-Version: 1.0'];
const WHOLE = 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="outer"';
const PLAIN = 'Content-Type: text/plain; charset=us-ascii';
const ALL = ['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type'];

const open = raw => openWith('', found.info, {raw});

await it('mimeSigned: Content-Type signed, duplicates and absent fields', () => {
  const raw = (...fields) => message(['From: ' + ALICE, ...fields], 'x');
  assert.equal(mimeSigned(['from'], raw(WHOLE)), false, 'Content-Type not signed');
  assert.equal(mimeSigned(['from', 'content-type'], raw(WHOLE)), true, 'Content-Type signed');
  assert.equal(mimeSigned(['from', 'content-type'], raw(WHOLE, PLAIN)), false, 'a second Content-Type, unsigned');
  assert.equal(mimeSigned(['from', 'content-type', 'content-type'], raw(WHOLE, PLAIN)), true, 'both signed (oversigned)');
  assert.equal(mimeSigned(['from', 'content-type'], raw()), true, 'absent, but named: none can be added');
  assert.equal(mimeSigned(['from'], raw()), false, 'absent and not named: one could be added or taken away');
  assert.equal(mimeSigned(['from', 'content-type'], raw(WHOLE, 'Content-Transfer-Encoding: base64')), false, 'Content-Transfer-Encoding unsigned');
  assert.equal(mimeSigned(['from', 'content-type', 'content-transfer-encoding'], raw(WHOLE, 'Content-Transfer-Encoding: 7bit')), true);
  assert.equal(mimeSigned(['from', 'content-type'], raw('MIME-Version: 1.0', WHOLE)), false, 'MIME-Version unsigned');
  assert.equal(mimeSigned(['from', 'mime-version', 'content-type'], raw('MIME-Version: 1.0', WHOLE)), true);
  assert.equal(mimeSigned(undefined, raw(WHOLE)), false);
});

// The audit's recipe: one signature of From alone, one body; only
// Content-Type differs.
const signedBody = pgpMime(await encrypted(alice, alice));
const asSent = signed([...HEAD, PLAIN], signedBody, ['from']);
const reread = asSent.map(f => f === PLAIN ? WHOLE : f);

await it('B03 recipe: DKIM of From alone passes for text/plain and for multipart/encrypted alike', async () => {
  for (const raw of [message(asSent, signedBody), message(reread, signedBody)]) {
    const d = await dkim(raw, ALICE);
    assert.equal(d.state, 'pass');
    assert.equal(d.aligned, true);
    assert.deepEqual(d.covers, ['from']);
  }
});

await it('B03 recipe: text/plain reads as quoted and teaches no key', async () => {
  forget();
  const m = await open(message(asSent, signedBody));
  assert.equal(m.sender.quoted, true);
  assert.equal(m.sender.learned, '');
  assert.equal(await contacts.recordOf(ALICE), undefined);
});

await it('B03 recipe: the same body as multipart/encrypted, Content-Type unsigned: no key learned, none offered', async () => {
  forget();
  const m = await open(message(reread, signedBody));
  assert.equal(m.sender.quoted, false);
  assert.equal(m.sender.dkim.state, 'pass');
  assert.equal(m.sender.learned, '');
  assert.equal(m.sender.offered, null);
  assert.equal(await contacts.recordOf(ALICE), undefined);
});

await it('Content-Type signed, message signed with the key it brings: the first key is kept', async () => {
  forget();
  const m = await open(message(signed([...HEAD, WHOLE], signedBody, ALL), signedBody));
  assert.equal(m.sender.learned, 'new');
  assert.equal(m.sender.signed.state, 'ok');
  assert.equal(m.sender.signed.by, 'known');
  assert.equal((await contacts.recordOf(ALICE)).fingerprint, fpr(alice.publicKey));
});

await it('A key already kept is never replaced by a message: a new one, even signed with itself, waits', async () => {
  // Alice's first key is kept (above); a message brings another.
  const body = pgpMime(await encrypted(alice2, alice2));
  const m = await open(message(signed([...HEAD, WHOLE], body, ALL), body));
  assert.equal(m.sender.learned, 'changed');
  assert.equal(m.sender.signed.by, 'new');
  const c = await contacts.recordOf(ALICE);
  assert.equal(c.fingerprint, fpr(alice.publicKey));
  assert.equal(c.change.fingerprint, fpr(alice2.publicKey));
  assert.equal(await contacts.take(openpgp, ALICE, alice2.publicKey.armor(), fpr(alice2.publicKey)), false, 'take does not replace it either');
  assert.equal((await contacts.recordOf(ALICE)).fingerprint, fpr(alice.publicKey));
});

await it('Content-Type signed, message not signed: the first key is only offered, then taken by its fingerprint', async () => {
  forget();
  const body = pgpMime(await encrypted(alice, null));
  const m = await open(message(signed([...HEAD, WHOLE], body, ALL), body));
  assert.equal(m.sender.signed, null);
  assert.equal(m.sender.learned, 'offered');
  assert.equal(m.sender.offered.fingerprint, fpr(alice.publicKey));
  assert.equal(await contacts.recordOf(ALICE), undefined, 'nothing kept');
  assert.equal(await contacts.take(openpgp, ALICE, m.sender.offered.armored, fpr(alice2.publicKey)), false, 'another fingerprint');
  assert.equal(await contacts.take(openpgp, ALICE, m.sender.offered.armored, m.sender.offered.fingerprint), true);
  const c = await contacts.recordOf(ALICE);
  assert.equal(c.fingerprint, fpr(alice.publicKey));
  assert.ok(c.checked, 'kept as checked with them');
  assert.equal(c.accepted.by, 'you');
});

await it('Content-Type signed, message signed with another key than it brings: offered, not kept', async () => {
  forget();
  const body = pgpMime(await encrypted(alice, alice2));
  const m = await open(message(signed([...HEAD, WHOLE], body, ALL), body));
  assert.equal(m.sender.learned, 'offered');
  assert.equal(await contacts.recordOf(ALICE), undefined);
});

await it('A Content-Type added above the signed one: DKIM still passes, but nothing is learned', async () => {
  forget();
  const fields = signed([...HEAD, PLAIN], signedBody, ALL);
  const raw = message([fields[0], WHOLE, ...fields.slice(1)], signedBody);
  const d = await dkim(raw, ALICE);
  assert.equal(d.state, 'pass', 'the signature takes the bottom Content-Type');
  assert.equal(mimeSigned(d.covers, raw), false);
  const m = await open(raw);
  assert.equal(m.sender.learned, '');
  assert.equal(await contacts.recordOf(ALICE), undefined);
});

await it('Duplicate Content-Type, both multipart/encrypted, one signed: nothing is learned', async () => {
  forget();
  const fields = signed([...HEAD, WHOLE], signedBody, ALL);
  const m = await open(message([fields[0], WHOLE, ...fields.slice(1)], signedBody));
  assert.equal(m.sender.learned, '');
  assert.equal(await contacts.recordOf(ALICE), undefined);
});

await it('MIME-Version present but unsigned: nothing is learned', async () => {
  forget();
  const m = await open(message(signed([...HEAD, WHOLE], signedBody, ALL.filter(n => n !== 'mime-version')), signedBody));
  assert.equal(m.sender.dkim.state, 'pass');
  assert.equal(m.sender.learned, '');
  assert.equal(await contacts.recordOf(ALICE), undefined);
});

await it('contacts.learn: a first key needs the message signed with it; our own domains never count', async () => {
  forget();
  assert.equal(await contacts.learn(openpgp, ALICE, alice.publicKey.armor()), 'offered');
  assert.equal(await contacts.recordOf(ALICE), undefined);
  assert.equal(await contacts.learn(openpgp, ALICE, alice.publicKey.armor(), true), 'new');
  assert.equal(await contacts.learn(openpgp, ALICE, alice2.publicKey.armor(), true), 'changed');
  assert.equal((await contacts.recordOf(ALICE)).fingerprint, fpr(alice.publicKey));
  const ours = await openpgp.generateKey({type: 'ecc', curve: 'curve25519Legacy', userIDs: [{email: 'bob@legalmachines.org'}], format: 'object'});
  assert.equal(await contacts.learn(openpgp, 'bob@legalmachines.org', ours.publicKey.armor(), true), '');
  assert.equal(await contacts.take(openpgp, 'bob@legalmachines.org', ours.publicKey.armor(), fpr(ours.publicKey)), false);
});

console.log(`all ${passed} passed`);
process.exit(0);  // contacts.mjs keeps a BroadcastChannel open
