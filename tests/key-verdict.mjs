// check.mjs says "Yes, this is the key in this browser" only for a record
// of the address asked about, with the encryption subkey and the primary key
// (the key that signs) asked about (store.mjs, keyVerdict). The audit's
// recipe (B11): a record with the subkey and no key that signs, asked with
// another primary key, must not give Yes; nor a record of another address.
// Run with plain node from the repository: node tests/key-verdict.mjs
import assert from 'node:assert/strict';
import {keyVerdict} from '../store.mjs';

const P = 'a'.repeat(40), OTHER_P = 'b'.repeat(40), S = 'c'.repeat(40), OTHER_S = 'd'.repeat(40);
const ADDRESS = 'alice@legalmachines.org';
const record = (fields = {}) => ({info: {fingerprint: S}, signer: {fingerprint: P, keyId: P.slice(24)}, addresses: [ADDRESS],
                                  created: '2026-10-01T10:00:00.000Z', ...fields});
const made = Date.parse('2026-10-07T10:00:00Z') / 1000;  // when the mail server got the key waiting

let passed = 0;
const it = (name, f) => { f(); passed++; console.log(`ok ${passed} - ${name}`); };
const kind = (records, address = ADDRESS, primary = P, subkey = S, madeAt = 0) => keyVerdict(records, address, primary, subkey, madeAt).kind;

it('the whole record of the address: good', () => {
  const r = record();
  assert.deepEqual(keyVerdict([r], ADDRESS, P, S), {kind: 'good', record: r});
});
it('the address in another case: still the same address', () => {
  assert.equal(kind([record({addresses: ['Alice@LegalMachines.org']})]), 'good');
  assert.equal(kind([record()], 'ALICE@legalmachines.org'), 'good');
});
it('the encryption subkey alone, no key that signs: not good', () => {
  assert.equal(kind([record({signer: undefined})]), 'other');
  assert.equal(kind([record({signer: undefined})], ADDRESS, OTHER_P), 'other');
  assert.equal(kind([record({signer: null})]), 'other');
});
it('another primary key: not good', () => {
  assert.equal(kind([record()], ADDRESS, OTHER_P), 'other');
});
it('another encryption subkey: not good', () => {
  assert.equal(kind([record()], ADDRESS, P, OTHER_S), 'other');
});
it('the same key, kept for another address only: not good', () => {
  assert.equal(kind([record({addresses: ['bob@legalmachines.org']})]), 'none');
  assert.equal(kind([record({addresses: ['bob@legalmachines.org']}), record({info: {fingerprint: OTHER_S}})]), 'other');
});
it('no records: none', () => {
  assert.equal(kind([]), 'none');
});
it('an older key of the address only: "older" softens a No, never makes a Yes', () => {
  // Kept here well before the key waiting was made.
  assert.equal(kind([record({info: {fingerprint: OTHER_S}})], ADDRESS, P, S, made), 'older');
  assert.equal(kind([record({signer: undefined})], ADDRESS, P, S, made), 'older');
  assert.equal(kind([record()], ADDRESS, OTHER_P, S, made), 'older');
  // Kept here after it: a No stays a No.
  assert.equal(kind([record({info: {fingerprint: OTHER_S}, created: '2026-10-07T12:00:00Z'})], ADDRESS, P, S, made), 'other');
  // One recent record among older ones: a No.
  assert.equal(kind([record({info: {fingerprint: OTHER_S}}), record({info: {fingerprint: OTHER_S}, created: '2026-10-07T12:00:00Z'})], ADDRESS, P, S, made), 'other');
  // The right record still says Yes, whatever the time.
  assert.equal(kind([record({created: '2026-10-07T12:00:00Z'})], ADDRESS, P, S, made), 'good');
});
console.log(`all ${passed} passed`);
