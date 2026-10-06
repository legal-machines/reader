// Opening messages: which keys a message is for, and its content, read with
// a key that is open in the vault (vault.mjs). Used by the page's hub
// (hub.mjs) and by the reader's own tab (embed.mjs).

import {open} from './sealed-core.mjs';
import {addressOf, read} from './mime.mjs';
import {deriver} from './vault.mjs';
import {addressHash, check} from './seal.mjs';
import {dkim, fieldsOf, mailbox, values} from './dkim.mjs';
import * as contacts from './contacts.mjs';
import {measure, now} from './clock.mjs';

measure();  // GitHub's time, for checking signatures: asked once, early

// OpenPGP.js (about 400 KB) loads only when there is something to open.
let library = null;
export const openpgpLib = () => (library ||= import('./openpgp.min.mjs'));

// The key IDs a message is encrypted to: its Public-Key Encrypted Session Key
// packets (RFC 9580, sections 4.2 and 5.1), read from the armored text.
export function recipients(text) {
  const body = text.split(/-----BEGIN PGP MESSAGE-----/)[1]?.split(/-----END PGP MESSAGE-----/)[0];
  if (!body) throw new Error('no message');
  const lines = body.trim().split(/\r?\n/);
  const start = lines.findIndex(l => l.trim() === '');  // after the armor headers
  const b64 = lines.slice(start + 1).filter(l => !l.startsWith('=')).join('');
  const bytes = Uint8Array.from(atob(b64.slice(0, 4096 - 4096 % 4)), c => c.charCodeAt(0));
  const ids = [];
  for (let at = 0; at < bytes.length;) {
    const head = bytes[at++];
    if (!(head & 0x80)) throw new Error('not a packet');
    let tag, length;
    if (head & 0x40) {  // new format
      tag = head & 0x3f;
      const first = bytes[at++];
      if (first < 192) length = first;
      else if (first < 224) length = ((first - 192) << 8) + bytes[at++] + 192;
      else if (first === 255) { length = (bytes[at] << 24 | bytes[at + 1] << 16 | bytes[at + 2] << 8 | bytes[at + 3]) >>> 0; at += 4; }
      else break;  // partial lengths only follow the session keys
    } else {  // old format
      tag = (head >> 2) & 0x0f;
      const kind = head & 3;
      if (kind === 3) break;
      length = 0;
      for (let i = 0; i < [1, 2, 4][kind]; i++) length = length * 256 + bytes[at++];
    }
    if (tag === 1 && bytes[at] === 3) ids.push([...bytes.subarray(at + 1, at + 9)].map(b => b.toString(16).padStart(2, '0')).join(''));
    else if (tag !== 1 && tag !== 3) break;  // the encrypted data: no more session keys
    at += length;
  }
  return ids;
}

// The same, for messages the quick reading above cannot follow.
export async function recipientsOf(armored) {
  try {
    return recipients(armored);
  } catch (e) {
    const openpgp = await openpgpLib();
    const message = await openpgp.readMessage({armoredMessage: armored});
    return message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey).map(p => p.publicKeyID.toHex());
  }
}

// WebCrypto X25519, which keeps the key unreadable even to this site's code:
// Safari 17, Chrome and Edge 133, Firefox 130 and later.
let capable = null;
export const canOpen = () => (capable ||= crypto.subtle.importKey('raw', new Uint8Array(32).fill(9), {name: 'X25519'}, false, []).then(() => true, () => false));

const OURS = /@(?:[a-z0-9-]+\.)*(?:legalmachines\.org|dzyza\.com)$/;  // our domains and any name under them
const KEY_BLOCK = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const ascii = bytes => new TextDecoder().decode(bytes.subarray(0, 4e6));
const isKey = f => f.type === 'application/pgp-keys' || ascii(f.data.subarray(0, 4096)).includes(KEY_BLOCK);
const keyData = f => ascii(f.data).includes(KEY_BLOCK) ? ascii(f.data) : f.data;

// The encrypted text when it is all there is: one armored block, nothing
// around it.
const single = text => {
  const t = String(text || '').trim();
  return t.startsWith('-----BEGIN PGP MESSAGE-----') && t.endsWith('-----END PGP MESSAGE-----') && t.indexOf('-----BEGIN PGP MESSAGE-----', 1) < 0 ? t : '';
};

// The message as the mail server holds it: its sender, read strictly from
// its one From field (dkim.mjs), its encrypted text and its Autocrypt header.
// The encrypted text counts only where the whole message is it: PGP/MIME
// (RFC 3156), or a text body that is one armored block (inline, as some apps
// send it). Encrypted text quoted or forwarded in a message the domain
// signed was not written by the domain's sender, and is not read as theirs.
function outer(raw) {
  const {fields} = fieldsOf(raw);
  const froms = values(fields, 'from'), types = values(fields, 'content-type');
  const from = froms.length === 1 ? mailbox(froms[0]) : '';
  const type = (types.length === 1 ? types[0] : types.length ? 'x/several' : 'text/plain').trim().toLowerCase();
  const m = read(raw);
  let armored = '';
  if (/^multipart\/encrypted\b/.test(type) && /protocol\s*=\s*"?application\/pgp-encrypted/.test(type) && m.text === undefined && m.html === undefined &&
      m.files.length === 2 && m.files[0].type === 'application/pgp-encrypted' && m.files[1].type === 'application/octet-stream')
    armored = single(ascii(m.files[1].data));
  else if ((/^text\/plain\b/.test(type) || /^multipart\/alternative\b/.test(type)) && !m.files.length)
    armored = single(m.text);
  // Otherwise the first encrypted text anywhere in it, quoted or forwarded:
  // it opens, but nothing in the message around it vouches for it.
  const quoted = armored ? '' : [m.text, ...m.files.map(f => ascii(f.data))].map(t => /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/.exec(t || '')?.[0]).find(Boolean) || '';
  return {from, armored, quoted, autocrypt: values(fields, 'autocrypt')};
}

// The keys of a sender outside, learned only from what its domain signed
// (dkim.mjs): the Autocrypt header when the signature covers it, or a key
// inside the encrypted text (part of the signed body, and the whole of it,
// so written by that sender). 'new', 'same', 'changed' or ''.
async function learn(openpgp, from, wrapper, content) {
  const found = [];
  if (wrapper.signedAutocrypt && wrapper.autocrypt.length === 1) {
    const t = Object.fromEntries(wrapper.autocrypt[0].split(';').map(p => p.split('=')).filter(p => p.length >= 2).map(([k, ...v]) => [k.trim().toLowerCase(), v.join('=')]));
    if ((t.addr || '').trim().toLowerCase() === from && t.keydata) {
      try { found.push(Uint8Array.from(atob(t.keydata.replace(/\s/g, '')), c => c.charCodeAt(0))); } catch (e) {}
    }
  }
  try { found.push(...read(content).files.filter(isKey).map(keyData)); } catch (e) {}
  let result = '';
  for (const data of found.slice(0, 6)) {
    const r = await contacts.learn(openpgp, from, data);
    if (r === 'changed' || (r === 'new' && result !== 'changed') || (r && !result)) result = r;
  }
  return result;
}

async function domainSigned(raw, from) {
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', raw))].map(b => b.toString(16).padStart(2, '0')).join('');
  const kept = await contacts.checkedOf(hash);
  if (kept?.state === 'pass' && kept.from === from) return kept;
  const d = await dkim(raw, from).catch(() => ({state: 'unknown', why: 'error'}));
  if (d.state === 'pass') contacts.keepChecked(hash, {...d, from});
  return d;
}

// The message read with the open key keyId ({fingerprint, keyId, hash,
// cipher}: info), or an error. extra.raw: the whole message as the mail
// server holds it, for the signature of the sender's domain (DKIM); its
// encrypted text is then read from it, not taken as handed over.
export async function openWith(armored, info, extra = {}) {
  const openpgp = await openpgpLib(), derive = deriver(info.keyId);
  const wrapper = extra.raw instanceof Uint8Array ? outer(extra.raw) : null;
  if (wrapper) {
    if (!wrapper.armored && !wrapper.quoted) throw new Error('This message holds no encrypted text.');
    armored = wrapper.armored || wrapper.quoted;
  }
  const quoted = !!wrapper && !wrapper.armored;
  // With the whole message, its own From field and nothing Mail says.
  const from = wrapper ? wrapper.from : addressOf(String(extra.sentFrom || ''));
  const unclear = !!wrapper && !from;
  const outside = unclear || (!!from && !OURS.test(from));
  // The domain's signature, checked while the message opens: for a sender
  // outside only (our own mail server signs ours, so it would prove nothing).
  const checking = unclear ? Promise.resolve({state: 'fail', why: 'from'}) : quoted ? Promise.resolve({state: 'none', why: 'quoted'})
    : outside && wrapper ? domainSigned(extra.raw, from) : Promise.resolve({state: 'none', why: wrapper ? '' : 'not handed'});
  let learned = null;
  const learnOnce = async content => {
    if (learned !== null) return;
    const d = await checking;
    learned = '';
    if (d.state === 'pass' && d.aligned && from && !quoted) learned = await learn(openpgp, from, {...wrapper, signedAutocrypt: d.covers.includes('autocrypt')}, content);
  };
  // The sender's own signature, checked with the key known for that address.
  const verifier = outside && from ? async (content, ids) => {
    await learnOnce(content);
    const c = await contacts.recordOf(from);
    const keys = [];
    for (const armoredKey of [c?.armored, c?.change?.armored].filter(Boolean)) keys.push(await openpgp.readKey({armoredKey}));
    return keys.filter(k => k.getKeyIDs().some(id => ids.includes(id.toHex())));
  } : null;
  const {data: bytes, signed} = await open(openpgp, armored, derive, info, verifier, new Date(now()));
  if (outside) await learnOnce(bytes);
  const sealed = await check(openpgp, bytes, info.keyId, derive).catch(() => ({state: 'none', rest: bytes}));
  const message = read(sealed.rest);
  // Whether the key that sealed it is the key of the sender named inside
  // (by the hash of that address), and the key's domain.
  const inside = addressOf(message.from || '');
  message.seal = {state: sealed.state, domain: sealed.domain || '', inside: !!inside && (sealed.hashes || []).includes(await addressHash(inside))};
  if (wrapper) message.sentFrom = from;
  if (outside) {
    const c = from ? await contacts.recordOf(from) : null;
    let by = null;
    if (signed?.by && c) {
      const known = await openpgp.readKey({armoredKey: c.armored});
      by = known.getKeyIDs().some(id => id.toHex() === signed.by) ? 'known' : 'new';
    }
    message.sender = {from, quoted, dkim: await checking, signed: signed ? {state: signed.state, by} : null, learned,
                      fingerprint: c?.fingerprint || '', checked: c?.checked || '', change: c?.change?.fingerprint || ''};
  }
  bytes.fill(0);
  return message;
}

// What a list shows of a message: the subject and the start of its text.
export function glance(m) {
  let text = m.text;
  if (text === undefined && m.html !== undefined) text = new DOMParser().parseFromString(m.html, 'text/html').body?.textContent || '';
  text = (text || '').replace(/[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁯ㅤ﻿ﾠ]/g, '').replace(/\s+/g, ' ').trim();
  if (!text) text = m.files.length ? (m.files.length === 1 ? 'Attachment: ' : `${m.files.length} attachments: `) + m.files.map(f => f.name).join(', ') : 'No text';
  // Files as the message shows them: a picture its text shows is not one.
  const files = m.files.filter(f => !(m.html !== undefined && f.id && f.type.startsWith('image/') && m.html.includes('cid:' + f.id))).length;
  return {subject: m.subject, preview: text.slice(0, 300), date: m.date, files};
}
