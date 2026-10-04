// Opening messages: which keys a message is for, and its content, read with
// a key that is open in the vault (vault.mjs). Used by the page's hub
// (hub.mjs) and by the reader's own tab (embed.mjs).

import {open} from './sealed-core.mjs';
import {addressOf, read} from './mime.mjs';
import {deriver} from './vault.mjs';
import {addressHash, check} from './seal.mjs';

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

// The message read with the open key keyId ({fingerprint, keyId, hash,
// cipher}: info), or an error.
export async function openWith(armored, info) {
  const openpgp = await openpgpLib(), derive = deriver(info.keyId);
  const bytes = await open(openpgp, armored, derive, info);
  const sealed = await check(openpgp, bytes, info.keyId, derive).catch(() => ({state: 'none', rest: bytes}));
  const message = read(sealed.rest);
  // Whether the key that sealed it is the key of the sender named inside
  // (by the hash of that address), and the key's domain.
  const inside = addressOf(message.from || '');
  message.seal = {state: sealed.state, domain: sealed.domain || '', inside: !!inside && (sealed.hashes || []).includes(await addressHash(inside))};
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
