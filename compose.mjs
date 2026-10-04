// Writing an end-to-end encrypted message inside the Mail app: the subject
// and the text are typed here, in a frame of another site that the mail page
// cannot read, and encrypted here to keys this reader carries (keys.mjs,
// published with it), never to keys the mail page offers. The mail page gets
// the encrypted message and sends it; this page sends nothing itself.

import {MAIL_SITES} from './sites.mjs';
import {escape} from './mime.mjs';
import {KEYS} from './keys.mjs';

const subject = document.getElementById('subject'), body = document.getElementById('body');
let parentOrigin = null, library = null;
const openpgpLib = () => (library ||= import('./openpgp.min.mjs'));
const tell = m => { if (parentOrigin) parent.postMessage(m, parentOrigin); };
const report = () => tell({type: 'reader-height', height: Math.ceil(document.documentElement.getBoundingClientRect().height)});
new ResizeObserver(report).observe(document.documentElement);
const grow = () => { body.style.height = 'auto'; body.style.height = Math.max(body.scrollHeight, 240) + 'px'; };
body.addEventListener('input', () => { grow(); tell({type: 'reader-dirty'}); });
subject.addEventListener('input', () => tell({type: 'reader-dirty'}));

// The keys of our own addresses, published as part of this reader (keys.mjs).
const keys = async () => KEYS;

// RFC 2047, for a header that is not plain ASCII.
const header = text => /^[\x20-\x7e]*$/.test(text) ? text
  : '=?UTF-8?B?' + btoa(String.fromCharCode(...new TextEncoder().encode(text))) + '?=';
const list = addresses => addresses.join(', ');

async function encrypt({from, to, cc, bcc}) {
  const all = [...to, ...cc, ...bcc].map(a => a.toLowerCase());
  if (!all.length) throw new Error('Add a recipient.');
  const known = await keys();
  const keyOf = address => known.find(k => k.address === address);
  const missing = [...all, from.toLowerCase()].filter(a => !keyOf(a));
  if (missing.length) throw new Error(`End to end goes only to mailboxes here with keys; not to ${missing.join(', ')}.`);
  const openpgp = await openpgpLib();
  const recipients = await Promise.all([...new Set([...all, from.toLowerCase()])].map(a => openpgp.readKey({armoredKey: keyOf(a).armored})));
  // The headers people read travel inside (protected-headers="v1", as
  // Thunderbird writes them); outside the subject is "...".
  const inner = `Content-Type: text/plain; charset=UTF-8; protected-headers="v1"\r\n` +
                `From: ${from}\r\nTo: ${list(to)}\r\n` + (cc.length ? `Cc: ${list(cc)}\r\n` : '') +
                `Subject: ${header(subject.value.trim())}\r\nDate: ${new Date().toUTCString()}\r\nContent-Transfer-Encoding: 8bit\r\n\r\n` +
                body.value.replace(/\r?\n/g, '\r\n') + '\r\n';
  const message = await openpgp.createMessage({binary: new TextEncoder().encode(inner)});
  return openpgp.encrypt({message, encryptionKeys: recipients, format: 'armored'});
}

addEventListener('message', async e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  parentOrigin = e.origin;
  if (e.data?.type === 'reader-compose') {  // the frame's first word from the Mail app: the reply's quote, if any
    if (typeof e.data.subject === 'string' && !subject.value) subject.value = e.data.subject;
    if (typeof e.data.quote === 'string' && !body.value) { body.value = e.data.quote; grow(); body.setSelectionRange(0, 0); }
    report();
  } else if (e.data?.type === 'reader-encrypt') {
    const s = v => Array.isArray(v) ? v.filter(a => typeof a === 'string').slice(0, 100) : [];
    try {
      if (!subject.value.trim() && !body.value.trim()) throw new Error('The message is empty.');
      const armored = await encrypt({from: String(e.data.from || ''), to: s(e.data.to), cc: s(e.data.cc), bcc: s(e.data.bcc)});
      tell({type: 'reader-encrypted', armored});
    } catch (err) {
      tell({type: 'reader-error', message: escape(err.message)});
    }
  }
});
if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');
grow();
