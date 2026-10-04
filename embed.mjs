// The reader inside a message of the Mail app: the mail page hands it the
// encrypted message (which its server has anyway) and gets back only the
// height to give the frame. The text is opened and shown here, in a frame
// of another site, which the mail page cannot look into; this page may
// make no network requests at all (index.html, its Content-Security-Policy).

import {open} from './sealed-core.mjs';
import {all, unlock, valid} from './store.mjs';
import {read, escape, linkify} from './mime.mjs';
import {MAIL_SITES} from './sites.mjs';
import {icon} from './icons.mjs';
import {LETTER_CSS} from './letter.mjs';

const view = document.getElementById('view');
let parentOrigin = null, armored = null, handedRecords = [], sentFrom = '', hideTimer = null, urls = [];
// Inside a conversation the subject goes to the Mail app's title line, shown
// by this site's subject frame (title.mjs): the channel, and what it shows now.
let titleChannel = null, shownSubject = '';
const announce = text => { shownSubject = text; titleChannel?.postMessage({subject: text}); };
// Shown inside a message (a frame), or in a tab of its own that the Mail
// app opened for the message (a site whose frames cannot share this
// browser's key, see sites.mjs).
const host = parent !== window ? parent : window.opener;

const tell = message => { if (parentOrigin && host === parent) parent.postMessage(message, parentOrigin); };
const report = () => tell({type: 'reader-height', height: Math.ceil(document.documentElement.getBoundingClientRect().height)});
new ResizeObserver(report).observe(document.documentElement);

function show(html) {
  for (const u of urls) URL.revokeObjectURL(u);
  urls = [];
  view.innerHTML = html;
  report();
}

// Drawn with the Mail app's own markup and stylesheet (mail.css), so that
// the reader looks like the rest of the message: its locked card here.
const card = (title, text, extra = '') =>
  `<div class="sealed-card"><span class="sealed-icon">${icon('lock')}</span><div class="sealed-text"><b>${title}</b><p>${text}</p>${extra}</div></div>`;

const setupLink = '<a class="tonal" href="setup.html" target="_blank" rel="noopener">Set up this browser</a>';

// OpenPGP.js (about 400 KB) loads only when a message is opened, alongside
// the passkey prompt; which key a message is for is read here directly.
let library = null;
const openpgpLib = () => (library ||= import('./openpgp.min.mjs'));

// The key IDs a message is encrypted to: its Public-Key Encrypted Session Key
// packets (RFC 9580, sections 4.2 and 5.1), read from the armored text.
function recipients(text) {
  const body = text.split(/-----BEGIN PGP MESSAGE-----/)[1]?.split(/-----END PGP MESSAGE-----/)[0];
  if (!body) throw new Error('no message');
  const lines = body.trim().split(/\r?\n/);
  const start = lines.findIndex(l => l.trim() === '');  // after the armor headers
  const b64 = lines.slice(start + 1).filter(l => !l.startsWith('=')).join('');
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
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

// WebCrypto X25519, which keeps the key unreadable even to this page's code:
// Safari 17, Chrome and Edge 133, Firefox 130 and later.
let capable = null;
const canOpen = () => (capable ||= crypto.subtle.importKey('raw', new Uint8Array(32).fill(9), {name: 'X25519'}, false, []).then(() => true, () => false));

async function prepare() {
  if (shownSubject) announce('');
  if (!await canOpen())
    return show(card('End-to-end encrypted', 'This browser is too old to open it safely. Update it (Safari 17, Chrome or Edge 133, Firefox 130 or later), or read it in Thunderbird.'));
  let ids = [];
  try {
    ids = recipients(armored);
  } catch (e) {
    try {
      const openpgp = await openpgpLib();
      const message = await openpgp.readMessage({armoredMessage: armored});
      ids = message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey).map(p => p.publicKeyID.toHex());
    } catch (e2) {
      return show(card('End-to-end encrypted', 'This message could not be read as OpenPGP.'));
    }
  }
  // The sealed keys the Mail app keeps for this mailbox, and any in this
  // site's storage (which Safari does not share with frames).
  const records = [...handedRecords];
  try {
    for (const r of await all()) if (!records.some(h => h.credentialId === r.credentialId)) records.push({...r, rp: r.rp || location.hostname});
  } catch (e) {}
  const fitting = records.filter(r => r.rp === location.hostname && ids.includes(r.keyId));
  const record = fitting[0];
  if (!record) {
    return show(card('End-to-end encrypted',
      records.length ? 'It was encrypted to a key this browser does not hold yet. Open the message "Your encryption key" of that mailbox and click Add to this browser.'
                     : 'This browser has no key for it yet. Open the message "Your encryption key" in your Inbox and click Add to this browser: then messages open here with Touch ID or your fingerprint.',
      `<div class="actions">${setupLink}</div>`));
  }
  const withPin = fitting.some(r => r.pinSalt);
  const pin = withPin ? '<label class="field"><span>PIN</span><input type="password" id="pin" inputmode="numeric" autocomplete="off"></label>' : '';
  show(card('End-to-end encrypted', `Only your key opens it: ${withPin ? 'your PIN and ' : ''}Touch ID, your fingerprint or the screen lock.`,
    `<form id="unlock" class="unlock">${pin}<div class="actions"><button class="filled" type="submit">Open</button></div><p class="alert" role="alert" hidden></p></form>`));
  document.getElementById('unlock').addEventListener('submit', async e => {
    e.preventDefault();
    const button = e.target.querySelector('button'), error = e.target.querySelector('.alert');
    button.disabled = true;
    error.hidden = true;
    try {
      const loading = openpgpLib();  // downloads while the passkey is asked
      let {privateKey, record: used} = await unlock(fitting, document.getElementById('pin')?.value || '');
      const bytes = await open(await loading, armored, privateKey, used.info);
      privateKey = null;  // gone with this page; nothing else holds it
      render(read(bytes));
      bytes.fill(0);
    } catch (err) {
      // A browser that keeps passkeys out of frames, or a touch that was
      // cancelled: inside a message, the Mail app can open the reader in a tab.
      const framed = host === parent;
      error.innerHTML = escape(err.name === 'NotAllowedError' ? 'Cancelled or not allowed here.' : err.name === 'SecurityError' ? 'This browser does not allow passkeys here.' : err.message) +
        (framed ? ' <button class="text" type="button" id="in-tab">Open in a tab</button>' : '');
      error.hidden = false;
      button.disabled = false;
      document.getElementById('in-tab')?.addEventListener('click', () => tell({type: 'reader-tab'}));
    }
  });
}

// HTML from the message, made inert: no scripts, frames, forms, styles that
// load anything, or addresses that could reach out when the message is shown.
function inert(html, files) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.querySelectorAll('script,iframe,frame,object,embed,form,input,button,textarea,select,link,meta,base,svg,math,audio,video,source,track,applet,noscript').forEach(n => n.remove());
  for (const el of doc.querySelectorAll('*')) {
    for (const attr of [...el.attributes]) {
      const name = attr.name.toLowerCase(), value = attr.value.trim();
      if (name.startsWith('on') || name === 'srcset' || name === 'background' || name === 'formaction' || name === 'ping') el.removeAttribute(attr.name);
      else if (name === 'src') {
        const id = value.toLowerCase().startsWith('cid:') ? value.slice(4) : null;
        const file = id && files.find(f => f.id === id && f.type.startsWith('image/') && f.data.length < 4 * 1024 * 1024);
        if (file) el.setAttribute('src', `data:${file.type};base64,${btoa(String.fromCharCode(...file.data))}`);
        else el.removeAttribute('src');
      } else if (name === 'href') {
        if (/^(https?:|mailto:)/i.test(value)) { el.setAttribute('target', '_blank'); el.setAttribute('rel', 'noopener noreferrer'); }
        else el.removeAttribute('href');
      }
    }
  }
  return doc.body.innerHTML;
}

// The address in a From line ("Name <a@b>" or a@b), in lower case.
const addressOf = text => (/<([^<>\s]+@[^<>\s]+)>/.exec(text)?.[1] || /[^\s<>"',;]+@[^\s<>"',;]+/.exec(text)?.[0] || '').toLowerCase();

// Sizes as the Mail app writes them.
const sizeText = n => n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(1)} GB`;
const picture = f => ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(f.type) && f.data.length <= 8 * 1024 * 1024;

function render(m) {
  // Anyone can encrypt to a public key and write any sender inside; the
  // Mail app hands over the sender its server received the message from.
  const inside = addressOf(m.from), other = sentFrom && inside && inside !== sentFrom;
  const warning = other ? `<div class="reader-alert" role="alert">${icon('warning')}<div><b>Check who sent it</b><p>It says it is from ${escape(inside)}, ` +
                          `but it was sent from ${escape(sentFrom)}. Be careful with links and requests in it.</p></div></div>` : '';
  // In a frame of the Mail app the letter is what the Mail app shows of any
  // message, with its markup: the text, pictures and attachments. The
  // subject goes to the title line; the sender is the Mail app's line above.
  const framed = host === parent;
  if (framed) announce(m.subject || '');
  let body;
  if (m.text !== undefined) body = `<pre class="plain">${linkify(m.text)}</pre>`;
  else if (m.html !== undefined) body = '<iframe class="mail-frame" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" title="Message"></iframe>';
  else body = '';
  const files = m.files.filter(f => !(m.html !== undefined && f.id && f.type.startsWith('image/')));
  const thumbs = files.map((f, i) => picture(f) ? `<a class="thumb" data-view="${i}" target="_blank" rel="noopener" title="${escape(f.name)}"><img data-img="${i}" alt="${escape(f.name)}"></a>` : '').join('');
  const list = files.map((f, i) => `<span class="attachment">${icon(picture(f) ? 'image' : 'attach')}<span>${escape(f.name)}</span><small>${sizeText(f.data.length)}</small>` +
    (f.type === 'application/pdf' ? `<a class="icon-button" data-pdf="${i}" target="_blank" rel="noopener" title="Open" aria-label="Open">${icon('open')}</a>` : '') +
    `<a class="icon-button" data-file="${i}" download="${escape(f.name)}" title="Download" aria-label="Download">${icon('download')}</a></span>`).join('');
  const date = m.date && !isNaN(new Date(m.date)) ? new Date(m.date).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : m.date;
  show('<article class="letter">' +
       (framed ? '' : `<div class="letter-head"><span class="badge">${icon('lock')}<span>End-to-end encrypted</span></span>` +
                      `<button class="text" type="button" id="hide">Hide</button></div>` + (m.subject ? `<h2>${escape(m.subject)}</h2>` : '') +
                      `<p class="meta">${escape(other || !m.from ? sentFrom : m.from)}${date ? `<br>${escape(date)}` : ''}</p>`) +
       warning + body + (thumbs ? `<div class="thumbs">${thumbs}</div>` : '') + (list ? `<div class="attachments">${list}</div>` : '') + '</article>');
  // Files only as downloads (or, a PDF or a picture, in the browser's own
  // viewer): nothing from a message runs as a page of this site.
  const blob = (f, type) => { const url = URL.createObjectURL(new Blob([f.data], {type})); urls.push(url); return url; };
  view.querySelectorAll('[data-file]').forEach(a => { a.href = blob(files[Number(a.dataset.file)], 'application/octet-stream'); });
  view.querySelectorAll('[data-pdf]').forEach(a => { a.href = blob(files[Number(a.dataset.pdf)], 'application/pdf'); });
  view.querySelectorAll('[data-view]').forEach(a => {
    const f = files[Number(a.dataset.view)], url = blob(f, f.type);
    a.href = url;
    a.querySelector('img').src = url;
  });
  const frame = view.querySelector('iframe.mail-frame');
  if (frame) {
    frame.addEventListener('load', () => {
      frame.style.height = frame.contentDocument.documentElement.scrollHeight + 'px';
      frame.style.visibility = 'visible';
      report();
    });
    frame.srcdoc = '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'">' +
      '<base target="_blank"><style>' + LETTER_CSS + '</style></head><body>' + inert(m.html, m.files) + '</body></html>';
  }
  document.getElementById('hide')?.addEventListener('click', prepare);
}

// The text goes away when the tab has been in the background for two minutes.
document.addEventListener('visibilitychange', () => {
  clearTimeout(hideTimer);
  if (document.hidden && view.querySelector('.letter')) hideTimer = setTimeout(prepare, 120000);
});

addEventListener('message', e => {
  if (!host || e.source !== host || !MAIL_SITES.includes(e.origin) || e.data?.type !== 'reader-open' || typeof e.data.armored !== 'string') return;
  parentOrigin = e.origin;
  armored = e.data.armored;
  handedRecords = Array.isArray(e.data.records) ? e.data.records.filter(valid).slice(0, 20) : [];
  sentFrom = typeof e.data.from === 'string' && e.data.from.length <= 320 ? addressOf(e.data.from) : '';
  if (!titleChannel && typeof e.data.title === 'string' && /^subject-[\w-]{8,64}$/.test(e.data.title)) {
    titleChannel = new BroadcastChannel(e.data.title);
    titleChannel.onmessage = m => { if (m.data?.type === 'title-ready' && shownSubject) titleChannel.postMessage({subject: shownSubject}); };
  }
  prepare();
});

if (!host) {
  show(card('Mail Reader', 'This page opens end-to-end encrypted messages inside the Mail app. Open a message there.', `<div class="actions">${setupLink}</div>`));
} else {
  if (host !== parent) document.body.classList.replace('embed', 'page');
  host.postMessage({type: 'reader-ready'}, '*');  // carries nothing; the message itself is checked by origin
}
