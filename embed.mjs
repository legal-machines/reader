// The reader inside a message of the Mail app: the mail page hands it the
// encrypted message (which its server has anyway) and gets back only the
// height to give the frame. The text is opened and shown here, in a frame
// of another site, which the mail page cannot look into; this page may
// make no network requests at all (index.html, its Content-Security-Policy).

import {open} from './sealed-core.mjs';
import {all, unlock, valid} from './store.mjs';
import {read, escape, linkify} from './mime.mjs';
import {MAIL_SITES} from './sites.mjs';

const view = document.getElementById('view');
const LOCK = '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>';
let parentOrigin = null, armored = null, handedRecords = [], sentFrom = '', hideTimer = null, urls = [];
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

const card = (title, text, extra = '') =>
  `<div class="sealed"><span class="seal-icon">${LOCK}</span><div class="seal-text"><b>${title}</b><p>${text}</p>${extra}</div></div>`;

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
    `<form id="unlock" class="unlock">${pin}<div class="actions"><button class="filled" type="submit">Open</button></div><p class="error" role="alert" hidden></p></form>`));
  document.getElementById('unlock').addEventListener('submit', async e => {
    e.preventDefault();
    const button = e.target.querySelector('button'), error = e.target.querySelector('.error');
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

function render(m) {
  // Anyone can encrypt to a public key and write any sender inside; the
  // Mail app hands over the sender its server received the message from.
  const inside = addressOf(m.from), other = sentFrom && inside && inside !== sentFrom;
  const warning = other ? `<p class="warn">It says it is from ${escape(inside)}, but it was sent from ${escape(sentFrom)}. Be careful with links and requests in it.</p>` : '';
  const date = m.date && !isNaN(new Date(m.date)) ? new Date(m.date).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : m.date;
  let body;
  if (m.text !== undefined) body = `<div class="body-text">${linkify(m.text)}</div>`;
  else if (m.html !== undefined) body = '<iframe class="html" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" title="Message"></iframe>';
  else body = '<p class="hint">This message has no text.</p>';
  const files = m.files.filter(f => !(m.html !== undefined && f.id && f.type.startsWith('image/')));
  const list = files.map((f, i) => `<li><a data-file="${i}" download="${escape(f.name)}">${escape(f.name)}</a><small>${f.data.length < 1024 ? f.data.length + ' B' : Math.round(f.data.length / 1024) + ' KB'}</small></li>`).join('');
  show(`<article class="letter"><div class="letter-head"><span class="badge">${LOCK}<span>End-to-end encrypted</span></span>` +
       `<button class="text" type="button" id="hide">Hide</button></div>` +
       (m.subject ? `<h2>${escape(m.subject)}</h2>` : '') +
       `<p class="meta">${escape(other || !m.from ? sentFrom : m.from)}${date ? `<br>${escape(date)}` : ''}</p>${warning}${body}` +
       (list ? `<ul class="files">${list}</ul>` : '') + '</article>');
  view.querySelectorAll('[data-file]').forEach(a => {
    const f = files[Number(a.dataset.file)], url = URL.createObjectURL(new Blob([f.data], {type: f.type}));
    urls.push(url);
    a.href = url;
  });
  const frame = view.querySelector('iframe.html');
  if (frame) {
    frame.addEventListener('load', () => { frame.style.height = frame.contentDocument.documentElement.scrollHeight + 'px'; report(); });
    frame.srcdoc = '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'">' +
      '<style>body{margin:0;font:14px/1.5 system-ui,-apple-system,sans-serif;color:CanvasText;background:transparent;overflow-wrap:anywhere}img{max-width:100%;height:auto}</style>' +
      '</head><body>' + inert(m.html, m.files) + '</body></html>';
  }
  document.getElementById('hide').addEventListener('click', prepare);
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
  prepare();
});

if (!host) {
  show(card('Mail Reader', 'This page opens end-to-end encrypted messages inside the Mail app. Open a message there.', `<div class="actions">${setupLink}</div>`));
} else {
  if (host !== parent) document.body.classList.replace('embed', 'page');
  host.postMessage({type: 'reader-ready'}, '*');  // carries nothing; the message itself is checked by origin
}
