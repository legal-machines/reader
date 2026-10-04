// The reader inside a message of the Mail app: the mail page hands it the
// encrypted message (which its server has anyway) and gets back only the
// height to give the frame. The text is opened and shown here, in a frame
// of another site, which the mail page cannot look into; this page may
// make no network requests at all (index.html, its Content-Security-Policy).

import * as openpgp from './openpgp.min.mjs';
import {open} from './sealed-core.mjs';
import {all, unlock} from './store.mjs';
import {read, escape, linkify} from './mime.mjs';
import {MAIL_SITES} from './sites.mjs';

const view = document.getElementById('view');
const LOCK = '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>';
let parentOrigin = null, armored = null, hideTimer = null, urls = [];
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

async function prepare() {
  let ids = [];
  try {
    const message = await openpgp.readMessage({armoredMessage: armored});
    ids = message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey).map(p => p.publicKeyID.toHex());
  } catch (e) {
    return show(card('End-to-end encrypted', 'This message could not be read as OpenPGP.'));
  }
  const records = await all();
  const record = records.find(r => ids.includes(r.keyId));
  if (!record) {
    return show(card('End-to-end encrypted',
      records.length ? 'The key on this browser does not open this message; it was encrypted to another key.'
                     : 'This browser has no key for it yet. Set it up once, with your key file, and messages open here with Touch ID.',
      `<div class="actions">${setupLink}</div>`));
  }
  const pin = record.pinSalt ? '<label class="field"><span>Device PIN</span><input type="password" id="pin" inputmode="numeric" autocomplete="off" required></label>' : '';
  show(card('End-to-end encrypted', `Only your key opens it, and on this browser your key opens with ${record.pinSalt ? 'your PIN and ' : ''}Touch ID or your device's screen lock.`,
    `<form id="unlock" class="unlock">${pin}<div class="actions"><button class="filled" type="submit">Open</button></div><p class="error" role="alert" hidden></p></form>`));
  document.getElementById('unlock').addEventListener('submit', async e => {
    e.preventDefault();
    const button = e.target.querySelector('button'), error = e.target.querySelector('.error');
    button.disabled = true;
    error.hidden = true;
    try {
      let key = await unlock(record, document.getElementById('pin')?.value || '');
      const bytes = await open(openpgp, armored, key, record.info);
      key = null;  // gone with this page; nothing else holds it
      render(read(bytes));
      bytes.fill(0);
    } catch (err) {
      error.textContent = err.name === 'NotAllowedError' ? 'Touch ID was cancelled.' : err.message;
      error.hidden = false;
      button.disabled = false;
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

function render(m) {
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
       `<p class="meta">${escape(m.from)}${date ? `<br>${escape(date)}` : ''}</p>${body}` +
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
  prepare();
});

if (!host) {
  show(card('Mail Reader', 'This page opens end-to-end encrypted messages inside the Mail app. Open a message there.', `<div class="actions">${setupLink}</div>`));
} else {
  if (host !== parent) document.body.classList.replace('embed', 'page');
  host.postMessage({type: 'reader-ready'}, '*');  // carries nothing; the message itself is checked by origin
}
