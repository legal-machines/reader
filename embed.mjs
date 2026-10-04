// A message of the Mail app, end-to-end encrypted. In a frame of a page of
// Mail it shows the encrypted text until the page's hub (hub.mjs) opens the
// message and passes it here on this site's BroadcastChannel, then shows the
// letter in its place; Mail learns only the height to give the frame. In a
// tab of its own (opened by Mail where a browser keeps passkeys out of
// frames) it is handed the message and opens it itself.
// This page may make no network requests at all (index.html, its policy).

import {all, valid} from './store.mjs';
import {escape, linkify} from './mime.mjs';
import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {icon} from './icons.mjs';
import {LETTER_CSS} from './letter.mjs';
import * as vault from './vault.mjs';
import {canOpen, openWith, openpgpLib, recipientsOf} from './decrypt.mjs';

const view = document.getElementById('view');
const host = parent !== window ? parent : window.opener;
const framed = host === parent;
let parentOrigin = null, urls = [], cipher = '', slot = null, channel = null, shown = null, asked = false;
const still = matchMedia('(prefers-reduced-motion: reduce)');

const tell = message => { if (parentOrigin && framed) parent.postMessage(message, parentOrigin); };
// What Mail learns of a letter is the room it takes, and Mail sets the
// frame's width: were the letter laid out at any width, Mail could narrow
// the frame step by step and learn from the heights where its lines break,
// word by word. So the letter takes one of a few fixed widths, the widest
// that fits, and its height goes out in steps of 32 pixels.
const WIDTHS = [280, 320, 360, 400, 480, 560, 640, 720, 800, 960, 1120, 1280];
let laid = 0;
function layout() {
  if (!framed) return;
  const w = WIDTHS.filter(x => x <= innerWidth).pop() || WIDTHS[0];
  if (w !== laid) { laid = w; view.style.width = w + 'px'; }
}
const report = () => {
  layout();
  tell({type: 'reader-height', height: Math.ceil(document.documentElement.getBoundingClientRect().height / 32) * 32});
};
new ResizeObserver(report).observe(document.documentElement);

function show(html) {
  for (const u of urls) URL.revokeObjectURL(u);
  urls = [];
  view.innerHTML = html;
  report();
}

// The encrypted text itself, as Mail draws it before the message is open.
const cipherBlock = () => `<pre class="cipher" aria-label="Encrypted text">${escape(cipher)}</pre>`;

// Drawn with the Mail app's own markup and stylesheet (mail.css), so that
// the reader looks like the rest of the message: its locked card here.
const card = (title, text, extra = '') =>
  `<div class="sealed-card"><span class="sealed-icon">${icon('lock')}</span><div class="sealed-text"><b>${title}</b><p>${text}</p>${extra}</div></div>`;
const setupLink = '<a class="tonal" href="setup.html" target="_blank" rel="noopener">Set up this browser</a>';

// HTML from the message, made inert: no scripts, frames, forms, styles that
// load anything, or addresses that could reach out when the message is shown.
function inert(html, files) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  // template too: a declarative shadow root would come alive in the letter's frame.
  doc.querySelectorAll('script,iframe,frame,object,embed,form,input,button,textarea,select,link,meta,base,svg,math,audio,video,source,track,applet,noscript,template,slot').forEach(n => n.remove());
  for (const el of doc.querySelectorAll('*')) {
    for (const attr of [...el.attributes]) {
      const name = attr.name.toLowerCase(), value = attr.value.trim();
      if (name.startsWith('on') || name === 'srcset' || name === 'background' || name === 'formaction' || name === 'ping') el.removeAttribute(attr.name);
      else if (name === 'src') {
        const id = value.toLowerCase().startsWith('cid:') ? value.slice(4) : null;
        const file = id && files.find(f => f.id === id && f.type.startsWith('image/') && f.data.length < 4 * 1024 * 1024);
        if (file) el.setAttribute('src', `data:${file.type};base64,${base64(file.data)}`);
        else el.removeAttribute('src');
      } else if (name === 'href') {
        if (/^(https?:|mailto:)/i.test(value)) { el.setAttribute('target', '_blank'); el.setAttribute('rel', 'noopener noreferrer'); }
        else el.removeAttribute('href');
      }
    }
  }
  return doc.body.innerHTML;
}
function base64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(s);
}

// The address in a From line ("Name <a@b>" or a@b), in lower case.
const addressOf = text => (/<([^<>\s]+@[^<>\s]+)>/.exec(text)?.[1] || /[^\s<>"',;]+@[^\s<>"',;]+/.exec(text)?.[0] || '').toLowerCase();

// Sizes as the Mail app writes them.
const sizeText = n => n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(1)} GB`;
const picture = f => ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(f.type) && f.data.length <= 8 * 1024 * 1024;
const shownFiles = m => m.files.filter(f => !(m.html !== undefined && f.id && f.type.startsWith('image/') && m.html.includes('cid:' + f.id)));

// The letter, as Mail shows any message: its text, pictures and attachments.
function letterHtml(m) {
  // Anyone can encrypt to a public key and write any sender inside; the
  // Mail app hands over the sender its server received the message from.
  const sentFrom = m.sentFrom || '';
  const inside = addressOf(m.from), other = sentFrom && inside && inside !== sentFrom;
  const warning = other ? `<div class="reader-alert" role="alert">${icon('warning')}<div><b>Check who sent it</b><p>It says it is from ${escape(inside)}, ` +
                          `but it was sent from ${escape(sentFrom)}. Be careful with links and requests in it.</p></div></div>` : '';
  // The sender's seal (seal.mjs): written with the key of a mailbox here,
  // which no one else holds, or a seal that does not hold.
  const sealed = m.seal || {state: 'none', addresses: []};
  // With the date sealed inside, so an old message passed off as new shows its own.
  const sealedOn = m.date && !isNaN(new Date(m.date)) ? ', ' + new Date(m.date).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : '';
  const verified = sealed.state === 'ok' && (!inside || sealed.addresses.includes(inside))
    ? `<p class="seal-line">${icon('verified_user')}<span>Sealed with the key of ${escape(inside || sealed.addresses[0])}${escape(sealedOn)}</span></p>`
    : sealed.state === 'ok' ? `<div class="reader-alert" role="alert">${icon('warning')}<div><b>Written with someone else's key</b><p>It says it is from ${escape(inside)}, ` +
                              `but it was sealed with the key of ${escape(sealed.addresses.join(', '))}.</p></div></div>`
    : sealed.state === 'bad' ? `<div class="reader-alert" role="alert">${icon('warning')}<div><b>Its seal does not hold</b><p>Do not trust who it says it is from, ` +
                               `nor its links and requests.</p></div></div>` : '';
  let body;
  if (m.html !== undefined) body = '<iframe class="mail-frame" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" title="Message"></iframe>';
  else if (m.text !== undefined) body = `<pre class="plain">${linkify(m.text)}</pre>`;
  else body = '';
  const files = shownFiles(m);
  const thumbs = files.map((f, i) => picture(f) ? `<a class="thumb" data-view="${i}" target="_blank" rel="noopener" title="${escape(f.name)}"><img data-img="${i}" alt="${escape(f.name)}"></a>` : '').join('');
  const list = files.map((f, i) => `<span class="attachment">${icon(picture(f) ? 'image' : 'attach')}<span>${escape(f.name)}</span><small>${sizeText(f.data.length)}</small>` +
    (f.type === 'application/pdf' ? `<a class="icon-button" data-pdf="${i}" target="_blank" rel="noopener" title="Open" aria-label="Open">${icon('open')}</a>` : '') +
    `<a class="icon-button" data-file="${i}" download="${escape(f.name)}" title="Download" aria-label="Download">${icon('download')}</a></span>`).join('');
  const date = m.date && !isNaN(new Date(m.date)) ? new Date(m.date).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : m.date;
  const head = framed ? '' : `<div class="letter-head"><span class="badge">${icon('lock')}<span>End-to-end encrypted</span></span></div>` +
    (m.subject ? `<h2>${escape(m.subject)}</h2>` : '') + `<p class="meta">${escape(other || !m.from ? sentFrom : m.from)}${date ? `<br>${escape(date)}` : ''}</p>`;
  return '<article class="letter">' + head + verified + warning + body + (thumbs ? `<div class="thumbs">${thumbs}</div>` : '') +
         (list ? `<div class="attachments">${list}</div>` : '') + '</article>';
}

function fill(m) {
  // Files only as downloads (or, a PDF or a picture, in the browser's own
  // viewer): nothing from a message runs as a page of this site.
  const files = shownFiles(m);
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
}

// The encrypted text gives way to the letter: its characters stir for a
// moment, and the letter is uncovered from the top as they fade.
function reveal(m) {
  const before = view.querySelector('.cipher');
  for (const u of urls) URL.revokeObjectURL(u);
  urls = [];
  const stage = document.createElement('div');
  stage.className = 'stage';
  stage.innerHTML = letterHtml(m);
  if (before && !still.matches) {
    before.classList.add('leaving');
    stage.querySelector('.letter').classList.add('arriving');
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const original = before.textContent, start = performance.now();
    const stir = now => {
      if (!before.isConnected) return;
      if (now - start > 450) return before.remove();  // Material 3 long1
      before.textContent = original.replace(/\S/g, c => Math.random() < 0.4 ? chars[Math.random() * 64 | 0] : c);
      requestAnimationFrame(stir);
    };
    requestAnimationFrame(stir);
    view.replaceChildren(stage, before);
  } else view.replaceChildren(stage);
  fill(m);
  report();
}

function locked() {
  shown = null;
  show(cipherBlock());
}

// In a frame of Mail: told which message it is, by the page.
function join(name, mySlot) {
  slot = mySlot;
  channel = new BroadcastChannel(name);
  channel.onmessage = e => {
    const d = e.data || {};
    if (d.type === 'hub-here') { if (asked) channel.postMessage({type: 'want', slot, kind: 'view'}); return; }
    if (d.type === 'locked') { if (shown && (!d.slot || d.slot === slot)) locked(); return; }
    if (d.slot !== slot) return;
    if (d.type === 'open' && d.model) {
      d.model.files ||= [];
      shown = {keyId: d.keyId};
      reveal(d.model);
    } else if (d.type === 'failed') {
      show(cipherBlock() + card('End-to-end encrypted', d.message && d.message !== 'locked'
        ? escape(d.message) : 'It was encrypted to a key this browser does not hold yet. Open the message "Your encryption key" of that mailbox and click Add to this browser.'));
    }
  };
  // The letter is asked for once this frame is on the screen, not before:
  // Mail cannot have letters opened in frames nobody sees.
  new IntersectionObserver(entries => {
    if (asked || !entries.some(e => e.isIntersecting)) return;
    asked = true;
    channel.postMessage({type: 'want', slot, kind: 'view'});
  }).observe(document.documentElement);
  addEventListener('pointerdown', () => channel.postMessage({type: 'use'}), {passive: true});
}

// In a tab of its own: the whole message is handed over, and it is opened here.
let armored = null, handedRecords = [], sentFrom = '';
async function prepare() {
  if (!await canOpen())
    return show(card('End-to-end encrypted', 'This browser is too old to open it safely. Update it (Safari 17, Chrome or Edge 133, Firefox 130 or later), or read it in Thunderbird.'));
  const ids = await recipientsOf(armored).catch(() => null);
  if (!ids) return show(card('End-to-end encrypted', 'This message could not be read as OpenPGP.'));
  const records = [...handedRecords];
  try {
    for (const r of await all()) if (!records.some(h => h.credentialId === r.credentialId)) records.push({...r, rp: r.rp || location.hostname});
  } catch (e) {}
  const fitting = records.filter(r => r.rp === location.hostname && ids.includes(r.keyId));
  const s = await vault.state();
  const open = ids.find(id => s.keyIds.includes(id));
  if (open) return openHere(s.infos[open], open);
  if (!fitting.length) {
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
      openpgpLib();  // downloads while the passkey is asked
      const record = await vault.unlock(fitting, document.getElementById('pin')?.value || '', 15);
      const st = await vault.state();
      await openHere(st.infos[record.keyId], record.keyId);
    } catch (err) {
      error.textContent = err.name === 'NotAllowedError' ? 'Cancelled or not allowed here.' : err.name === 'SecurityError' ? 'This browser does not allow passkeys here.' : err.message;
      error.hidden = false;
      button.disabled = false;
    }
  });
}
async function openHere(info, keyId) {
  const m = await openWith(armored, info);
  m.sentFrom = sentFrom;
  shown = {keyId};
  view.replaceChildren();
  reveal(m);
}

addEventListener('message', e => {
  if (!host || e.source !== host || !MAIL_SITES.includes(e.origin)) return;
  const d = e.data || {};
  parentOrigin = e.origin;
  if (Number.isFinite(d.vw)) widths(d.vw);
  if (d.type === 'view-init' && framed && !channel && typeof d.channel === 'string' && /^page-[\w-]{8,64}$/.test(d.channel) &&
      typeof d.slot === 'string' && d.slot.length <= 64) {
    cipher = typeof d.cipher === 'string' ? d.cipher.slice(0, 2000) : '';
    show(cipherBlock());
    join(d.channel, d.slot);
  } else if (d.type === 'reader-open' && !framed && typeof d.armored === 'string') {
    armored = d.armored;
    handedRecords = Array.isArray(d.records) ? d.records.filter(valid).slice(0, 20) : [];
    sentFrom = typeof d.from === 'string' && d.from.length <= 320 ? addressOf(d.from) : '';
    prepare();
  }
});

if (!host) {
  show(card('Mail Reader', 'This page opens end-to-end encrypted messages inside the Mail app. Open a message there.', `<div class="actions">${setupLink}</div>`));
} else {
  if (!framed) {
    document.body.classList.replace('embed', 'page');
    vault.watch(open => { if (!open && shown) { shown = null; view.replaceChildren(); prepare(); } });
  }
  host.postMessage({type: 'reader-ready'}, '*');  // carries nothing; the message itself is checked by origin
}
