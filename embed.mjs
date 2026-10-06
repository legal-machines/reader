// A message of the Mail app, end-to-end encrypted. In a frame of a page of
// Mail it shows the encrypted text until the page's hub (hub.mjs) opens the
// message and passes it here on this site's BroadcastChannel, then shows the
// letter in its place; Mail learns only the height to give the frame. In a
// tab of its own (opened by Mail where a browser keeps passkeys out of
// frames) it is handed the message and opens it itself.
// This page makes no network requests at all (index.html, its policy); the
// signing key of a sender's domain comes from dns.html, in a frame (dkim.mjs).

import {all, valid} from './store.mjs';
import {addressOf, escape, linkify} from './mime.mjs';
import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {icon} from './icons.mjs';
import {LETTER_CSS} from './letter.mjs';
import {markFor, tile} from './mark.mjs';
import * as contacts from './contacts.mjs';
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
// (The encrypted text before it is no secret: it keeps the full width and
// its exact height, so it stands exactly where Mail's own copy of it stood.)
function layout() {
  if (!framed) return;
  const w = shown ? WIDTHS.filter(x => x <= innerWidth).pop() || WIDTHS[0] : 0;
  if (w !== laid) { laid = w; view.style.width = w ? w + 'px' : ''; }
}
const report = () => {
  layout();
  const h = document.documentElement.getBoundingClientRect().height;
  tell({type: 'reader-height', height: shown ? Math.ceil(h / 32) * 32 : Math.ceil(h)});
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


// Sizes as the Mail app writes them.
const sizeText = n => n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(1)} GB`;
const picture = f => ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(f.type) && f.data.length <= 8 * 1024 * 1024;
const shownFiles = m => m.files.filter(f => !(m.html !== undefined && f.id && f.type.startsWith('image/') && m.html.includes('cid:' + f.id)));

// Whether the letter is sealed by the mailbox it says it is from.
const sealHolds = m => {
  const sealed = m.seal || {state: 'none'}, inside = addressOf(m.from);
  if (sealed.state === 'none' && m.sender) return sentBy(m) && (!inside || inside === m.sender.from);
  return sealed.state === 'ok' && (!inside || sealed.inside);
};
// A sender outside: signed with the key Seal knows for them, or sent, as it
// stands, by their domain's mail service (DKIM).
const sentBy = m => m.sender.signed?.state === 'ok' && m.sender.signed.by === 'known' || (m.sender.dkim.state === 'pass' && m.sender.dkim.aligned);

const alertBox = (title, text) => `<div class="reader-alert" role="alert">${icon('warning')}<div><b>${title}</b><p>${text}</p></div></div>`;
// A line that vouches for a message ends with Show my mark: Mail could draw
// a line like it beside a message of its own, but not your mark.
const sealLine = (text, weak) => `<p class="seal-line${weak ? ' none' : ''}">${icon(weak ? 'warning' : 'verified_user')}<span>${text}</span>` +
  (weak ? '' : '<button class="mark-check" type="button" hidden title="Only Seal can show your mark: Mail cannot">Show my mark</button>') + '</p>';
const reportLink = '<a href="setup.html#alarm" target="_blank" rel="noopener">Seal page</a>';

// What Seal could check of a message from outside our mailboxes (decrypt.mjs):
// first what proves its writer (their own signature, with the key Seal
// knows), then what proves its way here (their domain's signature).
const grouped = f => { const g = String(f).match(/.{1,4}/g) || []; return g.slice(0, 5).join(' ') + '\u2003' + g.slice(5).join(' '); };
function senderLines(s, when) {
  const d = s.dkim || {state: 'none'}, from = escape(s.from), domain = escape(s.from.split('@')[1] || '');
  if (!s.from) return alertBox('Who sent it is not clear', 'Its From line does not name one plain address, so Seal cannot tell who sent it. Do not trust its links and requests.');
  const signedKnown = s.signed?.state === 'ok' && s.signed.by === 'known', signedNew = s.signed?.state === 'ok' && s.signed.by === 'new';
  const domainOk = d.state === 'pass' && d.aligned, tampered = d.state === 'fail' && ['body', 'signature', 'from', 'part'].includes(d.why);
  // Encrypted text quoted or forwarded inside a message: the message around
  // it, and its domain's signature, say nothing about who wrote it.
  if (s.quoted) {
    const line = s.signed?.state === 'ok' && s.signed.by === 'known' ? sealLine(`Signed with the key of ${from}${s.checked ? ', checked with them' : ''}`) : '';
    return line + alertBox('Quoted or forwarded', 'The encrypted text is only part of this message: someone quoted or forwarded it. ' +
      (line ? 'Its signature shows who wrote it; the rest of the message, Seal cannot vouch for.' : 'Who wrote it is not known, whatever the message around it says.'));
  }
  if (s.signed?.state === 'bad') return alertBox('Its signature does not hold', `It says it is from ${from}, but its signature was not made with their key, or the text was changed after. Do not trust its links and requests.`);
  let out = '';
  if (tampered && !signedKnown)
    return alertBox('Not as its sender sent it', `${domain} signs the mail it sends, and this message does not match the signature: it was changed on the way, or made up. Do not trust who it says it is from, nor its links and requests.`);
  // Someone whose key Seal knows, in a message signed neither with it nor by
  // their domain: what a mail server writing in their name would send.
  if (!signedKnown && !signedNew && !domainOk && s.fingerprint)
    return alertBox(`Not signed by ${from}`, `Seal knows their key, and this message carries neither their signature nor their domain's` +
      (d.state === 'unknown' ? ' that Seal could check now' : '') + '. It may not be from them: do not trust its links and requests, and ask them another way.');
  if (signedKnown || domainOk) {
    const parts = [];
    if (signedKnown) parts.push(`Signed with the key of ${from}${s.checked ? ', checked with them' : ''}`);
    if (domainOk) parts.push(`${signedKnown ? 'sent' : 'Sent'} by the mail of ${escape(d.domain)}`);
    out += sealLine(parts.join('; ') + escape(when));
    if (tampered) out += alertBox('Changed on the way', `The text is theirs, signed with their key, but something around it was changed after it left the mail of ${domain}: only a mail server on the way could do that. Report it on the ${reportLink}.`);
    if (d.state === 'pass' && !d.aligned && !signedKnown) out += alertBox('Signed by another domain', `It says it is from ${from}, but ${escape(d.domain)} signed it. That says nothing about who wrote it.`);
  } else if (d.state === 'pass') {
    out += alertBox('Signed by another domain', `It says it is from ${from}, but ${escape(d.domain)} signed it. That says nothing about who wrote it.`);
  } else if (d.state === 'unknown') {
    out += sealLine(`Who sent it could not be checked now: ${d.why === 'browser' ? 'this browser cannot check its signature' : 'no answer from DNS'}. Open it again later`, true);
  } else {
    out += sealLine('Not signed in a way Seal can check: anyone who has your public key, the mail server included, could have written it', true);
  }
  // A new key from their mail: used only once you accept it, here, by the
  // fingerprint shown, after asking them another way.
  if (s.change)
    out += `<div class="reader-alert new-key" role="alert" data-fingerprint="${escape(s.change)}">${icon('warning')}<div><b>${from} has a new key</b>` +
      `<p>Their mail sent a key that differs from the one Seal knows${signedNew ? ', and this message is signed with it' : ''}. Seal goes on encrypting to the old key until you accept the new one. ` +
      `Ask them first, not by email, whether they changed it, and read them its fingerprint.</p><p class="fingerprint">${escape(grouped(s.change))}</p>` +
      `<div class="actions"><button class="text" type="button" data-accept-key>Use the new key</button><button class="text" type="button" data-decline-key>Keep the old one</button></div></div></div>`;
  else if (s.learned === 'new')
    out += sealLine(`Seal now knows the key of ${from}: what you write back to them can be encrypted end to end`);
  return out;
}

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
  const sealed = m.seal || {state: 'none', domain: '', inside: false};
  // With the time sealed inside, to the minute, so an old message passed off
  // as new shows its own: today the hour, otherwise the day and the hour,
  // and the year when it is not this one.
  const d = m.date && !isNaN(new Date(m.date)) ? new Date(m.date) : null, now = new Date();
  const time = d ? d.toLocaleTimeString(undefined, {timeStyle: 'short'}) : '';
  const sealedOn = !d ? '' : d.toDateString() === now.toDateString() ? ' at ' + time
    : ' on ' + d.toLocaleDateString(undefined, d.getFullYear() === now.getFullYear() ? {day: 'numeric', month: 'short'} : {day: 'numeric', month: 'short', year: 'numeric'}) + ' at ' + time;
  const verified = sealed.state === 'none' && m.sender ? senderLines(m.sender, sealedOn)
    : sealed.state === 'ok' && (!inside || sealed.inside)
    ? sealLine(`Sealed by ${escape(inside || 'a mailbox at ' + sealed.domain)}${escape(sealedOn)}`)
    : sealed.state === 'ok' ? `<div class="reader-alert" role="alert">${icon('warning')}<div><b>Written with someone else's key</b><p>It says it is from ${escape(inside)}, ` +
                              `but it was sealed with the key of another mailbox, at ${escape(sealed.domain)}.</p></div></div>`
    : sealed.state === 'bad' ? `<div class="reader-alert" role="alert">${icon('warning')}<div><b>Its seal does not hold</b><p>Do not trust who it says it is from, ` +
                               `nor its links and requests.</p></div></div>`
    // No seal: encrypted to your public key, which anyone can do, the mail
    // server among them (it encrypts mail between our mailboxes on arrival).
    : `<p class="seal-line none">${icon('warning')}<span>Not sealed: anyone who has your public key, the mail server included, could have written it</span></p>`;
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
  // End to end only with a seal that holds; otherwise it was encrypted, but
  // nothing shows by whom.
  const head = framed ? '' : `<div class="letter-head">` + (sealHolds(m)
      ? `<span class="badge">${icon('lock')}<span>End-to-end encrypted</span></span>` : `<span class="badge plain">${icon('lock')}<span>Encrypted</span></span>`) + '</div>' +
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
  let loaded = Promise.resolve();
  if (frame) {
    loaded = new Promise(done => {
      frame.addEventListener('load', () => {
        frame.style.height = frame.contentDocument.documentElement.scrollHeight + 'px';
        frame.style.visibility = 'visible';
        report();
        done();
      });
      setTimeout(done, 800);
    });
    frame.srcdoc = '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'">' +
      '<base target="_blank"><style>' + LETTER_CSS + '</style></head><body>' + inert(m.html, m.files) + '</body></html>';
  }
  return loaded;
}

// Show my mark: your mark, for ten seconds, beside a line that vouches for
// the message, on a press of yours, while this frame has the keyboard and
// the whole line is on the screen, so a page cannot cut the frame down to
// the mark and set it beside a line of its own; where the browser can tell
// (Chrome), only while nothing covers or fades it.
const lines = new Map();  // line -> {whole, visible}
let lineWatch = null, markTimer = 0;
function hideMarks() {
  clearTimeout(markTimer);
  for (const b of view.querySelectorAll('.mark-check[data-shown]')) { b.textContent = 'Show my mark'; delete b.dataset.shown; b.removeAttribute('aria-label'); }
  report();
}
function markChecks() {
  const m = shown?.keyId && markFor([shown.keyId]);
  try {
    lineWatch ||= new IntersectionObserver(entries => {
      for (const en of entries) {
        lines.set(en.target, {whole: en.intersectionRatio >= 0.98, visible: typeof en.isVisible === 'boolean' ? en.isVisible : null});
        if (!lines.get(en.target).whole || lines.get(en.target).visible === false) hideMarks();
      }
    }, {trackVisibility: true, delay: 100, threshold: [0, 0.5, 0.9, 0.98, 1]});
  } catch (e) {}
  for (const b of view.querySelectorAll('.mark-check')) {
    if (!m || !lineWatch) { b.remove(); continue; }
    const line = b.closest('.seal-line');
    lineWatch.observe(line);
    b.hidden = false;
    b.addEventListener('click', e => {
      const seen = lines.get(line);
      if (!e.isTrusted || !document.hasFocus() || !seen?.whole || seen.visible === false) return;
      b.innerHTML = tile(m.mark, ' data-small');
      b.dataset.shown = '';
      b.setAttribute('aria-label', 'Your mark');
      report();
      clearTimeout(markTimer);
      markTimer = setTimeout(hideMarks, 10000);
    });
  }
}
// Use the new key / Keep the old one, under the letter that brought it: on a
// press of yours, while this frame has the keyboard and the whole notice is
// on the screen (in Chrome, not covered either).
function keyChoices(m) {
  for (const box of view.querySelectorAll('.new-key')) {
    lineWatch?.observe(box);
    const ok = e => { const seen = lines.get(box); return e.isTrusted && document.hasFocus() && (!lineWatch || (seen?.whole && seen.visible !== false)); };
    const done = text => { box.outerHTML = sealLine(text); report(); };
    box.querySelector('[data-accept-key]').addEventListener('click', async e => {
      if (!ok(e)) return;
      if (await contacts.acceptChange(m.sender.from, box.dataset.fingerprint)) done(`Seal now encrypts to the new key of ${escape(m.sender.from)}`);
    });
    box.querySelector('[data-decline-key]').addEventListener('click', async e => {
      if (!ok(e)) return;
      await contacts.declineChange(m.sender.from);
      done(`Seal keeps the key it knew for ${escape(m.sender.from)}`);
    });
  }
}
addEventListener('blur', hideMarks);
document.addEventListener('visibilitychange', hideMarks);

// The encrypted text gives way to the letter in Material 3's fade through:
// the letter is laid out first, unseen, so the frame takes its new height
// once; then the encrypted text fades out and the letter fades in, growing
// a little, on opacity and transform alone, which the graphics card draws.
async function reveal(m) {
  const before = view.querySelector('.cipher');
  for (const u of urls) URL.revokeObjectURL(u);
  urls = [];
  const stage = document.createElement('div');
  stage.className = 'stage';
  stage.innerHTML = letterHtml(m);
  const moving = before && !still.matches;
  if (moving) {
    stage.classList.add('pending');
    before.classList.add('held');
    view.replaceChildren(stage, before);
  } else view.replaceChildren(stage);
  await fill(m);
  markChecks();
  if (m.sender) keyChoices(m);
  report();
  // Mail's header says "End-to-end encrypted" only for a letter whose seal
  // holds; until the reader says so, it says "Encrypted".
  tell({type: 'reader-seal', sealed: sealHolds(m)});
  if (!moving) return;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    before.classList.add('leaving');
    before.addEventListener('animationend', () => before.remove(), {once: true});
    stage.classList.remove('pending');
    stage.classList.add('arriving');
  }));
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
let armored = null, handedRecords = [], sentFrom = '', handedRaw;
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
  const m = await openWith(armored, info, {raw: handedRaw, sentFrom});
  if (!handedRaw) m.sentFrom ||= sentFrom;  // with the whole message, its own From only
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
  } else if (d.type === 'reader-open' && !framed && armored === null && typeof d.armored === 'string') {  // once: the letter checked stays the letter shown
    armored = d.armored;
    handedRecords = Array.isArray(d.records) ? d.records.filter(valid).slice(0, 20) : [];
    sentFrom = typeof d.from === 'string' && d.from.length <= 320 ? addressOf(d.from) : '';
    handedRaw = d.raw instanceof Uint8Array && d.raw.length <= 40e6 ? d.raw : undefined;
    prepare();
  }
});

if (!host) {
  show(card('Seal', 'This page opens end-to-end encrypted messages inside the Mail app. Open a message there.', `<div class="actions">${setupLink}</div>`));
} else {
  if (!framed) {
    document.body.classList.replace('embed', 'page');
    vault.watch(open => { if (!open && shown) { shown = null; view.replaceChildren(); prepare(); } });
  }
  host.postMessage({type: 'reader-ready'}, '*');  // carries nothing; the message itself is checked by origin
}
