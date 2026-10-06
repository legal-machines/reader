// Setting up a browser: the secret key file is opened here with its
// passphrase, its decryption subkey is sealed under a new passkey and the
// device PIN, and only the sealed copy is kept (store.mjs).

import * as openpgp from './openpgp.min.mjs';
import {extract, pkcs8Of} from './sealed-core.mjs';
import {all, keep, newPasskey, remove} from './store.mjs';
import {known, markOf, remember, setExplained, tile} from './mark.mjs';
import {hold, lock} from './vault.mjs';
import {clear as clearAlarm, raise, raised} from './alarm.mjs';
import {escape} from './mime.mjs';
import {icon} from './icons.mjs';
import {MAIL_SITES} from './sites.mjs';
import {KEYS} from './keys.mjs';

if (window.top !== window) {
  // Never inside another page: the key file and the PIN are typed only here,
  // with this site's address in the address bar.
  document.body.textContent = 'Open this page on its own.';
  throw new Error('framed');
}

const form = document.getElementById('setup'), error = form.querySelector('.error'), done = document.querySelector('.done');
// The key can come from the Mail app instead of a file: its key message
// (Add to this browser) opens this tab and hands over the key, still locked
// with its passphrase. Only the Mail app's own addresses are listened to.
// A page that opened this tab can still change it, so nothing secret is typed
// here: Continue opens this page again in a tab no page holds, which takes
// the key over through this site's own storage (for minutes, still locked),
// and this tab only hands the finished record back to the Mail app.
const HANDOFF = 'seal-setup-handoff';
const relay = new BroadcastChannel('seal-setup');
const showHanded = () => {
  document.getElementById('file-field').hidden = true;
  document.getElementById('file').required = false;
  document.getElementById('handed').hidden = false;
};
let handed = null, mailOrigin = null, relayId = null, createFor = null;
// An address of one of our domains, as the Mail app names its mailbox.
const OURS = /^[a-z0-9._%+-]{1,64}@(legalmachines\.org|dzyza\.com)$/;
if (window.opener) {
  form.hidden = true;
  const card = document.getElementById('continue');
  card.hidden = false;
  addEventListener('message', e => {
    if (e.source !== window.opener || !MAIL_SITES.includes(e.origin)) return;
    if (e.data?.type === 'reader-hello') {  // opened by the Mail app, without a key; perhaps to create one for its mailbox
      mailOrigin = e.origin;
      const c = e.data.create;
      if (c && typeof c.address === 'string' && OURS.test(c.address.toLowerCase()))
        createFor = {address: c.address.toLowerCase(), name: typeof c.name === 'string' ? c.name.replace(/[\x00-\x1f<>]/g, '').slice(0, 80) : ''};
      return;
    }
    if (e.data?.type !== 'reader-key' || typeof e.data.armored !== 'string' || e.data.armored.length > 200000) return;
    mailOrigin = e.origin;
    handed = e.data.armored;
  });
  window.opener.postMessage({type: 'reader-ready'}, '*');
  document.getElementById('continue-button').addEventListener('click', e => {
    if (!e.isTrusted) return;
    const id = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');
    try { localStorage.setItem(HANDOFF, JSON.stringify({id, armored: handed, create: createFor, at: Date.now()})); } catch (err) {}
    relay.onmessage = m => {
      if (m.data?.type !== 'sealed' || m.data.id !== id) return;
      // Whether Mail kept the key, for the new tab, which offers Connect to
      // Mail when it did not (the mail page may have moved on meanwhile).
      const answer = kept => { relay.postMessage({type: kept ? 'kept' : 'not-kept', id}); window.close(); };
      if (!mailOrigin || !window.opener) return answer(false);
      addEventListener('message', e => {
        if (e.source === window.opener && e.origin === mailOrigin && ['reader-kept', 'reader-not-kept'].includes(e.data?.type)) answer(e.data.type === 'reader-kept');
      });
      setTimeout(() => answer(false), 8000);
      // A key made in the new tab: its public half and its copy locked with
      // the recovery code, for the mailbox (only the code opens that copy).
      const k = m.data.newKey;
      if (k) window.opener.postMessage({type: 'reader-newkey', publicKey: k.publicKey, lockedKey: k.lockedKey, fingerprint: k.fingerprint}, mailOrigin);
      window.opener.postMessage({type: 'reader-sealed', record: m.data.record}, mailOrigin);
    };
    window.open(`${location.origin}${location.pathname}#handoff=${id}`, '_blank', 'noopener');
    card.querySelector('p').textContent = 'Finish in the new tab. This one closes once your key is added there.';
    e.target.hidden = true;
  });
} else if (/^#handoff=[0-9a-f]{32}$/.test(location.hash)) {
  relayId = location.hash.slice(9);
  try {
    const h = JSON.parse(localStorage.getItem(HANDOFF) || 'null');
    localStorage.removeItem(HANDOFF);
    if (h && h.id === relayId && Date.now() - h.at < 10 * 60000) {
      if (typeof h.armored === 'string') { handed = h.armored; showHanded(); }
      else if (h.create && OURS.test(h.create.address)) createFor = h.create;
    }
  } catch (err) {}
  history.replaceState(null, '', location.pathname);
}
document.getElementById('use-pin').addEventListener('change', e => { document.getElementById('pin-fields').hidden = !e.target.checked; });

// Each key on a panel of its own: its mark as the composer shows it, the
// address, when it was added (a key added twice has two passkeys, told apart
// by the time) and its key ID; Remove asks first, in a dialog.
const two = n => String(n).padStart(2, '0');
const when = iso => { const d = new Date(iso); return isNaN(d) ? '' : `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())} at ${two(d.getHours())}:${two(d.getMinutes())}`; };
const hideMarks = () => {
  for (const b of document.querySelectorAll('.mark-reveal[data-shown]')) {
    b.innerHTML = `<span class="mark-tile" data-list data-hidden aria-hidden="true">${'<span>?</span>'.repeat(4)}</span>`;
    b.setAttribute('aria-label', 'Show my mark');
    b.nextElementSibling.textContent = 'Show my mark';
    delete b.dataset.shown;
  }
};
addEventListener('blur', hideMarks);
document.addEventListener('visibilitychange', hideMarks);
async function list() {
  const records = await all(), box = document.getElementById('keys');
  box.hidden = !records.length;
  const times = {};
  for (const r of records) times[r.keyId] = (times[r.keyId] || 0) + 1;
  box.querySelector('.key-list').innerHTML = records.map(r => {
    const mark = known()[r.keyId], who = escape(r.addresses.join(', '));
    return `<div class="key-panel" role="listitem">` +
      (mark ? `<figure class="key-mark"><button class="mark-reveal" type="button" data-key="${escape(r.keyId)}" aria-label="Show my mark">` +
              `<span class="mark-tile" data-list data-hidden aria-hidden="true">${'<span>?</span>'.repeat(4)}</span></button><figcaption>Show my mark</figcaption></figure>` : '') +
      `<div class="key-text"><p class="key-name">${who}</p>` +
      `<p class="key-meta">Added ${escape(when(r.created))}${r.pinSalt ? ', with a PIN' : ''}</p>` +
      `<p class="key-meta">Key ${escape(String(r.keyId).toUpperCase().replace(/(.{4})(?=.)/g, '$1 '))}</p>` +
      (times[r.keyId] > 1 ? `<p class="key-note">This key is here ${times[r.keyId]} times, each time with a passkey of its own. One is enough: remove the ones you do not use.</p>` : '') +
      // Only in a tab no page opened (a page holding this one could word it its own way).
      (!window.opener && mailFor(r) ? `<div class="actions"><button class="text" type="button" data-connect="${escape(r.credentialId)}" ` +
        `title="If Mail asks to set up this browser although your key is here">Connect to Mail</button></div>` : '') +
      `</div><button class="icon-button danger" type="button" data-remove="${escape(r.credentialId)}" data-who="${who}" title="Remove from this browser" aria-label="Remove ${who} from this browser">${icon('delete')}</button></div>`;
  }).join('');
  showAlarm(records);
  // The mark shows only on a press of yours, in a tab of its own with this
  // site's address in view, and goes when the tab loses the keyboard or
  // leaves the screen: a page cannot open this one in a small window beside
  // a fake composer to borrow your mark.
  box.querySelectorAll('.mark-reveal').forEach(b => b.addEventListener('click', e => {
    if (!e.isTrusted || !window.locationbar?.visible || !window.toolbar?.visible || !document.hasFocus()) return;
    const mark = known()[b.dataset.key];
    if (mark) b.innerHTML = tile(mark, ' data-list');
    b.setAttribute('aria-label', 'Your mark');
    b.nextElementSibling.textContent = 'Your mark';
    b.dataset.shown = '';
  }));
  box.querySelectorAll('[data-connect]').forEach(b => b.addEventListener('click', e => {
    const r = records.find(x => x.credentialId === b.dataset.connect);
    if (e.isTrusted && r) connect(r);
  }));
  box.querySelectorAll('[data-remove]').forEach(b => b.addEventListener('click', e => {
    if (!e.isTrusted) return;
    ask('Remove this key?', `Encrypted messages to ${b.dataset.who} will not open in this browser until you add the key again. The key itself stays in your mailbox.`,
        'Remove', async () => { await remove(b.dataset.remove); list(); });
  }));
}

// The alarm, only for someone whose key is set up in this browser. Raised
// here, in this site's own tab, never in a frame (see the top), and only by
// a real press: the Mail app can neither raise nor clear it.
async function showAlarm(records) {
  const card = document.getElementById('alarm');
  card.hidden = !records.length;
  if (!records.length) return;
  const at = await raised();
  card.querySelector('.alarm-off').hidden = !!at;
  card.querySelector('.alarm-on').hidden = !at;
  if (at) card.querySelector('.alarm-when').textContent = new Date(at).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'});
}
// A note in the team's private repository on GitHub, which neither the mail
// server nor its hosting company can stop: you sign in there and send it.
function openReport() {
  const body = `Reported at ${location.host} on ${new Date().toISOString()}.\n\nWhat I saw (where, which mark, what I had typed there):\n\n\n` +
               `Encrypted mail is locked in the browser I reported from until the report is cleared at ${location.host}/setup.html.`;
  const url = 'https://github.com/legal-machines/mail/issues/new?' +
              new URLSearchParams({title: `Seal alarm: a composer without my mark (${location.host})`, body, labels: 'alarm'});
  window.open(url, '_blank', 'noopener,noreferrer');
}
document.getElementById('raise').addEventListener('click', async e => {
  if (!e.isTrusted) return;
  await raise();
  try { await lock(); } catch (err) {}
  openReport();
  list();
});
document.getElementById('report-again').addEventListener('click', e => { if (e.isTrusted) openReport(); });
// A question before something is undone, in a Material 3 dialog of this
// page: it works where a browser's own confirm() may not (a page that opens
// this one sandboxed can switch those off).
function ask(title, text, action, run) {
  const dialog = document.getElementById('remove-dialog');
  dialog.querySelector('h2').textContent = title;
  dialog.querySelector('.confirm-text').textContent = text;
  dialog.querySelector('button[value=remove]').textContent = action;
  dialog.returnValue = '';
  dialog.onclose = () => { if (dialog.returnValue === 'remove') run(); };
  dialog.showModal();
}
document.getElementById('clear-alarm').addEventListener('click', e => {
  if (!e.isTrusted) return;
  ask('Clear the report?', 'Encrypted mail can be unlocked in this browser again.', 'Clear', async () => { await clearAlarm(); list(); });
});

// The button does the work itself, as Enter in a field does: a sandbox that
// stops forms from submitting does not stop it.
form.addEventListener('submit', e => { e.preventDefault(); setUp(); });
form.querySelector('.actions button').addEventListener('click', e => { e.preventDefault(); if (e.isTrusted && form.reportValidity()) setUp(); });
// A key opened here, sealed under a new passkey (and the PIN, if chosen),
// kept for this browser and its mark remembered; then held open for Mail for
// a while (vault.mjs).
async function adopt(found, addresses, pin) {
  const passkey = await newPasskey(addresses[0]);
  const record = await keep(passkey, pin, pkcs8Of(found.scalar), found.info, addresses);
  const bytes = pkcs8Of(found.scalar);
  const key = await crypto.subtle.importKey('pkcs8', bytes, {name: 'X25519'}, false, ['deriveBits']);
  bytes.fill(0);
  const mark = await markOf(key);
  remember({[record.keyId]: mark});
  setExplained(record.keyId);
  await hold(record, pkcs8Of(found.scalar).buffer, 15).catch(() => {});
  found.scalar.fill(0);
  return {record, mark};
}
// Connect to Mail: the sealed record of a key in this browser, handed to the
// Mail app of its domain in the fragment of the address (which no request
// carries), in a tab that cannot reach this one. Mail keeps it on a press
// there, and only for the mailbox whose key it is. It is what Mail gets after
// any setup, and opens nothing without this browser's passkey.
function mailFor(record) {
  const domain = String(record.addresses?.[0] || '').split('@')[1] || '';
  return MAIL_SITES.find(site => new URL(site).hostname === 'mail.' + domain) || MAIL_SITES.find(site => domain && new URL(site).hostname.endsWith('.' + domain));
}
function connect(record) {
  const site = mailFor(record);
  if (!site) return;
  const bytes = new TextEncoder().encode(JSON.stringify(record));
  const text = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  // A link, not window.open: it can say where it comes from (this site's
  // origin alone, which Mail checks), while this page tells no one else.
  const a = document.createElement('a');
  a.href = `${site}/keys/connect#record=${text}`;
  a.target = '_blank';
  a.rel = 'noopener';
  a.referrerPolicy = 'origin';
  a.click();
}
// After a key is added in the tab that the Mail app's tab handed over to: if
// Mail did not say it kept the key (the mail page moved on, or closed), this
// tab offers Connect to Mail itself.
function awaitKept(record) {
  if (!relayId) return;
  let settled = false;
  const offer = () => {
    if (settled) return;
    settled = true;
    const box = document.getElementById('connect');
    box.hidden = false;
    box.querySelector('button').onclick = e => { if (e.isTrusted) connect(record); };
  };
  const hear = m => {
    if (m.data?.id !== relayId) return;
    if (m.data.type === 'kept') { settled = true; relay.removeEventListener('message', hear); }
    else if (m.data.type === 'not-kept') offer();
  };
  relay.addEventListener('message', hear);
  setTimeout(offer, 12000);
}

// The key's mark, shown here once with what it is for.
function showDone(addresses, mark, closing = !!handed || !!createFor) {
  done.innerHTML = `<b>Ready.</b> Encrypted messages to ${escape(addresses.join(', '))} now open in this browser, right in the Mail app.` +
    `<span class="mark-line">${tile(mark, ' data-big')}<span><b>This is your mark.</b> When you write end to end, ` +
    `this square of four pictures appears at the foot of the message as you type, and a tap on it says what it is. Mail cannot show it: type only where it appears. ` +
    `Your key's passphrase or recovery code goes only into this page, at ${escape(location.host)}.</span></span>` +
    (closing ? 'You can close this tab.' : '');
  done.hidden = false;
  list();
}

// ---- A new key, made in this tab for the mailbox the Mail app named. Its
// copy for the mailbox is locked with a recovery code of 20 characters (100
// bits, Crockford's base32) under Argon2, which no server can guess; the code
// is shown once, on a sheet to print, and never leaves this page.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const newCode = () => [...crypto.getRandomValues(new Uint8Array(20))].map(b => CROCKFORD[b & 31]).join('');
const createCard = document.getElementById('create'), createError = createCard.querySelector('.error'), sheet = document.getElementById('sheet');
document.getElementById('create-use-pin').addEventListener('change', e => { document.getElementById('create-pin-fields').hidden = !e.target.checked; });
if (createFor && !window.opener) {
  createCard.hidden = false;
  form.hidden = true;
  document.getElementById('create-address').textContent = createFor.address;
}
let lockedCopy = null, madeFor = null, madeMark = null;
document.getElementById('create-button').addEventListener('click', async e => {
  if (!e.isTrusted || !createFor) return;
  createError.hidden = true;
  const usePin = document.getElementById('create-use-pin').checked, pin = usePin ? document.getElementById('create-pin').value : '';
  if (usePin && (pin.length < 6 || pin !== document.getElementById('create-pin2').value)) {
    createError.textContent = pin.length < 6 ? 'Choose a PIN of at least 6 characters.' : 'The two PINs differ.';
    createError.hidden = false;
    return;
  }
  e.target.disabled = true;
  try {
    const code = newCode();
    const {privateKey: locked, publicKey} = await openpgp.generateKey({type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{name: createFor.name || undefined, email: createFor.address}], passphrase: code, keyExpirationTime: 3 * 365 * 86400,
      format: 'armored', config: {s2kType: openpgp.enums.s2k.argon2, aeadProtect: true}});
    const found = await extract(openpgp, locked, code);
    const {record, mark} = await adopt(found, [createFor.address], pin);
    const fingerprint = (await openpgp.readKey({armoredKey: publicKey})).getFingerprint().toUpperCase();
    if (relayId) relay.postMessage({type: 'sealed', id: relayId, record, newKey: {publicKey, lockedKey: locked, fingerprint}});
    awaitKept(record);
    lockedCopy = locked; madeFor = createFor.address; madeMark = mark;
    document.getElementById('sheet-address').textContent = createFor.address;
    document.getElementById('sheet-fingerprint').innerHTML = fingerprint.match(/.{4}/g).reduce((a, g, i) => a + (i === 5 ? '</span><span>' : i ? ' ' : '') + g, '<span>') + '</span>';
    document.getElementById('sheet-code').textContent = code.match(/.{4}/g).join('-');
    document.getElementById('sheet-date').textContent = new Date().toISOString().slice(0, 10);
    document.getElementById('sheet-site').textContent = `${location.host}, in a tab of its own; and Mail, at ${createFor.address.split('@')[1]}`;
    createCard.hidden = true;
    sheet.hidden = false;
    sheet.scrollIntoView({block: 'start'});
  } catch (err) {
    createError.textContent = err.name === 'NotAllowedError' ? 'The passkey was not made (cancelled or not allowed).' : err.message;
    createError.hidden = false;
    e.target.disabled = false;
  }
});
document.getElementById('sheet-print').addEventListener('click', () => print());
document.getElementById('sheet-save').addEventListener('click', () => {
  if (!lockedCopy) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([lockedCopy], {type: 'application/pgp-keys'}));
  a.download = `encryption-key-${madeFor}.asc`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
document.getElementById('sheet-kept').addEventListener('change', e => { document.getElementById('sheet-done').disabled = !e.target.checked; });
document.getElementById('sheet-done').addEventListener('click', () => {
  // The code leaves the page: the sheet goes, and with it the only copy here.
  document.getElementById('sheet-code').textContent = '';
  sheet.hidden = true;
  lockedCopy = null;
  showDone([madeFor], madeMark, true);
});

async function setUp() {
  error.hidden = true;
  const usePin = document.getElementById('use-pin').checked, pin = usePin ? document.getElementById('pin').value : '';
  if (usePin && (pin.length < 6 || pin !== document.getElementById('pin2').value)) {
    error.textContent = pin.length < 6 ? 'Choose a PIN of at least 6 characters.' : 'The two PINs differ.';
    error.hidden = false;
    return;
  }
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    const text = handed || await document.getElementById('file').files[0].text();
    let found;
    try {
      const typed = document.getElementById('passphrase').value, asCode = typed.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
      try { found = await extract(openpgp, text, typed); }
      catch (first) { if (asCode !== typed && /^[0-9A-Z]{20}$/.test(asCode)) found = await extract(openpgp, text, asCode); else throw first; }
    } catch (err) {
      throw new Error(/passphrase|decrypt|auth/i.test(err.message) ? 'Wrong passphrase or recovery code.' : err.message.includes('Curve25519') ? err.message : 'This is not a secret key file.');
    }
    // Only a key of one of our mailboxes (keys.mjs, published with this
    // site): a page cannot hand this one a key of its own making.
    if (!KEYS.some(k => (k.subkeys || []).includes(String(found.info.keyId).toLowerCase())))
      throw new Error('This key is not published yet, or is not the key of one of our mailboxes. A new key works once an administrator has published it.');
    const addresses = found.userIds.map(u => (/<([^>]+)>/.exec(u) || [, u])[1].toLowerCase());
    const {record, mark} = await adopt(found, addresses, pin);
    // The Mail app keeps the sealed key with the mailbox, for frames and for
    // the owner's other devices; without the passkey it opens nothing.
    if (relayId) relay.postMessage({type: 'sealed', id: relayId, record});  // to the tab the Mail app opened, which hands it over
    awaitKept(record);
    form.reset();
    if (handed) form.hidden = true;  // its work is done; what is left is the mark
    showDone(addresses, mark);
  } catch (err) {
    error.textContent = err.name === 'NotAllowedError' ? 'The passkey was not made (cancelled or not allowed).' : err.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

list();
