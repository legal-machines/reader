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
let handed = null, mailOrigin = null;
if (window.opener) {
  addEventListener('message', e => {
    if (e.source !== window.opener || !MAIL_SITES.includes(e.origin)) return;
    if (e.data?.type === 'reader-hello') { mailOrigin = e.origin; return; }  // opened by the Mail app, without a key
    if (e.data?.type !== 'reader-key' || typeof e.data.armored !== 'string') return;
    mailOrigin = e.origin;
    handed = e.data.armored;
    document.getElementById('file-field').hidden = true;
    document.getElementById('file').required = false;
    document.getElementById('handed').hidden = false;
  });
  window.opener.postMessage({type: 'reader-ready'}, '*');
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
      found = await extract(openpgp, text, document.getElementById('passphrase').value);
    } catch (err) {
      throw new Error(/passphrase|decrypt/i.test(err.message) ? 'Wrong passphrase.' : err.message.includes('Curve25519') ? err.message : 'This is not a secret key file.');
    }
    // Only a key of one of our mailboxes (keys.mjs, published with this
    // site): a page cannot hand this one a key of its own making.
    if (!KEYS.some(k => (k.subkeys || []).includes(String(found.info.keyId).toLowerCase()))) throw new Error('This is not the key of one of our mailboxes.');
    const addresses = found.userIds.map(u => (/<([^>]+)>/.exec(u) || [, u])[1].toLowerCase());
    const passkey = await newPasskey(addresses[0]);
    const record = await keep(passkey, pin, pkcs8Of(found.scalar), found.info, addresses);
    // The key's mark (mark.mjs), shown here once with what it is for; and the
    // key, just opened, kept open for Mail for a while (vault.mjs).
    const bytes = pkcs8Of(found.scalar);
    const key = await crypto.subtle.importKey('pkcs8', bytes, {name: 'X25519'}, false, ['deriveBits']);
    bytes.fill(0);
    const mark = await markOf(key);
    remember({[record.keyId]: mark});
    setExplained(record.keyId);
    await hold(record, pkcs8Of(found.scalar).buffer, 15).catch(() => {});
    found.scalar.fill(0);
    // The Mail app keeps the sealed key with the mailbox, for frames and for
    // the owner's other devices; without the passkey it opens nothing.
    if (mailOrigin && window.opener) window.opener.postMessage({type: 'reader-sealed', record}, mailOrigin);
    form.reset();
    if (handed) form.hidden = true;  // its work is done; what is left is the mark
    done.innerHTML = `<b>Ready.</b> Encrypted messages to ${escape(addresses.join(', '))} now open in this browser, right in the Mail app.` +
      `<span class="mark-line">${tile(mark, ' data-big')}<span><b>This is your mark.</b> When you write end to end, ` +
      `this square of four pictures appears at the foot of the message as you type, and a tap on it says what it is. Mail cannot show it: type only where it appears. ` +
      `Your key's passphrase goes only into this page, at ${escape(location.host)}.</span></span>` +
      (handed ? 'You can close this tab.' : '');
    done.hidden = false;
    list();
  } catch (err) {
    error.textContent = err.name === 'NotAllowedError' ? 'The passkey was not made (cancelled or not allowed).' : err.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

list();
