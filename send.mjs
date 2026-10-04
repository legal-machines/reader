// Send, for a message written end to end: the reader's own button, in
// Mail's row of buttons. Only a press here has the message encrypted: it
// asks the composer (compose.mjs) for the text on this site's channel,
// seals it with your key (seal.mjs; Touch ID first if encrypted mail is
// locked), encrypts it to the recipients' keys (keys.mjs) and hands Mail the
// encrypted message to send. Mail cannot have a draft encrypted behind your
// back, nor learn from it how much you have written.

import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {keyOf, seal} from './seal.mjs';
import * as vault from './vault.mjs';
import {valid} from './store.mjs';
import {openpgpLib} from './decrypt.mjs';

const button = document.getElementById('send'), pinField = document.querySelector('.send-pin'), pin = document.getElementById('pin');
let parentOrigin = null, channel = null, records = [], minutes = 15, from = '', people = {to: [], cc: [], bcc: []}, busy = false;
const tell = m => { if (parentOrigin) parent.postMessage(m, parentOrigin); };
const report = () => { const r = document.getElementById('actions').getBoundingClientRect(); tell({type: 'reader-size', width: Math.ceil(r.width), height: Math.ceil(r.height)}); };
new ResizeObserver(report).observe(document.getElementById('actions'));

// The message from the composer you typed in. Every composer on the
// channel that someone typed into answers; more than one, and nothing is
// sent: Mail may have slipped in a second one with words of its own.
const ask = (to, cc) => new Promise((resolve, reject) => {
  const id = crypto.randomUUID(), answers = new Map();
  const hear = m => { if (m.data?.type === 'message' && m.data.id === id && typeof m.data.from === 'string') answers.set(m.data.from, m.data); };
  channel.addEventListener('message', hear);
  channel.postMessage({type: 'compose-message', id, to, cc});
  setTimeout(() => {
    channel.removeEventListener('message', hear);
    const all = [...answers.values()];
    if (all.length > 1) return reject(new Error('More than one message answered: nothing was sent. Reload the page.'));
    if (!all.length) return reject(new Error('Click into the message first, then press Send.'));
    if (typeof all[0].text === 'string') resolve(all[0].text); else reject(new Error(all[0].error || 'The message could not be read.'));
  }, 400);
});

// Where the browser can tell (Chrome), Send works only while it is in plain
// view: not under something laid over it, not see-through, not moved.
let inView = !('IntersectionObserverEntry' in window && 'isVisible' in IntersectionObserverEntry.prototype);
if (!inView) {
  new IntersectionObserver(entries => { for (const e of entries) inView = e.isVisible; },
                           {trackVisibility: true, delay: 100}).observe(button);
}

button.addEventListener('click', async e => {
  if (busy || !channel || !e.isTrusted) return;
  if (!inView) { tell({type: 'reader-error', message: 'Send is covered by something on the page: nothing was sent.'}); return; }
  busy = true;
  button.disabled = true;
  const to = [...people.to], cc = [...people.cc], bcc = [...people.bcc];  // as they stood at the press
  try {
    const everyone = [...to, ...cc, ...bcc].map(a => a.toLowerCase());
    if (!everyone.length) throw new Error('Add a recipient.');
    // Our keys only (keys.mjs, by the hash of each address).
    const known = new Map(await Promise.all([...new Set([...everyone, from])].map(async a => [a, await keyOf(a)])));
    const own = known.get(from);
    const missing = [...everyone, from].filter(a => !known.get(a));
    if (missing.length) throw new Error(`End to end goes only to mailboxes here with keys; not to ${missing.join(', ')}.`);
    // Your key, for the seal: open already, or opened now with this press.
    const fromId = own.subkeys[0];
    const mine = records.filter(r => r.keyId === fromId);
    let derive = null;
    if (mine.length) {
      if (!(await vault.state()).keyIds.includes(fromId)) {
        if (mine.some(r => r.pinSalt) && !pin.value) { pinField.hidden = false; report(); pin.focus(); throw new Error('Enter your PIN, then press Send.'); }
        await vault.unlock(mine, pin.value, minutes);
        pin.value = '';
        pinField.hidden = true;
      }
      derive = vault.deriver(fromId);
    }
    const openpgp = await openpgpLib();
    let text = await ask(to, cc);
    const keys = [...new Set([...everyone, from])].map(a => known.get(a));
    if (derive) text = await seal(openpgp, text, fromId, derive, keys.map(k => k.subkeys[0]));
    const encryptionKeys = await Promise.all(keys.map(k => openpgp.readKey({armoredKey: k.armored})));
    const armored = await openpgp.encrypt({message: await openpgp.createMessage({binary: new TextEncoder().encode(text)}), encryptionKeys, format: 'armored'});
    tell({type: 'reader-encrypted', armored});
  } catch (err) {
    tell({type: 'reader-error', message: err.name === 'NotAllowedError' ? 'Sending end to end needs your key: Touch ID was cancelled.'
                                       : err.message === 'locked' ? 'Your key could not be opened here. Unlock encrypted mail, then press Send.' : err.message});
  } finally {
    busy = false;
    button.disabled = false;
  }
});

addEventListener('message', e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  parentOrigin = e.origin;
  const d = e.data || {};
  if (Number.isFinite(d.vw)) widths(d.vw);
  if (d.type === 'send-init' && !channel && typeof d.channel === 'string' && /^page-[\w-]{8,64}$/.test(d.channel)) {
    channel = new BroadcastChannel(d.channel);
    records = Array.isArray(d.records) ? d.records.filter(valid).slice(0, 20) : [];
    minutes = [0, 5, 15, 30, 60].includes(d.minutes) ? d.minutes : 15;
    from = typeof d.from === 'string' ? d.from.toLowerCase().slice(0, 254) : '';
    report();
  } else if (d.type === 'send-people') {
    const s = v => Array.isArray(v) ? v.filter(a => typeof a === 'string').slice(0, 100) : [];
    people = {to: s(d.to), cc: s(d.cc), bcc: s(d.bcc)};
  } else if (d.type === 'send-label' && typeof d.label === 'string') {
    // Send now, or Schedule send once a time is picked in Mail's menu.
    button.textContent = d.label === 'schedule' ? 'Schedule send' : 'Send now';
    report();
  }
});
if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');
vault.warm();
