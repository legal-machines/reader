// The reader's hub: one small frame on every page of Mail for someone whose
// key is set up. It opens the key with one touch of the passkey (Unlock, for
// every encrypted message on the page at once), keeps it open in the vault
// while Mail is in use (vault.mjs, sw.js), opens the messages Mail hands it
// and passes their content to the reader's other frames on the page (the
// message frames, the lines of a list, the subject) on a BroadcastChannel of
// this site, which Mail cannot join. Mail learns only whether the key is
// open and how tall this frame is.

import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {all, valid} from './store.mjs';
import {keyOf} from './seal.mjs';
import {escape} from './mime.mjs';
import {icon} from './icons.mjs';
import * as vault from './vault.mjs';
import {alarmText, raised} from './alarm.mjs';
import {canOpen, glance, openWith, openpgpLib, recipientsOf} from './decrypt.mjs';
import {keyFor} from './contacts.mjs';

const view = document.getElementById('hub');
const opened = new Map();     // slot -> {model, keyId}, while the key is open
const wants = new Map();      // slot -> Set of kinds: what frames on the page asked to show
const waiting = new Map();    // slot -> {armored, from, ids}
let parentOrigin = null, channel = null, records = [], minutes = 15, mode = 'quiet', count = 0;
let unlocked = false, busy = false, failure = '', alarm = false;
raised().then(at => { if (at) { alarm = true; draw(); } });

const tell = message => { if (parentOrigin) parent.postMessage(message, parentOrigin); };
const report = () => tell({type: 'reader-height', height: Math.ceil(document.documentElement.getBoundingClientRect().height)});
new ResizeObserver(report).observe(document.documentElement);
const post = message => channel?.postMessage(message);

// The keys a page's messages may need: the records Mail keeps for this mailbox.
const mine = () => records.filter(r => r.rp === location.hostname);
const needed = () => {
  const ids = new Set([...waiting.values()].flatMap(w => w.ids || []));
  const fit = mine().filter(r => ids.has(r.keyId));
  return fit.length ? fit : mine();
};

function draw() {
  const lockedHere = [...waiting.keys()].filter(s => !opened.has(s)).length;
  const shownCount = Math.max(count, lockedHere);
  let html = '';
  if (mode === 'panel') {
    html = `<div class="hub-panel"><div class="hub-status">${unlocked ? `<span>${icon('lock_open')}Encrypted mail is unlocked on this device.</span><button class="text" type="button" id="lock">Lock now</button>`
                                          : `<span>${icon('lock')}Encrypted mail is locked.</span>${mine().length ? unlockForm() : ''}`}</div></div>`;
  } else if (!unlocked && shownCount > 0 && mine().length) {
    // A Material 3 list item: the lock, a headline and one line under it,
    // and Unlock at the end. No mark here: anything shown without a
    // condition could be cut out by Mail and set beside a field of its own.

    const headline = mode === 'list' ? (shownCount === 1 ? '1 encrypted message' : `${shownCount} encrypted messages`) : 'End-to-end encrypted';
    const hint = alarm ? 'Locked after your report' : shownCount === 1 ? 'One touch unlocks it' : shownCount === 2 ? 'One touch unlocks both' : `One touch unlocks all ${shownCount}`;
    html = `<div class="hub-bar"><span class="hub-icon">${icon('lock')}</span>` +
      `<div class="hub-text"><b>${headline}</b><span class="hub-support">${hint}</span></div>` +
      unlockForm() + `</div>`;
  }
  view.innerHTML = html;
  view.querySelector('form.hub-unlock')?.addEventListener('submit', submit);
  view.querySelector('#lock')?.addEventListener('click', async () => { await vault.lock(); });
  view.querySelector('#in-tab')?.addEventListener('click', () => tell({type: 'hub-tab'}));
  view.querySelector('form.hub-unlock button')?.addEventListener('pointerenter', () => openpgpLib(), {once: true});
  tell({type: 'hub-state', unlocked, shown: !!html});
  report();
}

function unlockForm() {
  if (alarm) return `<p class="hub-error" role="alert">${escape(alarmText())}</p>`;
  const pin = needed().some(r => r.pinSalt);
  return `<form class="hub-unlock">` +
    `<button class="tonal" type="submit"${busy ? ' disabled' : ''}>${icon('lock_open')}<span>Unlock</span></button>` +
    (pin ? '<label class="field hub-pin"><span>PIN</span><input type="password" id="pin" inputmode="numeric" autocomplete="off"></label>' : '') +
    (failure ? `<p class="hub-error" role="alert">${failure}</p>` : '') + `</form>`;
}

async function submit(e) {
  e.preventDefault();
  if (busy) return;
  busy = true;
  failure = '';
  e.target.querySelector('button').disabled = true;
  try {
    openpgpLib();  // loads while the passkey is asked
    await vault.unlock(needed(), document.getElementById('pin')?.value || '', minutes);
    unlocked = true;
    await openAll();
  } catch (err) {
    failure = escape(err.name === 'NotAllowedError' ? 'Cancelled or not allowed here.' : err.name === 'SecurityError' ? 'This browser does not allow passkeys here.' : err.message) +
              (err.name === 'SecurityError' || err.name === 'NotAllowedError' ? ' <button class="text" type="button" id="in-tab">Open in a tab</button>' : '');
  } finally {
    busy = false;
    draw();
  }
}

// Every message waiting that an open key fits, opened and passed on.
async function openAll() {
  const s = await vault.state();
  unlocked = s.unlocked;
  if (!unlocked) return;
  for (const [slot, w] of waiting) {
    // Only what a frame on the page asked to show: Mail cannot have the hub
    // open the whole mailbox by handing it everything.
    if (opened.has(slot) || ![...(wants.get(slot) || [])].some(k => k === 'view' || k === 'line')) continue;
    w.ids ||= await recipientsOf(w.armored).catch(() => []);
    const keyId = w.ids.find(id => s.keyIds.includes(id)) || (w.ids.includes('0000000000000000') ? s.keyIds[0] : null);
    if (!keyId) { post({type: 'failed', slot}); continue; }
    try {
      const model = await openWith(w.armored, s.infos[keyId], {raw: w.raw, sentFrom: w.from});
      if (!w.raw) model.sentFrom ||= w.from;  // with the whole message, its own From only
      opened.set(slot, {model, keyId});
      send(slot);
    } catch (err) {
      if (err.message === 'locked') { unlocked = false; break; }
      post({type: 'failed', slot, message: err.message});
    }
  }
}

// What a frame of this page asked for: the whole message, or its line.
function send(slot) {
  const o = opened.get(slot);
  if (!o) return;
  const kinds = wants.get(slot) || new Set();
  if (kinds.has('view')) post({type: 'open', slot, model: o.model, keyId: o.keyId});
  if (kinds.has('line') || kinds.has('title')) post({type: 'line', slot, ...glance(o.model)});
}

function forget() {
  opened.clear();
  post({type: 'locked'});
}

vault.watch(open => {
  if (open && !unlocked) openAll().then(draw);
  if (!open && unlocked) { unlocked = false; forget(); draw(); }
});

// Keeping the vault: every 20 seconds it hears that a page of Mail is open
// (and in view or not); it locks on its own after 5 minutes out of view.
setInterval(async () => {
  if (document.visibilityState === 'visible') await vault.seen(); else await vault.state();
  const s = await vault.state();
  if (unlocked && !s.unlocked) { unlocked = false; forget(); draw(); }
}, 20000);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') vault.seen(); });

addEventListener('message', async e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  const d = e.data || {};
  parentOrigin = e.origin;
  if (Number.isFinite(d.vw)) widths(d.vw);
  if (d.type === 'hub-init' && !channel) {
    if (typeof d.channel === 'string' && /^page-[\w-]{8,64}$/.test(d.channel)) {
      channel = new BroadcastChannel(d.channel);
      channel.onmessage = m => {
        const x = m.data || {};
        if (x.type === 'want' && typeof x.slot === 'string' && ['view', 'line', 'title'].includes(x.kind)) {
          if (!wants.has(x.slot)) wants.set(x.slot, new Set());
          wants.get(x.slot).add(x.kind);
          if (opened.has(x.slot)) send(x.slot);
          else if (!unlocked && waiting.has(x.slot)) post({type: 'locked', slot: x.slot});
          else if (unlocked && waiting.has(x.slot) && x.kind !== 'title') openAll().then(draw);
        } else if (x.type === 'use') vault.used(true);
      };
      channel.postMessage({type: 'hub-here'});  // frames that loaded first ask again
    }
    records = Array.isArray(d.records) ? d.records.filter(valid).slice(0, 20) : [];
    // A key of this mailbox that this browser holds and Mail does not know of
    // (added in a tab of Seal that Mail did not open, or whose answer never
    // reached Mail): it counts here at once, and its sealed record goes to
    // Mail, as after a setup Mail opened. Mail learns nothing it would not
    // have had then: the record opens only with this browser's passkey.
    if (typeof d.me === 'string' && d.me.length <= 254) {
      const ours = await keyOf(d.me.toLowerCase()).catch(() => null);
      const local = ours ? (await all().catch(() => [])).filter(r => valid(r) && ours.subkeys.includes(r.keyId) && !records.some(m => m.credentialId === r.credentialId)) : [];
      if (local.length) {
        records = [...records, ...local].slice(0, 20);
        tell({type: 'hub-records', records: local});
      }
    }
    minutes = [0, 5, 15, 30, 60].includes(d.minutes) ? d.minutes : 15;
    mode = ['thread', 'list', 'panel', 'quiet'].includes(d.mode) ? d.mode : 'quiet';
    count = Number.isInteger(d.count) ? Math.min(d.count, 999) : 0;
    if (!await canOpen()) { tell({type: 'hub-state', unlocked: false, shown: false, old: true}); return; }
    const s = await vault.state();
    unlocked = s.unlocked;
    if (unlocked && count) openpgpLib();
    if (unlocked) await openAll();  // messages handed over while the vault was asked
    draw();
  } else if (d.type === 'hub-items' && Array.isArray(d.items)) {
    for (const it of d.items.slice(0, 200)) {
      if (typeof it.slot !== 'string' || it.slot.length > 64 || typeof it.armored !== 'string' || it.armored.length > 30e6 || waiting.has(it.slot)) continue;
      // The whole message, where Mail hands it over too: for the signature of
      // the sender's domain (decrypt.mjs, dkim.mjs).
      const raw = it.raw instanceof Uint8Array && it.raw.length <= 40e6 ? it.raw : undefined;
      waiting.set(it.slot, {armored: it.armored, raw, from: typeof it.from === 'string' ? it.from.slice(0, 320).toLowerCase() : ''});
    }
    if (unlocked) await openAll();
    draw();
  } else if (d.type === 'hub-keys-for' && Array.isArray(d.addresses)) {
    // Which of these addresses outside our mailboxes have a key here (one
    // learned from their signed mail, with no new key waiting): yes or no
    // for each, never a key. Mail knows whom you wrote to anyway.
    const asked = d.addresses.filter(a => typeof a === 'string' && a.length <= 254).slice(0, 100).map(a => a.toLowerCase());
    const have = [];
    for (const a of asked) { const k = await keyFor(a).catch(() => null); if (k?.contact) have.push(a); }
    tell({type: 'hub-keys', have});
  } else if (d.type === 'hub-lock') {
    await vault.lock();
    unlocked = false;
    forget();
    draw();
    tell({type: 'hub-locked'});
  } else if (d.type === 'hub-use') {
    vault.used();
  }
});

if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');  // carries nothing
vault.warm();
