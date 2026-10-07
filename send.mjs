// Send, for a message written end to end: the reader's own button, in
// Mail's row of buttons. Only a press here has the message encrypted: it
// finds the composer (compose.mjs) among this tab's frames itself, asks it
// for the text, seals it with your key (seal.mjs; Touch ID first if encrypted mail is
// locked), encrypts it to the recipients' keys (keys.mjs for our mailboxes,
// contacts.mjs for people outside, learned from their signed mail) and hands Mail the
// encrypted message to send. Mail cannot have a draft encrypted behind your
// back, nor learn from it how much you have written.

import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {seal} from './seal.mjs';
import {signedPackets} from './sign.mjs';
import {measure, now} from './clock.mjs';
import {armoredFor} from './wkd.mjs';
import {keyFor} from './contacts.mjs';
import {onKeysChanged} from './seal.mjs';
const OURS = /@(?:[a-z0-9-]+\.)*(?:legalmachines\.org|dzyza\.com)$/;  // our domains and any name under them
import * as vault from './vault.mjs';
import {all, valid} from './store.mjs';
import {openpgpLib} from './decrypt.mjs';
import {fromOurFrame, readerFrames} from './tab.mjs';
import {alarmText, raised} from './alarm.mjs';

const button = document.getElementById('send'), pinField = document.querySelector('.send-pin'), pin = document.getElementById('pin');
let parentOrigin = null, ready = false, records = [], minutes = 15, from = '', people = {to: [], cc: [], bcc: []}, busy = false;
let changedAt = 0;  // when Mail last changed who it goes to
// An address as it may stand in a header: nothing that could end the line
// and start a header of Mail's choosing inside the sealed message.
const ADDRESS = /^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/;
const tell = m => { if (parentOrigin) parent.postMessage(m, parentOrigin); };
// The button's own size, whatever room the frame has now; nothing while
// Mail keeps the frame hidden (End to end off), which lays it out at nothing.
const report = () => {
  if (!innerWidth || !innerHeight) return;
  const r = document.getElementById('actions').getBoundingClientRect();
  if (r.width && r.height) tell({type: 'reader-size', width: Math.ceil(r.width), height: Math.ceil(r.height)});
};
new ResizeObserver(report).observe(document.getElementById('actions'));

// The message from the one composer in this tab, found here, not named by
// Mail. A second one, and nothing is sent: Mail may have slipped it in with
// words of its own.
const ask = (to, cc) => new Promise((resolve, reject) => {
  const composers = readerFrames('compose.html');
  if (composers.length > 1) return reject(new Error('This page holds a second end-to-end message: nothing was sent. Reload the page.'));
  if (!composers.length) return reject(new Error('There is no message to send on this page.'));
  const id = crypto.randomUUID(), w = composers[0];
  const done = () => { removeEventListener('message', hear); clearTimeout(timer); };
  const hear = m => {
    if (m.source !== w || !fromOurFrame(m, 'compose.html') || m.data?.type !== 'message' || m.data.id !== id) return;
    done();
    if (typeof m.data.text === 'string') resolve(m.data.text); else reject(new Error(m.data.error || 'The message could not be read.'));
  };
  const timer = setTimeout(() => { done(); reject(new Error('The message did not answer: nothing was sent. Reload the page.')); }, 3000);
  addEventListener('message', hear);
  w.postMessage({type: 'compose-message', id, to, cc, from}, location.origin);
});

// The composer shows whom the message will be encrypted to, from the very
// list this button uses, inside the reader where Mail cannot change it.
// With each address, what Seal has for it: 'ours' (a mailbox here), 'known'
// or 'checked' (someone outside whose key it learned; checked with them),
// 'changed' (a new key waits for you to accept it) or 'none'.
const keysShown = async list => Object.fromEntries(await Promise.all([...new Set(list)].map(async a => {
  const k = await keyFor(a).catch(() => null);
  return [a, !k ? (OURS.test(String(a).toLowerCase()) ? 'unpublished' : 'none') : k.internal ? 'ours' : k.changed ? 'changed' : k.contact?.checked ? 'checked' : 'known'];
})));
const share = async () => {
  const keys = await keysShown([...people.to, ...people.cc, ...people.bcc]);
  for (const w of readerFrames('compose.html')) w.postMessage({type: 'send-shows', ...people, from, keys}, location.origin);
};
addEventListener('message', e => { if (e.data?.type === 'compose-hello' && fromOurFrame(e, 'compose.html')) share(); });
onKeysChanged(share);  // a newer Seal took over: the keys of the people shown, again

// Where the browser can tell (Chrome), Send works only while it is in plain
// view: not under something laid over it, not see-through, not moved.
let inView = !('IntersectionObserverEntry' in window && 'isVisible' in IntersectionObserverEntry.prototype);
if (!inView) {
  new IntersectionObserver(entries => { for (const e of entries) inView = e.isVisible; },
                           {trackVisibility: true, delay: 100}).observe(button);
}

button.addEventListener('click', async e => {
  if (busy || !ready || !e.isTrusted) return;
  if (!inView) { tell({type: 'reader-error', message: 'Send is covered by something on the page: nothing was sent.'}); return; }
  // Who it goes to may not change under your finger: a list changed just
  // before the press waits for a second look at the For line.
  if (Date.now() - changedAt < 2000) { tell({type: 'reader-error', message: 'Who it goes to just changed. Check the For line, then press Send again.'}); return; }
  busy = true;
  button.disabled = true;
  const to = [...people.to], cc = [...people.cc], bcc = [...people.bcc];  // as they stood at the press
  try {
    if (await raised()) throw new Error(alarmText());
    const everyone = [...to, ...cc, ...bcc].map(a => a.toLowerCase());
    if (!everyone.length) throw new Error('Add a recipient.');
    if (!ADDRESS.test(from) || everyone.some(a => !ADDRESS.test(a))) throw new Error('An address here is not a plain email address: nothing was sent.');
    // Our keys (keys.mjs, by the hash of each address), and the keys of
    // people outside that Seal learned from their signed mail (contacts.mjs).
    const known = new Map(await Promise.all([...new Set([...everyone, from])].map(async a => [a, await keyFor(a)])));
    const own = known.get(from);
    if (!own?.internal) throw new Error('End to end goes only from a mailbox here with a key.');
    const changed = everyone.filter(a => known.get(a)?.changed);
    if (changed.length) throw new Error(`New key for ${changed.join(', ')}: accept it or keep the old one under their latest message, or on the Security page, then press Send. Nothing was sent.`);
    const missing = everyone.filter(a => !known.get(a));
    const unpublished = missing.filter(a => OURS.test(String(a).toLowerCase())), outsiders = missing.filter(a => !unpublished.includes(a));
    if (unpublished.length) throw new Error(`${unpublished.join(', ')} has no published key yet: its owner makes one in Mail (Security), and an administrator publishes it once checked. Nothing was sent.`);
    if (outsiders.length) throw new Error(`Seal has no key for ${outsiders.join(', ')}. It learns one from a message of theirs that carries it and is signed with it and by their domain; a key in a message not signed with it waits under that message for you to take it.`);
    // Your key, for the seal: open already, or opened now with this press.
    // Every message written here is sealed: one that is not could have come
    // from anyone who has your public key, the mail server included, so
    // there is no sending without it. The records Mail hands over count, and
    // so do those this browser keeps itself, so Mail cannot leave them out.
    const fromId = own.subkeys[0];
    const mine = records.filter(r => r.keyId === fromId);
    // This browser's own copy of a record stands over Mail's, which could
    // leave a part out (the key that signs).
    try { for (const r of await all()) if (valid(r) && r.keyId === fromId) { const at = mine.findIndex(m => m.credentialId === r.credentialId); if (at >= 0) mine[at] = r; else mine.push(r); } } catch (e) {}
    let st = await vault.state();
    const opened = st.keyIds.includes(fromId);
    if (!mine.length && !opened) throw new Error('Sending end to end needs your own key in this browser. Add it on the Security page, then press Send.');
    // Your OpenPGP signature on it, which the recipient's app checks with
    // your published key (sign.mjs). To people outside a message goes signed
    // or not at all: there the seal means nothing, and an unsigned message
    // could come from anyone with their key, the mail server included.
    const outside = keys0 => keys0.some(k => !k.internal);
    const toOutside = outside([...new Set(everyone)].map(a => known.get(a)));
    const signing = mine.filter(r => r.signSealed);
    if (toOutside && !st.signers?.[fromId] && !signing.length)
      throw new Error('Your key in this browser does not sign yet, and to people outside a message goes signed or not at all. Add your key to this browser again, once (Security, Add my key to this browser), then press Send. If it asks again after that, report it on the Seal page. Nothing was sent.');
    let derive = null;
    {
      if (!opened || (toOutside && !st.signers?.[fromId])) {
        const use = signing.length ? signing : mine;
        if (use.some(r => r.pinSalt) && !pin.value) { pinField.hidden = false; report(); pin.focus(); throw new Error('Enter your PIN, then press Send.'); }
        await vault.unlock(use, pin.value, minutes);
        pin.value = '';
        pinField.hidden = true;
        st = await vault.state();
      }
      derive = vault.deriver(fromId);
    }
    const signer = st.signers?.[fromId] || null;
    if (toOutside && !signer) throw new Error('Your key that signs could not be opened in this browser: nothing was sent. Add your key to this browser again (Security, Add my key to this browser).');
    const openpgp = await openpgpLib();
    const text = await ask(to, cc);
    // Our keys that keys.mjs lists without the key itself come from the Web
    // Key Directory, each only as the key it names (wkd.mjs).
    const keyOfAddress = async a => {
      const k = known.get(a);
      return openpgp.readKey({armoredKey: k.armored || await armoredFor(openpgp, a, k.entry)});
    };
    // Signed and encrypted at the right time, whatever this device's clock says.
    await measure();
    const at = now();
    // One message for the people it names (To and Cc), and one of its own
    // for each Bcc: a copy for many would name every key it is encrypted to
    // (in its packets, for anyone holding it, the mail server too) and carry
    // a seal line for each, so the people in To would see who else got it.
    // Each copy has its own seal and signature, and says inside that it is
    // a Bcc, for its reader. An address in To or Cc as well gets the one
    // message.
    const named = [...new Set([...to, ...cc].map(a => a.toLowerCase()))];
    const hidden = [...new Set(bcc.map(a => a.toLowerCase()))].filter(a => !named.includes(a));
    const encrypt = async (body, list) => {
      const people = [...new Set([...list, from])];
      // The seal goes to our mailboxes only: Seal elsewhere has no key of theirs to check it with.
      const sealed = await seal(openpgp, body, fromId, derive, people.map(a => known.get(a)).filter(k => k.internal).map(k => k.subkeys[0]));
      const data = new TextEncoder().encode(sealed);
      const message = signer ? await signedPackets(openpgp, data, signer, vault.signer(fromId), at) : await openpgp.createMessage({binary: data, date: new Date(at)});
      // SEIPD version 1 always, as Thunderbird and GnuPG read it (neither
      // opens version 2, which keys made in Seal asked for until October
      // 2026): a session key with no AEAD algorithm makes OpenPGP.js write 1.
      const sessionKey = {data: crypto.getRandomValues(new Uint8Array(32)), algorithm: 'aes256'};
      try {
        return await openpgp.encrypt({message, encryptionKeys: await Promise.all(people.map(keyOfAddress)), sessionKey, format: 'armored', date: new Date(at)});
      } finally {
        sessionKey.data.fill(0);
      }
    };
    const armored = await encrypt(text, named), copies = {};
    for (const a of hidden) copies[a] = await encrypt(`Bcc: ${a}\r\n` + text, [a]);
    tell({type: 'reader-encrypted', armored, bcc: copies});
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
  if (d.type === 'send-init' && !ready) {
    ready = true;
    records = Array.isArray(d.records) ? d.records.filter(valid).slice(0, 20) : [];
    minutes = [0, 5, 15, 30, 60].includes(d.minutes) ? d.minutes : 15;
    from = typeof d.from === 'string' && ADDRESS.test(d.from.toLowerCase()) ? d.from.toLowerCase() : '';
    report();
    share();
  } else if (d.type === 'send-people') {
    const s = v => Array.isArray(v) ? v.filter(a => typeof a === 'string').map(a => a.toLowerCase()).slice(0, 100) : [];
    const next = {to: s(d.to), cc: s(d.cc), bcc: s(d.bcc)};
    if (JSON.stringify(next) !== JSON.stringify(people)) changedAt = Date.now();
    people = next;
    share();
  } else if (d.type === 'send-label' && typeof d.label === 'string') {
    // Send now, or Schedule send once a time is picked in Mail's menu.
    button.textContent = d.label === 'schedule' ? 'Schedule send' : 'Send now';
    report();
  }
});
if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');
vault.warm();
