// Link a device, on the device that holds your key: a tab of this site that
// the Mail app opens (Link a device, in the menu under your picture). The
// camera reads the code the new device's Seal shows, a touch of your passkey
// opens your key, and it goes to that device encrypted for it alone
// (link.mjs). Mail carries it and can open nothing of it; the camera is this
// site's alone (Mail's pages may use none), and neither its picture nor the
// code reaches Mail. A tab, not a frame: a browser gives a frame the camera
// only where the page around it may use it too.

import {MAIL_SITES} from './sites.mjs';
import {all, unseal, valid, forgetWithdrawn} from './store.mjs';
import {keyOf, currentKeys} from './seal.mjs';
import {packKey, readOffer, sealFor} from './link.mjs';
import {openRelay} from './relay.mjs';
import {escape} from './mime.mjs';
import {icon} from './icons.mjs';

if (window.top !== window) {
  // Never inside another page: a page around it could draw over what it asks.
  document.body.textContent = 'Open this page on its own.';
  throw new Error('framed');
}
// Keys withdrawn on 2026-10-18 are not handed on, nor kept (store.mjs).
await currentKeys().then(forgetWithdrawn).catch(() => {});
const view = document.getElementById('link');
let mailOrigin = null, records = [], stream = null, timer = 0, offer = null, busy = false;
// Opened by a phone's own camera (the new device's code is an address of this
// page, its offer after the #), with no Mail tab behind it: Mail is reached
// through its relay, signed in on this phone, and the key goes to the mailbox
// signed in here whose published key this phone holds.
let mailRelay = null, me = '', here = [];
const fromCamera = !window.opener && location.hash.startsWith('#SEAL1.') ? readOffer(location.hash.slice(1)) : null;
const tell = m => { if (mailOrigin && window.opener) window.opener.postMessage(m, mailOrigin); };

const card = (title, text, actions = '', extra = '') =>
  `<section class="link-card"><h2>${title}</h2>${text ? `<p>${text}</p>` : ''}${extra}${actions ? `<div class="actions">${actions}</div>` : ''}</section>`;

function stop() {
  clearTimeout(timer);
  for (const t of stream?.getTracks() || []) t.stop();
  stream = null;
}

// The camera, until it sees a code of Seal's.
async function scan() {
  stop();
  offer = null;
  view.innerHTML = card('Scan the code', 'On the new device, Seal shows a square code. Point the camera at it.',
    '<button class="text" type="button" data-close>Cancel</button>', '<div class="link-camera"><video muted playsinline></video><span class="link-frame-mark" aria-hidden="true"></span></div><p class="link-note"></p>');
  bind();
  const video = view.querySelector('video'), note = view.querySelector('.link-note');
  if (!navigator.mediaDevices?.getUserMedia) {
    note.textContent = 'This browser gives Seal no camera here.';
    return;
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({video: {facingMode: {ideal: 'environment'}}, audio: false});
  } catch (err) {
    view.innerHTML = card('The camera is off', 'Allow the camera for this page, then try again. The picture stays in Seal: the Mail app does not see it.',
      '<button class="text" type="button" data-close>Cancel</button><button class="filled" type="button" data-scan>Try again</button>');
    bind();
    return;
  }
  video.srcObject = stream;
  await video.play().catch(() => {});
  // The browser's own reader where there is one (Chrome on Android), else jsQR.
  let detector = null;
  try { if ('BarcodeDetector' in self && (await BarcodeDetector.getSupportedFormats()).includes('qr_code')) detector = new BarcodeDetector({formats: ['qr_code']}); } catch (e) {}
  const canvas = document.createElement('canvas'), ctx = canvas.getContext('2d', {willReadFrequently: true});
  const look = async () => {
    if (!stream) return;
    let text = null;
    try {
      if (detector) text = (await detector.detect(video)).map(c => c.rawValue).find(v => typeof v === 'string' && v.startsWith('SEAL1.')) || null;
      else if (video.videoWidth && self.jsQR) {
        const w = Math.min(video.videoWidth, 800), h = Math.round(video.videoHeight * w / video.videoWidth);
        canvas.width = w;
        canvas.height = h;
        ctx.drawImage(video, 0, 0, w, h);
        text = self.jsQR(ctx.getImageData(0, 0, w, h).data, w, h, {inversionAttempts: 'dontInvert'})?.data || null;
      }
    } catch (e) {}
    const found = text && readOffer(text);
    if (found) { stop(); offer = found; confirm(); return; }
    if (text) note.textContent = 'That is not a code of Seal. Scan the one Seal shows on the new device.';
    timer = setTimeout(look, 160);
  };
  look();
}

// A code read: what giving the key there means, and the press that does it.
function confirm(failure = '') {
  const pin = records.some(r => r.pinSalt);
  view.innerHTML = card('Add your key to that device?',
    'It will open your encrypted mail with a passkey of its own, as this one does. Add it only to a device of yours, and only when its code is shown on a page at ' +
    `<b>${escape(location.host)}</b>, in a tab of its own: a code shown anywhere else could be someone else's.`,
    // From the camera, the phone's own camera reads again: here, only Cancel.
    (mailRelay ? '<button class="text" type="button" data-close>Cancel</button>' : '<button class="text" type="button" data-scan>Scan again</button>') +
    '<button class="filled" type="button" data-send>' + icon('key') + '<span>Add my key there</span></button>',
    (pin ? '<label class="field link-pin"><span>Your PIN</span><input type="password" inputmode="numeric" autocomplete="off"></label>' : '') +
    (failure ? `<p class="error" role="alert">${escape(failure)}</p>` : ''));
  bind();
}

async function send(e) {
  if (!e.isTrusted || busy || !offer) return;
  busy = true;
  e.currentTarget.disabled = true;
  try {
    // A touch of your passkey opens the key here, once, for this.
    const own = records.filter(r => here.some(h => h.credentialId === r.credentialId));
    const {record, pkcs8, signPkcs8} = await unseal(own.length ? own : records, view.querySelector('.link-pin input')?.value || '');
    const plain = packKey(record, pkcs8, signPkcs8);
    new Uint8Array(pkcs8).fill(0);
    if (signPkcs8) new Uint8Array(signPkcs8).fill(0);
    const blob = await sealFor(offer, plain);
    plain.fill(0);
    view.innerHTML = card('Sending…', 'Your key goes to the new device, encrypted for it alone.');
    if (mailRelay) {
      const d = await mailRelay.ask('relay-send', {address: me, channel: offer.channel, blob});
      if (d.ok) sent();
      else confirm(d.error === 'signed-out' ? 'Mail is signed out on this phone: sign in, then scan again.' : d.error || 'Mail could not pass your key on. Try again.');
    } else tell({type: 'link-send', channel: offer.channel, blob});
  } catch (err) {
    confirm(err.name === 'NotAllowedError' ? 'Cancelled or not allowed here.' : err.message);
  } finally {
    busy = false;
  }
}

function sent() {
  view.innerHTML = card('Sent', 'Finish on the new device: it asks for its own passkey there (Touch ID, Face ID, Windows Hello or Google Password Manager), and its encrypted mail opens. You can close this tab.',
    '<button class="filled" type="button" data-close>Done</button>');
  bind();
}

// From the camera: which mailbox signed in here sends its key.
async function standalone() {
  view.innerHTML = card('Add your key to the new device', 'One moment…');
  mailRelay = openRelay();
  const d = mailRelay ? await mailRelay.ask('relay-accounts') : {accounts: []};
  const accounts = Array.isArray(d.accounts) ? d.accounts : [];
  if (!accounts.length) {
    view.innerHTML = card('Sign in to Mail on this phone', 'Your key goes to the new device through your mailbox. Sign in to Mail here, then point the camera at the code again.',
      mailRelay ? `<a class="filled" href="${escape(mailRelay.site)}/login" target="_blank" rel="noopener">Sign in to Mail</a>` : '');
    return;
  }
  here = (await all().catch(() => [])).filter(valid);
  const usable = [];
  for (const a of accounts) {
    const ours = await keyOf(String(a.user || '')).catch(() => null);
    if (!ours) continue;
    const byId = new Map();
    for (const r of [...(Array.isArray(a.records) ? a.records.filter(valid).slice(0, 20) : []), ...here])
      if (ours.subkeys?.includes(r.keyId)) byId.set(r.credentialId, here.find(h => h.credentialId === r.credentialId) || r);
    if (byId.size) usable.push({user: a.user, records: [...byId.values()]});
  }
  if (!usable.length) {
    view.innerHTML = card('Your key is not on this phone', 'Scan the code with the device where your encrypted mail opens: the one you made your key on, or one you added it to.',
      '<button class="text" type="button" data-close>Close</button>');
    bind();
    return;
  }
  const pick = u => { me = u.user; records = u.records; offer = fromCamera; confirm(); };
  if (usable.length === 1) return pick(usable[0]);
  view.innerHTML = card('Which mailbox?', 'Several of your mailboxes are signed in on this phone. Send the key of the one the new device signed in to.', '',
    `<div class="link-choice">${usable.map((u, i) => `<button class="tonal" type="button" data-pick="${i}">${escape(u.user)}</button>`).join('')}</div>`);
  for (const b of view.querySelectorAll('[data-pick]')) b.addEventListener('click', e => { if (e.isTrusted) pick(usable[Number(b.dataset.pick)]); });
}

function bind() {
  view.querySelector('[data-scan]')?.addEventListener('click', e => { if (e.isTrusted) scan(); });
  view.querySelector('[data-send]')?.addEventListener('click', send);
  view.querySelector('[data-close]')?.addEventListener('click', e => { if (e.isTrusted) { stop(); window.close(); } });
}

document.addEventListener('visibilitychange', () => { if (document.hidden && stream) { stop(); view.innerHTML = card('Scan the code', 'The camera stopped while this page was away.', '<button class="filled" type="button" data-scan>Scan again</button>'); bind(); } });

addEventListener('message', async e => {
  if (!window.opener || e.source !== window.opener || !MAIL_SITES.includes(e.origin)) return;
  const d = e.data || {};
  if (d.type === 'link-init' && !mailOrigin) {
    mailOrigin = e.origin;
    // The mailbox's published key only, as Mail keeps its sealed records and
    // as this browser keeps them: an older key is not handed on.
    const me = typeof d.me === 'string' ? d.me.toLowerCase().slice(0, 254) : '';
    const ours = me ? await keyOf(me).catch(() => null) : null;
    const handed = Array.isArray(d.records) ? d.records.filter(valid).slice(0, 20) : [];
    const here = (await all().catch(() => [])).filter(valid);
    const byId = new Map();
    for (const r of [...handed, ...here]) if (ours?.subkeys?.includes(r.keyId)) byId.set(r.credentialId, here.find(h => h.credentialId === r.credentialId) || r);
    records = [...byId.values()];
    if (!records.length) {
      view.innerHTML = card('Your key is not on this device', 'Link a device from the one where your encrypted mail opens: your phone, or the computer you made your key on.',
        '<button class="text" type="button" data-close>Close</button>');
      bind();
      return;
    }
    scan();
  } else if (d.type === 'link-sent') {
    sent();
  } else if (d.type === 'link-failed') {
    confirm(typeof d.error === 'string' ? d.error.slice(0, 200) : 'Mail could not pass your key on. Try again.');
  }
});

// Only from the Mail app's Link a device, which hands over the mailbox's
// sealed keys and carries what goes to the new device.
if (window.opener) window.opener.postMessage({type: 'reader-ready'}, '*');  // carries nothing
else if (fromCamera) standalone();
else {
  view.innerHTML = card('Link a device', 'On the new device, choose Add your key to this device: it shows a code. Point this phone\'s camera at it.');
}
