// The way to Mail for a page of Seal that no Mail tab opened: a new device's
// tab (Add your key to this device) and a phone's link page opened by its
// camera. Mail's relay (/keys/relay on the mail site of this Seal's domain)
// in a hidden frame, which only Seal's own pages may frame: it names the
// mailboxes signed in on this device with their sealed keys, and carries what
// a Mail tab would carry. Nothing of a key goes through it but encrypted for
// one device (link.mjs), or sealed under a device's passkey (store.mjs).

import {MAIL_SITES} from './sites.mjs';

// seal.legalmachines.org's Mail is mail.legalmachines.org, and so on.
export function mailSite() {
  const host = location.hostname, domain = host.startsWith('seal.') ? host.slice(5) : host;
  return MAIL_SITES.find(site => { const h = new URL(site).hostname; return h === 'mail.' + domain || h === domain; }) || null;
}

export function openRelay() {
  const site = mailSite();
  if (!site) return null;
  const frame = document.createElement('iframe');
  frame.hidden = true;
  frame.title = 'Mail';
  frame.src = site + '/keys/relay';
  let ready, n = 0;
  const isReady = new Promise(done => { ready = done; });
  const waiting = new Map();
  addEventListener('message', e => {
    if (e.source !== frame.contentWindow || e.origin !== site) return;
    const d = e.data || {};
    if (d.type === 'relay-ready') { ready(true); return; }
    const done = waiting.get(d.id);
    if (done) { waiting.delete(d.id); done(d); }
  });
  document.body.append(frame);
  // One question, its answer; ms 0 waits as long as Mail does (a code's ten minutes).
  const ask = async (type, payload = {}, ms = 20000) => {
    if (!await Promise.race([isReady, new Promise(done => setTimeout(() => done(false), 15000))])) return {type: 'relay-error', error: 'unreachable'};
    const id = ++n;
    return new Promise(done => {
      waiting.set(id, done);
      frame.contentWindow.postMessage({...payload, type, id}, site);
      if (ms) setTimeout(() => { if (waiting.delete(id)) done({type: 'relay-error', error: 'slow'}); }, ms);
    });
  };
  return {ask, site};
}
