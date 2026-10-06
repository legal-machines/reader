// The keys of people outside our mailboxes that Seal learned from their
// signed mail (contacts.mjs), in a frame on the Mail app's Security page:
// where the frames that open and send messages keep them (Safari keeps a
// frame's storage apart from this site's own tabs). Each on a panel: its
// fingerprint, whether you checked it with them, a new key waiting. A choice
// takes a press of yours and a second one to confirm, while this frame has
// the keyboard and the panel is whole on the screen (in Chrome, not covered
// either), so Mail cannot press for you nor hide what you press.

import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {escape} from './mime.mjs';
import {icon} from './icons.mjs';
import * as contacts from './contacts.mjs';

const view = document.getElementById('people');
let parentOrigin = null;
const tell = m => { if (parentOrigin) parent.postMessage(m, parentOrigin); };
const report = () => tell({type: 'reader-height', height: Math.ceil(document.documentElement.getBoundingClientRect().height)});
new ResizeObserver(report).observe(document.documentElement);

const two = n => String(n).padStart(2, '0');
const day = iso => { const d = new Date(iso); return isNaN(d) ? '' : `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}`; };
const grouped = f => { const g = String(f).match(/.{1,4}/g) || []; return g.slice(0, 5).join(' ') + ' ' + g.slice(5).join(' '); };

const seen = new Map();  // panel -> {whole, visible}
let watch = null;
try {
  watch = new IntersectionObserver(entries => {
    for (const en of entries) seen.set(en.target, {whole: en.intersectionRatio >= 0.98, visible: typeof en.isVisible === 'boolean' ? en.isVisible : null});
  }, {trackVisibility: true, delay: 100, threshold: [0, 0.5, 0.9, 0.98, 1]});
} catch (e) {}
const allowed = (e, panel) => {
  const s = seen.get(panel);
  return e.isTrusted && document.hasFocus() && (!watch || (s?.whole && s.visible !== false));
};

async function draw() {
  const list = (await contacts.all().catch(() => [])).sort((a, b) => a.address.localeCompare(b.address));
  view.innerHTML = '<p class="people-intro">Seal learns the key of someone outside our mailboxes from a message of theirs that carries it, once their domain\'s ' +
    'signature shows the mail server did not put it there, and encrypts to them from then on. To be sure a key is theirs, read its fingerprint with ' +
    'them by phone or in another app, not by email. These keys are kept in this browser.</p>' +
    (list.length ? '<div class="key-list" role="list">' + list.map(panel).join('') + '</div>' : '<p class="people-none">No keys yet.</p>');
  for (const p of view.querySelectorAll('.key-panel')) { watch?.observe(p); wire(p); }
  report();
}

function panel(c) {
  const who = escape(c.address);
  return `<div class="key-panel person" role="listitem" data-address="${who}" data-change="${escape(c.change?.fingerprint || '')}"><div class="key-text"><p class="key-name">${who}</p>` +
    `<p class="key-meta">${c.checked ? `Checked with them on ${escape(day(c.checked))}` : `From their mail since ${escape(day(c.first))}, not checked with them`}</p>` +
    `<p class="key-meta fingerprint">${escape(grouped(c.fingerprint))}</p>` +
    (c.change ? `<p class="key-note bad">Their mail sent a new key on ${escape(day(c.change.seen))}:<br><span class="fingerprint">${escape(grouped(c.change.fingerprint))}</span><br>` +
                `Seal encrypts to the old key until you accept this one. Ask them first, not by email, whether they changed it.</p>` : '') +
    `<div class="actions choices">` +
    (c.change ? `<button class="tonal" type="button" data-do="accept">Use the new key</button><button class="text" type="button" data-do="decline">Keep the old one</button>` : '') +
    `<button class="text" type="button" data-do="${c.checked ? 'uncheck' : 'check'}">${c.checked ? 'Mark as not checked' : 'I checked it with them'}</button></div>` +
    `<div class="confirm-inline" hidden><p></p><div class="actions"><button class="text" type="button" data-cancel>Cancel</button><button class="filled" type="button" data-confirm></button></div></div>` +
    `</div><button class="icon-button danger" type="button" data-do="forget" title="Forget this key" aria-label="Forget the key of ${who}">${icon('delete')}</button></div>`;
}

// What each choice asks before it is done, and what it does.
const CHOICES = {
  check: c => ({text: `Only if you read the fingerprint above with ${c.address} by phone, in person or in another app, and it matched theirs.`, action: 'It matched', run: () => contacts.check(c.address, true)}),
  uncheck: c => ({run: () => contacts.check(c.address, false)}),
  accept: c => ({text: `Messages to ${c.address} will be encrypted to the new key from now on. Do this once they told you, not by email, that they changed it, and its fingerprint matched.`,
                 action: 'Use it', run: () => contacts.acceptChange(c.address, c.change)}),
  decline: c => ({run: () => contacts.declineChange(c.address)}),
  forget: c => ({text: `Seal will not encrypt to ${c.address} until a signed message of theirs brings a key again.`, action: 'Forget', run: () => contacts.remove(c.address)}),
};

function wire(p) {
  const c = {address: p.dataset.address, change: p.dataset.change};
  const box = p.querySelector('.confirm-inline'), choices = p.querySelector('.choices');
  let pending = null;
  const close = () => { pending = null; box.hidden = true; choices.hidden = false; report(); };
  for (const b of p.querySelectorAll('[data-do]')) b.addEventListener('click', async e => {
    if (!allowed(e, p)) return;
    const choice = CHOICES[b.dataset.do](c);
    if (!choice.text) { await choice.run(); draw(); return; }
    pending = choice;
    box.querySelector('p').textContent = choice.text;
    box.querySelector('[data-confirm]').textContent = choice.action;
    box.hidden = false;
    choices.hidden = true;
    report();
  });
  box.querySelector('[data-cancel]').addEventListener('click', e => { if (e.isTrusted) close(); });
  box.querySelector('[data-confirm]').addEventListener('click', async e => {
    if (!pending || !allowed(e, p)) return;
    await pending.run();
    draw();
  });
}

addEventListener('message', e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  const d = e.data || {};
  if (Number.isFinite(d.vw)) widths(d.vw);
  if (d.type === 'people-init' && !parentOrigin) { parentOrigin = e.origin; draw(); }
});
// New keys arrive while Mail is used: drawn again whenever the page is seen again.
document.addEventListener('visibilitychange', () => { if (parentOrigin && document.visibilityState === 'visible') draw(); });
if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');  // carries nothing
