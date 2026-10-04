// A line of the Mail app's list, or the folded line of a message in a
// conversation: the subject and the start of an encrypted message, once the
// page's hub (hub.mjs) has opened it, in the place Mail drew "Encrypted
// message". Mail tells this frame where its words stand and how they look;
// it learns nothing back but that the line is shown.
import {MAIL_SITES} from './sites.mjs';

const LOCK = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>';
// Material's attach_file: the line of a message with files, as Mail marks its own.
const CLIP = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5c0-1.38 1.12-2.5 2.5-2.5s2.5 1.12 2.5 2.5v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5c0 1.38 1.12 2.5 2.5 2.5s2.5-1.12 2.5-2.5V5c0-2.21-1.79-4-4-4S7 2.79 7 5v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"/></svg>';
const parts = {subject: document.getElementById('s'), preview: document.getElementById('p')};
const still = matchMedia('(prefers-reduced-motion: reduce)');
let mailOrigin = null, channel = null, slot = null, shown = null, asked = false;

// Where the words stand and how they look, as Mail measured them: one line
// (line: its box; the subject, then the text after it), or two parts each
// with a box of its own.
const line = document.getElementById('line');
function place(boxes) {
  const flow = !!boxes?.line;
  document.body.classList.toggle('flow', flow);
  const at = (el, b) => Object.assign(el.style, {left: b.x + 'px', top: b.y + 'px', width: b.w + 'px', height: b.h + 'px'});
  if (flow) at(line, boxes.line);
  for (const [name, el] of Object.entries(parts)) {
    const b = boxes?.[name];
    if (!b) { el.hidden = true; continue; }
    el.hidden = false;
    if (!flow) at(el, b); else el.removeAttribute('style');
    Object.assign(el.style, {font: b.font, color: b.color, letterSpacing: b.spacing || 'normal'});
  }
}

// The words take the place of encrypted characters, left to right: the
// characters still to go stay put (nothing flickers); only the edge moves,
// over Material 3's long1 (450 ms) on its emphasized decelerate curve.
const ease = t => 1 - Math.pow(1 - t, 4);
function write(el, text, lock, files = 0) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const holder = document.createElement('span');
  holder.className = 'text';
  el.replaceChildren();
  if (lock) el.insertAdjacentHTML('beforeend', `<span class="lock">${LOCK}</span>`);
  if (files > 0) el.insertAdjacentHTML('beforeend', `<span class="clip" title="${files === 1 ? '1 attachment' : files + ' attachments'}">${CLIP}</span>`);
  el.append(holder);
  if (still.matches) { holder.textContent = text; return; }
  const length = Math.min(text.length, 160);
  const cipher = [...text.slice(0, length)].map(c => c === ' ' ? ' ' : chars[Math.random() * 64 | 0]).join('');
  const start = performance.now();
  let last = -1;
  const step = now => {
    const t = Math.min(1, (now - start) / 450), done = Math.round(ease(t) * length);
    if (done !== last) { last = done; holder.textContent = text.slice(0, done) + cipher.slice(done) + text.slice(length); }
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

addEventListener('message', e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  const d = e.data || {};
  mailOrigin = e.origin;
  if (d.type === 'line-place') place(d.boxes);
  if (d.type !== 'line-init' || channel || typeof d.channel !== 'string' || !/^page-[\w-]{8,64}$/.test(d.channel) || typeof d.slot !== 'string') return;
  slot = d.slot;
  place(d.boxes);
  channel = new BroadcastChannel(d.channel);
  channel.onmessage = m => {
    const x = m.data || {};
    if (x.type === 'hub-here') { if (asked) channel.postMessage({type: 'want', slot, kind: 'line'}); return; }
    if (x.type === 'locked') {
      if (shown) { shown = null; parts.subject.replaceChildren(); parts.preview.replaceChildren(); parent.postMessage({type: 'line-shown', shown: false}, mailOrigin); }
      return;
    }
    if (x.type !== 'line' || x.slot !== slot || shown) return;
    shown = x;
    if (!parts.subject.hidden) write(parts.subject, String(x.subject || '(no subject)').slice(0, 300), false);
    write(parts.preview, String(x.preview || '').slice(0, 300), true, Number.isInteger(x.files) ? x.files : 0);
    parent.postMessage({type: 'line-shown', shown: true}, mailOrigin);
  };
  // Asked for once the line is on the screen (see embed.mjs).
  new IntersectionObserver(entries => {
    if (asked || !entries.some(e => e.isIntersecting)) return;
    asked = true;
    channel.postMessage({type: 'want', slot, kind: 'line'});
  }).observe(document.documentElement);
});
if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');  // carries nothing
