// The subject of an encrypted conversation, in place of the Mail app's
// "Encrypted subject". The page's hub (hub.mjs), a page of this same site,
// passes it on a BroadcastChannel that the Mail app names but, being another
// site, can neither read nor write. This page shows it and tells the Mail
// app only how much room it takes.
import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';

const subject = document.getElementById('subject'), measure = document.getElementById('measure');
let mailOrigin = null, channel = null, slot = null;

// As with a letter (embed.mjs): the subject wraps at one of a few fixed
// widths, so that Mail cannot learn its words from where it breaks.
const WIDTHS = [280, 320, 360, 400, 480, 560, 640, 720, 800, 960, 1120, 1280];
function report() {
  if (!mailOrigin) return;
  subject.style.maxWidth = (WIDTHS.filter(x => x <= innerWidth).pop() || WIDTHS[0]) + 'px';
  const text = subject.textContent;
  measure.textContent = text;
  // In steps of 48 pixels: room enough for the line, and too coarse to tell
  // Mail the subject's length to the letter.
  const step = 48, width = Math.ceil((measure.getBoundingClientRect().width + 1) / step) * step;
  parent.postMessage({type: 'reader-title-size', width: text ? width : 0,
                      height: text ? Math.ceil(subject.getBoundingClientRect().height / 32) * 32 : 0}, mailOrigin);
}
new ResizeObserver(report).observe(document.documentElement);

addEventListener('message', e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  if (Number.isFinite(e.data?.vw)) { widths(e.data.vw); report(); }
  if (channel || e.data?.type !== 'reader-title' || typeof e.data.channel !== 'string' || !/^page-[\w-]{8,64}$/.test(e.data.channel) || typeof e.data.slot !== 'string') return;
  mailOrigin = e.origin;
  slot = e.data.slot;
  channel = new BroadcastChannel(e.data.channel);
  channel.onmessage = m => {
    const d = m.data || {};
    if (d.type === 'hub-here') { channel.postMessage({type: 'want', slot, kind: 'title'}); return; }
    if (d.type === 'locked') subject.textContent = '';
    else if (d.type === 'line' && d.slot === slot && typeof d.subject === 'string') subject.textContent = d.subject.slice(0, 998);
    else return;
    report();
  };
  channel.postMessage({type: 'want', slot, kind: 'title'});
});

if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');  // carries nothing
