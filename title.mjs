// The subject of an encrypted conversation, in place of the Mail app's
// "Encrypted subject". The message's own frame (embed.mjs), a page of this
// same site, hands it over on a BroadcastChannel that the Mail app names
// but, being another site, can neither read nor write. This page shows it
// and tells the Mail app only how much room it takes.
import {MAIL_SITES} from './sites.mjs';

const subject = document.getElementById('subject'), measure = document.getElementById('measure');
let mailOrigin = null, channel = null;

function report() {
  if (!mailOrigin) return;
  const text = subject.textContent;
  measure.textContent = text;
  parent.postMessage({type: 'reader-title-size', width: text ? Math.ceil(measure.getBoundingClientRect().width) + 1 : 0,
                      height: text ? Math.ceil(subject.getBoundingClientRect().height) : 0}, mailOrigin);
}
new ResizeObserver(report).observe(document.documentElement);

addEventListener('message', e => {
  if (channel || e.source !== parent || !MAIL_SITES.includes(e.origin) || e.data?.type !== 'reader-title' ||
      typeof e.data.channel !== 'string' || !/^subject-[\w-]{8,64}$/.test(e.data.channel)) return;
  mailOrigin = e.origin;
  channel = new BroadcastChannel(e.data.channel);
  channel.onmessage = m => {
    if (typeof m.data?.subject !== 'string') return;
    subject.textContent = m.data.subject.slice(0, 998);
    report();
  };
  channel.postMessage({type: 'title-ready'});  // a message opened before this frame loaded says its subject again
});

if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');  // carries nothing
