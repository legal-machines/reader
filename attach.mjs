// The clip of an end-to-end message, in Mail's row of buttons: files picked
// here go straight to the message's frame (compose.mjs) on this site's
// BroadcastChannel, so the mail page never holds them.
import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {icon} from './icons.mjs';

const clip = document.getElementById('clip'), pick = document.getElementById('pick');
clip.insertAdjacentHTML('afterbegin', icon('attach'));
let channel = null;
pick.addEventListener('change', () => {
  if (channel && pick.files.length) channel.postMessage({type: 'files', files: [...pick.files]});
  pick.value = '';
});
addEventListener('message', e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  const d = e.data || {};
  if (Number.isFinite(d.vw)) widths(d.vw);
  if (d.type === 'attach-init' && !channel && typeof d.files === 'string' && /^page-[\w-]{8,64}$/.test(d.files)) channel = new BroadcastChannel(d.files);
});
if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');
