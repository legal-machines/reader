// Whether a key waiting to be published is the one kept in this browser:
// scripts/keys-approve.py in the mail repository opens this page with the
// key's address and fingerprints in the fragment (#a=, p= the primary key,
// s= the encryption subkey), from the waiting copy the mail server holds.
// Records get into this browser's storage only through setup.html (a key
// made or added here, behind a passkey), so a match means the key is the
// one made or added here, and a mail server that put its own key in its
// place shows as a mismatch. The page reads; it sends nothing anywhere.
import {all, valid} from './store.mjs';

if (window.top !== window) {
  // Only on its own, with this site's address in view.
  document.body.textContent = 'Open this page on its own.';
  throw new Error('framed');
}

const $ = id => document.getElementById(id);
const grouped = f => f.match(/.{4}/g).reduce((a, g, i) => a + (i === 5 ? '\n' : i ? ' ' : '') + g, '');
const when = iso => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}); };

function verdict(kind, title, text) {
  const box = $('verdict');
  box.className = 'verdict ' + kind;
  $('verdict-title').textContent = title;
  $('verdict-text').textContent = text;
  box.hidden = false;
}

const asked = new URLSearchParams(location.hash.slice(1));
const address = String(asked.get('a') || '').toLowerCase().trim();
const primary = String(asked.get('p') || '').toLowerCase(), subkey = String(asked.get('s') || '').toLowerCase();

if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(address) || !/^[0-9a-f]{40}$/.test(primary) || !/^[0-9a-f]{40}$/.test(subkey)) {
  verdict('bad', 'This link is not whole', 'Copy it again from the screen that gave it to you, all of it.');
} else {
  $('asked-address').textContent = address;
  for (const half of grouped(primary.toUpperCase()).split('\n')) $('asked-fingerprint').append(Object.assign(document.createElement('span'), {textContent: half}));
  $('asked').hidden = false;
  let records = [];
  try { records = (await all()).filter(valid); } catch (e) {}
  // The same key: its encryption subkey, and the key that signs (for a key
  // Seal made, the primary key itself) where the record names one.
  const same = records.find(r => r.info.fingerprint === subkey && (!r.signer || r.signer.fingerprint === primary));
  const mine = records.filter(r => r.addresses.some(a => String(a).toLowerCase() === address));
  if (same)
    verdict('good', 'Yes, this is the key in this browser',
            `Seal keeps this key here for ${address}, added ${when(same.created)}. It is safe to publish.`);
  else if (mine.length)
    verdict('bad', 'No, this is not the key in this browser',
            `This browser keeps another key for ${address}. Do not publish the one waiting: someone may have put it in place of yours. Tell the administrator.`);
  else
    verdict('none', `This browser keeps no key for ${address}`,
            'Open this page in the browser where the key was made: another browser on this computer, or another device. If nobody made a key for this address, do not publish it.');
}
