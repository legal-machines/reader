// Whether a key waiting to be published is the one kept in this browser:
// scripts/keys-approve.py in the mail repository opens this page with the
// key's address and fingerprints in the fragment (#a=, p= the primary key,
// s= the encryption subkey), from the waiting copy the mail server holds.
// Records get into this browser's storage only through setup.html (a key
// made or added here, behind a passkey), so a match means the key is the
// one made or added here, and a mail server that put its own key in its
// place shows as a mismatch. The page reads; it sends nothing anywhere.
import {all, keyVerdict, valid} from './store.mjs';

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
// When the mail server got the key (seconds since 1970, from its note): a
// key kept here from well before then is an older one, not a sign that
// someone swapped this one. It only softens a No to "not here"; nothing in
// it can turn a No into a Yes.
const madeAt = Number(asked.get('t')) || 0;

if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(address) || !/^[0-9a-f]{40}$/.test(primary) || !/^[0-9a-f]{40}$/.test(subkey)) {
  verdict('bad', 'This link is not whole', 'Copy it again from the screen that gave it to you, all of it.');
} else {
  $('asked-address').textContent = address;
  for (const half of grouped(primary.toUpperCase()).split('\n')) $('asked-fingerprint').append(Object.assign(document.createElement('span'), {textContent: half}));
  $('asked').hidden = false;
  let records = [];
  try { records = (await all()).filter(valid); } catch (e) {}
  // The same key, kept here for this address: its encryption subkey, and
  // the key that signs, the primary key itself for a key Seal makes. A
  // record without the key that signs cannot vouch for the primary key, nor
  // a record of another address for this one (store.mjs, keyVerdict).
  const found = keyVerdict(records, address, primary, subkey, madeAt);
  if (found.kind === 'good')
    verdict('good', 'Yes, this is the key in this browser',
            `Seal keeps this key here for ${address}, added ${when(found.record.created)}. It is safe to publish.`);
  else if (found.kind === 'older')
    verdict('none', `This browser keeps only an older key for ${address}`,
            'The key waiting was made after the one kept here. Open this page in the browser where the new key was made. If nobody made a new key for this address, do not publish it.');
  else if (found.kind === 'other')
    verdict('bad', 'No, this is not the key in this browser',
            `This browser keeps another key for ${address}. Do not publish the one waiting: someone may have put it in place of yours. Tell the administrator.`);
  else
    verdict('none', `This browser keeps no key for ${address}`,
            'Open this page in the browser where the key was made: another browser on this computer, or another device. If nobody made a key for this address, do not publish it.');
}
