// Setting up a browser: the secret key file is opened here with its
// passphrase, its decryption subkey is sealed under a new passkey and the
// device PIN, and only the sealed copy is kept (store.mjs).

import * as openpgp from './openpgp.min.mjs';
import {extract, pkcs8Of} from './sealed-core.mjs';
import {all, keep, newPasskey, remove} from './store.mjs';
import {known, markOf, pictures, remember, setExplained, text as markText} from './mark.mjs';
import {hold} from './vault.mjs';
import {escape} from './mime.mjs';
import {MAIL_SITES} from './sites.mjs';

if (window.top !== window) {
  // Never inside another page: the key file and the PIN are typed only here,
  // with this site's address in the address bar.
  document.body.textContent = 'Open this page on its own.';
  throw new Error('framed');
}

const form = document.getElementById('setup'), error = form.querySelector('.error'), done = document.querySelector('.done');
// The key can come from the Mail app instead of a file: its key message
// (Add to this browser) opens this tab and hands over the key, still locked
// with its passphrase. Only the Mail app's own addresses are listened to.
let handed = null, mailOrigin = null;
if (window.opener) {
  addEventListener('message', e => {
    if (e.source !== window.opener || !MAIL_SITES.includes(e.origin)) return;
    if (e.data?.type === 'reader-hello') { mailOrigin = e.origin; return; }  // opened by the Mail app, without a key
    if (e.data?.type !== 'reader-key' || typeof e.data.armored !== 'string') return;
    mailOrigin = e.origin;
    handed = e.data.armored;
    document.getElementById('file-field').hidden = true;
    document.getElementById('file').required = false;
    document.getElementById('handed').hidden = false;
  });
  window.opener.postMessage({type: 'reader-ready'}, '*');
}
document.getElementById('use-pin').addEventListener('change', e => { document.getElementById('pin-fields').hidden = !e.target.checked; });

async function list() {
  const records = await all(), box = document.getElementById('keys');
  box.hidden = !records.length;
  box.querySelector('.key-list').innerHTML = records.map(r =>
    `<li><div><b>${escape(r.addresses.join(', '))}</b><small>Added ${escape(r.created.slice(0, 10))}${r.pinSalt ? ', with a PIN' : ''}` +
    `${known()[r.keyId] ? `. Your mark: ${markText(known()[r.keyId])}` : ''}</small></div>` +
    `<button class="text" type="button" data-remove="${escape(r.credentialId)}">Remove</button></li>`).join('');
  box.querySelectorAll('[data-remove]').forEach(b => b.addEventListener('click', async () => {
    if (confirm('Remove this key from this browser? Encrypted messages will no longer open here until you add it again.')) { await remove(b.dataset.remove); list(); }
  }));
}

form.addEventListener('submit', async e => {
  e.preventDefault();
  error.hidden = true;
  const usePin = document.getElementById('use-pin').checked, pin = usePin ? document.getElementById('pin').value : '';
  if (usePin && (pin.length < 6 || pin !== document.getElementById('pin2').value)) {
    error.textContent = pin.length < 6 ? 'Choose a PIN of at least 6 characters.' : 'The two PINs differ.';
    error.hidden = false;
    return;
  }
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    const text = handed || await document.getElementById('file').files[0].text();
    let found;
    try {
      found = await extract(openpgp, text, document.getElementById('passphrase').value);
    } catch (err) {
      throw new Error(/passphrase|decrypt/i.test(err.message) ? 'Wrong passphrase.' : err.message.includes('Curve25519') ? err.message : 'This is not a secret key file.');
    }
    const addresses = found.userIds.map(u => (/<([^>]+)>/.exec(u) || [, u])[1].toLowerCase());
    const passkey = await newPasskey(addresses[0]);
    const record = await keep(passkey, pin, pkcs8Of(found.scalar), found.info, addresses);
    // The key's mark (mark.mjs), shown here once with what it is for; and the
    // key, just opened, kept open for Mail for a while (vault.mjs).
    const bytes = pkcs8Of(found.scalar);
    const key = await crypto.subtle.importKey('pkcs8', bytes, {name: 'X25519'}, false, ['deriveBits']);
    bytes.fill(0);
    const mark = await markOf(key);
    remember({[record.keyId]: mark});
    setExplained(record.keyId);
    await hold(record, pkcs8Of(found.scalar).buffer, 15).catch(() => {});
    found.scalar.fill(0);
    // The Mail app keeps the sealed key with the mailbox, for frames and for
    // the owner's other devices; without the passkey it opens nothing.
    if (mailOrigin && window.opener) window.opener.postMessage({type: 'reader-sealed', record}, mailOrigin);
    form.reset();
    if (handed) form.hidden = true;  // its work is done; what is left is the mark
    done.innerHTML = `<b>Ready.</b> Encrypted messages to ${escape(addresses.join(', '))} now open in this browser, right in the Mail app.` +
      `<span class="mark-line"><span class="reader-mark" data-big role="img" aria-label="${markText(mark)}">${pictures(mark)}</span><span><b>This is your mark.</b> When you write end to end, ` +
      `these four pictures appear at the foot of the message as you type. Mail cannot show them: type only where they appear. ` +
      `Your key's passphrase goes only into this page, at ${escape(location.host)}.</span></span>` +
      (handed ? 'You can close this tab.' : '');
    done.hidden = false;
    list();
  } catch (err) {
    error.textContent = err.name === 'NotAllowedError' ? 'The passkey was not made (cancelled or not allowed).' : err.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
});

list();
