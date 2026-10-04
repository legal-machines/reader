# Mail Reader

Opens and writes end-to-end encrypted (OpenPGP) messages inside the Mail app
of legalmachines.org and dzyza.com, so that neither the mail server nor its
hosting company can read them or take the key.

It is served by GitHub Pages, not by the mail server: this repository is
https://reader.legalmachines.org, and legal-machines/reader2 is the same files
at https://reader.dzyza.com. The Mail app shows it in frames and hands it the
encrypted message, which the mail server holds anyway. The browser keeps the
Mail app out of these frames and out of this site's storage.

## Two keys, and why the public one cannot read

Every mailbox has a key pair, which works like a padlock and its key.

* **The public key is the open padlock.** It is published (WKD, Autocrypt
  headers) so that anyone can snap it shut: encrypt a message that only the
  mailbox can open. A public key cannot open anything, and the private key
  cannot be worked out from it (X25519; the best known attack costs about
  2^128 operations).
* **The private key opens it.** Only its owner has it: in GnuPG or
  Thunderbird, and here, sealed under the owner's passkey.

Writing therefore needs only the recipients' public keys, and reading needs
the recipient's private key. A message written in the Mail app is encrypted
to every recipient's public key and to the sender's own, so the copy in Sent
opens for the sender too.

Because anyone can encrypt to a public key, an encrypted message does not
prove who wrote it. The reader compares the sender written inside the
message with the sender the mail server received it from, and warns when
they differ. Signatures, which would prove it, are not made yet.

## Reading

* **The key stays on the device.** It is set up once per browser, in a tab of
  this site (`setup.html`, its address in the address bar), from the key file
  and its passphrase. The decryption subkey is sealed (AES-GCM) under a key
  made from a passkey's PRF output (Touch ID, a fingerprint, the screen lock
  or a security key) and, if chosen, a PIN. The sealed copy is kept by the
  Mail app with the mailbox (it cannot open it) and in this site's
  IndexedDB; a passkey synced by iCloud Keychain or Google Password Manager
  opens it on the owner's other devices. Opened, the key becomes a
  non-extractable WebCrypto X25519 key in the memory of one page.
* **Every message opens with the passkey** (and the PIN, if there is one).
* **The message looks like any other.** Inside a conversation the reader
  draws the text, pictures and attachments with the Mail app's own
  stylesheet and icons (`mail.css`, `icons.mjs`, `letter.mjs`, copied from
  its source by `make-styles.py`, never from the mail server). The subject
  goes to the Mail app's title line through `title.html`, a frame of this
  site that the message's frame hands it to on a BroadcastChannel; the Mail
  app learns only its size.
* **Inert content.** HTML messages are stripped of scripts, frames, forms and
  remote addresses and shown in a sandboxed frame without scripts.
  Attachments are only downloaded or shown in the browser's own viewer.

## Writing

`compose.html` is the text field of the Mail app's composer when End to end
is on. The subject and the text are typed and encrypted there, to the public
keys in `keys.mjs` (made by `make-keys.py` from the mail repository's
published keys, not taken from the mail page), so the Mail app receives only
the encrypted message. No private key and no passkey are needed to write.

## No network, and watched

* Every page carries a Content-Security-Policy that allows no requests
  beyond this site's own files: nothing decrypted, and nothing about the
  key, can be sent anywhere.
* `SHA256SUMS` lists every file's hash. Two watches compare what is served at
  both addresses with it, and look for signs that someone else serves these
  names: the domains' delegation and DNSSEC at their registries, the CNAME at
  deSEC, and certificates for the names in the Certificate Transparency logs
  that GitHub Pages does not serve. One runs on the mail server every 10
  minutes, one here in GitHub Actions every 15 (`watch/`), which also checks
  the Mail app's own files against what was deployed. While either reports a
  problem, the Mail app opens no encrypted message, adds no key and offers
  no End to end by itself.

## What it cannot do

* Protect a device on which someone else's program records the screen or
  the keyboard.
* Stop whoever serves these files from changing them: GitHub, or someone who
  takes the names through their registrar or DNS. The watches make such a
  change visible within minutes, not impossible, and a change served to one
  person only may pass them.
* Stop the mail server's hosting company from drawing a fake text field in
  place of `compose.html`, which the frame's missing address bar cannot
  reveal. The watch at GitHub sees a change of the Mail app's files made for
  everyone, not one made for a single person.
* Hide who writes to whom and when, or mail that arrives unencrypted: the
  mail server encrypts that on delivery, but has read it by then.

Files: `sealed-core.mjs` (ECDH session key with the WebCrypto key, RFC 6637),
`store.mjs` (sealing and passkeys), `mime.mjs`, `embed.mjs` (the message
frame), `title.mjs` (the subject frame), `setup.mjs`, `compose.mjs`, and
OpenPGP.js 6.3.2, unmodified (`openpgp.min.mjs`, LGPL-3.0,
https://openpgpjs.org).
