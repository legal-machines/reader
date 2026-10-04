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
* **One touch for a while, not one per message.** A touch of the passkey
  (and the PIN, if there is one) unlocks every encrypted message at once:
  the key goes into a service worker of this site (`sw.js`, `vault.mjs`)
  and stays in its memory, never on a disk, while Mail is used. It is
  locked by Lock encrypted mail (the menu under the owner's picture), by
  signing out, by closing every Mail tab (the browser ends the worker
  about half a minute later), by restarting the browser, after the chosen
  time without use (5, 15 (the default), 30 or 60 minutes, or every
  message), after 5 minutes with no Mail page in view, and after 12 hours
  in any case. Pages of the reader never get the key back: they ask the
  worker for the one X25519 secret a message needs.
* **One frame does the work.** Each page of Mail has one frame of the
  reader, the hub (`hub.mjs`): it shows Unlock, opens every message the
  page hands it (OpenPGP.js loads once per page) and passes the content to
  the reader's other frames on the page (the letters, the lines of a list,
  the subject) on a BroadcastChannel of this site, which Mail cannot join.
  Until then each message shows its own encrypted text.
* **Your mark.** Four pictures made from the key (X25519 of the key with a
  fixed point, `mark.mjs`): the same on every device that holds the key,
  and out of reach of Mail and its server, which have only the public key.
  The reader shows them in one place only: the Subject line of an
  end-to-end message, while the keyboard is in the reader's field (and
  once, on `setup.html`, in a tab of its own). Shown anywhere without that
  condition, Mail could cut them out of a frame of the reader and set them
  beside a field of its own; shown only while you type in the reader,
  every key you press goes to the reader.
* **Mail learns sizes, coarsely.** A letter is laid out at one of a few
  fixed widths and its height is reported in steps of 32 pixels; the
  subject's room in steps of 48. Otherwise Mail could narrow a frame step
  by step and learn from its height where the lines break. The hub opens a
  message only when a frame on the screen asks for it.
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

`compose.html` is the Mail app's composer from the Subject line down when End
to end is on, in its own look: the formatting bar, the signature with the
end-to-end notice, pictures in the text and attachments (the clip,
`attach.html`, stands where Mail's does and hands the files straight to the
composer). The subject, the text and the files are encrypted there, as one
PGP/MIME message, to the public keys in `keys.mjs` (made by `make-keys.py`
from the mail repository's published keys, not taken from the mail page),
so the Mail app receives only the encrypted message. No private key and no
passkey are needed to write.

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

## What staying unlocked costs

While encrypted mail is unlocked, the key is in the memory of this site's
service worker on that device. Exactly what that allows:

* **This site's code** can open any message to that key without a touch.
  It is GitHub's to serve: if someone made GitHub, or the names' DNS, serve
  other code during the window, that code could open every stored message
  quietly, where before it needed a touch for each. The watches see such a
  change within 15 minutes; Lock or a short window bounds it.
* **The mail page** (its server, its hosting company) can hand the reader
  stored encrypted messages and have them shown in frames on the screen,
  without a touch. It cannot read what is shown; it learns each frame's
  height at a few fixed widths, in steps of 32 pixels: about the length of
  the text, which the size of the encrypted message tells anyway. It
  chooses the time without use and reports use, so a page that lies can
  keep the window open, but not past an hour without anything done in the
  reader's own frames, nor past 5 minutes out of sight (the reader's own
  pages tell that), and without reading anything.
* **Someone at the unlocked device** reads encrypted mail without a touch
  until the window ends, as they would read the rest of the open mailbox.
* **The device itself**: a program that reads the browser's memory (or its
  swap, a crash report) can find the key, as it could find the text.

## What it cannot do

* Protect a device on which someone else's program records the screen or
  the keyboard.
* Stop whoever serves these files from changing them: GitHub, or someone who
  takes the names through their registrar or DNS. The watches make such a
  change visible within minutes, not impossible, and a change served to one
  person only may pass them.
* Stop the mail server's hosting company from drawing a fake text field in
  place of `compose.html`. Your mark shows only in the real one, and only
  while you type there (a field laid over it would take the keyboard, and
  the mark would go); a person who does not look for it can still be
  fooled. Before the key has been opened once in a browser, that browser
  knows no mark yet. A fake letter can be laid over a real one, leaving the
  mark in view; Safari and Firefox give a frame no way to tell.
* Hide who writes to whom and when, or mail that arrives unencrypted: the
  mail server encrypts that on delivery, but has read it by then.
* Cover a file dialog with the mark: a mail page that draws its own clip
  in place of the reader's gets the files picked through it.
* Prove the sender: messages are not signed, so the mail server could
  write an encrypted message in anyone's name. The reader warns only when
  the name inside differs from the sender the server reports.
* Stop a lying mail page from asking the composer for its encrypted copy
  before Send, to recipients of the page's choosing among our mailboxes
  with keys. It learns no more than the size, padded to steps of 4 KB.

Files: `sealed-core.mjs` (ECDH session key, RFC 6637), `store.mjs` (sealing
and passkeys), `vault.mjs` and `sw.js` (the key while unlocked), `hub.mjs`
(Unlock and opening), `decrypt.mjs`, `mime.mjs`, `mark.mjs`, `embed.mjs`
(a letter), `row.mjs` (a line of a list), `title.mjs` (the subject),
`compose.mjs` and `attach.mjs` (writing), `setup.mjs`, `width.mjs`, and
OpenPGP.js 6.3.2, unmodified (`openpgp.min.mjs`, LGPL-3.0,
https://openpgpjs.org).
