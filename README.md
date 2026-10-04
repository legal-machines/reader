# Mail Reader

Opens end-to-end encrypted (OpenPGP) messages inside the Mail app of
legalmachines.org and dzyza.com, so that neither the mail server nor its
hosting company can read them or take the key.

It is served from here, by GitHub Pages, at https://reader.legalmachines.org,
not by the mail server. The mail page shows it in a frame and hands it the
encrypted message, which the mail server has anyway; the browser keeps the
mail page out of this frame, and out of this site's storage.

* **The key stays on the device.** Set up once on `setup.html` with your
  secret key file and its passphrase. The decryption subkey is sealed
  (AES-GCM) under a key made from a passkey's PRF output (Touch ID, a
  fingerprint, the screen lock or a security key) and a device PIN; only the
  sealed copy is stored, in this site's IndexedDB. Opened, it becomes a
  non-extractable WebCrypto X25519 key, which no script can read back, and it
  lives only in the memory of one page.
* **Every message opens with the passkey and the PIN.**
* **No network.** Both pages carry a Content-Security-Policy that allows no
  requests beyond this site's own files: nothing decrypted, and nothing about
  the key, can be sent anywhere.
* **Inert content.** HTML messages are stripped of scripts, frames, forms and
  remote addresses and shown in a sandboxed frame without scripts.

Files: `sealed-core.mjs` (ECDH session key with the WebCrypto key, RFC 6637),
`store.mjs` (sealing and passkeys), `mime.mjs`, `embed.mjs` (the frame),
`setup.mjs`, and OpenPGP.js 6.3.2, unmodified (`openpgp.min.mjs`, LGPL-3.0,
https://openpgpjs.org). `SHA256SUMS` lists every file's hash.

What it cannot do: protect a device on which someone else's program may
record the screen, and protect against GitHub itself changing these files
(compare them with `SHA256SUMS` and this repository's history).
