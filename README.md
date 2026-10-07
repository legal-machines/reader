# Seal

Opens and writes end-to-end encrypted (OpenPGP) messages inside the Mail app
of legalmachines.org and dzyza.com, so that neither the mail server nor its
hosting company can read them or take the key.

It is served by GitHub Pages, not by the mail server: this repository is
https://seal.legalmachines.org, and legal-machines/reader2 is the same files
at https://seal.dzyza.com, except keys.html, which shows only its own
domain's key. The Mail app shows it in frames and hands it the
encrypted message, which the mail server holds anyway. The browser keeps the
Mail app out of these frames and out of this site's storage.

## Two keys, and why the public one cannot read

Every mailbox has a key pair, which works like a padlock and its key.

* **The public key is the open padlock.** It is published (the Web Key
  Directory at openpgpkey.<domain>, which GitHub Pages serves from
  legal-machines/openpgpkey and openpgpkey2, and Autocrypt headers, which
  the mail server writes) so that anyone can snap it shut: encrypt a message that only the
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
prove who wrote it. Messages written here carry the sender's seal (see
Writing), which does; Seal says "Sealed by" for one whose seal holds,
"Not sealed" for one without (written elsewhere, or encrypted by the mail
server on delivery), and warns when the sender written inside differs from
the one the mail server received it from. The Mail app's header says
"Encrypted", and "End-to-end encrypted" only once Seal reports that
the seal holds.

## Reading

* **A key of one's own, made here.** Someone whose mailbox has no key yet
  gets Create my key when they first sign in to Mail (and on Security). Seal
  makes the key in that browser (OpenPGP.js: Ed25519 with a Curve25519
  encryption subkey), seals it under a passkey like any other, and shows a
  sheet to print once: the address, the fingerprint and a recovery code of
  20 characters (100 bits). Mail gets only the public half and a copy locked
  with that code, which it files in the inbox as "Your encryption key" for
  the person's other devices. The copy is locked the classic OpenPGP way
  that Thunderbird and GnuPG open (iterated and salted S2K with SHA-256,
  AES-256), not with Argon2: what keeps a server from guessing the code is
  its 100 random bits, not the cost of each guess. (Keys Seal made before
  October 2026 were locked with Argon2 and AEAD; `setup.html` makes a
  classic copy of such a file.) Mail cannot publish the key: the owner of the keys reads the
  fingerprint with the person by phone or in person and publishes it from
  his Mac (`scripts/keys-approve.py` in the mail repository), since a key
  the server published could be its own.
* **The key stays on the device.** It is set up once per browser, in a tab of
  this site (`setup.html`, its address in the address bar), from the key file
  and its passphrase, and only a key of one of our mailboxes (`keys.mjs`). A
  tab another page opened (the Mail app's Add to this browser) asks for
  nothing: that page could still change it. Continue opens `setup.html` again
  in a tab no page holds, which takes the key over through this site's
  storage, still locked, for minutes at most; the passphrase is typed only
  there, and the first tab only hands the finished record back to the Mail
  app, waits for Mail to say it kept it, and closes. When Mail does not say
  so (the mail page moved on, or the key was added in a tab Mail never
  opened), Seal offers Connect to Mail, also on every key on `setup.html`:
  a tab of Mail, which cannot reach Seal's, opens at /keys/connect with the
  sealed record in the address's fragment (no request carries it), and Mail
  keeps it on a press there, and only when Seal's origin opened the page. Where the frames share this site's storage with
  its tabs (Chrome; Safari keeps frames apart), the hub also hands Mail the
  record of a key of the mailbox that Mail lacks. The mail server keeps a
  record only for the mailbox's own key, published or waiting. The decryption subkey is sealed (AES-GCM) under a key
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
  in any case. Pages of Seal never get the key back: they ask the
  worker for the one X25519 secret a message needs.
* **One frame does the work.** Each page of Mail has one frame of
  Seal, the hub (`hub.mjs`): it shows Unlock, opens every message the
  page hands it (OpenPGP.js loads once per page) and passes the content to
  Seal's other frames on the page (the letters, the lines of a list,
  the subject) on a BroadcastChannel of this site, which Mail cannot join.
  Until then each message shows its own encrypted text.
* **Your mark.** Four pictures made from the key (X25519 of the key with a
  fixed point, `mark.mjs`): the same on every device that holds the key,
  and out of reach of Mail and its server, which have only the public key.
  Seal shows them in one place only: at the foot of the text of an
  end-to-end message, while the keyboard is in Seal's composer, after a key,
  a touch or a paste of yours there (a page that only moves the focus into
  the frame does not light it), and while the whole composer is on the
  screen (so a page cannot cut the frame down to the mark); it goes at once
  when the keyboard leaves. In Chrome the composer must also not be covered,
  faded or shrunk (IntersectionObserver v2). On `setup.html`, in a tab of its
  own with the address bar in view, it shows behind Show my mark, and goes
  when the tab loses the keyboard. Shown anywhere without these conditions,
  Mail could cut it out of a frame of Seal and set it beside a field of its
  own; shown only while you type or attach in Seal, every key you press and
  every file you pick goes to Seal.
  The pictures sit two by two on a square; above it, the count of files
  Seal holds for the message, so a file that went to Mail instead shows
  by not raising it. A tap on either says what they are.
* **Seal keeps its own code.** `sw.js` carries the SHA-256 of every
  file of Seal (written by `make-pins.py` at publishing), installs
  only when the site serves exactly those, keeps them, and serves Seal's pages from that copy; only a page it served may use the key.
  Code served later by someone else would need a new `sw.js`, and a new
  worker starts with an empty vault: nothing opens without a new touch.
* **Mail learns sizes, coarsely.** A letter is laid out at one of a few
  fixed widths and its height is reported in steps of 32 pixels; the
  subject's room in steps of 48. Otherwise Mail could narrow a frame step
  by step and learn from its height where the lines break. The hub opens a
  message only when a frame on the screen asks for it.
* **The message looks like any other.** Inside a conversation Seal
  draws the text, pictures and attachments with the Mail app's own
  stylesheet and icons (`mail.css`, `icons.mjs`, `letter.mjs`, copied from
  its source by `make-styles.py`, never from the mail server). The subject
  goes to the Mail app's title line through `title.html`, a frame of this
  site that the message's frame hands it to on a BroadcastChannel; the Mail
  app learns only its size.
* **Inert content.** HTML messages are stripped of scripts, frames, forms and
  remote addresses and shown in a sandboxed frame without scripts.
  Attachments are only downloaded or shown in the browser's own viewer.
* **Senders outside our mailboxes** (`dkim.mjs`, `contacts.mjs`). Mail hands
  Seal the whole message as the server holds it, and Seal reads the sender
  and the encrypted text out of it itself. The sender is the one address of
  its one From field, read strictly: a name holding @, < or >, two
  addresses, or a header field that is not written by the rules, and nothing
  vouches for it. Seal checks the DKIM signature of the sender's domain in
  the browser: the key comes from public DNS through Cloudflare and Google,
  and counts only when both give the same, so the mail server, which holds
  no such key, cannot make up or change a message that passes. Only the
  sender's own domain counts, for a failure or for "could not be checked"
  as much as for a pass. A message that passes, and was first opened so,
  stays passed (by the SHA-256 of the whole message) after the domain
  withdraws its key. The encrypted text counts as the sender's only when the
  message is it as a whole (PGP/MIME, or a text body that is one armored
  block); encrypted text quoted or forwarded in a message opens with a
  warning that nothing around it vouches for it, and teaches Seal no key.
  Whether the message is the encrypted text as a whole is read from its
  Content-Type, so for learning a key the domain's signature must sign that
  field too (and Content-Transfer-Encoding and MIME-Version where the message
  has them), each as often as the message has it: otherwise a mail server
  could change an unsigned Content-Type and have text quoted in a signed
  message read as the whole of it.
  Seal learns the sender's OpenPGP key only from what the domain signed (the
  Autocrypt header when the signature covers it, or a key inside the
  encrypted text). It keeps the first one for that address, and encrypts to
  it, only when the message is also signed with that key: the domain's
  signature says its mail service sent the message, not that the key in it
  is the person's. A first key in a message not signed with it is only
  offered under that message, with its fingerprint, for you to take once you
  have read the fingerprint with them (kept as checked);
  a different key later waits, and no later one takes its place, until you
  accept it by the fingerprint shown, under the letter that brought it or in
  the list on the Mail app's Security page (`people.html`, a frame of Seal:
  Safari keeps a frame's storage apart from Seal's own tabs, so the keys live
  where the frames that open and send messages are). Our domains and any name
  under them never count as outside. The sender's own signature in the
  message is checked with the key Seal knows, and with a key the message
  brings. The letter then says "Signed
  with the key of", "Sent by the mail of" the domain, or warns: changed on
  the way, signed by another domain, a new key, quoted or forwarded, a From
  that names no one plainly, or a message from someone whose key Seal knows
  that carries neither their signature nor their domain's.
* **Show my mark** ends every line that vouches for a letter ("Sealed by",
  "Signed with the key of"): Mail could draw such a line beside a message of
  its own, but not your mark. It shows for ten seconds on a press of yours,
  while the frame has the keyboard and the whole line is on the screen (so the
  frame cannot be cut down to the mark), and in Chrome only while nothing
  covers or fades it.

## Writing

`compose.html` is the Mail app's composer from the Subject line down when End
to end is on, in its own look: a For line with the addresses Send will
encrypt to (Bcc too), the formatting bar with its own clip for files, the
signature, pictures in the text. The subject, the text and the files stay
there. The Mail app hands over the signature alone; the notices under it
(the end-to-end one and the domain's own) Seal writes itself, from
`notices.mjs` (made by `make-notices.py` from the mail repository), so the
mail server has no say in what they tell the recipient.

`send.html` is Send: Seal's own button where Mail's stands. Only a
press there has the message sealed with your key (`seal.mjs`; Touch ID first
if encrypted mail is locked) and encrypted, as one PGP/MIME message padded
to steps of 4 KB, to the public keys in `keys.mjs` (made by `make-keys.py`
from the mail repository's published keys, never taken from the mail page).
Send finds the composer itself, by walking the frames of its own tab
(`tab.mjs`), and refuses if there is more than one: the Mail app cannot
point it at a composer of its own. The sender must be a mailbox here with
its key, and every recipient a plain address with a key: ours from
`keys.mjs`, someone outside with the key Seal learned from their signed mail
(`contacts.mjs`; a new key waiting for you stops the message, and the For
line names each recipient's key: from their mail, checked, new, none). A
message goes sealed or not at all (no key of yours in this browser, no
sending), with its own Message-ID inside; the seal goes to our mailboxes
only. The
Mail app gets the encrypted message and sends it; it cannot have a draft
encrypted at any other time. A time picked in Schedule send waits for that
press. A reply quotes an encrypted message as "X wrote" only when its seal
holds, and says "not sealed" otherwise.

`keys.mjs` lists no addresses: it has one entry a key, with the SHA-256 of
each address the key serves (lower case, hex) and the key itself with one
user ID, an address our sites show anyway (inbox@ the domain). Seal
hashes an address to find its key. A short address can still be found by
trying names against the hashes; they keep the list out of sight, not
secret.

* **Your OpenPGP signature** (`sign.mjs`). A message Send encrypts is
  signed with your key that signs (a signing subkey, or a primary key that
  signs: Ed25519), as OpenPGP apps write it, so a recipient's app (Thunderbird,
  Proton, GnuPG) checks it with your published key; a message the mail server
  encrypts to someone in your name carries none. To people outside a message
  goes signed or not at all; between our mailboxes the seal vouches for it,
  and it is signed where the key in this browser signs. The key that signs is
  sealed beside the key that decrypts, under the same passkey, and bound to
  its record (this browser's own copy of a record stands over Mail's); while
  unlocked it waits in the vault, which signs only for Send and only a
  signature on a message, making the digest itself. It is taken from a key
  file only where it is part of the published key. A browser that added the
  key before this signs nothing until the key is added again, once.
* **The keys of people you write to, alike on your devices.** Mail keeps the
  list sealed under a key made from yours (X25519 with a point of its own,
  which no message can lead the vault to, through HKDF): it can neither read
  nor change it, only hand over an older copy or none, which a device that
  knows nothing yet would take and pass on. So a merge never puts one key in
  another's place: only your own Use the new key does that, on any of your
  devices, when it is later than the key in use there came into use; any
  other key a merge brings waits beside it for you to accept or decline.
  Checked goes with the fingerprint you were shown; forgotten keys stay as
  dated marks, and the newer stands. Mail keeps a copy only over the one the
  hub merged, and a copy the key does not open is left alone. The hub merges
  it in once your key is open and hands it back when it changes.
* **The sender's seal.** Encryption alone proves nothing about who wrote a
  message: anyone can encrypt to a public key, the mail server too.
  Seal adds, for each recipient, an HMAC over the whole message under the
  X25519 secret of the sender's key and the recipient's: only those two keys
  can make or check it. A letter whose seal holds says "Sealed by" and the
  sender written inside, when the sealing key is that address's key (by its
  hash); otherwise it warns that the message was sealed with the key of
  another mailbox, and names that key's domain. One whose seal does not hold
  is marked as such. The line gives the time sealed, to the minute, so an
  old message passed off as new shows its own.

## No network, and watched

* Every page carries a Content-Security-Policy that allows no requests
  beyond this site's own files: nothing decrypted, and nothing about the
  key, can be sent anywhere. One page alone reaches the network: `dns.html`,
  in a hidden frame of the page that opens a letter, asks cloudflare-dns.com
  and dns.google for the DKIM key of a sender's domain, by the selector and
  domain the message shows in the open, and holds no key and no message.
* `SHA256SUMS` lists every file's hash. Two watches compare what is served at
  both addresses with it, and look for signs that someone else serves these
  names: the domains' delegation and DNSSEC at their registries, the CNAMEs
  of seal.<domain> and openpgpkey.<domain> at deSEC, and certificates for the
  names in the Certificate Transparency logs that GitHub Pages does not
  serve. One runs on the mail server every 10 minutes, one here in GitHub
  Actions, also every 10 minutes (`watch/`; cron-job.org starts each run
  through the API, since GitHub starts a schedule only every few hours),
  which also checks the Mail app's own files against what was deployed. The
  mail server's watch reports a problem when the one here has finished no
  check for three hours. The mail server's watch also checks every served
  file against the hashes `publish.sh` sends it from the owner's Mac at each
  publish, not against GitHub's own SHA256SUMS, so a change made at GitHub
  alone, sums and all, shows there; and both watches require that nothing
  is served at /.well-known/webauthn, which would let other sites, the Mail
  app among them, use this site's passkeys. The mail server's DNS token can
  change only its _dmarc and _mta-sts records, so the server cannot repoint
  these names itself. While either reports a
  problem, the Mail app opens no encrypted message, adds no key and offers
  no End to end by itself.
* A watch run ends in one of three states: a problem; not verified, when a
  check could not be done (the network, an API's limit or error, a file or
  `SHA256SUMS` that could not be fetched), which is never taken for all
  clear; or all clear. A file that differs stays a problem when GitHub's
  history cannot be read. The run here fails on a problem and on "not
  verified" alike, so GitHub mails its owner either way, apart from the mail
  server; the mail server's watch tells the two apart and stops the Mail
  app's encrypted mail only on a problem.
* What the watches cannot do: they see what is served to them, from where
  they ask, and some public records (DNS, the CT logs, our keys). They
  cannot prove what one person's browser was served, so a change served to
  one person only, or only now and then, may pass them; nor do they see what
  a page of the mail server shows a signed-in user. Nor can they notice the
  mail server or its hosting company copying or reading what it stores:
  encrypted mail stays unreadable to them, but nothing reports that it was
  read, and ordinary mail they can read anyway.
* Both watches also check our public keys as the mail server hands them out
  against this repository's copy (`watch/keys.json`, made by
  `make-keys.py`: fingerprints, subkeys and the Web Key Directory hash of
  each address, no addresses): the fingerprint on
  https://mail.<domain>/encryption, and the key for each address from the
  Web Key Directory and from that page's download, asked by hash. Each must
  be exactly our key, with that address's user ID alone. The mail server's
  own run reads `watch/keys.json` from GitHub.
* `keys.html` shows the fingerprint of its own domain's key (each site its
  own), for people to compare with the one their mail app shows. GitHub serves it from this repository, so
  the mail server and its hosting company cannot change it; the Mail app's
  guide (/encryption) sends people here to check.

## What staying unlocked costs

While encrypted mail is unlocked, the key is in the memory of this site's
service worker on that device. Exactly what that allows:

* **This site's code** as published can open any message to that key
  without a touch. Code served by anyone else (through GitHub, or the
  names' DNS) cannot: pages not served from the worker's checked copy may
  not use the key, and a new `sw.js` means a new worker with an empty
  vault. Such code could still ask for a new touch; the watches see a
  change served to them within about 10 minutes, but not one served to one
  person only (see No network, and watched).
* **The mail page** (its server, its hosting company) can hand Seal
  stored encrypted messages and have them shown in frames on the screen,
  without a touch. It cannot read what is shown; it learns each frame's
  height at a few fixed widths, in steps of 32 pixels: about the length of
  the text, which the size of the encrypted message tells anyway. It
  chooses the time without use and reports use, so a page that lies can
  keep the window open, but not past an hour without anything done in Seal's own frames, nor past 5 minutes out of sight (Seal's own
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
  mark in view; Safari and Firefox give a frame no way to tell, and frames
  of letters cannot tell whether they are seen there either.
* Stop Mail from showing what it likes in the composer: it hands over the
  signature (cut to a signature's length, without quotes; Seal's notices
  come after it) and who the message is from and for (the For line shows
  both as Send will use them, and Send refuses a list changed in the two
  seconds before the press). Read the For line and the text before Send.
* Stop a page from asking for screen sharing: a person who allows it shows
  that page everything, the mark included. Never share the screen with the
  Mail app.
* Hide who writes to whom and when, or mail that arrives unencrypted: the
  mail server encrypts that on delivery, but has read it by then.
* Stop a mail page that ignores all of the above from drawing a whole
  composer of its own, clip and Send included, with no reader in it. It
  cannot show your mark; a person who does not look for it can be fooled.
* Prove the sender of mail written elsewhere that neither its writer nor its
  domain signed: it says "Not signed". Nor tell which person at a domain sent
  a message only the domain signed.
* Make a recipient look at the signature: an app that shows unsigned mail
  quietly leaves it to them to notice that a message in your name lacks it.
* Prove that a message was delivered, or that one sent to you was not held
  back. A reply signed by the other side's domain that answers yours shows it
  arrived.
* Keep the mail server from changing what it writes in ordinary mail: the
  Autocrypt key in its headers, the footer and the /encryption page. The
  Web Key Directory and keys.html, which GitHub serves, are where to check.
* Hide the size of a message from the mail server, beyond steps of 4 KB.

Files: `sealed-core.mjs` (ECDH session key, RFC 6637), `store.mjs` (sealing
and passkeys), `vault.mjs` and `sw.js` (the key while unlocked), `hub.mjs`
(Unlock and opening), `decrypt.mjs`, `mime.mjs`, `mark.mjs`, `embed.mjs`
(a letter), `row.mjs` (a line of a list), `title.mjs` (the subject),
`compose.mjs`, `send.mjs` and `sign.mjs` (writing), `tab.mjs` (Seal's frames in a
tab), `seal.mjs` (the sender's seal and key lookup by hash), `dkim.mjs`
(the signature of a sender's domain), `dns.html` (its keys, the only page with network), `contacts.mjs` and
`people.html` (keys of people outside), `keys.mjs` and
`keys.html` (our public keys, from `make-keys.py`), `notices.mjs` (from
`make-notices.py`), `setup.mjs`, `width.mjs`, `publish.sh` (both sites, with
`make-styles.py` and `make-pins.py`), `tests/` (plain `node` and `python3`, nothing
to install: `node tests/learning.mjs`, `node tests/key-verdict.mjs`,
`python3 tests/test_watch.py`), and
OpenPGP.js 6.3.2, unmodified (`openpgp.min.mjs`, LGPL-3.0,
https://openpgpjs.org).
