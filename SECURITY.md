# Security fixes

Fixes made to Seal after its reviews, newest first. To report a problem,
write to postmaster@legalmachines.org.

| Date | Fix | Commit |
|---|---|---|
| 2026-10-07 | A sender's key is learned only when their domain's DKIM signature also signs the fields that say how to read the message (Content-Type, and Content-Transfer-Encoding and MIME-Version where present), so a server on the way cannot have quoted encrypted text read as the whole message. A first key is kept only from a message signed with it; otherwise Seal offers it with its fingerprint to check. | `25082ad` |
| 2026-10-07 | The check page says a key is safe to publish only for a record of the requested address, with the same encryption subkey and the primary key as its signer. | `25082ad` |
| 2026-10-07 | The watch reports a check it could not run as not done (UNVERIFIED), never as clear, and keeps a changed file an alarm even when GitHub's history is unavailable; its run fails in both cases. | `25082ad` |
| 2026-10-07 | Making a new key no longer deletes the older keys kept in the browser: mail encrypted to them still opens until their owner removes them. | `72c6ea1` |
| 2026-10-07 | The README describes the recovery copy's protection as it is (iterated and salted S2K) and says what the watches cannot see. | `25082ad` |
