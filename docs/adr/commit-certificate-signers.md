# Unique commit-certificate signers

Decoding certificate JSON directly into a string-keyed map can discard a
corrupt signature when a later entry repeats its name. Collecting normalized
addresses into another map can also discard entries whose different names
identify the same signer. A genuine remaining quorum can then cause finality
to advance even though some claimed entries were never checked. This does not
demonstrate signature forgery or duplicate weight inflation.

Decode map entries with a Serde visitor and reject repeated normalized
addresses before inserting or decoding their replacement values. Use the
same rule for the current tagged signatures and the legacy hex container.
Keep unique `Address(...)` spellings, signature tags and the existing rule
that a certificate uses one of those container formats, not a mixture.

The canonical encoder already emits unique canonical signer names. This
changes rejection of ambiguous input without changing the signature domain,
weighted threshold, block hash, activation schedules or valid encoder output.
It performs no database migration or rewriting of existing sidecars or
finalized cursors. All certificate intake paths use the shared decoder.

The regression uses real temporary signatures and controlled stored canonical
headers, checks every database row after refusal, then finalizes with a unique
genuine certificate. It also checks that rejected inputs cannot overwrite
evidence after finalization. These fixtures do not establish executed transfers,
peer transport, full quorum AIR or a public release.

```bash
cargo test --locked -p shell-node --lib fast_finalize -- --nocapture
cargo test --locked -p shell-node --lib commit_certificate_codec -- --nocapture
```
