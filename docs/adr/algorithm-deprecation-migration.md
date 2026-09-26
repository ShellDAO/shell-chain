# Registered-account transactions after algorithm deprecation

## Context

The whitepaper's algorithm-agility section states that deprecation prevents new
address derivation while existing accounts remain operational. The legacy
transaction policy rejects all deprecated signatures, including registered
accounts trying to transfer their funds.

## Decision

Introduce an independent, default-off `algorithm_deprecation_height`. At and
after this candidate block height, built-in root-key transaction validation may
accept `Deprecated` only when the sender already has a registered public key.
Continue checking embedded-key conflicts, the account key hash, the actual PQ
signature, nonce, balance and all other transaction requirements. A funded but
unregistered address cannot acquire the exception. `PendingActivation` never
qualifies. Registered keys may have been rotated, so address re-derivation must
not replace the existing registered-key binding.

Use the execution/import header rather than the current head for replay. The
mempool uses the next block height. Read lifecycle status through the existing
branch-local registry override, preserving fork and historical isolation.
Persist the schedule in genesis/chain configuration, reject later edits or
removal, and validate it against the trusted snapshot configuration before
publishing imported data. Existing chains may add only a future activation.

## Scope and remaining work

This step enables ordinary transactions and AA bundles signed directly by their
registered root key. It supplies the transfer path for voluntary migration.
Session-key authorization, paymaster signatures, custom validator cryptographic
operations and validator consensus policy are separate assertions needed to
complete the whitepaper's broader operational guarantee. Do not globally mark
`Deprecated` as accepted: callers without account context could otherwise admit
new accounts. This schedule neither changes live network activation nor declares
the full algorithm-agility protocol implemented.
