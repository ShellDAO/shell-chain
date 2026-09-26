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

## Session authorization by original registered roots

Use a separate, default-off `algorithm_session_deprecation_height` so the
root-transaction schedule retains its original meaning. At activation, authorize
an active session under an original registered root whose address algorithm is
`Active` or `Deprecated`. Resolve the root algorithm from the registered key and
account address before verifying its signature. This prevents ML-DSA's legacy
Dilithium compatibility fallback from masking a pending ML-DSA registry entry.
Preserve that historical fallback before activation and when the schedule is
absent. New addresses still require an active root algorithm.

Share root verification between AA validation and both canonical and fork block
import. Only the actual branch-local registered key qualifies; an earlier
embedded key collected during batch preparation alone is insufficient. Keep
session algorithm status, signature binding, expiry, value cap and target checks.
Apply the same immutable, future-only scheduling and trusted snapshot checks as
the direct-root upgrade, using the explicit candidate height for replay.

The exception covers address-derived original roots. Rotation preserves the
address without recording the new algorithm identifier; legacy active-only
root verification and import's address-binding restriction remain in place for
rotated keys. Persisting a rotation algorithm and defining its upgrade semantics
requires a separate implementation. This bounded step does not close that gap,
change paymaster or validator policy, or activate a live network.

## Import binding after a confirmed key rotation

A separate `session_registered_root_height` repairs the mismatch between AA
validation, which uses the registered key, and import batching, which previously
required that key to derive the sender address. At and after activation, import
may use an exact match with the current branch's registered public key. Full AA
validation still checks the account public-key hash and both session signatures.
Canonical import and fork replay call the same batch helper.

This schedule is independent of the original-root deprecation exception. Before
activation, and when omitted, import retains its historical address check. Store
and validate the immutable schedule using the existing future-only startup and
trusted snapshot rules. Coordinate activation across participating nodes.

The bounded change covers rotations confirmed in a prior block. It neither
persists an algorithm identifier for rotated keys nor changes their existing
active-verifier fallback policy. Same-block rotation may still be rejected by
parent-state batch/prevalidation; supporting it requires a separate validation
ordering change. Full network activation is not implied by source availability.
