# Persist the algorithm selected during account key rotation

## Problem

AccountManager accepted an algorithm ID but stored only BLAKE3(pubkey). A rotated
SLH root could sign ordinary transactions after deprecation while its genuine
session authorizations and sponsor signatures were rejected. Trying compatible
active verifiers cannot reliably recover the selected algorithm, particularly
for ML-DSA and Dilithium keys.

## Decision

Use independent, default-off `registered_key_algorithm_height`. At that candidate
height and later, rotation and guardian recovery store BLAKE3(algo_id || pubkey)
in the existing account key-hash field. The ID is one byte, using the existing
address-derivation encoding without changing the account address. Combine this
state-root commitment with matching registered public-key bytes. Resolve the
algorithm only among installed IDs, then verify the genuine signature under
that exact ID and the applicable lifecycle schedule.

This avoids a new account serialization or uncommitted side table. Default
account validation, session-root verification and EOA sponsorship share the
binding resolver. Import batching reads its candidate parent state; sequential
validation still checks current transaction state. Pending algorithms fail
closed. Custom validator contracts keep their own policy. Mempool entries retain
the validated account commitment so canonical pruning does not evict valid
algorithm-bound roots.

## Compatibility and limits

Earlier heights write the original raw-key hash. Historical bindings are not
retrospectively assigned an inferred algorithm: an authorized rotation can
reaffirm the same key after activation. This is explicit migration, not automatic
upgrade of all existing accounts. The established direct/session/paymaster
lifecycle and rotated-root import/sponsor schedules remain independent.

The height is immutable, can only be added in the future on an existing chain,
and must match trusted snapshots. No transaction format, fee budget, consensus
signature rule or live activation height changes. Rotation followed by use of
the replacement key within the same imported block remains a separate limitation.

## Verification

Three genuine replacement algorithms exercise active, deprecated and pending
states for direct, session and sponsor authorization. Additional regressions
cover absent/pre/boundary/post activation, reaffirmation, matured recovery,
parent-state import binding, tampered signatures, transaction-pool pruning and
snapshot/startup configuration integrity. Runtime acceptance uses isolated nodes
and records actual receipts, fees, history and restart behavior separately.
