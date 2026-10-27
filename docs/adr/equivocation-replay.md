# Persistent equivocation replay identity

## Decision

Authenticated local detection and received evidence share replay suppression. Use the
unordered pair of recomputed header hashes plus the offender identity, rather
than a message hash, signatures, or a permanent per-validator ban on further
penalties. This catches order reversal and different valid signature encodings
while preserving penalties for distinct evidence. Both header signatures must
pass the existing registered-key verification first.

Store one fixed-size marker per accepted pair under `node/equivocation/v1/`.
Commit that marker and the existing absolute penalty snapshot in one KV batch.
Do not retain a second unbounded in-memory set or expire markers, since expiry
would make old evidence chargeable again. Disk usage grows with distinct valid
pairs; receiving identical evidence does not create more records. Existing
challenge state and subsequent challenge penalties share the penalty snapshot.
A failed batch rolls back memory and leaves neither the marker nor its penalty.

The chain configuration's optional `equivocation_replay_height` is immutable
once scheduled, default-off, and bound by trusted snapshot import checks.
Activation uses the canonical head at reception, not an untrusted proof height.
A configured node records pre-boundary evidence but keeps legacy charging until
the boundary. It never reconstructs or removes historical penalties whose
original evidence was not recorded. Local replay protection cannot guarantee
that all nodes receive identical evidence at identical times.

When configured, wrap the existing challenge/penalty snapshot in a version-2
envelope at the same key. The legacy decoder requires top-level challenge
records and therefore rejects the envelope before network service starts.
An upgraded decoder checks the envelope version and its stored schedule, and
refuses missing or conflicting chain configuration. This deliberately prevents
an older writer from dropping the policy on its next save. Scheduling this
upgrade consequently requires upgraded binaries even before the boundary.
Complete KV snapshot export/import includes both the envelope and markers.

After activation, local import commits the penalty before queuing its verified
proof, so a detecting node cannot depend on an echo of its own broadcast.
The event loop drains activated evidence independently of canonical NewBlock
success: range sync and side-fork validation can authenticate an offense without
adopting the candidate as canonical. Legacy local detection and broadcast timing
remain unchanged before activation or without a configured schedule.
Do not copy only the penalty record or erase evidence keys to downgrade.

## Validation and limits

Regressions cover default-off behavior, the canonical-head boundary, write
failure and retry, order reversal, a distinct offense, recovery, schedule
conflicts and snapshot trust mismatch. The portable TCP/Noise acceptance uses
real ML-DSA signatures and independently observes effective weights from two
nodes, including RocksDB reopen and CLI snapshot restore. Its malformed-signature
control must leave weights unchanged. An optional older-binary check confirms
refusal without losing recoverable protected penalties. A separate real full-block fork case observes local and receiving-peer weight
agreement and restart persistence, without requiring competing-branch adoption.
This change is
unreleased and does not select an activation height for an existing network.
