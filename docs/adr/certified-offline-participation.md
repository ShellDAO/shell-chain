# Certified offline participation

## Status and scope

Unreleased implementation under validation. `offline_accounting_height` defaults
to absent and preserves legacy headers, state transitions and consensus paths.
Activation requires completed node, ecosystem and public-entry acceptance and a
future immutable chain schedule. Fresh isolated test chains may start at zero.

## Problem

Elapsed block distance cannot establish that a validator missed an assigned
proposal. A local timeout observation also cannot authorize canonical suspension.
Availability changes must survive import, branch replay, restart and snapshots
without deducting balances, stake or stored economic weight.

## Decision

Count consecutive assigned misses only from complete sequential view-change
certificates. Each certificate binds the chain, height, view and actual parent
hash and requires distinct address-bound PQ signatures with strictly more than
two-thirds effective voting weight. Include the bounded sequence in a separate
proposer-signed consensus header envelope. This preserves the prohibition on
block-header STARK settlement. Legacy opaque header data remains opaque before
activation.

The parent branch's epoch state determines proposal assignments and timeout
quorum. Follow that branch's ancestry to its boundary when canonical height
indexes describe a competing branch. Verify the complete sequence before
changing counters. A valid assigned proposal resets its consecutive counter.

At 100 misses, queue suspension for the common epoch boundary. Once triggered,
a later proposal cannot cancel that obligation. Suspension masks effective
consensus participation while retaining registered membership, stored weight,
stake, balance and governance rights. Reject a boundary that would leave no
participating validator until authenticated recovery resolves it.

Recovery requires a genuine registered root signature and the existing strict
weighted governance quorum. Bind the suspension generation in signed calldata;
old votes or held transactions cannot recover a later generation. Apply approved
recovery and reset the counter at a common boundary. Rejoining clears availability
state while retaining the monotonic generation. Preserve the independently
scheduled emergency-governance primary-algorithm restriction and its immutable
genesis fallback opt-in. A configured height alone must preserve the legacy opt-out.

Confirmation identities and weights use the target block's epoch, preserving
the existing boundary reload convention. Attestations, commit-certificate checks,
fork selection and finality must use the same branch context. A competing branch
that restores a member or changes a weight cannot borrow the live canonical
branch's quorum. Keep legacy paths unchanged before activation.

An early certificate can authenticate a current-roster quorum before its target
block exists, but cannot establish that block's actual roster or weight quorum.
Retain only the next height within the consensus-message budget, then fully
reverify after import. Malformed, tampered, algorithm-mismatched or insufficient
current-roster signatures cannot replace authenticated pending evidence.
Certificates requiring an unseen new roster can be verified from sync sidecars
after target state exists. An unsuccessful precheck must not suppress that
post-import verification. A known header must match the claimed height, so an
old published certificate cannot evict next-height evidence through a forged
height. Retention alone never advances finality.

A joining validator can reject pending transactions before its sender state
catches up. Gossip deduplication prevents replaying the identical signed payload
through gossip alone. After a successful empty response to a next-tip block probe,
resend the existing bounded nonce-ordered pending prefix directly to that peer.
Use a per-peer cooldown and retain ordinary signature, balance and nonce checks;
no new transaction-admission exception or network message is required.

Direct-message bursts can exceed the existing byte-bounded stream concurrency.
A stream cancelled before receiving any body must return a transport EOF before
application decoding; otherwise an empty JSON error can falsely penalize and ban
an honest peer. Keep the concurrency and byte bounds, malformed nonempty-message
rejection and peer-ban thresholds unchanged. This does not guarantee delivery of
every request; ordinary bounded synchronization retries remain necessary.

For an unchanged retained certificate, an existing canonical finalized checkpoint
is the trust boundary for the earlier quorum decision. Require matching durable
and in-memory finalized ranges, canonical hash, actual header height and exact
stored bytes; reverify every signature against retained address-bound keys.
Do not reinterpret that proof using later off-chain voting reductions. Stored
certificate or signer metadata alone is insufficient for an unfinalized block.
This uses existing atomic checkpoint/certificate/signer persistence without a
new storage format or wire message. It does not supply missing historical
sanction provenance to a cold importer or an unseen side branch.

Preflight the destination epoch state before committing startup rollback or
preferred-fork adoption. Publish the effective roster with the committed state.
Missing epoch state fails before canonical mutation. Preserve existing absolute
voting sanctions without applying another percentage reduction. Historical
changes to off-chain sanction evidence remain a separate acceptance obligation.

Retain and flush the complete current-height proof sequence before advancing an
activated local view. A failed write leaves the candidate view retryable. At
startup, reverify the sequence against the current finalized parent and roster;
stale observations cannot alter a different round. The diagnostic observation
journal remains separate from canonical participation state.

## Verification and remaining work

Source regressions use fresh genuine signatures, independent receivers and
explicit development timestamps. They cover 100 assigned certificates, epoch
suspension and root-authenticated recovery, historical state, physical process
reopen, trusted snapshots, atomic startup rollback and recovery forks with a
simultaneous weight update. Exactly two-thirds cannot authorize adoption or
finality, including through the commit-certificate path. Invalid side-branch
proofs cannot publish metadata.

Fresh native CLI/P2P acceptance with ML-DSA authorities weighted 3:1 covers
100 actual assigned timeouts, suspension, root recovery and a confirmed proposal
from the returning validator. An uninterrupted second profile uses an SLH-DSA
producer/recovery root and an ML-DSA returning validator, with matching recovery
receipts, canonical roots and historical suspension on three independent stores.
A shorter cold-join diagnostic separately verifies pending-pool recovery without
replacing the full lifecycle. Other configurations, additional native AA/resource
profiles and changing historical sanction context still require acceptance.
Source validation does not establish public release availability or network
activation. The regression entry is:

```bash
cargo test -p shell-node --features rocksdb canonical_timeouts -- --nocapture
```
