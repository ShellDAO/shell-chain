# Fixed L1 prover worker cohorts

Status: explicit cohorts and coordinated future epochs; unreleased.

The whitepaper describes disjoint proof work across Prover nodes. Independent
local queues currently let two healthy registered workers compute the same L1
window. Importing one winning proof does not recover the duplicated CPU work.

An explicit `prover.worker_cohort` provides a bounded initial operating mode.
Every worker uses the same distinct address list, sorted by address bytes.
Future membership is selected by the range's first source height, leaving ranges
which cross an activation whole. The owner index is the first source hash's first eight bytes interpreted as an
unsigned big-endian integer, modulo the number of members. An L1 range ends at
the first canonical block meeting the existing entry minimum. A worker with an
additional queued successor must therefore reserve the same range as a worker
which has only just received that threshold block.

Before listeners or CPU proving start, bind the sorted cohort to the local
prover database. Reopen accepts reordered configuration but rejects silently
changing or disabling a persisted cohort. Existing canonical proof artifacts
prevent recomputation. This metadata does not enter state roots, alter proof
validity, change rewards or validator registration, or require a new wire message
or signature domain. A fresh database with no cohort keeps independent scheduling.

Workers reserve ranges assigned to another member without running their CPU job.
These deferred reservations are bounded at 64 ranges. A stored proof or canonical
change releases them; storage errors retain the reservation until orderly
shutdown. Shutdown drains active jobs and releases deferred reservations so
normal canonical seeding can recover them on restart. Deferred entries do not
silently transfer to a different owner when that member is offline.

The initial cohort and at most 63 strictly increasing future epochs form an
explicit operator schedule. Persist the full schedule atomically as local
metadata. Only append epochs beyond the database's current canonical head;
never remove or rewrite an announced epoch. When migrating a static cohort,
replace its old metadata with a marker that makes static-only binaries fail
rather than silently ignore scheduled assignments on database reopen.

An operator must stop and synchronize all workers, install the same schedule,
and restart before the future activation. New identities still require normal
registration. Retiring workers retain their historical assignments. Fresh
joining nodes use the full historical schedule; reordering addresses within
an epoch is harmless. This does not negotiate conflicting operator schedules,
automatically discover members, or take over offline work. No exactly-once
computation claim is made for partitions or crashes. Proof and settlement rules
are unchanged.

The portable native acceptance is `tests/e2e/prover-cohort.mjs`. It uses genuine
ML-DSA signed transfers, two registered standalone provers, one validator, actual
libp2p and RocksDB. It checks one generated proof across both workers, canonical
receipts and state, rejection of a changed persisted cohort, and all-node reopen
without recomputation. Queue-level tests independently verify real STARK proofs
and prover authentication for disjoint assignments, bounded offline reservations,
canonical replacement, and storage-error preservation.

With `SHELL_COHORT_RECONFIGURE=1`, the same native entry adds two windows after
appending a future membership. It checks a whole range crossing the activation,
a subsequent proof from the new owner, rejection of backdating/history edits/
static downgrade, and physical RocksDB reopens with no recomputation.

`SHELL_COHORT_LATE_JOIN=1` additionally checks a freshly joining epoch-only identity.
The first two workers settle an initial window before the new key is registered.
The fresh fourth native process then synchronizes that history using the full
schedule, observes the historical balance and nonce without generating old proofs,
and proves a later range assigned only to its future membership. All four
databases reopen with balances, nonces, receipts and settlement counters intact.
This is explicit operator scheduling, not automatic recruitment.

## Completion order and recovery

Independent workers can complete later canonical ranges first. Storage admission
therefore verifies range structure, canonical sources, non-overlap, authentication,
compression and cryptographic source binding without requiring the L1 frontier
to have reached that range yet. The completed proof remains in the existing
amendment store; it is not placed in the settlement queue until its predecessor
is pending or settled. Recovery retains that proof instead of deleting and
regenerating it. Block inclusion, import and replay keep strict frontier ordering.
Committed settlement markers must advance before scanning recovery artifacts,
otherwise the just-settled proofs can be queued again.
Canonical settlement also removes fully covered queued tasks. A peer's proof
can arrive before the last local source task, leaving an otherwise permanent
sub-threshold prefix if those earlier tasks remain queued. Partial overlaps,
other layers and in-flight CPU jobs are preserved, and all queue indexes are
updated together. Ordinary validators recover only stored frontier proofs,
without creating proving tasks; storage read errors preserve artifacts for retry.

`SHELL_COHORT_DELAY_PREDECESSOR=1` exercises the same native entry with the earlier
owner absent until the later proof has been generated and its databases reopened.
It then checks source-ordered settlements, exact rewards and all-node reopen
without recomputing the completed range. This does not change owner selection or
add an offline takeover policy.
