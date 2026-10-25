# L1 prover worker cohorts

Status: explicit cohorts, coordinated future epochs and optional registry-derived membership; unreleased.

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

### Persisted proof delivery after reconnection

A CPU result can be durable before any peer receives its announcement. Recovery
into the local settlement queue alone does not deliver that result to an
independent validator. On peer connection, send recovered canonical L1 frontier
proofs directly to that peer; reuse the existing periodic transaction retry for
bounded proof rebroadcast as well. Read only the current frontier, reuse the two
pending settlement slots, and revalidate the complete ordered sequence, prover
authentication and canonical source binding before sending. Later stored ranges
remain behind a missing predecessor and become eligible after canonical progress.
Storage and transport errors preserve the original artifacts. Canonical
settlement removes the queued range and ends retries; neither recovery nor
rebroadcast starts a CPU job or increments the generated-proof counter.

The manual parallel acceptance mode uses pre-synchronized isolated dev workers
to make two short CPU calls overlap without pausing either call. It then rejoins
the native network, checks that settlement uses those exact proof bytes with
ordered rewards, and reopens the databases. This is a bounded concurrency and
delivery check; it does not qualify online recruitment, takeover or throughput.

### Recovery before local result handoff

A CPU worker persists its signed proof before handing it to the node event loop.
Frontier recovery can queue that exact proof while the result is still in flight.
After authenticating the local result and releasing its backlog reservation, the
receive branch recognizes an identical pending amendment or a range already
settled on the canonical chain. It leaves the stored artifacts, canonical
settlement metadata and any existing queue entry intact. Generated work is
counted once at handoff. Unsettled amendments still undergo the usual ordering
check; block inclusion never accepts
duplicate source ranges. This changes local result delivery only.

The focused regression pauses storage completion after a genuine 512-entry proof
is committed, recovers one pending settlement, then resumes the actual service
and guarded event-loop receive. A second timing settles the recovered proof
before resuming local handoff. Both check stored proof bytes, source pointers,
one settlement and its exact reward; the second also preserves the canonical
settlement transaction link. The deterministic in-process scheduling check
does not qualify native disk-crash recovery or wider network scheduling.

### Connected native proof work

Run the same acceptance entry with `SHELL_COHORT_CONNECTED=1` and its existing
`SHELL_NODE_BIN` and `SHELL_SDK_ENTRY` inputs. Use this unreleased cohort node
implementation built with `libp2p`; the connected scenario was verified with
published `shell-sdk@0.14.0-rc.2`. The authority stays online while
two registered standalone provers synchronize, generate disjoint scheduled
ranges and deliver their original proof bytes for ordered settlement. CPU start
and completion logs must show overlapping calls; successful settlement alone
does not satisfy the concurrency assertion. The entry checks peer connectivity,
exact rewards, balances, nonce, finality, and all three physical database reopens
without regenerating settled work. This bounded development-network scenario
retains explicit scheduled membership; automatic recruitment, offline takeover,
partitions and production throughput remain unqualified.

## Registry-derived membership

A standalone prover may instead select automatic canonical membership:

```toml
[prover]
worker_cohort_from_registry = true
```

The option defaults to false and cannot be combined with `worker_cohort` or
`worker_cohort_schedule`. The network must already configure
`prover_registry_height`; the option does not activate registration or change
that height. Initialize a fresh database with this compatible node and sync
through ordinary block execution. Registration still uses the normal native
registry transaction and does not grant validator authority. All coordinating
workers must use the same membership mode. Unconfigured independent workers
are not prevented from computing duplicate work.

Read registered identities from the finalized canonical state and retain only
records registered at or before a range's last source height. For backlog older
than every registration, use the first finalized registration height. Sort
addresses and reuse the first source hash modulo member count. Thus later
registrations join subsequent ranges without rewriting old ownership, even
when an older historical state root has been pruned. A range waits until its
last source is finalized and at least one eligible registration exists. Deferred
work becoming locally owned releases its reservation for ordinary canonical
reseeding, rather than executing an entry-cleared task.

The registry's current append-only, immutable registration-height semantics are
required for this historical derivation. A future deregistration or replacement
protocol must revisit this rule before use. The operational cohort supports at
most 64 registered members; a larger set is rejected rather than truncated.
An assigned member going offline still retains its historical ranges. This
mode adds recruitment, not a timeout, lease or takeover mechanism.

Address preimages live in an auxiliary local candidate index. Candidates from
rolled-back or orphaned execution are harmless: every discovery reads actual
registry storage at the selected trie root and verifies public-key identity.
Read candidates in bounded pages without imposing a cap on orphaned hints.
The hints, selected mode and writer coverage cursor are outside consensus state
roots and do not change genesis hashes, proof authentication, rewards or wire
formats. Ordinary non-cohort behavior remains available on old databases.

Fresh genesis initialization atomically certifies an empty index only when no
custom native-registry storage was supplied. Canonical execution/import captures
registrations and advances coverage with the block publication. Rewinds retain
candidate preimages but move coverage atomically with the canonical head. If an
older writer advances the database without capture, a later compatible writer
cannot silently certify that gap. Startup and assignment fail closed.
Snapshot candidates and coverage are not authenticated by the snapshot state
root; import ignores them and invalidates the destination's discovery certificate.
Legacy and snapshot index rebuilding remain unavailable in this initial mode.
A persisted registry mode cannot silently downgrade to independent scheduling
or a static list. Do not manually create or copy completeness markers.

The manual native acceptance uses the existing single entry:

```sh
SHELL_COHORT_REGISTRY=1 node tests/e2e/prover-cohort.mjs
```

Set `SHELL_NODE_BIN` to this compatible unreleased node built with `libp2p`, and
`SHELL_SDK_ENTRY` to a compatible SDK module (`shell-sdk@0.14.0-rc.2` is the
acceptance baseline). The isolated development network creates its own keys,
uses activation height zero, registers two workers, settles genuine transfers,
then normally registers a fresh third worker without editing the original
workers' configuration. It checks that worker's later range, original proof
bytes, exact canonical rewards, independent state/finality agreement and four
physical database reopens without regeneration. It does not qualify production
partitions, index rebuilding, or offline takeover.
