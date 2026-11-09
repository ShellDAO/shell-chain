# Automatic canonical sender-proof production

Status: unreleased implementation.

## Context

The offline complete-graph producer has no normal node lifecycle. The legacy
background accumulator combines at least 512 entries while complete sender
certificates are bounded per block to 16 transactions and can exceed native
settlement payload limits. Lowering that threshold or reinterpreting the
settlement carrier would change unrelated protocol behavior.

## Decision

Add a separately opted-in prover-role path at native canonical publication and
startup. Persist bounded public inputs and checkpoint jobs in the native store,
with an exclusive writer lock, atomic quota accounting and immutable logical source and
certificate bytes. Limit retained jobs to two and checkpoint key/value bytes to
256 MiB globally; reserve 64 KiB for terminal status/error metadata. The raw
availability cache keeps its existing separate 512 MiB bound. Refuse capacity
rather than deleting old state. There is no failed-job retry loop within a worker
session. Starting a new worker after repairing the cause rechecks each retained
failed job once, including its source and every cached mathematical certificate.
It atomically marks those attempts queued before publishing the worker handle,
so RPC observers distinguish the new attempt from the retained prior failure.
Failure never clears source data, bypasses a proof or authorizes Native execution.

Capture the canonical body, parent header, parent account MPT witnesses and
registry keys while the sealed historical view is available. On recovery,
strictly decode and canonically reserialize the source, verify its body
commitment and account witnesses against independently retained canonical
headers/mappings, then verify public-key commitments and raw signatures.
Never read the live registry/trie as the parent state. This recovery yields
inputs only; it cannot construct the canonical verifier's authorization token.
Recheck canonical identity before output publication and exposure. Stale jobs
remain retained, and forks cannot inherit their completion status.

Run one blocking CPU worker behind the normal readiness gate. Check readiness,
shutdown and optional per-process component budget between certificates. Resume
by rechecking every cached certificate with its exact inputs. Publish verified
raw bytes into the existing bounded chunk cache and expose a read-only job RPC
with the captured block and manifest. `complete` describes generation and
`ready` describes availability; neither attests native execution. Independent
consumers still require full AIR, source, consensus and execution validation.
Keep legacy accumulation, settlement, activation and pruning behavior unchanged.

Compact availability framing pools a complete BLAKE3 hash object when it fits the
existing per-certificate byte bound. Its compression certificates and public
inputs remain intact; this reduces dictionary entries without changing the hash
predicate. Larger hash objects retain bounded per-child framing. Availability
frame version 3 explicitly permits these containers; version 2
keeps its leaf-only predicate and remains readable alongside legacy JSON.
Dictionary count, payload, expansion and reference limits remain unchanged.
Older readers reject version 3; decoding still grants no verification authority.

Local account-MPT checkpoints share complete Keccak subcertificates in a
content-addressed dictionary under the same globally counted production
namespace. Component envelopes retain the original compact component length and
hash; restoration must reproduce its exact bytes before the producer rechecks
full AIR. Missing, altered, oversized, chained or unused dictionary entries
cannot supply a valid component. The per-component and global byte bounds,
logical job index, source identities and mathematical proof formats stay intact.

Only explicit opt-in producer startup compacts existing inline account
checkpoints, in one atomic batch when it reduces physical storage. New account
checkpoints use the same representation. Read-only status and historical replay
never compact. Shared parts and envelopes count toward the original 256 MiB
quota; a rejected batch leaves no orphan parts or counter changes. Atomic
accounting checks the final replacement batch, without exposing an intermediate
state. Inline legacy JSON and compact components and existing one-hop references
remain readable. Older workers cannot read dictionary envelopes; restore their
original logical component bytes, or retain a pre-compaction database backup,
before reverting the worker. This local storage format changes no Native chain,
account, key, receipt or consensus data and grants no admission authority.

## Validation and limits

Legacy JSON certificates can exhaust the shared physical quota when a rotation
introduces another independent key. Opt-in producer startup compacts eligible
inline JSON values in one atomic batch; new legacy values use the same bounded
zlib representation when it saves space. The envelope records the original byte
length and BLAKE3 hash. Decoding requires a complete stream, exact input/output
lengths and the original hash; truncated, trailing, changed or over-limit streams
refuse. Original JSON property order and whitespace survive exactly. Source
descriptors, job index versions, logical component hashes, per-job limits and
full AIR checks are unchanged. Compression uses the already locked implementation
and adds no mathematical primitive or native verification fallback.

References resolve the original bytes before their existing integrity checks.
Compressed storage and its metadata count toward the same physical quota.
Historical reads never rewrite it. Older workers require restored inline bytes
or the retained pre-compaction database backup before downgrade. No Native chain,
account, registry, receipt, activation or consensus data is migrated by this local
representation change.

The self-contained `mldsa-automatic-proof` regression exercises real Node.run,
fresh signatures, native import to height 130, cold pause/resume, authenticated
RPC download and independent CLI import/cold replay. Source/store regressions
cover stale canonical mappings, modified MPT/account/key/body inputs, unknown
source fields, quota accounting and immutable batch refusal. Simulated quota
boundaries do not establish a 256 MiB load test. Legacy cached producer graphs
must retain their original source identity after the source representation
change. Opt-in fresh peer admission is specified in
[live canonical admission](live-canonical-proof-admission.md). Fork/amendment
consumption, full proposer cryptography and compact settlement graphs remain separate work.
