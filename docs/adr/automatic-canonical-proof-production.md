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

Bound registered genuine Dilithium3 senders use an explicitly versioned PQClean
raw transcript: SampleInBall consumes the first 32 of 48 c-tilde bytes, and mu
omits FIPS empty-context framing. The producer selects only signatures accepted
by that transcript; its final graph verifies the distinct challenge domain and
complete commitment through AIR. The existing Native verifier's SDK adapter
keeps its Native behavior and uses a distinct bound proof profile below. Shared tagged-key checkpoints
additionally require equal algorithm tags. No old source descriptor, proof
version, job quota or activation schedule changes meaning. The standalone
`dilithium-full-proof` entry covers pause/resume, peer Native import/finality,
ordinary successor state changes, cold replay and genuine-certificate refusal;
the `both` mode selects distinct genuine raw sender and proposer keys together.
Other account arrangements require separate qualification.

Genuine locked PQClean proposer seals can also be captured as full version-2
sources. Seal proof version 2 routes their header-hash message to the existing
raw32/no-context signature AIR; version 1 stays FIPS-only. Source restoration
checks the retained Native key/seal evidence for the selected transcript, and
final verification requires its matching proof version. SDK-adapter tag-zero
seals and older captured version-1 jobs keep sender-only semantics. The proposer
regression uses a primary65 sender, real peer Native import/finality and changed-
current-state historical replay. The `both` regression additionally consumes raw
sender profile 3 and proposer seal version 2 in the same full graph, with genuine
foreign raw certificate refusals. Defaults, quotas and schedules are unchanged.

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


Genuine unbound Dilithium3 default senders select account proof profile 4 and the
same raw signature AIR as bound profile 3. Their mandatory address certificate
uses the actual tag zero and full public key; initial Embedded and later Reference
sources resolve keys from their respective historical parents. SDK-adapter tag
zero is still excluded from raw proving. The `unbound` Dilithium entry requires
both original blocks to reach full proof-backed Native import/finality and checks
history after an ordinary third block under unchanged resource limits.


## Bound Native SDK FIPS senders

A parent-registered bound SDK sender under Native algorithm tag zero selects
account profile 5, transaction source envelope 3 and complete FIPS signature/
challenge version 1. The producer freezes that explicit selection in source
format 3. Its 48-byte sampler seed and empty-context framing remain distinct
from raw version 2. Old source formats 1/2 omit the selection field and retain
their exact bytes and meaning; outer batch versions still indicate the presence
of a proposer proof. Recovery rejects unknown, missing or relabelled markers.

`dilithium-full-proof.sh sdk output` retains real published SDK signer inputs and
uses its provider through actual local Node RPC. The same original graph must
complete automatic production, durable recovery, peer Native import/finality,
changed-state history and genuine/cross-profile refusals. Signed-input Native
intake and wrong-root rollback controls retain their own scope. SDK-tag-zero proposer proofs remain separate; no defaults, quotas,
activation or public-release status change.


## Funded unbound Native SDK senders

Account profile 6 routes Native tag-zero FIPS inputs to the same complete
transaction envelope 3/signature version 1 and mandatory full derived-address
AIR. New source format 4 freezes that unbound SDK choice; old bound source format
3, genuine raw formats 1/2 and all existing immutable jobs retain their meanings.
Recovery uses the captured parent MPT/key, never a later registry entry. Original
Embedded and Reference graphs must independently reach actual peer Native
import/finality before ordinary advancement and cold read-only dual replay.
The `sdk-unbound` entry exercises these boundaries through the published SDK and
keeps ordinary Native intake/registration rollback controls separately labelled.
There is no quota, default or activation change.
