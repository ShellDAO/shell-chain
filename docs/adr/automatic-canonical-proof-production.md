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
with an exclusive writer lock, atomic quota accounting and immutable source and
certificate bytes. Limit retained jobs to two and checkpoint key/value bytes to
256 MiB globally; reserve 64 KiB for terminal status/error metadata. The raw
availability cache keeps its existing separate 512 MiB bound. Refuse capacity
rather than deleting old state. There is no job retry loop after failure.

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

## Validation and limits

The self-contained `mldsa-automatic-proof` regression exercises real Node.run,
fresh signatures, native import to height 130, cold pause/resume, authenticated
RPC download and independent CLI import/cold replay. Source/store regressions
cover stale canonical mappings, modified MPT/account/key/body inputs, unknown
source fields, quota accounting and immutable batch refusal. Simulated quota
boundaries do not establish a 256 MiB load test. Legacy cached producer graphs
must retain their original source identity after the source representation
change. Automatic fresh peer admission, fork/amendment consumption, full
proposer cryptography and compact settlement graphs remain separate work.
