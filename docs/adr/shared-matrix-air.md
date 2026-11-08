# Shared matrix AIR and resumable proof parts

## Context

Independent ML-DSA sender keys require separate matrix expansion statements.
Per-coordinate proofs repeat sampler and sponge transcripts, and checkpoints
duplicate public routing states. This limits the number of independently keyed
transactions that fit within the existing bounded full-proof job.

## Decision

Complete matrix version 2 binds all thirty row-major coordinates to the decoded
public-key seed. It verifies sampler and SHAKE128 bridge statements in groups of
at most eight coordinates, and full Keccak permutations in groups of at most
eight across the same ordered streams. Separate domains bind counts, endpoints
and ordering. Every original arithmetic constraint remains in the recipient AIR.

Version 2 polynomial objects and version 3 SHAKE objects carry routing witnesses
only. Standalone verifiers reject them. Only the complete matrix verifier accepts
them after checking every expected sampler, sponge and permutation group.

New jobs with more than eight distinct senders use checkpoint version 3. The
producer reconstructs witnesses from captured public inputs and persists each
proof part separately. Recovery and cross-job reuse decode and fully verify each
part against its current statement before continuation. Failed verification
writes no checkpoint. Existing index versions 1 and 2 keep their original layout
and immutable components when reopened; completed proofs remain readable.

## Consequences

Proof parts reduce duplicate transcripts and persisted routing without increasing
payload, checkpoint, job-count or transport limits. Routing reconstruction is
prover work; the recipient never substitutes native SHAKE or sampling for AIR
verification. Native permissions, consensus, execution, receipts, rollback and
historical replay remain independent requirements. Activation still requires the
existing explicit opt-in and operational gates. Capacity and load claims require
actual complete-flow evidence for the relevant key layout.

The executable acceptance entry is `tests/e2e/mldsa-full-proof.sh sixteen-keys`;
it requires an output directory as its second argument. The separate `verify`
mode replays retained proof bytes without generating new proofs.
