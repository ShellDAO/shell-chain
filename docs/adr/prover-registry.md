# Canonical standalone prover registration

Status: implemented behind optional, default-off `prover_registry_height`.

## Problem

The prover guide promises identities independent of consensus membership, but
its AddValidator request either fails for an unknown key or adds voting power.
The in-memory consensus ProverRegistry is not connected to execution or storage.

## Decision

Expose `registerProver(bytes,uint8)` at the existing native Registry and reuse
its strict weighted-majority membership admission rule in a distinct vote domain.
Derive the prover address from the submitted full PQ public key and algorithm;
store the identity, registration height and settlement counters in domain-separated
state-trie slots. This does not add a validator, require a prover funding
transaction, or change consensus weights. A vote receipt may succeed before
quorum, so clients must query the committed record and finalized block.

Admission verifies the existing amendment signature and canonical registration.
Producer execution, canonical import and fork replay enforce registration against
their execution-local state. Proof counts change only with successful settlements,
not gossip; transaction/batch rollback and state-root restoration therefore also
restore votes, registrations and counts. Pending recovery rechecks admission.

A dedicated activation schedule preserves old blocks and default deployments.
Registration rejects before activation. Registered-only proof rules start at the
settlement/admission height, including proofs of earlier sources. Import and replay
must not consult today's registry state. Startup allows only future scheduling;
saved schedules are immutable, and snapshot configuration must match before writes.

The existing unused consensus registry's numeric stake/reputation prototype does
not define token denominations or executable bonding rules. This change delivers
identity admission and accounting without inventing a monetary policy. Prover
bonds, challenges and removal remain separate capabilities to implement and verify.

## Verification

Native tests cover activation boundaries, governance authorization, duplicate and
malformed identities, all three signature algorithms, quorum, and AA rollback of
both pending votes and complete registrations. Storage/startup tests cover trusted
snapshot matching and persisted schedules. The two-node acceptance script verifies
512 real signed transfers, a standalone prover's actual authenticated STARK,
tampering rejection, unchanged authorities, replicated counters and RocksDB restart.
These checks do not constitute a public release or network activation.
