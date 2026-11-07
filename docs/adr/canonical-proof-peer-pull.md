# Dedicated transfer of retained canonical proofs

Status: accepted for unreleased node source.

## Context

A complete sender proof can exceed the existing peer-message limit. The local
admin upload store already bounds and persists its raw bytes, then verifies
the complete graph and replays retained canonical transactions. Legacy direct
messages can fall back to gossip, which cannot preserve an explicitly selected
provider as the response source. A provider can also send immutable chunks
whose corruption becomes detectable only after the final payload hash.

## Decision

Use a separately negotiated `/shell/canonical-proof/1` stream over the existing
authenticated transport. An administrator pins the provider and manifest;
responses must match that peer, proof ID, chunk index and outstanding persisted
nonce. Keep the existing message ceilings and bandwidth bounds. Send one chunk
at a time and stop after bounded retries or disconnect, retaining progress for
explicit resume. These frames never use the legacy stream or gossip fallback.

Reuse the upload store and Node verifier instead of treating transport or stored
status as proof approval. Put the immutable manifest and chunk geometry in the
shared core crate, retaining the original identity hash and storage reexports.
The receiver checks its own canonical source and verifies the complete received
graph before reporting a successful historical replay.

Retain a hash-corrupt generation and reserve a fresh generation under the same
manifest on explicit retry. Failed bytes remain inspectable and count toward
the same eight-attempt and 512 MiB total limits. Keep generation-zero keys and
metadata readable. A correctly hashed but invalid proof is rechecked explicitly
rather than downloaded again. This local artifact cache does not change block
admission, proof reward settlement, pruning authorization or activation.

## Validation

`tests/e2e/mldsa-p2p-proof.sh` consumes the independently generated native Node
and HTTP proof fixtures described in `docs/mldsa-transaction-source-proof.md`.
Its transfer mode runs actual TCP/Noise peers and Node loops, rejects wrong
peer/nonce responses, reopens partial storage, retains a failed payload and
verifies a fresh generation against independent native receipts and state.
Verify mode cold-rechecks the received graph and retained failure without
changing canonical state. Focused tests cover protocol and quota bounds,
unsolicited data, archive reopen and nonce recovery. Fresh block/amendment
consensus consumption, larger sender batches, hostile power loss and public
release/network activation remain separate acceptance work.
