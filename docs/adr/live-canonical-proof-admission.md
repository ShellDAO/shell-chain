# Live canonical sender-proof admission

Status: unreleased, opt-in implementation.

## Context

Complete sender graphs can exceed ordinary block and amendment frames. An
already canonical block can be replayed with a downloaded graph, but a fresh
follower needs an independent current parent before it can accept that block.
A producer's completed job and a cache's verified flag are never authorization.

## Decision

At ordinary `NewBlock` and `BlockResponse` intake, a separately enabled follower
stages an eligible signed extension as an untrusted immutable local source.
Keep at most two retained bodies, each at most 2 MiB. Admit only the existing
1–16 registered default-account ML-DSA-65 sender profile after body-commitment
activation. Native proposer consensus, body commitments, economics, witnesses,
execution, rollback and canonical parent checks still apply. Unsupported
profiles follow existing native admission; a selected proof-backed candidate's
proof failure does not fall back to native sender verification.

Use authenticated Identify protocol advertisements to select discovery peers.
Offer `/shell/canonical-proof/2` alongside the existing chunk protocol version 1.
Only peers advertising version 2 receive manifest discovery or availability
frames. All these messages stay on the dedicated bounded unicast transport;
there is no gossip fallback. Bind discovery replies to peer/block/nonce, and
bind chunks to their existing persisted peer/manifest/index/nonce. Unsolicited
availability can only select a matching staged body after native source checks.
Retain the existing 512 MiB raw cache and immutable corruption generations.
Allow two distinct manifests per candidate and one hash-corrupt recovery;
rotate discovery among connected compatible peers without retrying the same
cryptographically rejected manifest. Retained failures consume capacity.

One blocking worker verifies full AIR against the independent native parent.
It can send only an opaque verified result to the serialized node event loop.
That loop rechecks parent and body context and invokes the native atomic
importer. The worker never writes canonical state. Shutdown joins a running
worker and releases its claim without committing its result. Restart rechecks
all cryptography, including when local metadata says verified. If native commit
preceded status persistence, recover through canonical replay and receipts;
do not replay execution or emit a second import event.

## Limits

This is a bounded experimental extension path, not general fork, amendment,
key-registration/rotation or AA proof consumption. Proposer cryptography remains
native. It introduces no settlement reward, fee, consensus schedule or activation
change. The retained-body cap and large raw graphs limit throughput; there is no
automatic eviction. Public release and network activation require separate
acceptance. The live peer regression is linked from the STARK guide.
