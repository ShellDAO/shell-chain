# Retain next-height commit certificates until block import

## Context

Block and certificate gossip can arrive in either order. A producer can reach
quorum locally and publish its certificate before publishing the block. A
follower previously rejected that certificate because the canonical block did
not exist yet. Later block import advanced the head without advancing finality.
The block-sync path could also persist newer finality without updating the
shared RPC cursor, leaving the finalized tag stale after restart catch-up.

## Decision

Retain at most one certificate for the immediate next height, after verifying
its quorum and signatures. Invalid or more distant certificates do not replace
that entry. Recheck the retained certificate with the existing canonical-target
and signature checks after either gossip or synchronization imports the block.
Only those checks may persist finality and update its RPC view. Publish that
view after synchronized certificate finalization as well.

This is a transport-ordering fix. It changes no block format, quorum rule or
activation schedule. A certificate does not authorize bypassing block validation,
and a certificate for a conflicting hash cannot finalize the imported block.

## Limits

The buffer is transient and holds one next-height certificate, not a historical
certificate queue. Longer gaps and certificates that cannot yet be verified
against local validator state use the existing block synchronization protocol.
Recovery after loss of the certificate itself, rather than reversed delivery
order, remains outside this change.
