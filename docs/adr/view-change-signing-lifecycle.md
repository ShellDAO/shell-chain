# Keep view-change signing outside the node event loop

## Context

A timeout signature can take longer than a block tick with a post-quantum key.
Running it in `block_in_place` permits a replacement async worker to drive socket
I/O, but the node event loop still waits for that signature. Incoming proposals,
requests and votes can queue while repeated timeout signing prevents the node
from importing the block that would end the timeout.

## Decision

Spawn one tracked blocking signing job and continue selecting network events.
Keep its chain ID, next height, view, highest finalized hash and validator identity
with the job. Apply and broadcast the result only if that context still matches
the node and the identity remains an active validator. Context changes discard
the result; they do not authorize an obsolete vote or change the current round.
Do not queue additional signing work while a job remains in flight. A signing
failure clears that slot so the existing timeout path can try again.

Normal shutdown stops consuming results and drains the running CPU job before
releasing node resources. It does not broadcast a signature completed during
shutdown. A running cryptographic operation is not forcibly interrupted.

## Validation and limits

The event-loop regression holds a real signer's first timeout operation, sends a
peer ping, and requires the node's pong before releasing signing. It independently
verifies the resulting post-quantum signature. This distinguishes node event
consumption from merely keeping another executor worker available. The existing
native fork synchronization entry checks actual authority keys, transactions,
quorum finality and database recovery. The controlled signer hold is a concurrency
experiment, not a production timing or throughput measurement.

Wire formats, signature verification, weighted quorum, proposer selection and
activation schedules are unchanged.
