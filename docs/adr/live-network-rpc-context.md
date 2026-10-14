# Live P2P context for RPC queries

Status: accepted for unreleased node source.

## Context

The node supplied no P2P context to its RPC server. Network statistics returned
port 30303 even when libp2p bound an ephemeral loopback port, and reported mDNS
when that behaviour was disabled. Static strings also could not follow listener
expiry or transport shutdown.

## Decision

Extend the existing network-service handle pattern with a shared, read-only-to-
RPC snapshot of the actual local peer identity, bound addresses and enabled
behaviours. The libp2p actor refreshes addresses on listener events and clears
its snapshot when the actor exits. RPC clones share the same snapshot. Other
network-service implementations default to unavailable transport metadata.

Preserve the existing JSON response shape, selecting the first sorted bound
address for its single address field. Return an empty address when none is
bound and no protocols for an absent or stopped transport. Keep the explicit
static RPC-handler context builder for embedded callers; the node uses the
live handle. Do not persist transient transport metadata or change chain state,
network identity, genesis, consensus parameters or protocol activation.

## Validation

A real libp2p regression binds port zero, connects a TCP socket to the assigned
port and observes metadata reset on shutdown. RPC regressions check shared
updates across cloned handlers and absent transport behaviour. Run
`python3 tests/e2e/operator-p2p-monitoring.py --network-stats` after building
`shell-cli` with the `libp2p` feature for actual two-node RPC, backlog import,
canonical hash agreement and enabled/disabled transport restarts. IPv6,
multiple listeners and external-network reachability remain unverified.
