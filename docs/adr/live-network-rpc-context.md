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

## Outbound admin control

The same context now carries an optional typed `PeerDialer` handle. The event
receiver remains owned by the node; RPC clones only the bounded swarm command
sender and byte budget. A oneshot reply is completed after the actor calls
`Swarm::dial`, so a queued request alone cannot report initiation. Address input
is limited to 4096 bytes before parsing, queue admission is non-blocking, and
command bytes use the existing shared semaphore. The transport's existing
pending/established connection limits continue to apply. Known peer IDs use
`DisconnectedAndNotDialing`; the actor rejects its own peer ID explicitly.

The opt-in namespace and API-key middleware remain the authority boundary.
Metadata-only or disabled network implementations expose no dial handle and
return feature-not-enabled. Dynamic dialing does not write bootnode settings;
operators retain the existing startup configuration for persistent peers.
`admin_peers` still requires a separate real per-peer snapshot capability.

`tests/e2e/admin-peer-dial.py` exercises authenticated HTTP/WebSocket control,
actual connections, signed transaction import and physical state reopen.
Network tests cover pending/connected duplicates, invalid input, bounded queue
and bytes, and transport shutdown. IPv6, relay addresses and external-network
reachability remain outside this local acceptance.
