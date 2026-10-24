# Native circuit-relay service

Status: Accepted for the Unreleased native implementation.

The network layer already constructs relay client/server behaviours, but native
operators need an executable server role and an inbound reservation entry. A
relay's configured transport alone does not reserve a listening circuit.

The `relay` command runs the existing network service with relay serving enabled,
application gossip subscriptions disabled, and no chain database or validator
signer. Its separate persisted `relay.key` identifies the transport service.
Ordinary chain nodes retain their existing defaults, including no relay serving.

Servers require explicitly configured reachable transport endpoints. Arbitrary
remote address observations are not automatically confirmed. Existing libp2p
reservation, circuit-count, duration, and byte limits remain in force.

Chain nodes opt into reservations through `--relay-listen` or TOML. The network
service validates reservation addresses and calls the real relay transport's
listener. It reports the actual resulting listening address. Complete circuit
addresses identify the final destination separately from the relay hop.

The local native acceptance disables alternate discovery and direct upgrades,
checks transport-confirmed relayed connections, and verifies genuine signed
transfers, independent receipts, database reopen, and a bounded relay outage.
Keeping the relay outside application gossip prevents that test from passing
through a chain-node gossip star. This is not a qualification of Internet NAT
hole-punching, all relay policies, or the planned PQ Noise migration.
