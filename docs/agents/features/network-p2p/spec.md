# Feature: Network P2P

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

> Legacy header (preserved): ID `network-p2p` · Priority P2 · Module `shell-chain/crates/network`

## 1. Purpose

P2P networking layer for shell-chain nodes. Provides a trait-based `NetworkService` abstraction
with two concrete backends:

- **`ChannelNetwork`**: in-process broadcast channels for single-node dev mode and integration
  tests — no TCP, no real peer connections.
- **`Libp2pNetwork`** (feature flag `libp2p`): production-grade TCP + Noise + Yamux transport
  with GossipSub block/tx propagation, mDNS local discovery, and Kademlia DHT.

> **Correction from prior spec**: The transport layer does NOT use Kyber (PQ-KEM). The
> production implementation uses standard `TCP + Noise + Yamux` (libp2p 0.56). The
> `security.rs` module contains `PeerBanList`/`PeerTracker` (ban/deny-list logic), not a
> post-quantum key exchange. Kyber was speculative and was never implemented.

## 2. Public API Surface

```rust
// crates/network/src/lib.rs (re-exports)
pub use bandwidth::{BandwidthStats, BandwidthTracker};
pub use channel::{ChannelNetwork, NetworkBus};
pub use config::NetworkConfig;
pub use error::NetworkError;
#[cfg(feature = "libp2p")]
pub use libp2p_service::Libp2pNetwork;
pub use message::{
    deserialize_checked, validate_message_size, NetworkEvent, NetworkMessage, PeerId,
    MAX_MESSAGE_SIZE,
};
pub use security::{PeerBanList, PeerTracker};
pub use service::NetworkService;

// Core trait
pub trait NetworkService: Send + Sync {
    fn broadcast(&self, msg: NetworkMessage) -> Result<(), NetworkError>;
    fn subscribe(&self) -> broadcast::Receiver<NetworkEvent>;
    fn peer_count(&self) -> usize;
    fn local_peer_id(&self) -> PeerId;
    fn ban_peer(&self, peer: PeerId);
}

// Message types
pub enum NetworkMessage {
    NewBlock(Block),
    NewTransaction(SignedTransaction),
    GetHeaders { from: u64, limit: usize },
    Headers(Vec<BlockHeader>),
    GetBodies(Vec<ShellHash>),
    Bodies(Vec<BlockBody>),
    ProofAmendment(ProofAmendment),
    WitnessBundle { block_hash: ShellHash, bundle: WitnessBundle },
}

pub enum NetworkEvent {
    Message { peer: PeerId, message: NetworkMessage },
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
}

pub struct NetworkConfig {
    pub listen_addr: Multiaddr,
    pub boot_nodes: Vec<Multiaddr>,
    pub max_peers: usize,
    pub identity_path: Option<PathBuf>,   // persists libp2p Ed25519 identity key
    pub enable_mdns: bool,                // dev-only local discovery
}
```

## 3. Implementation Map

| Component | File | Notes |
|-----------|------|-------|
| `NetworkService` trait | `crates/network/src/service.rs` | Trait definition; impl by both backends |
| `ChannelNetwork`, `NetworkBus` | `crates/network/src/channel.rs` | In-process backend; `tokio::broadcast` channels |
| `Libp2pNetwork` | `crates/network/src/libp2p_service.rs` | Libp2p 0.56; TCP+Noise+Yamux; feature-gated `libp2p` |
| `BandwidthTracker`, `BandwidthStats` | `crates/network/src/bandwidth.rs` | Per-peer bandwidth monitoring |
| `PeerBanList`, `PeerTracker` | `crates/network/src/security.rs` | IP-level and peer-level ban list; deny-list management |
| `NetworkMessage`, `NetworkEvent`, `MAX_MESSAGE_SIZE` | `crates/network/src/message.rs` | Wire types; `validate_message_size`, `deserialize_checked` |
| `NetworkConfig` | `crates/network/src/config.rs` | `validate_bootnode_multiaddr` (libp2p feature) |
| `NetworkError` | `crates/network/src/error.rs` | Typed error variants |
| Public re-exports | `crates/network/src/lib.rs:1-35` | Full crate surface |

### Transport stack (libp2p backend)

```
TCP  →  Noise (XX handshake, Ed25519 identity)  →  Yamux (multiplexing)
```

libp2p version: **0.56** (workspace `Cargo.toml`).

Features enabled: `tcp`, `dns`, `noise`, `yamux`, `gossipsub`, `mdns`, `tokio`,
`identify`, `kad`, `relay`, `dcutr`, `autonat`.

### GossipSub mesh

- Topics: `new-block`, `new-transaction`, `proof-amendment`, `witness-bundle`.
- `PeerScoreParams` and `PeerScoreThresholds` are configured to penalise peers that
  forward invalid messages or behave inconsistently.
- `IdentTopic` keyed by topic string; no content-based routing.

### Peer discovery

- **mDNS** (`enable_mdns = true`): local network discovery, development-only.
- **Kademlia DHT**: production peer discovery seeded from `boot_nodes`; runs in server
  mode for validators, client mode for light nodes.
- **AutoNAT + Relay + DCUTR**: NAT hole-punching for validators behind firewalls.

### Message size guard

`MAX_MESSAGE_SIZE` is enforced on every inbound message by `validate_message_size` and
`deserialize_checked`. Messages exceeding the limit are dropped; the sending peer's score
is penalised.

### BandwidthTracker

Records per-peer bytes sent/received; `BandwidthStats` is exposed via the admin RPC
(`net_peerCount`, `getNetworkStats`) for ops monitoring.

### PeerBanList / PeerTracker

`PeerBanList`: IP-level and peer-id–level deny list; persistent across reconnect attempts.
`PeerTracker`: tracks peer connection state (connected/disconnecting/banned); feeds into
GossipSub score thresholds.

## 4. Invariants

- **INV-NET-1**: Transport layer uses Noise XX (Ed25519), NOT Kyber/PQ-KEM. PQ transport is
  not implemented. Do not claim PQ network security in documentation.
  Cross-ref: CONSTITUTION §NetworkSecurity.
- **INV-NET-2**: `MAX_MESSAGE_SIZE` MUST be enforced on all inbound messages before
  deserialization. Oversized messages MUST be dropped without decoding.
- **INV-NET-3**: `ChannelNetwork` MUST be functionally equivalent to `Libp2pNetwork` from the
  perspective of the node event loop; the harness switches backends via feature flag only.
- **INV-NET-4**: mDNS MUST be disabled (`enable_mdns = false`) in testnet and mainnet configs.
- **INV-NET-5**: A banned peer (`PeerBanList`) MUST NOT be reconnected until the ban expires or
  is manually lifted.

## 5. Tests

Tests live in `crates/network/src/` (inline `#[cfg(test)]`) using `ChannelNetwork`.

Key test cases:
- `ChannelNetwork::broadcast` → subscriber receives `NetworkEvent::Message`.
- `PeerBanList::ban` → `is_banned` returns true; subsequent connection rejected.
- `BandwidthTracker`: bytes increment after send/receive calls.
- `validate_message_size`: returns error for oversized payloads.
- `deserialize_checked`: returns error on malformed bytes.
- `NetworkConfig::validate_bootnode_multiaddr`: rejects invalid multiaddrs.

Integration tests using `ChannelNetwork` backend: `cargo test -p shell-node -- network`.

## 6. Related ADRs

- CONSTITUTION §NetworkSecurity — transport layer requirements
- `../adrs/ADR-002-stark-tx-level-settlement.md` — `ProofAmendment`
  messages are propagated via P2P (`NetworkMessage::ProofAmendment`)

## 7. Known Limitations / Open Work

- **No PQ transport**: Kyber (or ML-KEM) handshake integration is not scheduled. Current
  threat model relies on PQ application-layer signatures rather than PQ channel encryption.
- mDNS is dev-only; production peer discovery depends on manually configured `boot_nodes`.
- `Libp2pNetwork` identity key (`identity_path`) is Ed25519 (not PQ); peer identity is
  separate from validator PQ keys.
- Relay and DCUTR (NAT traversal) may not work behind symmetric NAT without a relay node.
- P2P authentication of `ProofAmendment` messages (prover identity check) is not yet
  enforced at the network layer; filtering happens in the node event loop.

## 8. Change Log

| Version | Change |
|---------|--------|
| v0.22.2 | Spec rewritten from draft; corrected Kyber transport claim; added ChannelNetwork, BandwidthTracker, PeerBanList/PeerTracker, MAX_MESSAGE_SIZE, libp2p 0.56 version, GossipSub details |
| M2 | Initial draft spec (incorrectly described Kyber+Noise as implemented) |
