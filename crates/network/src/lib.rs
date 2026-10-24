//! shell-network: P2P networking layer for the shell-chain node.
//!
//! Provides a trait-based network abstraction (`NetworkService`) with
//! pluggable implementations:
//!
//! - `ChannelNetwork`: In-process broadcast channels for testing and
//!   single-node development. No real TCP connections needed.
//! - `Libp2pNetwork` (feature `libp2p`): Production TCP+Noise+Yamux
//!   transport with GossipSub broadcast and mDNS peer discovery.

pub mod bandwidth;
pub mod channel;
pub mod config;
pub mod error;
#[cfg(feature = "libp2p")]
pub mod libp2p_service;
pub mod message;
pub mod security;
pub mod service;

pub use bandwidth::{BandwidthStats, BandwidthTracker};
pub use channel::{ChannelNetwork, NetworkBus};
#[cfg(feature = "libp2p")]
pub use config::validate_bootnode_multiaddr;
pub use config::NetworkConfig;
pub use error::NetworkError;
#[cfg(feature = "libp2p")]
pub use libp2p_service::Libp2pNetwork;
pub use message::{
    deserialize_checked, validate_message_size, NetworkEvent, NetworkMessage, PeerId,
    MAX_MESSAGE_SIZE,
};
pub use security::{PeerBanList, PeerTracker};
pub use service::{LocalNodeInfo, NetworkService};

#[cfg(feature = "libp2p")]
mod peer_bandwidth;
pub use service::PeerBandwidthStats;
