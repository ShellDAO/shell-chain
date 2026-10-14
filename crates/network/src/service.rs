//! Network service trait defining the P2P interface.

use async_trait::async_trait;

use crate::error::NetworkError;
use crate::message::{NetworkEvent, NetworkMessage, PeerId};

use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};

/// Local transport identity and currently bound listener addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalNodeInfo {
    pub peer_id: String,
    pub listen_addresses: Vec<String>,
    pub protocols: Vec<String>,
}

/// Trait abstracting the P2P network layer.
///
/// Implementations handle peer management, message serialization,
/// and gossip protocol details. The node interacts with the network
/// exclusively through this trait.
// async_trait adds redundant must_use attributes to its boxed futures.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait NetworkService: Send + Sync {
    /// Broadcast a message to all connected peers.
    async fn broadcast(&self, msg: NetworkMessage) -> Result<(), NetworkError>;

    /// Send a message to a specific peer only (unicast).
    ///
    /// Default implementation falls back to broadcast when the transport does
    /// not support addressing individual peers. Implementations that support
    /// true unicast (e.g. libp2p request-response) should override this method
    /// to avoid message amplification.
    async fn send_to_peer(
        &self,
        _peer_id: &PeerId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        // Fallback: broadcast to all peers when unicast is not implemented.
        self.broadcast(msg).await
    }

    /// Wait for the next network event.
    /// Returns `None` if the network has shut down.
    async fn next_event(&mut self) -> Option<NetworkEvent>;

    /// Returns the number of currently connected peers.
    async fn peer_count(&self) -> usize;

    /// Returns a shared atomic handle to the live peer count.
    /// External consumers (e.g. RPC) can read this without async.
    fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(0))
    }

    /// Shared live local transport information; absent transports expose no listener.
    fn local_node_info_handle(&self) -> Arc<RwLock<LocalNodeInfo>> {
        Arc::new(RwLock::new(LocalNodeInfo::default()))
    }

    /// Shut down the network service gracefully.
    async fn shutdown(&self) -> Result<(), NetworkError>;
}
