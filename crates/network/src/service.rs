//! Network service trait defining the P2P interface.

use async_trait::async_trait;

use crate::error::NetworkError;
use crate::message::{NetworkEvent, NetworkMessage, PeerId};

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Trait abstracting the P2P network layer.
///
/// Implementations handle peer management, message serialization,
/// and gossip protocol details. The node interacts with the network
/// exclusively through this trait.
#[async_trait]
pub trait NetworkService: Send + Sync {
    /// Broadcast a message to all connected peers.
    async fn broadcast(&self, msg: NetworkMessage) -> Result<(), NetworkError>;

    /// Send a message to a specific peer only (unicast).
    ///
    /// Default implementation falls back to broadcast. Implementations that
    /// support direct peer messaging should override this to avoid amplification.
    async fn send_to_peer(
        &self,
        _peer_id: &PeerId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
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

    /// Shut down the network service gracefully.
    async fn shutdown(&self) -> Result<(), NetworkError>;
}
