//! Network error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("invalid peer address: {0}")]
    InvalidPeerAddress(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("channel closed")]
    ChannelClosed,

    #[error("network shut down")]
    Shutdown,

    /// F-069: Incoming message exceeds the configured size limit.
    #[error("message too large: {size} bytes (limit: {limit})")]
    MessageTooLarge { size: usize, limit: usize },

    /// F-070: Peer connection limit reached.
    #[error("connection limit reached ({current}/{max})")]
    ConnectionLimitReached { current: usize, max: usize },

    /// F-071: Peer is temporarily banned.
    #[error("peer banned: {peer} until {until_secs}s from now")]
    PeerBanned { peer: String, until_secs: u64 },
}
