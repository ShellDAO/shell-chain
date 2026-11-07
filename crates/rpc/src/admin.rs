//! `admin_*` JSON-RPC namespace.
//!
//! Provides node administration methods for operators:
//!
//! - `admin_nodeInfo` — static metadata about this node instance.
//! - `admin_peers`    — reserved for future per-peer snapshots; currently returns method-not-found.
//! - `admin_addPeer`  — dynamically add a bootnode / dial-out peer.
//!
//! The `admin` namespace is **opt-in** via `--rpc-api admin` and should
//! **never** be exposed on a public endpoint without API-key protection.

use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

/// Static information about this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    /// Software version string (e.g. `"shell-node/0.13.0"`).
    pub name: String,
    /// Node network identity (libp2p PeerId in base58).
    pub id: String,
    /// Listening address for P2P connections.
    pub listen_addr: String,
    /// JSON-RPC HTTP listen address.
    pub rpc_addr: String,
    /// Chain ID this node is operating on.
    pub chain_id: u64,
    /// Number of seconds the node has been running.
    pub uptime_seconds: u64,
    /// Block number at the tip of this node's chain.
    pub block_height: u64,
    /// Number of pending transactions in the mempool.
    pub tx_pool_size: u64,
    /// Number of currently connected peers.
    pub peer_count: usize,
}

/// Snapshot of a single connected peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    /// Peer ID (libp2p PeerId in base58).
    pub id: String,
    /// Remote multiaddr as seen by this node.
    pub remote_addr: String,
    /// Self-reported client version (from Identify protocol).
    pub client_version: String,
    /// Block height last announced by this peer.
    pub block_height: u64,
    /// Seconds since the connection was established.
    pub connected_seconds: u64,
}

/// Admin namespace RPC API trait.
#[rpc(server, namespace = "admin")]
pub trait AdminApi {
    #[method(name = "canonicalProofProduction")]
    async fn canonical_proof_production(
        &self,
        block: shell_primitives::ShellHash,
    ) -> Result<Option<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "fetchCanonicalProof")]
    async fn fetch_canonical_proof(
        &self,
        peer: String,
        manifest: shell_storage::CanonicalProofManifest,
    ) -> Result<shell_storage::CanonicalProofFetchStatus, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "canonicalProofFetchStatus")]
    async fn canonical_proof_fetch_status(
        &self,
        id: shell_primitives::ShellHash,
        generation: Option<u64>,
    ) -> Result<Option<shell_storage::CanonicalProofFetchStatus>, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "canonicalProofAttemptStatus")]
    async fn canonical_proof_attempt_status(
        &self,
        id: shell_primitives::ShellHash,
        generation: u64,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "getCanonicalProofAttemptChunk")]
    async fn get_canonical_proof_attempt_chunk(
        &self,
        id: shell_primitives::ShellHash,
        generation: u64,
        index: u32,
    ) -> Result<shell_primitives::Bytes, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "beginCanonicalProof")]
    async fn begin_canonical_proof(
        &self,
        manifest: shell_storage::CanonicalProofManifest,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "appendCanonicalProof")]
    async fn append_canonical_proof(
        &self,
        id: shell_primitives::ShellHash,
        index: u32,
        chunk: shell_primitives::Bytes,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "canonicalProofStatus")]
    async fn canonical_proof_status(
        &self,
        id: shell_primitives::ShellHash,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "getCanonicalProofChunk")]
    async fn get_canonical_proof_chunk(
        &self,
        id: shell_primitives::ShellHash,
        index: u32,
    ) -> Result<shell_primitives::Bytes, jsonrpsee::types::ErrorObjectOwned>;
    #[method(name = "verifyCanonicalProof")]
    async fn verify_canonical_proof(
        &self,
        id: shell_primitives::ShellHash,
        recheck: Option<bool>,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, jsonrpsee::types::ErrorObjectOwned>;
    /// Returns static metadata about this node.
    #[method(name = "nodeInfo")]
    async fn node_info(&self) -> Result<NodeInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the list of currently connected peers.
    ///
    /// Currently returns method-not-found until the network layer exposes real
    /// per-peer snapshots. Use `admin_nodeInfo.peer_count` for aggregate count.
    #[method(name = "peers")]
    async fn peers(&self) -> Result<Vec<PeerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Dial a peer given its multiaddr.
    ///
    /// Returns `true` if the dial was initiated (connection outcome is async).
    #[method(name = "addPeer")]
    async fn add_peer(&self, multiaddr: String)
        -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;
}
