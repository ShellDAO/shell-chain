//! Node error types.

use shell_primitives::ShellHash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] shell_storage::StorageError),

    #[error("consensus error: {0}")]
    Consensus(#[from] shell_consensus::ConsensusError),

    #[error("pqvm error: {0}")]
    Pqvm(#[from] shell_pqvm::ExecutorError),

    #[error("network error: {0}")]
    Network(#[from] shell_network::NetworkError),

    #[error("node not configured as proposer")]
    NotProposer,

    #[error("missing genesis block")]
    NoGenesis,

    #[error("block gap detected: incoming #{incoming} but expected #{expected}")]
    GapDetected { incoming: u64, expected: u64 },

    #[error("block #{incoming} conflicts with finalized chain (finalized up to #{fin_number})")]
    ConflictsWithFinalized { incoming: u64, fin_number: u64 },

    #[error("invalid fork block {block_hash}: {reason}")]
    InvalidFork {
        block_hash: ShellHash,
        reason: String,
    },

    #[error("startup failed: {0}")]
    Startup(String),
}
