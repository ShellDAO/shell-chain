//! shell-node: Node harness assembling all shell-chain components.
//!
//! Provides `NodeBuilder` for ergonomic construction and `Node` for
//! running the event loop with block production, mempool management,
//! and network message handling.

pub mod builder;
pub mod checkpoint;
pub mod config;
pub mod error;
pub mod historical_sync;
pub mod metrics;
pub mod node;
pub mod prover_service;
pub mod pruning;
pub mod reorg;

pub use builder::NodeBuilder;
pub use config::{MetricsConfig, NodeConfig, NodeRole};
pub use error::NodeError;
pub use historical_sync::{PeerCapabilityTracker, SyncStatus};
pub use metrics::Metrics;
pub use node::Node;
pub use prover_service::{ProverConfig, ProverService, ProverServiceHandle, ProvingPriority};
pub use pruning::{PruningConfig, StateRootTracker, StorageProfile};
pub use reorg::{ReorgEngine, ReorgResult};
