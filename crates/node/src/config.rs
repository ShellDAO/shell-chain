//! Node configuration aggregating all component configs.

use std::net::SocketAddr;

use shell_consensus::PoaConfig;
pub use shell_evm::ParallelEvmConfig;
use shell_genesis::NetworkType;
use shell_mempool::MempoolConfig;
use shell_network::NetworkConfig;
use shell_primitives::Address;
use shell_rpc::RpcConfig;

use crate::pruning::PruningConfig;

/// H2: The operational role of a node in the wPoA+STARK network.
///
/// - `Validator`: Standard block-producing authority. Participates in PoA
///   consensus, signs blocks, does not run the prover service full-time.
/// - `ValidatorProver`: Validator that also runs the background prover service
///   during idle (non-proposing) slots to contribute proof work.
/// - `Prover`: **Standalone prover node** — syncs the chain, runs the prover
///   service continuously, submits `ProofAmendment` messages via P2P, but
///   has **no block production authority**. Must register in ProverRegistry
///   (I5) and stake the minimum bond before submitting proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeRole {
    /// Standard block-producing validator (default).
    #[default]
    Validator,
    /// Validator that also contributes proof work on idle slots.
    ValidatorProver,
    /// Standalone prover node — no block production, full-time proving.
    Prover,
}

impl NodeRole {
    /// Parse from a CLI string (`validator`, `validator-prover`, `prover`).
    pub fn from_role_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "validator" => Ok(Self::Validator),
            "validator-prover" => Ok(Self::ValidatorProver),
            "prover" => Ok(Self::Prover),
            other => Err(format!(
                "unknown node role '{other}'; expected validator, validator-prover, or prover"
            )),
        }
    }

    /// Returns true if this role involves block production.
    pub fn is_validator(&self) -> bool {
        matches!(self, Self::Validator | Self::ValidatorProver)
    }

    /// Returns true if this role runs the prover service.
    pub fn runs_prover(&self) -> bool {
        matches!(self, Self::ValidatorProver | Self::Prover)
    }
}

impl std::str::FromStr for NodeRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_role_str(s)
    }
}

/// Configuration for the Prometheus metrics HTTP endpoint.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Whether the metrics server is enabled.
    pub enabled: bool,
    /// Address the metrics HTTP server listens on.
    pub listen_addr: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
        }
    }
}

/// Top-level configuration for a shell-chain node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Chain identifier.
    pub chain_id: u64,
    /// Network profile this node is operating on.
    ///
    /// Drives sensible defaults: Dev/Testnet use 30 s blocks to save
    /// resources; Mainnet uses 2 s blocks.
    pub network_type: NetworkType,
    /// PoA consensus configuration.
    pub consensus: PoaConfig,
    /// Transaction pool configuration.
    pub mempool: MempoolConfig,
    /// JSON-RPC server configuration.
    pub rpc: RpcConfig,
    /// P2P network configuration.
    pub network: NetworkConfig,
    /// This node's authority address (if it is a block producer).
    pub proposer_address: Option<Address>,
    /// Block production interval in milliseconds.
    ///
    /// When building from genesis, prefer deriving this from
    /// [`NetworkType::default_block_time_ms`] so that Dev/Testnet
    /// automatically get 30 s blocks and Mainnet gets 2 s blocks.
    pub block_time_ms: u64,
    /// Data directory for persistent storage.
    pub data_dir: String,
    /// State-root pruning configuration.
    pub pruning: PruningConfig,
    /// Prometheus metrics endpoint configuration.
    pub metrics: MetricsConfig,
    /// Maximum idle interval in ms before producing a heartbeat block.
    /// When the mempool is empty and the time since the last block exceeds
    /// this threshold, an empty heartbeat block is produced to keep the chain
    /// alive (sync, light clients, timestamp monotonicity).
    /// `0` disables idle-skip and produces a block on every tick (legacy).
    /// Default: `60_000` (60 s) — skip empty blocks but heartbeat once a minute.
    pub max_idle_interval_ms: u64,
    /// Account cache size in MiB for the world state LRU trie cache.
    /// Default: 64 MiB.  Higher values reduce state trie decode overhead.
    pub state_cache_size_mb: usize,
    /// Parallel-EVM PoC configuration. Disabled by default until promoted.
    pub parallel_evm: ParallelEvmConfig,
    /// Enable STARK aggregate proof generation during block production.
    /// When true, `produce_block` calls `prove_sig_batch()` over all transaction
    /// entries and stores the result in `BlockHeader::sig_aggregate_proof`.
    /// Off by default — generating a STARK proof per block is expensive (~150ms).
    pub enable_stark_aggregation: bool,
    /// H2: Operational role of this node in the wPoA+STARK network.
    pub node_role: NodeRole,
}

impl NodeConfig {
    /// Create a minimal dev-mode configuration with a single authority.
    ///
    /// Block time is derived from [`NetworkType::Dev`] (30 s) so that local
    /// development and tests don't consume resources at mainnet throughput.
    pub fn dev(authority: Address) -> Self {
        Self::for_network(authority, NetworkType::Dev)
    }

    /// Create a configuration for the given [`NetworkType`].
    ///
    /// All time-sensitive and resource-sensitive defaults are derived from
    /// `network_type`, so callers only need to override what differs.
    pub fn for_network(authority: Address, network_type: NetworkType) -> Self {
        let params = network_type.default_params();
        // ops-defaults: STARK-enabled nodes default to witness_retention=0
        // (witnesses are replaced by proofs immediately after proof commit).
        // Bodies are always retained in archive mode.
        let pruning = if params.stark_aggregation {
            PruningConfig {
                witness_retention: 0,
                ..PruningConfig::default()
            }
        } else {
            PruningConfig::default()
        };
        Self {
            chain_id: 1337,
            network_type,
            consensus: PoaConfig::new(vec![authority], params.block_time_ms / 1_000),
            mempool: MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            },
            rpc: RpcConfig {
                listen_addr: SocketAddr::from(([127, 0, 0, 1], 8545)),
                ws_addr: None,
                ..RpcConfig::default()
            },
            network: NetworkConfig::default(),
            proposer_address: Some(authority),
            block_time_ms: params.block_time_ms,
            data_dir: "shell-data".into(),
            pruning,
            metrics: MetricsConfig::default(),
            max_idle_interval_ms: 60_000,
            state_cache_size_mb: 64,
            parallel_evm: ParallelEvmConfig::default(),
            enable_stark_aggregation: params.stark_aggregation,
            node_role: NodeRole::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MetricsConfig tests ────────────────────────────────────

    #[test]
    fn metrics_default_is_enabled() {
        let m = MetricsConfig::default();
        assert!(m.enabled);
    }

    #[test]
    fn metrics_default_listen_addr() {
        let m = MetricsConfig::default();
        assert_eq!(m.listen_addr, SocketAddr::from(([127, 0, 0, 1], 9090)));
    }

    #[test]
    fn metrics_clone_equals_original() {
        let m = MetricsConfig::default();
        let cloned = m.clone();
        assert_eq!(m.enabled, cloned.enabled);
        assert_eq!(m.listen_addr, cloned.listen_addr);
    }

    #[test]
    fn metrics_debug_format() {
        let m = MetricsConfig::default();
        let debug = format!("{:?}", m);
        assert!(debug.contains("MetricsConfig"));
    }

    // ── NodeConfig::dev tests ──────────────────────────────────

    #[test]
    fn dev_config_chain_id() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.chain_id, 1337);
    }

    #[test]
    fn dev_config_mempool_chain_id_matches() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.mempool.chain_id, cfg.chain_id);
    }

    #[test]
    fn dev_config_proposer_is_authority() {
        let addr = Address::from_slice(&[0xAB; 20]);
        let cfg = NodeConfig::dev(addr);
        assert_eq!(cfg.proposer_address, Some(addr));
    }

    #[test]
    fn dev_config_consensus_has_authority() {
        let addr = Address::from_slice(&[0xCD; 20]);
        let cfg = NodeConfig::dev(addr);
        assert_eq!(cfg.consensus.authorities.len(), 1);
        assert_eq!(cfg.consensus.authorities[0], addr);
    }

    #[test]
    fn dev_config_block_time_is_30s() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.block_time_ms, 30_000);
    }

    #[test]
    fn dev_config_network_type_is_dev() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.network_type, NetworkType::Dev);
    }

    #[test]
    fn mainnet_config_block_time_is_2s() {
        let cfg = NodeConfig::for_network(Address::ZERO, NetworkType::Mainnet);
        assert_eq!(cfg.block_time_ms, 2_000);
    }

    #[test]
    fn testnet_config_block_time_is_30s() {
        let cfg = NodeConfig::for_network(Address::ZERO, NetworkType::Testnet);
        assert_eq!(cfg.block_time_ms, 30_000);
    }

    #[test]
    fn mainnet_config_stark_aggregation_enabled() {
        let cfg = NodeConfig::for_network(Address::ZERO, NetworkType::Mainnet);
        assert!(cfg.enable_stark_aggregation);
    }

    #[test]
    fn dev_config_stark_aggregation_disabled() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert!(!cfg.enable_stark_aggregation);
    }

    #[test]
    fn dev_config_rpc_listen_addr() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(
            cfg.rpc.listen_addr,
            SocketAddr::from(([127, 0, 0, 1], 8545))
        );
    }

    #[test]
    fn dev_config_no_websocket() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert!(cfg.rpc.ws_addr.is_none());
    }

    #[test]
    fn dev_config_data_dir() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.data_dir, "shell-data");
    }

    #[test]
    fn dev_config_metrics_enabled() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert!(cfg.metrics.enabled);
    }

    #[test]
    fn dev_config_debug_format() {
        let cfg = NodeConfig::dev(Address::ZERO);
        let debug = format!("{:?}", cfg);
        assert!(debug.contains("NodeConfig"));
    }

    // ── H2: NodeRole tests ─────────────────────────────────────

    #[test]
    fn node_role_default_is_validator() {
        assert_eq!(NodeRole::default(), NodeRole::Validator);
    }

    #[test]
    fn node_role_from_str_valid() {
        assert_eq!(
            "validator".parse::<NodeRole>().unwrap(),
            NodeRole::Validator
        );
        assert_eq!(
            "validator-prover".parse::<NodeRole>().unwrap(),
            NodeRole::ValidatorProver
        );
        assert_eq!("prover".parse::<NodeRole>().unwrap(), NodeRole::Prover);
    }

    #[test]
    fn node_role_from_str_case_insensitive() {
        assert_eq!(
            "Validator".parse::<NodeRole>().unwrap(),
            NodeRole::Validator
        );
        assert_eq!("PROVER".parse::<NodeRole>().unwrap(), NodeRole::Prover);
    }

    #[test]
    fn node_role_from_str_unknown_is_error() {
        assert!("miner".parse::<NodeRole>().is_err());
        assert!("".parse::<NodeRole>().is_err());
    }

    #[test]
    fn node_role_is_validator() {
        assert!(NodeRole::Validator.is_validator());
        assert!(NodeRole::ValidatorProver.is_validator());
        assert!(!NodeRole::Prover.is_validator());
    }

    #[test]
    fn node_role_runs_prover() {
        assert!(!NodeRole::Validator.runs_prover());
        assert!(NodeRole::ValidatorProver.runs_prover());
        assert!(NodeRole::Prover.runs_prover());
    }

    #[test]
    fn node_config_default_role_is_validator() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.node_role, NodeRole::Validator);
    }
}
