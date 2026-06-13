//! Node configuration aggregating all component configs.

use std::net::SocketAddr;

use shell_consensus::{PoaConfig, WPoaConfig};
use shell_genesis::NetworkType;
use shell_mempool::MempoolConfig;
use shell_network::NetworkConfig;
pub use shell_pqvm::ParallelPqvmConfig;
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
/// Which consensus engine the node should use.
///
/// The config variant determines which engine is instantiated at startup.
/// WPoA is the standard consensus (white-paper §4); PoA is an explicit opt-in
/// for compatibility or single-validator local deployments.
#[derive(Debug, Clone)]
pub enum ConsensusEngineConfig {
    /// Proof-of-Authority (Phase 1, explicit opt-in for compatibility).
    Poa(PoaConfig),
    /// Weighted Proof-of-Authority — the standard shell-chain consensus protocol.
    WPoa(WPoaConfig),
}

impl ConsensusEngineConfig {
    /// Return the underlying PoaConfig (present in both variants).
    pub fn poa_config(&self) -> &PoaConfig {
        match self {
            Self::Poa(c) => c,
            Self::WPoa(c) => &c.poa,
        }
    }

    /// Return the engine type identifier string.
    pub fn engine_kind(&self) -> &'static str {
        match self {
            Self::Poa(_) => "poa",
            Self::WPoa(_) => "wpoa",
        }
    }
}

/// Operational state of L2 STARK recursive aggregation.
///
/// Controls whether the node builds and maintains the L2 input index, triggers
/// the aggregation scheduler, and (eventually) executes recursive proving.
/// Defaults to [`Disabled`] for testnet safety — recursive proving is not yet
/// production-ready and enabling it prematurely would emit invalid L2 settlements.
///
/// [`Disabled`]: L2StarkMode::Disabled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L2StarkMode {
    /// No L2 activity: input index is not maintained, scheduler never fires,
    /// no L2 settlements are produced.  Safe default for all current deployments.
    #[default]
    Disabled,
    /// Input index and job tracking are active; scheduler windows are computed
    /// and logged; but recursive proving is NOT executed.  Use this to gain
    /// operational visibility (metrics, gap detection) without emitting L2 proofs.
    Scaffold,
    /// Full recursive aggregation: input index, job store, scheduler, and the
    /// recursive prover all run.  Requires the `recursive` cargo feature to have
    /// any effect; without it the mode is accepted but recursive proving is skipped.
    Active,
}

impl L2StarkMode {
    /// Returns `true` for [`Scaffold`] and [`Active`] — i.e. any mode where the
    /// L2 input index and observability infrastructure are maintained.
    ///
    /// [`Scaffold`]: L2StarkMode::Scaffold
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Returns `true` only for [`Active`] — i.e. when recursive proving should run.
    ///
    /// [`Active`]: L2StarkMode::Active
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Parse from a CLI/config string: `"disabled"`, `"scaffold"`, or `"active"`.
    pub fn from_mode_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "disabled" => Ok(Self::Disabled),
            "scaffold" => Ok(Self::Scaffold),
            "active" => Ok(Self::Active),
            other => Err(format!(
                "unknown L2 STARK mode '{other}'; expected disabled, scaffold, or active"
            )),
        }
    }
}

impl std::str::FromStr for L2StarkMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_mode_str(s)
    }
}

impl std::fmt::Display for L2StarkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("disabled"),
            Self::Scaffold => f.write_str("scaffold"),
            Self::Active => f.write_str("active"),
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
    /// Drives sensible defaults: Dev uses slower blocks for local work;
    /// Testnet/Mainnet use 2 s transaction-driven blocks.
    pub network_type: NetworkType,
    /// Consensus engine configuration.
    pub consensus: ConsensusEngineConfig,
    /// Transaction pool configuration.
    pub mempool: MempoolConfig,
    /// JSON-RPC server configuration.
    pub rpc: RpcConfig,
    /// Whether [`Node::run`](crate::node::Node::run) starts the JSON-RPC server.
    ///
    /// Defaults to true for normal node operation. Tests and embedded runtimes
    /// that drive the event loop without opening sockets can disable it.
    pub rpc_enabled: bool,
    /// P2P network configuration.
    pub network: NetworkConfig,
    /// This node's authority address (if it is a block producer).
    pub proposer_address: Option<Address>,
    /// Block production interval in milliseconds.
    ///
    /// When building from genesis, prefer deriving this from
    /// [`NetworkType::default_block_time_ms`] so that Testnet/Mainnet
    /// get 2 s blocks and Dev keeps its local-friendly default.
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
    /// Default: `600_000` (600 s) — skip empty blocks but heartbeat every 10 minutes.
    pub max_idle_interval_ms: u64,
    /// Account cache size in MiB for the world state LRU trie cache.
    /// Default: 64 MiB.  Higher values reduce state trie decode overhead.
    pub state_cache_size_mb: usize,
    /// Parallel-PQVM PoC configuration. Disabled by default until promoted.
    pub parallel_pqvm: ParallelPqvmConfig,
    /// Enable STARK aggregate proof generation during block production.
    /// When true, `produce_block` calls `prove_sig_batch()` over all transaction
    /// entries and stores the result in `BlockHeader::sig_aggregate_proof`.
    /// Off by default — generating a STARK proof per block is expensive (~150ms).
    pub enable_stark_aggregation: bool,
    /// Operational mode for L2 recursive STARK aggregation.
    /// Defaults to [`L2StarkMode::Disabled`] for testnet safety; set to
    /// [`L2StarkMode::Scaffold`] to activate observability without proving.
    pub l2_stark_mode: L2StarkMode,
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
        // WPoA is the standard shell-chain consensus (white-paper §4).
        // Single-validator dev/testnet setups use uniform weight=1, which
        // is equivalent to plain PoA but routes through the WPoA engine.
        let base_poa = PoaConfig::new(vec![authority], params.block_time_ms / 1_000);
        Self {
            chain_id: 1337,
            network_type,
            consensus: ConsensusEngineConfig::WPoa(WPoaConfig::from_poa(base_poa)),
            mempool: MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            },
            rpc: RpcConfig {
                listen_addr: SocketAddr::from(([127, 0, 0, 1], 8545)),
                ws_addr: None,
                ..RpcConfig::default()
            },
            rpc_enabled: true,
            network: NetworkConfig::default(),
            proposer_address: Some(authority),
            block_time_ms: params.block_time_ms,
            data_dir: "shell-data".into(),
            pruning,
            metrics: MetricsConfig::default(),
            max_idle_interval_ms: 600_000,
            state_cache_size_mb: 64,
            parallel_pqvm: ParallelPqvmConfig::default(),
            enable_stark_aggregation: params.stark_aggregation,
            l2_stark_mode: L2StarkMode::Disabled,
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
        let addr = Address::from_slice(&[0xAB; 32]);
        let cfg = NodeConfig::dev(addr);
        assert_eq!(cfg.proposer_address, Some(addr));
    }

    #[test]
    fn dev_config_consensus_has_authority() {
        let addr = Address::from_slice(&[0xCD; 32]);
        let cfg = NodeConfig::dev(addr);
        assert_eq!(cfg.consensus.poa_config().authorities.len(), 1);
        assert_eq!(cfg.consensus.poa_config().authorities[0], addr);
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
    fn testnet_config_block_time_is_2s() {
        let cfg = NodeConfig::for_network(Address::ZERO, NetworkType::Testnet);
        assert_eq!(cfg.block_time_ms, 2_000);
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

    // ── L2StarkMode tests ──────────────────────────────────────

    #[test]
    fn l2_stark_mode_default_is_disabled() {
        assert_eq!(L2StarkMode::default(), L2StarkMode::Disabled);
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.l2_stark_mode, L2StarkMode::Disabled);
    }

    #[test]
    fn l2_stark_mode_is_enabled() {
        assert!(!L2StarkMode::Disabled.is_enabled());
        assert!(L2StarkMode::Scaffold.is_enabled());
        assert!(L2StarkMode::Active.is_enabled());
    }

    #[test]
    fn l2_stark_mode_is_active() {
        assert!(!L2StarkMode::Disabled.is_active());
        assert!(!L2StarkMode::Scaffold.is_active());
        assert!(L2StarkMode::Active.is_active());
    }

    #[test]
    fn l2_stark_mode_from_str_valid() {
        assert_eq!(
            "disabled".parse::<L2StarkMode>().unwrap(),
            L2StarkMode::Disabled
        );
        assert_eq!(
            "scaffold".parse::<L2StarkMode>().unwrap(),
            L2StarkMode::Scaffold
        );
        assert_eq!(
            "active".parse::<L2StarkMode>().unwrap(),
            L2StarkMode::Active
        );
    }

    #[test]
    fn l2_stark_mode_from_str_case_insensitive() {
        assert_eq!(
            "DISABLED".parse::<L2StarkMode>().unwrap(),
            L2StarkMode::Disabled
        );
        assert_eq!(
            "Scaffold".parse::<L2StarkMode>().unwrap(),
            L2StarkMode::Scaffold
        );
        assert_eq!(
            "ACTIVE".parse::<L2StarkMode>().unwrap(),
            L2StarkMode::Active
        );
    }

    #[test]
    fn l2_stark_mode_from_str_unknown_is_error() {
        assert!("recursive".parse::<L2StarkMode>().is_err());
        assert!("".parse::<L2StarkMode>().is_err());
    }

    #[test]
    fn l2_stark_mode_display() {
        assert_eq!(L2StarkMode::Disabled.to_string(), "disabled");
        assert_eq!(L2StarkMode::Scaffold.to_string(), "scaffold");
        assert_eq!(L2StarkMode::Active.to_string(), "active");
    }

    // ── WPoA default consensus tests ──────────────────────────

    #[test]
    fn default_consensus_is_wpoa() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.consensus.engine_kind(), "wpoa");
    }

    #[test]
    fn testnet_default_consensus_is_wpoa() {
        let cfg = NodeConfig::for_network(Address::ZERO, NetworkType::Testnet);
        assert_eq!(cfg.consensus.engine_kind(), "wpoa");
    }

    #[test]
    fn mainnet_default_consensus_is_wpoa() {
        let cfg = NodeConfig::for_network(Address::ZERO, NetworkType::Mainnet);
        assert_eq!(cfg.consensus.engine_kind(), "wpoa");
    }

    #[test]
    fn wpoa_default_preserves_authority() {
        let addr = Address::from_slice(&[0xAB; 32]);
        let cfg = NodeConfig::dev(addr);
        // poa_config() works for both Poa and WPoa variants.
        assert_eq!(cfg.consensus.poa_config().authorities[0], addr);
    }

    #[test]
    fn heartbeat_default_is_600s() {
        // White paper: heartbeat blocks keep the chain alive during idle periods.
        // Default max_idle_interval is 600 000 ms (10 minutes).
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.max_idle_interval_ms, 600_000);
    }

    #[test]
    fn heartbeat_nonzero_means_idle_skip_enabled() {
        // A non-zero max_idle_interval means idle-block-skip is active,
        // i.e. heartbeat blocks are produced, not every tick.
        let cfg = NodeConfig::dev(Address::ZERO);
        assert!(cfg.max_idle_interval_ms > 0);
    }
}
