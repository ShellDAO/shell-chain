//! Node configuration aggregating all component configs.

use std::net::SocketAddr;

use shell_consensus::PoaConfig;
pub use shell_evm::ParallelEvmConfig;
use shell_mempool::MempoolConfig;
use shell_network::NetworkConfig;
use shell_primitives::Address;
use shell_rpc::RpcConfig;

use crate::pruning::PruningConfig;

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
    pub block_time_ms: u64,
    /// Data directory for persistent storage.
    pub data_dir: String,
    /// State-root pruning configuration.
    pub pruning: PruningConfig,
    /// Prometheus metrics endpoint configuration.
    pub metrics: MetricsConfig,
    /// Maximum idle interval in ms before producing a heartbeat block.
    /// When 0, every block_time tick produces a block (legacy behavior).
    pub max_idle_interval_ms: u64,
    /// Account cache size in MiB for the world state LRU trie cache.
    /// Default: 64 MiB.  Higher values reduce state trie decode overhead.
    pub state_cache_size_mb: usize,
    /// Parallel-EVM PoC configuration. Disabled by default until promoted.
    pub parallel_evm: ParallelEvmConfig,
}

impl NodeConfig {
    /// Create a minimal dev-mode configuration with a single authority.
    pub fn dev(authority: Address) -> Self {
        Self {
            chain_id: 1337,
            consensus: PoaConfig::new(vec![authority], 2),
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
            block_time_ms: 2000,
            data_dir: "shell-data".into(),
            pruning: PruningConfig::default(),
            metrics: MetricsConfig::default(),
            max_idle_interval_ms: 0,
            state_cache_size_mb: 64,
            parallel_evm: ParallelEvmConfig::default(),
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
    fn dev_config_block_time() {
        let cfg = NodeConfig::dev(Address::ZERO);
        assert_eq!(cfg.block_time_ms, 2000);
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
}
