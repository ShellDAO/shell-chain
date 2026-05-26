//! TOML configuration file support for `shell-node`.
//!
//! Configuration values loaded from a TOML file act as defaults that CLI
//! flags can override. All sections and fields are optional.

use serde::Deserialize;

/// Top-level configuration file structure (TOML format).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ShellConfig {
    pub node: NodeSection,
    pub rpc: RpcSection,
    pub p2p: P2pSection,
    pub consensus: ConsensusSection,
    pub metrics: MetricsSection,
    pub logging: LoggingSection,
    #[serde(alias = "parallel_evm")]
    pub parallel_pqvm: ParallelPqvmSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct NodeSection {
    pub datadir: Option<String>,
    pub chain_id: Option<u64>,
    /// Network profile: "dev", "testnet", or "mainnet".
    pub network: Option<String>,
    pub block_time: Option<u64>,
    pub keystore: Option<String>,
    pub db: Option<String>,
    pub pruning: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RpcSection {
    pub listen_addr: Option<String>,
    pub ws_enabled: Option<bool>,
    pub ws_port: Option<u16>,
    pub cors_origins: Option<Vec<String>>,
    pub rate_limit: Option<u32>,
    pub api_modules: Option<Vec<String>>,
    pub unsafe_dev_exposed: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct P2pSection {
    pub enabled: Option<bool>,
    pub listen_addr: Option<String>,
    pub bootnodes: Option<Vec<String>>,
    pub enable_mdns: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ConsensusSection {
    pub engine: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MetricsSection {
    pub enabled: Option<bool>,
    pub listen_addr: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LoggingSection {
    pub level: Option<String>,
    pub format: Option<String>,
}

/// Parallel-PQVM scheduling configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ParallelPqvmSection {
    /// Enable conflict-graph scheduling.
    pub enabled: Option<bool>,
    /// Maximum worker threads for parallelizable waves.
    pub worker_threads: Option<usize>,
}

/// Load and parse a TOML configuration file.
pub fn load_config(path: &std::path::Path) -> Result<ShellConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file '{}': {e}", path.display()))?;
    let config: ShellConfig = toml::from_str(&content)
        .map_err(|e| format!("failed to parse config file '{}': {e}", path.display()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_toml_config() {
        let toml_str = r#"
[node]
datadir = "/var/shell"
chain_id = 42
block_time = 5000
keystore = "keys/validator.json"
db = "rocksdb"
pruning = 1000

[rpc]
listen_addr = "0.0.0.0:8545"
ws_enabled = true
ws_port = 8546
cors_origins = ["*"]
rate_limit = 100
api_modules = ["eth", "net", "web3"]
unsafe_dev_exposed = true

[p2p]
enabled = true
listen_addr = "0.0.0.0:30303"
bootnodes = ["/ip4/10.0.0.1/tcp/30303/p2p/abc123"]
enable_mdns = false

[consensus]
engine = "poa"

[metrics]
enabled = true
listen_addr = "127.0.0.1:9090"

[logging]
level = "debug"
format = "json"
"#;
        let config: ShellConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.node.datadir.as_deref(), Some("/var/shell"));
        assert_eq!(config.node.chain_id, Some(42));
        assert_eq!(config.node.block_time, Some(5000));
        assert_eq!(config.node.keystore.as_deref(), Some("keys/validator.json"));
        assert_eq!(config.node.db.as_deref(), Some("rocksdb"));
        assert_eq!(config.node.pruning, Some(1000));

        assert_eq!(config.rpc.listen_addr.as_deref(), Some("0.0.0.0:8545"));
        assert_eq!(config.rpc.ws_enabled, Some(true));
        assert_eq!(config.rpc.ws_port, Some(8546));
        assert_eq!(
            config.rpc.cors_origins.as_deref(),
            Some(vec!["*".to_string()].as_slice())
        );
        assert_eq!(config.rpc.rate_limit, Some(100));
        assert_eq!(
            config.rpc.api_modules.as_deref(),
            Some(vec!["eth".to_string(), "net".to_string(), "web3".to_string()].as_slice())
        );
        assert_eq!(config.rpc.unsafe_dev_exposed, Some(true));

        assert_eq!(config.p2p.enabled, Some(true));
        assert_eq!(config.p2p.listen_addr.as_deref(), Some("0.0.0.0:30303"));
        assert_eq!(config.p2p.enable_mdns, Some(false));
        assert_eq!(config.p2p.bootnodes.as_ref().unwrap().len(), 1);

        assert_eq!(config.consensus.engine.as_deref(), Some("poa"));

        assert_eq!(config.metrics.enabled, Some(true));
        assert_eq!(
            config.metrics.listen_addr.as_deref(),
            Some("127.0.0.1:9090")
        );

        assert_eq!(config.logging.level.as_deref(), Some("debug"));
        assert_eq!(config.logging.format.as_deref(), Some("json"));
    }

    #[test]
    fn default_values_when_sections_missing() {
        let config: ShellConfig = toml::from_str("").unwrap();

        assert!(config.node.datadir.is_none());
        assert!(config.node.chain_id.is_none());
        assert!(config.node.block_time.is_none());
        assert!(config.node.keystore.is_none());
        assert!(config.node.db.is_none());
        assert!(config.node.pruning.is_none());
        assert!(config.rpc.listen_addr.is_none());
        assert!(config.rpc.ws_enabled.is_none());
        assert!(config.rpc.ws_port.is_none());
        assert!(config.rpc.cors_origins.is_none());
        assert!(config.rpc.rate_limit.is_none());
        assert!(config.rpc.api_modules.is_none());
        assert!(config.rpc.unsafe_dev_exposed.is_none());
        assert!(config.p2p.enabled.is_none());
        assert!(config.p2p.listen_addr.is_none());
        assert!(config.p2p.bootnodes.is_none());
        assert!(config.p2p.enable_mdns.is_none());
        assert!(config.consensus.engine.is_none());
        assert!(config.metrics.enabled.is_none());
        assert!(config.metrics.listen_addr.is_none());
        assert!(config.logging.level.is_none());
        assert!(config.logging.format.is_none());
    }

    #[test]
    fn partial_config_uses_defaults_for_missing() {
        let toml_str = r#"
[node]
chain_id = 1

[rpc]
ws_enabled = true
"#;
        let config: ShellConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.node.chain_id, Some(1));
        assert!(config.node.datadir.is_none());
        assert!(config.node.block_time.is_none());
        assert_eq!(config.rpc.ws_enabled, Some(true));
        assert!(config.rpc.listen_addr.is_none());
        assert!(config.rpc.unsafe_dev_exposed.is_none());
        assert!(config.p2p.enabled.is_none());
    }

    #[test]
    fn cli_override_simulation() {
        let toml_str = r#"
[node]
chain_id = 42
block_time = 5000
db = "rocksdb"

[rpc]
listen_addr = "0.0.0.0:8545"
"#;
        let config: ShellConfig = toml::from_str(toml_str).unwrap();

        // Simulate CLI providing chain_id=1337 (override) but not db (use config).
        let cli_chain_id: Option<u64> = Some(1337);
        let cli_db: Option<String> = None;

        let effective_chain_id = cli_chain_id.or(config.node.chain_id).unwrap_or(1337);
        let effective_db = cli_db
            .or(config.node.db.clone())
            .unwrap_or_else(|| "memory".to_string());

        assert_eq!(effective_chain_id, 1337); // CLI wins
        assert_eq!(effective_db, "rocksdb"); // Config wins (CLI was None)
    }

    #[test]
    fn metrics_addr_cli_overrides_config() {
        let toml_str = r#"
[metrics]
listen_addr = "0.0.0.0:9100"
"#;
        let config: ShellConfig = toml::from_str(toml_str).unwrap();

        // CLI explicitly provides --metrics-addr
        let cli_metrics: Option<String> = Some("192.168.1.1:9090".to_string());
        let effective = cli_metrics
            .or(config.metrics.listen_addr)
            .unwrap_or_else(|| "127.0.0.1:9090".to_string());
        assert_eq!(effective, "192.168.1.1:9090");
    }

    #[test]
    fn metrics_addr_falls_back_to_config() {
        let toml_str = r#"
[metrics]
listen_addr = "0.0.0.0:9100"
"#;
        let config: ShellConfig = toml::from_str(toml_str).unwrap();

        // CLI does not provide --metrics-addr
        let cli_metrics: Option<String> = None;
        let effective = cli_metrics
            .or(config.metrics.listen_addr)
            .unwrap_or_else(|| "127.0.0.1:9090".to_string());
        assert_eq!(effective, "0.0.0.0:9100");
    }

    #[test]
    fn metrics_addr_default_when_no_cli_no_config() {
        let config = ShellConfig::default();

        let cli_metrics: Option<String> = None;
        let effective = cli_metrics
            .or(config.metrics.listen_addr)
            .unwrap_or_else(|| "127.0.0.1:9090".to_string());
        assert_eq!(effective, "127.0.0.1:9090");
    }
}
