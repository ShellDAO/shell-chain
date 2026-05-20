use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shell_primitives::{Address, ShellHash, U256};

// ── NetworkType ───────────────────────────────────────────────────────────────

/// Identifies which network profile this chain runs under.
///
/// This drives sensible defaults for block time, transaction limits, and
/// prover/consensus parameters so that development and test environments
/// don't burn resources at mainnet throughput.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum NetworkType {
    /// Local development: 30 s blocks, relaxed validation, slashing disabled.
    #[default]
    Dev,
    /// Public test network: 2 s transaction-driven blocks, full validation.
    Testnet,
    /// Production main network: 2 s blocks, strict parameters.
    Mainnet,
}

impl NetworkType {
    /// Target block time in milliseconds for this network profile.
    ///
    /// - Dev: **30 000 ms**.
    /// - Testnet / Mainnet: **2 000 ms**.
    pub fn default_block_time_ms(self) -> u64 {
        match self {
            NetworkType::Dev => 30_000,
            NetworkType::Testnet | NetworkType::Mainnet => 2_000,
        }
    }

    /// Convenience: same as [`default_block_time_ms`] but in whole seconds.
    pub fn default_block_time_secs(self) -> u64 {
        self.default_block_time_ms() / 1_000
    }

    /// Return the full set of network-specific default parameters.
    pub fn default_params(self) -> NetworkParams {
        match self {
            NetworkType::Dev => NetworkParams {
                block_time_ms: 30_000,
                max_tx_per_block: 100,
                stark_aggregation: false,
                async_prover: false,
                min_validators: 1,
                slashing_enabled: false,
                proof_challenge_window: 10,
            },
            NetworkType::Testnet => NetworkParams {
                block_time_ms: 2_000,
                max_tx_per_block: 500,
                stark_aggregation: true,
                async_prover: true,
                min_validators: 3,
                slashing_enabled: true,
                proof_challenge_window: 100,
            },
            NetworkType::Mainnet => NetworkParams {
                block_time_ms: 2_000,
                max_tx_per_block: 500,
                stark_aggregation: true,
                async_prover: true,
                min_validators: 5,
                slashing_enabled: true,
                proof_challenge_window: 100,
            },
        }
    }

    /// Human-readable name used in log messages.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkType::Dev => "dev",
            NetworkType::Testnet => "testnet",
            NetworkType::Mainnet => "mainnet",
        }
    }

    /// Parse from a string, defaulting to `Dev` for unknown values.
    pub fn from_network_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mainnet" => NetworkType::Mainnet,
            "testnet" => NetworkType::Testnet,
            _ => NetworkType::Dev,
        }
    }
}

impl std::str::FromStr for NetworkType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_network_str(s))
    }
}

/// Network-profile-specific default parameters.
///
/// Returned by [`NetworkType::default_params`].  Consumers (NodeConfig, PoA
/// consensus) should derive their defaults from this struct so that a single
/// `NetworkType` value drives the whole system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    /// Target block interval in milliseconds.
    pub block_time_ms: u64,
    /// Maximum transactions included per block.
    pub max_tx_per_block: usize,
    /// Whether the block producer should generate STARK aggregate proofs.
    pub stark_aggregation: bool,
    /// Whether proving is decoupled from block production (async).
    pub async_prover: bool,
    /// Minimum validator count required for consensus.
    pub min_validators: usize,
    /// Whether on-chain slashing is enforced.
    pub slashing_enabled: bool,
    /// Number of blocks after proof acceptance in which a challenge is valid.
    pub proof_challenge_window: u64,
}

/// Genesis configuration for the Shell-Chain network.
///
/// Parsed from a `genesis.json` file. Defines chain identity,
/// consensus parameters, and initial account allocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Unique chain identifier.
    pub chain_id: u64,
    /// Human-readable chain name.
    #[serde(default = "default_chain_name")]
    pub chain_name: String,
    /// Network profile — drives default block time, slashing, and prover config.
    ///
    /// Defaults to [`NetworkType::Dev`] when omitted from the JSON file so
    /// that existing genesis files continue to work unchanged.
    #[serde(default)]
    pub network_type: NetworkType,
    /// Unix timestamp for the genesis block.
    pub timestamp: u64,
    /// Block gas limit.
    #[serde(default = "default_gas_limit")]
    pub gas_limit: u64,
    /// Extra data embedded in the genesis block header.
    #[serde(default)]
    pub extra_data: String,
    /// Consensus engine configuration.
    pub consensus: ConsensusConfig,
    /// Initial account allocations (address → balance + optional code/storage).
    #[serde(default)]
    pub alloc: HashMap<Address, AllocEntry>,
    /// Bootstrap node multiaddrs for P2P peer discovery.
    ///
    /// Each entry should be a full multiaddr with a `/p2p/<peer_id>` component,
    /// e.g. `/ip4/1.2.3.4/tcp/30303/p2p/12D3KooW...`.
    #[serde(default)]
    pub boot_nodes: Vec<String>,
}

fn default_chain_name() -> String {
    "shell-chain".to_string()
}

fn default_gas_limit() -> u64 {
    30_000_000
}

fn default_poa_max_future_secs() -> u64 {
    60
}

/// Consensus engine configuration within genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "engine")]
pub enum ConsensusConfig {
    /// Proof of Authority consensus.
    #[serde(rename = "poa")]
    PoA {
        /// Ordered list of authority addresses.
        authorities: Vec<Address>,
        /// Ordered authority PQ public keys encoded as hex strings.
        ///
        /// Entries must align with `authorities` by index so followers can
        /// verify proposer seals immediately on first block import.
        #[serde(default)]
        authority_pubkeys: Vec<String>,
        /// Minimum seconds between blocks.
        block_time_secs: u64,
        /// Maximum seconds a block timestamp may be ahead of wall-clock time.
        #[serde(default = "default_poa_max_future_secs")]
        max_future_secs: u64,
        /// Number of blocks per epoch. Defaults to 0 (no epochs).
        #[serde(default)]
        epoch_length: u64,
    },
    /// Weighted Proof of Authority consensus (Phase 1.5).
    ///
    /// Identical to PoA but adds per-validator weights for proportional proposer
    /// selection. `weights[i]` corresponds to `authorities[i]`. Missing weights
    /// default to 1.
    #[serde(rename = "wpoa")]
    WPoA {
        /// Ordered list of authority addresses.
        authorities: Vec<Address>,
        /// Ordered authority PQ public keys encoded as hex strings.
        #[serde(default)]
        authority_pubkeys: Vec<String>,
        /// Minimum seconds between blocks.
        block_time_secs: u64,
        /// Maximum seconds a block timestamp may be ahead of wall-clock time.
        #[serde(default = "default_poa_max_future_secs")]
        max_future_secs: u64,
        /// Number of blocks per epoch. Defaults to 0 (no epochs).
        #[serde(default)]
        epoch_length: u64,
        /// Per-validator weights (aligned with `authorities`). Defaults to all-1.
        #[serde(default)]
        weights: Vec<u64>,
    },
}

impl ConsensusConfig {
    /// Return the ordered authority addresses (PoA or wPoA).
    pub fn authorities(&self) -> &[Address] {
        match self {
            Self::PoA { authorities, .. } | Self::WPoA { authorities, .. } => authorities,
        }
    }

    /// Return the authority PQ public keys.
    pub fn authority_pubkeys(&self) -> &[String] {
        match self {
            Self::PoA {
                authority_pubkeys, ..
            }
            | Self::WPoA {
                authority_pubkeys, ..
            } => authority_pubkeys,
        }
    }

    /// Return the block time in seconds.
    pub fn block_time_secs(&self) -> u64 {
        match self {
            Self::PoA {
                block_time_secs, ..
            }
            | Self::WPoA {
                block_time_secs, ..
            } => *block_time_secs,
        }
    }

    /// Return the max future seconds.
    pub fn max_future_secs(&self) -> u64 {
        match self {
            Self::PoA {
                max_future_secs, ..
            }
            | Self::WPoA {
                max_future_secs, ..
            } => *max_future_secs,
        }
    }

    /// Return the epoch length.
    pub fn epoch_length(&self) -> u64 {
        match self {
            Self::PoA { epoch_length, .. } | Self::WPoA { epoch_length, .. } => *epoch_length,
        }
    }

    /// Return validator weights aligned with `authorities`.
    ///
    /// PoA authorities and missing/zero wPoA weights default to 1.
    pub fn authority_weights(&self) -> Vec<u64> {
        match self {
            Self::PoA { authorities, .. } => vec![1; authorities.len()],
            Self::WPoA {
                authorities,
                weights,
                ..
            } => (0..authorities.len())
                .map(|idx| weights.get(idx).copied().unwrap_or(1).max(1))
                .collect(),
        }
    }
}

/// An entry in the genesis allocation table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocEntry {
    /// Initial balance in wei.
    pub balance: U256,
    /// Optional nonce override (default 0).
    #[serde(default)]
    pub nonce: u64,
    /// Optional contract code (hex-encoded).
    #[serde(default)]
    pub code: Option<String>,
    /// Optional storage entries (slot → value).
    #[serde(default)]
    pub storage: Option<HashMap<ShellHash, ShellHash>>,
}

impl GenesisConfig {
    /// Parse genesis configuration from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Parse genesis configuration from a JSON file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, GenesisError> {
        let content = std::fs::read_to_string(path).map_err(|e| GenesisError::Io(e.to_string()))?;
        Self::from_json(&content).map_err(|e| GenesisError::Parse(e.to_string()))
    }

    /// Serialize to JSON string (pretty-printed).
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Returns the effective PoA block time in seconds.
    ///
    /// If the consensus config specifies a non-zero `block_time_secs`, that
    /// value is used directly (allows operator overrides).  If it is zero,
    /// falls back to the [`NetworkType`] default so that a genesis file only
    /// needs to set `network_type` without repeating the block time.
    pub fn effective_block_time_secs(&self) -> u64 {
        let explicit = self.consensus.block_time_secs();
        if explicit > 0 {
            explicit
        } else {
            self.network_type.default_block_time_secs()
        }
    }

    /// Validates that the consensus `block_time_secs` is consistent with
    /// the `network_type` default.
    ///
    /// Returns `Ok(())` if consistent or if the caller explicitly set a
    /// custom block time on a `Dev` chain (always allowed).
    /// Returns `Err(GenesisError::Validation)` when a non-Dev network has
    /// a block time that disagrees with its network-type default by more
    /// than 50% — this catches accidental mismatches while still allowing
    /// intentional operator customization with a small tolerance.
    pub fn validate_network_consistency(&self) -> Result<(), GenesisError> {
        let explicit = self.consensus.block_time_secs();
        // Zero means "use network default" — always valid.
        if explicit == 0 {
            return Ok(());
        }
        // Dev networks may use any block time.
        if self.network_type == NetworkType::Dev {
            return Ok(());
        }
        let expected = self.network_type.default_block_time_secs();
        // Allow up to 50% deviation for intentional tuning on non-Dev networks.
        let lower = expected / 2;
        let upper = expected * 2;
        if explicit < lower || explicit > upper {
            return Err(GenesisError::Validation(format!(
                "network_type={} expects block_time_secs≈{} but genesis has {}; \
                 fix the genesis or use network_type=Dev for custom timing",
                self.network_type.as_str(),
                expected,
                explicit,
            )));
        }
        Ok(())
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GenesisError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("state initialization error: {0}")]
    StateInit(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_genesis_json() -> String {
        let authority = Address::from([0x01; 32]);
        let funded = Address::from([0x02; 32]);
        serde_json::json!({
            "chain_id": 1337,
            "chain_name": "shell-testnet",
            "timestamp": 1700000000u64,
            "gas_limit": 30000000u64,
            "extra_data": "shell-genesis",
            "consensus": {
                "engine": "poa",
                "authorities": [authority],
                "authority_pubkeys": ["0x1234"],
                "block_time_secs": 2u64,
                "max_future_secs": 45u64
            },
            "alloc": {
                authority.to_string(): {
                    "balance": "0x3635c9adc5dea00000"
                },
                funded.to_string(): {
                    "balance": "0xde0b6b3a7640000",
                    "nonce": 5u64
                }
            }
        })
        .to_string()
    }

    #[test]
    fn parse_genesis_json() {
        let config = GenesisConfig::from_json(&sample_genesis_json()).unwrap();
        assert_eq!(config.chain_id, 1337);
        assert_eq!(config.chain_name, "shell-testnet");
        assert_eq!(config.gas_limit, 30_000_000);
        assert_eq!(config.alloc.len(), 2);
    }

    #[test]
    fn consensus_config_is_poa() {
        let config = GenesisConfig::from_json(&sample_genesis_json()).unwrap();
        match &config.consensus {
            ConsensusConfig::PoA {
                authorities,
                authority_pubkeys,
                block_time_secs,
                max_future_secs,
                ..
            } => {
                assert_eq!(authorities.len(), 1);
                assert_eq!(authority_pubkeys, &vec!["0x1234".to_string()]);
                assert_eq!(*block_time_secs, 2);
                assert_eq!(*max_future_secs, 45);
            }
            _ => panic!("expected PoA consensus"),
        }
    }

    #[test]
    fn alloc_entry_with_nonce() {
        let config = GenesisConfig::from_json(&sample_genesis_json()).unwrap();
        // Find the entry with nonce=5
        let entry = config
            .alloc
            .values()
            .find(|e| e.nonce == 5)
            .expect("should have entry with nonce 5");
        assert_eq!(entry.nonce, 5);
    }

    #[test]
    fn roundtrip_json() {
        let config = GenesisConfig::from_json(&sample_genesis_json()).unwrap();
        let json = config.to_json_pretty().unwrap();
        let config2 = GenesisConfig::from_json(&json).unwrap();
        assert_eq!(config.chain_id, config2.chain_id);
        assert_eq!(config.alloc.len(), config2.alloc.len());
    }

    #[test]
    fn serialized_genesis_uses_hex_addresses() {
        let config = GenesisConfig::from_json(&sample_genesis_json()).unwrap();
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains(&Address::from([0x01; 32]).to_string()));
        assert!(json.contains(&Address::from([0x02; 32]).to_string()));
    }

    #[test]
    fn defaults_applied() {
        let json = r#"{
            "chain_id": 42,
            "timestamp": 0,
            "consensus": {
                "engine": "poa",
                "authorities": [],
                "block_time_secs": 1
            }
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.chain_name, "shell-chain");
        assert_eq!(config.gas_limit, 30_000_000);
        assert!(config.alloc.is_empty());
        assert!(config.boot_nodes.is_empty());
        match config.consensus {
            ConsensusConfig::PoA {
                max_future_secs, ..
            } => assert_eq!(max_future_secs, 60),
            _ => panic!("expected PoA consensus"),
        }
    }

    #[test]
    fn boot_nodes_deserialization() {
        let json = r#"{
            "chain_id": 1337,
            "timestamp": 0,
            "consensus": {
                "engine": "poa",
                "authorities": [],
                "block_time_secs": 1
            },
            "boot_nodes": [
                "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
                "/ip4/5.6.7.8/tcp/30303/p2p/12D3KooWRPnSKiKCPdjoEyrYJzJEMc4TYuknR7ik3jCRe6RkNhWh"
            ]
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.boot_nodes.len(), 2);
        assert!(config.boot_nodes[0].contains("/ip4/1.2.3.4/"));
        assert!(config.boot_nodes[1].contains("/ip4/5.6.7.8/"));
    }

    #[test]
    fn boot_nodes_optional_defaults_to_empty() {
        let json = r#"{
            "chain_id": 99,
            "timestamp": 0,
            "consensus": {
                "engine": "poa",
                "authorities": [],
                "block_time_secs": 1
            }
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert!(config.boot_nodes.is_empty());
    }

    #[test]
    fn boot_nodes_roundtrip_json() {
        let json = r#"{
            "chain_id": 1337,
            "timestamp": 0,
            "consensus": {
                "engine": "poa",
                "authorities": [],
                "block_time_secs": 1
            },
            "boot_nodes": [
                "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            ]
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.boot_nodes.len(), 1);

        let serialized = config.to_json_pretty().unwrap();
        let config2 = GenesisConfig::from_json(&serialized).unwrap();
        assert_eq!(config2.boot_nodes.len(), 1);
        assert_eq!(config.boot_nodes[0], config2.boot_nodes[0]);
    }

    // ── NetworkType tests ─────────────────────────────────────────────────────

    #[test]
    fn network_type_default_is_dev() {
        let json = r#"{
            "chain_id": 1337,
            "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 1}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.network_type, NetworkType::Dev);
    }

    #[test]
    fn network_type_dev_block_time() {
        assert_eq!(NetworkType::Dev.default_block_time_ms(), 30_000);
        assert_eq!(NetworkType::Dev.default_block_time_secs(), 30);
    }

    #[test]
    fn network_type_testnet_block_time() {
        assert_eq!(NetworkType::Testnet.default_block_time_ms(), 2_000);
        assert_eq!(NetworkType::Testnet.default_block_time_secs(), 2);
    }

    #[test]
    fn network_type_mainnet_block_time() {
        assert_eq!(NetworkType::Mainnet.default_block_time_ms(), 2_000);
        assert_eq!(NetworkType::Mainnet.default_block_time_secs(), 2);
    }

    #[test]
    fn network_params_dev() {
        let p = NetworkType::Dev.default_params();
        assert_eq!(p.block_time_ms, 30_000);
        assert_eq!(p.max_tx_per_block, 100);
        assert!(!p.stark_aggregation);
        assert!(!p.async_prover);
        assert_eq!(p.min_validators, 1);
        assert!(!p.slashing_enabled);
        assert_eq!(p.proof_challenge_window, 10);
    }

    #[test]
    fn network_params_testnet() {
        let p = NetworkType::Testnet.default_params();
        assert_eq!(p.block_time_ms, 2_000);
        assert!(p.stark_aggregation);
        assert!(p.async_prover);
        assert!(p.slashing_enabled);
        assert_eq!(p.min_validators, 3);
    }

    #[test]
    fn network_params_mainnet() {
        let p = NetworkType::Mainnet.default_params();
        assert_eq!(p.block_time_ms, 2_000);
        assert!(p.stark_aggregation);
        assert!(p.slashing_enabled);
        assert_eq!(p.min_validators, 5);
    }

    #[test]
    fn network_type_serde_roundtrip() {
        let json = r#"{
            "chain_id": 1338,
            "network_type": "Testnet",
            "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 30}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.network_type, NetworkType::Testnet);

        let serialized = config.to_json_pretty().unwrap();
        let config2 = GenesisConfig::from_json(&serialized).unwrap();
        assert_eq!(config2.network_type, NetworkType::Testnet);
    }

    #[test]
    fn network_type_mainnet_serde() {
        let json = r#"{
            "chain_id": 1,
            "network_type": "Mainnet",
            "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 2}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.network_type, NetworkType::Mainnet);
    }

    #[test]
    fn network_type_as_str() {
        assert_eq!(NetworkType::Dev.as_str(), "dev");
        assert_eq!(NetworkType::Testnet.as_str(), "testnet");
        assert_eq!(NetworkType::Mainnet.as_str(), "mainnet");
    }

    // ── F4: effective_block_time_secs + validate_network_consistency ──────────

    #[test]
    fn effective_block_time_uses_explicit_when_nonzero() {
        let json = r#"{
            "chain_id": 1337, "network_type": "Dev", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 5}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.effective_block_time_secs(), 5);
    }

    #[test]
    fn effective_block_time_falls_back_to_network_default_when_zero() {
        let json = r#"{
            "chain_id": 1337, "network_type": "Mainnet", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 0}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.effective_block_time_secs(), 2); // Mainnet default
    }

    #[test]
    fn effective_block_time_dev_fallback() {
        let json = r#"{
            "chain_id": 1337, "network_type": "Dev", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 0}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.effective_block_time_secs(), 30); // Dev default
    }

    #[test]
    fn effective_block_time_testnet_fallback() {
        let json = r#"{
            "chain_id": 1338, "network_type": "Testnet", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 0}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.effective_block_time_secs(), 2); // Testnet default
    }

    #[test]
    fn validate_consistency_ok_when_matching() {
        let json = r#"{
            "chain_id": 1, "network_type": "Mainnet", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 2}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert!(config.validate_network_consistency().is_ok());
    }

    #[test]
    fn validate_consistency_ok_when_zero() {
        let json = r#"{
            "chain_id": 1, "network_type": "Mainnet", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 0}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert!(config.validate_network_consistency().is_ok());
    }

    #[test]
    fn validate_consistency_err_mainnet_with_dev_block_time() {
        let json = r#"{
            "chain_id": 1, "network_type": "Mainnet", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 30}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert!(config.validate_network_consistency().is_err());
    }

    #[test]
    fn validate_consistency_ok_dev_any_block_time() {
        // Dev networks may use any block time without error.
        let json = r#"{
            "chain_id": 1337, "network_type": "Dev", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 999}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert!(config.validate_network_consistency().is_ok());
    }

    #[test]
    fn validate_consistency_testnet_close_value_ok() {
        // 3s on testnet (expected 2s) is within 50% tolerance -> ok
        let json = r#"{
            "chain_id": 1338, "network_type": "Testnet", "timestamp": 0,
            "consensus": {"engine": "poa", "authorities": [], "block_time_secs": 3}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        assert!(config.validate_network_consistency().is_ok());
    }

    #[test]
    fn wpoa_consensus_config_roundtrip() {
        let json = r#"{
            "chain_id": 10,
            "chain_name": "shell-testnet-wpoa",
            "network_type": "Testnet",
            "timestamp": 1700000000,
            "consensus": {
                "engine": "wpoa",
                "authorities": [],
                "weights": [2, 1, 1],
                "block_time_secs": 2,
                "max_future_secs": 60,
                "epoch_length": 0
            },
            "alloc": {}
        }"#;
        let config = GenesisConfig::from_json(json).unwrap();
        match &config.consensus {
            ConsensusConfig::WPoA {
                weights,
                block_time_secs,
                max_future_secs,
                ..
            } => {
                assert_eq!(weights, &[2u64, 1, 1]);
                assert_eq!(*block_time_secs, 2);
                assert_eq!(*max_future_secs, 60);
            }
            _ => panic!("expected WPoA consensus"),
        }
        // roundtrip
        let serialized = config.to_json_pretty().unwrap();
        let config2 = GenesisConfig::from_json(&serialized).unwrap();
        assert!(matches!(config2.consensus, ConsensusConfig::WPoA { .. }));
        assert_eq!(config2.consensus.block_time_secs(), 2);
    }
}
