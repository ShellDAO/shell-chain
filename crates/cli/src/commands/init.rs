//! `shell-node init` — initialize genesis and data directory.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use shell_crypto::DilithiumSigner;
use shell_crypto::Signer;
use shell_genesis::{
    initialize_genesis, AllocEntry, ConsensusConfig, GenesisConfig, NetworkType,
    MAX_GENESIS_FILE_SIZE,
};
use shell_primitives::{Address, U256};
use shell_storage::MemoryDb;

use tracing::info;

const DEV_AUTHORITY_INITIAL_BALANCE: u128 = 1_000_000_000_000_000_000_000_000_000u128;

/// Initialize a data directory with genesis block.
///
/// If no genesis.json is provided, creates a dev genesis with a single
/// pre-funded authority account. The `network` parameter controls block time
/// and feature defaults ("dev", "testnet", or "mainnet").
pub fn init(
    datadir: PathBuf,
    genesis_path: Option<PathBuf>,
    chain_id: u64,
    network: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // F-096: Canonicalize data directory path.
    let datadir = if datadir.exists() {
        datadir.canonicalize()?
    } else {
        std::fs::create_dir_all(&datadir)?;
        datadir.canonicalize()?
    };

    let genesis_config = match genesis_path {
        Some(path) => {
            // F-082: Validate genesis file path.
            if !path.exists() {
                return Err(format!("genesis file not found: {}", path.display()).into());
            }
            let path = path.canonicalize().map_err(|e| {
                format!(
                    "failed to canonicalize genesis path '{}': {e}",
                    path.display()
                )
            })?;
            let file_size = std::fs::metadata(&path)?.len();
            if file_size > MAX_GENESIS_FILE_SIZE {
                return Err(format!(
                    "genesis file too large: {} bytes (max {} bytes)",
                    file_size, MAX_GENESIS_FILE_SIZE
                )
                .into());
            }
            info!("Loading genesis from {}", path.display());
            GenesisConfig::from_file(&path)?
        }
        None => {
            let network_type: NetworkType = network.parse().unwrap_or_default();
            let block_time_secs = network_type.default_block_time_secs();
            info!(
                "No genesis.json provided, generating {} genesis (block_time={}s)",
                network_type.as_str(),
                block_time_secs
            );
            let signer = DilithiumSigner::generate();
            let authority =
                Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

            let mut alloc = HashMap::new();
            alloc.insert(
                authority,
                AllocEntry {
                    balance: U256::from(DEV_AUTHORITY_INITIAL_BALANCE),
                    nonce: 0,
                    code: None,
                    storage: None,
                },
            );

            GenesisConfig {
                chain_id,
                chain_name: format!("shell-chain-{}", network_type.as_str()),
                network_type,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| format!("system clock is before UNIX epoch: {e}"))?
                    .as_secs(),
                gas_limit: 30_000_000,
                extra_data: String::new(),
                consensus: ConsensusConfig::PoA {
                    authorities: vec![authority],
                    authority_pubkeys: vec![format!("0x{}", hex::encode(signer.public_key()))],
                    block_time_secs,
                    max_future_secs: 60,
                    epoch_length: 0,
                },
                economics: None,
                alloc,
                boot_nodes: vec![],
            }
        }
    };

    // Use MemoryDb to compute genesis state (actual storage on `run`).
    let store = Arc::new(MemoryDb::new());
    let genesis_block = initialize_genesis(&genesis_config, store)?;

    let genesis_json = serde_json::to_string_pretty(&genesis_config)?;
    let genesis_file = datadir.join("genesis.json");
    std::fs::write(&genesis_file, &genesis_json)?;

    info!(
        "Genesis block #{} written (state_root: {:?})",
        genesis_block.number(),
        genesis_block.header.state_root
    );

    eprintln!("✓ Genesis initialized at {}", datadir.display());
    eprintln!("  Network:    {}", network);
    eprintln!("  Block hash: {:?}", genesis_block.hash());
    eprintln!("  State root: {:?}", genesis_block.header.state_root);
    eprintln!("  Alloc accounts: {}", genesis_config.alloc.len());

    Ok(())
}
