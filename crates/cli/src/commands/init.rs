//! `shell-node init` — initialize genesis and data directory.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use shell_crypto::Signer;
use shell_genesis::{
    initialize_genesis, AllocEntry, ConsensusConfig, GenesisConfig, NetworkType,
    MAX_GENESIS_FILE_SIZE,
};
use shell_primitives::{Address, U256};
use shell_storage::MemoryDb;

use tracing::info;

use super::run::{load_or_create_dev_signer, DEV_AUTHORITY_KEY_FILE};

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
    let network_type: NetworkType = network.parse()?;

    // F-096: Canonicalize data directory path.
    let datadir = if datadir.exists() {
        datadir.canonicalize()?
    } else {
        std::fs::create_dir_all(&datadir)?;
        datadir.canonicalize()?
    };

    let genesis_file = datadir.join("genesis.json");
    match std::fs::symlink_metadata(&genesis_file) {
        Ok(_) => {
            return Err(format!(
                "genesis.json already exists in {}; refusing to replace it",
                datadir.display()
            )
            .into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

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
            let block_time_secs = network_type.default_block_time_secs();
            info!(
                "No genesis.json provided, generating {} genesis (block_time={}s)",
                network_type.as_str(),
                block_time_secs
            );
            let signer = load_or_create_dev_signer(&datadir.join(DEV_AUTHORITY_KEY_FILE))?;
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
                log_address_activation_height: None,
                algorithm_voting_window_activation_height: None,
                algorithm_proposal_identity_height: None,
                algorithm_proposal_staging_height: None,
                algorithm_quorum_activation_height: None,
                algorithm_timelock_activation_height: None,
                bloom_activation_height: None,
                fee_accounting_activation_height: None,
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
    let mut temp = tempfile::NamedTempFile::new_in(&datadir)?;
    temp.write_all(genesis_json.as_bytes())?;
    temp.as_file().sync_all()?;
    // Another initializer may have published a genesis since the early check.
    temp.persist_noclobber(&genesis_file)
        .map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(&datadir)?.sync_all()?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_genesis_persists_the_authority_used_on_startup() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path().to_path_buf(), None, 1337, "dev".into()).unwrap();

        let key_path = dir.path().join(DEV_AUTHORITY_KEY_FILE);
        assert!(
            key_path.is_file(),
            "init must retain the genesis authority key"
        );
        let signer = load_or_create_dev_signer(&key_path).unwrap();
        let genesis = GenesisConfig::from_file(&dir.path().join("genesis.json")).unwrap();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        assert_eq!(genesis.consensus.authorities(), &[authority]);
        assert_eq!(
            genesis.consensus.authority_pubkeys(),
            &[format!("0x{}", hex::encode(signer.public_key()))]
        );
        assert!(genesis.alloc.contains_key(&authority));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn default_genesis_reuses_an_existing_dev_authority() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(DEV_AUTHORITY_KEY_FILE);
        let signer = load_or_create_dev_signer(&key_path).unwrap();
        let original = std::fs::read(&key_path).unwrap();

        init(dir.path().to_path_buf(), None, 1337, "dev".into()).unwrap();

        let genesis = GenesisConfig::from_file(&dir.path().join("genesis.json")).unwrap();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        assert_eq!(genesis.consensus.authorities(), &[authority]);
        assert!(
            std::fs::read(key_path).unwrap() == original,
            "existing key must not be replaced"
        );
    }

    #[test]
    fn default_genesis_rejects_invalid_key_without_replacing_files() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(DEV_AUTHORITY_KEY_FILE);
        let genesis_path = dir.path().join("genesis.json");
        std::fs::write(&key_path, b"invalid key").unwrap();
        std::fs::write(&genesis_path, b"existing genesis").unwrap();

        assert!(init(dir.path().to_path_buf(), None, 1337, "dev".into()).is_err());

        assert_eq!(std::fs::read(key_path).unwrap(), b"invalid key");
        assert_eq!(std::fs::read(genesis_path).unwrap(), b"existing genesis");
    }

    #[test]
    fn supplied_genesis_does_not_generate_a_dev_key() {
        let source = tempfile::tempdir().unwrap();
        init(source.path().to_path_buf(), None, 1337, "dev".into()).unwrap();
        let genesis_path = source.path().join("genesis.json");
        let destination = tempfile::tempdir().unwrap();

        init(
            destination.path().to_path_buf(),
            Some(genesis_path.clone()),
            1337,
            "dev".into(),
        )
        .unwrap();

        assert!(!destination.path().join(DEV_AUTHORITY_KEY_FILE).exists());
        assert_eq!(
            std::fs::read(destination.path().join("genesis.json")).unwrap(),
            std::fs::read(genesis_path).unwrap()
        );
    }

    #[test]
    fn rejects_unknown_network_before_creating_datadir() {
        let parent = tempfile::tempdir().unwrap();
        let datadir = parent.path().join("chain-data");

        let error = init(datadir.clone(), None, 1337, "mianet".into()).unwrap_err();

        assert!(error.to_string().contains("unsupported network profile"));
        assert!(!datadir.exists());
    }
}
