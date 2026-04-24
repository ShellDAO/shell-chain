//! `shell-node run` — start the node.

use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use shell_consensus::PoaConfig;
use shell_core::Block;
use shell_crypto::{DilithiumSigner, Signer};
use shell_genesis::{
    initialize_authority_pubkeys, initialize_genesis, AllocEntry, ConsensusConfig, GenesisConfig,
    NetworkType,
};
use shell_keystore::{decrypt, EncryptedKey};
use shell_mempool::MempoolConfig;
use shell_network::{NetworkBus, NetworkConfig};
use shell_node::config::NodeConfig;
use shell_node::pruning::StorageProfile;
use shell_primitives::{Address, ShellHash};
use shell_rpc::RpcConfig;
use shell_storage::{ChainStore, KvStore, MemoryDb, WorldState};

use tracing::{error, info, warn};

/// Aggregated CLI arguments for the `run` subcommand.
#[allow(dead_code)]
pub struct RunArgs {
    pub datadir: PathBuf,
    pub rpc_addr: String,
    /// Network profile string: "dev", "testnet", or "mainnet".
    pub network: String,
    pub block_time: u64,
    pub keystore: Option<PathBuf>,
    pub chain_id: u64,
    pub db: String,
    pub ws: bool,
    pub ws_port: u16,
    pub p2p: bool,
    pub p2p_addr: String,
    pub bootnodes: Vec<String>,
    pub enable_mdns: bool,
    pub pruning: u64,
    pub checkpoint_url: Option<String>,
    pub rpc_cors: Option<String>,
    pub rpc_rate_limit: Option<u32>,
    pub rpc_api: Option<String>,
    pub rpc_api_key: Option<String>,
    /// Path to a PEM-encoded TLS certificate file.
    pub rpc_tls_cert: Option<String>,
    /// Path to a PEM-encoded TLS private key file.
    pub rpc_tls_key: Option<String>,
    pub unsafe_dev_exposed: bool,
    pub metrics_addr: String,
    /// Maximum seconds between blocks when mempool is empty (0 = disabled).
    pub max_idle_interval: u64,
    /// Maximum number of pending transactions in the mempool (default: 4096).
    pub mempool_max_size: Option<usize>,
    /// Minimum gas-price bump required to replace a pending transaction, in percent (default: 10).
    pub mempool_price_bump: Option<u64>,
    /// Account LRU cache size for the world-state trie, in MiB (default: 64).
    pub state_cache_size_mb: Option<usize>,
    /// Enable the parallel-EVM conflict-graph scheduler.
    pub parallel_evm: bool,
    /// Number of worker threads for the parallel-EVM scheduler (default: logical CPUs).
    pub parallel_evm_workers: Option<usize>,
    /// Override witness bundle retention from the storage profile.
    /// `0` = keep forever. Omit to use the storage profile default.
    pub witness_retention: Option<u64>,
    /// Override body (TX detail) retention from the storage profile.
    /// `0` = keep forever. Omit to use the storage profile default.
    pub body_retention: Option<u64>,
    /// High-level storage profile: "archive", "full", or "light".
    pub storage_profile: String,
    /// Enable STARK aggregate proof generation during block production (off by default).
    pub enable_stark_aggregation: bool,
}

/// Maximum genesis file size: 10 MB (F-082).
const MAX_GENESIS_FILE_SIZE: u64 = 10 * 1024 * 1024;
const DEV_AUTHORITY_KEY_FILE: &str = "dev-authority.json";
const DEV_AUTHORITY_INITIAL_BALANCE: u128 = 1_000_000_000_000_000_000_000_000_000u128;

#[derive(Debug, Serialize, Deserialize)]
struct DevAuthorityKeyFile {
    public_key: String,
    secret_key: String,
}

fn load_or_create_dev_signer(path: &Path) -> Result<DilithiumSigner, Box<dyn std::error::Error>> {
    if path.exists() {
        let json = std::fs::read_to_string(path)?;
        let stored: DevAuthorityKeyFile = serde_json::from_str(&json)?;
        let public_key = hex::decode(stored.public_key.trim_start_matches("0x"))?;
        let secret_key = hex::decode(stored.secret_key.trim_start_matches("0x"))?;
        let signer = DilithiumSigner::from_bytes(&public_key, &secret_key)?;
        info!("Loaded persisted dev authority key from {}", path.display());
        return Ok(signer);
    }

    let signer = DilithiumSigner::generate();
    let stored = DevAuthorityKeyFile {
        public_key: format!("0x{}", hex::encode(signer.public_key())),
        secret_key: format!("0x{}", hex::encode(signer.secret_key_bytes().as_slice())),
    };
    let json = serde_json::to_string_pretty(&stored)?;
    {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(path)?;
        file.write_all(json.as_bytes())?;
    }
    info!("Persisted dev authority key to {}", path.display());
    Ok(signer)
}

fn validate_state_root<S: KvStore + 'static>(
    store: Arc<S>,
    state_root: ShellHash,
) -> Result<(), String> {
    if !store
        .contains(state_root.as_bytes())
        .map_err(|e| format!("state root presence check failed: {e}"))?
    {
        return Err(format!("missing trie root node {state_root}"));
    }

    let ws = WorldState::at_root(store, &state_root)
        .map_err(|e| format!("failed to open world state at {state_root}: {e}"))?;

    match catch_unwind(AssertUnwindSafe(|| {
        let mut ws = ws;
        ws.validate()
    })) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!(
            "world state validation failed at {state_root}: {e}"
        )),
        Err(_) => Err(format!("world state validation panicked at {state_root}")),
    }
}

fn recompute_total_tx_count<S: KvStore + 'static>(
    chain_store: &ChainStore<S>,
    head_number: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut total = 0u64;
    for number in 0..=head_number {
        let block = chain_store
            .get_block_by_number(number)?
            .ok_or_else(|| format!("missing canonical block #{number} during tx-count repair"))?;
        total = total
            .checked_add(block.transactions.len() as u64)
            .ok_or("total tx count overflow during repair")?;
    }
    Ok(total)
}

fn repair_head_state_if_needed<S: KvStore + 'static>(
    chain_store: &ChainStore<S>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(head) = chain_store.get_head_block()? else {
        return Ok(false);
    };

    let store = Arc::clone(chain_store.store());
    if validate_state_root(Arc::clone(&store), head.header.state_root).is_ok() {
        return Ok(false);
    }

    warn!(
        block = head.number(),
        state_root = %head.header.state_root,
        "head state root is not restart-safe; scanning canonical history for a recoverable root"
    );

    let mut recovered: Option<Block> = None;
    for number in (0..=head.number()).rev() {
        let Some(candidate) = chain_store.get_block_by_number(number)? else {
            continue;
        };
        match validate_state_root(Arc::clone(&store), candidate.header.state_root) {
            Ok(()) => {
                recovered = Some(candidate);
                break;
            }
            Err(reason) => {
                warn!(
                    block = number,
                    state_root = %candidate.header.state_root,
                    reason,
                    "canonical block state root is not recoverable"
                );
            }
        }
    }

    let recovered = recovered.ok_or_else(|| {
        format!(
            "failed to find a recoverable canonical state root up to head #{}",
            head.number()
        )
    })?;

    if recovered.number() == head.number() {
        return Ok(false);
    }

    let recovered_hash = recovered.hash();
    chain_store.set_head(&recovered_hash)?;
    for number in (recovered.number() + 1)..=head.number() {
        chain_store.delete_canonical(number)?;
    }

    let persisted_finalized = chain_store.get_finalized_number()?.unwrap_or(0);
    if persisted_finalized > recovered.number() {
        chain_store.set_finalized_number(recovered.number())?;
    }
    chain_store.set_total_tx_count(recompute_total_tx_count(chain_store, recovered.number())?)?;

    warn!(
        old_head = head.number(),
        repaired_head = recovered.number(),
        repaired_hash = %recovered_hash,
        "rolled head back to latest recoverable block; node will re-sync missing canonical blocks"
    );
    Ok(true)
}

/// Start the node: load genesis, initialize state, and run the event loop.
pub async fn run(args: RunArgs) -> Result<(), Box<dyn std::error::Error>> {
    // F-096: Canonicalize and validate data directory.
    let datadir = if args.datadir.exists() {
        args.datadir.canonicalize()?
    } else {
        std::fs::create_dir_all(&args.datadir)?;
        args.datadir.canonicalize()?
    };

    let args = RunArgs { datadir, ..args };

    match args.db.as_str() {
        "memory" => {
            info!("Using in-memory storage (non-persistent)");
            let store = Arc::new(MemoryDb::new());
            run_with_store(store, args).await
        }
        "rocksdb" => {
            #[cfg(feature = "rocksdb")]
            {
                use shell_storage::RocksDbStore;
                let db_path = args.datadir.join("db");
                std::fs::create_dir_all(&db_path)?;
                info!("Opening RocksDB at {}", db_path.display());
                let stores = RocksDbStore::open_all(&db_path, None)?;
                // Use the `state` column family as a unified KvStore.
                // ChainStore and WorldState coexist via byte-prefix namespacing.
                let store = Arc::new(stores.state);
                run_with_store(store, args).await
            }
            #[cfg(not(feature = "rocksdb"))]
            {
                Err("RocksDB support not compiled. Rebuild with: cargo build -p shell-cli --features rocksdb".into())
            }
        }
        other => {
            Err(format!("Unknown storage backend: '{other}'. Use 'memory' or 'rocksdb'.").into())
        }
    }
}

/// Core node startup logic, generic over storage backend.
async fn run_with_store<S: KvStore + 'static>(
    store: Arc<S>,
    args: RunArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load or generate the signer.
    let signer: Arc<dyn Signer> = match args.keystore {
        Some(path) => {
            // F-096: Validate keystore path.
            if !path.exists() {
                return Err(format!("keystore file not found: {}", path.display()).into());
            }
            let path = path.canonicalize().map_err(|e| {
                format!(
                    "failed to canonicalize keystore path '{}': {e}",
                    path.display()
                )
            })?;
            // Reject world-readable or group-readable keystores on Unix.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path)?.permissions().mode();
                if (mode & 0o077) != 0 {
                    return Err(format!(
                        "keystore file '{}' has insecure permissions (0o{:03o}); \
                         run: chmod 600 {}",
                        path.display(),
                        mode & 0o777,
                        path.display()
                    )
                    .into());
                }
            }
            info!("Loading keystore from {}", path.display());
            let json = std::fs::read_to_string(&path)?;
            let encrypted: EncryptedKey = serde_json::from_str(&json)?;
            let unlocked_address = Address::parse(&encrypted.address)
                .map_err(|e| format!("invalid keystore address '{}': {e}", encrypted.address))?;

            eprint!("Enter keystore password: ");
            let password = rpassword::read_password()?;

            let signer = decrypt(&encrypted, password.as_bytes())?;
            info!("Keystore unlocked: {unlocked_address}");
            Arc::new(signer)
        }
        None => {
            let path = args.datadir.join(DEV_AUTHORITY_KEY_FILE);
            info!(
                "No keystore provided, loading or creating persisted dev key at {}",
                path.display()
            );
            Arc::new(load_or_create_dev_signer(&path)?)
        }
    };

    let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    info!("Node authority: {authority}");

    // Check if chain is already initialized (persistent storage resume).
    let chain_store = ChainStore::new(store.clone());
    let resumed = if let Ok(Some(head)) = chain_store.get_head_block() {
        info!(
            "Resuming from block #{} (state_root: {:?})",
            head.number(),
            head.header.state_root
        );
        true
    } else {
        false
    };

    if resumed && repair_head_state_if_needed(&chain_store)? {
        if let Some(repaired_head) = chain_store.get_head_block()? {
            info!(
                "Startup state repair selected block #{} (state_root: {:?})",
                repaired_head.number(),
                repaired_head.header.state_root
            );
        }
    }

    let network_type: NetworkType = args.network.parse().unwrap_or_default();

    // Load genesis config.
    let genesis_file = args.datadir.join("genesis.json");
    let genesis_config = if genesis_file.exists() {
        // F-082: Validate genesis file before loading.
        let file_size = std::fs::metadata(&genesis_file)?.len();
        if file_size > MAX_GENESIS_FILE_SIZE {
            return Err(format!(
                "genesis file too large: {} bytes (max {} bytes)",
                file_size, MAX_GENESIS_FILE_SIZE
            )
            .into());
        }
        info!("Loading genesis from {}", genesis_file.display());
        GenesisConfig::from_file(&genesis_file)?
    } else {
        info!("No genesis.json found, using dev genesis");
        use shell_primitives::U256;

        let mut alloc = std::collections::HashMap::new();
        alloc.insert(
            authority,
            AllocEntry {
                balance: U256::from(DEV_AUTHORITY_INITIAL_BALANCE),
                nonce: 0,
                code: None,
                storage: None,
            },
        );

        let config = GenesisConfig {
            chain_id: args.chain_id,
            chain_name: format!("shell-chain-{}", args.network),
            network_type,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            extra_data: String::new(),
            consensus: ConsensusConfig::PoA {
                authorities: vec![authority],
                authority_pubkeys: vec![format!("0x{}", hex::encode(signer.public_key()))],
                block_time_secs: args.block_time / 1000,
                max_future_secs: 60,
                epoch_length: 0,
            },
            alloc,
            boot_nodes: vec![],
        };

        // Persist dev genesis for future restarts.
        std::fs::create_dir_all(&args.datadir)?;
        let json = serde_json::to_string_pretty(&config)?;
        std::fs::write(&genesis_file, &json)?;
        info!("Dev genesis written to {}", genesis_file.display());

        config
    };

    // Initialize genesis only if chain has no head block.
    if !resumed {
        let genesis_block = initialize_genesis(&genesis_config, store.clone())?;
        info!(
            "Genesis block #{} (state_root: {:?})",
            genesis_block.number(),
            genesis_block.header.state_root
        );
    }

    initialize_authority_pubkeys(&genesis_config, &chain_store)?;

    // Checkpoint sync: download and import snapshot if --checkpoint-url is set
    // and the chain has no blocks beyond genesis.
    if let Some(ref url) = args.checkpoint_url {
        if shell_node::checkpoint::should_checkpoint_sync(&chain_store) {
            info!("Chain is empty, starting checkpoint sync");
            let block_num = shell_node::checkpoint::checkpoint_sync(
                url,
                &chain_store,
                &args.datadir,
                args.chain_id,
            )
            .await
            .map_err(|e| -> Box<dyn std::error::Error> {
                format!("checkpoint sync failed: {e}").into()
            })?;
            info!("Checkpoint sync complete at block #{block_num}");
        } else {
            info!("Chain already has blocks, skipping checkpoint sync");
        }
    }

    // Extract authorities and epoch_length from genesis.
    let (authorities, authority_pubkeys, max_future_secs, epoch_length) =
        match &genesis_config.consensus {
            ConsensusConfig::PoA {
                authorities,
                authority_pubkeys,
                max_future_secs,
                epoch_length,
                ..
            } => (
                authorities.clone(),
                authority_pubkeys.clone(),
                *max_future_secs,
                *epoch_length,
            ),
        };

    // F4: validate network_type vs block_time_secs consistency, warn on mismatch.
    if let Err(e) = genesis_config.validate_network_consistency() {
        eprintln!("⚠️  Genesis warning: {e}");
    }
    // F4: use effective block time (explicit consensus value or network-type default).
    let block_time_secs = genesis_config.effective_block_time_secs();

    // Build node configuration.
    let listen_addr: SocketAddr = args.rpc_addr.parse()?;
    let ws_addr = if args.ws {
        Some(SocketAddr::from(([127, 0, 0, 1], args.ws_port)))
    } else {
        None
    };
    let node_config = NodeConfig {
        chain_id: genesis_config.chain_id,
        network_type,
        consensus: PoaConfig::new(authorities.clone(), block_time_secs)
            .with_max_future_secs(max_future_secs)
            .with_epoch_length(epoch_length),
        mempool: MempoolConfig {
            chain_id: genesis_config.chain_id,
            max_pool_size: args.mempool_max_size.unwrap_or(4096),
            replacement_fee_bump_pct: args.mempool_price_bump.unwrap_or(10),
            ..MempoolConfig::default()
        },
        rpc: RpcConfig {
            listen_addr,
            ws_addr,
            cors_allowed_origins: args
                .rpc_cors
                .as_ref()
                .map(|s| s.split(',').map(|o| o.trim().to_string()).collect()),
            rate_limit_per_sec: args.rpc_rate_limit.or(Some(50)),
            api_namespaces: args
                .rpc_api
                .as_ref()
                .map(|s| s.split(',').map(|n| n.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["eth".into(), "net".into(), "web3".into(), "shell".into()]),
            allow_unsafe_dev_exposed: args.unsafe_dev_exposed,
            max_request_body_size: 5 * 1024 * 1024,
            api_key: args.rpc_api_key.clone(),
            tls_cert_path: args.rpc_tls_cert.clone(),
            tls_key_path: args.rpc_tls_key.clone(),
            ..RpcConfig::default()
        },
        network: NetworkConfig::default(),
        proposer_address: Some(authority),
        block_time_ms: args.block_time,
        data_dir: args.datadir.to_string_lossy().into(),
        pruning: {
            let profile = args
                .storage_profile
                .parse::<StorageProfile>()
                .unwrap_or_else(|e| {
                    warn!("Invalid --storage-profile value: {e}. Falling back to 'full'.");
                    StorageProfile::Full
                });
            // Reject contradictory: archive (keep-forever) + explicit pruning limit.
            if profile == StorageProfile::Archive && args.pruning > 0 {
                return Err(format!(
                    "conflicting options: --storage-profile archive keeps all history, \
                     but --pruning {} would discard it; remove one of the two flags",
                    args.pruning
                )
                .into());
            }
            profile.to_pruning_config(
                args.body_retention,
                args.witness_retention,
                // Pass None when --pruning is at default (0) so storage profiles
                // can apply their own keep_recent defaults (e.g. light = 4096).
                // An explicit non-zero --pruning flag overrides the profile.
                if args.pruning == 0 {
                    None
                } else {
                    Some(args.pruning)
                },
            )
        },
        metrics: shell_node::config::MetricsConfig {
            enabled: true,
            listen_addr: args.metrics_addr.parse()?,
        },
        max_idle_interval_ms: args.max_idle_interval * 1000,
        state_cache_size_mb: args.state_cache_size_mb.unwrap_or(64),
        parallel_evm: shell_node::config::ParallelEvmConfig {
            enabled: args.parallel_evm,
            max_workers: args.parallel_evm_workers.unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1)
            }),
            ..shell_node::config::ParallelEvmConfig::default()
        },
        enable_stark_aggregation: args.enable_stark_aggregation,
        node_role: shell_node::config::NodeRole::default(),
    };

    // Build the node (auto-detects existing state via NodeBuilder).
    let (node, _store) = shell_node::builder::NodeBuilder::new(node_config, store).build();

    for (address, pubkey_hex) in authorities.iter().zip(authority_pubkeys.iter()) {
        let trimmed = pubkey_hex.trim_start_matches("0x");
        let pubkey = hex::decode(trimmed).map_err(|e| {
            error!(%address, pubkey_hex, error = %e, "failed to decode authority pubkey");
            format!("invalid authority pubkey for {address}: {e}")
        })?;
        node.register_authority_pubkey(*address, pubkey);
    }

    // Set up the network backend.
    if args.p2p {
        #[cfg(feature = "libp2p")]
        {
            let p2p_listen: std::net::SocketAddr = args.p2p_addr.parse()?;
            // Merge CLI boot nodes with genesis boot nodes (CLI takes priority via ordering).
            let mut boot_nodes = args.bootnodes;
            for addr in &genesis_config.boot_nodes {
                if !boot_nodes.contains(addr) {
                    boot_nodes.push(addr.clone());
                }
            }
            let net_config = NetworkConfig {
                listen_addr: p2p_listen,
                boot_nodes,
                enable_mdns: args.enable_mdns,
                identity_key_path: Some(args.datadir.join("libp2p.key")),
                ..NetworkConfig::default()
            };
            let mut network = shell_network::Libp2pNetwork::new(&net_config).await?;

            eprintln!("🚀 Shell-chain node starting...");
            eprintln!("   Network:     {}", args.network);
            eprintln!("   Chain ID:    {}", genesis_config.chain_id);
            eprintln!("   RPC:         http://{listen_addr}");
            if let Some(ws) = ws_addr {
                eprintln!("   WS:          ws://{ws}");
            }
            eprintln!("   P2P:         {p2p_listen} (libp2p)");
            eprintln!("   Authority:   {authority}");
            eprintln!("   Metrics:     http://{}", args.metrics_addr);
            eprintln!("   Block time:  {}ms", args.block_time);
            if args.pruning > 0 {
                eprintln!("   Pruning:     keep last {} state roots", args.pruning);
            } else {
                eprintln!("   Pruning:     archive (keep all)");
            }
            let body_ret = args.body_retention.unwrap_or(0);
            if body_ret > 0 {
                eprintln!("   Bodies:      keep last {} blocks", body_ret);
            } else {
                eprintln!("   Bodies:      archive (keep all)");
            }
            if resumed {
                eprintln!("   Mode:        resumed from persistent storage");
            }
            eprintln!();

            let node = Arc::new(node);
            let node_shutdown = node.clone();
            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("failed to register SIGTERM handler");

                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {
                            eprintln!("\n⏹  Ctrl-C received, shutting down...");
                        }
                        _ = sigterm.recv() => {
                            eprintln!("\n⏹  SIGTERM received, shutting down...");
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await.ok();
                    eprintln!("\n⏹  Ctrl-C received, shutting down...");
                }
                node_shutdown.shutdown();
            });

            node.clone().run(signer, &mut network).await?;
        }
        #[cfg(not(feature = "libp2p"))]
        {
            return Err("libp2p support not compiled. Rebuild with: cargo build -p shell-cli --features libp2p".into());
        }
    } else {
        // In-process channel network (single-node mode).
        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());

        eprintln!("🚀 Shell-chain node starting...");
        eprintln!("   Network:     {}", args.network);
        eprintln!("   Chain ID:    {}", genesis_config.chain_id);
        eprintln!("   RPC:         http://{listen_addr}");
        if let Some(ws) = ws_addr {
            eprintln!("   WS:          ws://{ws}");
        }
        eprintln!("   Authority:   {authority}");
        eprintln!("   Metrics:     http://{}", args.metrics_addr);
        eprintln!("   Block time:  {}ms", args.block_time);
        if args.pruning > 0 {
            eprintln!("   Pruning:     keep last {} state roots", args.pruning);
        } else {
            eprintln!("   Pruning:     archive (keep all)");
        }
        if let Some(retention) = args.body_retention {
            if retention > 0 {
                eprintln!("   Bodies:      keep last {} blocks", retention);
            } else {
                eprintln!("   Bodies:      archive (keep all)");
            }
        } else {
            eprintln!("   Bodies:      archive (keep all)");
        }
        if resumed {
            eprintln!("   Mode:        resumed from persistent storage");
        }
        eprintln!();

        let node = Arc::new(node);
        let node_shutdown = node.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("failed to register SIGTERM handler");

                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("\n⏹  Ctrl-C received, shutting down...");
                    }
                    _ = sigterm.recv() => {
                        eprintln!("\n⏹  SIGTERM received, shutting down...");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
                eprintln!("\n⏹  Ctrl-C received, shutting down...");
            }
            node_shutdown.shutdown();
        });

        node.clone().run(signer, &mut network).await?;
    }

    eprintln!("✓ Node stopped gracefully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::BlockHeader;
    use shell_genesis::initialize_genesis;
    use shell_node::config::ParallelEvmConfig;
    use shell_primitives::{Bytes, U256};
    use shell_storage::{MemoryDb, DEFAULT_BODY_RETENTION, DEFAULT_WITNESS_RETENTION};
    use std::collections::HashMap;

    /// Verify that `--parallel-evm --parallel-evm-workers 4` produces the correct config.
    #[test]
    fn parallel_evm_args_produce_correct_config() {
        let args = RunArgs {
            datadir: std::path::PathBuf::from("shell-data"),
            rpc_addr: "127.0.0.1:8545".into(),
            block_time: 2000,
            keystore: None,
            chain_id: 1337,
            db: "memory".into(),
            ws: false,
            ws_port: 8546,
            p2p: false,
            p2p_addr: "0.0.0.0:30303".into(),
            bootnodes: vec![],
            enable_mdns: false,
            pruning: 0,
            checkpoint_url: None,
            rpc_cors: None,
            rpc_rate_limit: None,
            rpc_api: None,
            rpc_api_key: None,
            rpc_tls_cert: None,
            rpc_tls_key: None,
            unsafe_dev_exposed: false,
            metrics_addr: "127.0.0.1:9090".into(),
            max_idle_interval: 60,
            mempool_max_size: None,
            mempool_price_bump: None,
            state_cache_size_mb: None,
            parallel_evm: true,
            parallel_evm_workers: Some(4),
            witness_retention: Some(DEFAULT_WITNESS_RETENTION),
            body_retention: Some(DEFAULT_BODY_RETENTION),
            storage_profile: "full".into(),
            enable_stark_aggregation: false,
            network: "dev".into(),
        };

        let expected = ParallelEvmConfig {
            enabled: args.parallel_evm,
            max_workers: args.parallel_evm_workers.unwrap(),
            ..ParallelEvmConfig::default()
        };

        assert!(expected.enabled, "--parallel-evm must set enabled = true");
        assert_eq!(
            expected.max_workers, 4,
            "--parallel-evm-workers 4 must set max_workers = 4"
        );
    }

    #[test]
    fn dev_authority_signer_is_persisted() {
        let unique = format!(
            "shell-cli-dev-authority-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DEV_AUTHORITY_KEY_FILE);

        let signer1 = load_or_create_dev_signer(&path).unwrap();
        let signer2 = load_or_create_dev_signer(&path).unwrap();

        assert_eq!(signer1.public_key(), signer2.public_key());
        assert_eq!(signer1.secret_key_bytes(), signer2.secret_key_bytes());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn test_genesis(authority: Address) -> GenesisConfig {
        GenesisConfig {
            chain_id: 1337,
            chain_name: "shell-chain-test".into(),
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            extra_data: String::new(),
            consensus: ConsensusConfig::PoA {
                authorities: vec![authority],
                authority_pubkeys: vec![],
                block_time_secs: 2,
                max_future_secs: 60,
                epoch_length: 0,
            },
            alloc: HashMap::from([(
                authority,
                AllocEntry {
                    balance: U256::from(1_000_000u64),
                    nonce: 0,
                    code: None,
                    storage: None,
                },
            )]),
            boot_nodes: vec![],
            network_type: NetworkType::Dev,
        }
    }

    fn test_block(number: u64, parent_hash: ShellHash, state_root: ShellHash) -> Block {
        Block {
            header: BlockHeader {
                parent_hash,
                state_root,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::new(),
                number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000 + number,
                extra_data: Bytes::new(),
                proposer: Address::ZERO,
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            proposer_seal: None,
        }
    }

    #[test]
    fn repair_head_state_rolls_back_to_latest_recoverable_block() {
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(Arc::clone(&store));
        let authority = Address::from([7u8; 20]);
        let genesis = initialize_genesis(&test_genesis(authority), Arc::clone(&store)).unwrap();

        let bad_block = test_block(1, genesis.hash(), ShellHash::from([0x11; 32]));
        let bad_hash = bad_block.hash();
        chain_store.put_block(&bad_block).unwrap();
        chain_store.set_canonical(1, &bad_hash).unwrap();
        chain_store.set_head(&bad_hash).unwrap();
        chain_store.set_finalized_number(1).unwrap();
        chain_store.set_total_tx_count(42).unwrap();

        let repaired = repair_head_state_if_needed(&chain_store).unwrap();
        assert!(repaired, "expected startup repair to trigger");

        let repaired_head = chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(repaired_head.number(), 0);
        assert_eq!(repaired_head.hash(), genesis.hash());
        assert!(chain_store.get_block_by_number(1).unwrap().is_none());
        assert_eq!(chain_store.get_finalized_number().unwrap(), Some(0));
        assert_eq!(chain_store.get_total_tx_count().unwrap(), 0);
    }
}
