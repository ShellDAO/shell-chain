//! Shell-chain node CLI.
//!
//! Binary entry point for the post-quantum blockchain node.
//! Subcommands:
//! - `run`           — start the node (block production + RPC + network)
//! - `init`          — initialize genesis and data directory
//! - `key generate`  — create a new encrypted keystore file
//! - `tx send|deploy|call` — transaction operations
//! - `account list|balance|nonce` — account management
//! - `wallet create|balance|send|export` — lightweight wallet UX
//! - `export-state`  — export chain state to a snapshot file
//! - `import-state`  — import chain state from a snapshot file
//! - `removedb`      — remove the chain database
//! - `version`       — print version information

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod config;

use config::ShellConfig;

#[derive(Parser)]
#[command(
    name = "shell-node",
    about = "Shell-chain post-quantum blockchain node",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    /// Data directory for chain storage and keystore.
    #[arg(long, default_value = "shell-data", global = true)]
    datadir: PathBuf,

    /// Log output format: "text" (human-readable), "json" (structured), or "compact".
    #[arg(long, default_value = "text", global = true)]
    log_format: String,

    /// Log level filter (RUST_LOG style, e.g. "debug", "shell_node=trace").
    #[arg(long, global = true)]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Start the node.
    Run {
        /// Path to TOML configuration file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// JSON-RPC listen address.
        #[arg(long, default_value = "127.0.0.1:8545")]
        rpc_addr: String,

        /// Network profile: "dev", "testnet", or "mainnet".
        /// Drives block time (dev/testnet=30s, mainnet=2s) and feature defaults.
        /// Block time can be further overridden with --block-time.
        #[arg(long, default_value = "dev")]
        network: String,

        /// Block production interval in milliseconds.
        /// Defaults to the network profile default (dev/testnet: 30000, mainnet: 2000).
        /// Explicit values override the network profile default.
        #[arg(long)]
        block_time: Option<u64>,

        /// Path to the encrypted keystore file.
        #[arg(long)]
        keystore: Option<PathBuf>,

        /// Chain ID.
        #[arg(long, default_value = "1337")]
        chain_id: u64,

        /// Storage backend: "memory" or "rocksdb".
        #[arg(long, default_value = "memory")]
        db: String,

        /// Enable dedicated WebSocket RPC server on a separate port.
        #[arg(long)]
        ws: bool,

        /// WebSocket RPC listen port (used with --ws).
        #[arg(long, default_value = "8546")]
        ws_port: u16,

        /// Enable libp2p P2P networking (requires --features libp2p).
        #[arg(long)]
        p2p: bool,

        /// P2P listen address (ip:port for libp2p TCP).
        #[arg(long, default_value = "0.0.0.0:30303")]
        p2p_addr: String,

        /// Bootstrap peer multiaddrs (repeatable).
        #[arg(long)]
        bootnode: Vec<String>,

        /// Comma-separated bootstrap peer multiaddrs.
        #[arg(long, value_delimiter = ',')]
        bootnodes: Vec<String>,

        /// Enable mDNS local peer discovery (disable in production/cloud).
        #[arg(long)]
        enable_mdns: bool,

        /// Number of recent state roots to retain (0 = archive mode, keeps all).
        #[arg(long, default_value = "0")]
        pruning: u64,

        /// Checkpoint sync: download snapshot from URL on first start.
        #[arg(long)]
        checkpoint_url: Option<String>,

        /// CORS allowed origins (comma-separated, '*' for all).
        #[arg(long)]
        rpc_cors: Option<String>,

        /// RPC rate limit per second per connection.
        #[arg(long)]
        rpc_rate_limit: Option<u32>,

        /// API namespaces to enable (comma-separated: eth,net,web3,shell,evm,debug,trace).
        #[arg(long)]
        rpc_api: Option<String>,

        /// Bearer token API key required on every RPC request (disabled if not set).
        #[arg(long)]
        rpc_api_key: Option<String>,

        /// Path to a PEM TLS certificate file for HTTPS/WSS (requires --rpc-tls-key).
        #[arg(long)]
        rpc_tls_cert: Option<String>,

        /// Path to a PEM TLS private key file for HTTPS/WSS (requires --rpc-tls-cert).
        #[arg(long)]
        rpc_tls_key: Option<String>,

        /// Allow exposing dev-only `evm` RPC methods on non-loopback listeners.
        #[arg(long)]
        unsafe_dev_exposed: bool,

        /// Metrics HTTP server listen address (ip:port).
        #[arg(long)]
        metrics_addr: Option<String>,

        /// Max idle seconds before producing a heartbeat block (0 = always produce).
        #[arg(long, default_value = "0")]
        max_idle_interval: u64,

        /// Maximum number of pending transactions in the mempool.
        #[arg(long)]
        mempool_max_size: Option<usize>,

        /// Minimum gas-price bump (%) required to replace a pending transaction.
        #[arg(long)]
        mempool_price_bump: Option<u64>,

        /// Account LRU cache size for the world-state trie in MiB.
        #[arg(long)]
        state_cache_size_mb: Option<usize>,

        /// Enable the parallel-EVM conflict-graph scheduler.
        #[arg(long)]
        parallel_evm: bool,

        /// Worker threads for the parallel-EVM scheduler (default: logical CPUs).
        #[arg(long)]
        parallel_evm_workers: Option<usize>,

        /// High-level storage classification for this node.
        ///
        /// Controls which block data is retained and for how long:
        ///
        ///   archive — TX bodies + PQ signatures + STARK proofs kept forever.
        ///             Witness bundles are never deleted, even after a STARK proof arrives.
        ///             ~12.8 GB/day at 50 tx/block.
        ///
        ///   full    — TX bodies kept forever; PQ signatures replaced by STARK proofs
        ///             once the proof lands. Recommended default. ~1.5 GB/day.
        ///
        ///   light   — Rolling 4 096-block window (~2.3 h at 2 s/block). ~1 GB total (stable).
        ///
        /// Individual --body-retention / --witness-retention flags override the profile default.
        #[arg(long, default_value = "full")]
        storage_profile: String,

        /// Override witness bundle retention from the storage profile.
        /// 0 = keep forever. If omitted, the storage profile default is used.
        #[arg(long)]
        witness_retention: Option<u64>,

        /// Override body (TX detail) retention from the storage profile.
        /// 0 = keep forever. If omitted, the storage profile default is used.
        #[arg(long)]
        body_retention: Option<u64>,

        /// Enable STARK aggregate proof generation during block production.
        /// WARNING: expensive (~150ms per block). Off by default.
        #[arg(long, default_value = "false")]
        enable_stark_aggregation: bool,
    },

    /// Initialize genesis block and data directory.
    Init {
        /// Path to genesis.json configuration file.
        #[arg(long)]
        genesis: Option<PathBuf>,

        /// Chain ID.
        #[arg(long, default_value = "1337")]
        chain_id: u64,

        /// Network profile: "dev", "testnet", or "mainnet".
        #[arg(long, default_value = "dev")]
        network: String,
    },

    /// Key management subcommands.
    Key {
        #[command(subcommand)]
        action: KeyCommands,
    },

    /// Export chain state to a snapshot file.
    ExportState {
        /// Block number to export state at (default: latest).
        #[arg(long)]
        block: Option<u64>,

        /// Output file path.
        #[arg(long, default_value = "snapshot.jsonl")]
        output: PathBuf,
    },

    /// Import chain state from a snapshot file.
    ImportState {
        /// Path to the snapshot file.
        #[arg(long)]
        snapshot: PathBuf,
    },

    /// Remove the chain database directory.
    Removedb {
        /// Remove without confirmation prompt.
        #[arg(long)]
        force: bool,
    },

    /// Print version information.
    Version,

    /// Send, deploy, or call transactions.
    Tx {
        #[command(subcommand)]
        command: commands::tx::TxCommand,
    },

    /// Account management (list keystores, query balance/nonce).
    Account {
        #[command(subcommand)]
        command: commands::account::AccountCommand,
    },

    /// Lightweight wallet UX built on top of key/account/tx primitives.
    Wallet {
        #[command(subcommand)]
        command: commands::wallet::WalletCommand,
    },

    /// Hot backup and restore for the RocksDB data directory.
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },
}

#[derive(Subcommand)]
enum BackupCommands {
    /// Create a RocksDB checkpoint (hot backup).
    Create {
        /// Output directory for the backup (default: <datadir>/backups/<timestamp>/).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Restore the data directory from a RocksDB checkpoint.
    Restore {
        /// Path to the backup directory created by `backup create`.
        backup_path: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new Dilithium3 keypair and save as encrypted keystore.
    Generate {
        /// Output path for the keystore file.
        #[arg(long, default_value = "keystore.json")]
        output: PathBuf,
    },

    /// Display the address of a keystore file.
    Inspect {
        /// Path to the keystore file.
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Build env filter: --log-level flag > RUST_LOG env var > "info" default.
    let filter = match &cli.log_level {
        Some(level) => EnvFilter::new(level),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };

    // Initialize tracing subscriber with the chosen format.
    match cli.log_format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_env_filter(filter)
                .init();
        }
        "compact" => {
            tracing_subscriber::fmt()
                .compact()
                .with_target(false)
                .with_env_filter(filter)
                .init();
        }
        _ => {
            // Default "text" format with full target and thread IDs for debugging.
            tracing_subscriber::fmt()
                .with_target(true)
                .with_thread_ids(false)
                .with_env_filter(filter)
                .init();
        }
    }

    let result = match cli.command {
        Commands::Run {
            config: config_path,
            rpc_addr,
            network,
            block_time,
            keystore,
            chain_id,
            db,
            ws,
            ws_port,
            p2p,
            p2p_addr,
            bootnode,
            bootnodes,
            enable_mdns,
            pruning,
            checkpoint_url,
            rpc_cors,
            rpc_rate_limit,
            rpc_api,
            rpc_api_key,
            rpc_tls_cert,
            rpc_tls_key,
            unsafe_dev_exposed,
            metrics_addr,
            max_idle_interval,
            mempool_max_size,
            mempool_price_bump,
            state_cache_size_mb,
            parallel_evm,
            parallel_evm_workers,
            storage_profile,
            witness_retention,
            body_retention,
            enable_stark_aggregation,
        } => {
            // Load config file if specified (CLI args override file values).
            let file_config = match &config_path {
                Some(path) => match config::load_config(path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                },
                None => ShellConfig::default(),
            };

            // Merge: CLI explicit values take priority over config file.
            let datadir = if cli.datadir != *"shell-data" {
                cli.datadir
            } else {
                file_config
                    .node
                    .datadir
                    .map(PathBuf::from)
                    .unwrap_or(cli.datadir)
            };

            let effective_rpc_addr = if rpc_addr != "127.0.0.1:8545" {
                rpc_addr
            } else {
                file_config.rpc.listen_addr.unwrap_or(rpc_addr)
            };

            // Resolve network type first so block_time default can come from it.
            let effective_network = if network != "dev" {
                network.clone()
            } else {
                file_config
                    .node
                    .network
                    .clone()
                    .unwrap_or_else(|| network.clone())
            };

            // Block time: explicit CLI > config file > network-profile default.
            let network_default_block_time = match effective_network.as_str() {
                "mainnet" => 2_000u64,
                _ => 30_000u64, // dev + testnet
            };
            let effective_block_time = block_time
                .or(file_config.node.block_time)
                .unwrap_or(network_default_block_time);

            let effective_keystore =
                keystore.or_else(|| file_config.node.keystore.map(PathBuf::from));

            let effective_chain_id = if chain_id != 1337 {
                chain_id
            } else {
                file_config.node.chain_id.unwrap_or(chain_id)
            };

            let effective_db = if db != "memory" {
                db
            } else {
                file_config.node.db.unwrap_or(db)
            };

            let effective_ws = ws || file_config.rpc.ws_enabled.unwrap_or(false);

            let effective_ws_port = if ws_port != 8546 {
                ws_port
            } else {
                file_config.rpc.ws_port.unwrap_or(ws_port)
            };

            let effective_p2p = p2p || file_config.p2p.enabled.unwrap_or(false);

            let effective_p2p_addr = if p2p_addr != "0.0.0.0:30303" {
                p2p_addr
            } else {
                file_config.p2p.listen_addr.unwrap_or(p2p_addr)
            };

            let effective_enable_mdns = enable_mdns || file_config.p2p.enable_mdns.unwrap_or(false);

            let effective_pruning = if pruning != 0 {
                pruning
            } else {
                file_config.node.pruning.unwrap_or(pruning)
            };

            let effective_rpc_cors =
                rpc_cors.or_else(|| file_config.rpc.cors_origins.map(|v| v.join(",")));

            let effective_rpc_rate_limit = rpc_rate_limit.or(file_config.rpc.rate_limit);

            let effective_rpc_api =
                rpc_api.or_else(|| file_config.rpc.api_modules.map(|v| v.join(",")));

            let effective_unsafe_dev_exposed =
                unsafe_dev_exposed || file_config.rpc.unsafe_dev_exposed.unwrap_or(false);

            // Merge --bootnode (repeatable) and --bootnodes (comma-separated).
            let mut all_bootnodes = bootnode;
            all_bootnodes.extend(bootnodes);
            if all_bootnodes.is_empty() {
                if let Some(cfg_bootnodes) = file_config.p2p.bootnodes {
                    all_bootnodes = cfg_bootnodes;
                }
            }

            let effective_metrics_addr = metrics_addr
                .or(file_config.metrics.listen_addr)
                .unwrap_or_else(|| "127.0.0.1:9090".to_string());

            let effective_parallel_evm =
                parallel_evm || file_config.parallel_evm.enabled.unwrap_or(false);
            let effective_parallel_evm_workers =
                parallel_evm_workers.or(file_config.parallel_evm.worker_threads);

            commands::run(commands::run::RunArgs {
                datadir,
                rpc_addr: effective_rpc_addr,
                network: effective_network,
                block_time: effective_block_time,
                keystore: effective_keystore,
                chain_id: effective_chain_id,
                db: effective_db,
                ws: effective_ws,
                ws_port: effective_ws_port,
                p2p: effective_p2p,
                p2p_addr: effective_p2p_addr,
                bootnodes: all_bootnodes,
                enable_mdns: effective_enable_mdns,
                pruning: effective_pruning,
                checkpoint_url,
                rpc_cors: effective_rpc_cors,
                rpc_rate_limit: effective_rpc_rate_limit,
                rpc_api: effective_rpc_api,
                rpc_api_key,
                rpc_tls_cert,
                rpc_tls_key,
                unsafe_dev_exposed: effective_unsafe_dev_exposed,
                metrics_addr: effective_metrics_addr,
                max_idle_interval,
                mempool_max_size,
                mempool_price_bump,
                state_cache_size_mb,
                parallel_evm: effective_parallel_evm,
                parallel_evm_workers: effective_parallel_evm_workers,
                storage_profile,
                witness_retention,
                body_retention,
                enable_stark_aggregation,
            })
            .await
        }
        Commands::Init {
            genesis,
            chain_id,
            network,
        } => commands::init(cli.datadir, genesis, chain_id, network),
        Commands::Key { action } => match action {
            KeyCommands::Generate { output } => commands::key_generate(output),
            KeyCommands::Inspect { path } => commands::key_inspect(path),
        },
        Commands::ExportState { block, output } => {
            commands::export_state(cli.datadir, output, block)
        }
        Commands::ImportState { snapshot } => commands::import_state(cli.datadir, snapshot),
        Commands::Removedb { force } => commands::removedb(cli.datadir, force),
        Commands::Version => commands::version(),
        Commands::Tx { command } => commands::tx::execute(command),
        Commands::Account { command } => commands::account::execute(command),
        Commands::Wallet { command } => commands::wallet::execute(command),
        Commands::Backup { command } => match command {
            BackupCommands::Create { output } => commands::create_backup(cli.datadir, output),
            BackupCommands::Restore { backup_path } => {
                commands::restore_backup(cli.datadir, backup_path)
            }
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
