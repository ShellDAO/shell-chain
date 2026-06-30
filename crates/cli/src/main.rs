//! Shell-chain node CLI.
//!
//! Binary entry point for the post-quantum blockchain node.
//! Subcommands:
//! - `run`           — start the node (block production + RPC + network)
//! - `init`          — initialize genesis and data directory
//! - `key generate`  — create a new encrypted keystore file
//! - `key inspect`   — display keystore address (no password required)
//! - `key migrate`   — migrate keystore to current v1 sk-only format
//! - `genesis add-alloc` — add allocation entry to a genesis JSON file
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
mod password;
mod secure_file;

use config::ShellConfig;
use password::PasswordArgs;

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

    /// Read keystore password from this file (first non-empty line).
    /// Avoids interactive prompt; useful for CI and automation.
    #[arg(long, global = true)]
    password_file: Option<PathBuf>,

    /// Read keystore password from stdin (one line, no echo).
    /// Pipe the password: `echo "pw" | shell-node key generate --password-stdin`.
    #[arg(long, global = true, default_value = "false")]
    password_stdin: bool,

    /// Allow reading the keystore password from the SHELL_KEYSTORE_PASSWORD
    /// environment variable. Must be opted-in explicitly; never active by default.
    /// Example: `SHELL_KEYSTORE_PASSWORD=pw shell-node --allow-env-password key generate`.
    #[arg(long, global = true, default_value = "false")]
    allow_env_password: bool,

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
        /// Drives block time (dev=30s, testnet/mainnet=2s) and feature defaults.
        /// Block time can be further overridden with --block-time.
        #[arg(long, default_value = "dev")]
        network: String,

        /// Block production interval in milliseconds.
        /// Defaults to the network profile default (dev: 30000, testnet/mainnet: 2000).
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
        /// Defaults to "rocksdb" for testnet/mainnet (persistent) and "memory" for dev (ephemeral).
        /// Explicit values always override the network-profile default.
        #[arg(long)]
        db: Option<String>,

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

        /// Max idle seconds before producing a heartbeat block when mempool is
        /// empty. `0` disables idle-skip and produces a block on every tick
        /// (legacy behavior). Default `600`: skip empty blocks but heartbeat
        /// every ten minutes to keep sync, light clients, and timestamp
        /// monotonicity healthy without reward inflation.
        #[arg(long, default_value = "600")]
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

        /// Enable the parallel-PQVM conflict-graph scheduler.
        #[arg(long, alias = "parallel-evm")]
        parallel_pqvm: bool,

        /// Worker threads for the parallel-PQVM scheduler (default: logical CPUs).
        #[arg(long, alias = "parallel-evm-workers")]
        parallel_pqvm_workers: Option<usize>,

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
        /// WARNING: expensive. Keep disabled on ordinary validators; use a
        /// dedicated prover or validator-prover node when proof work is needed.
        #[arg(long, default_value = "false")]
        enable_stark_aggregation: bool,

        /// L2 STARK aggregation mode: disabled, scaffold, or active.
        ///
        /// disabled — no L2 scheduler/input/job activity.
        /// scaffold — maintain L2 observability and durable jobs, but do not prove.
        /// active   — reserved for the real recursive prover path.
        #[arg(long, default_value = "disabled")]
        l2_stark_mode: String,

        /// Consensus engine: "poa" (default) or "wpoa".
        #[arg(long)]
        consensus_engine: Option<String>,

        /// Node role: "validator" (default), "validator-prover", or "prover".
        ///
        ///   validator        — produces blocks only (no STARK proof work).
        ///   validator-prover — produces blocks AND runs the background ProverService.
        ///   prover           — no block production; dedicated proof work only.
        ///
        /// Use "validator-prover" when --enable-stark-aggregation is set to
        /// actually generate and commit STARK proofs.
        #[arg(long, default_value = "validator")]
        node_role: String,
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

    /// Genesis file management utilities.
    Genesis {
        #[command(subcommand)]
        action: GenesisCommands,
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

    /// Shell PQ-HD v1 hierarchical-deterministic wallet.
    ///
    /// Generate or restore a BIP-39 mnemonic-backed wallet that derives
    /// post-quantum accounts (ML-DSA-65 or SLH-DSA) via the Shell PQ-HD v1
    /// BLAKE3-keyed hardened tree.  See ADR-011 for the full specification.
    PqHd {
        #[command(subcommand)]
        action: PqHdCommands,
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
    /// Generate a new PQ keypair and save as encrypted keystore.
    Generate {
        /// Output path for the keystore file.
        #[arg(long, default_value = "keystore.json")]
        output: PathBuf,

        /// PQ algorithm to use: `dilithium3` (default) or `mldsa65` (FIPS 204).
        #[arg(long, default_value = "dilithium3")]
        algorithm: String,
    },

    /// Inspect the address of a keystore file (no password required).
    Inspect {
        /// Path to the keystore file.
        path: PathBuf,
    },

    /// Migrate a keystore to the current v1 sk-only format.
    ///
    /// Use this if you have keystores produced by shell-sdk < 0.6.0 (sk‖pk ciphertext).
    /// Decrypts with the current password and re-encrypts using the v1 sk-only format.
    Migrate {
        /// Input keystore path (source).
        #[arg(long)]
        input: PathBuf,

        /// Output keystore path (destination).
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum GenesisCommands {
    /// Add an allocation entry to a genesis JSON file.
    ///
    /// Reads the genesis file, inserts (or updates) the `alloc` entry for the
    /// given address with the specified balance, and writes the file back.
    AddAlloc {
        /// Path to genesis.json to modify (modified in-place unless --output is set).
        #[arg(long)]
        genesis: PathBuf,

        /// Shell-chain address to add (`0x` + 64 lowercase hex).
        #[arg(long)]
        address: String,

        /// Balance in wei (e.g. 1000000000000000000 for 1 SHELL).
        #[arg(long)]
        balance: String,

        /// Write output to this file instead of modifying genesis in-place.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PqHdCommands {
    /// Generate a new BIP-39 mnemonic and save an encrypted HD keystore.
    ///
    /// The recovery phrase is printed ONCE to stderr — write it down.
    Generate {
        /// Output path for the encrypted HD keystore file.
        #[arg(long, default_value = "hd-keystore.json")]
        output: PathBuf,

        /// PQ algorithm for account 0: `mldsa65` (default) or `slhdsa`.
        #[arg(long, default_value = "mldsa65")]
        algo: String,
    },

    /// Derive a specific account from an encrypted HD keystore.
    Derive {
        /// Path to the encrypted HD keystore file.
        #[arg(long)]
        keystore: PathBuf,

        /// Account index (raw, hardened applied automatically). Default: 0.
        #[arg(long, default_value = "0")]
        account: u32,

        /// Change index (0 = external, 1 = internal). Default: 0.
        #[arg(long, default_value = "0")]
        change: u32,

        /// Address index. Default: 0.
        #[arg(long, default_value = "0")]
        index: u32,

        /// PQ algorithm: `mldsa65` (default) or `slhdsa`.
        #[arg(long, default_value = "mldsa65")]
        algo: String,
    },

    /// Print addresses for a mnemonic without storing anything (dry run).
    /// The mnemonic is read from stdin (never passed as a CLI argument).
    Address {
        /// Number of accounts to derive (account indices 0..count-1).
        #[arg(long, default_value = "5")]
        count: u32,

        /// PQ algorithm: `mldsa65` (default) or `slhdsa`.
        #[arg(long, default_value = "mldsa65")]
        algo: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Build password args from global flags (used by key/run/tx subcommands).
    let password_args = PasswordArgs {
        password_file: cli.password_file,
        password_stdin: cli.password_stdin,
        allow_env_password: cli.allow_env_password,
    };

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
            parallel_pqvm,
            parallel_pqvm_workers,
            storage_profile,
            witness_retention,
            body_retention,
            enable_stark_aggregation,
            l2_stark_mode,
            consensus_engine,
            node_role,
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
                "testnet" | "mainnet" => 2_000u64,
                _ => 30_000u64, // dev
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

            // Storage backend: explicit CLI > config file > network-profile default.
            // dev → memory (ephemeral); testnet/mainnet → rocksdb (persistent).
            // If the binary was compiled without the rocksdb feature, fall back to
            // memory and warn so operators notice and rebuild with the feature enabled.
            let network_default_db = match effective_network.as_str() {
                "testnet" | "mainnet" => {
                    if cfg!(feature = "rocksdb") {
                        "rocksdb"
                    } else {
                        tracing::warn!(
                            "rocksdb feature not compiled in; falling back to memory for \
                             {effective_network} — DATA WILL NOT PERSIST across restarts. \
                             Rebuild with --features shell-cli/rocksdb."
                        );
                        "memory"
                    }
                }
                _ => "memory",
            };
            let effective_db = db
                .or(file_config.node.db.clone())
                .unwrap_or_else(|| network_default_db.to_string());

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

            let effective_parallel_pqvm =
                parallel_pqvm || file_config.parallel_pqvm.enabled.unwrap_or(false);
            let effective_parallel_pqvm_workers =
                parallel_pqvm_workers.or(file_config.parallel_pqvm.worker_threads);

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
                parallel_pqvm: effective_parallel_pqvm,
                parallel_pqvm_workers: effective_parallel_pqvm_workers,
                storage_profile,
                witness_retention,
                body_retention,
                enable_stark_aggregation,
                l2_stark_mode,
                consensus_engine,
                node_role,
                password_args: password_args.clone(),
            })
            .await
        }
        Commands::Init {
            genesis,
            chain_id,
            network,
        } => commands::init(cli.datadir, genesis, chain_id, network),
        Commands::Key { action } => match action {
            KeyCommands::Generate { output, algorithm } => {
                commands::key_generate(output, password_args, algorithm)
            }
            KeyCommands::Inspect { path } => commands::key_inspect(path),
            KeyCommands::Migrate { input, output } => {
                commands::key_migrate(input, output, &password_args)
            }
        },
        Commands::Genesis { action } => match action {
            GenesisCommands::AddAlloc {
                genesis,
                address,
                balance,
                output,
            } => commands::genesis_add_alloc(genesis, address, balance, output),
        },
        Commands::ExportState { block, output } => {
            commands::export_state(cli.datadir, output, block)
        }
        Commands::ImportState { snapshot } => commands::import_state(cli.datadir, snapshot),
        Commands::Removedb { force } => commands::removedb(cli.datadir, force),
        Commands::Version => commands::version(),
        Commands::Tx { command } => commands::tx::execute(command, password_args),
        Commands::Account { command } => commands::account::execute(command),
        Commands::Wallet { command } => commands::wallet::execute(command, password_args),
        Commands::PqHd { action } => match action {
            PqHdCommands::Generate { output, algo } => {
                commands::pqhd::execute(commands::pqhd::PqHdCommand::Generate {
                    output,
                    algo,
                    password_args,
                })
            }
            PqHdCommands::Derive {
                keystore,
                account,
                change,
                index,
                algo,
            } => commands::pqhd::execute(commands::pqhd::PqHdCommand::Derive {
                keystore,
                account,
                change,
                index,
                algo,
                password_args,
            }),
            PqHdCommands::Address { count, algo } => {
                commands::pqhd::execute(commands::pqhd::PqHdCommand::Address { count, algo })
            }
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stark_aggregation_is_opt_in_for_run() {
        let cli = Cli::try_parse_from(["shell-node", "run"]).unwrap();

        match cli.command {
            Commands::Run {
                enable_stark_aggregation,
                node_role,
                ..
            } => {
                assert!(!enable_stark_aggregation);
                assert_eq!(node_role, "validator");
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn stark_aggregation_flag_enables_local_proving() {
        let cli = Cli::try_parse_from(["shell-node", "run", "--enable-stark-aggregation"]).unwrap();

        match cli.command {
            Commands::Run {
                enable_stark_aggregation,
                ..
            } => assert!(enable_stark_aggregation),
            _ => panic!("expected run command"),
        }
    }
}
