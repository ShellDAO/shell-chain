# Feature: CLI

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

`shell-node` is the single binary entry point for the Shell-Chain post-quantum
blockchain node.  It exposes a `clap`-powered CLI with the following
responsibilities:

- Start the full node (block production, JSON-RPC, optional P2P / WS / metrics)
- Initialize a data directory and genesis block
- Manage post-quantum keystores (generate, inspect, migrate keys)
- Provide a lightweight wallet UX over a running node
- Manage accounts (list, balance, nonce)
- Send transactions and call contracts
- Manage a genesis configuration file
- Backup and restore the RocksDB data directory
- Export and import chain state snapshots
- Remove the database

The binary reads global flags before dispatch (data directory, log format/level,
password resolution mode), then routes to one of the subcommand implementations
in `commands/`.  TOML config files (`ShellConfig`) supply defaults that CLI
flags override.

## 2. Public API surface (with file:line)

The crate is a binary crate; its "API" is the CLI surface and the public
subcommand functions exported from `commands/mod.rs`.

### Global flags (`main.rs`)

| Flag | Default | Description |
|------|---------|-------------|
| `--datadir <PATH>` | `shell-data` | Data directory for chain storage and keystore |
| `--log-format <text\|json\|compact>` | `text` | Log output format |
| `--log-level <filter>` | — | `RUST_LOG`-style level filter |
| `--password-file <PATH>` | — | Read keystore password from first non-empty line of file |
| `--password-stdin` | false | Read keystore password from stdin (no echo) |
| `--allow-env-password` | false | Allow `SHELL_KEYSTORE_PASSWORD` env var (must opt in) |

### Subcommands

#### `run` — Start the node

Purpose: start block production + JSON-RPC server + optional WS / P2P / metrics.

Key flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | — | TOML config file (all other flags override) |
| `--rpc-addr <IP:PORT>` | `127.0.0.1:8545` | JSON-RPC listen address |
| `--network <dev\|testnet\|mainnet>` | `dev` | Network profile (drives block time and feature defaults) |
| `--block-time <ms>` | profile default | Block production interval |
| `--keystore <PATH>` | — | Encrypted keystore file (block proposer key) |
| `--chain-id <u64>` | `1337` | EVM chain ID |
| `--db <memory\|rocksdb>` | `memory` | Storage backend |
| `--ws` / `--ws-port <u16>` | — / `8546` | Enable WebSocket RPC on a separate port |
| `--p2p` / `--p2p-addr <IP:PORT>` | — / `0.0.0.0:30303` | Enable libp2p P2P networking |
| `--bootnode <MULTIADDR>` (repeatable) | — | Bootstrap peer multiaddrs |
| `--bootnodes <CSV>` | — | Comma-separated bootstrap peer multiaddrs |
| `--enable-mdns` | false | mDNS local peer discovery (disable in production) |
| `--pruning <u64>` | `0` | State root retention count (0 = archive) |
| `--checkpoint-url <URL>` | — | Checkpoint sync: download snapshot on first start |
| `--rpc-cors <origins>` | — | CORS allowed origins (`*` for all) |
| `--rpc-rate-limit <u32>` | — | RPC requests per second per connection |
| `--rpc-api <namespaces>` | — | Comma-separated API namespaces: `eth,net,web3,shell,evm,debug,trace` |
| `--rpc-api-key <token>` | — | Bearer token required on every RPC request |
| `--rpc-tls-cert` / `--rpc-tls-key` | — | PEM cert + key for HTTPS/WSS |
| `--unsafe-dev-exposed` | false | Allow `evm` dev methods on non-loopback listeners |
| `--metrics-addr <IP:PORT>` | — | Prometheus metrics HTTP server |
| `--max-idle-interval <s>` | `600` | Max idle seconds before heartbeat block (0 = always produce) |
| `--mempool-max-size <usize>` | — | Max pending transactions in mempool |
| `--mempool-price-bump <u64>` | — | Min gas-price bump (%) to replace a pending tx |
| `--state-cache-size-mb <usize>` | — | World-state trie account LRU cache in MiB |
| `--parallel-evm` | false | Enable conflict-graph parallel-EVM scheduler |

#### `init` — Initialize data directory

Purpose: create the data directory and write genesis block; optionally load a
custom `genesis.json`.

Key flags: `--chain-id`, `--network <dev|testnet|mainnet>`, optional `--genesis <PATH>`.  
Max genesis file size: 10 MiB (F-082).

#### `key generate` — Generate a new PQ keystore

Purpose: create a new keypair, encrypt it with argon2id + XChaCha20-Poly1305,
write JSON to `--output`.

Key flags: `--output <PATH>`, `--algorithm <dilithium3|mldsa65>` (default: `dilithium3`), password flags.

#### `key inspect` — Display keystore address (no password)

Purpose: read a keystore JSON and display the `pq1…` address without decrypting.

Key flags: `<keystore-path>`.

#### `key migrate` — Migrate keystore to v1 sk-only format

Purpose: re-encrypt a legacy keystore to the current v1 secret-key-only format
(strips redundant fields from older formats).

Key flags: `<keystore-path>`, password flags.

#### `wallet create` — Create a new wallet

Purpose: shorthand for `key generate`; writes to `wallet.json` by default.

#### `wallet balance` — Query address balance

Purpose: call `eth_getBalance` via JSON-RPC for a `pq1…` address.

Key flags: `<address>`, `--rpc-url` (default: `http://127.0.0.1:8545`).

#### `wallet send` — Send a value transfer

Purpose: sign and broadcast a transfer transaction from the wallet keystore.

Key flags: `--to`, `--value`, `--keystore`, `--rpc-url`, `--chain-id`, password flags.

#### `wallet export` — Export keystore public information

Purpose: print `pq1…` address and public key hex from a wallet keystore.

#### `account list` — List keystore addresses in data directory

Purpose: scan `--datadir` for keystore JSON files and print each `pq1…` address.

#### `account balance` — Query account balance

Purpose: equivalent to `wallet balance`; accepts `pq1…` Bech32m addresses.

Key flags: `<address>`, `--rpc-url`.

#### `account nonce` — Query account nonce

Purpose: call `eth_getTransactionCount` for an address.

Key flags: `<address>`, `--rpc-url`.

#### `genesis add-alloc` — Add allocation to genesis file

Purpose: insert or update an `alloc[address] = {balance, nonce}` entry in a
genesis JSON file in-place (or to `--output`).

Key flags: `<genesis-path>`, `--address <pq1…>`, `--balance <decimal-wei>`, `--output <PATH>`.

#### `tx send` — Send a value transfer transaction

Purpose: sign and submit a raw `eth_sendRawTransaction` via JSON-RPC.

Key flags: `--to`, `--value`, `--keystore`, `--rpc-url`, `--chain-id`, `--nonce`, `--gas-limit`, password flags.

#### `tx deploy` — Deploy a contract

Purpose: send a transaction with no `to` address and `--code` as init bytecode.

Key flags: `--code <0x-hex>`, `--keystore`, `--rpc-url`, `--chain-id`, password flags.

#### `tx call` — Read-only contract call (`eth_call`)

Purpose: call a contract method without submitting a transaction.

Key flags: `--to`, `--data <0x-hex>`, `--from`, `--rpc-url`.

#### `backup create` — Create RocksDB offline backup

Purpose: create a hard-linked SST checkpoint via `rocksdb::checkpoint::Checkpoint`.
**Node must be stopped** (RocksDB exclusive lock).

Key flags: `--output <dir>` (default: `<datadir>/backups/<unix_timestamp>/`).

#### `backup restore` — Restore from a RocksDB checkpoint

Purpose: rename live `db/` to `db.bak.<timestamp>` then copy the checkpoint into
`db/`.

Key flags: `<backup-dir>`.

#### `export-state` — Export chain state snapshot

Purpose: dump chain state (accounts, storage, code) at a given block to a file.

Key flags: `--output <PATH>`, `--block <u64>` (default: latest).  
Requires `rocksdb` feature.

#### `import-state` — Import chain state snapshot

Purpose: load a previously exported state snapshot into the database.

Key flags: `<snapshot-path>`.  
Validates snapshot before writing.

#### `removedb` — Remove chain database

Purpose: delete the `db/` sub-directory of the data directory.

Key flags: `--force` (dry-run by default; shows size and path, does not delete without `--force`).

#### `version` — Print version

Purpose: print `{name} {version}` and optional `commit: {git_hash}` from
`GIT_HASH` build-time env var.

### Password resolution (`password.rs`)

`PasswordArgs` + `resolve_password` / `resolve_new_password` implement a
priority chain:

1. `--password-file <PATH>` — first non-empty line of file
2. `--password-stdin` — read one line from stdin (no echo)
3. `--allow-env-password` + `SHELL_KEYSTORE_PASSWORD` env var
4. Interactive TTY prompt (using `rpassword`); for new keys, prompts twice

### TOML config (`config.rs`)

`ShellConfig` is the top-level TOML struct; all sections and fields are optional
(`#[serde(default)]`).  Loaded via `--config <PATH>` in the `run` subcommand;
CLI flags override every field.

| Section | Fields |
|---------|--------|
| `[node]` | `datadir`, `chain_id`, `network`, `block_time`, `keystore`, `db`, `pruning` |
| `[rpc]` | `listen_addr`, `ws_enabled`, `ws_port`, `cors_origins`, `rate_limit`, `api_modules`, `unsafe_dev_exposed` |
| `[p2p]` | `enabled`, `listen_addr`, `bootnodes`, `enable_mdns` |
| `[consensus]` | `engine` |
| `[metrics]` | `enabled`, `listen_addr` |
| `[logging]` | `level`, `format` |
| `[parallel_evm]` | `enabled` |

## 3. Implementation map (table)

| Concern | Module | File |
|---------|--------|------|
| CLI entry point, `clap` struct, flag dispatch | — | `cli/src/main.rs` |
| Node start: assembles `NodeConfig`, wires crates | `commands::run` | `cli/src/commands/run.rs` |
| Genesis initialization | `commands::init` | `cli/src/commands/init.rs` |
| Key generation / inspection / migration | `commands::key` | `cli/src/commands/key.rs` |
| Lightweight wallet UX | `commands::wallet` | `cli/src/commands/wallet.rs` |
| Account list / balance / nonce | `commands::account` | `cli/src/commands/account.rs` |
| Transaction send / deploy / call | `commands::tx` | `cli/src/commands/tx.rs` |
| Genesis add-alloc | `commands::genesis` | `cli/src/commands/genesis.rs` |
| RocksDB backup / restore | `commands::backup` | `cli/src/commands/backup.rs` |
| State export | `commands::export_state` | `cli/src/commands/export_state.rs` |
| State import | `commands::import_state` | `cli/src/commands/import_state.rs` |
| Remove database | `commands::removedb` | `cli/src/commands/removedb.rs` |
| Version display | `commands::version` | `cli/src/commands/version.rs` |
| TOML config deserialization | `config` | `cli/src/config.rs` |
| Password resolution (file / stdin / env / TTY) | `password` | `cli/src/password.rs` |

## 4. Invariants (cross-ref CONSTITUTION + ADRs)

- **Password security**: `--allow-env-password` must be explicitly opted in;
  `SHELL_KEYSTORE_PASSWORD` is never read unless this flag is set.  This
  prevents accidental secret leakage in process listings.
- **`pq1…` address format**: all address inputs are parsed via
  `Address::parse()`; legacy `0x…` hex addresses are accepted only where
  explicitly documented (wallet balance/send).  All address outputs are
  Bech32m `pq1…` (CONSTITUTION §2.3).
- **Genesis file size**: genesis files larger than 10 MiB are rejected by
  `init` with a structured error (F-082).
- **Data directory canonicalization**: `init` and `export-state` canonicalize
  the data directory path before use (F-096) to prevent symlink attacks.
- **`removedb` dry-run**: without `--force`, the command prints what would be
  deleted and exits cleanly without modifying any state.
- **`NodeConfig` source of truth**: the `run` subcommand translates CLI flags
  into `shell_node::config::NodeConfig` (see `node/src/config.rs`).
  `ConsensusEngineConfig`, `L2StarkMode`, and `NodeRole` are set there.
- **CONSTITUTION T-1 (PQ-native)**: `key generate` only supports
  `"dilithium3"` and `"mldsa65"` algorithms; ECDSA / secp256k1 key generation
  is not exposed.

## 5. Tests

```
cargo test -p shell-node
```

Key tests (inline `#[cfg(test)]` in `config.rs` and `password.rs`; integration
tests via CI end-to-end scripts):

| Test | Module |
|------|--------|
| `config_deserialization_empty_toml` | `config.rs` |
| `config_deserialization_partial_fields` | `config.rs` |
| `shell_config_default` | `config.rs` |
| `parallel_evm_section_default` | `config.rs` |
| `password_from_file_reads_first_nonempty_line` | `password.rs` |
| `password_env_var_requires_opt_in` | `password.rs` |
| `password_env_var_read_when_opted_in` | `password.rs` |
| E2E: `run + init + key generate + tx send` | `tests/e2e/` |

## 6. Related ADRs

- **ADR-001** — PQ signature stack (key generation algorithm selection)
- **ADR-002** — STARK settlement (`run` wires `L2StarkMode` into `NodeConfig`)
- **ADR-005** — Node crate consolidation (run subcommand defers to `shell-node` crate)
- CONSTITUTION §2.3 — Bech32m address format (CLI address I/O)
- CONSTITUTION T-1 — PQ-native (no ECDSA keygen exposed)
- `shell_node::config::NodeConfig` — canonical run-time configuration struct

## 7. Known limitations / open work

- **No `admin_createSnapshot` RPC method yet** — live (in-process) backup
  without stopping the node is planned but not implemented; `backup create`
  requires the node to be stopped.
- **`export-state` / `import-state` require `rocksdb` feature** — they compile
  to no-ops in memory-only builds.
- **No subcommand for SPHINCS+ key generation** — `key generate --algorithm`
  only accepts `dilithium3` and `mldsa65`; generating SPHINCS+ keys requires
  direct API use.
- **`wallet export` does not support ML-DSA-65 keystores** in all edge cases —
  dispatch relies on `decrypt_any` which handles all types, but the output
  format only shows Bech32m address and raw pubkey hex.
- **TOML config does not cover all `run` flags** — some newer flags (e.g.
  `--rpc-tls-cert`, `--mempool-price-bump`) have no TOML equivalent; they can
  only be set via CLI.
- **Password prompting is synchronous / TTY-only** — no support for
  hardware security modules or external secret managers.

## 8. Change log

- v0.22.2 (2026-05): spec written from source; all subcommands documented;
  password resolution chain documented; TOML config sections inventoried;
  known limitations noted
