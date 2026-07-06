# Shell Node CLI Reference

> `shell-node` v0.25.2 — post-quantum blockchain node (ML-DSA-65 primary, Dilithium3 legacy-compatible)

---

## Table of Contents

1. [Global Flags](#1-global-flags)
2. [Subcommands](#2-subcommands)
   - [run](#21-run---start-the-node)
   - [init](#22-init---initialize-data-directory)
   - [key generate](#23-key-generate---create-keystore)
   - [key inspect](#24-key-inspect---show-address)
   - [tx send / deploy / call](#25-tx-subcommands)
   - [account list / balance / nonce](#26-account-subcommands)
   - [wallet](#27-wallet-subcommands)
   - [backup create / restore](#28-backup-subcommands)
   - [export-state / import-state](#29-export-state--import-state)
   - [removedb](#210-removedb)
   - [version](#211-version)
3. [Environment Variables](#3-environment-variables)
4. [Exit Codes](#4-exit-codes)

---

## 1. Global Flags

These flags apply to every subcommand:

| Flag | Default | Description |
|------|---------|-------------|
| `--datadir <PATH>` | `shell-data` | Data directory for chain storage and keystore |
| `--log-format <FORMAT>` | `text` | Log output format: `text`, `json`, or `compact` |
| `--log-level <FILTER>` | `info` | Log level (RUST_LOG style, e.g. `debug`, `shell_node=trace`) |
| `--password-file <PATH>` | — | Read keystore password from file (first non-empty line) |
| `--password-stdin` | `false` | Read keystore password from stdin (one line) |
| `--allow-env-password` | `false` | Allow reading password from `SHELL_KEYSTORE_PASSWORD` env var |

---

## 2. Subcommands

### 2.1 `run` — Start the Node

```
shell-node [GLOBAL FLAGS] run [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | — | TOML configuration file (overrides individual flags) |
| `--rpc-addr <ADDR>` | `127.0.0.1:8545` | JSON-RPC HTTP listen address |
| `--network <PROFILE>` | `dev` | Network profile: `dev`, `testnet`, or `mainnet` |
| `--block-time <MS>` | profile default | Block production interval in milliseconds (overrides profile) |
| `--keystore <PATH>` | — | Path to encrypted keystore file |
| `--chain-id <ID>` | `1337` | Chain ID |
| `--db <BACKEND>` | profile default | Storage backend: `memory` or `rocksdb` (`dev` defaults to `memory`; `testnet`/`mainnet` default to `rocksdb`) |
| `--ws` | `false` | Enable WebSocket RPC server |
| `--ws-port <PORT>` | `8546` | WebSocket RPC port (used with `--ws`) |
| `--p2p` | `false` | Enable libp2p P2P networking |
| `--p2p-addr <ADDR>` | `0.0.0.0:30303` | P2P TCP listen address |
| `--bootnode <MULTIADDR>` | — | Bootstrap peer multiaddr (repeatable) |
| `--bootnodes <MULTIADDRS>` | — | Comma-separated bootstrap peer multiaddrs |
| `--enable-mdns` | `false` | Enable mDNS local peer discovery (disable in cloud) |
| `--pruning <N>` | `0` | Retain last N state roots (0 = archive, keep all) |
| `--checkpoint-url <URL>` | — | Download snapshot from URL on first start |
| `--rpc-cors <ORIGINS>` | — | CORS allowed origins (comma-separated, `*` for all) |
| `--rpc-rate-limit <N>` | — | RPC rate limit requests/second per bearer token or public bucket |
| `--rpc-api <NAMESPACES>` | all | Enabled namespaces: `eth,net,web3,shell,evm,debug,trace` |
| `--rpc-api-key <TOKEN>` | — | Bearer token required on every RPC request |
| `--rpc-tls-cert <PATH>` | — | PEM TLS certificate for HTTPS/WSS |
| `--rpc-tls-key <PATH>` | — | PEM TLS private key for HTTPS/WSS |
| `--unsafe-dev-exposed` | `false` | Allow `evm_*` dev methods on non-loopback listeners |
| `--metrics-addr <ADDR>` | `127.0.0.1:9090` | Prometheus metrics HTTP address |
| `--max-idle-interval <SECS>` | `600` | Max idle seconds before heartbeat block (0 = disabled) |
| `--mempool-max-size <N>` | `4096` | Maximum pending transactions in mempool |
| `--mempool-price-bump <PCT>` | `10` | Minimum gas-price bump % to replace a pending tx |
| `--state-cache-size-mb <MB>` | `64` | Account LRU cache size for world-state trie |
| `--parallel-pqvm` | `false` | Enable parallel-PQVM conflict-graph scheduler (`--parallel-evm` remains a deprecated alias) |
| `--parallel-pqvm-workers <N>` | logical CPUs | Worker threads for parallel-PQVM (`--parallel-evm-workers` remains a deprecated alias) |
| `--storage-profile <PROFILE>` | `full` | Storage classification: `archive`, `full`, or `light` |
| `--witness-retention <N>` | profile default | Override witness bundle retention (0 = keep forever) |
| `--body-retention <N>` | profile default | Override TX body retention (0 = keep forever) |
| `--enable-stark-aggregation` | `false` | Enable local STARK aggregate proof generation. Expensive; use only on prover or validator-prover nodes. |
| `--consensus-engine <ENGINE>` | `poa` | Consensus engine: `poa` or `wpoa` |

**Network Profile Defaults:**

| Profile | Block Time | Chain ID default |
|---------|-----------|------------------|
| `dev` | 30 000 ms | 1337 |
| `testnet` | 2 000 ms | 10 |
| `mainnet` | 2 000 ms | 1 |

**Storage Profiles:**

| Profile | Bodies | Witnesses | Approx. Size |
|---------|--------|-----------|-------------|
| `archive` | forever | forever | ~12.8 GB/day |
| `full` (default) | forever | replaced by STARK proof | ~1.5 GB/day |
| `light` | rolling 4 096 blocks | rolling | ~1 GB total |

**Example — testnet validator:**

```bash
shell-node \
  --password-file /etc/shell/ks-password \
  run \
  --keystore /opt/shell/validator.json \
  --rpc-addr 0.0.0.0:8545 \
  --network testnet \
  --block-time 2000 \
  --db rocksdb \
  --chain-id 10 \
  --p2p \
  --p2p-addr 0.0.0.0:30303 \
  --rpc-cors '*' \
  --metrics-addr 0.0.0.0:9090 \
  --storage-profile full
```

---

### 2.2 `init` — Initialize Data Directory

```
shell-node [GLOBAL FLAGS] init [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--genesis <PATH>` | — | Path to genesis.json (uses built-in dev genesis if omitted) |
| `--chain-id <ID>` | `1337` | Chain ID |
| `--network <PROFILE>` | `dev` | Network profile |

**Example:**

```bash
shell-node --datadir /opt/shell/data init \
  --genesis /opt/shell/testnet-genesis.json \
  --chain-id 10 \
  --network testnet
```

---

### 2.3 `key generate` — Create Keystore

```
shell-node [GLOBAL FLAGS] key generate [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output <PATH>` | `keystore.json` | Output path for keystore file |
| `--algorithm <ALGO>` | `dilithium3` | PQ algorithm: `mldsa65` (FIPS 204, recommended) or `dilithium3` (legacy-compatible) |

The command prompts for a password unless a non-interactive source is configured.

**Examples:**

```bash
# Interactive
shell-node key generate --algorithm mldsa65 --output validator.json

# CI / scripted
echo "password" | shell-node --password-stdin key generate \
    --algorithm mldsa65 --output validator.json

shell-node --password-file /run/secrets/pw key generate \
    --algorithm dilithium3 --output test-account.json
```

---

### 2.4 `key inspect` — Show Address

```
shell-node key inspect <PATH>
```

Prints the Shell-chain address for a keystore. No password required (address is stored in cleartext).

```bash
shell-node key inspect validator.json
# Address: 0x9f0b8f6d0a0c2d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789
```

---

### 2.5 `tx` Subcommands

```
shell-node [GLOBAL FLAGS] tx <send|deploy|call> [OPTIONS]
```

| Subcommand | Description |
|-----------|-------------|
| `tx send` | Send a transfer or generic transaction |
| `tx deploy` | Deploy a smart contract |
| `tx call` | Call a contract (read-only or state-changing) |

Common flags include `--keystore`, `--to`, `--value`, `--rpc-url`, `--gas`, `--gas-price`, `--nonce`, and optional `--chain-id`.

---

### 2.6 `account` Subcommands

```
shell-node account <balance|nonce> [OPTIONS]
```

| Subcommand | Description |
|-----------|-------------|
| `account balance <ADDR> --rpc-url <URL>` | Query account balance |
| `account nonce <ADDR> --rpc-url <URL>` | Query account nonce |

---

### 2.7 `wallet` Subcommands

High-level wallet UX built on key/account/tx primitives:

```
shell-node wallet <create|balance|send|export> [OPTIONS]
```

---

### 2.8 `backup` Subcommands

Hot backup and restore for the RocksDB data directory:

```
shell-node backup create [--output <DIR>]
shell-node backup restore <BACKUP_DIR>
```

---

### 2.9 `export-state` / `import-state`

```
shell-node export-state [--block <N>] [--output <PATH>]
shell-node import-state --snapshot <PATH>
```

---

### 2.10 `removedb`

```
shell-node removedb [--force]
```

Removes the chain database directory. `--force` skips the confirmation prompt.

---

### 2.11 `version`

```
shell-node --version
```

Prints the binary version and build metadata.

---

## 3. Environment Variables

| Variable | Description |
|----------|-------------|
| `SHELL_KEYSTORE_PASSWORD` | Keystore password (only used when `--allow-env-password` is set) |
| `RUST_LOG` | Log filter (overridden by `--log-level`) |
| `RUST_BACKTRACE` | Enable panic backtraces (`1` or `full`) |

---

## 4. Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime error (check stderr) |
| `2` | CLI argument parse error |
| `130` | Interrupted (Ctrl-C / SIGINT) |
| `143` | Terminated (SIGTERM) |

---

## See Also

- [CLI Automation Guide](cli-automation.md)
- [Keystore Format Specification](keystore-format.md)
- [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md)
- [JSON-RPC API](JSON_RPC_API.md)
