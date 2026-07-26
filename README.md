# shell-chain

<!-- [![Build Status](https://img.shields.io/github/actions/workflow/status/ShellDAO/shell-chain/ci.yml?branch=main)](https://github.com/ShellDAO/shell-chain/actions) -->
<!-- [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) -->
<!-- [![Version](https://img.shields.io/badge/version-0.27.2-green.svg)](CHANGELOG.md) -->

The first PQVM-native, post-quantum blockchain — quantum-safe **before Q-Day**, no migration needed.

## Overview

Shell-Chain follows [Vitalik Buterin's vision](https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901) for Ethereum's quantum upgrade, but skips the migration path entirely by building a new chain with PQ cryptography as the foundation.

### Key Features

- 🔐 **Post-Quantum Signatures** — ML-DSA-65 (FIPS 204) is the primary governed algorithm; Dilithium3 remains deployed for legacy compatibility, with SPHINCS+ as a conservative fallback
- ⚙️ **PQVM Execution** — EVM-familiar Cancun-style arithmetic, memory, storage, and control flow, with native 32-byte PQ addresses, PQTx, and PQ precompiles/opcodes
- 🏗️ **Native Account Abstraction** — protocol-level smart accounts with built-in PQ validation, key rotation, and custom validator hooks
- 🧩 **PQ Precompile Suite** — 6 on-chain precompiles at `0x0001`–`0x0006`: ML-DSA-65 verify, SLH-DSA-SHA2-256f verify, ML-DSA-65 batch verify, BLAKE3-256, BLAKE3-512, PQAddr derive
- ⚖️ **wPoA Consensus** — Weighted Proof-of-Authority with weighted proposer rotation, view-change fallback, offline/equivocation handling, economic slash weights, and finality tracking
- ⚡ **STARK Sig-Aggregation** — Winterfell proofs compress PQ witness data, track challenges through `Open → Resolved/Slashed`, and in v0.24.x ship multi-layer (L1/L2/L3) settlement, trie-pruning integration, and consensus liveness hardening for lighter storage profiles.
- 🗄️ **Storage Profiles** — `--storage-profile archive|full|light` controls data retention; nodes auto-backfill missing history from richer peers via P2P
- 🛠️ **Developer Ecosystem** — TypeScript SDK (`shell-sdk`) with viem-based PQ signers and AA transaction builders
- 🌐 **P2P Networking** — libp2p with GossipSub, Kademlia DHT, peer scoring, and message signature verification
- 📡 **Full JSON-RPC** — Ethereum-shaped read namespaces (`eth_*`, `web3_*`, `net_*`, `debug_*`) plus Shell-specific APIs such as `shell_getFinalityInfo` and `shell_getAlgorithmRegistry`, secured by TLS, rate limiting, and API keys
- 🐳 **Production Ready** — Docker Compose orchestration, Prometheus/Grafana monitoring, hot backups, and TOML configuration
- 🛡️ **Security Hardened** — 50+ audit findings addressed, Criterion benchmarks, and continuous fuzzing

## Quick Start

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for a complete guide to running a local node.

```bash
# Build
cargo build --release -p shell-cli --bin shell-node

# Initialize a new dev chain with built-in genesis
./target/release/shell-node --datadir ./data init --network dev --chain-id 1337

# Run a node
./target/release/shell-node --datadir ./data run --network dev --db memory
```

For production deployments with Docker, see the [Operator Guide](docs/TESTNET_OPERATOR_GUIDE.md).

## Native Account Abstraction

Shell-Chain's long-term account model is **native AA**.
Accounts are identified by `0x`-prefixed 64-character lowercase hex addresses —
the full 32-byte BLAKE3 hash of `algo_id ‖ public_key`.

At the **canonical layer** (RPC, storage, consensus, signing), addresses are always
the full 32 bytes. At the **revm adapter boundary**, Shell-Chain maintains a
20-byte mapping layer: `Address::to_alloy()` takes the last 20 bytes of the 32-byte
canonical address for use with revm, and `Address::from_alloy()` zero-pads left
back to 32 bytes. This boundary is internal — external callers (SDK, CLI, explorer)
always see and submit the full 32-byte `0x`+64-hex form.

Transaction validation follows three protocol-level paths:

1. **First use** — derive `tx.from` from `(algo_id, pubkey)` and verify the PQ signature
2. **Default existing account** — verify `pq_pubkey_hash` and the PQ signature
3. **Custom AA account** — call account-specific validator code through `validation_code_hash`

This design lets Shell-Chain support key rotation and custom validation logic
without introducing an ERC-4337 bundler or changing the account's address.

For the full design and current implementation status, see
[docs/ACCOUNT_ABSTRACTION_GUIDE.md](docs/ACCOUNT_ABSTRACTION_GUIDE.md).

## Architecture

```
┌─────────────────────────────────────────────┐
│                 shell-node                  │
│          (Node Builder / CLI)               │
├─────────┬──────────┬──────────┬─────────────┤
│   RPC   │ Mempool  │Consensus │  Network    │
├─────────┴──────────┴────┬─────┴─────────────┤
│                    shell-core               │
│       (Block, Transaction, Account)         │
├──────────┬──────────────┼───────────────────┤
│ shell-pqvm│ shell-crypto │  shell-storage    │
│(PQVM/revm│  (PQ Crypto) │   (RocksDB)      │
│ adapter) │              │                  │
├──────────┴──────────────┴───────────────────┤
│              shell-primitives               │
│        (Hash, Address, U256, Bytes)         │
└─────────────────────────────────────────────┘
```

### Crate Map

| Crate | Description |
|-------|-------------|
| `shell-primitives` | Foundational types: Keccak-256, BLAKE3, H256, Address, U256, Bytes |
| `shell-crypto` | ML-DSA-65 primary (FIPS 204) & Dilithium3 legacy-compatible active path & SPHINCS+ fallback signing, multi-algorithm Signer/Verifier traits |
| `shell-core` | Block, Transaction (AA-native), Account, Receipt, EIP-1559 gas model |
| `shell-storage` | RocksDB backend, Merkle Patricia Trie, RLP serialization, state pruning, storage profiles |
| `shell-consensus` | PoA engine (default); optional wPoA extension: weight-based fork choice, BFT finality, slashing |
| `shell-pqvm` | PQVM execution adapter over revm for retained Cancun-style semantics, PQ precompiles, EIP-2930/4844 fields, system contracts |
| `shell-mempool` | Transaction pool with PQ validation, fee-priority ordering, Replace-by-Fee |
| `shell-network` | libp2p P2P: GossipSub, Kademlia DHT, NAT traversal, peer scoring, tx gossip |
| `shell-rpc` | JSON-RPC (HTTP + WebSocket), CORS, rate limiting, filters, subscriptions, debug/trace APIs |
| `shell-node` | Async node harness, block production, chain sync, health endpoint, Prometheus metrics |
| `shell-cli` | CLI binary: `run`, `init`, `key`, `tx`, `account`, TOML config, structured logging |
| `shell-genesis` | Genesis block initialization from config |
| `shell-keystore` | PQ keystore with argon2id + XChaCha20-Poly1305 encryption |
| `shell-stark-prover` | STARK proof generation and aggregation service (`crates/stark-prover/`) |

### Project Structure

```
shell-chain/
├── Cargo.toml           # Workspace root
├── crates/
│   ├── cli/             # CLI binary and TOML config
│   ├── consensus/       # Weighted PoA consensus engine and slashing
│   ├── core/            # Block, Transaction, Account
│   ├── crypto/          # Post-quantum cryptography
│   ├── pqvm/             # PQVM/revm execution adapter and precompiles
│   ├── genesis/         # Genesis configuration
│   ├── keystore/        # Encrypted key storage
│   ├── mempool/         # Transaction pool
│   ├── network/         # P2P networking
│   ├── node/            # Node harness
│   ├── primitives/      # Foundational types
│   ├── rpc/             # JSON-RPC server
│   └── storage/         # RocksDB storage
├── tests/e2e/           # End-to-end tests
├── fuzz/                # Fuzzing targets for serialization and protocols
├── docs/                # Documentation
├── CHANGELOG.md         # Release history
├── LICENSE              # MIT
└── README.md            # This file
```

## Post-Quantum Cryptography

| Algorithm | Type | Use Case | Status |
|-----------|------|----------|--------|
| **ML-DSA-65** (FIPS 204) | Lattice-based | Transaction signing (primary) | Deployed — NIST FIPS 204 |
| **Dilithium3** | Lattice-based | Transaction signing (legacy-compatible active path) | Deployed — NIST Round 3 reference |
| **SPHINCS+** (SLH-DSA) | Hash-based | High-security accounts (fallback) | Deployed — NIST Level 5 |
| **STARKs** | Hash-based proofs | Signature aggregation, storage compression | Deployed (optional, off by default in dev) |
| **Kyber / ML-KEM** (P2P) | KEM | Validator transport (future) | **Not yet deployed** — classical libp2p Noise/XX is current |

Addresses are derived as `BLAKE3(algo_id || pq_public_key)` — full 32 bytes,
displayed as `0x` + 64 lowercase hex chars.

For details, see [docs/PQ_CRYPTO_GUIDE.md](docs/PQ_CRYPTO_GUIDE.md).

## Documentation

- [Quick Start Guide](docs/QUICKSTART.md) — run your first node in minutes
- [Operator Guide](docs/TESTNET_OPERATOR_GUIDE.md) — production deployment with Docker and monitoring
- [API Reference](docs/JSON_RPC_API.md) — complete JSON-RPC API documentation
- [PQ Crypto Guide](docs/PQ_CRYPTO_GUIDE.md) — post-quantum cryptography details
- [Native Account Abstraction Guide](docs/ACCOUNT_ABSTRACTION_GUIDE.md) — 32-byte PQ addresses, validation layers, and AA rollout
- [Block Pruning & Compression](docs/BLOCK_PRUNING_AND_COMPRESSION.md) — storage profiles (archive/full/light), block body lifecycle, STARK compression
- [STARK Aggregation](docs/stark-aggregation.md) — STARK aggregate proof architecture and multi-layer settlement
- [Prover Guide](docs/PROVER_GUIDE.md) — running a dedicated prover node
- [Consensus Details](docs/CONSENSUS_DETAILS.md) — wPoA consensus engine internals
- [Changelog](CHANGELOG.md) — full release history

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) © ShellDAO
