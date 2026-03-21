# Crate Structure & Module Boundaries

> Defines the workspace topology and dependency management for the `shell-chain` Rust implementation.

## 1. Design Principles
- **Stateless Verification First**: Data primitives must be physically isolated from the networking stack and consensus execution, enabling extremely low-dependency target compilation for light clients.
- **Protocol Mapping**: Module boundaries must strictly map to business domains defined in `specs/protocol/`.
- **Interface Anti-Corruption**: PQ cryptography library changes must not affect `shell-state` and `shell-mempool`. Isolation must be enforced via unified Traits.

## 2. Workspace Topology

```text
shell-chain/
├── crates/
│   ├── shell-primitives/  # Foundation: SSZ derivation, U256/H256, Block/Tx payload bindings
│   ├── shell-crypto/      # Crypto isolation: PQ signature wrappers (ML-DSA, etc.), SHA-256 bindings
│   ├── shell-state/       # State layer: Unified Binary Tree implementation
│   ├── shell-execution/   # Execution engine: EVM layer interaction, gas mechanics, transitions
│   ├── shell-mempool/     # Mempool: Tx buffering and admission rules based on Witness Separation
│   ├── shell-consensus/   # Consensus control: Envelope & Sidecar lifecycle management
│   ├── shell-network/     # P2P layer: Gossipsub, node discovery, Sidecar sync
│   └── shell-cli/         # CLI: Node orchestration, RPC servers
```

## 3. Cross-Module Contracts
- `shell-primitives` is the foundation. It is **strictly prohibited** for `primitives` to reverse-depend on `state` or `consensus`.
- `shell-mempool` depends only on `primitives` and `crypto`. It should never pull the complete `state` implementation directly, relying instead on `trait StateReader` for stateless verifications.
- Assembly of `ExecutionWitnessSidecar` happens after `shell-execution` completes, with pairing performed by `shell-consensus` before passing downward to `shell-network` for broadcast.

## 4. Critical Third-Party Dependencies
Driven by ADR-004 and ADR-005, the following third-party dependencies must be strictly controlled at the `Cargo.toml` workspace level:
- **SSZ**: `ssz_rs` (or equivalent Lighthouse/Ethereum macro), with extremely rigorous macro derivation restrictions.
- **Hashing**: Standardization on high-performance `sha2` (pure Rust or SIMD accelerated). All legacy `keccak` usage is heavily isolated (used exclusively inside smart contract evaluation boundaries).
- **PQ Signatures**: Cryptographic suites providing bindings that adhere to `shell-crypto` Traits.
