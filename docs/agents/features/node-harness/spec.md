# Feature: Node Harness

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

> Legacy header (preserved): ID `node-harness` · Priority P3 · Module `shell-chain/crates/node`

## 1. Purpose

`shell-node` is the assembly layer that wires all shell-chain crates (storage, crypto,
consensus, EVM, mempool, network, RPC, prover) into a single runnable node binary.
`NodeBuilder` constructs the node; `Node` runs the async event loop.

Also exports subsystems consumed by the CLI and integration tests:
`ProverService`, `ReorgEngine`, `HistoricalSync`, `Metrics`, `PruningConfig`,
`ReorgEngine`, and `validator_store`.

## 2. Public API Surface

```rust
// crates/node/src/lib.rs (re-exports)
pub use builder::NodeBuilder;
pub use config::{ConsensusEngineConfig, MetricsConfig, NodeConfig, NodeRole};
pub use error::NodeError;
pub use historical_sync::{PeerCapabilityTracker, SyncStatus};
pub use metrics::Metrics;
pub use node::Node;
pub use prover_service::{ProverConfig, ProverService, ProverServiceHandle, ProvingPriority};
pub use pruning::{PruningConfig, StateRootTracker, StorageProfile};
pub use reorg::{ReorgEngine, ReorgResult};
pub mod validator_store;

// NodeBuilder
pub struct NodeBuilder { config: NodeConfig }
impl NodeBuilder {
    pub fn new(config: NodeConfig) -> Self;
    pub async fn build(self) -> Result<Node, NodeError>;
}

// Node (NOT ShellNode — spec correction)
pub struct Node { /* assembled subsystems */ }
impl Node {
    pub async fn run(self) -> Result<(), NodeError>;  // blocks until shutdown
    pub async fn shutdown(&self);
}

// NodeRole
pub enum NodeRole {
    Validator,        // block production only (default)
    ValidatorProver,  // block production + background proving on idle slots
    Prover,           // standalone prover: sync + prove + broadcast, no block production
}

// L2StarkMode
pub enum L2StarkMode {
    Disabled,   // no L2 input indexing; default for testnet safety
    Scaffold,   // build L2 input index and observability, no actual proving
    Active,     // full recursive aggregation (future milestone)
}
```

### NodeConfig (key fields)

```rust
pub struct NodeConfig {
    pub data_dir: String,
    pub node_role: NodeRole,            // default: Validator
    pub l2_stark_mode: L2StarkMode,     // default: Disabled
    pub enable_stark_aggregation: bool, // enables ProverService when true
    pub parallel_evm: ParallelEvmConfig,// disabled by default
    pub consensus: ConsensusEngineConfig, // Poa(PoaConfig) | WPoa(WPoaConfig)
    pub network: NetworkConfig,
    pub mempool: MempoolConfig,
    pub rpc: RpcConfig,
    pub metrics: MetricsConfig,
    pub pruning: PruningConfig,
    pub max_idle_interval_ms: u64,
    pub state_cache_size_mb: usize,
    // ... additional fields
}
```

## 3. Implementation Map

| Component | File | Notes |
|-----------|------|-------|
| `NodeBuilder` | `crates/node/src/builder.rs` | Wires all subsystems; calls `NodeConfig::dev()` for dev defaults |
| `Node` (event loop) | `crates/node/src/node/` | Block production, mempool drain, P2P dispatch |
| `NodeConfig`, `NodeRole`, `L2StarkMode`, `MetricsConfig`, `ConsensusEngineConfig` | `crates/node/src/config.rs:1-300` | All configuration types; `NodeRole::from_role_str`, `L2StarkMode::from_str` |
| `ProverService`, `ProverConfig`, `ProverServiceHandle`, `ProvingPriority` | `crates/node/src/prover_service.rs:1-80` | Background STARK prover; drains `ProofBacklog`, calls `prove_sig_batch`, stores `ProofAmendment`, broadcasts P2P |
| `system_rewards` | `crates/node/src/node/system_rewards.rs` | `encode_system_extra`, `decode_system_extra`, `stark_reward_value`, `build_stark_reward_tx` |
| `ReorgEngine`, `ReorgResult` | `crates/node/src/reorg.rs` | Chain reorganization handling |
| `HistoricalSync`, `PeerCapabilityTracker`, `SyncStatus` | `crates/node/src/historical_sync.rs` | Block sync from peers on startup |
| `Metrics` | `crates/node/src/metrics.rs` | Prometheus counters and gauges |
| `MetricsConfig` | `crates/node/src/config.rs` | `enabled`, `listen_addr` (default `127.0.0.1:9090`) |
| `PruningConfig`, `StateRootTracker`, `StorageProfile` | `crates/node/src/pruning.rs` | `witness_retention`, `body_retention`, `StorageProfile` enum |
| `validator_store` | `crates/node/src/validator_store.rs` | Persistent validator signing-key management |
| `checkpoint` | `crates/node/src/checkpoint.rs` | Checkpoint anchoring for fast-sync |
| `NodeError` | `crates/node/src/error.rs` | Typed error variants |
| Public re-exports | `crates/node/src/lib.rs:1-27` | Full crate surface |

### NodeRole semantics

| Role | Block production | ProverService | ProverRegistry stake required |
|------|-----------------|---------------|-------------------------------|
| `Validator` | ✅ | ❌ | ❌ |
| `ValidatorProver` | ✅ | ✅ (idle slots) | ✅ |
| `Prover` | ❌ | ✅ (continuous) | ✅ |

Parsed from CLI string: `validator` / `validator-prover` / `prover`.

### L2StarkMode semantics

| Mode | L2 input index | Aggregation scheduler | Recursive proving |
|------|---------------|----------------------|-------------------|
| `Disabled` | ❌ | ❌ | ❌ |
| `Scaffold` | ✅ | ✅ (observability) | ❌ |
| `Active` | ✅ | ✅ | ✅ (future) |

Default: `Disabled`. Set `Scaffold` to activate observability without proof work.

### ProverService

Background `tokio::spawn`-ed service that:
1. Continuously drains `ProofBacklog` from `shell-stark-prover`.
2. Calls `prove_sig_batch` for each `ProofTask`/`L2ProverTask`.
3. Stores the resulting `ProofAmendment` in `ChainStore` (via `ProofAmendmentStore`).
4. Broadcasts `NetworkMessage::ProofAmendment` via P2P.
5. Checks `L2StarkMode` before queuing L2 aggregation tasks.

Shutdown: `ProverServiceHandle` holds a `watch::Sender<bool>`; sending `true` stops the loop.

### system_rewards

`crates/node/src/node/system_rewards.rs` provides:
- `encode_system_extra(amendments)` — serializes `ProofAmendment` list into block `extra_data`.
- `decode_system_extra(extra_data)` — deserializes from `extra_data`.
- `stark_reward_value(block_number, amendment)` — computes STARK mint value for a proof.
- `build_stark_reward_tx(...)` — constructs `SystemTransaction::stark_reward(...)` for block inclusion.

STARK reward transactions are deterministic system transactions injected by the proposer.

### Metrics / Prometheus

`Metrics` struct exposes counters and gauges registered with a Prometheus `Registry`.
`MetricsConfig` default: `enabled=true`, `listen_addr=127.0.0.1:9090`.
NodeBuilder spawns an HTTP server at `metrics.listen_addr` serving `/metrics`.

### PruningConfig / StorageProfile

```rust
pub enum StorageProfile { Archive, Full, Light }
pub struct PruningConfig {
    pub witness_retention: u64,         // 0 = archive (keep forever)
    pub body_retention: u64,
    pub proof_replacement_grace: u64,   // u64::MAX = archive mode
    pub keep_recent_state_roots: u64,
}
```

`WitnessPruner` in `shell-storage` reads `witness_retention`; enabled when
`enable_stark_aggregation = true`.

### HistoricalSync

`HistoricalSync` syncs block history from peers on startup using `GetHeaders`/`GetBodies`
P2P request-response messages. `PeerCapabilityTracker` tracks which peers have advertised
historical-sync capability. `SyncStatus` (distinct from the RPC type) tracks sync progress.

### validator_store

`crates/node/src/validator_store.rs` — persistent storage for the validator's PQ signing key.
Keys are loaded from the keystore (via `shell-keystore`) and held in memory for block signing.

## 4. Invariants

- **INV-NODE-1**: A `Prover`-role node MUST NOT produce blocks (`is_validator() == false`).
  Cross-ref: CONSTITUTION §NodeRoles.
- **INV-NODE-2**: `ProverService` MUST NOT start when `node_role == NodeRole::Validator` AND
  `enable_stark_aggregation == false`.
- **INV-NODE-3**: STARK reward transactions (`build_stark_reward_tx`) are deterministic; all
  validators MUST compute the same reward value for the same amendment.
  Cross-ref: CONSTITUTION §Determinism.
- **INV-NODE-4**: `L2StarkMode::Active` is a future milestone — enabling it in production before
  the recursive prover is certified is prohibited. Default MUST remain `Disabled`.
- **INV-NODE-5**: `NodeBuilder::build()` MUST validate that the consensus engine config matches
  the genesis config before starting the event loop.

## 5. Tests

Tests live in `crates/node/src/` (inline `#[cfg(test)]`) and `shell-chain/tests/`.

Key test cases:
- `NodeRole::default()` is `Validator`.
- `NodeRole::from_str("validator-prover")` parses correctly; unknown role returns error.
- `L2StarkMode::default()` is `Disabled`.
- `L2StarkMode::from_str("scaffold")` parses; `is_enabled()` and `is_active()` correct.
- `MetricsConfig::default()` has `listen_addr = 127.0.0.1:9090`.
- `NodeConfig::dev(address)` builds a valid config for local dev.
- `ProverService`: enqueues a task, proof is stored, broadcast triggered.
- `ReorgEngine`: detects fork and returns `ReorgResult` with replaced blocks.
- `system_rewards::encode_system_extra` / `decode_system_extra` round-trip.

Run: `cargo test -p shell-node -- --nocapture`

## 6. Related ADRs

- `../adrs/ADR-002-stark-tx-level-settlement.md` — ProverService, STARK reward, system_rewards
- (historical AA design — superseded by `features/account-abstraction/spec.md`) — AaBundle ingress in node event loop
- CONSTITUTION §NodeRoles — NodeRole invariants
- CONSTITUTION §Determinism — system reward determinism requirement
- `workspace/ops/shell-chain-testnet/DEPLOYMENT-RUNBOOK.md` — testnet node configuration

## 7. Known Limitations / Open Work

- `L2StarkMode::Active` is scaffolded but the recursive prover is not yet certified for production.
- `HistoricalSync` does not yet implement checksum verification during peer sync (planned).
- `validator_store` does not yet support hardware security module (HSM) key storage.
- `ParallelEvmConfig` integration in the event loop is present but disabled by default;
  promotion criteria not yet defined.
- `checkpoint.rs` checkpoint anchoring is not yet connected to a light client verification protocol.
- Metrics labels for per-peer bandwidth (`BandwidthTracker`) are not yet wired into Prometheus.

## 8. Change Log

| Version | Change |
|---------|--------|
| v0.22.2 | Spec rewritten from draft; corrected `Node` type name (was `ShellNode`); added ProverService, NodeRole, L2StarkMode 3-mode, ReorgEngine, HistoricalSync, Metrics/Prometheus, system_rewards, PruningConfig, validator_store |
| M9 | Added ProverService, STARK reward system, L2StarkMode scaffold |
| M2 | Initial draft spec |
