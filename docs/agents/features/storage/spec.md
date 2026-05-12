# Feature: Storage

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

Provides the full persistent storage stack for Shell-Chain: a typed KV-store
abstraction over RocksDB (with an in-memory backend for testing), Merkle
Patricia Trie world-state management, and a rich set of domain stores that
have grown well beyond the original "block + state + receipts" scope to include
witness bundles, STARK proof jobs, proof amendments, guardian recovery, and
state snapshots.

## 2. Public API surface

All items re-exported from `shell-chain/crates/storage/src/lib.rs:1-37`:

### KV-store abstraction

| Symbol | Kind | Notes |
|--------|------|-------|
| `KvStore` | trait | Single-namespace KV interface (`get`, `put`, `delete`, `flush`, `write_batch`, `contains`) |
| `WriteBatch` | struct | Ordered list of `WriteBatchOp`; atomically committed |
| `WriteBatchOp` | enum | `Put { key, value }` / `Delete { key }` |
| `MemoryDb` | struct | In-memory KvStore for tests |
| `StorageError` | enum | Unified error type |

**`KvStore` trait** (`kv_store.rs:52-60`):

```rust
pub trait KvStore: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;
    fn flush(&self) -> Result<(), StorageError>;
    fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError>;
    fn contains(&self, key: &[u8]) -> Result<bool, StorageError>;  // default impl
}
```

> **Note**: the trait is named `KvStore`, NOT `Database`. The spec draft was wrong.
> The trait operates on a single logical namespace (one CF per instance).

### RocksDB backend (feature `rocksdb`)

| Symbol | Notes |
|--------|-------|
| `RocksDbStore` | Single-CF RocksDB handle |
| `RocksDbStores` | Full set of all five CFs bundled together |
| `RocksDbConfig` | Open/tune options (`path`, `cache_size_mb`, `max_open_files`) |
| `RocksCompactionStyle` | Level / Universal / FIFO |
| `CfCompressionStrategy` | Per-CF compression choice |

### Column families (all five)

| Constant | CF name | Contents |
|----------|---------|----------|
| `CF_CHAIN` | `"chain"` | Block headers (`h/<hash>`), bodies (`b/<hash>`), canonical number→hash (`n/<number>`) |
| `CF_STATE` | `"state"` | MPT trie nodes for world state; keyed by node hash |
| `CF_RECEIPTS` | `"receipts"` | Transaction receipts indexed by tx hash |
| `CF_INDEX` | `"index"` | `tx_hash → (block_number, tx_index)` reverse index |
| `CF_WITNESS` | `"witness"` | `WitnessBundle` data keyed by block hash; prunable via `WitnessPruner` |

All five constants are exported from the `rocksdb` feature gate:
`storage/src/lib.rs:34-37`.

### Chain store (`chain_store.rs`)

`ChainStore<S: KvStore>` is the primary domain accessor. It also implements
`WitnessStore` and `L2JobStore`.

**Block access**:
- `put_block(&Block)` — writes header + body; updates canonical index
- `get_block_by_number(u64)` / `get_block_by_hash(&ShellHash)` → `Option<Block>`
- `get_header_by_number` / `get_header_by_hash`
- `get_canonical_hash(number: u64)` / `set_canonical_hash`

**WitnessStore trait** (implemented on `ChainStore`):
- `put_witness_bundle(block_hash: &ShellHash, bundle: &WitnessBundle)`
- `get_witness_bundle(block_hash: &ShellHash) -> Option<WitnessBundle>`

**L2JobStore trait** (implemented on `ChainStore`):
- `put_aggregation_job(job: &L2AggregationJob)`
- `get_aggregation_job(block_number: u64) -> Option<L2AggregationJob>`
- `update_job_status(block_number: u64, status: L2JobStatus)`

**ProofAmendmentStore trait** (implemented on `ChainStore`):
- `put_proof_amendment(block_hash: &ShellHash, amendment: &[u8])`
- `get_proof_amendment(block_hash: &ShellHash) -> Option<Vec<u8>>`

**Social recovery**:
- `put_guardian_config(account: &Address, config: &GuardianConfig)`
- `get_guardian_config(account: &Address) -> Option<GuardianConfig>`
- `put_recovery_proposal(account: &Address, proposal: &RecoveryProposal)`
- `get_recovery_proposal(account: &Address) -> Option<RecoveryProposal>`

**Block availability** (for proof replication):
- `set_block_availability(block_hash: &ShellHash, avail: BlockAvailability)`
- `get_block_availability(block_hash: &ShellHash) -> Option<BlockAvailability>`

**Chain config** (written once at genesis):
- `ChainConfig { chain_id: u64, genesis_hash: ShellHash }`
- `put_chain_config` / `get_chain_config`

### L2 job types

| Symbol | Notes |
|--------|-------|
| `L2AggregationJob` | Aggregation job record for one block: `block_number`, `block_hash`, `input_index`, `status`, timestamps |
| `L2InputIndex` | Identifies one input to the aggregation batch |
| `L2JobStatus` | `Pending` / `Proving` / `Proven` / `Failed` |

### Recovery / guardian types

| Symbol | Notes |
|--------|-------|
| `GuardianConfig` | `guardians: Vec<[u8; 20]>`, `threshold: u8`, `timelock: u64` |
| `RecoveryProposal` | Proposed new pubkey + votes + `maturity_block` |
| `MAX_GUARDIANS` | `5` |
| `MIN_RECOVERY_TIMELOCK` | `100` blocks |

### Pruners

| Symbol | File | Notes |
|--------|------|-------|
| `WitnessPruner` | `witness_pruner.rs` | Prunes `CF_WITNESS` entries older than `retention_count` blocks; `0` = archive mode |
| `DEFAULT_WITNESS_RETENTION` | `witness_pruner.rs` | `128` blocks |
| `WitnessPruneResult` | `witness_pruner.rs` | `pruned_count`, `not_found_count` |
| `BodyPruner` | `body_pruner.rs` | Prunes `b/<hash>` entries (block bodies) after `retention_count`; headers preserved |
| `DEFAULT_BODY_RETENTION` | `body_pruner.rs` | `512` blocks |
| `BodyPruneResult` | `body_pruner.rs` | `blocks_checked`, `bodies_pruned` |
| `StatePruner` | `state_pruner.rs` | Prunes stale MPT trie nodes |
| `PruneResult` | `state_pruner.rs` | Prune pass result |

**`WitnessPruner` and the STARK guard**: `retention_count = 0` is archive mode.
For nodes with `enable_stark_aggregation = true`, the retention must be kept high
enough that the STARK prover can still access witness bundles for in-progress proof
windows. Default 128 blocks provides comfortable headroom.

### Snapshot (fast sync)

| Symbol | Notes |
|--------|-------|
| `SnapshotWriter` | Exports world state at a given block to an append-only snapshot file |
| `SnapshotReader` | Reads and applies a snapshot file to bootstrap state |
| `SnapshotEntry` | `(key, value)` pair within the snapshot |
| `SnapshotMetadata` | Header: `block_number`, `state_root`, `timestamp`, `chain_id` |

### World state

| Symbol | Notes |
|--------|-------|
| `WorldState<S>` | Read/write account state over a `KvStore` + `MerkleTrie`; computes `state_root` |
| `account_manager_addr() -> Address` | Returns the deterministic `AccountManager` system contract address |
| `validator_registry_addr() -> Address` | Returns the deterministic `ValidatorRegistry` system contract address |

### Trie

| Symbol | Notes |
|--------|-------|
| `MerkleTrie` | Ethereum-compatible Merkle Patricia Trie implementation |
| `KvStoreTrieDb` | Adapts `KvStore` to the `eth_trie::DB` interface used by `MerkleTrie` |

### Storage key prefixes (in `chain_store.rs`)

Block data uses `h/<32-byte-hash>`, `b/<32-byte-hash>`, `n/<8-byte-LE-number>`.
Witness data uses a `ss/` prefix for social-recovery structures. Proof amendments
use a separate prefix constant.

## 3. Implementation map

| Concern | Module | File:Line |
|---------|--------|-----------|
| `KvStore` trait, `WriteBatch`, `WriteBatchOp` | `kv_store.rs` | `storage/src/kv_store.rs:1-80` |
| `MemoryDb` | `memory_db.rs` | `storage/src/memory_db.rs` |
| `RocksDbStore`, `RocksDbStores`, CF constants | `rocks_db.rs` | `storage/src/rocks_db.rs` (feature `rocksdb`) |
| `ChainStore`, `WitnessStore`, `L2JobStore`, `ProofAmendmentStore` | `chain_store.rs` | `storage/src/chain_store.rs:1-400` |
| `GuardianConfig`, `RecoveryProposal`, `L2AggregationJob`, `BlockAvailability` | `chain_store.rs` | `storage/src/chain_store.rs:20-90` |
| `WitnessPruner` | `witness_pruner.rs` | `storage/src/witness_pruner.rs:1-60` |
| `BodyPruner` | `body_pruner.rs` | `storage/src/body_pruner.rs:1-60` |
| `StatePruner` | `state_pruner.rs` | `storage/src/state_pruner.rs` |
| `SnapshotReader`, `SnapshotWriter` | `snapshot.rs` | `storage/src/snapshot.rs` |
| `WorldState`, system-contract address helpers | `world_state.rs` | `storage/src/world_state.rs` |
| `MerkleTrie` | `merkle_trie.rs` | `storage/src/merkle_trie.rs` |
| `KvStoreTrieDb` | `trie_adapter.rs` | `storage/src/trie_adapter.rs` |
| Public re-exports | `lib.rs` | `storage/src/lib.rs:1-37` |

## 4. Invariants (cross-ref CONSTITUTION & ADRs)

- **T-8 (Storage Profile Symmetry)**: Archive / full / light storage behavior is controlled by `PruningConfig` in node-harness (`witness_retention`, `body_retention`, `StorageProfile`). The three pruners (`WitnessPruner`, `BodyPruner`, `StatePruner`) are the only pruning mechanisms — no second code path.
- **CF_WITNESS is mandatory**: all nodes must open `CF_WITNESS` regardless of pruning mode. `WitnessPruner` with `retention_count = 0` acts as archive mode; it does not skip the CF.
- **Atomic writes**: all multi-key mutations must go through `WriteBatch` to maintain consistency between `CF_CHAIN`, `CF_INDEX`, and `CF_WITNESS`.
- **`KvStore` is not `Database`**: the spec draft used the wrong type name. The trait is `KvStore`; there is no `Database` trait in this crate.
- **Trie backend**: `MerkleTrie` uses a custom `KvStoreTrieDb` adapter — NOT a direct `alloy-trie` or `eth-trie` crate dependency. The MPT implementation is internal.
- **Social recovery data** (`GuardianConfig`, `RecoveryProposal`) is stored under the `ss/` prefix in `CF_CHAIN` (not a separate CF). This is an implementation detail; callers should use the `ChainStore` accessors.

## 5. Tests

```
cargo test -p shell-storage
cargo test -p shell-storage --features rocksdb
```

Key test areas:

| Concern | File |
|---------|------|
| `MemoryDb` KvStore round-trip | `memory_db.rs` |
| `ChainStore` block put/get | `chain_store.rs` |
| `WitnessStore` put/get witness bundle | `chain_store.rs` |
| `WitnessPruner` retention logic | `witness_pruner.rs` |
| `BodyPruner` retention and header preservation | `body_pruner.rs` |
| `MerkleTrie` insert/get/delete + state root | `merkle_trie.rs` |
| `WorldState` account read/write + root | `world_state.rs` |
| `SnapshotWriter` → `SnapshotReader` round-trip | `snapshot.rs` |

## 6. Related ADRs

- CONSTITUTION T-8 (Storage Profile Symmetry)
- `../adrs/ADR-007-witness-pruner-stark-guard.md` (witness separation → `CF_WITNESS` rationale)
- `../adrs/ADR-002-stark-tx-level-settlement.md` (ProofAmendment storage)

## 7. Known limitations / open work

- `ProofAmendmentStore` stores raw bytes; decoding to `ProofAmendment` is the caller's responsibility. A typed accessor would reduce coupling.
- `SnapshotReader` does not currently verify the `state_root` against the snapshot metadata after applying — callers must do a separate state-root check.
- RocksDB column family compaction tuning (`CfCompressionStrategy`) is not yet exposed through `NodeConfig`; defaults are used.
- `StatePruner` pruning is conservative; it does not yet implement the "safe pruning depth" guard that respects the STARK proof window.

## 8. Change log (this spec)

- v0.22.2 (2026-05): rewritten from M2 draft to production; `KvStore` trait corrected from `Database`; all five CF constants documented including `CF_WITNESS`; `WitnessPruner` + STARK guard documented; `BodyPruner`, `StatePruner`, `WitnessStore`, `L2JobStore`, `ProofAmendmentStore`, `GuardianConfig`, `RecoveryProposal`, `BlockAvailability`, `SnapshotReader`/`SnapshotWriter`, `account_manager_addr`/`validator_registry_addr` all added; storage key prefix scheme noted
