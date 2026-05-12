# Feature: EVM Executor

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

> Legacy header (preserved): ID `evm-executor` · Priority P1 · Module `shell-chain/crates/evm`

## 1. Purpose

Bridges the shell-chain storage layer (WorldState + ChainStore) with **revm** to execute
EVM-compatible smart contracts and plain transfers on a PQ-native chain.

Key design principles:
- **PQ-first**: `ecrecover` (0x01) is disabled — returns empty, no secp256k1 on-chain.
- All sender verification happens *before* EVM dispatch, using Dilithium3 / ML-DSA-65
  or custom `validation_code_hash` dispatch.
- Cancun EVM spec is supported (EIP-4844 blob fields in block headers, EIP-1559 fees).

## 2. Public API Surface

```rust
// crates/evm/src/lib.rs (re-exports)

pub use executor::{commit_evm_state, ExecutorError, ShellEvm, TxExecutionResult};
pub use aa_validation::{validate_aa_tx, AaValidationError, AaValidationOutcome, VALIDATION_GAS_CAP};
pub use parallel::{
    ConflictMetric, ConflictReason, ExecutionWave, ParallelEvmConfig, ParallelExecutionPlan,
    ParallelScheduler, TxConflict, TxConflictGraph,
};
pub use precompiles::{ShellPrecompiles, PQ_DILITHIUM_VERIFY_GAS};
pub use rwset::{HeuristicRwSetExtractor, ReadWriteSetExtractor, TxAccessPath, TxReadWriteSet};
pub use state_db::{ShellStateDb, StateDbError};
pub use system_contracts::{
    account_manager_address, encode_add_validator_calldata, encode_clear_validation_code_calldata,
    encode_remove_validator_calldata, encode_rotate_key_calldata,
    encode_set_validation_code_calldata, execute_system_contract, execute_system_contract_call,
    is_system_contract, registry_address, system_contract_code_hash,
    SystemContractEffects, SystemContractError, SystemContractOutcome,
    ACCOUNT_MANAGER_ADDR, SYSTEM_CALL_BASE_GAS, SYSTEM_CALL_OP_GAS, VALIDATOR_REGISTRY_ADDR,
};
pub use tracer::{decode_revert_reason, CallFrame, TraceResult};
pub use tx_validation::{
    compute_intrinsic_gas, validate_aa_bundle_structure, validate_tx, validate_tx_for_import,
    TxValidationError,
};
```

Core execution flow:
```rust
// ShellEvm wraps revm and implements the shell-chain Database bridge
pub struct ShellEvm<S: KvStore + 'static> { /* ... */ }

impl<S: KvStore + 'static> ShellEvm<S> {
    pub fn execute_tx(&mut self, tx: &SignedTransaction, block: &BlockHeader)
        -> Result<TxExecutionResult, ExecutorError>;
    pub fn execute_block(&mut self, block: &Block)
        -> Result<Vec<TxExecutionResult>, ExecutorError>;
}
pub fn commit_evm_state<S: KvStore>(
    world_state: &mut WorldState<S>,
    results: Vec<TxExecutionResult>,
) -> Result<ShellHash, ExecutorError>;
```

## 3. Implementation Map

| Component | File | Notes |
|-----------|------|-------|
| `ShellEvm`, `TxExecutionResult` | `crates/evm/src/executor.rs` | Main executor; revm v36 integration |
| `ShellStateDb` | `crates/evm/src/state_db.rs` | `revm::Database` bridge over `WorldState`+`ChainStore` |
| `ShellPrecompiles` | `crates/evm/src/precompiles.rs` | PQ_DILITHIUM_VERIFY at 0x0100; ecrecover 0x01 disabled |
| `ParallelScheduler`, `TxConflictGraph` | `crates/evm/src/parallel.rs` | Optimistic parallel EVM; `ExecutionWave`, `HeuristicRwSetExtractor` |
| `validate_tx`, `compute_intrinsic_gas` | `crates/evm/src/tx_validation.rs` | Pre-EVM PQ signature + nonce + balance checks |
| `validate_aa_tx`, `AaValidationOutcome` | `crates/evm/src/aa_validation.rs` | AA bundle validation; `VALIDATION_GAS_CAP` |
| `ACCOUNT_MANAGER_ADDR`, `VALIDATOR_REGISTRY_ADDR` | `crates/evm/src/system_contracts.rs` | System contracts; `execute_system_contract` |
| `bloom` | `crates/evm/src/bloom.rs` | Log bloom filter population |
| `CallFrame`, `TraceResult` | `crates/evm/src/tracer.rs` | EVM call tracing for `debug_traceTransaction` |
| `HeuristicRwSetExtractor`, `TxReadWriteSet` | `crates/evm/src/rwset.rs` | Read-write set extraction for parallel conflict detection |
| Public re-exports | `crates/evm/src/lib.rs:1-46` | Full crate surface |

### revm version
`revm` 36.x (Shanghai/Cancun spec), from workspace `Cargo.toml`.
`alloy-primitives` 1.5.x (required by revm v36).

### Cancun support
EIP-4844 blob fee fields (`max_fee_per_blob_gas`, `blob_versioned_hashes`) are present on
`Transaction`; `BlockHeader` carries `excess_blob_gas` and `blob_gas_used`. EVM Cancun spec
opcodes (`BLOBHASH`, `BLOBBASEFEE`, `TLOAD`, `TSTORE`, `MCOPY`) are enabled by default.

### System contracts
| Address | Contract | Purpose |
|---------|----------|---------|
| `ACCOUNT_MANAGER_ADDR` | `AccountManager` | `rotateKey`, `setValidationCode`, `clearValidationCode` |
| `VALIDATOR_REGISTRY_ADDR` | `ValidatorRegistry` | `addValidator`, `removeValidator` |

`is_system_contract(addr)` detects system call dispatch; `execute_system_contract` runs the
deterministic side-effects and returns `SystemContractEffects`.

### PQ Precompiles
| Address | Name | Gas |
|---------|------|-----|
| `0x0100` | `PQ_DILITHIUM_VERIFY` | `PQ_DILITHIUM_VERIFY_GAS` (benchmark-calibrated) |
| `0x01` (ecrecover) | *disabled* | returns empty output |

Precompiles `0x0101`–`0x0103` (SPHINCS+/STARK) are deferred; STARK settlement uses
`ProofAmendment` via `stark-prover` crate, not an EVM precompile.

### Witness-separated execution
When executing a `StrippedBlock`, the executor operates on block bodies without embedded
PQ signatures; signatures reside in a separate `WitnessBundle`. The `validate_tx_for_import`
variant skips signature re-verification and is used during historical sync.

### ParallelEVM
`ParallelScheduler` executes transactions in dependency-sorted `ExecutionWave`s using
optimistic concurrency. Controlled by `ParallelEvmConfig` in `NodeConfig`; disabled by
default until promoted in a future milestone.

## 4. Invariants

- **INV-EVM-1**: `ecrecover` (0x01) MUST always return empty — secp256k1 is quantum-unsafe.
  Cross-ref: CONSTITUTION §PQ-Crypto.
- **INV-EVM-2**: Every `SignedTransaction` entering `execute_tx` MUST pass `validate_tx` first.
  Nonce, balance, and PQ signature checks are pre-conditions; skipping them is a consensus
  bug (cross-ref: ADR node-event-loop).
- **INV-EVM-3**: First-time sender binding: `blake3(version ‖ algo_id ‖ pubkey)[0..20] == from`.
  Stable-path: `pq_pubkey_hash` from chain store. Both conditions MUST hold before accepting.
- **INV-EVM-4**: System contract calls (`ACCOUNT_MANAGER_ADDR`, `VALIDATOR_REGISTRY_ADDR`) MUST
  only update state via `SystemContractEffects`; no arbitrary EVM code executes.
- **INV-EVM-5**: `commit_evm_state` MUST be called once per block; partial commits are not allowed.

## 5. Tests

Tests live in `crates/evm/src/` (inline `#[cfg(test)]`) and `shell-chain/tests/`.

Key test cases:
- Plain ETH transfer: balance updated, state root changes.
- Smart contract deploy + call: return value correct, storage committed.
- PQ precompile `0x0100`: callable from Solidity via `staticcall`; valid sig returns `true`.
- ecrecover disabled: `0x01` call returns empty bytes.
- Gas exhaustion: transaction reverts, no state change.
- System contract `rotateKey`: `AccountManager` updates `pq_pubkey_hash`.
- `ParallelScheduler`: two non-conflicting transfers execute in the same wave.
- AA bundle validation: `validate_aa_tx` rejects bundles over `VALIDATION_GAS_CAP`.

Run: `cargo test -p shell-evm -- --nocapture`

## 6. Related ADRs

- (historical AA design — superseded by `features/account-abstraction/spec.md`) — Native AA model (M9)
- `../adrs/ADR-002-stark-tx-level-settlement.md` — STARK vs precompile decision
- CONSTITUTION §PQ-Crypto — ecrecover ban rationale
- CONSTITUTION §SystemContracts — system contract invariants

## 7. Known Limitations / Open Work

- `ParallelEVM` is disabled by default (`ParallelEvmConfig::enabled = false`); promotion criteria TBD.
- Precompiles `0x0101` (SPHINCS+), `0x0102` (Kyber), `0x0103` (STARK) not implemented;
  STARK settlement path goes through `ProofAmendment` instead.
- `VALIDATION_GAS_CAP` for AA validation is a conservative constant; dynamic calibration planned.
- `debug_traceTransaction` tracer (`CallFrame`) does not yet support `stateDiff` or `vmTrace` modes.

## 8. Change Log

| Version | Change |
|---------|--------|
| v0.22.2 | Spec rewritten from approved draft; added ParallelEVM, system contracts, witness-separated path, Cancun notes |
| M9 | AA Phase 2: `validate_aa_tx`, `AccountManager`, native AA bundle handling |
| M2 | Initial approved spec; revm v36 integration, PQ precompile 0x0100, ecrecover disabled |
