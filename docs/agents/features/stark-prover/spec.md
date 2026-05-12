# Feature: STARK Prover

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

`shell-stark-prover` implements the batch-commitment STARK pipeline for
Shell-Chain's post-quantum block-proof subsystem.  Its responsibilities are:

1. **Batch-commitment proving (L1)** — given all Dilithium3 signatures in a
   block, derive field-element entries via a hash-chain accumulator AIR,
   generate a short STARK proof (~50 µs to verify), and expose the
   `batch_root` committed into the block header's `sig_aggregate_proof` field.
2. **Async proof lifecycle management** — `ProofBacklog`, `ProofAmendment`,
   `AmendmentStore`, and `ProofAvailabilityTracker` decouple block production
   from proof generation and replication.
3. **Recursive aggregation scheduling (L2, scaffold)** — `AggregationScheduler`
   decides when enough settled canonical L1 proofs exist to trigger an L2
   recursive aggregation round; `RecursiveProver` (scaffold) will aggregate N
   L1 `batch_root` values into a single L2 `aggregate_root`.
4. **Block proof state machine (K2)** — tracks each block's proof status from
   `Sealed` → `Proving` → `Proven` → `Available` → `Stripped` /
   `ProofUnavailable`.
5. **Prover health monitoring (K3)** — `ProverHealth` reports `Healthy` /
   `Degraded` / `Overloaded` / `Failing` based on backlog depth and failure
   rate to drive graceful shedding of work.

The crate does **not** orchestrate drain-frontier logic (ADR-003); that lives
in `shell-node/src/prover_service.rs`.  It also does not perform Dilithium3
signature verification — that is delegated to `shell-crypto`.

## 2. Public API surface (with file:line)

All items re-exported from `shell-chain/crates/stark-prover/src/lib.rs`.

### Core AIR types (`air.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `SigBatchAir` | struct | Winterfell `Air` impl — hash-chain accumulator circuit |
| `SigBatchPublicInputs` | struct | `batch_root: BaseElement`, `n_sigs: usize` |
| `COL_ACC` | const | Trace column 0 — running accumulator |
| `COL_ENTRY` | const | Trace column 1 — per-step entry value |
| `TRACE_WIDTH` | const | `2` — number of trace columns |

Transition constraint: `acc[t+1] = acc[t]^3 + entry[t]` (degree 3).  
Boundary assertions: `acc[0] = 0`, `acc[last] = batch_root`.

### Prover functions (`prover.rs`)

| Symbol | Kind | File:Line |
|--------|------|-----------|
| `SigBatchEntry` | struct | `prover.rs:35-44` — `{msg_hash: [u8;32], pk_hash: [u8;32]}` |
| `SigBatchEntry::to_field_element` | fn | `prover.rs:47` — XOR-folds hashes into `BaseElement` |
| `prove_sig_batch` | fn | `prover.rs` — builds trace, generates `SigBatchProof` |
| `verify_sig_batch` | fn | `prover.rs` — verifies proof against public inputs |
| `compute_batch_root` | fn | `prover.rs` — pure accumulator; returns `batch_root` without full proof |
| `default_proof_options` | fn | `prover.rs:58` — 28 queries, blowup 8, grinding 16, no field extension |

### Proof artifact (`proof.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `SigBatchProof` | struct | Serialisable STARK proof wrapper; holds Winterfell `StarkProof` bytes + `batch_root` |
| `SIG_BATCH_PROOF_VERSION` | const | Protocol version for serialisation |

### Proof amendment (`amendment.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `ProofAmendment` | struct | Async proof attached to a sealed block; carries `proof: SigBatchProof`, prover `Address`, `prover_signature`, `layer`, `source_hashes`, settlement metadata |
| `ProofPointer` | struct | Lightweight pointer to a stored amendment (block hash → amendment key) |
| `ProofRange` | struct | Inclusive block range `[start_block, end_block]` covered by an amendment |
| `StoredProofArtifact` | struct | DB-stored amendment with metadata |
| `amendment_key` | fn | Derives RocksDB key for an amendment (`amend/<block_hash>`) |
| `AMENDMENT_KEY_PREFIX` | const | `"amend/"` |
| `PROOF_AMENDMENT_VERSION` | const | `1` |
| `PROOF_POINTER_VERSION` | const | `1` |

### Proof availability (`availability.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `AvailabilityConfig` | struct | `min_ack_count: usize` (default 2), `availability_timeout_blocks: u64` (default 200) |
| `ProofAvailability` | enum | `Pending` / `Available { ack_count }` / `Unavailable` |
| `ProofAvailabilityTracker` | struct | Tracks per-block proof replication; counts `ProofAck` messages from peers |

### Proof backlog (`backlog.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `ProofTask` | struct | One block of signature entries queued for async proving |
| `L2ProverTask` | struct | Recursive aggregation job dispatched to the prover service |
| `ProverTask` | enum | Discriminated union: `L1(ProofTask)` / `L2(L2ProverTask)` |
| `ProofBacklog` | struct | In-memory async queue; supports watermark, contiguous-range pop, drain-frontier |
| `DEFAULT_MAX_L1_RANGE_SOURCES` | const | Maximum L1 amendment hashes in one L2 job |
| `DEFAULT_WATERMARK_THRESHOLD` | const | Queue depth triggering backlog-pressure signals |
| `MIN_L1_STARK_TXS` | const | Minimum signature entries before a task is pop-eligible |

### Proof metadata (`metadata.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `ProofLevel` | enum | `Async` (L1 per-block) / `Recursive` (L2 aggregated) |
| `ProofMetadata` | struct | `{level, block_range, settled_at, prover}` stored alongside an amendment |
| `proof_metadata_key` | fn | Derives RocksDB key (`pmeta/<block_hash>`) |
| `PROOF_METADATA_KEY_PREFIX` | const | `"pmeta/"` |
| `PROOF_METADATA_VERSION` | const | Wire version |

### Recursive AIR scaffold (`recursive_air.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `RecursiveProverError` | enum | `NotImplemented` / `InvalidInputs` / `VerificationFailed` |
| `RecursiveProof` | struct | Opaque L2 proof bytes + `aggregate_root`, `start_block`, `end_block`, `n_l1_proofs` |
| `RecursivePublicInputs` | struct | Public inputs for the L2 AIR: list of L1 `batch_root` elements + `aggregate_root` |
| `RecursiveVerifierAir` | struct | Winterfell `Air` scaffold (placeholder constraints) |
| `AggregationJob` | struct | Job descriptor: `job_id: ShellHash`, source L1 hashes, block range |
| `RecursiveProver` | trait | `prove(job) -> Result<RecursiveProof, RecursiveProverError>` |
| `ScaffoldRecursiveProver` | struct | Always returns `RecursiveProverError::NotImplemented` |
| `get_recursive_prover` | fn | Factory; returns `ScaffoldRecursiveProver` (real impl gated by `recursive` feature) |
| `compute_aggregate_root` | fn | Pure accumulator over L1 `batch_root` values (no proof) |
| `REC_COL_ACC` | const | `0` |
| `REC_COL_ROOT` | const | `1` |
| `REC_TRACE_WIDTH` | const | `2` |

### Aggregation scheduler (`scheduler.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `SettledL1Input` | struct | One settled canonical L1 proof; `{start_block, end_block, batch_root, source_hash}` |
| `AggregationConfig` | struct | `epoch_length`, `min_l1_proofs_for_l2`, `trigger_block_interval`, `max_source_range` |
| `TriggerReason` | enum | `ProofThreshold` / `BlockInterval` / `EpochBoundary` / `RangeCap` |
| `AggregationTrigger` | struct | Emitted by `on_block`; carries `reason`, the accumulated job, and gap info |
| `L1Gap` | struct | Detected contiguity gap; blocks further ingestion until filled |
| `AggregationScheduler` | struct | Maintains contiguous L1 proof window; emits `AggregationTrigger` |

### Block proof state machine (`state_machine.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `BlockProofState` | enum | `Sealed` / `Proving { claimer }` / `Proven` / `Available` / `Stripped` / `ProofUnavailable` |
| `InvalidTransition` | struct | Error returned when a disallowed state transition is attempted |
| `BlockStateMachine` | struct | Per-block state store; `transition(hash, to)` validates and applies |

### Prover health (`prover_health.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `ProverHealthConfig` | struct | `warn_backlog_depth` (10), `overload_backlog_depth` (50), `failure_window` (20), `max_failure_rate` (0.5), `stale_after` (60s) |
| `HealthStatus` | enum | `Healthy` / `Degraded` / `Overloaded` / `Failing` |
| `ProverHealth` | struct | Records proof outcomes; `update(backlog_depth)` → `HealthStatus` |

### Crate constant

| Symbol | Value | Notes |
|--------|-------|-------|
| `PROTOCOL_VERSION` | `1` | `SigBatchProof` serialisation version |

## 3. Implementation map (table)

| Concern | Module | File |
|---------|--------|------|
| AIR definition — 2-column hash-chain accumulator | `air` | `stark-prover/src/air.rs` |
| Trace builder, prove/verify entry points | `prover` | `stark-prover/src/prover.rs` |
| `SigBatchProof` wire type | `proof` | `stark-prover/src/proof.rs` |
| Async proof amendment, amendment DB keys | `amendment` | `stark-prover/src/amendment.rs` |
| Peer proof replication / `ProofAck` tracking | `availability` | `stark-prover/src/availability.rs` |
| Async queue; watermark / contiguous pop | `backlog` | `stark-prover/src/backlog.rs` |
| Proof level + settled metadata | `metadata` | `stark-prover/src/metadata.rs` |
| L2 recursive AIR scaffold + job types | `recursive_air` | `stark-prover/src/recursive_air.rs` |
| Canonical L1→L2 trigger logic | `scheduler` | `stark-prover/src/scheduler.rs` |
| Per-block proof lifecycle FSM | `state_machine` | `stark-prover/src/state_machine.rs` |
| Backlog / failure rate health monitor | `prover_health` | `stark-prover/src/prover_health.rs` |

## 4. Invariants (cross-ref CONSTITUTION + ADRs)

- **ADR-002 (STARK settlement)**: `ProofAmendment` is the wire format for async
  proof propagation; final settlement on-chain uses a `StarkReward` system
  transaction that carries `proof_payload` bytes.  The crate provides the
  amendment type and serialisation; the node crate inserts the `StarkReward`
  tx.
- **ADR-003 (drain-frontier)**: The drain-frontier `Arc<AtomicU64>` counter that
  breaks the drain-reseed loop lives in `shell-node/src/prover_service.rs`, not
  here.  `ProofBacklog` exposes `drain_front(take)` which the service calls.
- **ADR-004 (L2StarkMode)**: `L2StarkMode::Active` gates recursive proving.
  `get_recursive_prover()` always returns `ScaffoldRecursiveProver` until the
  `recursive` Cargo feature is enabled and a concrete verifier is wired.
- **ADR-006 (block-0 frontier)**: Block 0 may seed the backlog with a synthetic
  `ProofTask`; `ProofBacklog` must accept tasks at block number 0 without
  panicking.
- **Contiguity invariant**: `AggregationScheduler` only accepts `SettledL1Input`
  entries whose `start_block == previous_end_block + 1`.  Any gap causes the
  scheduler to enter a blocked state and refuse to emit a trigger until the gap
  is closed.
- **Minimum entry threshold**: `ProofBacklog::pop_contiguous_with_min_entries`
  requires `MIN_L1_STARK_TXS` entries before returning a task, preventing
  spuriously small STARK proofs.

## 5. Tests

```
cargo test -p shell-stark-prover
```

Key tests (inline `#[cfg(test)]` blocks):

| Test | Module |
|------|--------|
| `prove_and_verify_single_sig` | `prover.rs` |
| `prove_and_verify_multi_sig` | `prover.rs` |
| `compute_batch_root_deterministic` | `prover.rs` |
| `to_field_element_deterministic` | `prover.rs` |
| `proof_serde_roundtrip` | `proof.rs` |
| `amendment_serde_roundtrip` | `amendment.rs` |
| `amendment_key_format` | `amendment.rs` |
| `availability_pending_then_available` | `availability.rs` |
| `availability_timeout_marks_unavailable` | `availability.rs` |
| `backlog_push_pop_ordering` | `backlog.rs` |
| `backlog_watermark_signal` | `backlog.rs` |
| `backlog_pop_contiguous_min_entries` | `backlog.rs` |
| `scheduler_proof_threshold_trigger` | `scheduler.rs` |
| `scheduler_gap_blocks_trigger` | `scheduler.rs` |
| `scheduler_epoch_boundary_trigger` | `scheduler.rs` |
| `state_machine_valid_transitions` | `state_machine.rs` |
| `state_machine_invalid_transition_error` | `state_machine.rs` |
| `health_healthy_to_degraded` | `prover_health.rs` |
| `health_overloaded_sheds_work` | `prover_health.rs` |
| `recursive_scaffold_returns_not_implemented` | `recursive_air.rs` |
| `compute_aggregate_root_deterministic` | `recursive_air.rs` |
| `metadata_serde_roundtrip` | `metadata.rs` |

## 6. Related ADRs

- **ADR-002** — STARK settlement via canonical `StarkReward` system transactions
- **ADR-003** — Drain-frontier `Arc<AtomicU64>` (in `shell-node`, not here)
- **ADR-004** — `L2StarkMode` configuration gates recursive proving
- **ADR-006** — Block-0 continuous STARK frontier seeding
- CONSTITUTION §10 (STARK proof layer design philosophy)

## 7. Known limitations / open work

- **Recursive prover is a scaffold** — `ScaffoldRecursiveProver` always returns
  `RecursiveProverError::NotImplemented`.  Full in-field recursive verification
  (Rescue/Poseidon hash inside a Winterfell trace) is deferred post-Phase J2.
- **No field extension** — the current AIR uses `f128` without an extension
  field.  This limits soundness for very large batches; upgrading to a quadratic
  extension is tracked as future work.
- `ProofAvailabilityTracker` does not verify proof content — it counts peer acks
  only.  Challenge/slash logic (I2) is implemented in the node crate.
- `ProofBacklog` is in-memory; a node restart drops all unproven tasks.
  Persistent backlog recovery is not yet implemented.
- `AggregationConfig::max_source_range = 0` disables the range-cap trigger;
  unbounded windows may arise if the other triggers are misconfigured.

## 8. Change log

- v0.22.2 (2026-05): spec written from source; all modules inventoried;
  scheduler contiguity invariant documented; recursive scaffold noted as
  Phase J2 gap
