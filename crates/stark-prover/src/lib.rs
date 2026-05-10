//! STARK-based aggregate proof for PQ (Dilithium3) signature batches.
//!
//! # Design (Phase C)
//!
//! Full Dilithium3 verification in a STARK AIR requires encoding NTT over
//! the Dilithium ring `Zq[x]/(x^256+1)` as arithmetic constraints — roughly
//! 50K–100K trace rows per single verify.  That's 20–120 s of proof time,
//! which is not viable for inline block production.
//!
//! Instead, **C2 implements a batch-commitment STARK**:
//!
//! 1. The prover verifies all Dilithium3 signatures **natively** (fast, ~5 ms
//!    per signature using the existing `shell-crypto` library).
//! 2. From each verified (msg_hash, pk_hash) pair the prover derives a
//!    **field element entry** and builds a **hash-chain accumulator** trace.
//! 3. A STARK proof attests that the accumulator was computed correctly over
//!    the `n_sigs` entries, producing a `batch_root`.
//! 4. The `batch_root` + proof are stored in the block header's
//!    `sig_aggregate_proof` field.  Validators re-verify the short STARK proof
//!    (~50 µs) instead of re-running all Dilithium3 verifications.
//!
//! ## AIR description
//!
//! Trace width: 2 columns
//! - `col0`: running accumulator `acc`
//! - `col1`: entry value for this step
//!
//! Transition constraint (degree 3, evaluated at each step except the last):
//! ```text
//! acc[t+1] = acc[t]^3 + entry[t]
//! ```
//!
//! Boundary assertions:
//! - `acc[0] = 0` (accumulator starts at zero)
//! - `acc[trace_len - 1] = batch_root` (final value matches claimed root)
//!
//! Proof options are tuned for fast verification: 28 queries, blowup 8,
//! grinding 16, no field extension.

pub mod air;
pub mod amendment;
pub mod availability;
pub mod backlog;
pub mod metadata;
pub mod proof;
pub mod prover;
pub mod prover_health;
pub mod recursive_air;
pub mod scheduler;
pub mod state_machine;

pub use amendment::{
    amendment_key, ProofAmendment, ProofPointer, ProofRange, StoredProofArtifact,
    AMENDMENT_KEY_PREFIX, PROOF_AMENDMENT_VERSION, PROOF_POINTER_VERSION,
};
pub use availability::{AvailabilityConfig, ProofAvailability, ProofAvailabilityTracker};
pub use backlog::{
    ProofBacklog, ProofTask, ProverTask, L2ProverTask, DEFAULT_MAX_L1_RANGE_SOURCES, DEFAULT_WATERMARK_THRESHOLD,
    MIN_L1_STARK_TXS,
};
pub use metadata::{
    proof_metadata_key, ProofLevel, ProofMetadata, PROOF_METADATA_KEY_PREFIX,
    PROOF_METADATA_VERSION,
};
pub use proof::{SigBatchProof, SIG_BATCH_PROOF_VERSION};
pub use prover::{compute_batch_root, prove_sig_batch, verify_sig_batch, SigBatchEntry};
pub use prover_health::{HealthStatus, ProverHealth, ProverHealthConfig};
pub use recursive_air::{
    compute_aggregate_root, AggregationJob, RecursivePublicInputs, RecursiveVerifierAir,
    REC_COL_ACC, REC_COL_ROOT, REC_TRACE_WIDTH,
};
pub use scheduler::{AggregationConfig, AggregationScheduler, AggregationTrigger, L1Gap, SettledL1Input, TriggerReason};
pub use state_machine::{BlockProofState, BlockStateMachine, InvalidTransition};

/// Current protocol version for [`SigBatchProof`] serialization.
pub const PROTOCOL_VERSION: u8 = 1;
