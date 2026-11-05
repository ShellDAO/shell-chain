//! STARK batch-commitment proofs for PQ signature metadata.
//!
//! # Current proof statement
//!
//! The caller must verify PQ signatures natively before constructing
//! [`SigBatchEntry`] values. [`prove_sig_batch`] receives message/public-key
//! hashes, not raw signatures. Its AIR verifies dual hash-chain accumulator
//! constraints; it does not implement Dilithium3 or ML-DSA verification.
//! Full PQ signature verification inside the AIR remains a target, not a
//! capability supplied by this circuit.
//!
//! The caller derives each leaf as `BLAKE3(msg_hash || pk_hash)`. Its two
//! little-endian 128-bit halves feed independent f128 accumulators. Canonical
//! source binding requires checking the expected entries/root outside the AIR.
//!
//! # Circuit
//!
//! Four trace columns: `acc_lo`, `acc_hi`, `leaf_lo`, `leaf_hi`.
//! Two degree-three transitions:
//! ```text
//! acc_lo[t+1] = acc_lo[t]^3 + leaf_lo[t]
//! acc_hi[t+1] = acc_hi[t]^3 + leaf_hi[t]
//! ```
//! Both accumulators start at zero and end at the claimed root halves.
//! The root is the concatenation of those two little-endian halves (32 bytes).
//! Padding rows preserve both accumulators. Proof options use 28 queries,
//! blowup 8, grinding 16, and no field extension.
//!
//! Run `cargo run --locked -p shell-stark-prover --example batch-commitment`
//! for native signature checks, actual Winterfell proof generation, verification,
//! JSON roundtrip, and negative controls demonstrating the separate statements.

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
    L1StallDiagnosis, L2ProverTask, ProofBacklog, ProofTask, ProverTask,
    DEFAULT_MAX_L1_RANGE_SOURCES, DEFAULT_WATERMARK_THRESHOLD, MIN_L1_STARK_TXS,
};
pub use metadata::{
    proof_metadata_key, ProofLevel, ProofMetadata, PROOF_METADATA_KEY_PREFIX,
    PROOF_METADATA_VERSION,
};
pub use proof::{SigBatchProof, SIG_BATCH_PROOF_VERSION};
pub use prover::{compute_batch_root, prove_sig_batch, verify_sig_batch, SigBatchEntry};
pub use prover_health::{HealthStatus, ProverHealth, ProverHealthConfig};
pub use recursive_air::{
    compute_aggregate_root,
    get_recursive_prover,
    AggregationJob,
    // Boundary types
    RecursiveProof,
    RecursiveProver,
    RecursiveProverError,
    RecursivePublicInputs,
    RecursiveVerifierAir,
    ScaffoldRecursiveProver,
    REC_COL_ACC,
    REC_COL_ROOT,
    REC_TRACE_WIDTH,
};
pub use scheduler::{
    AggregationConfig, AggregationScheduler, AggregationTrigger, L1Gap, SettledL1Input,
    TriggerReason,
};
pub use state_machine::{BlockProofState, BlockStateMachine, InvalidTransition};

/// Current protocol version for [`SigBatchProof`] serialization.
pub const PROTOCOL_VERSION: u8 = 1;
