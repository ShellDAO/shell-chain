//! L2 Recursive Verifier AIR — scaffold for multi-block proof aggregation.
//!
//! # Design (Phase J2)
//!
//! The recursive verifier aggregates N Level-1 (`ProofLevel::Async`) STARK
//! proofs into a single Level-2 (`ProofLevel::Recursive`) proof covering a
//! range of blocks.  This enables "signature stripping" to proceed on a
//! per-epoch basis rather than per-block, dramatically compressing on-chain
//! proof data.
//!
//! ## Circuit Overview
//!
//! Each L1 proof produces a `batch_root: BaseElement` — a hash-chain
//! accumulator over the verified signatures in that block.  The L2 circuit
//! takes N such roots as public inputs and proves that:
//!
//! 1. Each input root was produced by a valid L1 STARK proof (verified
//!    natively in the recursive trace).
//! 2. A combined `aggregate_root` is computed by chaining all N roots through
//!    the same accumulator transition function as the L1 circuit.
//!
//! ## AIR Description (Scaffold)
//!
//! This is a **research-phase scaffold**.  The full recursive verifier requires
//! encoding a Winterfell proof verification inside a Winterfell trace, which
//! demands an in-field hash function (Rescue or Poseidon).  That work is
//! deferred until the prover infrastructure is stable.
//!
//! Current state:
//! - AIR skeleton compiles with placeholder transition constraints.
//! - Public inputs and trace format are defined.
//! - Proving is gated behind a `#[cfg(feature = "recursive")]` flag (unset by default).
//!
//! ## Trace Format
//!
//! | Column | Name | Description |
//! |--------|------|-------------|
//! | 0 | `acc` | Running aggregate accumulator |
//! | 1 | `l1_root` | Current L1 batch root (public input per row) |
//!
//! Trace length = N (number of L1 proofs being aggregated).
//!
//! ## Transition Constraint
//!
//! Same degree-3 accumulator as L1:
//! ```text
//! acc[t+1] = acc[t]^3 + l1_root[t]
//! ```
//!
//! ## Boundary Assertions
//!
//! - `acc[0] = 0`
//! - `acc[N-1] = aggregate_root`

use serde::{Deserialize, Serialize};

use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// ── Recursive Prover Boundary ─────────────────────────────────────────────────

/// Error type for the recursive prover boundary.
#[derive(Debug, thiserror::Error)]
pub enum RecursiveProverError {
    /// The recursive prover is not yet implemented.
    ///
    /// This is the only variant returned by [`ScaffoldRecursiveProver`].
    /// Real implementations will add `ProofFailed`, `InvalidInputs`, etc.
    #[error(
        "recursive prover not implemented (feature = \"recursive\" not enabled or stub active)"
    )]
    NotImplemented,

    /// The inputs were structurally invalid (wrong range, empty root list, …).
    #[error("invalid recursive prover inputs: {0}")]
    InvalidInputs(String),

    /// The proof was generated but verification failed.
    #[error("recursive proof verification failed: {0}")]
    VerificationFailed(String),
}

/// Opaque recursive (L2) STARK proof bytes.
///
/// The exact serialisation format is defined by the concrete [`RecursiveProver`]
/// implementation; callers must not inspect the bytes directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveProof {
    /// Serialised proof bytes (Winterfell proof when real impl is active).
    pub bytes: Vec<u8>,
    /// Aggregate root attested by this proof.
    pub aggregate_root: u128,
    /// First block covered (inclusive).
    pub start_block: u64,
    /// Last block covered (inclusive).
    pub end_block: u64,
    /// Number of L1 proofs aggregated.
    pub n_l1_proofs: usize,
}

/// Trait that a real recursive L2 prover must satisfy.
///
/// # Scaffold boundary
///
/// This trait exists to define the surface that testnet L2 proving needs.
/// [`ScaffoldRecursiveProver`] implements it by returning
/// [`RecursiveProverError::NotImplemented`] from every method.  The real
/// implementation (gated behind `feature = "recursive"`) will replace that.
///
/// **No code outside this module should produce a `RecursiveProof` without
/// going through an implementation of this trait.**
pub trait RecursiveProver: Send + Sync {
    /// Generate a recursive L2 proof that aggregates the given L1 proofs.
    ///
    /// `inputs.l1_roots` must be non-empty and ordered; `inputs.aggregate_root`
    /// must equal `compute_aggregate_root(&inputs.l1_roots)`.
    fn prove_aggregation(
        &self,
        inputs: &RecursivePublicInputs,
    ) -> Result<RecursiveProof, RecursiveProverError>;

    /// Verify a [`RecursiveProof`] against the expected public inputs.
    fn verify_aggregation(
        &self,
        proof: &RecursiveProof,
        inputs: &RecursivePublicInputs,
    ) -> Result<(), RecursiveProverError>;
}

/// Scaffold implementation of [`RecursiveProver`] that always returns
/// [`RecursiveProverError::NotImplemented`].
///
/// Used at runtime whenever `L2StarkMode` is not `Active` or the `recursive`
/// cargo feature is not enabled.
pub struct ScaffoldRecursiveProver;

impl RecursiveProver for ScaffoldRecursiveProver {
    fn prove_aggregation(
        &self,
        _inputs: &RecursivePublicInputs,
    ) -> Result<RecursiveProof, RecursiveProverError> {
        Err(RecursiveProverError::NotImplemented)
    }

    fn verify_aggregation(
        &self,
        _proof: &RecursiveProof,
        _inputs: &RecursivePublicInputs,
    ) -> Result<(), RecursiveProverError> {
        Err(RecursiveProverError::NotImplemented)
    }
}

/// Return the active [`RecursiveProver`] for the current build configuration.
///
/// - When `feature = "recursive"` is enabled: returns the real prover (once
///   implemented; currently still returns the scaffold).
/// - Otherwise: returns [`ScaffoldRecursiveProver`].
///
/// Callers should log the result and surface it in metrics when L2 is active.
pub fn get_recursive_prover() -> Box<dyn RecursiveProver> {
    #[cfg(feature = "recursive")]
    {
        // TODO: replace with the real implementation when available.
        tracing::warn!(
            "shell-stark-prover: feature `recursive` is enabled but real \
             recursive prover is not yet implemented — using scaffold"
        );
    }
    Box::new(ScaffoldRecursiveProver)
}

// ── Public Inputs ─────────────────────────────────────────────────────────────

/// Public inputs for the L2 recursive aggregation proof.
///
/// Contains the ordered list of L1 `batch_root` values and the expected
/// combined `aggregate_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePublicInputs {
    /// Ordered L1 batch roots, one per block being aggregated.
    pub l1_roots: Vec<u128>,
    /// Expected aggregate root — the final accumulator value.
    pub aggregate_root: u128,
    /// First block number in the aggregation range (inclusive).
    pub start_block: u64,
    /// Last block number in the aggregation range (inclusive).
    pub end_block: u64,
}

impl RecursivePublicInputs {
    /// Create public inputs from a slice of L1 batch roots.
    ///
    /// Computes `aggregate_root` by running the same accumulator function
    /// as the L1 circuit:  `acc[t+1] = acc[t]^3 + root[t]`.
    pub fn from_l1_roots(roots: &[u128], start_block: u64) -> Self {
        let aggregate_root = compute_aggregate_root(roots);
        Self {
            l1_roots: roots.to_vec(),
            aggregate_root,
            start_block,
            end_block: start_block + roots.len().saturating_sub(1) as u64,
        }
    }

    /// Number of L1 proofs being aggregated.
    pub fn n_proofs(&self) -> usize {
        self.l1_roots.len()
    }
}

impl ToElements<BaseElement> for RecursivePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elems = vec![
            BaseElement::new(self.aggregate_root),
            BaseElement::new(self.n_proofs() as u128),
            BaseElement::new(self.start_block as u128),
            BaseElement::new(self.end_block as u128),
        ];
        // Append each L1 root so the verifier can check inputs.
        for &root in &self.l1_roots {
            elems.push(BaseElement::new(root));
        }
        elems
    }
}

// ── Trace Column Indices ──────────────────────────────────────────────────────

/// Accumulator column index.
pub const REC_COL_ACC: usize = 0;
/// L1 root column index.
pub const REC_COL_ROOT: usize = 1;
/// Recursive verifier trace width.
pub const REC_TRACE_WIDTH: usize = 2;

// ── RecursiveVerifierAir ──────────────────────────────────────────────────────

/// AIR for the L2 recursive aggregation circuit.
///
/// ## Scaffold status
///
/// Transition constraints are structurally complete but the full recursive
/// proof-in-proof encoding is not yet implemented.  The accumulator
/// constraint is intentionally identical to the L1 AIR to validate the
/// aggregation math independently before adding the recursive verification
/// layer.
pub struct RecursiveVerifierAir {
    context: AirContext<BaseElement>,
    pub_inputs: RecursivePublicInputs,
}

impl Air for RecursiveVerifierAir {
    type BaseField = BaseElement;
    type PublicInputs = RecursivePublicInputs;

    fn new(
        trace_info: TraceInfo,
        pub_inputs: RecursivePublicInputs,
        options: ProofOptions,
    ) -> Self {
        assert_eq!(
            trace_info.width(),
            REC_TRACE_WIDTH,
            "recursive AIR requires 2-column trace"
        );
        let degrees = vec![TransitionConstraintDegree::new(3)];
        let context = AirContext::new(trace_info, degrees, 2, options);
        Self {
            context,
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let acc_curr = frame.current()[REC_COL_ACC];
        let root_curr = frame.current()[REC_COL_ROOT];
        let acc_next = frame.next()[REC_COL_ACC];

        // Constraint: acc[t+1] = acc[t]^3 + l1_root[t]
        result[0] = acc_next - (acc_curr.exp(3u32.into()) + root_curr);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(REC_COL_ACC, 0, BaseElement::ZERO),
            Assertion::single(
                REC_COL_ACC,
                last_step,
                BaseElement::new(self.pub_inputs.aggregate_root),
            ),
        ]
    }
}

// ── Aggregate Root Helper ─────────────────────────────────────────────────────

/// Compute the aggregate root from a slice of L1 batch roots.
///
/// Uses the same accumulator transition as the L1 circuit:
/// `acc[t+1] = acc[t]^3 + root[t]`
///
/// Returns 0 for an empty slice.
pub fn compute_aggregate_root(roots: &[u128]) -> u128 {
    // Work in the Winterfell f128 field to match the AIR.
    let mut acc = BaseElement::ZERO;
    for &root in roots {
        let entry = BaseElement::new(root);
        acc = acc.exp(3u32.into()) + entry;
    }
    acc.as_int()
}

// ── ProofLevel Mapping ────────────────────────────────────────────────────────

/// Metadata about a pending L2 aggregation job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationJob {
    /// Block range covered by this aggregation.
    pub start_block: u64,
    /// Last block (inclusive) in the range.
    pub end_block: u64,
    /// The L1 batch roots to aggregate (must all be present).
    pub l1_roots: Vec<u128>,
    /// Whether this job is ready to prove (all L1 proofs collected).
    pub ready: bool,
}

impl AggregationJob {
    /// Create a new aggregation job for the given block range.
    pub fn new(start_block: u64, end_block: u64) -> Self {
        Self {
            start_block,
            end_block,
            l1_roots: Vec::new(),
            ready: false,
        }
    }

    /// Push an L1 root for a block into this job.
    pub fn push_root(&mut self, root: u128) {
        self.l1_roots.push(root);
        let expected = (self.end_block - self.start_block + 1) as usize;
        self.ready = self.l1_roots.len() >= expected;
    }

    /// Number of blocks in this aggregation range.
    pub fn range_len(&self) -> usize {
        (self.end_block - self.start_block + 1) as usize
    }

    /// Build `RecursivePublicInputs` when the job is ready.
    pub fn build_inputs(&self) -> Option<RecursivePublicInputs> {
        if !self.ready {
            return None;
        }
        Some(RecursivePublicInputs::from_l1_roots(
            &self.l1_roots,
            self.start_block,
        ))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_aggregate_root_empty() {
        assert_eq!(compute_aggregate_root(&[]), 0);
    }

    #[test]
    fn compute_aggregate_root_single() {
        let root = 42u128;
        // acc = 0^3 + 42 = 42
        let expected = BaseElement::new(42).as_int();
        assert_eq!(compute_aggregate_root(&[root]), expected);
    }

    #[test]
    fn compute_aggregate_root_two_elements() {
        let r0 = 10u128;
        let r1 = 20u128;
        // step 0: acc = 0^3 + 10 = 10
        // step 1: acc = 10^3 + 20 = 1020
        let acc0 = BaseElement::new(r0);
        let acc1 = acc0.exp(3u32.into()) + BaseElement::new(r1);
        assert_eq!(compute_aggregate_root(&[r0, r1]), acc1.as_int());
    }

    #[test]
    fn compute_aggregate_root_deterministic() {
        let roots = [1u128, 2, 3, 4, 5];
        let a = compute_aggregate_root(&roots);
        let b = compute_aggregate_root(&roots);
        assert_eq!(a, b);
    }

    #[test]
    fn recursive_public_inputs_from_roots() {
        let roots = [100u128, 200, 300];
        let inputs = RecursivePublicInputs::from_l1_roots(&roots, 10);
        assert_eq!(inputs.start_block, 10);
        assert_eq!(inputs.end_block, 12);
        assert_eq!(inputs.n_proofs(), 3);
        assert_eq!(inputs.l1_roots, roots);
        assert_eq!(inputs.aggregate_root, compute_aggregate_root(&roots));
    }

    #[test]
    fn recursive_public_inputs_to_elements() {
        let roots = [1u128, 2];
        let inputs = RecursivePublicInputs::from_l1_roots(&roots, 0);
        let elems = inputs.to_elements();
        // aggregate_root, n_proofs, start_block, end_block, root[0], root[1]
        assert_eq!(elems.len(), 6);
        assert_eq!(elems[1].as_int(), 2); // n_proofs
        assert_eq!(elems[2].as_int(), 0); // start_block
        assert_eq!(elems[3].as_int(), 1); // end_block
    }

    #[test]
    fn aggregation_job_push_root_marks_ready() {
        let mut job = AggregationJob::new(5, 7); // 3 blocks
        assert!(!job.ready);
        job.push_root(10);
        assert!(!job.ready);
        job.push_root(20);
        assert!(!job.ready);
        job.push_root(30);
        assert!(job.ready);
    }

    #[test]
    fn aggregation_job_build_inputs_when_ready() {
        let mut job = AggregationJob::new(0, 1);
        job.push_root(100);
        assert!(job.build_inputs().is_none()); // not ready yet
        job.push_root(200);
        let inputs = job.build_inputs().expect("should be ready");
        assert_eq!(inputs.start_block, 0);
        assert_eq!(inputs.end_block, 1);
        assert_eq!(inputs.l1_roots, vec![100, 200]);
    }

    #[test]
    fn aggregation_job_range_len() {
        let job = AggregationJob::new(10, 19); // 10 blocks
        assert_eq!(job.range_len(), 10);
    }

    #[test]
    fn recursive_inputs_serde_roundtrip() {
        let roots = [1u128, 2, 3];
        let inputs = RecursivePublicInputs::from_l1_roots(&roots, 100);
        let json = serde_json::to_string(&inputs).unwrap();
        let decoded: RecursivePublicInputs = serde_json::from_str(&json).unwrap();
        assert_eq!(inputs, decoded);
    }
}
