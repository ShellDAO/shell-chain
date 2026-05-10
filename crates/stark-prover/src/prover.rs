//! STARK prover and verifier for the signature batch commitment circuit.
//!
//! # Entry points
//!
//! - [`prove_sig_batch`]: build trace from entries, generate STARK proof.
//! - [`verify_sig_batch`]: verify a [`SigBatchProof`] against claimed public inputs.

use winterfell::verify;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField},
    matrix::ColMatrix,
    AcceptableOptions, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, FieldExtension,
    PartitionOptions, ProofOptions, Prover, StarkDomain, TracePolyTable, TraceTable,
};

use crate::{
    air::{SigBatchAir, SigBatchPublicInputs, COL_ACC, COL_ENTRY, TRACE_WIDTH},
    proof::SigBatchProof,
};

// ── SigBatchEntry ─────────────────────────────────────────────────────────────

/// One entry in the signature batch — derived from a verified signature.
///
/// The entry value is computed by XOR-folding the first 16 bytes of
/// `msg_hash` and `pk_hash`, then interpreting the result as a little-endian
/// `u128` field element.
#[derive(Debug, Clone)]
pub struct SigBatchEntry {
    /// First 32 bytes of the message hash (e.g. SHA3-256 of message bytes).
    pub msg_hash: [u8; 32],
    /// First 32 bytes of the public key hash (e.g. SHA3-256 of serialised pubkey).
    pub pk_hash: [u8; 32],
}

impl SigBatchEntry {
    /// Derive the field element entry value for this signature.
    pub fn to_field_element(&self) -> BaseElement {
        let mut bytes = [0u8; 16];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = self.msg_hash[i] ^ self.pk_hash[i];
        }
        BaseElement::new(u128::from_le_bytes(bytes))
    }
}

// ── ProofOptions ─────────────────────────────────────────────────────────────

/// Default [`ProofOptions`] for the signature batch commitment circuit.
///
/// Tuned for fast verification (~50 µs) with ~100-bit conjectured security.
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        28,                   // number of queries
        8,                    // blowup factor
        16,                   // grinding factor
        FieldExtension::None, // f128 is large enough
        8,
        255,
        BatchingMethod::Linear, // constraint composition batching
        BatchingMethod::Linear, // DEEP polynomial batching
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the execution trace for the hash-chain accumulator circuit.
///
/// Returns `(trace, batch_root)`.
pub fn build_trace(entries: &[SigBatchEntry]) -> (TraceTable<BaseElement>, BaseElement) {
    assert!(!entries.is_empty(), "batch must have at least one entry");

    // Minimum trace length is 8 rows (Winterfell requirement); round up to
    // next power of two.
    //
    // IMPORTANT: we always add +1 before rounding so there is **at least one
    // padding row**.  The boundary assertion checks `acc[trace_len - 1] ==
    // batch_root`, which is only true if the last row is a stable padding row
    // where `acc` has already been updated by all real entries.  If
    // `trace_len == n_entries` exactly (no padding), the last row would hold
    // the intermediate accumulator before the final entry is applied — causing
    // `InconsistentOodConstraintEvaluations` during verification.
    let trace_len = ((entries.len() + 1).max(8)).next_power_of_two();

    // Pre-compute all accumulator values and entry values.
    let mut acc = BaseElement::ZERO;
    let mut accs: Vec<BaseElement> = Vec::with_capacity(trace_len);
    let mut entry_vals: Vec<BaseElement> = Vec::with_capacity(trace_len);

    for entry in entries.iter() {
        let fe = entry.to_field_element();
        accs.push(acc);
        entry_vals.push(fe);
        acc = acc.exp(3u32.into()) + fe;
    }

    // Padding rows: keep acc stable by choosing entry = acc - acc^3.
    // This satisfies the transition: acc^3 + (acc - acc^3) = acc. ✓
    for _ in entries.len()..trace_len {
        let padding_entry = acc - acc.exp(3u32.into());
        accs.push(acc);
        entry_vals.push(padding_entry);
    }

    let batch_root = acc;

    // Fill the Winterfell TraceTable.
    let accs_clone = accs.clone();
    let evs_clone = entry_vals.clone();
    let mut trace = TraceTable::new(TRACE_WIDTH, trace_len);
    trace.fill(
        |state| {
            state[COL_ACC] = accs_clone[0];
            state[COL_ENTRY] = evs_clone[0];
        },
        |step, state| {
            let next = step + 1;
            if next < trace_len {
                state[COL_ACC] = accs[next];
                state[COL_ENTRY] = entry_vals[next];
            }
        },
    );

    (trace, batch_root)
}

// ── Winterfell Prover impl ────────────────────────────────────────────────────

type SigHasher = Blake3_256<BaseElement>;
type SigVC = MerkleTree<SigHasher>;
type SigCoin = DefaultRandomCoin<SigHasher>;

struct SigBatchProverImpl {
    options: ProofOptions,
    pub_inputs: SigBatchPublicInputs,
}

impl SigBatchProverImpl {
    fn new(options: ProofOptions, pub_inputs: SigBatchPublicInputs) -> Self {
        Self {
            options,
            pub_inputs,
        }
    }
}

impl Prover for SigBatchProverImpl {
    type BaseField = BaseElement;
    type Air = SigBatchAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = SigHasher;
    type VC = SigVC;
    type RandomCoin = SigCoin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, SigHasher, SigVC>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, SigHasher, SigVC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, SigBatchAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SigBatchPublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &winterfell::TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winterfell::AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Recompute the batch root for a slice of entries without building the full
/// Winterfell execution trace.
///
/// Uses the same degree-3 accumulator as [`build_trace`]:
/// `acc[t+1] = acc[t]^3 + entry[t]`, starting from `acc = 0`.
///
/// Returns 16 little-endian bytes of the final field element (identical to
/// [`SigBatchProof::batch_root_bytes`]).  For an empty slice the result is
/// all-zero bytes (BaseElement::ZERO).
///
/// Callers can compare the returned bytes against `proof.batch_root_bytes` to
/// verify that a proof covers exactly the canonical entries they expect.
pub fn compute_batch_root(entries: &[SigBatchEntry]) -> [u8; 16] {
    let mut acc = BaseElement::ZERO;
    for entry in entries {
        acc = acc.exp(3u32.into()) + entry.to_field_element();
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&acc.as_int().to_le_bytes());
    bytes
}


///
/// The caller is responsible for verifying all Dilithium3 signatures natively
/// before calling this function.  The STARK proves only that the hash-chain
/// accumulator was correctly computed over the entries.
///
/// # Errors
/// Returns `Err(String)` if the Winterfell prover fails.
pub fn prove_sig_batch(entries: &[SigBatchEntry]) -> Result<SigBatchProof, String> {
    if entries.is_empty() {
        return Err("cannot prove empty batch".to_string());
    }
    let n_sigs = entries.len();
    let options = default_proof_options();
    let (trace, batch_root) = build_trace(entries);
    let batch_root_u128 = batch_root.as_int();
    let mut batch_root_bytes = [0u8; 16];
    batch_root_bytes.copy_from_slice(&batch_root_u128.to_le_bytes());
    let pub_inputs = SigBatchPublicInputs { batch_root, n_sigs };
    let prover = SigBatchProverImpl::new(options, pub_inputs);
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("prove_sig_batch failed: {:?}", e))?;
    Ok(SigBatchProof::from_proof(proof, batch_root_bytes, n_sigs))
}

/// Verify a [`SigBatchProof`].
///
/// Reconstructs the public inputs from the proof's `batch_root_bytes` and
/// `n_sigs`, then runs the Winterfell verifier.
///
/// # Errors
/// Returns `Err(String)` if proof decoding or verification fails.
pub fn verify_sig_batch(sig_proof: &SigBatchProof) -> Result<(), String> {
    let inner = sig_proof.inner_proof()?;
    let batch_root_u128 = u128::from_le_bytes(sig_proof.batch_root_bytes);
    let batch_root = BaseElement::new(batch_root_u128);
    let pub_inputs = SigBatchPublicInputs {
        batch_root,
        n_sigs: sig_proof.n_sigs,
    };
    let acceptable = AcceptableOptions::OptionSet(vec![default_proof_options()]);
    verify::<SigBatchAir, SigHasher, SigCoin, SigVC>(inner, pub_inputs, &acceptable)
        .map_err(|e| format!("verify_sig_batch failed: {:?}", e))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(seed: u8) -> SigBatchEntry {
        SigBatchEntry {
            msg_hash: [seed; 32],
            pk_hash: [seed.wrapping_add(1); 32],
        }
    }

    #[test]
    fn prove_and_verify_single_sig() {
        let entries = vec![make_entry(1)];
        let proof = prove_sig_batch(&entries).expect("prove failed");
        assert_eq!(proof.n_sigs, 1);
        assert!(proof.size_bytes() > 0, "proof should have bytes");
        verify_sig_batch(&proof).expect("verify failed");
    }

    #[test]
    fn prove_and_verify_batch_of_4() {
        let entries: Vec<_> = (1u8..=4).map(make_entry).collect();
        let proof = prove_sig_batch(&entries).expect("prove failed");
        assert_eq!(proof.n_sigs, 4);
        verify_sig_batch(&proof).expect("verify failed");
    }

    #[test]
    fn prove_and_verify_batch_of_10() {
        let entries: Vec<_> = (0u8..10).map(make_entry).collect();
        let proof = prove_sig_batch(&entries).expect("prove failed");
        assert_eq!(proof.n_sigs, 10);
        verify_sig_batch(&proof).expect("verify failed");
    }

    #[test]
    fn tampered_batch_root_fails_verification() {
        let entries: Vec<_> = (0u8..4).map(make_entry).collect();
        let mut proof = prove_sig_batch(&entries).expect("prove failed");
        proof.batch_root_bytes[0] ^= 0xFF;
        let result = verify_sig_batch(&proof);
        assert!(result.is_err(), "tampered proof must fail verification");
    }

    #[test]
    fn proof_json_roundtrip() {
        let entries: Vec<_> = (0u8..4).map(make_entry).collect();
        let proof = prove_sig_batch(&entries).expect("prove failed");
        let json = proof.to_json().expect("serialize failed");
        let decoded = SigBatchProof::from_json(&json).expect("deserialize failed");
        assert_eq!(proof, decoded);
        verify_sig_batch(&decoded).expect("verify after roundtrip failed");
    }

    #[test]
    fn empty_batch_returns_error() {
        assert!(prove_sig_batch(&[]).is_err());
    }
}
