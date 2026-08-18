//! STARK prover and verifier for the signature batch commitment circuit.
//!
//! # Entry points
//!
//! - [`prove_sig_batch`]: build trace from entries, generate STARK proof.
//! - [`verify_sig_batch`]: verify a [`SigBatchProof`] against claimed public inputs.
//! - [`compute_batch_root`]: compute the 32-byte Merkle-accumulator root without proving.

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
    air::{
        SigBatchAir, SigBatchPublicInputs, COL_ACC_HI, COL_ACC_LO, COL_LEAF_HI, COL_LEAF_LO,
        TRACE_WIDTH,
    },
    proof::SigBatchProof,
};

// ── SigBatchEntry ─────────────────────────────────────────────────────────────

/// One entry in the signature batch — derived from a verified signature.
///
/// The entry leaf is `BLAKE3(msg_hash ‖ pk_hash)` — a 256-bit value with
/// full collision resistance per WP §STARK.  The leaf is split into two
/// 128-bit f128 field elements (`lo`, `hi`) for the dual-accumulator STARK.
#[derive(Debug, Clone)]
pub struct SigBatchEntry {
    /// First 32 bytes of the message hash (BLAKE3 of the transaction signing bytes).
    pub msg_hash: [u8; 32],
    /// First 32 bytes of the public key hash (BLAKE3 of the serialized pubkey).
    pub pk_hash: [u8; 32],
}

impl SigBatchEntry {
    /// Compute the 256-bit BLAKE3 leaf: `BLAKE3(msg_hash ‖ pk_hash)`.
    pub fn to_leaf_bytes(&self) -> [u8; 32] {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&self.msg_hash);
        input[32..].copy_from_slice(&self.pk_hash);
        *blake3::hash(&input).as_bytes()
    }

    /// Split the 32-byte BLAKE3 leaf into two f128 field elements (lo, hi).
    ///
    /// `lo = u128::from_le_bytes(leaf[0..16])`, `hi = u128::from_le_bytes(leaf[16..32])`.
    pub fn to_field_elements(&self) -> (BaseElement, BaseElement) {
        let leaf = self.to_leaf_bytes();
        let lo = u128::from_le_bytes(leaf[0..16].try_into().unwrap());
        let hi = u128::from_le_bytes(leaf[16..32].try_into().unwrap());
        (BaseElement::new(lo), BaseElement::new(hi))
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

/// Build the 4-column execution trace for the dual hash-chain accumulator circuit.
///
/// Returns `(trace, batch_root_lo, batch_root_hi)`.
///
/// Columns: `[acc_lo, acc_hi, leaf_lo, leaf_hi]`
/// Transitions: `acc_lo[t+1] = acc_lo[t]^3 + leaf_lo[t]`
///              `acc_hi[t+1] = acc_hi[t]^3 + leaf_hi[t]`
pub fn build_trace(
    entries: &[SigBatchEntry],
) -> (TraceTable<BaseElement>, BaseElement, BaseElement) {
    assert!(!entries.is_empty(), "batch must have at least one entry");

    // Minimum trace length is 8 rows (Winterfell requirement); always add +1
    // to ensure at least one stable padding row at the end.
    let trace_len = ((entries.len() + 1).max(8)).next_power_of_two();

    // Fill the Winterfell TraceTable directly so the four columns are not
    // allocated and duplicated before being copied into the table.
    let (first_lo, first_hi) = entries[0].to_field_elements();
    let mut trace = TraceTable::new(TRACE_WIDTH, trace_len);
    trace.fill(
        |state| {
            state[COL_LEAF_LO] = first_lo;
            state[COL_LEAF_HI] = first_hi;
        },
        |step, state| {
            let next = step + 1;
            let acc_lo = state[COL_ACC_LO].exp(3u32.into()) + state[COL_LEAF_LO];
            let acc_hi = state[COL_ACC_HI].exp(3u32.into()) + state[COL_LEAF_HI];
            state[COL_ACC_LO] = acc_lo;
            state[COL_ACC_HI] = acc_hi;
            let (leaf_lo, leaf_hi) = entries
                .get(next)
                .map(SigBatchEntry::to_field_elements)
                .unwrap_or_else(|| {
                    // Keep both accumulators stable throughout the padding rows.
                    (
                        acc_lo - acc_lo.exp(3u32.into()),
                        acc_hi - acc_hi.exp(3u32.into()),
                    )
                });
            state[COL_LEAF_LO] = leaf_lo;
            state[COL_LEAF_HI] = leaf_hi;
        },
    );

    let batch_root_lo = trace.get(COL_ACC_LO, trace_len - 1);
    let batch_root_hi = trace.get(COL_ACC_HI, trace_len - 1);
    (trace, batch_root_lo, batch_root_hi)
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

/// Compute the 32-byte batch root for a slice of entries without building
/// the full Winterfell execution trace.
///
/// Each entry produces a 256-bit BLAKE3 leaf `BLAKE3(msg_hash ‖ pk_hash)`.
/// The leaf is split into (lo, hi) f128 halves, which are accumulated via:
/// `acc_lo[t+1] = acc_lo[t]^3 + leaf_lo[t]`
/// `acc_hi[t+1] = acc_hi[t]^3 + leaf_hi[t]`
///
/// Returns the 32-byte root `acc_lo_final ‖ acc_hi_final` (16 LE bytes each).
/// For an empty slice the result is 32 zero bytes.
///
/// Callers can compare the returned bytes against `proof.batch_root_bytes` to
/// verify that a proof covers exactly the canonical entries they expect.
pub fn compute_batch_root(entries: &[SigBatchEntry]) -> [u8; 32] {
    let mut acc_lo = BaseElement::ZERO;
    let mut acc_hi = BaseElement::ZERO;
    for entry in entries {
        let (lo, hi) = entry.to_field_elements();
        acc_lo = acc_lo.exp(3u32.into()) + lo;
        acc_hi = acc_hi.exp(3u32.into()) + hi;
    }
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&acc_lo.as_int().to_le_bytes());
    bytes[16..32].copy_from_slice(&acc_hi.as_int().to_le_bytes());
    bytes
}

/// Generate a STARK proof for a slice of signature batch entries.
///
/// The caller is responsible for verifying all PQ signatures natively
/// before calling this function.  The STARK proves only that the dual
/// hash-chain accumulator was correctly computed over the BLAKE3 entries.
///
/// # Errors
/// Returns `Err(String)` if the Winterfell prover fails.
pub fn prove_sig_batch(entries: &[SigBatchEntry]) -> Result<SigBatchProof, String> {
    if entries.is_empty() {
        return Err("cannot prove empty batch".to_string());
    }
    let n_sigs = entries.len();
    let options = default_proof_options();
    let (trace, batch_root_lo, batch_root_hi) = build_trace(entries);
    let batch_root_bytes = root_to_bytes(batch_root_lo, batch_root_hi);
    let pub_inputs = SigBatchPublicInputs {
        batch_root_lo,
        batch_root_hi,
        n_sigs,
    };
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
/// Returns `Err(String)` if the proof is commitment-only (no STARK bytes),
/// or if proof decoding or verification fails.
pub fn verify_sig_batch(sig_proof: &SigBatchProof) -> Result<(), String> {
    if !sig_proof.has_proof() {
        // Commitment-only payloads carry no verifiable STARK proof bytes.
        return Err(
            "sig_aggregate_proof is commitment-only; full STARK proof not yet settled".to_string(),
        );
    }
    let inner = sig_proof.inner_proof()?;
    let (batch_root_lo, batch_root_hi) = bytes_to_root(&sig_proof.batch_root_bytes);
    let pub_inputs = SigBatchPublicInputs {
        batch_root_lo,
        batch_root_hi,
        n_sigs: sig_proof.n_sigs,
    };
    let acceptable = AcceptableOptions::OptionSet(vec![default_proof_options()]);
    verify::<SigBatchAir, SigHasher, SigCoin, SigVC>(inner, pub_inputs, &acceptable)
        .map_err(|e| format!("verify_sig_batch failed: {:?}", e))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn root_to_bytes(lo: BaseElement, hi: BaseElement) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&lo.as_int().to_le_bytes());
    bytes[16..32].copy_from_slice(&hi.as_int().to_le_bytes());
    bytes
}

fn bytes_to_root(bytes: &[u8; 32]) -> (BaseElement, BaseElement) {
    let lo = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
    let hi = u128::from_le_bytes(bytes[16..32].try_into().unwrap());
    (BaseElement::new(lo), BaseElement::new(hi))
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
        assert_eq!(proof.batch_root_bytes.len(), 32);
        assert!(proof.size_bytes() > 0, "proof should have bytes");
        assert!(proof.has_proof());
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

    #[test]
    fn compute_batch_root_matches_prove() {
        let entries: Vec<_> = (1u8..=4).map(make_entry).collect();
        let proof = prove_sig_batch(&entries).expect("prove failed");
        let root = compute_batch_root(&entries);
        assert_eq!(root, proof.batch_root_bytes);
    }

    #[test]
    fn commitment_only_is_not_verifiable() {
        let entries = vec![make_entry(1)];
        let root = compute_batch_root(&entries);
        let commitment = SigBatchProof::commitment_only(root, 1);
        assert!(!commitment.has_proof());
        let result = verify_sig_batch(&commitment);
        assert!(result.is_err());
    }

    #[test]
    fn leaf_bytes_differ_from_inputs() {
        // BLAKE3(msg ‖ pk) must differ from just XOR-folding the inputs.
        let e = make_entry(0xAB);
        let leaf = e.to_leaf_bytes();
        // The leaf should not be trivially zero or match a naive XOR of inputs.
        assert_ne!(leaf, [0u8; 32]);
        let mut xor_fold = [0u8; 32];
        for (i, b) in xor_fold.iter_mut().enumerate() {
            *b = e.msg_hash[i] ^ e.pk_hash[i];
        }
        assert_ne!(leaf, xor_fold, "BLAKE3 leaf must differ from raw XOR fold");
    }
}
