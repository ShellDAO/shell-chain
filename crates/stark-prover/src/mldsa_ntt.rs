//! A complete forward ML-DSA NTT arithmetic proof (FIPS 204, Algorithm 41).
//!
//! The nine polynomial states are public. Sequence assertions bind every
//! butterfly's inputs, outputs and specified twiddle to those states. The AIR
//! checks modular arithmetic, canonical remainder/quotient ranges and carries.
//! This component does not prove signature decoding, SHAKE, norms or hints,
//! and is not accepted as a signature batch or settlement proof.

use serde::{Deserialize, Serialize};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    verify, AcceptableOptions, Air, AirContext, Assertion, CompositionPoly, CompositionPolyTrace,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

use crate::prover::default_proof_options;

pub const NTT_MODULUS: u32 = 8_380_417;
pub const NTT_DEGREE: usize = 256;
const STAGES: usize = 9;
const OPERATIONS: usize = 1024;
const TRACE_LENGTH: usize = OPERATIONS * 2;
const X: usize = 0;
const Y: usize = 1;
const ZETA: usize = 2;
const UPPER: usize = 3;
const LOWER: usize = 4;
const REMAINDER: usize = 5;
const QUOTIENT: usize = 6;
const ADD_CARRY: usize = 7;
const SUB_CARRY: usize = 8;
const BITS: usize = 9;
const RANGE_BITS: usize = 23;
const TRACE_WIDTH: usize = BITS + 4 * RANGE_BITS;
const CONSTRAINTS: usize = 5 + 4 * RANGE_BITS + 4;
const MAX_PROOF_BYTES: usize = 1_048_576;

/// Standalone component artifact, distinct from `SigBatchProof`.
/// Intermediate coefficients are public; this is not a zero-knowledge or
/// signature-compression representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NttProof {
    pub version: u8,
    pub stages: Vec<Vec<u32>>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone)]
struct Inputs(Vec<Vec<u32>>);

impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = vec![
            BaseElement::new(u64::from_le_bytes(*b"MLNTT001") as u128),
            BaseElement::new(NTT_MODULUS.into()),
            BaseElement::new(NTT_DEGREE as u128),
        ];
        elements.extend(self.0.iter().flatten().map(|&v| BaseElement::new(v.into())));
        elements
    }
}

#[derive(Clone, Copy)]
struct Butterfly {
    x: u32,
    y: u32,
    zeta: u32,
    upper: u32,
    lower: u32,
}

fn power(mut base: u64, mut exponent: u32) -> u32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % u64::from(NTT_MODULUS);
        }
        base = base * base % u64::from(NTT_MODULUS);
        exponent >>= 1;
    }
    result as u32
}

fn twiddle(index: u8) -> u32 {
    power(1753, index.reverse_bits().into())
}

fn validate_states(states: &[Vec<u32>]) -> Result<(), String> {
    if states.len() != STAGES
        || states.iter().any(|s| s.len() != NTT_DEGREE)
        || states.iter().flatten().any(|&v| v >= NTT_MODULUS)
    {
        return Err("NTT requires nine states of 256 canonical coefficients".into());
    }
    Ok(())
}

fn states(input: &[u32; NTT_DEGREE]) -> Result<Vec<Vec<u32>>, String> {
    if input.iter().any(|&v| v >= NTT_MODULUS) {
        return Err("NTT input coefficient is not canonical".into());
    }
    let mut states = vec![input.to_vec()];
    let mut len = NTT_DEGREE / 2;
    let mut index = 0;
    while len != 0 {
        let mut next = states.last().expect("initial state").clone();
        for start in (0..NTT_DEGREE).step_by(2 * len) {
            index += 1;
            let zeta = u64::from(twiddle(index));
            for j in start..start + len {
                let x = next[j];
                let t = (zeta * u64::from(next[j + len]) % u64::from(NTT_MODULUS)) as u32;
                next[j] = (x + t) % NTT_MODULUS;
                next[j + len] = (x + NTT_MODULUS - t) % NTT_MODULUS;
            }
        }
        states.push(next);
        len >>= 1;
    }
    Ok(states)
}

fn operations(states: &[Vec<u32>]) -> Vec<Butterfly> {
    let mut result = Vec::with_capacity(OPERATIONS);
    let mut len = NTT_DEGREE / 2;
    let mut index = 0;
    for stage in 0..STAGES - 1 {
        for start in (0..NTT_DEGREE).step_by(2 * len) {
            index += 1;
            let zeta = twiddle(index);
            for j in start..start + len {
                result.push(Butterfly {
                    x: states[stage][j],
                    y: states[stage][j + len],
                    zeta,
                    upper: states[stage + 1][j],
                    lower: states[stage + 1][j + len],
                });
            }
        }
        len >>= 1;
    }
    result
}

fn row(op: Butterfly) -> Vec<BaseElement> {
    let q = u64::from(NTT_MODULUS);
    let product = u64::from(op.zeta) * u64::from(op.y);
    let remainder = product % q;
    let quotient = product / q;
    let mut row = vec![BaseElement::ZERO; TRACE_WIDTH];
    for (column, value) in [
        (X, u64::from(op.x)),
        (Y, u64::from(op.y)),
        (ZETA, u64::from(op.zeta)),
        (UPPER, u64::from(op.upper)),
        (LOWER, u64::from(op.lower)),
        (REMAINDER, remainder),
        (QUOTIENT, quotient),
        (ADD_CARRY, (u64::from(op.x) + remainder) / q),
        (SUB_CARRY, (u64::from(op.x) + q - remainder) / q),
    ] {
        row[column] = BaseElement::new(value.into());
    }
    for (group, value) in [remainder, q - 1 - remainder, quotient, q - 1 - quotient]
        .into_iter()
        .enumerate()
    {
        for bit in 0..RANGE_BITS {
            row[BITS + group * RANGE_BITS + bit] = BaseElement::new(((value >> bit) & 1).into());
        }
    }
    row
}

struct NttAir {
    context: AirContext<BaseElement>,
    inputs: Inputs,
}

impl Air for NttAir {
    type BaseField = BaseElement;
    type PublicInputs = Inputs;

    fn new(info: TraceInfo, inputs: Inputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH));
        let mut degrees = vec![TransitionConstraintDegree::new(2)];
        degrees.extend((0..2).map(|_| TransitionConstraintDegree::new(1)));
        degrees.extend((0..2 + 4 * RANGE_BITS).map(|_| TransitionConstraintDegree::new(2)));
        degrees.extend((0..4).map(|_| TransitionConstraintDegree::new(1)));
        debug_assert_eq!(degrees.len(), CONSTRAINTS);
        Self {
            context: AirContext::new(info, degrees, 5, options),
            inputs,
        }
    }

    fn evaluate_transition<E: FieldElement + From<BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let r = frame.current();
        let q = E::from(BaseElement::new(NTT_MODULUS.into()));
        result[0] = r[ZETA] * r[Y] - r[REMAINDER] - q * r[QUOTIENT];
        result[1] = r[X] + r[REMAINDER] - r[UPPER] - q * r[ADD_CARRY];
        result[2] = r[X] + q - r[REMAINDER] - r[LOWER] - q * r[SUB_CARRY];
        result[3] = r[ADD_CARRY] * (r[ADD_CARRY] - E::ONE);
        result[4] = r[SUB_CARRY] * (r[SUB_CARRY] - E::ONE);
        let mut sums = [E::ZERO; 4];
        for (group, sum) in sums.iter_mut().enumerate() {
            let mut weight = E::ONE;
            for bit in 0..RANGE_BITS {
                let b = r[BITS + group * RANGE_BITS + bit];
                result[5 + group * RANGE_BITS + bit] = b * (b - E::ONE);
                *sum += b * weight;
                weight = weight + weight;
            }
        }
        let offset = 5 + 4 * RANGE_BITS;
        result[offset] = r[REMAINDER] - sums[0];
        result[offset + 1] = r[QUOTIENT] - sums[2];
        result[offset + 2] = sums[0] + sums[1] - (q - E::ONE);
        result[offset + 3] = sums[2] + sums[3] - (q - E::ONE);
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let ops = operations(&self.inputs.0);
        [X, Y, ZETA, UPPER, LOWER]
            .into_iter()
            .map(|column| {
                let values = ops
                    .iter()
                    .map(|op| {
                        BaseElement::new(
                            match column {
                                X => op.x,
                                Y => op.y,
                                ZETA => op.zeta,
                                UPPER => op.upper,
                                LOWER => op.lower,
                                _ => unreachable!(),
                            }
                            .into(),
                        )
                    })
                    .collect();
                // Every real operation is at an even row. The final operation
                // is at trace_length - 2 and is covered by transition checks.
                Assertion::sequence(column, 0, 2, values)
            })
            .collect()
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }
}

type Hasher = Blake3_256<BaseElement>;
type Commitment = MerkleTree<Hasher>;
type Coin = DefaultRandomCoin<Hasher>;

struct NttProver {
    inputs: Inputs,
    options: ProofOptions,
}

impl Prover for NttProver {
    type BaseField = BaseElement;
    type Air = NttAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, NttAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> Inputs {
        self.inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = BaseElement>>(
        &self,
        info: &TraceInfo,
        trace: &ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
        partitions: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(info, trace, domain, partitions)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a NttAir,
        random: Option<winterfell::AuxRandElements<E>>,
        coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, random, coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = BaseElement>>(
        &self,
        trace: CompositionPolyTrace<E>,
        columns: usize,
        domain: &StarkDomain<BaseElement>,
        partitions: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(trace, columns, domain, partitions)
    }
}

/// Prove every forward NTT butterfly for one canonical public polynomial.
pub fn prove_ntt(input: &[u32; NTT_DEGREE]) -> Result<NttProof, String> {
    let stages = states(input)?;
    let ops = operations(&stages);
    let rows: Vec<_> = ops.into_iter().map(row).collect();
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (i, values) in rows.iter().enumerate() {
        trace.update_row(2 * i, values);
        trace.update_row(2 * i + 1, values);
    }
    // No operation or boundary assertion uses the final odd row. Blind it
    // deterministically from the public statement so constant inputs do not
    // produce degenerate trace polynomials in Winterfell's degree checks.
    // The last real butterfly is at TRACE_LENGTH-2 and remains constrained.
    let mut padding = blake3::Hasher::new_derive_key("Shell-Chain ML-DSA NTT trace padding v1");
    for coefficient in stages.iter().flatten() {
        padding.update(&coefficient.to_le_bytes());
    }
    let mut bytes = [0u8; 16 * TRACE_WIDTH];
    padding.finalize_xof().fill(&mut bytes);
    let last: Vec<_> = bytes
        .chunks_exact(16)
        .map(|v| BaseElement::new(u128::from_le_bytes(v.try_into().expect("16-byte chunk"))))
        .collect();
    trace.update_row(TRACE_LENGTH - 1, &last);
    let prover = NttProver {
        inputs: Inputs(stages.clone()),
        options: default_proof_options(),
    };
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("NTT proving: {e:?}"))?;
    Ok(NttProof {
        version: 1,
        stages,
        proof_bytes: proof.to_bytes(),
    })
}

/// Verify the AIR and bind both endpoints supplied independently by the caller.
/// This verifier does not recompute the NTT in native code.
pub fn verify_ntt(
    proof: &NttProof,
    expected_input: &[u32; NTT_DEGREE],
    expected_output: &[u32; NTT_DEGREE],
) -> Result<(), String> {
    if proof.version != 1
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("unsupported or oversized NTT proof".into());
    }
    validate_states(&proof.stages)?;
    if proof.stages[0] != expected_input || proof.stages[STAGES - 1] != expected_output {
        return Err("NTT proof endpoints differ from the expected polynomial".into());
    }
    let inner = Proof::from_bytes(&proof.proof_bytes).map_err(|e| format!("NTT decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("unexpected NTT trace layout".into());
    }
    verify::<NttAir, Hasher, Coin, Commitment>(
        inner,
        Inputs(proof.stages.clone()),
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("NTT verification: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn input() -> [u32; NTT_DEGREE] {
        core::array::from_fn(|i| (i as u32 * 7919 + 19) % NTT_MODULUS)
    }

    // Direct polynomial evaluation, independent of the staged butterfly code.
    fn reference(input: &[u32; NTT_DEGREE]) -> [u32; NTT_DEGREE] {
        core::array::from_fn(|i| {
            let root = u64::from(power(1753, 2 * u32::from((i as u8).reverse_bits()) + 1));
            input.iter().rev().fold(0u64, |acc, &coefficient| {
                (acc * root + u64::from(coefficient)) % u64::from(NTT_MODULUS)
            }) as u32
        })
    }

    fn sample() -> &'static NttProof {
        static SAMPLE: OnceLock<NttProof> = OnceLock::new();
        SAMPLE.get_or_init(|| prove_ntt(&input()).unwrap())
    }

    #[test]
    fn all_ntt_outputs_match_independent_polynomial_evaluation() {
        for input in [input(), [0; NTT_DEGREE], [NTT_MODULUS - 1; NTT_DEGREE]] {
            let stages = states(&input).unwrap();
            assert_eq!(stages.last().unwrap(), &reference(&input));
            assert_eq!(operations(&stages).len(), OPERATIONS);
        }
        assert_eq!(twiddle(1), 4_808_194);
    }

    #[test]
    fn actual_ntt_proof_and_json_roundtrip_bind_independent_endpoints() {
        let proof = sample();
        assert!(!proof.proof_bytes.is_empty());
        verify_ntt(proof, &input(), &reference(&input())).unwrap();
        let bytes = serde_json::to_vec(proof).unwrap();
        let decoded: NttProof = serde_json::from_slice(&bytes).unwrap();
        verify_ntt(&decoded, &input(), &reference(&input())).unwrap();
    }

    #[test]
    fn zero_and_maximum_canonical_polynomials_have_real_proofs() {
        for input in [[0; NTT_DEGREE], [NTT_MODULUS - 1; NTT_DEGREE]] {
            let proof = prove_ntt(&input).unwrap();
            verify_ntt(&proof, &input, &reference(&input)).unwrap();
        }
    }

    #[test]
    fn changed_states_endpoints_and_payload_are_rejected() {
        let input = input();
        let output = reference(&input);
        let proof = sample();
        let mut changed = proof.clone();
        changed.stages[4][17] ^= 1;
        assert!(verify_ntt(&changed, &input, &output).is_err());
        let mut wrong_input = input;
        wrong_input[255] ^= 1;
        assert!(verify_ntt(proof, &wrong_input, &output).is_err());
        let mut wrong_output = output;
        wrong_output[255] ^= 1;
        assert!(verify_ntt(proof, &input, &wrong_output).is_err());
        let mut changed = proof.clone();
        changed.proof_bytes.truncate(changed.proof_bytes.len() / 2);
        assert!(verify_ntt(&changed, &input, &output).is_err());
        let mut changed = proof.clone();
        changed.stages[3][7] = NTT_MODULUS;
        assert!(verify_ntt(&changed, &input, &output).is_err());
        changed.stages.pop();
        assert!(verify_ntt(&changed, &input, &output).is_err());
        let mut changed = proof.clone();
        changed.version = 2;
        assert!(verify_ntt(&changed, &input, &output).is_err());
        let mut changed = proof.clone();
        changed.proof_bytes = crate::prove_sig_batch(&[crate::SigBatchEntry {
            msg_hash: [1; 32],
            pk_hash: [2; 32],
        }])
        .unwrap()
        .proof_bytes;
        assert!(verify_ntt(&changed, &input, &output)
            .unwrap_err()
            .contains("trace layout"));
    }

    fn residuals(row: &[BaseElement]) -> Vec<BaseElement> {
        let air = NttAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            Inputs(states(&input()).unwrap()),
            default_proof_options(),
        );
        let frame = EvaluationFrame::from_rows(row.to_vec(), row.to_vec());
        let mut result = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(&frame, &[], &mut result);
        result
    }

    fn encode_bits(row: &mut [BaseElement], group: usize, value: u32) {
        for bit in 0..RANGE_BITS {
            row[BITS + group * RANGE_BITS + bit] = BaseElement::new(((value >> bit) & 1).into());
        }
    }

    #[test]
    fn modular_quotient_range_and_carry_constraints_reject_field_escapes() {
        let op = Butterfly {
            x: 1,
            y: NTT_MODULUS - 1,
            zeta: NTT_MODULUS - 1,
            upper: 2,
            lower: 0,
        };
        let good = row(op);
        assert!(residuals(&good).iter().all(|v| *v == BaseElement::ZERO));

        // The three modular equations and carries can be satisfied with a
        // noncanonical remainder. Its 23-bit encoding fits, but the required
        // complement to q-1 is impossible. Range checks must reject this.
        let mut attack = good.clone();
        attack[REMAINDER] = BaseElement::new((NTT_MODULUS + 1).into());
        attack[QUOTIENT] = BaseElement::new((NTT_MODULUS - 3).into());
        attack[ADD_CARRY] = BaseElement::ONE;
        attack[SUB_CARRY] = BaseElement::ZERO;
        encode_bits(&mut attack, 0, NTT_MODULUS + 1);
        encode_bits(&mut attack, 1, 0);
        encode_bits(&mut attack, 2, NTT_MODULUS - 3);
        encode_bits(&mut attack, 3, 2);
        let rejected = residuals(&attack);
        assert!(rejected[..5].iter().all(|v| *v == BaseElement::ZERO));
        assert!(rejected.iter().any(|v| *v != BaseElement::ZERO));

        for column in [QUOTIENT, ADD_CARRY, SUB_CARRY, BITS, UPPER, LOWER] {
            let mut attack = good.clone();
            attack[column] += BaseElement::ONE;
            assert!(residuals(&attack).iter().any(|v| *v != BaseElement::ZERO));
        }
    }

    #[test]
    fn noncanonical_input_is_rejected_before_proving() {
        let mut input = input();
        input[0] = NTT_MODULUS;
        assert!(prove_ntt(&input).is_err());
    }
}
