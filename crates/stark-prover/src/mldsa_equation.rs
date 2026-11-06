//! Full ML-DSA-65 pointwise verification equation (FIPS 204 Algorithm 8).
//!
//! All six rows and 256 coordinates bind all five matrix products and the
//! subtractive challenge product. Public canonical operands are fixed boundary
//! assertions. Private bounded quotients prove the modular result; verification
//! does not calculate the native matrix equation. This is not a full signature.

use crate::{mldsa_ntt::NTT_MODULUS, prover::default_proof_options};
use serde::{Deserialize, Serialize};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    verify, AcceptableOptions, Air, AirContext, Assertion, CompositionPoly, CompositionPolyTrace,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

const ROWS: usize = 6;
const COLUMNS: usize = 5;
const N: usize = 256;
const OPERATIONS: usize = ROWS * N;
const SLOTS: usize = 2048;
const TRACE_LENGTH: usize = 2 * SLOTS;
const C: usize = 10;
const T: usize = 11;
const OUT: usize = 12;
const QUOTIENT: usize = 13;
const BITS: usize = 14;
const RANGE_BITS: usize = 26;
const QUOTIENT_MAX: u32 = 6 * NTT_MODULUS - 1;
const TRACE_WIDTH: usize = BITS + 2 * RANGE_BITS;
const CONSTRAINTS: usize = 1 + 2 * RANGE_BITS + 2;
const MAX_PROOF_BYTES: usize = 1_048_576;

/// Canonical ordinary residues. Matrix polynomials have exact row-major order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquationInputs {
    pub matrix_ntt: Vec<Vec<u32>>,
    pub z_ntt: Vec<Vec<u32>>,
    pub challenge_ntt: Vec<u32>,
    pub t1_scaled_ntt: Vec<Vec<u32>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquationProof {
    pub version: u8,
    pub inputs: EquationInputs,
    pub output: Vec<Vec<u32>>,
    pub proof_bytes: Vec<u8>,
}
#[derive(Clone)]
struct Statement {
    inputs: EquationInputs,
    output: Vec<Vec<u32>>,
}
impl ToElements<BaseElement> for Statement {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![
            BaseElement::new(u64::from_le_bytes(*b"MLEQ0001") as u128),
            BaseElement::new(NTT_MODULUS.into()),
        ];
        for values in [
            &self.inputs.matrix_ntt,
            &self.inputs.z_ntt,
            &self.inputs.t1_scaled_ntt,
            &self.output,
        ] {
            out.extend(values.iter().flatten().map(|&v| BaseElement::new(v.into())));
        }
        out.extend(
            self.inputs
                .challenge_ntt
                .iter()
                .map(|&v| BaseElement::new(v.into())),
        );
        out
    }
}
fn polynomials(values: &[Vec<u32>], count: usize) -> bool {
    values.len() == count
        && values
            .iter()
            .all(|p| p.len() == N && p.iter().all(|&v| v < NTT_MODULUS))
}
fn validate(inputs: &EquationInputs) -> Result<(), String> {
    if !polynomials(&inputs.matrix_ntt, ROWS * COLUMNS)
        || !polynomials(&inputs.z_ntt, COLUMNS)
        || !polynomials(&inputs.t1_scaled_ntt, ROWS)
        || inputs.challenge_ntt.len() != N
        || inputs.challenge_ntt.iter().any(|&v| v >= NTT_MODULUS)
    {
        return Err("equation requires canonical 6x5 matrix, five z, challenge and six scaled-t1 polynomials".into());
    }
    Ok(())
}
// Native equation constructs a witness only. The verifier never invokes it.
fn calculate(inputs: &EquationInputs) -> Vec<Vec<u32>> {
    let q = u64::from(NTT_MODULUS);
    (0..ROWS)
        .map(|row| {
            (0..N)
                .map(|i| {
                    let sum = (0..COLUMNS).fold(q * q, |v, col| {
                        v + u64::from(inputs.matrix_ntt[row * COLUMNS + col][i])
                            * u64::from(inputs.z_ntt[col][i])
                    });
                    ((sum
                        - u64::from(inputs.challenge_ntt[i])
                            * u64::from(inputs.t1_scaled_ntt[row][i]))
                        % q) as u32
                })
                .collect()
        })
        .collect()
}
// Fixed public routing only, including dummy zero slots; no native products.
fn public_rows(statement: &Statement) -> Vec<[u32; QUOTIENT]> {
    let mut rows = vec![[0; QUOTIENT]; SLOTS];
    for (n, row) in rows[..OPERATIONS].iter_mut().enumerate() {
        let r = n / N;
        let i = n % N;
        for col in 0..COLUMNS {
            row[col] = statement.inputs.matrix_ntt[r * COLUMNS + col][i];
            row[COLUMNS + col] = statement.inputs.z_ntt[col][i];
        }
        row[C] = statement.inputs.challenge_ntt[i];
        row[T] = statement.inputs.t1_scaled_ntt[r][i];
        row[OUT] = statement.output[r][i];
    }
    rows
}
fn witness(public: &[u32; QUOTIENT]) -> Vec<BaseElement> {
    let q = u64::from(NTT_MODULUS);
    let numerator = (0..COLUMNS).fold(q * q, |sum, col| {
        sum + u64::from(public[col]) * u64::from(public[COLUMNS + col])
    }) - u64::from(public[C]) * u64::from(public[T]);
    let quotient = (numerator - u64::from(public[OUT])) / q;
    let mut row = vec![BaseElement::ZERO; TRACE_WIDTH];
    for (column, &value) in public.iter().enumerate() {
        row[column] = BaseElement::new(value.into());
    }
    row[QUOTIENT] = BaseElement::new(quotient.into());
    for (group, value) in [quotient, u64::from(QUOTIENT_MAX) - quotient]
        .into_iter()
        .enumerate()
    {
        for bit in 0..RANGE_BITS {
            row[BITS + group * RANGE_BITS + bit] = BaseElement::new(((value >> bit) & 1).into());
        }
    }
    row
}
struct EquationAir {
    context: AirContext<BaseElement>,
    statement: Statement,
}
impl Air for EquationAir {
    type BaseField = BaseElement;
    type PublicInputs = Statement;
    fn new(info: TraceInfo, statement: Statement, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH));
        let mut degrees = vec![TransitionConstraintDegree::new(2); 1 + 2 * RANGE_BITS];
        degrees.extend((0..2).map(|_| TransitionConstraintDegree::new(1)));
        debug_assert_eq!(degrees.len(), CONSTRAINTS);
        Self {
            context: AirContext::new(info, degrees, QUOTIENT, options),
            statement,
        }
    }
    fn evaluate_transition<E: FieldElement + From<BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let row = frame.current();
        let q = E::from(BaseElement::new(NTT_MODULUS.into()));
        result[0] = (0..COLUMNS).fold(q * q, |sum, col| sum + row[col] * row[COLUMNS + col])
            - row[C] * row[T]
            - row[OUT]
            - q * row[QUOTIENT];
        let mut sums = [E::ZERO; 2];
        for (group, sum) in sums.iter_mut().enumerate() {
            let mut weight = E::ONE;
            for bit in 0..RANGE_BITS {
                let b = row[BITS + group * RANGE_BITS + bit];
                result[1 + group * RANGE_BITS + bit] = b * (b - E::ONE);
                *sum += b * weight;
                weight = weight + weight;
            }
        }
        result[1 + 2 * RANGE_BITS] = row[QUOTIENT] - sums[0];
        result[2 + 2 * RANGE_BITS] =
            sums[0] + sums[1] - E::from(BaseElement::new(QUOTIENT_MAX.into()));
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = public_rows(&self.statement);
        (0..QUOTIENT)
            .map(|column| {
                Assertion::sequence(
                    column,
                    0,
                    2,
                    rows.iter()
                        .map(|r| BaseElement::new(r[column].into()))
                        .collect(),
                )
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

struct EquationProver {
    statement: Statement,
    options: ProofOptions,
}

impl Prover for EquationProver {
    type BaseField = BaseElement;
    type Air = EquationAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, EquationAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> Statement {
        self.statement.clone()
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
        air: &'a EquationAir,
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

/// Prove all 1536 coordinates of the complete ML-DSA-65 pointwise equation.
pub fn prove_equation(inputs: &EquationInputs) -> Result<EquationProof, String> {
    validate(inputs)?;
    let output = calculate(inputs);
    let statement = Statement {
        inputs: inputs.clone(),
        output: output.clone(),
    };
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (i, public) in public_rows(&statement).iter().enumerate() {
        let row = witness(public);
        trace.update_row(2 * i, &row);
        trace.update_row(2 * i + 1, &row);
    }
    // Every real equation and all even dummy rows remain asserted/constrained.
    let mut padding =
        blake3::Hasher::new_derive_key("Shell-Chain ML-DSA verification equation padding v1");
    for value in statement.to_elements() {
        padding.update(&value.as_int().to_le_bytes());
    }
    let mut bytes = [0; 16 * TRACE_WIDTH];
    padding.finalize_xof().fill(&mut bytes);
    let last: Vec<_> = bytes
        .chunks_exact(16)
        .map(|v| BaseElement::new(u128::from_le_bytes(v.try_into().expect("16 bytes"))))
        .collect();
    trace.update_row(TRACE_LENGTH - 1, &last);
    let prover = EquationProver {
        statement,
        options: default_proof_options(),
    };
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("equation proving: {e:?}"))?;
    Ok(EquationProof {
        version: 1,
        inputs: inputs.clone(),
        output,
        proof_bytes: proof.to_bytes(),
    })
}
/// Verify actual modular constraints and bind all operands/results independently.
/// No native matrix multiplication or subtraction is evaluated here.
pub fn verify_equation(
    proof: &EquationProof,
    expected_inputs: &EquationInputs,
    expected_output: &[Vec<u32>],
) -> Result<(), String> {
    if proof.version != 1
        || proof.inputs != *expected_inputs
        || proof.output != expected_output
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("invalid equation version, endpoints or proof payload".into());
    }
    validate(expected_inputs)?;
    if !polynomials(expected_output, ROWS) {
        return Err("invalid canonical equation output shape".into());
    }
    let inner = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| format!("equation proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("unexpected equation trace layout".into());
    }
    verify::<EquationAir, Hasher, Coin, Commitment>(
        inner,
        Statement {
            inputs: expected_inputs.clone(),
            output: expected_output.to_vec(),
        },
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("equation verification: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    fn zero() -> EquationInputs {
        EquationInputs {
            matrix_ntt: vec![vec![0; N]; ROWS * COLUMNS],
            z_ntt: vec![vec![0; N]; COLUMNS],
            challenge_ntt: vec![0; N],
            t1_scaled_ntt: vec![vec![0; N]; ROWS],
        }
    }
    fn input() -> EquationInputs {
        EquationInputs {
            matrix_ntt: (0..ROWS * COLUMNS)
                .map(|r| {
                    (0..N)
                        .map(|i| ((r * 100003 + i * 347 + 19) as u32) % NTT_MODULUS)
                        .collect()
                })
                .collect(),
            z_ntt: (0..COLUMNS)
                .map(|r| {
                    (0..N)
                        .map(|i| ((r * 1879 + i * 53 + 7) as u32) % NTT_MODULUS)
                        .collect()
                })
                .collect(),
            challenge_ntt: (0..N)
                .map(|i| ((i * 1237) as u32 + NTT_MODULUS - 1) % NTT_MODULUS)
                .collect(),
            t1_scaled_ntt: (0..ROWS)
                .map(|r| {
                    (0..N)
                        .map(|i| ((r * 541 + i * 2029 + 11) as u32) % NTT_MODULUS)
                        .collect()
                })
                .collect(),
        }
    }
    fn reference(x: &EquationInputs) -> Vec<Vec<u32>> {
        let mut result = vec![vec![0i128; N]; ROWS];
        for (col, z) in x.z_ntt.iter().enumerate() {
            for (row, values) in result.iter_mut().enumerate() {
                for (i, value) in values.iter_mut().enumerate() {
                    *value += i128::from(x.matrix_ntt[row * COLUMNS + col][i]) * i128::from(z[i]);
                }
            }
        }
        result
            .iter()
            .enumerate()
            .map(|(row, values)| {
                values
                    .iter()
                    .enumerate()
                    .map(|(i, &value)| {
                        (value
                            - i128::from(x.challenge_ntt[i]) * i128::from(x.t1_scaled_ntt[row][i]))
                        .rem_euclid(i128::from(NTT_MODULUS)) as u32
                    })
                    .collect()
            })
            .collect()
    }
    fn sample() -> &'static EquationProof {
        static P: OnceLock<EquationProof> = OnceLock::new();
        P.get_or_init(|| prove_equation(&input()).unwrap())
    }
    fn residuals(row: &[BaseElement]) -> Vec<BaseElement> {
        let air = EquationAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            Statement {
                inputs: zero(),
                output: vec![vec![0; N]; ROWS],
            },
            default_proof_options(),
        );
        let mut out = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(
            &EvaluationFrame::from_rows(row.to_vec(), row.to_vec()),
            &[],
            &mut out,
        );
        out
    }
    #[test]
    fn full_equation_matches_signed_reference_and_boundary_rows() {
        let mut negative = zero();
        negative.challenge_ntt.fill(NTT_MODULUS - 1);
        negative
            .t1_scaled_ntt
            .iter_mut()
            .for_each(|p| p.fill(NTT_MODULUS - 1));
        let mut maximum = zero();
        maximum
            .matrix_ntt
            .iter_mut()
            .for_each(|p| p.fill(NTT_MODULUS - 1));
        maximum
            .z_ntt
            .iter_mut()
            .for_each(|p| p.fill(NTT_MODULUS - 1));
        for x in [input(), zero(), negative, maximum] {
            let output = calculate(&x);
            assert_eq!(output, reference(&x));
            let rows = public_rows(&Statement { inputs: x, output });
            assert_eq!(rows.len(), SLOTS);
            for row in rows {
                assert!(residuals(&witness(&row))
                    .iter()
                    .all(|&v| v == BaseElement::ZERO));
            }
        }
    }
    #[test]
    fn all_rows_and_all_five_products_are_executed() {
        for row in 0..ROWS {
            for col in 0..COLUMNS {
                let mut x = zero();
                x.matrix_ntt[row * COLUMNS + col][255] = (col + 2) as u32;
                x.z_ntt[col][255] = (row + 3) as u32;
                let mut expected = vec![vec![0; N]; ROWS];
                expected[row][255] = ((col + 2) * (row + 3)) as u32;
                assert_eq!(calculate(&x), expected);
                let public = public_rows(&Statement {
                    inputs: x,
                    output: expected,
                });
                assert!(residuals(&witness(&public[row * N + 255]))
                    .iter()
                    .all(|&v| v == BaseElement::ZERO));
            }
        }
    }
    #[test]
    fn real_full_and_zero_proofs_and_json_roundtrip() {
        let p = sample();
        verify_equation(p, &input(), &reference(&input())).unwrap();
        let restored: EquationProof =
            serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
        verify_equation(&restored, &input(), &reference(&input())).unwrap();
        let p = prove_equation(&zero()).unwrap();
        verify_equation(&p, &zero(), &reference(&zero())).unwrap();
    }
    #[test]
    fn every_term_last_coordinate_and_output_are_bound() {
        for field in 0..4 {
            let mut p = sample().clone();
            match field {
                0 => p.inputs.matrix_ntt[29][255] ^= 1,
                1 => p.inputs.z_ntt[4][255] ^= 1,
                2 => p.inputs.challenge_ntt[255] ^= 1,
                _ => p.inputs.t1_scaled_ntt[5][255] ^= 1,
            }
            assert!(verify_equation(&p, &p.inputs, &p.output).is_err());
        }
        let mut p = sample().clone();
        p.output[5][255] = (p.output[5][255] + 1) % NTT_MODULUS;
        assert!(verify_equation(&p, &p.inputs, &p.output).is_err());
    }
    #[test]
    fn private_quotient_bits_stop_a_base_field_escape() {
        let mut row = witness(&[0; QUOTIENT]);
        let q = BaseElement::new(NTT_MODULUS.into());
        row[OUT] = BaseElement::ONE;
        let false_q = q - q.inv();
        row[QUOTIENT] = false_q;
        row[BITS..].fill(BaseElement::ZERO);
        row[BITS] = false_q;
        row[BITS + RANGE_BITS] = BaseElement::new(QUOTIENT_MAX.into()) - false_q;
        let out = residuals(&row);
        assert_eq!(out[0], BaseElement::ZERO);
        assert!(out[1 + 2 * RANGE_BITS..]
            .iter()
            .all(|&v| v == BaseElement::ZERO));
        assert!(out[1..1 + 2 * RANGE_BITS]
            .iter()
            .any(|&v| v != BaseElement::ZERO));
        let mut row = witness(&[0; QUOTIENT]);
        row[QUOTIENT] = BaseElement::new((QUOTIENT_MAX + 1).into());
        row[BITS..].fill(BaseElement::ZERO);
        for bit in 0..RANGE_BITS {
            row[BITS + bit] = BaseElement::new((((QUOTIENT_MAX + 1) >> bit) & 1).into());
        }
        let out = residuals(&row);
        assert_eq!(out[1 + 2 * RANGE_BITS], BaseElement::ZERO);
        assert_ne!(out[2 + 2 * RANGE_BITS], BaseElement::ZERO);
    }
    #[test]
    fn canonical_shapes_versions_foreign_layout_and_payload_reject() {
        let mut x = input();
        x.matrix_ntt.pop();
        assert!(prove_equation(&x).is_err());
        let mut x = input();
        x.z_ntt[4][255] = NTT_MODULUS;
        assert!(prove_equation(&x).is_err());
        let p = sample();
        let mut bad = p.clone();
        bad.version = 2;
        assert!(verify_equation(&bad, &bad.inputs, &bad.output).is_err());
        let mut bad = p.clone();
        bad.output[5].pop();
        assert!(verify_equation(&bad, &bad.inputs, &bad.output).is_err());
        let mut bad = p.clone();
        bad.output[5][255] = NTT_MODULUS;
        assert!(verify_equation(&bad, &bad.inputs, &bad.output).is_err());
        let mut bad = p.clone();
        bad.proof_bytes.truncate(10);
        assert!(verify_equation(&bad, &bad.inputs, &bad.output).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = vec![0; MAX_PROOF_BYTES + 1];
        assert!(verify_equation(&bad, &bad.inputs, &bad.output).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = crate::prove_sig_batch(&[crate::SigBatchEntry {
            msg_hash: [1; 32],
            pk_hash: [2; 32],
        }])
        .unwrap()
        .proof_bytes;
        assert!(verify_equation(&bad, &bad.inputs, &bad.output)
            .unwrap_err()
            .contains("trace layout"));
    }
}
