//! ML-DSA-65 RejNTTPoly/ExpandA proofs (FIPS 204 Algorithms 14, 30, 32).
//!
//! Every triple, acceptance decision and output position is constrained and
//! linked to SHAKE128. Complete matrix verification binds all 30 coordinates.
//! Public, bounded development proofs; not a full signature or node settlement.

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

use crate::prover::default_proof_options;

use crate::keccak_permutation::{
    prove_keccak_batch, verify_keccak_batch, KeccakBatchProof, MAX_KECCAK_BATCH,
};
use crate::mldsa_ntt::NTT_MODULUS;
use crate::shake_sponge::{
    matrix_shake_witness, prove_shake, prove_shake_batched, prove_sponge_batch,
    validate_matrix_shake, verify_shake, verify_sponge_batch, ShakeKind, ShakeProof,
    SpongeBatchProof, MAX_SHAKE_OUTPUT_BYTES, MAX_SPONGE_BATCH,
};

pub const MATRIX_ROWS: usize = 6;
pub const MATRIX_COLUMNS: usize = 5;
const N: usize = 256;
const ACTIVE: usize = 0;
const BYTE: usize = 1;
const COUNT: usize = 4;
const NEXT: usize = 5;
const TARGET: usize = 6;
const ACCEPT: usize = 7;
const LOW: usize = 8;
const HIGH: usize = 15;
const GAP: usize = 16;
const SLACK: usize = 39;
const TRACE_WIDTH: usize = 47;
const CONSTRAINTS: usize = 45;
const MAX_PROOF_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixPolynomialProof {
    pub version: u8,
    pub rho: Vec<u8>,
    pub row: u8,
    pub column: u8,
    pub xof: ShakeProof,
    pub counts: Vec<u16>,
    pub coefficients: Vec<u32>,
    pub proof_bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixProof {
    pub version: u8,
    pub rho: Vec<u8>,
    pub polynomials: Vec<MatrixPolynomialProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batches: Option<MatrixBatches>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixSamplerBatchProof {
    pub version: u8,
    pub proof_bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixBatches {
    pub samplers: Vec<MatrixSamplerBatchProof>,
    pub sponges: Vec<SpongeBatchProof>,
    pub permutations: Vec<KeccakBatchProof>,
}
pub(crate) const MAX_MATRIX_BATCH: usize = 8;
pub(crate) const MAX_MATRIX_PERMUTATION_BATCHES: usize =
    (MATRIX_ROWS * MATRIX_COLUMNS * MAX_SHAKE_OUTPUT_BYTES.div_ceil(168))
        .div_ceil(MAX_KECCAK_BATCH);
#[derive(Clone)]
struct Inputs {
    rho: Vec<u8>,
    row: u8,
    column: u8,
    stream: Vec<u8>,
    counts: Vec<u16>,
    coefficients: Vec<u32>,
}
impl Inputs {
    fn attempts(&self) -> usize {
        self.counts.len() - 1
    }
    fn slots(&self) -> usize {
        self.attempts().next_power_of_two()
    }
    fn trace_length(&self) -> usize {
        self.slots() * 2
    }
}
impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![
            BaseElement::new(u64::from_le_bytes(*b"MLMATR01") as u128),
            BaseElement::new(self.row.into()),
            BaseElement::new(self.column.into()),
            BaseElement::new(self.stream.len() as u128),
            BaseElement::new(self.attempts() as u128),
        ];
        out.extend(
            self.rho
                .iter()
                .chain(&self.stream)
                .map(|&v| BaseElement::new(v.into())),
        );
        out.extend(self.counts.iter().map(|&v| BaseElement::new(v.into())));
        out.extend(
            self.coefficients
                .iter()
                .map(|&v| BaseElement::new(v.into())),
        );
        out
    }
}
fn seed(rho: &[u8], row: u8, column: u8) -> Result<Vec<u8>, String> {
    if rho.len() != 32 || usize::from(row) >= MATRIX_ROWS || usize::from(column) >= MATRIX_COLUMNS {
        return Err("invalid ML-DSA-65 rho or matrix coordinate".into());
    }
    let mut bytes = rho.to_vec();
    bytes.extend([column, row]);
    Ok(bytes)
}
// Native sampling constructs a witness only. The verifier does not invoke it.
fn sample(rho: &[u8], row: u8, column: u8, stream: &[u8]) -> Option<Inputs> {
    let mut coefficients = Vec::with_capacity(N);
    let mut counts = vec![0];
    for b in stream.chunks_exact(3) {
        let value = u32::from(b[0]) + (u32::from(b[1]) << 8) + (u32::from(b[2] & 127) << 16);
        if value < NTT_MODULUS {
            coefficients.push(value);
        }
        counts.push(coefficients.len() as u16);
        if coefficients.len() == N {
            return Some(Inputs {
                rho: rho.to_vec(),
                row,
                column,
                stream: stream.to_vec(),
                counts,
                coefficients,
            });
        }
    }
    None
}
// Fixed triple/counter/output routing only, with no masking, native acceptance
// comparison or native sampling in the verifier's boundary construction.
fn public_rows(inputs: &Inputs) -> Vec<Vec<BaseElement>> {
    let mut rows = vec![vec![BaseElement::ZERO; TRACE_WIDTH]; inputs.slots()];
    for (t, row) in rows[..inputs.attempts()].iter_mut().enumerate() {
        row[ACTIVE] = BaseElement::ONE;
        for i in 0..3 {
            row[BYTE + i] = BaseElement::new(inputs.stream[t * 3 + i].into());
        }
        row[COUNT] = BaseElement::new(inputs.counts[t].into());
        row[NEXT] = BaseElement::new(inputs.counts[t + 1].into());
        row[TARGET] = BaseElement::new(
            inputs
                .coefficients
                .get(usize::from(inputs.counts[t]))
                .copied()
                .unwrap_or(0)
                .into(),
        );
    }
    rows
}
fn witness(row: &mut [BaseElement]) {
    if row[ACTIVE] != BaseElement::ONE {
        return;
    }
    let b2 = row[BYTE + 2].as_int();
    row[HIGH] = BaseElement::new(b2 >> 7);
    for bit in 0..7 {
        row[LOW + bit] = BaseElement::new((b2 >> bit) & 1);
    }
    let value = (row[BYTE].as_int() + 256 * row[BYTE + 1].as_int() + 65536 * (b2 & 127)) as i64;
    row[ACCEPT] = BaseElement::new(u128::from(value < i64::from(NTT_MODULUS)));
    let gap = (value - i64::from(NTT_MODULUS)).rem_euclid(1 << 23) as u32;
    for bit in 0..23 {
        row[GAP + bit] = BaseElement::new(((gap >> bit) & 1).into());
    }
    let slack = (255 - row[COUNT].as_int() as i64).rem_euclid(256) as u16;
    for bit in 0..8 {
        row[SLACK + bit] = BaseElement::new(((slack >> bit) & 1).into());
    }
}
// A separate transcript binds every ordered child statement. Legacy inputs
// retain their exact original public vector, padding and trace layout.
#[derive(Clone)]
struct BatchInputs {
    polynomials: Vec<Inputs>,
    aggregate: bool,
}
impl BatchInputs {
    fn single(input: Inputs) -> Self {
        Self {
            polynomials: vec![input],
            aggregate: false,
        }
    }
    fn slots(&self) -> usize {
        if self.aggregate {
            self.polynomials
                .iter()
                .map(|p| p.attempts())
                .sum::<usize>()
                .next_power_of_two()
        } else {
            self.polynomials[0].slots()
        }
    }
    fn trace_length(&self) -> usize {
        self.slots() * 2
    }
}
impl ToElements<BaseElement> for BatchInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        if !self.aggregate {
            return self.polynomials[0].to_elements();
        }
        let mut values = vec![
            BaseElement::new(u64::from_le_bytes(*b"MLMATB01") as u128),
            BaseElement::new(self.polynomials.len() as u128),
        ];
        for input in &self.polynomials {
            values.extend(input.to_elements());
        }
        values
    }
}
fn batch_rows(inputs: &BatchInputs) -> Vec<Vec<BaseElement>> {
    if !inputs.aggregate {
        return public_rows(&inputs.polynomials[0]);
    }
    let mut rows = Vec::with_capacity(inputs.slots());
    for p in &inputs.polynomials {
        rows.extend(public_rows(p).into_iter().take(p.attempts()));
    }
    rows.resize(inputs.slots(), vec![BaseElement::ZERO; TRACE_WIDTH]);
    rows
}
struct MatrixPolyAir {
    context: AirContext<BaseElement>,
    inputs: BatchInputs,
}
impl Air for MatrixPolyAir {
    type BaseField = BaseElement;
    type PublicInputs = BatchInputs;
    fn new(info: TraceInfo, inputs: BatchInputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, inputs.trace_length()));
        let degrees = (0..CONSTRAINTS)
            .map(|i| TransitionConstraintDegree::new(if i == 44 { 3 } else { 2 }))
            .collect();
        Self {
            context: AirContext::new(info, degrees, ACCEPT, options),
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
        for bit in 0..40 {
            result[bit] = r[ACCEPT + bit] * (r[ACCEPT + bit] - E::ONE);
        }
        let sum = |bits: &[E]| {
            let mut v = E::ZERO;
            let mut w = E::ONE;
            for &b in bits {
                v += b * w;
                w = w + w;
            }
            v
        };
        let low = sum(&r[LOW..LOW + 7]);
        let value = r[BYTE]
            + E::from(BaseElement::new(256)) * r[BYTE + 1]
            + E::from(BaseElement::new(65536)) * low;
        result[40] = r[ACTIVE] * (r[BYTE + 2] - low - E::from(BaseElement::new(128)) * r[HIGH]);
        result[41] = r[ACTIVE]
            * (value - E::from(BaseElement::new(NTT_MODULUS.into())) - sum(&r[GAP..GAP + 23])
                + E::from(BaseElement::new(1 << 23)) * r[ACCEPT]);
        result[42] =
            r[ACTIVE] * (E::from(BaseElement::new(255)) - r[COUNT] - sum(&r[SLACK..SLACK + 8]));
        result[43] = r[ACTIVE] * (r[NEXT] - r[COUNT] - r[ACCEPT]);
        result[44] = r[ACTIVE] * r[ACCEPT] * (value - r[TARGET]);
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = batch_rows(&self.inputs);
        (0..ACCEPT)
            .map(|col| Assertion::sequence(col, 0, 2, rows.iter().map(|r| r[col]).collect()))
            .collect()
    }
    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }
}
fn trace(inputs: &BatchInputs) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(TRACE_WIDTH, inputs.trace_length());
    for (slot, mut row) in batch_rows(inputs).into_iter().enumerate() {
        witness(&mut row);
        trace.update_row(slot * 2, &row);
        trace.update_row(slot * 2 + 1, &row);
    }
    // Only the last unused odd row is free padding. Every real triple remains
    // constrained and asserted, including constant-rho cases.
    let mut h =
        blake3::Hasher::new_derive_key("Shell-Chain ML-DSA matrix sampling trace padding v1");
    for value in inputs.to_elements() {
        h.update(&value.as_int().to_le_bytes());
    }
    let mut bytes = [0u8; 16 * TRACE_WIDTH];
    h.finalize_xof().fill(&mut bytes);
    let row: Vec<_> = bytes
        .chunks_exact(16)
        .map(|v| BaseElement::new(u128::from_le_bytes(v.try_into().expect("16 bytes"))))
        .collect();
    trace.update_row(inputs.trace_length() - 1, &row);
    trace
}

type Hasher = Blake3_256<BaseElement>;
type Commitment = MerkleTree<Hasher>;
type Coin = DefaultRandomCoin<Hasher>;

struct MatrixPolyProver {
    inputs: BatchInputs,
    options: ProofOptions,
}

impl Prover for MatrixPolyProver {
    type BaseField = BaseElement;
    type Air = MatrixPolyAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, MatrixPolyAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BatchInputs {
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
        air: &'a MatrixPolyAir,
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

/// Prove one coordinate-bound ML-DSA-65 matrix polynomial in NTT representation.
pub fn prove_matrix_polynomial(
    rho: &[u8],
    row: u8,
    column: u8,
) -> Result<MatrixPolynomialProof, String> {
    prove_matrix_polynomial_inner(rho, row, column, false)
}
/// New large production jobs aggregate the SHAKE permutation statements. Legacy
/// polynomial and sponge transcripts remain verifiable without conversion.
pub fn prove_matrix_polynomial_batched(
    rho: &[u8],
    row: u8,
    column: u8,
) -> Result<MatrixPolynomialProof, String> {
    prove_matrix_polynomial_inner(rho, row, column, true)
}
fn prove_matrix_polynomial_inner(
    rho: &[u8],
    row: u8,
    column: u8,
    aggregate: bool,
) -> Result<MatrixPolynomialProof, String> {
    let bytes = seed(rho, row, column)?;
    let mut length = 840;
    let (xof, inputs) = loop {
        let xof = if aggregate {
            prove_shake_batched(ShakeKind::Shake128, &bytes, length)?
        } else {
            prove_shake(ShakeKind::Shake128, &bytes, length)?
        };
        if let Some(input) = sample(rho, row, column, &xof.output) {
            break (xof, input);
        }
        if length == MAX_SHAKE_OUTPUT_BYTES {
            return Err("matrix sampling exceeds development SHAKE stream resource bound".into());
        }
        length = (length * 2).min(MAX_SHAKE_OUTPUT_BYTES);
    };
    let prover = MatrixPolyProver {
        inputs: BatchInputs::single(inputs.clone()),
        options: default_proof_options(),
    };
    let inner = prover
        .prove(trace(&BatchInputs::single(inputs.clone())))
        .map_err(|e| format!("matrix sampling proof: {e:?}"))?;
    Ok(MatrixPolynomialProof {
        version: 1,
        rho: rho.to_vec(),
        row,
        column,
        xof,
        counts: inputs.counts,
        coefficients: inputs.coefficients,
        proof_bytes: inner.to_bytes(),
    })
}
fn validate_shape(
    p: &MatrixPolynomialProof,
    rho: &[u8],
    row: u8,
    column: u8,
    expected: &[u32],
) -> Result<(), String> {
    validate_shape_kind(p, rho, row, column, expected, false)
}
fn validate_shape_kind(
    p: &MatrixPolynomialProof,
    rho: &[u8],
    row: u8,
    column: u8,
    expected: &[u32],
    aggregate: bool,
) -> Result<(), String> {
    seed(rho, row, column)?;
    if p.version != if aggregate { 2 } else { 1 }
        || p.rho != rho
        || p.row != row
        || p.column != column
        || expected.len() != N
        || p.coefficients != expected
        || p.xof.output.len() < 3
        || p.xof.output.len() > MAX_SHAKE_OUTPUT_BYTES
        || p.counts.len() < N + 1
        || p.counts.len() > p.xof.output.len() / 3 + 1
        || p.counts.first() != Some(&0)
        || p.counts.last() != Some(&(N as u16))
        || p.proof_bytes.is_empty() != aggregate
        || p.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("invalid matrix polynomial version, endpoints, shape or payload".into());
    }
    Ok(())
}
/// Verify masking, rejection and output positions plus actual SHAKE128 proofs;
/// no native SHAKE, coefficient mask/acceptance or native sampling is executed.
pub fn verify_matrix_polynomial(
    p: &MatrixPolynomialProof,
    rho: &[u8],
    row: u8,
    column: u8,
    expected: &[u32],
) -> Result<(), String> {
    validate_shape(p, rho, row, column, expected)?;
    let inputs = Inputs {
        rho: p.rho.clone(),
        row,
        column,
        stream: p.xof.output.clone(),
        counts: p.counts.clone(),
        coefficients: p.coefficients.clone(),
    };
    let inner = Proof::from_bytes(&p.proof_bytes)
        .map_err(|e| format!("matrix sampling proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, inputs.trace_length()) {
        return Err("unexpected matrix sampler trace layout".into());
    }
    verify::<MatrixPolyAir, Hasher, Coin, Commitment>(
        inner,
        BatchInputs::single(inputs),
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("matrix sampling verification: {e:?}"))?;
    verify_shake(
        &p.xof,
        ShakeKind::Shake128,
        &seed(rho, row, column)?,
        &p.xof.output,
    )
}
/// Verify complete row-major 6x5 coverage; partial/duplicate/reordered or foreign
/// polynomials cannot stand in for a complete ExpandA result.
pub fn verify_matrix(p: &MatrixProof, rho: &[u8], expected: &[Vec<u32>]) -> Result<(), String> {
    if !matches!(p.version, 1 | 2)
        || (p.version == 2) != p.batches.is_some()
        || rho.len() != 32
        || p.rho != rho
        || p.polynomials.len() != MATRIX_ROWS * MATRIX_COLUMNS
        || expected.len() != MATRIX_ROWS * MATRIX_COLUMNS
        || expected.iter().any(|v| v.len() != N)
        || p.polynomials
            .iter()
            .zip(expected)
            .any(|(p, expected)| p.coefficients != *expected)
        || p.polynomials.iter().enumerate().any(|(i, v)| {
            usize::from(v.row) != i / MATRIX_COLUMNS
                || usize::from(v.column) != i % MATRIX_COLUMNS
                || v.rho != rho
        })
    {
        return Err("invalid complete matrix shape or coordinate coverage".into());
    }
    if p.version == 2 {
        return verify_matrix_batches(p);
    }
    for (i, poly) in p.polynomials.iter().enumerate() {
        verify_matrix_polynomial(
            poly,
            rho,
            (i / MATRIX_COLUMNS) as u8,
            (i % MATRIX_COLUMNS) as u8,
            &expected[i],
        )?;
    }
    Ok(())
}

fn routing_inputs(p: &MatrixPolynomialProof) -> Result<Inputs, String> {
    validate_shape_kind(p, &p.rho, p.row, p.column, &p.coefficients, true)?;
    validate_matrix_shake(&p.xof)?;
    if p.xof.message != seed(&p.rho, p.row, p.column)? {
        return Err("matrix SHAKE coordinate binding".into());
    }
    Ok(Inputs {
        rho: p.rho.clone(),
        row: p.row,
        column: p.column,
        stream: p.xof.output.clone(),
        counts: p.counts.clone(),
        coefficients: p.coefficients.clone(),
    })
}
fn sampler_batch_inputs(polynomials: &[MatrixPolynomialProof]) -> Result<BatchInputs, String> {
    if polynomials.is_empty() || polynomials.len() > MAX_MATRIX_BATCH {
        return Err("invalid matrix sampler batch count".into());
    }
    Ok(BatchInputs {
        polynomials: polynomials
            .iter()
            .map(routing_inputs)
            .collect::<Result<_, _>>()?,
        aggregate: true,
    })
}
pub(crate) fn prove_matrix_sampler_batch(
    polynomials: &[MatrixPolynomialProof],
) -> Result<MatrixSamplerBatchProof, String> {
    let inputs = sampler_batch_inputs(polynomials)?;
    for p in &inputs.polynomials {
        let expected = sample(&p.rho, p.row, p.column, &p.stream)
            .ok_or("incomplete matrix sampler witness")?;
        if expected.counts != p.counts || expected.coefficients != p.coefficients {
            return Err("invalid matrix sampler witness".into());
        }
    }
    let prover = MatrixPolyProver {
        inputs: inputs.clone(),
        options: default_proof_options(),
    };
    let proof = prover
        .prove(trace(&inputs))
        .map_err(|e| format!("matrix sampler batch proof: {e:?}"))?;
    Ok(MatrixSamplerBatchProof {
        version: 1,
        proof_bytes: proof.to_bytes(),
    })
}
pub(crate) fn verify_matrix_sampler_batch(
    p: &MatrixSamplerBatchProof,
    polynomials: &[MatrixPolynomialProof],
) -> Result<(), String> {
    let inputs = sampler_batch_inputs(polynomials)?;
    if p.version != 1 || p.proof_bytes.is_empty() || p.proof_bytes.len() > MAX_PROOF_BYTES {
        return Err("invalid matrix sampler batch version or size".into());
    }
    let proof = Proof::from_bytes(&p.proof_bytes)
        .map_err(|e| format!("matrix sampler batch decode: {e:?}"))?;
    if proof.trace_info() != &TraceInfo::new(TRACE_WIDTH, inputs.trace_length()) {
        return Err("unexpected matrix sampler batch layout".into());
    }
    verify::<MatrixPolyAir, Hasher, Coin, Commitment>(
        proof,
        inputs,
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("matrix sampler batch verification: {e:?}"))
}

/// Routing is constructed only on the prover. The recipient authenticates it
/// with the sampler, sponge and permutation AIRs, never native SHAKE/sampling.
pub(crate) fn matrix_witness(rho: &[u8]) -> Result<MatrixProof, String> {
    let mut polynomials = Vec::with_capacity(30);
    for row in 0..6 {
        for column in 0..5 {
            let message = seed(rho, row, column)?;
            let mut length = 840;
            let (xof, input) = loop {
                let xof = matrix_shake_witness(&message, length)?;
                if let Some(input) = sample(rho, row, column, &xof.output) {
                    break (xof, input);
                }
                if length == MAX_SHAKE_OUTPUT_BYTES {
                    return Err("matrix sampler resource bound".into());
                }
                length = (length * 2).min(MAX_SHAKE_OUTPUT_BYTES);
            };
            polynomials.push(MatrixPolynomialProof {
                version: 2,
                rho: rho.to_vec(),
                row,
                column,
                xof,
                counts: input.counts,
                coefficients: input.coefficients,
                proof_bytes: Vec::new(),
            });
        }
    }
    Ok(MatrixProof {
        version: 2,
        rho: rho.to_vec(),
        polynomials,
        batches: Some(MatrixBatches {
            samplers: Vec::new(),
            sponges: Vec::new(),
            permutations: Vec::new(),
        }),
    })
}
/// Complete bounded ExpandA proof; individual routing polynomials cannot verify
/// standalone or replace an ordered complete matrix.
pub fn prove_matrix_batched(rho: &[u8]) -> Result<MatrixProof, String> {
    let mut p = matrix_witness(rho)?;
    let mut batches = p.batches.take().ok_or("missing matrix batches")?;
    for group in p.polynomials.chunks(MAX_MATRIX_BATCH) {
        batches.samplers.push(prove_matrix_sampler_batch(group)?);
    }
    let streams: Vec<_> = p.polynomials.iter().map(|v| v.xof.clone()).collect();
    for group in streams.chunks(MAX_SPONGE_BATCH) {
        batches.sponges.push(prove_sponge_batch(group)?);
    }
    let permutations: Vec<_> = streams
        .iter()
        .flat_map(|v| v.permutations.iter().cloned())
        .collect();
    for group in permutations.chunks(MAX_KECCAK_BATCH) {
        batches.permutations.push(prove_keccak_batch(group)?);
    }
    p.batches = Some(batches);
    Ok(p)
}
fn verify_matrix_batches(p: &MatrixProof) -> Result<(), String> {
    let batches = p.batches.as_ref().ok_or("missing matrix batches")?;
    for v in &p.polynomials {
        routing_inputs(v)?;
    }
    let streams: Vec<_> = p.polynomials.iter().map(|v| v.xof.clone()).collect();
    let permutations: Vec<_> = streams
        .iter()
        .flat_map(|v| v.permutations.iter().cloned())
        .collect();
    if batches.samplers.len() != p.polynomials.len().div_ceil(MAX_MATRIX_BATCH)
        || batches.sponges.len() != streams.len().div_ceil(MAX_SPONGE_BATCH)
        || batches.permutations.len() != permutations.len().div_ceil(MAX_KECCAK_BATCH)
    {
        return Err("invalid complete matrix batch coverage".into());
    }
    for (proof, group) in batches
        .samplers
        .iter()
        .zip(p.polynomials.chunks(MAX_MATRIX_BATCH))
    {
        verify_matrix_sampler_batch(proof, group)?;
    }
    for (proof, group) in batches.sponges.iter().zip(streams.chunks(MAX_SPONGE_BATCH)) {
        verify_sponge_batch(proof, group)?;
    }
    for (proof, group) in batches
        .permutations
        .iter()
        .zip(permutations.chunks(MAX_KECCAK_BATCH))
    {
        verify_keccak_batch(proof, group)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };
    use std::sync::OnceLock;
    #[test]
    fn bounded_sampler_and_bridge_batches_bind_all_ordered_inputs() {
        let matrix = matrix_witness(&[0x73; 32]).unwrap();
        let polynomials = &matrix.polynomials[..8];
        let sampler = prove_matrix_sampler_batch(polynomials).unwrap();
        verify_matrix_sampler_batch(&sampler, polynomials).unwrap();
        let streams: Vec<_> = polynomials.iter().map(|p| p.xof.clone()).collect();
        let bridge = prove_sponge_batch(&streams).unwrap();
        verify_sponge_batch(&bridge, &streams).unwrap();
        for i in [0, 3, 7] {
            assert_eq!(
                polynomials[i].coefficients,
                native(&[0x73; 32], polynomials[i].row, polynomials[i].column)
            );
            let mut bad = polynomials.to_vec();
            bad[i].counts[1] = 65535;
            assert!(verify_matrix_sampler_batch(&sampler, &bad).is_err());
            assert!(prove_matrix_sampler_batch(&bad).is_err());
            let mut bad = streams.clone();
            bad[i].output[0] ^= 1;
            assert!(verify_sponge_batch(&bridge, &bad).is_err());
            assert!(prove_sponge_batch(&bad).is_err());
        }
        let mut swapped = polynomials.to_vec();
        swapped.swap(0, 1);
        assert!(verify_matrix_sampler_batch(&sampler, &swapped).is_err());
        let mut swapped = streams.clone();
        swapped.swap(0, 1);
        assert!(verify_sponge_batch(&bridge, &swapped).is_err());
        assert!(prove_matrix_sampler_batch(&[]).is_err());
        assert!(verify_matrix_sampler_batch(&sampler, &matrix.polynomials[..9]).is_err());
        assert!(verify_matrix_sampler_batch(&sampler, &polynomials[..7]).is_err());
        assert!(verify_sponge_batch(&bridge, &vec![streams[0].clone(); 9]).is_err());
        assert!(verify_shake(
            &streams[0],
            ShakeKind::Shake128,
            &streams[0].message,
            &streams[0].output
        )
        .is_err());
        assert!(verify_matrix_polynomial(
            &polynomials[0],
            &[0x73; 32],
            0,
            0,
            &polynomials[0].coefficients
        )
        .is_err());
        // Same endpoints and trace shape, different standalone/batch domain.
        let legacy_inputs = BatchInputs::single(routing_inputs(&polynomials[0]).unwrap());
        let legacy = MatrixPolyProver {
            inputs: legacy_inputs.clone(),
            options: default_proof_options(),
        }
        .prove(trace(&legacy_inputs))
        .unwrap();
        assert!(verify_matrix_sampler_batch(
            &MatrixSamplerBatchProof {
                version: 1,
                proof_bytes: legacy.to_bytes()
            },
            &polynomials[..1]
        )
        .is_err());
        use crate::production_store::ProductionStore;
        use shell_storage::{KvStore, MemoryDb};
        let mut db = MemoryDb::new();
        let mut job = ProductionStore::open_shared_matrix(&mut db, b"matrix-part", None).unwrap();
        job.checkpoint(
            "sender-0-matrix-sampler-0",
            || Ok(sampler.clone()),
            |v| verify_matrix_sampler_batch(v, polynomials),
        )
        .unwrap();
        drop(job);
        let saved = db.scan_all().unwrap();
        let mut job = ProductionStore::open_compact(&mut db, b"matrix-part", None).unwrap();
        assert!(job.shared_matrix_encoding());
        let _: MatrixSamplerBatchProof = job
            .checkpoint(
                "sender-0-matrix-sampler-0",
                || panic!("retained proof regenerated"),
                |v| verify_matrix_sampler_batch(v, polynomials),
            )
            .unwrap();
        let mut invalid = sampler.clone();
        invalid.version = 2;
        assert!(job
            .checkpoint(
                "sender-0-matrix-sampler-1",
                || Ok(invalid),
                |v| verify_matrix_sampler_batch(v, polynomials)
            )
            .is_err());
        drop(job);
        assert_eq!(db.scan_all().unwrap(), saved);
        let mut old = MemoryDb::new();
        drop(ProductionStore::open_compact(&mut old, b"old", None).unwrap());
        let saved = old.scan_all().unwrap();
        let job = ProductionStore::open_shared_matrix(&mut old, b"old", None).unwrap();
        assert!(!job.shared_matrix_encoding());
        drop(job);
        assert_eq!(old.scan_all().unwrap(), saved);
    }
    #[test]
    fn complete_shared_matrix_binds_every_coordinate_and_proof_group() {
        let rho = [0x51; 32];
        let p = prove_matrix_batched(&rho).unwrap();
        let expected: Vec<_> = (0..6)
            .flat_map(|row| (0..5).map(move |col| native(&rho, row, col)))
            .collect();
        verify_matrix(&p, &rho, &expected).unwrap();
        let mut wrong_expected = expected.clone();
        wrong_expected[29][255] ^= 1;
        assert!(verify_matrix(&p, &rho, &wrong_expected).is_err());
        let encoded = crate::compact_canonical::encode_component(&p).unwrap();
        let decoded = crate::compact_canonical::decode_component(&encoded).unwrap();
        verify_matrix(&decoded, &rho, &expected).unwrap();
        let mut bad = p.clone();
        bad.polynomials.swap(7, 8);
        assert!(verify_matrix(&bad, &rho, &expected).is_err());
        let mut bad = p.clone();
        bad.batches.as_mut().unwrap().samplers.pop();
        assert!(verify_matrix(&bad, &rho, &expected).is_err());
        let mut bad = p.clone();
        bad.batches.as_mut().unwrap().sponges.swap(0, 1);
        assert!(verify_matrix(&bad, &rho, &expected).is_err());
        let mut bad = p.clone();
        bad.batches.as_mut().unwrap().permutations.swap(0, 1);
        assert!(verify_matrix(&bad, &rho, &expected).is_err());
        for index in [0, 7, 8, 29] {
            let mut bad = p.clone();
            bad.polynomials[index].xof.permutations[0].rounds[11].theta[24] ^= 1;
            assert!(verify_matrix(&bad, &rho, &expected).is_err());
        }
        let mut bad = p.clone();
        bad.version = 1;
        assert!(verify_matrix(&bad, &rho, &expected).is_err());
        assert!(verify_matrix(&p, &[0x52; 32], &expected).is_err());
    }
    #[test]
    fn aggregate_matrix_sampler_binds_rho_coordinate_and_full_shake() {
        let rho = [0x69; 32];
        let p = prove_matrix_polynomial_batched(&rho, 5, 4).unwrap();
        let expected = native(&rho, 5, 4);
        assert_eq!(p.coefficients, expected);
        assert_eq!(p.xof.version, 2);
        verify_matrix_polynomial(&p, &rho, 5, 4, &expected).unwrap();
        assert!(verify_matrix_polynomial(&p, &[0x68; 32], 5, 4, &expected).is_err());
        assert!(verify_matrix_polynomial(&p, &rho, 4, 4, &expected).is_err());
        let mut bad = p.clone();
        bad.xof.permutations[4].rounds[23].output[24] ^= 1;
        assert!(verify_matrix_polynomial(&bad, &rho, 5, 4, &expected).is_err());
    }
    fn native(rho: &[u8], row: u8, column: u8) -> Vec<u32> {
        let mut h = Shake128::default();
        h.update(rho);
        h.update(&[column]);
        h.update(&[row]);
        let mut reader = h.finalize_xof();
        let mut out = Vec::new();
        while out.len() < 256 {
            let mut b = [0; 3];
            reader.read(&mut b);
            let value = u32::from_le_bytes([b[0], b[1], b[2], 0]) & 0x7fffff;
            if value < 8380417 {
                out.push(value);
            }
        }
        out
    }
    fn cases() -> &'static Vec<MatrixPolynomialProof> {
        static CASES: OnceLock<Vec<MatrixPolynomialProof>> = OnceLock::new();
        CASES.get_or_init(|| {
            [(vec![0; 32], 0, 0), (vec![255; 32], 5, 4)]
                .iter()
                .map(|(rho, row, col)| {
                    let p = prove_matrix_polynomial(rho, *row, *col).unwrap();
                    assert_eq!(p.coefficients, native(rho, *row, *col));
                    p
                })
                .collect()
        })
    }
    #[test]
    fn real_reject_and_no_reject_match_streaming_oracle_and_openssl_prefixes() {
        for p in cases() {
            verify_matrix_polynomial(p, &p.rho, p.row, p.column, &native(&p.rho, p.row, p.column))
                .unwrap();
        }
        assert_eq!(cases()[0].counts.len() - 1, 257);
        assert_eq!(cases()[1].counts.len() - 1, 256);
        // Independent Python hashlib/OpenSSL fixed-coordinate controls.
        assert_eq!(
            cases()[0].coefficients[..4],
            [5889865, 3971968, 4850004, 6999211]
        );
        assert_eq!(
            cases()[1].coefficients[..4],
            [2466100, 7337097, 2099609, 1984875]
        );
        assert_eq!(cases()[1].xof.message[32..], [4, 5]);
        let p = &cases()[0];
        let restored: MatrixPolynomialProof =
            serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
        verify_matrix_polynomial(&restored, &p.rho, p.row, p.column, &p.coefficients).unwrap();
    }
    #[test]
    fn coordinates_counters_output_and_stream_are_bound() {
        let p = &cases()[0];
        assert!(verify_matrix_polynomial(p, &p.rho, 1, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.row = 1;
        assert!(verify_matrix_polynomial(&bad, &p.rho, 1, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.rho[0] ^= 1;
        assert!(verify_matrix_polynomial(&bad, &bad.rho, 0, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.counts[1] = 65535;
        assert!(validate_shape(&bad, &p.rho, 0, 0, &p.coefficients).is_ok());
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.counts.push(256);
        assert!(validate_shape(&bad, &p.rho, 0, 0, &p.coefficients).is_ok());
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.coefficients[0] = NTT_MODULUS;
        let expected = bad.coefficients.clone();
        assert!(validate_shape(&bad, &p.rho, 0, 0, &expected).is_ok());
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &expected).is_err());
        let mut bad = p.clone();
        bad.xof.output[0] ^= 1;
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients).is_err());
    }
    fn residuals(air: &MatrixPolyAir, row: &[BaseElement]) -> Vec<BaseElement> {
        let mut out = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(
            &EvaluationFrame::from_rows(row.to_vec(), row.to_vec()),
            &[],
            &mut out,
        );
        out
    }
    fn synthetic() -> Inputs {
        let mut stream = Vec::new();
        for value in [
            0,
            NTT_MODULUS - 1,
            NTT_MODULUS,
            0x7fffff,
            0x800000,
            0xffffff,
        ] {
            stream.extend_from_slice(&value.to_le_bytes()[..3]);
        }
        for i in 3u32..256 {
            let value = i | if i % 2 == 0 { 0x800000 } else { 0 };
            stream.extend_from_slice(&value.to_le_bytes()[..3]);
        }
        sample(&[0; 32], 0, 0, &stream).unwrap()
    }
    #[test]
    fn threshold_top_bit_and_all_positions_have_valid_boundary_rows() {
        let i = synthetic();
        assert_eq!(i.attempts(), 259);
        assert_eq!(i.coefficients[..3], [0, NTT_MODULUS - 1, 0]);
        assert_eq!(i.coefficients[3..], (3..256).collect::<Vec<u32>>());
        let mut rows = public_rows(&i);
        let air = MatrixPolyAir::new(
            TraceInfo::new(TRACE_WIDTH, i.trace_length()),
            BatchInputs::single(i),
            default_proof_options(),
        );
        for row in &mut rows {
            witness(row);
            assert!(residuals(&air, row).iter().all(|&v| v == BaseElement::ZERO));
        }
        let mut bad = rows[1].clone();
        bad[TARGET] = BaseElement::new(NTT_MODULUS.into());
        assert_ne!(residuals(&air, &bad)[44], BaseElement::ZERO);
        let mut bad = rows[0].clone();
        bad[COUNT] = BaseElement::new(256);
        witness(&mut bad);
        assert_ne!(residuals(&air, &bad)[42], BaseElement::ZERO);
        assert_eq!(air.get_assertions().len(), ACCEPT);
    }
    #[test]
    fn boolean_bounds_stop_false_q_acceptance_and_wrong_high_bit_mask() {
        let i = synthetic();
        let mut rows = public_rows(&i);
        for r in &mut rows {
            witness(r);
        }
        let air = MatrixPolyAir::new(
            TraceInfo::new(TRACE_WIDTH, i.trace_length()),
            BatchInputs::single(i),
            default_proof_options(),
        );
        let mut bad = rows[2].clone();
        bad[ACCEPT] = BaseElement::ONE;
        bad[NEXT] = bad[COUNT] + BaseElement::ONE;
        bad[TARGET] = BaseElement::new(NTT_MODULUS.into());
        bad[GAP..GAP + 23].fill(BaseElement::ZERO);
        bad[GAP] = BaseElement::new(1 << 23);
        let out = residuals(&air, &bad);
        assert!(out[40..].iter().all(|&v| v == BaseElement::ZERO));
        assert!(out[..40].iter().any(|&v| v != BaseElement::ZERO));
        let mut bad = rows[4].clone();
        bad[LOW..LOW + 7].fill(BaseElement::ZERO);
        bad[LOW] = BaseElement::new(128);
        bad[HIGH] = BaseElement::ZERO;
        bad[ACCEPT] = BaseElement::ZERO;
        bad[NEXT] = bad[COUNT];
        let gap = (1u32 << 23) - NTT_MODULUS;
        for bit in 0..23 {
            bad[GAP + bit] = BaseElement::new(((gap >> bit) & 1).into());
        }
        let out = residuals(&air, &bad);
        assert!(out[40..].iter().all(|&v| v == BaseElement::ZERO));
        assert!(out[..40].iter().any(|&v| v != BaseElement::ZERO));
    }
    #[test]
    fn short_counter_sequence_rejects_before_proof_decoding() {
        let coefficients = vec![0; 256];
        let p = MatrixPolynomialProof {
            version: 1,
            rho: vec![0; 32],
            row: 0,
            column: 0,
            xof: ShakeProof {
                version: 1,
                kind: ShakeKind::Shake128,
                message: vec![0; 34],
                output: vec![0; 840],
                permutations: vec![],
                sponge_proof_bytes: vec![0],
                permutation_batches: vec![],
            },
            counts: vec![0, 256],
            coefficients: coefficients.clone(),
            proof_bytes: vec![0],
        };
        assert!(validate_shape(&p, &[0; 32], 0, 0, &coefficients).is_err());
        assert!(verify_matrix_polynomial(&p, &[0; 32], 0, 0, &coefficients)
            .unwrap_err()
            .contains("shape"));
    }
    #[test]
    fn shapes_versions_payloads_and_child_proofs_reject() {
        assert!(prove_matrix_polynomial(&[0; 31], 0, 0).is_err());
        assert!(prove_matrix_polynomial(&[0; 32], 6, 0).is_err());
        assert!(prove_matrix_polynomial(&[0; 32], 0, 5).is_err());
        let p = &cases()[0];
        let mut bad = p.clone();
        bad.version = 2;
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.counts.clear();
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.proof_bytes.truncate(bad.proof_bytes.len() / 2);
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = vec![0; MAX_PROOF_BYTES + 1];
        assert!(verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = p.xof.sponge_proof_bytes.clone();
        assert!(
            verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients)
                .unwrap_err()
                .contains("layout")
        );
        let mut bad = p.clone();
        bad.xof
            .sponge_proof_bytes
            .truncate(bad.xof.sponge_proof_bytes.len() / 2);
        assert!(
            verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients)
                .unwrap_err()
                .contains("SHAKE")
        );
        let mut bad = p.clone();
        bad.xof.permutations[4].rounds[11].theta[24] ^= 1;
        assert!(
            verify_matrix_polynomial(&bad, &p.rho, 0, 0, &p.coefficients)
                .unwrap_err()
                .contains("Keccak verification")
        );
    }
    #[test]
    fn complete_matrix_requires_all_distinct_ordered_coordinates() {
        let p = &cases()[0];
        let expected = vec![p.coefficients.clone(); 30];
        let mut matrix = MatrixProof {
            version: 1,
            rho: p.rho.clone(),
            polynomials: vec![p.clone(); 30],
            batches: None,
        };
        assert!(verify_matrix(&matrix, &p.rho, &expected)
            .unwrap_err()
            .contains("coverage"));
        for (i, poly) in matrix.polynomials.iter_mut().enumerate() {
            poly.row = (i / 5) as u8;
            poly.column = (i % 5) as u8;
        }
        matrix.polynomials.swap(0, 1);
        assert!(verify_matrix(&matrix, &p.rho, &expected)
            .unwrap_err()
            .contains("coverage"));
        matrix.polynomials.pop();
        assert!(verify_matrix(&matrix, &p.rho, &expected).is_err());
    }
}
