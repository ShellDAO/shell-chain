//! Public, byte-oriented SHAKE128/256 and Keccak-256 proofs over the Keccak AIR.
//!
//! Padding, XOR absorption, all permutation links and rate extraction are
//! constrained. Public messages/states are bounded development inputs, not
//! private or compact attestations, nor a complete PQ signature verifier.

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
    permutation_witness, prove_keccak_batch, prove_keccak_permutation, verify_keccak_batch,
    verify_keccak_permutation, KeccakBatchProof, KeccakPermutationProof, MAX_KECCAK_BATCH,
};

pub const MAX_SHAKE_MESSAGE_BYTES: usize = 4096;
pub const MAX_SHAKE_OUTPUT_BYTES: usize = 4096;
const BEFORE: usize = 0;
const MESSAGE: usize = 8;
const ABSORBED: usize = 16;
const PERMUTED: usize = 24;
const OUTPUT: usize = 32;
const DOMAIN: usize = 40;
const TERMINAL: usize = 41;
const EMIT: usize = 42;
const TRACE_WIDTH: usize = 43;
const CONSTRAINTS: usize = 16;
const MAX_PROOF_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShakeKind {
    Shake128,
    Shake256,
    /// Legacy Keccak-256: rate 136, suffix 0x01, exactly 32 output bytes.
    Keccak256,
}
impl ShakeKind {
    pub fn rate(self) -> usize {
        match self {
            Self::Shake128 => 168,
            Self::Shake256 | Self::Keccak256 => 136,
        }
    }

    fn suffix(self) -> u8 {
        match self {
            Self::Shake128 | Self::Shake256 => 0x1f,
            Self::Keccak256 => 0x01,
        }
    }
}

/// Compositional sponge proof. The bridge AIR checks padding/absorption/output;
/// Version one proves permutations separately; version two proves bounded groups
/// with the same complete Keccak-f1600 round constraints.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakeProof {
    pub version: u8,
    pub kind: ShakeKind,
    pub message: Vec<u8>,
    pub output: Vec<u8>,
    pub permutations: Vec<KeccakPermutationProof>,
    pub sponge_proof_bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permutation_batches: Vec<KeccakBatchProof>,
}

/// A bridge proof for at most eight ordered SHAKE128 streams. Permutations are
/// authenticated separately by the complete matrix verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpongeBatchProof {
    pub version: u8,
    pub proof_bytes: Vec<u8>,
}
pub(crate) const MAX_SPONGE_BATCH: usize = 8;

/// Prover-only routing construction; version three cannot verify standalone.
pub(crate) fn matrix_shake_witness(
    message: &[u8],
    output_bytes: usize,
) -> Result<ShakeProof, String> {
    let kind = ShakeKind::Shake128;
    let (absorbs, total) = schedule(kind, message.len(), output_bytes)?;
    let rate = kind.rate();
    let mut state = [0u64; 25];
    let mut permutations = Vec::with_capacity(total);
    let mut output = Vec::with_capacity(output_bytes);
    for step in 0..total {
        if step < absorbs {
            for offset in 0..rate {
                let index = step * rate + offset;
                let mut value = message.get(index).copied().unwrap_or(0);
                if index == message.len() {
                    value ^= kind.suffix();
                }
                if step == absorbs - 1 && offset == rate - 1 {
                    value ^= 0x80;
                }
                state[offset / 8] ^= u64::from(value) << (8 * (offset % 8));
            }
        }
        let permutation = permutation_witness(&state);
        state = permutation.rounds[23].output;
        permutations.push(permutation);
        if step >= absorbs - 1 {
            for offset in 0..rate.min(output_bytes - output.len()) {
                output.push(byte(&state, offset));
            }
        }
    }
    Ok(ShakeProof {
        version: 3,
        kind,
        message: message.to_vec(),
        output,
        permutations,
        sponge_proof_bytes: Vec::new(),
        permutation_batches: Vec::new(),
    })
}

pub(crate) fn validate_matrix_shake(p: &ShakeProof) -> Result<(), String> {
    let (_, count) = schedule(ShakeKind::Shake128, p.message.len(), p.output.len())?;
    if p.version != 3
        || p.kind != ShakeKind::Shake128
        || !p.sponge_proof_bytes.is_empty()
        || !p.permutation_batches.is_empty()
        || p.permutations.len() != count
        || p.permutations
            .iter()
            .any(|v| v.version != 1 || v.rounds.len() != 24 || !v.proof_bytes.is_empty())
    {
        return Err("invalid matrix SHAKE routing shape".into());
    }
    Ok(())
}
fn sponge_batch_inputs(streams: &[ShakeProof]) -> Result<BatchInputs, String> {
    if streams.is_empty() || streams.len() > MAX_SPONGE_BATCH {
        return Err("invalid sponge batch count".into());
    }
    let streams = streams
        .iter()
        .map(|p| {
            validate_matrix_shake(p)?;
            Ok(Inputs {
                kind: p.kind,
                message: p.message.clone(),
                output: p.output.clone(),
                steps: p
                    .permutations
                    .iter()
                    .map(|v| Endpoints {
                        input: v.input,
                        output: v.rounds[23].output,
                    })
                    .collect(),
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(BatchInputs {
        streams,
        aggregate: true,
    })
}
pub(crate) fn prove_sponge_batch(streams: &[ShakeProof]) -> Result<SpongeBatchProof, String> {
    let inputs = sponge_batch_inputs(streams)?;
    for p in streams {
        let expected = matrix_shake_witness(&p.message, p.output.len())?;
        if expected.output != p.output
            || expected
                .permutations
                .iter()
                .zip(&p.permutations)
                .any(|(a, b)| a.input != b.input || a.rounds != b.rounds)
        {
            return Err("invalid sponge batch witness".into());
        }
    }
    let prover = SpongeProver {
        inputs: inputs.clone(),
        options: default_proof_options(),
    };
    let proof = prover
        .prove(trace(&inputs))
        .map_err(|e| format!("sponge batch proof: {e:?}"))?;
    Ok(SpongeBatchProof {
        version: 1,
        proof_bytes: proof.to_bytes(),
    })
}
pub(crate) fn verify_sponge_batch(
    p: &SpongeBatchProof,
    streams: &[ShakeProof],
) -> Result<(), String> {
    let inputs = sponge_batch_inputs(streams)?;
    if p.version != 1 || p.proof_bytes.is_empty() || p.proof_bytes.len() > MAX_PROOF_BYTES {
        return Err("invalid sponge batch version or proof size".into());
    }
    let proof =
        Proof::from_bytes(&p.proof_bytes).map_err(|e| format!("sponge batch decode: {e:?}"))?;
    if proof.trace_info() != &TraceInfo::new(TRACE_WIDTH, inputs.trace_length()) {
        return Err("unexpected sponge batch trace layout".into());
    }
    verify::<SpongeAir, Hasher, Coin, Commitment>(
        proof,
        inputs,
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("sponge batch verification: {e:?}"))
}

#[derive(Clone)]
struct Endpoints {
    input: [u64; 25],
    output: [u64; 25],
}
#[derive(Clone)]
struct Inputs {
    kind: ShakeKind,
    message: Vec<u8>,
    output: Vec<u8>,
    steps: Vec<Endpoints>,
}
impl Inputs {
    fn slots(&self) -> usize {
        (self.steps.len() * 200).next_power_of_two()
    }
    fn trace_length(&self) -> usize {
        self.slots() * 2
    }
}
impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = vec![
            BaseElement::new(u64::from_le_bytes(if self.kind == ShakeKind::Keccak256 {
                *b"KECSP001"
            } else {
                *b"SHKSP001"
            }) as u128),
            BaseElement::new(self.kind.rate() as u128),
            BaseElement::new(self.message.len() as u128),
            BaseElement::new(self.output.len() as u128),
            BaseElement::new(self.steps.len() as u128),
        ];
        result.extend(
            self.message
                .iter()
                .chain(&self.output)
                .map(|&v| BaseElement::new(v.into())),
        );
        for step in &self.steps {
            result.extend(
                step.input
                    .iter()
                    .chain(&step.output)
                    .map(|&v| BaseElement::new(v.into())),
            );
        }
        result
    }
}

fn schedule(kind: ShakeKind, message: usize, output: usize) -> Result<(usize, usize), String> {
    if kind == ShakeKind::Keccak256 && output != 32 {
        return Err("Keccak-256 requires exactly 32 output bytes".into());
    }
    if message > MAX_SHAKE_MESSAGE_BYTES || output > MAX_SHAKE_OUTPUT_BYTES {
        return Err("SHAKE development message/output resource bound exceeded".into());
    }
    let absorbs = message / kind.rate() + 1;
    Ok((
        absorbs,
        absorbs + output.div_ceil(kind.rate()).saturating_sub(1),
    ))
}
fn byte(lanes: &[u64; 25], index: usize) -> u8 {
    lanes[index / 8].to_le_bytes()[index % 8]
}
fn bits(row: &mut [BaseElement], column: usize, byte: u8) {
    for bit in 0..8 {
        row[column + bit] = BaseElement::new(((byte >> bit) & 1).into());
    }
}

// Fixed public routing and bit extraction only. The XOR, domain suffix and
// terminal padding relations are evaluated inside the bridge AIR below.
fn public_rows(inputs: &Inputs) -> Vec<Vec<BaseElement>> {
    let mut rows = vec![vec![BaseElement::ZERO; TRACE_WIDTH]; inputs.slots()];
    let rate = inputs.kind.rate();
    let absorbs = inputs.message.len() / rate + 1;
    for (step, endpoints) in inputs.steps.iter().enumerate() {
        let previous = if step == 0 {
            [0; 25]
        } else {
            inputs.steps[step - 1].output
        };
        for offset in 0..200 {
            let row = &mut rows[step * 200 + offset];
            bits(row, BEFORE, byte(&previous, offset));
            bits(row, ABSORBED, byte(&endpoints.input, offset));
            bits(row, PERMUTED, byte(&endpoints.output, offset));
            if step < absorbs && offset < rate {
                let index = step * rate + offset;
                bits(
                    row,
                    MESSAGE,
                    inputs.message.get(index).copied().unwrap_or(0),
                );
                row[DOMAIN] = BaseElement::new(u128::from(index == inputs.message.len()));
                row[TERMINAL] =
                    BaseElement::new(u128::from(step == absorbs - 1 && offset == rate - 1));
            }
            if step >= absorbs - 1 && offset < rate {
                let index = (step - (absorbs - 1)) * rate + offset;
                if let Some(&value) = inputs.output.get(index) {
                    row[EMIT] = BaseElement::ONE;
                    bits(row, OUTPUT, value);
                }
            }
        }
    }
    rows
}
// A separate transcript binds every ordered child statement. Legacy inputs
// retain their exact original public vector, padding and trace layout.
#[derive(Clone)]
struct BatchInputs {
    streams: Vec<Inputs>,
    aggregate: bool,
}
impl BatchInputs {
    fn single(input: Inputs) -> Self {
        Self {
            streams: vec![input],
            aggregate: false,
        }
    }
    fn slots(&self) -> usize {
        if self.aggregate {
            self.streams
                .iter()
                .map(|p| p.steps.len() * 200)
                .sum::<usize>()
                .next_power_of_two()
        } else {
            self.streams[0].slots()
        }
    }
    fn trace_length(&self) -> usize {
        self.slots() * 2
    }
}
impl ToElements<BaseElement> for BatchInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        if !self.aggregate {
            return self.streams[0].to_elements();
        }
        let mut values = vec![
            BaseElement::new(u64::from_le_bytes(*b"SHKSPB01") as u128),
            BaseElement::new(self.streams.len() as u128),
        ];
        for input in &self.streams {
            values.extend(input.to_elements());
        }
        values
    }
}
fn batch_rows(inputs: &BatchInputs) -> Vec<Vec<BaseElement>> {
    if !inputs.aggregate {
        return public_rows(&inputs.streams[0]);
    }
    let mut rows = Vec::with_capacity(inputs.slots());
    for p in &inputs.streams {
        rows.extend(public_rows(p).into_iter().take(p.steps.len() * 200));
    }
    rows.resize(inputs.slots(), vec![BaseElement::ZERO; TRACE_WIDTH]);
    rows
}
struct SpongeAir {
    context: AirContext<BaseElement>,
    inputs: BatchInputs,
}
fn xor<E: FieldElement>(a: E, b: E) -> E {
    a + b - (a * b + a * b)
}
impl Air for SpongeAir {
    type BaseField = BaseElement;
    type PublicInputs = BatchInputs;
    fn new(info: TraceInfo, inputs: BatchInputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, inputs.trace_length()));
        let degrees = (0..CONSTRAINTS)
            .map(|i| {
                TransitionConstraintDegree::new(
                    if (i < 8 && inputs.streams[0].kind.suffix() & (1 << i) != 0) || i == 7 {
                        3
                    } else {
                        2
                    },
                )
            })
            .collect();
        Self {
            context: AirContext::new(info, degrees, TRACE_WIDTH, options),
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
        for bit in 0..8 {
            let mut block = r[MESSAGE + bit];
            if self.inputs.streams[0].kind.suffix() & (1 << bit) != 0 {
                block = xor(block, r[DOMAIN]);
            }
            if bit == 7 {
                block = xor(block, r[TERMINAL]);
            }
            result[bit] = r[ABSORBED + bit] - xor(r[BEFORE + bit], block);
            result[8 + bit] = r[EMIT] * (r[OUTPUT + bit] - r[PERMUTED + bit]);
        }
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = batch_rows(&self.inputs);
        (0..TRACE_WIDTH)
            .map(|col| Assertion::sequence(col, 0, 2, rows.iter().map(|r| r[col]).collect()))
            .collect()
    }
    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }
}
fn trace(inputs: &BatchInputs) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(TRACE_WIDTH, inputs.trace_length());
    for (slot, row) in batch_rows(inputs).into_iter().enumerate() {
        trace.update_row(slot * 2, &row);
        trace.update_row(slot * 2 + 1, &row);
    }
    // The last unused odd row is the only unconstrained trace padding row.
    let mut hash = blake3::Hasher::new_derive_key("Shell-Chain SHAKE sponge trace padding v1");
    for value in inputs.to_elements() {
        hash.update(&value.as_int().to_le_bytes());
    }
    let mut bytes = [0u8; 16 * TRACE_WIDTH];
    hash.finalize_xof().fill(&mut bytes);
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

struct SpongeProver {
    inputs: BatchInputs,
    options: ProofOptions,
}

impl Prover for SpongeProver {
    type BaseField = BaseElement;
    type Air = SpongeAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, SpongeAir, E>;

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
        air: &'a SpongeAir,
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

/// Prove a bounded byte-oriented SHAKE computation, including all sponge links.
pub fn prove_shake(
    kind: ShakeKind,
    message: &[u8],
    output_bytes: usize,
) -> Result<ShakeProof, String> {
    prove_shake_inner(kind, message, output_bytes, false)
}

/// Bound each aggregate to eight permutations while retaining every sponge
/// absorption, padding, squeeze and permutation constraint.
pub fn prove_shake_batched(
    kind: ShakeKind,
    message: &[u8],
    output_bytes: usize,
) -> Result<ShakeProof, String> {
    prove_shake_inner(kind, message, output_bytes, true)
}

fn prove_shake_inner(
    kind: ShakeKind,
    message: &[u8],
    output_bytes: usize,
    aggregate: bool,
) -> Result<ShakeProof, String> {
    let (absorbs, total) = schedule(kind, message.len(), output_bytes)?;
    let rate = kind.rate();
    let mut state = [0u64; 25];
    let mut permutations = Vec::with_capacity(total);
    let mut steps = Vec::with_capacity(total);
    let mut output = Vec::with_capacity(output_bytes);
    for step in 0..total {
        if step < absorbs {
            for offset in 0..rate {
                let index = step * rate + offset;
                let mut value = message.get(index).copied().unwrap_or(0);
                if index == message.len() {
                    value ^= kind.suffix();
                }
                if step == absorbs - 1 && offset == rate - 1 {
                    value ^= 0x80;
                }
                state[offset / 8] ^= u64::from(value) << (8 * (offset % 8));
            }
        }
        let permutation = if aggregate {
            permutation_witness(&state)
        } else {
            prove_keccak_permutation(&state)?
        };
        let end = permutation
            .rounds
            .last()
            .ok_or("missing Keccak round")?
            .output;
        steps.push(Endpoints {
            input: state,
            output: end,
        });
        state = end;
        permutations.push(permutation);
        if step >= absorbs - 1 {
            for offset in 0..rate.min(output_bytes - output.len()) {
                output.push(byte(&state, offset));
            }
        }
    }
    let inputs = Inputs {
        kind,
        message: message.to_vec(),
        output: output.clone(),
        steps,
    };
    let prover = SpongeProver {
        inputs: BatchInputs::single(inputs.clone()),
        options: default_proof_options(),
    };
    let inner = prover
        .prove(trace(&BatchInputs::single(inputs.clone())))
        .map_err(|e| format!("SHAKE sponge proof: {e:?}"))?;
    let permutation_batches = if aggregate {
        permutations
            .chunks(MAX_KECCAK_BATCH)
            .map(prove_keccak_batch)
            .collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    Ok(ShakeProof {
        version: if aggregate { 2 } else { 1 },
        kind,
        message: message.to_vec(),
        output,
        permutations,
        sponge_proof_bytes: inner.to_bytes(),
        permutation_batches,
    })
}

/// Verify the sponge AIR and every full permutation with caller-bound endpoints.
/// Does not evaluate a native SHAKE hash, padding XOR or Keccak permutation.
pub fn verify_shake(
    proof: &ShakeProof,
    kind: ShakeKind,
    expected_message: &[u8],
    expected_output: &[u8],
) -> Result<(), String> {
    let (_, total) = schedule(kind, expected_message.len(), expected_output.len())?;
    let aggregate = proof.version == 2;
    if !matches!(proof.version, 1 | 2)
        || if aggregate {
            proof.permutation_batches.len() != total.div_ceil(MAX_KECCAK_BATCH)
        } else {
            !proof.permutation_batches.is_empty()
        }
        || proof.kind != kind
        || proof.message != expected_message
        || proof.output != expected_output
        || proof.permutations.len() != total
        || proof.sponge_proof_bytes.is_empty()
        || proof.sponge_proof_bytes.len() > MAX_PROOF_BYTES
        || proof.permutation_batches.iter().any(|p| {
            p.version != 1 || p.proof_bytes.is_empty() || p.proof_bytes.len() > MAX_PROOF_BYTES
        })
        || proof.permutations.iter().any(|p| {
            p.version != 1
                || p.rounds.len() != 24
                || if aggregate {
                    !p.proof_bytes.is_empty()
                } else {
                    p.proof_bytes.is_empty()
                }
                || p.proof_bytes.len() > MAX_PROOF_BYTES
        })
    {
        return Err("invalid SHAKE version, endpoints, step count or payload shape".into());
    }
    let steps: Vec<_> = proof
        .permutations
        .iter()
        .map(|p| Endpoints {
            input: p.input,
            output: p.rounds[23].output,
        })
        .collect();
    let inputs = Inputs {
        kind,
        message: proof.message.clone(),
        output: proof.output.clone(),
        steps,
    };
    let inner = Proof::from_bytes(&proof.sponge_proof_bytes)
        .map_err(|e| format!("SHAKE sponge proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, inputs.trace_length()) {
        return Err("unexpected SHAKE sponge trace layout".into());
    }
    verify::<SpongeAir, Hasher, Coin, Commitment>(
        inner,
        BatchInputs::single(inputs.clone()),
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("SHAKE sponge verification: {e:?}"))?;
    if aggregate {
        for (batch, permutations) in proof
            .permutation_batches
            .iter()
            .zip(proof.permutations.chunks(MAX_KECCAK_BATCH))
        {
            verify_keccak_batch(batch, permutations)?;
        }
    } else {
        for (p, endpoints) in proof.permutations.iter().zip(inputs.steps) {
            verify_keccak_permutation(p, &endpoints.input, &endpoints.output)?;
        }
    }
    Ok(())
}

/// Prove the legacy Keccak-256 used by the native account trie. SHAKE proof
/// transcripts and their existing serialized bytes retain their original tag.
pub fn prove_keccak256(message: &[u8]) -> Result<ShakeProof, String> {
    prove_shake(ShakeKind::Keccak256, message, 32)
}

/// Verify every padding/absorption/output relation and complete permutation.
/// No native Keccak hash is evaluated as an acceptance fallback.
pub fn verify_keccak256(
    proof: &ShakeProof,
    expected_message: &[u8],
    expected_output: &[u8; 32],
) -> Result<(), String> {
    verify_shake(
        proof,
        ShakeKind::Keccak256,
        expected_message,
        expected_output,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128, Shake256,
    };
    use std::sync::OnceLock;

    fn native(kind: ShakeKind, message: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        match kind {
            ShakeKind::Shake128 => {
                let mut h = Shake128::default();
                h.update(message);
                h.finalize_xof().read(&mut out);
            }
            ShakeKind::Shake256 => {
                let mut h = Shake256::default();
                h.update(message);
                h.finalize_xof().read(&mut out);
            }
            ShakeKind::Keccak256 => {
                use sha3::Digest;
                out.copy_from_slice(&sha3::Keccak256::digest(message));
            }
        }
        out
    }
    fn cases() -> &'static Vec<ShakeProof> {
        static CASES: OnceLock<Vec<ShakeProof>> = OnceLock::new();
        CASES.get_or_init(|| {
            [
                (ShakeKind::Shake256, vec![], 0),
                (ShakeKind::Shake256, vec![0xa5; 135], 137),
                (ShakeKind::Shake256, vec![0x12; 136], 136),
                (ShakeKind::Shake128, vec![0x34; 168], 169),
                (ShakeKind::Shake128, vec![], 32),
            ]
            .into_iter()
            .map(|(kind, message, len)| {
                let p = prove_shake(kind, &message, len).unwrap();
                assert_eq!(p.output, native(kind, &message, len));
                p
            })
            .collect()
        })
    }
    fn inputs(p: &ShakeProof) -> Inputs {
        Inputs {
            kind: p.kind,
            message: p.message.clone(),
            output: p.output.clone(),
            steps: p
                .permutations
                .iter()
                .map(|x| Endpoints {
                    input: x.input,
                    output: x.rounds[23].output,
                })
                .collect(),
        }
    }
    #[test]
    fn singleton_bridge_batch_rejects_standalone_domain_with_identical_inputs() {
        let stream = matrix_shake_witness(&[0x51; 34], 840).unwrap();
        let batch = sponge_batch_inputs(std::slice::from_ref(&stream)).unwrap();
        let single = BatchInputs::single(batch.streams[0].clone());
        assert_eq!(single.trace_length(), batch.trace_length());
        let proof = SpongeProver {
            inputs: single.clone(),
            options: default_proof_options(),
        }
        .prove(trace(&single))
        .unwrap();
        assert!(verify_sponge_batch(
            &SpongeBatchProof {
                version: 1,
                proof_bytes: proof.to_bytes()
            },
            std::slice::from_ref(&stream)
        )
        .is_err());
        let proof = prove_sponge_batch(std::slice::from_ref(&stream)).unwrap();
        verify_sponge_batch(&proof, std::slice::from_ref(&stream)).unwrap();
        let inner = Proof::from_bytes(&proof.proof_bytes).unwrap();
        assert!(verify::<SpongeAir, Hasher, Coin, Commitment>(
            inner,
            single,
            &AcceptableOptions::OptionSet(vec![default_proof_options()])
        )
        .is_err());
    }
    #[test]
    fn aggregate_sponge_crosses_chunk_boundary_and_rejects_mixed_transcripts() {
        let message = [0x97; 34];
        let p = prove_shake_batched(ShakeKind::Shake128, &message, 9 * 168).unwrap();
        let expected = native(p.kind, &message, p.output.len());
        assert_eq!(p.output, expected);
        assert_eq!(p.permutation_batches.len(), 2);
        verify_shake(&p, p.kind, &message, &expected).unwrap();
        let compact = crate::compact_canonical::encode_component(&p).unwrap();
        let decoded: ShakeProof = crate::compact_canonical::decode_component(&compact).unwrap();
        verify_shake(&decoded, p.kind, &message, &expected).unwrap();
        for index in [0, 7, 8] {
            let mut bad = p.clone();
            bad.permutations[index].rounds[12].theta[24] ^= 1;
            assert!(verify_shake(&bad, p.kind, &message, &expected).is_err());
        }
        let mut bad = p.clone();
        bad.permutation_batches.swap(0, 1);
        assert!(verify_shake(&bad, p.kind, &message, &expected).is_err());
        let mut bad = p.clone();
        bad.permutation_batches.pop();
        assert!(verify_shake(&bad, p.kind, &message, &expected).is_err());
        let mut bad = p.clone();
        bad.version = 1;
        assert!(verify_shake(&bad, p.kind, &message, &expected).is_err());
        let mut legacy = cases()[0].clone();
        assert!(!serde_json::to_string(&legacy)
            .unwrap()
            .contains("permutation_batches"));
        legacy.version = 2;
        assert!(verify_shake(&legacy, legacy.kind, &legacy.message, &legacy.output).is_err());
        let mut bad = p.clone();
        bad.permutations[8].proof_bytes = cases()[0].permutations[0].proof_bytes.clone();
        assert!(verify_shake(&bad, p.kind, &message, &expected).is_err());
    }
    #[test]
    fn empty_last_byte_exact_rate_and_extended_outputs_real_proofs() {
        for p in cases() {
            verify_shake(
                p,
                p.kind,
                &p.message,
                &native(p.kind, &p.message, p.output.len()),
            )
            .unwrap();
        }
        assert_eq!(
            cases()
                .iter()
                .map(|p| p.permutations.len())
                .collect::<Vec<_>>(),
            vec![1, 2, 2, 3, 1]
        );
        let p = &cases()[1];
        let restored: ShakeProof = serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
        verify_shake(&restored, p.kind, &p.message, &p.output).unwrap();
        let expected = [
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
            0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac,
            0xfa, 0x66, 0xef, 0x26,
        ];
        assert_eq!(cases()[4].output, expected);
    }
    #[test]
    fn suffix_collision_and_exact_rate_get_correct_extra_blocks() {
        let p = &cases()[1];
        assert_eq!(byte(&p.permutations[0].input, 135), 0x1f ^ 0x80);
        let p = &cases()[2];
        let previous = p.permutations[0].rounds[23].output;
        let next = p.permutations[1].input;
        assert_eq!(byte(&previous, 0) ^ byte(&next, 0), 0x1f);
        assert_eq!(byte(&previous, 135) ^ byte(&next, 135), 0x80);
        for i in 136..200 {
            assert_eq!(byte(&previous, i), byte(&next, i));
        }
        let p = &cases()[3];
        assert_eq!(p.permutations[2].input, p.permutations[1].rounds[23].output);
    }
    #[test]
    fn changed_message_output_capacity_and_squeeze_links_reject() {
        let p = &cases()[1];
        let mut bad = p.clone();
        bad.message[0] ^= 1;
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.output[136] ^= 1;
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.permutations[0].input[24] ^= 1u64 << 63;
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.permutations[1].input[0] ^= 1;
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.permutations.swap(0, 1);
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.permutations[0].rounds[11].theta[24] ^= 1;
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output)
            .unwrap_err()
            .contains("Keccak verification"));
    }
    #[test]
    fn variant_endpoint_shape_version_and_payload_guards() {
        let p = &cases()[4];
        assert!(verify_shake(p, ShakeKind::Shake256, &p.message, &p.output).is_err());
        let mut bad = p.clone();
        bad.kind = ShakeKind::Shake256;
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        assert!(verify_shake(p, p.kind, b"changed", &p.output).is_err());
        assert!(verify_shake(p, p.kind, &p.message, &[0; 32]).is_err());
        let mut bad = p.clone();
        bad.version = 2;
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.permutations.clear();
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.permutations.push(p.permutations[0].clone());
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.permutations[0].rounds.pop();
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.sponge_proof_bytes
            .truncate(bad.sponge_proof_bytes.len() / 2);
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.sponge_proof_bytes = vec![0; MAX_PROOF_BYTES + 1];
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output).is_err());
        let mut bad = p.clone();
        bad.sponge_proof_bytes = p.permutations[0].proof_bytes.clone();
        assert!(verify_shake(&bad, bad.kind, &bad.message, &bad.output)
            .unwrap_err()
            .contains("layout"));
    }
    #[test]
    fn resource_bounds_are_checked_before_any_proving() {
        for kind in [ShakeKind::Shake128, ShakeKind::Shake256] {
            assert!(prove_shake(kind, &vec![0; MAX_SHAKE_MESSAGE_BYTES + 1], 1).is_err());
            assert!(prove_shake(kind, &[], MAX_SHAKE_OUTPUT_BYTES + 1).is_err());
            let (_, total) =
                schedule(kind, MAX_SHAKE_MESSAGE_BYTES, MAX_SHAKE_OUTPUT_BYTES).unwrap();
            assert!(total <= 61);
            assert!((total * 200).next_power_of_two() * 2 <= 32768);
        }
    }
    fn residuals(air: &SpongeAir, row: &[BaseElement]) -> Vec<BaseElement> {
        let mut out = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(
            &EvaluationFrame::from_rows(row.to_vec(), row.to_vec()),
            &[],
            &mut out,
        );
        out
    }
    #[test]
    fn bridge_constraints_bind_raw_bits_padding_capacity_and_emission() {
        let inputs = inputs(&cases()[1]);
        let rows = public_rows(&inputs);
        let air = SpongeAir::new(
            TraceInfo::new(TRACE_WIDTH, inputs.trace_length()),
            BatchInputs::single(inputs),
            default_proof_options(),
        );
        assert!(rows
            .iter()
            .all(|r| residuals(&air, r).iter().all(|&x| x == BaseElement::ZERO)));
        for (slot, col) in [
            (135, DOMAIN),
            (135, TERMINAL),
            (0, MESSAGE),
            (199, ABSORBED + 7),
            (200, BEFORE),
            (200, ABSORBED),
            (200, OUTPUT),
        ] {
            let mut row = rows[slot].clone();
            row[col] = BaseElement::ONE - row[col];
            assert!(
                residuals(&air, &row)
                    .iter()
                    .any(|&x| x != BaseElement::ZERO),
                "slot {slot} col {col}"
            );
        }
        assert_eq!(air.get_assertions().len(), TRACE_WIDTH);
    }
}
