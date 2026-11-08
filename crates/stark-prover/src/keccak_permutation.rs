//! Full public Keccak-f1600 permutation AIR (FIPS 202, sections 3.1–3.4).
//!
//! All 24 rounds and all 1600 bits are constrained. Intermediate states are
//! public routing inputs; this is not a private proof or a SHAKE sponge proof.

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

const ROUNDS: usize = 24;
const SLOTS: usize = 2048;
const TRACE_LENGTH: usize = SLOTS * 2;
const ACTIVE: usize = 0;
const INPUT: usize = 1;
const PARITY: usize = 26;
const PREVIOUS_PARITY: usize = 31;
const THETA: usize = 36;
const ROTATED: usize = 61;
const OUTPUT: usize = 86;
const ROUND_CONSTANT: usize = 111;
const TRACE_WIDTH: usize = 112;
const CONSTRAINTS: usize = 55;
pub const MAX_KECCAK_BATCH: usize = 8;

// Lane index is x + 5*y; the least significant bit has z = 0.
const ROTATION: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const RC: [u64; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermutationRound {
    pub parity: [u64; 5],
    pub theta: [u64; 25],
    pub output: [u64; 25],
}

/// Public execution artifact, including every intermediate routing state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeccakPermutationProof {
    pub version: u8,
    pub input: [u64; 25],
    pub rounds: Vec<PermutationRound>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone)]
struct Inputs {
    input: [u64; 25],
    rounds: Vec<PermutationRound>,
}

/// One ordered aggregate statement; individual artifacts contain routing states
/// only. Their empty proof fields cannot masquerade as standalone certificates.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeccakBatchProof {
    pub version: u8,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone)]
struct BatchInputs {
    permutations: Vec<Inputs>,
    aggregate: bool,
}
impl BatchInputs {
    fn slots(&self) -> usize {
        if self.aggregate {
            (self.permutations.len() * ROUNDS * 64).next_power_of_two()
        } else {
            SLOTS
        }
    }
    fn trace_length(&self) -> usize {
        self.slots() * 2
    }
}
impl ToElements<BaseElement> for BatchInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        if !self.aggregate {
            return self.permutations[0].to_elements();
        }
        let mut result = vec![
            BaseElement::new(u64::from_le_bytes(*b"KECBAT01") as u128),
            BaseElement::new(self.permutations.len() as u128),
        ];
        for permutation in &self.permutations {
            result.extend(permutation.to_elements());
        }
        result
    }
}

impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = vec![BaseElement::new(u64::from_le_bytes(*b"KECF1601") as u128)];
        result.extend(self.input.iter().map(|&v| BaseElement::new(v.into())));
        for round in &self.rounds {
            result.extend(
                round
                    .parity
                    .iter()
                    .chain(&round.theta)
                    .chain(&round.output)
                    .map(|&v| BaseElement::new(v.into())),
            );
        }
        result
    }
}

// Native arithmetic constructs the witness only, never verifies the statement.
fn witness(input: [u64; 25]) -> Inputs {
    let mut state = input;
    let mut rounds = Vec::with_capacity(ROUNDS);
    for constant in RC {
        let mut parity = [0; 5];
        for x in 0..5 {
            for y in 0..5 {
                parity[x] ^= state[x + 5 * y];
            }
        }
        let mut theta = [0; 25];
        let mut rotated = [0; 25];
        for y in 0..5 {
            for x in 0..5 {
                let lane = x + 5 * y;
                theta[lane] =
                    state[lane] ^ parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = theta[lane].rotate_left(ROTATION[lane]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] = rotated[x + 5 * y]
                    ^ ((!rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= constant;
        rounds.push(PermutationRound {
            parity,
            theta,
            output: state,
        });
    }
    Inputs { input, rounds }
}

// Only bit extraction and fixed wiring occur here: no XOR, AND, round execution,
// or native permutation check. Reused public values bind the cross-row edges.
fn permutation_rows(inputs: &Inputs) -> Vec<Vec<BaseElement>> {
    let bit = |value: u64, z: usize| BaseElement::new(((value >> z) & 1).into());
    let mut rows = vec![vec![BaseElement::ZERO; TRACE_WIDTH]; SLOTS];
    for (round, step) in inputs.rounds.iter().enumerate() {
        let state = if round == 0 {
            &inputs.input
        } else {
            &inputs.rounds[round - 1].output
        };
        for z in 0..64 {
            let row = &mut rows[round * 64 + z];
            row[ACTIVE] = BaseElement::ONE;
            row[ROUND_CONSTANT] = bit(RC[round], z);
            for x in 0..5 {
                row[PARITY + x] = bit(step.parity[x], z);
                row[PREVIOUS_PARITY + x] = bit(step.parity[x], (z + 63) % 64);
            }
            for y in 0..5 {
                for x in 0..5 {
                    let lane = x + 5 * y;
                    row[INPUT + lane] = bit(state[lane], z);
                    row[THETA + lane] = bit(step.theta[lane], z);
                    row[OUTPUT + lane] = bit(step.output[lane], z);
                    let source = (x + 3 * y) % 5 + 5 * x;
                    row[ROTATED + lane] = bit(
                        step.theta[source],
                        (z + 64 - ROTATION[source] as usize) % 64,
                    );
                }
            }
        }
    }
    rows
}

fn public_rows(inputs: &BatchInputs) -> Vec<Vec<BaseElement>> {
    if !inputs.aggregate {
        return permutation_rows(&inputs.permutations[0]);
    }
    let mut rows = Vec::with_capacity(inputs.slots());
    for permutation in &inputs.permutations {
        rows.extend(permutation_rows(permutation).into_iter().take(ROUNDS * 64));
    }
    rows.resize(inputs.slots(), vec![BaseElement::ZERO; TRACE_WIDTH]);
    rows
}

struct KeccakAir {
    context: AirContext<BaseElement>,
    inputs: BatchInputs,
}

fn xor<E: FieldElement>(a: E, b: E) -> E {
    a + b - (a * b + a * b)
}

impl Air for KeccakAir {
    type BaseField = BaseElement;
    type PublicInputs = BatchInputs;
    fn new(info: TraceInfo, inputs: BatchInputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, inputs.trace_length()));
        let degrees = (0..CONSTRAINTS)
            .map(|i| {
                TransitionConstraintDegree::new(if i < 5 {
                    6
                } else if i == 30 {
                    5
                } else {
                    4
                })
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
        for x in 0..5 {
            let mut parity = r[INPUT + x];
            for y in 1..5 {
                parity = xor(parity, r[INPUT + x + 5 * y]);
            }
            result[x] = r[ACTIVE] * (r[PARITY + x] - parity);
        }
        for y in 0..5 {
            for x in 0..5 {
                let lane = x + 5 * y;
                let d = xor(r[PARITY + (x + 4) % 5], r[PREVIOUS_PARITY + (x + 1) % 5]);
                result[5 + lane] = r[ACTIVE] * (r[THETA + lane] - xor(r[INPUT + lane], d));
                let nonlinear =
                    (E::ONE - r[ROTATED + (x + 1) % 5 + 5 * y]) * r[ROTATED + (x + 2) % 5 + 5 * y];
                let mut output = xor(r[ROTATED + lane], nonlinear);
                if lane == 0 {
                    output = xor(output, r[ROUND_CONSTANT]);
                }
                result[30 + lane] = r[ACTIVE] * (r[OUTPUT + lane] - output);
            }
        }
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = public_rows(&self.inputs);
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
    for (slot, row) in public_rows(inputs).into_iter().enumerate() {
        trace.update_row(slot * 2, &row);
        trace.update_row(slot * 2 + 1, &row);
    }
    // Only the last odd row is free of operations/assertions. Statement-derived
    // padding gives constant inputs full-degree trace polynomials as well.
    let mut hash =
        blake3::Hasher::new_derive_key("Shell-Chain Keccak permutation trace padding v1");
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

struct KeccakProver {
    inputs: BatchInputs,
    options: ProofOptions,
}

impl Prover for KeccakProver {
    type BaseField = BaseElement;
    type Air = KeccakAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, KeccakAir, E>;

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
        air: &'a KeccakAir,
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

/// Prove the full 24-round permutation. Input and intermediate lanes are public.
pub fn prove_keccak_permutation(input: &[u64; 25]) -> Result<KeccakPermutationProof, String> {
    let inputs = witness(*input);
    let statement = BatchInputs {
        permutations: vec![inputs.clone()],
        aggregate: false,
    };
    let prover = KeccakProver {
        inputs: statement.clone(),
        options: default_proof_options(),
    };
    let inner = prover
        .prove(trace(&statement))
        .map_err(|e| format!("Keccak proof: {e:?}"))?;
    Ok(KeccakPermutationProof {
        version: 1,
        input: *input,
        rounds: inputs.rounds,
        proof_bytes: inner.to_bytes(),
    })
}

/// Verify the AIR with independently supplied input and final output lanes.
/// This path never executes a native Keccak permutation or SHAKE hash.
pub fn verify_keccak_permutation(
    proof: &KeccakPermutationProof,
    expected_input: &[u64; 25],
    expected_output: &[u64; 25],
) -> Result<(), String> {
    if proof.version != 1
        || &proof.input != expected_input
        || proof.rounds.len() != ROUNDS
        || proof.rounds.last().map(|v| &v.output) != Some(expected_output)
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > 1_048_576
    {
        return Err("invalid Keccak version, shape, endpoint binding or proof size".into());
    }
    let inner =
        Proof::from_bytes(&proof.proof_bytes).map_err(|e| format!("Keccak proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("unexpected Keccak trace layout".into());
    }
    verify::<KeccakAir, Hasher, Coin, Commitment>(
        inner,
        BatchInputs {
            permutations: vec![Inputs {
                input: proof.input,
                rounds: proof.rounds.clone(),
            }],
            aggregate: false,
        },
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("Keccak verification: {e:?}"))
}

pub(crate) fn permutation_witness(input: &[u64; 25]) -> KeccakPermutationProof {
    let inputs = witness(*input);
    KeccakPermutationProof {
        version: 1,
        input: *input,
        rounds: inputs.rounds,
        proof_bytes: Vec::new(),
    }
}

fn batch_inputs(permutations: &[KeccakPermutationProof]) -> Result<BatchInputs, String> {
    if permutations.is_empty()
        || permutations.len() > MAX_KECCAK_BATCH
        || permutations
            .iter()
            .any(|p| p.version != 1 || p.rounds.len() != ROUNDS || !p.proof_bytes.is_empty())
    {
        return Err("invalid Keccak aggregate count, routing shape or standalone proof".into());
    }
    Ok(BatchInputs {
        permutations: permutations
            .iter()
            .map(|p| Inputs {
                input: p.input,
                rounds: p.rounds.clone(),
            })
            .collect(),
        aggregate: true,
    })
}

/// Prove every bit and all 24 rounds of at most eight ordered permutations.
/// The supplied round states are witnesses, not trusted execution results.
pub fn prove_keccak_batch(
    permutations: &[KeccakPermutationProof],
) -> Result<KeccakBatchProof, String> {
    let inputs = batch_inputs(permutations)?;
    // Prover-side witness validation prevents malformed requests from reaching
    // backend assertions. The verifier still uses only the full AIR statement.
    if inputs
        .permutations
        .iter()
        .any(|p| witness(p.input).rounds != p.rounds)
    {
        return Err("invalid Keccak aggregate round witness".into());
    }
    let prover = KeccakProver {
        inputs: inputs.clone(),
        options: default_proof_options(),
    };
    let inner = prover
        .prove(trace(&inputs))
        .map_err(|e| format!("Keccak aggregate proof: {e:?}"))?;
    Ok(KeccakBatchProof {
        version: 1,
        proof_bytes: inner.to_bytes(),
    })
}

/// Verify caller-bound ordered routing states without native round execution.
/// Standalone and aggregate transcripts have different public input domains.
pub fn verify_keccak_batch(
    proof: &KeccakBatchProof,
    permutations: &[KeccakPermutationProof],
) -> Result<(), String> {
    let inputs = batch_inputs(permutations)?;
    if proof.version != 1 || proof.proof_bytes.is_empty() || proof.proof_bytes.len() > 1_048_576 {
        return Err("invalid Keccak aggregate version or proof size".into());
    }
    let inner = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| format!("Keccak aggregate decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, inputs.trace_length()) {
        return Err("unexpected Keccak aggregate trace layout".into());
    }
    verify::<KeccakAir, Hasher, Coin, Commitment>(
        inner,
        inputs,
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("Keccak aggregate verification: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    use std::sync::OnceLock;

    // XKCP full-state known answers, independently published for zero input
    // and a second application. Not generated by this module.
    // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt
    const ZERO_OUTPUT: [u64; 25] = [
        0xF1258F7940E1DDE7,
        0x84D5CCF933C0478A,
        0xD598261EA65AA9EE,
        0xBD1547306F80494D,
        0x8B284E056253D057,
        0xFF97A42D7F8E6FD4,
        0x90FEE5A0A44647C4,
        0x8C5BDA0CD6192E76,
        0xAD30A6F71B19059C,
        0x30935AB7D08FFC64,
        0xEB5AA93F2317D635,
        0xA9A6E6260D712103,
        0x81A57C16DBCF555F,
        0x43B831CD0347C826,
        0x01F22F1A11A5569F,
        0x05E5635A21D9AE61,
        0x64BEFEF28CC970F2,
        0x613670957BC46611,
        0xB87C5A554FD00ECB,
        0x8C3EE88A1CCF32C8,
        0x940C7922AE3A2614,
        0x1841F924A2C509E4,
        0x16F53526E70465C2,
        0x75F644E97F30A13B,
        0xEAF1FF7B5CECA249,
    ];
    const SECOND_OUTPUT: [u64; 25] = [
        0x2D5C954DF96ECB3C,
        0x6A332CD07057B56D,
        0x093D8D1270D76B6C,
        0x8A20D9B25569D094,
        0x4F9C4F99E5E7F156,
        0xF957B9A2DA65FB38,
        0x85773DAE1275AF0D,
        0xFAF4F247C3D810F7,
        0x1F1B9EE6F79A8759,
        0xE4FECC0FEE98B425,
        0x68CE61B6B9CE68A1,
        0xDEEA66C4BA8F974F,
        0x33C43D836EAFB1F5,
        0xE00654042719DBD9,
        0x7CF8A9F009831265,
        0xFD5449A6BF174743,
        0x97DDAD33D8994B40,
        0x48EAD5FC5D0BE774,
        0xE3B8C8EE55B7B03C,
        0x91A0226E649E42E9,
        0x900E3129E7BADD7B,
        0x202A9EC5FAA3CCE8,
        0x5B3402464E1C3DB6,
        0x609F4E62A44C1059,
        0x20D06CD26A8FBF5C,
    ];

    fn sample() -> &'static KeccakPermutationProof {
        static SAMPLE: OnceLock<KeccakPermutationProof> = OnceLock::new();
        SAMPLE.get_or_init(|| prove_keccak_permutation(&[0; 25]).unwrap())
    }

    #[test]
    fn zero_full_state_known_answer_real_proof_and_json_reload() {
        let proof = sample();
        assert_eq!(proof.rounds[23].output, ZERO_OUTPUT);
        verify_keccak_permutation(proof, &[0; 25], &ZERO_OUTPUT).unwrap();
        let restored: KeccakPermutationProof =
            serde_json::from_slice(&serde_json::to_vec(proof).unwrap()).unwrap();
        verify_keccak_permutation(&restored, &[0; 25], &ZERO_OUTPUT).unwrap();
        assert_eq!(witness(ZERO_OUTPUT).rounds[23].output, SECOND_OUTPUT);
    }

    // Bit-array oracle uses coordinate routing and independently generated
    // iota constants, rather than witness word rotations/XOR implementation.
    fn constant(round: usize) -> u64 {
        let mut value = 0;
        for j in 0..7 {
            let t = (j + 7 * round) % 255;
            let mut lfsr = 1u8;
            for _ in 0..t {
                lfsr = (lfsr << 1) ^ if lfsr & 128 != 0 { 0x71 } else { 0 };
            }
            value |= u64::from(lfsr & 1) << ((1 << j) - 1);
        }
        value
    }
    fn bit_reference(input: [u64; 25]) -> [u64; 25] {
        let mut state = [[false; 64]; 25];
        for lane in 0..25 {
            for (z, bit) in state[lane].iter_mut().enumerate() {
                *bit = (input[lane] >> z) & 1 != 0;
            }
        }
        let mut offsets = [0; 25];
        let (mut x, mut y) = (1, 0);
        for t in 0..24 {
            offsets[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }
        for round in 0..24 {
            let mut theta = state;
            for y in 0..5 {
                for x in 0..5 {
                    for z in 0..64 {
                        let left =
                            (0..5).filter(|&yy| state[(x + 4) % 5 + 5 * yy][z]).count() % 2 == 1;
                        let right = (0..5)
                            .filter(|&yy| state[(x + 1) % 5 + 5 * yy][(z + 63) % 64])
                            .count()
                            % 2
                            == 1;
                        theta[x + 5 * y][z] = state[x + 5 * y][z] ^ left ^ right;
                    }
                }
            }
            let mut b = [[false; 64]; 25];
            for y in 0..5 {
                for x in 0..5 {
                    for z in 0..64 {
                        let source = (x + 3 * y) % 5 + 5 * x;
                        b[x + 5 * y][z] = theta[source][(z + 64 - offsets[source]) % 64];
                    }
                }
            }
            for y in 0..5 {
                for x in 0..5 {
                    for z in 0..64 {
                        state[x + 5 * y][z] = b[x + 5 * y][z]
                            ^ (!b[(x + 1) % 5 + 5 * y][z] & b[(x + 2) % 5 + 5 * y][z]);
                    }
                }
            }
            for (z, bit) in state[0].iter_mut().enumerate() {
                *bit ^= (constant(round) >> z) & 1 != 0;
            }
        }
        core::array::from_fn(|lane| (0..64).fold(0, |v, z| v | (u64::from(state[lane][z]) << z)))
    }

    #[test]
    fn all_bits_set_real_proof_and_independent_bit_oracle() {
        let input = [u64::MAX; 25];
        let expected = bit_reference(input);
        let proof = prove_keccak_permutation(&input).unwrap();
        verify_keccak_permutation(&proof, &input, &expected).unwrap();
        for input in [
            core::array::from_fn(|i| 1u64 << (i * 17 % 64)),
            core::array::from_fn(|i| (i as u64).wrapping_mul(0x0123456789abcdef)),
        ] {
            assert_eq!(witness(input).rounds[23].output, bit_reference(input));
        }
        assert_eq!(RC, core::array::from_fn(constant));
    }

    fn residuals(air: &KeccakAir, row: &[BaseElement]) -> Vec<BaseElement> {
        let mut result = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(
            &EvaluationFrame::from_rows(row.to_vec(), row.to_vec()),
            &[],
            &mut result,
        );
        result
    }

    #[test]
    fn all_round_bit_rows_and_each_step_reject_invalid_witness() {
        let inputs = BatchInputs {
            permutations: vec![witness(core::array::from_fn(|i| 1u64 << (i * 17 % 64)))],
            aggregate: false,
        };
        let rows = public_rows(&inputs);
        let air = KeccakAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            inputs,
            default_proof_options(),
        );
        assert!(rows
            .iter()
            .all(|r| residuals(&air, r).iter().all(|&v| v == BaseElement::ZERO)));
        for slot in [0, 63, 64, 767, 1535] {
            for col in [
                PARITY,
                PREVIOUS_PARITY + 4,
                THETA + 24,
                ROTATED + 1,
                OUTPUT,
                OUTPUT + 24,
                ROUND_CONSTANT,
            ] {
                let mut row = rows[slot].clone();
                row[col] = BaseElement::ONE - row[col];
                assert!(
                    residuals(&air, &row)
                        .iter()
                        .any(|&v| v != BaseElement::ZERO),
                    "slot {slot} column {col}"
                );
            }
        }
        // Every operation row is public-bit-bound; nonbinary values cannot
        // satisfy those fixed boundary assertions, even if algebra cancels.
        assert_eq!(air.get_assertions().len(), TRACE_WIDTH);
    }

    #[test]
    fn aggregate_binds_all_rounds_order_count_and_domain() {
        let permutations: Vec<_> = [
            [0; 25],
            ZERO_OUTPUT,
            [u64::MAX; 25],
            core::array::from_fn(|i| 1u64 << (i * 17 % 64)),
        ]
        .iter()
        .map(permutation_witness)
        .collect();
        for p in &permutations {
            assert_eq!(p.rounds[23].output, bit_reference(p.input));
        }
        let proof = prove_keccak_batch(&permutations).unwrap();
        verify_keccak_batch(&proof, &permutations).unwrap();
        let encoded = serde_json::to_vec(&proof).unwrap();
        let decoded = serde_json::from_slice(&encoded).unwrap();
        verify_keccak_batch(&decoded, &permutations).unwrap();
        for index in 0..permutations.len() {
            for round in [0, 11, 23] {
                let mut bad = permutations.clone();
                bad[index].rounds[round].output[24] ^= 1u64 << 63;
                assert!(verify_keccak_batch(&proof, &bad).is_err());
                assert!(prove_keccak_batch(&bad).is_err());
            }
        }
        let mut bad = permutations.clone();
        bad.swap(0, 1);
        assert!(verify_keccak_batch(&proof, &bad).is_err());
        assert!(verify_keccak_batch(&proof, &permutations[..3]).is_err());
        assert!(prove_keccak_batch(&[]).is_err());
        assert!(
            verify_keccak_batch(&proof, &vec![permutations[0].clone(); MAX_KECCAK_BATCH + 1])
                .is_err()
        );
        let mut bad = permutations.clone();
        bad[2].rounds.pop();
        assert!(verify_keccak_batch(&proof, &bad).is_err());
        let mut bad = permutations.clone();
        bad[0].proof_bytes = sample().proof_bytes.clone();
        assert!(verify_keccak_batch(&proof, &bad).is_err());
        let one = prove_keccak_batch(&permutations[..1]).unwrap();
        assert!(verify_keccak_batch(
            &KeccakBatchProof {
                version: 1,
                proof_bytes: sample().proof_bytes.clone(),
            },
            &permutations[..1]
        )
        .is_err());
        let mut standalone = sample().clone();
        standalone.proof_bytes = one.proof_bytes;
        assert!(verify_keccak_permutation(&standalone, &[0; 25], &ZERO_OUTPUT).is_err());
    }

    #[test]
    fn parity_theta_middle_round_and_final_output_tampering_reject() {
        let proof = sample();
        for (round, field) in [(0, 0), (11, 1), (22, 2), (23, 2)] {
            let mut bad = proof.clone();
            match field {
                0 => bad.rounds[round].parity[4] ^= 1u64 << 63,
                1 => bad.rounds[round].theta[24] ^= 1,
                _ => bad.rounds[round].output[24] ^= 1u64 << 63,
            }
            // Even accepting a changed endpoint cannot repair the old AIR.
            let expected = bad.rounds[23].output;
            assert!(verify_keccak_permutation(&bad, &[0; 25], &expected).is_err());
        }
        let mut bad = proof.clone();
        bad.input[24] = 1u64 << 63;
        assert!(verify_keccak_permutation(&bad, &bad.input, &ZERO_OUTPUT).is_err());
    }

    #[test]
    fn endpoint_shape_version_payload_and_foreign_layout_reject() {
        let p = sample();
        assert!(verify_keccak_permutation(p, &[1; 25], &ZERO_OUTPUT).is_err());
        assert!(verify_keccak_permutation(p, &[0; 25], &[0; 25]).is_err());
        let mut bad = p.clone();
        bad.rounds.pop();
        assert!(verify_keccak_permutation(&bad, &[0; 25], &ZERO_OUTPUT).is_err());
        let mut bad = p.clone();
        bad.version = 2;
        assert!(verify_keccak_permutation(&bad, &[0; 25], &ZERO_OUTPUT).is_err());
        let mut bad = p.clone();
        bad.proof_bytes.truncate(bad.proof_bytes.len() / 2);
        assert!(verify_keccak_permutation(&bad, &[0; 25], &ZERO_OUTPUT).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = vec![0; 1_048_577];
        assert!(verify_keccak_permutation(&bad, &[0; 25], &ZERO_OUTPUT).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = crate::mldsa_key::prove_public_key_decode(&[0; 1952])
            .unwrap()
            .proof_bytes;
        assert!(verify_keccak_permutation(&bad, &[0; 25], &ZERO_OUTPUT)
            .unwrap_err()
            .contains("layout"));
    }

    #[test]
    fn native_shake256_single_block_control_includes_rate_edge() {
        for message in [Vec::new(), b"abc".to_vec(), vec![0xa5; 135]] {
            let mut padded = [0u8; 200];
            padded[..message.len()].copy_from_slice(&message);
            padded[message.len()] ^= 0x1f;
            padded[135] ^= 0x80;
            let input = core::array::from_fn(|i| {
                u64::from_le_bytes(padded[i * 8..i * 8 + 8].try_into().unwrap())
            });
            let words = witness(input).rounds[23].output;
            let output: Vec<_> = words.iter().flat_map(|v| v.to_le_bytes()).collect();
            let mut h = Shake256::default();
            h.update(&message);
            let mut expected = [0u8; 136];
            h.finalize_xof().read(&mut expected);
            assert_eq!(output[..136], expected);
        }
        // Padding/absorption/squeeze here are native controls, not AIR claims.
    }
}
