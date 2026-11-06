//! Complete public BLAKE3 compression and bounded unkeyed digest proofs.
//!
//! All seven rounds, additions, XOR/rotations and feedforward operations are
//! constrained. The verifier routes public operands and actual compression
//! certificates; it never evaluates native BLAKE3 for acceptance.

use crate::prover::default_proof_options;
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

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];
const ROTATIONS: [usize; 5] = [16, 12, 8, 7, 0];
const OPERATIONS: usize = 7 * 8 * 8 + 16;
const SLOTS: usize = 512;
const TRACE_LENGTH: usize = 2 * SLOTS;
const PUBLIC: usize = 10;
const X_BITS: usize = 10;
const Y_BITS: usize = 42;
const Z_BITS: usize = 74;
const OUT_BITS: usize = 106;
const CARRY_BITS: usize = 138;
const TRACE_WIDTH: usize = 140;
const BOOLS: usize = TRACE_WIDTH - PUBLIC;
const CONSTRAINTS: usize = BOOLS + 4 + 1 + 32;
const MAX_PROOF_BYTES: usize = 1_048_576;
/// Development input bound; this does not define transaction limits or gas.
pub const MAX_HASH_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionInput {
    pub chaining_value: [u32; 8],
    pub block: [u32; 16],
    pub counter: u64,
    pub block_len: u8,
    pub flags: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionProof {
    pub version: u8,
    pub input: CompressionInput,
    /// All 448 round-operation results, then all 16 feedforward results.
    pub operations: Vec<u32>,
    pub proof_bytes: Vec<u8>,
}
impl CompressionProof {
    pub fn output(&self) -> Option<[u32; 16]> {
        self.operations.get(OPERATIONS - 16..)?.try_into().ok()
    }
}
#[derive(Clone)]
struct Statement {
    input: CompressionInput,
    operations: Vec<u32>,
}
impl ToElements<BaseElement> for Statement {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![BaseElement::new(u64::from_le_bytes(*b"B3COMP01") as u128)];
        out.extend(
            self.input
                .chaining_value
                .iter()
                .chain(&self.input.block)
                .map(|&v| BaseElement::new(v.into())),
        );
        out.extend(
            [
                self.input.counter as u32,
                (self.input.counter >> 32) as u32,
                u32::from(self.input.block_len),
                u32::from(self.input.flags),
            ]
            .map(|v| BaseElement::new(v.into())),
        );
        out.extend(self.operations.iter().map(|&v| BaseElement::new(v.into())));
        out
    }
}
#[derive(Clone, Copy)]
struct Operation {
    kind: usize,
    x: u32,
    y: u32,
    z: u32,
}
// Fixed register/message routing only. The callback supplies each arithmetic
// result; verification takes those from the certificate, never native math.
fn route(input: &CompressionInput, mut step: impl FnMut(Operation) -> u32) -> [u32; 16] {
    let mut state = [0; 16];
    state[..8].copy_from_slice(&input.chaining_value);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = input.counter as u32;
    state[13] = (input.counter >> 32) as u32;
    state[14] = input.block_len.into();
    state[15] = input.flags.into();
    for schedule in SCHEDULE {
        for (i, indices) in [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15],
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ]
        .into_iter()
        .enumerate()
        {
            let [a, b, c, d] = indices;
            for (message, rotation1, rotation2) in [
                (input.block[schedule[2 * i]], 1, 2),
                (input.block[schedule[2 * i + 1]], 3, 4),
            ] {
                state[a] = step(Operation {
                    kind: 0,
                    x: state[a],
                    y: state[b],
                    z: message,
                });
                state[d] = step(Operation {
                    kind: rotation1,
                    x: state[d],
                    y: state[a],
                    z: 0,
                });
                state[c] = step(Operation {
                    kind: 0,
                    x: state[c],
                    y: state[d],
                    z: 0,
                });
                state[b] = step(Operation {
                    kind: rotation2,
                    x: state[b],
                    y: state[c],
                    z: 0,
                });
            }
        }
    }
    std::array::from_fn(|i| {
        step(Operation {
            kind: 5,
            x: state[i],
            y: if i < 8 {
                state[i + 8]
            } else {
                input.chaining_value[i - 8]
            },
            z: 0,
        })
    })
}
fn native(op: Operation) -> u32 {
    if op.kind == 0 {
        op.x.wrapping_add(op.y).wrapping_add(op.z)
    } else {
        (op.x ^ op.y).rotate_right(ROTATIONS[op.kind - 1] as u32)
    }
}
fn validate(input: &CompressionInput) -> Result<(), String> {
    if input.block_len > 64 || input.flags > 127 {
        return Err("invalid BLAKE3 compression block length or flags".into());
    }
    Ok(())
}
fn public_rows(s: &Statement) -> Vec<[u32; PUBLIC]> {
    let mut rows = vec![[0; PUBLIC]; SLOTS];
    let mut n = 0;
    route(&s.input, |op| {
        let value = s.operations[n];
        rows[n][op.kind] = 1;
        rows[n][6..].copy_from_slice(&[op.x, op.y, op.z, value]);
        n += 1;
        value
    });
    rows
}
fn witness(public: &[u32; PUBLIC]) -> Vec<BaseElement> {
    let mut row = vec![BaseElement::ZERO; TRACE_WIDTH];
    for (i, &v) in public.iter().enumerate() {
        row[i] = BaseElement::new(v.into());
    }
    for (group, &v) in public[6..].iter().enumerate() {
        for bit in 0..32 {
            row[PUBLIC + group * 32 + bit] = BaseElement::new(((v >> bit) & 1).into());
        }
    }
    let carry = if public[0] == 1 {
        (u64::from(public[6]) + u64::from(public[7]) + u64::from(public[8])) >> 32
    } else {
        0
    };
    for bit in 0..2 {
        row[CARRY_BITS + bit] = BaseElement::new(((carry >> bit) & 1).into());
    }
    row
}
struct CompressionAir {
    context: AirContext<BaseElement>,
    statement: Statement,
}
impl Air for CompressionAir {
    type BaseField = BaseElement;
    type PublicInputs = Statement;
    fn new(info: TraceInfo, statement: Statement, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH));
        let mut degrees = vec![TransitionConstraintDegree::new(2); BOOLS];
        degrees.extend((0..4).map(|_| TransitionConstraintDegree::new(1)));
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.extend((0..32).map(|_| TransitionConstraintDegree::new(3)));
        debug_assert_eq!(degrees.len(), CONSTRAINTS);
        Self {
            context: AirContext::new(info, degrees, PUBLIC, options),
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
        let two = E::ONE + E::ONE;
        for col in PUBLIC..TRACE_WIDTH {
            result[col - PUBLIC] = row[col] * (row[col] - E::ONE);
        }
        for (group, start) in [X_BITS, Y_BITS, Z_BITS, OUT_BITS].into_iter().enumerate() {
            let mut sum = E::ZERO;
            let mut weight = E::ONE;
            for bit in 0..32 {
                sum += row[start + bit] * weight;
                weight = weight + weight;
            }
            result[BOOLS + group] = row[6 + group] - sum;
        }
        let carry = row[CARRY_BITS] + two * row[CARRY_BITS + 1];
        result[BOOLS + 4] = row[0]
            * (row[6] + row[7] + row[8] - row[9] - E::from(BaseElement::new(1u128 << 32)) * carry);
        for bit in 0..32 {
            result[BOOLS + 5 + bit] = E::ZERO;
            for (kind, &rotation) in ROTATIONS.iter().enumerate() {
                let i = (bit + rotation) % 32;
                let x = row[X_BITS + i];
                let y = row[Y_BITS + i];
                result[BOOLS + 5 + bit] +=
                    row[kind + 1] * (row[OUT_BITS + bit] - x - y + two * x * y);
            }
        }
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = public_rows(&self.statement);
        (0..PUBLIC)
            .map(|col| {
                Assertion::sequence(
                    col,
                    0,
                    2,
                    rows.iter()
                        .map(|row| BaseElement::new(row[col].into()))
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

struct CompressionProver {
    statement: Statement,
    options: ProofOptions,
}

impl Prover for CompressionProver {
    type BaseField = BaseElement;
    type Air = CompressionAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, CompressionAir, E>;

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
        air: &'a CompressionAir,
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

/// Prove the entire compression, including all 16 output words.
pub fn prove_compression(input: &CompressionInput) -> Result<CompressionProof, String> {
    validate(input)?;
    let mut operations = Vec::with_capacity(OPERATIONS);
    route(input, |op| {
        let v = native(op);
        operations.push(v);
        v
    });
    let statement = Statement {
        input: input.clone(),
        operations: operations.clone(),
    };
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (i, p) in public_rows(&statement).iter().enumerate() {
        let row = witness(p);
        trace.update_row(2 * i, &row);
        trace.update_row(2 * i + 1, &row);
    }
    let mut padding = blake3::Hasher::new_derive_key("Shell-Chain BLAKE3 compression padding v1");
    for v in statement.to_elements() {
        padding.update(&v.as_int().to_le_bytes());
    }
    let mut bytes = [0; 16 * TRACE_WIDTH];
    padding.finalize_xof().fill(&mut bytes);
    let last: Vec<_> = bytes
        .chunks_exact(16)
        .map(|v| BaseElement::new(u128::from_le_bytes(v.try_into().expect("16 bytes"))))
        .collect();
    trace.update_row(TRACE_LENGTH - 1, &last);
    let proof = CompressionProver {
        statement,
        options: default_proof_options(),
    }
    .prove(trace)
    .map_err(|e| format!("BLAKE3 compression proving: {e:?}"))?;
    Ok(CompressionProof {
        version: 1,
        input: input.clone(),
        operations,
        proof_bytes: proof.to_bytes(),
    })
}
/// Verify fixed routing and actual arithmetic constraints, with no native hash.
pub fn verify_compression(
    p: &CompressionProof,
    input: &CompressionInput,
    output: &[u32; 16],
) -> Result<(), String> {
    validate(input)?;
    if p.version != 1
        || p.input != *input
        || p.operations.len() != OPERATIONS
        || p.output().as_ref() != Some(output)
        || p.proof_bytes.is_empty()
        || p.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("invalid BLAKE3 compression version, binding, operations or payload".into());
    }
    let proof = Proof::from_bytes(&p.proof_bytes)
        .map_err(|e| format!("BLAKE3 compression decode: {e:?}"))?;
    if proof.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("unexpected BLAKE3 compression trace layout".into());
    }
    verify::<CompressionAir, Hasher, Coin, Commitment>(
        proof,
        Statement {
            input: input.clone(),
            operations: p.operations.clone(),
        },
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("BLAKE3 compression verification: {e:?}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blake3HashProof {
    pub version: u8,
    pub message: Vec<u8>,
    pub output: [u8; 32],
    /// Depth-first chunk and parent certificates, including the root domain.
    pub compressions: Vec<CompressionProof>,
}
fn subtree(
    message: &[u8],
    first: usize,
    count: usize,
    root: bool,
    compress: &mut impl FnMut(CompressionInput) -> Result<[u32; 16], String>,
) -> Result<[u32; 8], String> {
    if count == 1 {
        let data = &message[first * 1024..message.len().min((first + 1) * 1024)];
        let blocks = data.len().div_ceil(64).max(1);
        let mut cv = IV;
        for i in 0..blocks {
            let start = i * 64;
            let len = data.len().saturating_sub(start).min(64);
            let mut bytes = [0; 64];
            bytes[..len].copy_from_slice(&data[start..start + len]);
            let words = std::array::from_fn(|n| {
                u32::from_le_bytes(bytes[4 * n..4 * n + 4].try_into().expect("four bytes"))
            });
            let flags = u8::from(i == 0)
                + 2 * u8::from(i == blocks - 1)
                + 8 * u8::from(root && i == blocks - 1);
            let out = compress(CompressionInput {
                chaining_value: cv,
                block: words,
                counter: first as u64,
                block_len: len as u8,
                flags,
            })?;
            cv.copy_from_slice(&out[..8]);
        }
        Ok(cv)
    } else {
        let left = count.next_power_of_two() / 2;
        let a = subtree(message, first, left, false, compress)?;
        let b = subtree(message, first + left, count - left, false, compress)?;
        let mut block = [0; 16];
        block[..8].copy_from_slice(&a);
        block[8..].copy_from_slice(&b);
        let out = compress(CompressionInput {
            chaining_value: IV,
            block,
            counter: 0,
            block_len: 64,
            flags: 4 + 8 * u8::from(root),
        })?;
        Ok(out[..8].try_into().expect("eight words"))
    }
}
fn hash_route(
    message: &[u8],
    mut compress: impl FnMut(CompressionInput) -> Result<[u32; 16], String>,
) -> Result<[u8; 32], String> {
    if message.len() > MAX_HASH_BYTES {
        return Err("BLAKE3 development input bound exceeded".into());
    }
    let words = subtree(
        message,
        0,
        message.len().div_ceil(1024).max(1),
        true,
        &mut compress,
    )?;
    let mut bytes = [0; 32];
    for (i, v) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    Ok(bytes)
}
/// Prove a complete unkeyed 32-byte digest, including chunk/tree/root domains.
pub fn prove_hash(message: &[u8]) -> Result<Blake3HashProof, String> {
    let mut compressions = Vec::new();
    let output = hash_route(message, |input| {
        let p = prove_compression(&input)?;
        let out = p.output().ok_or("missing compression output")?;
        compressions.push(p);
        Ok(out)
    })?;
    Ok(Blake3HashProof {
        version: 1,
        message: message.to_vec(),
        output,
        compressions,
    })
}
/// Bind expected bytes and digest, verify every compression and all fixed
/// byte/chaining/tree routing. No native BLAKE3 computation substitutes here.
pub fn verify_hash(p: &Blake3HashProof, message: &[u8], output: &[u8; 32]) -> Result<(), String> {
    if p.version != 1
        || p.message != message
        || p.output != *output
        || message.len() > MAX_HASH_BYTES
        || p.compressions.is_empty()
        || p.compressions.len() > 67
    {
        return Err("invalid BLAKE3 hash version, binding, size or coverage".into());
    }
    let mut index = 0;
    let digest = hash_route(message, |input| {
        let child = p
            .compressions
            .get(index)
            .ok_or("missing BLAKE3 compression")?;
        let out = child.output().ok_or("missing compression output")?;
        verify_compression(child, &input, &out).map_err(|e| format!("compression {index}: {e}"))?;
        index += 1;
        Ok(out)
    })?;
    if index != p.compressions.len() || digest != *output {
        return Err("invalid BLAKE3 digest or extra compression coverage".into());
    }
    Ok(())
}
/// Exact existing outer-transaction signing payload. AA sender bundle framing
/// is separate and is not asserted by this outer-transaction proof.
pub fn prove_transaction_signing_hash(
    tx: &shell_core::Transaction,
    sig_type: u8,
) -> Result<Blake3HashProof, String> {
    prove_hash(&tx.signing_payload(sig_type))
}
pub fn verify_transaction_signing_hash(
    p: &Blake3HashProof,
    tx: &shell_core::Transaction,
    sig_type: u8,
    output: &[u8; 32],
) -> Result<(), String> {
    verify_hash(p, &tx.signing_payload(sig_type), output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    fn input() -> CompressionInput {
        CompressionInput {
            chaining_value: IV,
            block: std::array::from_fn(|i| u32::MAX.wrapping_sub(i as u32 * 719)),
            counter: 0x1122334455667788,
            block_len: 64,
            flags: 3,
        }
    }
    fn sample() -> &'static CompressionProof {
        static P: OnceLock<CompressionProof> = OnceLock::new();
        P.get_or_init(|| prove_compression(&input()).unwrap())
    }
    fn residuals(row: &[BaseElement]) -> Vec<BaseElement> {
        let air = CompressionAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            Statement {
                input: input(),
                operations: vec![0; OPERATIONS],
            },
            default_proof_options(),
        );
        let mut result = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(
            &EvaluationFrame::from_rows(row.to_vec(), row.to_vec()),
            &[],
            &mut result,
        );
        result
    }
    #[test]
    fn every_arx_boundary_and_carry_satisfies_constraints() {
        for kind in 0..6 {
            for (x, y, z) in [
                (0, 0, 0),
                (u32::MAX, u32::MAX, u32::MAX),
                (0x81234567, 0xfedcba98, 33),
            ] {
                let op = Operation {
                    kind,
                    x,
                    y,
                    z: if kind == 0 { z } else { 0 },
                };
                let mut public = [0; PUBLIC];
                public[kind] = 1;
                public[6..].copy_from_slice(&[op.x, op.y, op.z, native(op)]);
                assert!(residuals(&witness(&public))
                    .iter()
                    .all(|&v| v == BaseElement::ZERO));
            }
        }
    }
    #[test]
    fn private_nonbinary_words_and_fractional_carry_cannot_escape() {
        let mut row = witness(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        row[9] = BaseElement::ONE;
        row[OUT_BITS] = BaseElement::ONE;
        row[CARRY_BITS] = -BaseElement::new(1u128 << 32).inv();
        let out = residuals(&row);
        assert!(out[BOOLS..].iter().all(|&v| v == BaseElement::ZERO));
        assert!(out[..BOOLS].iter().any(|&v| v != BaseElement::ZERO));
        let mut row = witness(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        row[6] = BaseElement::new(2);
        row[X_BITS] = BaseElement::new(2);
        row[9] = BaseElement::new(2);
        row[OUT_BITS] = BaseElement::new(2);
        let out = residuals(&row);
        assert!(out[BOOLS..].iter().all(|&v| v == BaseElement::ZERO));
        assert!(out[..BOOLS].iter().any(|&v| v != BaseElement::ZERO));
    }
    #[test]
    fn real_compression_json_and_all_rounds_outputs_bind() {
        let p = sample();
        verify_compression(p, &input(), &p.output().unwrap()).unwrap();
        let p: CompressionProof = serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
        verify_compression(&p, &input(), &p.output().unwrap()).unwrap();
        for index in [0, 63, 447, 448, 463] {
            let mut p = p.clone();
            p.operations[index] ^= 1;
            assert!(verify_compression(&p, &p.input, &p.output().unwrap()).is_err());
        }
        for field in 0..5 {
            let mut p = p.clone();
            match field {
                0 => p.input.counter ^= 1u64 << 40,
                1 => p.input.block[15] ^= 1,
                2 => p.input.chaining_value[7] ^= 1,
                3 => p.input.flags ^= 8,
                _ => p.input.block_len = 63,
            }
            assert!(verify_compression(&p, &p.input, &p.output().unwrap()).is_err());
        }
    }
    #[test]
    fn hash_graph_native_controls_cover_block_chunk_tree_and_maximum() {
        for n in [
            0usize, 1, 3, 63, 64, 65, 1023, 1024, 1025, 1952, 2048, 2049, 3072, 3073, 4096,
        ] {
            let msg: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let mut calls = 0;
            let result = hash_route(&msg, |input| {
                calls += 1;
                Ok(route(&input, native))
            })
            .unwrap();
            assert_eq!(result, *blake3::hash(&msg).as_bytes(), "length {n}");
            assert_eq!(calls, n.div_ceil(64).max(1) + n.div_ceil(1024).max(1) - 1);
        }
    }
    #[test]
    fn official_vectors_and_real_root_hash_proofs() {
        for (n, hex) in [
            (
                0,
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                3,
                "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
            ),
            (
                64,
                "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
            ),
            (
                1024,
                "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            ),
            (
                1025,
                "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            ),
            (
                2048,
                "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            ),
            (
                4096,
                "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
            ),
        ] {
            let msg: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let result = hash_route(&msg, |input| Ok(route(&input, native))).unwrap();
            let text: String = result.iter().map(|v| format!("{v:02x}")).collect();
            assert_eq!(text, hex);
        }
        for msg in [Vec::new(), vec![0, 1, 2]] {
            let p = prove_hash(&msg).unwrap();
            verify_hash(&p, &msg, blake3::hash(&msg).as_bytes()).unwrap();
            let restored: Blake3HashProof =
                serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
            verify_hash(&restored, &msg, &p.output).unwrap();
            let mut bad = p.clone();
            bad.compressions[0].input.flags ^= 8;
            assert!(verify_hash(&bad, &msg, &p.output).is_err());
            let mut bad = p.clone();
            bad.compressions.push(p.compressions[0].clone());
            assert!(verify_hash(&bad, &msg, &p.output).is_err());
            let mut bad = p.clone();
            bad.output[31] ^= 1;
            assert!(verify_hash(&bad, &msg, &bad.output).is_err());
        }
    }
    #[test]
    fn malformed_shapes_versions_layout_and_bounds_reject() {
        let p = sample();
        for kind in 0..6 {
            let mut bad = p.clone();
            match kind {
                0 => bad.version = 2,
                1 => {
                    bad.operations.pop();
                }
                2 => bad.input.flags = 128,
                3 => bad.input.block_len = 65,
                4 => bad.proof_bytes.truncate(10),
                _ => bad.proof_bytes = vec![0; MAX_PROOF_BYTES + 1],
            }
            assert!(verify_compression(&bad, &bad.input, &p.output().unwrap()).is_err());
        }
        let mut bad = p.clone();
        bad.proof_bytes = crate::prove_sig_batch(&[crate::SigBatchEntry {
            msg_hash: [1; 32],
            pk_hash: [2; 32],
        }])
        .unwrap()
        .proof_bytes;
        assert!(verify_compression(&bad, &input(), &p.output().unwrap())
            .unwrap_err()
            .contains("trace layout"));
        assert!(prove_hash(&vec![0; MAX_HASH_BYTES + 1]).is_err());
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    #[test]
    fn valid_nonroot_certificate_cannot_replace_root_domain() {
        let input = CompressionInput {
            chaining_value: IV,
            block: [0; 16],
            counter: 0,
            block_len: 0,
            flags: 3,
        };
        let child = prove_compression(&input).unwrap();
        let output = child.output().unwrap();
        verify_compression(&child, &input, &output).unwrap();
        let bytes: Vec<_> = output[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        let p = Blake3HashProof {
            version: 1,
            message: vec![],
            output: bytes.try_into().unwrap(),
            compressions: vec![child],
        };
        assert!(verify_hash(&p, &[], &p.output)
            .unwrap_err()
            .contains("binding"));
    }

    #[test]
    fn official_root_xof_binds_all_sixteen_feedforward_words() {
        for (n,hex) in [(0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"), (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de")] {let mut block=[0u8;64];for (i,v)in block[..n].iter_mut().enumerate(){*v=(i%251)as u8;}let input=CompressionInput{chaining_value:IV,block:std::array::from_fn(|i|u32::from_le_bytes(block[4*i..4*i+4].try_into().unwrap())),counter:0,block_len:n as u8,flags:11};let p=prove_compression(&input).unwrap();let output=p.output().unwrap();verify_compression(&p,&input,&output).unwrap();let bytes:Vec<u8>=output.into_iter().flat_map(u32::to_le_bytes).collect();let actual:String=bytes.iter().map(|v|format!("{v:02x}")).collect();assert_eq!(actual,hex);}
    }
    #[test]
    fn canonical_outer_payload_preserves_exact_big_endian_field_layout() {
        use shell_primitives::{Address, Bytes, U256};
        let tx = shell_core::Transaction {
            chain_id: 10,
            nonce: 7,
            to: Some(Address::from([0x11; 32])),
            value: U256::from(1u64),
            data: Bytes::from(vec![0xaa, 0xbb]),
            gas_limit: 21000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 0,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let mut expected = b"PQTX_SIGNING_V2\0".to_vec();
        expected.extend_from_slice(&10u64.to_be_bytes());
        expected.extend_from_slice(&7u64.to_be_bytes());
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());
        expected.extend_from_slice(&[0xaa, 0xbb]);
        for v in [21000u64, 2, 1] {
            expected.extend_from_slice(&v.to_be_bytes());
        }
        expected.extend_from_slice(&[0xc0, 3, 0]);
        assert_eq!(tx.signing_payload(3), expected);
        assert_eq!(
            tx.signing_hash(3).as_bytes(),
            blake3::hash(&expected).as_bytes()
        );
        let mut blob = tx.clone();
        blob.tx_type = 3;
        blob.max_fee_per_blob_gas = Some(9);
        blob.blob_versioned_hashes = Some(vec![shell_primitives::ShellHash::from([0x44; 32])]);
        let mut expected = tx.signing_payload(3);
        *expected.last_mut().unwrap() = 3;
        expected.extend_from_slice(&9u64.to_be_bytes());
        expected.extend_from_slice(&[0x44; 32]);
        assert_eq!(blob.signing_payload(3), expected);
        assert_eq!(
            blob.signing_hash(3).as_bytes(),
            blake3::hash(&expected).as_bytes()
        );
    }
}
