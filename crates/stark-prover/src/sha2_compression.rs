//! Complete batched SHA-256/SHA-512 compression AIRs for hash-based signatures.
//!
//! Public routing binds every schedule, round and feedforward result. All bit
//! operations and 32-bit limb carries are constrained; acceptance never calls a
//! native SHA implementation. Callers must bind the independently expected
//! compression inputs, padding/chaining and higher-level signature structure.
use serde::{Deserialize, Serialize};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    verify, AcceptableOptions, Air, AirContext, Assertion, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

/// Independent compression blocks in one proof; not a native transaction limit.
pub const MAX_SHA2_BATCH: usize = 16;
const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const SHIFTS: [usize; 18] = [
    1, 2, 3, 6, 7, 8, 9, 10, 11, 13, 14, 17, 18, 19, 22, 25, 28, 29,
];
const KINDS: usize = 3 + SHIFTS.len();
const PUBLIC: usize = KINDS + 5;
const X: usize = PUBLIC;
const Y: usize = X + 32;
const OUT: usize = Y + 32;
const WIDTH: usize = OUT + 32;
const BOOLS: usize = 96;
const CONSTRAINTS: usize = BOOLS + 2 + 3 + 1 + 2 + 32;
const K256: [u64; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];
/// FIPS 180-4 SHA-256 initial state.
pub const SHA256_INITIAL_STATE: [u64; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
/// FIPS 180-4 SHA-512 initial state.
pub const SHA512_INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sha2Algorithm {
    Sha256,
    Sha512,
}
impl Sha2Algorithm {
    fn lanes(self) -> usize {
        if self == Self::Sha256 {
            1
        } else {
            2
        }
    }
    fn operations(self) -> usize {
        if self == Self::Sha256 {
            2168
        } else {
            2760
        }
    }
    fn additions(self) -> usize {
        if self == Self::Sha256 {
            600
        } else {
            760
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionInput {
    pub chaining_value: [u64; 8],
    pub block: [u64; 16],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sha2CompressionProof {
    pub version: u8,
    pub algorithm: Sha2Algorithm,
    pub inputs: Vec<CompressionInput>,
    /// Fixed routing's word results; no native result is trusted by verification.
    pub operations: Vec<u64>,
    /// Packed low/high addition carry bits, in routing order.
    pub carries: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}
#[derive(Clone, Copy)]
enum Kind {
    Add,
    Xor,
    And,
    Rotate(u32),
    Shift(u32),
}
#[derive(Clone, Copy)]
struct Operation {
    kind: Kind,
    x: u64,
    y: u64,
}
fn step(kind: Kind, x: u64, y: u64, f: &mut impl FnMut(Operation) -> u64) -> u64 {
    f(Operation { kind, x, y })
}
fn sigma(x: u64, rot: [u32; 3], shift: bool, f: &mut impl FnMut(Operation) -> u64) -> u64 {
    let a = step(Kind::Rotate(rot[0]), x, 0, f);
    let b = step(Kind::Rotate(rot[1]), x, 0, f);
    let d = step(
        if shift {
            Kind::Shift(rot[2])
        } else {
            Kind::Rotate(rot[2])
        },
        x,
        0,
        f,
    );
    let ab = step(Kind::Xor, a, b, f);
    step(Kind::Xor, ab, d, f)
}
// Operand routing only; the callback supplies every arithmetic/Boolean result.
fn route(
    a: Sha2Algorithm,
    input: &CompressionInput,
    mut f: impl FnMut(Operation) -> u64,
) -> [u64; 8] {
    let (rounds, small0, small1, big0, big1) = if a == Sha2Algorithm::Sha256 {
        (64, [7, 18, 3], [17, 19, 10], [2, 13, 22], [6, 11, 25])
    } else {
        (80, [1, 8, 7], [19, 61, 6], [28, 34, 39], [14, 18, 41])
    };
    let mut w = [0; 80];
    w[..16].copy_from_slice(&input.block);
    for i in 16..rounds {
        let s0 = sigma(w[i - 15], small0, true, &mut f);
        let s1 = sigma(w[i - 2], small1, true, &mut f);
        let x = step(Kind::Add, w[i - 16], s0, &mut f);
        let y = step(Kind::Add, x, w[i - 7], &mut f);
        w[i] = step(Kind::Add, y, s1, &mut f);
    }
    let mut v = input.chaining_value;
    for (i, &word) in w[..rounds].iter().enumerate() {
        let [aa, b, c, d, e, ff, g, h] = v;
        let s1 = sigma(e, big1, false, &mut f);
        let fg = step(Kind::Xor, ff, g, &mut f);
        let efg = step(Kind::And, e, fg, &mut f);
        let ch = step(Kind::Xor, g, efg, &mut f);
        let k = if a == Sha2Algorithm::Sha256 {
            K256[i]
        } else {
            K512[i]
        };
        let mut t1 = step(Kind::Add, h, s1, &mut f);
        t1 = step(Kind::Add, t1, ch, &mut f);
        t1 = step(Kind::Add, t1, k, &mut f);
        t1 = step(Kind::Add, t1, word, &mut f);
        let s0 = sigma(aa, big0, false, &mut f);
        let ab = step(Kind::And, aa, b, &mut f);
        let axb = step(Kind::Xor, aa, b, &mut f);
        let abc = step(Kind::And, axb, c, &mut f);
        let maj = step(Kind::Xor, ab, abc, &mut f);
        let t2 = step(Kind::Add, s0, maj, &mut f);
        let ne = step(Kind::Add, d, t1, &mut f);
        let na = step(Kind::Add, t1, t2, &mut f);
        v = [na, aa, b, c, ne, e, ff, g];
    }
    std::array::from_fn(|i| step(Kind::Add, v[i], input.chaining_value[i], &mut f))
}
fn native(a: Sha2Algorithm, op: Operation) -> u64 {
    match op.kind {
        Kind::Add => {
            if a == Sha2Algorithm::Sha256 {
                (op.x + op.y) & u64::from(u32::MAX)
            } else {
                op.x.wrapping_add(op.y)
            }
        }
        Kind::Xor => op.x ^ op.y,
        Kind::And => op.x & op.y,
        Kind::Rotate(n) => {
            if a == Sha2Algorithm::Sha256 {
                u64::from((op.x as u32).rotate_right(n))
            } else {
                op.x.rotate_right(n)
            }
        }
        Kind::Shift(n) => op.x >> n,
    }
}
fn validate_inputs(a: Sha2Algorithm, inputs: &[CompressionInput]) -> Result<(), String> {
    if inputs.is_empty() || inputs.len() > MAX_SHA2_BATCH {
        return Err("invalid SHA2 compression batch count".into());
    }
    if a == Sha2Algorithm::Sha256
        && inputs.iter().any(|i| {
            i.chaining_value
                .iter()
                .chain(&i.block)
                .any(|&v| v > u64::from(u32::MAX))
        })
    {
        return Err("SHA256 word exceeds32 bits".into());
    }
    Ok(())
}
fn options() -> ProofOptions {
    // Preserve the existing query/blowup/grinding/FRI profile; quadratic Goldilocks
    // gives a 128-bit extension while limb values stay strictly below the base prime.
    ProofOptions::new(
        28,
        8,
        16,
        FieldExtension::Quadratic,
        8,
        255,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}
#[derive(Clone)]
struct Statement {
    algorithm: Sha2Algorithm,
    inputs: Vec<CompressionInput>,
    operations: Vec<u64>,
    carries: Vec<u8>,
}
impl Statement {
    fn carry_count(&self) -> usize {
        self.algorithm.additions() * self.algorithm.lanes() * self.inputs.len()
    }
    fn slots(&self) -> usize {
        (self.operations.len() * self.algorithm.lanes()).next_power_of_two()
    }
    fn trace_info(&self) -> TraceInfo {
        TraceInfo::new(WIDTH, 2 * self.slots())
    }
    fn validate(&self) -> Result<(), String> {
        validate_inputs(self.algorithm, &self.inputs)?;
        if self.operations.len() != self.algorithm.operations() * self.inputs.len()
            || self.carries.len() != self.carry_count().div_ceil(8)
            || self.algorithm == Sha2Algorithm::Sha256
                && self.operations.iter().any(|&v| v > u64::from(u32::MAX))
        {
            return Err("invalid SHA2 operation/carry shape".into());
        }
        let extra = self.carry_count() % 8;
        if extra != 0 && self.carries.last().is_some_and(|b| *b >> extra != 0) {
            return Err("noncanonical SHA2 carry padding".into());
        }
        Ok(())
    }
    fn public_rows(&self) -> Vec<[u32; PUBLIC]> {
        let mut rows: Vec<[u32; PUBLIC]> = Vec::with_capacity(self.slots());
        let mut op_index = 0;
        let mut carry_index = 0;
        let mut carry = || {
            let b = (self.carries[carry_index / 8] >> (carry_index % 8)) & 1;
            carry_index += 1;
            u32::from(b)
        };
        for input in &self.inputs {
            route(self.algorithm, input, |op| {
                let out = self.operations[op_index];
                op_index += 1;
                let lanes = self.algorithm.lanes();
                for lane in 0..lanes {
                    let word = |v: u64| (v >> (32 * lane)) as u32;
                    let (kind, x, y, cin, cout) = match op.kind {
                        Kind::Add => {
                            let lo = if lane == 0 {
                                0
                            } else {
                                rows.last().expect("low limb row")[KINDS + 4]
                            };
                            (0, word(op.x), word(op.y), lo, carry())
                        }
                        Kind::Xor => (1, word(op.x), word(op.y), 0, 0),
                        Kind::And => (2, word(op.x), word(op.y), 0, 0),
                        Kind::Rotate(n) | Kind::Shift(n) => {
                            let d = n as usize;
                            let k = d % 32;
                            let other = if matches!(op.kind, Kind::Rotate(_)) {
                                if lanes == 1 {
                                    op.x as u32
                                } else {
                                    (op.x >> (32 * (1 - lane))) as u32
                                }
                            } else if lanes == 2 && lane == 0 {
                                (op.x >> 32) as u32
                            } else {
                                0
                            };
                            let (x, y) = if d >= 32 {
                                (other, word(op.x))
                            } else {
                                (word(op.x), other)
                            };
                            (
                                3 + SHIFTS
                                    .iter()
                                    .position(|&v| v == k)
                                    .expect("fixed SHA2 shift"),
                                x,
                                y,
                                0,
                                0,
                            )
                        }
                    };
                    let mut row = [0; PUBLIC];
                    row[kind] = 1;
                    row[KINDS..].copy_from_slice(&[x, y, cin, word(out), cout]);
                    rows.push(row);
                }
                out
            });
        }
        debug_assert_eq!(op_index, self.operations.len());
        debug_assert_eq!(carry_index, self.carry_count());
        rows.resize(self.slots(), [0; PUBLIC]);
        rows
    }
}
impl ToElements<BaseElement> for Statement {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![
            BaseElement::new(u64::from_le_bytes(*b"SHA2CMP1")),
            BaseElement::new(if self.algorithm == Sha2Algorithm::Sha256 {
                256
            } else {
                512
            }),
            BaseElement::new(self.inputs.len() as u64),
        ];
        // Split ALL 64-bit words: direct Goldilocks reduction would alias values
        // at or above its modulus, including valid SHA512 chaining/block words.
        for &v in self
            .inputs
            .iter()
            .flat_map(|i| i.chaining_value.iter().chain(&i.block))
            .chain(&self.operations)
        {
            out.push(BaseElement::new(u64::from(v as u32)));
            out.push(BaseElement::new(v >> 32));
        }
        out.extend(self.carries.iter().map(|&v| BaseElement::new(u64::from(v))));
        out
    }
}
fn witness(public: &[u32; PUBLIC]) -> Vec<BaseElement> {
    let mut row = vec![BaseElement::ZERO; WIDTH];
    for (i, &v) in public.iter().enumerate() {
        row[i] = BaseElement::new(u64::from(v));
    }
    for (group, &v) in [public[KINDS], public[KINDS + 1], public[KINDS + 3]]
        .iter()
        .enumerate()
    {
        for bit in 0..32 {
            row[PUBLIC + 32 * group + bit] = BaseElement::new(u64::from((v >> bit) & 1));
        }
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
        assert_eq!(info, statement.trace_info());
        let mut degrees = vec![TransitionConstraintDegree::new(2); BOOLS + 2];
        degrees.extend((0..3).map(|_| TransitionConstraintDegree::new(1)));
        degrees.extend((0..3).map(|_| TransitionConstraintDegree::new(2)));
        degrees.extend((0..32).map(|_| TransitionConstraintDegree::new(3)));
        debug_assert_eq!(degrees.len(), CONSTRAINTS);
        Self {
            context: AirContext::new(info, degrees, PUBLIC, options),
            statement,
        }
    }
    fn evaluate_transition<E: FieldElement<BaseField = BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _: &[E],
        result: &mut [E],
    ) {
        let row = frame.current();
        let one = E::ONE;
        let two = E::from(2u32);
        for i in 0..BOOLS {
            let b = row[PUBLIC + i];
            result[i] = b * (b - one);
        }
        let cin = row[KINDS + 2];
        let cout = row[KINDS + 4];
        result[BOOLS] = cin * (cin - one);
        result[BOOLS + 1] = cout * (cout - one);
        for (group, col) in [KINDS, KINDS + 1, KINDS + 3].into_iter().enumerate() {
            let mut v = E::ZERO;
            let mut p = one;
            for bit in 0..32 {
                v += row[PUBLIC + 32 * group + bit] * p;
                p += p;
            }
            result[BOOLS + 2 + group] = v - row[col];
        }
        result[BOOLS + 5] = row[0]
            * (row[KINDS] + row[KINDS + 1] + cin
                - row[KINDS + 3]
                - cout * E::from(BaseElement::new(1u64 << 32)));
        result[BOOLS + 6] = (one - row[0]) * cin;
        result[BOOLS + 7] = (one - row[0]) * cout;
        for bit in 0..32 {
            let x = row[X + bit];
            let y = row[Y + bit];
            let out = row[OUT + bit];
            let mut v = row[1] * (out - x - y + two * x * y) + row[2] * (out - x * y);
            for (i, &shift) in SHIFTS.iter().enumerate() {
                let index = bit + shift;
                let expected = if index < 32 {
                    row[X + index]
                } else {
                    row[Y + index - 32]
                };
                v += row[3 + i] * (out - expected);
            }
            result[BOOLS + 8 + bit] = v;
        }
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = self.statement.public_rows();
        (0..PUBLIC)
            .map(|col| {
                Assertion::sequence(
                    col,
                    0,
                    2,
                    rows.iter()
                        .map(|row| BaseElement::new(u64::from(row[col])))
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

/// Prove every compression's full schedule,64/80 rounds and eight-word feedforward.
/// Inputs may have independently supplied chaining values for verified prefix reuse.
pub fn prove_compression_batch(
    algorithm: Sha2Algorithm,
    inputs: &[CompressionInput],
) -> Result<Sha2CompressionProof, String> {
    validate_inputs(algorithm, inputs)?;
    let mut operations = Vec::new();
    let mut carries = Vec::new();
    let mut carry_count = 0;
    let mut append_carry = |value: u64| {
        if carry_count % 8 == 0 {
            carries.push(0);
        }
        carries[carry_count / 8] |= (value as u8) << (carry_count % 8);
        carry_count += 1;
    };
    for input in inputs {
        route(algorithm, input, |op| {
            let value = native(algorithm, op);
            operations.push(value);
            if matches!(op.kind, Kind::Add) {
                let low = ((op.x as u32 as u64) + (op.y as u32 as u64)) >> 32;
                append_carry(low);
                if algorithm == Sha2Algorithm::Sha512 {
                    append_carry(((op.x >> 32) + (op.y >> 32) + low) >> 32);
                }
            }
            value
        });
    }
    let statement = Statement {
        algorithm,
        inputs: inputs.to_vec(),
        operations: operations.clone(),
        carries: carries.clone(),
    };
    statement.validate()?;
    let info = statement.trace_info();
    let mut trace = TraceTable::new(WIDTH, info.length());
    for (i, row) in statement.public_rows().iter().enumerate() {
        let row = witness(row);
        trace.update_row(2 * i, &row);
        trace.update_row(2 * i + 1, &row);
    }
    let mut padding =
        blake3::Hasher::new_derive_key("Shell-Chain SHA2 compression terminal row v1");
    for v in statement.to_elements() {
        padding.update(&v.as_int().to_le_bytes());
    }
    let mut bytes = vec![0; 8 * WIDTH];
    padding.finalize_xof().fill(&mut bytes);
    let last = bytes
        .chunks_exact(8)
        .map(|b| BaseElement::new(u64::from_le_bytes(b.try_into().expect("eight bytes"))))
        .collect::<Vec<_>>();
    trace.update_row(info.length() - 1, &last);
    let proof = CompressionProver {
        statement,
        options: options(),
    }
    .prove(trace)
    .map_err(|e| format!("SHA2 compression proving: {e:?}"))?;
    Ok(Sha2CompressionProof {
        version: 1,
        algorithm,
        inputs: inputs.to_vec(),
        operations,
        carries,
        proof_bytes: proof.to_bytes(),
    })
}
/// Verify against caller-supplied expected inputs, without evaluating native SHA.
/// Compression certificates alone do not establish padding, digest chaining or SLH.
pub fn verify_compression_batch(
    proof: &Sha2CompressionProof,
    algorithm: Sha2Algorithm,
    expected: &[CompressionInput],
) -> Result<Vec<[u64; 8]>, String> {
    validate_inputs(algorithm, expected)?;
    if proof.version != 1
        || proof.algorithm != algorithm
        || proof.inputs != expected
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("invalid SHA2 compression version/input/payload binding".into());
    }
    if proof.operations.len() != algorithm.operations() * expected.len()
        || proof.carries.len()
            != (algorithm.additions() * algorithm.lanes() * expected.len()).div_ceil(8)
    {
        return Err("invalid SHA2 operation/carry count".into());
    }
    let statement = Statement {
        algorithm,
        inputs: expected.to_vec(),
        operations: proof.operations.clone(),
        carries: proof.carries.clone(),
    };
    statement.validate()?;
    let inner = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| format!("SHA2 compression decode: {e:?}"))?;
    if inner.trace_info() != &statement.trace_info() {
        return Err("unexpected SHA2 compression trace layout".into());
    }
    let outputs = statement
        .operations
        .chunks_exact(algorithm.operations())
        .map(|ops| {
            ops[ops.len() - 8..]
                .try_into()
                .expect("eight feedforward words")
        })
        .collect();
    verify::<CompressionAir, Hasher, Coin, Commitment>(
        inner,
        statement,
        &AcceptableOptions::OptionSet(vec![options()]),
    )
    .map_err(|e| format!("SHA2 compression verification: {e:?}"))?;
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha512};
    use winterfell::math::StarkField;

    fn padded(a: Sha2Algorithm, message: &[u8]) -> CompressionInput {
        let mut block = [0u8; 128];
        let size = if a == Sha2Algorithm::Sha256 { 64 } else { 128 };
        block[..message.len()].copy_from_slice(message);
        block[message.len()] = 0x80;
        block[size - 8..size].copy_from_slice(&((message.len() as u64) * 8).to_be_bytes());
        let words = if a == Sha2Algorithm::Sha256 {
            std::array::from_fn(|i| {
                u64::from(u32::from_be_bytes(
                    block[4 * i..4 * i + 4].try_into().unwrap(),
                ))
            })
        } else {
            std::array::from_fn(|i| u64::from_be_bytes(block[8 * i..8 * i + 8].try_into().unwrap()))
        };
        CompressionInput {
            chaining_value: if a == Sha2Algorithm::Sha256 {
                SHA256_INITIAL_STATE
            } else {
                SHA512_INITIAL_STATE
            },
            block: words,
        }
    }
    fn reference(a: Sha2Algorithm, input: &CompressionInput) -> [u64; 8] {
        if a == Sha2Algorithm::Sha256 {
            let mut state = input.chaining_value.map(|x| x as u32);
            let bytes: [u8; 64] = input
                .block
                .iter()
                .flat_map(|&x| (x as u32).to_be_bytes())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            sha2::compress256(&mut state, &[bytes.into()]);
            state.map(u64::from)
        } else {
            let mut state = input.chaining_value;
            let bytes: [u8; 128] = input
                .block
                .iter()
                .flat_map(|x| x.to_be_bytes())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            sha2::compress512(&mut state, &[bytes.into()]);
            state
        }
    }
    fn check(a: Sha2Algorithm) {
        let mask = if a == Sha2Algorithm::Sha256 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let mut arbitrary = CompressionInput {
            chaining_value: [mask; 8],
            block: [mask; 16],
        };
        arbitrary.chaining_value[0] = 0;
        if a == Sha2Algorithm::Sha512 {
            arbitrary.block[7] = BaseElement::MODULUS;
        }
        let inputs = vec![padded(a, b""), padded(a, b"abc"), arbitrary];
        let expected = inputs.iter().map(|x| reference(a, x)).collect::<Vec<_>>();
        let proof = prove_compression_batch(a, &inputs).unwrap();
        assert_eq!(
            verify_compression_batch(&proof, a, &inputs).unwrap(),
            expected
        );
        let digest = if a == Sha2Algorithm::Sha256 {
            expected[1]
                .iter()
                .flat_map(|&x| (x as u32).to_be_bytes())
                .collect::<Vec<_>>()
        } else {
            expected[1]
                .iter()
                .flat_map(|x| x.to_be_bytes())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            digest,
            if a == Sha2Algorithm::Sha256 {
                Sha256::digest(b"abc").to_vec()
            } else {
                Sha512::digest(b"abc").to_vec()
            }
        );
        let mut encoded = Vec::new();
        ciborium::into_writer(&proof, &mut encoded).unwrap();
        let reopened: Sha2CompressionProof = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(
            verify_compression_batch(&reopened, a, &inputs).unwrap(),
            expected
        );
        let mut changed = inputs.clone();
        changed[0].block[0] ^= 1;
        assert!(verify_compression_batch(&proof, a, &changed).is_err());
        let other = if a == Sha2Algorithm::Sha256 {
            Sha2Algorithm::Sha512
        } else {
            Sha2Algorithm::Sha256
        };
        assert!(verify_compression_batch(&proof, other, &inputs).is_err());
        for mutation in 0..6 {
            let mut forged = proof.clone();
            match mutation {
                0 => forged.version = 0,
                1 => forged.operations[0] ^= 1,
                2 => forged.carries[0] ^= 1,
                3 => {
                    forged.operations.pop();
                }
                4 => forged.carries.push(0),
                _ => {
                    let n = forged.proof_bytes.len() / 2;
                    forged.proof_bytes[n] ^= 1;
                }
            }
            assert!(
                verify_compression_batch(&forged, a, &inputs).is_err(),
                "mutation{mutation}"
            );
        }
        if a == Sha2Algorithm::Sha512 {
            let mut alias = proof.clone();
            alias.inputs[2].chaining_value[0] = BaseElement::MODULUS;
            assert!(
                verify_compression_batch(&alias, a, &alias.inputs).is_err(),
                "full64-bit public values must not alias modulo Goldilocks"
            );
        }
        assert!(prove_compression_batch(a, &[]).is_err());
        assert!(prove_compression_batch(a, &vec![inputs[0].clone(); MAX_SHA2_BATCH + 1]).is_err());
        println!("SHA2 {a:?}: three independent blocks, full rounds/feedforward, max-word carries, serialized reopen and genuine STARK refusals; {} proof bytes",proof.proof_bytes.len());
    }
    #[test]
    fn sha256_real_batch_and_refusals() {
        check(Sha2Algorithm::Sha256);
    }
    #[test]
    fn sha512_real_batch_and_refusals() {
        check(Sha2Algorithm::Sha512);
    }
    #[test]
    fn sha256_rejects_wide_words() {
        let mut p = padded(Sha2Algorithm::Sha256, b"");
        p.block[0] = 1u64 << 32;
        assert!(prove_compression_batch(Sha2Algorithm::Sha256, &[p]).is_err());
    }
    #[test]
    fn each_operator_and_carry_is_constrained() {
        let statement = Statement {
            algorithm: Sha2Algorithm::Sha512,
            inputs: vec![CompressionInput {
                chaining_value: [0; 8],
                block: [0; 16],
            }],
            operations: vec![0; 2760],
            carries: vec![0; 190],
        };
        let air = CompressionAir::new(statement.trace_info(), statement, options());
        let valid = |p: &[u32; PUBLIC]| {
            let row = witness(p);
            let mut frame = EvaluationFrame::new(WIDTH);
            frame.current_mut().copy_from_slice(&row);
            frame.next_mut().copy_from_slice(&row);
            let mut result = vec![BaseElement::ZERO; CONSTRAINTS];
            air.evaluate_transition(&frame, &[], &mut result);
            result.iter().all(|x| *x == BaseElement::ZERO)
        };
        for kind in 0..KINDS {
            let x = 0xfedcba98u32;
            let y = 0x7f3c91d5u32;
            let (out, carry) = match kind {
                0 => {
                    let sum = u64::from(x) + u64::from(y);
                    (sum as u32, (sum >> 32) as u32)
                }
                1 => (x ^ y, 0),
                2 => (x & y, 0),
                _ => {
                    let k = SHIFTS[kind - 3];
                    ((x >> k) | (y << (32 - k)), 0)
                }
            };
            let mut p = [0; PUBLIC];
            p[kind] = 1;
            p[KINDS..].copy_from_slice(&[x, y, 0, out, carry]);
            assert!(valid(&p), "operator{kind}");
            p[KINDS + 3] ^= 1;
            assert!(!valid(&p), "operator{kind} must constrain output");
        }
        let mut p = [0; PUBLIC];
        p[0] = 1;
        p[KINDS..].copy_from_slice(&[u32::MAX, 1, 1, 1, 1]);
        assert!(valid(&p));
        p[KINDS + 4] = 0;
        assert!(!valid(&p));
        p[KINDS + 4] = 2;
        assert!(!valid(&p));
    }
}
