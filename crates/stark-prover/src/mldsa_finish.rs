//! ML-DSA-65 Decompose/UseHint, strict z norm and w1 encoding constraints.
//!
//! Public canonical inputs are authenticated by the signature/equation proofs.
//! Private bounded decompositions prove every hint and norm; verification does
//! not run native Decompose, UseHint, norm checks or nibble packing.

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

const N: usize = 256;
const K: usize = 6;
const L: usize = 5;
const GAMMA2: u32 = (NTT_MODULUS - 1) / 32;
/// FIPS 204 ML-DSA-65 gamma1 - beta; the z norm must be strictly smaller.
pub const Z_NORM_BOUND: u32 = 524_288 - 196;
const SLOTS: usize = 4096;
const TRACE_LENGTH: usize = 2 * SLOTS;
const H: usize = 0;
const NORM: usize = 1;
const PACK: usize = 2;
const X: usize = 3;
const Y: usize = 4;
const Z: usize = 5;
const W: usize = 6;
const POS: usize = 7;
const PLUS: usize = 8;
const MINUS: usize = 9;
const LOW: usize = 10;
const COMP: usize = 29;
const GAP: usize = 48;
const HIGH: usize = 66;
const RESULT: usize = 70;
const INV: usize = 74;
const TRACE_WIDTH: usize = 75;
const BOOLS: usize = INV - W;
const CONSTRAINTS: usize = BOOLS + 12;
const MAX_PROOF_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishInputs {
    pub w_approx: Vec<Vec<u32>>,
    pub hints: Vec<Vec<u8>>,
    pub z: Vec<Vec<u32>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishProof {
    pub version: u8,
    pub inputs: FinishInputs,
    pub w1: Vec<Vec<u8>>,
    pub encoded: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}
#[derive(Clone)]
struct Statement {
    inputs: FinishInputs,
    w1: Vec<Vec<u8>>,
    encoded: Vec<u8>,
}
impl ToElements<BaseElement> for Statement {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![BaseElement::new(u64::from_le_bytes(*b"MLFIN001") as u128)];
        for values in [&self.inputs.w_approx, &self.inputs.z] {
            out.extend(values.iter().flatten().map(|&v| BaseElement::new(v.into())));
        }
        for values in [&self.inputs.hints, &self.w1] {
            out.extend(values.iter().flatten().map(|&v| BaseElement::new(v.into())));
        }
        out.extend(self.encoded.iter().map(|&v| BaseElement::new(v.into())));
        out
    }
}
fn polynomials(values: &[Vec<u32>], count: usize) -> bool {
    values.len() == count
        && values
            .iter()
            .all(|p| p.len() == N && p.iter().all(|&v| v < NTT_MODULUS))
}
fn bytes(values: &[Vec<u8>]) -> bool {
    values.len() == K && values.iter().all(|p| p.len() == N)
}
fn validate(inputs: &FinishInputs) -> Result<(), String> {
    if !polynomials(&inputs.w_approx, K) || !polynomials(&inputs.z, L) || !bytes(&inputs.hints) {
        return Err(
            "finish requires six canonical w, six hint and five canonical z polynomials".into(),
        );
    }
    Ok(())
}
// Prover witness only. The right-closed low interval and q-1 exception follow
// FIPS 204 Decompose; hint at low == 0 decrements, including high == 0 wrap.
fn decompose(r: u32) -> (u32, i64, u32) {
    let alpha = i64::from(2 * GAMMA2);
    let r = i64::from(r);
    let mut low = r % alpha;
    if low > i64::from(GAMMA2) {
        low -= alpha;
    }
    if r - low == i64::from(NTT_MODULUS - 1) {
        (0, low - 1, 1)
    } else {
        (((r - low) / alpha) as u32, low, 0)
    }
}
fn calculate(inputs: &FinishInputs) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    if inputs.hints.iter().flatten().any(|&h| h > 1) {
        return Err("nonbinary hint".into());
    }
    for &z in inputs.z.iter().flatten() {
        if z.min(NTT_MODULUS - z) >= Z_NORM_BOUND {
            return Err("z norm is not strictly below gamma1 - beta".into());
        }
    }
    let w1: Vec<Vec<u8>> = inputs
        .w_approx
        .iter()
        .zip(&inputs.hints)
        .map(|(w, hints)| {
            w.iter()
                .zip(hints)
                .map(|(&r, &h)| {
                    let (high, low, _) = decompose(r);
                    (i64::from(high) + i64::from(h) * if low > 0 { 1 } else { -1 }).rem_euclid(16)
                        as u8
                })
                .collect()
        })
        .collect();
    let encoded = w1
        .iter()
        .flat_map(|p| p.chunks_exact(2).map(|a| a[0] | a[1] << 4))
        .collect();
    Ok((w1, encoded))
}
// Public routing and selectors, without arithmetic decisions about the witness.
fn public_rows(s: &Statement) -> Vec<[u32; W]> {
    let mut rows = vec![[0; W]; SLOTS];
    for r in 0..K {
        for i in 0..N {
            rows[r * N + i] = [
                1,
                0,
                0,
                s.inputs.w_approx[r][i],
                s.inputs.hints[r][i].into(),
                s.w1[r][i].into(),
            ];
        }
    }
    for r in 0..L {
        for i in 0..N {
            rows[K * N + r * N + i] = [0, 1, 0, s.inputs.z[r][i], 0, 0];
        }
    }
    for r in 0..K {
        for i in 0..N / 2 {
            rows[(K + L) * N + r * N / 2 + i] = [
                0,
                0,
                1,
                s.w1[r][2 * i].into(),
                s.w1[r][2 * i + 1].into(),
                s.encoded[r * N / 2 + i].into(),
            ];
        }
    }
    rows
}
fn bits(row: &mut [BaseElement], start: usize, count: usize, value: u32) {
    for bit in 0..count {
        row[start + bit] = BaseElement::new(((value >> bit) & 1).into());
    }
}
fn witness(public: &[u32; W]) -> Vec<BaseElement> {
    let mut row = vec![BaseElement::ZERO; TRACE_WIDTH];
    for (col, &v) in public.iter().enumerate() {
        row[col] = BaseElement::new(v.into());
    }
    if public[H] == 1 {
        let (high, low, wrap) = decompose(public[X]);
        let m = (low + i64::from(GAMMA2)) as u32;
        let pos = u32::from(low > 0);
        let gap = (low - 1 + i64::from((1 - pos) * (1 << 18))) as u32;
        let tentative = i64::from(high) + i64::from(public[Y]) * (2 * i64::from(pos) - 1);
        row[W] = BaseElement::new(wrap.into());
        row[POS] = BaseElement::new(pos.into());
        row[PLUS] = BaseElement::new(u32::from(tentative < 0).into());
        row[MINUS] = BaseElement::new(u32::from(tentative >= 16).into());
        bits(&mut row, LOW, 19, m);
        bits(&mut row, COMP, 19, 2 * GAMMA2 - m);
        bits(&mut row, GAP, 18, gap);
        bits(&mut row, HIGH, 4, high);
        bits(&mut row, RESULT, 4, public[Z]);
        row[INV] = BaseElement::new((m + wrap).into()).inv();
    } else if public[NORM] == 1 {
        let magnitude = public[X].min(NTT_MODULUS - public[X]);
        row[W] = BaseElement::new(u32::from(public[X] > (NTT_MODULUS - 1) / 2).into());
        bits(&mut row, LOW, 19, magnitude);
        bits(&mut row, COMP, 19, Z_NORM_BOUND - 1 - magnitude);
    }
    row
}
struct FinishAir {
    context: AirContext<BaseElement>,
    statement: Statement,
}
impl Air for FinishAir {
    type BaseField = BaseElement;
    type PublicInputs = Statement;
    fn new(info: TraceInfo, statement: Statement, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH));
        let mut degrees = vec![TransitionConstraintDegree::new(2); BOOLS];
        degrees.extend([3, 2, 2, 3, 2, 3, 2, 3, 3, 3, 2, 2].map(TransitionConstraintDegree::new));
        debug_assert_eq!(degrees.len(), CONSTRAINTS);
        Self {
            context: AirContext::new(info, degrees, W, options),
            statement,
        }
    }
    fn evaluate_transition<E: FieldElement + From<BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let r = frame.current();
        let f = |v: u32| E::from(BaseElement::new(v.into()));
        let sum = |start: usize, count: usize| {
            let mut out = E::ZERO;
            let mut weight = E::ONE;
            for &b in &r[start..start + count] {
                out += b * weight;
                weight = weight + weight;
            }
            out
        };
        for col in W..INV {
            result[col - W] = r[col] * (r[col] - E::ONE);
        }
        let m = sum(LOW, 19);
        let comp = sum(COMP, 19);
        let high = sum(HIGH, 4);
        let o = &mut result[BOOLS..];
        o[0] = r[H] * r[Y] * (r[Y] - E::ONE);
        o[1] = r[H] * (r[X] - f(2 * GAMMA2) * high - (m - f(GAMMA2)) - f(NTT_MODULUS) * r[W]);
        o[2] = r[H] * (m + comp - f(2 * GAMMA2));
        o[3] = r[H] * ((m + r[W]) * r[INV] - E::ONE);
        o[4] = r[H] * (m - f(GAMMA2) - E::ONE - sum(GAP, 18) + f(1 << 18) * (E::ONE - r[POS]));
        o[5] = r[H] * r[W] * high;
        o[6] = r[H] * (r[Z] - sum(RESULT, 4));
        o[7] = r[H] * r[PLUS] * r[MINUS];
        o[8] = r[H]
            * (r[Z] - high - r[Y] * (f(2) * r[POS] - E::ONE) - f(16) * r[PLUS] + f(16) * r[MINUS]);
        o[9] = r[NORM] * (r[X] - m - f(NTT_MODULUS) * r[W] + f(2) * m * r[W]);
        o[10] = r[NORM] * (m + comp - f(Z_NORM_BOUND - 1));
        o[11] = r[PACK] * (r[Z] - r[X] - f(16) * r[Y]);
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = public_rows(&self.statement);
        (0..W)
            .map(|col| {
                Assertion::sequence(
                    col,
                    0,
                    2,
                    rows.iter()
                        .map(|r| BaseElement::new(r[col].into()))
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

struct FinishProver {
    statement: Statement,
    options: ProofOptions,
}

impl Prover for FinishProver {
    type BaseField = BaseElement;
    type Air = FinishAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, FinishAir, E>;

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
        air: &'a FinishAir,
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

/// Prove all six hint polynomials, five strict z norms and 768 encoded bytes.
pub fn prove_finish(inputs: &FinishInputs) -> Result<FinishProof, String> {
    validate(inputs)?;
    let (w1, encoded) = calculate(inputs)?;
    let statement = Statement {
        inputs: inputs.clone(),
        w1: w1.clone(),
        encoded: encoded.clone(),
    };
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (i, public) in public_rows(&statement).iter().enumerate() {
        let row = witness(public);
        trace.update_row(2 * i, &row);
        trace.update_row(2 * i + 1, &row);
    }
    // Only the unused final odd row is padding; every real operation is bound.
    let mut padding = blake3::Hasher::new_derive_key("Shell-Chain ML-DSA finish padding v1");
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
    let proof = FinishProver {
        statement,
        options: default_proof_options(),
    }
    .prove(trace)
    .map_err(|e| format!("finish proving: {e:?}"))?;
    Ok(FinishProof {
        version: 1,
        inputs: inputs.clone(),
        w1,
        encoded,
        proof_bytes: proof.to_bytes(),
    })
}
/// Verify constraints and independently bind the authenticated input and output.
pub fn verify_finish(
    proof: &FinishProof,
    inputs: &FinishInputs,
    w1: &[Vec<u8>],
    encoded: &[u8],
) -> Result<(), String> {
    if proof.version != 1
        || proof.inputs != *inputs
        || proof.w1 != w1
        || proof.encoded != encoded
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("invalid finish version, endpoints or proof payload".into());
    }
    validate(inputs)?;
    // Values of hints, w1 and norms are proved in AIR, not precomputed here.
    if !bytes(w1) || encoded.len() != K * N / 2 {
        return Err("invalid finish output shape".into());
    }
    let inner =
        Proof::from_bytes(&proof.proof_bytes).map_err(|e| format!("finish proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("unexpected finish trace layout".into());
    }
    verify::<FinishAir, Hasher, Coin, Commitment>(
        inner,
        Statement {
            inputs: inputs.clone(),
            w1: w1.to_vec(),
            encoded: encoded.to_vec(),
        },
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("finish verification: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    fn zero() -> FinishInputs {
        FinishInputs {
            w_approx: vec![vec![0; N]; K],
            hints: vec![vec![0; N]; K],
            z: vec![vec![0; N]; L],
        }
    }
    fn input() -> FinishInputs {
        let mut x = zero();
        let boundary = [
            0,
            GAMMA2,
            GAMMA2 + 1,
            NTT_MODULUS - GAMMA2 - 1,
            NTT_MODULUS - GAMMA2,
            NTT_MODULUS - 1,
        ];
        for r in 0..K {
            for i in 0..N {
                x.w_approx[r][i] = boundary[(r + i) % boundary.len()];
                x.hints[r][i] = ((i / 6) % 2) as u8;
            }
        }
        for r in 0..L {
            for i in 0..N {
                x.z[r][i] = [0, Z_NORM_BOUND - 1, NTT_MODULUS - Z_NORM_BOUND + 1][(r + i) % 3];
            }
        }
        x
    }
    fn sample() -> &'static FinishProof {
        static P: OnceLock<FinishProof> = OnceLock::new();
        P.get_or_init(|| prove_finish(&input()).unwrap())
    }
    fn residuals(row: &[BaseElement]) -> Vec<BaseElement> {
        let air = FinishAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            Statement {
                inputs: zero(),
                w1: vec![vec![0; N]; K],
                encoded: vec![0; K * N / 2],
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
    fn holds(row: &[BaseElement]) {
        assert!(residuals(row).iter().all(|&v| v == BaseElement::ZERO));
    }
    #[test]
    fn fips_ties_wrap_zero_hint_and_nibble_order() {
        // Independently enumerated expected FIPS boundaries, including low=0.
        let rs = [
            0,
            GAMMA2,
            GAMMA2 + 1,
            NTT_MODULUS - GAMMA2 - 1,
            NTT_MODULUS - GAMMA2,
            NTT_MODULUS - 1,
        ];
        let high = [0, 0, 1, 15, 0, 0];
        let hinted = [15, 1, 0, 0, 15, 15];
        let mut x = zero();
        for (i, &r) in rs.iter().enumerate() {
            x.w_approx[0][i] = r;
            x.w_approx[1][i] = r;
            x.hints[1][i] = 1;
        }
        let (w, encoded) = calculate(&x).unwrap();
        assert_eq!(&w[0][..6], high);
        assert_eq!(&w[1][..6], hinted);
        assert_eq!(encoded[128], 31);
        let (w1, encoded) = calculate(&input()).unwrap();
        for row in public_rows(&Statement {
            inputs: input(),
            w1,
            encoded,
        }) {
            holds(&witness(&row));
        }
    }
    #[test]
    fn real_boundary_and_zero_proofs_json_and_all_endpoints() {
        let p = sample();
        verify_finish(p, &input(), &p.w1, &p.encoded).unwrap();
        let p: FinishProof = serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
        verify_finish(&p, &input(), &p.w1, &p.encoded).unwrap();
        let p = prove_finish(&zero()).unwrap();
        verify_finish(&p, &zero(), &p.w1, &p.encoded).unwrap();
        for field in 0..6 {
            let mut p = sample().clone();
            match field {
                0 => p.inputs.w_approx[5][255] ^= 1,
                1 => p.inputs.hints[5][255] ^= 1,
                2 => p.inputs.z[4][255] ^= 1,
                3 => p.w1[5][255] ^= 1,
                4 => p.encoded[767] ^= 1,
                _ => p.w1[5][255] = 16,
            }
            assert!(verify_finish(&p, &p.inputs, &p.w1, &p.encoded).is_err());
        }
    }
    #[test]
    fn strict_norm_rejects_both_signed_boundaries() {
        for z in [Z_NORM_BOUND, NTT_MODULUS - Z_NORM_BOUND] {
            let mut x = zero();
            x.z[4][255] = z;
            assert!(prove_finish(&x).unwrap_err().contains("z norm"));
            // A forged field-valued complement satisfies all linear equations;
            // boolean range constraints must reject this strict-boundary escape.
            let mut row = witness(&[0, 1, 0, 0, 0, 0]);
            row[X] = BaseElement::new(z.into());
            row[W] = BaseElement::new(u32::from(z > NTT_MODULUS / 2).into());
            bits(&mut row, LOW, 19, Z_NORM_BOUND);
            row[COMP..GAP].fill(BaseElement::ZERO);
            row[COMP] = -BaseElement::ONE;
            let out = residuals(&row);
            assert!(out[BOOLS..].iter().all(|&v| v == BaseElement::ZERO));
            assert!(out[..BOOLS].iter().any(|&v| v != BaseElement::ZERO));
        }
    }
    #[test]
    fn private_positivity_and_negative_tie_forgery_reject() {
        let mut row = witness(&[1, 0, 0, 0, 1, 15]);
        row[POS] = BaseElement::ONE;
        row[Z] = BaseElement::ONE;
        row[PLUS] = BaseElement::ZERO;
        bits(&mut row, RESULT, 4, 1);
        row[GAP..HIGH].fill(BaseElement::ZERO);
        row[GAP] = -BaseElement::ONE;
        let out = residuals(&row);
        assert!(out[BOOLS..].iter().all(|&v| v == BaseElement::ZERO));
        assert!(out[..BOOLS].iter().any(|&v| v != BaseElement::ZERO));
        let mut row = witness(&[1, 0, 0, GAMMA2, 0, 0]);
        row[W..].fill(BaseElement::ZERO);
        row[Z] = BaseElement::ONE;
        bits(&mut row, COMP, 19, 2 * GAMMA2);
        bits(&mut row, GAP, 18, (1 << 18) - GAMMA2 - 1);
        bits(&mut row, HIGH, 4, 1);
        bits(&mut row, RESULT, 4, 1);
        let out = residuals(&row);
        for (i, &v) in out.iter().enumerate() {
            if i == BOOLS + 3 {
                assert_ne!(v, BaseElement::ZERO);
            } else {
                assert_eq!(v, BaseElement::ZERO);
            }
        }
    }
    #[test]
    fn four_bit_high_and_result_stop_modulus_wrap_forgery() {
        let mut row = witness(&[1, 0, 0, NTT_MODULUS - 2, 0, 0]);
        row[W] = BaseElement::ZERO;
        bits(&mut row, LOW, 19, GAMMA2 - 1);
        bits(&mut row, COMP, 19, GAMMA2 + 1);
        bits(&mut row, GAP, 18, (1 << 18) - 2);
        row[INV] = BaseElement::new((GAMMA2 - 1).into()).inv();
        row[Z] = BaseElement::new(16);
        row[HIGH..INV].fill(BaseElement::ZERO);
        row[HIGH] = BaseElement::new(16);
        row[RESULT] = BaseElement::new(16);
        let out = residuals(&row);
        assert!(out[BOOLS..].iter().all(|&v| v == BaseElement::ZERO));
        assert!(out[..BOOLS].iter().any(|&v| v != BaseElement::ZERO));
    }
    #[test]
    fn malformed_shapes_noncanonical_inputs_and_foreign_proofs_reject() {
        let mut x = zero();
        x.z[0][0] = NTT_MODULUS;
        assert!(prove_finish(&x).is_err());
        let mut x = zero();
        x.hints[5][255] = 2;
        assert!(prove_finish(&x).is_err());
        let mut x = zero();
        x.w_approx.pop();
        assert!(prove_finish(&x).is_err());
        for kind in 0..6 {
            let mut p = sample().clone();
            match kind {
                0 => p.version = 2,
                1 => {
                    p.w1[5].pop();
                }
                2 => {
                    p.encoded.pop();
                }
                3 => p.proof_bytes.truncate(10),
                4 => p.proof_bytes = vec![0; MAX_PROOF_BYTES + 1],
                _ => {
                    p.proof_bytes = crate::prove_sig_batch(&[crate::SigBatchEntry {
                        msg_hash: [1; 32],
                        pk_hash: [2; 32],
                    }])
                    .unwrap()
                    .proof_bytes
                }
            }
            assert!(verify_finish(&p, &p.inputs, &p.w1, &p.encoded).is_err());
        }
    }
}
