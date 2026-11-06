//! ML-DSA-65 signature encoding proof, FIPS 204 Algorithms 19, 21 and 27.
//!
//! Raw signature bytes and decoded outputs are public. The AIR checks byte
//! unpacking, canonical z representation, hint ordering, delimiters and unused
//! padding. It does not verify SHAKE, signature norms, hints applied to the
//! verification equation, or the signature's cryptographic validity.

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

use crate::{mldsa_ntt::NTT_MODULUS, prover::default_proof_options};

pub const MLDSA_SIGNATURE_BYTES: usize = 3309;
const CHALLENGE: usize = 48;
const L: usize = 5;
const K: usize = 6;
const N: usize = 256;
const OMEGA: usize = 55;
const GAMMA1: u32 = 1 << 19;
const HINT_OFFSET: usize = CHALLENGE + L * 640;
const SLOTS: usize = 1024;
const TRACE_LENGTH: usize = SLOTS * 2;
const Z_SELECTOR: usize = 0;
const H_SELECTOR: usize = 1;
const D_SELECTOR: usize = 2;
const COPY_SELECTOR: usize = 3;
const BYTE: usize = 4;
const Z0: usize = 9;
const Z1: usize = 10;
const SIGN0: usize = 11;
const SIGN1: usize = 12;
const Z_BITS: usize = 13;
const POSITION: usize = 53;
const INDEX: usize = 54;
const START: usize = 55;
const END: usize = 56;
const TOTAL: usize = 57;
const SELECTED: usize = 58;
const PREVIOUS: usize = 59;
const FIRST: usize = 60;
const ACTIVE: usize = 61;
const HINT_SUM: usize = 62;
const RANGE: usize = 63;
const RANGE_WIDTHS: [usize; 6] = [6, 6, 6, 8, 6, 6];
const TRACE_WIDTH: usize = 101;
const CONSTRAINTS: usize = 97;
const ASSERTED: [usize; 21] = [
    Z_SELECTOR,
    H_SELECTOR,
    D_SELECTOR,
    COPY_SELECTOR,
    BYTE,
    BYTE + 1,
    BYTE + 2,
    BYTE + 3,
    BYTE + 4,
    Z0,
    Z1,
    POSITION,
    INDEX,
    START,
    END,
    TOTAL,
    SELECTED,
    PREVIOUS,
    FIRST,
    ACTIVE,
    HINT_SUM,
];

/// Canonical field representatives of the five z polynomials and six hint maps.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodedSignature {
    pub challenge: Vec<u8>,
    pub z: Vec<Vec<u32>>,
    pub hints: Vec<Vec<u8>>,
}

/// Public encoding component artifact; not a `SigBatchProof` or signature proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureDecodeProof {
    pub version: u8,
    pub signature: Vec<u8>,
    pub decoded: DecodedSignature,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone)]
struct Inputs {
    signature: Vec<u8>,
    decoded: DecodedSignature,
}

impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = vec![BaseElement::new(u64::from_le_bytes(*b"MLDEC001") as u128)];
        result.extend(self.signature.iter().map(|&v| BaseElement::new(v.into())));
        result.extend(
            self.decoded
                .challenge
                .iter()
                .map(|&v| BaseElement::new(v.into())),
        );
        result.extend(
            self.decoded
                .z
                .iter()
                .flatten()
                .map(|&v| BaseElement::new(v.into())),
        );
        result.extend(
            self.decoded
                .hints
                .iter()
                .flatten()
                .map(|&v| BaseElement::new(v.into())),
        );
        result
    }
}

fn validate_shape(inputs: &Inputs) -> Result<(), String> {
    let d = &inputs.decoded;
    if inputs.signature.len() != MLDSA_SIGNATURE_BYTES
        || d.challenge.len() != CHALLENGE
        || d.z.len() != L
        || d.z.iter().any(|v| v.len() != N)
        || d.z.iter().flatten().any(|&v| v >= NTT_MODULUS)
        || d.hints.len() != K
        || d.hints.iter().any(|v| v.len() != N)
    {
        return Err("invalid ML-DSA-65 decoder public-input shape".into());
    }
    // Hint entries are u8, hence nonnegative. Hint validity/order/count are
    // checked by the AIR, not by re-running the native decoder here.
    Ok(())
}

fn unpack_pair(bytes: &[u8]) -> [u32; 2] {
    let packed = u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], 0, 0, 0]);
    [(packed & 0xfffff) as u32, (packed >> 20) as u32]
}

fn canonical_z(packed: u32) -> u32 {
    (GAMMA1 as i32 - packed as i32).rem_euclid(NTT_MODULUS as i32) as u32
}

// Honest witness construction. Verification below does not call this decoder.
fn decode(signature: &[u8]) -> Result<DecodedSignature, String> {
    if signature.len() != MLDSA_SIGNATURE_BYTES {
        return Err("ML-DSA-65 signature must be 3309 bytes".into());
    }
    let mut z = vec![vec![0; N]; L];
    for (pair, bytes) in signature[CHALLENGE..HINT_OFFSET]
        .chunks_exact(5)
        .enumerate()
    {
        let values = unpack_pair(bytes);
        z[pair / 128][(pair % 128) * 2] = canonical_z(values[0]);
        z[pair / 128][(pair % 128) * 2 + 1] = canonical_z(values[1]);
    }
    let hint_bytes = &signature[HINT_OFFSET..];
    let mut hints = vec![vec![0; N]; K];
    let mut start = 0;
    for (poly, output) in hints.iter_mut().enumerate() {
        let end = usize::from(hint_bytes[OMEGA + poly]);
        if end < start || end > OMEGA {
            return Err("invalid hint delimiter".into());
        }
        for j in start..end {
            if j > start && hint_bytes[j - 1] >= hint_bytes[j] {
                return Err("hint positions must be strictly increasing".into());
            }
            output[usize::from(hint_bytes[j])] = 1;
        }
        start = end;
    }
    if hint_bytes[start..OMEGA].iter().any(|&v| v != 0) {
        return Err("unused hint bytes must be zero".into());
    }
    Ok(DecodedSignature {
        challenge: signature[..CHALLENGE].to_vec(),
        z,
        hints,
    })
}

// Only public address selection and linear sums are computed here. In
// particular, no hint validity predicate or z decoding is used by assertions.
fn public_rows(inputs: &Inputs) -> Vec<Vec<BaseElement>> {
    let mut rows = vec![vec![BaseElement::ZERO; TRACE_WIDTH]; SLOTS];
    let field = |v: usize| BaseElement::new(v as u128);
    for (pair, row) in rows[..640].iter_mut().enumerate() {
        row[Z_SELECTOR] = BaseElement::ONE;
        for i in 0..5 {
            row[BYTE + i] = field(inputs.signature[CHALLENGE + pair * 5 + i].into());
        }
        row[Z0] = BaseElement::new(inputs.decoded.z[pair / 128][pair % 128 * 2].into());
        row[Z1] = BaseElement::new(inputs.decoded.z[pair / 128][pair % 128 * 2 + 1].into());
    }
    let bytes = &inputs.signature[HINT_OFFSET..];
    let counts = &bytes[OMEGA..];
    for j in 0..OMEGA {
        let row = &mut rows[640 + j];
        row[H_SELECTOR] = BaseElement::ONE;
        row[POSITION] = field(bytes[j].into());
        row[INDEX] = field(j);
        row[TOTAL] = field(counts[K - 1].into());
        row[PREVIOUS] = field(if j == 0 { 0 } else { bytes[j - 1].into() });
        if let Some(poly) = counts.iter().position(|&end| j < usize::from(end)) {
            let start = if poly == 0 {
                0
            } else {
                usize::from(counts[poly - 1])
            };
            row[ACTIVE] = BaseElement::ONE;
            row[START] = field(start);
            row[END] = field(counts[poly].into());
            row[FIRST] = field(usize::from(j == start));
            row[SELECTED] = field(inputs.decoded.hints[poly][usize::from(bytes[j])].into());
        }
    }
    for poly in 0..K {
        let row = &mut rows[695 + poly];
        row[D_SELECTOR] = BaseElement::ONE;
        row[START] = field(if poly == 0 {
            0
        } else {
            counts[poly - 1].into()
        });
        row[END] = field(counts[poly].into());
        row[HINT_SUM] = field(
            inputs.decoded.hints[poly]
                .iter()
                .map(|&v| usize::from(v))
                .sum(),
        );
    }
    for i in 0..CHALLENGE {
        rows[701 + i][COPY_SELECTOR] = BaseElement::ONE;
        rows[701 + i][BYTE] = field(inputs.signature[i].into());
        rows[701 + i][Z0] = field(inputs.decoded.challenge[i].into());
    }
    rows
}

fn witness(row: &mut [BaseElement]) {
    let mut packed = [0u32; 2];
    for bit in 0..40 {
        let value = (row[BYTE + bit / 8].as_int() >> (bit % 8)) & 1;
        row[Z_BITS + bit] = BaseElement::new(value);
        packed[bit / 20] |= (value as u32) << (bit % 20);
    }
    row[SIGN0] = BaseElement::new(u128::from(packed[0] > GAMMA1));
    row[SIGN1] = BaseElement::new(u128::from(packed[1] > GAMMA1));
    let j = row[INDEX].as_int();
    let start = row[START].as_int();
    let end = row[END].as_int();
    let values = [
        j.saturating_sub(start),
        end.saturating_sub(j + 1),
        j.saturating_sub(row[TOTAL].as_int()),
        row[POSITION]
            .as_int()
            .saturating_sub(row[PREVIOUS].as_int() + 1),
        end.saturating_sub(start),
        55u128.saturating_sub(end),
    ];
    let mut column = RANGE;
    for (value, width) in values.into_iter().zip(RANGE_WIDTHS) {
        for bit in 0..width {
            row[column + bit] = BaseElement::new((value >> bit) & 1);
        }
        column += width;
    }
}

struct DecodeAir {
    context: AirContext<BaseElement>,
    inputs: Inputs,
}

impl Air for DecodeAir {
    type BaseField = BaseElement;
    type PublicInputs = Inputs;

    fn new(info: TraceInfo, inputs: Inputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH));
        let mut degrees = vec![TransitionConstraintDegree::new(2); 87];
        degrees.extend((0..6).map(|_| TransitionConstraintDegree::new(3)));
        degrees.extend((0..4).map(|_| TransitionConstraintDegree::new(2)));
        debug_assert_eq!(degrees.len(), CONSTRAINTS);
        Self {
            context: AirContext::new(info, degrees, ASSERTED.len(), options),
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
        let mut n = 0;
        for &b in &r[Z_BITS..Z_BITS + 40] {
            result[n] = b * (b - E::ONE);
            n += 1;
        }
        for &b in &r[RANGE..TRACE_WIDTH] {
            result[n] = b * (b - E::ONE);
            n += 1;
        }
        for c in [SIGN0, SIGN1] {
            result[n] = r[c] * (r[c] - E::ONE);
            n += 1;
        }
        let sum = |bits: &[E]| {
            let mut value = E::ZERO;
            let mut weight = E::ONE;
            for &b in bits {
                value += b * weight;
                weight = weight + weight;
            }
            value
        };
        for byte in 0..5 {
            result[n] = r[Z_SELECTOR]
                * (r[BYTE + byte] - sum(&r[Z_BITS + byte * 8..Z_BITS + byte * 8 + 8]));
            n += 1;
        }
        let gamma = E::from(BaseElement::new(GAMMA1.into()));
        let q = E::from(BaseElement::new(NTT_MODULUS.into()));
        for (offset, coefficient, sign) in [(0, Z0, SIGN0), (20, Z1, SIGN1)] {
            result[n] = r[Z_SELECTOR]
                * (r[coefficient] - gamma + sum(&r[Z_BITS + offset..Z_BITS + offset + 20])
                    - q * r[sign]);
            n += 1;
        }
        let mut ranges = [E::ZERO; 6];
        let mut column = RANGE;
        for (value, width) in ranges.iter_mut().zip(RANGE_WIDTHS) {
            *value = sum(&r[column..column + width]);
            column += width;
        }
        let h = r[H_SELECTOR];
        let a = r[ACTIVE];
        let checks = [
            h * a * (r[INDEX] - r[START] - ranges[0]),
            h * a * (r[END] - r[INDEX] - E::ONE - ranges[1]),
            h * (E::ONE - a) * (r[INDEX] - r[TOTAL] - ranges[2]),
            h * (E::ONE - a) * r[POSITION],
            h * a * (r[SELECTED] - E::ONE),
            h * (a - r[FIRST]) * (r[POSITION] - r[PREVIOUS] - E::ONE - ranges[3]),
            r[D_SELECTOR] * (r[END] - r[START] - ranges[4]),
            r[D_SELECTOR] * (E::from(BaseElement::new(55)) - r[END] - ranges[5]),
            r[D_SELECTOR] * (r[HINT_SUM] - r[END] + r[START]),
            r[COPY_SELECTOR] * (r[BYTE] - r[Z0]),
        ];
        result[n..].copy_from_slice(&checks);
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = public_rows(&self.inputs);
        ASSERTED
            .into_iter()
            .map(|column| {
                Assertion::sequence(column, 0, 2, rows.iter().map(|row| row[column]).collect())
            })
            .collect()
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }
}

fn trace(inputs: &Inputs) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (slot, mut row) in public_rows(inputs).into_iter().enumerate() {
        witness(&mut row);
        trace.update_row(2 * slot, &row);
        trace.update_row(2 * slot + 1, &row);
    }
    let mut hasher = blake3::Hasher::new_derive_key("Shell-Chain ML-DSA decode trace padding v1");
    for value in inputs.to_elements() {
        hasher.update(&value.as_int().to_le_bytes());
    }
    let mut bytes = [0u8; TRACE_WIDTH * 16];
    hasher.finalize_xof().fill(&mut bytes);
    let row: Vec<_> = bytes
        .chunks_exact(16)
        .map(|v| BaseElement::new(u128::from_le_bytes(v.try_into().expect("16 bytes"))))
        .collect();
    trace.update_row(TRACE_LENGTH - 1, &row);
    trace
}

type Hasher = Blake3_256<BaseElement>;
type Commitment = MerkleTree<Hasher>;
type Coin = DefaultRandomCoin<Hasher>;

struct DecodeProver {
    inputs: Inputs,
    options: ProofOptions,
}

impl Prover for DecodeProver {
    type BaseField = BaseElement;
    type Air = DecodeAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, DecodeAir, E>;

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
        air: &'a DecodeAir,
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

/// Prove the canonical encoding interpretation, independently of signature validity.
pub fn prove_signature_decode(signature: &[u8]) -> Result<SignatureDecodeProof, String> {
    let decoded = decode(signature)?;
    let inputs = Inputs {
        signature: signature.to_vec(),
        decoded: decoded.clone(),
    };
    let prover = DecodeProver {
        inputs: inputs.clone(),
        options: default_proof_options(),
    };
    let inner = prover
        .prove(trace(&inputs))
        .map_err(|e| format!("decoder proving: {e:?}"))?;
    Ok(SignatureDecodeProof {
        version: 1,
        signature: signature.to_vec(),
        decoded,
        proof_bytes: inner.to_bytes(),
    })
}

/// Verify the AIR against exact signature bytes supplied independently by the caller.
/// Does not invoke the native signature decoder or native signature verifier.
pub fn verify_signature_decode(
    proof: &SignatureDecodeProof,
    expected_signature: &[u8],
) -> Result<(), String> {
    if proof.version != 1
        || proof.signature != expected_signature
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > 1_048_576
    {
        return Err("invalid decoder version, signature binding or proof size".into());
    }
    let inputs = Inputs {
        signature: proof.signature.clone(),
        decoded: proof.decoded.clone(),
    };
    validate_shape(&inputs)?;
    let inner = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| format!("decoder proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("unexpected decoder trace layout".into());
    }
    verify::<DecodeAir, Hasher, Coin, Commitment>(
        inner,
        inputs,
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("decoder verification: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
    use std::sync::OnceLock;

    struct Sample {
        public_key: Vec<u8>,
        signature: Vec<u8>,
        proof: SignatureDecodeProof,
    }

    fn sample() -> &'static Sample {
        static SAMPLE: OnceLock<Sample> = OnceLock::new();
        SAMPLE.get_or_init(|| {
            let signer = MlDsaSigner::generate();
            let signature = signer.sign(b"decoder AIR genuine ML-DSA-65").unwrap();
            assert!(MlDsaVerifier
                .verify(
                    signer.public_key(),
                    b"decoder AIR genuine ML-DSA-65",
                    &signature
                )
                .unwrap());
            let proof = prove_signature_decode(&signature.data).unwrap();
            Sample {
                public_key: signer.public_key().to_vec(),
                signature: signature.data,
                proof,
            }
        })
    }

    // Independent bit-by-bit encoding, rather than the five-byte unpack loop.
    fn reencode(d: &DecodedSignature) -> Vec<u8> {
        let mut signature = vec![0; MLDSA_SIGNATURE_BYTES];
        signature[..CHALLENGE].copy_from_slice(&d.challenge);
        for (i, &v) in d.z.iter().flatten().enumerate() {
            let signed = if v <= GAMMA1 {
                v as i32
            } else {
                v as i32 - NTT_MODULUS as i32
            };
            let packed = (GAMMA1 as i32 - signed) as u32;
            assert!(packed < (1 << 20));
            for bit in 0..20 {
                let offset = i * 20 + bit;
                signature[CHALLENGE + offset / 8] |= (((packed >> bit) & 1) as u8) << (offset % 8);
            }
        }
        let mut cursor = 0;
        for (poly, hints) in d.hints.iter().enumerate() {
            for (index, &value) in hints.iter().enumerate() {
                assert!(value <= 1);
                if value == 1 {
                    signature[HINT_OFFSET + cursor] = index as u8;
                    cursor += 1;
                }
            }
            signature[HINT_OFFSET + OMEGA + poly] = cursor as u8;
        }
        signature
    }

    fn residuals(row: &[BaseElement]) -> Vec<BaseElement> {
        let inputs = Inputs {
            signature: vec![0; MLDSA_SIGNATURE_BYTES],
            decoded: decode(&vec![0; MLDSA_SIGNATURE_BYTES]).unwrap(),
        };
        let air = DecodeAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            inputs,
            default_proof_options(),
        );
        let frame = EvaluationFrame::from_rows(row.to_vec(), row.to_vec());
        let mut values = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(&frame, &[], &mut values);
        values
    }

    fn all_rows_valid(inputs: &Inputs) -> bool {
        public_rows(inputs).into_iter().all(|mut row| {
            witness(&mut row);
            residuals(&row).iter().all(|&v| v == BaseElement::ZERO)
        })
    }

    #[test]
    fn genuine_signature_encoding_and_real_proof_roundtrip() {
        let sample = sample();
        verify_signature_decode(&sample.proof, &sample.signature).unwrap();
        assert_eq!(reencode(&sample.proof.decoded), sample.signature);
        let json = serde_json::to_vec(&sample.proof).unwrap();
        let restored: SignatureDecodeProof = serde_json::from_slice(&json).unwrap();
        verify_signature_decode(&restored, &sample.signature).unwrap();
        let pq = PQSignature::new(SignatureType::MlDsa65, sample.signature.clone());
        assert!(!MlDsaVerifier
            .verify(&sample.public_key, b"different message", &pq)
            .unwrap());
        // Message validity is deliberately outside this encoding statement.
        verify_signature_decode(&restored, &sample.signature).unwrap();
    }

    #[test]
    fn packing_extremes_and_empty_maximum_hints_match_independent_encoder() {
        for byte in [0, 255, 0x12, 0xab] {
            let mut raw = vec![byte; MLDSA_SIGNATURE_BYTES];
            raw[HINT_OFFSET..].fill(0);
            let decoded = decode(&raw).unwrap();
            assert_eq!(reencode(&decoded), raw);
            assert!(all_rows_valid(&Inputs {
                signature: raw,
                decoded
            }));
        }
        let mut raw = vec![0; MLDSA_SIGNATURE_BYTES];
        for i in 0..OMEGA {
            raw[HINT_OFFSET + i] = i as u8;
        }
        raw[HINT_OFFSET + OMEGA..].fill(OMEGA as u8);
        let decoded = decode(&raw).unwrap();
        assert_eq!(
            decoded.hints[0]
                .iter()
                .map(|&v| usize::from(v))
                .sum::<usize>(),
            OMEGA
        );
        assert_eq!(reencode(&decoded), raw);
        assert!(all_rows_valid(&Inputs {
            signature: raw,
            decoded
        }));
    }

    #[test]
    fn zero_encoding_has_a_real_proof() {
        let raw = vec![0; MLDSA_SIGNATURE_BYTES];
        let proof = prove_signature_decode(&raw).unwrap();
        verify_signature_decode(&proof, &raw).unwrap();
        assert_eq!(proof.decoded.z[0], vec![GAMMA1; N]);
    }

    #[test]
    fn malformed_hint_delimiters_order_and_unused_padding_fail_air() {
        let valid = vec![0; MLDSA_SIGNATURE_BYTES];
        let decoded = decode(&valid).unwrap();
        let mut cases = Vec::new();
        let mut bad = valid.clone();
        bad[HINT_OFFSET + OMEGA] = 56;
        cases.push(bad);
        let mut bad = valid.clone();
        bad[HINT_OFFSET + OMEGA] = 2;
        bad[HINT_OFFSET + OMEGA + 1] = 1;
        cases.push(bad);
        let mut bad = valid.clone();
        bad[HINT_OFFSET] = 3;
        bad[HINT_OFFSET + 1] = 3;
        bad[HINT_OFFSET + OMEGA..].fill(2);
        cases.push(bad);
        let mut bad = valid.clone();
        bad[HINT_OFFSET] = 9;
        bad[HINT_OFFSET + 1] = 3;
        bad[HINT_OFFSET + OMEGA..].fill(2);
        cases.push(bad);
        let mut bad = valid.clone();
        bad[HINT_OFFSET + 54] = 1;
        cases.push(bad);
        for bad in cases {
            assert!(decode(&bad).is_err());
            // Bypass the honest decoder: the actual AIR must also refuse the
            // malformed public encoding with a fabricated output witness.
            assert!(!all_rows_valid(&Inputs {
                signature: bad,
                decoded: decoded.clone()
            }));
        }
    }

    #[test]
    fn output_count_and_private_bit_sign_constraints_are_not_native_checks() {
        let raw = vec![0; MLDSA_SIGNATURE_BYTES];
        let mut decoded = decode(&raw).unwrap();
        decoded.hints[5][255] = 1;
        assert!(!all_rows_valid(&Inputs {
            signature: raw.clone(),
            decoded
        }));
        let inputs = Inputs {
            signature: raw.clone(),
            decoded: decode(&raw).unwrap(),
        };
        let mut row = public_rows(&inputs).remove(0);
        witness(&mut row);
        assert!(residuals(&row).iter().all(|&v| v == BaseElement::ZERO));
        for column in [Z0, SIGN0, Z_BITS, BYTE] {
            let mut bad = row.clone();
            bad[column] += BaseElement::ONE;
            assert!(residuals(&bad).iter().any(|&v| v != BaseElement::ZERO));
        }
    }

    #[test]
    fn tampered_public_encoding_output_version_and_payload_are_rejected() {
        let s = sample();
        let mut bad = s.proof.clone();
        bad.decoded.z[4][255] = (bad.decoded.z[4][255] + 1) % NTT_MODULUS;
        assert!(verify_signature_decode(&bad, &s.signature).is_err());
        let mut bad = s.proof.clone();
        bad.decoded.hints[0][0] ^= 1;
        assert!(verify_signature_decode(&bad, &s.signature).is_err());
        let mut bad = s.proof.clone();
        bad.decoded.challenge[47] ^= 1;
        assert!(verify_signature_decode(&bad, &s.signature).is_err());
        let mut bad = s.proof.clone();
        bad.signature[0] ^= 1;
        assert!(verify_signature_decode(&bad, &bad.signature).is_err());
        let mut bad = s.proof.clone();
        bad.version = 2;
        assert!(verify_signature_decode(&bad, &s.signature).is_err());
        let mut bad = s.proof.clone();
        bad.proof_bytes.truncate(bad.proof_bytes.len() / 2);
        assert!(verify_signature_decode(&bad, &s.signature).is_err());
    }

    #[test]
    fn decoded_polynomial_connects_to_ntt_but_proof_domains_stay_separate() {
        let s = sample();
        verify_signature_decode(&s.proof, &s.signature).unwrap();
        let input: [u32; N] = s.proof.decoded.z[0].clone().try_into().unwrap();
        let ntt = crate::mldsa_ntt::prove_ntt(&input).unwrap();
        let output: [u32; N] = ntt.stages[8].clone().try_into().unwrap();
        crate::mldsa_ntt::verify_ntt(&ntt, &input, &output).unwrap();
        let mut wrong_domain = s.proof.clone();
        wrong_domain.proof_bytes = ntt.proof_bytes;
        assert!(verify_signature_decode(&wrong_domain, &s.signature).is_err());
    }
}
