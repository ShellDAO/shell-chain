//! Public ML-DSA-65 key decoding, FIPS 204 Algorithms 18 and 23.
//!
//! The AIR binds all public key bytes to rho and six ten-bit t1 polynomials.
//! It does not prove key possession or cryptographic signature validity.

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

pub const MLDSA_PUBLIC_KEY_BYTES: usize = 1952;
const RHO: usize = 32;
const K: usize = 6;
const N: usize = 256;
const GROUPS: usize = 384;
const SLOTS: usize = 512;
const TRACE_LENGTH: usize = SLOTS * 2;
const UNPACK: usize = 0;
const COPY: usize = 1;
const BYTE: usize = 2;
const COEFFICIENT: usize = 7;
const BITS: usize = 11;
const TRACE_WIDTH: usize = 51;
const CONSTRAINTS: usize = 50;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodedPublicKey {
    pub rho: Vec<u8>,
    pub t1: Vec<Vec<u16>>,
}

/// Standalone encoding artifact; neither a key-possession nor a signature proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyDecodeProof {
    pub version: u8,
    pub public_key: Vec<u8>,
    pub decoded: DecodedPublicKey,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone)]
struct Inputs {
    key: Vec<u8>,
    decoded: DecodedPublicKey,
}

impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = vec![BaseElement::new(u64::from_le_bytes(*b"MLKEY001") as u128)];
        result.extend(self.key.iter().map(|&v| BaseElement::new(v.into())));
        result.extend(self.decoded.rho.iter().map(|&v| BaseElement::new(v.into())));
        result.extend(
            self.decoded
                .t1
                .iter()
                .flatten()
                .map(|&v| BaseElement::new(v.into())),
        );
        result
    }
}

fn validate_shape(key: &[u8], decoded: &DecodedPublicKey) -> Result<(), String> {
    if key.len() != MLDSA_PUBLIC_KEY_BYTES
        || decoded.rho.len() != RHO
        || decoded.t1.len() != K
        || decoded.t1.iter().any(|v| v.len() != N)
    {
        return Err("invalid ML-DSA-65 public-key encoding shape".into());
    }
    // No native ten-bit range filter: the AIR must establish that bound.
    Ok(())
}

fn decode(key: &[u8]) -> Result<DecodedPublicKey, String> {
    if key.len() != MLDSA_PUBLIC_KEY_BYTES {
        return Err("ML-DSA-65 public key must be 1952 bytes".into());
    }
    let mut t1 = vec![vec![0; N]; K];
    for (group, bytes) in key[RHO..].chunks_exact(5).enumerate() {
        let packed =
            u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], 0, 0, 0]);
        for i in 0..4 {
            t1[group / 64][group % 64 * 4 + i] = ((packed >> (i * 10)) & 1023) as u16;
        }
    }
    Ok(DecodedPublicKey {
        rho: key[..RHO].to_vec(),
        t1,
    })
}

fn public_rows(inputs: &Inputs) -> Vec<Vec<BaseElement>> {
    let mut rows = vec![vec![BaseElement::ZERO; TRACE_WIDTH]; SLOTS];
    for (group, row) in rows[..GROUPS].iter_mut().enumerate() {
        row[UNPACK] = BaseElement::ONE;
        for i in 0..5 {
            row[BYTE + i] = BaseElement::new(inputs.key[RHO + group * 5 + i].into());
        }
        for i in 0..4 {
            row[COEFFICIENT + i] =
                BaseElement::new(inputs.decoded.t1[group / 64][group % 64 * 4 + i].into());
        }
    }
    for i in 0..RHO {
        rows[GROUPS + i][COPY] = BaseElement::ONE;
        rows[GROUPS + i][BYTE] = BaseElement::new(inputs.key[i].into());
        rows[GROUPS + i][COEFFICIENT] = BaseElement::new(inputs.decoded.rho[i].into());
    }
    rows
}

fn witness(row: &mut [BaseElement]) {
    for bit in 0..40 {
        row[BITS + bit] = BaseElement::new((row[BYTE + bit / 8].as_int() >> (bit % 8)) & 1);
    }
}

struct KeyAir {
    context: AirContext<BaseElement>,
    inputs: Inputs,
}

impl Air for KeyAir {
    type BaseField = BaseElement;
    type PublicInputs = Inputs;

    fn new(info: TraceInfo, inputs: Inputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH));
        Self {
            context: AirContext::new(
                info,
                vec![TransitionConstraintDegree::new(2); CONSTRAINTS],
                BITS,
                options,
            ),
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
            result[bit] = r[BITS + bit] * (r[BITS + bit] - E::ONE);
        }
        let sum = |bits: &[E]| {
            let mut value = E::ZERO;
            let mut weight = E::ONE;
            for &bit in bits {
                value += bit * weight;
                weight = weight + weight;
            }
            value
        };
        for i in 0..5 {
            result[40 + i] = r[UNPACK] * (r[BYTE + i] - sum(&r[BITS + i * 8..BITS + i * 8 + 8]));
        }
        for i in 0..4 {
            result[45 + i] =
                r[UNPACK] * (r[COEFFICIENT + i] - sum(&r[BITS + i * 10..BITS + i * 10 + 10]));
        }
        result[49] = r[COPY] * (r[BYTE] - r[COEFFICIENT]);
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = public_rows(&self.inputs);
        (0..BITS)
            .map(|column| {
                Assertion::sequence(column, 0, 2, rows.iter().map(|r| r[column]).collect())
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
        trace.update_row(slot * 2, &row);
        trace.update_row(slot * 2 + 1, &row);
    }
    // This final odd row carries no operation or assertion. Statement-derived
    // padding avoids degenerate trace polynomials for constant key encodings.
    let mut hash =
        blake3::Hasher::new_derive_key("Shell-Chain ML-DSA key decoding trace padding v1");
    for value in inputs.to_elements() {
        hash.update(&value.as_int().to_le_bytes());
    }
    let mut bytes = [0u8; 16 * TRACE_WIDTH];
    hash.finalize_xof().fill(&mut bytes);
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

struct KeyProver {
    inputs: Inputs,
    options: ProofOptions,
}

impl Prover for KeyProver {
    type BaseField = BaseElement;
    type Air = KeyAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, KeyAir, E>;

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
        air: &'a KeyAir,
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

/// Prove the public-key encoding interpretation, not possession of a secret key.
pub fn prove_public_key_decode(key: &[u8]) -> Result<PublicKeyDecodeProof, String> {
    let decoded = decode(key)?;
    let inputs = Inputs {
        key: key.to_vec(),
        decoded: decoded.clone(),
    };
    let prover = KeyProver {
        inputs: inputs.clone(),
        options: default_proof_options(),
    };
    let inner = prover
        .prove(trace(&inputs))
        .map_err(|e| format!("key decoding proof: {e:?}"))?;
    Ok(PublicKeyDecodeProof {
        version: 1,
        public_key: key.to_vec(),
        decoded,
        proof_bytes: inner.to_bytes(),
    })
}

/// Verify the AIR against independently supplied expected public-key bytes.
/// Does not invoke the native public-key decoder.
pub fn verify_public_key_decode(
    proof: &PublicKeyDecodeProof,
    expected_key: &[u8],
) -> Result<(), String> {
    if proof.version != 1
        || proof.public_key != expected_key
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > 1_048_576
    {
        return Err("invalid key decoding version, key binding or proof size".into());
    }
    validate_shape(&proof.public_key, &proof.decoded)?;
    let inner =
        Proof::from_bytes(&proof.proof_bytes).map_err(|e| format!("key proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("unexpected public-key trace layout".into());
    }
    let inputs = Inputs {
        key: proof.public_key.clone(),
        decoded: proof.decoded.clone(),
    };
    verify::<KeyAir, Hasher, Coin, Commitment>(
        inner,
        inputs,
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("key decoding verification: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
    use std::sync::OnceLock;

    struct Sample {
        key: Vec<u8>,
        signature: Vec<u8>,
        proof: PublicKeyDecodeProof,
    }

    fn sample() -> &'static Sample {
        static SAMPLE: OnceLock<Sample> = OnceLock::new();
        SAMPLE.get_or_init(|| {
            let signer = MlDsaSigner::generate();
            let signature = signer.sign(b"public-key decoding AIR").unwrap();
            assert!(MlDsaVerifier
                .verify(signer.public_key(), b"public-key decoding AIR", &signature)
                .unwrap());
            let proof = prove_public_key_decode(signer.public_key()).unwrap();
            Sample {
                key: signer.public_key().to_vec(),
                signature: signature.data,
                proof,
            }
        })
    }

    // Independent per-bit encoder, not the five-byte integer unpack loop.
    fn reencode(decoded: &DecodedPublicKey) -> Vec<u8> {
        let mut key = vec![0; MLDSA_PUBLIC_KEY_BYTES];
        key[..RHO].copy_from_slice(&decoded.rho);
        for (i, &coefficient) in decoded.t1.iter().flatten().enumerate() {
            assert!(coefficient < 1024);
            for bit in 0..10 {
                let offset = i * 10 + bit;
                key[RHO + offset / 8] |= (((coefficient >> bit) & 1) as u8) << (offset % 8);
            }
        }
        key
    }

    #[test]
    fn genuine_key_proof_json_and_independent_reencoding() {
        let s = sample();
        verify_public_key_decode(&s.proof, &s.key).unwrap();
        assert_eq!(reencode(&s.proof.decoded), s.key);
        let restored: PublicKeyDecodeProof =
            serde_json::from_slice(&serde_json::to_vec(&s.proof).unwrap()).unwrap();
        verify_public_key_decode(&restored, &s.key).unwrap();
        let signature = PQSignature::new(SignatureType::MlDsa65, s.signature.clone());
        assert!(!MlDsaVerifier
            .verify(&s.key, b"different message", &signature)
            .unwrap());
        // Key encoding validity is independent of that message/signature check.
        verify_public_key_decode(&s.proof, &s.key).unwrap();
    }

    #[test]
    fn all_polynomials_cross_byte_boundaries_match_bit_encoder() {
        for byte in [0, 255, 0x12, 0xab] {
            let key = vec![byte; MLDSA_PUBLIC_KEY_BYTES];
            let decoded = decode(&key).unwrap();
            assert_eq!(reencode(&decoded), key);
            assert_eq!(decoded.t1.iter().flatten().count(), 1536);
        }
        assert_eq!(1023u32 << 13, crate::mldsa_ntt::NTT_MODULUS - 1);
    }

    #[test]
    fn zero_and_ff_key_encodings_have_real_proofs() {
        for byte in [0, 255] {
            let key = vec![byte; MLDSA_PUBLIC_KEY_BYTES];
            let proof = prove_public_key_decode(&key).unwrap();
            verify_public_key_decode(&proof, &key).unwrap();
            assert_eq!(reencode(&proof.decoded), key);
        }
    }

    #[test]
    fn changed_rho_coefficients_raw_key_version_and_bytes_reject() {
        let s = sample();
        let mut bad = s.proof.clone();
        bad.decoded.rho[31] ^= 1;
        assert!(verify_public_key_decode(&bad, &s.key).is_err());
        let mut bad = s.proof.clone();
        bad.decoded.t1[5][255] = (bad.decoded.t1[5][255] + 1) % 1024;
        assert!(verify_public_key_decode(&bad, &s.key).is_err());
        let mut bad = s.proof.clone();
        bad.public_key[0] ^= 1;
        assert!(verify_public_key_decode(&bad, &bad.public_key).is_err());
        let mut bad = s.proof.clone();
        bad.version = 2;
        assert!(verify_public_key_decode(&bad, &s.key).is_err());
        let mut bad = s.proof.clone();
        bad.proof_bytes.truncate(bad.proof_bytes.len() / 2);
        assert!(verify_public_key_decode(&bad, &s.key).is_err());
    }

    #[test]
    fn shape_and_ten_bit_domain_are_distinct_checks() {
        assert!(prove_public_key_decode(&[0; MLDSA_PUBLIC_KEY_BYTES - 1]).is_err());
        let s = sample();
        let mut bad = s.proof.clone();
        bad.decoded.t1[0].pop();
        assert!(verify_public_key_decode(&bad, &s.key).is_err());
        let mut bad = s.proof.clone();
        bad.decoded.t1[0][0] = 1024;
        assert!(validate_shape(&bad.public_key, &bad.decoded).is_ok());
        assert!(verify_public_key_decode(&bad, &s.key).is_err());
    }

    fn residuals(row: &[BaseElement]) -> Vec<BaseElement> {
        let key = vec![0; MLDSA_PUBLIC_KEY_BYTES];
        let inputs = Inputs {
            decoded: decode(&key).unwrap(),
            key,
        };
        let air = KeyAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            inputs,
            default_proof_options(),
        );
        let mut values = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(
            &EvaluationFrame::from_rows(row.to_vec(), row.to_vec()),
            &[],
            &mut values,
        );
        values
    }

    #[test]
    fn bit_constraints_reject_a_nonbinary_witness_even_if_sums_match() {
        let key = vec![0; MLDSA_PUBLIC_KEY_BYTES];
        let inputs = Inputs {
            decoded: decode(&key).unwrap(),
            key,
        };
        let mut row = public_rows(&inputs).remove(0);
        witness(&mut row);
        assert!(residuals(&row).iter().all(|&v| v == BaseElement::ZERO));
        let mut attack = row.clone();
        attack[BITS] = BaseElement::new(2);
        attack[BYTE] = BaseElement::new(2);
        attack[COEFFICIENT] = BaseElement::new(2);
        let values = residuals(&attack);
        assert!(values[40..].iter().all(|&v| v == BaseElement::ZERO));
        assert_ne!(values[0], BaseElement::ZERO);
        row[COEFFICIENT] = BaseElement::new(1024);
        assert!(residuals(&row).iter().any(|&v| v != BaseElement::ZERO));
    }

    #[test]
    fn first_scaled_t1_connects_to_ntt_and_foreign_layout_rejects() {
        let s = sample();
        verify_public_key_decode(&s.proof, &s.key).unwrap();
        let input: [u32; N] = s.proof.decoded.t1[0]
            .iter()
            .map(|&v| u32::from(v) << 13)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let ntt = crate::mldsa_ntt::prove_ntt(&input).unwrap();
        let output: [u32; N] = ntt.stages[8].clone().try_into().unwrap();
        crate::mldsa_ntt::verify_ntt(&ntt, &input, &output).unwrap();
        let mut bad = s.proof.clone();
        bad.proof_bytes = ntt.proof_bytes;
        assert!(verify_public_key_decode(&bad, &s.key)
            .unwrap_err()
            .contains("trace layout"));
    }
}
