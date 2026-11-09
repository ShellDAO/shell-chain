//! Public ML-DSA-65 SampleInBall AIR, FIPS 204 Algorithm 29.
//!
//! Rejection order, byte consumption, all 49 polynomial updates and sign bits
//! are constrained and linked to an actual SHAKE256 sponge proof. States are
//! public; the complete signature equation and node workflow remain separate.

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

use crate::shake_sponge::{
    prove_shake, verify_shake, ShakeKind, ShakeProof, MAX_SHAKE_OUTPUT_BYTES,
};

pub const CHALLENGE_SEED_BYTES: usize = 48;
pub const CHALLENGE_WEIGHT: usize = 49;
const N: usize = 256;
const FIRST: usize = N - CHALLENGE_WEIGHT;
const ATTEMPT: usize = 0;
const UPDATE: usize = 1;
const BYTE: usize = 2;
const COUNT: usize = 3;
const NEXT: usize = 4;
const INDEX: usize = 5;
const OLD: usize = 6;
const NEW: usize = 7;
const CARRY: usize = 8;
const SIGN: usize = 9;
const IS_I: usize = 10;
const IS_J: usize = 11;
const ACCEPT: usize = 12;
const GAP: usize = 13;
const SLACK: usize = 21;
const TRACE_WIDTH: usize = 27;
const CONSTRAINTS: usize = 22;
const MAX_PROOF_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeProof {
    pub version: u8,
    pub seed: Vec<u8>,
    pub xof: ShakeProof,
    pub indices: Vec<u8>,
    pub counts: Vec<u8>,
    pub states: Vec<Vec<i8>>,
    pub proof_bytes: Vec<u8>,
}
impl ChallengeProof {
    pub fn challenge(&self) -> Option<&[i8]> {
        self.states.last().map(Vec::as_slice)
    }
}
#[derive(Clone)]
struct Inputs {
    version: u8,
    seed: Vec<u8>,
    stream: Vec<u8>,
    indices: Vec<u8>,
    counts: Vec<u8>,
    states: Vec<Vec<i8>>,
}
impl Inputs {
    fn attempts(&self) -> usize {
        self.counts.len() - 1
    }
    fn slots(&self) -> usize {
        (self.attempts() + CHALLENGE_WEIGHT * N).next_power_of_two()
    }
    fn trace_length(&self) -> usize {
        self.slots() * 2
    }
}
fn signed(value: i8) -> BaseElement {
    let magnitude = BaseElement::new(value.unsigned_abs().into());
    if value < 0 {
        BaseElement::ZERO - magnitude
    } else {
        magnitude
    }
}
impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = vec![
            BaseElement::new(u64::from_le_bytes(if self.version == 1 {
                *b"MLCHAL01"
            } else {
                *b"DLCHAL01"
            }) as u128),
            BaseElement::new(self.stream.len() as u128),
            BaseElement::new(self.attempts() as u128),
        ];
        result.extend(
            self.seed
                .iter()
                .chain(&self.stream)
                .chain(&self.indices)
                .chain(&self.counts)
                .map(|&v| BaseElement::new(v.into())),
        );
        result.extend(self.states.iter().flatten().map(|&v| signed(v)));
        result
    }
}

// Native witness construction only. Verification never invokes this sampler.
fn sample(seed: &[u8], stream: &[u8], version: u8) -> Option<Inputs> {
    if stream.len() < 8 {
        return None;
    }
    let mut counts = vec![0];
    let mut indices = Vec::new();
    let mut states = Vec::new();
    let mut polynomial = vec![0i8; N];
    for &j in &stream[8..] {
        let step = indices.len();
        let i = FIRST + step;
        if usize::from(j) <= i {
            polynomial[i] = polynomial[usize::from(j)];
            polynomial[usize::from(j)] = 1 - 2 * ((stream[step / 8] >> (step % 8)) & 1) as i8;
            indices.push(j);
            states.push(polynomial.clone());
        }
        counts.push(indices.len() as u8);
        if indices.len() == CHALLENGE_WEIGHT {
            return Some(Inputs {
                version,
                seed: seed.to_vec(),
                stream: stream.to_vec(),
                indices,
                counts,
                states,
            });
        }
    }
    None
}

// No native acceptance comparison, sampling or polynomial update occurs here.
// Public routing reuses the same counter/index/state values at every edge.
fn public_rows(inputs: &Inputs) -> Vec<Vec<BaseElement>> {
    let mut rows = vec![vec![BaseElement::ZERO; TRACE_WIDTH]; inputs.slots()];
    for (t, row) in rows[..inputs.attempts()].iter_mut().enumerate() {
        row[ATTEMPT] = BaseElement::ONE;
        row[BYTE] = BaseElement::new(inputs.stream[8 + t].into());
        row[COUNT] = BaseElement::new(inputs.counts[t].into());
        row[NEXT] = BaseElement::new(inputs.counts[t + 1].into());
        row[INDEX] = BaseElement::new(
            inputs
                .indices
                .get(usize::from(inputs.counts[t]))
                .copied()
                .unwrap_or(0)
                .into(),
        );
    }
    for step in 0..CHALLENGE_WEIGHT {
        let j = usize::from(inputs.indices[step]);
        for coefficient in 0..N {
            let row = &mut rows[inputs.attempts() + step * N + coefficient];
            row[UPDATE] = BaseElement::ONE;
            row[OLD] = signed(if step == 0 {
                0
            } else {
                inputs.states[step - 1][coefficient]
            });
            row[NEW] = signed(inputs.states[step][coefficient]);
            row[CARRY] = signed(if step == 0 {
                0
            } else {
                inputs.states[step - 1][j]
            });
            row[SIGN] = BaseElement::new(((inputs.stream[step / 8] >> (step % 8)) & 1).into());
            row[IS_I] = BaseElement::new(u128::from(coefficient == FIRST + step));
            row[IS_J] = BaseElement::new(u128::from(coefficient == j));
        }
    }
    rows
}
fn witness(row: &mut [BaseElement]) {
    if row[ATTEMPT] != BaseElement::ONE {
        return;
    }
    let i = FIRST as i16 + row[COUNT].as_int() as i16;
    let j = row[BYTE].as_int() as i16;
    row[ACCEPT] = BaseElement::new(u128::from(i >= j));
    let gap = (i - j).rem_euclid(256) as u16;
    let slack = (48 - row[COUNT].as_int() as i16).rem_euclid(64) as u16;
    for bit in 0..8 {
        row[GAP + bit] = BaseElement::new(((gap >> bit) & 1).into());
    }
    for bit in 0..6 {
        row[SLACK + bit] = BaseElement::new(((slack >> bit) & 1).into());
    }
}
struct ChallengeAir {
    context: AirContext<BaseElement>,
    inputs: Inputs,
}
impl Air for ChallengeAir {
    type BaseField = BaseElement;
    type PublicInputs = Inputs;
    fn new(info: TraceInfo, inputs: Inputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(TRACE_WIDTH, inputs.trace_length()));
        let degrees = (0..CONSTRAINTS)
            .map(|i| {
                TransitionConstraintDegree::new(if i >= 19 {
                    4
                } else if i == 18 {
                    3
                } else {
                    2
                })
            })
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
        for bit in 0..15 {
            result[bit] = r[ACCEPT + bit] * (r[ACCEPT + bit] - E::ONE);
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
        result[15] = r[ATTEMPT] * (r[NEXT] - r[COUNT] - r[ACCEPT]);
        result[16] = r[ATTEMPT]
            * (E::from(BaseElement::new(FIRST as u128)) + r[COUNT]
                - r[BYTE]
                - sum(&r[GAP..GAP + 8])
                + E::from(BaseElement::new(256)) * (E::ONE - r[ACCEPT]));
        result[17] =
            r[ATTEMPT] * (E::from(BaseElement::new(48)) - r[COUNT] - sum(&r[SLACK..SLACK + 6]));
        result[18] = r[ATTEMPT] * r[ACCEPT] * (r[BYTE] - r[INDEX]);
        let sign = E::ONE - r[SIGN] - r[SIGN];
        let expected =
            r[OLD] + r[IS_I] * (r[CARRY] - r[OLD]) * (E::ONE - r[IS_J]) + r[IS_J] * (sign - r[OLD]);
        result[19] = r[UPDATE] * (r[NEW] - expected);
        result[20] = r[UPDATE] * r[OLD] * (r[OLD] - E::ONE) * (r[OLD] + E::ONE);
        result[21] = r[UPDATE] * r[NEW] * (r[NEW] - E::ONE) * (r[NEW] + E::ONE);
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows = public_rows(&self.inputs);
        (0..ACCEPT)
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
    let mut trace = TraceTable::new(TRACE_WIDTH, inputs.trace_length());
    for (slot, mut row) in public_rows(inputs).into_iter().enumerate() {
        witness(&mut row);
        trace.update_row(slot * 2, &row);
        trace.update_row(slot * 2 + 1, &row);
    }
    // Final unused odd padding gives full-degree trace polynomials, including
    // constant seeds. Every actual operation remains constrained and asserted.
    let mut hash = blake3::Hasher::new_derive_key("Shell-Chain ML-DSA challenge trace padding v1");
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

struct ChallengeProver {
    inputs: Inputs,
    options: ProofOptions,
}

impl Prover for ChallengeProver {
    type BaseField = BaseElement;
    type Air = ChallengeAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, ChallengeAir, E>;

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
        air: &'a ChallengeAir,
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

/// Prove ML-DSA-65 SampleInBall for a 48-byte commitment seed.
/// The existing bounded SHAKE component limits exceptional stream expansion.
pub fn prove_challenge(seed: &[u8]) -> Result<ChallengeProof, String> {
    prove_profile(seed, 1)
}

/// Prove the locked PQClean Dilithium3 sampler over the first 32 commitment bytes.
/// A separate proof version and AIR domain prevent FIPS profile substitution.
pub fn prove_dilithium_challenge(seed: &[u8]) -> Result<ChallengeProof, String> {
    prove_profile(seed, 2)
}
fn seed_bytes(version: u8) -> usize {
    if version == 1 {
        CHALLENGE_SEED_BYTES
    } else {
        32
    }
}
fn prove_profile(seed: &[u8], version: u8) -> Result<ChallengeProof, String> {
    if seed.len() != seed_bytes(version) {
        return Err("challenge seed length differs from the selected transcript".into());
    }
    let mut length = 128;
    let (xof, inputs) = loop {
        let xof = prove_shake(ShakeKind::Shake256, seed, length)?;
        if let Some(inputs) = sample(seed, &xof.output, version) {
            break (xof, inputs);
        }
        if length == MAX_SHAKE_OUTPUT_BYTES {
            return Err("challenge exceeds development SHAKE stream resource bound".into());
        }
        length = (length * 2).min(MAX_SHAKE_OUTPUT_BYTES);
    };
    let prover = ChallengeProver {
        inputs: inputs.clone(),
        options: default_proof_options(),
    };
    let inner = prover
        .prove(trace(&inputs))
        .map_err(|e| format!("challenge proof: {e:?}"))?;
    Ok(ChallengeProof {
        version,
        seed: seed.to_vec(),
        xof,
        indices: inputs.indices,
        counts: inputs.counts,
        states: inputs.states,
        proof_bytes: inner.to_bytes(),
    })
}
#[cfg(test)]
fn validate_shape(
    proof: &ChallengeProof,
    expected_seed: &[u8],
    expected_output: &[i8],
) -> Result<(), String> {
    validate_profile_shape(proof, expected_seed, expected_output, 1)
}
fn validate_profile_shape(
    proof: &ChallengeProof,
    expected_seed: &[u8],
    expected_output: &[i8],
    version: u8,
) -> Result<(), String> {
    if proof.version != version
        || expected_seed.len() != seed_bytes(version)
        || proof.seed != expected_seed
        || proof.xof.output.len() < 9
        || proof.xof.output.len() > MAX_SHAKE_OUTPUT_BYTES
        || proof.indices.len() != CHALLENGE_WEIGHT
        || proof.states.len() != CHALLENGE_WEIGHT
        || proof.states.iter().any(|v| v.len() != N)
        || expected_output.len() != N
        || proof.challenge() != Some(expected_output)
        || proof.counts.len() < 2
        || proof.counts.len() > proof.xof.output.len() - 7
        || proof.counts.first() != Some(&0)
        || proof.counts.last() != Some(&(CHALLENGE_WEIGHT as u8))
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("invalid challenge version, endpoints, shape or payload size".into());
    }
    Ok(())
}
/// Verify sampling arithmetic and the actual SHAKE stream, without native
/// SampleInBall, acceptance comparisons or native hashing in the verifier.
pub fn verify_challenge(
    proof: &ChallengeProof,
    expected_seed: &[u8],
    expected_output: &[i8],
) -> Result<(), String> {
    verify_profile(proof, expected_seed, expected_output, 1)
}

/// Verify the explicit version-two, 32-byte PQClean transcript using only AIRs.
pub fn verify_dilithium_challenge(
    proof: &ChallengeProof,
    expected_seed: &[u8],
    expected_output: &[i8],
) -> Result<(), String> {
    verify_profile(proof, expected_seed, expected_output, 2)
}
fn verify_profile(
    proof: &ChallengeProof,
    expected_seed: &[u8],
    expected_output: &[i8],
    version: u8,
) -> Result<(), String> {
    validate_profile_shape(proof, expected_seed, expected_output, version)?;
    let inputs = Inputs {
        version,
        seed: proof.seed.clone(),
        stream: proof.xof.output.clone(),
        indices: proof.indices.clone(),
        counts: proof.counts.clone(),
        states: proof.states.clone(),
    };
    let inner = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| format!("challenge proof decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(TRACE_WIDTH, inputs.trace_length()) {
        return Err("unexpected challenge trace layout".into());
    }
    verify::<ChallengeAir, Hasher, Coin, Commitment>(
        inner,
        inputs,
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("challenge verification: {e:?}"))?;
    verify_shake(
        &proof.xof,
        ShakeKind::Shake256,
        expected_seed,
        &proof.xof.output,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    use shell_crypto::{MlDsaSigner, MlDsaVerifier, Signer, Verifier};
    use std::sync::OnceLock;

    // Independent streaming oracle: signs are one shifting u64 and index
    // rejection reads directly from XofReader, not the bounded witness parser.
    fn native(seed: &[u8]) -> Vec<i8> {
        let mut h = Shake256::default();
        h.update(seed);
        let mut reader = h.finalize_xof();
        let mut bytes = [0; 8];
        reader.read(&mut bytes);
        let mut signs = u64::from_le_bytes(bytes);
        let mut c = vec![0; 256];
        for i in FIRST..256 {
            let mut b = [0; 1];
            loop {
                reader.read(&mut b);
                if usize::from(b[0]) <= i {
                    break;
                }
            }
            let j = usize::from(b[0]);
            c[i] = c[j];
            c[j] = if signs & 1 == 0 { 1 } else { -1 };
            signs >>= 1;
        }
        c
    }
    fn cases() -> &'static Vec<ChallengeProof> {
        static CASES: OnceLock<Vec<ChallengeProof>> = OnceLock::new();
        CASES.get_or_init(|| {
            let signer = MlDsaSigner::generate();
            let message = b"ML-DSA challenge proof";
            let sig = signer.sign(message).unwrap();
            assert!(MlDsaVerifier
                .verify(signer.public_key(), message, &sig)
                .unwrap());
            assert!(!MlDsaVerifier
                .verify(signer.public_key(), b"wrong message", &sig)
                .unwrap());
            [vec![0; 48], vec![255; 48], sig.data[..48].to_vec()]
                .iter()
                .map(|seed| {
                    let p = prove_challenge(seed).unwrap();
                    assert_eq!(p.challenge().unwrap(), native(seed));
                    p
                })
                .collect()
        })
    }
    #[test]
    fn dilithium_raw_sampler_has_distinct_seed_version_and_air_domain() {
        use shell_crypto::{DilithiumSigner, DilithiumVerifier};
        let signer = DilithiumSigner::generate();
        let message = b"genuine PQClean raw transcript";
        let signature = signer.sign(message).unwrap();
        assert!(DilithiumVerifier.verify_legacy_transcript(
            signer.public_key(),
            message,
            &signature
        ));
        for seed in [vec![0; 32], vec![255; 32], signature.data[..32].to_vec()] {
            let expected = native(&seed);
            let p = prove_dilithium_challenge(&seed).unwrap();
            verify_dilithium_challenge(&p, &seed, &expected).unwrap();
            assert!(verify_challenge(&p, &seed, &expected).is_err());
            let mut relabelled = p.clone();
            relabelled.version = 1;
            relabelled.seed.extend_from_slice(&[0; 16]);
            assert!(verify_challenge(&relabelled, &relabelled.seed, &expected).is_err());
            let mut wrong = p.clone();
            wrong.version = 3;
            assert!(verify_dilithium_challenge(&wrong, &seed, &expected).is_err());
            let mut wrong = p.clone();
            wrong.seed[0] ^= 1;
            assert!(verify_dilithium_challenge(&wrong, &wrong.seed, &expected).is_err());
        }
        assert!(prove_dilithium_challenge(&signature.data[..48]).is_err());
        assert!(prove_challenge(&signature.data[..32]).is_err());
        let adapter = MlDsaSigner::generate();
        let mut signature = adapter.sign(message).unwrap();
        signature.sig_type = shell_crypto::SignatureType::Dilithium3;
        assert!(DilithiumVerifier
            .verify(adapter.public_key(), message, &signature)
            .unwrap());
        assert!(!DilithiumVerifier.verify_legacy_transcript(
            adapter.public_key(),
            message,
            &signature
        ));
    }
    #[test]
    fn zero_ff_and_genuine_seed_real_proofs_match_streaming_oracle() {
        for p in cases() {
            let expected = native(&p.seed);
            verify_challenge(p, &p.seed, &expected).unwrap();
            assert_eq!(expected.iter().filter(|&&v| v != 0).count(), 49);
            assert!(expected.iter().all(|&v| (-1..=1).contains(&v)));
        }
        let p = &cases()[2];
        let restored: ChallengeProof =
            serde_json::from_slice(&serde_json::to_vec(p).unwrap()).unwrap();
        verify_challenge(&restored, &p.seed, &native(&p.seed)).unwrap();
    }
    #[test]
    fn changed_indices_counters_and_seed_reject() {
        let p = &cases()[0];
        let expected = native(&p.seed);
        let mut bad = p.clone();
        bad.indices[0] ^= 1;
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.counts[1] = 255;
        assert!(validate_shape(&bad, &p.seed, &expected).is_ok());
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.counts
            .insert(bad.counts.len() - 1, bad.counts[bad.counts.len() - 2]);
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.counts.push(49);
        assert!(validate_shape(&bad, &p.seed, &expected).is_ok());
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.seed[0] ^= 1;
        assert!(verify_challenge(&bad, &bad.seed, &expected).is_err());
    }
    #[test]
    fn intermediate_output_sign_and_ternary_changes_reject() {
        let p = &cases()[0];
        let expected = native(&p.seed);
        let mut bad = p.clone();
        bad.states[0][255] = 1;
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.states[48][0] = 2;
        let changed = bad.challenge().unwrap().to_vec();
        assert!(validate_shape(&bad, &p.seed, &changed).is_ok());
        assert!(verify_challenge(&bad, &p.seed, &changed).is_err());
        let mut bad = p.clone();
        bad.xof.output[0] ^= 1;
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
    }
    fn residuals(air: &ChallengeAir, row: &[BaseElement]) -> Vec<BaseElement> {
        let mut out = vec![BaseElement::ZERO; CONSTRAINTS];
        air.evaluate_transition(
            &EvaluationFrame::from_rows(row.to_vec(), row.to_vec()),
            &[],
            &mut out,
        );
        out
    }
    fn synthetic(repeat_zero: bool) -> Inputs {
        let mut stream = vec![0x55; 8];
        for i in FIRST..256 {
            if i < 255 {
                stream.push(255);
            }
            stream.push(if repeat_zero { 0 } else { i as u8 });
        }
        sample(&[0; 48], &stream, 1).unwrap()
    }
    #[test]
    fn rejection_self_index_and_repeated_index_update_every_coefficient() {
        for repeat in [false, true] {
            let input = synthetic(repeat);
            assert_eq!(input.attempts(), 97);
            assert!(input.counts.windows(2).any(|v| v[0] == v[1]));
            let mut expected = vec![0i8; 256];
            for k in 0..49 {
                let sign = if k % 2 == 0 { -1 } else { 1 };
                if repeat {
                    if k > 0 {
                        expected[FIRST + k] = if (k - 1) % 2 == 0 { -1 } else { 1 };
                    }
                    expected[0] = sign;
                } else {
                    expected[FIRST + k] = sign;
                }
            }
            assert_eq!(input.states[48], expected);
            let mut rows = public_rows(&input);
            let air = ChallengeAir::new(
                TraceInfo::new(TRACE_WIDTH, input.trace_length()),
                input.clone(),
                default_proof_options(),
            );
            for row in &mut rows {
                witness(row);
                assert!(residuals(&air, row).iter().all(|&v| v == BaseElement::ZERO));
            }
            let mut invalid = rows[input.attempts() + FIRST].clone();
            invalid[NEW] = BaseElement::new(2);
            assert_ne!(residuals(&air, &invalid)[21], BaseElement::ZERO);
            let mut invalid = rows[input.attempts() + 100].clone();
            invalid[NEW] = BaseElement::ONE;
            assert_ne!(residuals(&air, &invalid)[19], BaseElement::ZERO);
        }
        assert!(sample(&[0; 48], &[0; 8], 1).is_none());
        assert!(sample(&[0; 48], &[255; 128], 1).is_none());
    }
    #[test]
    fn bit_bounds_stop_a_forged_acceptance_despite_linear_equalities() {
        let input = synthetic(false);
        let mut row = public_rows(&input)[0].clone();
        witness(&mut row);
        let air = ChallengeAir::new(
            TraceInfo::new(TRACE_WIDTH, input.trace_length()),
            input,
            default_proof_options(),
        );
        assert_eq!(row[BYTE], BaseElement::new(255));
        assert_eq!(row[COUNT], BaseElement::ZERO);
        row[ACCEPT] = BaseElement::ONE;
        row[NEXT] = BaseElement::ONE;
        row[INDEX] = row[BYTE];
        row[GAP..GAP + 8].fill(BaseElement::ZERO);
        row[GAP] = BaseElement::ZERO - BaseElement::new(48);
        let values = residuals(&air, &row);
        assert!(values[15..].iter().all(|&v| v == BaseElement::ZERO));
        assert!(values[..15].iter().any(|&v| v != BaseElement::ZERO));
        let mut invalid = row.clone();
        invalid[COUNT] = BaseElement::new(49);
        witness(&mut invalid);
        assert_ne!(residuals(&air, &invalid)[17], BaseElement::ZERO);
    }
    #[test]
    fn shape_version_payload_and_all_child_proofs_are_verified() {
        assert!(prove_challenge(&[0; 47]).is_err());
        assert!(prove_challenge(&[0; 64]).is_err());
        let p = &cases()[0];
        let expected = native(&p.seed);
        assert!(verify_challenge(p, &[0; 47], &expected).is_err());
        assert!(verify_challenge(p, &p.seed, &[0; 255]).is_err());
        let mut bad = p.clone();
        bad.version = 2;
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.states[0].pop();
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.counts.clear();
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.proof_bytes.truncate(bad.proof_bytes.len() / 2);
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = vec![0; MAX_PROOF_BYTES + 1];
        assert!(verify_challenge(&bad, &p.seed, &expected).is_err());
        let mut bad = p.clone();
        bad.proof_bytes = p.xof.sponge_proof_bytes.clone();
        assert!(verify_challenge(&bad, &p.seed, &expected)
            .unwrap_err()
            .contains("layout"));
        let mut bad = p.clone();
        bad.xof
            .sponge_proof_bytes
            .truncate(bad.xof.sponge_proof_bytes.len() / 2);
        assert!(verify_challenge(&bad, &p.seed, &expected)
            .unwrap_err()
            .contains("SHAKE"));
        let mut bad = p.clone();
        bad.xof.permutations[0].rounds[11].theta[24] ^= 1;
        assert!(verify_challenge(&bad, &p.seed, &expected)
            .unwrap_err()
            .contains("Keccak verification"));
    }
}
