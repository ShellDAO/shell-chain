//! Bounded integer AIR for strict weighted quorum over an expected public context.
//!
//! This ingredient proves weight arithmetic, not signature validity, validator-set
//! provenance, proposer selection, penalty history or finality authorization. It
//! is separate from canonical signature batches and commit certificates.
use crate::{
    production_store::{bounded_json, ProductionError, ProductionProgress, ProductionStore},
    prover::default_proof_options,
};
use serde::{Deserialize, Serialize};
use shell_primitives::{Address, ShellHash};
use shell_storage::KvStore;
use std::collections::BTreeSet;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    verify, AcceptableOptions, Air, AirContext, Assertion, CompositionPoly, CompositionPolyTrace,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

pub const MAX_QUORUM_AUTHORITIES: usize = 1000;
/// Fixed version-one bound; a later Native bound change cannot alter this AIR.
pub const MAX_QUORUM_WEIGHT: u64 = 1_000_000;
const MAX_TOTAL: u64 = MAX_QUORUM_AUTHORITIES as u64 * MAX_QUORUM_WEIGHT;
const MAX_PROOF_BYTES: usize = 1024 * 1024;
const WEIGHT: usize = 0;
const SIGNED: usize = 1;
const TOTAL_BEFORE: usize = 2;
const TOTAL_AFTER: usize = 3;
const SIGNED_BEFORE: usize = 4;
const SIGNED_AFTER: usize = 5;
const FINAL_TOTAL: usize = 6;
const FINAL_SIGNED: usize = 7;
const INVERSE: usize = 8;
const BITS: usize = 9;
const RANGE_BITS: usize = 32;
const WIDTH: usize = BITS + RANGE_BITS;
const CONSTRAINTS: usize = 5 + RANGE_BITS;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityWeight {
    pub address: Address,
    /// Independently authenticated effective weight. Zero contributes nothing.
    pub weight: u64,
}

/// The verifier supplies this independently of the proof. Lists use ascending,
/// unique addresses. Signer membership here does not authenticate a signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumWeightContext {
    pub chain_id: u64,
    pub parent_hash: ShellHash,
    pub block_hash: ShellHash,
    pub block_number: u64,
    pub authorities: Vec<AuthorityWeight>,
    pub signers: Vec<Address>,
}

impl QuorumWeightContext {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.authorities.is_empty()
            || self.authorities.len() > MAX_QUORUM_AUTHORITIES
            || self.signers.len() > self.authorities.len()
            || self
                .authorities
                .windows(2)
                .any(|v| v[0].address.as_bytes() >= v[1].address.as_bytes())
            || self
                .signers
                .windows(2)
                .any(|v| v[0].as_bytes() >= v[1].as_bytes())
            || self
                .authorities
                .iter()
                .any(|v| v.weight > MAX_QUORUM_WEIGHT)
        {
            return Err("quorum weight context count/order/range mismatch".into());
        }
        let addresses: BTreeSet<_> = self
            .authorities
            .iter()
            .map(|v| *v.address.as_bytes())
            .collect();
        if self
            .signers
            .iter()
            .any(|a| !addresses.contains(a.as_bytes()))
        {
            return Err("quorum signer absent from expected authorities".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumWeightProof {
    pub version: u8,
    pub context: QuorumWeightContext,
    /// Public cumulative [total, signed] weights, starting at zero. The AIR
    /// checks every addition and the strict threshold; verification does not
    /// replace it with a native sum or trust these claimed intermediate values.
    pub prefixes: Vec<[u64; 2]>,
    pub proof_bytes: Vec<u8>,
}

/// Arithmetic result only, with no constructor or deserializer.
#[derive(Clone, Debug)]
pub struct VerifiedQuorumWeight {
    total: u64,
    signed: u64,
}
impl VerifiedQuorumWeight {
    pub fn total(&self) -> u64 {
        self.total
    }
    pub fn signed(&self) -> u64 {
        self.signed
    }
}

#[derive(Clone)]
struct Inputs {
    context: QuorumWeightContext,
    prefixes: Vec<[u64; 2]>,
}
impl Inputs {
    fn operations(&self) -> usize {
        self.context.authorities.len().next_power_of_two().max(4)
    }
    fn total(&self) -> [u64; 2] {
        *self.prefixes.last().expect("validated nonempty prefixes")
    }
    fn row(&self, index: usize) -> Vec<BaseElement> {
        let last = self.total();
        let authority = self.context.authorities.get(index);
        let weight = authority.map_or(0, |v| v.weight);
        let signed = authority.is_some_and(|v| {
            self.context
                .signers
                .binary_search_by(|a| a.as_bytes().cmp(v.address.as_bytes()))
                .is_ok()
        });
        let before = self.prefixes.get(index).copied().unwrap_or(last);
        let after = self.prefixes.get(index + 1).copied().unwrap_or(last);
        let mut row = vec![BaseElement::ZERO; WIDTH];
        for (column, value) in [
            (WEIGHT, weight),
            (SIGNED, u64::from(signed)),
            (TOTAL_BEFORE, before[0]),
            (TOTAL_AFTER, after[0]),
            (SIGNED_BEFORE, before[1]),
            (SIGNED_AFTER, after[1]),
            (FINAL_TOTAL, last[0]),
            (FINAL_SIGNED, last[1]),
        ] {
            row[column] = BaseElement::new(value.into());
        }
        if last[0] != 0 {
            row[INVERSE] = row[FINAL_TOTAL].inv();
        }
        // Invalid witnesses cannot represent a negative margin with 32 bits.
        let margin = (3 * last[1]).wrapping_sub(2 * last[0] + 1);
        for bit in 0..RANGE_BITS {
            row[BITS + bit] = BaseElement::new(((margin >> bit) & 1).into());
        }
        row
    }
}
impl ToElements<BaseElement> for Inputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let c = &self.context;
        let mut values = vec![
            BaseElement::new(u64::from_le_bytes(*b"WPQWT001").into()),
            BaseElement::new(c.chain_id.into()),
            BaseElement::new(c.block_number.into()),
            BaseElement::new(c.authorities.len() as u128),
            BaseElement::new(c.signers.len() as u128),
        ];
        for bytes in [c.parent_hash.as_bytes(), c.block_hash.as_bytes()] {
            values.extend(bytes.iter().map(|&v| BaseElement::new(v.into())));
        }
        for v in &c.authorities {
            values.extend(
                v.address
                    .as_bytes()
                    .iter()
                    .map(|&v| BaseElement::new(v.into())),
            );
            values.push(BaseElement::new(v.weight.into()));
        }
        for a in &c.signers {
            values.extend(a.as_bytes().iter().map(|&v| BaseElement::new(v.into())));
        }
        values.extend(
            self.prefixes
                .iter()
                .flatten()
                .map(|&v| BaseElement::new(v.into())),
        );
        values
    }
}

struct QuorumAir {
    context: AirContext<BaseElement>,
    inputs: Inputs,
}
impl Air for QuorumAir {
    type BaseField = BaseElement;
    type PublicInputs = Inputs;
    fn new(info: TraceInfo, inputs: Inputs, options: ProofOptions) -> Self {
        assert_eq!(info, TraceInfo::new(WIDTH, 2 * inputs.operations()));
        let mut degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
        ];
        degrees.extend((0..RANGE_BITS).map(|_| TransitionConstraintDegree::new(2)));
        debug_assert_eq!(degrees.len(), CONSTRAINTS);
        Self {
            context: AirContext::new(info, degrees, 8, options),
            inputs,
        }
    }
    fn evaluate_transition<E: FieldElement + From<BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _: &[E],
        result: &mut [E],
    ) {
        let r = frame.current();
        result[0] = r[TOTAL_AFTER] - r[TOTAL_BEFORE] - r[WEIGHT];
        result[1] = r[SIGNED_AFTER] - r[SIGNED_BEFORE] - r[WEIGHT] * r[SIGNED];
        result[2] = r[SIGNED] * (r[SIGNED] - E::ONE);
        result[3] = r[FINAL_TOTAL] * r[INVERSE] - E::ONE;
        let mut margin = E::ZERO;
        let mut power = E::ONE;
        for bit in 0..RANGE_BITS {
            let b = r[BITS + bit];
            result[5 + bit] = b * (b - E::ONE);
            margin += b * power;
            power += power;
        }
        let two = E::ONE + E::ONE;
        result[4] = (two + E::ONE) * r[FINAL_SIGNED] - two * r[FINAL_TOTAL] - E::ONE - margin;
    }
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let rows: Vec<_> = (0..self.inputs.operations())
            .map(|i| self.inputs.row(i))
            .collect();
        (0..8)
            .map(|column| {
                Assertion::sequence(column, 0, 2, rows.iter().map(|r| r[column]).collect())
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

struct QuorumProver {
    inputs: Inputs,
    options: ProofOptions,
}

impl Prover for QuorumProver {
    type BaseField = BaseElement;
    type Air = QuorumAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = Commitment;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Hasher, Commitment>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Hasher, Commitment>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, QuorumAir, E>;

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
        air: &'a QuorumAir,
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

fn witness(context: &QuorumWeightContext) -> Result<Inputs, String> {
    context.validate()?;
    let mut prefixes = vec![[0, 0]];
    for authority in &context.authorities {
        let [total, signed] = *prefixes.last().expect("initial prefix");
        let signed_weight = if context
            .signers
            .binary_search_by(|a| a.as_bytes().cmp(authority.address.as_bytes()))
            .is_ok()
        {
            authority.weight
        } else {
            0
        };
        prefixes.push([total + authority.weight, signed + signed_weight]);
    }
    let [total, signed] = *prefixes.last().expect("nonempty prefixes");
    if total == 0 || 3 * signed <= 2 * total {
        return Err("expected signer weight does not exceed two thirds".into());
    }
    Ok(Inputs {
        context: context.clone(),
        prefixes,
    })
}

/// Prove the bounded strict predicate, using the existing repository security options.
pub fn prove_quorum_weight(context: &QuorumWeightContext) -> Result<QuorumWeightProof, String> {
    let inputs = witness(context)?;
    let prefixes = inputs.prefixes.clone();
    let length = 2 * inputs.operations();
    let mut trace = TraceTable::new(WIDTH, length);
    for i in 0..inputs.operations() {
        let row = inputs.row(i);
        trace.update_row(2 * i, &row);
        trace.update_row(2 * i + 1, &row);
    }
    // Last odd row is unused by assertions or transition checks. Blind it from
    // the public statement to avoid degenerate constant trace polynomials.
    let mut padding =
        blake3::Hasher::new_derive_key("Shell-Chain weighted quorum trace padding v1");
    for e in inputs.to_elements() {
        padding.update(&e.as_int().to_le_bytes());
    }
    let mut bytes = [0u8; 16 * WIDTH];
    padding.finalize_xof().fill(&mut bytes);
    let last: Vec<_> = bytes
        .chunks_exact(16)
        .map(|v| BaseElement::new(u128::from_le_bytes(v.try_into().expect("16 bytes"))))
        .collect();
    trace.update_row(length - 1, &last);
    let inner = QuorumProver {
        inputs,
        options: default_proof_options(),
    }
    .prove(trace)
    .map_err(|e| format!("quorum weight proving: {e:?}"))?;
    Ok(QuorumWeightProof {
        version: 1,
        context: context.clone(),
        prefixes,
        proof_bytes: inner.to_bytes(),
    })
}

/// Verify arithmetic with an independently expected context. No native sum or
/// native quorum verdict substitutes for verification of the AIR certificate.
pub fn verify_quorum_weight(
    proof: &QuorumWeightProof,
    expected: &QuorumWeightContext,
) -> Result<VerifiedQuorumWeight, String> {
    expected.validate()?;
    if proof.version != 1
        || proof.context != *expected
        || proof.prefixes.len() != expected.authorities.len() + 1
        || proof.prefixes.first() != Some(&[0, 0])
        || proof.prefixes.iter().flatten().any(|&v| v > MAX_TOTAL)
        || proof.proof_bytes.is_empty()
        || proof.proof_bytes.len() > MAX_PROOF_BYTES
    {
        return Err("quorum weight proof context/version/range mismatch".into());
    }
    let inputs = Inputs {
        context: expected.clone(),
        prefixes: proof.prefixes.clone(),
    };
    let inner = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| format!("quorum weight decode: {e:?}"))?;
    if inner.trace_info() != &TraceInfo::new(WIDTH, 2 * inputs.operations()) {
        return Err("unexpected quorum weight trace layout".into());
    }
    let [total, signed] = inputs.total();
    verify::<QuorumAir, Hasher, Coin, Commitment>(
        inner,
        inputs,
        &AcceptableOptions::OptionSet(vec![default_proof_options()]),
    )
    .map_err(|e| format!("quorum weight verification: {e:?}"))?;
    Ok(VerifiedQuorumWeight { total, signed })
}

/// Persist one real component in an exclusively owned separate production job.
/// Reopening re-verifies stored bytes against the exact current source. This
/// does not write to a Native chain database or produce a commit certificate.
pub fn prove_quorum_weight_persistent<S: KvStore>(
    store: &mut S,
    context: &QuorumWeightContext,
) -> Result<(QuorumWeightProof, ProductionProgress), ProductionError> {
    witness(context)?;
    let source = bounded_json(&("weighted-quorum-arithmetic-v1", context), 256 * 1024)?;
    let mut job = ProductionStore::open(store, &source, None)?;
    let proof = job.checkpoint(
        "quorum-weight",
        || prove_quorum_weight(context),
        |p| verify_quorum_weight(p, context).map(|_| ()),
    )?;
    Ok((proof, job.progress()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_consensus::FinalityState;
    use shell_storage::MemoryDb;
    use std::sync::OnceLock;

    fn context(weights: &[u64], indices: &[usize]) -> QuorumWeightContext {
        let address = |i: usize| {
            let mut a = [0; 32];
            a[24..].copy_from_slice(&(i as u64).to_be_bytes());
            Address::from(a)
        };
        QuorumWeightContext {
            chain_id: u64::MAX,
            parent_hash: ShellHash::from([1; 32]),
            block_hash: ShellHash::from([2; 32]),
            block_number: u64::MAX,
            authorities: weights
                .iter()
                .enumerate()
                .map(|(i, &weight)| AuthorityWeight {
                    address: address(i),
                    weight,
                })
                .collect(),
            signers: indices.iter().map(|&i| address(i)).collect(),
        }
    }
    fn sample() -> &'static QuorumWeightProof {
        static PROOF: OnceLock<QuorumWeightProof> = OnceLock::new();
        PROOF.get_or_init(|| prove_quorum_weight(&context(&[2, 1, 1], &[0, 1])).unwrap())
    }
    #[test]
    fn real_air_roundtrip_and_all_expected_context_domains() {
        let good = sample();
        let bytes = serde_json::to_vec(good).unwrap();
        let decoded: QuorumWeightProof = serde_json::from_slice(&bytes).unwrap();
        let result = verify_quorum_weight(&decoded, &good.context).unwrap();
        assert_eq!((result.total(), result.signed()), (4, 3));
        for field in 0..7 {
            let mut changed = good.clone();
            match field {
                0 => changed.context.chain_id -= 1,
                1 => changed.context.block_number -= 1,
                2 => changed.context.parent_hash = ShellHash::ZERO,
                3 => changed.context.block_hash = ShellHash::ZERO,
                4 => changed.context.authorities[0].weight = 3,
                5 => {
                    changed.context.signers.pop();
                }
                _ => {
                    changed.context.authorities[2].address = Address::from([255; 32]);
                }
            }
            assert!(
                verify_quorum_weight(&changed, &changed.context).is_err(),
                "domain {field}"
            );
        }
    }
    #[test]
    fn real_weight_boundaries_match_independent_native_quorum() {
        assert_eq!(MAX_QUORUM_WEIGHT, shell_primitives::MAX_VALIDATOR_WEIGHT);
        for (weights, signers) in [
            (vec![1, 1, 1], vec![0, 1]), // exactly two thirds fails
            (vec![1, 1, 1], vec![0, 1, 2]),
            (vec![2, 1, 1], vec![0]),
            (vec![2, 1, 1], vec![0, 1]),
            (vec![1, 3], vec![1]),
            (vec![0, 0], vec![0, 1]),
            (vec![0, MAX_QUORUM_WEIGHT], vec![1]),
            (vec![MAX_QUORUM_WEIGHT; 3], vec![0, 1, 2]),
        ] {
            let total: u64 = weights.iter().sum();
            let signed: u64 = signers.iter().map(|&i| weights[i]).sum();
            let expected = FinalityState::has_weighted_quorum(signed, total);
            let c = context(&weights, &signers);
            let proved = prove_quorum_weight(&c);
            assert_eq!(proved.is_ok(), expected);
            if let Ok(p) = proved {
                let v = verify_quorum_weight(&p, &c).unwrap();
                assert_eq!((v.total(), v.signed()), (total, signed));
            }
        }
        let c = context(
            &[MAX_QUORUM_WEIGHT; MAX_QUORUM_AUTHORITIES],
            &(0..MAX_QUORUM_AUTHORITIES).collect::<Vec<_>>(),
        );
        let p = prove_quorum_weight(&c).unwrap();
        let v = verify_quorum_weight(&p, &c).unwrap();
        assert_eq!((v.total(), v.signed()), (MAX_TOTAL, MAX_TOTAL));
    }
    #[test]
    fn malformed_contexts_and_proof_shapes_fail_closed() {
        let base = sample();
        for case in 0..7 {
            let mut c = base.context.clone();
            match case {
                0 => c.authorities.clear(),
                1 => c.authorities[0].weight = MAX_QUORUM_WEIGHT + 1,
                2 => c.authorities[1].address = c.authorities[0].address,
                3 => c.authorities.swap(0, 1),
                4 => c.signers.push(c.signers[0]),
                5 => c.signers.reverse(),
                _ => c.signers = vec![Address::from([255; 32])],
            }
            assert!(prove_quorum_weight(&c).is_err());
        }
        assert!(prove_quorum_weight(&context(&[1; MAX_QUORUM_AUTHORITIES + 1], &[])).is_err());
        for case in 0..7 {
            let mut p = base.clone();
            match case {
                0 => p.version += 1,
                1 => {
                    p.prefixes.pop();
                }
                2 => p.prefixes[0][0] = 1,
                3 => p.prefixes[1][1] += 1,
                4 => p.prefixes[1][0] = u64::MAX,
                5 => p.proof_bytes.clear(),
                _ => p.proof_bytes[0] ^= 1,
            }
            assert!(verify_quorum_weight(&p, &base.context).is_err());
        }
        let mut zero = base.clone();
        zero.context = context(&[0, 0, 0], &[0, 1]);
        zero.prefixes = vec![[0, 0]; 4];
        assert!(verify_quorum_weight(&zero, &zero.context).is_err());
    }
    #[test]
    fn constraints_reject_forged_additions_flags_inverse_and_range_bits() {
        let c = context(&[2, 1, 1], &[0, 1]);
        let inputs = witness(&c).unwrap();
        let air = QuorumAir::new(
            TraceInfo::new(WIDTH, 2 * inputs.operations()),
            inputs.clone(),
            default_proof_options(),
        );
        for i in 0..inputs.operations() {
            let row = inputs.row(i);
            let evaluate = |row: &[BaseElement]| {
                let frame = EvaluationFrame::from_rows(row.to_vec(), row.to_vec());
                let mut r = vec![BaseElement::ZERO; CONSTRAINTS];
                air.evaluate_transition(&frame, &[], &mut r);
                r
            };
            assert!(evaluate(&row).iter().all(|v| *v == BaseElement::ZERO));
            for column in [
                TOTAL_AFTER,
                SIGNED_AFTER,
                SIGNED,
                INVERSE,
                FINAL_TOTAL,
                FINAL_SIGNED,
                BITS,
            ] {
                let mut bad = row.clone();
                bad[column] += BaseElement::new(if column == SIGNED { 2 } else { 1 });
                assert!(
                    evaluate(&bad).iter().any(|v| *v != BaseElement::ZERO),
                    "column {column}"
                );
            }
        }
        // An exact-two-thirds and zero-total forged witness must violate AIR,
        // even when their public prefix shape/ranges are otherwise valid.
        for prefixes in [vec![[0, 0], [1, 1], [2, 2], [3, 2]], vec![[0, 0]; 4]] {
            let bad = Inputs {
                context: context(&[1, 1, 1], &[0, 1]),
                prefixes,
            };
            let mut r = vec![BaseElement::ZERO; CONSTRAINTS];
            let row = bad.row(2);
            air.evaluate_transition(&EvaluationFrame::from_rows(row.clone(), row), &[], &mut r);
            assert!(r.iter().any(|v| *v != BaseElement::ZERO));
        }
    }
    #[test]
    fn durable_component_reentry_reverifies_and_source_refusal_keeps_kv_rows() {
        let mut store = MemoryDb::new();
        let c = sample().context.clone();
        let (first, progress) = prove_quorum_weight_persistent(&mut store, &c).unwrap();
        assert_eq!(
            (progress.components, progress.newly_proved, progress.reused),
            (1, 1, 0)
        );
        let snapshot = |s: &MemoryDb| {
            let mut rows = Vec::new();
            s.visit_all(&mut |k, v| {
                rows.push((k.to_vec(), v.to_vec()));
                Ok(())
            })
            .unwrap();
            rows
        };
        let before = snapshot(&store);
        let (second, progress) = prove_quorum_weight_persistent(&mut store, &c).unwrap();
        assert_eq!(
            (progress.components, progress.newly_proved, progress.reused),
            (1, 0, 1)
        );
        assert_eq!(first.proof_bytes, second.proof_bytes);
        assert_eq!(before, snapshot(&store));
        let mut changed = c;
        changed.block_hash = ShellHash::ZERO;
        assert!(prove_quorum_weight_persistent(&mut store, &changed).is_err());
        assert_eq!(before, snapshot(&store));
        let mut empty = MemoryDb::new();
        assert!(prove_quorum_weight_persistent(&mut empty, &context(&[1, 1, 1], &[0, 1])).is_err());
        assert!(snapshot(&empty).is_empty());
    }
}
