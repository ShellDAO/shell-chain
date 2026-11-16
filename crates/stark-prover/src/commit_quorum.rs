//! Full signature AIR and strict weight AIR for an expected commit context.
//! Native supplies current authority keys and weights independently. Historical
//! provenance, proposer selection and penalty lifecycle are not proved here.
use crate::{
    mldsa_verification::{verify_dilithium3, verify_mldsa65, Mldsa65VerificationProof},
    production_store::{bounded_json, ProductionError, ProductionProgress, ProductionStore},
    weighted_quorum::{
        prove_quorum_weight, verify_quorum_weight, QuorumWeightContext, QuorumWeightProof,
    },
};
use serde::{Deserialize, Serialize};
use shell_core::BlockSignerEvidence;
use shell_crypto::{CryptoError, PQSignature, SignatureType, Verifier};
use shell_storage::KvStore;
use std::num::NonZeroUsize;

pub mod payload;
pub mod slh;

pub const MAX_COMMIT_PROOF_SIGNERS: usize = 16;

/// Expected inputs selected independently of the proof. The address/key binding
/// and current registry provenance are Native predicates, not additional AIRs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitQuorumSource {
    pub context: QuorumWeightContext,
    pub signatures: Vec<BlockSignerEvidence>,
}
impl CommitQuorumSource {
    /// Check bounded shape and Native address/key tags, without authenticating signatures.
    pub fn validate(&self) -> Result<(), String> {
        self.context.validate()?;
        if self.signatures.is_empty()
            || self.signatures.len() > MAX_COMMIT_PROOF_SIGNERS
            || self.signatures.len() != self.context.signers.len()
        {
            return Err("commit proof signer count mismatch".into());
        }
        for (entry, address) in self.signatures.iter().zip(&self.context.signers) {
            if entry.address != *address
                || !match entry.signature.sig_type {
                    SignatureType::MlDsa65 | SignatureType::Dilithium3 => {
                        entry.public_key.len() == 1952 && entry.signature.data.len() == 3309
                    }
                    SignatureType::SphincsSha2256f => {
                        entry.public_key.len() == 64
                            && entry.signature.data.len()
                                == crate::slh_fors::SLH_SHA2_256F_SIGNATURE_BYTES
                    }
                }
                || shell_crypto::infer_signature_type_from_address(&entry.public_key, address)
                    != Some(entry.signature.sig_type)
            {
                return Err("commit proof signer order/key/tag/profile mismatch".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitQuorumProof {
    pub version: u8,
    pub weight: QuorumWeightProof,
    #[serde(deserialize_with = "payload::deserialize_signatures")]
    pub signatures: Vec<Mldsa65VerificationProof>,
    /// Empty and omitted in legacy version one; version two carries complete SLH graphs.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "payload::deserialize_slh_signatures"
    )]
    pub slh_signatures: Vec<slh::CommitSlhProof>,
}

/// Only full proof verification constructs this exact-tuple verifier. It is not
/// serializable and grants no authority for another key, hash, signer or context.
#[derive(Clone, Debug)]
pub struct VerifiedCommitQuorum {
    source: CommitQuorumSource,
}
impl VerifiedCommitQuorum {
    pub fn matches_source(&self, source: &CommitQuorumSource) -> bool {
        self.source == *source
    }
}
impl Verifier for VerifiedCommitQuorum {
    fn verify(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        if !shell_crypto::is_algorithm_allowed(signature.sig_type) {
            return Err(CryptoError::UnsupportedSignatureType(signature.sig_type));
        }
        Ok(message == self.source.context.block_hash.as_bytes()
            && self
                .source
                .signatures
                .iter()
                .any(|entry| key == entry.public_key && signature == &entry.signature))
    }
    fn sig_type(&self) -> SignatureType {
        SignatureType::Dilithium3
    }
}

/// Verify every full raw block-hash signature graph and the strict weighted AIR.
/// There is no native cryptographic fallback for a missing or invalid proof.
pub fn verify_commit_quorum(
    proof: &CommitQuorumProof,
    expected: &CommitQuorumSource,
) -> Result<VerifiedCommitQuorum, String> {
    expected.validate()?;
    let slh_count = expected
        .signatures
        .iter()
        .filter(|e| e.signature.sig_type == SignatureType::SphincsSha2256f)
        .count();
    if proof.version != if slh_count == 0 { 1 } else { 2 }
        || proof.signatures.len() != expected.signatures.len() - slh_count
        || proof.slh_signatures.len() != slh_count
    {
        return Err("commit proof version/signature count mismatch".into());
    }
    verify_quorum_weight(&proof.weight, &expected.context)?;
    let mut lattice = proof.signatures.iter();
    let mut slh = proof.slh_signatures.iter();
    for entry in &expected.signatures {
        if entry.signature.sig_type == SignatureType::SphincsSha2256f {
            slh::verify(
                slh.next().ok_or("commit SLH proof absent")?,
                entry,
                &expected.context.block_hash,
            )?;
            continue;
        }
        let proof = lattice.next().ok_or("commit lattice proof absent")?;
        let verify = match (entry.signature.sig_type, proof.version) {
            (SignatureType::MlDsa65 | SignatureType::Dilithium3, 1) => verify_mldsa65,
            (SignatureType::Dilithium3, 2) => verify_dilithium3,
            _ => return Err("commit signature transcript mismatch".into()),
        };
        verify(
            proof,
            &entry.public_key,
            expected.context.block_hash.as_bytes(),
            &entry.signature.data,
        )?;
    }
    Ok(VerifiedCommitQuorum {
        source: expected.clone(),
    })
}

/// Exclusively own a separate job store. The original source and every reused
/// checkpoint are checked on reopen. A component limit pauses without changing
/// the Native chain; complete proof output is returned only after verification.
pub fn prove_commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    commit_quorum_persistent(store, source, limit, false, None, None, None)
}

/// Node lifecycle cancellation is checked at the same durable component boundaries.
pub fn prove_commit_quorum_persistent_interruptible<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
    interrupt: &dyn Fn() -> bool,
    progress: &mut ProductionProgress,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    commit_quorum_persistent(
        store,
        source,
        limit,
        false,
        None,
        Some(interrupt),
        Some(progress),
    )
}

/// Reverify all original certificates without initializing a job or invoking
/// any proving closure. Missing or invalid components refuse rather than heal.
pub fn reverify_commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    commit_quorum_persistent(store, source, None, true, None, None, None)
}

/// Reverify a complete, independently pinned donor before opening destination
/// checkpoints. Only exact key/address/signature/transcript and message matches
/// may supply untrusted component bytes; every borrowed certificate is verified
/// again against the destination input. Weight proofs are never borrowed.
/// Both stores must be separate and exclusively owned by the caller.
pub fn prove_commit_quorum_persistent_reusing<S: KvStore, D: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
    donor: &mut D,
    donor_source: &CommitQuorumSource,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    source.validate()?;
    reverify_commit_quorum_persistent(donor, donor_source)?;
    let reuse = |name: &str| {
        let Some(name) = donor_component_name(source, donor_source, name) else {
            return Ok(None);
        };
        let key = [b"production/component/".as_slice(), name.as_bytes()].concat();
        donor
            .get(&key)
            .map_err(|e| e.to_string())?
            .map(Some)
            .ok_or_else(|| "missing input-matched donor checkpoint".to_string())
    };
    commit_quorum_persistent(store, source, limit, false, Some(&reuse), None, None)
}

fn donor_component_name(
    source: &CommitQuorumSource,
    donor: &CommitQuorumSource,
    name: &str,
) -> Option<String> {
    if source.context.block_hash != donor.context.block_hash {
        return None;
    }
    let (position, suffix) = name.strip_prefix("commit-signer-")?.split_once('-')?;
    let index: usize = position.parse().ok()?;
    if position != index.to_string() || suffix.is_empty() {
        return None;
    }
    let entry = source.signatures.get(index)?;
    let old = donor.signatures.iter().position(|other| other == entry)?;
    Some(format!("commit-signer-{old}-{suffix}"))
}

fn commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
    read_only: bool,
    reuse: Option<&crate::production_store::ComponentReuse<'_>>,
    interrupt: Option<&dyn Fn() -> bool>,
    observed: Option<&mut ProductionProgress>,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    source.validate()?;
    // Validate the strict public arithmetic and native signatures before opening
    // a mutable job. Native verification selects a transcript only for proving.
    let total: u64 = source.context.authorities.iter().map(|a| a.weight).sum();
    let signed: u64 = source
        .context
        .authorities
        .iter()
        .filter(|a| {
            source
                .context
                .signers
                .binary_search_by(|s| s.as_bytes().cmp(a.address.as_bytes()))
                .is_ok()
        })
        .map(|a| a.weight)
        .sum();
    if total == 0 || 3 * signed <= 2 * total {
        return Err("commit source is below strict quorum".to_string().into());
    }
    let mut legacy = Vec::with_capacity(source.signatures.len());
    for entry in &source.signatures {
        let message = source.context.block_hash.as_bytes();
        let raw = entry.signature.sig_type == SignatureType::Dilithium3
            && shell_crypto::DilithiumVerifier.verify_legacy_transcript(
                &entry.public_key,
                message,
                &entry.signature,
            );
        let valid = raw
            || match entry.signature.sig_type {
                SignatureType::MlDsa65 => shell_crypto::MlDsaVerifier
                    .verify(&entry.public_key, message, &entry.signature)
                    .unwrap_or(false),
                SignatureType::Dilithium3 => shell_crypto::DilithiumVerifier.verify_sdk_transcript(
                    &entry.public_key,
                    message,
                    &entry.signature,
                ),
                SignatureType::SphincsSha2256f => shell_crypto::SphincsVerifier
                    .verify(&entry.public_key, message, &entry.signature)
                    .unwrap_or(false),
            };
        if !valid {
            return Err("invalid commit source signature".to_string().into());
        }
        legacy.push(raw);
    }
    let has_slh = source
        .signatures
        .iter()
        .any(|e| e.signature.sig_type == SignatureType::SphincsSha2256f);
    let domain = if has_slh {
        "commit-signature-weight-v2"
    } else {
        "commit-signature-weight-v1"
    };
    let bytes = bounded_json(&(domain, source), 1024 * 1024)?;
    let mut job = if read_only {
        ProductionStore::open_existing_shared_matrix(store, &bytes)?
    } else {
        ProductionStore::open_shared_matrix(store, &bytes, limit)?
    };
    if let Some(reuse) = reuse {
        job = job.with_reuse(reuse);
    }
    if let Some(interrupt) = interrupt {
        job = job.with_interrupt(interrupt);
    }
    let result = (|| -> Result<CommitQuorumProof, ProductionError> {
        let weight = job.checkpoint(
            "commit-weight",
            || prove_quorum_weight(&source.context),
            |p| verify_quorum_weight(p, &source.context).map(|_| ()),
        )?;
        let mut signatures = Vec::with_capacity(source.signatures.len());
        let mut slh_signatures = Vec::new();
        for (i, (entry, raw)) in source.signatures.iter().zip(legacy).enumerate() {
            if entry.signature.sig_type == SignatureType::SphincsSha2256f {
                slh_signatures.push(slh::prove(
                    &mut job,
                    &format!("commit-signer-{i}"),
                    entry,
                    &source.context.block_hash,
                )?);
                continue;
            }
            signatures.push(crate::canonical_producer::prove_signature(
                &mut job,
                &format!("commit-signer-{i}"),
                &entry.public_key,
                source.context.block_hash.as_bytes(),
                &entry.signature.data,
                raw,
            )?);
        }
        let proof = CommitQuorumProof {
            version: if has_slh { 2 } else { 1 },
            weight,
            signatures,
            slh_signatures,
        };
        verify_commit_quorum(&proof, source)?;
        Ok(proof)
    })();
    if let Some(observed) = observed {
        *observed = job.progress();
    }
    result.map(|proof| (proof, job.progress()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::weighted_quorum::{AuthorityWeight, QuorumWeightContext};
    use shell_primitives::{Address, ShellHash};
    fn source() -> CommitQuorumSource {
        let address = Address::from([1; 32]);
        CommitQuorumSource {
            context: QuorumWeightContext {
                chain_id: 1337,
                parent_hash: ShellHash::ZERO,
                block_hash: ShellHash::from([3; 32]),
                block_number: 1,
                authorities: vec![AuthorityWeight { address, weight: 1 }],
                signers: vec![address],
            },
            signatures: vec![BlockSignerEvidence {
                address,
                public_key: vec![4; 1952],
                signature: PQSignature::new(SignatureType::MlDsa65, vec![5; 3309]),
            }],
        }
    }

    fn slh_source() -> CommitQuorumSource {
        use shell_crypto::{Signer, SphincsSigner};
        let signer = SphincsSigner::generate();
        let mut source = source();
        let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        source.context.authorities[0].address = address;
        source.context.signers[0] = address;
        source.signatures[0] = BlockSignerEvidence {
            address,
            public_key: signer.public_key().to_vec(),
            signature: signer.sign(source.context.block_hash.as_bytes()).unwrap(),
        };
        source
    }
    #[test]
    fn genuine_slh_source_pauses_after_weight_and_read_only_reopen_never_heals_missing_graph() {
        use shell_storage::MemoryDb;
        let source = slh_source();
        source.validate().unwrap();
        let mut db = MemoryDb::new();
        assert!(matches!(
            prove_commit_quorum_persistent(&mut db, &source, NonZeroUsize::new(1)),
            Err(ProductionError::Paused)
        ));
        let rows = db.scan_all().unwrap();
        assert!(rows
            .iter()
            .any(|(k, _)| k.as_slice() == b"production/component/commit-weight"));
        assert!(!rows
            .iter()
            .any(|(k, _)| k.starts_with(b"production/component/commit-signer-0-fors-")));
        // Reuse the genuine stored weight certificate; a native-valid signature
        // and correct arithmetic still cannot stand in for the full SLH graph.
        let frozen = bounded_json(&("commit-signature-weight-v2", &source), 1024 * 1024).unwrap();
        let weight: QuorumWeightProof = {
            let mut reader =
                ProductionStore::open_existing_shared_matrix(&mut db, &frozen).unwrap();
            reader
                .checkpoint(
                    "commit-weight",
                    || Err("must not regenerate cached weight".into()),
                    |p| verify_quorum_weight(p, &source.context).map(|_| ()),
                )
                .unwrap()
        };
        let entry = &source.signatures[0];
        assert!(shell_crypto::SphincsVerifier
            .verify(
                &entry.public_key,
                source.context.block_hash.as_bytes(),
                &entry.signature
            )
            .unwrap());
        let input = crate::slh_fors::SlhForsInputs {
            public_seed: entry.public_key[..32].try_into().unwrap(),
            public_root: entry.public_key[32..].try_into().unwrap(),
            message: *source.context.block_hash.as_bytes(),
            signature: entry.signature.data.to_vec(),
        };
        let incomplete = CommitQuorumProof {
            version: 2,
            weight,
            signatures: vec![],
            slh_signatures: vec![slh::CommitSlhProof {
                version: 2,
                manifest: crate::slh_signature::SlhSignatureManifest::new(input.clone()),
                fors: crate::slh_fors::SlhForsProof {
                    version: 1,
                    inputs: input,
                    hashes: vec![],
                },
                layers: vec![],
            }],
        };
        assert!(verify_commit_quorum(&incomplete, &source)
            .unwrap_err()
            .contains("layer count"));
        assert_eq!(db.scan_all().unwrap(), rows);

        assert!(reverify_commit_quorum_persistent(&mut db, &source).is_err());
        assert_eq!(db.scan_all().unwrap(), rows);
        let mut changed = source.clone();
        changed.signatures[0].signature.data[0] ^= 1;
        assert!(prove_commit_quorum_persistent(&mut db, &changed, NonZeroUsize::new(1)).is_err());
        assert_eq!(db.scan_all().unwrap(), rows);
    }
    #[test]
    fn legacy_payload_has_exact_old_three_field_encoding_and_cannot_authorize_slh() {
        #[derive(Serialize)]
        struct Legacy<'a> {
            version: u8,
            weight: &'a QuorumWeightProof,
            signatures: &'a Vec<Mldsa65VerificationProof>,
        }
        let source = slh_source();
        let mut proof = CommitQuorumProof {
            version: 1,
            weight: QuorumWeightProof {
                version: 1,
                context: source.context.clone(),
                prefixes: vec![[0, 0]],
                proof_bytes: vec![1],
            },
            signatures: vec![],
            slh_signatures: vec![],
        };
        let old = crate::compact_canonical::cbor(
            &Legacy {
                version: 1,
                weight: &proof.weight,
                signatures: &proof.signatures,
            },
            4096,
        )
        .unwrap();
        let encoded = payload::encode(&proof, 4096).unwrap();
        assert_eq!(
            encoded,
            [b"\0commit-quorum/cbor/v1/".as_slice(), old.as_slice()].concat()
        );
        assert!(verify_commit_quorum(&proof, &source)
            .unwrap_err()
            .contains("signature count"));
        proof.version = 2;
        assert!(payload::encode(&proof, 4096).is_err());
        assert!(verify_commit_quorum(&proof, &source).is_err());
        let mut changed = source.clone();
        changed.signatures[0].public_key.push(0);
        assert!(changed.validate().is_err());
        changed = source.clone();
        changed.signatures[0].signature.sig_type = SignatureType::MlDsa65;
        assert!(changed.validate().is_err());
    }
    #[test]
    fn donor_policy_matches_exact_signature_message_and_relocated_position() {
        let donor = source();
        let mut current = donor.clone();
        current.context.authorities[0].weight = 2;
        let mut added = current.signatures[0].clone();
        added.address = Address::from([0; 32]);
        added.public_key[0] ^= 1;
        current.signatures.insert(0, added);
        assert_eq!(
            donor_component_name(&current, &donor, "commit-signer-1-key").as_deref(),
            Some("commit-signer-0-key")
        );
        assert!(donor_component_name(&current, &donor, "commit-signer-0-key").is_none());
        for name in [
            "commit-weight",
            "commit-signer-01-key",
            "commit-signer-1-",
            "commit-signer-2-key",
        ] {
            assert!(donor_component_name(&current, &donor, name).is_none());
        }
        for field in 0..5 {
            let mut changed = current.clone();
            match field {
                0 => changed.context.block_hash = ShellHash::ZERO,
                1 => changed.signatures[1].public_key[0] ^= 1,
                2 => changed.signatures[1].signature.data[0] ^= 1,
                3 => changed.signatures[1].signature.sig_type = SignatureType::Dilithium3,
                _ => changed.signatures[1].address = Address::from([2; 32]),
            };
            assert!(donor_component_name(&changed, &donor, "commit-signer-1-key").is_none());
        }
    }
}
