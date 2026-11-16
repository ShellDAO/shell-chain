//! Complete raw SHA2-256f commit signatures over the existing seventeen-layer AIR.
use crate::{
    production_store::{ProductionError, ProductionStore},
    sha2_compression::{prove_wide_sha256_batch, verify_wide_sha256_batch},
    slh_fors::{prove_fors_using, verify_fors, SlhForsInputs, SlhForsProof},
    slh_sha2::{prove_slh_sha2, verify_slh_sha2},
    slh_signature::{
        verify_slh_signature_profile_using, SlhSignatureManifest, SLH_HYPERTREE_LAYERS,
    },
    slh_xmss::{prove_xmss_profile_using, SlhXmssProof},
};
use serde::{Deserialize, Serialize};
use shell_core::BlockSignerEvidence;
use shell_crypto::SignatureType;
use shell_primitives::ShellHash;
use shell_storage::KvStore;
use std::cell::RefCell;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitSlhProof {
    /// Version two uses the existing explicit wide-WOTS certificate profile.
    pub version: u8,
    pub manifest: SlhSignatureManifest,
    pub fors: SlhForsProof,
    #[serde(deserialize_with = "layers")]
    pub layers: Vec<SlhXmssProof>,
}
fn layers<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<SlhXmssProof>, D::Error> {
    crate::compact_canonical::bounded_vec::<D, SlhXmssProof, 17>(d)
}
fn inputs(entry: &BlockSignerEvidence, hash: &ShellHash) -> Result<SlhForsInputs, String> {
    if entry.signature.sig_type != SignatureType::SphincsSha2256f
        || entry.public_key.len() != 64
        || entry.signature.data.len() != crate::slh_fors::SLH_SHA2_256F_SIGNATURE_BYTES
    {
        return Err("commit SLH key/signature profile mismatch".into());
    }
    Ok(SlhForsInputs {
        public_seed: entry.public_key[..32].try_into().expect("checked key"),
        public_root: entry.public_key[32..].try_into().expect("checked key"),
        message: *hash.as_bytes(),
        signature: entry.signature.data.to_vec(),
    })
}
pub(super) fn verify(
    proof: &CommitSlhProof,
    entry: &BlockSignerEvidence,
    hash: &ShellHash,
) -> Result<(), String> {
    if proof.version != 2 || proof.layers.len() != usize::from(SLH_HYPERTREE_LAYERS) {
        return Err("commit SLH profile/layer count mismatch".into());
    }
    let expected = inputs(entry, hash)?;
    verify_slh_signature_profile_using(
        true,
        &proof.manifest,
        &expected,
        &proof.fors,
        |layer, _| Ok(proof.layers[usize::from(layer)].clone()),
    )?;
    Ok(())
}
fn checked<T>(
    failure: &RefCell<Option<ProductionError>>,
    result: Result<T, ProductionError>,
) -> Result<T, String> {
    result.map_err(|error| {
        let message = error.to_string();
        *failure.borrow_mut() = Some(error);
        message
    })
}
pub(super) fn prove<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    prefix: &str,
    entry: &BlockSignerEvidence,
    hash: &ShellHash,
) -> Result<CommitSlhProof, ProductionError> {
    let input = inputs(entry, hash)?;
    let failure = RefCell::new(None);
    let store = RefCell::new(job);
    let result = (|| -> Result<_, String> {
        let fors = prove_fors_using(&input, |at, request| {
            checked(
                &failure,
                store.borrow_mut().checkpoint(
                    &format!("{prefix}-fors-{at}"),
                    || prove_slh_sha2(request),
                    |p| verify_slh_sha2(p, request).map(|_| ()),
                ),
            )
        })?;
        verify_fors(&fors, &input)?;
        let manifest = SlhSignatureManifest::new(input.clone());
        let mut layers = Vec::new();
        verify_slh_signature_profile_using(true, &manifest, &input, &fors, |layer, expected| {
            let proof = prove_xmss_profile_using(
                true,
                expected,
                |at, inputs| {
                    checked(
                        &failure,
                        store.borrow_mut().checkpoint(
                            &if at == 0 {
                                format!("{prefix}-seed-prefix")
                            } else {
                                format!("{prefix}-layer-{layer}-chain-{at}")
                            },
                            || {
                                if at == 0 {
                                    crate::sha2_compression::prove_compression_batch(
                                        crate::sha2_compression::Sha2Algorithm::Sha256,
                                        inputs,
                                    )
                                } else {
                                    prove_wide_sha256_batch(inputs)
                                }
                            },
                            |p| {
                                (if at == 0 {
                                    crate::sha2_compression::verify_compression_batch(
                                        p,
                                        crate::sha2_compression::Sha2Algorithm::Sha256,
                                        inputs,
                                    )
                                } else {
                                    verify_wide_sha256_batch(p, inputs)
                                })
                                .map(|_| ())
                            },
                        ),
                    )
                },
                |at, request| {
                    checked(
                        &failure,
                        store.borrow_mut().checkpoint(
                            &format!("{prefix}-layer-{layer}-hash-{at}"),
                            || prove_slh_sha2(request),
                            |p| verify_slh_sha2(p, request).map(|_| ()),
                        ),
                    )
                },
            )?;
            layers.push(proof.clone());
            Ok(proof)
        })?;
        Ok(CommitSlhProof {
            version: 2,
            manifest,
            fors,
            layers,
        })
    })();
    result.map_err(|e| failure.into_inner().unwrap_or(ProductionError::Failed(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_manifest_cannot_replace_all_seventeen_layers() {
        let expected = SlhForsInputs {
            public_seed: [1; 32],
            public_root: [2; 32],
            message: [3; 32],
            signature: vec![0; 49_856],
        };
        let entry = BlockSignerEvidence {
            address: shell_primitives::Address::ZERO,
            public_key: [
                expected.public_seed.as_slice(),
                expected.public_root.as_slice(),
            ]
            .concat(),
            signature: shell_crypto::PQSignature::new(
                SignatureType::SphincsSha2256f,
                expected.signature.clone(),
            ),
        };
        let mut proof = CommitSlhProof {
            version: 2,
            manifest: SlhSignatureManifest::new(expected.clone()),
            fors: SlhForsProof {
                version: 1,
                inputs: expected,
                hashes: vec![],
            },
            layers: vec![],
        };
        assert!(verify(&proof, &entry, &ShellHash::from([3; 32]))
            .unwrap_err()
            .contains("layer count"));
        proof.version = 1;
        assert!(verify(&proof, &entry, &ShellHash::from([3; 32])).is_err());
    }
}
