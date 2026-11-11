//! Complete SHA2-256f raw header seals. Native authority selection remains external.
use crate::{
    header_hash::{verify_header_hash, BlockHeaderProof},
    production_store::{ProductionError, ProductionStore},
    sha2_compression::{prove_compression_batch, verify_compression_batch, Sha2Algorithm},
    slh_fors::{prove_fors_using, verify_fors, SlhForsInputs, SlhForsProof},
    slh_sha2::{prove_slh_sha2, verify_slh_sha2},
    slh_signature::{verify_slh_signature_using, SlhSignatureManifest},
    slh_xmss::{prove_xmss_using, SlhXmssProof},
};
use serde::{Deserialize, Serialize};
use shell_core::BlockHeader;
use shell_crypto::{PQSignature, SignatureType};
use shell_primitives::ShellHash;
use shell_storage::KvStore;
use std::cell::RefCell;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhProposerSealProof {
    pub version: u8,
    pub header: BlockHeaderProof,
    pub manifest: SlhSignatureManifest,
    pub fors: SlhForsProof,
    pub layers: Vec<SlhXmssProof>,
}
pub(crate) fn inputs(
    key: &[u8],
    hash: &ShellHash,
    seal: &PQSignature,
) -> Result<SlhForsInputs, String> {
    if seal.sig_type != SignatureType::SphincsSha2256f
        || key.len() != 64
        || seal.data.len() != 49856
    {
        return Err("unsupported SLH proposer key/seal framing".into());
    }
    Ok(SlhForsInputs {
        public_seed: key[..32].try_into().expect("checked key"),
        public_root: key[32..].try_into().expect("checked key"),
        message: *hash.as_bytes(),
        signature: seal.data.to_vec(),
    })
}
pub(crate) fn verify_graph(
    proof: &SlhProposerSealProof,
    key: &[u8],
    header: &BlockHeader,
    hash: &ShellHash,
    seal: &PQSignature,
) -> Result<(), String> {
    if proof.version != 1 || proof.layers.len() != 17 {
        return Err("SLH proposer version/layer count mismatch".into());
    }
    verify_header_hash(&proof.header, header, hash)?;
    let expected = inputs(key, hash, seal)?;
    verify_slh_signature_using(&proof.manifest, &expected, &proof.fors, |layer, _| {
        Ok(proof.layers[usize::from(layer)].clone())
    })?;
    Ok(())
}
pub(crate) fn produce<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    header: &BlockHeader,
    key: &[u8],
    seal: &PQSignature,
) -> Result<SlhProposerSealProof, ProductionError> {
    let hash = header.hash();
    // Callback APIs expose Strings; retain the typed pause to distinguish a
    // completed durable boundary from an invalid proof or failed store write.
    let failure = RefCell::new(None);
    let store = RefCell::new(job);
    let input = inputs(key, &hash, seal)?;
    let result = (|| -> Result<_, String> {
        let fors = prove_fors_using(&input, |at, request| {
            checked(
                &failure,
                store.borrow_mut().checkpoint(
                    &format!("slh-proposer-fors-{at}"),
                    || prove_slh_sha2(request),
                    |p| verify_slh_sha2(p, request).map(|_| ()),
                ),
            )
        })?;
        verify_fors(&fors, &input)?;
        let manifest = SlhSignatureManifest::new(input.clone());
        let mut layers = Vec::new();
        verify_slh_signature_using(&manifest, &input, &fors, |layer, expected| {
            let proof = prove_xmss_using(
                expected,
                |at, inputs| {
                    checked(
                        &failure,
                        store.borrow_mut().checkpoint(
                            &if at == 0 {
                                "slh-proposer-seed-prefix".to_string()
                            } else {
                                format!("slh-proposer-layer-{layer}-chain-{at}")
                            },
                            || prove_compression_batch(Sha2Algorithm::Sha256, inputs),
                            |p| {
                                verify_compression_batch(p, Sha2Algorithm::Sha256, inputs)
                                    .map(|_| ())
                            },
                        ),
                    )
                },
                |at, request| {
                    checked(
                        &failure,
                        store.borrow_mut().checkpoint(
                            &format!("slh-proposer-layer-{layer}-hash-{at}"),
                            || prove_slh_sha2(request),
                            |p| verify_slh_sha2(p, request).map(|_| ()),
                        ),
                    )
                },
            )?;
            layers.push(proof.clone());
            Ok(proof)
        })?;
        let header_proof = checked(
            &failure,
            store.borrow_mut().checkpoint(
                "slh-proposer-header",
                || crate::header_hash::prove_header_hash(header),
                |p| crate::header_hash::verify_header_hash(p, header, &hash).map(|_| ()),
            ),
        )?;
        let proof = SlhProposerSealProof {
            version: 1,
            header: header_proof,
            manifest,
            fors,
            layers,
        };
        verify_graph(&proof, key, header, &hash, seal)?;
        Ok(proof)
    })();
    match result {
        Ok(proof) => Ok(proof),
        Err(error) => Err(failure
            .into_inner()
            .unwrap_or(ProductionError::Failed(error))),
    }
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
