//! Real source-bound, resumable SLH certificates. No successful status is reused.
use crate::{
    account_state::{prove_account_state, verify_account_state},
    blake3_hash::{
        large_body_witness_inputs, prove_compression, prove_hash, prove_large_body_hash_using,
        verify_compression, verify_hash, CompressionProof,
    },
    body_membership::{prove_large_transaction_body_using, LargeTransactionEnvelopeProof},
    canonical_slh::{inputs, verify_at_source, CanonicalSlhTransactionProof},
    production_store::{ProductionError, ProductionStore},
    sha2_compression::{prove_compression_batch, verify_compression_batch, Sha2Algorithm},
    slh_fors::{prove_fors_using, verify_fors},
    slh_sha2::{prove_slh_sha2, verify_slh_sha2},
    slh_signature::{verify_slh_signature_using, SlhSignatureManifest},
    slh_xmss::prove_xmss_using,
    SigBatchEntry,
};
use shell_core::{Account, Block, BlockHeader, PQTX_ID_DOMAIN};
use shell_primitives::{blake3_hash, ShellHash};
use shell_storage::KvStore;
use std::cell::RefCell;

pub(crate) fn produce<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    parent: &BlockHeader,
    block: &Block,
    key: &[u8],
    account: &Account,
    nodes: &[Vec<u8>],
) -> Result<CanonicalSlhTransactionProof, ProductionError> {
    let signed = &block.transactions[0];
    let hash = |job: &mut ProductionStore<'_, S>, name: &str, bytes: &[u8]| {
        job.checkpoint(
            name,
            || prove_hash(bytes),
            |p| verify_hash(p, bytes, blake3_hash(bytes).as_bytes()),
        )
    };
    let account_proof = job.checkpoint(
        "sender-0-account",
        || prove_account_state(signed.from.as_bytes(), nodes),
        |p| {
            verify_account_state(
                p,
                parent.state_root.as_bytes(),
                signed.from.as_bytes(),
                Some(account),
            )
            .map(|_| ())
        },
    )?;
    let public_key_hash = hash(job, "sender-0-key-hash", key)?;
    let tagged_key = if account.pq_pubkey_hash != ShellHash::ZERO
        && account.pq_pubkey_hash == ShellHash::from(public_key_hash.output)
    {
        None
    } else {
        let mut bytes = vec![signed.signature.sig_type.as_u8()];
        bytes.extend_from_slice(key);
        Some(hash(job, "sender-0-tagged-key", &bytes)?)
    };
    let signing_hash = hash(
        job,
        "sender-0-signing-hash",
        &signed.tx.signing_payload(signed.signature.sig_type.as_u8()),
    )?;
    let mut id = PQTX_ID_DOMAIN.to_vec();
    id.extend_from_slice(signed.from.as_bytes());
    id.extend_from_slice(&signing_hash.output);
    let transaction_id = hash(job, "sender-0-id", &id)?;
    let entry = SigBatchEntry::from_signed_transaction(signed);
    let mut bytes = entry.msg_hash.to_vec();
    bytes.extend_from_slice(&entry.pk_hash);
    let leaf = hash(job, "sender-0-leaf", &bytes)?;
    // Callback APIs expose Strings; retain the typed pause to distinguish a
    // completed durable boundary from an invalid proof or failed store write.
    let failure = RefCell::new(None);
    let store = RefCell::new(job);
    let input = inputs(signed, key, signing_hash.output)?;
    let result = (|| -> Result<_, String> {
        let fors = prove_fors_using(&input, |at, request| {
            checked(
                &failure,
                store.borrow_mut().checkpoint(
                    &format!("sender-0-fors-{at}"),
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
                                "sender-0-seed-prefix".to_string()
                            } else {
                                format!("sender-0-layer-{layer}-chain-{at}")
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
                            &format!("sender-0-layer-{layer}-hash-{at}"),
                            || prove_slh_sha2(request),
                            |p| verify_slh_sha2(p, request).map(|_| ()),
                        ),
                    )
                },
            )?;
            layers.push(proof.clone());
            Ok(proof)
        })?;
        let body = prove_large_transaction_body_using(block, 0, |at, bytes, large| {
            if !large {
                return checked(
                    &failure,
                    hash(
                        &mut store.borrow_mut(),
                        &format!("sender-0-body-{at}"),
                        bytes,
                    ),
                );
            }
            // Native witness construction supplies operands only. Each sixteen-
            // compression checkpoint is verified independently, then every
            // output is rebound to the exact full hash route before consumption.
            let expected = large_body_witness_inputs(bytes)?;
            let mut active = Vec::<CompressionProof>::new();
            prove_large_body_hash_using(bytes, |ordinal, input| {
                if ordinal % 16 == 0 {
                    let group = &expected[ordinal..expected.len().min(ordinal + 16)];
                    active = checked(
                        &failure,
                        store.borrow_mut().checkpoint(
                            &format!("sender-0-body-group-{}", ordinal / 16),
                            || group.iter().map(prove_compression).collect(),
                            |proofs: &Vec<CompressionProof>| {
                                if proofs.len() != group.len() {
                                    return Err("body checkpoint group count mismatch".into());
                                }
                                for (p, expected) in proofs.iter().zip(group) {
                                    verify_compression(
                                        p,
                                        expected,
                                        &p.output().ok_or("body compression output absent")?,
                                    )?;
                                }
                                Ok(())
                            },
                        ),
                    )?;
                }
                let proof = active[ordinal % 16].clone();
                if proof.input != *input {
                    return Err("body checkpoint group routing mismatch".into());
                }
                Ok(proof)
            })
        })?;
        let proof = CanonicalSlhTransactionProof {
            version: if account.pq_pubkey_hash == ShellHash::ZERO {
                2
            } else {
                1
            },
            account: account_proof,
            public_key_hash,
            tagged_key,
            envelope: LargeTransactionEnvelopeProof {
                version: 1,
                body,
                signing_hash,
                transaction_id,
            },
            leaf,
            manifest,
            fors,
            layers,
        };
        verify_at_source(&proof, parent, &block.header, signed, 0, key, account)?;
        Ok(proof)
    })();
    match result {
        Ok(proof) => Ok(proof),
        Err(e) => Err(failure.into_inner().unwrap_or(ProductionError::Failed(e))),
    }
}

fn checked<T>(
    failure: &RefCell<Option<ProductionError>>,
    result: Result<T, ProductionError>,
) -> Result<T, String> {
    result.map_err(|e| {
        let message = e.to_string();
        *failure.borrow_mut() = Some(e);
        message
    })
}
