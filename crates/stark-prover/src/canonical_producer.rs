//! Complete raw-source canonical sender proofs with resumable component generation.
//! The source is a retained trusted native block; consensus/execution remain native.
use crate::{
    account_state::{prove_account_state, verify_account_state},
    blake3_hash::{prove_hash, verify_hash},
    canonical_batch::{
        verify_canonical_signature_batch, CanonicalSignatureBatchProof, CanonicalTransactionProof,
        MAX_CANONICAL_SIGNATURE_BATCH,
    },
    mldsa_challenge::{prove_challenge, verify_challenge, ChallengeProof},
    mldsa_decode::{prove_signature_decode, verify_signature_decode, SignatureDecodeProof},
    mldsa_equation::{prove_equation, verify_equation, EquationInputs, EquationProof},
    mldsa_finish::{prove_finish, verify_finish, FinishProof},
    mldsa_inverse::{prove_inverse_ntt, verify_inverse_ntt, InverseNttProof},
    mldsa_key::{prove_public_key_decode, verify_public_key_decode, PublicKeyDecodeProof},
    mldsa_matrix::{
        prove_matrix_polynomial, verify_matrix_polynomial, MatrixPolynomialProof, MatrixProof,
    },
    mldsa_ntt::{prove_ntt, verify_ntt, NttProof, NTT_MODULUS},
    mldsa_source::TransactionSignatureProof,
    mldsa_verification::{
        verify_completion, verify_equation_pipeline, CompletionProof, EquationPipeline,
        Mldsa65VerificationProof,
    },
    production_store::{bounded_json, ProductionError, ProductionStore},
    registered_signature::RegisteredSignatureProof,
    shake_sponge::{prove_shake, verify_shake, ShakeKind, ShakeProof},
    SigBatchEntry,
};
use serde::Serialize;
use shell_core::{Account, Block, PQTX_ID_DOMAIN};
use shell_crypto::{MlDsaVerifier, SignatureType, Verifier};
use shell_primitives::{blake3_hash, keccak256, ShellHash};
use shell_storage::{CanonicalParentView, ChainStore, KvStore, MerkleTrie};

#[derive(Serialize)]
struct SenderSource {
    key: Vec<u8>,
    account: Account,
    nodes: Vec<Vec<u8>>,
}
/// Captured native canonical context, with no public unchecked constructor.
/// Keep the backing database offline/exclusive until production finishes.
pub struct CanonicalProductionSource<S: KvStore> {
    view: CanonicalParentView<S>,
    block: Block,
    senders: Vec<SenderSource>,
    identity: Vec<u8>,
}
impl<S: KvStore + 'static> CanonicalProductionSource<S> {
    pub fn capture(chain: &ChainStore<S>, tip: ShellHash, hash: ShellHash) -> Result<Self, String> {
        let block = chain
            .get_block_by_hash(&hash)
            .map_err(|e| e.to_string())?
            .ok_or("production block unavailable")?;
        if block.hash() != hash
            || block.transactions.is_empty()
            || block.transactions.len() > MAX_CANONICAL_SIGNATURE_BATCH
        {
            return Err("production canonical block hash/count/profile mismatch".into());
        }
        let view = chain
            .canonical_parent_view(tip, block.header.parent_hash)
            .map_err(|e| e.to_string())?;
        crate::canonical_signature::canonical_child_hash(&view, &block.header)?;
        ChainStore::new(view.store())
            .verify_block_body_commitment(&block)
            .map_err(|e| e.to_string())?;
        if block
            .system_transactions
            .iter()
            .any(|tx| tx.kind != shell_core::SystemTxKind::BlockGasReward)
        {
            return Err(
                "production profile supports only block gas reward system transactions".into(),
            );
        }
        let mut senders = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for signed in &block.transactions {
            if signed.tx.tx_type > 3
                || signed.aa_bundle.is_some()
                || signed.tx.chain_id != view.config().chain_id
                || signed.signature.sig_type != SignatureType::MlDsa65
                || signed.signature.data.len() != 3309
                || signed
                    .tx
                    .signing_payload(SignatureType::MlDsa65.as_u8())
                    .len()
                    > crate::blake3_hash::MAX_HASH_BYTES
                || !seen.insert(signed.hash())
            {
                return Err("unsupported or duplicate production sender source".into());
            }
            let key = view
                .registered_key(&signed.from)
                .map_err(|e| e.to_string())?
                .ok_or("production requires a parent-registered key")?;
            let account = view
                .world_state()
                .map_err(|e| e.to_string())?
                .get_account(&signed.from)
                .map_err(|e| e.to_string())?
                .ok_or("production requires a parent account")?;
            let mut tagged = vec![SignatureType::MlDsa65.as_u8()];
            tagged.extend_from_slice(&key);
            if key.len() != 1952
                || signed.pubkey_mode.pubkey_bytes().is_some_and(|p| p != key)
                || account.validation_code_hash.is_some()
                || (account.pq_pubkey_hash != blake3_hash(&key)
                    && account.pq_pubkey_hash != blake3_hash(&tagged))
            {
                return Err("production parent key/default account binding mismatch".into());
            }
            // Producer preflight only. Reuse and final acceptance still run full AIR verification.
            if !MlDsaVerifier
                .verify(
                    &key,
                    signed.sender_signing_hash().as_bytes(),
                    &signed.signature,
                )
                .map_err(|e| e.to_string())?
            {
                return Err("invalid raw production signature".into());
            }
            let nodes = MerkleTrie::at_root(view.store(), view.parent().state_root.as_bytes())
                .map_err(|e| e.to_string())?
                .get_proof(keccak256(signed.from.as_bytes()).as_bytes())
                .map_err(|e| e.to_string())?;
            if nodes.len() > crate::account_state::MAX_ACCOUNT_PROOF_NODES
                || nodes
                    .iter()
                    .any(|node| node.len() > crate::shake_sponge::MAX_SHAKE_MESSAGE_BYTES)
            {
                return Err("production account witness resource bound exceeded".into());
            }
            senders.push(SenderSource {
                key,
                account,
                nodes,
            });
        }
        let identity = bounded_json(&serde_json::json!({"version":1,"tip":tip,"config":view.config(),"parent":view.parent(),"block":block,"senders":senders}), 4 * 1024 * 1024).map_err(|e| e.to_string())?;
        Ok(Self {
            view,
            block,
            senders,
            identity,
        })
    }
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
    pub fn block(&self) -> &Block {
        &self.block
    }
    pub fn chain_id(&self) -> u64 {
        self.view.config().chain_id
    }
    pub fn genesis_hash(&self) -> ShellHash {
        self.view.config().genesis_hash
    }

    /// All new and reused components are cryptographically checked. Pauses publish
    /// only durable components, never an incomplete final proof or verified token.
    pub fn produce<J: KvStore>(
        &self,
        job: &mut ProductionStore<'_, J>,
    ) -> Result<CanonicalSignatureBatchProof, ProductionError> {
        if !job.matches_source(&self.identity) {
            return Err("production job belongs to another canonical source"
                .to_string()
                .into());
        }
        let mut transactions = Vec::new();
        for (i, (signed, source)) in self
            .block
            .transactions
            .iter()
            .zip(&self.senders)
            .enumerate()
        {
            let prefix = format!("sender-{i}");
            let signature = prove_mldsa(
                job,
                &prefix,
                &source.key,
                signed.sender_signing_hash().as_bytes(),
                &signed.signature.data,
            )?;
            let account = job.checkpoint(
                &format!("{prefix}-account"),
                || prove_account_state(signed.from.as_bytes(), &source.nodes),
                |p| {
                    verify_account_state(
                        p,
                        self.view.parent().state_root.as_bytes(),
                        signed.from.as_bytes(),
                        Some(&source.account),
                    )
                    .map(|_| ())
                },
            )?;
            let signing_payload = signed.tx.signing_payload(SignatureType::MlDsa65.as_u8());
            let signing_hash = hash(job, &format!("{prefix}-signing-hash"), &signing_payload)?;
            let public_key_hash = hash(job, &format!("{prefix}-key-hash"), &source.key)?;
            let mut id = PQTX_ID_DOMAIN.to_vec();
            id.extend_from_slice(signed.from.as_bytes());
            id.extend_from_slice(&signing_hash.output);
            let transaction_id = hash(job, &format!("{prefix}-id"), &id)?;
            let entry = SigBatchEntry::from_signed_transaction(signed);
            let mut leaf = entry.msg_hash.to_vec();
            leaf.extend_from_slice(&entry.pk_hash);
            let leaf = hash(job, &format!("{prefix}-leaf"), &leaf)?;
            let tagged_key = if source.account.pq_pubkey_hash.as_bytes() == &public_key_hash.output
            {
                None
            } else {
                let mut bytes = vec![SignatureType::MlDsa65.as_u8()];
                bytes.extend_from_slice(&source.key);
                Some(hash(job, &format!("{prefix}-tagged-key"), &bytes)?)
            };
            transactions.push(CanonicalTransactionProof {
                account,
                signature: RegisteredSignatureProof {
                    version: 1,
                    transaction: TransactionSignatureProof {
                        version: 1,
                        signing_hash,
                        public_key_hash,
                        signature,
                    },
                    transaction_id,
                    leaf,
                    tagged_key,
                },
            });
        }
        let proof = CanonicalSignatureBatchProof {
            version: 1,
            transactions,
        };
        verify_canonical_signature_batch(&self.view, &self.block, &proof)?;
        Ok(proof)
    }
}
fn hash<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    name: &str,
    bytes: &[u8],
) -> Result<crate::blake3_hash::Blake3HashProof, ProductionError> {
    job.checkpoint(
        name,
        || prove_hash(bytes),
        |p| verify_hash(p, bytes, blake3_hash(bytes).as_bytes()),
    )
}
fn array(values: &[u32]) -> Result<[u32; 256], String> {
    values
        .try_into()
        .map_err(|_| "expected 256 coefficients".into())
}
fn last(p: &NttProof) -> Result<[u32; 256], String> {
    array(p.stages.last().ok_or("missing NTT endpoint")?)
}
fn ntt<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    name: &str,
    input: &[u32; 256],
) -> Result<NttProof, ProductionError> {
    job.checkpoint(
        name,
        || prove_ntt(input),
        |p| verify_ntt(p, input, &last(p)?),
    )
}
fn shake<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    name: &str,
    input: &[u8],
    len: usize,
) -> Result<ShakeProof, ProductionError> {
    job.checkpoint(
        name,
        || prove_shake(ShakeKind::Shake256, input, len),
        |p| {
            if p.output.len() != len {
                return Err("production SHAKE output size mismatch".into());
            }
            verify_shake(p, ShakeKind::Shake256, input, &p.output)
        },
    )
}
fn prove_mldsa<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    prefix: &str,
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<Mldsa65VerificationProof, ProductionError> {
    let key: PublicKeyDecodeProof = job.checkpoint(
        &format!("{prefix}-key"),
        || prove_public_key_decode(pk),
        |p| verify_public_key_decode(p, pk),
    )?;
    let signature: SignatureDecodeProof = job.checkpoint(
        &format!("{prefix}-signature"),
        || prove_signature_decode(sig),
        |p| verify_signature_decode(p, sig),
    )?;
    let mut polynomials = Vec::new();
    for row in 0..6 {
        for col in 0..5 {
            let p: MatrixPolynomialProof = job.checkpoint(
                &format!("{prefix}-matrix-{row}-{col}"),
                || prove_matrix_polynomial(&key.decoded.rho, row, col),
                |p| verify_matrix_polynomial(p, &key.decoded.rho, row, col, &p.coefficients),
            )?;
            polynomials.push(p);
        }
    }
    let challenge: ChallengeProof = job.checkpoint(
        &format!("{prefix}-challenge"),
        || prove_challenge(&signature.decoded.challenge),
        |p| {
            verify_challenge(
                p,
                &signature.decoded.challenge,
                p.challenge().ok_or("missing challenge endpoint")?,
            )
        },
    )?;
    let mut z_ntt = Vec::new();
    for col in 0..5 {
        z_ntt.push(ntt(
            job,
            &format!("{prefix}-z-{col}"),
            &array(&signature.decoded.z[col])?,
        )?);
    }
    let mut t1_ntt = Vec::new();
    for row in 0..6 {
        let input = array(
            &key.decoded.t1[row]
                .iter()
                .map(|&v| u32::from(v) * 8192)
                .collect::<Vec<_>>(),
        )?;
        t1_ntt.push(ntt(job, &format!("{prefix}-t1-{row}"), &input)?);
    }
    let c_input = array(
        &challenge
            .challenge()
            .ok_or_else(|| "missing challenge endpoint".to_string())?
            .iter()
            .map(|&v| match v {
                -1 => NTT_MODULUS - 1,
                0 => 0,
                1 => 1,
                _ => NTT_MODULUS,
            })
            .collect::<Vec<_>>(),
    )?;
    let c_ntt = ntt(job, &format!("{prefix}-c-ntt"), &c_input)?;
    let inputs = EquationInputs {
        matrix_ntt: polynomials.iter().map(|p| p.coefficients.clone()).collect(),
        z_ntt: z_ntt
            .iter()
            .map(|p| last(p).map(|v| v.to_vec()))
            .collect::<Result<_, _>>()?,
        t1_scaled_ntt: t1_ntt
            .iter()
            .map(|p| last(p).map(|v| v.to_vec()))
            .collect::<Result<_, _>>()?,
        challenge_ntt: last(&c_ntt)?.to_vec(),
    };
    let equation: EquationProof = job.checkpoint(
        &format!("{prefix}-equation"),
        || prove_equation(&inputs),
        |p| verify_equation(p, &inputs, &p.output),
    )?;
    let mut inverse = Vec::new();
    for row in 0..6 {
        let input = array(&equation.output[row])?;
        let p: InverseNttProof = job.checkpoint(
            &format!("{prefix}-inverse-{row}"),
            || prove_inverse_ntt(&input),
            |p| {
                verify_inverse_ntt(
                    p,
                    &input,
                    &array(p.forward.stages.first().ok_or("missing inverse endpoint")?)?,
                )
            },
        )?;
        inverse.push(p);
    }
    let equation = EquationPipeline {
        key,
        signature,
        matrix: MatrixProof {
            version: 1,
            rho: pk[..32].to_vec(),
            polynomials,
        },
        challenge,
        z_ntt,
        t1_ntt,
        c_ntt,
        equation,
        inverse,
    };
    let token = verify_equation_pipeline(&equation, pk, sig)?;
    let finish: FinishProof = job.checkpoint(
        &format!("{prefix}-finish"),
        || prove_finish(token.finish_inputs()),
        |p| verify_finish(p, token.finish_inputs(), &p.w1, &p.encoded),
    )?;
    let tr = shake(job, &format!("{prefix}-tr"), pk, 64)?;
    let mut mu_input = tr.output.clone();
    mu_input.extend_from_slice(&[0, 0]);
    mu_input.extend_from_slice(message);
    let mu = shake(job, &format!("{prefix}-mu"), &mu_input, 64)?;
    let mut commitment_input = mu.output.clone();
    commitment_input.extend_from_slice(&finish.encoded);
    let commitment = shake(job, &format!("{prefix}-commitment"), &commitment_input, 48)?;
    let completion = CompletionProof {
        finish,
        tr,
        mu,
        commitment,
    };
    verify_completion(&token, message, &completion)?;
    Ok(Mldsa65VerificationProof {
        version: 1,
        equation,
        completion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{BlockHeader, Transaction};
    use shell_crypto::PQSignature;
    use shell_primitives::{Address, U256};
    use shell_storage::MemoryDb;
    use std::sync::Arc;
    #[test]
    fn source_capture_rejects_unsupported_inactive_stale_and_unregistered_without_writes() {
        for mode in ["unsupported", "inactive", "stale", "unregistered"] {
            let db = Arc::new(MemoryDb::new());
            let chain = ChainStore::new(db.clone());
            let mut world = shell_storage::WorldState::new(db.clone());
            let root = world.state_root().unwrap();
            let genesis = Block {
                header: BlockHeader {
                    state_root: root,
                    ..Default::default()
                },
                transactions: vec![],
                system_transactions: vec![],
                proposer_seal: None,
            };
            let cfg = serde_json::from_value(serde_json::json!({"chain_id":10,"genesis_hash":genesis.hash(),"block_commitment_height": if mode == "inactive" { None } else { Some(1u64) }})).unwrap();
            chain.commit_genesis_block(&genesis, &cfg).unwrap();
            let tx = Transaction {
                chain_id: 10,
                nonce: 0,
                to: Some(Address::ZERO),
                value: U256::ZERO,
                data: Default::default(),
                gas_limit: 21_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 0,
                tx_type: if mode == "unsupported" { 127 } else { 0 },
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let mut block = Block {
                header: BlockHeader {
                    state_root: root,
                    parent_hash: genesis.hash(),
                    number: 1,
                    ..Default::default()
                },
                transactions: vec![shell_core::SignedTransaction::new(
                    Address::ZERO,
                    tx,
                    PQSignature::new(SignatureType::MlDsa65, vec![0; 3309]),
                )],
                system_transactions: vec![],
                proposer_seal: None,
            };
            if mode != "inactive" {
                block.header.transactions_root =
                    shell_core::block_body_root(&block.transactions, &block.system_transactions)
                        .unwrap();
            }
            let receipts = vec![shell_core::TransactionReceipt {
                tx_hash: block.transactions[0].hash(),
                block_number: 1,
                tx_index: 0,
                status: 1,
                gas_used: 0,
                cumulative_gas_used: 0,
                contract_address: None,
                logs_bloom: Default::default(),
                logs: vec![],
            }];
            block.header.receipts_root = shell_core::block_receipts_root(&receipts);
            // These are storage fixtures only, never claimed executed blocks.
            let overlay = Arc::new(shell_storage::OverlayStore::new(db.clone()));
            let staged = ChainStore::new(overlay.clone());
            staged
                .stage_address_metadata_undo(
                    &block.hash(),
                    &staged.address_metadata_checkpoint().unwrap(),
                )
                .unwrap();
            staged
                .commit_canonical_block(&block, Some(&receipts))
                .unwrap();
            overlay.commit().unwrap();
            let before = db.scan_all().unwrap();
            let tip = if mode == "stale" {
                genesis.hash()
            } else {
                block.hash()
            };
            assert!(
                CanonicalProductionSource::capture(&chain, tip, block.hash()).is_err(),
                "{mode}"
            );
            assert_eq!(before, db.scan_all().unwrap(), "{mode}");
        }
    }
}
