//! Complete raw-source canonical sender proofs with resumable component generation.
//! The source is a retained trusted native block; consensus/execution remain native.
use crate::{
    account_state::{prove_account_state, verify_account_state},
    blake3_hash::{prove_hash, verify_hash},
    canonical_batch::{
        CanonicalSignatureBatchProof, CanonicalTransactionProof, MAX_CANONICAL_SIGNATURE_BATCH,
    },
    header_hash::{prove_header_hash, verify_header_hash},
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
    proposer_seal::ProposerSealProof,
    registered_signature::{verify_registered_signature_entry, RegisteredSignatureProof},
    shake_sponge::{prove_shake, verify_shake, ShakeKind, ShakeProof},
    SigBatchEntry,
};
use alloy_rlp::Encodable;
use serde::{Deserialize, Serialize};
use shell_core::{Account, Block, BlockHeader, PQTX_ID_DOMAIN};
use shell_crypto::{MlDsaVerifier, SignatureType, Verifier};
use shell_primitives::{blake3_hash, keccak256, ShellHash};
use shell_storage::{ChainConfig, ChainStore, KvStore, MemoryDb, MerkleTrie};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderSource {
    key: Vec<u8>,
    account: Account,
    nodes: Vec<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedInputs {
    version: u8,
    tip: ShellHash,
    config: ChainConfig,
    parent: BlockHeader,
    block: Block,
    senders: Vec<SenderSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proposer_key: Option<Vec<u8>>,
}
/// Immutable public proving inputs, never a canonical authorization token.
/// Capture freezes the native source once; proving makes no live state reads.
/// Recovery authenticates headers/body/MPT/key bindings again before reuse.
pub struct CanonicalProductionSource {
    input: CapturedInputs,
    identity: Vec<u8>,
}
impl CanonicalProductionSource {
    pub fn capture<S: KvStore + 'static>(
        chain: &ChainStore<S>,
        tip: ShellHash,
        hash: ShellHash,
    ) -> Result<Self, String> {
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
        let proposer_key = if block
            .proposer_seal
            .as_ref()
            .is_some_and(|s| s.sig_type == SignatureType::MlDsa65)
        {
            Some(
                view.registered_key(&block.header.proposer)
                    .map_err(|e| e.to_string())?
                    .ok_or("full production requires a parent-registered proposer key")?,
            )
        } else {
            None
        };
        let input = CapturedInputs {
            version: if proposer_key.is_some() { 2 } else { 1 },
            tip,
            config: view.config().clone(),
            parent: view.parent().clone(),
            block,
            senders,
            proposer_key,
        };
        let identity = bounded_json(
            &serde_json::to_value(&input).map_err(|e| e.to_string())?,
            4 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?;
        let source = Self { input, identity };
        source.recheck_canonical(chain)?;
        Ok(source)
    }
    /// Restore public inputs only. No verified token or cached success flag is decoded.
    /// Historical registry reads are replaced by a complete native MPT/key-hash
    /// preflight against the independently retained canonical parent header.
    pub fn restore<S: KvStore + 'static>(
        chain: &ChainStore<S>,
        bytes: &[u8],
    ) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err("production source size limit".into());
        }
        let input: CapturedInputs =
            serde_json::from_slice(bytes).map_err(|e| format!("production source decode: {e}"))?;
        let identity = bounded_json(
            &serde_json::to_value(&input).map_err(|e| e.to_string())?,
            4 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?;
        if identity != bytes {
            return Err("noncanonical production source encoding".into());
        }
        let source = Self { input, identity };
        source.recheck_canonical(chain)?;
        Ok(source)
    }
    pub fn recheck_canonical<S: KvStore + 'static>(
        &self,
        chain: &ChainStore<S>,
    ) -> Result<(), String> {
        let i = &self.input;
        let cfg = chain
            .get_chain_config()
            .map_err(|e| e.to_string())?
            .ok_or("production chain configuration absent")?;
        if !matches!(
            (i.version, i.proposer_key.is_some()),
            (1, false) | (2, true)
        ) || cfg.chain_id != i.config.chain_id
            || cfg.genesis_hash != i.config.genesis_hash
            || chain
                .get_block_hash_by_number(0)
                .map_err(|e| e.to_string())?
                != Some(cfg.genesis_hash)
            || cfg
                .block_commitment_height
                .is_none_or(|h| i.block.number() < h)
            || i.config
                .block_commitment_height
                .is_none_or(|h| i.block.number() < h)
            || i.parent.number.checked_add(1) != Some(i.block.number())
            || i.block.header.parent_hash != i.parent.hash()
            || chain
                .get_header_by_hash(&i.block.hash())
                .map_err(|e| e.to_string())?
                .as_ref()
                != Some(&i.block.header)
            || chain
                .get_header_by_hash(&i.parent.hash())
                .map_err(|e| e.to_string())?
                .as_ref()
                != Some(&i.parent)
            || chain
                .get_block_hash_by_number(i.block.number())
                .map_err(|e| e.to_string())?
                != Some(i.block.hash())
            || chain
                .get_block_hash_by_number(i.parent.number)
                .map_err(|e| e.to_string())?
                != Some(i.parent.hash())
            || shell_core::block_body_root(&i.block.transactions, &i.block.system_transactions)
                .map_err(|e| e.to_string())?
                != i.block.header.transactions_root
        {
            return Err(
                "production source is not the activated trusted canonical body/parent".into(),
            );
        }
        if i.block.transactions.is_empty()
            || i.block.transactions.len() > MAX_CANONICAL_SIGNATURE_BATCH
            || i.senders.len() != i.block.transactions.len()
            || i.block
                .system_transactions
                .iter()
                .any(|tx| tx.kind != shell_core::SystemTxKind::BlockGasReward)
        {
            return Err("production source count/system profile mismatch".into());
        }
        if let Some(key) = &i.proposer_key {
            let seal = i
                .block
                .proposer_seal
                .as_ref()
                .ok_or("full production seal absent")?;
            let signer = chain
                .get_block_signers(&i.block.hash())
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|s| s.address == i.block.header.proposer)
                .ok_or("full production retained native proposer evidence absent")?;
            if key.len() != 1952
                || seal.sig_type != SignatureType::MlDsa65
                || seal.data.len() != 3309
                || signer.public_key != *key
                || !MlDsaVerifier
                    .verify(key, i.block.hash().as_bytes(), seal)
                    .map_err(|e| e.to_string())?
            {
                return Err("full production frozen proposer key/seal evidence mismatch".into());
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (tx, sender) in i.block.transactions.iter().zip(&i.senders) {
            if tx.tx.chain_id != cfg.chain_id
                || tx.tx.tx_type > 3
                || tx.aa_bundle.is_some()
                || tx.signature.sig_type != SignatureType::MlDsa65
                || tx.signature.data.len() != 3309
                || sender.key.len() != 1952
                || !seen.insert(tx.uncached_hash())
                || tx.tx.signing_payload(SignatureType::MlDsa65.as_u8()).len()
                    > crate::blake3_hash::MAX_HASH_BYTES
                || tx
                    .pubkey_mode
                    .pubkey_bytes()
                    .is_some_and(|key| key != sender.key)
                || sender.account.validation_code_hash.is_some()
                || sender.nodes.len() > crate::account_state::MAX_ACCOUNT_PROOF_NODES
                || sender
                    .nodes
                    .iter()
                    .any(|n| n.len() > crate::shake_sponge::MAX_SHAKE_MESSAGE_BYTES)
            {
                return Err("production source sender profile/resource mismatch".into());
            }
            let mut tagged = vec![SignatureType::MlDsa65.as_u8()];
            tagged.extend_from_slice(&sender.key);
            if sender.account.pq_pubkey_hash != blake3_hash(&sender.key)
                && sender.account.pq_pubkey_hash != blake3_hash(&tagged)
            {
                return Err("production source parent key commitment mismatch".into());
            }
            let actual = MerkleTrie::verify_proof(
                Arc::new(MemoryDb::new()),
                i.parent.state_root.as_bytes(),
                keccak256(tx.from.as_bytes()).as_bytes(),
                sender.nodes.clone(),
            )
            .map_err(|e| e.to_string())?;
            let mut encoded = Vec::new();
            sender.account.encode(&mut encoded);
            if actual.as_deref() != Some(encoded.as_slice()) {
                return Err("production source native MPT/account mismatch".into());
            }
            if !MlDsaVerifier
                .verify(
                    &sender.key,
                    tx.sender_signing_hash().as_bytes(),
                    &tx.signature,
                )
                .map_err(|e| e.to_string())?
            {
                return Err("invalid raw production signature".into());
            }
        }
        Ok(())
    }
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
    pub fn block(&self) -> &Block {
        &self.input.block
    }
    pub fn chain_id(&self) -> u64 {
        self.input.config.chain_id
    }
    pub fn genesis_hash(&self) -> ShellHash {
        self.input.config.genesis_hash
    }
    /// Verify complete mathematics against captured public inputs only. Callers
    /// must independently recheck canonicality and native execution/admission.
    pub fn verify(&self, proof: &CanonicalSignatureBatchProof) -> Result<(), String> {
        if proof.version != self.input.version
            || proof.transactions.len() != self.input.senders.len()
            || proof.proposer.is_some() != self.input.proposer_key.is_some()
        {
            return Err("production proof source/count mismatch".into());
        }
        if let (Some(seal), Some(key)) = (&proof.proposer, &self.input.proposer_key) {
            let block = &self.input.block;
            if seal.version != 1 {
                return Err("unsupported production proposer proof".into());
            }
            verify_header_hash(&seal.header, &block.header, &block.hash())?;
            crate::mldsa_verification::verify_mldsa65(
                &seal.signature,
                key,
                block.hash().as_bytes(),
                &block
                    .proposer_seal
                    .as_ref()
                    .ok_or("missing source seal")?
                    .data,
            )?;
        }
        for ((tx, sender), p) in self
            .input
            .block
            .transactions
            .iter()
            .zip(&self.input.senders)
            .zip(&proof.transactions)
        {
            let account = verify_account_state(
                &p.account,
                self.input.parent.state_root.as_bytes(),
                tx.from.as_bytes(),
                Some(&sender.account),
            )?;
            let entry = SigBatchEntry::from_signed_transaction(tx);
            verify_registered_signature_entry(
                &p.signature,
                tx,
                &sender.key,
                &account,
                tx.uncached_hash().as_bytes(),
                &entry,
                &entry.to_leaf_bytes(),
            )?;
        }
        Ok(())
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
            .input
            .block
            .transactions
            .iter()
            .zip(&self.input.senders)
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
                        self.input.parent.state_root.as_bytes(),
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
            version: self.input.version,
            transactions,
            proposer: if let Some(key) = &self.input.proposer_key {
                let block = &self.input.block;
                let signature = prove_mldsa(
                    job,
                    "proposer",
                    key,
                    block.hash().as_bytes(),
                    &block
                        .proposer_seal
                        .as_ref()
                        .ok_or_else(|| "full source seal missing".to_string())?
                        .data,
                )?;
                let header = job.checkpoint(
                    "proposer-header",
                    || prove_header_hash(&block.header),
                    |p| verify_header_hash(p, &block.header, &block.hash()).map(|_| ()),
                )?;
                Some(ProposerSealProof {
                    version: 1,
                    header,
                    signature,
                })
            } else {
                None
            },
        };
        self.verify(&proof)?;
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

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use shell_core::{SignedTransaction, Transaction, TransactionReceipt};
    use shell_crypto::{MlDsaSigner, Signer};
    use shell_primitives::{Address, U256};
    use shell_storage::{OverlayStore, StorageError};
    fn fixture() -> (Arc<MemoryDb>, CanonicalProductionSource) {
        fixture_profile(false)
    }
    fn fixture_profile(full: bool) -> (Arc<MemoryDb>, CanonicalProductionSource) {
        // Storage-context fixture only; real native execution is exercised by the runtime regression.
        let db = Arc::new(MemoryDb::new());
        let chain = ChainStore::new(db.clone());
        let signer = MlDsaSigner::generate();
        let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let mut world = shell_storage::WorldState::new(db.clone());
        world
            .set_account(
                &address,
                &Account::new_user_account(blake3_hash(signer.public_key()), U256::from(1_000_000)),
            )
            .unwrap();
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
        let cfg=serde_json::from_value(serde_json::json!({"chain_id":10,"genesis_hash":genesis.hash(),"block_commitment_height":1})).unwrap();
        chain.put_pubkey(&address, signer.public_key()).unwrap();
        chain.commit_genesis_block(&genesis, &cfg).unwrap();
        let tx = Transaction {
            chain_id: 10,
            nonce: 0,
            to: Some(Address::from([17; 32])),
            value: U256::from(1),
            data: Default::default(),
            gas_limit: 21000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            tx_type: 0,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let signature = signer
            .sign(tx.signing_hash(signer.sig_type().as_u8()).as_bytes())
            .unwrap();
        let signed = SignedTransaction::new(address, tx, signature);
        let receipts = vec![TransactionReceipt {
            tx_hash: signed.uncached_hash(),
            block_number: 1,
            tx_index: 0,
            status: 1,
            gas_used: 0,
            cumulative_gas_used: 0,
            contract_address: None,
            logs_bloom: Default::default(),
            logs: vec![],
        }];
        let mut block = Block {
            header: BlockHeader {
                parent_hash: genesis.hash(),
                state_root: root,
                number: 1,
                receipts_root: shell_core::block_receipts_root(&receipts),
                ..Default::default()
            },
            transactions: vec![signed],
            system_transactions: vec![],
            proposer_seal: None,
        };
        block.header.transactions_root =
            shell_core::block_body_root(&block.transactions, &[]).unwrap();
        if full {
            block.header.proposer = address;
            block.proposer_seal = Some(signer.sign(block.hash().as_bytes()).unwrap());
        }
        let overlay = Arc::new(OverlayStore::new(db.clone()));
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
        if full {
            staged
                .put_block_signers(
                    &block.hash(),
                    &[shell_core::BlockSignerEvidence {
                        address,
                        public_key: signer.public_key().to_vec(),
                        signature: block.proposer_seal.clone().unwrap(),
                    }],
                )
                .unwrap();
        }
        overlay.commit().unwrap();
        let source =
            CanonicalProductionSource::capture(&chain, block.hash(), block.hash()).unwrap();
        if full {
            // A later authenticated vote can carry another randomized signature
            // for the same authority/key/hash without changing the captured seal.
            let vote = signer.sign(block.hash().as_bytes()).unwrap();
            assert!(MlDsaVerifier
                .verify(signer.public_key(), block.hash().as_bytes(), &vote)
                .unwrap());
            chain
                .put_block_signers(
                    &block.hash(),
                    &[shell_core::BlockSignerEvidence {
                        address,
                        public_key: signer.public_key().to_vec(),
                        signature: vote,
                    }],
                )
                .unwrap();
        }
        (db, source)
    }
    struct NoTrieReads(Arc<MemoryDb>);
    impl KvStore for NoTrieReads {
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            if k.len() == 32 {
                return Err(StorageError::State(
                    "live trie access forbidden after capture".into(),
                ));
            }
            self.0.get(k)
        }
        fn put(&self, _: &[u8], _: &[u8]) -> Result<(), StorageError> {
            Err(StorageError::State("read-only".into()))
        }
        fn delete(&self, _: &[u8]) -> Result<(), StorageError> {
            Err(StorageError::State("read-only".into()))
        }
        fn flush(&self) -> Result<(), StorageError> {
            Err(StorageError::State("read-only".into()))
        }
        fn write_batch(&self, _: shell_storage::WriteBatch) -> Result<(), StorageError> {
            Err(StorageError::State("read-only".into()))
        }
        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            if prefix.starts_with(b"BSIG") {
                return self.0.scan_prefix(prefix);
            }
            Err(StorageError::State("live scan forbidden".into()))
        }
    }
    #[test]
    fn full_seal_source_freezes_native_signer_across_registry_change_and_rejects_tampering() {
        let (db, source) = fixture_profile(true);
        assert_eq!(source.input.version, 2);
        let chain = ChainStore::new(db.clone());
        chain
            .put_pubkey(&source.block().header.proposer, &[9; 1952])
            .unwrap();
        let before = db.scan_all().unwrap();
        let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
        assert_eq!(
            CanonicalProductionSource::restore(&frozen, source.identity())
                .unwrap()
                .identity(),
            source.identity()
        );
        let mut value: serde_json::Value = serde_json::from_slice(source.identity()).unwrap();
        let old = value["proposer_key"][0].as_u64().unwrap();
        value["proposer_key"][0] = serde_json::json!(old ^ 1);
        assert!(
            CanonicalProductionSource::restore(&frozen, &serde_json::to_vec(&value).unwrap())
                .is_err()
        );
        assert_eq!(db.scan_all().unwrap(), before);
    }
    #[test]
    fn restore_uses_authenticated_snapshot_not_current_keys_or_live_trie() {
        let (db, source) = fixture();
        let chain = ChainStore::new(db.clone());
        chain
            .put_pubkey(&source.block().transactions[0].from, &[9; 1952])
            .unwrap();
        let before = db.scan_all().unwrap();
        let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
        let recovered = CanonicalProductionSource::restore(&frozen, source.identity()).unwrap();
        assert_eq!(recovered.identity(), source.identity());
        assert_eq!(recovered.block(), source.block());
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn source_tampering_and_stale_canonical_target_refuse_without_writes() {
        let (db, source) = fixture();
        let chain = ChainStore::new(db.clone());
        let original: serde_json::Value = serde_json::from_slice(source.identity()).unwrap();
        for mode in ["account", "key", "body", "parent", "version", "unknown"] {
            let mut v = original.clone();
            match mode {
                "account" => v["senders"][0]["account"]["nonce"] = serde_json::json!(1),
                "key" => {
                    let n = v["senders"][0]["key"][0].as_u64().unwrap();
                    v["senders"][0]["key"][0] = serde_json::json!(n ^ 1);
                }
                "body" => v["block"]["transactions"][0]["tx"]["nonce"] = serde_json::json!(1),
                "parent" => v["parent"]["state_root"] = serde_json::json!(ShellHash::ZERO),
                "version" => v["version"] = serde_json::json!(2),
                _ => v["untrusted_success"] = serde_json::json!(true),
            }
            let before = db.scan_all().unwrap();
            assert!(
                CanonicalProductionSource::restore(&chain, &serde_json::to_vec(&v).unwrap())
                    .is_err(),
                "{mode}"
            );
            assert_eq!(before, db.scan_all().unwrap());
        }
        chain.set_canonical(1, &ShellHash::from([8; 32])).unwrap();
        let before = db.scan_all().unwrap();
        assert!(CanonicalProductionSource::restore(&chain, source.identity()).is_err());
        assert_eq!(before, db.scan_all().unwrap());
    }
}
