//! Complete raw-source canonical sender proofs with resumable component generation.
//! The source is a retained trusted native block; consensus/execution remain native.
use crate::{
    account_state::{prove_account_state, verify_account_state},
    blake3_hash::{prove_hash, verify_hash},
    canonical_batch::{
        CanonicalSignatureBatchProof, CanonicalTransactionProof, MAX_CANONICAL_SIGNATURE_BATCH,
    },
    header_hash::{prove_header_hash, verify_header_hash},
    keccak_permutation::{
        prove_keccak_batch, verify_keccak_batch, KeccakBatchProof, MAX_KECCAK_BATCH,
    },
    mldsa_challenge::{
        prove_challenge, prove_dilithium_challenge, verify_challenge, verify_dilithium_challenge,
        ChallengeProof,
    },
    mldsa_decode::{prove_signature_decode, verify_signature_decode, SignatureDecodeProof},
    mldsa_equation::{prove_equation, verify_equation, EquationInputs, EquationProof},
    mldsa_finish::{prove_finish, verify_finish, FinishProof},
    mldsa_inverse::{prove_inverse_ntt, verify_inverse_ntt, InverseNttProof},
    mldsa_key::{prove_public_key_decode, verify_public_key_decode, PublicKeyDecodeProof},
    mldsa_matrix::{
        matrix_witness, prove_matrix_polynomial, prove_matrix_polynomial_batched,
        prove_matrix_sampler_batch, verify_matrix_polynomial, verify_matrix_sampler_batch,
        MatrixBatches, MatrixPolynomialProof, MatrixProof, MatrixSamplerBatchProof,
        MAX_MATRIX_BATCH, MAX_MATRIX_PERMUTATION_BATCHES,
    },
    mldsa_ntt::{prove_ntt, verify_ntt, NttProof, NTT_MODULUS},
    mldsa_source::TransactionSignatureProof,
    mldsa_verification::{
        verify_completion, verify_dilithium_equation_pipeline, verify_equation_pipeline,
        CompletionProof, EquationPipeline, Mldsa65VerificationProof,
    },
    production_store::{bounded_json, ProductionError, ProductionStore},
    proposer_seal::ProposerSealProof,
    registered_signature::{
        verify_registered_signature_entry, verify_unbound_signature_entry, RegisteredSignatureProof,
    },
    shake_sponge::{
        prove_shake, prove_sponge_batch, verify_shake, verify_sponge_batch, ShakeKind, ShakeProof,
        SpongeBatchProof, MAX_SPONGE_BATCH,
    },
    SigBatchEntry,
};
use alloy_rlp::Encodable;
use serde::{Deserialize, Serialize};
use shell_core::{Account, Block, BlockHeader, PQTX_ID_DOMAIN};
use shell_crypto::{DilithiumVerifier, MlDsaVerifier, SignatureType, SphincsVerifier, Verifier};
use shell_primitives::{blake3_hash, keccak256, ShellHash};
use shell_storage::{ChainConfig, ChainStore, KvStore, MemoryDb, MerkleTrie};
use std::sync::Arc;

// Support selection in the producer only; final acceptance always verifies AIRs.
fn verify_production_signature(
    key: &[u8],
    message: &[u8],
    signature: &shell_crypto::PQSignature,
) -> Result<bool, String> {
    match signature.sig_type {
        SignatureType::MlDsa65 => MlDsaVerifier
            .verify(key, message, signature)
            .map_err(|e| e.to_string()),
        SignatureType::Dilithium3 => {
            Ok(DilithiumVerifier.verify_legacy_transcript(key, message, signature))
        }
        SignatureType::SphincsSha2256f => SphincsVerifier
            .verify(key, message, signature)
            .map_err(|e| e.to_string()),
    }
}

/// Resource/framing preflight only. Complete AIR verification and native policy
/// are mandatory before any canonical proof can authorize execution.
pub fn supports_production_senders(block: &Block) -> bool {
    let slh = block
        .transactions
        .iter()
        .any(|t| t.signature.sig_type == SignatureType::SphincsSha2256f);
    if slh && (block.transactions.len() != 1 || block.proposer_seal.is_none()) {
        return false;
    }
    !block.transactions.is_empty()
        && block.transactions.len() <= MAX_CANONICAL_SIGNATURE_BATCH
        && block.transactions.iter().all(|t| {
            t.tx.tx_type <= 3
                && t.aa_bundle.is_none()
                && match t.signature.sig_type {
                    SignatureType::MlDsa65 | SignatureType::Dilithium3 => {
                        t.signature.data.len() == 3309
                    }
                    SignatureType::SphincsSha2256f => t.signature.data.len() == 49_856,
                }
        })
}
fn sender_shape(kind: SignatureType, key: usize, signature: usize) -> bool {
    match kind {
        SignatureType::MlDsa65 | SignatureType::Dilithium3 => key == 1952 && signature == 3309,
        SignatureType::SphincsSha2256f => key == 64 && signature == 49_856,
    }
}

fn matrix_part(suffix: &str) -> bool {
    let Some((kind, index)) = suffix
        .strip_prefix("matrix-")
        .and_then(|v| v.split_once('-'))
    else {
        return false;
    };
    let max = match kind {
        "sampler" | "sponge" => 4,
        "keccak" => MAX_MATRIX_PERMUTATION_BATCHES,
        _ => return false,
    };
    index
        .parse::<usize>()
        .is_ok_and(|i| i < max && i.to_string() == index)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderSource {
    key: Vec<u8>,
    account: Account,
    nodes: Vec<Vec<u8>>,
    /// Native SDK FIPS sender transcript marker in source formats three through five.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sdk_fips: Option<u8>,
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
    /// Native SDK FIPS proposer transcript marker in source formats five to seven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proposer_sdk_fips: Option<u8>,
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
            || !supports_production_senders(&block)
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
                || signed
                    .tx
                    .signing_payload(signed.signature.sig_type.as_u8())
                    .len()
                    > crate::blake3_hash::MAX_HASH_BYTES
                || !seen.insert(signed.hash())
            {
                return Err("unsupported or duplicate production sender source".into());
            }
            let registered = view
                .registered_key(&signed.from)
                .map_err(|e| e.to_string())?;
            let key = registered
                .as_deref()
                .or_else(|| signed.pubkey_mode.pubkey_bytes())
                .ok_or("production requires an Embedded first-use key or parent registration")?
                .to_vec();
            let account = view
                .world_state()
                .map_err(|e| e.to_string())?
                .get_account(&signed.from)
                .map_err(|e| e.to_string())?
                .ok_or("production requires a parent account")?;
            let mut tagged = vec![signed.signature.sig_type.as_u8()];
            tagged.extend_from_slice(&key);
            if !sender_shape(
                signed.signature.sig_type,
                key.len(),
                signed.signature.data.len(),
            ) || signed.pubkey_mode.pubkey_bytes().is_some_and(|p| p != key)
                || account.validation_code_hash.is_some()
            {
                return Err("production parent key/default account binding mismatch".into());
            }
            if account.pq_pubkey_hash == ShellHash::ZERO {
                if shell_primitives::Address::from_public_key(
                    &key,
                    signed.signature.sig_type.as_u8(),
                ) != signed.from
                {
                    return Err("production unbound sender address mismatch".into());
                }
            } else if registered.is_none()
                || (account.pq_pubkey_hash != blake3_hash(&key)
                    && account.pq_pubkey_hash != blake3_hash(&tagged))
            {
                return Err("production bound account requires its parent-registered key".into());
            }
            // Select once from actual signature bytes; final acceptance still verifies full AIR.
            let raw_or_primary = verify_production_signature(
                &key,
                signed.sender_signing_hash().as_bytes(),
                &signed.signature,
            )?;
            let sdk_fips = if !raw_or_primary
                && signed.signature.sig_type == SignatureType::Dilithium3
                && DilithiumVerifier.verify_sdk_transcript(
                    &key,
                    signed.sender_signing_hash().as_bytes(),
                    &signed.signature,
                ) {
                Some(1)
            } else {
                None
            };
            if !raw_or_primary && sdk_fips.is_none() {
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
                sdk_fips,
            });
        }
        let mut proposer_sdk_fips = None;
        let proposer_key = match block.proposer_seal.as_ref() {
            Some(seal) if seal.sig_type == SignatureType::MlDsa65 => Some(
                view.registered_key(&block.header.proposer)
                    .map_err(|e| e.to_string())?
                    .ok_or("full production requires a parent-registered proposer key")?,
            ),
            Some(seal) if seal.sig_type == SignatureType::Dilithium3 => view
                .registered_key(&block.header.proposer)
                .map_err(|e| e.to_string())?
                .and_then(|key| {
                    if DilithiumVerifier.verify_legacy_transcript(
                        &key,
                        block.hash().as_bytes(),
                        seal,
                    ) {
                        Some(key)
                    } else if DilithiumVerifier.verify_sdk_transcript(
                        &key,
                        block.hash().as_bytes(),
                        seal,
                    ) {
                        proposer_sdk_fips = Some(1);
                        Some(key)
                    } else {
                        None
                    }
                }),
            Some(seal)
                if seal.sig_type == SignatureType::SphincsSha2256f
                    && block.transactions.len() == 1
                    && block.transactions[0].signature.sig_type == SignatureType::MlDsa65 =>
            {
                Some(
                    view.registered_key(&block.header.proposer)
                        .map_err(|e| e.to_string())?
                        .ok_or("SLH proposer parent key absent")?,
                )
            }
            _ => None,
        };
        let input = CapturedInputs {
            version: if proposer_key.is_some()
                && block
                    .proposer_seal
                    .as_ref()
                    .is_some_and(|seal| seal.sig_type == SignatureType::SphincsSha2256f)
            {
                if senders[0].account.pq_pubkey_hash == ShellHash::ZERO {
                    9
                } else {
                    8
                }
            } else if block
                .transactions
                .iter()
                .any(|tx| tx.signature.sig_type == SignatureType::SphincsSha2256f)
            {
                if proposer_key.is_none() {
                    return Err("canonical SLH requires a supported registered proposer".into());
                }
                if senders
                    .iter()
                    .any(|s| s.account.pq_pubkey_hash == ShellHash::ZERO)
                {
                    7
                } else {
                    6
                }
            } else if proposer_sdk_fips.is_some() {
                5
            } else if senders
                .iter()
                .any(|s| s.sdk_fips.is_some() && s.account.pq_pubkey_hash == ShellHash::ZERO)
            {
                4
            } else if senders.iter().any(|s| s.sdk_fips.is_some()) {
                3
            } else if proposer_key.is_some() {
                2
            } else {
                1
            },
            tip,
            config: view.config().clone(),
            parent: view.parent().clone(),
            block,
            senders,
            proposer_key,
            proposer_sdk_fips,
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
        let has_sdk = i.senders.iter().any(|s| s.sdk_fips.is_some());
        let has_unbound_sdk = i
            .senders
            .iter()
            .any(|s| s.sdk_fips.is_some() && s.account.pq_pubkey_hash == ShellHash::ZERO);
        let has_sdk_proposer = i.proposer_sdk_fips.is_some();
        let has_slh = i
            .block
            .transactions
            .iter()
            .any(|t| t.signature.sig_type == SignatureType::SphincsSha2256f);
        let profile_valid = (!has_slh || matches!(i.version, 6 | 7))
            && match i.version {
                1 => i.proposer_key.is_none() && !has_sdk && !has_sdk_proposer,
                2 => i.proposer_key.is_some() && !has_sdk && !has_sdk_proposer,
                3 => has_sdk && !has_unbound_sdk && !has_sdk_proposer,
                4 => has_unbound_sdk && !has_sdk_proposer,
                5 => i.proposer_sdk_fips == Some(1) && i.proposer_key.is_some(),
                6 => {
                    has_slh
                        && matches!(i.proposer_sdk_fips, None | Some(1))
                        && i.block.transactions.len() == 1
                        && i.proposer_key.is_some()
                        && !has_sdk
                        && i.senders
                            .iter()
                            .all(|s| s.account.pq_pubkey_hash != ShellHash::ZERO)
                }
                7 => {
                    has_slh
                        && matches!(i.proposer_sdk_fips, None | Some(1))
                        && i.block.transactions.len() == 1
                        && i.proposer_key.is_some()
                        && !has_sdk
                        && i.senders
                            .iter()
                            .all(|s| s.account.pq_pubkey_hash == ShellHash::ZERO)
                }
                8 | 9 => {
                    i.proposer_key.is_some()
                        && i.proposer_sdk_fips.is_none()
                        && i.block
                            .proposer_seal
                            .as_ref()
                            .is_some_and(|seal| seal.sig_type == SignatureType::SphincsSha2256f)
                        && i.block.transactions.len() == 1
                        && i.block.transactions[0].signature.sig_type == SignatureType::MlDsa65
                        && !has_sdk
                        && i.senders.iter().all(|sender| {
                            (sender.account.pq_pubkey_hash == ShellHash::ZERO) == (i.version == 9)
                        })
                }
                _ => false,
            };
        if !profile_valid
            || cfg.chain_id != i.config.chain_id
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
            let signature_valid = if i.proposer_sdk_fips == Some(1) {
                !DilithiumVerifier.verify_legacy_transcript(key, i.block.hash().as_bytes(), seal)
                    && DilithiumVerifier.verify_sdk_transcript(key, i.block.hash().as_bytes(), seal)
            } else {
                verify_production_signature(key, i.block.hash().as_bytes(), seal)?
            };
            let shape = if matches!(i.version, 8 | 9) {
                key.len() == 64
                    && seal.sig_type == SignatureType::SphincsSha2256f
                    && seal.data.len() == 49856
            } else {
                key.len() == 1952
                    && matches!(
                        seal.sig_type,
                        SignatureType::MlDsa65 | SignatureType::Dilithium3
                    )
                    && seal.data.len() == 3309
            };
            if !shape || signer.public_key != *key || !signature_valid {
                return Err("full production frozen proposer key/seal evidence mismatch".into());
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (tx, sender) in i.block.transactions.iter().zip(&i.senders) {
            if tx.tx.chain_id != cfg.chain_id
                || tx.tx.tx_type > 3
                || tx.aa_bundle.is_some()
                || !sender_shape(
                    tx.signature.sig_type,
                    sender.key.len(),
                    tx.signature.data.len(),
                )
                || !seen.insert(tx.uncached_hash())
                || tx.tx.signing_payload(tx.signature.sig_type.as_u8()).len()
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
            let mut tagged = vec![tx.signature.sig_type.as_u8()];
            tagged.extend_from_slice(&sender.key);
            if sender.sdk_fips.is_some()
                && (sender.sdk_fips != Some(1)
                    || tx.signature.sig_type != SignatureType::Dilithium3
                    || DilithiumVerifier.verify_legacy_transcript(
                        &sender.key,
                        tx.sender_signing_hash().as_bytes(),
                        &tx.signature,
                    ))
            {
                return Err("production SDK source profile mismatch".into());
            }
            let binding_matches = if sender.account.pq_pubkey_hash == ShellHash::ZERO {
                shell_primitives::Address::from_public_key(
                    &sender.key,
                    tx.signature.sig_type.as_u8(),
                ) == tx.from
            } else {
                sender.account.pq_pubkey_hash == blake3_hash(&sender.key)
                    || sender.account.pq_pubkey_hash == blake3_hash(&tagged)
            };
            if !binding_matches {
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
            let signature_valid = if sender.sdk_fips == Some(1) {
                DilithiumVerifier.verify_sdk_transcript(
                    &sender.key,
                    tx.sender_signing_hash().as_bytes(),
                    &tx.signature,
                )
            } else {
                verify_production_signature(
                    &sender.key,
                    tx.sender_signing_hash().as_bytes(),
                    &tx.signature,
                )?
            };
            if !signature_valid {
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
    /// Explicit large bound or funded-unbound source; requires compact checkpoints.
    pub fn has_slh_senders(&self) -> bool {
        matches!(self.input.version, 6 | 7)
    }
    /// Full raw-header SLH proposer with one bound or explicit first-use primary sender.
    pub fn has_slh_proposer(&self) -> bool {
        matches!(self.input.version, 8 | 9)
    }
    /// Shared bounded witness encoding for either supported large signature role.
    pub fn needs_slh_encoding(&self) -> bool {
        self.has_slh_senders() || self.has_slh_proposer()
    }
    /// Unbound address certificates need compact checkpoints even in small batches.
    pub fn has_unbound_senders(&self) -> bool {
        self.input
            .senders
            .iter()
            .any(|sender| sender.account.pq_pubkey_hash == ShellHash::ZERO)
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
        if proof.version
            != (if self.has_slh_proposer() {
                if self.has_unbound_senders() {
                    5
                } else {
                    4
                }
            } else if self.has_slh_senders() {
                3
            } else if self.input.proposer_key.is_some() {
                2
            } else {
                1
            })
            || (if self.has_slh_senders() {
                proof.slh_transactions.as_ref().map_or(0, Vec::len)
            } else {
                proof.transactions.len()
            }) != self.input.senders.len()
            || (self.has_slh_senders() && !proof.transactions.is_empty())
            || (!self.has_slh_senders() && proof.slh_transactions.is_some())
            || (proof.proposer.is_some() || proof.slh_proposer.is_some())
                != self.input.proposer_key.is_some()
            || proof.slh_proposer.is_some() != self.has_slh_proposer()
            || (self.has_slh_proposer() && proof.proposer.is_some())
        {
            return Err("production proof source/count mismatch".into());
        }
        if let Some(seal) = &proof.slh_proposer {
            let block = &self.input.block;
            crate::slh_proposer::verify_graph(
                seal,
                self.input
                    .proposer_key
                    .as_ref()
                    .ok_or_else(|| "SLH proposer key absent".to_string())?,
                &block.header,
                &block.hash(),
                block
                    .proposer_seal
                    .as_ref()
                    .ok_or("SLH source seal absent")?,
            )?;
        }
        if let (Some(seal), Some(key)) = (&proof.proposer, &self.input.proposer_key) {
            let block = &self.input.block;
            let native_seal = block.proposer_seal.as_ref().ok_or("missing source seal")?;
            let expected_version = if self.input.proposer_sdk_fips == Some(1) {
                3
            } else if native_seal.sig_type == SignatureType::Dilithium3 {
                2
            } else {
                1
            };
            if seal.version != expected_version
                || !matches!(
                    (seal.version, native_seal.sig_type),
                    (1, SignatureType::MlDsa65) | (2 | 3, SignatureType::Dilithium3)
                )
            {
                return Err("unsupported production proposer proof".into());
            }
            verify_header_hash(&seal.header, &block.header, &block.hash())?;
            let verify = if seal.version == 2 {
                crate::mldsa_verification::verify_dilithium3
            } else {
                crate::mldsa_verification::verify_mldsa65
            };
            verify(
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
        if self.has_slh_senders() {
            crate::canonical_slh::verify_at_source(
                &proof.slh_transactions.as_ref().ok_or("SLH proof absent")?[0],
                &self.input.parent,
                &self.input.block.header,
                &self.input.block.transactions[0],
                0,
                &self.input.senders[0].key,
                &self.input.senders[0].account,
            )?;
            return Ok(());
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
            if sender.account.pq_pubkey_hash == ShellHash::ZERO {
                verify_unbound_signature_entry(
                    &p.signature,
                    tx,
                    &sender.key,
                    &account,
                    tx.uncached_hash().as_bytes(),
                    &entry,
                    &entry.to_leaf_bytes(),
                )?;
            } else {
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
        }
        Ok(())
    }

    /// Locate only an equal mathematical input, never an authorization token.
    /// Earlier positions in this source may supply key or identical account witnesses.
    pub fn reusable_component_from(&self, donor: &Self, name: &str) -> Option<String> {
        if self.chain_id() != donor.chain_id() || self.genesis_hash() != donor.genesis_hash() {
            return None;
        }
        let (position, key, suffix, sender) = if let Some(suffix) = name.strip_prefix("proposer-") {
            (
                self.input.senders.len(),
                self.input.proposer_key.as_ref()?,
                suffix,
                None,
            )
        } else {
            let (index, suffix) = name.strip_prefix("sender-")?.split_once('-')?;
            let index = index.parse::<usize>().ok()?;
            (
                index,
                &self.input.senders.get(index)?.key,
                suffix,
                Some(index),
            )
        };
        let stable = matches!(suffix, "key" | "tr")
            || matrix_part(suffix)
            || suffix
                .strip_prefix("t1-")
                .is_some_and(|row| row.parse::<usize>().is_ok_and(|r| r < 6))
            || suffix
                .strip_prefix("matrix-")
                .and_then(|v| v.split_once('-'))
                .is_some_and(|(r, c)| {
                    r.parse::<usize>().is_ok_and(|r| r < 6)
                        && c.parse::<usize>().is_ok_and(|c| c < 5)
                });
        if !stable && !matches!(suffix, "key-hash" | "tagged-key" | "account") {
            return None;
        }
        for old_position in 0..=donor.input.senders.len() {
            if self.block().hash() == donor.block().hash() && old_position >= position {
                continue;
            }
            let (old_key, old_sender, prefix) = if old_position < donor.input.senders.len() {
                (
                    &donor.input.senders[old_position].key,
                    Some(old_position),
                    format!("sender-{old_position}"),
                )
            } else {
                let Some(key) = donor.input.proposer_key.as_ref() else {
                    continue;
                };
                (key, None, "proposer".to_string())
            };
            if key != old_key {
                continue;
            }
            if !stable {
                let (Some(index), Some(old_index)) = (sender, old_sender) else {
                    continue;
                };
                let current = &self.input.senders[index];
                let old = &donor.input.senders[old_index];
                if suffix == "tagged-key"
                    && (self.input.block.transactions[index].signature.sig_type
                        != donor.input.block.transactions[old_index].signature.sig_type
                        || (current.account.pq_pubkey_hash != ShellHash::ZERO
                            && current.account.pq_pubkey_hash == blake3_hash(key))
                        || (old.account.pq_pubkey_hash != ShellHash::ZERO
                            && old.account.pq_pubkey_hash == blake3_hash(old_key)))
                {
                    continue;
                }
                if suffix == "account"
                    && (self.input.parent.state_root != donor.input.parent.state_root
                        || self.input.block.transactions[index].from
                            != donor.input.block.transactions[old_index].from
                        || current.account != old.account
                        || current.nodes != old.nodes)
                {
                    continue;
                }
            }
            return Some(format!("{prefix}-{suffix}"));
        }
        None
    }
    pub fn can_reuse_component_from(&self, donor: &Self, name: &str) -> bool {
        self.reusable_component_from(donor, name).is_some()
    }
    fn local_reuse_components(&self) -> std::collections::BTreeMap<String, String> {
        let mut map = std::collections::BTreeMap::new();
        for position in 0..=self.input.senders.len() {
            if position == self.input.senders.len() && self.input.proposer_key.is_none() {
                continue;
            }
            let prefix = if position < self.input.senders.len() {
                format!("sender-{position}")
            } else {
                "proposer".into()
            };
            let mut suffixes = vec!["key".to_string(), "tr".to_string()];
            for row in 0..6 {
                suffixes.push(format!("t1-{row}"));
                for col in 0..5 {
                    suffixes.push(format!("matrix-{row}-{col}"));
                }
            }
            if position < self.input.senders.len() {
                suffixes.extend(["key-hash".into(), "tagged-key".into(), "account".into()]);
            }
            for kind in ["sampler", "sponge", "keccak"] {
                let max = if kind == "keccak" {
                    MAX_MATRIX_PERMUTATION_BATCHES
                } else {
                    4
                };
                for i in 0..max {
                    suffixes.push(format!("matrix-{kind}-{i}"));
                }
            }
            for suffix in suffixes {
                let name = format!("{prefix}-{suffix}");
                if let Some(donor) = self.reusable_component_from(self, &name) {
                    map.insert(name, donor);
                }
            }
        }
        map
    }

    /// All new and reused components are cryptographically checked. Pauses publish
    /// only durable components, never an incomplete final proof or verified token.
    pub fn produce<J: KvStore>(
        &self,
        job: &mut ProductionStore<'_, J>,
    ) -> Result<CanonicalSignatureBatchProof, ProductionError> {
        if self.needs_slh_encoding() != job.slh_encoding() {
            return Err(
                "production source requires its explicit checkpoint encoding"
                    .to_string()
                    .into(),
            );
        }
        if !job.matches_source(&self.identity) {
            return Err("production job belongs to another canonical source"
                .to_string()
                .into());
        }
        job.set_local_reuse(self.local_reuse_components());
        let mut transactions = Vec::new();
        let mut slh_transactions = None;
        if self.has_slh_senders() {
            let sender = &self.input.senders[0];
            slh_transactions = Some(vec![crate::canonical_slh_producer::produce(
                job,
                &self.input.parent,
                &self.input.block,
                &sender.key,
                &sender.account,
                &sender.nodes,
            )?]);
        }
        for (i, (signed, source)) in self
            .input
            .block
            .transactions
            .iter()
            .zip(&self.input.senders)
            .enumerate()
        {
            if self.has_slh_senders() {
                break;
            }
            let prefix = format!("sender-{i}");
            let signature = prove_signature(
                job,
                &prefix,
                &source.key,
                signed.sender_signing_hash().as_bytes(),
                &signed.signature.data,
                signed.signature.sig_type == SignatureType::Dilithium3 && source.sdk_fips.is_none(),
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
            let signing_payload = signed.tx.signing_payload(signed.signature.sig_type.as_u8());
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
            let tagged_key = if source.account.pq_pubkey_hash != ShellHash::ZERO
                && source.account.pq_pubkey_hash.as_bytes() == &public_key_hash.output
            {
                None
            } else {
                let mut bytes = vec![signed.signature.sig_type.as_u8()];
                bytes.extend_from_slice(&source.key);
                Some(hash(job, &format!("{prefix}-tagged-key"), &bytes)?)
            };
            transactions.push(CanonicalTransactionProof {
                account,
                signature: RegisteredSignatureProof {
                    version: if source.sdk_fips == Some(1) {
                        if source.account.pq_pubkey_hash == ShellHash::ZERO {
                            6
                        } else {
                            5
                        }
                    } else if source.account.pq_pubkey_hash == ShellHash::ZERO {
                        if signed.signature.sig_type == SignatureType::Dilithium3 {
                            4
                        } else {
                            2
                        }
                    } else if signed.signature.sig_type == SignatureType::Dilithium3 {
                        3
                    } else {
                        1
                    },
                    transaction: TransactionSignatureProof {
                        version: if source.sdk_fips == Some(1) {
                            3
                        } else if signed.signature.sig_type == SignatureType::Dilithium3 {
                            2
                        } else {
                            1
                        },
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
            slh_proposer: if self.has_slh_proposer() {
                Some(crate::slh_proposer::produce(
                    job,
                    &self.input.block.header,
                    self.input
                        .proposer_key
                        .as_ref()
                        .ok_or_else(|| "SLH proposer key absent".to_string())?,
                    self.input
                        .block
                        .proposer_seal
                        .as_ref()
                        .ok_or_else(|| "SLH proposer seal absent".to_string())?,
                )?)
            } else {
                None
            },
            slh_transactions,
            version: if self.has_slh_proposer() {
                if self.has_unbound_senders() {
                    5
                } else {
                    4
                }
            } else if self.has_slh_senders() {
                3
            } else if self.input.proposer_key.is_some() {
                2
            } else {
                1
            },
            transactions,
            proposer: if self.has_slh_proposer() {
                None
            } else if let Some(key) = &self.input.proposer_key {
                let block = &self.input.block;
                let signature = prove_signature(
                    job,
                    "proposer",
                    key,
                    block.hash().as_bytes(),
                    &block
                        .proposer_seal
                        .as_ref()
                        .ok_or_else(|| "full source seal missing".to_string())?
                        .data,
                    block
                        .proposer_seal
                        .as_ref()
                        .is_some_and(|seal| seal.sig_type == SignatureType::Dilithium3)
                        && self.input.proposer_sdk_fips.is_none(),
                )?;
                let header = job.checkpoint(
                    "proposer-header",
                    || prove_header_hash(&block.header),
                    |p| verify_header_hash(p, &block.header, &block.hash()).map(|_| ()),
                )?;
                Some(ProposerSealProof {
                    version: if self.input.proposer_sdk_fips == Some(1) {
                        3
                    } else if block
                        .proposer_seal
                        .as_ref()
                        .is_some_and(|seal| seal.sig_type == SignatureType::Dilithium3)
                    {
                        2
                    } else {
                        1
                    },
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
fn produce_matrix<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    prefix: &str,
    rho: &[u8],
) -> Result<MatrixProof, ProductionError> {
    if !job.shared_matrix_encoding() {
        let mut polynomials = Vec::new();
        let aggregate = job.compact_encoding();
        for row in 0..6 {
            for col in 0..5 {
                let p: MatrixPolynomialProof = job.checkpoint(
                    &format!("{prefix}-matrix-{row}-{col}"),
                    || {
                        if aggregate {
                            prove_matrix_polynomial_batched(rho, row, col)
                        } else {
                            prove_matrix_polynomial(rho, row, col)
                        }
                    },
                    |p| verify_matrix_polynomial(p, rho, row, col, &p.coefficients),
                )?;
                polynomials.push(p);
            }
        }
        return Ok(MatrixProof {
            version: 1,
            rho: rho.to_vec(),
            polynomials,
            batches: None,
        });
    }
    let mut matrix = matrix_witness(rho)?;
    let mut batches = MatrixBatches {
        samplers: Vec::new(),
        sponges: Vec::new(),
        permutations: Vec::new(),
    };
    for (i, group) in matrix.polynomials.chunks(MAX_MATRIX_BATCH).enumerate() {
        let proof: MatrixSamplerBatchProof = job.checkpoint(
            &format!("{prefix}-matrix-sampler-{i}"),
            || prove_matrix_sampler_batch(group),
            |p| verify_matrix_sampler_batch(p, group),
        )?;
        batches.samplers.push(proof);
    }
    let streams: Vec<_> = matrix.polynomials.iter().map(|p| p.xof.clone()).collect();
    for (i, group) in streams.chunks(MAX_SPONGE_BATCH).enumerate() {
        let proof: SpongeBatchProof = job.checkpoint(
            &format!("{prefix}-matrix-sponge-{i}"),
            || prove_sponge_batch(group),
            |p| verify_sponge_batch(p, group),
        )?;
        batches.sponges.push(proof);
    }
    let permutations: Vec<_> = streams
        .iter()
        .flat_map(|p| p.permutations.iter().cloned())
        .collect();
    for (i, group) in permutations.chunks(MAX_KECCAK_BATCH).enumerate() {
        let proof: KeccakBatchProof = job.checkpoint(
            &format!("{prefix}-matrix-keccak-{i}"),
            || prove_keccak_batch(group),
            |p| verify_keccak_batch(p, group),
        )?;
        batches.permutations.push(proof);
    }
    matrix.batches = Some(batches);
    Ok(matrix)
}

fn prove_signature<S: KvStore>(
    job: &mut ProductionStore<'_, S>,
    prefix: &str,
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
    legacy_transcript: bool,
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
    let matrix = produce_matrix(job, prefix, &key.decoded.rho)?;
    let (seed, prove, verify) = if legacy_transcript {
        (
            &signature.decoded.challenge[..32],
            prove_dilithium_challenge as fn(&[u8]) -> Result<ChallengeProof, String>,
            verify_dilithium_challenge as fn(&ChallengeProof, &[u8], &[i8]) -> Result<(), String>,
        )
    } else {
        (
            signature.decoded.challenge.as_slice(),
            prove_challenge as fn(&[u8]) -> Result<ChallengeProof, String>,
            verify_challenge as fn(&ChallengeProof, &[u8], &[i8]) -> Result<(), String>,
        )
    };
    let challenge: ChallengeProof = job.checkpoint(
        &format!("{prefix}-challenge"),
        || prove(seed),
        |p| verify(p, seed, p.challenge().ok_or("missing challenge endpoint")?),
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
        matrix_ntt: matrix
            .polynomials
            .iter()
            .map(|p| p.coefficients.clone())
            .collect(),
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
        matrix,
        challenge,
        z_ntt,
        t1_ntt,
        c_ntt,
        equation,
        inverse,
    };
    let token = if legacy_transcript {
        verify_dilithium_equation_pipeline(&equation, pk, sig)?
    } else {
        verify_equation_pipeline(&equation, pk, sig)?
    };
    let finish: FinishProof = job.checkpoint(
        &format!("{prefix}-finish"),
        || prove_finish(token.finish_inputs()),
        |p| verify_finish(p, token.finish_inputs(), &p.w1, &p.encoded),
    )?;
    let tr = shake(job, &format!("{prefix}-tr"), pk, 64)?;
    let mut mu_input = tr.output.clone();
    if !legacy_transcript {
        mu_input.extend_from_slice(&[0, 0]);
    }
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
        version: if legacy_transcript { 2 } else { 1 },
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
    use shell_crypto::{MlDsaSigner, PQSignature, Signer};
    use shell_primitives::{Address, U256};
    use shell_storage::{OverlayStore, StorageError};
    fn fixture() -> (Arc<MemoryDb>, CanonicalProductionSource) {
        fixture_profile(false)
    }
    #[test]
    fn donor_selection_only_shares_equal_public_key_inputs() {
        let (_, mut donor) = fixture_profile(true);
        // Input-selection fixture only; actual signed successor execution is in the runtime.
        let mut next = CanonicalProductionSource {
            input: serde_json::from_slice(donor.identity()).unwrap(),
            identity: vec![],
        };
        next.input.block.header.number += 1;
        next.input.block.transactions[0].tx.nonce += 1;
        for prefix in ["sender-0", "proposer"] {
            for suffix in [
                "key",
                "matrix-0-0",
                "matrix-5-4",
                "t1-0",
                "t1-5",
                "tr",
                "matrix-sampler-0",
                "matrix-sampler-3",
                "matrix-sponge-3",
                "matrix-keccak-93",
            ] {
                assert!(next.can_reuse_component_from(&donor, &format!("{prefix}-{suffix}")));
            }
            for suffix in [
                "signature",
                "challenge",
                "equation",
                "z-0",
                "c-ntt",
                "inverse-0",
                "finish",
                "mu",
                "commitment",
                "signing-hash",
                "id",
                "leaf",
                "header",
                "matrix-6-0",
                "matrix-0-5",
                "matrix-sampler-4",
                "matrix-sponge-4",
                "matrix-keccak-94",
                "matrix-keccak-01",
                "t1-6",
            ] {
                assert!(
                    !next.can_reuse_component_from(&donor, &format!("{prefix}-{suffix}")),
                    "{suffix}"
                );
            }
        }
        assert!(next.can_reuse_component_from(&donor, "sender-0-key-hash"));
        assert!(!next.can_reuse_component_from(&donor, "sender-0-tagged-key"));
        assert!(!next.can_reuse_component_from(&donor, "proposer-key-hash"));
        assert!(next.can_reuse_component_from(&donor, "sender-0-account"));
        assert!(!next.can_reuse_component_from(&donor, "proposer-account"));
        let account: SenderSource =
            serde_json::from_value(serde_json::to_value(&next.input.senders[0]).unwrap()).unwrap();
        next.input.senders.push(account);
        next.input
            .block
            .transactions
            .push(next.input.block.transactions[0].clone());
        assert_eq!(
            next.reusable_component_from(&next, "sender-1-key"),
            Some("sender-0-key".into())
        );
        assert_eq!(
            next.reusable_component_from(&next, "sender-1-account"),
            Some("sender-0-account".into())
        );
        let root = next.input.parent.state_root;
        next.input.parent.state_root = ShellHash::ZERO;
        assert!(!next.can_reuse_component_from(&donor, "sender-0-account"));
        next.input.parent.state_root = root;
        let mut bytes = vec![SignatureType::MlDsa65.as_u8()];
        bytes.extend_from_slice(&donor.input.senders[0].key);
        donor.input.senders[0].account.pq_pubkey_hash = blake3_hash(&bytes);
        next.input.senders[0].account.pq_pubkey_hash = blake3_hash(&bytes);
        assert!(next.can_reuse_component_from(&donor, "sender-0-tagged-key"));
        next.input.block.transactions[0].signature.sig_type = SignatureType::Dilithium3;
        assert!(!next.can_reuse_component_from(&donor, "sender-0-tagged-key"));
        assert!(next.can_reuse_component_from(&donor, "sender-0-key-hash"));
        next.input.block.transactions[0].signature.sig_type = SignatureType::MlDsa65;
        next.input.senders[0].key[0] ^= 1;
        next.input.proposer_key.as_mut().unwrap()[0] ^= 1;
        assert!(!next.can_reuse_component_from(&donor, "sender-0-key"));
        assert!(!next.can_reuse_component_from(&donor, "proposer-matrix-0-0"));
    }
    #[test]
    fn raw_and_sdk_proposers_freeze_distinct_sources_missing_key_stays_sender_only() {
        use shell_crypto::{DilithiumSigner, MultiVerifier};
        for case in ["raw", "sdk", "missing-key"] {
            // Storage source-selection fixture; the public runtime executes Native blocks.
            let (db, original) = fixture();
            let proposer: Box<dyn Signer> = if case == "sdk" {
                Box::new(MlDsaSigner::generate())
            } else {
                Box::new(DilithiumSigner::generate())
            };
            let chain = ChainStore::new(db.clone());
            let mut block = original.block().clone();
            block.header.proposer =
                Address::from_public_key(proposer.public_key(), SignatureType::Dilithium3.as_u8());
            let mut seal = proposer.sign(block.hash().as_bytes()).unwrap();
            seal.sig_type = SignatureType::Dilithium3;
            assert!(MultiVerifier
                .verify(proposer.public_key(), block.hash().as_bytes(), &seal)
                .unwrap());
            block.proposer_seal = Some(seal.clone());
            if case != "missing-key" {
                chain
                    .put_pubkey(&block.header.proposer, proposer.public_key())
                    .unwrap();
            }
            let receipts = chain
                .get_receipts(&original.block().hash())
                .unwrap()
                .unwrap();
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
            staged
                .put_block_signers(
                    &block.hash(),
                    &[shell_core::BlockSignerEvidence {
                        address: block.header.proposer,
                        public_key: proposer.public_key().to_vec(),
                        signature: seal,
                    }],
                )
                .unwrap();
            overlay.commit().unwrap();
            let before = db.scan_all().unwrap();
            let captured =
                CanonicalProductionSource::capture(&chain, block.hash(), block.hash()).unwrap();
            assert_eq!(
                captured.input.version,
                if case == "raw" {
                    2
                } else if case == "sdk" {
                    5
                } else {
                    1
                }
            );
            assert_eq!(captured.input.proposer_key.is_some(), case != "missing-key");
            assert_eq!(
                captured.input.proposer_sdk_fips,
                if case == "sdk" { Some(1) } else { None }
            );
            if case == "sdk" {
                let mut old: CapturedInputs = serde_json::from_slice(captured.identity()).unwrap();
                old.version = 1;
                old.proposer_key = None;
                old.proposer_sdk_fips = None;
                let bytes =
                    bounded_json(&serde_json::to_value(old).unwrap(), 4 * 1024 * 1024).unwrap();
                let restored = CanonicalProductionSource::restore(&chain, &bytes).unwrap();
                assert_eq!(restored.identity(), bytes);
                assert!(restored.input.proposer_key.is_none());
                for mode in [
                    "old-version",
                    "missing-marker",
                    "unknown-marker",
                    "wrong-tag",
                    "foreign-key",
                ] {
                    let mut bad: CapturedInputs =
                        serde_json::from_slice(captured.identity()).unwrap();
                    match mode {
                        "old-version" => bad.version = 2,
                        "missing-marker" => bad.proposer_sdk_fips = None,
                        "unknown-marker" => bad.proposer_sdk_fips = Some(2),
                        "wrong-tag" => {
                            bad.block.proposer_seal.as_mut().unwrap().sig_type =
                                SignatureType::MlDsa65
                        }
                        "foreign-key" => bad.proposer_key.as_mut().unwrap()[0] ^= 1,
                        _ => unreachable!(),
                    }
                    assert!(
                        CanonicalProductionSource::restore(
                            &chain,
                            &serde_json::to_vec(&bad).unwrap()
                        )
                        .is_err(),
                        "{mode}"
                    );
                }
            }
            CanonicalProductionSource::restore(&chain, captured.identity()).unwrap();
            assert_eq!(db.scan_all().unwrap(), before);
        }
    }
    #[test]
    fn sdk_proposer_marker_cannot_relabel_primary_or_raw_seal() {
        let (db, source) = fixture_profile(true);
        let chain = ChainStore::new(db.clone());
        let before = db.scan_all().unwrap();
        let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
        input.version = 5;
        input.proposer_sdk_fips = Some(1);
        assert!(
            CanonicalProductionSource::restore(&chain, &serde_json::to_vec(&input).unwrap())
                .is_err()
        );
        assert_eq!(before, db.scan_all().unwrap());
    }
    fn fixture_profile(full: bool) -> (Arc<MemoryDb>, CanonicalProductionSource) {
        fixture_binding(full, false)
    }
    fn fixture_binding(full: bool, unbound: bool) -> (Arc<MemoryDb>, CanonicalProductionSource) {
        fixture_algorithm(full, unbound, false)
    }
    fn fixture_algorithm(
        full: bool,
        unbound: bool,
        legacy: bool,
    ) -> (Arc<MemoryDb>, CanonicalProductionSource) {
        fixture_transcript(full, unbound, legacy, false)
    }
    // Test-only FIPS signer with the existing Native SDK algorithm tag. Actual
    // published SDK signing and RPC execution have a separate runtime entry.
    struct SdkTaggedSigner(MlDsaSigner);
    impl Signer for SdkTaggedSigner {
        fn sign(&self, message: &[u8]) -> Result<PQSignature, shell_crypto::CryptoError> {
            Ok(PQSignature::new(
                SignatureType::Dilithium3,
                self.0.sign(message)?.data,
            ))
        }
        fn public_key(&self) -> &[u8] {
            self.0.public_key()
        }
        fn sig_type(&self) -> SignatureType {
            SignatureType::Dilithium3
        }
    }
    fn fixture_transcript(
        full: bool,
        unbound: bool,
        legacy: bool,
        sdk: bool,
    ) -> (Arc<MemoryDb>, CanonicalProductionSource) {
        fixture_transcript_slh(full, unbound, legacy, sdk, false)
    }
    fn fixture_transcript_slh(
        full: bool,
        unbound: bool,
        legacy: bool,
        sdk: bool,
        slh: bool,
    ) -> (Arc<MemoryDb>, CanonicalProductionSource) {
        fixture_transcript_roles(full, unbound, legacy, sdk, slh, false)
    }
    fn fixture_transcript_roles(
        full: bool,
        unbound: bool,
        legacy: bool,
        sdk: bool,
        slh: bool,
        slh_proposer: bool,
    ) -> (Arc<MemoryDb>, CanonicalProductionSource) {
        // Storage-context fixture only; real native execution is exercised by the runtime regression.
        let db = Arc::new(MemoryDb::new());
        let chain = ChainStore::new(db.clone());
        let signer: Box<dyn Signer> = if slh {
            Box::new(shell_crypto::SphincsSigner::generate())
        } else if sdk {
            Box::new(SdkTaggedSigner(MlDsaSigner::generate()))
        } else if legacy {
            Box::new(shell_crypto::DilithiumSigner::generate())
        } else {
            Box::new(MlDsaSigner::generate())
        };
        let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let independent: Option<Box<dyn Signer>> = if slh_proposer {
            Some(Box::new(shell_crypto::SphincsSigner::generate()))
        } else if slh {
            Some(Box::new(MlDsaSigner::generate()))
        } else {
            None
        };
        let proposer: &dyn Signer = independent.as_ref().map_or(signer.as_ref(), |s| s.as_ref());
        let proposer_address =
            Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
        if slh || slh_proposer {
            chain
                .put_pubkey(&proposer_address, proposer.public_key())
                .unwrap();
        }
        let mut world = shell_storage::WorldState::new(db.clone());
        world
            .set_account(
                &address,
                &Account::new_user_account(
                    if unbound {
                        ShellHash::ZERO
                    } else {
                        blake3_hash(signer.public_key())
                    },
                    U256::from(1_000_000),
                ),
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
        if !unbound {
            chain.put_pubkey(&address, signer.public_key()).unwrap();
        }
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
        let mut signed = SignedTransaction::new(address, tx, signature);
        if unbound {
            signed.pubkey_mode = shell_core::PubkeyMode::Embedded(signer.public_key().to_vec());
        }
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
            block.header.proposer = proposer_address;
            block.proposer_seal = Some(proposer.sign(block.hash().as_bytes()).unwrap());
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
                        address: proposer_address,
                        public_key: proposer.public_key().to_vec(),
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
            let vote = proposer.sign(block.hash().as_bytes()).unwrap();
            assert!(if slh_proposer {
                shell_crypto::SphincsVerifier
                    .verify(proposer.public_key(), block.hash().as_bytes(), &vote)
                    .unwrap()
            } else {
                MlDsaVerifier
                    .verify(proposer.public_key(), block.hash().as_bytes(), &vote)
                    .unwrap()
            });
            chain
                .put_block_signers(
                    &block.hash(),
                    &[shell_core::BlockSignerEvidence {
                        address: proposer_address,
                        public_key: proposer.public_key().to_vec(),
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
    fn slh_proposer_source_eight_freezes_registered_seal_and_refuses_profile_rebinding() {
        let (db, source) = fixture_transcript_roles(true, false, false, false, false, true);
        assert_eq!(source.input.version, 8);
        assert!(
            source.has_slh_proposer() && source.needs_slh_encoding() && !source.has_slh_senders()
        );
        assert_eq!(source.input.proposer_key.as_ref().unwrap().len(), 64);
        ChainStore::new(db.clone())
            .put_pubkey(&source.block().header.proposer, &[7; 64])
            .unwrap();
        let before = db.scan_all().unwrap();
        let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
        assert_eq!(
            CanonicalProductionSource::restore(&frozen, source.identity())
                .unwrap()
                .identity(),
            source.identity()
        );
        for case in [
            "small-profile",
            "sender-profile",
            "unbound-profile",
            "wrong-key",
            "missing-key",
            "sdk-proposer",
            "unbound-sender",
            "changed-header",
        ] {
            let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
            match case {
                "small-profile" => input.version = 2,
                "sender-profile" => input.version = 6,
                "unbound-profile" => input.version = 9,
                "wrong-key" => input.proposer_key.as_mut().unwrap()[0] ^= 1,
                "missing-key" => input.proposer_key = None,
                "sdk-proposer" => input.proposer_sdk_fips = Some(1),
                "unbound-sender" => input.senders[0].account.pq_pubkey_hash = ShellHash::ZERO,
                _ => input.block.header.timestamp += 1,
            }
            let bytes =
                bounded_json(&serde_json::to_value(input).unwrap(), 4 * 1024 * 1024).unwrap();
            assert!(
                CanonicalProductionSource::restore(&frozen, &bytes).is_err(),
                "{case}"
            );
        }
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn primary_first_use_slh_proposer_source_nine_freezes_both_roles_and_refuses_rebinding() {
        let (db, source) = fixture_transcript_roles(true, true, false, false, false, true);
        assert_eq!(source.input.version, 9);
        assert!(
            source.has_slh_proposer()
                && source.has_unbound_senders()
                && source.needs_slh_encoding()
        );
        let chain = ChainStore::new(db.clone());
        chain
            .put_pubkey(&source.block().transactions[0].from, &[7; 1952])
            .unwrap();
        chain
            .put_pubkey(&source.block().header.proposer, &[7; 64])
            .unwrap();
        let before = db.scan_all().unwrap();
        let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
        assert_eq!(
            CanonicalProductionSource::restore(&frozen, source.identity())
                .unwrap()
                .identity(),
            source.identity()
        );
        for case in [
            "bound-profile",
            "small-profile",
            "missing-proposer-key",
            "wrong-proposer-key",
            "bound-account",
            "reference-without-parent-key",
            "changed-header",
        ] {
            let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
            match case {
                "bound-profile" => input.version = 8,
                "small-profile" => input.version = 4,
                "missing-proposer-key" => input.proposer_key = None,
                "wrong-proposer-key" => input.proposer_key.as_mut().unwrap()[0] ^= 1,
                "bound-account" => {
                    input.senders[0].account.pq_pubkey_hash = blake3_hash(&input.senders[0].key)
                }
                "reference-without-parent-key" => {
                    input.block.transactions[0].pubkey_mode = shell_core::PubkeyMode::Reference
                }
                _ => input.block.header.timestamp += 1,
            }
            let bytes =
                bounded_json(&serde_json::to_value(input).unwrap(), 4 * 1024 * 1024).unwrap();
            assert!(
                CanonicalProductionSource::restore(&frozen, &bytes).is_err(),
                "{case}"
            );
        }
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn slh_proposer_legacy_sender_only_source_remains_explicitly_partial() {
        let (db, source) = fixture_transcript_roles(true, false, false, false, false, true);
        let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
        input.version = 1;
        input.proposer_key = None;
        let bytes = bounded_json(&serde_json::to_value(input).unwrap(), 4 * 1024 * 1024).unwrap();
        let before = db.scan_all().unwrap();
        let legacy =
            CanonicalProductionSource::restore(&ChainStore::new(db.clone()), &bytes).unwrap();
        assert!(!legacy.has_slh_proposer() && !legacy.needs_slh_encoding());
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn funded_unbound_slh_source_freezes_address_and_rejects_profile_rebinding() {
        let (db, source) = fixture_transcript_slh(true, true, false, false, true);
        assert_eq!(source.input.version, 7);
        assert!(source.has_slh_senders() && source.has_unbound_senders());
        assert_eq!(source.input.senders[0].key.len(), 64);
        assert!(source.block().transactions[0].pubkey_mode.is_embedded());
        ChainStore::new(db.clone())
            .put_pubkey(&source.block().transactions[0].from, &[9; 64])
            .unwrap();
        let before = db.scan_all().unwrap();
        let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
        assert_eq!(
            CanonicalProductionSource::restore(&frozen, source.identity())
                .unwrap()
                .identity(),
            source.identity()
        );
        for mode in [
            "bound-v6",
            "old-v4",
            "sdk-marker",
            "foreign-key",
            "bound-state",
            "custom-validator",
            "nonce",
            "changed-envelope",
        ] {
            let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
            match mode {
                "bound-v6" => input.version = 6,
                "old-v4" => input.version = 4,
                "sdk-marker" => input.senders[0].sdk_fips = Some(1),
                "foreign-key" => input.senders[0].key[0] ^= 1,
                "bound-state" => {
                    input.senders[0].account.pq_pubkey_hash = blake3_hash(&input.senders[0].key)
                }
                "custom-validator" => {
                    input.senders[0].account.validation_code_hash = Some(ShellHash::from([8; 32]))
                }
                "nonce" => input.senders[0].account.nonce = 1,
                _ => input.block.transactions[0].pubkey_mode = shell_core::PubkeyMode::Reference,
            }
            let bytes =
                bounded_json(&serde_json::to_value(input).unwrap(), 4 * 1024 * 1024).unwrap();
            assert!(
                CanonicalProductionSource::restore(&frozen, &bytes).is_err(),
                "{mode}"
            );
        }
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn bound_slh_source_keeps_six_and_refuses_unbound_seven() {
        let (db, source) = fixture_transcript_slh(true, false, false, false, true);
        assert_eq!(source.input.version, 6);
        assert!(!source.has_unbound_senders());
        let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
        input.version = 7;
        let bytes = bounded_json(&serde_json::to_value(input).unwrap(), 4 * 1024 * 1024).unwrap();
        let before = db.scan_all().unwrap();
        assert!(CanonicalProductionSource::restore(&ChainStore::new(db.clone()), &bytes).is_err());
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn unbound_first_use_capture_recovers_frozen_inputs_and_rejects_key_or_account_rebinding() {
        for legacy in [false, true] {
            let (db, source) = fixture_algorithm(false, true, legacy);
            assert!(source.has_unbound_senders());
            let tx = &source.block().transactions[0];
            assert!(tx.pubkey_mode.is_embedded());
            assert_eq!(
                source.input.senders[0].account.pq_pubkey_hash,
                ShellHash::ZERO
            );
            let chain = ChainStore::new(db.clone());
            assert!(chain.get_pubkey(&tx.from).unwrap().is_none());
            // Current registration may change after capture; recovery uses the frozen
            // parent MPT/key, not live trie nodes or a later registry entry.
            chain
                .put_pubkey(&tx.from, &source.input.senders[0].key)
                .unwrap();
            let before = db.scan_all().unwrap();
            let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
            let recovered = CanonicalProductionSource::restore(&frozen, source.identity()).unwrap();
            assert_eq!(recovered.identity(), source.identity());
            for mode in ["key", "account"] {
                let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
                if mode == "key" {
                    input.senders[0].key[0] ^= 1;
                } else {
                    input.senders[0].account.pq_pubkey_hash = blake3_hash(&input.senders[0].key);
                }
                let bytes =
                    bounded_json(&serde_json::to_value(input).unwrap(), 4 * 1024 * 1024).unwrap();
                assert!(
                    CanonicalProductionSource::restore(&frozen, &bytes).is_err(),
                    "{mode}"
                );
            }
            assert_eq!(before, db.scan_all().unwrap());
        }
    }
    #[test]
    fn unbound_sdk_source_requires_new_profile_and_frozen_address() {
        let (db, source) = fixture_transcript(false, true, false, true);
        assert_eq!(source.input.version, 4);
        assert!(source.has_unbound_senders());
        assert_eq!(source.input.senders[0].sdk_fips, Some(1));
        let chain = ChainStore::new(db.clone());
        chain
            .put_pubkey(&source.block().transactions[0].from, &[9; 1952])
            .unwrap();
        let before = db.scan_all().unwrap();
        let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
        assert_eq!(
            CanonicalProductionSource::restore(&frozen, source.identity())
                .unwrap()
                .identity(),
            source.identity()
        );
        for mode in [
            "old-bound-sdk",
            "old-raw",
            "missing-marker",
            "unknown-marker",
            "bound-account",
            "foreign-key",
        ] {
            let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
            match mode {
                "old-bound-sdk" => input.version = 3,
                "old-raw" => {
                    input.version = 1;
                    input.senders[0].sdk_fips = None;
                }
                "missing-marker" => input.senders[0].sdk_fips = None,
                "unknown-marker" => input.senders[0].sdk_fips = Some(2),
                "bound-account" => {
                    input.senders[0].account.pq_pubkey_hash = blake3_hash(&input.senders[0].key)
                }
                "foreign-key" => input.senders[0].key[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                CanonicalProductionSource::restore(&frozen, &serde_json::to_vec(&input).unwrap())
                    .is_err(),
                "{mode}"
            );
        }
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn sdk_source_freezes_explicit_transcript_and_rejects_relabelling() {
        let (db, source) = fixture_transcript(false, false, false, true);
        assert_eq!(source.input.version, 3);
        assert_eq!(source.input.senders[0].sdk_fips, Some(1));
        assert_eq!(
            source.block().transactions[0].signature.sig_type,
            SignatureType::Dilithium3
        );
        let before = db.scan_all().unwrap();
        let frozen = ChainStore::new(Arc::new(NoTrieReads(db.clone())));
        assert_eq!(
            CanonicalProductionSource::restore(&frozen, source.identity())
                .unwrap()
                .identity(),
            source.identity()
        );
        for mode in ["old-format", "missing-marker", "unknown-marker", "unbound"] {
            let mut input: CapturedInputs = serde_json::from_slice(source.identity()).unwrap();
            match mode {
                "old-format" => input.version = 1,
                "missing-marker" => input.senders[0].sdk_fips = None,
                "unknown-marker" => input.senders[0].sdk_fips = Some(2),
                "unbound" => input.senders[0].account.pq_pubkey_hash = ShellHash::ZERO,
                _ => unreachable!(),
            }
            assert!(
                CanonicalProductionSource::restore(&frozen, &serde_json::to_vec(&input).unwrap())
                    .is_err(),
                "{mode}"
            );
        }
        for legacy in [false, true] {
            let (old_db, old) = fixture_algorithm(false, false, legacy);
            assert_eq!(old.input.version, 1);
            assert!(!std::str::from_utf8(old.identity())
                .unwrap()
                .contains("sdk_fips"));
            let mut input: CapturedInputs = serde_json::from_slice(old.identity()).unwrap();
            input.version = 3;
            input.senders[0].sdk_fips = Some(1);
            assert!(CanonicalProductionSource::restore(
                &ChainStore::new(old_db),
                &serde_json::to_vec(&input).unwrap()
            )
            .is_err());
        }
        assert_eq!(before, db.scan_all().unwrap());
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

#[cfg(test)]
mod slh_profile_tests {
    use super::*;
    use shell_core::{SignedTransaction, Transaction};
    use shell_crypto::PQSignature;
    use shell_primitives::Address;
    #[test]
    fn slh_requires_one_sender_and_a_seal_without_relaxing_old_shapes() {
        let transaction = SignedTransaction::new(
            Address::ZERO,
            Transaction {
                chain_id: 10,
                nonce: 0,
                to: None,
                value: Default::default(),
                data: Default::default(),
                gas_limit: 21_000,
                max_fee_per_gas: 2,
                max_priority_fee_per_gas: 1,
                access_list: None,
                tx_type: 0,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            PQSignature::new(SignatureType::SphincsSha2256f, vec![0; 49_856]),
        );
        let mut block = Block {
            header: BlockHeader::default(),
            transactions: vec![transaction.clone()],
            system_transactions: vec![],
            proposer_seal: None,
        };
        assert!(!supports_production_senders(&block));
        block.proposer_seal = Some(PQSignature::new(SignatureType::MlDsa65, vec![0; 3309]));
        // Framing is not authority; no signature verification takes place here.
        assert!(supports_production_senders(&block));
        block.transactions.push(transaction);
        assert!(!supports_production_senders(&block));
        assert!(!sender_shape(SignatureType::MlDsa65, 64, 49_856));
        assert!(!sender_shape(SignatureType::SphincsSha2256f, 1952, 3309));
        assert!(!sender_shape(SignatureType::SphincsSha2256f, 64, 49_855));
    }
}
