//! Authenticated timeout wire data. Canonical admission and quorum verification
//! belong to consensus; these types do not activate offline enforcement.
use crate::{BlockSignerEvidence, SystemTransaction};
use serde::{Deserialize, Serialize};
use shell_crypto::PQSignature;
use shell_primitives::{Address, ShellHash};

/// Commit ordered effective authorities without discarding proposer order.
/// Shared by timeout verification and root-backed historical context storage.
pub fn timeout_authority_set_hash(authorities: &[(Address, u64)]) -> Result<ShellHash, String> {
    if authorities.is_empty() {
        return Err("empty authority set".into());
    }
    let mut seen = std::collections::HashSet::new();
    let mut bytes = b"shell:timeout-authorities:v1".to_vec();
    bytes.extend_from_slice(&(authorities.len() as u64).to_be_bytes());
    for (address, weight) in authorities {
        if *weight == 0
            || *weight > shell_primitives::MAX_VALIDATOR_WEIGHT
            || !seen.insert(*address)
        {
            return Err("invalid weight or duplicate authority".into());
        }
        bytes.extend_from_slice(address.as_bytes());
        bytes.extend_from_slice(&weight.to_be_bytes());
    }
    Ok(shell_primitives::keccak256(&bytes))
}

const TIMEOUT_DOMAIN: &[u8; 16] = b"SHELL_TIMEOUT_V1";

/// Expected context comes from the canonical parent and opportunity admission,
/// never from the submitted certificate itself. Epoch and authority ordering
/// are included because both affect the assigned proposer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutContext {
    pub chain_id: u64,
    pub block_number: u64,
    pub view: u64,
    pub parent_hash: ShellHash,
    pub epoch: u64,
    pub authority_set_hash: ShellHash,
    pub proposer: Address,
    /// Commitment to admitted work or a protocol heartbeat opportunity.
    /// A local clock observation or an idle mempool is not an opportunity.
    pub opportunity_hash: ShellHash,
}

impl TimeoutContext {
    pub fn signing_message(&self, validator: &Address) -> Vec<u8> {
        let mut payload = Vec::with_capacity(208);
        payload.extend_from_slice(TIMEOUT_DOMAIN);
        payload.extend_from_slice(&self.chain_id.to_be_bytes());
        payload.extend_from_slice(&self.block_number.to_be_bytes());
        payload.extend_from_slice(&self.view.to_be_bytes());
        payload.extend_from_slice(self.parent_hash.as_bytes());
        payload.extend_from_slice(&self.epoch.to_be_bytes());
        payload.extend_from_slice(self.authority_set_hash.as_bytes());
        payload.extend_from_slice(self.proposer.as_bytes());
        payload.extend_from_slice(self.opportunity_hash.as_bytes());
        payload.extend_from_slice(validator.as_bytes());
        payload
    }
}

/// Durable work witness, independent of an observer's current mempool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeoutOpportunity {
    Work {
        transaction: Box<crate::SignedTransaction>,
        admitted_at: u64,
    },
    Heartbeat,
}

impl TimeoutOpportunity {
    /// Bind the complete signed transaction (including identity, signature,
    /// key mode and AA payload), or the frozen heartbeat eligibility time.
    pub fn commitment(
        &self,
        parent: &crate::BlockHeader,
        chain_id: u64,
        heartbeat_interval_secs: u64,
    ) -> Option<ShellHash> {
        let mut bytes = b"shell:timeout-opportunity:v1".to_vec();
        bytes.extend_from_slice(&chain_id.to_be_bytes());
        bytes.extend_from_slice(parent.hash().as_bytes());
        match self {
            Self::Work {
                transaction,
                admitted_at,
            } => {
                bytes.push(0);
                bytes.extend_from_slice(&admitted_at.to_be_bytes());
                bytes.extend_from_slice(&alloy_rlp::encode(transaction.as_ref()));
            }
            Self::Heartbeat => {
                bytes.push(1);
                bytes.extend_from_slice(
                    &parent
                        .timestamp
                        .checked_add(heartbeat_interval_secs)?
                        .to_be_bytes(),
                );
            }
        }
        Some(shell_primitives::keccak256(&bytes))
    }
}

/// Distinct bound timeout transport. Legacy V1 votes cannot populate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutVoteMessage {
    pub vote: TimeoutVote,
    pub public_key: Vec<u8>,
    pub opportunity: TimeoutOpportunity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutVote {
    pub context: TimeoutContext,
    pub validator: Address,
    pub signature: PQSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutCertificate {
    /// Component kernels may omit a witness; live admission requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opportunity: Option<TimeoutOpportunity>,
    pub context: TimeoutContext,
    pub signers: Vec<BlockSignerEvidence>,
}

impl TimeoutCertificate {
    /// Decode only the canonical zero-value evidence envelope. Quorum and
    /// canonical-parent admission still require the consensus verifier.
    pub fn from_system_transaction(
        tx: &SystemTransaction,
        expected_index: u32,
    ) -> Result<Self, String> {
        if tx.kind != crate::SystemTxKind::TimeoutEvidence {
            return Err("not a timeout evidence transaction".into());
        }
        let bytes = tx
            .proof_payload
            .as_ref()
            .ok_or("missing timeout proof payload")?;
        let proof: Self = serde_json::from_slice(bytes.as_ref())
            .map_err(|e| format!("invalid timeout proof: {e}"))?;
        let canonical = proof
            .system_transaction(expected_index)
            .map_err(|e| e.to_string())?;
        if *tx != canonical {
            return Err("noncanonical timeout evidence envelope".into());
        }
        Ok(proof)
    }

    /// Canonical proof bytes are committed by the system transaction hash.
    /// This encoder does not grant admission: block execution still verifies
    /// activation, canonical context, opportunity and every signature.
    pub fn system_transaction(
        &self,
        tx_index: u32,
    ) -> Result<SystemTransaction, serde_json::Error> {
        let mut canonical = self.clone();
        canonical
            .signers
            .sort_by_key(|signer| *signer.address.as_bytes());
        Ok(SystemTransaction::timeout_evidence(
            self.context.chain_id,
            self.context.block_number,
            tx_index,
            self.context.proposer,
            self.context.parent_hash,
            serde_json::to_vec(&canonical)?.into(),
        ))
    }
}
