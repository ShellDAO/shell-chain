use serde::{Deserialize, Serialize};
use shell_primitives::{Address, Bytes, ShellHash, U256};

/// System-level transaction kind exposed through RPC/explorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SystemTxKind {
    BlockGasReward,
    StarkReward,
    TimeoutEvidence,
}

impl SystemTxKind {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::BlockGasReward => 1,
            Self::StarkReward => 2,
            Self::TimeoutEvidence => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockGasReward => "blockGasReward",
            Self::StarkReward => "starkReward",
            Self::TimeoutEvidence => "timeoutEvidence",
        }
    }
}

/// A first-class deterministic system transaction record.
///
/// System transactions are not user-signed EVM transactions. They are derived
/// from consensus rules, indexed by transaction hash, and surfaced through RPC
/// with tx-like fields so explorers and clients can account for rewards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemTransaction {
    pub kind: SystemTxKind,
    pub chain_id: u64,
    pub block_number: u64,
    pub tx_index: u32,
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub source_hash: ShellHash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<u64>,
    /// Serialized STARK proof settlement payload carried by the `StarkReward`
    /// transaction. The core crate treats this as opaque bytes; nodes decode it
    /// as `ProofAmendment` during block validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_payload: Option<Bytes>,
}

/// Inputs for constructing a first-class STARK reward system transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkRewardParams {
    pub chain_id: u64,
    pub block_number: u64,
    pub tx_index: u32,
    pub recipient: Address,
    pub value: U256,
    pub source_hash: ShellHash,
    pub layer: u32,
    pub original_size: u64,
    pub compressed_size: u64,
    pub proof_payload: Bytes,
}

impl SystemTransaction {
    pub fn block_gas_reward(
        chain_id: u64,
        block_number: u64,
        tx_index: u32,
        recipient: Address,
        value: U256,
        parent_hash: ShellHash,
    ) -> Self {
        Self {
            kind: SystemTxKind::BlockGasReward,
            chain_id,
            block_number,
            tx_index,
            from: Address::ZERO,
            to: recipient,
            value,
            source_hash: parent_hash,
            layer: None,
            original_size: None,
            compressed_size: None,
            proof_payload: None,
        }
    }

    pub fn stark_reward(params: StarkRewardParams) -> Self {
        Self {
            kind: SystemTxKind::StarkReward,
            chain_id: params.chain_id,
            block_number: params.block_number,
            tx_index: params.tx_index,
            from: Address::ZERO,
            to: params.recipient,
            value: params.value,
            source_hash: params.source_hash,
            layer: Some(params.layer),
            original_size: Some(params.original_size),
            compressed_size: Some(params.compressed_size),
            proof_payload: Some(params.proof_payload),
        }
    }

    /// Zero-value consensus evidence. Admission is verified by the activated
    /// timeout rules; this constructor does not authorize a validator penalty.
    pub fn timeout_evidence(
        chain_id: u64,
        block_number: u64,
        tx_index: u32,
        proposer: Address,
        parent_hash: ShellHash,
        proof_payload: Bytes,
    ) -> Self {
        Self {
            kind: SystemTxKind::TimeoutEvidence,
            chain_id,
            block_number,
            tx_index,
            from: Address::ZERO,
            to: proposer,
            value: U256::ZERO,
            source_hash: parent_hash,
            layer: None,
            original_size: None,
            compressed_size: None,
            proof_payload: Some(proof_payload),
        }
    }

    pub fn is_compression_valid(&self) -> bool {
        match (self.original_size, self.compressed_size) {
            (Some(original), Some(compressed)) => compressed.saturating_mul(2) < original,
            _ => true,
        }
    }

    pub fn hash(&self) -> ShellHash {
        let mut preimage = Vec::with_capacity(160);
        preimage.extend_from_slice(b"shell:system-tx:v1");
        preimage.push(self.kind.as_u8());
        preimage.extend_from_slice(&self.chain_id.to_be_bytes());
        preimage.extend_from_slice(&self.block_number.to_be_bytes());
        preimage.extend_from_slice(&self.tx_index.to_be_bytes());
        preimage.extend_from_slice(self.from.as_ref());
        preimage.extend_from_slice(self.to.as_ref());
        preimage.extend_from_slice(&self.value.to_be_bytes::<32>());
        preimage.extend_from_slice(self.source_hash.as_bytes());
        preimage.extend_from_slice(&self.layer.unwrap_or(0).to_be_bytes());
        preimage.extend_from_slice(&self.original_size.unwrap_or(0).to_be_bytes());
        preimage.extend_from_slice(&self.compressed_size.unwrap_or(0).to_be_bytes());
        if let Some(payload) = &self.proof_payload {
            preimage.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            preimage.extend_from_slice(payload.as_ref());
        }
        shell_primitives::keccak256(&preimage)
    }

    pub fn to_wire_bytes(&self) -> Result<Bytes, serde_json::Error> {
        serde_json::to_vec(self).map(Bytes::from)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_tx_hash_is_deterministic_and_domain_separated_by_kind() {
        let recipient = Address::from([0x11; 20]);
        let source = ShellHash::from([0x22; 32]);
        let block_reward =
            SystemTransaction::block_gas_reward(10, 7, 3, recipient, U256::from(123u64), source);
        let same =
            SystemTransaction::block_gas_reward(10, 7, 3, recipient, U256::from(123u64), source);
        let stark_reward = SystemTransaction::stark_reward(StarkRewardParams {
            chain_id: 10,
            block_number: 7,
            tx_index: 3,
            recipient,
            value: U256::from(123u64),
            source_hash: source,
            layer: 1,
            original_size: 100,
            compressed_size: 49,
            proof_payload: Bytes::from_static(b"proof"),
        });

        assert_eq!(block_reward.hash(), same.hash());
        assert_ne!(block_reward.hash(), stark_reward.hash());
    }

    #[test]
    fn compression_valid_requires_strictly_under_half() {
        let recipient = Address::from([0x11; 20]);
        let source = ShellHash::from([0x22; 32]);
        let valid = SystemTransaction::stark_reward(StarkRewardParams {
            chain_id: 10,
            block_number: 7,
            tx_index: 3,
            recipient,
            value: U256::from(1u8),
            source_hash: source,
            layer: 1,
            original_size: 100,
            compressed_size: 49,
            proof_payload: Bytes::from_static(b"proof"),
        });
        let exactly_half = SystemTransaction::stark_reward(StarkRewardParams {
            chain_id: 10,
            block_number: 7,
            tx_index: 3,
            recipient,
            value: U256::from(1u8),
            source_hash: source,
            layer: 1,
            original_size: 100,
            compressed_size: 50,
            proof_payload: Bytes::from_static(b"proof"),
        });

        assert!(valid.is_compression_valid());
        assert!(!exactly_half.is_compression_valid());
    }
}
