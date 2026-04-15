use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_crypto::PQSignature;
use shell_primitives::{Address, Bytes, ShellHash};

use crate::SignedTransaction;

/// Block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: ShellHash,
    pub state_root: ShellHash,
    pub transactions_root: ShellHash,
    pub receipts_root: ShellHash,
    /// Bloom filter over all logs in this block (2048-bit / 256 bytes).
    /// Populated by EVM executor; empty during construction.
    pub logs_bloom: Bytes,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub proposer: Address,
    /// Aggregated proof for batched signature verification (future use).
    pub sig_aggregate_proof: Option<Bytes>,
    /// EIP-1559 base fee per gas. 0 for the genesis block.
    pub base_fee_per_gas: u64,
    /// Withdrawals root (EIP-4895). Always empty-trie root for PoA chains.
    pub withdrawals_root: ShellHash,
    /// Parent beacon block root (EIP-4788). Zero for non-beacon chains.
    pub parent_beacon_block_root: ShellHash,
    /// EIP-4844: total blob gas used in this block.
    #[serde(default)]
    pub blob_gas_used: u64,
    /// EIP-4844: excess blob gas carried forward for pricing.
    #[serde(default)]
    pub excess_blob_gas: u64,
}

impl Encodable for BlockHeader {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        self.parent_hash.encode(out);
        self.state_root.encode(out);
        self.transactions_root.encode(out);
        self.receipts_root.encode(out);
        self.logs_bloom.encode(out);
        self.number.encode(out);
        self.gas_limit.encode(out);
        self.gas_used.encode(out);
        self.timestamp.encode(out);
        self.extra_data.encode(out);
        self.proposer.encode(out);
        match &self.sig_aggregate_proof {
            Some(proof) => proof.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        self.base_fee_per_gas.encode(out);
        self.withdrawals_root.encode(out);
        self.parent_beacon_block_root.encode(out);
        self.blob_gas_used.encode(out);
        self.excess_blob_gas.encode(out);
    }

    fn length(&self) -> usize {
        let payload = self.fields_len();
        alloy_rlp::Header {
            list: true,
            payload_length: payload,
        }
        .length()
        .saturating_add(payload)
    }
}

impl BlockHeader {
    fn fields_len(&self) -> usize {
        let proof_len = match &self.sig_aggregate_proof {
            Some(proof) => proof.length(),
            None => 1, // 0x80
        };
        self.parent_hash
            .length()
            .saturating_add(self.state_root.length())
            .saturating_add(self.transactions_root.length())
            .saturating_add(self.receipts_root.length())
            .saturating_add(self.logs_bloom.length())
            .saturating_add(self.number.length())
            .saturating_add(self.gas_limit.length())
            .saturating_add(self.gas_used.length())
            .saturating_add(self.timestamp.length())
            .saturating_add(self.extra_data.length())
            .saturating_add(self.proposer.length())
            .saturating_add(proof_len)
            .saturating_add(self.base_fee_per_gas.length())
            .saturating_add(self.withdrawals_root.length())
            .saturating_add(self.parent_beacon_block_root.length())
            .saturating_add(self.blob_gas_used.length())
            .saturating_add(self.excess_blob_gas.length())
    }

    /// Compute the block hash (keccak256 of RLP-encoded header).
    pub fn hash(&self) -> ShellHash {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        shell_primitives::keccak256(&buf)
    }

    pub fn is_genesis(&self) -> bool {
        self.number == 0 && self.parent_hash == ShellHash::ZERO
    }
}

/// A complete block: header + body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<SignedTransaction>,
    /// PoA proposer seal (PQ signature over the header hash).
    /// Stored outside the header to avoid circular hashing.
    pub proposer_seal: Option<PQSignature>,
}

impl Block {
    pub fn hash(&self) -> ShellHash {
        self.header.hash()
    }

    pub fn number(&self) -> u64 {
        self.header.number
    }

    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    fn rlp_fields_len(&self) -> usize {
        let txs_payload: usize = self.transactions.iter().map(|t| t.length()).sum();
        let txs_list_len = alloy_rlp::Header {
            list: true,
            payload_length: txs_payload,
        }
        .length()
        .saturating_add(txs_payload);
        let seal_len = match &self.proposer_seal {
            Some(seal) => seal.length(),
            None => 1, // 0x80 empty bytes
        };
        self.header
            .length()
            .saturating_add(txs_list_len)
            .saturating_add(seal_len)
    }
}

impl Decodable for BlockHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let parent_hash = ShellHash::decode(buf)?;
        let state_root = ShellHash::decode(buf)?;
        let transactions_root = ShellHash::decode(buf)?;
        let receipts_root = ShellHash::decode(buf)?;
        let logs_bloom = Bytes::decode(buf)?;
        let number = u64::decode(buf)?;
        let gas_limit = u64::decode(buf)?;
        let gas_used = u64::decode(buf)?;
        let timestamp = u64::decode(buf)?;
        let extra_data = Bytes::decode(buf)?;
        let proposer = Address::decode(buf)?;

        // sig_aggregate_proof: empty bytes → None, non-empty → Some
        let proof_bytes = Bytes::decode(buf)?;
        let sig_aggregate_proof = if proof_bytes.is_empty() {
            None
        } else {
            Some(proof_bytes)
        };

        let base_fee_per_gas = u64::decode(buf)?;
        let withdrawals_root = ShellHash::decode(buf)?;
        let parent_beacon_block_root = ShellHash::decode(buf)?;
        let blob_gas_used = u64::decode(buf)?;
        let excess_blob_gas = u64::decode(buf)?;

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            parent_hash,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            proposer,
            sig_aggregate_proof,
            base_fee_per_gas,
            withdrawals_root,
            parent_beacon_block_root,
            blob_gas_used,
            excess_blob_gas,
        })
    }
}

impl Encodable for Block {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_fields_len(),
        };
        header.encode(out);
        self.header.encode(out);
        // Transactions as an RLP list
        let txs_payload: usize = self.transactions.iter().map(|t| t.length()).sum();
        alloy_rlp::Header {
            list: true,
            payload_length: txs_payload,
        }
        .encode(out);
        for tx in &self.transactions {
            tx.encode(out);
        }
        match &self.proposer_seal {
            Some(seal) => seal.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
    }

    fn length(&self) -> usize {
        let payload = self.rlp_fields_len();
        alloy_rlp::Header {
            list: true,
            payload_length: payload,
        }
        .length()
        .saturating_add(payload)
    }
}

impl Decodable for Block {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let end = remaining.saturating_sub(header.payload_length);

        let block_header = BlockHeader::decode(buf)?;

        // Transactions list
        let txs_header = alloy_rlp::Header::decode(buf)?;
        if !txs_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut transactions = Vec::new();
        let txs_end = buf.len().saturating_sub(txs_header.payload_length);
        while buf.len() > txs_end {
            transactions.push(SignedTransaction::decode(buf)?);
        }

        // Proposer seal: empty bytes (0x80) → None, RLP list → PQSignature
        let proposer_seal = if buf.len() > end && buf.first().copied().unwrap_or(0) == 0x80 {
            let _ = alloy_rlp::Header::decode_bytes(buf, false)?;
            None
        } else if buf.len() > end {
            Some(PQSignature::decode(buf)?)
        } else {
            None
        };

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            header: block_header,
            transactions,
            proposer_seal,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            parent_hash: ShellHash::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            logs_bloom: Bytes::new(),
            number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1700000000,
            extra_data: Bytes::new(),
            proposer: Address::ZERO,
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    #[test]
    fn genesis_block() {
        let header = sample_header();
        assert!(header.is_genesis());
    }

    #[test]
    fn non_genesis_block() {
        let mut header = sample_header();
        header.number = 1;
        header.parent_hash = shell_primitives::keccak256(b"parent");
        assert!(!header.is_genesis());
    }

    #[test]
    fn header_hash_deterministic() {
        let header = sample_header();
        assert_eq!(header.hash(), header.hash());
    }

    #[test]
    fn header_hash_changes_with_number() {
        let h1 = sample_header();
        let mut h2 = sample_header();
        h2.number = 1;
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn header_rlp_encodes() {
        let header = sample_header();
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert!(!buf.is_empty());
        // Hash from encoded bytes should be consistent
        let hash = shell_primitives::keccak256(&buf);
        assert_eq!(hash, header.hash());
    }

    #[test]
    fn block_basic() {
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            proposer_seal: None,
        };
        assert_eq!(block.number(), 0);
        assert_eq!(block.tx_count(), 0);
    }

    #[test]
    fn block_serde_roundtrip() {
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            proposer_seal: None,
        };
        let json = serde_json::to_string(&block).unwrap();
        let block2: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(block.header, block2.header);
    }

    #[test]
    fn header_rlp_roundtrip() {
        let header = sample_header();
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let decoded = BlockHeader::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_rlp_roundtrip_with_proof() {
        let mut header = sample_header();
        header.sig_aggregate_proof = Some(Bytes::from(vec![0xAA; 64]));
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let decoded = BlockHeader::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn block_rlp_roundtrip() {
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            proposer_seal: None,
        };
        let mut buf = Vec::new();
        block.encode(&mut buf);
        let decoded = Block::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(block, decoded);
    }
}
