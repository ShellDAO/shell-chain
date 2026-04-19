use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_crypto::{PQSignature, SignatureType};
use shell_primitives::{Address, Bytes, ShellHash};

use crate::transaction::PubkeyMode;
use crate::witness::{StrippedTransaction, TxWitness, WitnessBundle};
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
    /// Witness Merkle root (Phase B). `None` for pre-witness blocks.
    /// Commits to the ordered `WitnessBundle` for this block, enabling
    /// light clients to verify witness data without downloading it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_root: Option<ShellHash>,
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
        // witness_root: None → empty bytes (0x80), Some(h) → 32-byte hash
        match &self.witness_root {
            Some(root) => root.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
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
            .saturating_add(match &self.witness_root {
                Some(root) => root.length(),
                None => 1, // 0x80 empty bytes
            })
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

        // witness_root: empty bytes → None, 32-byte hash → Some
        // For backward compatibility: older blocks without this field will
        // hit ListLengthMismatch at consumed != header.payload_length — handled
        // gracefully by treating absent field as None via the consumed check below.
        let witness_root = if !buf.is_empty() {
            let root_bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
            if root_bytes.is_empty() {
                None
            } else {
                let arr: [u8; 32] = root_bytes
                    .try_into()
                    .map_err(|_| alloy_rlp::Error::Custom("witness_root must be 32 bytes"))?;
                Some(ShellHash::from(arr))
            }
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
            witness_root,
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

// ── StrippedBlock ─────────────────────────────────────────────────────────────

/// A block body with PQ signatures stripped out (Phase B storage format).
///
/// Stored at `b/<hash>` — contains the block header, stripped transaction
/// payloads (no signatures/pubkeys), and the proposer seal.  PQ witness
/// material lives in a parallel [`WitnessBundle`] at `w/<hash>`.
///
/// ## Wire encoding (RLP)
/// Same structure as [`Block`] but `transactions` is a list of
/// [`StrippedTransaction`] instead of [`SignedTransaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrippedBlock {
    pub header: BlockHeader,
    pub transactions: Vec<StrippedTransaction>,
    /// PoA proposer seal — kept in the stripped body (not a tx witness).
    pub proposer_seal: Option<PQSignature>,
}

impl StrippedBlock {
    /// Split a full [`Block`] into a [`StrippedBlock`] and its [`WitnessBundle`].
    ///
    /// All PQ signature material is moved into the bundle; the stripped block
    /// retains only transaction payloads (from + tx fields).
    pub fn split(block: &Block) -> (Self, WitnessBundle) {
        let mut stripped_txs = Vec::with_capacity(block.transactions.len());
        let mut witnesses = Vec::with_capacity(block.transactions.len());

        for tx in &block.transactions {
            stripped_txs.push(StrippedTransaction::new(tx.from, tx.tx.clone()));
            let pubkey = match &tx.pubkey_mode {
                PubkeyMode::Embedded(pk) => Some(pk.clone()),
                PubkeyMode::Reference => None,
            };
            witnesses.push(TxWitness {
                signature: tx.signature.clone(),
                pubkey,
            });
        }

        let stripped = Self {
            header: block.header.clone(),
            transactions: stripped_txs,
            proposer_seal: block.proposer_seal.clone(),
        };
        (stripped, WitnessBundle::new(witnesses))
    }

    /// Reconstruct a full [`Block`] from a [`StrippedBlock`] and an optional [`WitnessBundle`].
    ///
    /// If `bundle` is `None` (block is STARK-compressed and witnesses were pruned),
    /// the returned transactions carry empty stub signatures so callers can still
    /// read transaction payloads (from / to / value / etc.).
    pub fn into_block(self, bundle: Option<WitnessBundle>) -> Block {
        let transactions = match bundle {
            Some(b) => self
                .transactions
                .into_iter()
                .zip(b.witnesses)
                .map(|(st, w)| {
                    if let Some(pk) = w.pubkey {
                        SignedTransaction::with_pubkey(st.from, st.tx, w.signature, pk)
                    } else {
                        SignedTransaction::new(st.from, st.tx, w.signature)
                    }
                })
                .collect(),
            None => {
                // Witnesses pruned after STARK proof acceptance: return stub sigs.
                let stub_sig =
                    PQSignature { sig_type: SignatureType::Dilithium3, data: Vec::new() };
                self.transactions
                    .into_iter()
                    .map(|st| SignedTransaction::new(st.from, st.tx, stub_sig.clone()))
                    .collect()
            }
        };
        Block { header: self.header, transactions, proposer_seal: self.proposer_seal }
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
            None => 1,
        };
        self.header
            .length()
            .saturating_add(txs_list_len)
            .saturating_add(seal_len)
    }
}

impl Encodable for StrippedBlock {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_fields_len(),
        };
        header.encode(out);
        self.header.encode(out);
        let txs_payload: usize = self.transactions.iter().map(|t| t.length()).sum();
        alloy_rlp::Header { list: true, payload_length: txs_payload }.encode(out);
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
        alloy_rlp::Header { list: true, payload_length: payload }.length().saturating_add(payload)
    }
}

impl Decodable for StrippedBlock {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let end = remaining.saturating_sub(header.payload_length);

        let block_header = BlockHeader::decode(buf)?;

        let txs_header = alloy_rlp::Header::decode(buf)?;
        if !txs_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut transactions = Vec::new();
        let txs_end = buf.len().saturating_sub(txs_header.payload_length);
        while buf.len() > txs_end {
            transactions.push(StrippedTransaction::decode(buf)?);
        }

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

        Ok(Self { header: block_header, transactions, proposer_seal })
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
            witness_root: None,
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

    // ── B2: witness_root tests ─────────────────────────────────────────────

    #[test]
    fn witness_root_default_is_none() {
        let header = sample_header();
        assert!(header.witness_root.is_none());
    }

    #[test]
    fn witness_root_some_rlp_roundtrip() {
        let mut header = sample_header();
        let root = shell_primitives::keccak256(b"witness-bundle-root");
        header.witness_root = Some(root);
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let decoded = BlockHeader::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.witness_root, Some(root));
    }

    #[test]
    fn witness_root_none_rlp_roundtrip() {
        let header = sample_header(); // witness_root: None
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let decoded = BlockHeader::decode(&mut buf.as_slice()).unwrap();
        assert!(decoded.witness_root.is_none());
    }

    #[test]
    fn witness_root_affects_block_hash() {
        let h1 = sample_header();
        let mut h2 = sample_header();
        h2.witness_root = Some(shell_primitives::keccak256(b"bundle"));
        assert_ne!(
            h1.hash(),
            h2.hash(),
            "witness_root must influence block hash"
        );
    }

    #[test]
    fn witness_root_serde_absent_when_none() {
        let header = sample_header();
        let json = serde_json::to_string(&header).unwrap();
        assert!(
            !json.contains("witness_root"),
            "witness_root should be absent from JSON when None"
        );
    }

    #[test]
    fn witness_root_serde_present_when_some() {
        let mut header = sample_header();
        header.witness_root = Some(shell_primitives::keccak256(b"root"));
        let json = serde_json::to_string(&header).unwrap();
        assert!(
            json.contains("witness_root"),
            "witness_root should appear in JSON when Some"
        );
        let decoded: BlockHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.witness_root, header.witness_root);
    }

    // ── StrippedBlock tests ───────────────────────────────────────────────────

    fn make_signed_tx() -> SignedTransaction {
        use shell_crypto::{DilithiumSigner, Signer};
        use shell_primitives::{Address, U256};
        use crate::transaction::Transaction;

        let signer = DilithiumSigner::generate();
        let pk = signer.public_key().to_vec();
        let sig = signer.sign(b"test").unwrap();
        let tx = Transaction {
            chain_id: 1,
            nonce: 0,
            to: Some(Address::from([0xBB; 20])),
            value: U256::from(42u64),
            data: shell_primitives::Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000,
            max_priority_fee_per_gas: 1_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        SignedTransaction::with_pubkey(Address::from([0xAA; 20]), tx, sig, pk)
    }

    #[test]
    fn stripped_block_rlp_roundtrip_empty() {
        let stripped = StrippedBlock {
            header: sample_header(),
            transactions: vec![],
            proposer_seal: None,
        };
        let mut buf = Vec::new();
        stripped.encode(&mut buf);
        let decoded = StrippedBlock::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.header, stripped.header);
        assert!(decoded.transactions.is_empty());
    }

    #[test]
    fn stripped_block_split_preserves_tx_payload() {
        let signed = make_signed_tx();
        let block = Block {
            header: sample_header(),
            transactions: vec![signed.clone()],
            proposer_seal: None,
        };

        let (stripped, bundle) = StrippedBlock::split(&block);

        assert_eq!(stripped.transactions.len(), 1);
        assert_eq!(bundle.witnesses.len(), 1);
        // Sender and tx fields preserved in stripped body
        assert_eq!(stripped.transactions[0].from, signed.from);
        assert_eq!(stripped.transactions[0].tx, signed.tx);
        // Witness carries the signature and pubkey
        assert!(bundle.witnesses[0].has_pubkey());
    }

    #[test]
    fn stripped_block_reconstruct_full_roundtrip() {
        let signed = make_signed_tx();
        let original = Block {
            header: sample_header(),
            transactions: vec![signed],
            proposer_seal: None,
        };

        let (stripped, bundle) = StrippedBlock::split(&original);
        let reconstructed = stripped.into_block(Some(bundle));

        assert_eq!(reconstructed.header, original.header);
        assert_eq!(reconstructed.transactions.len(), 1);
        assert_eq!(reconstructed.transactions[0].from, original.transactions[0].from);
        assert_eq!(reconstructed.transactions[0].tx, original.transactions[0].tx);
        assert_eq!(
            reconstructed.transactions[0].signature,
            original.transactions[0].signature
        );
    }

    #[test]
    fn stripped_block_no_witness_returns_stub_sig() {
        let signed = make_signed_tx();
        let original = Block {
            header: sample_header(),
            transactions: vec![signed.clone()],
            proposer_seal: None,
        };

        let (stripped, _bundle) = StrippedBlock::split(&original);
        // Reconstruct without witness (simulates STARK-compressed block)
        let stub_block = stripped.into_block(None);

        assert_eq!(stub_block.transactions.len(), 1);
        // Payload preserved
        assert_eq!(stub_block.transactions[0].from, signed.from);
        assert_eq!(stub_block.transactions[0].tx, signed.tx);
        // Signature is an empty stub
        assert!(stub_block.transactions[0].signature.data.is_empty());
    }
}
