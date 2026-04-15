use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_crypto::{PQSignature, SignatureType};
use shell_primitives::{Address, Bytes, ShellHash, U256};
use std::sync::OnceLock;

/// EIP-2930 access list entry: an address and its pre-warmed storage keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccessListItem {
    /// Account address to pre-warm.
    pub address: Address,
    /// Storage keys to pre-warm for this address.
    pub storage_keys: Vec<ShellHash>,
}

/// EIP-4844: maximum number of blob hashes per transaction.
pub const MAX_BLOB_HASHES_PER_TX: usize = 6;

/// An unsigned transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    /// Recipient address. `None` means contract creation.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    /// EIP-2930 access list. Pre-warms account and storage slot access.
    /// None means no access list (legacy behavior).
    #[serde(default)]
    pub access_list: Option<Vec<AccessListItem>>,
    /// EIP-2718 transaction type (0=legacy, 1=access list, 2=EIP-1559, 3=blob).
    #[serde(default = "default_tx_type")]
    pub tx_type: u8,
    /// EIP-4844 max fee per blob gas (only for type 3 transactions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_blob_gas: Option<u64>,
    /// EIP-4844 blob versioned hashes (only for type 3 transactions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_versioned_hashes: Option<Vec<ShellHash>>,
}

fn default_tx_type() -> u8 {
    2
}

impl Encodable for Transaction {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        self.chain_id.encode(out);
        self.nonce.encode(out);
        // Ethereum convention: None → empty bytes, Some → 20-byte address
        match &self.to {
            Some(addr) => addr.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        self.value.encode(out);
        self.data.encode(out);
        self.gas_limit.encode(out);
        self.max_fee_per_gas.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        // EIP-2930 access list (encoded as list of [address, [keys...]])
        self.encode_access_list(out);
        // EIP-4844 fields
        self.tx_type.encode(out);
        // Use flag byte: 0 = None, 1 = Some (preserves Some(0) round-trip)
        match &self.max_fee_per_blob_gas {
            Some(fee) => {
                1u8.encode(out);
                fee.encode(out);
            }
            None => {
                0u8.encode(out);
                0u64.encode(out);
            }
        }
        self.encode_blob_hashes(out);
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

/// Maximum number of entries in an access list.
pub const MAX_ACCESS_LIST_ENTRIES: usize = 256;
/// Maximum number of storage keys per access list entry.
pub const MAX_ACCESS_LIST_STORAGE_KEYS: usize = 512;

impl Transaction {
    /// RLP-encode the access list as a list of [address, [key, key, ...]].
    fn encode_access_list(&self, out: &mut dyn alloy_rlp::BufMut) {
        match &self.access_list {
            None => {
                // Empty list
                let header = alloy_rlp::Header {
                    list: true,
                    payload_length: 0,
                };
                header.encode(out);
            }
            Some(items) => {
                // Calculate total payload length
                let payload: usize = items
                    .iter()
                    .map(|item| {
                        let keys_payload: usize =
                            item.storage_keys.iter().map(|k| k.length()).sum();
                        let keys_list_len = alloy_rlp::Header {
                            list: true,
                            payload_length: keys_payload,
                        }
                        .length()
                        .saturating_add(keys_payload);
                        let entry_payload = item.address.length().saturating_add(keys_list_len);
                        alloy_rlp::Header {
                            list: true,
                            payload_length: entry_payload,
                        }
                        .length()
                        .saturating_add(entry_payload)
                    })
                    .sum();
                let header = alloy_rlp::Header {
                    list: true,
                    payload_length: payload,
                };
                header.encode(out);
                for item in items {
                    let keys_payload: usize = item.storage_keys.iter().map(|k| k.length()).sum();
                    let keys_list_len = alloy_rlp::Header {
                        list: true,
                        payload_length: keys_payload,
                    }
                    .length()
                    .saturating_add(keys_payload);
                    let entry_payload = item.address.length().saturating_add(keys_list_len);
                    let entry_header = alloy_rlp::Header {
                        list: true,
                        payload_length: entry_payload,
                    };
                    entry_header.encode(out);
                    item.address.encode(out);
                    let keys_header = alloy_rlp::Header {
                        list: true,
                        payload_length: keys_payload,
                    };
                    keys_header.encode(out);
                    for key in &item.storage_keys {
                        key.encode(out);
                    }
                }
            }
        }
    }

    fn access_list_rlp_len(&self) -> usize {
        match &self.access_list {
            None => alloy_rlp::Header {
                list: true,
                payload_length: 0,
            }
            .length(),
            Some(items) => {
                let payload: usize = items
                    .iter()
                    .map(|item| {
                        let keys_payload: usize =
                            item.storage_keys.iter().map(|k| k.length()).sum();
                        let keys_list_len = alloy_rlp::Header {
                            list: true,
                            payload_length: keys_payload,
                        }
                        .length()
                        .saturating_add(keys_payload);
                        let entry_payload = item.address.length().saturating_add(keys_list_len);
                        alloy_rlp::Header {
                            list: true,
                            payload_length: entry_payload,
                        }
                        .length()
                        .saturating_add(entry_payload)
                    })
                    .sum();
                alloy_rlp::Header {
                    list: true,
                    payload_length: payload,
                }
                .length()
                .saturating_add(payload)
            }
        }
    }

    fn fields_len(&self) -> usize {
        let to_len = match &self.to {
            Some(addr) => addr.length(),
            None => 1, // RLP encoding of empty bytes
        };
        let blob_fee_len = match &self.max_fee_per_blob_gas {
            Some(fee) => 1u8.length().saturating_add(fee.length()),
            None => 0u8.length().saturating_add(0u64.length()),
        };
        self.chain_id
            .length()
            .saturating_add(self.nonce.length())
            .saturating_add(to_len)
            .saturating_add(self.value.length())
            .saturating_add(self.data.length())
            .saturating_add(self.gas_limit.length())
            .saturating_add(self.max_fee_per_gas.length())
            .saturating_add(self.max_priority_fee_per_gas.length())
            .saturating_add(self.access_list_rlp_len())
            .saturating_add(self.tx_type.length())
            .saturating_add(blob_fee_len)
            .saturating_add(self.blob_hashes_rlp_len())
    }

    /// Validate access list size limits.
    pub fn validate_access_list(&self) -> Result<(), &'static str> {
        if let Some(ref items) = self.access_list {
            if items.len() > MAX_ACCESS_LIST_ENTRIES {
                return Err("access list exceeds maximum entry count");
            }
            for item in items {
                if item.storage_keys.len() > MAX_ACCESS_LIST_STORAGE_KEYS {
                    return Err("access list entry exceeds maximum storage key count");
                }
            }
        }
        Ok(())
    }

    /// Validate EIP-4844 blob transaction fields.
    /// Type 3 transactions must have 1..=6 blob hashes and a max_fee_per_blob_gas.
    pub fn validate_blob_tx(&self) -> Result<(), &'static str> {
        if self.tx_type == 3 {
            let hashes = self
                .blob_versioned_hashes
                .as_ref()
                .ok_or("blob tx (type 3) must have blob_versioned_hashes")?;
            if hashes.is_empty() {
                return Err("blob tx must have at least 1 blob hash");
            }
            if hashes.len() > MAX_BLOB_HASHES_PER_TX {
                return Err("blob tx exceeds maximum blob hash count (6)");
            }
            if self.max_fee_per_blob_gas.is_none() {
                return Err("blob tx must have max_fee_per_blob_gas");
            }
            if self.to.is_none() {
                return Err("blob tx cannot be a contract creation");
            }
        }
        Ok(())
    }

    /// RLP-encode the blob versioned hashes as a list of hashes.
    fn encode_blob_hashes(&self, out: &mut dyn alloy_rlp::BufMut) {
        match &self.blob_versioned_hashes {
            None => {
                let header = alloy_rlp::Header {
                    list: true,
                    payload_length: 0,
                };
                header.encode(out);
            }
            Some(hashes) => {
                let payload: usize = hashes.iter().map(|h| h.length()).sum();
                let header = alloy_rlp::Header {
                    list: true,
                    payload_length: payload,
                };
                header.encode(out);
                for hash in hashes {
                    hash.encode(out);
                }
            }
        }
    }

    fn blob_hashes_rlp_len(&self) -> usize {
        match &self.blob_versioned_hashes {
            None => alloy_rlp::Header {
                list: true,
                payload_length: 0,
            }
            .length(),
            Some(hashes) => {
                let payload: usize = hashes.iter().map(|h| h.length()).sum();
                alloy_rlp::Header {
                    list: true,
                    payload_length: payload,
                }
                .length()
                .saturating_add(payload)
            }
        }
    }

    /// Compute the signing hash (keccak256 of the RLP-encoded transaction).
    pub fn hash(&self) -> ShellHash {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        shell_primitives::keccak256(&buf)
    }

    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }
}

/// A transaction with an attached PQ signature.
///
/// PQ signatures (unlike ECDSA) do not allow public key recovery from the
/// signature alone. The sender must explicitly declare their address so
/// nodes can look up the account and verify the signature.
///
/// The optional `sender_pubkey` field implements the **Hybrid registration**
/// model: the first transaction from a new address carries the full PQ
/// public key (~1952 bytes for Dilithium3). Subsequent transactions omit it,
/// and the pubkey is read from the on-chain registry.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The sender's address (derived from their PQ public key).
    /// Required because PQ signatures are not recoverable.
    pub from: Address,
    pub tx: Transaction,
    pub signature: PQSignature,
    /// Optional full PQ public key for first-time registration.
    /// If present, the node registers it on-chain after verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_pubkey: Option<Vec<u8>>,
    /// Lazily cached hash — computed from the unsigned tx on first access.
    #[serde(skip)]
    tx_hash: OnceLock<ShellHash>,
}

impl Clone for SignedTransaction {
    fn clone(&self) -> Self {
        let lock = OnceLock::new();
        if let Some(&h) = self.tx_hash.get() {
            let _ = lock.set(h);
        }
        Self {
            from: self.from,
            tx: self.tx.clone(),
            signature: self.signature.clone(),
            sender_pubkey: self.sender_pubkey.clone(),
            tx_hash: lock,
        }
    }
}

impl PartialEq for SignedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.from == other.from
            && self.tx == other.tx
            && self.signature == other.signature
            && self.sender_pubkey == other.sender_pubkey
    }
}

impl Eq for SignedTransaction {}

impl SignedTransaction {
    pub fn new(from: Address, tx: Transaction, signature: PQSignature) -> Self {
        Self {
            from,
            tx,
            signature,
            sender_pubkey: None,
            tx_hash: OnceLock::new(),
        }
    }

    /// Create a signed transaction with an attached public key for
    /// first-time registration on the PQ pubkey registry.
    pub fn with_pubkey(
        from: Address,
        tx: Transaction,
        signature: PQSignature,
        pubkey: Vec<u8>,
    ) -> Self {
        Self {
            from,
            tx,
            signature,
            sender_pubkey: Some(pubkey),
            tx_hash: OnceLock::new(),
        }
    }

    /// Transaction hash (excludes signature data and sender).
    /// Cached after first computation via `OnceLock`.
    pub fn hash(&self) -> ShellHash {
        *self.tx_hash.get_or_init(|| self.tx.hash())
    }

    pub fn sig_type(&self) -> SignatureType {
        self.signature.sig_type
    }

    pub fn sender(&self) -> Address {
        self.from
    }
}

impl Encodable for SignedTransaction {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        self.from.encode(out);
        self.tx.encode(out);
        self.signature.encode(out);
        // Encode sender_pubkey: Some(bytes) → bytes, None → empty bytes
        match &self.sender_pubkey {
            Some(pk) => pk.as_slice().encode(out),
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

impl SignedTransaction {
    fn fields_len(&self) -> usize {
        let pk_len = match &self.sender_pubkey {
            Some(pk) => pk.as_slice().length(),
            None => 1, // RLP encoding of empty bytes
        };
        self.from
            .length()
            .saturating_add(self.tx.length())
            .saturating_add(self.signature.length())
            .saturating_add(pk_len)
    }
}

impl Decodable for Transaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let chain_id = u64::decode(buf)?;
        let nonce = u64::decode(buf)?;

        // to: empty bytes → None, 20-byte address → Some
        let to_raw = alloy_rlp::Header::decode_bytes(buf, false)?;
        let to = if to_raw.is_empty() {
            None
        } else if to_raw.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(to_raw);
            Some(Address::from(arr))
        } else {
            return Err(alloy_rlp::Error::Custom("invalid 'to' address length"));
        };

        let value = U256::decode(buf)?;
        let data = Bytes::decode(buf)?;
        let gas_limit = u64::decode(buf)?;
        let max_fee_per_gas = u64::decode(buf)?;
        let max_priority_fee_per_gas = u64::decode(buf)?;
        let access_list = Self::decode_access_list(buf)?;

        // EIP-4844 fields
        let tx_type = u8::decode(buf)?;
        let blob_fee_flag = u8::decode(buf)?;
        let blob_fee_raw = u64::decode(buf)?;
        let max_fee_per_blob_gas = if blob_fee_flag == 1 {
            Some(blob_fee_raw)
        } else {
            None
        };
        let blob_versioned_hashes = Self::decode_blob_hashes(buf)?;

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            chain_id,
            nonce,
            to,
            value,
            data,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
            tx_type,
            max_fee_per_blob_gas,
            blob_versioned_hashes,
        })
    }
}

impl Transaction {
    fn decode_access_list(buf: &mut &[u8]) -> alloy_rlp::Result<Option<Vec<AccessListItem>>> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if header.payload_length == 0 {
            return Ok(None);
        }
        let end = buf.len().saturating_sub(header.payload_length);
        let mut items = Vec::new();
        while buf.len() > end {
            let entry_header = alloy_rlp::Header::decode(buf)?;
            if !entry_header.list {
                return Err(alloy_rlp::Error::UnexpectedString);
            }
            let address = Address::decode(buf)?;
            let keys_header = alloy_rlp::Header::decode(buf)?;
            if !keys_header.list {
                return Err(alloy_rlp::Error::UnexpectedString);
            }
            let keys_end = buf.len().saturating_sub(keys_header.payload_length);
            let mut storage_keys = Vec::new();
            while buf.len() > keys_end {
                storage_keys.push(ShellHash::decode(buf)?);
            }
            items.push(AccessListItem {
                address,
                storage_keys,
            });
        }
        Ok(Some(items))
    }

    fn decode_blob_hashes(buf: &mut &[u8]) -> alloy_rlp::Result<Option<Vec<ShellHash>>> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if header.payload_length == 0 {
            return Ok(None);
        }
        let end = buf.len().saturating_sub(header.payload_length);
        let mut hashes = Vec::new();
        while buf.len() > end {
            hashes.push(ShellHash::decode(buf)?);
        }
        Ok(Some(hashes))
    }
}

impl Decodable for SignedTransaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let from = Address::decode(buf)?;
        let tx = Transaction::decode(buf)?;
        let signature = PQSignature::decode(buf)?;

        // sender_pubkey: empty bytes → None, non-empty → Some
        let pk_bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        let sender_pubkey = if pk_bytes.is_empty() {
            None
        } else {
            Some(pk_bytes.to_vec())
        };

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            from,
            tx,
            signature,
            sender_pubkey,
            tx_hash: OnceLock::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> Transaction {
        Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::from(1000),
            data: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    }

    #[test]
    fn tx_hash_deterministic() {
        let tx = sample_tx();
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn tx_hash_changes_with_nonce() {
        let tx1 = sample_tx();
        let mut tx2 = sample_tx();
        tx2.nonce = 1;
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn signed_tx_hash_excludes_signature() {
        let tx = sample_tx();
        let hash_before = tx.hash();
        let from = Address::from([0x42; 20]);

        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(from, tx, sig);

        assert_eq!(signed.hash(), hash_before);
        assert_eq!(signed.sender(), from);
    }

    #[test]
    fn contract_creation_tx() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: None,
            value: U256::ZERO,
            data: Bytes::from(vec![0x60, 0x80]),
            gas_limit: 1_000_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        assert!(tx.is_contract_creation());

        // Hash differs from a regular transfer
        let transfer = sample_tx();
        assert_ne!(tx.hash(), transfer.hash());
    }

    #[test]
    fn tx_serde_roundtrip() {
        let tx = sample_tx();
        let json = serde_json::to_string(&tx).unwrap();
        let tx2: Transaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx, tx2);
    }

    #[test]
    fn contract_creation_rlp_to_none_encoding() {
        // F-015: Verify to: None produces shorter RLP (0x80) vs 21-byte address
        let tx_with_to = sample_tx();
        let mut buf_with = Vec::new();
        tx_with_to.encode(&mut buf_with);

        let tx_none = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: None,
            value: U256::from(1000),
            data: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let mut buf_none = Vec::new();
        tx_none.encode(&mut buf_none);

        // to: None encodes as 0x80 (1 byte) vs to: Some → 21 bytes
        assert!(buf_none.len() < buf_with.len());
        // The hashes must differ
        assert_ne!(
            shell_primitives::keccak256(&buf_with),
            shell_primitives::keccak256(&buf_none),
        );
    }

    #[test]
    fn signed_tx_hash_cached_via_oncelock() {
        let tx = sample_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(from, tx, sig);

        // First call computes and caches
        let h1 = signed.hash();
        // Second call returns cached value
        let h2 = signed.hash();
        assert_eq!(h1, h2);

        // Deserialized version also works (OnceLock starts empty)
        let json = serde_json::to_string(&signed).unwrap();
        let signed2: SignedTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(signed2.hash(), h1);
        assert_eq!(signed, signed2);
    }

    #[test]
    fn signed_tx_rlp_roundtrip() {
        let tx = sample_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let signed = SignedTransaction::new(from, tx, sig);

        let mut buf = Vec::new();
        signed.encode(&mut buf);
        assert!(!buf.is_empty());

        let decoded = SignedTransaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(signed, decoded);
    }

    #[test]
    fn tx_rlp_roundtrip() {
        let tx = sample_tx();
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = Transaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn tx_rlp_roundtrip_contract_creation() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: None,
            value: U256::ZERO,
            data: Bytes::from(vec![0x60, 0x80]),
            gas_limit: 1_000_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = Transaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn signed_tx_rlp_roundtrip_with_pubkey() {
        let tx = sample_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let signed = SignedTransaction::with_pubkey(from, tx, sig, vec![0xCC; 1952]);

        let mut buf = Vec::new();
        signed.encode(&mut buf);
        let decoded = SignedTransaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(signed, decoded);
    }

    // ── EIP-4844 blob transaction tests ────────────────────────

    #[test]
    fn blob_tx_valid() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![ShellHash::ZERO]),
        };
        assert!(tx.validate_blob_tx().is_ok());
    }

    #[test]
    fn blob_tx_missing_hashes() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: None,
        };
        assert!(tx.validate_blob_tx().is_err());
    }

    #[test]
    fn blob_tx_empty_hashes() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![]),
        };
        assert_eq!(
            tx.validate_blob_tx().unwrap_err(),
            "blob tx must have at least 1 blob hash"
        );
    }

    #[test]
    fn blob_tx_too_many_hashes() {
        let hashes = vec![ShellHash::ZERO; 7];
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(hashes),
        };
        assert_eq!(
            tx.validate_blob_tx().unwrap_err(),
            "blob tx exceeds maximum blob hash count (6)"
        );
    }

    #[test]
    fn blob_tx_missing_fee() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: Some(vec![ShellHash::ZERO]),
        };
        assert_eq!(
            tx.validate_blob_tx().unwrap_err(),
            "blob tx must have max_fee_per_blob_gas"
        );
    }

    #[test]
    fn blob_tx_no_contract_creation() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: None,
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![ShellHash::ZERO]),
        };
        assert_eq!(
            tx.validate_blob_tx().unwrap_err(),
            "blob tx cannot be a contract creation"
        );
    }

    #[test]
    fn non_blob_tx_skips_validation() {
        let tx = sample_tx(); // type 2
        assert!(tx.validate_blob_tx().is_ok());
    }

    #[test]
    fn blob_tx_rlp_encodes() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![ShellHash::ZERO, ShellHash::ZERO]),
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        assert!(!buf.is_empty());
        // Hash is deterministic
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn blob_tx_hash_differs_from_regular() {
        let regular = sample_tx();
        let blob = Transaction {
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![ShellHash::ZERO]),
            ..regular.clone()
        };
        assert_ne!(regular.hash(), blob.hash());
    }

    #[test]
    fn blob_tx_serde_roundtrip() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![ShellHash::ZERO]),
        };
        let json = serde_json::to_string(&tx).unwrap();
        let tx2: Transaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx, tx2);
    }

    #[test]
    fn blob_tx_max_six_hashes_ok() {
        let hashes = vec![ShellHash::ZERO; 6];
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(hashes),
        };
        assert!(tx.validate_blob_tx().is_ok());
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: Transaction type serialization/deserialization tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn tx_type0_legacy_rlp_roundtrip() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::from(1000),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 0,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = Transaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
        assert_eq!(decoded.tx_type, 0);
    }

    #[test]
    fn tx_type1_access_list_rlp_roundtrip() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 5,
            to: Some(Address::from([0x02; 20])),
            value: U256::from(500),
            data: Bytes::from(vec![0xAA, 0xBB]),
            gas_limit: 50_000,
            max_fee_per_gas: 30,
            max_priority_fee_per_gas: 2,
            access_list: Some(vec![AccessListItem {
                address: Address::from([0xCC; 20]),
                storage_keys: vec![ShellHash::from([0x11; 32]), ShellHash::from([0x22; 32])],
            }]),
            tx_type: 1,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = Transaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
        assert_eq!(decoded.tx_type, 1);
        assert_eq!(decoded.access_list.as_ref().unwrap().len(), 1);
        assert_eq!(
            decoded.access_list.as_ref().unwrap()[0].storage_keys.len(),
            2
        );
    }

    #[test]
    fn tx_type2_eip1559_rlp_roundtrip() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 10,
            to: Some(Address::from([0x03; 20])),
            value: U256::from(1_000_000),
            data: Bytes::from(vec![0x60, 0x80]),
            gas_limit: 100_000,
            max_fee_per_gas: 50,
            max_priority_fee_per_gas: 5,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = Transaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
        assert_eq!(decoded.tx_type, 2);
        assert_eq!(decoded.max_fee_per_gas, 50);
        assert_eq!(decoded.max_priority_fee_per_gas, 5);
    }

    #[test]
    fn tx_type3_blob_rlp_roundtrip() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 20,
            to: Some(Address::from([0x04; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(5_000_000),
            blob_versioned_hashes: Some(vec![
                ShellHash::from([0xAA; 32]),
                ShellHash::from([0xBB; 32]),
            ]),
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = Transaction::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
        assert_eq!(decoded.tx_type, 3);
        assert_eq!(decoded.max_fee_per_blob_gas, Some(5_000_000));
        assert_eq!(decoded.blob_versioned_hashes.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn tx_type0_serde_roundtrip() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::from(1000),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 0,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn tx_type1_serde_roundtrip() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 5,
            to: Some(Address::from([0x02; 20])),
            value: U256::from(500),
            data: Bytes::from(vec![0xAA]),
            gas_limit: 50_000,
            max_fee_per_gas: 30,
            max_priority_fee_per_gas: 2,
            access_list: Some(vec![AccessListItem {
                address: Address::from([0xCC; 20]),
                storage_keys: vec![ShellHash::from([0x11; 32])],
            }]),
            tx_type: 1,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn tx_hash_unique_per_type() {
        let base = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x01; 20])),
            value: U256::from(1000),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 0,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let type0 = base.clone();
        let type1 = Transaction {
            tx_type: 1,
            ..base.clone()
        };
        let type2 = Transaction {
            tx_type: 2,
            ..base.clone()
        };
        let type3 = Transaction {
            tx_type: 3,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![ShellHash::ZERO]),
            ..base
        };

        let h0 = type0.hash();
        let h1 = type1.hash();
        let h2 = type2.hash();
        let h3 = type3.hash();

        assert_ne!(h0, h1, "type 0 and type 1 hashes must differ");
        assert_ne!(h0, h2, "type 0 and type 2 hashes must differ");
        assert_ne!(h0, h3, "type 0 and type 3 hashes must differ");
        assert_ne!(h1, h2, "type 1 and type 2 hashes must differ");
        assert_ne!(h1, h3, "type 1 and type 3 hashes must differ");
        assert_ne!(h2, h3, "type 2 and type 3 hashes must differ");
    }

    #[test]
    fn signed_tx_hash_consistent_across_types() {
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);

        for tx_type in [0u8, 1, 2, 3] {
            let tx = Transaction {
                chain_id: 1337,
                nonce: 0,
                to: Some(Address::from([0x01; 20])),
                value: U256::from(1000),
                data: Bytes::new(),
                gas_limit: 21_000,
                max_fee_per_gas: 20,
                max_priority_fee_per_gas: 1,
                access_list: if tx_type >= 1 {
                    Some(vec![AccessListItem {
                        address: Address::from([0xDD; 20]),
                        storage_keys: vec![],
                    }])
                } else {
                    None
                },
                tx_type,
                max_fee_per_blob_gas: if tx_type == 3 { Some(1_000_000) } else { None },
                blob_versioned_hashes: if tx_type == 3 {
                    Some(vec![ShellHash::ZERO])
                } else {
                    None
                },
            };
            let signed = SignedTransaction::new(from, tx, sig.clone());
            let h1 = signed.hash();
            let h2 = signed.hash();
            assert_eq!(h1, h2, "hash for type {tx_type} must be deterministic");
        }
    }

    #[test]
    fn signed_tx_rlp_roundtrip_all_types() {
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 100]);

        for tx_type in [0u8, 1, 2, 3] {
            let tx = Transaction {
                chain_id: 1337,
                nonce: tx_type as u64,
                to: Some(Address::from([0x01; 20])),
                value: U256::from(1000),
                data: Bytes::from(vec![0xCC]),
                gas_limit: 21_000,
                max_fee_per_gas: 20,
                max_priority_fee_per_gas: 1,
                access_list: if tx_type >= 1 {
                    Some(vec![AccessListItem {
                        address: Address::from([0xDD; 20]),
                        storage_keys: vec![ShellHash::from([0xEE; 32])],
                    }])
                } else {
                    None
                },
                tx_type,
                max_fee_per_blob_gas: if tx_type == 3 { Some(1_000_000) } else { None },
                blob_versioned_hashes: if tx_type == 3 {
                    Some(vec![ShellHash::from([0xFF; 32])])
                } else {
                    None
                },
            };
            let signed = SignedTransaction::new(from, tx, sig.clone());
            let mut buf = Vec::new();
            signed.encode(&mut buf);
            let decoded = SignedTransaction::decode(&mut buf.as_slice()).unwrap();
            assert_eq!(
                signed, decoded,
                "RLP roundtrip failed for tx type {tx_type}"
            );
        }
    }

    #[test]
    fn tx_type_affects_contract_creation_hash() {
        let t2 = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: None,
            value: U256::ZERO,
            data: Bytes::from(vec![0x60, 0x80]),
            gas_limit: 100_000,
            max_fee_per_gas: 20,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let t0 = Transaction {
            tx_type: 0,
            ..t2.clone()
        };
        assert_ne!(
            t0.hash(),
            t2.hash(),
            "contract creation hashes should differ by type"
        );
    }
}
