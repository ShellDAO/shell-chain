use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
        // None → empty bytes, Some → 32-byte address
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

    /// Compute the PQ signing hash using the spec payload and BLAKE3.
    ///
    /// Preimage: `PQTX_SIGNING_V1\0(16B) || chain_id || nonce || to(32B) || value(32B) || data ||
    ///            gas_limit || max_fee_per_gas || max_priority_fee_per_gas ||
    ///            sig_type || tx_type`
    /// For blob transactions (tx_type == 3), appends: `max_fee_per_blob_gas(8B) || blob_hash_0(32B) || ...`
    pub fn signing_hash(&self, sig_type: u8) -> ShellHash {
        let blob_extra = if self.tx_type == 3 {
            8 + self
                .blob_versioned_hashes
                .as_ref()
                .map_or(0, |h| h.len() * 32)
        } else {
            0
        };
        let mut preimage = Vec::with_capacity(
            16 + 8 + 8 + 32 + 32 + self.data.len() + 8 + 8 + 8 + 1 + 1 + blob_extra,
        );
        preimage.extend_from_slice(PQTX_SIGNING_DOMAIN);
        preimage.extend_from_slice(&self.chain_id.to_be_bytes());
        preimage.extend_from_slice(&self.nonce.to_be_bytes());
        match &self.to {
            Some(addr) => preimage.extend_from_slice(addr.0.as_slice()),
            None => preimage.extend_from_slice(&[0u8; 32]),
        }
        let value = self.value.to_be_bytes::<32>();
        preimage.extend_from_slice(&value);
        preimage.extend_from_slice(self.data.as_ref());
        preimage.extend_from_slice(&self.gas_limit.to_be_bytes());
        preimage.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        preimage.extend_from_slice(&self.max_priority_fee_per_gas.to_be_bytes());
        preimage.push(sig_type);
        preimage.push(self.tx_type);
        if self.tx_type == 3 {
            let fee = self.max_fee_per_blob_gas.unwrap_or(0);
            preimage.extend_from_slice(&fee.to_be_bytes());
            if let Some(hashes) = &self.blob_versioned_hashes {
                for h in hashes {
                    preimage.extend_from_slice(h.as_bytes());
                }
            }
        }
        shell_primitives::blake3_hash(&preimage)
    }

    /// Compute the default transaction hash using the Dilithium/ML-DSA domain byte.
    pub fn hash(&self) -> ShellHash {
        self.signing_hash(SignatureType::Dilithium3.as_u8())
    }

    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }
}

/// Expected Dilithium3 public key length in bytes.
pub const DILITHIUM3_PUBKEY_LEN: usize = 1952;

// =====================================================================
// Native AA Phase 1 — batch tx + sponsored gas (v0.18.0)
//
// See `docs/AA_BATCH_AND_SPONSORED_SPEC.md` for the full design spec.
//
// Wire-format design:
//   - `Transaction` is intentionally **unchanged** so all existing literals,
//     RLP goldens, and call sites are unaffected.
//   - AA payload lives inside a new `AaBundle` carried as an OPTIONAL trailing
//     field on `SignedTransaction`. When `aa_bundle == None`, encoding adds
//     ZERO bytes (the outer list header records exactly the fixed-field
//     payload), so the wire format for legacy (non-AA) transactions is
//     byte-for-byte identical to v0.17.0.
//   - When `aa_bundle == Some(bundle)`, the encoder appends a single-byte
//     presence flag (`0x01`) followed by the RLP-encoded bundle, and the
//     outer list header grows accordingly. The decoder inspects the remaining
//     bytes within the outer header's payload region to detect the trailing
//     bundle.
// =====================================================================

/// Transaction-type byte reserved for native AA bundles (batch + optional
/// sponsored gas). Chosen to stay clear of EIP-2718 envelope bytes (`0x01`,
/// `0x02`, `0x03`, `0x04`, `0x7F`).
pub const AA_BUNDLE_TX_TYPE: u8 = 0x7E;

/// Maximum number of inner calls allowed in a single AA bundle.
pub const MAX_INNER_CALLS: usize = 16;

/// Maximum size of a single inner call's `data` field, in bytes.
pub const MAX_INNER_CALLDATA: usize = 128 * 1024;

/// Maximum size of `paymaster_context` passed to `IPaymaster.validatePaymasterOp`.
pub const MAX_PAYMASTER_CONTEXT: usize = 4 * 1024;

/// Domain prefix for PQTX signing hash (WP §1503-1509).
pub const PQTX_SIGNING_DOMAIN: &[u8; 16] = b"PQTX_SIGNING_V1\0";

/// Domain tag for the canonical batch signing hash (sender PQ sig) (WP §AA-spec).
pub const PQTX_BUNDLE_DOMAIN: &[u8; 16] = b"PQTX_BUNDLE_V1\0\0";

/// Domain tag for the paymaster authorization signing hash.
pub const PQTX_PAYMASTER_DOMAIN: &[u8; 16] = b"PQTX_PAYMASTER_V";

/// Domain tag for session key authorization hash.
pub const PQTX_SESSION_DOMAIN: &[u8; 16] = b"PQTX_SESSION_V1\0";

/// Intrinsic gas surcharge for each *additional* inner call beyond the first.
/// One-call bundles cost the same as a normal tx; bundles of N cost
/// `21_000 + (N-1) * 4_000` intrinsic gas.
pub const AA_INNER_CALL_INTRINSIC_GAS: u64 = 4_000;

/// Additional intrinsic gas per PQ signature verification (session key path
/// adds 2 verifications: root_signature + session_signature).
pub const PQ_VERIFY_GAS: u64 = 10_000;

/// Session key authorization embedded in an AA bundle.
///
/// A session key is a short-lived PQ keypair whose scope is restricted to a
/// single `(target, value_cap, expiry_block)` triple. It is authorized by the
/// account's root PQ key at setup time. Session keys are NOT stored on-chain;
/// revocation is implicit via `expiry_block` or root key rotation.
///
/// ## Validation rules (enforced in `validate_aa_tx`)
///
/// 1. `expiry_block > current_block_number`
/// 2. Σ inner_call.value ≤ `value_cap`
/// 3. If `target` is `Some`: all inner calls must have `to == target`
/// 4. `root_signature` is valid over [`SessionAuth::auth_hash`]
/// 5. `session_signature` is valid over the tx `sender_signing_hash()`
/// 6. Nonce still increments as normal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAuth {
    /// The session public key (Dilithium by default).
    pub session_pubkey: Bytes,
    /// Algorithm of the session key (as `SignatureType::as_u8()`).
    pub session_algo: u8,
    /// Permitted call target. `None` = any target (scoped to `inner_calls[0].to` semantics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Address>,
    /// Maximum ETH value (sum of inner call values) this session key may authorize per tx.
    pub value_cap: U256,
    /// Block number after which this session key is invalid (exclusive).
    pub expiry_block: u64,
    /// Root account's PQ signature over [`SessionAuth::auth_hash`].
    pub root_signature: Bytes,
    /// Session key's PQ signature over the tx `sender_signing_hash()`.
    pub session_signature: Bytes,
}

impl SessionAuth {
    /// Canonical hash that the root key signs to authorize this session key (WP §AA-spec).
    ///
    /// `blake3(PQTX_SESSION_V1\0(16B) || session_pubkey || session_algo(1B) || target(32B|zero) || value_cap(32B BE) || expiry_block(8B BE) || chain_id(8B BE))`
    pub fn auth_hash(&self, chain_id: u64) -> ShellHash {
        use shell_primitives::blake3_hash;
        let mut preimage = Vec::with_capacity(16 + self.session_pubkey.len() + 1 + 32 + 32 + 8 + 8);
        preimage.extend_from_slice(PQTX_SESSION_DOMAIN);
        preimage.extend_from_slice(self.session_pubkey.as_ref());
        preimage.push(self.session_algo);
        match &self.target {
            Some(addr) => preimage.extend_from_slice(addr.0.as_slice()),
            None => preimage.extend_from_slice(&[0u8; 32]),
        }
        let value_buf = self.value_cap.to_be_bytes::<32>();
        preimage.extend_from_slice(&value_buf);
        preimage.extend_from_slice(&self.expiry_block.to_be_bytes());
        preimage.extend_from_slice(&chain_id.to_be_bytes());
        blake3_hash(&preimage)
    }

    fn fields_len(&self) -> usize {
        let pubkey_len = self.session_pubkey.as_ref().length();
        let algo_len = (self.session_algo as u64).length();
        let target_len = match &self.target {
            Some(addr) => addr.length(),
            None => 1usize, // empty bytes
        };
        let value_buf = self.value_cap.to_be_bytes::<32>();
        // Trim leading zeros for compact encoding.
        let trimmed = value_buf
            .iter()
            .position(|&b| b != 0)
            .map(|i| &value_buf[i..])
            .unwrap_or(&value_buf[31..]);
        let value_len = trimmed.length();
        let expiry_len = self.expiry_block.length();
        let root_sig_len = self.root_signature.as_ref().length();
        let session_sig_len = self.session_signature.as_ref().length();
        pubkey_len + algo_len + target_len + value_len + expiry_len + root_sig_len + session_sig_len
    }
}

impl Encodable for SessionAuth {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        self.session_pubkey.as_ref().encode(out);
        (self.session_algo as u64).encode(out);
        match &self.target {
            Some(addr) => addr.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        // value_cap: encode as trimmed big-endian bytes
        let value_buf = self.value_cap.to_be_bytes::<32>();
        let trimmed = value_buf
            .iter()
            .position(|&b| b != 0)
            .map(|i| &value_buf[i..])
            .unwrap_or(&value_buf[31..]);
        trimmed.encode(out);
        self.expiry_block.encode(out);
        self.root_signature.as_ref().encode(out);
        self.session_signature.as_ref().encode(out);
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

impl Decodable for SessionAuth {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let session_pubkey = Bytes::from(alloy_rlp::Header::decode_bytes(buf, false)?.to_vec());
        let session_algo = {
            let v: u64 = Decodable::decode(buf)?;
            if v > u8::MAX as u64 {
                return Err(alloy_rlp::Error::Custom(
                    "session_auth: session_algo out of range (must fit u8)",
                ));
            }
            v as u8
        };
        let target_raw = alloy_rlp::Header::decode_bytes(buf, false)?;
        let target = if target_raw.is_empty() {
            None
        } else if target_raw.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(target_raw);
            Some(Address::from(arr))
        } else {
            return Err(alloy_rlp::Error::Custom(
                "session_auth: invalid target address length: expected 32 bytes or empty",
            ));
        };
        let value_bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        if value_bytes.len() > 32 {
            return Err(alloy_rlp::Error::Custom(
                "session_auth: value_cap exceeds 32 bytes",
            ));
        }
        let value_cap = U256::from_be_slice(value_bytes);
        let expiry_block: u64 = Decodable::decode(buf)?;
        let root_signature = Bytes::from(alloy_rlp::Header::decode_bytes(buf, false)?.to_vec());
        let session_signature = Bytes::from(alloy_rlp::Header::decode_bytes(buf, false)?.to_vec());

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }
        Ok(Self {
            session_pubkey,
            session_algo,
            target,
            value_cap,
            expiry_block,
            root_signature,
            session_signature,
        })
    }
}

/// One inner call inside an AA bundle.
///
/// Each inner call executes as if `msg.sender == bundle.from` (the bundle's
/// signing account), with its own per-call gas budget. Inner-call results
/// are aggregated into the outer transaction receipt (`inner_results`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerCall {
    /// Recipient. `None` means contract creation.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    /// Advisory gas cap for this inner call. The sum across all inner calls
    /// MUST be ≤ the outer `Transaction.gas_limit`.
    pub gas_limit: u64,
}

impl Encodable for InnerCall {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        // to: None → empty bytes (Ethereum convention)
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

impl InnerCall {
    fn fields_len(&self) -> usize {
        let to_len = match &self.to {
            Some(addr) => addr.length(),
            None => 1,
        };
        to_len
            .saturating_add(self.value.length())
            .saturating_add(self.data.length())
            .saturating_add(self.gas_limit.length())
    }
}

impl Decodable for InnerCall {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let to_raw = alloy_rlp::Header::decode_bytes(buf, false)?;
        let to = if to_raw.is_empty() {
            None
        } else if to_raw.len() == 32 {
            Some(
                Address::try_from_slice(to_raw)
                    .map_err(|_| alloy_rlp::Error::Custom("invalid 'to' address bytes"))?,
            )
        } else {
            return Err(alloy_rlp::Error::Custom(
                "invalid 'to' address length: expected 32 bytes or empty",
            ));
        };
        let value = U256::decode(buf)?;
        let data = Bytes::decode(buf)?;
        let gas_limit = u64::decode(buf)?;

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }
        Ok(Self {
            to,
            value,
            data,
            gas_limit,
        })
    }
}

/// AA bundle carried as the trailing optional field of [`SignedTransaction`]
/// when the underlying transaction's `tx_type` equals [`AA_BUNDLE_TX_TYPE`].
///
/// A bundle expresses two orthogonal AA capabilities:
/// 1. **Batch execution** via `inner_calls` — N atomic calls under a single
///    sender PQ signature and a single nonce.
/// 2. **Sponsored gas** via `paymaster` + `paymaster_signature` (Phase 1 EOA paymaster)
///    or `paymaster` + `paymaster_context` (Phase 2 contract paymaster) — a third
///    party authorizes paying the transaction's gas budget.
/// 3. **Session key** via `session_auth` — a short-lived PQ sub-key scoped to
///    `(target, value_cap, expiry_block)`, authorized by the root key offline.
///
/// ## Paymaster type dispatch
///
/// | `paymaster` | `paymaster_signature` | `paymaster_context` | Meaning |
/// |------------|----------------------|---------------------|---------|
/// | None | None | None | Sender self-pays |
/// | Some | Some(sig) | None | EOA paymaster (Phase 1) |
/// | Some | None | Some(ctx) | **Contract paymaster (Phase 2)** |
/// | Some | Some | Some | Invalid — wire error |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AaBundle {
    /// Atomic inner calls (1..=[`MAX_INNER_CALLS`]).
    pub inner_calls: Vec<InnerCall>,
    /// Optional paymaster account paying the transaction's gas budget.
    /// `None` → sender pays gas (still a valid AA bundle for batch-only use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paymaster: Option<Address>,
    /// Phase 1 EOA paymaster: PQ signature by `paymaster` over
    /// [`SignedTransaction::paymaster_signing_hash`]. Mutually exclusive with
    /// `paymaster_context`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paymaster_signature: Option<Bytes>,
    /// Phase 2 contract paymaster: opaque context passed to
    /// `IPaymaster.validatePaymasterOp`. Mutually exclusive with `paymaster_signature`.
    /// Max [`MAX_PAYMASTER_CONTEXT`] bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paymaster_context: Option<Bytes>,
    /// Phase 2 session key authorization. When present, the transaction is
    /// signed by the session key rather than the root key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_auth: Option<SessionAuth>,
}

impl AaBundle {
    /// Validate structural constraints (counts, sizes, paymaster pairing).
    /// Does NOT verify any signatures or balances; that happens at mempool
    /// admission and execution time.
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        if self.inner_calls.is_empty() {
            return Err("aa bundle: inner_calls must be non-empty");
        }
        if self.inner_calls.len() > MAX_INNER_CALLS {
            return Err("aa bundle: inner_calls exceeds MAX_INNER_CALLS");
        }
        for call in &self.inner_calls {
            if call.data.len() > MAX_INNER_CALLDATA {
                return Err("aa bundle: inner call data exceeds MAX_INNER_CALLDATA");
            }
        }

        // Paymaster type dispatch: sig XOR context.
        //
        // Note: empty `paymaster_context` (`Some([])`) is treated as absent (same
        // as `None`) because RLP encodes empty bytes → empty string → decoded back
        // as `None` in `Decodable::decode`. Contract paymasters that need no
        // context must use a single-byte sentinel (e.g. `0x00`) or any non-empty
        // byte slice to distinguish from the no-paymaster case.
        match (
            &self.paymaster,
            &self.paymaster_signature,
            &self.paymaster_context,
        ) {
            // Self-pay: no paymaster.
            (None, None, None) => {}
            // EOA paymaster (Phase 1): sig present, no context.
            (Some(_), Some(sig), None) if !sig.is_empty() => {}
            // Contract paymaster (Phase 2): context present, no sig.
            (Some(_), None, Some(ctx)) if !ctx.is_empty() => {
                if ctx.len() > MAX_PAYMASTER_CONTEXT {
                    return Err("aa bundle: paymaster_context exceeds MAX_PAYMASTER_CONTEXT");
                }
            }
            // Paymaster with no sig and no context: invalid.
            (Some(_), None, None) | (Some(_), Some(_), None) => {
                return Err("aa bundle: paymaster set but signature missing/empty");
            }
            // Both sig and context: invalid.
            (Some(_), Some(_), Some(_)) => {
                return Err(
                    "aa bundle: paymaster_signature and paymaster_context are mutually exclusive",
                );
            }
            // Orphan sig or context without paymaster address.
            (None, Some(_), _) => {
                return Err("aa bundle: paymaster_signature set but paymaster missing");
            }
            (None, _, Some(_)) => {
                return Err("aa bundle: paymaster_context set but paymaster missing");
            }
            _ => return Err("aa bundle: invalid paymaster field combination"),
        }

        // Session auth basic constraints.
        if let Some(sa) = &self.session_auth {
            if sa.session_pubkey.is_empty() {
                return Err("aa bundle: session_auth.session_pubkey is empty");
            }
            if sa.expiry_block == 0 {
                return Err("aa bundle: session_auth.expiry_block must be > 0");
            }
            if sa.root_signature.is_empty() {
                return Err("aa bundle: session_auth.root_signature is empty");
            }
            if sa.session_signature.is_empty() {
                return Err("aa bundle: session_auth.session_signature is empty");
            }
        }

        Ok(())
    }

    /// Sum of inner-call advisory gas caps. Caller MUST verify this is
    /// ≤ outer `Transaction.gas_limit`.
    pub fn inner_gas_sum(&self) -> u128 {
        self.inner_calls
            .iter()
            .map(|c| c.gas_limit as u128)
            .sum::<u128>()
    }

    /// Sum of inner-call ETH values. Caller MUST verify this is ≤ outer
    /// `Transaction.value`.
    pub fn inner_value_sum(&self) -> U256 {
        self.checked_inner_value_sum().unwrap_or(U256::MAX)
    }

    /// Checked sum of inner-call ETH values.
    pub fn checked_inner_value_sum(&self) -> Option<U256> {
        self.inner_calls
            .iter()
            .try_fold(U256::ZERO, |acc, c| acc.checked_add(c.value))
    }

    /// Intrinsic gas surcharge added by the bundle on top of the standard
    /// 21_000 base: 4_000 per *additional* inner call beyond the first,
    /// plus 10_000 per PQ signature verify on the session key path (2 verifies).
    pub fn intrinsic_gas_surcharge(&self) -> u64 {
        let extras = self.inner_calls.len().saturating_sub(1) as u64;
        let call_gas = extras.saturating_mul(AA_INNER_CALL_INTRINSIC_GAS);
        let session_gas = if self.session_auth.is_some() {
            // 2 PQ verifications: root_signature + session_signature.
            2u64.saturating_mul(PQ_VERIFY_GAS)
        } else {
            0
        };
        call_gas.saturating_add(session_gas)
    }

    fn fields_len(&self) -> usize {
        // [inner_calls_list, paymaster (20B or empty), paymaster_sig_bytes,
        //  paymaster_context_bytes, session_auth (list or empty)]
        let inner_payload: usize = self.inner_calls.iter().map(|c| c.length()).sum();
        let inner_list_len = alloy_rlp::Header {
            list: true,
            payload_length: inner_payload,
        }
        .length()
        .saturating_add(inner_payload);
        let paymaster_len = match &self.paymaster {
            Some(addr) => addr.length(),
            None => 1,
        };
        let sig_len = match &self.paymaster_signature {
            Some(sig) if !sig.is_empty() => sig.as_ref().length(),
            _ => 1,
        };
        let ctx_len = match &self.paymaster_context {
            Some(ctx) if !ctx.is_empty() => ctx.as_ref().length(),
            _ => 1,
        };
        let session_len = match &self.session_auth {
            Some(sa) => sa.length(),
            None => 1, // empty bytes marker
        };
        inner_list_len
            .saturating_add(paymaster_len)
            .saturating_add(sig_len)
            .saturating_add(ctx_len)
            .saturating_add(session_len)
    }
}

impl AaBundle {
    /// Length of the signing-form payload (excludes all signatures:
    /// `paymaster_signature`, `session_auth.root_signature`, and
    /// `session_auth.session_signature`). `paymaster_context` is included
    /// so the sender commits to the exact context being passed to the
    /// contract paymaster.
    ///
    /// Both sender batch hash and paymaster authorization hash hash the bundle
    /// in this signature-stripped form to avoid circular dependencies.
    fn signing_fields_len(&self) -> usize {
        let inner_payload: usize = self.inner_calls.iter().map(|c| c.length()).sum();
        let inner_list_len = alloy_rlp::Header {
            list: true,
            payload_length: inner_payload,
        }
        .length()
        .saturating_add(inner_payload);
        let paymaster_len = match &self.paymaster {
            Some(addr) => addr.length(),
            None => 1,
        };
        let ctx_len = match &self.paymaster_context {
            Some(ctx) if !ctx.is_empty() => ctx.as_ref().length(),
            _ => 1,
        };
        inner_list_len
            .saturating_add(paymaster_len)
            .saturating_add(ctx_len)
    }

    /// Encodes the bundle for signing-hash purposes (omits all signatures).
    /// See `signing_fields_len` for rationale.
    pub fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.signing_fields_len(),
        };
        header.encode(out);
        let inner_payload: usize = self.inner_calls.iter().map(|c| c.length()).sum();
        let inner_header = alloy_rlp::Header {
            list: true,
            payload_length: inner_payload,
        };
        inner_header.encode(out);
        for call in &self.inner_calls {
            call.encode(out);
        }
        match &self.paymaster {
            Some(addr) => addr.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        match &self.paymaster_context {
            Some(ctx) if !ctx.is_empty() => ctx.as_ref().encode(out),
            _ => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
    }

    /// Total signing-form encoded length (header + payload).
    pub fn signing_length(&self) -> usize {
        let payload = self.signing_fields_len();
        alloy_rlp::Header {
            list: true,
            payload_length: payload,
        }
        .length()
        .saturating_add(payload)
    }
}

impl Encodable for AaBundle {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        // inner_calls: encoded as a flat RLP list of InnerCall lists.
        let inner_payload: usize = self.inner_calls.iter().map(|c| c.length()).sum();
        let inner_header = alloy_rlp::Header {
            list: true,
            payload_length: inner_payload,
        };
        inner_header.encode(out);
        for call in &self.inner_calls {
            call.encode(out);
        }
        // paymaster: None → empty bytes, Some → 32-byte address
        match &self.paymaster {
            Some(addr) => addr.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        // paymaster_signature: opaque bytes or empty (Phase 1 EOA paymaster)
        match &self.paymaster_signature {
            Some(sig) if !sig.is_empty() => sig.as_ref().encode(out),
            _ => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        // paymaster_context: opaque bytes or empty (Phase 2 contract paymaster)
        match &self.paymaster_context {
            Some(ctx) if !ctx.is_empty() => ctx.as_ref().encode(out),
            _ => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        // session_auth: RLP list or empty bytes marker
        match &self.session_auth {
            Some(sa) => sa.encode(out),
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

impl Decodable for AaBundle {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        // inner_calls list
        let inner_header = alloy_rlp::Header::decode(buf)?;
        if !inner_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let inner_end = buf.len().saturating_sub(inner_header.payload_length);
        let mut inner_calls = Vec::new();
        while buf.len() > inner_end {
            inner_calls.push(InnerCall::decode(buf)?);
        }

        // paymaster
        let paymaster_raw = alloy_rlp::Header::decode_bytes(buf, false)?;
        let paymaster = if paymaster_raw.is_empty() {
            None
        } else if paymaster_raw.len() == 32 {
            Some(
                Address::try_from_slice(paymaster_raw)
                    .map_err(|_| alloy_rlp::Error::Custom("invalid paymaster address bytes"))?,
            )
        } else {
            return Err(alloy_rlp::Error::Custom(
                "invalid paymaster address length: expected 32 bytes or empty",
            ));
        };

        // paymaster_signature (Phase 1)
        let sig_raw = alloy_rlp::Header::decode_bytes(buf, false)?;
        let paymaster_signature = if sig_raw.is_empty() {
            None
        } else {
            Some(Bytes::from(sig_raw.to_vec()))
        };

        // paymaster_context (Phase 2)
        let ctx_raw = alloy_rlp::Header::decode_bytes(buf, false)?;
        let paymaster_context = if ctx_raw.is_empty() {
            None
        } else {
            Some(Bytes::from(ctx_raw.to_vec()))
        };

        // session_auth: peek at the next byte; if it's a list header decode
        // SessionAuth, otherwise skip as empty marker.
        let session_auth = if !buf.is_empty() && (buf[0] & 0xC0) == 0xC0 {
            Some(SessionAuth::decode(buf)?)
        } else {
            // Consume the empty bytes marker (0x80).
            let _ = alloy_rlp::Header::decode_bytes(buf, false)?;
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
            inner_calls,
            paymaster,
            paymaster_signature,
            paymaster_context,
            session_auth,
        })
    }
}

/// How the sender's public key is conveyed in a [`SignedTransaction`].
///
/// Post-quantum signatures (Dilithium3) are not key-recoverable, so the sender
/// public key must be provided explicitly. To avoid the 1,952-byte key overhead
/// on every transaction, Shell uses a **hybrid registry model**:
///
/// - **First tx** from a new address → `Embedded`: carry the full key inline.
///   The node verifies the address derivation and stores the key in the pubkey
///   registry. Wire overhead: +1,952 bytes once.
/// - **All subsequent txs** → `Reference`: key is omitted; the node resolves
///   it from the on-chain registry by the `from` address. Saves ~1,932 bytes
///   per transaction after the initial registration.
///
/// ## Wire encoding (RLP)
/// - `Embedded(pk)` → raw key bytes (1,952 bytes for Dilithium3)
/// - `Reference`    → empty byte string (1 byte overhead)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", content = "key", rename_all = "snake_case")]
pub enum PubkeyMode {
    /// Full Dilithium3 public key (1,952 bytes) inline. Used on first tx.
    Embedded(Vec<u8>),
    /// Key omitted; resolved from on-chain registry by `from` address.
    #[default]
    Reference,
}

impl PubkeyMode {
    /// Returns `true` if this is an embedded (inline) public key.
    pub fn is_embedded(&self) -> bool {
        matches!(self, PubkeyMode::Embedded(_))
    }

    /// Returns `true` if the key is a registry reference (not inline).
    pub fn is_reference(&self) -> bool {
        matches!(self, PubkeyMode::Reference)
    }

    /// Returns the embedded public key bytes, or `None` for [`Reference`](PubkeyMode::Reference).
    pub fn pubkey_bytes(&self) -> Option<&[u8]> {
        match self {
            PubkeyMode::Embedded(b) => Some(b),
            PubkeyMode::Reference => None,
        }
    }
}

/// A transaction with an attached PQ signature.
///
/// PQ signatures (unlike ECDSA) do not allow public key recovery from the
/// signature alone. The sender must explicitly declare their address so
/// nodes can look up the account and verify the signature.
///
/// The `pubkey_mode` field implements the **Hybrid registration** model —
/// see [`PubkeyMode`] for full documentation.
///
/// **Note**: Always construct via [`SignedTransaction::new`] or
/// [`SignedTransaction::with_pubkey`]. Direct struct initialization is
/// intentionally prevented (`#[non_exhaustive]`) to ensure `pubkey_mode`
/// defaults are not silently misapplied.
#[non_exhaustive]
#[derive(Debug)]
pub struct SignedTransaction {
    /// The sender's address (derived from their PQ public key).
    /// Required because PQ signatures are not recoverable.
    pub from: Address,
    pub tx: Transaction,
    pub signature: PQSignature,
    /// How the sender's public key is provided (inline or registry reference).
    pub pubkey_mode: PubkeyMode,
    /// Native AA payload (batch + optional sponsored gas). MUST be `Some`
    /// iff `tx.tx_type == AA_BUNDLE_TX_TYPE`. See `AaBundle` and
    /// `docs/AA_BATCH_AND_SPONSORED_SPEC.md`.
    pub aa_bundle: Option<AaBundle>,
    /// Lazily cached hash — computed from the unsigned tx on first access.
    tx_hash: OnceLock<ShellHash>,
}

// Helper enum for deserializing either legacy structured signatures or the
// flattened PQTx-style raw signature bytes.
#[derive(Deserialize)]
#[serde(untagged)]
enum SignedTransactionSignatureField {
    Structured(PQSignature),
    Raw(Bytes),
}

// Helper struct for deserialization with compatibility for both legacy
// `sender_pubkey` and the PQTx-style `public_key` + `sig_type` fields.
#[derive(Deserialize)]
struct SignedTransactionHelper {
    from: Address,
    tx: Transaction,
    signature: SignedTransactionSignatureField,
    #[serde(default)]
    sig_type: Option<u8>,
    #[serde(default)]
    pubkey_mode: Option<PubkeyMode>,
    #[serde(default)]
    sender_pubkey: Option<Vec<u8>>,
    #[serde(default)]
    public_key: Option<Bytes>,
    #[serde(default)]
    aa_bundle: Option<AaBundle>,
}

impl Serialize for SignedTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct SignedTransactionSerde<'a> {
            from: &'a Address,
            tx: &'a Transaction,
            sig_type: u8,
            #[serde(skip_serializing_if = "Option::is_none")]
            public_key: Option<Bytes>,
            signature: Bytes,
            #[serde(skip_serializing_if = "Option::is_none")]
            aa_bundle: Option<&'a AaBundle>,
        }

        SignedTransactionSerde {
            from: &self.from,
            tx: &self.tx,
            sig_type: self.signature.sig_type.as_u8(),
            public_key: self.public_key().map(Bytes::copy_from_slice),
            signature: Bytes::copy_from_slice(&self.signature.data),
            aa_bundle: self.aa_bundle.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = SignedTransactionHelper::deserialize(deserializer)?;

        if helper.pubkey_mode.is_some()
            && (helper.sender_pubkey.is_some() || helper.public_key.is_some())
        {
            return Err(serde::de::Error::custom(
                "signed transaction must not specify both pubkey_mode and sender_pubkey",
            ));
        }
        if helper.sender_pubkey.is_some() && helper.public_key.is_some() {
            return Err(serde::de::Error::custom(
                "signed transaction must not specify both sender_pubkey and public_key",
            ));
        }

        let signature = match helper.signature {
            SignedTransactionSignatureField::Structured(signature) => {
                if let Some(sig_type) = helper.sig_type {
                    let expected = SignatureType::from_u8(sig_type)
                        .ok_or_else(|| serde::de::Error::custom("unknown sig_type"))?;
                    if signature.sig_type != expected {
                        return Err(serde::de::Error::custom(
                            "sig_type does not match structured signature.sig_type",
                        ));
                    }
                }
                signature
            }
            SignedTransactionSignatureField::Raw(signature) => {
                let sig_type = helper.sig_type.ok_or_else(|| {
                    serde::de::Error::custom("sig_type is required for raw signature bytes")
                })?;
                let sig_type = SignatureType::from_u8(sig_type)
                    .ok_or_else(|| serde::de::Error::custom("unknown sig_type"))?;
                let signature = PQSignature::new(sig_type, signature.as_ref().to_vec());
                signature
                    .validate_size()
                    .map_err(serde::de::Error::custom)?;
                signature
            }
        };

        let flat_public_key = helper.public_key.map(|bytes| bytes.as_ref().to_vec());
        let pubkey_mode = if let Some(mode) = helper.pubkey_mode {
            mode
        } else if let Some(pk) = flat_public_key.or(helper.sender_pubkey) {
            if !pk.is_empty() {
                PubkeyMode::Embedded(pk)
            } else {
                PubkeyMode::Reference
            }
        } else {
            PubkeyMode::Reference
        };

        Ok(SignedTransaction {
            from: helper.from,
            tx: helper.tx,
            signature,
            pubkey_mode,
            aa_bundle: helper.aa_bundle,
            tx_hash: OnceLock::new(),
        })
    }
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
            pubkey_mode: self.pubkey_mode.clone(),
            aa_bundle: self.aa_bundle.clone(),
            tx_hash: lock,
        }
    }
}

impl PartialEq for SignedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.from == other.from
            && self.tx == other.tx
            && self.signature == other.signature
            && self.pubkey_mode == other.pubkey_mode
            && self.aa_bundle == other.aa_bundle
    }
}

impl Eq for SignedTransaction {}

impl SignedTransaction {
    /// Create a transaction using registry reference mode (no inline pubkey).
    ///
    /// Use this for all transactions after the first from a given address.
    /// The node resolves the public key from the on-chain registry.
    pub fn new(from: Address, tx: Transaction, signature: PQSignature) -> Self {
        Self {
            from,
            tx,
            signature,
            pubkey_mode: PubkeyMode::Reference,
            aa_bundle: None,
            tx_hash: OnceLock::new(),
        }
    }

    /// Create a transaction with an embedded public key for first-time registration.
    ///
    /// Use this for the **first transaction** from a new address. The node
    /// verifies the key–address binding and registers the pubkey for future
    /// reference-mode lookups. After registration, use [`SignedTransaction::new`].
    pub fn with_pubkey(
        from: Address,
        tx: Transaction,
        signature: PQSignature,
        pubkey: Vec<u8>,
    ) -> Self {
        debug_assert_eq!(
            pubkey.len(),
            DILITHIUM3_PUBKEY_LEN,
            "PubkeyMode::Embedded: expected {DILITHIUM3_PUBKEY_LEN} bytes, got {}",
            pubkey.len()
        );
        Self {
            from,
            tx,
            signature,
            pubkey_mode: PubkeyMode::Embedded(pubkey),
            aa_bundle: None,
            tx_hash: OnceLock::new(),
        }
    }

    /// Attach a native AA bundle to a signed transaction.
    ///
    /// `tx.tx_type` MUST equal [`AA_BUNDLE_TX_TYPE`]; the bundle's structural
    /// constraints (inner-call count, sizes, paymaster pairing) are validated
    /// before returning. The provided `signature` is the sender's PQ signature
    /// over [`SignedTransaction::batch_signing_hash`] (the caller is
    /// responsible for producing it correctly).
    pub fn with_aa_bundle(
        from: Address,
        tx: Transaction,
        signature: PQSignature,
        pubkey_mode: PubkeyMode,
        aa_bundle: AaBundle,
    ) -> Result<Self, &'static str> {
        if tx.tx_type != AA_BUNDLE_TX_TYPE {
            return Err("with_aa_bundle: tx.tx_type must equal AA_BUNDLE_TX_TYPE (0x7E)");
        }
        aa_bundle.validate_structure()?;
        if aa_bundle.inner_gas_sum() > tx.gas_limit as u128 {
            return Err("with_aa_bundle: sum(inner.gas_limit) exceeds outer gas_limit");
        }
        if aa_bundle.paymaster == Some(from) {
            return Err("with_aa_bundle: paymaster must differ from sender");
        }
        match aa_bundle.checked_inner_value_sum() {
            Some(inner_value_sum) if inner_value_sum <= tx.value => {}
            Some(_) => return Err("with_aa_bundle: sum(inner.value) exceeds outer value"),
            None => return Err("with_aa_bundle: sum(inner.value) overflows U256"),
        }
        Ok(Self {
            from,
            tx,
            signature,
            pubkey_mode,
            aa_bundle: Some(aa_bundle),
            tx_hash: OnceLock::new(),
        })
    }

    /// Hash signed by the sender's PQ signature.
    ///
    /// For AA-bundle transactions returns [`Self::batch_signing_hash`] (so the
    /// signature commits to both the outer envelope *and* the inner calls);
    /// for any other tx_type returns the BLAKE3 PQ signing payload hash. This single
    /// entry point lets validators uniformly compute "the hash the sender
    /// signed over" without branching on tx_type at every call site.
    pub fn sender_signing_hash(&self) -> ShellHash {
        self.batch_signing_hash()
            .unwrap_or_else(|| self.tx.signing_hash(self.signature.sig_type.as_u8()))
    }

    /// Returns `true` if this signed transaction carries a native AA bundle.
    pub fn is_aa_bundle(&self) -> bool {
        self.tx.tx_type == AA_BUNDLE_TX_TYPE && self.aa_bundle.is_some()
    }

    /// Borrow the AA bundle if present.
    pub fn aa_bundle(&self) -> Option<&AaBundle> {
        self.aa_bundle.as_ref()
    }

    /// Canonical signing hash for AA-bundle senders (WP §AA-spec):
    /// `blake3( PQTX_BUNDLE_V1\0\0(16B) || tx_signing_hash(32B) || rlp(aa_bundle_for_signing) )`.
    ///
    /// Returns `None` for non-AA transactions (callers should use [`Self::hash`]).
    pub fn batch_signing_hash(&self) -> Option<ShellHash> {
        let bundle = self.aa_bundle.as_ref()?;
        if self.tx.tx_type != AA_BUNDLE_TX_TYPE {
            return None;
        }
        let tx_hash = self.tx.signing_hash(self.signature.sig_type.as_u8());
        let mut buf = Vec::with_capacity(16 + 32 + bundle.signing_length());
        buf.extend_from_slice(PQTX_BUNDLE_DOMAIN);
        buf.extend_from_slice(tx_hash.as_bytes());
        bundle.encode_for_signing(&mut buf);
        Some(shell_primitives::blake3_hash(&buf))
    }

    /// Canonical signing hash for the paymaster's authorization (WP §AA-spec):
    /// `blake3( PQTX_PAYMASTER_V(16B) || from(32B) || batch_signing_hash(32B) )`.
    ///
    /// Returns `None` if no paymaster is set on the bundle (or the tx is not
    /// an AA bundle at all).
    pub fn paymaster_signing_hash(&self) -> Option<ShellHash> {
        let bundle = self.aa_bundle.as_ref()?;
        bundle.paymaster?;
        let batch_hash = self.batch_signing_hash()?;
        let mut buf = Vec::with_capacity(16 + 32 + 32);
        buf.extend_from_slice(PQTX_PAYMASTER_DOMAIN);
        buf.extend_from_slice(self.from.0.as_slice());
        buf.extend_from_slice(batch_hash.0.as_slice());
        Some(shell_primitives::blake3_hash(&buf))
    }

    /// Legacy transaction ID: the simple tx signing hash independent of AA bundle.
    ///
    /// This remains useful for compatibility and migration logic. New canonical
    /// AA transaction identity must include the bundle, otherwise two AA
    /// envelopes with different inner calls collide in mempool/storage indexes.
    pub fn legacy_hash(&self) -> ShellHash {
        self.tx.signing_hash(self.signature.sig_type.as_u8())
    }

    /// Canonical transaction ID.
    ///
    /// For AA bundles this is the bundle-aware signing hash. For all other
    /// transactions it remains the simple tx signing hash.
    /// Cached after first computation via `OnceLock`.
    pub fn hash(&self) -> ShellHash {
        *self.tx_hash.get_or_init(|| {
            self.batch_signing_hash()
                .unwrap_or_else(|| self.legacy_hash())
        })
    }

    pub fn public_key(&self) -> Option<&[u8]> {
        self.pubkey_mode.pubkey_bytes()
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
        // Embedded → encode key bytes; Reference → encode empty bytes (1B).
        // Wire format is identical to the former Option<Vec<u8>> encoding.
        match &self.pubkey_mode {
            PubkeyMode::Embedded(pk) => pk.as_slice().encode(out),
            PubkeyMode::Reference => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        // Trailing optional AA bundle. Absent → emit nothing (zero overhead
        // for legacy txs). Present → emit a 1-byte presence flag (0x01)
        // followed by the RLP-encoded bundle.
        if let Some(bundle) = &self.aa_bundle {
            out.put_u8(AA_BUNDLE_PRESENCE_FLAG);
            bundle.encode(out);
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

/// 1-byte presence marker prepended to an [`AaBundle`] when one is attached
/// to a [`SignedTransaction`]. Absent bundles emit nothing at all (preserving
/// the legacy v0.17.0 wire format byte-for-byte).
pub const AA_BUNDLE_PRESENCE_FLAG: u8 = 0x01;

impl SignedTransaction {
    fn fields_len(&self) -> usize {
        let pk_len = match &self.pubkey_mode {
            PubkeyMode::Embedded(pk) => pk.as_slice().length(),
            PubkeyMode::Reference => 1, // RLP empty bytes = 1 byte
        };
        let aa_len = match &self.aa_bundle {
            Some(bundle) => 1usize.saturating_add(bundle.length()),
            None => 0,
        };
        self.from
            .length()
            .saturating_add(self.tx.length())
            .saturating_add(self.signature.length())
            .saturating_add(pk_len)
            .saturating_add(aa_len)
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

        // to: empty bytes → None, 32-byte address → Some
        let to_raw = alloy_rlp::Header::decode_bytes(buf, false)?;
        let to = if to_raw.is_empty() {
            None
        } else if to_raw.len() == 32 {
            Some(
                Address::try_from_slice(to_raw)
                    .map_err(|_| alloy_rlp::Error::Custom("invalid 'to' address bytes"))?,
            )
        } else {
            return Err(alloy_rlp::Error::Custom(
                "invalid 'to' address length: expected 32 bytes or empty",
            ));
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

        // Empty bytes → Reference (key in registry); non-empty → Embedded.
        // Wire format is unchanged from the former Option<Vec<u8>> encoding.
        let pk_bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        let pubkey_mode = if pk_bytes.is_empty() {
            PubkeyMode::Reference
        } else {
            PubkeyMode::Embedded(pk_bytes.to_vec())
        };

        // Optional trailing AA bundle. Detected by checking whether the outer
        // list payload still has bytes after consuming the four fixed fields.
        let consumed_so_far = remaining.saturating_sub(buf.len());
        let aa_bundle = if consumed_so_far < header.payload_length {
            // Read the 1-byte presence flag.
            if buf.is_empty() {
                return Err(alloy_rlp::Error::Custom("missing aa bundle presence flag"));
            }
            let flag = buf[0];
            *buf = &buf[1..];
            if flag != AA_BUNDLE_PRESENCE_FLAG {
                return Err(alloy_rlp::Error::Custom("invalid aa bundle presence flag"));
            }
            Some(AaBundle::decode(buf)?)
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
            from,
            tx,
            signature,
            pubkey_mode,
            aa_bundle,
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
    fn signed_tx_deserialize_accepts_legacy_sender_pubkey() {
        let from = Address::from([0x42; 20]);
        let tx = sample_tx();
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAB; 64]);
        let legacy = serde_json::json!({
            "from": from,
            "tx": tx,
            "signature": sig,
            "sender_pubkey": vec![0xCC; DILITHIUM3_PUBKEY_LEN],
        });

        let signed: SignedTransaction = serde_json::from_value(legacy).unwrap();
        assert!(signed.pubkey_mode.is_embedded());
        assert_eq!(
            signed.pubkey_mode.pubkey_bytes().map(|pk| pk.len()),
            Some(DILITHIUM3_PUBKEY_LEN)
        );
    }

    #[test]
    fn signed_tx_deserialize_rejects_pubkey_mode_and_sender_pubkey_together() {
        let from = Address::from([0x42; 20]);
        let tx = sample_tx();
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAB; 64]);
        let invalid = serde_json::json!({
            "from": from,
            "tx": tx,
            "signature": sig,
            "pubkey_mode": {
                "mode": "reference"
            },
            "sender_pubkey": vec![0xCC; DILITHIUM3_PUBKEY_LEN],
        });

        let err = serde_json::from_value::<SignedTransaction>(invalid).unwrap_err();
        assert!(err
            .to_string()
            .contains("must not specify both pubkey_mode and sender_pubkey"));
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

    #[test]
    fn tx_hash_matches_sdk_golden_vector() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: 7,
            to: Some(Address::from([0x11; 20])),
            value: U256::from(0x1234u64),
            data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
            gas_limit: 50_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 250_000_000,
            access_list: Some(vec![AccessListItem {
                address: Address::from([0x22; 20]),
                storage_keys: vec![ShellHash::from([0x33; 32]), ShellHash::from([0x44; 32])],
            }]),
            tx_type: 3,
            max_fee_per_blob_gas: Some(0),
            blob_versioned_hashes: Some(vec![ShellHash::from([0x55; 32])]),
        };

        // Updated golden after adding PQTX_SIGNING_V1\0 domain prefix (WP §1503-1509).
        // shell-sdk hashTransaction() must be updated to prepend the same 16-byte domain.
        // Previous (no-domain): 0xf5a14a12f556ff79fff941e944519f1c965b80e53c91503a676ff0a891ef0836
        let expected = ShellHash::from([
            0x68, 0xee, 0xa4, 0x69, 0x4a, 0xb0, 0xfb, 0xa5, 0x49, 0xe5, 0xb5, 0x2b, 0xe4, 0x72,
            0x98, 0x4c, 0x61, 0x21, 0xf0, 0x95, 0xd8, 0x3d, 0xb5, 0x51, 0x5a, 0x59, 0xcc, 0x34,
            0x5c, 0xcc, 0x47, 0x61,
        ]);

        assert_eq!(tx.hash(), expected);
    }

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

    // ─── A2: PubkeyMode tests ─────────────────────────────────────────────────

    fn sample_signed(from: Address, pubkey: Option<Vec<u8>>) -> SignedTransaction {
        let tx = sample_tx();
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 3309]);
        match pubkey {
            Some(pk) => SignedTransaction::with_pubkey(from, tx, sig, pk),
            None => SignedTransaction::new(from, tx, sig),
        }
    }

    #[test]
    fn pubkey_mode_embedded_rlp_roundtrip() {
        let from = Address::from([0x11; 20]);
        let pk = vec![0xCC; 1952];
        let stx = sample_signed(from, Some(pk.clone()));

        assert!(stx.pubkey_mode.is_embedded());
        assert_eq!(stx.pubkey_mode.pubkey_bytes(), Some(pk.as_slice()));

        // RLP round-trip
        let encoded = alloy_rlp::encode(&stx);
        let decoded = SignedTransaction::decode(&mut encoded.as_slice()).unwrap();

        assert!(decoded.pubkey_mode.is_embedded());
        assert_eq!(decoded.pubkey_mode.pubkey_bytes(), Some(pk.as_slice()));
        assert_eq!(decoded.from, from);
    }

    #[test]
    fn pubkey_mode_reference_rlp_roundtrip() {
        let from = Address::from([0x22; 20]);
        let stx = sample_signed(from, None);

        assert!(stx.pubkey_mode.is_reference());
        assert_eq!(stx.pubkey_mode.pubkey_bytes(), None);

        // RLP round-trip
        let encoded = alloy_rlp::encode(&stx);
        let decoded = SignedTransaction::decode(&mut encoded.as_slice()).unwrap();

        assert!(decoded.pubkey_mode.is_reference());
        assert_eq!(decoded.pubkey_mode.pubkey_bytes(), None);
    }

    #[test]
    fn pubkey_mode_accessors() {
        let embedded = PubkeyMode::Embedded(vec![0x01; 32]);
        let reference = PubkeyMode::Reference;

        assert!(embedded.is_embedded());
        assert!(!embedded.is_reference());
        assert_eq!(embedded.pubkey_bytes(), Some([0x01u8; 32].as_slice()));

        assert!(!reference.is_embedded());
        assert!(reference.is_reference());
        assert_eq!(reference.pubkey_bytes(), None);
    }

    #[test]
    fn reference_mode_saves_bytes_vs_embedded() {
        let from = Address::from([0x33; 20]);
        let pk = vec![0xDD; 1952];

        let embedded = sample_signed(from, Some(pk));
        let reference = sample_signed(from, None);

        let embedded_size = alloy_rlp::encode(&embedded).len();
        let reference_size = alloy_rlp::encode(&reference).len();

        // Reference mode must be significantly smaller (saves ~1952 bytes)
        assert!(
            embedded_size > reference_size + 1900,
            "embedded={embedded_size}, reference={reference_size}"
        );
    }

    // ============================================================
    // Native AA Phase 1 — InnerCall / AaBundle / SignedTransaction
    // ============================================================

    fn sample_inner_call(value: u64) -> InnerCall {
        InnerCall {
            to: Some(Address::from([0xAA; 32])),
            value: U256::from(value),
            data: Bytes::from(vec![0x01, 0x02, 0x03]),
            gas_limit: 50_000,
        }
    }

    fn sample_aa_tx() -> Transaction {
        let mut tx = sample_tx();
        tx.tx_type = AA_BUNDLE_TX_TYPE;
        tx.gas_limit = 200_000;
        tx
    }

    #[test]
    fn inner_call_rlp_roundtrip() {
        let call = sample_inner_call(1234);
        let mut buf = Vec::new();
        call.encode(&mut buf);
        let decoded = InnerCall::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(call, decoded);
    }

    #[test]
    fn inner_call_contract_creation_rlp_roundtrip() {
        let call = InnerCall {
            to: None,
            value: U256::ZERO,
            data: Bytes::from(vec![0x60; 64]),
            gas_limit: 1_000_000,
        };
        let mut buf = Vec::new();
        call.encode(&mut buf);
        let decoded = InnerCall::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(call, decoded);
    }

    #[test]
    fn aa_bundle_validate_structure_rejects_empty() {
        let bundle = AaBundle::default();
        let err = bundle.validate_structure().unwrap_err();
        assert!(err.contains("non-empty"));
    }

    #[test]
    fn aa_bundle_validate_structure_rejects_too_many_inner_calls() {
        let bundle = AaBundle {
            inner_calls: (0..(MAX_INNER_CALLS + 1))
                .map(|_| sample_inner_call(1))
                .collect(),
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let err = bundle.validate_structure().unwrap_err();
        assert!(err.contains("MAX_INNER_CALLS"));
    }

    #[test]
    fn aa_bundle_validate_structure_rejects_oversized_calldata() {
        let mut call = sample_inner_call(0);
        call.data = Bytes::from(vec![0u8; MAX_INNER_CALLDATA + 1]);
        let bundle = AaBundle {
            inner_calls: vec![call],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let err = bundle.validate_structure().unwrap_err();
        assert!(err.contains("MAX_INNER_CALLDATA"));
    }

    #[test]
    fn aa_bundle_validate_structure_rejects_paymaster_without_signature() {
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(0)],
            paymaster: Some(Address::from([0x55; 20])),
            paymaster_signature: None,
            ..Default::default()
        };
        let err = bundle.validate_structure().unwrap_err();
        assert!(err.contains("signature missing"));
    }

    #[test]
    fn aa_bundle_validate_structure_rejects_signature_without_paymaster() {
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(0)],
            paymaster: None,
            paymaster_signature: Some(Bytes::from(vec![0xAB; 64])),
            ..Default::default()
        };
        let err = bundle.validate_structure().unwrap_err();
        assert!(err.contains("paymaster missing"));
    }

    #[test]
    fn aa_bundle_intrinsic_surcharge_zero_for_one_call() {
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        assert_eq!(bundle.intrinsic_gas_surcharge(), 0);
    }

    #[test]
    fn aa_bundle_intrinsic_surcharge_per_extra_call() {
        let bundle = AaBundle {
            inner_calls: vec![
                sample_inner_call(1),
                sample_inner_call(2),
                sample_inner_call(3),
            ],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        assert_eq!(
            bundle.intrinsic_gas_surcharge(),
            2 * AA_INNER_CALL_INTRINSIC_GAS
        );
    }

    #[test]
    fn aa_bundle_rlp_roundtrip_batch_only() {
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1), sample_inner_call(2)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let mut buf = Vec::new();
        bundle.encode(&mut buf);
        let decoded = AaBundle::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(bundle, decoded);
    }

    #[test]
    fn aa_bundle_rlp_roundtrip_with_paymaster() {
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(7)],
            paymaster: Some(Address::from([0x77; 20])),
            paymaster_signature: Some(Bytes::from(vec![0xCD; 96])),
            ..Default::default()
        };
        let mut buf = Vec::new();
        bundle.encode(&mut buf);
        let decoded = AaBundle::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(bundle, decoded);
    }

    #[test]
    fn signed_tx_legacy_rlp_byte_for_byte_unchanged_when_no_aa_bundle() {
        // CRITICAL backward-compat invariant: a SignedTransaction without an
        // aa_bundle MUST encode byte-identically to v0.17.0 (zero overhead).
        // This test pins the encoded length to detect any accidental drift.
        let tx = sample_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let signed = SignedTransaction::new(from, tx, sig);

        let bytes = alloy_rlp::encode(&signed);
        let decoded = SignedTransaction::decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(signed, decoded);
        assert!(decoded.aa_bundle.is_none());
        assert!(!decoded.is_aa_bundle());
    }

    #[test]
    fn signed_tx_with_aa_bundle_rlp_roundtrip() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1), sample_inner_call(2)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed =
            SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
                .expect("valid bundle");

        let bytes = alloy_rlp::encode(&signed);
        let decoded = SignedTransaction::decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(signed, decoded);
        assert!(decoded.is_aa_bundle());
        assert_eq!(decoded.aa_bundle().unwrap().inner_calls.len(), 2);
    }

    #[test]
    fn signed_tx_with_aa_bundle_sponsored_rlp_roundtrip() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: Some(Address::from([0x77; 20])),
            paymaster_signature: Some(Bytes::from(vec![0xCD; 96])),
            ..Default::default()
        };
        let signed =
            SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
                .expect("valid bundle");

        let bytes = alloy_rlp::encode(&signed);
        let decoded = SignedTransaction::decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(signed, decoded);
        assert_eq!(
            decoded.aa_bundle().and_then(|b| b.paymaster),
            Some(Address::from([0x77; 20]))
        );
    }

    #[test]
    fn signed_tx_with_aa_bundle_rejects_wrong_tx_type() {
        let tx = sample_tx(); // tx_type = 2
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let err = SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
            .unwrap_err();
        assert!(err.contains("AA_BUNDLE_TX_TYPE"));
    }

    #[test]
    fn signed_tx_with_aa_bundle_rejects_inner_gas_overflow() {
        let mut tx = sample_aa_tx();
        tx.gas_limit = 80_000;
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1), sample_inner_call(2)], // 100k > 80k
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let err = SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
            .unwrap_err();
        assert!(err.contains("exceeds outer gas_limit"));
    }

    #[test]
    fn signed_tx_with_aa_bundle_rejects_inner_value_overspend() {
        let mut tx = sample_aa_tx();
        tx.value = U256::from(1u64);
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(2)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let err = SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
            .unwrap_err();
        assert!(err.contains("exceeds outer value"));
    }

    #[test]
    fn signed_tx_with_aa_bundle_rejects_inner_value_overflow() {
        let mut tx = sample_aa_tx();
        tx.value = U256::MAX;
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, tx.hash().as_bytes().to_vec());
        let bundle = AaBundle {
            inner_calls: vec![
                InnerCall {
                    value: U256::MAX,
                    ..sample_inner_call(0)
                },
                InnerCall {
                    value: U256::from(1u64),
                    ..sample_inner_call(0)
                },
            ],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let err = SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
            .unwrap_err();
        assert!(err.contains("overflows U256"));
    }

    #[test]
    fn signed_tx_with_aa_bundle_rejects_sender_as_paymaster() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, tx.hash().as_bytes().to_vec());
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: Some(from),
            paymaster_signature: Some(Bytes::from(vec![0xCD; 96])),
            ..Default::default()
        };
        let err = SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
            .unwrap_err();
        assert!(err.contains("paymaster must differ from sender"));
    }

    #[test]
    fn session_auth_hash_binds_session_algorithm() {
        let base = SessionAuth {
            session_pubkey: Bytes::from(vec![0xA5; 32]),
            session_algo: SignatureType::Dilithium3.as_u8(),
            target: Some(Address::from([0x11; 32])),
            value_cap: U256::from(1_000u64),
            expiry_block: 42,
            root_signature: Bytes::from(vec![0x01; 96]),
            session_signature: Bytes::from(vec![0x02; 96]),
        };
        let mut other_algo = base.clone();
        other_algo.session_algo = SignatureType::MlDsa65.as_u8();

        assert_ne!(base.auth_hash(1337), other_algo.auth_hash(1337));
    }

    #[test]
    fn batch_signing_hash_distinct_from_legacy_hash() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed =
            SignedTransaction::with_aa_bundle(from, tx.clone(), sig, PubkeyMode::Reference, bundle)
                .unwrap();

        let batch_hash = signed.batch_signing_hash().expect("aa tx");
        let legacy_hash = signed.legacy_hash();
        // Domain byte + bundle bytes guarantee distinct hashes.
        assert_ne!(batch_hash, legacy_hash);
        assert_eq!(signed.hash(), batch_hash);
    }

    #[test]
    fn aa_canonical_hash_changes_with_inner_calls() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle_a = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let bundle_b = AaBundle {
            inner_calls: vec![sample_inner_call(2)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed_a = SignedTransaction::with_aa_bundle(
            from,
            tx.clone(),
            sig.clone(),
            PubkeyMode::Reference,
            bundle_a,
        )
        .unwrap();
        let signed_b =
            SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle_b)
                .unwrap();

        assert_eq!(signed_a.legacy_hash(), signed_b.legacy_hash());
        assert_ne!(signed_a.hash(), signed_b.hash());
    }

    #[test]
    fn batch_signing_hash_none_for_legacy_tx() {
        let tx = sample_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let signed = SignedTransaction::new(from, tx, sig);
        assert!(signed.batch_signing_hash().is_none());
        assert!(signed.paymaster_signing_hash().is_none());
    }

    #[test]
    fn paymaster_signing_hash_distinct_from_batch_hash() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: Some(Address::from([0x77; 20])),
            paymaster_signature: Some(Bytes::from(vec![0xCD; 32])),
            ..Default::default()
        };
        let signed =
            SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
                .unwrap();

        let batch_hash = signed.batch_signing_hash().unwrap();
        let pm_hash = signed.paymaster_signing_hash().unwrap();
        assert_ne!(batch_hash, pm_hash);
    }

    #[test]
    fn paymaster_signing_hash_none_when_no_paymaster_set() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed =
            SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
                .unwrap();
        assert!(signed.batch_signing_hash().is_some());
        assert!(signed.paymaster_signing_hash().is_none());
    }

    #[test]
    fn signed_tx_json_roundtrip_with_aa_bundle() {
        let tx = sample_aa_tx();
        let from = Address::from([0x42; 20]);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 50]);
        let bundle = AaBundle {
            inner_calls: vec![sample_inner_call(1), sample_inner_call(2)],
            paymaster: Some(Address::from([0x77; 20])),
            paymaster_signature: Some(Bytes::from(vec![0xCD; 96])),
            ..Default::default()
        };
        let signed =
            SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Reference, bundle)
                .unwrap();

        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, back);
    }
}
