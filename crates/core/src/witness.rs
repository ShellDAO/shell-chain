use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_crypto::PQSignature;
use shell_primitives::{Address, ShellHash};

use crate::transaction::{AaBundle, Transaction, AA_BUNDLE_PRESENCE_FLAG, AA_BUNDLE_TX_TYPE};

// ── StrippedTransaction ──────────────────────────────────────────────────────

/// A transaction payload without its PQ signature or public key.
///
/// Used in the **witness-separated block body** (Phase B). The block body stores
/// only stripped payloads; all PQ cryptographic material is moved to a separate
/// [`WitnessBundle`]. Full nodes store both; light clients can skip the bundle.
///
/// ## Wire encoding (RLP)
/// Fields: `from`, `tx` (same fields as [`Transaction`] encoded as a nested list),
/// followed by an OPTIONAL trailing AA bundle (presence-flag + RLP) when
/// `tx.tx_type == AA_BUNDLE_TX_TYPE`. Mirrors the encoding of
/// [`SignedTransaction`] so that stripped/full forms agree on which bytes
/// represent the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrippedTransaction {
    /// Sender address (required: PQ signatures are not key-recoverable).
    pub from: Address,
    /// The unsigned transaction payload.
    pub tx: Transaction,
    /// Optional Native-AA bundle. Present iff `tx.tx_type == AA_BUNDLE_TX_TYPE`.
    /// `paymaster_signature` (when set) is body data here too: the paymaster
    /// signature is not the per-tx PQ witness (the sender's signature is) and
    /// rides with the bundle for execution-time verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aa_bundle: Option<AaBundle>,
}

impl StrippedTransaction {
    /// Create a [`StrippedTransaction`] from a sender address and transaction.
    pub fn new(from: Address, tx: Transaction) -> Self {
        Self {
            from,
            tx,
            aa_bundle: None,
        }
    }

    /// Create a [`StrippedTransaction`] carrying a Native-AA bundle.
    ///
    /// Returns `Err` when `tx.tx_type != AA_BUNDLE_TX_TYPE`.
    pub fn with_aa_bundle(
        from: Address,
        tx: Transaction,
        aa_bundle: AaBundle,
    ) -> Result<Self, &'static str> {
        if tx.tx_type != AA_BUNDLE_TX_TYPE {
            return Err(
                "StrippedTransaction::with_aa_bundle: tx.tx_type must equal AA_BUNDLE_TX_TYPE",
            );
        }
        Ok(Self {
            from,
            tx,
            aa_bundle: Some(aa_bundle),
        })
    }

    /// Encode to RLP bytes.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    /// Decode from RLP bytes.
    pub fn rlp_decode(bytes: &[u8]) -> Result<Self, alloy_rlp::Error> {
        Self::decode(&mut &bytes[..])
    }

    fn fields_len(&self) -> usize {
        let aa_len = match &self.aa_bundle {
            Some(b) => 1usize.saturating_add(b.length()),
            None => 0,
        };
        self.from
            .length()
            .saturating_add(self.tx.length())
            .saturating_add(aa_len)
    }
}

impl Encodable for StrippedTransaction {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let payload_len = self.fields_len();
        let header = alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        };
        header.encode(out);
        self.from.encode(out);
        self.tx.encode(out);
        // Trailing optional AA bundle. Absent → emit nothing (preserves the
        // pre-v0.18.0 wire format byte-for-byte for legacy stripped txs).
        if let Some(bundle) = &self.aa_bundle {
            out.put_u8(AA_BUNDLE_PRESENCE_FLAG);
            bundle.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_len = self.fields_len();
        alloy_rlp::length_of_length(payload_len) + payload_len
    }
}

impl Decodable for StrippedTransaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let start_remaining = buf.len();
        let from = Address::decode(buf)?;
        let tx = Transaction::decode(buf)?;
        let consumed_so_far = start_remaining.saturating_sub(buf.len());

        let aa_bundle = if consumed_so_far < header.payload_length {
            // At least one trailing byte present — must be the bundle presence flag.
            if buf.is_empty() {
                return Err(alloy_rlp::Error::InputTooShort);
            }
            let flag = buf[0];
            if flag != AA_BUNDLE_PRESENCE_FLAG {
                return Err(alloy_rlp::Error::Custom(
                    "invalid AA bundle presence flag in StrippedTransaction",
                ));
            }
            *buf = &buf[1..];
            Some(AaBundle::decode(buf)?)
        } else {
            None
        };

        Ok(Self {
            from,
            tx,
            aa_bundle,
        })
    }
}

// ── TxWitness ────────────────────────────────────────────────────────────────

/// The PQ cryptographic material for one transaction: signature and (optionally)
/// the sender's public key.
///
/// A `TxWitness` corresponds 1-to-1 with a [`StrippedTransaction`] in the block
/// body at the same index. Together they reconstitute a full [`SignedTransaction`].
///
/// ## Public key inclusion rule (mirrors [`PubkeyMode`])
/// - `pubkey = Some(bytes)` → sender's first tx; key stored in the witness
/// - `pubkey = None`        → key already in the on-chain registry; omitted
///
/// ## Wire encoding (RLP)
/// Fields: `signature` (raw bytes), `pubkey` (bytes or empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxWitness {
    /// Dilithium3 signature (3,309 bytes for Dilithium3).
    pub signature: PQSignature,
    /// Sender public key when this is the sender's first tx (1,952 bytes for Dilithium3).
    /// `None` means the key is already registered and can be omitted from the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<Vec<u8>>,
}

impl TxWitness {
    /// Create a witness without an inline public key (reference mode).
    pub fn new_reference(signature: PQSignature) -> Self {
        Self {
            signature,
            pubkey: None,
        }
    }

    /// Create a witness with an inline public key (embedded / first-tx mode).
    pub fn new_embedded(signature: PQSignature, pubkey: Vec<u8>) -> Self {
        Self {
            signature,
            pubkey: Some(pubkey),
        }
    }

    /// `true` if this witness carries an inline public key.
    pub fn has_pubkey(&self) -> bool {
        self.pubkey.is_some()
    }

    /// Encode to RLP bytes.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

impl Encodable for TxWitness {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let pk_bytes: &[u8] = self.pubkey.as_deref().unwrap_or(&[]);
        let payload_len = self.signature.length() + pk_bytes.length();
        let header = alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        };
        header.encode(out);
        self.signature.encode(out);
        pk_bytes.encode(out);
    }

    fn length(&self) -> usize {
        let pk_bytes: &[u8] = self.pubkey.as_deref().unwrap_or(&[]);
        let payload_len = self.signature.length() + pk_bytes.length();
        alloy_rlp::length_of_length(payload_len) + payload_len
    }
}

impl Decodable for TxWitness {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let signature = PQSignature::decode(buf)?;
        let pk_bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        let pubkey = if pk_bytes.is_empty() {
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
        Ok(Self { signature, pubkey })
    }
}

// ── WitnessBundle ─────────────────────────────────────────────────────────────

/// All PQ witnesses for a single block, parallel to the stripped transaction list.
///
/// `witnesses[i]` corresponds to the transaction at `body.transactions[i]`.
/// The bundle is identified by the block's `witness_root` header field (Phase B2).
///
/// ## Storage
/// - Full nodes: stored in a dedicated `witness` column family (Phase B3).
/// - Light clients: may omit the bundle entirely.
/// - Archive nodes: retain all bundles indefinitely.
/// - Pruning nodes: may drop bundles after finality + safety window (Phase D1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessBundle {
    /// One witness per transaction, in order.
    pub witnesses: Vec<TxWitness>,
}

impl WitnessBundle {
    /// Create an empty bundle.
    pub fn empty() -> Self {
        Self {
            witnesses: Vec::new(),
        }
    }

    /// Create a bundle from a vec of witnesses.
    pub fn new(witnesses: Vec<TxWitness>) -> Self {
        Self { witnesses }
    }

    /// Number of witnesses in the bundle.
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    /// True if the bundle contains no witnesses.
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    /// Compute a Merkle-style commitment over all witness RLP encodings.
    ///
    /// Each leaf = `keccak256(rlp(witness[i]))`. The root is built pairwise
    /// in the same way as the transaction root. Returns all-zeros for empty bundles.
    ///
    /// **Note**: This is a placeholder implementation using sequential hashing.
    /// Phase B2 will replace it with a proper Merkle trie compatible with
    /// the block header's `witness_root` field.
    pub fn compute_root(&self) -> ShellHash {
        if self.witnesses.is_empty() {
            return ShellHash::default();
        }
        use shell_primitives::keccak256;
        let mut leaves: Vec<[u8; 32]> = self
            .witnesses
            .iter()
            .map(|w| {
                let encoded = w.rlp_encode();
                let h = keccak256(&encoded);
                // ShellHash wraps B256; extract raw 32 bytes via AsRef<[u8]>
                let bytes: [u8; 32] = h.as_ref().try_into().expect("ShellHash is 32 bytes");
                bytes
            })
            .collect();
        // Pairwise Merkle fold
        while leaves.len() > 1 {
            let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
            let mut i = 0;
            while i < leaves.len() {
                let left = leaves[i];
                let right = if i + 1 < leaves.len() {
                    leaves[i + 1]
                } else {
                    left
                };
                let combined = [left, right].concat();
                let h = keccak256(&combined);
                let bytes: [u8; 32] = h.as_ref().try_into().expect("ShellHash is 32 bytes");
                next.push(bytes);
                i += 2;
            }
            leaves = next;
        }
        ShellHash::from(leaves[0])
    }

    /// Encode to RLP bytes.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

impl Encodable for WitnessBundle {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let payload_len: usize = self.witnesses.iter().map(|w| w.length()).sum();
        let header = alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        };
        header.encode(out);
        for w in &self.witnesses {
            w.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_len: usize = self.witnesses.iter().map(|w| w.length()).sum();
        alloy_rlp::length_of_length(payload_len) + payload_len
    }
}

impl Decodable for WitnessBundle {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut payload = buf
            .get(..header.payload_length)
            .ok_or(alloy_rlp::Error::InputTooShort)?;
        let mut witnesses = Vec::new();
        while !payload.is_empty() {
            witnesses.push(TxWitness::decode(&mut payload)?);
        }
        *buf = &buf[header.payload_length..];
        Ok(Self { witnesses })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::{DilithiumSigner, PQSignature, Signer};
    use shell_primitives::Address;

    fn dummy_tx() -> Transaction {
        use crate::transaction::Transaction;
        use shell_primitives::U256;
        Transaction {
            chain_id: 1,
            nonce: 0,
            to: Some(Address::from([0xBB; 20])),
            value: U256::from(1_000u64),
            data: shell_primitives::Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    }

    fn dummy_sig_and_pk() -> (PQSignature, Vec<u8>) {
        let signer = DilithiumSigner::generate();
        let pk = signer.public_key().to_vec();
        let sig = signer.sign(b"test message").expect("sign");
        (sig, pk)
    }

    // ── StrippedTransaction ──────────────────────────────────────────────────

    #[test]
    fn stripped_tx_rlp_roundtrip() {
        let from = Address::from([0xAA; 20]);
        let tx = dummy_tx();
        let stripped = StrippedTransaction::new(from, tx);
        let encoded = stripped.rlp_encode();
        let decoded = StrippedTransaction::rlp_decode(&encoded).expect("decode failed");
        assert_eq!(stripped, decoded);
    }

    #[test]
    fn stripped_tx_smaller_than_signed() {
        use crate::transaction::SignedTransaction;
        let from = Address::from([0xAA; 20]);
        let tx = dummy_tx();
        let (sig, pk) = dummy_sig_and_pk();

        let stripped = StrippedTransaction::new(from, tx.clone());
        let signed = SignedTransaction::with_pubkey(from, tx, sig, pk);

        let stripped_bytes = stripped.rlp_encode().len();
        let mut signed_buf = Vec::new();
        signed.encode(&mut signed_buf);
        let signed_bytes = signed_buf.len();

        // StrippedTransaction must be significantly smaller (no sig/pubkey)
        assert!(
            stripped_bytes < signed_bytes,
            "stripped ({stripped_bytes} B) should be smaller than signed ({signed_bytes} B)"
        );
        // At minimum saves sig (3309) + pubkey (1952) bytes
        assert!(
            signed_bytes - stripped_bytes >= 3_000,
            "savings should be at least 3000 bytes, got {}",
            signed_bytes - stripped_bytes
        );
    }

    // ── TxWitness ─────────────────────────────────────────────────────────────

    #[test]
    fn tx_witness_reference_rlp_roundtrip() {
        let (sig, _pk) = dummy_sig_and_pk();
        let witness = TxWitness::new_reference(sig);
        let encoded = witness.rlp_encode();
        let decoded = TxWitness::decode(&mut &encoded[..]).expect("decode failed");
        assert_eq!(witness, decoded);
        assert!(!decoded.has_pubkey());
    }

    #[test]
    fn tx_witness_embedded_rlp_roundtrip() {
        let (sig, pk) = dummy_sig_and_pk();
        let witness = TxWitness::new_embedded(sig, pk.clone());
        let encoded = witness.rlp_encode();
        let decoded = TxWitness::decode(&mut &encoded[..]).expect("decode failed");
        assert_eq!(witness, decoded);
        assert!(decoded.has_pubkey());
        assert_eq!(decoded.pubkey.as_deref(), Some(pk.as_slice()));
    }

    #[test]
    fn tx_witness_reference_smaller_than_embedded() {
        let (sig, pk) = dummy_sig_and_pk();
        let ref_witness = TxWitness::new_reference(sig.clone());
        let emb_witness = TxWitness::new_embedded(sig, pk);
        assert!(
            ref_witness.rlp_encode().len() < emb_witness.rlp_encode().len(),
            "reference witness should be smaller"
        );
    }

    // ── WitnessBundle ─────────────────────────────────────────────────────────

    #[test]
    fn witness_bundle_empty_rlp_roundtrip() {
        let bundle = WitnessBundle::empty();
        let encoded = bundle.rlp_encode();
        let decoded = WitnessBundle::decode(&mut &encoded[..]).expect("decode failed");
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn witness_bundle_rlp_roundtrip() {
        let (sig1, pk1) = dummy_sig_and_pk();
        let (sig2, _pk2) = dummy_sig_and_pk();
        let bundle = WitnessBundle::new(vec![
            TxWitness::new_embedded(sig1, pk1),
            TxWitness::new_reference(sig2),
        ]);
        let encoded = bundle.rlp_encode();
        let decoded = WitnessBundle::decode(&mut &encoded[..]).expect("decode failed");
        assert_eq!(bundle, decoded);
        assert_eq!(decoded.len(), 2);
        assert!(decoded.witnesses[0].has_pubkey());
        assert!(!decoded.witnesses[1].has_pubkey());
    }

    #[test]
    fn witness_bundle_root_deterministic() {
        let (sig1, pk1) = dummy_sig_and_pk();
        let (sig2, _) = dummy_sig_and_pk();
        let bundle = WitnessBundle::new(vec![
            TxWitness::new_embedded(sig1.clone(), pk1.clone()),
            TxWitness::new_reference(sig2.clone()),
        ]);
        let root1 = bundle.compute_root();
        let root2 = bundle.compute_root();
        assert_eq!(root1, root2, "root must be deterministic");
        // Non-empty bundle root should differ from default (all-zeros)
        assert_ne!(root1, ShellHash::default());
    }

    #[test]
    fn witness_bundle_root_empty_is_zero() {
        let bundle = WitnessBundle::empty();
        assert_eq!(bundle.compute_root(), ShellHash::default());
    }

    #[test]
    fn stripped_and_witness_parallel_invariant() {
        // Verify that stripped tx count matches witness count (parallel invariant)
        let from = Address::from([0xAA; 20]);
        let (sig1, pk1) = dummy_sig_and_pk();
        let (sig2, _pk2) = dummy_sig_and_pk();

        let stripped_txs = vec![
            StrippedTransaction::new(from, dummy_tx()),
            StrippedTransaction::new(from, dummy_tx()),
        ];
        let bundle = WitnessBundle::new(vec![
            TxWitness::new_embedded(sig1, pk1),
            TxWitness::new_reference(sig2),
        ]);

        assert_eq!(
            stripped_txs.len(),
            bundle.len(),
            "stripped tx count must equal witness count"
        );
    }
}
