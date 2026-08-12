//! ProofAmendment — a STARK proof attached to an already-sealed block.
//!
//! When async proving is enabled, blocks are broadcast immediately without a
//! proof.  After the prover service generates the proof (potentially on a
//! separate node), it wraps it in a [`ProofAmendment`] and propagates it via
//! P2P gossip.  Peers store the amendment alongside the block so that future
//! importers can verify without re-running native signature checks.

use serde::{Deserialize, Serialize};
use shell_crypto::{verify_signature, PQSignature, SignatureType, Signer, MAX_SIGNATURE_BYTES};
use shell_primitives::{Address, Bytes, ShellHash};

use crate::proof::SigBatchProof;

// ── ProofAmendment ────────────────────────────────────────────────────────────

/// A STARK proof generated asynchronously and attached to a sealed block.
///
/// The amendment is self-contained: it carries everything a verifier needs —
/// the target block identity, the proof, and the prover's cryptographic
/// signature (preventing forgeries by nodes that did not actually run the
/// prover).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAmendment {
    /// Protocol version for forward-compatibility.
    pub version: u8,
    /// Hash of the block this proof covers.
    pub block_hash: ShellHash,
    /// Inclusive end block of the contiguous source range.
    #[serde(rename = "end_block", alias = "block_number")]
    pub block_number: u64,
    /// Inclusive start block of the contiguous source range.
    ///
    /// Legacy single-block amendments may omit this; callers then infer it from
    /// `block_number + 1 - covered_hashes().len()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_block: Option<u64>,
    /// The STARK batch-commitment proof.
    pub proof: SigBatchProof,
    /// The prover's address (registered in ProverRegistry).
    pub prover: Address,
    /// Versioned authentication envelope containing the prover's signature
    /// algorithm, public key, and raw post-quantum signature.
    ///
    /// The signature covers all proof, source-range, compression, and reward
    /// metadata returned by [`ProofAmendment::signing_message`].
    pub prover_signature: Bytes,
    /// STARK compression layer. L1 covers canonical block witnesses; L2+
    /// covers lower-layer artifacts.
    #[serde(default = "default_layer")]
    pub layer: u32,
    /// Inclusive source range covered by this proof artifact.
    ///
    /// For legacy single-block amendments this is empty on the wire and is
    /// interpreted as `[block_hash]` / `block_number..=block_number`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_hashes: Vec<ShellHash>,
    /// Total byte size of source payloads covered by the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_size: Option<u64>,
    /// Byte size of the compressed artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<u64>,
    /// Settlement transaction that carries the canonical proof payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_tx_hash: Option<ShellHash>,
}

/// Current serialization version.
pub const PROOF_AMENDMENT_VERSION: u8 = 1;
pub const PROOF_POINTER_VERSION: u8 = 1;
const PROVER_AUTH_VERSION: u8 = 1;
const PROVER_AUTH_HEADER_BYTES: usize = 4;
const MAX_PROVER_PUBLIC_KEY_BYTES: usize = 4_096;

fn default_layer() -> u32 {
    1
}

impl ProofAmendment {
    /// Serialize to JSON bytes for P2P transmission or storage.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Compute the canonical, domain-separated signing message for this amendment.
    ///
    /// The prover must sign this message with their registered PQ key.
    /// Validators verify the signature before accepting the amendment.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = b"shell-proof-amendment-auth-v1".to_vec();
        msg.push(self.version);
        msg.extend_from_slice(self.block_hash.as_bytes());
        msg.extend_from_slice(&self.block_number.to_be_bytes());
        push_optional_u64(&mut msg, self.start_block);
        msg.push(self.proof.version);
        msg.extend_from_slice(&self.proof.batch_root_bytes);
        msg.extend_from_slice(&(self.proof.n_sigs as u64).to_be_bytes());
        msg.extend_from_slice(blake3::hash(&self.proof.proof_bytes).as_bytes());
        msg.extend_from_slice(self.prover.as_bytes());
        msg.extend_from_slice(&self.layer.to_be_bytes());
        msg.extend_from_slice(&(self.source_hashes.len() as u64).to_be_bytes());
        for source_hash in &self.source_hashes {
            msg.extend_from_slice(source_hash.as_bytes());
        }
        push_optional_u64(&mut msg, self.original_size);
        push_optional_u64(&mut msg, self.compressed_size);
        msg
    }

    /// Bind the prover identity and all reward-relevant amendment metadata to a
    /// self-contained post-quantum signature envelope.
    pub fn sign_prover_authentication(&mut self, signer: &dyn Signer) -> Result<(), String> {
        let public_key = signer.public_key();
        let public_key_len = u16::try_from(public_key.len())
            .map_err(|_| "prover public key exceeds authentication envelope limit".to_owned())?;
        if public_key.is_empty() || public_key.len() > MAX_PROVER_PUBLIC_KEY_BYTES {
            return Err("invalid prover public key length".to_owned());
        }

        let sig_type = signer.sig_type();
        self.prover = Address::from_public_key(public_key, sig_type.as_u8());
        self.compressed_size = None;

        // The final signature length is algorithm-fixed. A provisional envelope
        // lets the existing size estimate include its full authentication cost.
        self.prover_signature = encode_prover_authentication(
            sig_type,
            public_key,
            signer
                .sign(&self.signing_message())
                .map_err(|e| format!("sign prover authentication: {e}"))?,
            public_key_len,
        )?;
        self.compressed_size = Some(self.size_bytes() as u64);
        self.prover_signature = encode_prover_authentication(
            sig_type,
            public_key,
            signer
                .sign(&self.signing_message())
                .map_err(|e| format!("sign prover authentication: {e}"))?,
            public_key_len,
        )?;
        Ok(())
    }

    /// Verify the embedded prover key, address binding, and signature.
    pub fn verify_prover_authentication(&self) -> Result<(), String> {
        let envelope = self.prover_signature.as_ref();
        if envelope.len() < PROVER_AUTH_HEADER_BYTES {
            return Err("missing prover authentication envelope".to_owned());
        }
        if envelope[0] != PROVER_AUTH_VERSION {
            return Err("unsupported prover authentication version".to_owned());
        }
        let sig_type = SignatureType::from_u8(envelope[1])
            .ok_or_else(|| "unsupported prover authentication algorithm".to_owned())?;
        let public_key_len = u16::from_be_bytes([envelope[2], envelope[3]]) as usize;
        if public_key_len == 0 || public_key_len > MAX_PROVER_PUBLIC_KEY_BYTES {
            return Err("invalid prover public key length".to_owned());
        }
        let signature_start = PROVER_AUTH_HEADER_BYTES
            .checked_add(public_key_len)
            .ok_or_else(|| "invalid prover authentication envelope".to_owned())?;
        if signature_start >= envelope.len() {
            return Err("missing prover authentication signature".to_owned());
        }
        let public_key = envelope
            .get(PROVER_AUTH_HEADER_BYTES..signature_start)
            .ok_or_else(|| "truncated prover public key".to_owned())?;
        let signature = envelope
            .get(signature_start..)
            .ok_or_else(|| "truncated prover authentication signature".to_owned())?;
        if signature.len() > MAX_SIGNATURE_BYTES {
            return Err("prover authentication signature exceeds size limit".to_owned());
        }
        let expected_compressed_size = self.estimated_wire_size_bytes();
        if self.compressed_size != Some(expected_compressed_size) {
            return Err(format!(
                "compressed_size does not match proof artifact size: expected {expected_compressed_size}, got {:?}",
                self.compressed_size
            ));
        }
        if Address::from_public_key(public_key, sig_type.as_u8()) != self.prover {
            return Err("prover address does not match authentication key".to_owned());
        }
        match verify_signature(sig_type, public_key, &self.signing_message(), signature) {
            Ok(true) => Ok(()),
            Ok(false) => Err("invalid prover authentication signature".to_owned()),
            Err(e) => Err(format!("verify prover authentication: {e}")),
        }
    }

    /// Estimated wire size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.compressed_size
            .unwrap_or_else(|| self.estimated_wire_size_bytes()) as usize
    }

    fn estimated_wire_size_bytes(&self) -> u64 {
        self.proof.size_bytes() as u64
            + 32  // block_hash
            + 8   // block_number
            + 20  // prover address
            + self.prover_signature.len() as u64
            + (self.source_hashes.len() as u64).saturating_mul(32)
            + 32 // JSON/range metadata overhead estimate
    }

    /// Source block/artifact hashes covered by this amendment.
    pub fn covered_hashes(&self) -> Vec<ShellHash> {
        if self.source_hashes.is_empty() {
            vec![self.block_hash]
        } else {
            self.source_hashes.clone()
        }
    }

    /// Inclusive source-range start block.
    pub fn range_start_block(&self) -> Option<u64> {
        self.start_block.or_else(|| {
            let source_count = self.covered_hashes().len() as u64;
            self.block_number
                .checked_add(1)
                .and_then(|end_plus_one| end_plus_one.checked_sub(source_count))
        })
    }

    /// Inclusive source-range end block.
    pub fn range_end_block(&self) -> u64 {
        self.block_number
    }

    /// Serialized artifacts for storing this proof range.
    ///
    /// The full proof is stored only under the final covered source hash. Earlier
    /// covered sources store a compact pointer to the final proof target.
    pub fn storage_artifacts(&self) -> Result<Vec<(ShellHash, Vec<u8>)>, serde_json::Error> {
        self.storage_artifacts_with_settlement(self.settlement_tx_hash)
    }

    pub fn storage_artifacts_with_settlement(
        &self,
        settlement_tx_hash: Option<ShellHash>,
    ) -> Result<Vec<(ShellHash, Vec<u8>)>, serde_json::Error> {
        let mut full = self.clone();
        full.settlement_tx_hash = settlement_tx_hash;
        let full_proof = full.to_json()?;
        let covered = full.covered_hashes();
        let start_block = full.range_start_block().unwrap_or(full.block_number);
        let mut artifacts = Vec::with_capacity(covered.len().max(1));

        for (offset, source_hash) in covered.iter().enumerate() {
            if *source_hash == full.block_hash {
                artifacts.push((*source_hash, full_proof.clone()));
            } else {
                let pointer = ProofPointer {
                    version: PROOF_POINTER_VERSION,
                    source_hash: *source_hash,
                    source_block: start_block.saturating_add(offset as u64),
                    target_hash: full.block_hash,
                    target_block: full.block_number,
                    start_block,
                    end_block: full.block_number,
                    layer: full.layer,
                    settlement_tx_hash,
                };
                artifacts.push((*source_hash, pointer.to_json()?));
            }
        }

        Ok(artifacts)
    }

    /// Returns true when this proof is strictly smaller than 50% of the
    /// source payload it is intended to replace.
    pub fn is_compression_valid_for(&self, original_size: u64) -> bool {
        (self.size_bytes() as u64).saturating_mul(2) < original_size
    }

    /// Returns true when embedded source-size metadata proves strict <50%
    /// compression, or when the source range has zero original bytes (empty
    /// blocks whose witness data is trivially absent).
    /// Returns false when metadata is missing entirely.
    pub fn has_valid_embedded_compression(&self) -> bool {
        match self.original_size {
            None => false,
            Some(0) => true, // empty source range: trivially valid
            Some(original) => self.is_compression_valid_for(original),
        }
    }
}

fn push_optional_u64(message: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            message.push(1);
            message.extend_from_slice(&value.to_be_bytes());
        }
        None => message.push(0),
    }
}

fn encode_prover_authentication(
    sig_type: SignatureType,
    public_key: &[u8],
    signature: PQSignature,
    public_key_len: u16,
) -> Result<Bytes, String> {
    if signature.sig_type != sig_type || signature.data.is_empty() {
        return Err("signer returned an invalid authentication signature".to_owned());
    }
    if signature.data.len() > MAX_SIGNATURE_BYTES {
        return Err("prover authentication signature exceeds size limit".to_owned());
    }
    let mut envelope =
        Vec::with_capacity(PROVER_AUTH_HEADER_BYTES + public_key.len() + signature.data.len());
    envelope.push(PROVER_AUTH_VERSION);
    envelope.push(sig_type.as_u8());
    envelope.extend_from_slice(&public_key_len.to_be_bytes());
    envelope.extend_from_slice(public_key);
    envelope.extend_from_slice(&signature.data);
    Ok(Bytes::from(envelope))
}

/// A compact marker stored for source blocks covered by a later range proof.
///
/// Full proof bytes are stored only under the final source block hash. Earlier
/// covered blocks store this pointer so RPC/storage can still report their
/// compression layer and proof target without duplicating the proof payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofPointer {
    pub version: u8,
    pub source_hash: ShellHash,
    pub source_block: u64,
    pub target_hash: ShellHash,
    pub target_block: u64,
    pub start_block: u64,
    pub end_block: u64,
    pub layer: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_tx_hash: Option<ShellHash>,
}

impl ProofPointer {
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredProofArtifact {
    Amendment(ProofAmendment),
    Pointer(ProofPointer),
}

impl StoredProofArtifact {
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        match ProofAmendment::from_json(bytes) {
            Ok(amendment) => Ok(Self::Amendment(amendment)),
            Err(amendment_err) => match ProofPointer::from_json(bytes) {
                Ok(pointer) => Ok(Self::Pointer(pointer)),
                Err(_) => Err(amendment_err),
            },
        }
    }

    pub fn layer(&self) -> u32 {
        match self {
            Self::Amendment(amendment) => amendment.layer,
            Self::Pointer(pointer) => pointer.layer,
        }
    }
}

/// Cross-block compression work item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRange {
    pub layer: u32,
    pub start_block: u64,
    pub end_block: u64,
    pub source_hashes: Vec<ShellHash>,
    pub original_size: u64,
}

impl ProofRange {
    pub fn is_contiguous(&self) -> bool {
        self.start_block <= self.end_block
            && self
                .end_block
                .saturating_sub(self.start_block)
                .saturating_add(1)
                == self.source_hashes.len() as u64
    }

    pub fn compression_valid(&self, compressed_size: u64) -> bool {
        compressed_size.saturating_mul(2) < self.original_size
    }
}

// ── Storage key helpers ───────────────────────────────────────────────────────

/// Key prefix for proof amendments in the key-value store.
///
/// Full key: `AMENDMENT_PREFIX ‖ block_hash_bytes (32 bytes)`
pub const AMENDMENT_KEY_PREFIX: &[u8] = b"pa/";

/// Build a storage key for a proof amendment.
pub fn amendment_key(block_hash: &ShellHash) -> Vec<u8> {
    let mut key = AMENDMENT_KEY_PREFIX.to_vec();
    key.extend_from_slice(block_hash.as_bytes());
    key
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::DilithiumSigner;
    use shell_primitives::ShellHash;

    fn make_amendment() -> ProofAmendment {
        use crate::prover::{prove_sig_batch, SigBatchEntry};
        let entries = vec![
            SigBatchEntry {
                msg_hash: [1u8; 32],
                pk_hash: [2u8; 32],
            },
            SigBatchEntry {
                msg_hash: [3u8; 32],
                pk_hash: [4u8; 32],
            },
        ];
        let proof = prove_sig_batch(&entries).expect("prove failed");
        ProofAmendment {
            version: PROOF_AMENDMENT_VERSION,
            block_hash: ShellHash::from([0xAA; 32]),
            block_number: 42,
            start_block: Some(42),
            proof,
            prover: Address::from([0x01; 20]),
            prover_signature: Bytes::from(vec![0u8; 16]),
            layer: 1,
            source_hashes: vec![ShellHash::from([0xAA; 32])],
            original_size: Some(10_000),
            compressed_size: Some(1_000),
            settlement_tx_hash: None,
        }
    }

    #[test]
    fn amendment_json_roundtrip() {
        let a = make_amendment();
        let json = a.to_json().expect("serialize");
        let text = String::from_utf8(json.clone()).expect("json is utf8");
        assert!(text.contains("\"end_block\":42"));
        assert!(!text.contains("\"block_number\""));
        let decoded = ProofAmendment::from_json(&json).expect("deserialize");
        assert_eq!(a, decoded);
    }

    #[test]
    fn proof_pointer_json_roundtrip() {
        let pointer = ProofPointer {
            version: PROOF_POINTER_VERSION,
            source_hash: ShellHash::from([0x11; 32]),
            source_block: 40,
            target_hash: ShellHash::from([0x22; 32]),
            target_block: 42,
            start_block: 40,
            end_block: 42,
            layer: 1,
            settlement_tx_hash: None,
        };
        let json = pointer.to_json().expect("serialize");
        let decoded = ProofPointer::from_json(&json).expect("deserialize");
        assert_eq!(pointer, decoded);
        assert!(matches!(
            StoredProofArtifact::from_json(&json).expect("stored artifact"),
            StoredProofArtifact::Pointer(_)
        ));
    }

    #[test]
    fn amendment_storage_artifacts_keep_full_proof_at_range_end() {
        let mut amendment = make_amendment();
        let first = ShellHash::from([0x10; 32]);
        amendment.source_hashes = vec![first, amendment.block_hash];
        amendment.start_block = Some(41);

        let artifacts = amendment.storage_artifacts().expect("storage artifacts");
        assert_eq!(artifacts.len(), 2);
        assert!(matches!(
            StoredProofArtifact::from_json(&artifacts[0].1).expect("first artifact"),
            StoredProofArtifact::Pointer(_)
        ));
        assert!(matches!(
            StoredProofArtifact::from_json(&artifacts[1].1).expect("final artifact"),
            StoredProofArtifact::Amendment(_)
        ));
    }

    #[test]
    fn amendment_signing_message_is_deterministic() {
        let a = make_amendment();
        assert_eq!(a.signing_message(), a.signing_message());
    }

    #[test]
    fn amendment_signing_message_includes_prefix() {
        let a = make_amendment();
        let msg = a.signing_message();
        assert!(msg.starts_with(b"shell-proof-amendment-auth-v1"));
    }

    #[test]
    fn signed_prover_authentication_roundtrip() {
        let signer = DilithiumSigner::generate();
        let mut amendment = make_amendment();

        amendment
            .sign_prover_authentication(&signer)
            .expect("sign amendment");

        assert_eq!(
            amendment.prover,
            Address::from_public_key(signer.public_key(), signer.sig_type().as_u8())
        );
        amendment
            .verify_prover_authentication()
            .expect("verify amendment");
    }

    #[test]
    fn prover_authentication_rejects_underreported_compressed_size() {
        let signer = DilithiumSigner::generate();
        let mut amendment = make_amendment();
        amendment.original_size = Some(u64::MAX);
        amendment
            .sign_prover_authentication(&signer)
            .expect("sign amendment");

        amendment.compressed_size = Some(1);
        let message = amendment.signing_message();
        let public_key = signer.public_key();
        amendment.prover_signature = encode_prover_authentication(
            signer.sig_type(),
            public_key,
            signer.sign(&message).expect("sign tampered size"),
            u16::try_from(public_key.len()).expect("public key length"),
        )
        .expect("encode authentication");

        assert!(amendment.has_valid_embedded_compression());
        assert!(amendment
            .verify_prover_authentication()
            .unwrap_err()
            .contains("compressed_size does not match proof artifact size"));
    }

    #[test]
    fn prover_authentication_rejects_missing_or_malformed_envelopes() {
        let mut amendment = make_amendment();
        amendment.prover_signature = Bytes::new();
        assert!(amendment.verify_prover_authentication().is_err());

        amendment.prover_signature = Bytes::from(vec![PROVER_AUTH_VERSION, 0, 0, 1]);
        assert!(amendment.verify_prover_authentication().is_err());
    }

    #[test]
    fn prover_authentication_rejects_metadata_tampering() {
        let signer = DilithiumSigner::generate();
        let mut amendment = make_amendment();
        amendment
            .sign_prover_authentication(&signer)
            .expect("sign amendment");

        let mut wrong_prover = amendment.clone();
        wrong_prover.prover = Address::from([0x55; 32]);
        assert!(wrong_prover.verify_prover_authentication().is_err());

        let mut wrong_source = amendment.clone();
        wrong_source.source_hashes[0] = ShellHash::from([0x44; 32]);
        assert!(wrong_source.verify_prover_authentication().is_err());

        let mut wrong_original_size = amendment.clone();
        wrong_original_size.original_size = Some(20_000);
        assert!(wrong_original_size.verify_prover_authentication().is_err());

        let mut wrong_compressed_size = amendment;
        wrong_compressed_size.compressed_size = Some(999);
        assert!(wrong_compressed_size
            .verify_prover_authentication()
            .is_err());
    }

    #[test]
    fn amendment_key_uses_prefix() {
        let hash = ShellHash::from([0xBB; 32]);
        let key = amendment_key(&hash);
        assert!(key.starts_with(AMENDMENT_KEY_PREFIX));
        assert_eq!(key.len(), AMENDMENT_KEY_PREFIX.len() + 32);
    }

    #[test]
    fn amendment_size_bytes_nonzero() {
        let a = make_amendment();
        assert!(a.size_bytes() > 0);
    }

    #[test]
    fn amendment_embedded_compression_is_strict() {
        let mut a = make_amendment();
        a.original_size = Some(100);
        a.compressed_size = Some(49);
        assert!(a.has_valid_embedded_compression());
        a.compressed_size = Some(50);
        assert!(!a.has_valid_embedded_compression());
    }

    #[test]
    fn different_blocks_produce_different_keys() {
        let k1 = amendment_key(&ShellHash::from([0x01; 32]));
        let k2 = amendment_key(&ShellHash::from([0x02; 32]));
        assert_ne!(k1, k2);
    }
}
