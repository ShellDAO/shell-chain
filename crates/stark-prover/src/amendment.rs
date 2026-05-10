//! ProofAmendment — a STARK proof attached to an already-sealed block.
//!
//! When async proving is enabled, blocks are broadcast immediately without a
//! proof.  After the prover service generates the proof (potentially on a
//! separate node), it wraps it in a [`ProofAmendment`] and propagates it via
//! P2P gossip.  Peers store the amendment alongside the block so that future
//! importers can verify without re-running native signature checks.

use serde::{Deserialize, Serialize};
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
    /// Raw serialized PQ signature over `(block_hash ‖ block_number ‖ proof_commitment)`.
    ///
    /// The exact message is the SHA3-256 of:
    ///   `b"proof-amendment" ‖ block_hash.as_bytes() ‖ block_number.to_le_bytes() ‖ proof.batch_root_bytes`
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

    /// Compute the canonical signing message for this amendment.
    ///
    /// The prover must sign this message with their registered PQ key.
    /// Validators verify the signature before accepting the amendment.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = b"proof-amendment".to_vec();
        msg.extend_from_slice(self.block_hash.as_bytes());
        msg.extend_from_slice(&self.block_number.to_le_bytes());
        msg.extend_from_slice(&self.proof.batch_root_bytes);
        msg
    }

    /// Estimated wire size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.compressed_size.unwrap_or_else(|| {
            self.proof.size_bytes() as u64
            + 32  // block_hash
            + 8   // block_number
            + 20  // prover address
            + self.prover_signature.len() as u64
            + (self.source_hashes.len() as u64).saturating_mul(32)
            + 32 // JSON/range metadata overhead estimate
        }) as usize
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
        assert!(msg.starts_with(b"proof-amendment"));
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
