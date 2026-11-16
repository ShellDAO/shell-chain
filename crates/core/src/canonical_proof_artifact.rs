//! Off-chain artifact identity and bounded chunk geometry; no consensus approval.
use serde::{Deserialize, Serialize};
use shell_primitives::{blake3_hash, ShellHash};
/// Off-chain commit-signature/weight artifact; never a consensus certificate.
pub const COMMIT_QUORUM_ARTIFACT_VERSION: u8 = 2;
pub const CANONICAL_PROOF_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_CANONICAL_PROOF_BYTES: u64 = 256 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalProofManifest {
    pub version: u8,
    pub chain_id: u64,
    pub genesis_hash: ShellHash,
    pub block_hash: ShellHash,
    pub total_bytes: u64,
    pub payload_hash: ShellHash,
}

impl CanonicalProofManifest {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.version, 1 | COMMIT_QUORUM_ARTIFACT_VERSION)
            || self.total_bytes == 0
            || self.total_bytes > MAX_CANONICAL_PROOF_BYTES
        {
            return Err("canonical proof manifest version/size limit".into());
        }
        Ok(())
    }
    pub fn id(&self) -> ShellHash {
        let mut bytes = b"SHELL_CANONICAL_PROOF_UPLOAD_V1\0".to_vec();
        bytes.push(self.version);
        bytes.extend(self.chain_id.to_be_bytes());
        bytes.extend(self.genesis_hash.as_bytes());
        bytes.extend(self.block_hash.as_bytes());
        bytes.extend(self.total_bytes.to_be_bytes());
        bytes.extend(self.payload_hash.as_bytes());
        blake3_hash(&bytes)
    }
}

#[cfg(test)]
mod artifact_kind_tests {
    use super::*;
    #[test]
    fn quorum_kind_is_disjoint_without_changing_chunk_geometry() {
        let mut manifest = CanonicalProofManifest {
            version: 1,
            chain_id: 1337,
            genesis_hash: ShellHash::from([1; 32]),
            block_hash: ShellHash::from([2; 32]),
            total_bytes: 1,
            payload_hash: ShellHash::from([3; 32]),
        };
        let sender_id = manifest.id();
        manifest.validate().unwrap();
        manifest.version = COMMIT_QUORUM_ARTIFACT_VERSION;
        manifest.validate().unwrap();
        assert_ne!(sender_id, manifest.id());
        manifest.version = 3;
        assert!(manifest.validate().is_err());
        manifest.version = COMMIT_QUORUM_ARTIFACT_VERSION;
        manifest.total_bytes = MAX_CANONICAL_PROOF_BYTES + 1;
        assert!(manifest.validate().is_err());
        manifest.total_bytes = 0;
        assert!(manifest.validate().is_err());
    }
}
