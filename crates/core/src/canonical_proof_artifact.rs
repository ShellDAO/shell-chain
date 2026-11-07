//! Off-chain artifact identity and bounded chunk geometry; no consensus approval.
use serde::{Deserialize, Serialize};
use shell_primitives::{blake3_hash, ShellHash};
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
        if self.version != 1
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
