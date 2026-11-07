use shell_primitives::{Bytes, ShellHash};
use shell_storage::{CanonicalProofManifest, CanonicalProofUploadStatus};
use std::sync::Arc;

/// Operator-only artifact intake. The node owns persistence and actual sender
/// proof/replay verification; the RPC layer never manufactures verified results.
pub trait CanonicalProofControl: Send + Sync {
    fn begin(&self, manifest: CanonicalProofManifest)
        -> Result<CanonicalProofUploadStatus, String>;
    fn append(
        &self,
        id: ShellHash,
        index: u32,
        chunk: Bytes,
    ) -> Result<CanonicalProofUploadStatus, String>;
    fn status(&self, id: ShellHash) -> Result<CanonicalProofUploadStatus, String>;
    fn chunk(&self, id: ShellHash, index: u32) -> Result<Bytes, String>;
    fn verify(
        self: Arc<Self>,
        id: ShellHash,
        recheck: bool,
    ) -> Result<CanonicalProofUploadStatus, String>;
}
pub type DynCanonicalProofControl = Arc<dyn CanonicalProofControl>;
