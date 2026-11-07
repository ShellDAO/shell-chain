//! Bounded, immutable operator proof uploads, separate from canonical state.
//! A stored verification receipt is informational, never a settlement ticket
//! or a constructor for a cryptographic verifier.
use crate::{KvStore, StorageError, WriteBatch};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use shell_primitives::{blake3_hash, ShellHash};
use std::sync::Arc;

pub const CANONICAL_PROOF_CACHE_PREFIX: &[u8] = b"local/canonical-proof-upload/v1/";
pub const CANONICAL_PROOF_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_CANONICAL_PROOF_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CANONICAL_PROOF_CACHE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_CANONICAL_PROOF_OBJECTS: usize = 8;
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

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
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.version != 1
            || self.total_bytes == 0
            || self.total_bytes > MAX_CANONICAL_PROOF_BYTES
        {
            return Err(invalid("canonical proof manifest version/size limit"));
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CanonicalProofUploadState {
    Uploading,
    Ready,
    Verifying,
    Verified,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalProofUploadStatus {
    pub version: u8,
    pub proof_id: ShellHash,
    pub manifest: CanonicalProofManifest,
    pub state: CanonicalProofUploadState,
    pub received_bytes: u64,
    pub next_chunk: u32,
    pub verification_attempts: u32,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u8,
    reserved_bytes: u64,
    objects: Vec<ShellHash>,
}
fn invalid(text: &str) -> StorageError {
    StorageError::InvalidInput(text.into())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError> {
    serde_json::to_vec(value).map_err(|e| StorageError::Database(e.to_string()))
}
fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, StorageError> {
    serde_json::from_slice(bytes).map_err(|e| StorageError::Database(e.to_string()))
}
fn key(suffix: &[u8]) -> Vec<u8> {
    [CANONICAL_PROOF_CACHE_PREFIX, suffix].concat()
}
fn object_key(id: &ShellHash) -> Vec<u8> {
    key(&[b"object/".as_slice(), id.as_bytes()].concat())
}
fn chunk_key(id: &ShellHash, index: u32) -> Vec<u8> {
    key(&[b"data/".as_slice(), id.as_bytes(), &index.to_be_bytes()].concat())
}

/// All writers for one node share this store/lock. Chunk and progress writes are
/// atomic. Reservations include partial and rejected objects; nothing is erased.
pub struct CanonicalProofUploadStore<S: KvStore> {
    store: Arc<S>,
    verifying: Mutex<Option<ShellHash>>,
}
impl<S: KvStore> CanonicalProofUploadStore<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            verifying: Mutex::new(None),
        }
    }
    pub fn status(&self, id: &ShellHash) -> Result<CanonicalProofUploadStatus, StorageError> {
        let status: CanonicalProofUploadStatus = decode(
            &self
                .store
                .get(&object_key(id))?
                .ok_or_else(|| invalid("canonical proof upload not found"))?,
        )?;
        status.manifest.validate()?;
        if status.version != 1
            || status.proof_id != *id
            || status.manifest.id() != *id
            || status.received_bytes > status.manifest.total_bytes
            || status.next_chunk as u64
                != status
                    .received_bytes
                    .div_ceil(CANONICAL_PROOF_CHUNK_BYTES as u64)
        {
            return Err(invalid("canonical proof upload metadata inconsistent"));
        }
        Ok(status)
    }
    pub fn begin(
        &self,
        manifest: CanonicalProofManifest,
    ) -> Result<CanonicalProofUploadStatus, StorageError> {
        manifest.validate()?;
        let _guard = self.verifying.lock();
        let id = manifest.id();
        if self.store.get(&object_key(&id))?.is_some() {
            return self.status(&id);
        }
        let mut index: Index = match self.store.get(&key(b"index"))? {
            Some(bytes) => decode(&bytes)?,
            None => Index {
                version: 1,
                reserved_bytes: 0,
                objects: vec![],
            },
        };
        let unique: std::collections::HashSet<_> = index.objects.iter().collect();
        if index.version != 1
            || unique.len() != index.objects.len()
            || index.objects.len() >= MAX_CANONICAL_PROOF_OBJECTS
            || index
                .reserved_bytes
                .checked_add(manifest.total_bytes)
                .is_none_or(|n| n > MAX_CANONICAL_PROOF_CACHE_BYTES)
        {
            return Err(invalid("canonical proof cache reservation limit"));
        }
        index.reserved_bytes += manifest.total_bytes;
        index.objects.push(id);
        let status = CanonicalProofUploadStatus {
            version: 1,
            proof_id: id,
            manifest,
            state: CanonicalProofUploadState::Uploading,
            received_bytes: 0,
            next_chunk: 0,
            verification_attempts: 0,
            result: None,
            error: None,
        };
        let mut batch = WriteBatch::new();
        batch.put(key(b"index"), encode(&index)?);
        batch.put(object_key(&id), encode(&status)?);
        self.store.write_batch(batch)?;
        Ok(status)
    }
    pub fn append(
        &self,
        id: &ShellHash,
        index: u32,
        data: &[u8],
    ) -> Result<CanonicalProofUploadStatus, StorageError> {
        if data.is_empty() || data.len() > CANONICAL_PROOF_CHUNK_BYTES {
            return Err(invalid("canonical proof chunk size limit"));
        }
        let _guard = self.verifying.lock();
        let mut status = self.status(id)?;
        if index < status.next_chunk {
            if self.store.get(&chunk_key(id, index))?.as_deref() != Some(data) {
                return Err(invalid("canonical proof conflicting retransmission"));
            }
            return Ok(status);
        }
        let expected = (status.manifest.total_bytes - status.received_bytes)
            .min(CANONICAL_PROOF_CHUNK_BYTES as u64) as usize;
        if status.state != CanonicalProofUploadState::Uploading
            || index != status.next_chunk
            || data.len() != expected
        {
            return Err(invalid("canonical proof chunk order/length mismatch"));
        }
        status.next_chunk += 1;
        status.received_bytes += data.len() as u64;
        if status.received_bytes == status.manifest.total_bytes {
            status.state = CanonicalProofUploadState::Ready;
        }
        let mut batch = WriteBatch::new();
        batch.put(chunk_key(id, index), data.to_vec());
        batch.put(object_key(id), encode(&status)?);
        self.store.write_batch(batch)?;
        Ok(status)
    }
    pub fn chunk(&self, id: &ShellHash, index: u32) -> Result<Vec<u8>, StorageError> {
        if index >= self.status(id)?.next_chunk {
            return Err(invalid("canonical proof chunk unavailable"));
        }
        self.store
            .get(&chunk_key(id, index))?
            .ok_or_else(|| invalid("canonical proof chunk missing"))
    }
    /// True only for a newly claimed worker. A persisted Verifying state can
    /// be reclaimed after process restart, but not while its worker is alive.
    pub fn claim(
        &self,
        id: &ShellHash,
        recheck: bool,
    ) -> Result<(CanonicalProofUploadStatus, bool), StorageError> {
        let mut worker = self.verifying.lock();
        let mut status = self.status(id)?;
        if *worker == Some(*id)
            || (!recheck
                && matches!(
                    status.state,
                    CanonicalProofUploadState::Verified | CanonicalProofUploadState::Rejected
                ))
        {
            return Ok((status, false));
        }
        if worker.is_some() {
            return Err(invalid("canonical proof verifier busy"));
        }
        if !matches!(
            status.state,
            CanonicalProofUploadState::Ready
                | CanonicalProofUploadState::Verifying
                | CanonicalProofUploadState::Verified
                | CanonicalProofUploadState::Rejected
        ) || status.received_bytes != status.manifest.total_bytes
        {
            return Err(invalid("canonical proof upload incomplete"));
        }
        status.verification_attempts = status
            .verification_attempts
            .checked_add(1)
            .ok_or_else(|| invalid("canonical proof attempt overflow"))?;
        status.state = CanonicalProofUploadState::Verifying;
        status.result = None;
        status.error = None;
        self.store.put(&object_key(id), &encode(&status)?)?;
        *worker = Some(*id);
        Ok((status, true))
    }
    pub fn payload(&self, id: &ShellHash) -> Result<Vec<u8>, StorageError> {
        let status = self.status(id)?;
        if status.received_bytes != status.manifest.total_bytes {
            return Err(invalid("canonical proof upload incomplete"));
        }
        let mut bytes = Vec::with_capacity(status.manifest.total_bytes as usize);
        for index in 0..status.next_chunk {
            let chunk = self.chunk(id, index)?;
            let expected = (status.manifest.total_bytes - bytes.len() as u64)
                .min(CANONICAL_PROOF_CHUNK_BYTES as u64) as usize;
            if chunk.len() != expected {
                return Err(invalid("canonical proof stored chunk length mismatch"));
            }
            bytes.extend(chunk);
        }
        if bytes.len() as u64 != status.manifest.total_bytes
            || blake3_hash(&bytes) != status.manifest.payload_hash
        {
            return Err(invalid("canonical proof payload hash mismatch"));
        }
        Ok(bytes)
    }
    pub fn complete(
        &self,
        id: &ShellHash,
        result: Result<serde_json::Value, String>,
    ) -> Result<(), StorageError> {
        let mut worker = self.verifying.lock();
        if *worker != Some(*id) {
            return Err(invalid("canonical proof worker claim mismatch"));
        }
        let mut status = self.status(id)?;
        let result = result.and_then(|value| {
            if serde_json::to_vec(&value).map_err(|e| e.to_string())?.len() > MAX_RESULT_BYTES {
                Err("canonical proof result exceeds receipt budget".into())
            } else {
                Ok(value)
            }
        });
        match result {
            Ok(result) => {
                status.state = CanonicalProofUploadState::Verified;
                status.result = Some(result);
                status.error = None;
            }
            Err(error) => {
                status.state = CanonicalProofUploadState::Rejected;
                status.result = None;
                status.error = Some(error.chars().take(2048).collect());
            }
        }
        let write = self.store.put(&object_key(id), &encode(&status)?);
        *worker = None;
        write
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;
    fn manifest(bytes: &[u8], tag: u8) -> CanonicalProofManifest {
        CanonicalProofManifest {
            version: 1,
            chain_id: 10,
            genesis_hash: ShellHash::from([1; 32]),
            block_hash: ShellHash::from([tag; 32]),
            total_bytes: bytes.len() as u64,
            payload_hash: blake3_hash(bytes),
        }
    }
    #[test]
    fn canonical_proof_upload_resumes_and_refuses_conflicts_without_writes() {
        let db = Arc::new(MemoryDb::new());
        let bytes = vec![7; CANONICAL_PROOF_CHUNK_BYTES + 3];
        let m = manifest(&bytes, 2);
        let cache = CanonicalProofUploadStore::new(db.clone());
        let id = cache.begin(m.clone()).unwrap().proof_id;
        assert!(cache.claim(&id, false).is_err());
        cache
            .append(&id, 0, &bytes[..CANONICAL_PROOF_CHUNK_BYTES])
            .unwrap();
        let before = db.scan_prefix(b"").unwrap();
        assert_eq!(
            cache
                .append(&id, 0, &bytes[..CANONICAL_PROOF_CHUNK_BYTES])
                .unwrap()
                .next_chunk,
            1
        );
        assert!(cache
            .append(&id, 0, &vec![8; CANONICAL_PROOF_CHUNK_BYTES])
            .is_err());
        assert!(cache.append(&id, 2, &[7; 3]).is_err());
        assert!(cache.append(&id, 1, &[7; 2]).is_err());
        assert!(cache
            .append(&id, 1, &vec![7; CANONICAL_PROOF_CHUNK_BYTES + 1])
            .is_err());
        assert_eq!(db.scan_prefix(b"").unwrap(), before);
        drop(cache);
        let cache = CanonicalProofUploadStore::new(db.clone());
        assert_eq!(cache.begin(m).unwrap().next_chunk, 1);
        assert_eq!(
            cache
                .append(&id, 1, &bytes[CANONICAL_PROOF_CHUNK_BYTES..])
                .unwrap()
                .state,
            CanonicalProofUploadState::Ready
        );
        assert_eq!(cache.payload(&id).unwrap(), bytes);
        assert!(cache.claim(&id, false).unwrap().1);
        assert!(!cache.claim(&id, false).unwrap().1);
        let other = cache.begin(manifest(&[4], 3)).unwrap().proof_id;
        cache.append(&other, 0, &[4]).unwrap();
        let before = db.scan_prefix(b"").unwrap();
        assert!(cache.claim(&other, false).is_err());
        assert_eq!(db.scan_prefix(b"").unwrap(), before);
        // Reopening a process-local worker table must fully reclaim verification,
        // not convert an interrupted job into an accepted proof.
        drop(cache);
        let cache = CanonicalProofUploadStore::new(db.clone());
        let (status, claimed) = cache.claim(&id, false).unwrap();
        assert!(claimed);
        assert_eq!(status.verification_attempts, 2);
        cache.complete(&id, Err("invalid proof".into())).unwrap();
        assert_eq!(
            cache.status(&id).unwrap().state,
            CanonicalProofUploadState::Rejected
        );
        assert!(!cache.claim(&id, false).unwrap().1);
        let (retried, claimed) = cache.claim(&id, true).unwrap();
        assert!(claimed);
        assert_eq!(retried.verification_attempts, 3);
        assert!(retried.result.is_none() && retried.error.is_none());
        assert!(!cache.claim(&id, true).unwrap().1);
        cache
            .complete(&id, Ok(serde_json::json!({"rechecked":true})))
            .unwrap();
        assert!(!cache.claim(&id, false).unwrap().1);
        assert_eq!(cache.payload(&id).unwrap(), bytes);
        assert!(cache.claim(&other, false).unwrap().1);
        cache
            .complete(&other, Ok(serde_json::json!({"checked":true})))
            .unwrap();
        assert_eq!(
            cache.status(&other).unwrap().state,
            CanonicalProofUploadState::Verified
        );
    }
    #[test]
    fn canonical_proof_upload_reservations_and_object_count_are_bounded() {
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        let mut m = manifest(&[1], 1);
        m.total_bytes = 0;
        assert!(cache.begin(m.clone()).is_err());
        m.total_bytes = MAX_CANONICAL_PROOF_BYTES + 1;
        assert!(cache.begin(m.clone()).is_err());
        m.total_bytes = 1;
        m.version = 0;
        assert!(cache.begin(m.clone()).is_err());
        assert!(db.scan_prefix(b"").unwrap().is_empty());
        m.version = 1;
        m.total_bytes = MAX_CANONICAL_PROOF_BYTES;
        let first = cache.begin(m.clone()).unwrap();
        assert_eq!(cache.begin(m.clone()).unwrap(), first);
        m.block_hash = ShellHash::from([2; 32]);
        cache.begin(m.clone()).unwrap();
        m.total_bytes = 1;
        m.block_hash = ShellHash::from([3; 32]);
        let before = db.scan_prefix(b"").unwrap();
        assert!(cache.begin(m).is_err());
        assert_eq!(db.scan_prefix(b"").unwrap(), before);
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        for tag in 0..MAX_CANONICAL_PROOF_OBJECTS as u8 {
            cache.begin(manifest(&[1], tag)).unwrap();
        }
        let before = db.scan_prefix(b"").unwrap();
        assert!(cache.begin(manifest(&[1], 255)).is_err());
        assert_eq!(db.scan_prefix(b"").unwrap(), before);
    }
    #[test]
    fn canonical_proof_upload_hash_and_stored_chunk_corruption_fail_closed() {
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        let id = cache.begin(manifest(&[1, 2, 3], 1)).unwrap().proof_id;
        cache.append(&id, 0, &[3, 2, 1]).unwrap();
        let before = db.scan_prefix(b"").unwrap();
        assert!(cache.payload(&id).is_err());
        assert_eq!(db.scan_prefix(b"").unwrap(), before);
        db.put(&chunk_key(&id, 0), &[1]).unwrap();
        assert!(cache.payload(&id).is_err());
        db.delete(&chunk_key(&id, 0)).unwrap();
        assert!(cache.payload(&id).is_err());
    }
    #[test]
    fn canonical_proof_upload_receipt_and_error_metadata_are_bounded() {
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db);
        let id = cache.begin(manifest(&[1], 1)).unwrap().proof_id;
        cache.append(&id, 0, &[1]).unwrap();
        cache.claim(&id, false).unwrap();
        cache
            .complete(
                &id,
                Ok(serde_json::Value::String("x".repeat(MAX_RESULT_BYTES + 1))),
            )
            .unwrap();
        let status = cache.status(&id).unwrap();
        assert_eq!(status.state, CanonicalProofUploadState::Rejected);
        assert!(status.result.is_none());
    }
    #[cfg(feature = "rocksdb")]
    #[test]
    fn canonical_proof_upload_progress_and_result_survive_native_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "shell-canonical-proof-upload-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let bytes = vec![7; CANONICAL_PROOF_CHUNK_BYTES + 3];
        let m = manifest(&bytes, 1);
        let id = m.id();
        {
            let stores = crate::RocksDbStore::open_all(&dir, None).unwrap();
            let cache = CanonicalProofUploadStore::new(Arc::new(stores.state.clone()));
            cache.begin(m).unwrap();
            cache
                .append(&id, 0, &bytes[..CANONICAL_PROOF_CHUNK_BYTES])
                .unwrap();
            stores.state.flush().unwrap();
        }
        {
            let stores = crate::RocksDbStore::open_all(&dir, None).unwrap();
            let cache = CanonicalProofUploadStore::new(Arc::new(stores.state.clone()));
            assert_eq!(cache.status(&id).unwrap().next_chunk, 1);
            cache
                .append(&id, 1, &bytes[CANONICAL_PROOF_CHUNK_BYTES..])
                .unwrap();
            assert!(cache.claim(&id, false).unwrap().1);
            assert_eq!(cache.payload(&id).unwrap(), bytes);
            cache
                .complete(&id, Ok(serde_json::json!({"native_reopen":true})))
                .unwrap();
            stores.state.flush().unwrap();
        }
        {
            let stores = crate::RocksDbStore::open_all(&dir, None).unwrap();
            let cache = CanonicalProofUploadStore::new(Arc::new(stores.state));
            assert_eq!(
                cache.status(&id).unwrap().state,
                CanonicalProofUploadState::Verified
            );
            assert_eq!(cache.status(&id).unwrap().verification_attempts, 1);
        }
        println!("canonical proof upload store retained at {}", dir.display());
    }
}
