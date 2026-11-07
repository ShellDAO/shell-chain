//! Bounded, immutable operator proof uploads, separate from canonical state.
//! A stored verification receipt is informational, never a settlement ticket
//! or a constructor for a cryptographic verifier.
use crate::{KvStore, StorageError, WriteBatch};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use shell_primitives::{blake3_hash, ShellHash};
use std::sync::Arc;

pub const CANONICAL_PROOF_CACHE_PREFIX: &[u8] = b"local/canonical-proof-upload/v1/";
pub use shell_core::{
    CanonicalProofManifest, CANONICAL_PROOF_CHUNK_BYTES, MAX_CANONICAL_PROOF_BYTES,
};
pub const MAX_CANONICAL_PROOF_CACHE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_CANONICAL_PROOF_OBJECTS: usize = 8;
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

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
    #[serde(default, skip_serializing_if = "is_zero")]
    pub generation: u64,
    pub proof_id: ShellHash,
    pub manifest: CanonicalProofManifest,
    pub state: CanonicalProofUploadState,
    pub received_bytes: u64,
    pub next_chunk: u32,
    pub verification_attempts: u32,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CanonicalProofFetchState {
    Receiving,
    Verifying,
    Complete,
    Failed,
    Paused,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalProofFetchStatus {
    pub version: u8,
    pub proof_id: ShellHash,
    pub generation: u64,
    pub peer: String,
    pub nonce: u64,
    pub next_chunk: u32,
    pub received_bytes: u64,
    pub state: CanonicalProofFetchState,
    pub error: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u8,
    reserved_bytes: u64,
    objects: Vec<ShellHash>,
    #[serde(default, skip_serializing_if = "is_zero")]
    archived_attempts: u64,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
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

fn generation_chunk_key(id: &ShellHash, generation: u64, index: u32) -> Vec<u8> {
    if generation == 0 {
        return chunk_key(id, index);
    }
    key(&[
        b"generation-data/".as_slice(),
        id.as_bytes(),
        &generation.to_be_bytes(),
        &index.to_be_bytes(),
    ]
    .concat())
}
fn attempt_key(id: &ShellHash, generation: u64) -> Vec<u8> {
    key(&[
        b"attempt/".as_slice(),
        id.as_bytes(),
        &generation.to_be_bytes(),
    ]
    .concat())
}
fn fetch_key(id: &ShellHash) -> Vec<u8> {
    key(&[b"fetch/".as_slice(), id.as_bytes()].concat())
}
fn fetch_attempt_key(id: &ShellHash, generation: u64) -> Vec<u8> {
    key(&[
        b"fetch-attempt/".as_slice(),
        id.as_bytes(),
        &generation.to_be_bytes(),
    ]
    .concat())
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
        status.manifest.validate().map_err(|e| invalid(&e))?;
        if status.version != 1
            || status.proof_id != *id
            || status.manifest.id() != *id
            || status.generation >= MAX_CANONICAL_PROOF_OBJECTS as u64
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
    /// Byte availability only. Callers independently validate source identity and
    /// cryptography; neither ready nor persisted verified metadata authorizes import.
    pub fn available_manifests(&self) -> Result<Vec<CanonicalProofManifest>, StorageError> {
        let Some(bytes) = self.store.get(&key(b"index"))? else {
            return Ok(vec![]);
        };
        if bytes.len() > 16 * 1024 {
            return Err(invalid("canonical cache index size limit"));
        }
        let index: Index = decode(&bytes)?;
        if index.version != 1
            || index.objects.len() > MAX_CANONICAL_PROOF_OBJECTS
            || (index.objects.len() as u64)
                .checked_add(index.archived_attempts)
                .is_none_or(|n| n > MAX_CANONICAL_PROOF_OBJECTS as u64)
            || index.reserved_bytes > MAX_CANONICAL_PROOF_CACHE_BYTES
            || index
                .objects
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != index.objects.len()
        {
            return Err(invalid("canonical cache index invalid"));
        }
        let mut result = Vec::new();
        for id in index.objects {
            let status = self.status(&id)?;
            if matches!(
                status.state,
                CanonicalProofUploadState::Ready | CanonicalProofUploadState::Verified
            ) && status.received_bytes == status.manifest.total_bytes
            {
                result.push(status.manifest);
            }
        }
        Ok(result)
    }
    pub fn begin(
        &self,
        manifest: CanonicalProofManifest,
    ) -> Result<CanonicalProofUploadStatus, StorageError> {
        manifest.validate().map_err(|e| invalid(&e))?;
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
                archived_attempts: 0,
            },
        };
        let unique: std::collections::HashSet<_> = index.objects.iter().collect();
        if index.version != 1
            || unique.len() != index.objects.len()
            || (index.objects.len() as u64)
                .checked_add(index.archived_attempts)
                .is_none_or(|n| n >= MAX_CANONICAL_PROOF_OBJECTS as u64)
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
            generation: 0,
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
            if self
                .store
                .get(&generation_chunk_key(id, status.generation, index))?
                .as_deref()
                != Some(data)
            {
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
        batch.put(
            generation_chunk_key(id, status.generation, index),
            data.to_vec(),
        );
        batch.put(object_key(id), encode(&status)?);
        self.store.write_batch(batch)?;
        Ok(status)
    }
    pub fn chunk(&self, id: &ShellHash, index: u32) -> Result<Vec<u8>, StorageError> {
        self.attempt_chunk(id, self.status(id)?.generation, index)
    }
    pub fn attempt_status(
        &self,
        id: &ShellHash,
        generation: u64,
    ) -> Result<CanonicalProofUploadStatus, StorageError> {
        let current = self.status(id)?;
        if current.generation == generation {
            return Ok(current);
        }
        let bytes = self
            .store
            .get(&attempt_key(id, generation))?
            .ok_or_else(|| invalid("canonical proof attempt unavailable"))?;
        let status: CanonicalProofUploadStatus = decode(&bytes)?;
        if status.version != 1
            || status.proof_id != *id
            || status.manifest != current.manifest
            || status.generation != generation
            || generation >= current.generation
            || status.received_bytes > status.manifest.total_bytes
            || status.next_chunk as u64
                != status
                    .received_bytes
                    .div_ceil(CANONICAL_PROOF_CHUNK_BYTES as u64)
        {
            return Err(invalid("canonical proof attempt metadata inconsistent"));
        }
        Ok(status)
    }
    pub fn attempt_chunk(
        &self,
        id: &ShellHash,
        generation: u64,
        index: u32,
    ) -> Result<Vec<u8>, StorageError> {
        let status = self.attempt_status(id, generation)?;
        if index >= status.next_chunk {
            return Err(invalid("canonical proof chunk unavailable"));
        }
        self.store
            .get(&generation_chunk_key(id, generation, index))?
            .ok_or_else(|| invalid("canonical proof chunk missing"))
    }
    pub fn restart_corrupt(
        &self,
        id: &ShellHash,
    ) -> Result<CanonicalProofUploadStatus, StorageError> {
        let worker = self.verifying.lock();
        if worker.is_some() {
            return Err(invalid("canonical proof verifier busy"));
        }
        let mut status = self.status(id)?;
        if status.state != CanonicalProofUploadState::Rejected {
            return Err(invalid("canonical proof attempt is not rejected"));
        }
        match self.payload(id) {
            Err(StorageError::InvalidInput(message))
                if message == "canonical proof payload hash mismatch" => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(invalid(
                    "canonical proof content is intact; use explicit verification recheck",
                ))
            }
        }
        let mut index: Index = decode(
            &self
                .store
                .get(&key(b"index"))?
                .ok_or_else(|| invalid("canonical proof cache index missing"))?,
        )?;
        let reserved = index
            .reserved_bytes
            .checked_add(status.manifest.total_bytes)
            .ok_or_else(|| invalid("canonical proof reservation overflow"))?;
        let archived = index
            .archived_attempts
            .checked_add(1)
            .ok_or_else(|| invalid("canonical proof archive overflow"))?;
        if index.version != 1
            || !index.objects.contains(id)
            || (index.objects.len() as u64)
                .checked_add(archived)
                .is_none_or(|n| n > MAX_CANONICAL_PROOF_OBJECTS as u64)
            || reserved > MAX_CANONICAL_PROOF_CACHE_BYTES
        {
            return Err(invalid("canonical proof cache reservation limit"));
        }
        let generation = status
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("canonical proof generation overflow"))?;
        if self
            .store
            .get(&attempt_key(id, status.generation))?
            .is_some()
        {
            return Err(invalid("canonical proof archive already exists"));
        }
        let mut batch = WriteBatch::new();
        batch.put(attempt_key(id, status.generation), encode(&status)?);
        if let Some(fetch) = self.store.get(&fetch_key(id))? {
            batch.put(fetch_attempt_key(id, status.generation), fetch);
        }
        status.generation = generation;
        status.state = CanonicalProofUploadState::Uploading;
        status.received_bytes = 0;
        status.next_chunk = 0;
        status.result = None;
        status.error = None;
        index.reserved_bytes = reserved;
        index.archived_attempts = archived;
        batch.put(key(b"index"), encode(&index)?);
        batch.put(object_key(id), encode(&status)?);
        self.store.write_batch(batch)?;
        Ok(status)
    }
    pub fn fetch_status(
        &self,
        id: &ShellHash,
        generation: Option<u64>,
    ) -> Result<Option<CanonicalProofFetchStatus>, StorageError> {
        let current = self.status(id)?;
        let record = match generation {
            Some(generation) if generation != current.generation => {
                fetch_attempt_key(id, generation)
            }
            _ => fetch_key(id),
        };
        let status = self
            .store
            .get(&record)?
            .map(|bytes| decode::<CanonicalProofFetchStatus>(&bytes))
            .transpose()?;
        if let Some(ref status) = status {
            // A crash after archiving but before the next request leaves the last
            // persisted nonce in the preceding generation. Never lose that nonce.
            if generation == Some(current.generation) && status.generation < current.generation {
                return Ok(None);
            }
            if status.version != 1
                || status.proof_id != *id
                || status.generation > current.generation
                || generation.is_some_and(|g| g != status.generation)
                || status.peer.is_empty()
                || status.peer.len() > 128
                || status.nonce == 0
                || status.received_bytes > current.manifest.total_bytes
                || status
                    .error
                    .as_ref()
                    .is_some_and(|e| e.chars().count() > 2048)
            {
                return Err(invalid("canonical proof fetch metadata inconsistent"));
            }
        }
        Ok(status)
    }
    pub fn save_fetch_status(
        &self,
        status: &CanonicalProofFetchStatus,
    ) -> Result<(), StorageError> {
        let _guard = self.verifying.lock();
        let current = self.status(&status.proof_id)?;
        if status.version != 1
            || status.generation != current.generation
            || status.peer.is_empty()
            || status.peer.len() > 128
            || status.nonce == 0
            || status.next_chunk != current.next_chunk
            || status.received_bytes != current.received_bytes
            || status
                .error
                .as_ref()
                .is_some_and(|e| e.chars().count() > 2048)
            || (status.state == CanonicalProofFetchState::Complete
                && current.state != CanonicalProofUploadState::Verified)
        {
            return Err(invalid("canonical proof fetch metadata inconsistent"));
        }
        self.store
            .put(&fetch_key(&status.proof_id), &encode(status)?)
    }
    pub fn verification_in_flight(&self, id: &ShellHash) -> bool {
        *self.verifying.lock() == Some(*id)
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
    /// Release a joined worker without an execution receipt. Raw chunks and attempt
    /// counters remain immutable; a later owner must perform full verification again.
    pub fn pause_claim(&self, id: &ShellHash, attempt: u32) -> Result<(), StorageError> {
        let mut worker = self.verifying.lock();
        let mut status = self.status(id)?;
        if *worker != Some(*id)
            || status.state != CanonicalProofUploadState::Verifying
            || status.verification_attempts != attempt
        {
            return Err(invalid("canonical claim owner changed"));
        }
        status.state = CanonicalProofUploadState::Ready;
        status.result = None;
        status.error =
            Some("verification interrupted before native commit; full recheck required".into());
        self.store.put(&object_key(id), &encode(&status)?)?;
        self.store.flush()?;
        *worker = None;
        Ok(())
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
    fn interrupted_claim_keeps_bytes_and_requires_new_verification_owner() {
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        let m = manifest(b"abc", 2);
        let id = cache.begin(m.clone()).unwrap().proof_id;
        assert!(cache.available_manifests().unwrap().is_empty());
        cache.append(&id, 0, b"abc").unwrap();
        assert_eq!(cache.available_manifests().unwrap(), vec![m.clone()]);
        let (first, claimed) = cache.claim(&id, true).unwrap();
        assert!(claimed);
        let before = db.scan_all().unwrap();
        assert!(cache
            .pause_claim(&id, first.verification_attempts + 1)
            .is_err());
        assert_eq!(db.scan_all().unwrap(), before);
        cache.pause_claim(&id, first.verification_attempts).unwrap();
        assert_eq!(cache.payload(&id).unwrap(), b"abc");
        assert_eq!(
            cache.status(&id).unwrap().state,
            CanonicalProofUploadState::Ready
        );
        assert!(cache
            .complete(&id, Ok(serde_json::json!({"forged":true})))
            .is_err());
        let (second, claimed) = cache.claim(&id, true).unwrap();
        assert!(claimed);
        assert_eq!(
            second.verification_attempts,
            first.verification_attempts + 1
        );
        cache.complete(&id, Err("invalid full AIR".into())).unwrap();
        assert!(cache.available_manifests().unwrap().is_empty());
        assert_eq!(cache.payload(&id).unwrap(), b"abc");
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
    fn reject_corrupt<S: KvStore>(cache: &CanonicalProofUploadStore<S>, tag: u8) -> ShellHash {
        let id = cache.begin(manifest(b"a", tag)).unwrap().proof_id;
        cache.append(&id, 0, b"b").unwrap();
        cache.claim(&id, false).unwrap();
        let error = cache.payload(&id).unwrap_err().to_string();
        cache.complete(&id, Err(error)).unwrap();
        id
    }
    #[test]
    fn canonical_proof_upload_corrupt_generation_archive_and_recovery_keep_all_bytes() {
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        let id = reject_corrupt(&cache, 7);
        let rejected = cache.status(&id).unwrap();
        assert!(!serde_json::to_value(&rejected)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("generation"));
        let failed = CanonicalProofFetchStatus {
            version: 1,
            proof_id: id,
            generation: 0,
            peer: "peer-a".into(),
            nonce: 1,
            next_chunk: 1,
            received_bytes: 1,
            state: CanonicalProofFetchState::Failed,
            error: Some("hash mismatch".into()),
        };
        cache.save_fetch_status(&failed).unwrap();
        let raw = db.get(&chunk_key(&id, 0)).unwrap();
        let fresh = cache.restart_corrupt(&id).unwrap();
        assert_eq!(fresh.generation, 1);
        assert_eq!(fresh.received_bytes, 0);
        assert_eq!(fresh.verification_attempts, 1);
        assert_eq!(cache.attempt_status(&id, 0).unwrap(), rejected);
        assert_eq!(cache.attempt_chunk(&id, 0, 0).unwrap(), b"b");
        assert_eq!(cache.fetch_status(&id, Some(0)).unwrap(), Some(failed));
        assert_eq!(db.get(&chunk_key(&id, 0)).unwrap(), raw);
        let before = db.scan_all().unwrap();
        assert!(cache.restart_corrupt(&id).is_err());
        assert_eq!(db.scan_all().unwrap(), before);
        cache.append(&id, 0, b"a").unwrap();
        cache.claim(&id, false).unwrap();
        assert_eq!(cache.payload(&id).unwrap(), b"a");
        cache
            .complete(&id, Ok(serde_json::json!({"receipt":"informational"})))
            .unwrap();
        drop(cache);
        let cache = CanonicalProofUploadStore::new(db.clone());
        assert_eq!(cache.status(&id).unwrap().generation, 1);
        assert_eq!(cache.attempt_chunk(&id, 0, 0).unwrap(), b"b");
        assert_eq!(cache.chunk(&id, 0).unwrap(), b"a");
        let before = db.scan_all().unwrap();
        assert!(cache.restart_corrupt(&id).is_err());
        assert_eq!(db.scan_all().unwrap(), before);
        assert!(cache.attempt_status(&id, 2).is_err());
    }
    #[test]
    fn canonical_proof_upload_retry_reserves_failed_data_and_refuses_intact_invalid_proofs() {
        for full_bytes in [false, true] {
            let db = Arc::new(MemoryDb::new());
            let cache = CanonicalProofUploadStore::new(db.clone());
            let id = reject_corrupt(&cache, 1);
            if full_bytes {
                let mut m = manifest(b"a", 2);
                m.total_bytes = MAX_CANONICAL_PROOF_BYTES;
                cache.begin(m).unwrap();
                let mut m = manifest(b"a", 3);
                m.total_bytes = MAX_CANONICAL_PROOF_BYTES - 1;
                cache.begin(m).unwrap();
            } else {
                for tag in 2..=8 {
                    cache.begin(manifest(b"a", tag)).unwrap();
                }
            }
            let before = db.scan_all().unwrap();
            assert!(cache.restart_corrupt(&id).is_err());
            assert_eq!(db.scan_all().unwrap(), before);
        }
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        let id = cache.begin(manifest(b"a", 1)).unwrap().proof_id;
        cache.append(&id, 0, b"a").unwrap();
        cache.claim(&id, false).unwrap();
        cache
            .complete(&id, Err("canonical proof payload hash mismatch".into()))
            .unwrap();
        let before = db.scan_all().unwrap();
        assert!(cache.restart_corrupt(&id).is_err());
        assert_eq!(db.scan_all().unwrap(), before);
    }
    #[test]
    #[cfg(feature = "rocksdb")]
    fn canonical_proof_upload_archive_survives_native_restart() {
        let dir = std::env::temp_dir().join(format!(
            "shell-canonical-proof-archive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let id;
        {
            let stores = crate::RocksDbStore::open_all(&dir, None).unwrap();
            let cache = CanonicalProofUploadStore::new(Arc::new(stores.state));
            id = reject_corrupt(&cache, 9);
            cache.restart_corrupt(&id).unwrap();
            cache.append(&id, 0, b"a").unwrap();
        }
        {
            let stores = crate::RocksDbStore::open_all(&dir, None).unwrap();
            let cache = CanonicalProofUploadStore::new(Arc::new(stores.state));
            assert_eq!(cache.status(&id).unwrap().generation, 1);
            assert_eq!(cache.payload(&id).unwrap(), b"a");
            assert_eq!(cache.attempt_chunk(&id, 0, 0).unwrap(), b"b");
            cache.claim(&id, false).unwrap();
            cache
                .complete(&id, Ok(serde_json::json!({"saved":true})))
                .unwrap();
        }
        {
            let stores = crate::RocksDbStore::open_all(&dir, None).unwrap();
            let cache = CanonicalProofUploadStore::new(Arc::new(stores.state));
            assert_eq!(
                cache.status(&id).unwrap().state,
                CanonicalProofUploadState::Verified
            );
            assert_eq!(
                cache.attempt_status(&id, 0).unwrap().state,
                CanonicalProofUploadState::Rejected
            );
        }
        println!("canonical proof upload store retained at {}", dir.display());
    }
    #[test]
    fn canonical_proof_upload_archive_crash_window_preserves_last_issued_nonce() {
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        let id = reject_corrupt(&cache, 3);
        let prior = CanonicalProofFetchStatus {
            version: 1,
            proof_id: id,
            generation: 0,
            peer: "peer".into(),
            nonce: 91,
            next_chunk: 1,
            received_bytes: 1,
            state: CanonicalProofFetchState::Failed,
            error: Some("bad hash".into()),
        };
        cache.save_fetch_status(&prior).unwrap();
        cache.restart_corrupt(&id).unwrap();
        drop(cache);
        let cache = CanonicalProofUploadStore::new(db);
        assert_eq!(cache.fetch_status(&id, None).unwrap(), Some(prior.clone()));
        assert!(cache.fetch_status(&id, Some(1)).unwrap().is_none());
        assert_eq!(
            cache.fetch_status(&id, Some(0)).unwrap(),
            Some(prior.clone())
        );
        let next = CanonicalProofFetchStatus {
            generation: 1,
            nonce: prior.nonce + 1,
            next_chunk: 0,
            received_bytes: 0,
            state: CanonicalProofFetchState::Receiving,
            error: None,
            ..prior
        };
        cache.save_fetch_status(&next).unwrap();
        assert_eq!(cache.fetch_status(&id, None).unwrap(), Some(next));
    }
}
