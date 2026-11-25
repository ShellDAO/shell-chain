//! Bounded opt-in automatic full sender-proof generation, separate from settlement.
mod compressed;
use super::*;
use serde::{Deserialize, Serialize};
use shell_primitives::blake3_hash;
use shell_stark_prover::{
    canonical_producer::CanonicalProductionSource,
    production_store::{ProductionError, ProductionStore},
};
use shell_storage::{
    CanonicalProofManifest, EntryVisitor, StorageError, WriteBatch, WriteBatchOp,
    CANONICAL_PROOF_CHUNK_BYTES, MAX_CANONICAL_PROOF_BYTES,
};
use std::time::Duration;
use std::{
    collections::{BTreeMap, HashSet},
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
};

const PREFIX: &[u8] = b"local/canonical-production/v1/";
const MAX_JOBS: usize = 2;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const DATA_CEILING: u64 = MAX_BYTES - 64 * 1024;
const REFERENCE: &[u8] = b"\0canonical-certificate/v1/";
const ACCOUNT_POOL: &[u8] = b"\0canonical-account-pool/v1/";
const MAX_ACCOUNT_COMPONENT: usize = 8 * 1024 * 1024 + 64;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountCertificate {
    version: u8,
    bytes: usize,
    hash: ShellHash,
    template: String,
    certificates: Vec<ShellHash>,
}
fn account_part_key(hash: ShellHash) -> Vec<u8> {
    key(&[b"account-parts/".as_slice(), hash.as_bytes()].concat())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateReference {
    version: u8,
    block: ShellHash,
    bytes: usize,
    hash: ShellHash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    component: Option<String>,
}
fn certificate_prefix(hash: ShellHash) -> Vec<u8> {
    key(&[b"certificates/".as_slice(), hash.as_bytes(), b"/"].concat())
}
fn key(suffix: &[u8]) -> Vec<u8> {
    [PREFIX, suffix].concat()
}
fn record_key(hash: ShellHash) -> Vec<u8> {
    key(&[b"record/".as_slice(), hash.as_bytes()].concat())
}
fn source_key(hash: ShellHash) -> Vec<u8> {
    key(&[b"source/".as_slice(), hash.as_bytes()].concat())
}
fn error(e: impl std::fmt::Display) -> StorageError {
    StorageError::State(e.to_string())
}
fn encode(v: &impl Serialize) -> Result<Vec<u8>, StorageError> {
    serde_json::to_vec(v).map_err(error)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CanonicalProductionState {
    Queued,
    Proving,
    Paused,
    Complete,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalProductionStatus {
    pub version: u8,
    pub block_hash: ShellHash,
    pub block_number: u64,
    pub source_hash: ShellHash,
    pub state: CanonicalProductionState,
    pub components: usize,
    pub checkpoint_bytes: usize,
    pub newly_proved: usize,
    pub reused: usize,
    pub manifest: Option<CanonicalProofManifest>,
    pub error: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuorumJobIndex {
    version: u8,
    active: Vec<ShellHash>,
    completed: Vec<ShellHash>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderJobIndex {
    version: u8,
    role: String,
    active: Vec<ShellHash>,
    completed: Vec<ShellHash>,
}
#[derive(Clone, Copy)]
enum ProductionRole {
    Sender,
    Quorum,
}

/// One shared writer lock and global quota for descriptors, records and certificates.
pub(super) struct CanonicalProductionStore<S: KvStore> {
    store: Arc<S>,
    lock: Arc<parking_lot::Mutex<Option<u64>>>,
    role: ProductionRole,
}
impl<S: KvStore> CanonicalProductionStore<S> {
    pub(super) fn new(store: Arc<S>) -> Self {
        Self {
            store,
            lock: Arc::new(parking_lot::Mutex::new(None)),
            role: ProductionRole::Sender,
        }
    }
    pub(super) fn new_quorum(store: Arc<S>) -> Self {
        Self {
            role: ProductionRole::Quorum,
            ..Self::new(store)
        }
    }
    fn job_index(&self) -> Result<QuorumJobIndex, StorageError> {
        let bytes = self
            .store
            .get(&key(b"jobs"))?
            .unwrap_or_else(|| b"[]".to_vec());
        if bytes.len() > 4096 {
            return Err(error("production job index byte limit"));
        }
        let index = if bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
            match self.role {
                ProductionRole::Quorum => {
                    let index: QuorumJobIndex = serde_json::from_slice(&bytes).map_err(error)?;
                    if index.version != 2 {
                        return Err(error("quorum job history version"));
                    }
                    index
                }
                ProductionRole::Sender => {
                    let index: SenderJobIndex = serde_json::from_slice(&bytes).map_err(error)?;
                    if index.version != 3 || index.role != "sender" {
                        return Err(error("sender job history role/version"));
                    }
                    QuorumJobIndex {
                        version: index.version,
                        active: index.active,
                        completed: index.completed,
                    }
                }
            }
        } else {
            QuorumJobIndex {
                version: 1,
                active: serde_json::from_slice(&bytes).map_err(error)?,
                completed: vec![],
            }
        };
        let ids: Vec<_> = index.completed.iter().chain(&index.active).collect();
        if index.active.len() > MAX_JOBS
            || ids.len() > shell_storage::MAX_CANONICAL_PROOF_OBJECTS
            || ids.iter().copied().collect::<HashSet<_>>().len() != ids.len()
        {
            return Err(error("canonical production job index corrupt"));
        }
        Ok(index)
    }
    pub(super) fn all_ids(&self) -> Result<Vec<ShellHash>, StorageError> {
        let index = self.job_index()?;
        Ok(index.completed.into_iter().chain(index.active).collect())
    }
    pub(super) fn ids(&self) -> Result<Vec<ShellHash>, StorageError> {
        Ok(self.job_index()?.active)
    }
    fn checked_total(&self, observed: &mut Option<u64>) -> Result<u64, StorageError> {
        let old = self
            .store
            .get(&key(b"bytes"))?
            .map(|b| {
                <[u8; 8]>::try_from(b)
                    .map(u64::from_be_bytes)
                    .map_err(|_| error("canonical production quota width mismatch"))
            })
            .transpose()?
            .unwrap_or(0);
        if let Some(expected) = *observed {
            if old != expected {
                return Err(error("canonical production quota counter changed"));
            }
        } else {
            let mut actual = 0u64;
            self.store
                .visit_prefix_range(PREFIX, PREFIX, None, false, &mut |k, v| {
                    if k != key(b"bytes") {
                        actual = actual
                            .checked_add((k.len() + v.len()) as u64)
                            .ok_or_else(|| error("canonical production accounting overflow"))?;
                    }
                    if actual > MAX_BYTES {
                        return Err(error("canonical production retained data exceeds quota"));
                    }
                    Ok(true)
                })?;
            if actual != old {
                return Err(error("canonical production quota counter mismatch"));
            }
        }
        *observed = Some(old);
        Ok(old)
    }
    fn write_locked(
        &self,
        changes: Vec<(Vec<u8>, Vec<u8>)>,
        observed: &mut Option<u64>,
        ceiling: u64,
    ) -> Result<(), StorageError> {
        let old = self.checked_total(observed)?;
        let mut total = old;
        let changes: BTreeMap<_, _> = changes.into_iter().collect();
        let mut batch = WriteBatch::new();
        for (k, v) in changes {
            if !k.starts_with(PREFIX) || k == key(b"bytes") {
                return Err(error("canonical production namespace violation"));
            }
            let prior = self.store.get(&k)?;
            if let Some(bytes) = prior {
                total = total
                    .checked_sub((k.len() + bytes.len()) as u64)
                    .ok_or_else(|| error("canonical production accounting corrupt"))?;
            }
            total = total
                .checked_add((k.len() + v.len()) as u64)
                .ok_or_else(|| error("canonical production size overflow"))?;
            batch.put(k, v);
        }
        if total > ceiling {
            return Err(error(
                "canonical production global checkpoint quota exceeded",
            ));
        }
        batch.put(key(b"bytes"), total.to_be_bytes().to_vec());
        self.store.write_batch(batch)?;
        *observed = Some(total);
        self.store.flush()
    }
    // Writer-only compaction of reconstructible local checkpoints. Historical
    // reads never call this, and Native chain/state/receipt keys are untouched.
    fn compact_accounts(&self) -> Result<(), StorageError> {
        let mut guard = self.lock.lock();
        let old = self.checked_total(&mut guard)?;
        let mut changes = BTreeMap::new();
        let mut candidates = Vec::new();
        for block in self.ids()? {
            let job = self.job(block);
            let prefix = [job.prefix.as_slice(), b"production/component/"].concat();
            self.store
                .visit_prefix_range(&prefix, &prefix, None, false, &mut |k, v| {
                    let local = &k[job.prefix.len()..];
                    if local.ends_with(b"-account")
                        && !v.starts_with(REFERENCE)
                        && !v.starts_with(ACCOUNT_POOL)
                    {
                        if candidates.len()
                            >= MAX_JOBS
                                * shell_stark_prover::canonical_batch::MAX_CANONICAL_SIGNATURE_BATCH
                        {
                            return Err(error("account dictionary component count limit"));
                        }
                        candidates.push((block, k.to_vec(), local.to_vec(), v.to_vec()));
                    }
                    Ok(true)
                })?;
        }
        // Finish the storage iterator before looking up shared parts; some KV
        // implementations hold a read guard while visiting their entries.
        for (block, physical, local, bytes) in candidates {
            let pooled = self.job(block).pool_account(&local, &bytes, &mut changes)?;
            if pooled != bytes {
                changes.insert(physical, pooled);
            }
        }
        let mut total = old;
        for (k, v) in &changes {
            if let Some(prior) = self.store.get(k)? {
                total = total
                    .checked_sub((k.len() + prior.len()) as u64)
                    .ok_or_else(|| error("account pool accounting corrupt"))?;
            }
            total = total
                .checked_add((k.len() + v.len()) as u64)
                .ok_or_else(|| error("account pool size overflow"))?;
        }
        // Do not rewrite an inline component merely to add dictionary overhead.
        if total < old {
            self.write_locked(changes.into_iter().collect(), &mut guard, DATA_CEILING)?;
        }
        Ok(())
    }
    fn compact_legacy(&self) -> Result<(), StorageError> {
        let mut guard = self.lock.lock();
        self.checked_total(&mut guard)?;
        let mut candidates = Vec::new();
        for block in self.ids()? {
            let prefix = [
                certificate_prefix(block).as_slice(),
                b"production/component/",
            ]
            .concat();
            self.store
                .visit_prefix_range(&prefix, &prefix, None, false, &mut |k, v| {
                    if compressed::eligible(v) {
                        if candidates.len() >= MAX_JOBS * 2048 {
                            return Err(error("legacy compaction component count limit"));
                        }
                        candidates.push((k.to_vec(), v.to_vec()));
                    }
                    Ok(true)
                })?;
        }
        let mut changes = Vec::new();
        for (k, original) in candidates {
            if let Some(packed) = compressed::pack(&original)? {
                if compressed::restore(packed.clone())? != original {
                    return Err(error("legacy compaction roundtrip mismatch"));
                }
                changes.push((k, packed));
            }
        }
        if !changes.is_empty() {
            self.write_locked(changes, &mut guard, DATA_CEILING)?;
        }
        Ok(())
    }
    pub(super) fn status(
        &self,
        hash: ShellHash,
    ) -> Result<Option<CanonicalProductionStatus>, StorageError> {
        self.store
            .get(&record_key(hash))?
            .map(|b| {
                if b.len() > 16 * 1024 {
                    return Err(error("canonical production record size limit"));
                }
                let s: CanonicalProductionStatus = serde_json::from_slice(&b).map_err(error)?;
                if s.version != 1
                    || s.block_hash != hash
                    || s.components > 2048
                    || s.checkpoint_bytes > MAX_BYTES as usize
                {
                    return Err(error("canonical production record corrupt"));
                }
                Ok(s)
            })
            .transpose()
    }
    pub(super) fn save(&self, status: &CanonicalProductionStatus) -> Result<(), StorageError> {
        let mut guard = self.lock.lock();
        self.write_locked(
            vec![(record_key(status.block_hash), encode(status)?)],
            &mut guard,
            MAX_BYTES,
        )
    }
    pub(super) fn source(
        &self,
        status: &CanonicalProductionStatus,
    ) -> Result<Vec<u8>, StorageError> {
        let bytes = self
            .store
            .get(&source_key(status.block_hash))?
            .ok_or_else(|| error("canonical production source absent"))?;
        if bytes.len() > 4 * 1024 * 1024 || blake3_hash(&bytes) != status.source_hash {
            return Err(error("canonical production source hash/size mismatch"));
        }
        Ok(bytes)
    }
    #[cfg(test)]
    pub(super) fn insert_source(
        &self,
        hash: ShellHash,
        number: u64,
        identity: &[u8],
    ) -> Result<(), StorageError> {
        self.insert_source_retiring(hash, number, identity, None)
    }
    pub(super) fn insert_source_retiring(
        &self,
        hash: ShellHash,
        number: u64,
        identity: &[u8],
        retire: Option<ShellHash>,
    ) -> Result<(), StorageError> {
        if identity.len() > 4 * 1024 * 1024 {
            return Err(error("production source size limit"));
        }
        let mut guard = self.lock.lock();
        let index = self.job_index()?;
        if let Some(status) = self.status(hash)? {
            if !index.active.contains(&hash) && !index.completed.contains(&hash) {
                return Err(error("orphaned canonical production status retained"));
            }
            if status.block_number != number || self.source(&status)? != identity {
                return Err(error("immutable production source conflict"));
            }
            return Ok(());
        }
        let mut ids = index.active;
        let mut completed = index.completed;
        if ids.contains(&hash)
            || completed.contains(&hash)
            || self.store.get(&source_key(hash))?.is_some()
        {
            return Err(error("orphaned canonical production source/index retained"));
        }
        if ids.len() + completed.len() >= shell_storage::MAX_CANONICAL_PROOF_OBJECTS {
            return Err(error("canonical production retained history limit reached"));
        }
        if let Some(old) = retire {
            if ids.len() != MAX_JOBS || !ids.contains(&old) {
                return Err(error("completed production job retirement index mismatch"));
            }
            let status = self
                .status(old)?
                .ok_or_else(|| error("completed production job absent"))?;
            let version = match self.role {
                ProductionRole::Sender => 1,
                ProductionRole::Quorum => 2,
            };
            if status.state != CanonicalProductionState::Complete
                || status.error.is_some()
                || status.components == 0
                || status.checkpoint_bytes == 0
                || status.manifest.as_ref().is_none_or(|m| {
                    m.version != version || m.block_hash != old || m.validate().is_err()
                })
            {
                return Err(error("production job is not complete and available"));
            }
            self.source(&status)?;
            ids.retain(|id| *id != old);
            completed.push(old);
        } else if ids.len() >= MAX_JOBS {
            return Err(error("canonical production retained job limit reached"));
        }
        let status = CanonicalProductionStatus {
            version: 1,
            block_hash: hash,
            block_number: number,
            source_hash: blake3_hash(identity),
            state: CanonicalProductionState::Queued,
            components: 0,
            checkpoint_bytes: 0,
            newly_proved: 0,
            reused: 0,
            manifest: None,
            error: None,
        };
        ids.push(hash);
        // One index value prevents readers from observing mixed active/history sets.
        // Original source, record and checkpoint keys are never moved or deleted.
        let encoded = if completed.is_empty() {
            encode(&ids)?
        } else {
            match self.role {
                ProductionRole::Quorum => encode(&QuorumJobIndex {
                    version: 2,
                    active: ids,
                    completed,
                })?,
                ProductionRole::Sender => encode(&SenderJobIndex {
                    version: 3,
                    role: "sender".into(),
                    active: ids,
                    completed,
                })?,
            }
        };
        self.write_locked(
            vec![
                (key(b"jobs"), encoded),
                (record_key(hash), encode(&status)?),
                (source_key(hash), identity.to_vec()),
            ],
            &mut guard,
            DATA_CEILING,
        )
    }
    pub(super) fn job(&self, hash: ShellHash) -> ProductionJob<S> {
        ProductionJob {
            store: self.store.clone(),
            lock: self.lock.clone(),
            block: hash,
            prefix: certificate_prefix(hash),
            role: self.role,
        }
    }
}
/// Scoped job KV reuses the mathematical producer's atomic checkpoint format.
pub(super) struct ProductionJob<S: KvStore> {
    store: Arc<S>,
    lock: Arc<parking_lot::Mutex<Option<u64>>>,
    block: ShellHash,
    prefix: Vec<u8>,
    role: ProductionRole,
}
impl<S: KvStore> ProductionJob<S> {
    fn component_name(k: &[u8]) -> Result<&str, StorageError> {
        let name = std::str::from_utf8(
            k.strip_prefix(b"production/component/")
                .ok_or_else(|| error("not a production component"))?,
        )
        .map_err(error)?;
        if name.is_empty()
            || name.len() > 96
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(error("invalid referenced component name"));
        }
        Ok(name)
    }
    fn restore_account(&self, bytes: Vec<u8>) -> Result<Vec<u8>, StorageError> {
        let bytes = compressed::restore(bytes)?;
        let Some(encoded) = bytes.strip_prefix(ACCOUNT_POOL) else {
            return Ok(bytes);
        };
        if encoded.len() > MAX_ACCOUNT_COMPONENT {
            return Err(error("account dictionary envelope byte limit"));
        }
        let account: AccountCertificate = serde_json::from_slice(encoded).map_err(error)?;
        if account.version != 1
            || account.bytes > MAX_ACCOUNT_COMPONENT
            || account.certificates.len() > 2048
            || account.template.len() > 4 * 1024 * 1024
        {
            return Err(error("account dictionary metadata limit"));
        }
        let mut parts = Vec::new();
        let mut total = 0usize;
        for hash in account.certificates {
            let part = self
                .store
                .get(&account_part_key(hash))?
                .ok_or_else(|| error("missing account dictionary certificate"))?;
            total = total
                .checked_add(part.len())
                .ok_or_else(|| error("account dictionary size overflow"))?;
            if part.len() > 8 * 1024 * 1024
                || total > MAX_ACCOUNT_COMPONENT + 2048 * 64
                || blake3_hash(&part) != hash
            {
                return Err(error(
                    "account dictionary certificate integrity/size mismatch",
                ));
            }
            parts.push(part);
        }
        let restored =
            shell_stark_prover::compact_canonical::restore_checkpoint(&account.template, &parts)
                .map_err(error)?;
        if restored.len() != account.bytes || blake3_hash(&restored) != account.hash {
            return Err(error("account dictionary component integrity mismatch"));
        }
        Ok(restored)
    }
    fn pool_account(
        &self,
        k: &[u8],
        bytes: &[u8],
        changes: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, StorageError> {
        if !Self::component_name(k)?.ends_with("-account") {
            return Ok(bytes.to_vec());
        }
        let Some(parts) =
            shell_stark_prover::compact_canonical::split_checkpoint(bytes).map_err(error)?
        else {
            return Ok(bytes.to_vec());
        };
        // Roundtrip before replacing any physical bytes. The original index,
        // length and hash continue to describe exactly the same logical value.
        if shell_stark_prover::compact_canonical::restore_checkpoint(
            &parts.template,
            &parts.certificates,
        )
        .map_err(error)?
            != bytes
        {
            return Err(error("account dictionary roundtrip mismatch"));
        }
        let mut certificates = Vec::new();
        for part in parts.certificates {
            let hash = blake3_hash(&part);
            let key = account_part_key(hash);
            if let Some(prior) = changes.get(&key).cloned().or(self.store.get(&key)?) {
                if prior != part {
                    return Err(error("account dictionary certificate hash collision"));
                }
            } else {
                changes.insert(key, part);
            }
            certificates.push(hash);
        }
        let envelope = AccountCertificate {
            version: 1,
            bytes: bytes.len(),
            hash: blake3_hash(bytes),
            template: parts.template,
            certificates,
        };
        let encoded = encode(&envelope)?;
        if encoded.len() > MAX_ACCOUNT_COMPONENT {
            return Err(error("account dictionary envelope byte limit"));
        }
        Ok([ACCOUNT_POOL, encoded.as_slice()].concat())
    }
    fn anchor(
        &self,
        k: &[u8],
        bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, ShellHash, String), StorageError> {
        let name = Self::component_name(k)?;
        let Some(encoded) = bytes.strip_prefix(REFERENCE) else {
            return Ok((self.restore_account(bytes)?, self.block, name.into()));
        };
        if encoded.len() > 1024 {
            return Err(error("production certificate reference size limit"));
        }
        let reference: CertificateReference = serde_json::from_slice(encoded).map_err(error)?;
        let target_name = match (reference.version, reference.component.as_deref()) {
            (1, None) if reference.block != self.block => name,
            (2, Some(target)) if reference.block != self.block || target != name => target,
            _ => return Err(error("invalid production certificate reference target")),
        };
        let target_key = [b"production/component/", target_name.as_bytes()].concat();
        Self::component_name(&target_key)?;
        let owner = CanonicalProductionStore {
            store: self.store.clone(),
            lock: self.lock.clone(),
            role: self.role,
        };
        let ids = owner.all_ids()?;
        if reference.bytes > MAX_BYTES as usize
            || !ids.contains(&self.block)
            || !ids.contains(&reference.block)
        {
            return Err(error("invalid production certificate reference owner"));
        }
        let target = self
            .store
            .get(
                &[
                    certificate_prefix(reference.block).as_slice(),
                    target_key.as_slice(),
                ]
                .concat(),
            )?
            .ok_or_else(|| error("missing production certificate reference target"))?;
        if target.starts_with(REFERENCE) {
            return Err(error("chained production certificate reference"));
        }
        let target = self.restore_account(target)?;
        if target.len() != reference.bytes || blake3_hash(&target) != reference.hash {
            return Err(error("production certificate reference integrity mismatch"));
        }
        Ok((target, reference.block, target_name.into()))
    }
    fn resolve(&self, k: &[u8], bytes: Vec<u8>) -> Result<Vec<u8>, StorageError> {
        if !k.starts_with(b"production/component/") {
            return Ok(bytes);
        }
        self.anchor(k, bytes).map(|v| v.0)
    }
    fn reference_to(
        &self,
        k: &[u8],
        v: &[u8],
    ) -> Result<Option<CertificateReference>, StorageError> {
        let current = Self::component_name(k)?;
        let hash = blake3_hash(v);
        let owner = CanonicalProductionStore {
            store: self.store.clone(),
            lock: self.lock.clone(),
            role: self.role,
        };
        for block in owner.all_ids()? {
            let job = owner.job(block);
            let mut candidates = Vec::new();
            if block != self.block {
                candidates.push(k.to_vec());
            }
            if let Some(index) = job.get(b"production/index")? {
                if index.len() > 256 * 1024 {
                    return Err(error("production donor index size limit"));
                }
                let index: serde_json::Value = serde_json::from_slice(&index).map_err(error)?;
                let entries = index["components"]
                    .as_object()
                    .ok_or_else(|| error("production donor index shape"))?;
                if !matches!(index["version"].as_u64(), Some(1..=4)) || entries.len() > 2048 {
                    return Err(error("production donor index version/count"));
                }
                for (name, entry) in entries {
                    if entry["bytes"].as_u64() == Some(v.len() as u64)
                        && entry["hash"] == serde_json::to_value(hash).map_err(error)?
                    {
                        let key = [b"production/component/", name.as_bytes()].concat();
                        Self::component_name(&key)?;
                        if block != self.block || name != current {
                            candidates.push(key);
                        }
                    }
                }
            }
            for target in candidates {
                if let Some(raw) = self
                    .store
                    .get(&[job.prefix.as_slice(), target.as_slice()].concat())?
                {
                    let (bytes, anchor, name) = job.anchor(&target, raw)?;
                    if bytes != v {
                        continue;
                    }
                    if anchor == self.block && name == current {
                        return Err(error("cyclic production reference"));
                    }
                    let named = anchor == self.block || name != current;
                    return Ok(Some(CertificateReference {
                        version: if named { 2 } else { 1 },
                        block: anchor,
                        bytes: v.len(),
                        hash,
                        component: named.then_some(name),
                    }));
                }
            }
        }
        Ok(None)
    }
}
impl<S: KvStore> KvStore for ProductionJob<S> {
    fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.store
            .get(&[self.prefix.as_slice(), k].concat())?
            .map(|bytes| self.resolve(k, bytes))
            .transpose()
    }
    fn put(&self, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
        let mut b = WriteBatch::new();
        b.put(k.to_vec(), v.to_vec());
        self.write_batch(b)
    }
    fn delete(&self, _: &[u8]) -> Result<(), StorageError> {
        Err(error("canonical production certificates cannot be deleted"))
    }
    fn flush(&self) -> Result<(), StorageError> {
        self.store.flush()
    }
    fn scan_prefix(&self, p: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        self.store
            .scan_prefix(&[self.prefix.as_slice(), p].concat())
            .and_then(|rows| {
                rows.into_iter()
                    .map(|(k, v)| {
                        let local = k[self.prefix.len()..].to_vec();
                        Ok((local.clone(), self.resolve(&local, v)?))
                    })
                    .collect()
            })
    }
    fn visit_all(&self, visitor: &mut EntryVisitor<'_>) -> Result<(), StorageError> {
        self.store
            .visit_prefix_range(&self.prefix, &self.prefix, None, false, &mut |k, v| {
                let local = &k[self.prefix.len()..];
                let bytes = self.resolve(local, v.to_vec())?;
                visitor(local, &bytes)?;
                Ok(true)
            })
    }
    fn write_batch(&self, b: WriteBatch) -> Result<(), StorageError> {
        let mut guard = self.lock.lock();
        let mut changes = BTreeMap::new();
        for op in b.ops() {
            match op {
                WriteBatchOp::Put { key: k, value: v } => {
                    if (k == b"production/source" || k.starts_with(b"production/component/"))
                        && self.get(k)?.is_some_and(|old| old != *v)
                    {
                        return Err(error("immutable production certificate conflict"));
                    }
                    let physical = [self.prefix.as_slice(), k].concat();
                    let mut value = v.clone();
                    if k.starts_with(b"production/component/") {
                        if let Some(existing) = self.store.get(&physical)? {
                            // Preserve an existing inline certificate or reference exactly.
                            value = existing;
                        } else if let Some(reference) = self.reference_to(k, v)? {
                            value = [REFERENCE, encode(&reference)?.as_slice()].concat();
                        } else {
                            value = self.pool_account(k, v, &mut changes)?;
                            value = compressed::pack(&value)?.unwrap_or(value);
                        }
                    }
                    changes.insert(physical, value);
                }
                WriteBatchOp::Delete { .. } => {
                    return Err(error("canonical production checkpoint deletion refused"))
                }
            }
        }
        CanonicalProductionStore {
            store: self.store.clone(),
            lock: self.lock.clone(),
            role: self.role,
        }
        .write_locked(changes.into_iter().collect(), &mut guard, DATA_CEILING)
    }
}

impl<S: KvStore + 'static> Node<S> {
    /// Called after native canonical publication; errors cannot undo or authorize a block.
    pub(super) fn capture_canonical_production(&self, block: &Block) {
        if !self.config.canonical_proof_production
            || !self.config.node_role.runs_prover()
            || block.transactions.is_empty()
        {
            return;
        }
        if !shell_stark_prover::canonical_producer::supports_production_senders(block) {
            return;
        }
        let captured = (|| -> Result<(), String> {
            if self
                .canonical_production
                .status(block.hash())
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Ok(());
            }
            let tip = self
                .chain_store
                .get_head_hash()
                .map_err(|e| e.to_string())?
                .ok_or("canonical production tip absent")?;
            let source = CanonicalProductionSource::capture(&self.chain_store, tip, block.hash())?;
            let retire = if self
                .canonical_production
                .ids()
                .map_err(|e| e.to_string())?
                .len()
                >= MAX_JOBS
            {
                self.completed_sender_job_slot()?
            } else {
                None
            };
            self.canonical_production
                .insert_source_retiring(
                    source.block().hash(),
                    source.block().number(),
                    source.identity(),
                    retire,
                )
                .map_err(|e| e.to_string())
        })();
        if let Err(error) = captured {
            warn!(block=%block.hash(),%error,"canonical sender proof capture unavailable; native block remains committed");
        }
    }
    fn completed_sender_job_slot(&self) -> Result<Option<ShellHash>, String> {
        let finalized = self
            .chain_store
            .get_finalized_number()
            .map_err(|e| e.to_string())?;
        let available = self
            .canonical_proof_uploads
            .available_manifests()
            .map_err(|e| e.to_string())?;
        let mut eligible = Vec::new();
        for id in self.canonical_production.ids().map_err(|e| e.to_string())? {
            let status = self
                .canonical_production
                .status(id)
                .map_err(|e| e.to_string())?
                .ok_or("indexed sender status absent")?;
            if status.state != CanonicalProductionState::Complete
                || status.error.is_some()
                || status.components == 0
                || status.checkpoint_bytes == 0
                || finalized.is_none_or(|n| n < status.block_number)
            {
                continue;
            }
            let source = self.restore_canonical_job(&status)?;
            if self
                .chain_store
                .get_block_by_hash(&id)
                .map_err(|e| e.to_string())?
                .as_ref()
                != Some(source.block())
            {
                return Err("completed sender canonical body changed".into());
            }
            let manifest = status
                .manifest
                .as_ref()
                .ok_or("completed sender manifest absent")?;
            if manifest.version != 1 {
                return Err("completed sender manifest role mismatch".into());
            }
            if !available.contains(manifest) {
                continue;
            }
            let upload = self
                .canonical_proof_uploads
                .status(&manifest.id())
                .map_err(|e| e.to_string())?;
            if upload.manifest != *manifest {
                return Err("completed sender availability source changed".into());
            }
            if !matches!(
                upload.state,
                shell_storage::CanonicalProofUploadState::Ready
                    | shell_storage::CanonicalProofUploadState::Verified
            ) {
                continue;
            }
            // Availability and finality permit local index rotation only. The
            // receiver still verifies the full proof before authorizing execution.
            self.canonical_proof_uploads
                .payload(&manifest.id())
                .map_err(|e| e.to_string())?;
            eligible.push((status.block_number, id));
        }
        Ok(eligible
            .into_iter()
            .min_by_key(|(number, _)| *number)
            .map(|(_, hash)| hash))
    }
    fn restore_canonical_job(
        &self,
        status: &CanonicalProductionStatus,
    ) -> Result<CanonicalProductionSource, String> {
        let bytes = self
            .canonical_production
            .source(status)
            .map_err(|e| e.to_string())?;
        let source = CanonicalProductionSource::restore(&self.chain_store, &bytes)?;
        if source.block().hash() != status.block_hash
            || source.block().number() != status.block_number
        {
            return Err("canonical production record/source identity mismatch".into());
        }
        if let Some(m) = &status.manifest {
            m.validate()?;
            if m.block_hash != status.block_hash
                || m.chain_id != source.chain_id()
                || m.genesis_hash != source.genesis_hash()
            {
                return Err("canonical production manifest/source identity mismatch".into());
            }
        }
        Ok(source)
    }
    pub fn canonical_production_status(
        &self,
        hash: ShellHash,
    ) -> Result<Option<serde_json::Value>, String> {
        {
            let mut guard = self.canonical_production.lock.lock();
            self.canonical_production
                .checked_total(&mut guard)
                .map_err(|e| e.to_string())?;
        }
        let status = self
            .canonical_production
            .status(hash)
            .map_err(|e| e.to_string())?;
        status.map(|s|{
            let source=self.restore_canonical_job(&s)?;
            Ok(serde_json::json!({"status":s,"block":source.block(),"nativeExecutionVerified":false}))
        }).transpose()
    }
    pub(super) fn production_manifest_source(
        &self,
        manifest: &CanonicalProofManifest,
    ) -> Result<bool, String> {
        let Some(status) = self
            .canonical_production
            .status(manifest.block_hash)
            .map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        if status.manifest.as_ref() != Some(manifest) {
            return Ok(false);
        }
        let source = self.restore_canonical_job(&status)?;
        Ok(source.chain_id() == manifest.chain_id
            && source.genesis_hash() == manifest.genesis_hash
            && source.block().hash() == manifest.block_hash)
    }
    fn produce_canonical_job(
        &self,
        mut status: CanonicalProductionStatus,
        limit: Option<NonZeroUsize>,
        cancel: &AtomicBool,
    ) -> usize {
        let mut spent = 0;
        status.newly_proved = 0;
        status.reused = 0;
        status.state = CanonicalProductionState::Proving;
        status.error = None;
        let result = (|| -> Result<CanonicalProofManifest, String> {
            let source = self.restore_canonical_job(&status)?;
            status.state = CanonicalProductionState::Proving;
            status.error = None;
            self.canonical_production
                .save(&status)
                .map_err(|e| e.to_string())?;
            let mut kv = self.canonical_production.job(status.block_hash);
            let mut donors = Vec::new();
            for hash in self
                .canonical_production
                .all_ids()
                .map_err(|e| e.to_string())?
            {
                if hash == status.block_hash {
                    continue;
                }
                if let Some(record) = self
                    .canonical_production
                    .status(hash)
                    .map_err(|e| e.to_string())?
                {
                    if record.state == CanonicalProductionState::Complete {
                        donors.push((hash, self.restore_canonical_job(&record)?));
                    }
                }
            }
            let reuse = |name: &str| -> Result<Option<Vec<u8>>, String> {
                for (hash, donor) in &donors {
                    if let Some(component) = source.reusable_component_from(donor, name) {
                        let donor_store = self.canonical_production.job(*hash);
                        let bytes = donor_store
                            .get(&[b"production/component/", component.as_bytes()].concat())
                            .map_err(|e| e.to_string())?;
                        if bytes.is_none()
                            && ["-matrix-sampler-", "-matrix-sponge-", "-matrix-keccak-"]
                                .iter()
                                .any(|v| component.contains(v))
                        {
                            let index = donor_store
                                .get(b"production/index")
                                .map_err(|e| e.to_string())?
                                .ok_or("donor index missing")?;
                            if index.len() > 256 * 1024 {
                                return Err("production donor index size limit".into());
                            }
                            let index: serde_json::Value =
                                serde_json::from_slice(&index).map_err(|e| e.to_string())?;
                            // Older layouts have no shared matrix proof parts.
                            // A missing part in a newer layout remains corruption.
                            if matches!(index["version"].as_u64(), Some(1 | 2)) {
                                continue;
                            }
                        }
                        return Ok(Some(bytes.ok_or("matching donor certificate missing")?));
                    }
                }
                Ok(None)
            };
            let interrupt =
                || cancel.load(Ordering::Acquire) || !self.prover_ready.load(Ordering::Acquire);
            let distinct_senders = source
                .block()
                .transactions
                .iter()
                .map(|tx| tx.from.as_bytes().to_vec())
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            let mut job = if source.needs_slh_encoding() {
                ProductionStore::open_slh(&mut kv, source.identity(), limit)
            } else if distinct_senders > 8 {
                ProductionStore::open_shared_matrix(&mut kv, source.identity(), limit)
            } else if source.block().transactions.len() > 2
                || source.has_unbound_senders()
                || source.needs_slh_encoding()
            {
                ProductionStore::open_compact(&mut kv, source.identity(), limit)
            } else {
                ProductionStore::open(&mut kv, source.identity(), limit)
            }
            .map_err(|e| e.to_string())?
            .with_interrupt(&interrupt)
            .with_reuse(&reuse);
            let result = source.produce(&mut job);
            let progress = job.progress();
            spent = progress.newly_proved;
            status.components = progress.components;
            status.checkpoint_bytes = progress.checkpoint_bytes;
            status.newly_proved = spent;
            status.reused = progress.reused;
            let proof = match result {
                Ok(p) => p,
                Err(ProductionError::Paused) => {
                    status.state = CanonicalProductionState::Paused;
                    return Err("component budget, readiness or shutdown pause".into());
                }
                Err(e) => return Err(e.to_string()),
            };
            source.recheck_canonical(&self.chain_store)?;
            if interrupt() {
                status.state = CanonicalProductionState::Paused;
                return Err("readiness or shutdown pause".into());
            }
            let payload = shell_stark_prover::compact_canonical::encode_payload(
                &proof,
                MAX_CANONICAL_PROOF_BYTES as usize,
                source.block().transactions.len() > 2 || source.needs_slh_encoding(),
            )?;
            let manifest = CanonicalProofManifest {
                version: 1,
                chain_id: source.chain_id(),
                genesis_hash: source.genesis_hash(),
                block_hash: source.block().hash(),
                total_bytes: payload.len() as u64,
                payload_hash: blake3_hash(&payload),
            };
            let mut cache = self
                .canonical_proof_uploads
                .begin(manifest.clone())
                .map_err(|e| e.to_string())?;
            for (index, chunk) in payload.chunks(CANONICAL_PROOF_CHUNK_BYTES).enumerate() {
                source.recheck_canonical(&self.chain_store)?;
                if index < (cache.next_chunk as usize) {
                    if self
                        .canonical_proof_uploads
                        .chunk(&manifest.id(), index as u32)
                        .map_err(|e| e.to_string())?
                        != chunk
                    {
                        return Err("canonical production cached chunk conflict".into());
                    }
                } else {
                    cache = self
                        .canonical_proof_uploads
                        .append(&manifest.id(), index as u32, chunk)
                        .map_err(|e| e.to_string())?;
                }
            }
            source.recheck_canonical(&self.chain_store)?;
            // Ready is byte availability, not an execution receipt or admission token.
            Ok(manifest)
        })();
        match result {
            Ok(manifest) => {
                status.state = CanonicalProductionState::Complete;
                status.manifest = Some(manifest);
                status.error = None;
            }
            Err(e) => {
                if status.state != CanonicalProductionState::Paused {
                    status.state = CanonicalProductionState::Failed;
                }
                status.error = Some(e.chars().take(2048).collect());
            }
        }
        if let Err(error) = self.canonical_production.save(&status) {
            warn!(%error,"canonical production status persistence failed; retained source/components require restart recheck");
        }
        spent
    }
    pub(super) fn start_canonical_production(
        self: &Arc<Self>,
    ) -> Result<Option<CanonicalProductionHandle>, NodeError> {
        if !self.config.canonical_proof_production {
            return Ok(None);
        }
        if !self.config.node_role.runs_prover() {
            return Err(NodeError::Startup(
                "canonical proof production requires a prover role".into(),
            ));
        }
        if let Some(block) = self.chain_store.get_head_block()? {
            self.capture_canonical_production(&block);
        }
        self.canonical_production.compact_accounts()?;
        self.canonical_production.compact_legacy()?;
        // Publish the explicit new-session retry before returning the handle.
        // RPC observers must not mistake the previous session's failure, pause
        // or in-flight state for this attempt while it waits for readiness.
        {
            let owner = &self.canonical_production;
            let mut guard = owner.lock.lock();
            let mut changes = Vec::new();
            for hash in owner.ids()? {
                if let Some(mut status) = owner.status(hash)? {
                    if matches!(
                        status.state,
                        CanonicalProductionState::Failed
                            | CanonicalProductionState::Paused
                            | CanonicalProductionState::Proving
                    ) {
                        status.state = CanonicalProductionState::Queued;
                        status.error = None;
                        changes.push((record_key(hash), encode(&status)?));
                    }
                }
            }
            if !changes.is_empty() {
                owner.write_locked(changes, &mut guard, MAX_BYTES)?;
            }
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let node = self.clone();
        let handle = tokio::spawn(async move {
            let mut attempted = HashSet::new();
            let mut used = 0usize;
            while !worker_cancel.load(Ordering::Acquire) {
                let budget = node.config.canonical_proof_component_budget;
                let available = budget.map(|n| n.get().saturating_sub(used));
                if node.prover_ready.load(Ordering::Acquire) && available != Some(0) {
                    let next = node.canonical_production.ids().and_then(|ids| {
                        for hash in ids {
                            if attempted.contains(&hash) {
                                continue;
                            }
                            if let Some(s) = node.canonical_production.status(hash)? {
                                // A new worker session may recover a failed attempt
                                // after its cause is fixed. The attempted set still
                                // prevents repeated failure dispatch in this session;
                                // source and all retained AIR certificates are rechecked.
                                if s.state != CanonicalProductionState::Complete {
                                    return Ok(Some(s));
                                }
                            }
                        }
                        Ok(None)
                    });
                    match next {
                        Ok(Some(status)) => {
                            let hash = status.block_hash;
                            attempted.insert(hash);
                            let n = node.clone();
                            let c = worker_cancel.clone();
                            let limit = available.and_then(NonZeroUsize::new);
                            match tokio::task::spawn_blocking(move || {
                                n.produce_canonical_job(status, limit, &c)
                            })
                            .await
                            {
                                Ok(spent) => {
                                    used = used.saturating_add(spent);
                                    if !cancellation_budget_exhausted(budget, used)
                                        && !worker_cancel.load(Ordering::Acquire)
                                        && node
                                            .canonical_production
                                            .status(hash)
                                            .ok()
                                            .flatten()
                                            .is_some_and(|s| {
                                                s.state == CanonicalProductionState::Paused
                                            })
                                    {
                                        attempted.remove(&hash);
                                    }
                                }
                                Err(error) => {
                                    warn!(%error,"canonical production worker panicked; source/components retained")
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!(%error,"canonical production queue is unavailable; no repeated dispatch");
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        Ok(Some(CanonicalProductionHandle {
            cancel,
            handle: Some(handle),
        }))
    }
}
pub(super) struct CanonicalProductionHandle {
    cancel: Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}
impl CanonicalProductionHandle {
    pub(super) fn new(cancel: Arc<AtomicBool>, handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            cancel,
            handle: Some(handle),
        }
    }
    pub(super) async fn shutdown(mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}
impl Drop for CanonicalProductionHandle {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

fn cancellation_budget_exhausted(budget: Option<NonZeroUsize>, used: usize) -> bool {
    budget.is_some_and(|n| used >= n.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_storage::MemoryDb;
    #[test]
    fn completed_sender_jobs_retain_sources_and_certificates_through_typed_history() {
        let db = Arc::new(MemoryDb::new());
        let (node, _) = crate::NodeBuilder::new(NodeConfig::dev(Address::ZERO), db.clone())
            .build()
            .unwrap();
        let owner = &node.canonical_production;
        let first = ShellHash::from([0x91; 32]);
        let second = ShellHash::from([0x92; 32]);
        let third = ShellHash::from([0x93; 32]);
        // Index/quota codec values only; these are not AIR or Native authorization.
        for (number, hash) in [first, second].into_iter().enumerate() {
            owner
                .insert_source(hash, number as u64 + 1, b"retained source")
                .unwrap();
            owner
                .job(hash)
                .put(b"production/component/key", b"certificate")
                .unwrap();
            let mut status = owner.status(hash).unwrap().unwrap();
            status.state = CanonicalProductionState::Complete;
            status.components = 1;
            status.checkpoint_bytes = 1;
            status.manifest = Some(CanonicalProofManifest {
                version: 1,
                chain_id: 1337,
                genesis_hash: ShellHash::from([9; 32]),
                block_hash: hash,
                total_bytes: 1,
                payload_hash: blake3_hash(b"x"),
            });
            owner.save(&status).unwrap();
        }
        let retained: Vec<_> = db
            .scan_all()
            .unwrap()
            .into_iter()
            .filter(|(k, _)| k != &key(b"jobs") && k != &key(b"bytes"))
            .collect();
        owner
            .insert_source_retiring(third, 3, b"new source", Some(first))
            .unwrap();
        assert_eq!(owner.ids().unwrap(), vec![second, third]);
        assert_eq!(owner.all_ids().unwrap(), vec![first, second, third]);
        let index: serde_json::Value =
            serde_json::from_slice(&db.get(&key(b"jobs")).unwrap().unwrap()).unwrap();
        assert_eq!(index["version"], 3);
        assert_eq!(index["role"], "sender");
        assert_eq!(
            owner
                .source(&owner.status(first).unwrap().unwrap())
                .unwrap(),
            b"retained source"
        );
        for (k, value) in retained {
            assert_eq!(db.get(&k).unwrap(), Some(value));
        }
        let before = db.scan_all().unwrap();
        assert_eq!(
            owner
                .job(first)
                .get(b"production/component/key")
                .unwrap()
                .unwrap(),
            b"certificate"
        );
        assert!(CanonicalProductionStore::new_quorum(db.clone())
            .all_ids()
            .is_err());
        assert_eq!(db.scan_all().unwrap(), before);
        owner
            .job(third)
            .put(b"production/component/key", b"certificate")
            .unwrap();
        let reopened = CanonicalProductionStore::new(db.clone());
        let before = db.scan_all().unwrap();
        for hash in [first, second, third] {
            assert_eq!(
                reopened.job(hash).get(b"production/component/key").unwrap(),
                Some(b"certificate".to_vec())
            );
        }
        assert_eq!(db.scan_all().unwrap(), before);
    }
    fn sender_history_fixture<S: KvStore + 'static>(db: Arc<S>) -> (Node<S>, Vec<Block>) {
        use shell_core::{Account, BlockHeader, SignedTransaction, Transaction};
        use shell_crypto::{DilithiumSigner, Signer};
        let signer = DilithiumSigner::generate();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let mut node = super::super::tests::setup_node_with_store(authority, db);
        node.config.enable_stark_aggregation = false;
        node.chain_store
            .put_pubkey(&authority, signer.public_key())
            .unwrap();
        let root = {
            let mut world = node.world_state.write();
            world
                .set_account(
                    &authority,
                    &Account::new_user_account(
                        blake3_hash(signer.public_key()),
                        U256::from(1_000_000_000u64),
                    ),
                )
                .unwrap();
            world.state_root().unwrap()
        };
        let genesis = Block {
            header: BlockHeader {
                state_root: root,
                proposer: authority,
                gas_limit: 30_000_000,
                base_fee_per_gas: 1,
                timestamp: 1_700_000_000,
                ..Default::default()
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let cfg = serde_json::from_value(serde_json::json!({
            "chain_id":1337,"genesis_hash":genesis.hash(),"fee_accounting_activation_height":1,
            "native_address_context_height":1,"block_commitment_height":1
        }))
        .unwrap();
        node.chain_store
            .commit_genesis_block(&genesis, &cfg)
            .unwrap();
        let mut blocks = vec![];
        for nonce in 0..3 {
            let tx = Transaction {
                chain_id: 1337,
                nonce,
                to: Some(Address::from([0x74; 32])),
                value: U256::from(100u64),
                data: Default::default(),
                gas_limit: 21_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 0,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let sig = signer
                .sign(tx.signing_hash(signer.sig_type().as_u8()).as_bytes())
                .unwrap();
            node.handle_incoming_tx(SignedTransaction::new(authority, tx, sig), &MultiVerifier)
                .unwrap();
            let block = node.produce_block(&signer, 1).unwrap();
            let cert = Node::<S>::encode_commit_certificate(&HashMap::from([(
                authority,
                signer.sign(block.hash().as_bytes()).unwrap(),
            )]))
            .unwrap();
            assert!(node.fast_finalize_with_certificate(block.number(), block.hash(), &cert));
            if nonce < 2 {
                let source = CanonicalProductionSource::capture(
                    &node.chain_store,
                    block.hash(),
                    block.hash(),
                )
                .unwrap();
                node.canonical_production
                    .insert_source(block.hash(), block.number(), source.identity())
                    .unwrap();
                let mut status = node
                    .canonical_production
                    .status(block.hash())
                    .unwrap()
                    .unwrap();
                status.state = CanonicalProductionState::Complete;
                status.components = 1;
                status.checkpoint_bytes = 1;
                // Availability markers exercise local lifecycle eligibility only.
                // Genuine full AIR and peer acceptance run through the example.
                let manifest = CanonicalProofManifest {
                    version: 1,
                    chain_id: 1337,
                    genesis_hash: genesis.hash(),
                    block_hash: block.hash(),
                    total_bytes: 1,
                    payload_hash: blake3_hash(b"x"),
                };
                let upload = node
                    .canonical_proof_uploads
                    .begin(manifest.clone())
                    .unwrap();
                node.canonical_proof_uploads
                    .append(&upload.proof_id, 0, b"x")
                    .unwrap();
                status.manifest = Some(manifest);
                node.canonical_production.save(&status).unwrap();
            }
            blocks.push(block);
        }
        node.config.canonical_proof_production = true;
        node.config.node_role = crate::NodeRole::Prover;
        (node, blocks)
    }
    #[test]
    fn completed_sender_capture_retires_oldest_with_native_state_unchanged() {
        let db = Arc::new(MemoryDb::new());
        let (node, blocks) = sender_history_fixture(db.clone());
        // Deliberately reverse active order: age, not index position, selects retirement.
        {
            let owner = &node.canonical_production;
            let mut guard = owner.lock.lock();
            owner
                .write_locked(
                    vec![(
                        key(b"jobs"),
                        encode(&vec![blocks[1].hash(), blocks[0].hash()]).unwrap(),
                    )],
                    &mut guard,
                    DATA_CEILING,
                )
                .unwrap();
        }
        assert_eq!(
            node.completed_sender_job_slot().unwrap(),
            Some(blocks[0].hash())
        );
        let before: Vec<_> = db
            .scan_all()
            .unwrap()
            .into_iter()
            .filter(|(k, _)| !k.starts_with(PREFIX))
            .collect();
        node.capture_canonical_production(&blocks[2]);
        assert_eq!(
            node.canonical_production.ids().unwrap(),
            vec![blocks[1].hash(), blocks[2].hash()]
        );
        assert_eq!(
            node.canonical_production.all_ids().unwrap(),
            blocks.iter().map(Block::hash).collect::<Vec<_>>()
        );
        assert_eq!(
            db.scan_all()
                .unwrap()
                .into_iter()
                .filter(|(k, _)| !k.starts_with(PREFIX))
                .collect::<Vec<_>>(),
            before
        );
        let before = db.scan_all().unwrap();
        for block in &blocks {
            assert!(node
                .canonical_production_status(block.hash())
                .unwrap()
                .is_some());
        }
        assert_eq!(db.scan_all().unwrap(), before);
    }
    #[test]
    fn completed_sender_capture_requires_finality_availability_and_valid_source() {
        for corruption in 0..8 {
            let db = Arc::new(MemoryDb::new());
            let (mut node, blocks) = sender_history_fixture(db.clone());
            let owner = &node.canonical_production;
            for block in &blocks[..2] {
                let mut s = owner.status(block.hash()).unwrap().unwrap();
                match corruption {
                    1 => s.state = CanonicalProductionState::Paused,
                    2 => s.error = Some("unfinished".into()),
                    3 => s.source_hash = ShellHash::ZERO,
                    4 => s.manifest.as_mut().unwrap().version = 2,
                    5 => s.manifest.as_mut().unwrap().chain_id += 1,
                    6 => {
                        s.manifest.as_mut().unwrap().payload_hash = blake3_hash(b"unavailable");
                    }
                    _ => (),
                }
                owner.save(&s).unwrap();
            }
            if corruption == 0 {
                node.chain_store.set_finalized_number(0).unwrap();
            } else if corruption == 7 {
                for (k, v) in db
                    .scan_prefix(shell_storage::CANONICAL_PROOF_CACHE_PREFIX)
                    .unwrap()
                {
                    if k.starts_with(
                        &[shell_storage::CANONICAL_PROOF_CACHE_PREFIX, b"data/"].concat(),
                    ) && v == b"x"
                    {
                        db.put(&k, b"y").unwrap();
                    }
                }
            }
            let before = db.scan_all().unwrap();
            node.capture_canonical_production(&blocks[2]);
            assert!(owner.status(blocks[2].hash()).unwrap().is_none());
            assert_eq!(db.scan_all().unwrap(), before);
            node.config.canonical_proof_production = false;
            node.capture_canonical_production(&blocks[2]);
            assert_eq!(db.scan_all().unwrap(), before);
        }
    }
    #[test]
    fn completed_sender_capture_rolls_back_the_entire_local_batch() {
        let db = Arc::new(super::super::tests::FailingBatchDb::new());
        let (node, blocks) = sender_history_fixture(db.clone());
        let before = db.scan_all().unwrap();
        db.fail_next_batch();
        node.capture_canonical_production(&blocks[2]);
        assert_eq!(db.scan_all().unwrap(), before);
        node.capture_canonical_production(&blocks[2]);
        assert_eq!(node.canonical_production.all_ids().unwrap().len(), 3);
    }
    #[test]
    fn sender_history_rejects_wrong_role_version_duplicate_and_oversize_indices_read_only() {
        let db = Arc::new(MemoryDb::new());
        let owner = CanonicalProductionStore::new(db.clone());
        let a = ShellHash::from([1; 32]);
        let b = ShellHash::from([2; 32]);
        let index = encode(&vec![a, b]).unwrap();
        db.put(&key(b"jobs"), &index).unwrap();
        let before = db.scan_all().unwrap();
        assert_eq!(owner.all_ids().unwrap(), vec![a, b]);
        assert_eq!(db.scan_all().unwrap(), before);
        for bad in [
            serde_json::json!({"version":2,"active":[b],"completed":[a]}),
            serde_json::json!({"version":3,"role":"quorum","active":[b],"completed":[a]}),
            serde_json::json!({"version":2,"role":"sender","active":[b],"completed":[a]}),
            serde_json::json!({"version":3,"role":"sender","active":[a],"completed":[a]}),
            serde_json::json!({"version":3,"role":"sender","active":[b],"completed":[a],"unknown":true}),
            serde_json::json!({"version":3,"role":"sender","active":[a,b,a],"completed":[]}),
        ] {
            db.put(&key(b"jobs"), &encode(&bad).unwrap()).unwrap();
            let before = db.scan_all().unwrap();
            assert!(owner.all_ids().is_err());
            assert_eq!(db.scan_all().unwrap(), before);
        }
    }
    #[test]
    fn sender_history_counts_archived_data_and_refuses_a_ninth_source_atomically() {
        let db = Arc::new(MemoryDb::new());
        let owner = CanonicalProductionStore::new(db.clone());
        for i in 1..=shell_storage::MAX_CANONICAL_PROOF_OBJECTS {
            let hash = ShellHash::from([i as u8; 32]);
            let ids = owner.ids().unwrap();
            owner
                .insert_source_retiring(
                    hash,
                    i as u64,
                    &[i as u8],
                    (ids.len() == MAX_JOBS).then(|| ids[0]),
                )
                .unwrap();
            owner
                .job(hash)
                .put(b"production/component/shared", b"retained")
                .unwrap();
            let mut s = owner.status(hash).unwrap().unwrap();
            s.state = CanonicalProductionState::Complete;
            s.components = 1;
            s.checkpoint_bytes = 8;
            s.manifest = Some(CanonicalProofManifest {
                version: 1,
                chain_id: 1337,
                genesis_hash: ShellHash::from([9; 32]),
                block_hash: hash,
                total_bytes: 1,
                payload_hash: blake3_hash(b"x"),
            });
            owner.save(&s).unwrap();
        }
        assert_eq!(owner.ids().unwrap().len(), MAX_JOBS);
        assert_eq!(
            owner.all_ids().unwrap().len(),
            shell_storage::MAX_CANONICAL_PROOF_OBJECTS
        );
        let before = db.scan_all().unwrap();
        let actual: u64 = before
            .iter()
            .filter(|(k, _)| k != &key(b"bytes"))
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum();
        assert_eq!(
            u64::from_be_bytes(db.get(&key(b"bytes")).unwrap().unwrap().try_into().unwrap()),
            actual
        );
        assert!(owner
            .insert_source_retiring(
                ShellHash::from([10; 32]),
                9,
                b"ninth",
                Some(owner.ids().unwrap()[0])
            )
            .is_err());
        assert_eq!(db.scan_all().unwrap(), before);
        let reopened = CanonicalProductionStore::new(db.clone());
        for id in reopened.all_ids().unwrap() {
            assert_eq!(
                reopened
                    .job(id)
                    .get(b"production/component/shared")
                    .unwrap(),
                Some(b"retained".to_vec())
            );
        }
        assert_eq!(db.scan_all().unwrap(), before);
    }
    #[test]
    fn legacy_compaction_preserves_original_bytes_references_and_native_state() {
        let db = Arc::new(MemoryDb::new());
        db.put(b"HEAD", b"native anchor").unwrap();
        let owner = CanonicalProductionStore::new(db.clone());
        let first = ShellHash::from([1; 32]);
        let second = ShellHash::from([2; 32]);
        let a = owner.job(first);
        let b = owner.job(second);
        let component = b"production/component/key";
        let original = format!(
            "{{ \"z\": [{}], \"a\": 7 }}",
            "17,".repeat(4096).trim_end_matches(',')
        )
        .into_bytes();
        {
            let mut guard = owner.lock.lock();
            owner
                .write_locked(
                    vec![
                        (key(b"jobs"), encode(&vec![first, second]).unwrap()),
                        ([a.prefix.as_slice(), component].concat(), original.clone()),
                    ],
                    &mut guard,
                    DATA_CEILING,
                )
                .unwrap();
        }
        b.put(component, &original).unwrap();
        let reference_key = [b.prefix.as_slice(), component].concat();
        let reference = db.get(&reference_key).unwrap().unwrap();
        assert!(reference.starts_with(REFERENCE));
        let before = owner.checked_total(&mut None).unwrap();
        owner.compact_legacy().unwrap();
        assert!(owner.checked_total(&mut None).unwrap() < before);
        let physical = [a.prefix.as_slice(), component].concat();
        let packed = db.get(&physical).unwrap().unwrap();
        assert!(packed.starts_with(compressed::PREFIX));
        let saved = db.scan_all().unwrap();
        assert_eq!(a.get(component).unwrap().unwrap(), original);
        assert_eq!(b.get(component).unwrap().unwrap(), original);
        assert_eq!(
            a.scan_prefix(b"production/component/").unwrap()[0].1,
            original
        );
        assert_eq!(db.get(&reference_key).unwrap().unwrap(), reference);
        owner.compact_legacy().unwrap();
        assert_eq!(saved, db.scan_all().unwrap());
        let mut changed = packed.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        db.put(&physical, &changed).unwrap();
        assert!(a.get(component).is_err());
        assert!(b.get(component).is_err());
        db.put(&physical, &packed).unwrap();
        assert_eq!(a.get(component).unwrap().unwrap(), original);
        let fresh = format!(
            "{{\"proof_bytes\":[{}]}}",
            "23,".repeat(4096).trim_end_matches(',')
        )
        .into_bytes();
        a.put(b"production/component/fresh", &fresh).unwrap();
        assert!(db
            .get(&[a.prefix.as_slice(), b"production/component/fresh"].concat())
            .unwrap()
            .unwrap()
            .starts_with(compressed::PREFIX));
        assert_eq!(db.get(b"HEAD").unwrap().unwrap(), b"native anchor");
    }
    #[test]
    fn account_dictionary_compaction_preserves_logical_bytes_references_and_native_data() {
        use shell_stark_prover::compact_canonical::encode_component;
        let db = Arc::new(MemoryDb::new());
        db.put(b"HEAD", b"native anchor").unwrap();
        let owner = CanonicalProductionStore::new(db.clone());
        let first = ShellHash::from([1; 32]);
        let second = ShellHash::from([2; 32]);
        let a = owner.job(first);
        let b = owner.job(second);
        // Codec/storage values only; these never claim mathematical authority.
        let account = |tag| {
            encode_component(&serde_json::json!({"version":1,
            "address_hash":{"proof_bytes":vec![1;4096]},
            "nodes":[{"proof_bytes":vec![2;4096]}, {"proof_bytes":vec![tag;4096]}]}))
            .unwrap()
        };
        let one = account(3);
        let two = account(4);
        let k0 = b"production/component/sender-0-account";
        let k1 = b"production/component/sender-1-account";
        {
            let mut guard = owner.lock.lock();
            owner
                .write_locked(
                    vec![
                        (key(b"jobs"), encode(&vec![first, second]).unwrap()),
                        ([a.prefix.as_slice(), k0].concat(), one.clone()),
                        ([a.prefix.as_slice(), k1].concat(), two.clone()),
                    ],
                    &mut guard,
                    DATA_CEILING,
                )
                .unwrap();
        }
        b.put(k0, &one).unwrap();
        let reference_key = [b.prefix.as_slice(), k0].concat();
        let reference = db.get(&reference_key).unwrap().unwrap();
        assert!(reference.starts_with(REFERENCE));
        let old = owner.checked_total(&mut None).unwrap();
        owner.compact_accounts().unwrap();
        assert!(owner.checked_total(&mut None).unwrap() < old);
        assert_eq!(db.get(&reference_key).unwrap().unwrap(), reference);
        let physical = [a.prefix.as_slice(), k0].concat();
        let envelope = db.get(&physical).unwrap().unwrap();
        assert!(envelope.starts_with(ACCOUNT_POOL));
        let before = db.scan_all().unwrap();
        assert_eq!(a.get(k0).unwrap().unwrap(), one);
        assert_eq!(a.get(k1).unwrap().unwrap(), two);
        assert_eq!(b.get(k0).unwrap().unwrap(), one);
        assert_eq!(a.scan_prefix(b"production/component/").unwrap().len(), 2);
        owner.compact_accounts().unwrap();
        assert_eq!(before, db.scan_all().unwrap());
        let parts_before = db.scan_prefix(&key(b"account-parts/")).unwrap().len();
        let three = account(5);
        b.put(b"production/component/sender-2-account", &three)
            .unwrap();
        assert_eq!(
            db.scan_prefix(&key(b"account-parts/")).unwrap().len(),
            parts_before + 1
        );
        assert_eq!(
            b.get(b"production/component/sender-2-account")
                .unwrap()
                .unwrap(),
            three
        );
        let row: AccountCertificate =
            serde_json::from_slice(envelope.strip_prefix(ACCOUNT_POOL).unwrap()).unwrap();
        let part_key = account_part_key(row.certificates[0]);
        let original = db.get(&part_key).unwrap().unwrap();
        let mut bad = original.clone();
        bad[0] ^= 1;
        db.put(&part_key, &bad).unwrap();
        assert!(a.get(k0).is_err());
        assert!(b.get(k0).is_err());
        db.delete(&part_key).unwrap();
        assert!(a.get(k0).is_err());
        db.put(&part_key, &original).unwrap();
        let mut row = row;
        row.hash = ShellHash::ZERO;
        db.put(
            &physical,
            &[ACCOUNT_POOL, encode(&row).unwrap().as_slice()].concat(),
        )
        .unwrap();
        assert!(a.get(k0).is_err());
        db.put(&physical, &envelope).unwrap();
        assert_eq!(a.get(k0).unwrap().unwrap(), one);
        assert_eq!(db.get(b"HEAD").unwrap().unwrap(), b"native anchor");
    }
    #[test]
    fn atomic_checkpoint_replacement_checks_final_quota_and_refuses_orphan_parts() {
        let db = Arc::new(MemoryDb::new());
        let owner = CanonicalProductionStore::new(db.clone());
        let mut guard = owner.lock.lock();
        owner
            .write_locked(vec![(key(b"z"), vec![0; 4096])], &mut guard, DATA_CEILING)
            .unwrap();
        let old = owner.checked_total(&mut guard).unwrap();
        owner
            .write_locked(
                vec![(key(b"a"), vec![1; 2048]), (key(b"z"), vec![2; 1024])],
                &mut guard,
                old,
            )
            .unwrap();
        assert!(owner.checked_total(&mut None).unwrap() < old);
        drop(guard);
        // Simulated counter boundary, not a claim of real 256MiB stress.
        *owner.lock.lock() = Some(MAX_BYTES - 1);
        db.put(&key(b"bytes"), &(MAX_BYTES - 1).to_be_bytes())
            .unwrap();
        let account = shell_stark_prover::compact_canonical::encode_component(&serde_json::json!({
            "address_hash":{"proof_bytes":[1]},"nodes":[{"proof_bytes":[2]}]}))
        .unwrap();
        let before = db.scan_all().unwrap();
        assert!(owner
            .job(ShellHash::ZERO)
            .put(b"production/component/sender-0-account", &account)
            .is_err());
        assert_eq!(before, db.scan_all().unwrap());
        assert!(db.scan_prefix(&key(b"account-parts/")).unwrap().is_empty());
    }
    #[test]
    fn named_local_references_and_cross_job_flattening_preserve_inline_anchor() {
        let db = Arc::new(MemoryDb::new());
        let owner = CanonicalProductionStore::new(db.clone());
        let first = ShellHash::from([1; 32]);
        let second = ShellHash::from([2; 32]);
        {
            let mut guard = owner.lock.lock();
            owner
                .write_locked(
                    vec![(key(b"jobs"), encode(&vec![first, second]).unwrap())],
                    &mut guard,
                    DATA_CEILING,
                )
                .unwrap();
        }
        let a = owner.job(first);
        let b = owner.job(second);
        let value = vec![7u8; 4096];
        let hash = blake3_hash(&value);
        a.put(b"production/component/z-key", &value).unwrap();
        let index = |both| {
            serde_json::to_vec(&if both {serde_json::json!({"version":1,"components":{"a-key":{"bytes":4096,"hash":hash},"z-key":{"bytes":4096,"hash":hash}}})}else{serde_json::json!({"version":1,"components":{"z-key":{"bytes":4096,"hash":hash}}})}).unwrap()
        };
        a.put(b"production/index", &index(false)).unwrap();
        a.put(b"production/component/a-key", &value).unwrap();
        assert_eq!(
            a.get(b"production/component/a-key").unwrap().unwrap(),
            value
        );
        a.put(b"production/index", &index(true)).unwrap();
        b.put(b"production/component/b-key", &value).unwrap();
        let physical = [b.prefix.as_slice(), b"production/component/b-key"].concat();
        let raw = db.get(&physical).unwrap().unwrap();
        let reference: CertificateReference =
            serde_json::from_slice(raw.strip_prefix(REFERENCE).unwrap()).unwrap();
        assert_eq!(reference.version, 2);
        assert_eq!(reference.block, first);
        assert_eq!(reference.component.as_deref(), Some("z-key"));
        assert_eq!(
            b.get(b"production/component/b-key").unwrap().unwrap(),
            value
        );
        assert_eq!(
            db.get(&[a.prefix.as_slice(), b"production/component/z-key"].concat())
                .unwrap()
                .unwrap(),
            value
        );
        assert!(owner.checked_total(&mut None).unwrap() < 6000);
        let mut cycle = reference;
        cycle.block = second;
        cycle.component = Some("b-key".into());
        db.put(
            &physical,
            &[REFERENCE, encode(&cycle).unwrap().as_slice()].concat(),
        )
        .unwrap();
        assert!(b.get(b"production/component/b-key").is_err());
    }
    #[test]
    fn one_hop_references_deduplicate_and_refuse_changed_missing_or_cyclic_targets() {
        let db = Arc::new(MemoryDb::new());
        db.put(b"HEAD", b"native anchor").unwrap();
        let owner = CanonicalProductionStore::new(db.clone());
        let first = ShellHash::from([1; 32]);
        let second = ShellHash::from([2; 32]);
        {
            let mut guard = owner.lock.lock();
            owner
                .write_locked(
                    vec![(key(b"jobs"), encode(&vec![first, second]).unwrap())],
                    &mut guard,
                    DATA_CEILING,
                )
                .unwrap();
        }
        let a = owner.job(first);
        let b = owner.job(second);
        let k = b"production/component/key";
        let certificate = vec![7u8; 4096];
        a.put(k, &certificate).unwrap();
        let original = db.get(&[a.prefix.as_slice(), k].concat()).unwrap().unwrap();
        b.put(k, &certificate).unwrap();
        let physical = [b.prefix.as_slice(), k].concat();
        let reference = db.get(&physical).unwrap().unwrap();
        assert!(reference.starts_with(REFERENCE) && reference.len() < 256);
        assert_eq!(b.get(k).unwrap().unwrap(), certificate);
        assert_eq!(
            db.get(&[a.prefix.as_slice(), k].concat()).unwrap().unwrap(),
            original
        );
        let total = owner.checked_total(&mut None).unwrap();
        assert!(total < 5000);
        b.put(k, &certificate).unwrap();
        assert_eq!(owner.checked_total(&mut None).unwrap(), total);
        let target = [a.prefix.as_slice(), k].concat();
        db.put(&target, &vec![8u8; 4096]).unwrap();
        assert!(b.get(k).is_err());
        db.delete(&target).unwrap();
        assert!(b.get(k).is_err());
        db.put(&target, &reference).unwrap();
        assert!(b.get(k).is_err());
        db.put(&target, &original).unwrap();
        let bad = CertificateReference {
            version: 1,
            block: second,
            bytes: 4096,
            hash: blake3_hash(&certificate),
            component: None,
        };
        db.put(
            &physical,
            &[REFERENCE, encode(&bad).unwrap().as_slice()].concat(),
        )
        .unwrap();
        assert!(b.get(k).is_err());
        assert_eq!(db.get(b"HEAD").unwrap().unwrap(), b"native anchor");
    }
    #[test]
    fn namespaces_are_immutable_and_global_accounting_rejects_tampering() {
        let db = Arc::new(MemoryDb::new());
        db.put(b"HEAD", b"native anchor").unwrap();
        let owner = CanonicalProductionStore::new(db.clone());
        let kv = owner.job(ShellHash::from([1; 32]));
        kv.put(b"production/source", b"raw public source").unwrap();
        kv.put(b"production/component/key", b"certificate").unwrap();
        let before = db.scan_all().unwrap();
        assert!(kv.put(b"production/component/key", b"different").is_err());
        assert!(kv.delete(b"production/source").is_err());
        assert_eq!(before, db.scan_all().unwrap());
        assert!(owner
            .job(ShellHash::from([2; 32]))
            .get(b"production/source")
            .unwrap()
            .is_none());
        db.put(&key(b"bytes"), &0u64.to_be_bytes()).unwrap();
        let before = db.scan_all().unwrap();
        assert!(kv.put(b"production/component/new", b"x").is_err());
        assert_eq!(before, db.scan_all().unwrap());
        let restored = CanonicalProductionStore::new(db.clone());
        assert!(restored
            .job(ShellHash::from([1; 32]))
            .put(b"x", b"y")
            .is_err());
        assert_eq!(db.get(b"HEAD").unwrap(), Some(b"native anchor".to_vec()));
    }
    #[test]
    fn completed_quorum_jobs_simulated_quota_refuses_atomic_index_replacement() {
        let db = Arc::new(MemoryDb::new());
        let owner = CanonicalProductionStore::new_quorum(db.clone());
        let a = ShellHash::from([1; 32]);
        let b = ShellHash::from([2; 32]);
        let c = ShellHash::from([3; 32]);
        for (i, id) in [a, b].into_iter().enumerate() {
            owner.insert_source(id, i as u64, b"source").unwrap();
            let mut s = owner.status(id).unwrap().unwrap();
            s.state = CanonicalProductionState::Complete;
            s.components = 1;
            s.checkpoint_bytes = 1;
            s.manifest = Some(CanonicalProofManifest {
                version: 2,
                chain_id: 1337,
                genesis_hash: ShellHash::from([9; 32]),
                block_hash: id,
                total_bytes: 1,
                payload_hash: blake3_hash(b"x"),
            });
            owner.save(&s).unwrap();
        }
        // Counter-boundary simulation, not a physical256MiB stress qualification.
        *owner.lock.lock() = Some(MAX_BYTES - 1);
        db.put(&key(b"bytes"), &(MAX_BYTES - 1).to_be_bytes())
            .unwrap();
        let before = db.scan_all().unwrap();
        assert!(owner
            .insert_source_retiring(c, 3, b"new source", Some(a))
            .is_err());
        assert_eq!(db.scan_all().unwrap(), before);
    }
    #[test]
    fn simulated_global_quota_refuses_whole_batch_without_changing_native_data() {
        let db = Arc::new(MemoryDb::new());
        let owner = CanonicalProductionStore::new(db.clone());
        // Counter boundary simulation only; no claim of a 256MiB load/stress test.
        *owner.lock.lock() = Some(MAX_BYTES - 1);
        db.put(&key(b"bytes"), &(MAX_BYTES - 1).to_be_bytes())
            .unwrap();
        let before = db.scan_all().unwrap();
        let kv = owner.job(ShellHash::from([1; 32]));
        let mut batch = WriteBatch::new();
        batch.put(b"a".to_vec(), b"b".to_vec());
        batch.put(b"c".to_vec(), b"d".to_vec());
        assert!(kv.write_batch(batch).is_err());
        assert_eq!(before, db.scan_all().unwrap());
        let legacy = format!(
            "{{\"proof_bytes\":[{}]}}",
            "17,".repeat(4096).trim_end_matches(',')
        )
        .into_bytes();
        assert!(kv.put(b"production/component/legacy", &legacy).is_err());
        assert_eq!(before, db.scan_all().unwrap());
    }
    #[test]
    fn default_and_non_prover_role_do_not_allocate_work() {
        let mut cfg = NodeConfig::dev(Address::ZERO);
        assert!(!cfg.canonical_proof_production);
        assert!(cfg.canonical_proof_component_budget.is_none());
        cfg.node_role = crate::NodeRole::Prover;
        let disabled_db = Arc::new(MemoryDb::new());
        let (disabled, _) = crate::NodeBuilder::new(cfg.clone(), disabled_db.clone())
            .build()
            .unwrap();
        let before_disabled = disabled_db.scan_all().unwrap();
        assert!(Arc::new(disabled)
            .start_canonical_production()
            .unwrap()
            .is_none());
        assert_eq!(before_disabled, disabled_db.scan_all().unwrap());
        assert!(disabled_db.scan_prefix(PREFIX).unwrap().is_empty());
        cfg.node_role = crate::NodeRole::Validator;
        cfg.canonical_proof_production = true;
        let db = Arc::new(MemoryDb::new());
        let (node, _) = crate::NodeBuilder::new(cfg, db.clone()).build().unwrap();
        let node = Arc::new(node);
        let before = db.scan_all().unwrap();
        assert!(node.start_canonical_production().is_err());
        assert_eq!(before, db.scan_all().unwrap());
        assert!(db.scan_prefix(PREFIX).unwrap().is_empty());
    }
    #[tokio::test]
    async fn unfinished_sessions_publish_retry_before_readiness_without_changing_checkpoints() {
        for state in [
            CanonicalProductionState::Paused,
            CanonicalProductionState::Proving,
            CanonicalProductionState::Failed,
        ] {
            let mut cfg = NodeConfig::dev(Address::ZERO);
            cfg.node_role = crate::NodeRole::Prover;
            cfg.canonical_proof_production = true;
            let db = Arc::new(MemoryDb::new());
            let (node, _) = crate::NodeBuilder::new(cfg, db.clone()).build().unwrap();
            let node = Arc::new(node);
            let source = br#"{"retained":"not dispatched before readiness"}"#.to_vec();
            let block = ShellHash::from([0x40; 32]);
            let complete = ShellHash::from([0x41; 32]);
            let mut changes = vec![(key(b"jobs"), encode(&vec![block, complete]).unwrap())];
            for (hash, prior) in [
                (block, state),
                (complete, CanonicalProductionState::Complete),
            ] {
                let status = CanonicalProductionStatus {
                    version: 1,
                    block_hash: hash,
                    block_number: 1,
                    source_hash: blake3_hash(&source),
                    state: prior.clone(),
                    components: 1,
                    checkpoint_bytes: 64,
                    newly_proved: 1,
                    reused: 0,
                    manifest: None,
                    error: (prior != CanonicalProductionState::Complete)
                        .then(|| "previous attempt".into()),
                };
                changes.push((record_key(hash), encode(&status).unwrap()));
                changes.push((source_key(hash), source.clone()));
            }
            {
                let owner = &node.canonical_production;
                let mut guard = owner.lock.lock();
                owner
                    .write_locked(changes, &mut guard, DATA_CEILING)
                    .unwrap();
            }
            let before = db.scan_all().unwrap();
            let complete_before = db.get(&record_key(complete)).unwrap();
            node.prover_ready.store(false, Ordering::Release);
            let worker = node.start_canonical_production().unwrap().unwrap();
            let status = node.canonical_production.status(block).unwrap().unwrap();
            assert_eq!(status.state, CanonicalProductionState::Queued);
            assert!(status.error.is_none());
            assert_eq!((status.components, status.checkpoint_bytes), (1, 64));
            tokio::time::sleep(Duration::from_millis(250)).await;
            assert_eq!(
                node.canonical_production
                    .status(block)
                    .unwrap()
                    .unwrap()
                    .state,
                CanonicalProductionState::Queued
            );
            worker.shutdown().await;
            assert_eq!(complete_before, db.get(&record_key(complete)).unwrap());
            let retained = |rows: Vec<(Vec<u8>, Vec<u8>)>| {
                rows.into_iter()
                    .filter(|(k, _)| k != &key(b"bytes") && k != &record_key(block))
                    .collect::<Vec<_>>()
            };
            assert_eq!(retained(before), retained(db.scan_all().unwrap()));
        }
    }

    #[tokio::test]
    async fn failed_job_is_rechecked_once_per_worker_session_without_native_writes() {
        let mut cfg = NodeConfig::dev(Address::ZERO);
        cfg.node_role = crate::NodeRole::Prover;
        cfg.canonical_proof_production = true;
        let db = Arc::new(MemoryDb::new());
        let (node, _) = crate::NodeBuilder::new(cfg, db.clone()).build().unwrap();
        let node = Arc::new(node);
        let native = db.scan_all().unwrap();
        let block = ShellHash::from([0x31; 32]);
        let source = br#"{"invalid":true}"#.to_vec();
        let status = CanonicalProductionStatus {
            version: 1,
            block_hash: block,
            block_number: 1,
            source_hash: blake3_hash(&source),
            state: CanonicalProductionState::Failed,
            components: 0,
            checkpoint_bytes: 0,
            newly_proved: 0,
            reused: 0,
            manifest: None,
            error: Some("previous failure".into()),
        };
        {
            let owner = &node.canonical_production;
            let mut guard = owner.lock.lock();
            owner
                .write_locked(
                    vec![
                        (key(b"jobs"), encode(&vec![block]).unwrap()),
                        (record_key(block), encode(&status).unwrap()),
                        (source_key(block), source.clone()),
                    ],
                    &mut guard,
                    DATA_CEILING,
                )
                .unwrap();
        }
        node.prover_ready.store(true, Ordering::Release);
        let first = node.start_canonical_production().unwrap().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let error = loop {
            let status = node.canonical_production.status(block).unwrap().unwrap();
            if status.state == CanonicalProductionState::Failed
                && status.error.as_deref() != Some("previous failure")
            {
                break status.error.unwrap();
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(!error.contains("hash/size mismatch"));
        // Same-size tampering keeps quota accounting valid, but must fail the
        // independent source-hash check when a new worker explicitly retries.
        let mut corrupted = source;
        corrupted[0] ^= 1;
        db.put(&source_key(block), &corrupted).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            node.canonical_production
                .status(block)
                .unwrap()
                .unwrap()
                .error
                .as_deref(),
            Some(error.as_str())
        );
        first.shutdown().await;
        let second = node.start_canonical_production().unwrap().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let status = node.canonical_production.status(block).unwrap().unwrap();
            if status
                .error
                .as_deref()
                .is_some_and(|s| s.contains("source hash/size mismatch"))
            {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        second.shutdown().await;
        assert_eq!(
            native,
            db.scan_all()
                .unwrap()
                .into_iter()
                .filter(|(k, _)| !k.starts_with(PREFIX))
                .collect::<Vec<_>>()
        );
    }
}
