//! Exclusive, source-bound offline proof checkpoints. Status never authenticates a proof.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shell_primitives::{blake3_hash, ShellHash};
use shell_storage::{KvStore, WriteBatch};
use std::{collections::BTreeMap, fmt, io::Write, num::NonZeroUsize};

pub const MAX_CHECKPOINT_BYTES: usize = 256 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_COMPONENTS: usize = 2048;
const INDEX: &[u8] = b"production/index";
const SOURCE: &[u8] = b"production/source";
const COMPONENT: &[u8] = b"production/component/";

#[derive(Debug)]
pub enum ProductionError {
    Paused,
    Failed(String),
}
impl fmt::Display for ProductionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paused => f.write_str("proof production paused at the requested component limit"),
            Self::Failed(e) => f.write_str(e),
        }
    }
}
impl std::error::Error for ProductionError {}
impl From<String> for ProductionError {
    fn from(e: String) -> Self {
        Self::Failed(e)
    }
}
fn failure(e: impl fmt::Display) -> ProductionError {
    ProductionError::Failed(e.to_string())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    bytes: usize,
    hash: ShellHash,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u8,
    source_hash: ShellHash,
    source_bytes: usize,
    components: BTreeMap<String, Component>,
}
#[derive(Debug, Serialize)]
pub struct ProductionProgress {
    pub components: usize,
    pub checkpoint_bytes: usize,
    pub newly_proved: usize,
    pub reused: usize,
}
type ComponentReuse<'a> = dyn Fn(&str) -> Result<Option<Vec<u8>>, String> + 'a;

/// The caller must exclusively own this separate job store. No chain writes are made.
/// Every reused certificate is decoded and verified against the current inputs.
pub struct ProductionStore<'a, S: KvStore> {
    store: &'a mut S,
    index: Index,
    limit: Option<NonZeroUsize>,
    added: usize,
    reused: usize,
    interrupt: Option<&'a dyn Fn() -> bool>,
    reuse: Option<&'a ComponentReuse<'a>>,
    local_reuse: BTreeMap<String, String>,
}
impl<'a, S: KvStore> ProductionStore<'a, S> {
    pub(crate) fn slh_encoding(&self) -> bool {
        self.index.version == 4
    }
    pub(crate) fn compact_encoding(&self) -> bool {
        self.index.version >= 2
    }

    pub fn open(
        store: &'a mut S,
        source: &[u8],
        limit: Option<NonZeroUsize>,
    ) -> Result<Self, ProductionError> {
        Self::open_format(store, source, limit, 1)
    }
    /// New large jobs store unique mathematical inputs in bounded compact bytes.
    /// Existing jobs retain their original index/encoding and immutable components.
    pub fn open_compact(
        store: &'a mut S,
        source: &[u8],
        limit: Option<NonZeroUsize>,
    ) -> Result<Self, ProductionError> {
        Self::open_format(store, source, limit, 2)
    }
    /// Explicit source-six encoding; old jobs are never rewritten or reinterpreted.
    /// The same checkpoint quota bounds stored v2 component bytes, and the
    /// decoder retains the existing per-certificate expansion bound.
    pub fn open_slh(
        store: &'a mut S,
        source: &[u8],
        limit: Option<NonZeroUsize>,
    ) -> Result<Self, ProductionError> {
        Self::open_format(store, source, limit, 4)
    }
    /// New high-diversity jobs persist shared matrix proof parts. Existing
    /// index-one/two jobs keep their immutable layout when reopened.
    pub fn open_shared_matrix(
        store: &'a mut S,
        source: &[u8],
        limit: Option<NonZeroUsize>,
    ) -> Result<Self, ProductionError> {
        Self::open_format(store, source, limit, 3)
    }
    pub(crate) fn shared_matrix_encoding(&self) -> bool {
        self.index.version == 3
    }

    fn open_format(
        store: &'a mut S,
        source: &[u8],
        limit: Option<NonZeroUsize>,
        format: u8,
    ) -> Result<Self, ProductionError> {
        if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
            return Err(failure("production source size limit"));
        }
        let index = if let Some(bytes) = store.get(INDEX).map_err(failure)? {
            if bytes.len() > 256 * 1024 {
                return Err(failure("production index size limit"));
            }
            let index: Index = serde_json::from_slice(&bytes).map_err(failure)?;
            if !matches!(index.version, 1..=4)
                || index.source_hash != blake3_hash(source)
                || index.source_bytes != source.len()
                || store.get(SOURCE).map_err(failure)?.as_deref() != Some(source)
                || index.components.len() > MAX_COMPONENTS
            {
                return Err(failure("production source/index mismatch"));
            }
            if (format == 4 || index.version == 4) && format != index.version {
                return Err(failure(
                    "checkpoint encoding differs; retain existing job and use a new owned output",
                ));
            }
            index
        } else {
            let mut empty = true;
            let inspected = store.visit_all(&mut |_, _| {
                empty = false;
                Err(shell_storage::StorageError::State(
                    "nonempty job store".into(),
                ))
            });
            if empty {
                inspected.map_err(failure)?;
            }
            if !empty {
                return Err(failure("refusing unowned nonempty production store"));
            }
            let index = Index {
                version: format,
                source_hash: blake3_hash(source),
                source_bytes: source.len(),
                components: BTreeMap::new(),
            };
            let mut batch = WriteBatch::new();
            batch.put(SOURCE.to_vec(), source.to_vec());
            batch.put(INDEX.to_vec(), serde_json::to_vec(&index).map_err(failure)?);
            store.write_batch(batch).map_err(failure)?;
            store.flush().map_err(failure)?;
            index
        };
        let mut total = index.source_bytes;
        for (name, c) in &index.components {
            component_key(name)?;
            total = total
                .checked_add(c.bytes)
                .ok_or_else(|| failure("production size overflow"))?;
        }
        if total > MAX_CHECKPOINT_BYTES {
            return Err(failure("production checkpoint quota exceeded"));
        }
        // Detect missing, altered and unindexed bytes before allowing any new work.
        let mut seen = 0;
        store
            .visit_all(&mut |key, bytes| {
                let valid = if key == INDEX || key == SOURCE {
                    true
                } else if let Some(name) = key.strip_prefix(COMPONENT) {
                    std::str::from_utf8(name)
                        .ok()
                        .and_then(|name| index.components.get(name))
                        .is_some_and(|c| c.bytes == bytes.len() && c.hash == blake3_hash(bytes))
                } else {
                    false
                };
                if !valid {
                    return Err(shell_storage::StorageError::State(
                        "corrupt or unindexed production component".into(),
                    ));
                }
                seen += 1;
                Ok(())
            })
            .map_err(failure)?;
        if seen != index.components.len() + 2 {
            return Err(failure("missing production components"));
        }
        Ok(Self {
            store,
            index,
            limit,
            added: 0,
            reused: 0,
            interrupt: None,
            reuse: None,
            local_reuse: BTreeMap::new(),
        })
    }
    /// Stop between mathematical certificates; already committed bytes remain immutable.
    pub fn with_interrupt(mut self, check: &'a dyn Fn() -> bool) -> Self {
        self.interrupt = Some(check);
        self
    }
    /// An input-matched donor supplies only untrusted certificate bytes. The
    /// ordinary component verifier must succeed before any checkpoint is written.
    pub fn with_reuse(mut self, reuse: &'a ComponentReuse<'a>) -> Self {
        self.reuse = Some(reuse);
        self
    }
    pub(crate) fn set_local_reuse(&mut self, names: BTreeMap<String, String>) {
        self.local_reuse = names;
    }
    pub(crate) fn matches_source(&self, source: &[u8]) -> bool {
        self.index.source_hash == blake3_hash(source) && self.index.source_bytes == source.len()
    }
    pub fn progress(&self) -> ProductionProgress {
        ProductionProgress {
            components: self.index.components.len(),
            checkpoint_bytes: self.index.source_bytes
                + self
                    .index
                    .components
                    .values()
                    .map(|c| c.bytes)
                    .sum::<usize>(),
            newly_proved: self.added,
            reused: self.reused,
        }
    }
    pub(crate) fn checkpoint<T: Serialize + DeserializeOwned>(
        &mut self,
        name: &str,
        prove: impl FnOnce() -> Result<T, String>,
        verify: impl FnOnce(&T) -> Result<(), String>,
    ) -> Result<T, ProductionError> {
        if self.interrupt.is_some_and(|check| check()) {
            return Err(ProductionError::Paused);
        }
        let shared = if self.index.version >= 2 {
            self.local_reuse.get(name).cloned()
        } else {
            None
        };
        if shared
            .as_ref()
            .is_some_and(|name| !self.index.components.contains_key(name))
        {
            return Err(failure("shared compact input checkpoint missing"));
        }
        let name = shared.as_deref().unwrap_or(name);
        let key = component_key(name)?;
        if self.index.components.contains_key(name) {
            let bytes = self
                .store
                .get(&key)
                .map_err(failure)?
                .ok_or_else(|| failure("missing production checkpoint"))?;
            let p = crate::compact_canonical::decode_component(&bytes).map_err(failure)?;
            verify(&p)?;
            self.reused += 1;
            eprintln!("Reverified {name}");
            return Ok(p);
        }
        if self.limit.is_some_and(|n| self.added >= n.get()) {
            return Err(ProductionError::Paused);
        }
        if self.index.components.len() >= MAX_COMPONENTS {
            return Err(failure("production component count limit"));
        }
        let local = self
            .local_reuse
            .get(name)
            .filter(|other| self.index.components.contains_key(*other));
        let donor = if let Some(other) = local {
            Some(
                self.store
                    .get(&component_key(other)?)
                    .map_err(failure)?
                    .ok_or_else(|| failure("local donor certificate missing"))?,
            )
        } else {
            self.reuse.map(|reuse| reuse(name)).transpose()?.flatten()
        };
        let borrowed = donor.is_some();
        let remaining = MAX_CHECKPOINT_BYTES - self.progress().checkpoint_bytes;
        let p = if let Some(bytes) = donor {
            if bytes.len() > MAX_CHECKPOINT_BYTES
                || (self.index.version == 1 && bytes.len() > remaining)
            {
                return Err(failure("production reused checkpoint quota exceeded"));
            }
            crate::compact_canonical::decode_component(&bytes).map_err(failure)?
        } else {
            eprintln!("Proving {name}");
            prove()?
        };
        verify(&p)?;
        let bytes = if self.index.version >= 2 {
            let bytes = if self.index.version == 4 {
                crate::compact_canonical::encode_slh_component(&p)
            } else {
                crate::compact_canonical::encode_component(&p)
            }
            .map_err(failure)?;
            if bytes.len() > remaining {
                return Err(failure("compact checkpoint quota exceeded"));
            }
            bytes
        } else {
            bounded_json(&p, remaining)?
        };
        let mut next = self.index.clone();
        next.components.insert(
            name.into(),
            Component {
                bytes: bytes.len(),
                hash: blake3_hash(&bytes),
            },
        );
        let mut batch = WriteBatch::new();
        batch.put(key, bytes);
        batch.put(INDEX.to_vec(), bounded_json(&next, 256 * 1024)?);
        self.store.write_batch(batch).map_err(failure)?;
        self.store.flush().map_err(failure)?;
        self.index = next;
        if borrowed {
            self.reused += 1;
            eprintln!("Borrowed and reverified {name}");
        } else {
            self.added += 1;
            eprintln!("Persisted {name}");
        }
        Ok(p)
    }
}
fn component_key(name: &str) -> Result<Vec<u8>, ProductionError> {
    if name.is_empty()
        || name.len() > 96
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(failure("invalid production component name"));
    }
    Ok([COMPONENT, name.as_bytes()].concat())
}
/// Serialize without allocating beyond the caller's logical byte quota.
pub fn bounded_json(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, ProductionError> {
    struct Limited {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit - self.bytes.len() {
                return Err(std::io::Error::other("production JSON quota exceeded"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Limited {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value).map_err(failure)?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_storage::MemoryDb;
    #[test]
    fn explicit_slh_checkpoint_format_never_rewrites_an_existing_job() {
        let mut old = MemoryDb::new();
        drop(ProductionStore::open_compact(&mut old, b"source", None).unwrap());
        let before = old.scan_all().unwrap();
        assert!(ProductionStore::open_slh(&mut old, b"source", None).is_err());
        assert_eq!(old.scan_all().unwrap(), before);
        let mut current = MemoryDb::new();
        let mut job = ProductionStore::open_slh(&mut current, b"source", None).unwrap();
        assert!(job.slh_encoding());
        job.checkpoint(
            "first",
            || Ok(7u8),
            |v| {
                if *v == 7 {
                    Ok(())
                } else {
                    Err("wrong value".into())
                }
            },
        )
        .unwrap();
        drop(job);
        let before = current.scan_all().unwrap();
        assert!(ProductionStore::open_compact(&mut current, b"source", None).is_err());
        assert_eq!(current.scan_all().unwrap(), before);
        let mut job = ProductionStore::open_slh(&mut current, b"source", None).unwrap();
        assert!(job
            .checkpoint("first", || Ok(7u8), |_: &u8| Err("must reverify".into()))
            .is_err());
        assert_eq!(job.progress().newly_proved, 0);
    }
    #[test]
    fn compact_aliases_reverify_without_duplicate_logical_bytes_and_legacy_reopens() {
        let mut db = MemoryDb::new();
        let source = b"compact-source";
        let mut job = ProductionStore::open_compact(&mut db, source, None).unwrap();
        job.checkpoint(
            "sender-0-key",
            || Ok(serde_json::json!({"proof_bytes":vec![7;2048]})),
            |_| Ok(()),
        )
        .unwrap();
        let before = job.progress().checkpoint_bytes;
        job.set_local_reuse(BTreeMap::from([(
            "sender-1-key".into(),
            "sender-0-key".into(),
        )]));
        assert!(job
            .checkpoint::<serde_json::Value>(
                "sender-1-key",
                || panic!("duplicate input reproved"),
                |_| Err("recipient refuses".into())
            )
            .is_err());
        let value: serde_json::Value = job
            .checkpoint(
                "sender-1-key",
                || panic!("duplicate input reproved"),
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(value["proof_bytes"].as_array().unwrap().len(), 2048);
        assert_eq!(job.progress().components, 1);
        assert_eq!(job.progress().checkpoint_bytes, before);
        drop(job);
        assert!(db
            .get(&component_key("sender-1-key").unwrap())
            .unwrap()
            .is_none());
        assert_eq!(
            ProductionStore::open(&mut db, source, None)
                .unwrap()
                .progress()
                .components,
            1
        );
        let mut legacy = MemoryDb::new();
        let mut old = ProductionStore::open(&mut legacy, b"old", None).unwrap();
        old.checkpoint("key", || Ok(7u32), |_| Ok(())).unwrap();
        drop(old);
        let bytes = legacy.scan_all().unwrap();
        drop(ProductionStore::open_compact(&mut legacy, b"old", None).unwrap());
        assert_eq!(legacy.scan_all().unwrap(), bytes);
    }
    #[test]
    fn local_position_reuse_rechecks_and_persists_without_reproving() {
        let mut db = MemoryDb::new();
        let mut job = ProductionStore::open(&mut db, b"source", None).unwrap();
        job.checkpoint("sender-0-key", || Ok(7u32), |_| Ok(()))
            .unwrap();
        job.set_local_reuse(BTreeMap::from([(
            "sender-1-key".into(),
            "sender-0-key".into(),
        )]));
        assert!(job
            .checkpoint::<u32>(
                "sender-1-key",
                || panic!("must not reprove"),
                |_| Err("different input".into())
            )
            .is_err());
        assert_eq!(job.progress().components, 1);
        assert_eq!(
            job.checkpoint::<u32>(
                "sender-1-key",
                || panic!("must not reprove"),
                |p| if *p == 7 { Ok(()) } else { Err("bad".into()) }
            )
            .unwrap(),
            7
        );
        assert_eq!(job.progress().newly_proved, 1);
        assert_eq!(job.progress().reused, 1);
        drop(job);
        assert_eq!(
            ProductionStore::open(&mut db, b"source", None)
                .unwrap()
                .progress()
                .components,
            2
        );
    }
    #[test]
    fn donor_is_verified_before_atomic_publication_and_never_reproved() {
        let mut db = FailingBatch {
            inner: MemoryDb::new(),
            fail: std::sync::atomic::AtomicBool::new(false),
        };
        drop(ProductionStore::open(&mut db, b"new source", None).unwrap());
        let before = db.scan_all().unwrap();
        let donor = |_: &str| Ok(Some(b"7".to_vec()));
        {
            let mut job = ProductionStore::open(&mut db, b"new source", None)
                .unwrap()
                .with_reuse(&donor);
            assert!(job
                .checkpoint::<u32>(
                    "key",
                    || panic!("must not reprove donor"),
                    |_| Err("bad AIR".into())
                )
                .is_err());
            assert_eq!(job.progress().components, 0);
        }
        assert_eq!(db.scan_all().unwrap(), before);
        db.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        {
            let mut job = ProductionStore::open(&mut db, b"new source", None)
                .unwrap()
                .with_reuse(&donor);
            assert!(job
                .checkpoint::<u32>("key", || panic!("must not reprove donor"), |_| Ok(()))
                .is_err());
            assert_eq!(job.progress().reused, 0);
        }
        assert_eq!(db.scan_all().unwrap(), before);
        db.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut job = ProductionStore::open(&mut db, b"new source", None)
            .unwrap()
            .with_reuse(&donor);
        assert_eq!(
            job.checkpoint::<u32>(
                "key",
                || panic!("must not reprove donor"),
                |n| if *n == 7 {
                    Ok(())
                } else {
                    Err("wrong input".into())
                }
            )
            .unwrap(),
            7
        );
        assert_eq!(job.progress().reused, 1);
        assert_eq!(job.progress().newly_proved, 0);
    }
    #[test]
    fn pause_reopen_reverify_and_reject_altered_sources_and_checkpoints() {
        let mut db = MemoryDb::new();
        let mut job = ProductionStore::open(&mut db, b"source", NonZeroUsize::new(1)).unwrap();
        assert_eq!(
            job.checkpoint(
                "first",
                || Ok(7u32),
                |n| if *n == 7 { Ok(()) } else { Err("bad".into()) }
            )
            .unwrap(),
            7
        );
        assert!(matches!(
            job.checkpoint("second", || Ok(8u32), |_| Ok(())),
            Err(ProductionError::Paused)
        ));
        drop(job);
        let before = db.scan_all().unwrap();
        assert!(ProductionStore::open(&mut db, b"other", None).is_err());
        assert_eq!(before, db.scan_all().unwrap());
        let mut job = ProductionStore::open(&mut db, b"source", None).unwrap();
        assert!(job
            .checkpoint::<u32>(
                "first",
                || panic!("must reuse"),
                |_| Err("invalid certificate".into())
            )
            .is_err());
        assert_eq!(job.progress().reused, 0);
        assert_eq!(
            job.checkpoint::<u32>("first", || panic!("must reuse"), |_| Ok(()))
                .unwrap(),
            7u32
        );
        assert_eq!(job.progress().reused, 1);
        drop(job);
        db.put(&component_key("first").unwrap(), b"8").unwrap();
        let before = db.scan_all().unwrap();
        assert!(ProductionStore::open(&mut db, b"source", None).is_err());
        assert_eq!(before, db.scan_all().unwrap());
    }
    struct FailingBatch {
        inner: MemoryDb,
        fail: std::sync::atomic::AtomicBool,
    }
    impl KvStore for FailingBatch {
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, shell_storage::StorageError> {
            self.inner.get(k)
        }
        fn put(&self, k: &[u8], v: &[u8]) -> Result<(), shell_storage::StorageError> {
            self.inner.put(k, v)
        }
        fn delete(&self, k: &[u8]) -> Result<(), shell_storage::StorageError> {
            self.inner.delete(k)
        }
        fn flush(&self) -> Result<(), shell_storage::StorageError> {
            self.inner.flush()
        }
        fn scan_prefix(
            &self,
            p: &[u8],
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, shell_storage::StorageError> {
            self.inner.scan_prefix(p)
        }
        fn write_batch(&self, b: WriteBatch) -> Result<(), shell_storage::StorageError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(shell_storage::StorageError::Database(
                    "injected atomic checkpoint refusal".into(),
                ));
            }
            self.inner.write_batch(b)
        }
    }
    #[test]
    fn atomic_batch_failure_preserves_source_index_and_completed_components() {
        let mut db = FailingBatch {
            inner: MemoryDb::new(),
            fail: std::sync::atomic::AtomicBool::new(false),
        };
        {
            let _ = ProductionStore::open(&mut db, b"source", None).unwrap();
        }
        let before = db.scan_all().unwrap();
        db.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut job = ProductionStore::open(&mut db, b"source", None).unwrap();
        assert!(job.checkpoint("first", || Ok(7u8), |_| Ok(())).is_err());
        assert_eq!(job.progress().components, 0);
        drop(job);
        assert_eq!(before, db.scan_all().unwrap());
        assert!(ProductionStore::open(&mut db, b"source", None).is_ok());
    }
    #[test]
    fn interrupt_preserves_checkpoint_and_never_returns_cached_success() {
        let mut db = MemoryDb::new();
        let stop = || true;
        let mut job = ProductionStore::open(&mut db, b"source", None)
            .unwrap()
            .with_interrupt(&stop);
        assert!(matches!(
            job.checkpoint("first", || Ok(7u32), |_| Ok(())),
            Err(ProductionError::Paused)
        ));
        assert_eq!(job.progress().components, 0);
    }
    #[test]
    fn quota_unknown_keys_and_failed_verification_never_publish() {
        assert!(bounded_json(&vec![0u8; 20], 10).is_err());
        let mut db = MemoryDb::new();
        let mut job = ProductionStore::open(&mut db, b"source", None).unwrap();
        assert!(job
            .checkpoint("bad", || Ok(3u8), |_| Err("bad proof".into()))
            .is_err());
        assert_eq!(job.progress().components, 0);
        assert!(job.checkpoint("../bad", || Ok(3u8), |_| Ok(())).is_err());
        drop(job);
        db.put(b"unknown", b"x").unwrap();
        assert!(ProductionStore::open(&mut db, b"source", None).is_err());
    }
}
