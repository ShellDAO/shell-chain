//! Full QC jobs reuse the bounded sender owner through a disjoint local namespace.
use super::canonical_production::{
    CanonicalProductionHandle, CanonicalProductionState as State,
    CanonicalProductionStatus as Status,
};
use super::*;
use serde::{Deserialize, Serialize};
use shell_stark_prover::{
    commit_quorum::{
        prove_commit_quorum_persistent_interruptible, reverify_commit_quorum_persistent,
        CommitQuorumSource,
    },
    production_store::{bounded_json, ProductionError, ProductionProgress},
};
use shell_storage::{
    RangeEntryVisitor, StorageError, WriteBatch, WriteBatchOp, CANONICAL_PROOF_CHUNK_BYTES,
};
use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
type Rows = Vec<(Vec<u8>, Vec<u8>)>;
const OWNER: &[u8] = b"local/canonical-production/v1/";
const QUORUM: &[u8] = b"local/quorum-production/v1/";
fn error(e: impl std::fmt::Display) -> StorageError {
    StorageError::State(e.to_string())
}
/// Only owner-local keys can cross this adapter; Native and sender keys cannot.
pub(super) struct QuorumNamespace<S: KvStore> {
    store: Arc<S>,
}
impl<S: KvStore> QuorumNamespace<S> {
    pub(super) fn new(store: Arc<S>) -> Self {
        Self { store }
    }
    fn physical(k: &[u8]) -> Result<Vec<u8>, StorageError> {
        Ok([
            QUORUM,
            k.strip_prefix(OWNER)
                .ok_or_else(|| error("quorum namespace escape"))?,
        ]
        .concat())
    }
    fn logical(k: &[u8]) -> Result<Vec<u8>, StorageError> {
        Ok([
            OWNER,
            k.strip_prefix(QUORUM)
                .ok_or_else(|| error("quorum namespace mismatch"))?,
        ]
        .concat())
    }
}
impl<S: KvStore> KvStore for QuorumNamespace<S> {
    fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.get(&Self::physical(k)?)
    }
    fn put(&self, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
        let mut b = WriteBatch::new();
        b.put(k.to_vec(), v.to_vec());
        self.write_batch(b)
    }
    fn delete(&self, _: &[u8]) -> Result<(), StorageError> {
        Err(error("quorum checkpoint deletion refused"))
    }
    fn flush(&self) -> Result<(), StorageError> {
        self.store.flush()
    }
    fn write_batch(&self, b: WriteBatch) -> Result<(), StorageError> {
        let mut out = WriteBatch::new();
        for op in b.ops() {
            match op {
                WriteBatchOp::Put { key, value } => out.put(Self::physical(key)?, value.clone()),
                WriteBatchOp::Delete { .. } => {
                    return Err(error("quorum checkpoint deletion refused"))
                }
            }
        }
        self.store.write_batch(out)
    }
    fn scan_prefix(&self, p: &[u8]) -> Result<Rows, StorageError> {
        let prefix = if p.is_empty() {
            QUORUM.to_vec()
        } else {
            Self::physical(p)?
        };
        self.store
            .scan_prefix(&prefix)?
            .into_iter()
            .map(|(k, v)| Ok((Self::logical(&k)?, v)))
            .collect()
    }
    fn visit_prefix_range(
        &self,
        p: &[u8],
        start: &[u8],
        end: Option<&[u8]>,
        reverse: bool,
        visitor: &mut RangeEntryVisitor<'_>,
    ) -> Result<(), StorageError> {
        let prefix = if p.is_empty() {
            QUORUM.to_vec()
        } else {
            Self::physical(p)?
        };
        let first = if start.is_empty() {
            QUORUM.to_vec()
        } else {
            Self::physical(start)?
        };
        let last = end.map(Self::physical).transpose()?;
        self.store
            .visit_prefix_range(&prefix, &first, last.as_deref(), reverse, &mut |k, v| {
                visitor(&Self::logical(k)?, v)
            })
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Source {
    version: u8,
    genesis: ShellHash,
    source: CommitQuorumSource,
}
impl<S: KvStore + 'static> Node<S> {
    fn capture_quorum_source(&self, hash: ShellHash) -> Result<Source, String> {
        let cfg = self
            .chain_store
            .get_chain_config()
            .map_err(|e| e.to_string())?
            .ok_or("quorum config absent")?;
        let block = self
            .chain_store
            .get_block_by_hash(&hash)
            .map_err(|e| e.to_string())?
            .ok_or("quorum block absent")?;
        if cfg.chain_id != self.config.chain_id
            || self
                .chain_store
                .get_block_hash_by_number(0)
                .map_err(|e| e.to_string())?
                != Some(cfg.genesis_hash)
            || self
                .chain_store
                .get_block_hash_by_number(block.number())
                .map_err(|e| e.to_string())?
                != Some(hash)
            || self
                .chain_store
                .get_finalized_number()
                .map_err(|e| e.to_string())?
                .is_none_or(|n| n < block.number())
            || cfg
                .block_commitment_height
                .is_none_or(|h| block.number() < h)
            || block
                .system_transactions
                .iter()
                .any(|t| t.kind != SystemTxKind::BlockGasReward)
        {
            return Err("quorum canonical identity/finality/profile mismatch".into());
        }
        self.chain_store
            .verify_block_body_commitment(&block)
            .map_err(|e| e.to_string())?;
        let cert = self
            .chain_store
            .get_commit_certificate(&hash)
            .map_err(|e| e.to_string())?
            .ok_or("stored quorum certificate absent")?;
        let source = self.commit_quorum_source(block.number(), hash, &cert)?;
        source.validate()?;
        if !self.verify_commit_certificate(block.number(), hash, &cert) {
            return Err("stored quorum certificate invalid".into());
        }
        Ok(Source {
            version: 1,
            genesis: cfg.genesis_hash,
            source,
        })
    }
    fn restore_quorum_source(&self, s: &Status) -> Result<Source, String> {
        let bytes = self
            .quorum_production
            .source(s)
            .map_err(|e| e.to_string())?;
        let expected = self.capture_quorum_source(s.block_hash)?;
        let stored: Source = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if stored != expected
            || s.block_number != expected.source.context.block_number
            || bounded_json(&stored, 1024 * 1024).map_err(|e| e.to_string())? != bytes
        {
            return Err("immutable quorum production source changed".into());
        }
        if let Some(m) = &s.manifest {
            m.validate()?;
            if m.version != shell_core::COMMIT_QUORUM_ARTIFACT_VERSION
                || m.block_hash != s.block_hash
                || m.chain_id != expected.source.context.chain_id
                || m.genesis_hash != expected.genesis
            {
                return Err("quorum production manifest role/context mismatch".into());
            }
        }
        Ok(expected)
    }
    /// Recover only a separate complete source-bound job while this node is offline.
    /// Every checkpoint is reverified before any owned descriptor/component is written.
    pub fn recover_quorum_production_job<D: KvStore>(
        &mut self,
        block: ShellHash,
        donor: &mut D,
    ) -> Result<ProductionProgress, String> {
        let source = self.capture_quorum_source(block)?;
        let (_, progress) =
            reverify_commit_quorum_persistent(donor, &source.source).map_err(|e| e.to_string())?;
        let mut rows = WriteBatch::new();
        let mut total = 0usize;
        let mut count = 0usize;
        donor
            .visit_all(&mut |k, v| {
                count += 1;
                total = total
                    .checked_add(k.len() + v.len())
                    .ok_or_else(|| error("quorum recovery size overflow"))?;
                if !k.starts_with(b"production/") || count > 2050 || total > 256 * 1024 * 1024 {
                    return Err(error("quorum recovery namespace/count/size limit"));
                }
                rows.put(k.to_vec(), v.to_vec());
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        let identity = bounded_json(&source, 1024 * 1024).map_err(|e| e.to_string())?;
        self.quorum_production
            .insert_source(block, source.source.context.block_number, &identity)
            .map_err(|e| e.to_string())?;
        self.quorum_production
            .job(block)
            .write_batch(rows)
            .map_err(|e| e.to_string())?;
        let mut status = self
            .quorum_production
            .status(block)
            .map_err(|e| e.to_string())?
            .ok_or("quorum recovery status absent")?;
        status.state = State::Paused;
        status.components = progress.components;
        status.checkpoint_bytes = progress.checkpoint_bytes;
        status.newly_proved = 0;
        status.reused = progress.reused;
        status.error = Some(
            "recovered checkpoints require node-worker verification before availability".into(),
        );
        self.quorum_production
            .save(&status)
            .map_err(|e| e.to_string())?;
        Ok(progress)
    }
    pub fn quorum_production_status(
        &self,
        block: ShellHash,
    ) -> Result<Option<serde_json::Value>, String> {
        self.quorum_production.status(block).map_err(|e|e.to_string())?.map(|s|{self.restore_quorum_source(&s)?;Ok(serde_json::json!({"status":s,"artifactVersion":2,"nativeExecutionVerified":false}))}).transpose()
    }
    fn capture_next_quorum_job(&self) -> Result<(), String> {
        let ids = self.quorum_production.ids().map_err(|e| e.to_string())?;
        if ids.len() >= 2 {
            return Ok(());
        }
        let cfg = self
            .chain_store
            .get_chain_config()
            .map_err(|e| e.to_string())?
            .ok_or("quorum config absent")?;
        let Some(mut next) = cfg.block_commitment_height else {
            return Ok(());
        };
        next = next.max(1);
        for id in ids {
            if let Some(s) = self
                .quorum_production
                .status(id)
                .map_err(|e| e.to_string())?
            {
                next = next.max(
                    s.block_number
                        .checked_add(1)
                        .ok_or("quorum height overflow")?,
                );
            }
        }
        if self
            .chain_store
            .get_finalized_number()
            .map_err(|e| e.to_string())?
            .is_none_or(|n| n < next)
        {
            return Ok(());
        }
        let hash = self
            .chain_store
            .get_block_hash_by_number(next)
            .map_err(|e| e.to_string())?
            .ok_or("finalized quorum header missing")?;
        let source = self.capture_quorum_source(hash)?;
        let bytes = bounded_json(&source, 1024 * 1024).map_err(|e| e.to_string())?;
        self.quorum_production
            .insert_source(hash, next, &bytes)
            .map_err(|e| e.to_string())
    }
    fn produce_quorum_job(
        &self,
        mut status: Status,
        limit: Option<NonZeroUsize>,
        cancel: &AtomicBool,
    ) -> usize {
        let mut progress = ProductionProgress {
            components: 0,
            checkpoint_bytes: 0,
            newly_proved: 0,
            reused: 0,
        };
        status.state = State::Proving;
        status.newly_proved = 0;
        status.reused = 0;
        status.error = None;
        let outcome = (|| -> Result<shell_storage::CanonicalProofManifest, String> {
            self.quorum_production
                .save(&status)
                .map_err(|e| e.to_string())?;
            let source = self.restore_quorum_source(&status)?;
            let mut kv = self.quorum_production.job(status.block_hash);
            let interrupt =
                || cancel.load(Ordering::Acquire) || !self.prover_ready.load(Ordering::Acquire);
            let result = prove_commit_quorum_persistent_interruptible(
                &mut kv,
                &source.source,
                limit,
                &interrupt,
                &mut progress,
            );
            let (proof, _) = match result {
                Ok(v) => v,
                Err(ProductionError::Paused) => {
                    status.state = State::Paused;
                    return Err("component budget, readiness or shutdown pause".into());
                }
                Err(e) => return Err(e.to_string()),
            };
            self.restore_quorum_source(&status)?;
            if interrupt() {
                status.state = State::Paused;
                return Err("readiness or shutdown pause".into());
            }
            let payload = shell_stark_prover::commit_quorum::payload::encode(
                &proof,
                shell_core::MAX_CANONICAL_PROOF_BYTES as usize,
            )?;
            let m = shell_storage::CanonicalProofManifest {
                version: shell_core::COMMIT_QUORUM_ARTIFACT_VERSION,
                chain_id: source.source.context.chain_id,
                genesis_hash: source.genesis,
                block_hash: status.block_hash,
                total_bytes: payload.len() as u64,
                payload_hash: shell_primitives::blake3_hash(&payload),
            };
            let mut upload = self
                .canonical_proof_uploads
                .begin(m.clone())
                .map_err(|e| e.to_string())?;
            for (index, chunk) in payload.chunks(CANONICAL_PROOF_CHUNK_BYTES).enumerate() {
                self.restore_quorum_source(&status)?;
                if interrupt() {
                    status.state = State::Paused;
                    return Err("availability publication paused".into());
                }
                if index < upload.next_chunk as usize {
                    if self
                        .canonical_proof_uploads
                        .chunk(&m.id(), index as u32)
                        .map_err(|e| e.to_string())?
                        != chunk
                    {
                        return Err("quorum cached chunk conflict".into());
                    }
                } else {
                    upload = self
                        .canonical_proof_uploads
                        .append(&m.id(), index as u32, chunk)
                        .map_err(|e| e.to_string())?;
                }
            }
            self.restore_quorum_source(&status)?;
            Ok(m)
        })();
        if progress.components > 0 || status.components == 0 {
            status.components = progress.components;
            status.checkpoint_bytes = progress.checkpoint_bytes;
        }
        status.newly_proved = progress.newly_proved;
        status.reused = progress.reused;
        match outcome {
            Ok(m) => {
                status.state = State::Complete;
                status.manifest = Some(m);
                status.error = None;
            }
            Err(e) => {
                if status.state != State::Paused {
                    status.state = State::Failed;
                }
                status.error = Some(e.chars().take(2048).collect());
            }
        }
        if let Err(e) = self.quorum_production.save(&status) {
            warn!(%e,"quorum status persistence failed; source/checkpoints retained");
        }
        progress.newly_proved
    }
    pub(super) fn start_quorum_production(
        self: &Arc<Self>,
    ) -> Result<Option<CanonicalProductionHandle>, NodeError> {
        if !self.config.canonical_quorum_production {
            return Ok(None);
        }
        if !self.config.node_role.runs_prover() {
            return Err(NodeError::Startup(
                "quorum proof production requires a prover role".into(),
            ));
        }
        self.capture_next_quorum_job().map_err(NodeError::Startup)?;
        // Cold startup always rechecks complete checkpoints; persisted state is not authority.
        for id in self.quorum_production.ids()? {
            if let Some(mut s) = self.quorum_production.status(id)? {
                s.state = State::Queued;
                s.error = None;
                self.quorum_production.save(&s)?;
            }
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let node = self.clone();
        let handle = tokio::spawn(async move {
            let mut attempted = HashSet::new();
            let mut used = 0usize;
            while !stop.load(Ordering::Acquire) {
                if node.prover_ready.load(Ordering::Acquire) {
                    if let Err(e) = node.capture_next_quorum_job() {
                        warn!(%e,"quorum capture stopped; native state unchanged");
                        break;
                    }
                    let remaining = node
                        .config
                        .canonical_proof_component_budget
                        .map(|n| n.get().saturating_sub(used));
                    if remaining != Some(0) {
                        let next = node.quorum_production.ids().and_then(|ids| {
                            for id in ids {
                                if !attempted.contains(&id) {
                                    if let Some(s) = node.quorum_production.status(id)? {
                                        if s.state != State::Complete {
                                            return Ok(Some(s));
                                        }
                                    }
                                }
                            }
                            Ok(None)
                        });
                        match next {
                            Ok(Some(s)) => {
                                let id = s.block_hash;
                                attempted.insert(id);
                                let n = node.clone();
                                let c = stop.clone();
                                let limit = remaining.and_then(NonZeroUsize::new);
                                match tokio::task::spawn_blocking(move || {
                                    n.produce_quorum_job(s, limit, &c)
                                })
                                .await
                                {
                                    Ok(spent) => {
                                        used = used.saturating_add(spent);
                                        if !stop.load(Ordering::Acquire)
                                            && node
                                                .config
                                                .canonical_proof_component_budget
                                                .is_none_or(|n| used < n.get())
                                            && node
                                                .quorum_production
                                                .status(id)
                                                .ok()
                                                .flatten()
                                                .is_some_and(|s| s.state == State::Paused)
                                        {
                                            attempted.remove(&id);
                                        }
                                    }
                                    Err(e) => {
                                        warn!(%e,"quorum worker panicked; checkpoints retained")
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                warn!(%e,"quorum queue unavailable; no repeated dispatch");
                                break;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        Ok(Some(CanonicalProductionHandle::new(cancel, handle)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::canonical_production::CanonicalProductionStore;
    use super::*;
    use shell_storage::MemoryDb;
    #[test]
    fn quorum_owner_isolates_roles_and_rejects_mixed_native_batch() {
        let raw = Arc::new(MemoryDb::new());
        raw.put(b"HEAD", b"Native anchor").unwrap();
        let scoped = Arc::new(QuorumNamespace::new(raw.clone()));
        let quorum = CanonicalProductionStore::new(scoped.clone());
        let sender = CanonicalProductionStore::new(raw.clone());
        let block = ShellHash::from([7; 32]);
        sender.insert_source(block, 1, b"sender input").unwrap();
        quorum.insert_source(block, 1, b"quorum input").unwrap();
        quorum
            .job(block)
            .put(b"production/source", b"untrusted checkpoint input")
            .unwrap();
        assert_eq!(
            sender
                .source(&sender.status(block).unwrap().unwrap())
                .unwrap(),
            b"sender input"
        );
        assert_eq!(
            quorum
                .source(&quorum.status(block).unwrap().unwrap())
                .unwrap(),
            b"quorum input"
        );
        let before = raw.scan_all().unwrap();
        let mut batch = WriteBatch::new();
        batch.put([OWNER, b"test"].concat(), b"local".to_vec());
        batch.put(b"HEAD".to_vec(), b"forbidden".to_vec());
        assert!(scoped.write_batch(batch).is_err());
        assert!(scoped.delete(&[OWNER, b"test"].concat()).is_err());
        assert_eq!(raw.scan_all().unwrap(), before);
        assert_eq!(raw.get(b"HEAD").unwrap().unwrap(), b"Native anchor");
        assert!(scoped
            .scan_prefix(b"")
            .unwrap()
            .iter()
            .all(|(k, _)| k.starts_with(OWNER)));
        let reopened = CanonicalProductionStore::new(Arc::new(QuorumNamespace::new(raw.clone())));
        let mut status = reopened.status(block).unwrap().unwrap();
        status.state = State::Paused;
        reopened.save(&status).unwrap();
        assert_eq!(reopened.source(&status).unwrap(), b"quorum input");
    }
}
