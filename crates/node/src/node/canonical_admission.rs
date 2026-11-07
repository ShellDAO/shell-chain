//! Pending fresh bodies are untrusted durable inputs. Only newly verified opaque
//! tuples may cross from a CPU worker into the serialized canonical event loop.
use super::*;
use serde::{Deserialize, Serialize};
use shell_network::PeerId;
use shell_stark_prover::canonical_batch::{
    CanonicalSignatureBatchProof, VerifiedCanonicalSignatureBatch,
};
use shell_storage::{CanonicalProofManifest, WriteBatch};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
const PREFIX: &[u8] = b"local/canonical-admission/v1/";
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_JOBS: usize = 2;
fn key(part: &[u8], hash: Option<ShellHash>) -> Vec<u8> {
    let mut k = [PREFIX, part].concat();
    if let Some(h) = hash {
        k.extend_from_slice(h.as_bytes());
    }
    k
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum AdmissionState {
    Waiting,
    Pulling,
    Verifying,
    Paused,
    Complete,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AdmissionRecord {
    version: u8,
    pub block: ShellHash,
    number: u64,
    parent: ShellHash,
    source_hash: ShellHash,
    pub peer: String,
    pub state: AdmissionState,
    pub manifest: Option<CanonicalProofManifest>,
    attempts: u8,
    hash_retries: u8,
    error: Option<String>,
}
enum VerifiedCandidate {
    Fresh(VerifiedCanonicalSignatureBatch),
    Canonical(CanonicalProofReplay),
}
struct Worker {
    record: AdmissionRecord,
    attempt: u32,
    result: mpsc::Receiver<Result<VerifiedCandidate, String>>,
    handle: tokio::task::JoinHandle<()>,
}
#[derive(Default)]
pub(super) struct LiveAdmissionRuntime {
    worker: Option<Worker>,
    discovery: Option<(ShellHash, u64, PeerId, Instant)>,
    discovery_cursor: usize,
    advertised: std::collections::HashSet<(String, ShellHash)>,
}
impl<S: KvStore + 'static> Node<S> {
    fn admission_ids(&self) -> Result<Vec<ShellHash>, String> {
        let bytes = self
            .store
            .get(&key(b"jobs", None))
            .map_err(|e| e.to_string())?;
        let ids: Vec<ShellHash> = bytes
            .map(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or_default();
        if ids.len() > MAX_JOBS
            || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
        {
            return Err("live admission index corrupt".into());
        }
        Ok(ids)
    }
    fn admission_record(&self, hash: ShellHash) -> Result<Option<AdmissionRecord>, String> {
        self.store
            .get(&key(b"record/", Some(hash)))
            .map_err(|e| e.to_string())?
            .map(|b| {
                if b.len() > 16 * 1024 {
                    return Err("live admission record limit".into());
                }
                let r: AdmissionRecord = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
                if r.version != 1
                    || r.block != hash
                    || r.peer.is_empty()
                    || r.peer.len() > 128
                    || r.attempts > 2
                    || r.hash_retries > 1
                    || r.manifest
                        .as_ref()
                        .is_some_and(|m| m.block_hash != hash || m.validate().is_err())
                {
                    return Err("live admission record corrupt".into());
                }
                Ok(r)
            })
            .transpose()
    }
    fn admission_body(&self, r: &AdmissionRecord) -> Result<Block, String> {
        let bytes = self
            .store
            .get(&key(b"body/", Some(r.block)))
            .map_err(|e| e.to_string())?
            .ok_or("live candidate body absent")?;
        if bytes.len() > MAX_BODY || shell_primitives::blake3_hash(&bytes) != r.source_hash {
            return Err("live candidate source hash/size mismatch".into());
        }
        let block: Block = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if block.hash() != r.block
            || block.number() != r.number
            || block.header.parent_hash != r.parent
            || serde_json::to_vec(&block).map_err(|e| e.to_string())? != bytes
        {
            return Err("live candidate source identity mismatch".into());
        }
        Ok(block)
    }
    fn save_admission(&self, r: &AdmissionRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec(r).map_err(|e| e.to_string())?;
        if bytes.len() > 16 * 1024 {
            return Err("live candidate status limit".into());
        }
        self.store
            .put(&key(b"record/", Some(r.block)), &bytes)
            .map_err(|e| e.to_string())?;
        self.store.flush().map_err(|e| e.to_string())
    }
    pub fn canonical_admission_status(
        &self,
        hash: ShellHash,
    ) -> Result<Option<serde_json::Value>, String> {
        self.admission_record(hash)?.map(|r|{
            self.admission_body(&r)?;
            let canonical=self.chain_store.get_block_hash_by_number(r.number).map_err(|e|e.to_string())?==Some(hash);
            Ok(serde_json::json!({"status":r,"nativeCanonical":canonical,"statusIsAuthorization":false}))
        }).transpose()
    }
    /// Called only by ordinary message handling, before native import. False keeps
    /// the existing native path for disabled, unsupported or non-extension traffic.
    pub(super) fn stage_live_candidate(
        &self,
        peer: &PeerId,
        block: &Block,
    ) -> Result<bool, String> {
        if !self.config.canonical_proof_admission
            || block.transactions.is_empty()
            || block.transactions.len()
                > shell_stark_prover::canonical_batch::MAX_CANONICAL_SIGNATURE_BATCH
            || block.transactions.iter().any(|tx| {
                tx.tx.tx_type > 3
                    || tx.aa_bundle.is_some()
                    || tx.signature.sig_type != shell_crypto::SignatureType::MlDsa65
                    || tx.signature.data.len() != 3309
                    || tx.tx.signing_payload(tx.signature.sig_type.as_u8()).len() > 4096
            })
            || block
                .system_transactions
                .iter()
                .any(|tx| tx.kind != SystemTxKind::BlockGasReward)
        {
            return Ok(false);
        }
        let head = self
            .chain_store
            .get_head_block()
            .map_err(|e| e.to_string())?
            .ok_or("native parent absent")?;
        if block.header.parent_hash != head.hash()
            || head.number().checked_add(1) != Some(block.number())
        {
            return Ok(false);
        }
        let cfg = self
            .chain_store
            .get_chain_config()
            .map_err(|e| e.to_string())?
            .ok_or("native configuration absent")?;
        if cfg
            .block_commitment_height
            .is_none_or(|h| block.number() < h)
        {
            return Ok(false);
        }
        // Default-account support is selected from independently trusted parent state.
        let view = self
            .chain_store
            .canonical_parent_view(head.hash(), head.hash())
            .map_err(|e| e.to_string())?;
        for tx in &block.transactions {
            if view
                .registered_key(&tx.from)
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Ok(false);
            }
            if view
                .world_state()
                .map_err(|e| e.to_string())?
                .get_account(&tx.from)
                .map_err(|e| e.to_string())?
                .is_none_or(|a| a.validation_code_hash.is_some())
            {
                return Ok(false);
            }
        }
        self.validate_live_candidate_source(head.hash(), block)
            .map_err(|e| e.to_string())?;
        if peer.0.is_empty() || peer.0.len() > 128 {
            return Err("candidate peer identity limit".into());
        }
        if let Some(existing) = self.admission_record(block.hash())? {
            if self.admission_body(&existing)? != *block {
                return Err("immutable live candidate conflict".into());
            }
            return Ok(true);
        }
        let mut ids = self.admission_ids()?;
        if ids.len() >= MAX_JOBS {
            return Err("live admission retained candidate limit".into());
        }
        if ids.iter().any(|id| {
            self.admission_record(*id).ok().flatten().is_some_and(|r| {
                !matches!(r.state, AdmissionState::Complete | AdmissionState::Failed)
            })
        }) {
            return Err("live candidate already pending".into());
        }
        let body = shell_stark_prover::production_store::bounded_json(block, MAX_BODY)
            .map_err(|e| e.to_string())?;
        let r = AdmissionRecord {
            version: 1,
            block: block.hash(),
            number: block.number(),
            parent: head.hash(),
            source_hash: shell_primitives::blake3_hash(&body),
            peer: peer.0.clone(),
            state: AdmissionState::Waiting,
            manifest: None,
            attempts: 0,
            hash_retries: 0,
            error: None,
        };
        ids.push(r.block);
        let mut batch = WriteBatch::new();
        batch.put(key(b"body/", Some(r.block)), body);
        batch.put(
            key(b"record/", Some(r.block)),
            serde_json::to_vec(&r).map_err(|e| e.to_string())?,
        );
        batch.put(
            key(b"jobs", None),
            serde_json::to_vec(&ids).map_err(|e| e.to_string())?,
        );
        self.store.write_batch(batch).map_err(|e| e.to_string())?;
        self.store.flush().map_err(|e| e.to_string())?;
        Ok(true)
    }
    fn pending_admission(&self) -> Result<Option<AdmissionRecord>, String> {
        if !self.config.canonical_proof_admission {
            return Ok(None);
        }
        for id in self.admission_ids()? {
            if let Some(r) = self.admission_record(id)? {
                if !matches!(r.state, AdmissionState::Complete | AdmissionState::Failed) {
                    return Ok(Some(r));
                }
            }
        }
        Ok(None)
    }
    pub(super) fn pending_manifest_source(
        &self,
        m: &CanonicalProofManifest,
    ) -> Result<bool, String> {
        if !self.config.canonical_proof_admission {
            return Ok(false);
        }
        let Some(r) = self.admission_record(m.block_hash)? else {
            return Ok(false);
        };
        if r.state == AdmissionState::Complete || r.manifest.as_ref() != Some(m) {
            return Ok(false);
        }
        let cfg = self
            .chain_store
            .get_chain_config()
            .map_err(|e| e.to_string())?
            .ok_or("native configuration absent")?;
        if cfg.chain_id != m.chain_id
            || cfg.genesis_hash != m.genesis_hash
            || self.config.chain_id != m.chain_id
        {
            return Err("candidate manifest network mismatch".into());
        }
        let block = self.admission_body(&r)?;
        if self
            .chain_store
            .get_block_hash_by_number(block.number())
            .map_err(|e| e.to_string())?
            == Some(block.hash())
        {
            return Ok(false);
        }
        self.validate_live_candidate_source(r.parent, &block)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }
    pub(super) fn has_live_manifest(&self, id: ShellHash) -> bool {
        self.config.canonical_proof_admission
            && self.admission_ids().is_ok_and(|ids| {
                ids.into_iter().any(|h| {
                    self.admission_record(h).ok().flatten().is_some_and(|r| {
                        r.state != AdmissionState::Complete
                            && r.manifest.as_ref().is_some_and(|m| m.id() == id)
                    })
                })
            })
    }
    pub(super) fn accept_live_manifest(
        &self,
        peer: &PeerId,
        block: ShellHash,
        nonce: u64,
        manifest: Option<CanonicalProofManifest>,
    ) -> Result<(), String> {
        if !self.config.canonical_proof_admission {
            return Ok(());
        }
        let Some(mut r) = self.admission_record(block)? else {
            return Ok(());
        };
        if r.state == AdmissionState::Complete
            || (r.state == AdmissionState::Verifying && self.live_admission.lock().worker.is_some())
        {
            return Ok(());
        }
        if r.state == AdmissionState::Failed && manifest.as_ref() == r.manifest.as_ref() {
            return Ok(());
        }
        if r.block != block {
            return Ok(());
        }
        if nonce != 0 {
            let runtime = self.live_admission.lock();
            if runtime
                .discovery
                .as_ref()
                .is_none_or(|(h, n, p, _)| *h != block || *n != nonce || p != peer)
            {
                return Ok(());
            }
        }
        let Some(m) = manifest else {
            return Ok(());
        };
        m.validate()?;
        if m.block_hash != r.block {
            return Err("candidate manifest block mismatch".into());
        }
        if r.manifest.as_ref() != Some(&m) {
            if r.attempts >= 2 {
                return Err("candidate manifest attempt limit".into());
            }
            r.attempts += 1;
        }
        // Save only after independent native identity and source preflight.
        let cfg = self
            .chain_store
            .get_chain_config()
            .map_err(|e| e.to_string())?
            .ok_or("native configuration absent")?;
        if m.chain_id != cfg.chain_id || m.genesis_hash != cfg.genesis_hash {
            return Err("candidate manifest network mismatch".into());
        }
        let body = self.admission_body(&r)?;
        if self
            .chain_store
            .get_block_hash_by_number(r.number)
            .map_err(|e| e.to_string())?
            == Some(r.block)
        {
            // Recovery after native commit must use the canonical source checks.
            self.validate_proof_upload_source(&m)?;
        } else {
            self.validate_live_candidate_source(r.parent, &body)
                .map_err(|e| e.to_string())?;
        }
        r.peer = peer.0.clone();
        r.manifest = Some(m.clone());
        r.state = AdmissionState::Pulling;
        r.error = None;
        self.save_admission(&r)?;
        match self.start_canonical_proof_fetch(peer.0.clone(), m) {
            Ok(_) => {
                self.live_admission.lock().discovery = None;
                Ok(())
            }
            Err(e) if e.contains("busy") => Ok(()),
            Err(e) => {
                r.state = AdmissionState::Paused;
                r.error = Some(e.clone());
                self.save_admission(&r)?;
                Err(e)
            }
        }
    }
    pub(super) fn start_live_candidate_verification(
        self: &Arc<Self>,
        id: ShellHash,
    ) -> Result<(), String> {
        let Some(mut r) = self.pending_admission()? else {
            return Err("live candidate absent".into());
        };
        if r.manifest.as_ref().is_none_or(|m| m.id() != id) {
            return Err("candidate proof identity mismatch".into());
        }
        let mut runtime = self.live_admission.lock();
        if runtime.worker.is_some() {
            return Ok(());
        }
        let body = self.admission_body(&r)?;
        let (status, claimed) = self
            .canonical_proof_uploads
            .claim(&id, true)
            .map_err(|e| e.to_string())?;
        if !claimed {
            return Ok(());
        }
        r.state = AdmissionState::Verifying;
        if let Err(e) = self.save_admission(&r) {
            let _ = self
                .canonical_proof_uploads
                .pause_claim(&id, status.verification_attempts);
            return Err(e);
        }
        let (tx, rx) = mpsc::channel();
        let node = self.clone();
        let parent = r.parent;
        let hash = r.block;
        let handle = tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> Result<VerifiedCandidate, String> {
                    let payload = node
                        .canonical_proof_uploads
                        .payload(&id)
                        .map_err(|e| e.to_string())?;
                    let proof: CanonicalSignatureBatchProof = serde_json::from_slice(&payload)
                        .map_err(|e| {
                            format!("candidate proof decode {}:{}", e.line(), e.column())
                        })?;
                    if node
                        .chain_store
                        .get_block_hash_by_number(body.number())
                        .map_err(|e| e.to_string())?
                        == Some(hash)
                    {
                        let tip = node
                            .chain_store
                            .get_head_hash()
                            .map_err(|e| e.to_string())?
                            .ok_or("native tip absent")?;
                        return node
                            .replay_canonical_transactions_with_proof(tip, hash, &proof)
                            .map(VerifiedCandidate::Canonical)
                            .map_err(|e| e.to_string());
                    }
                    node.verify_live_candidate_signatures(parent, &body, &proof)
                        .map(VerifiedCandidate::Fresh)
                        .map_err(|e| e.to_string())
                },
            ))
            .unwrap_or_else(|_| Err("candidate verification worker panicked".into()));
            let _ = tx.send(result);
        });
        runtime.worker = Some(Worker {
            record: r,
            attempt: status.verification_attempts,
            result: rx,
            handle,
        });
        Ok(())
    }
    /// The only live canonical mutation point: invoke from Node.run, never a worker.
    pub(super) fn finish_live_candidate(&self) -> Option<(CanonicalProofReplay, bool)> {
        let pair = {
            let mut runtime = self.live_admission.lock();
            let worker = runtime.worker.as_ref()?;
            match worker.result.try_recv() {
                Ok(result) => Some((runtime.worker.take().unwrap(), result)),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => Some((
                    runtime.worker.take().unwrap(),
                    Err("candidate worker disconnected".into()),
                )),
            }
        };
        let (worker, result) = pair?;
        let mut r = worker.record;
        let id = r.manifest.as_ref()?.id();
        let new_commit = matches!(&result, Ok(VerifiedCandidate::Fresh(_)));
        let result = result.and_then(|verified| {
            let block = self.admission_body(&r)?;
            match verified {
                VerifiedCandidate::Fresh(v) => self
                    .commit_live_verified_candidate(r.parent, block, &v)
                    .map_err(|e| e.to_string()),
                VerifiedCandidate::Canonical(replay) => {
                    if self
                        .chain_store
                        .get_block_hash_by_number(r.number)
                        .map_err(|e| e.to_string())?
                        != Some(r.block)
                        || self
                            .chain_store
                            .get_receipts(&r.block)
                            .map_err(|e| e.to_string())?
                            .as_ref()
                            != Some(&replay.receipts)
                    {
                        return Err("recovered candidate native receipt changed".into());
                    }
                    Ok(replay)
                }
            }
        });
        let success = result.as_ref().ok().cloned();
        match &result {
            Ok(_) => {
                r.state = AdmissionState::Complete;
                r.error = None;
            }
            Err(e) => {
                if e.contains("payload hash mismatch") && r.hash_retries == 0 {
                    r.hash_retries = 1;
                    r.state = AdmissionState::Paused;
                } else {
                    r.state = AdmissionState::Failed;
                }
                r.error = Some(e.chars().take(2048).collect());
            }
        }
        let receipt = result.and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()));
        if let Err(e) = self.canonical_proof_uploads.complete(&id, receipt) {
            r.state = AdmissionState::Paused;
            r.error = Some(format!(
                "candidate result not persisted; full recheck required: {e}"
            ));
            warn!(%e,"candidate result not persisted; full recheck required");
        }
        if let Err(e) = self.save_admission(&r) {
            warn!(%e,"candidate status not persisted; native state remains authoritative");
        }
        success.map(|replay| (replay, new_commit))
    }
    pub(super) async fn shutdown_live_candidate(&self) {
        let worker = self.live_admission.lock().worker.take();
        if let Some(worker) = worker {
            let _ = worker.handle.await;
            let mut r = worker.record;
            if let Some(m) = &r.manifest {
                let _ = self
                    .canonical_proof_uploads
                    .pause_claim(&m.id(), worker.attempt);
            }
            r.state = AdmissionState::Paused;
            r.error =
                Some("node stopped before native candidate commit; full recheck required".into());
            if let Err(e) = self.save_admission(&r) {
                warn!(%e,"candidate pause persistence failed");
            }
        }
    }
    pub(super) fn live_discovery_request(
        &self,
        peers: &[PeerId],
    ) -> Option<(PeerId, shell_network::NetworkMessage)> {
        if peers.is_empty() {
            return None;
        }
        let r = self.pending_admission().ok().flatten().or_else(|| {
            self.admission_ids().ok()?.into_iter().find_map(|id| {
                let r = self.admission_record(id).ok().flatten()?;
                (r.state == AdmissionState::Failed && r.attempts < 2).then_some(r)
            })
        })?;
        if r.state == AdmissionState::Verifying && self.live_admission.lock().worker.is_some() {
            return None;
        }
        let mut runtime = self.live_admission.lock();
        if runtime
            .discovery
            .as_ref()
            .is_some_and(|(_, _, _, t)| t.elapsed() < Duration::from_secs(30))
        {
            return None;
        }
        let nonce = Self::wall_clock_millis().checked_add(1)?;
        let peer = peers[runtime.discovery_cursor % peers.len()].clone();
        runtime.discovery_cursor = runtime.discovery_cursor.wrapping_add(1);
        runtime.discovery = Some((r.block, nonce, peer.clone(), Instant::now()));
        Some((
            peer,
            shell_network::NetworkMessage::CanonicalProofManifestRequest {
                version: 1,
                block_hash: r.block,
                nonce,
            },
        ))
    }
    pub(super) fn proof_availability_announcements(
        &self,
        peers: &[PeerId],
    ) -> Vec<(PeerId, shell_network::NetworkMessage)> {
        let manifests = self
            .canonical_proof_uploads
            .available_manifests()
            .unwrap_or_default();
        let mut actions = vec![];
        for m in manifests {
            if self.validate_proof_upload_source(&m).is_err() {
                continue;
            }
            let mut runtime = self.live_admission.lock();
            for peer in peers {
                if runtime.advertised.len() >= 256 * 8 {
                    break;
                }
                if runtime.advertised.insert((peer.0.clone(), m.id())) {
                    actions.push((
                        peer.clone(),
                        shell_network::NetworkMessage::CanonicalProofManifestResponse {
                            version: 1,
                            block_hash: m.block_hash,
                            nonce: 0,
                            manifest: Some(m.clone()),
                        },
                    ));
                }
            }
        }
        actions
    }
    pub(super) fn admission_peer_disconnected(&self, peer: &PeerId) {
        self.live_admission
            .lock()
            .advertised
            .retain(|(p, _)| *p != peer.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_storage::MemoryDb;
    #[test]
    fn manifest_wrong_peer_nonce_and_network_do_not_allocate_proof_bytes() {
        let db = Arc::new(MemoryDb::new());
        let mut node =
            super::super::tests::setup_node_with_store(Address::from([1; 32]), db.clone());
        let config: shell_storage::ChainConfig=serde_json::from_value(serde_json::json!({"chain_id":node.config.chain_id,"genesis_hash":ShellHash::from([1;32])})).unwrap();
        node.chain_store.put_chain_config(&config).unwrap();
        let block = ShellHash::from([7; 32]);
        let peer = PeerId("provider".into());
        let m = CanonicalProofManifest {
            version: 1,
            chain_id: 999,
            genesis_hash: ShellHash::ZERO,
            block_hash: block,
            total_bytes: 1,
            payload_hash: ShellHash::ZERO,
        };
        let before = db.scan_all().unwrap();
        node.accept_live_manifest(&peer, block, 0, Some(m.clone()))
            .unwrap();
        assert_eq!(db.scan_all().unwrap(), before);
        node.config.canonical_proof_admission = true;
        let r = AdmissionRecord {
            version: 1,
            block,
            number: 1,
            parent: ShellHash::ZERO,
            source_hash: ShellHash::ZERO,
            peer: peer.0.clone(),
            state: AdmissionState::Waiting,
            manifest: None,
            attempts: 0,
            hash_retries: 0,
            error: None,
        };
        node.save_admission(&r).unwrap();
        node.live_admission.lock().discovery = Some((block, 19, peer.clone(), Instant::now()));
        let before = db.scan_all().unwrap();
        node.accept_live_manifest(&PeerId("foreign".into()), block, 19, Some(m.clone()))
            .unwrap();
        node.accept_live_manifest(&peer, block, 18, Some(m.clone()))
            .unwrap();
        assert!(node
            .accept_live_manifest(&peer, block, 19, Some(m))
            .unwrap_err()
            .contains("network mismatch"));
        assert_eq!(db.scan_all().unwrap(), before);
        let mut interrupted = r;
        interrupted.state = AdmissionState::Verifying;
        node.save_admission(&interrupted).unwrap();
        db.put(
            &key(b"jobs", None),
            &serde_json::to_vec(&vec![block]).unwrap(),
        )
        .unwrap();
        node.live_admission.lock().discovery = None;
        let bad_network = CanonicalProofManifest {
            version: 1,
            chain_id: 999,
            genesis_hash: ShellHash::ZERO,
            block_hash: block,
            total_bytes: 1,
            payload_hash: ShellHash::ZERO,
        };
        assert!(node
            .accept_live_manifest(&peer, block, 0, Some(bad_network))
            .unwrap_err()
            .contains("network mismatch"));
        assert!(node
            .live_discovery_request(std::slice::from_ref(&peer))
            .is_some());
        assert!(db
            .scan_prefix(shell_storage::CANONICAL_PROOF_CACHE_PREFIX)
            .unwrap()
            .is_empty());
    }
}
