use super::*;
use shell_network::{NetworkMessage, PeerId};
use shell_rpc::CanonicalProofControl;
use shell_storage::{
    CanonicalProofFetchState as FetchState, CanonicalProofFetchStatus, CanonicalProofManifest,
    CanonicalProofUploadState as UploadState, CanonicalProofUploadStatus,
};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u8 = 2;
const MAX_PROOF_PEERS: usize = 256;

#[derive(Default)]
pub(super) struct CanonicalProofPeerState {
    running: bool,
    peers: HashSet<PeerId>,
    active: Option<Pull>,
}
struct Pull {
    status: CanonicalProofFetchStatus,
    sent_at: Option<Instant>,
    retries: u8,
}
pub(super) struct ProofPeerAction {
    peer: PeerId,
    message: NetworkMessage,
}
pub(super) struct ProofPeerGuard<'a, S: KvStore + 'static> {
    node: &'a Node<S>,
}
impl<S: KvStore + 'static> Drop for ProofPeerGuard<'_, S> {
    fn drop(&mut self) {
        let mut state = self.node.canonical_proof_peer.lock();
        state.running = false;
        state.peers.clear();
        if let Some(mut pull) = state.active.take() {
            self.node.finish_proof_pull(
                &mut pull,
                FetchState::Paused,
                "proof network stopped; resume explicitly".into(),
            );
        }
    }
}
impl<S: KvStore + 'static> Node<S> {
    pub(super) fn activate_canonical_proof_network(&self, enabled: bool) -> ProofPeerGuard<'_, S> {
        self.canonical_proof_peer.lock().running = enabled;
        ProofPeerGuard { node: self }
    }
    pub(super) fn canonical_proof_peer_connected(&self, peer: PeerId) {
        let mut state = self.canonical_proof_peer.lock();
        if state.running && state.peers.len() < MAX_PROOF_PEERS {
            state.peers.insert(peer);
        }
    }
    pub(super) fn canonical_proof_peer_disconnected(&self, peer: &PeerId) {
        let mut state = self.canonical_proof_peer.lock();
        state.peers.remove(peer);
        if state
            .active
            .as_ref()
            .is_some_and(|pull| pull.status.peer == peer.0)
        {
            if let Some(mut pull) = state.active.take() {
                self.finish_proof_pull(
                    &mut pull,
                    FetchState::Paused,
                    "proof peer disconnected; resume explicitly".into(),
                );
            }
        }
    }
    pub(super) fn start_canonical_proof_fetch(
        &self,
        peer: String,
        manifest: CanonicalProofManifest,
    ) -> Result<CanonicalProofFetchStatus, String> {
        let mut state = self.canonical_proof_peer.lock();
        if !state.running {
            return Err("canonical proof dedicated network is not running".into());
        }
        if peer.is_empty() || peer.len() > 128 || !state.peers.contains(&PeerId(peer.clone())) {
            return Err("canonical proof peer is not connected".into());
        }
        if state.active.is_some() {
            return Err("canonical proof transfer busy".into());
        }
        self.validate_proof_upload_source(&manifest)?;
        let mut upload = self
            .canonical_proof_uploads
            .begin(manifest)
            .map_err(|e| e.to_string())?;
        let previous = self
            .canonical_proof_uploads
            .fetch_status(&upload.proof_id, None)
            .map_err(|e| e.to_string())?;
        if upload.state == UploadState::Rejected {
            upload = self
                .canonical_proof_uploads
                .restart_corrupt(&upload.proof_id)
                .map_err(|e| e.to_string())?;
        }
        let nonce = previous
            .map_or(0, |p| p.nonce)
            .max(Self::wall_clock_millis())
            .checked_add(1)
            .ok_or("canonical proof nonce overflow")?;
        let status = CanonicalProofFetchStatus {
            version: 1,
            proof_id: upload.proof_id,
            generation: upload.generation,
            peer,
            nonce,
            next_chunk: upload.next_chunk,
            received_bytes: upload.received_bytes,
            state: if upload.state == UploadState::Verified {
                FetchState::Complete
            } else {
                FetchState::Receiving
            },
            error: None,
        };
        self.canonical_proof_uploads
            .save_fetch_status(&status)
            .map_err(|e| e.to_string())?;
        if status.state != FetchState::Complete {
            state.active = Some(Pull {
                status: status.clone(),
                sent_at: None,
                retries: 0,
            });
        }
        Ok(status)
    }
    pub(super) fn canonical_proof_fetch_status(
        &self,
        id: ShellHash,
        generation: Option<u64>,
    ) -> Result<Option<CanonicalProofFetchStatus>, String> {
        let state = self.canonical_proof_peer.lock();
        let mut status = self
            .canonical_proof_uploads
            .fetch_status(&id, generation)
            .map_err(|e| e.to_string())?;
        if let Some(ref mut status) = status {
            if matches!(status.state, FetchState::Receiving | FetchState::Verifying)
                && !state.active.as_ref().is_some_and(|p| {
                    p.status.proof_id == id && p.status.generation == status.generation
                })
            {
                status.state = FetchState::Paused;
                status.error = Some("proof transfer interrupted; resume explicitly".into());
            }
        }
        Ok(status)
    }
    fn pull_progress(&self, pull: &mut Pull) -> Result<CanonicalProofUploadStatus, String> {
        let upload = self
            .canonical_proof_uploads
            .status(&pull.status.proof_id)
            .map_err(|e| e.to_string())?;
        if upload.generation != pull.status.generation {
            return Err("canonical proof upload generation changed".into());
        }
        if upload.next_chunk != pull.status.next_chunk {
            pull.sent_at = None;
            pull.retries = 0;
        }
        pull.status.next_chunk = upload.next_chunk;
        pull.status.received_bytes = upload.received_bytes;
        Ok(upload)
    }
    fn finish_proof_pull(&self, pull: &mut Pull, state: FetchState, error: String) {
        let _ = self.pull_progress(pull);
        pull.status.state = state;
        pull.status.error = Some(error.chars().take(2048).collect());
        if let Err(error) = self.canonical_proof_uploads.save_fetch_status(&pull.status) {
            warn!(%error,"proof transfer status persistence failed; raw upload retained");
        }
    }
    fn step_proof_pull(
        self: &Arc<Self>,
        pull: &mut Pull,
    ) -> Result<(Option<ProofPeerAction>, bool), String> {
        let upload = self.pull_progress(pull)?;
        match upload.state {
            UploadState::Verified => {
                pull.status.state = FetchState::Complete;
                pull.status.error = None;
                self.canonical_proof_uploads
                    .save_fetch_status(&pull.status)
                    .map_err(|e| e.to_string())?;
                return Ok((None, true));
            }
            UploadState::Rejected => {
                return Err(upload
                    .error
                    .unwrap_or_else(|| "canonical proof rejected".into()))
            }
            UploadState::Ready | UploadState::Verifying => {
                if upload.state == UploadState::Verifying
                    && pull.status.state == FetchState::Verifying
                    && !self
                        .canonical_proof_uploads
                        .verification_in_flight(&upload.proof_id)
                {
                    let current = self
                        .canonical_proof_uploads
                        .status(&upload.proof_id)
                        .map_err(|e| e.to_string())?;
                    if current.state == UploadState::Verifying {
                        return Err(
                            "canonical proof verification interrupted; resume explicitly".into(),
                        );
                    }
                    return Ok((None, false));
                }

                if pull.status.state != FetchState::Verifying {
                    <Self as CanonicalProofControl>::verify(self.clone(), upload.proof_id, false)?;
                    pull.status.state = FetchState::Verifying;
                    pull.sent_at = None;
                    self.canonical_proof_uploads
                        .save_fetch_status(&pull.status)
                        .map_err(|e| e.to_string())?;
                }
                return Ok((None, false));
            }
            UploadState::Uploading => {}
        }
        if let Some(sent) = pull.sent_at {
            if sent.elapsed() < REQUEST_TIMEOUT {
                return Ok((None, false));
            }
            if pull.retries >= MAX_RETRIES {
                return Err("canonical proof request timeout; resume explicitly".into());
            }
            pull.retries += 1;
        }
        pull.status.nonce = pull
            .status
            .nonce
            .checked_add(1)
            .ok_or("canonical proof nonce overflow")?;
        // Persist before sending so restart cannot reuse a previously issued nonce.
        self.canonical_proof_uploads
            .save_fetch_status(&pull.status)
            .map_err(|e| e.to_string())?;
        pull.sent_at = Some(Instant::now());
        Ok((
            Some(ProofPeerAction {
                peer: PeerId(pull.status.peer.clone()),
                message: NetworkMessage::CanonicalProofChunkRequest {
                    version: 1,
                    proof_id: pull.status.proof_id,
                    index: pull.status.next_chunk,
                    nonce: pull.status.nonce,
                },
            }),
            false,
        ))
    }
    pub(super) fn drive_canonical_proof_pull(self: &Arc<Self>) -> Option<ProofPeerAction> {
        let mut state = self.canonical_proof_peer.lock();
        let mut pull = state.active.take()?;
        match self.step_proof_pull(&mut pull) {
            Ok((action, finished)) => {
                if !finished {
                    state.active = Some(pull);
                }
                action
            }
            Err(error) => {
                self.finish_proof_pull(&mut pull, FetchState::Failed, error);
                None
            }
        }
    }
    pub(super) fn canonical_proof_message(
        self: &Arc<Self>,
        peer: &PeerId,
        message: NetworkMessage,
    ) -> Option<ProofPeerAction> {
        match message {
            NetworkMessage::CanonicalProofChunkRequest {
                version,
                proof_id,
                index,
                nonce,
            } => {
                let allowed = {
                    let state = self.canonical_proof_peer.lock();
                    state.running && state.peers.contains(peer)
                };
                if !allowed
                    || version != 1
                    || nonce == 0
                    || u64::from(index)
                        >= shell_core::MAX_CANONICAL_PROOF_BYTES
                            .div_ceil(shell_core::CANONICAL_PROOF_CHUNK_BYTES as u64)
                {
                    return None;
                }
                let data = <Self as CanonicalProofControl>::status(self, proof_id)
                    .ok()
                    .filter(|status| status.state == UploadState::Verified)
                    .and_then(|_| {
                        <Self as CanonicalProofControl>::chunk(self, proof_id, index).ok()
                    });
                let error = data
                    .is_none()
                    .then(|| "canonical proof chunk unavailable".to_string());
                Some(ProofPeerAction {
                    peer: peer.clone(),
                    message: NetworkMessage::CanonicalProofChunkResponse {
                        version: 1,
                        proof_id,
                        index,
                        nonce,
                        data,
                        error,
                    },
                })
            }
            NetworkMessage::CanonicalProofChunkResponse {
                version,
                proof_id,
                index,
                nonce,
                data,
                error,
            } => {
                {
                    let mut state = self.canonical_proof_peer.lock();
                    let pull = state.active.as_ref()?;
                    if !state.running
                        || version != 1
                        || pull.sent_at.is_none()
                        || pull.status.state != FetchState::Receiving
                        || pull.status.peer != peer.0
                        || pull.status.proof_id != proof_id
                        || pull.status.next_chunk != index
                        || pull.status.nonce != nonce
                    {
                        return None;
                    }
                    let mut pull = state.active.take()?;
                    if let Some(error) = error {
                        self.finish_proof_pull(&mut pull, FetchState::Failed, error);
                        return None;
                    }
                    let Some(data) = data else {
                        self.finish_proof_pull(
                            &mut pull,
                            FetchState::Failed,
                            "canonical proof response missing data".into(),
                        );
                        return None;
                    };
                    match <Self as CanonicalProofControl>::append(self, proof_id, index, data) {
                        Ok(upload) => {
                            pull.status.next_chunk = upload.next_chunk;
                            pull.status.received_bytes = upload.received_bytes;
                            pull.sent_at = None;
                            pull.retries = 0;
                            if let Err(error) =
                                self.canonical_proof_uploads.save_fetch_status(&pull.status)
                            {
                                self.finish_proof_pull(
                                    &mut pull,
                                    FetchState::Failed,
                                    error.to_string(),
                                );
                                return None;
                            }
                            state.active = Some(pull);
                        }
                        Err(error) => {
                            self.finish_proof_pull(&mut pull, FetchState::Failed, error);
                            return None;
                        }
                    }
                }
                self.drive_canonical_proof_pull()
            }
            _ => None,
        }
    }
    pub(super) async fn send_canonical_proof_action<N: NetworkService + ?Sized>(
        &self,
        network: &NetworkInterface<'_, N>,
        action: Option<ProofPeerAction>,
    ) {
        if let Some(action) = action {
            if let Err(error) = network
                .send_to_peer(&action.peer, action.message.clone())
                .await
            {
                if let NetworkMessage::CanonicalProofChunkRequest {
                    proof_id,
                    index,
                    nonce,
                    ..
                } = action.message
                {
                    let mut state = self.canonical_proof_peer.lock();
                    if state.active.as_ref().is_some_and(|p| {
                        p.status.peer == action.peer.0
                            && p.status.proof_id == proof_id
                            && p.status.next_chunk == index
                            && p.status.nonce == nonce
                    }) {
                        if let Some(mut pull) = state.active.take() {
                            self.finish_proof_pull(
                                &mut pull,
                                FetchState::Failed,
                                error.to_string(),
                            );
                        }
                    }
                }
                warn!(%error,"canonical proof direct send failed; no gossip fallback");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_storage::{CanonicalProofUploadStore, MemoryDb};
    fn node(db: Arc<MemoryDb>) -> Arc<Node<MemoryDb>> {
        Arc::new(super::super::tests::setup_node_with_store(
            Address::from([1; 32]),
            db,
        ))
    }
    fn manifest() -> CanonicalProofManifest {
        CanonicalProofManifest {
            version: 1,
            chain_id: 10,
            genesis_hash: ShellHash::ZERO,
            block_hash: ShellHash::ZERO,
            total_bytes: 1,
            payload_hash: shell_primitives::blake3_hash(b"a"),
        }
    }
    fn meta(id: ShellHash) -> CanonicalProofFetchStatus {
        CanonicalProofFetchStatus {
            version: 1,
            proof_id: id,
            generation: 0,
            peer: "provider".into(),
            nonce: 19,
            next_chunk: 0,
            received_bytes: 0,
            state: FetchState::Receiving,
            error: None,
        }
    }
    #[test]
    fn canonical_proof_peer_inactive_unknown_source_and_unrequested_frames_do_not_allocate() {
        let db = Arc::new(MemoryDb::new());
        let node = node(db.clone());
        let before = db.scan_all().unwrap();
        assert!(node
            .start_canonical_proof_fetch("provider".into(), manifest())
            .is_err());
        {
            let _runtime = node.activate_canonical_proof_network(true);
            assert!(node
                .start_canonical_proof_fetch("provider".into(), manifest())
                .is_err());
            node.canonical_proof_peer_connected(PeerId("provider".into()));
            assert!(node
                .start_canonical_proof_fetch("provider".into(), manifest())
                .is_err());
            let response = NetworkMessage::CanonicalProofChunkResponse {
                version: 1,
                proof_id: manifest().id(),
                index: 0,
                nonce: 19,
                data: Some(Bytes::copy_from_slice(b"a")),
                error: None,
            };
            assert!(node
                .canonical_proof_message(&PeerId("provider".into()), response)
                .is_none());
        }
        assert!(!node.canonical_proof_peer.lock().running);
        assert_eq!(db.scan_all().unwrap(), before);
    }
    #[test]
    fn canonical_proof_peer_wrong_peer_id_nonce_and_index_cannot_write_pending_upload() {
        let db = Arc::new(MemoryDb::new());
        let node = node(db.clone());
        let id = node
            .canonical_proof_uploads
            .begin(manifest())
            .unwrap()
            .proof_id;
        let _runtime = node.activate_canonical_proof_network(true);
        let status = meta(id);
        node.canonical_proof_peer.lock().active = Some(Pull {
            status: status.clone(),
            sent_at: Some(Instant::now()),
            retries: 0,
        });
        let before = db.scan_all().unwrap();
        for (peer, proof_id, index, nonce) in [
            ("other", id, 0, 19),
            ("provider", ShellHash::from([7; 32]), 0, 19),
            ("provider", id, 1, 19),
            ("provider", id, 0, 20),
        ] {
            let message = NetworkMessage::CanonicalProofChunkResponse {
                version: 1,
                proof_id,
                index,
                nonce,
                data: Some(Bytes::copy_from_slice(b"a")),
                error: None,
            };
            assert!(node
                .canonical_proof_message(&PeerId(peer.into()), message)
                .is_none());
            assert_eq!(db.scan_all().unwrap(), before);
        }
        assert_eq!(
            node.canonical_proof_peer
                .lock()
                .active
                .as_ref()
                .unwrap()
                .status,
            status
        );
    }
    #[test]
    fn canonical_proof_peer_restart_status_is_read_only_and_stale_worker_requires_explicit_resume()
    {
        let db = Arc::new(MemoryDb::new());
        let cache = CanonicalProofUploadStore::new(db.clone());
        let id = cache.begin(manifest()).unwrap().proof_id;
        let status = meta(id);
        cache.save_fetch_status(&status).unwrap();
        let node = node(db.clone());
        let before = db.scan_all().unwrap();
        assert_eq!(
            node.canonical_proof_fetch_status(id, None)
                .unwrap()
                .unwrap()
                .state,
            FetchState::Paused
        );
        assert_eq!(cache.fetch_status(&id, None).unwrap(), Some(status));
        assert_eq!(db.scan_all().unwrap(), before);
        cache.append(&id, 0, b"a").unwrap();
        cache.claim(&id, false).unwrap();
        drop(cache);
        let _runtime = node.activate_canonical_proof_network(true);
        let status = CanonicalProofFetchStatus {
            next_chunk: 1,
            received_bytes: 1,
            state: FetchState::Verifying,
            ..meta(id)
        };
        node.canonical_proof_uploads
            .save_fetch_status(&status)
            .unwrap();
        node.canonical_proof_peer.lock().active = Some(Pull {
            status,
            sent_at: None,
            retries: 0,
        });
        assert!(node.drive_canonical_proof_pull().is_none());
        assert!(node.canonical_proof_peer.lock().active.is_none());
        let failed = node
            .canonical_proof_fetch_status(id, None)
            .unwrap()
            .unwrap();
        assert_eq!(failed.state, FetchState::Failed);
        assert!(failed.error.unwrap().contains("interrupted"));
        assert_eq!(node.canonical_proof_uploads.payload(&id).unwrap(), b"a");
    }
}
