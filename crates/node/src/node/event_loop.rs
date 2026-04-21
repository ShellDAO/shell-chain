use super::*;

impl<S: KvStore + 'static> Node<S> {
    /// Run the async event loop.
    ///
    /// Drives block production, network event handling, and RPC serving:
    /// - **Block production**: on a timer, if this node is the current proposer,
    ///   produce a block from pending mempool txs and broadcast it.
    /// - **Network events**: import blocks and transactions from peers.
    /// - **RPC server**: serves JSON-RPC on the configured address.
    /// - **Shutdown**: stops on `shutdown()` call or Ctrl-C.
    pub async fn run(
        self: Arc<Self>,
        signer: Arc<dyn Signer>,
        network: &mut dyn NetworkService,
    ) -> Result<(), NodeError> {
        use shell_network::{NetworkEvent, NetworkMessage};
        use shell_rpc::{start_rpc_server, BlockEvent};
        use tokio::time::{interval, Duration};

        *self.runtime_signer.write() = Some(Arc::clone(&signer));

        // Spawn the Prometheus metrics HTTP server if enabled.
        if self.config.metrics.enabled {
            let metrics = Arc::clone(&self.metrics);
            let metrics_addr = self.config.metrics.listen_addr;
            tokio::spawn(crate::metrics::serve_metrics(metrics, metrics_addr));
        }

        // Create a bounded channel for the RPC layer to forward submitted transactions
        // to the network broadcast loop. A capacity of 4096 provides ample buffering for
        // burst submissions while bounding memory growth under sustained RPC spam.
        let (tx_broadcast_tx, mut tx_broadcast_rx) =
            tokio::sync::mpsc::channel::<SignedTransaction>(4096);

        // Create a broadcast channel for block events (eth_subscribe).
        // F-042: Use larger capacity to reduce subscriber lag.
        let (block_event_tx, _) = tokio::sync::broadcast::channel::<BlockEvent>(256);

        // Start JSON-RPC server.
        // Pass the signer to the RPC layer if this node is a validator,
        // enabling governance RPCs (proposeAddValidator / proposeRemoveValidator).
        let proposer_signer: Option<Arc<dyn Signer>> = if self.config.proposer_address.is_some() {
            Some(Arc::clone(&signer))
        } else {
            None
        };
        // Shared finalized block number for the RPC layer.
        // F-107: recover persisted finalized_number from ChainStore on restart,
        // falling back to finality state and then 0.
        let finality_num = self.finality.read().last_finalized_number();
        let persisted_num = self
            .chain_store
            .get_finalized_number()
            .ok()
            .flatten()
            .unwrap_or(0);
        let finalized_number = Arc::new(parking_lot::RwLock::new(finality_num.max(persisted_num)));

        // Get the peer count handle from the network for RPC.
        let peer_count_handle = network.peer_count_handle();

        self.config
            .rpc
            .validate_dev_rpc_exposure()
            .map_err(NodeError::Startup)?;

        let rpc_handle = start_rpc_server(
            self.config.rpc.clone(),
            self.chain_store.clone(),
            self.world_state.clone(),
            self.tx_pool.clone(),
            self.config.chain_id,
            Some(tx_broadcast_tx),
            block_event_tx.clone(),
            proposer_signer,
            self.config.proposer_address,
            finalized_number.clone(),
            self.finality.clone(),
            peer_count_handle,
            if self.config.rpc.has_api_namespace("evm") {
                Some(self.clone() as Arc<dyn DevRpcControl>)
            } else {
                None
            },
            None, // admin_p2p_context: wire peer_id + p2p_listen when P2P layer is integrated
            Some(Arc::clone(&self.witness_store)), // B5: witness store wired
        )
        .await
        .map_err(|e| NodeError::Startup(format!("RPC: {e}")))?;

        // Register own authority pubkey for seal verification.
        if let Some(addr) = self.config.proposer_address {
            self.register_authority_pubkey(addr, signer.public_key().to_vec());
        }

        // ops-banner: print storage policy at startup.
        self.log_pruning_banner();

        let mut block_timer = interval(Duration::from_millis(self.config.block_time_ms));
        let mut peer_count_timer = interval(Duration::from_secs(10));
        let mut sync_retry_timer = interval(Duration::from_secs(SYNC_RETRY_BASE_INTERVAL_SECS));
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        // Track the last time a block was produced for idle-block-skip.
        let mut last_block_time = std::time::Instant::now();
        let mut sync_retry_attempts_without_progress = 0u32;

        // Skip the first immediate tick.
        block_timer.tick().await;
        peer_count_timer.tick().await;
        sync_retry_timer.tick().await;

        // Startup sync: request blocks we don't have from peers.
        // Track whether we are catching up so we don't spam requests.
        let mut sync_requested = false;
        if network.peer_count().await > 0 {
            self.request_missing_blocks(network, &mut sync_requested, "initial-sync")
                .await;
        }

        // H3: Start background prover service if this node is configured to run proving.
        if self.config.node_role.runs_prover() {
            let prover_address = self.config.proposer_address.unwrap_or_default();
            let prover_config = ProverConfig::default();
            let service = ProverService::new(
                Arc::clone(&self.proof_backlog),
                self.amendment_store.clone(),
                prover_config,
                prover_address,
            );
            let handle = service.start();
            *self.prover_service_handle.lock() = Some(handle);
            info!(
                role = ?self.config.node_role,
                "H3: Background prover service started"
            );
        }

        // L4: Advertise storage capability to the network so peers know what
        // historical data this node holds.
        {
            let profile = StorageProfile::from_pruning_config(&self.config.pruning);
            let oldest_body_block = self.oldest_available_body_block();
            let cap_msg = NetworkMessage::StorageCapability {
                profile: profile.as_str().to_string(),
                oldest_body_block,
            };
            let _ = network.broadcast(cap_msg).await;
            info!(
                profile = profile.as_str(),
                oldest_body_block, "L4: broadcasted storage capability"
            );
        }

        // L4: After advertising capability, give peers a brief window to respond,
        // then scan for missing bodies and issue the initial BodyRequest to kick
        // off historical body back-fill on nodes that upgraded their storage profile.
        {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if network.peer_count().await > 0 {
                let oldest = self.oldest_available_body_block();
                let head = self.head_number();
                if oldest > 0 {
                    // There are gaps — request bodies starting from the beginning.
                    let _ = network
                        .broadcast(NetworkMessage::BodyRequest {
                            start_number: 0,
                            count: 128,
                        })
                        .await;
                    info!(
                        oldest_available = oldest,
                        head, "L4: kicked historical body back-fill startup scan"
                    );
                }
            }
        }

        loop {
            tokio::select! {
                _ = block_timer.tick() => {
                    if self.config.proposer_address.is_some() {
                        // Idle-block-skip: when mempool is empty and we haven't
                        // exceeded max_idle_interval, skip block production.
                        let max_idle_ms = self.config.max_idle_interval_ms;
                        if max_idle_ms > 0 && self.tx_pool.is_empty() {
                            let idle_dur = std::time::Duration::from_millis(max_idle_ms);
                            if last_block_time.elapsed() < idle_dur {
                                continue;
                            }
                            // Heartbeat: produce an empty block to keep chain alive.
                        }

                        let start = std::time::Instant::now();
                        match self.produce_block(&*signer, 500) {
                            Ok(block) => {
                                last_block_time = std::time::Instant::now();
                                let elapsed = start.elapsed().as_secs_f64();
                                self.metrics.block_production_ms.observe(elapsed);
                                self.metrics.blocks_imported.inc();
                                self.metrics.block_height.set(block.number() as i64);
                                self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);

                                let number = block.number();
                                let tx_count = block.transactions.len();
                                let gas = block.header.gas_used;
                                // F-046: Use scope blocks to manage lock lifetimes.
                                {
                                    let consensus = self.consensus.read();
                                    if consensus.config().is_epoch_boundary(number) {
                                        let epoch = consensus.config().epoch_of(number);
                                        info!(epoch, block = number, "new epoch started");
                                    }
                                }
                                // Reload validators at epoch boundaries (F-041: handle errors).
                                // F-061: Scope read lock explicitly to prevent deadlock.
                                let is_epoch = {
                                    self.consensus.read().config().is_epoch_boundary(number)
                                };
                                if is_epoch {
                                    let validators = {
                                        let ws = self.world_state.read();
                                        ws.get_validators()
                                    };
                                    match validators {
                                        Ok(v) if !v.is_empty() => {
                                            self.consensus.write().config_mut().set_authorities(v);
                                        }
                                        Ok(_) => {
                                            // Empty validator set in world state — keep current authorities.
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                error = %e,
                                                block = number,
                                                "CRITICAL: failed to reload validators at epoch boundary — \
                                                 continuing with stale validator set may cause consensus divergence"
                                            );
                                        }
                                    }
                                }
                                eprintln!(
                                    "⛏  Block #{number} produced ({tx_count} txs, {gas} gas)"
                                );

                                // Notify eth_subscribe listeners.
                                let block_hash = block.hash();
                                let receipts = self
                                    .chain_store
                                    .get_receipts(&block_hash)
                                    .ok()
                                    .flatten()
                                    .unwrap_or_default();
                                if block_event_tx.send(BlockEvent::NewBlock {
                                    header: block.header.clone(),
                                    receipts,
                                }).is_err() {
                                    tracing::warn!("no active subscribers for block events");
                                }

                                let msg = NetworkMessage::NewBlock(Box::new(block));
                                let _ = network.broadcast(msg).await;
                            }
                            Err(NodeError::NotProposer) => {
                                // Not our turn to propose; silently skip.
                            }
                            Err(e) => {
                                eprintln!("⚠  Block production error: {e}");
                            }
                        }
                    }
                }

                event = network.next_event() => {
                    match event {
                        Some(NetworkEvent::MessageReceived { peer, message }) => {
                            match message {
                                NetworkMessage::NewBlock(block) => {
                                    let verifier = MultiVerifier;
                                    let saved_header = block.header.clone();
                                    let saved_hash = block.hash();
                                    let imported_number = block.number();
                                    match self.import_block(*block, &verifier) {
                                        Ok(()) => {
                                            sync_requested = false;
                                            sync_retry_attempts_without_progress = 0;
                                            sync_retry_timer.reset_after(Duration::from_secs(
                                                SYNC_RETRY_BASE_INTERVAL_SECS,
                                            ));
                                            self.metrics.blocks_imported.inc();
                                            self.metrics.block_height.set(imported_number as i64);
                                            self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);

                                            // Notify eth_subscribe listeners.
                                            let receipts = self
                                                .chain_store
                                                .get_receipts(&saved_hash)
                                                .ok()
                                                .flatten()
                                                .unwrap_or_default();
                                            if block_event_tx.send(BlockEvent::NewBlock {
                                                header: saved_header,
                                                receipts,
                                            }).is_err() {
                                                tracing::warn!("no active subscribers for block events");
                                            }

                                            // I1: Drain any equivocation proofs discovered
                                            // during import and broadcast to the network.
                                            let pending: Vec<EquivocationProof> = {
                                                let mut q = self.equivocation_queue.lock();
                                                std::mem::take(&mut *q)
                                            };
                                            for equivocation in pending {
                                                let msg = NetworkMessage::EquivocationEvidence(
                                                    Box::new(equivocation),
                                                );
                                                let _ = network.broadcast(msg).await;
                                            }
                                        }
                                        Err(NodeError::GapDetected { .. }) => {
                                            // Only request missing blocks on genuine gap,
                                            // NOT on invalid signatures or other errors (F-037).
                                            if !sync_requested {
                                                self.request_missing_blocks(
                                                    network,
                                                    &mut sync_requested,
                                                    "gap-detected",
                                                )
                                                .await;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("⚠  Block import error: {e}");
                                        }
                                    }
                                }
                                NetworkMessage::NewTransaction(tx) => {
                                    // F-043: Use insert() directly — it returns Duplicate
                                    // error if already known, avoiding TOCTOU race.
                                    let verifier = MultiVerifier;
                                    match self.handle_incoming_tx(*tx, &verifier) {
                                        Ok(_hash) => {
                                            self.metrics.txs_received.inc();
                                            self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);
                                        }
                                        Err(e) => {
                                            // MempoolError::Duplicate is expected for re-broadcast; don't log it as error.
                                            let msg = format!("{e}");
                                            if !msg.contains("duplicate") && !msg.contains("Duplicate") {
                                                eprintln!("⚠  Tx handling error: {e}");
                                            }
                                        }
                                    }
                                }
                                NetworkMessage::BlockRequest { start_number, count } => {
                                    const MAX_BLOCK_RESPONSE: u64 = 128;
                                    let safe_count = count.min(MAX_BLOCK_RESPONSE);
                                    debug!(
                                        %peer,
                                        start_number,
                                        count,
                                        safe_count,
                                        "received BlockRequest"
                                    );
                                    let mut blocks = Vec::new();
                                    for n in start_number..start_number.saturating_add(safe_count) {
                                        match self.chain_store.get_block_by_number(n) {
                                            Ok(Some(block)) => blocks.push(block),
                                            _ => break,
                                        }
                                    }
                                    if !blocks.is_empty() {
                                        info!(
                                            count = blocks.len(),
                                            from = start_number,
                                            "responding with blocks"
                                        );
                                        let resp = NetworkMessage::BlockResponse { blocks };
                                        let _ = network.broadcast(resp).await;
                                    }
                                }
                                NetworkMessage::BlockResponse { blocks } => {
                                    info!(
                                        count = blocks.len(),
                                        "received BlockResponse, importing blocks"
                                    );
                                    let verifier = MultiVerifier;
                                    let mut last_ok = 0u64;
                                    for block in blocks {
                                        let num = block.number();
                                        let hdr = block.header.clone();
                                        let bhash = block.hash();
                                        match self.import_block(block, &verifier) {
                                            Ok(()) => {
                                                last_ok = num;
                                                self.metrics.blocks_imported.inc();
                                                self.metrics.block_height.set(num as i64);
                                                debug!(number = num, "synced block");

                                                // Notify eth_subscribe listeners.
                                                let receipts = self
                                                    .chain_store
                                                    .get_receipts(&bhash)
                                                    .ok()
                                                    .flatten()
                                                    .unwrap_or_default();
                                                if block_event_tx.send(BlockEvent::NewBlock {
                                                    header: hdr,
                                                    receipts,
                                                }).is_err() {
                                                    tracing::warn!("no active subscribers for block events");
                                                }
                                            }
                                            Err(e) => {
                                                warn!(
                                                    number = num,
                                                    error = %e,
                                                    "block sync import failed"
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    // Request next batch if we imported blocks
                                    // (there may be more to catch up on).
                                    if last_ok > 0 {
                                        let req = NetworkMessage::BlockRequest {
                                            start_number: last_ok + 1,
                                            count: 128,
                                        };
                                        let _ = network.broadcast(req).await;
                                        sync_requested = true;
                                        sync_retry_attempts_without_progress = 0;
                                        sync_retry_timer.reset_after(Duration::from_secs(
                                            SYNC_RETRY_BASE_INTERVAL_SECS,
                                        ));
                                    } else {
                                        sync_requested = false;
                                        sync_retry_attempts_without_progress = 0;
                                        sync_retry_timer.reset_after(Duration::from_secs(
                                            SYNC_RETRY_BASE_INTERVAL_SECS,
                                        ));
                                    }
                                }
                                NetworkMessage::Ping => {
                                    debug!(%peer, "received Ping, responding with Pong");
                                    let _ = network.broadcast(NetworkMessage::Pong).await;
                                }
                                NetworkMessage::Pong => {
                                    debug!(%peer, "received Pong");
                                }
                                NetworkMessage::NewAttestation(attestation) => {
                                    let verifier = MultiVerifier;
                                    if let Err(e) = self.handle_attestation(*attestation, &verifier) {
                                        tracing::warn!("attestation error: {e}");
                                    }
                                    // Push latest finalized number to the RPC layer.
                                    let fin = self.finality.read().last_finalized_number();
                                    let mut fn_w = finalized_number.write();
                                    if fin > *fn_w {
                                        *fn_w = fin;
                                    }
                                }
                                // G5: Receive async STARK proof amendment from a prover node.
                                // Deserialize, store via ProofAmendmentStore, log result.
                                NetworkMessage::ProofAmendment { block_hash, block_number, payload } => {
                                    debug!(%peer, block = block_number, "received ProofAmendment");
                                    if let Err(e) = self.amendment_store.put_amendment(&block_hash, &payload) {
                                        warn!(%peer, block = block_number, "failed to store proof amendment: {e}");
                                    } else {
                                        info!(block = block_number, "G5: proof amendment stored from peer {peer}");
                                        // L2: delete witness bundle once proof is secured, unless grace window is active.
                                        let grace = self.config.pruning.proof_replacement_grace;
                                        if grace == 0 {
                                            match self.chain_store.delete_witness_bundle(&block_hash) {
                                                Ok(()) => info!(block = block_number, "L2: witness bundle deleted after proof replacement"),
                                                Err(e) => warn!(block = block_number, "L2: failed to delete witness bundle: {e}"),
                                            }
                                        } else {
                                            let head = self.chain_store.get_head_block()
                                                .ok().flatten().map(|b| b.header.number).unwrap_or(0);
                                            if head.saturating_sub(block_number) >= grace {
                                                match self.chain_store.delete_witness_bundle(&block_hash) {
                                                    Ok(()) => info!(block = block_number, "L2: witness bundle deleted after grace period"),
                                                    Err(e) => warn!(block = block_number, "L2: failed to delete witness bundle: {e}"),
                                                }
                                            } else {
                                                // Schedule deletion: delete once head reaches block_number + grace.
                                                let delete_at = block_number.saturating_add(grace);
                                                self.pending_grace_deletes.lock().insert(block_hash, delete_at);
                                                debug!(block = block_number, grace, head, delete_at, "L2: proof stored, within grace window — deletion scheduled");
                                            }
                                        }
                                    }
                                }
                                // G5: Acknowledge that a peer has stored a proof amendment.
                                NetworkMessage::ProofAck { block_hash, holder } => {
                                    debug!(%peer, ?holder, "received ProofAck for block {}", block_hash);
                                }
                                // I1: Received equivocation evidence from a peer.
                                // Independently verify and apply slashing if valid.
                                NetworkMessage::EquivocationEvidence(equivocation) => {
                                    if equivocation.verify() {
                                        warn!(
                                            offender = %equivocation.offender,
                                            block_number = equivocation.header_a.number,
                                            "I1: equivocation evidence verified, slashing {}",
                                            equivocation.offender
                                        );
                                        self.consensus
                                            .write()
                                            .slash_authority(&equivocation.offender);
                                        warn!(
                                            offender = %equivocation.offender,
                                            "I1: authority slashed — excluded from future block production"
                                        );
                                    } else {
                                        warn!(%peer, "I1: received invalid equivocation evidence, ignoring");
                                    }
                                }
                                // I2: Received a proof challenge from a peer.
                                // If we hold the proof, respond with raw bytes.
                                NetworkMessage::ProofChallenge(challenge) => {
                                    debug!(%peer, block = challenge.block_number, reason = %challenge.reason, "I2: received ProofChallenge");
                                    if let Ok(Some(proof_bytes)) = self.amendment_store.get_amendment(&challenge.block_hash) {
                                        use shell_consensus::ChallengeResponse;
                                        if let Some(our_address) = self.config.proposer_address {
                                            let resp = ChallengeResponse {
                                                block_hash: challenge.block_hash,
                                                proof_bytes,
                                                responder: our_address,
                                            };
                                            let _ = network.broadcast(NetworkMessage::ProofChallengeResponse(Box::new(resp))).await;
                                            debug!(block = challenge.block_number, "I2: sent ChallengeResponse");
                                        }
                                    }
                                }
                                // I2: Received a challenge response with raw proof bytes.
                                // Re-verify and store if valid.
                                NetworkMessage::ProofChallengeResponse(resp) => {
                                    debug!(%peer, "I2: received ChallengeResponse for block {}", resp.block_hash);
                                    // Attempt to verify the provided proof bytes.
                                    match shell_stark_prover::proof::SigBatchProof::from_json(&resp.proof_bytes) {
                                        Ok(sig_proof) => {
                                            if shell_stark_prover::prover::verify_sig_batch(&sig_proof).is_ok() {
                                                if let Err(e) = self.amendment_store.put_amendment(&resp.block_hash, &resp.proof_bytes) {
                                                    warn!("I2: failed to store verified challenge response: {e}");
                                                } else {
                                                    info!(block = %resp.block_hash, "I2: challenge response verified and stored");
                                                }
                                            } else {
                                                warn!(%peer, "I2: challenge response proof verification failed");
                                            }
                                        }
                                        Err(e) => {
                                            warn!(%peer, "I2: challenge response malformed: {e}");
                                        }
                                    }
                                }
                                // L4: Peer announces its storage capability.
                                NetworkMessage::StorageCapability { profile, oldest_body_block } => {
                                    debug!(%peer, profile, oldest_body_block, "L4: received StorageCapability");
                                    self.peer_caps.record(peer.clone(), profile, oldest_body_block);
                                }
                                // L4: Peer requests block bodies for historical back-fill.
                                NetworkMessage::BodyRequest { start_number, count } => {
                                    debug!(%peer, start_number, count, "L4: received BodyRequest");
                                    let end = start_number.saturating_add(count.min(128));
                                    let mut blocks = Vec::new();
                                    for n in start_number..end {
                                        if let Ok(Some(block)) = self.chain_store.get_block_by_number(n) {
                                            blocks.push(block);
                                        } else {
                                            break;
                                        }
                                    }
                                    if !blocks.is_empty() {
                                        debug!(
                                            %peer,
                                            start_number,
                                            count = blocks.len(),
                                            "L4: serving BodyResponse via unicast to requesting peer"
                                        );
                                        let _ = network
                                            .send_to_peer(
                                                &peer,
                                                NetworkMessage::BodyResponse { blocks },
                                            )
                                            // Note: send_to_peer falls back to broadcast if the
                                            // transport does not support unicast addressing.
                                            .await;
                                    }
                                }
                                // L4: Receive block bodies from a peer as historical back-fill.
                                NetworkMessage::BodyResponse { blocks } => {
                                    debug!(%peer, count = blocks.len(), "L4: received BodyResponse");
                                    let head_number = self.chain_store
                                        .get_head_block()
                                        .ok()
                                        .flatten()
                                        .map(|b| b.header.number)
                                        .unwrap_or(0);
                                    // Track the first block in this response so we can
                                    // advance past a bad batch even if no block is stored.
                                    let batch_start = blocks.first().map(|b| b.header.number);
                                    let mut last_stored: Option<u64> = None;
                                    // Track first gap (mismatch or storage failure) so we
                                    // re-request from that point and don't silently skip blocks.
                                    let mut first_gap: Option<u64> = None;
                                    for block in &blocks {
                                        let n = block.header.number;
                                        // Validate block hash matches canonical chain before storing.
                                        let expected_hash = self.chain_store
                                            .get_block_hash_by_number(n)
                                            .ok()
                                            .flatten();
                                        let actual_hash = block.hash();
                                        if expected_hash.as_ref() != Some(&actual_hash) {
                                            warn!(
                                                block = n,
                                                "L4: BodyResponse hash mismatch — skipping (peer may be malicious)"
                                            );
                                            first_gap.get_or_insert(n);
                                            continue;
                                        }
                                        if self.chain_store.has_body(&actual_hash).unwrap_or(false) {
                                            last_stored = Some(n);
                                            continue;
                                        }
                                        if let Err(e) = self.chain_store.put_body_only(block) {
                                            warn!(block = n, error = %e, "L4: failed to store backfill body");
                                            first_gap.get_or_insert(n);
                                        } else {
                                            last_stored = Some(n);
                                        }
                                    }
                                    // If any block failed (mismatch or store error), re-request from
                                    // the first gap so missing blocks are never permanently skipped.
                                    // If all succeeded, continue from last_stored + 1.
                                    // If the entire batch was bad, skip it to avoid stalling.
                                    let next_start = first_gap
                                        .or_else(|| last_stored.map(|n| n + 1))
                                        .or_else(|| batch_start.map(|s| s.saturating_add(128)));
                                    if let Some(next) = next_start {
                                        if next <= head_number {
                                            // More blocks needed — request next batch.
                                            let _ = network.broadcast(NetworkMessage::BodyRequest {
                                                start_number: next,
                                                count: 128,
                                            }).await;
                                        } else {
                                            info!("L4: historical body back-fill complete");
                                        }
                                    }
                                }
                            }
                        }
                        Some(NetworkEvent::PeerConnected(peer)) => {
                            info!(%peer, "peer connected");
                            sync_requested = false;
                            sync_retry_attempts_without_progress = 0;
                            sync_retry_timer
                                .reset_after(Duration::from_secs(SYNC_RETRY_BASE_INTERVAL_SECS));
                            // L4: re-advertise storage capability so newly connected peer knows.
                            {
                                let profile = StorageProfile::from_pruning_config(&self.config.pruning);
                                let oldest = self.oldest_available_body_block();
                                let _ = network.broadcast(NetworkMessage::StorageCapability {
                                    profile: profile.as_str().to_string(),
                                    oldest_body_block: oldest,
                                }).await;
                            }
                            self.request_missing_blocks(
                                network,
                                &mut sync_requested,
                                "peer-connected",
                            )
                            .await;
                        }
                        Some(NetworkEvent::PeerDisconnected(peer)) => {
                            info!(%peer, "peer disconnected");
                            self.peer_caps.remove(&peer);
                            sync_requested = false;
                            sync_retry_attempts_without_progress = 0;
                            sync_retry_timer
                                .reset_after(Duration::from_secs(SYNC_RETRY_BASE_INTERVAL_SECS));
                        }
                        Some(NetworkEvent::RoutingTableUpdated { peer_count }) => {
                            debug!(peer_count, "routing table updated");
                            if peer_count > 0 && !sync_requested {
                                sync_retry_attempts_without_progress = 0;
                                sync_retry_timer.reset_after(Duration::from_secs(
                                    SYNC_RETRY_BASE_INTERVAL_SECS,
                                ));
                                self.request_missing_blocks(
                                    network,
                                    &mut sync_requested,
                                    "routing-update",
                                )
                                .await;
                            }
                        }
                        None => {
                            eprintln!("Network channel closed, shutting down");
                            break;
                        }
                    }
                }

                // Forward RPC-submitted transactions to peers.
                Some(signed_tx) = tx_broadcast_rx.recv() => {
                    let msg = NetworkMessage::NewTransaction(Box::new(signed_tx));
                    let _ = network.broadcast(msg).await;
                }

                // Periodically update peer count metric.
                _ = peer_count_timer.tick() => {
                    let peers = network.peer_count().await;
                    self.metrics.peer_count.set(peers as i64);
                // ops-metrics: update per-CF storage size gauges with a 300s TTL cache.
                // The fallback approximate_prefix_bytes() scans all matching keys; refreshing
                // it every 10s scales poorly as the DB grows. Cache with atomics to amortize.
                {
                    use std::sync::atomic::{AtomicU64, Ordering};
                    use std::time::{SystemTime, UNIX_EPOCH};

                    const STORAGE_SIZE_CACHE_TTL_SECS: u64 = 300;
                    static LAST_STORAGE_SIZE_UPDATE: AtomicU64 = AtomicU64::new(0);
                    static CACHED_CHAIN_BYTES: AtomicU64 = AtomicU64::new(0);
                    static CACHED_WITNESS_BYTES: AtomicU64 = AtomicU64::new(0);
                    static CACHED_PROOF_BYTES: AtomicU64 = AtomicU64::new(0);

                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let last = LAST_STORAGE_SIZE_UPDATE.load(Ordering::Relaxed);

                    if now_secs.saturating_sub(last) >= STORAGE_SIZE_CACHE_TTL_SECS {
                        let chain_bytes = self
                            .chain_store
                            .approximate_prefix_bytes(b"b/")
                            .unwrap_or(0)
                            .saturating_add(
                                self.chain_store.approximate_prefix_bytes(b"h/").unwrap_or(0),
                            )
                            .saturating_add(
                                self.chain_store.approximate_prefix_bytes(b"n/").unwrap_or(0),
                            );
                        let witness_bytes =
                            self.chain_store.approximate_prefix_bytes(b"w/").unwrap_or(0);
                        let proof_bytes =
                            self.chain_store.approximate_prefix_bytes(b"pa/").unwrap_or(0);

                        CACHED_CHAIN_BYTES.store(chain_bytes, Ordering::Relaxed);
                        CACHED_WITNESS_BYTES.store(witness_bytes, Ordering::Relaxed);
                        CACHED_PROOF_BYTES.store(proof_bytes, Ordering::Relaxed);
                        LAST_STORAGE_SIZE_UPDATE.store(now_secs, Ordering::Relaxed);
                    }

                    // State trie bytes are stored in a separate KV namespace; use 0 until
                    // the trie store exposes a size_estimate().
                    self.metrics.update_cf_sizes(
                        CACHED_CHAIN_BYTES.load(Ordering::Relaxed),
                        CACHED_WITNESS_BYTES.load(Ordering::Relaxed),
                        0,
                        CACHED_PROOF_BYTES.load(Ordering::Relaxed),
                    );
                }
                }

                _ = sync_retry_timer.tick() => {
                    if sync_requested && network.peer_count().await > 0 {
                        self.request_missing_blocks(
                            network,
                            &mut sync_requested,
                            "sync-retry",
                        )
                        .await;
                        sync_retry_attempts_without_progress =
                            sync_retry_attempts_without_progress.saturating_add(1);
                        sync_retry_timer.reset_after(Duration::from_secs(
                            Self::sync_retry_delay_secs(sync_retry_attempts_without_progress),
                        ));
                    }
                }

                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        eprintln!("Shutdown signal received");
                        break;
                    }
                }
            }
        }

        // Graceful shutdown: stop RPC servers first.
        rpc_handle.http_handle.stop().ok();
        if let Some(ws) = rpc_handle.ws_handle {
            ws.stop().ok();
        }
        eprintln!("✓ RPC server stopped");

        // Flush storage to disk.
        if let Err(e) = self.store.flush() {
            eprintln!("⚠  Storage flush failed: {e}");
        } else {
            eprintln!("✓ Storage flushed to disk");
        }

        let _ = network.shutdown().await;
        Ok(())
    }
}
