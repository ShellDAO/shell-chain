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
        let local_signer_address =
            Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

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
        let can_produce_blocks =
            self.config.node_role.is_validator() && self.config.proposer_address.is_some();
        let proposer_signer: Option<Arc<dyn Signer>> = if can_produce_blocks {
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

        let invariant_snapshot = self.check_core_invariants()?;
        info!(
            head = invariant_snapshot.head_number,
            head_hash = %invariant_snapshot.head_hash,
            finalized = invariant_snapshot.finalized_number,
            finalized_hash = %invariant_snapshot.finalized_hash,
            chain_totals_head = ?invariant_snapshot.chain_totals_head,
            tx_pool_len = invariant_snapshot.tx_pool_len,
            "core chain invariants satisfied"
        );

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
            Some({
                let p = &self.config.pruning;
                shell_rpc::types::StorageProfileInfo {
                    profile: StorageProfile::from_pruning_config(p).as_str().to_string(),
                    body_retention: p.body_retention,
                    witness_retention: p.witness_retention,
                    keep_recent: p.keep_recent,
                    proof_replacement_grace: p.proof_replacement_grace,
                    state_pruning_experimental: p.state_pruning_experimental,
                }
            }),
            Some(Arc::clone(&self.consensus)
                as Arc<
                    parking_lot::RwLock<dyn shell_consensus::ConsensusEngine>,
                >), // W.6: wire consensus engine for shell_consensusInfo
            Some(Arc::new(self.amendment_store.clone())), // STK.4: wire proof amendment store
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
        // Use Skip so missed ticks are discarded rather than burst-fired; prevents
        // simultaneous multi-block production by multiple validators when the event
        // loop is briefly delayed (e.g. startup sync, block import latency).
        block_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut peer_count_timer = interval(Duration::from_secs(10));
        let mut sync_retry_timer = interval(Duration::from_secs(SYNC_RETRY_BASE_INTERVAL_SECS));
        let mut tx_rebroadcast_timer = interval(Duration::from_secs(TX_REBROADCAST_INTERVAL_SECS));
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut sync_retry_attempts_without_progress = 0u32;
        let startup_sync_grace = Self::startup_sync_grace(self.config.block_time_ms);
        let catch_up_timeout = Self::catch_up_timeout(self.config.block_time_ms);

        // Skip the first immediate tick.
        block_timer.tick().await;
        peer_count_timer.tick().await;
        sync_retry_timer.tick().await;
        tx_rebroadcast_timer.tick().await;

        // Startup sync: request blocks we don't have from peers.
        // Track whether we are catching up so we don't spam requests.
        let mut sync_requested = false;
        let mut sync_request_nonce: Option<u64> = None;
        let startup_peers = network.peer_count().await;
        let allow_isolated_production = self.config.network_type == shell_genesis::NetworkType::Dev
            || self.consensus.read().poa_config().authorities.len() == 1;
        let mut production_readiness = ProductionReadiness::new(
            allow_isolated_production,
            startup_peers,
            self.head_number(),
            std::time::Instant::now(),
            startup_sync_grace,
        );
        if startup_peers > 0 {
            self.request_missing_blocks(
                network,
                None,
                &mut sync_requested,
                &mut sync_request_nonce,
                "initial-sync",
            )
            .await;
        }

        let rebuilt_stark_settlements = self.rebuild_settled_stark_sources_from_chain()?;
        if rebuilt_stark_settlements > 0 {
            info!(
                rebuilt = rebuilt_stark_settlements,
                "rebuilt settled STARK source index from canonical chain"
            );
        }

        let (prover_amendment_tx, mut prover_amendment_rx) = tokio::sync::mpsc::unbounded_channel();

        // H3: Start background prover service if this node is configured to run proving.
        if self.config.node_role.runs_prover() {
            // Seed enough frontier blocks to form a provable batch (≥ MIN_L1_STARK_TXS entries).
            // Using a single block or very few blocks risks seeding a batch that passes the
            // backlog pop but then fails the n_sigs ≥ 512 settlement check.  Seeding up to
            // DEFAULT_MAX_L1_RANGE_SOURCES ensures the initial batch is large enough while
            // still respecting the prover's maximum range size.
            let seeded = self.enqueue_stark_frontier_backlog(DEFAULT_MAX_L1_RANGE_SOURCES)?;
            if seeded > 0 {
                info!(
                    seeded,
                    "queued historical STARK frontier proof tasks before starting prover"
                );
            }
            let prover_address = self.config.proposer_address.unwrap_or(local_signer_address);
            let prover_config = ProverConfig::default();
            let service = ProverService::new(
                Arc::clone(&self.proof_backlog),
                self.amendment_store.clone(),
                prover_config,
                prover_address,
            )
            .with_amendment_sender(prover_amendment_tx);
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
                Some(amendment) = prover_amendment_rx.recv() => {
                    if let Err(e) = self.validate_stark_amendment_ordering(&amendment) {
                        debug!(
                            block = amendment.block_number,
                            layer = amendment.layer,
                            "local STARK proof is stored but not settlement-ready: {e}"
                        );
                        continue;
                    }
                    if can_produce_blocks {
                        self.pending_stark_settlements.lock().push(amendment.clone());
                        info!(
                            block = amendment.block_number,
                            layer = amendment.layer,
                            "local STARK proof queued for reward settlement"
                        );
                    }
                    match amendment.to_json() {
                        Ok(payload) => {
                            let block_hash = amendment.block_hash;
                            let block_number = amendment.block_number;
                            let msg = NetworkMessage::ProofAmendment {
                                block_hash,
                                block_number,
                                payload,
                            };
                            if let Err(e) = network.broadcast(msg).await {
                                warn!(
                                    %block_hash,
                                    block = block_number,
                                    "failed to broadcast local STARK proof amendment: {e}"
                                );
                            } else {
                                self.metrics.stark_amendments_broadcast.inc();
                                info!(
                                    %block_hash,
                                    block = block_number,
                                    layer = amendment.layer,
                                    "broadcast local STARK proof amendment"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                block = amendment.block_number,
                                "failed to serialize local STARK proof amendment for broadcast: {e}"
                            );
                        }
                    }
                }
                _ = block_timer.tick() => {
                    if can_produce_blocks {
                        let peers = network.peer_count().await;
                        production_readiness.refresh(
                            peers,
                            sync_requested,
                            self.head_number(),
                            std::time::Instant::now(),
                        );
                        if !production_readiness.can_produce() {
                            debug!(
                                state = ?production_readiness.state(),
                                reason = production_readiness.reason(),
                                peers,
                                head = self.head_number(),
                                "block production paused by readiness gate"
                            );
                            continue;
                        }
                        if let Some((preferred_hash, preferred_number, canonical_number)) =
                            self.preferred_fork_ahead()
                        {
                            debug!(
                                %preferred_hash,
                                preferred_number,
                                canonical_number,
                                "block production paused because fork-choice prefers an ahead non-canonical branch"
                            );
                            continue;
                        }

                        let head = match self.chain_store.get_head_block() {
                            Ok(Some(head)) => head,
                            Ok(None) => {
                                tracing::error!(
                                    "block production paused because canonical head is missing"
                                );
                                continue;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "block production paused because canonical head could not be loaded"
                                );
                                continue;
                            }
                        };
                        let now_secs = Self::wall_clock_secs();
                        if !Self::block_time_elapsed(
                            head.header.timestamp,
                            now_secs,
                            self.config.block_time_ms,
                        ) {
                            tracing::trace!(
                                head = head.number(),
                                head_timestamp = head.header.timestamp,
                                now_secs,
                                block_time_ms = self.config.block_time_ms,
                                "block production paused until global block cadence elapses"
                            );
                            continue;
                        }

                        // Idle-block-skip: when mempool is empty and we haven't
                        // exceeded max_idle_interval, skip block production.
                        let max_idle_ms = self.config.max_idle_interval_ms;
                        let has_pending_stark_settlement =
                            !self.pending_stark_settlements.lock().is_empty();
                        if max_idle_ms > 0
                            && self.tx_pool.is_empty()
                            && !has_pending_stark_settlement
                            && !Self::block_time_elapsed(head.header.timestamp, now_secs, max_idle_ms)
                        {
                            continue;
                        }
                        // Heartbeat: produce an empty block to keep chain alive.

                        let start = std::time::Instant::now();
                        match self.produce_block(&*signer, 500) {
                            Ok(block) => {
                                let elapsed = start.elapsed().as_secs_f64();
                                self.metrics.block_production_ms.observe(elapsed);
                                self.metrics.blocks_imported.inc();
                                self.metrics.block_height.set(block.number() as i64);
                                self.metrics.update_finality(
                                    block.number(),
                                    self.finality.read().last_finalized_number(),
                                );
                                self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);

                                let number = block.number();
                                let tx_count = block.transactions.len();
                                let gas = block.header.gas_used;
                                // F-046: Use scope blocks to manage lock lifetimes.
                                {
                                    let consensus = self.consensus.read();
                                    if consensus.poa_config().is_epoch_boundary(number) {
                                        let epoch = consensus.poa_config().epoch_of(number);
                                        info!(epoch, block = number, "new epoch started");
                                    }
                                }
                                // Reload validators at epoch boundaries (F-041: handle errors).
                                // F-061: Scope read lock explicitly to prevent deadlock.
                                let is_epoch = {
                                    self.consensus.read().poa_config().is_epoch_boundary(number)
                                };
                                if is_epoch {
                                    let validators = {
                                        let ws = self.world_state.read();
                                        ws.get_validators()
                                    };
                                    match validators {
                                        Ok(v) if !v.is_empty() => {
                                            self.consensus.write().set_authorities(v);
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

                                // W.5: When using wPoA, initialize the round state machine
                                // for the block we just produced and broadcast our vote.
                                // Also record our own vote locally so the proposer can
                                // reach quorum without waiting for an echo of its own message.
                                if self.consensus.read().engine_type() == EngineType::WPoA {
                                    let weights = self.consensus.read().validator_weights();
                                    let mut round = WPoaRound::new(number, 0, weights);
                                    let proposer = block.header.proposer;
                                    let _ = round.on_block_proposed(block_hash, proposer);
                                    *self.wpoa_round.lock() = Some(round);
                                    if can_produce_blocks {
                                        let voter = self
                                            .config
                                            .proposer_address
                                            .expect("validated block producer has proposer address");
                                        if let Ok(pq_sig) = signer.sign(block_hash.as_bytes()) {
                                            let vote_msg = NetworkMessage::WPoaVote {
                                                block_hash,
                                                block_number: number,
                                                voter,
                                                signature: pq_sig.clone(),
                                            };
                                            let _ = network.broadcast(vote_msg).await;
                                            // Record own vote locally so proposer can reach
                                            // quorum without waiting for its message to echo.
                                            self.handle_wpoa_vote(voter, block_hash, number, pq_sig);
                                        }
                                    }
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

                    // W.5: Tick wPoA round state machine to detect proposal/vote timeouts.
                    {
                        let now = std::time::Instant::now();
                        let events = if let Some(ref round) = *self.wpoa_round.lock() {
                            round.tick(now)
                        } else {
                            vec![]
                        };
                        for event in events {
                            match event {
                                WPoaEvent::VoteTimeout { current_round }
                                | WPoaEvent::ProposeTimeout { current_round } => {
                                    warn!(
                                        current_round,
                                        "W.5: wPoA round timeout — initiating view change"
                                    );
                                    let new_view = current_round + 1;
                                    if let Some(ref mut r) = *self.wpoa_round.lock() {
                                        r.start_view_change(new_view);
                                    }
                                    if can_produce_blocks {
                                        let voter = self
                                            .config
                                            .proposer_address
                                            .expect("validated block producer has proposer address");
                                        let block_number = self
                                            .wpoa_round
                                            .lock()
                                            .as_ref()
                                            .map(|r| r.block_number)
                                            .unwrap_or_else(|| self.head_number() + 1);
                                        let vc_msg = NetworkMessage::WPoaViewChange {
                                            new_view,
                                            block_number,
                                            voter,
                                        };
                                        let _ = network.broadcast(vc_msg).await;
                                    }
                                }
                                _ => {}
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
                                    let head_before_import = self.head_number();
                                    // Use block_in_place so the CPU-heavy rayon batch-verify
                                    // inside import_block doesn't starve other async tasks.
                                    match tokio::task::block_in_place(|| self.import_block(*block, &verifier)) {
                                        Ok(()) => {
                                            let head_after_import = self.head_number();
                                            let canonical_advanced =
                                                head_after_import > head_before_import
                                                    && head_after_import == imported_number;
                                            if !canonical_advanced {
                                                debug!(
                                                    number = imported_number,
                                                    %saved_hash,
                                                    head = head_after_import,
                                                    "NewBlock import did not advance canonical head"
                                                );
                                                continue;
                                            }
                                            if production_readiness.state()
                                                != ProductionReadinessState::CatchingUp
                                            {
                                                sync_requested = false;
                                                sync_request_nonce = None;
                                            }
                                            sync_retry_attempts_without_progress = 0;
                                            sync_retry_timer.reset_after(Duration::from_secs(
                                                SYNC_RETRY_BASE_INTERVAL_SECS,
                                            ));
                                            production_readiness.note_import_progress(imported_number);
                                            self.metrics.blocks_imported.inc();
                                            self.metrics.block_height.set(imported_number as i64);
                                            self.metrics.update_finality(
                                                imported_number,
                                                self.finality.read().last_finalized_number(),
                                            );
                                            self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);

                                            // Notify eth_subscribe listeners.
                                            let receipts = self
                                                .chain_store
                                                .get_receipts(&saved_hash)
                                                .ok()
                                                .flatten()
                                                .unwrap_or_default();
                                            if block_event_tx.send(BlockEvent::NewBlock {
                                                header: saved_header.clone(),
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

                                            // W.5: If wPoA is active and we're a validator,
                                            // send our vote for the imported block.
                                            // The proposer already cast its vote during block
                                            // production; non-proposer validators vote here.
                                            if self.consensus.read().engine_type() == EngineType::WPoA {
                                                let weights = self.consensus.read().validator_weights();
                                                // Initialize a round for this block if not already active.
                                                {
                                                    let mut round_guard = self.wpoa_round.lock();
                                                    let needs_init = round_guard
                                                        .as_ref()
                                                        .map(|r| r.block_number != imported_number)
                                                        .unwrap_or(true);
                                                    if needs_init {
                                                        let proposer = saved_header.proposer;
                                                        let mut round = WPoaRound::new(imported_number, 0, weights);
                                                        let _ = round.on_block_proposed(saved_hash, proposer);
                                                        *round_guard = Some(round);
                                                    }
                                                }
                                                if can_produce_blocks {
                                                    let voter = self
                                                        .config
                                                        .proposer_address
                                                        .expect("validated block producer has proposer address");
                                                    if let Ok(pq_sig) = signer.sign(saved_hash.as_bytes()) {
                                                        let vote_msg = NetworkMessage::WPoaVote {
                                                            block_hash: saved_hash,
                                                            block_number: imported_number,
                                                            voter,
                                                            signature: pq_sig.clone(),
                                                        };
                                                        let _ = network.broadcast(vote_msg).await;
                                                        // Record own vote locally; validators should not
                                                        // depend on receiving an echo of their own broadcast.
                                                        self.handle_wpoa_vote(
                                                            voter,
                                                            saved_hash,
                                                            imported_number,
                                                            pq_sig,
                                                        );
                                                        tracing::debug!(
                                                            block_number = imported_number,
                                                            %saved_hash,
                                                            "W.5: validator cast vote for imported block"
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                        Err(NodeError::GapDetected { .. }) => {
                                            // Only request missing blocks on genuine gap,
                                            // NOT on invalid signatures or other errors (F-037).
                                            if !sync_requested {
                                                self.request_missing_blocks(
                                                    network,
                                                    Some(&peer),
                                                    &mut sync_requested,
                                                    &mut sync_request_nonce,
                                                    "gap-detected",
                                                )
                                                .await;
                                                production_readiness.note_sync_requested(
                                                    self.head_number(),
                                                    std::time::Instant::now(),
                                                    catch_up_timeout,
                                                    "gap-detected",
                                                );
                                            } else {
                                                debug!(
                                                    head = self.head_number(),
                                                    "gap detected while sync request is already in flight"
                                                );
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
                                            // MempoolError::Duplicate and nonce-gap errors are
                                            // high-frequency under load; suppress them to avoid
                                            // blocking the event loop with eprintln! syscalls.
                                            let msg = format!("{e}");
                                            if !msg.contains("duplicate")
                                                && !msg.contains("Duplicate")
                                                && !msg.contains("nonce gap")
                                                && !msg.contains("nonce too low")
                                            {
                                                eprintln!("⚠  Tx handling error: {e}");
                                            }
                                        }
                                    }
                                }
                                NetworkMessage::BlockRequest { start_number, count, nonce } => {
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
                                    info!(
                                        count = blocks.len(),
                                        from = start_number,
                                        "responding to block request"
                                    );
                                    let commit_certificates = blocks
                                        .iter()
                                        .filter_map(|block| {
                                            let hash = block.hash();
                                            match self.chain_store.get_commit_certificate(&hash) {
                                                Ok(Some(cert)) => Some((hash, cert)),
                                                Ok(None) => None,
                                                Err(e) => {
                                                    warn!(
                                                        %hash,
                                                        error = %e,
                                                        "FF.7: failed to load commit certificate for BlockResponse"
                                                    );
                                                    None
                                                }
                                            }
                                        })
                                        .collect();
                                    let resp = NetworkMessage::BlockResponse {
                                        blocks,
                                        commit_certificates,
                                        nonce,
                                    };
                                    let _ = network.send_to_peer(&peer, resp).await;
                                }
                                NetworkMessage::BlockResponse { blocks, commit_certificates, nonce } => {
                                    info!(
                                        count = blocks.len(),
                                        nonce,
                                        "received BlockResponse, importing blocks"
                                    );
                                    let response_matches_sync = sync_request_nonce == Some(nonce);
                                    let verifier = MultiVerifier;
                                    let mut last_ok = 0u64;
                                    let certs: HashMap<ShellHash, Vec<u8>> =
                                        commit_certificates.into_iter().collect();
                                    for block in blocks {
                                        let num = block.number();
                                        let hdr = block.header.clone();
                                        let bhash = block.hash();
                                        let head_before_import = self.head_number();
                                        match tokio::task::block_in_place(|| self.import_block(block, &verifier)) {
                                            Ok(()) => {
                                                let head_after_import = self.head_number();
                                                let canonical_advanced =
                                                    head_after_import > head_before_import
                                                        && head_after_import == num;
                                                if !canonical_advanced {
                                                    debug!(
                                                        number = num,
                                                        %bhash,
                                                        head = head_after_import,
                                                        "BlockResponse import did not advance canonical head"
                                                    );
                                                    continue;
                                                }
                                                last_ok = num;
                                                production_readiness.note_import_progress(num);
                                                self.metrics.blocks_imported.inc();
                                                self.metrics.block_height.set(num as i64);
                                                self.metrics.update_finality(
                                                    num,
                                                    self.finality.read().last_finalized_number(),
                                                );
                                                debug!(number = num, "synced block");
                                                if let Some(cert) = certs.get(&bhash) {
                                                    self.fast_finalize_with_certificate(
                                                        num, bhash, cert,
                                                    );
                                                    self.metrics.update_finality(
                                                        num,
                                                        self.finality.read().last_finalized_number(),
                                                    );
                                                }

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
                                        let peers = network.peer_count().await;
                                        if peers == 0 {
                                            sync_requested = false;
                                            sync_request_nonce = None;
                                            production_readiness.refresh(
                                                peers,
                                                sync_requested,
                                                self.head_number(),
                                                std::time::Instant::now(),
                                            );
                                            sync_retry_attempts_without_progress = 0;
                                            sync_retry_timer.reset_after(Duration::from_secs(
                                                SYNC_RETRY_BASE_INTERVAL_SECS,
                                            ));
                                            continue;
                                        }
                                        let nonce = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_nanos() as u64;
                                        let req = NetworkMessage::BlockRequest {
                                            start_number: last_ok + 1,
                                            count: 1, // 1 block at a time — PQ-signed blocks can be several MB
                                            nonce,
                                        };
                                        let _ = network.send_to_peer(&peer, req).await;
                                        sync_requested = true;
                                        sync_request_nonce = Some(nonce);
                                        if response_matches_sync {
                                            production_readiness.note_sync_requested(
                                                self.head_number(),
                                                std::time::Instant::now(),
                                                catch_up_timeout,
                                                "block-response-next-batch",
                                            );
                                        } else {
                                            production_readiness.note_head_probe(
                                                self.head_number(),
                                                std::time::Instant::now(),
                                                startup_sync_grace,
                                                "block-response-next-batch",
                                            );
                                        }
                                        sync_retry_attempts_without_progress = 0;
                                        sync_retry_timer.reset_after(Duration::from_secs(
                                            SYNC_RETRY_BASE_INTERVAL_SECS,
                                        ));
                                    } else {
                                        // No blocks were imported (e.g. gap-rejected by a
                                        // broadcast response intended for another peer). Only a
                                        // response to our current sync request proves this request
                                        // is exhausted; unrelated broadcast responses must not
                                        // clear the gate.
                                        if response_matches_sync {
                                            sync_request_nonce = None;
                                            if production_readiness.state()
                                                == ProductionReadinessState::CatchingUp
                                            {
                                                sync_requested = true;
                                                production_readiness.refresh(
                                                    network.peer_count().await,
                                                    sync_requested,
                                                    self.head_number(),
                                                    std::time::Instant::now(),
                                                );
                                                sync_retry_attempts_without_progress = 0;
                                            } else {
                                                sync_requested = false;
                                                production_readiness.note_sync_idle();
                                                sync_retry_attempts_without_progress = 0;
                                            }
                                        }
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
                                    let mut amendment = match shell_stark_prover::ProofAmendment::from_json(&payload) {
                                        Ok(amendment) => amendment,
                                        Err(e) => {
                                            warn!(block = block_number, "invalid proof amendment payload: {e}");
                                            continue;
                                        }
                                    };
                                    if amendment.block_hash != block_hash {
                                        warn!(
                                            block = block_number,
                                            envelope_hash = %block_hash,
                                            payload_hash = %amendment.block_hash,
                                            "proof amendment envelope hash does not match payload"
                                        );
                                        continue;
                                    }
                                    let covered_hashes = amendment.covered_hashes();
                                    let original_size = match amendment.original_size {
                                        Some(size) => Some(size),
                                        None => {
                                            let mut total = 0u64;
                                            let mut complete = true;
                                            for hash in &covered_hashes {
                                                match self.witness_store.bundle_size(hash) {
                                                    Ok(Some(size)) => {
                                                        total = total.saturating_add(size);
                                                    }
                                                    Ok(None) => {
                                                        complete = false;
                                                        debug!(
                                                            block = block_number,
                                                            %hash,
                                                            "STARK source witness already absent; cannot prove compression from local source size"
                                                        );
                                                        break;
                                                    }
                                                    Err(e) => {
                                                        complete = false;
                                                        warn!(block = block_number, %hash, "failed to read witness size for compression accounting: {e}");
                                                        break;
                                                    }
                                                }
                                            }
                                            complete.then_some(total)
                                        }
                                    };
                                    let compression_valid = original_size
                                        .map(|size| amendment.is_compression_valid_for(size))
                                        .unwrap_or(false);
                                    if !compression_valid {
                                        warn!(
                                            block = block_number,
                                            layer = amendment.layer,
                                            source_count = covered_hashes.len(),
                                            proof_size = amendment.size_bytes(),
                                            original_size = original_size.unwrap_or_default(),
                                            "STARK proof did not meet strict <50% compression threshold; witness retained and reward ineligible"
                                        );
                                        continue;
                                    }
                                    let already_settled = {
                                        let settled = self.settled_stark_sources.lock();
                                        amendment.covered_hashes().into_iter().any(|source| {
                                            settled.contains(&(amendment.layer, source))
                                        })
                                    };
                                    if already_settled {
                                        debug!(
                                            block = block_number,
                                            source = %amendment.block_hash,
                                            layer = amendment.layer,
                                            "STARK proof already settled; ignoring duplicate amendment"
                                        );
                                        continue;
                                    }
                                    if amendment.original_size.is_none() {
                                        amendment.original_size = original_size;
                                    }
                                     if amendment.start_block.is_none() {
                                          amendment.start_block = amendment.range_start_block();
                                      }
                                      if amendment.compressed_size.is_none() {
                                          amendment.compressed_size =
                                              Some(amendment.size_bytes() as u64);
                                      }
                                     if let Err(e) = self.validate_stark_amendment_ordering(&amendment) {
                                         warn!(
                                             block = block_number,
                                             layer = amendment.layer,
                                             "STARK proof rejected by ordered compression frontier: {e}"
                                         );
                                         continue;
                                     }
                                    match self.store_stark_artifacts(&amendment, None) {
                                        Ok(stored) => {
                                            info!(
                                                block = block_number,
                                                layer = amendment.layer,
                                                stored,
                                                "G5: proof amendment artifacts stored from peer {peer}"
                                            );
                                        }
                                        Err(e) => {
                                            warn!(%peer, block = block_number, "failed to store proof amendment artifacts: {e}");
                                            continue;
                                        }
                                    }
                                    self.pending_stark_settlements.lock().push(amendment.clone());
                                    // L2: delete covered witness bundles once proof is secured, unless grace window is active.
                                    let grace = self.config.pruning.proof_replacement_grace;
                                    let head = self.chain_store.get_head_block()
                                        .ok().flatten().map(|b| b.header.number).unwrap_or(0);
                                    for hash in covered_hashes {
                                        if grace == 0 || head.saturating_sub(block_number) >= grace {
                                            match self.chain_store.delete_witness_bundle(&hash) {
                                                Ok(()) => info!(block = block_number, %hash, "L2: witness bundle deleted after proof replacement"),
                                                Err(e) => warn!(block = block_number, %hash, "L2: failed to delete witness bundle: {e}"),
                                            }
                                        } else {
                                            // Schedule deletion: delete once head reaches block_number + grace.
                                            let delete_at = block_number.saturating_add(grace);
                                            self.pending_grace_deletes.lock().insert(hash, delete_at);
                                            debug!(block = block_number, %hash, grace, head, delete_at, "L2: proof stored, within grace window — deletion scheduled");
                                        }
                                    }
                                }
                                // G5: Acknowledge that a peer has stored a proof amendment.
                                NetworkMessage::ProofAck { block_hash, holder } => {
                                    debug!(%peer, ?holder, "received ProofAck for block {}", block_hash);
                                }
                                // I1: Received equivocation evidence from a peer.
                                // Independently verify and log; slashing is deferred until
                                // the proposer-schedule epoch-boundary design is complete,
                                // to prevent mid-chain validator-set corruption causing
                                // cascading false-equivocation (wPoA stability fix).
                                NetworkMessage::EquivocationEvidence(equivocation) => {
                                    if equivocation.verify() {
                                        warn!(
                                            offender = %equivocation.offender,
                                            block_number = equivocation.header_a.number,
                                            "I1: equivocation evidence verified (slashing deferred — epoch-boundary not implemented)"
                                        );
                                        // TODO: apply slash_authority only at epoch boundary
                                        // once ValidatorSet epoch transitions are in place.
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
                                        if self.config.node_role.runs_prover() {
                                            let resp = ChallengeResponse {
                                                block_hash: challenge.block_hash,
                                                proof_bytes,
                                                responder: local_signer_address,
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
                                // W.5: Receive a wPoA vote from a peer validator.
                                NetworkMessage::WPoaVote { block_hash, block_number, voter, signature } => {
                                    debug!(%peer, block = block_number, %voter, "W.5: received WPoaVote");
                                    self.handle_wpoa_vote(voter, block_hash, block_number, signature);
                                    // PS.2: after every vote, flush scored-below-threshold peers to ban list.
                                    self.flush_scorer_bans();
                                }
                                // W.5: Receive a wPoA view-change vote from a peer validator.
                                NetworkMessage::WPoaViewChange { new_view, block_number, voter } => {
                                    debug!(%peer, new_view, block = block_number, %voter, "W.5: received WPoaViewChange");
                                    self.handle_wpoa_view_change(voter, new_view, block_number);
                                }
                            }
                        }
                        Some(NetworkEvent::PeerConnected(peer)) => {
                            info!(%peer, "peer connected");
                            // L4: re-advertise storage capability so newly connected peer knows.
                            {
                                let profile = StorageProfile::from_pruning_config(&self.config.pruning);
                                let oldest = self.oldest_available_body_block();
                                let _ = network.broadcast(NetworkMessage::StorageCapability {
                                    profile: profile.as_str().to_string(),
                                    oldest_body_block: oldest,
                                }).await;
                            }
                            if !sync_requested {
                                sync_retry_attempts_without_progress = 0;
                                sync_retry_timer.reset_after(Duration::from_secs(
                                    SYNC_RETRY_BASE_INTERVAL_SECS,
                                ));
                                self.request_missing_blocks(
                                    network,
                                    Some(&peer),
                                    &mut sync_requested,
                                    &mut sync_request_nonce,
                                    "peer-connected",
                                )
                                .await;
                                production_readiness.note_head_probe(
                                    self.head_number(),
                                    std::time::Instant::now(),
                                    startup_sync_grace,
                                    "peer-connected",
                                );
                            } else {
                                debug!(
                                    head = self.head_number(),
                                    "peer connected while sync request is already in flight"
                                );
                            }
                            self.rebroadcast_pending_transactions(
                                network,
                                Some(&peer),
                                MAX_TX_REBROADCAST_PER_TICK,
                                "peer-connected",
                            )
                            .await;
                        }
                        Some(NetworkEvent::PeerDisconnected(peer)) => {
                            info!(%peer, "peer disconnected");
                            self.peer_caps.remove(&peer);
                            if network.peer_count().await == 0 {
                                sync_requested = false;
                                sync_request_nonce = None;
                                sync_retry_attempts_without_progress = 0;
                                production_readiness.refresh(
                                    0,
                                    sync_requested,
                                    self.head_number(),
                                    std::time::Instant::now(),
                                );
                                sync_retry_timer.reset_after(Duration::from_secs(
                                    SYNC_RETRY_BASE_INTERVAL_SECS,
                                ));
                            }
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
                                    None,
                                    &mut sync_requested,
                                    &mut sync_request_nonce,
                                    "routing-update",
                                )
                                .await;
                                production_readiness.note_head_probe(
                                    self.head_number(),
                                    std::time::Instant::now(),
                                    startup_sync_grace,
                                    "routing-update",
                                );
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

                _ = tx_rebroadcast_timer.tick() => {
                    if network.peer_count().await > 0 && !self.tx_pool.is_empty() {
                        self.rebroadcast_pending_transactions(
                            network,
                            None,
                            MAX_TX_REBROADCAST_PER_TICK,
                            "periodic",
                        )
                        .await;
                    }
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
                    let peers = network.peer_count().await;
                    if sync_requested {
                        if peers == 0 {
                            warn!(
                                head = self.head_number(),
                                "sync requested but no peers are connected; clearing sync gate to prevent production deadlock"
                            );
                            sync_requested = false;
                            sync_request_nonce = None;
                            sync_retry_attempts_without_progress = 0;
                            production_readiness.refresh(
                                peers,
                                sync_requested,
                                self.head_number(),
                                std::time::Instant::now(),
                            );
                            sync_retry_timer.reset_after(Duration::from_secs(
                                SYNC_RETRY_BASE_INTERVAL_SECS,
                            ));
                            continue;
                        }
                        self.request_missing_blocks(
                            network,
                            None,
                            &mut sync_requested,
                            &mut sync_request_nonce,
                            "sync-retry",
                        )
                        .await;
                        sync_retry_attempts_without_progress =
                            sync_retry_attempts_without_progress.saturating_add(1);
                        if sync_retry_attempts_without_progress >= SYNC_RETRY_BACKOFF_THRESHOLD {
                            production_readiness.refresh(
                                peers,
                                sync_requested,
                                self.head_number(),
                                std::time::Instant::now(),
                            );
                        }
                        sync_retry_timer.reset_after(Duration::from_secs(
                            Self::sync_retry_delay_secs(sync_retry_attempts_without_progress),
                        ));
                    } else if peers > 0 {
                        // NewBlock gossip is best-effort. If a node misses the producer's
                        // announcement and no later block creates an explicit gap, it would
                        // otherwise stay stale until a reconnect/routing event. Periodically
                        // ask peers for head+1 as a cheap head probe; an empty response clears
                        // the sync request without moving readiness out of Ready.
                        self.request_missing_blocks(
                            network,
                            None,
                            &mut sync_requested,
                            &mut sync_request_nonce,
                            "periodic-head-probe",
                        )
                        .await;
                        production_readiness.note_head_probe(
                            self.head_number(),
                            std::time::Instant::now(),
                            startup_sync_grace,
                            "periodic-head-probe",
                        );
                        sync_retry_attempts_without_progress = 0;
                        sync_retry_timer.reset_after(Duration::from_secs(
                            SYNC_RETRY_BASE_INTERVAL_SECS,
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

    pub(crate) fn rebuild_settled_stark_sources_from_chain(&self) -> Result<usize, NodeError> {
        // Fast path: load from the persistent index if it has been populated.
        let index_entries = self.settled_source_index.all_entries()?;
        if !index_entries.is_empty() {
            let mut settled = self.settled_stark_sources.lock();
            settled.clear();
            let count = index_entries.len();
            let l1_count = index_entries.iter().filter(|(l, _)| *l == 1).count() as i64;
            settled.extend(index_entries);
            let head = self
                .chain_store
                .get_head_block()?
                .map(|block| block.number())
                .unwrap_or(0);
            let lag = (head as i64 + 1).saturating_sub(l1_count).max(0);
            self.metrics.stark_frontier_lag.set(lag);
            return Ok(count);
        }

        // Slow path: rebuild by scanning every block (first run / index missing).
        // Backfill the index as we go so subsequent restarts use the fast path.
        let head = self
            .chain_store
            .get_head_block()?
            .map(|block| block.number())
            .unwrap_or(0);
        let mut rebuilt = 0usize;
        let mut settled = self.settled_stark_sources.lock();
        settled.clear();
        for number in 0..=head {
            let Some(block) = self.chain_store.get_block_by_number(number)? else {
                continue;
            };
            let legacy = Self::decode_system_extra(&block.header.extra_data)?;
            let tx_settlements = block
                .system_transactions
                .iter()
                .filter(|tx| tx.kind == SystemTxKind::StarkReward)
                .filter_map(|tx| {
                    let payload = tx.proof_payload.as_ref()?;
                    let amendment = ProofAmendment::from_json(payload.as_ref()).ok()?;
                    Some((amendment, Some(tx.hash())))
                });
            for (amendment, settlement_tx_hash) in legacy
                .into_iter()
                .map(|amendment| (amendment, None))
                .chain(tx_settlements)
            {
                self.store_stark_artifacts(&amendment, settlement_tx_hash)?;
                for source in amendment.covered_hashes() {
                    if settled.insert((amendment.layer, source)) {
                        let _ = self.settled_source_index.put(amendment.layer, &source);
                        rebuilt += 1;
                    }
                }
            }
        }
        let l1_count = settled.iter().filter(|(l, _)| *l == 1).count() as i64;
        let lag = (head as i64 + 1).saturating_sub(l1_count).max(0);
        self.metrics.stark_frontier_lag.set(lag);
        Ok(rebuilt)
    }

    pub(crate) fn enqueue_stark_frontier_backlog(
        &self,
        max_blocks: usize,
    ) -> Result<usize, NodeError> {
        if max_blocks == 0 || !self.config.node_role.runs_prover() {
            return Ok(0);
        }
        if !self.pending_stark_settlements.lock().is_empty() {
            return Ok(0);
        }
        let head = self
            .chain_store
            .get_head_block()?
            .map(|block| block.number())
            .unwrap_or(0);
        let mut queued = 0usize;
        let mut tasks = Vec::new();
        for number in 0..=head {
            if queued >= max_blocks {
                break;
            }
            let Some(hash) = self.chain_store.get_block_hash_by_number(number)? else {
                continue;
            };
            if self.settled_stark_sources.lock().contains(&(1, hash)) {
                continue;
            }
            if self
                .pending_stark_settlements
                .lock()
                .iter()
                .any(|amendment| {
                    amendment.layer == 1
                        && amendment
                            .covered_hashes()
                            .into_iter()
                            .any(|source| source == hash)
                })
            {
                continue;
            }
            if self.proof_backlog.lock().contains_source(1, &hash) {
                continue;
            }
            if let Some(bytes) = self.amendment_store.get_amendment(&hash)? {
                if let Ok(amendment) = ProofAmendment::from_json(&bytes) {
                    if self.validate_stark_amendment_ordering(&amendment).is_ok() {
                        let covered = amendment.covered_hashes().len().max(1);
                        self.pending_stark_settlements.lock().push(amendment);
                        queued = queued.saturating_add(covered);
                        continue;
                    }
                }
            }
            if !self.is_stark_compression_source(&hash, &std::collections::HashMap::new())? {
                continue;
            }
            let Some(block) = self.chain_store.get_block_by_hash(&hash)? else {
                continue;
            };
            let entries: Vec<SigBatchEntry> = block
                .transactions
                .iter()
                .map(|tx| {
                    let mut msg_hash = [0u8; 32];
                    msg_hash.copy_from_slice(tx.hash().as_bytes());
                    let pk_hash = match &tx.pubkey_mode {
                        shell_core::PubkeyMode::Embedded(pk) => {
                            let mut h = [0u8; 32];
                            let copy_len = pk.len().min(32);
                            h[..copy_len].copy_from_slice(&pk[..copy_len]);
                            h
                        }
                        shell_core::PubkeyMode::Reference => {
                            let mut h = [0u8; 32];
                            h[..20].copy_from_slice(tx.from.0.as_slice());
                            h
                        }
                    };
                    SigBatchEntry { msg_hash, pk_hash }
                })
                .collect();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            let original_size = self.stark_source_original_size(&hash, &block, entries.len())?;
            tasks.push(ProofTask::with_sources(
                hash_bytes,
                number,
                entries,
                1,
                vec![hash],
                original_size,
            ));
            queued += 1;
        }
        if !tasks.is_empty() {
            let mut backlog = self.proof_backlog.lock();
            // Guard against starvation: if the backlog already contains tasks at a
            // LOWER block number than what we're about to push_front, adding our tasks
            // would displace the actual frontier and cause the prover to loop over
            // already-cached ranges while the true frontier is never reached.
            // Skip this seeding pass — the frontier blocks will be processed on the
            // next prover iteration, and we'll re-seed on the following call.
            let first_new_block = tasks[0].block_number;
            let min_existing = backlog.min_block_number_for_layer(tasks[0].layer);
            if min_existing.map_or(true, |min| first_new_block <= min) {
                for task in tasks.into_iter().rev() {
                    if !task
                        .source_hashes
                        .iter()
                        .any(|source| backlog.contains_source(task.layer, source))
                    {
                        backlog.push_front(task);
                    }
                }
            }
        }
        Ok(queued)
    }

    fn wall_clock_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn block_time_elapsed(parent_timestamp: u64, now_secs: u64, block_time_ms: u64) -> bool {
        let interval_secs = block_time_ms
            .saturating_add(999)
            .saturating_div(1_000)
            .max(1);
        now_secs >= parent_timestamp.saturating_add(interval_secs)
    }
}

#[cfg(test)]
mod cadence_tests {
    use super::*;
    use shell_storage::MemoryDb;

    #[test]
    fn block_time_elapsed_requires_global_parent_timestamp_gap() {
        assert!(!Node::<MemoryDb>::block_time_elapsed(1_000, 1_001, 2_000));
        assert!(Node::<MemoryDb>::block_time_elapsed(1_000, 1_002, 2_000));
    }

    #[test]
    fn block_time_elapsed_rounds_subsecond_config_up() {
        assert!(!Node::<MemoryDb>::block_time_elapsed(1_000, 1_000, 500));
        assert!(Node::<MemoryDb>::block_time_elapsed(1_000, 1_001, 500));
    }

    #[test]
    fn block_time_elapsed_gates_heartbeat_from_parent_timestamp() {
        assert!(!Node::<MemoryDb>::block_time_elapsed(1_000, 1_599, 600_000));
        assert!(Node::<MemoryDb>::block_time_elapsed(1_000, 1_600, 600_000));
    }
}
