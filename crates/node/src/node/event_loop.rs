use super::*;

const MAX_BLOCK_SYNC_RESPONSE_BLOCKS: usize = 128;
const FORK_ADOPTION_RETRY_BASE_SECS: u64 = 5;
const FORK_ADOPTION_RETRY_MAX_SECS: u64 = 30;

#[derive(Debug, Default)]
struct ForkAdoptionRetry {
    preferred_head: Option<ShellHash>,
    attempts: u32,
    retry_at: Option<std::time::Instant>,
}

impl ForkAdoptionRetry {
    fn permits(&mut self, preferred_head: ShellHash, now: std::time::Instant) -> bool {
        if self.preferred_head != Some(preferred_head) {
            self.preferred_head = Some(preferred_head);
            self.attempts = 0;
            self.retry_at = None;
            return true;
        }
        self.retry_at.is_none_or(|retry_at| now >= retry_at)
    }

    fn record_failure(
        &mut self,
        preferred_head: ShellHash,
        now: std::time::Instant,
    ) -> std::time::Duration {
        if self.preferred_head != Some(preferred_head) {
            self.preferred_head = Some(preferred_head);
            self.attempts = 0;
        }
        self.attempts = self.attempts.saturating_add(1);
        let exponent = self.attempts.saturating_sub(1).min(3);
        let seconds = FORK_ADOPTION_RETRY_BASE_SECS
            .saturating_mul(1u64 << exponent)
            .min(FORK_ADOPTION_RETRY_MAX_SECS);
        let delay = std::time::Duration::from_secs(seconds);
        self.retry_at = Some(now + delay);
        delay
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

fn block_response_import_allowed(block_count: usize, commit_certificate_count: usize) -> bool {
    block_count <= MAX_BLOCK_SYNC_RESPONSE_BLOCKS && commit_certificate_count <= block_count
}

fn block_response_matches_request(
    sync_requested: bool,
    expected_nonce: Option<u64>,
    expected_start: Option<u64>,
    nonce: u64,
    first_block_number: Option<u64>,
) -> bool {
    sync_requested
        && expected_nonce == Some(nonce)
        && expected_start.is_some_and(|start| first_block_number.is_none_or(|first| first == start))
}

fn matching_empty_block_response_exhausts_request(
    response_matches_sync: bool,
    response_is_empty: bool,
) -> bool {
    response_matches_sync && response_is_empty
}

fn body_response_import_allowed(block_count: usize) -> bool {
    block_count > 0 && block_count <= crate::historical_sync::BODY_BACKFILL_BATCH_SIZE as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyRequestState {
    nonce: u64,
    start_number: u64,
}

fn body_response_matches_request(
    expected: Option<BodyRequestState>,
    nonce: u64,
    first_block_number: Option<u64>,
) -> bool {
    expected.is_some_and(|request| {
        request.nonce == nonce && first_block_number == Some(request.start_number)
    })
}

fn bounded_request_numbers(
    start_number: u64,
    count: u64,
    max_count: u64,
) -> impl Iterator<Item = u64> {
    (0..count.min(max_count)).filter_map(move |offset| start_number.checked_add(offset))
}

fn next_block_sync_request_start(last_imported: u64) -> Option<u64> {
    last_imported.checked_add(1)
}

fn proof_amendment_envelope_matches(
    envelope_hash: ShellHash,
    envelope_block: u64,
    payload_hash: ShellHash,
    payload_block: u64,
) -> bool {
    envelope_hash == payload_hash && envelope_block == payload_block
}

fn decode_challenge_response_amendment(
    response_hash: ShellHash,
    payload: &[u8],
) -> Result<ProofAmendment, String> {
    let amendment = ProofAmendment::from_json(payload)
        .map_err(|error| format!("invalid proof amendment payload: {error}"))?;
    if amendment.block_hash != response_hash {
        return Err(format!(
            "challenge response hash {response_hash} does not match amendment target {}",
            amendment.block_hash
        ));
    }
    Ok(amendment)
}

struct NodeTaskLifecycle {
    tasks: tokio::task::JoinSet<()>,
    prover_service: Option<ProverServiceHandle>,
}

impl NodeTaskLifecycle {
    fn new() -> Self {
        Self {
            tasks: tokio::task::JoinSet::new(),
            prover_service: None,
        }
    }

    fn spawn<F>(&mut self, task: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(task);
    }

    fn attach_prover_service(&mut self, handle: ProverServiceHandle) {
        self.prover_service = Some(handle);
    }

    async fn shutdown(mut self) {
        if let Some(prover_service) = self.prover_service.take() {
            prover_service.shutdown().await;
        }

        self.tasks.abort_all();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(err) = result {
                if !err.is_cancelled() {
                    warn!(error = %err, "background task exited unexpectedly");
                }
            }
        }
    }
}

impl<S: KvStore + 'static> Node<S> {
    fn track_open_challenge(
        &self,
        challenge_id: ShellHash,
        block_number: u64,
        challenger: Address,
    ) {
        let prover = self
            .amendment_store
            .get_amendment(&challenge_id)
            .ok()
            .flatten()
            .and_then(|bytes| {
                ProofAmendment::from_json(&bytes)
                    .ok()
                    .map(|amendment| amendment.prover)
            })
            .or_else(|| {
                self.chain_store
                    .get_block_by_hash(&challenge_id)
                    .ok()
                    .flatten()
                    .map(|block| block.header.proposer)
            })
            .or_else(|| {
                self.chain_store
                    .get_block_by_number(block_number)
                    .ok()
                    .flatten()
                    .map(|block| block.header.proposer)
            })
            .unwrap_or(Address::ZERO);
        let inserted = self
            .challenge_lifecycle
            .lock()
            .open_challenge(ChallengeRecord {
                challenge_id,
                prover,
                challenger,
                opened_at_block: self.head_number(),
                status: ChallengeStatus::Open,
            });
        if !inserted {
            debug!(
                %challenge_id,
                "challenge already tracked or lifecycle capacity reached; ignoring duplicate"
            );
        }
    }

    fn resolve_open_challenge(&self, challenge_id: &ShellHash) {
        let _ = self
            .challenge_lifecycle
            .lock()
            .resolve_challenge(challenge_id);
    }

    fn slash_timed_out_challenges(&self, block_number: u64) {
        let slashed = self.challenge_lifecycle.lock().check_timeouts(block_number);
        for record in slashed {
            if record.prover == Address::ZERO {
                warn!(
                    challenge_id = %record.challenge_id,
                    challenger = %record.challenger,
                    opened_at_block = record.opened_at_block,
                    current_block = block_number,
                    timeout_blocks = CHALLENGE_TIMEOUT_BLOCKS,
                    "challenge timed out but prover is unknown; skipping slash"
                );
                continue;
            }
            warn!(
                challenge_id = %record.challenge_id,
                prover = %record.prover,
                challenger = %record.challenger,
                opened_at_block = record.opened_at_block,
                current_block = block_number,
                timeout_blocks = CHALLENGE_TIMEOUT_BLOCKS,
                "challenge timed out; slashing prover"
            );
            self.consensus.write().slash_authority(&record.prover);
        }
    }

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
        let mut network = NetworkInterface::new(network);
        let local_signer_address =
            Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let mut task_lifecycle = NodeTaskLifecycle::new();

        // Spawn the Prometheus metrics HTTP server if enabled.
        if self.config.metrics.enabled {
            let metrics = Arc::clone(&self.metrics);
            let metrics_addr = self.config.metrics.listen_addr;
            task_lifecycle.spawn(crate::metrics::serve_metrics(metrics, metrics_addr));
        }

        // Create a bounded channel for the RPC layer to forward submitted transactions
        // to the network broadcast loop. A capacity of 4096 provides ample buffering for
        // burst submissions while bounding memory growth under sustained RPC spam.
        let (tx_broadcast_tx, mut tx_broadcast_rx) =
            tokio::sync::mpsc::channel::<SignedTransaction>(4096);

        // Create a broadcast channel for block events (eth_subscribe).
        // Capacity 256 provides ample buffering to reduce subscriber lag.
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
        // Recover persisted finalized_number from ChainStore on restart,
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

        if self.config.rpc_enabled {
            self.config
                .rpc
                .validate_dev_rpc_exposure()
                .map_err(NodeError::Startup)?;
        }

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

        let rpc_handle = if self.config.rpc_enabled {
            Some(
                start_rpc_server(
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
                            profile: StorageProfile::from_pruning_config(p)
                                .whitepaper_name()
                                .to_string(),
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
                .map_err(|e| NodeError::Startup(format!("RPC: {e}")))?,
            )
        } else {
            None
        };

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
        let mut fork_adoption_retry = ForkAdoptionRetry::default();
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
        let mut sync_request_start: Option<u64> = None;
        let mut body_request: Option<BodyRequestState> = None;
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
            let _ = self
                .request_missing_blocks(
                    &network,
                    None,
                    &mut sync_requested,
                    &mut sync_request_nonce,
                    &mut sync_request_start,
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

        let (prover_amendment_tx, mut prover_amendment_rx) =
            tokio::sync::mpsc::channel(PROVER_AMENDMENT_CHANNEL_CAPACITY);
        let (prover_readiness_tx, prover_readiness_rx) = tokio::sync::watch::channel(false);

        // H3: Start background prover service if this node is configured to run proving.
        if self.config.node_role.runs_prover() {
            let prover_address = self.config.proposer_address.unwrap_or(local_signer_address);
            let prover_config = ProverConfig::default();
            let service = ProverService::new(
                Arc::clone(&self.proof_backlog),
                self.amendment_store.clone(),
                prover_config,
                prover_address,
            )
            .with_signer(Arc::clone(&signer))
            .with_amendment_sender(prover_amendment_tx)
            .with_readiness(prover_readiness_rx)
            .with_l2_mode(self.config.l2_stark_mode);
            let handle = service.start();
            task_lifecycle.attach_prover_service(handle);
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
                    let nonce = Self::wall_clock_millis();
                    if network
                        .broadcast(NetworkMessage::BodyRequest {
                            start_number: 0,
                            count: crate::historical_sync::BODY_BACKFILL_BATCH_SIZE,
                            nonce,
                        })
                        .await
                        .is_ok()
                    {
                        body_request = Some(BodyRequestState {
                            nonce,
                            start_number: 0,
                        });
                        info!(
                            oldest_available = oldest,
                            head, "L4: kicked historical body back-fill startup scan"
                        );
                    }
                }
            }
        }

        loop {
            let prover_ready = production_readiness.can_produce();
            self.prover_ready
                .store(prover_ready, std::sync::atomic::Ordering::Release);
            let _ = prover_readiness_tx.send_if_modified(|ready| {
                if *ready == prover_ready {
                    false
                } else {
                    *ready = prover_ready;
                    true
                }
            });
            self.metrics.syncing.set(i64::from(
                sync_requested && !production_readiness.can_produce(),
            ));
            self.metrics
                .production_ready
                .set(i64::from(production_readiness.can_produce()));
            self.metrics
                .stark_pending_settlements
                .set(self.pending_stark_settlements.lock().len() as i64);

            tokio::select! {
                Some(amendment) = prover_amendment_rx.recv(),
                    if production_readiness.can_produce()
                        && self.pending_stark_settlements.lock().len()
                            < MAX_PENDING_STARK_SETTLEMENTS => {
                    self.proof_backlog
                        .lock()
                        .complete_in_flight(amendment.layer, &amendment.covered_hashes());
                    if amendment.layer > 1 {
                        self.metrics.stark_l2_proofs_generated.inc();
                    } else {
                        self.metrics.stark_proofs_generated.inc();
                    }
                    if let Err(e) = self.validate_stark_amendment_ordering(&amendment) {
                        warn!(
                            block = amendment.block_number,
                            layer = amendment.layer,
                            "local STARK proof ordering check failed; discarding stored amendment: {e}"
                        );
                        // Delete all stored artifacts for this proof range so the source
                        // blocks are re-seeded as fresh tasks once the frontier catches up.
                        // Without this deletion, the next seed pass re-loads the failing
                        // amendment, creates new backlog tasks for the same tip range, the
                        // prover regenerates the same out-of-order proof, and the rejection
                        // counter spins indefinitely.
                        for source_hash in amendment.covered_hashes() {
                            if let Err(del_err) =
                                self.amendment_store.delete_amendment(&source_hash)
                            {
                                warn!(
                                    block = amendment.block_number,
                                    %source_hash,
                                    "failed to delete out-of-order amendment artifact: {del_err}"
                                );
                            }
                        }
                        continue;
                    }
                    self.pending_stark_settlements.lock().push(amendment.clone());
                    info!(
                        block = amendment.block_number,
                        layer = amendment.layer,
                        can_produce_blocks,
                        "local STARK proof queued for bounded settlement"
                    );
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
                    let peers = network.peer_count().await;
                    production_readiness.refresh(
                        peers,
                        sync_requested,
                        self.head_number(),
                        std::time::Instant::now(),
                    );
                    // Periodically reseed the STARK backlog so the prover is never
                    // starved of historical tasks.  Reseed when:
                    //   a) the backlog is completely empty, OR
                    //   b) the front of the backlog has a contiguous run whose total
                    //      entries fall below the proving threshold (prover consumed
                    //      most of the previously-seeded window; needs more history).
                    if self.config.node_role.runs_prover()
                        && production_readiness.can_produce()
                        && self.pending_stark_settlements.lock().len()
                            < MAX_PENDING_STARK_SETTLEMENTS
                    {
                        let needs_reseed = {
                            let backlog = self.proof_backlog.lock();
                            if backlog.is_empty() {
                                true
                            } else {
                                // If the contiguous front run has fewer entries than
                                // the minimum, the prover is stalled — seed more.
                                matches!(
                                    backlog.diagnose_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS),
                                    Some((entries, _, _)) if entries < MIN_L1_STARK_TXS
                                )
                            }
                        };
                        if needs_reseed {
                            if let Err(e) = self.enqueue_stark_frontier_backlog(DEFAULT_MAX_L1_RANGE_SOURCES) {
                                warn!("failed to reseed STARK backlog on timer: {e}");
                            }
                        }
                    }
                    if can_produce_blocks {
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
                        match self.preferred_fork_plan() {
                            Ok(Some(plan)) => {
                                let preferred_head = plan.preferred_hash;
                                let adoption_attempted_at = std::time::Instant::now();
                                if !fork_adoption_retry
                                    .permits(preferred_head, adoption_attempted_at)
                                {
                                    continue;
                                }
                                match self.adopt_preferred_fork(plan) {
                                    Ok(()) => fork_adoption_retry.reset(),
                                    Err(error) => {
                                        if let NodeError::InvalidFork {
                                            block_hash,
                                            reason,
                                        } = &error
                                        {
                                            if self
                                                .fork_choice
                                                .write()
                                                .remove_subtree(block_hash)
                                            {
                                                fork_adoption_retry.reset();
                                                tracing::error!(
                                                    rejected_block = %block_hash,
                                                    %reason,
                                                    "removed terminally invalid preferred-fork subtree"
                                                );
                                                continue;
                                            }
                                        }
                                        let retry_delay = fork_adoption_retry.record_failure(
                                            preferred_head,
                                            adoption_attempted_at,
                                        );
                                        tracing::error!(
                                            %error,
                                            retry_after_secs = retry_delay.as_secs(),
                                            "block production paused because preferred-fork adoption failed"
                                        );
                                    }
                                }
                                continue;
                            }
                            Ok(None) => fork_adoption_retry.reset(),
                            Err(error) => {
                                let preferred_head = *self.fork_choice.read().head();
                                let adoption_attempted_at = std::time::Instant::now();
                                if !fork_adoption_retry
                                    .permits(preferred_head, adoption_attempted_at)
                                {
                                    continue;
                                }
                                let retry_delay = fork_adoption_retry.record_failure(
                                    preferred_head,
                                    adoption_attempted_at,
                                );
                                tracing::error!(
                                    %error,
                                    retry_after_secs = retry_delay.as_secs(),
                                    "block production paused because preferred-fork planning failed"
                                );
                                continue;
                            }
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
                                            self.consensus.write().set_authorities(v.clone());

                                            // §5.4 offline-slash enforcement: at each epoch
                                            // boundary, detect validators that haven't proposed
                                            // for `offline_window_blocks` and slash them.
                                            let slash_config = SlashingConfig::default();
                                            let last_by = self.last_proposed_by.lock().clone();
                                            for addr in &v {
                                                let last = last_by
                                                    .get(addr)
                                                    .copied()
                                                    .unwrap_or(0);
                                                if let Some(record) = detect_offline(
                                                    addr,
                                                    last,
                                                    number,
                                                    &slash_config,
                                                ) {
                                                    warn!(
                                                        validator = %record.validator,
                                                        last_block = last,
                                                        current_block = number,
                                                        "offline-slash: validator has not proposed \
                                                         since block #{last}; slashing"
                                                    );
                                                    self.consensus
                                                        .write()
                                                        .slash_authority(&record.validator);
                                                }
                                            }
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
                                self.slash_timed_out_challenges(number);
                                self.consensus
                                    .write()
                                    .note_block_progress(Self::wall_clock_millis());
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
                                            if let Some(certificate) = self.handle_wpoa_vote(
                                                voter,
                                                block_hash,
                                                number,
                                                pq_sig,
                                            ) {
                                                let _ = network
                                                    .broadcast(NetworkMessage::CommitCertificate {
                                                        block_hash,
                                                        block_number: number,
                                                        certificate,
                                                    })
                                                    .await;
                                            }
                                            // Push WPoA-advanced finality to the RPC layer.
                                            let fin = self.finality.read().last_finalized_number();
                                            let mut fn_w = finalized_number.write();
                                            if fin > *fn_w { *fn_w = fin; }
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

                    // W.5: If the proposer fails to produce within the timeout,
                    // broadcast a signed view-change vote for the current height.
                    if self.consensus.read().engine_type() == EngineType::WPoA && can_produce_blocks {
                        let now_ms = Self::wall_clock_millis();
                        let timed_out = self
                            .consensus
                            .read()
                            .check_view_change_timeout(now_ms, self.config.block_time_ms);
                        if timed_out {
                            let validator = self
                                .config
                                .proposer_address
                                .expect("validated block producer has proposer address");
                            if self.local_validator_weight().is_none() {
                                debug!(
                                    %validator,
                                    "W.5: proposer timeout observed but local validator is not in the active validator set; skipping view change"
                                );
                                continue;
                            }
                            let view = self.consensus.read().current_view();
                            let block_number =
                                match ChainStateMachine::next_block_number(self.head_number()) {
                                    Ok(block_number) => block_number,
                                    Err(e) => {
                                        warn!("W.5: cannot broadcast view-change message: {e}");
                                        continue;
                                    }
                                };
                            let chain_id = self.config.chain_id;
                            let highest_qc_hash = *self.finality.read().last_finalized_hash();
                            let signing_message = ViewChangeMessage::signing_message(
                                chain_id,
                                block_number,
                                view,
                                &highest_qc_hash,
                            );
                            match signer.sign(&signing_message) {
                                Ok(signature) => {
                                    let msg = ViewChangeMessage::new(
                                        chain_id,
                                        block_number,
                                        view,
                                        highest_qc_hash,
                                        validator,
                                        signature.data,
                                    );
                                    let total_weight: u64 = self
                                        .consensus
                                        .read()
                                        .validator_weights()
                                        .values()
                                        .copied()
                                        .sum();
                                    let quorum = self
                                        .consensus
                                        .write()
                                        .handle_view_change_message(msg.clone(), total_weight);
                                    warn!(
                                        view,
                                        block_number,
                                        timeout_ms = VIEW_CHANGE_TIMEOUT_MS,
                                        quorum,
                                        "W.5: proposer timeout — broadcasting view change"
                                    );
                                    let _ = network
                                        .broadcast(NetworkMessage::WPoaViewChange(Box::new(msg)))
                                        .await;
                                }
                                Err(error) => {
                                    warn!(%error, view, block_number, "W.5: failed to sign view change");
                                }
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
                                            self.consensus
                                                .write()
                                                .note_block_progress(Self::wall_clock_millis());
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
                                                sync_request_start = None;
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
                                            self.slash_timed_out_challenges(imported_number);

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
                                                        if let Some(certificate) = self.handle_wpoa_vote(
                                                            voter,
                                                            saved_hash,
                                                            imported_number,
                                                            pq_sig,
                                                        ) {
                                                            let _ = network
                                                                .broadcast(NetworkMessage::CommitCertificate {
                                                                    block_hash: saved_hash,
                                                                    block_number: imported_number,
                                                                    certificate,
                                                                })
                                                                .await;
                                                        }
                                                        // Push WPoA-advanced finality to the RPC layer.
                                                        let fin = self.finality.read().last_finalized_number();
                                                        let mut fn_w = finalized_number.write();
                                                        if fin > *fn_w { *fn_w = fin; }
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
                                                if self.request_missing_blocks(
                                                    &network,
                                                    Some(&peer),
                                                    &mut sync_requested,
                                                    &mut sync_request_nonce,
                                                    &mut sync_request_start,
                                                    "gap-detected",
                                                )
                                                .await
                                                {
                                                    production_readiness.note_sync_requested(
                                                        self.head_number(),
                                                        std::time::Instant::now(),
                                                        catch_up_timeout,
                                                        "gap-detected",
                                                    );
                                                }
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
                                            // high-frequency under load; suppress them to keep
                                            // logs quiet during normal operation.
                                            // handle_incoming_tx() wraps mempool errors as
                                            // NodeError::Startup(<kind_str>) — match directly
                                            // to avoid a heap allocation and any risk of
                                            // account-state values reaching the log sink.
                                            if let NodeError::Startup(kind) = &e {
                                                if kind != "duplicate"
                                                    && kind != "nonce_gap"
                                                    && kind != "nonce_too_low"
                                                {
                                                    warn!(kind = kind.as_str(), "mempool rejection");
                                                }
                                            } else {
                                                warn!(error = %e, "incoming tx error");
                                            }
                                        }
                                    }
                                }
                                NetworkMessage::BlockRequest { start_number, count, nonce } => {
                                    let safe_count =
                                        count.min(MAX_BLOCK_SYNC_RESPONSE_BLOCKS as u64);
                                    debug!(
                                        %peer,
                                        start_number,
                                        count,
                                        safe_count,
                                        "received BlockRequest"
                                    );
                                    let mut blocks = Vec::new();
                                    for n in bounded_request_numbers(
                                        start_number,
                                        safe_count,
                                        MAX_BLOCK_SYNC_RESPONSE_BLOCKS as u64,
                                    ) {
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
                                    let first_block_number =
                                        blocks.first().map(|block| block.header.number);
                                    if !block_response_matches_request(
                                        sync_requested,
                                        sync_request_nonce,
                                        sync_request_start,
                                        nonce,
                                        first_block_number,
                                    ) {
                                        warn!(
                                            %peer,
                                            nonce,
                                            "dropping unsolicited, stale, or misaligned BlockResponse"
                                        );
                                        continue;
                                    }
                                    if !block_response_import_allowed(
                                        blocks.len(),
                                        commit_certificates.len(),
                                    ) {
                                        warn!(
                                            %peer,
                                            count = blocks.len(),
                                            commit_certificates = commit_certificates.len(),
                                            max_blocks = MAX_BLOCK_SYNC_RESPONSE_BLOCKS,
                                            "dropping oversized BlockResponse"
                                        );
                                        continue;
                                    }
                                    info!(
                                        count = blocks.len(),
                                        nonce,
                                        "received BlockResponse, importing blocks"
                                    );
                                    let response_matches_sync = sync_request_nonce == Some(nonce);
                                    let response_is_empty = blocks.is_empty();
                                    let verifier = MultiVerifier;
                                    let mut last_ok: Option<u64> = None;
                                    let certs: HashMap<ShellHash, Vec<u8>> =
                                        commit_certificates.into_iter().collect();
                                    for block in blocks {
                                        let num = block.number();
                                        let hdr = block.header.clone();
                                        let bhash = block.hash();
                                        let head_before_import = self.head_number();
                                        let verified_certificate = certs.get(&bhash).filter(|cert| {
                                            self.verify_commit_certificate(num, bhash, cert)
                                        });
                                        let import_result = tokio::task::block_in_place(|| {
                                            if verified_certificate.is_some() {
                                                self.import_finalized_block(block, &verifier)
                                            } else {
                                                self.import_block(block, &verifier)
                                            }
                                        });
                                        match import_result {
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
                                                last_ok = Some(num);
                                                production_readiness.note_import_progress(num);
                                                self.metrics.blocks_imported.inc();
                                                self.metrics.block_height.set(num as i64);
                                                self.metrics.update_finality(
                                                    num,
                                                    self.finality.read().last_finalized_number(),
                                                );
                                                debug!(number = num, "synced block");
                                                self.slash_timed_out_challenges(num);
                                                if let Some(cert) = verified_certificate {
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
                                    if let Some(last_ok) = last_ok {
                                        let peers = network.peer_count().await;
                                        if peers == 0 {
                                            sync_requested = false;
                                            sync_request_nonce = None;
                                            sync_request_start = None;
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
                                        let Some(next_start) =
                                            next_block_sync_request_start(last_ok)
                                        else {
                                            sync_requested = false;
                                            sync_request_nonce = None;
                                            sync_request_start = None;
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
                                        };
                                        let nonce = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_nanos() as u64;
                                        let req = NetworkMessage::BlockRequest {
                                            start_number: next_start,
                                            count: 1, // 1 block at a time — PQ-signed blocks can be several MB
                                            nonce,
                                        };
                                        let _ = network.send_to_peer(&peer, req).await;
                                        sync_requested = true;
                                        sync_request_nonce = Some(nonce);
                                        sync_request_start = Some(next_start);
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
                                        if matching_empty_block_response_exhausts_request(
                                            response_matches_sync,
                                            response_is_empty,
                                        ) {
                                            sync_request_nonce = None;
                                            sync_request_start = None;
                                            sync_requested = false;
                                            production_readiness.note_sync_idle();
                                            sync_retry_attempts_without_progress = 0;
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
                                    if !proof_amendment_envelope_matches(
                                        block_hash,
                                        block_number,
                                        amendment.block_hash,
                                        amendment.block_number,
                                    ) {
                                        warn!(
                                            envelope_block = block_number,
                                            envelope_hash = %block_hash,
                                            payload_block = amendment.block_number,
                                            payload_hash = %amendment.block_hash,
                                            "proof amendment envelope does not match signed payload"
                                        );
                                        continue;
                                    }
                                    if self.pending_stark_settlements.lock().len()
                                        >= MAX_PENDING_STARK_SETTLEMENTS
                                    {
                                        self.metrics.stark_amendments_rate_limited.inc();
                                        debug!(
                                            %peer,
                                            block = block_number,
                                            "STARK proof deferred because settlement window is full"
                                        );
                                        continue;
                                    }
                                    if let Err(e) = self.validate_stark_amendment_authentication(&amendment) {
                                        warn!(
                                            block = block_number,
                                            layer = amendment.layer,
                                            "STARK proof rejected by prover authentication: {e}"
                                        );
                                        continue;
                                    }
                                    if !self
                                        .proof_rate_limiter
                                        .lock()
                                        .try_consume(&amendment.prover)
                                    {
                                        self.metrics.stark_amendments_rate_limited.inc();
                                        warn!(
                                            %peer,
                                            prover = %amendment.prover,
                                            block = block_number,
                                            "STARK proof rejected by per-prover rate limit"
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
                                        covered_hashes.iter().any(|source| {
                                            settled.contains(&(amendment.layer, *source))
                                        })
                                    };
                                    // Also check the pending queue to prevent duplicate settlements
                                    // from concurrent proof-amendment messages for the same sources.
                                    let pending_dup = if !already_settled {
                                        // Build a set once for O(1) membership checks against
                                        // each queued entry's covered_hashes (avoids O(n²) scans).
                                        let covered_set: std::collections::HashSet<_> =
                                            covered_hashes.iter().copied().collect();
                                        let pending = self.pending_stark_settlements.lock();
                                        pending.iter().any(|queued| {
                                            queued.layer == amendment.layer
                                                && queued
                                                    .covered_hashes()
                                                    .iter()
                                                    .any(|s| covered_set.contains(s))
                                        })
                                    } else {
                                        false
                                    };
                                    if already_settled || pending_dup {
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
                                     if let Err(e) = self.validate_stark_proof_source_binding(&amendment) {
                                         warn!(
                                             block = block_number,
                                             layer = amendment.layer,
                                             "STARK proof rejected by proof-source binding check: {e}"
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
                                    self.pending_stark_settlements.lock().push(amendment);
                                }
                                // G5: Acknowledge that a peer has stored a proof amendment.
                                NetworkMessage::ProofAck { block_hash, holder } => {
                                    debug!(%peer, ?holder, "received ProofAck for block {}", block_hash);
                                }
                                // I1: Received signed equivocation evidence from a peer.
                                // Slashing requires both conflicting proposer seals to verify
                                // against the offender's registered public key.
                                NetworkMessage::EquivocationEvidence(equivocation) => {
                                    let offender_pubkey = self
                                        .known_authorities
                                        .read()
                                        .get(&equivocation.offender)
                                        .cloned()
                                        .or_else(|| {
                                            self.chain_store
                                                .get_pubkey(&equivocation.offender)
                                                .ok()
                                                .flatten()
                                        });
                                    let Some(pubkey) = offender_pubkey else {
                                        warn!(
                                            %peer,
                                            offender = %equivocation.offender,
                                            "I1: received equivocation evidence for unknown offender pubkey, ignoring"
                                        );
                                        continue;
                                    };
                                    let verifier = MultiVerifier;
                                    if !equivocation.verify_signed(&pubkey, &verifier) {
                                        warn!(
                                            %peer,
                                            offender = %equivocation.offender,
                                            "I1: received invalid signed equivocation evidence, ignoring"
                                        );
                                        continue;
                                    }
                                    warn!(
                                        offender = %equivocation.offender,
                                        block_number = equivocation.header_a.number,
                                        "I1: signed equivocation evidence verified, applying slash"
                                    );
                                    self.consensus.write().slash_authority(&equivocation.offender);
                                }
                                // I2: Received a proof challenge from a peer.
                                // If we hold the proof, respond with raw bytes.
                                NetworkMessage::ProofChallenge(challenge) => {
                                    debug!(%peer, block = challenge.block_number, reason = %challenge.reason, "I2: received ProofChallenge");
                                    self.track_open_challenge(
                                        challenge.block_hash,
                                        challenge.block_number,
                                        challenge.challenger,
                                    );
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
                                    let amendment = match decode_challenge_response_amendment(
                                        resp.block_hash,
                                        &resp.proof_bytes,
                                    ) {
                                        Ok(amendment) => amendment,
                                        Err(error) => {
                                            warn!(%peer, %error, "I2: challenge response malformed");
                                            continue;
                                        }
                                    };
                                    if let Err(error) = self.validate_stark_amendment_ordering(&amendment) {
                                        warn!(%peer, %error, "I2: challenge response ordering validation failed");
                                        continue;
                                    }
                                    if let Err(error) = self.validate_stark_proof_source_binding(&amendment) {
                                        warn!(%peer, %error, "I2: challenge response proof verification failed");
                                        continue;
                                    }
                                    if let Err(error) = self.store_stark_artifacts(&amendment, None) {
                                        warn!(%peer, %error, "I2: failed to store verified challenge response");
                                        continue;
                                    }
                                    self.resolve_open_challenge(&resp.block_hash);
                                    info!(block = %resp.block_hash, "I2: challenge response verified and stored");
                                }
                                // L4: Peer announces its storage capability.
                                NetworkMessage::StorageCapability { profile, oldest_body_block } => {
                                    debug!(%peer, profile, oldest_body_block, "L4: received StorageCapability");
                                    self.peer_caps.record(peer.clone(), profile, oldest_body_block);
                                }
                                // L4: Peer requests block bodies for historical back-fill.
                                NetworkMessage::BodyRequest { start_number, count, nonce } => {
                                    debug!(%peer, start_number, count, "L4: received BodyRequest");
                                    let mut blocks = Vec::new();
                                    for n in bounded_request_numbers(
                                        start_number,
                                        count,
                                        crate::historical_sync::BODY_BACKFILL_BATCH_SIZE,
                                    ) {
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
                                                NetworkMessage::BodyResponse { blocks, nonce },
                                            )
                                            // Note: send_to_peer falls back to broadcast if the
                                            // transport does not support unicast addressing.
                                            .await;
                                    }
                                }
                                // L4: Receive block bodies from a peer as historical back-fill.
                                NetworkMessage::BodyResponse { blocks, nonce } => {
                                    let first_block_number =
                                        blocks.first().map(|block| block.header.number);
                                    if !body_response_matches_request(
                                        body_request,
                                        nonce,
                                        first_block_number,
                                    ) {
                                        warn!(
                                            %peer,
                                            nonce,
                                            "L4: dropping unsolicited, stale, or misaligned BodyResponse"
                                        );
                                        continue;
                                    }
                                    if !body_response_import_allowed(blocks.len()) {
                                        warn!(
                                            %peer,
                                            count = blocks.len(),
                                            max_blocks = crate::historical_sync::BODY_BACKFILL_BATCH_SIZE,
                                            "L4: dropping invalid BodyResponse size"
                                        );
                                        continue;
                                    }
                                    body_request = None;
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
                                    let mut expected_next = batch_start;
                                    for block in &blocks {
                                        let n = block.header.number;
                                        track_body_response_sequence(
                                            &mut expected_next,
                                            &mut first_gap,
                                            n,
                                        );
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
                                    // If the entire batch was bad, skip it when there is room.
                                    let next_start = body_backfill_next_start(
                                        first_gap,
                                        last_stored,
                                        batch_start,
                                    );
                                    if let Some(next) = next_start {
                                        if next <= head_number {
                                            // More blocks needed — request next batch.
                                            let next_nonce = Self::wall_clock_millis()
                                                .max(nonce.saturating_add(1));
                                            if network
                                                .send_to_peer(
                                                    &peer,
                                                    NetworkMessage::BodyRequest {
                                                        start_number: next,
                                                        count: crate::historical_sync::BODY_BACKFILL_BATCH_SIZE,
                                                        nonce: next_nonce,
                                                    },
                                                )
                                                .await
                                                .is_ok()
                                            {
                                                body_request = Some(BodyRequestState {
                                                    nonce: next_nonce,
                                                    start_number: next,
                                                });
                                            }
                                        } else {
                                            info!("L4: historical body back-fill complete");
                                        }
                                    }
                                }
                                // W.5: Receive a wPoA vote from a peer validator.
                                NetworkMessage::WPoaVote { block_hash, block_number, voter, signature } => {
                                    debug!(%peer, block = block_number, %voter, "W.5: received WPoaVote");
                                    if let Some(certificate) = self.handle_wpoa_vote(
                                        voter,
                                        block_hash,
                                        block_number,
                                        signature,
                                    ) {
                                        let _ = network
                                            .broadcast(NetworkMessage::CommitCertificate {
                                                block_hash,
                                                block_number,
                                                certificate,
                                            })
                                            .await;
                                    }
                                    // Push WPoA-advanced finality to the RPC layer.
                                    let fin = self.finality.read().last_finalized_number();
                                    let mut fn_w = finalized_number.write();
                                    if fin > *fn_w { *fn_w = fin; }
                                    // PS.2: after every vote, flush scored-below-threshold peers to ban list.
                                    self.flush_scorer_bans();
                                }
                                NetworkMessage::CommitCertificate {
                                    block_hash,
                                    block_number,
                                    certificate,
                                } => {
                                    debug!(%peer, block = block_number, %block_hash, "FF.7: received commit certificate");
                                    if self.fast_finalize_with_certificate(
                                        block_number,
                                        block_hash,
                                        &certificate,
                                    ) {
                                        let fin = self.finality.read().last_finalized_number();
                                        let mut fn_w = finalized_number.write();
                                        if fin > *fn_w {
                                            *fn_w = fin;
                                        }
                                    }
                                }
                                // W.5: Receive a signed wPoA view-change vote from a peer validator.
                                NetworkMessage::WPoaViewChange(view_change) => {
                                    debug!(
                                        %peer,
                                        view = view_change.view,
                                        block = view_change.block_number,
                                        validator = %view_change.validator,
                                        "W.5: received WPoaViewChange"
                                    );
                                    let verifier = MultiVerifier;
                                    match self.handle_wpoa_view_change(*view_change, &verifier) {
                                        Ok(quorum) if quorum => {
                                            info!("W.5: view-change quorum reached; proposer rotated");
                                        }
                                        Ok(_) => {}
                                        Err(error) => {
                                            warn!(%error, %peer, "W.5: rejected view-change message");
                                        }
                                    }
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
                                if self.request_missing_blocks(
                                    &network,
                                    Some(&peer),
                                    &mut sync_requested,
                                    &mut sync_request_nonce,
                                    &mut sync_request_start,
                                    "peer-connected",
                                )
                                .await
                                {
                                    production_readiness.note_head_probe(
                                        self.head_number(),
                                        std::time::Instant::now(),
                                        startup_sync_grace,
                                        "peer-connected",
                                    );
                                }
                            } else {
                                debug!(
                                    head = self.head_number(),
                                    "peer connected while sync request is already in flight"
                                );
                            }
                            self.rebroadcast_pending_transactions(
                                &network,
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
                                sync_request_start = None;
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
                                if self.request_missing_blocks(
                                    &network,
                                    None,
                                    &mut sync_requested,
                                    &mut sync_request_nonce,
                                    &mut sync_request_start,
                                    "routing-update",
                                )
                                .await
                                {
                                    production_readiness.note_head_probe(
                                        self.head_number(),
                                        std::time::Instant::now(),
                                        startup_sync_grace,
                                        "routing-update",
                                    );
                                }
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
                            &network,
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
                            sync_request_start = None;
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
                        let request_sent = self.request_missing_blocks(
                            &network,
                            None,
                            &mut sync_requested,
                            &mut sync_request_nonce,
                            &mut sync_request_start,
                            "sync-retry",
                        )
                        .await;
                        if request_sent {
                            sync_retry_attempts_without_progress =
                                sync_retry_attempts_without_progress.saturating_add(1);
                        } else {
                            sync_retry_attempts_without_progress = 0;
                        }
                        if !request_sent
                            || sync_retry_attempts_without_progress
                                >= SYNC_RETRY_BACKOFF_THRESHOLD
                        {
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
                        let _ = self.request_missing_blocks(
                            &network,
                            None,
                            &mut sync_requested,
                            &mut sync_request_nonce,
                            &mut sync_request_start,
                            "periodic-head-probe",
                        )
                        .await;
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
        if let Some(rpc_handle) = rpc_handle {
            rpc_handle.http_handle.stop().ok();
            if let Some(ws) = rpc_handle.ws_handle {
                ws.stop().ok();
            }
            eprintln!("✓ RPC server stopped");
        }

        task_lifecycle.shutdown().await;

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
        // Always do a canonical scan so the persistent index cannot diverge from
        // the canonical chain after a reorg.  We collect all settled sources from
        // canonical StarkReward system-txs first, then reconcile the durable
        // `ss/` index by removing stale entries and back-filling missing ones.
        let head = self
            .chain_store
            .get_head_block()?
            .map(|block| block.number())
            .unwrap_or(0);

        // ── Step 1: build the canonical settled set from chain ────────────────
        let mut canonical: std::collections::HashSet<(u32, ShellHash)> =
            std::collections::HashSet::new();
        // Track L1 final source hashes for l2i/ reconcile (one per L1 amendment).
        let mut canonical_l1_finals: std::collections::HashSet<ShellHash> =
            std::collections::HashSet::new();
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
                    canonical.insert((amendment.layer, source));
                }
                // Collect L1 final source hashes for l2i/ reconcile.
                if amendment.layer == 1 {
                    canonical_l1_finals.insert(amendment.block_hash);
                }
            }
        }

        // ── Step 2: reconcile the persistent `ss/` index ─────────────────────
        // Remove stale entries that no longer exist on the canonical chain.
        let index_entries = self.settled_source_index.all_entries()?;
        let mut removed = 0usize;
        for (layer, hash) in &index_entries {
            if !canonical.contains(&(*layer, *hash)) {
                if let Err(e) = self.settled_source_index.delete(*layer, hash) {
                    warn!("rebuild_settled: failed to delete stale index entry ({layer}, {hash}): {e}");
                } else {
                    removed += 1;
                }
            }
        }

        // Add missing canonical entries to the index.
        let index_set: std::collections::HashSet<(u32, ShellHash)> =
            index_entries.into_iter().collect();
        for (layer, hash) in &canonical {
            if !index_set.contains(&(*layer, *hash)) {
                let _ = self.settled_source_index.put(*layer, hash);
            }
        }

        if !self.config.l2_stark_mode.is_enabled() {
            self.metrics.stark_l2_blocked_gap_start.set(0);
            self.metrics.stark_l2_last_trigger_block.set(0);
            self.metrics.stark_l2_pending_inputs.set(0);
            self.metrics.stark_l2_ready_jobs.set(0);
        } else {
            // ── Step 2b: reconcile the `l2i/` L2 input index ─────────────────────
            // Mirrors Step 2 but tracks final-source hashes of L1 amendments.
            let l2i_entries = self.l2_input_index.all_hashes()?;
            let mut l2i_removed = 0usize;
            for hash in &l2i_entries {
                if !canonical_l1_finals.contains(hash) {
                    if let Err(e) = self.l2_input_index.delete(hash) {
                        warn!("rebuild_settled: failed to delete stale l2i/ entry ({hash}): {e}");
                    } else {
                        l2i_removed += 1;
                    }
                }
            }
            let l2i_set: std::collections::HashSet<ShellHash> = l2i_entries.into_iter().collect();
            for hash in &canonical_l1_finals {
                if !l2i_set.contains(hash) {
                    let _ = self.l2_input_index.put(hash);
                }
            }
            if l2i_removed > 0 {
                info!(
                    "rebuild_settled: removed {l2i_removed} stale `l2i/` index entries after reorg"
                );
            }

            // ── Step 2c: reconcile the `l2j/` L2 job store ───────────────────────
            // Any L2 job whose source L1 hashes were orphaned by a reorg must be
            // reset to PendingInputs so it can re-accumulate canonical inputs rather
            // than attempting to prove with stale/phantom L1 roots.
            let all_l2_jobs = self.l2_job_store.all_jobs()?;
            let mut l2j_reset = 0usize;
            for job in &all_l2_jobs {
                // PendingInputs and FailedPermanent don't need to be touched.
                if matches!(
                    job.status,
                    L2JobStatus::PendingInputs | L2JobStatus::FailedPermanent
                ) {
                    continue;
                }
                let sources_canonical = job
                    .l1_source_hashes
                    .iter()
                    .all(|h| canonical_l1_finals.contains(h));
                if !sources_canonical {
                    // One or more source L1 amendments were orphaned — reset the job.
                    let updated = L2AggregationJob {
                        status: L2JobStatus::PendingInputs,
                        retry_count: job.retry_count,
                        last_error: Some(
                            "reset after reorg: source L1 amendment(s) no longer canonical".into(),
                        ),
                        updated_at_block: head,
                        ..job.clone()
                    };
                    if let Err(e) = self.l2_job_store.put(&updated) {
                        warn!("rebuild_settled: failed to reset L2 job {}: {e}", job.id);
                    } else {
                        l2j_reset += 1;
                    }
                }
            }
            if l2j_reset > 0 {
                warn!("rebuild_settled: reset {l2j_reset} L2 jobs to PendingInputs after reorg");
            }

            // ── Step 2d: update L2 observability metrics ─────────────────────────
            {
                let pending_inputs = all_l2_jobs
                    .iter()
                    .filter(|j| matches!(j.status, L2JobStatus::PendingInputs))
                    .count() as i64;
                let ready_jobs = all_l2_jobs
                    .iter()
                    .filter(|j| matches!(j.status, L2JobStatus::Ready))
                    .count() as i64;
                self.metrics.stark_l2_pending_inputs.set(pending_inputs);
                self.metrics.stark_l2_ready_jobs.set(ready_jobs);
            }
        }

        // ── Step 3: update the in-memory settled set ──────────────────────────
        let count = canonical.len();
        let mut settled = self.settled_stark_sources.lock();
        settled.clear();
        settled.extend(canonical);
        drop(settled);

        self.settled_stark_frontiers.lock().clear();
        let empty_overlay = std::collections::HashMap::new();
        for layer in 1..=3 {
            let frontier = self.first_canonical_block_below_layer(layer, &empty_overlay)?;
            self.settled_stark_frontiers.lock().insert(layer, frontier);
        }

        let l1_frontier = self
            .settled_stark_frontiers
            .lock()
            .get(&1)
            .copied()
            .unwrap_or(0) as i64;
        let lag = (head as i64 + 1).saturating_sub(l1_frontier).max(0);
        self.metrics.stark_frontier_lag.set(lag);

        if removed > 0 {
            info!("rebuild_settled: removed {removed} stale `ss/` index entries after reorg");
        }
        Ok(count)
    }

    pub(crate) fn enqueue_stark_frontier_backlog(
        &self,
        max_blocks: usize,
    ) -> Result<usize, NodeError> {
        if max_blocks == 0 || !self.config.node_role.runs_prover() {
            return Ok(0);
        }
        if self.pending_stark_settlements.lock().len() >= MAX_PENDING_STARK_SETTLEMENTS {
            return Ok(0);
        }
        // Note: we intentionally do NOT skip when pending_stark_settlements is
        // non-empty.  The inner loop already skips blocks that are covered by a
        // pending settlement, so the early-return here would incorrectly prevent
        // seeding frontier blocks that come *after* the already-proved range.
        let head = self
            .chain_store
            .get_head_block()?
            .map(|block| block.number())
            .unwrap_or(0);
        let mut queued = 0usize;
        // `pending_covered_sum` tracks blocks contributed to `queued` by old
        // amendments pushed to `pending_stark_settlements`. Used to recompute
        // `queued` after tasks.retain() removes covered source blocks.
        let mut pending_covered_sum = 0usize;
        let mut tasks = Vec::new();
        let mut rejected_stored_payloads = std::collections::HashSet::new();
        // Scan past max_blocks until the backlog contains enough source entries
        // to satisfy the L1 minimum (MIN_L1_STARK_TXS). Without this, a chain
        // with a long 0-tx prefix (e.g. pre-tx-worker genesis) would seed only
        // empty blocks and the prover would produce a proof with too few entries
        // (e.g. 2 < 512), which passes local storage but fails settlement
        // validation (n_sigs and embedded-compression checks).
        // Hard cap = 4 × max_blocks (at least DEFAULT_MAX_L1_RANGE_SOURCES × 4)
        // to bound startup cost.
        let hard_cap = max_blocks
            .saturating_mul(4)
            .max(DEFAULT_MAX_L1_RANGE_SOURCES * 4);
        let mut seeded_entries = 0usize;

        let pending_overlay = {
            let pending = self.pending_stark_settlements.lock();
            pending
                .iter()
                .filter(|a| a.layer == 1)
                .flat_map(|amendment| {
                    amendment
                        .covered_hashes()
                        .into_iter()
                        .map(move |hash| (hash, amendment.layer))
                })
                .collect::<std::collections::HashMap<_, _>>()
        };
        let settled_frontier = self
            .settled_stark_frontiers
            .lock()
            .get(&1)
            .copied()
            .unwrap_or(0);
        let contiguous_pending_end = self.first_canonical_block_below_layer(1, &pending_overlay)?;
        let scan_start = contiguous_pending_end.saturating_sub(16);
        info!(
            settled_frontier,
            contiguous_pending_end, scan_start, head, "STARK seeding: scan parameters"
        );

        for number in scan_start..=head {
            if queued >= max_blocks && seeded_entries >= MIN_L1_STARK_TXS {
                break;
            }
            if queued >= hard_cap {
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
                let payload_hash = shell_primitives::blake3_hash(&bytes);
                if rejected_stored_payloads.contains(&payload_hash) {
                    self.amendment_store.delete_amendment(&hash)?;
                } else {
                    match self.load_stored_stark_amendment_for_recovery(hash, number, &bytes) {
                        Ok(amendment) => {
                            let covered_hashes = amendment.covered_hashes();
                            let recovered_is_valid = self
                                .validate_stark_amendment_authentication(&amendment)
                                .and_then(|()| self.validate_stark_amendment_ordering(&amendment))
                                .and_then(|()| {
                                    if amendment.has_valid_embedded_compression() {
                                        Ok(())
                                    } else {
                                        Err(NodeError::Startup(
                                            "stored STARK amendment fails compression policy"
                                                .into(),
                                        ))
                                    }
                                })
                                .and_then(|()| {
                                    self.validate_stark_proof_source_binding(&amendment)
                                });
                            if let Err(error) = recovered_is_valid {
                                self.metrics.stark_settlements_rejected.inc();
                                warn!(
                                    block = amendment.block_number,
                                    layer = amendment.layer,
                                    %error,
                                    "discarding invalid stored STARK amendment during recovery"
                                );
                                rejected_stored_payloads.insert(payload_hash);
                                self.delete_stored_stark_amendment_artifacts(&amendment, hash)?;
                                // Continue with this canonical source so a fresh proof
                                // task replaces the invalid persisted artifact.
                            } else {
                                let covered_count = covered_hashes.len().max(1);
                                let start = amendment.range_start_block().unwrap_or(0);
                                if self.pending_stark_settlements.lock().len()
                                    >= MAX_PENDING_STARK_SETTLEMENTS
                                {
                                    debug!(
                                        block = amendment.block_number,
                                        start_block = start,
                                        "STARK seeding paused at settlement admission limit"
                                    );
                                    break;
                                }
                                info!(
                                    block = amendment.block_number,
                                    start_block = start,
                                    sources = covered_count,
                                    n_sigs = amendment.proof.n_sigs,
                                    "STARK seeding: existing amendment passes ordering; skipping covered range"
                                );
                                // Remove any source blocks already queued in `tasks` that
                                // are covered by this amendment. Without this, the source
                                // blocks inserted before we reach the end block create a
                                // gap in the contiguous backlog run, causing
                                // `pop_contiguous_with_min_entries` to return None.
                                let covered_set: std::collections::HashSet<_> =
                                    covered_hashes.into_iter().collect();
                                tasks.retain(|t: &ProofTask| {
                                    !t.source_hashes.iter().any(|s| covered_set.contains(s))
                                });
                                // Recompute seeded_entries from the retained tasks.
                                seeded_entries = tasks.iter().map(|t| t.entries.len()).sum();
                                // Recompute queued: retained regular tasks + all pending covered blocks.
                                pending_covered_sum =
                                    pending_covered_sum.saturating_add(covered_count);
                                queued = tasks.len().saturating_add(pending_covered_sum);
                                self.pending_stark_settlements.lock().push(amendment);
                                continue;
                            }
                        }
                        Err(error) => {
                            self.metrics.stark_settlements_rejected.inc();
                            warn!(
                                %hash,
                                %error,
                                "discarding malformed stored STARK amendment during recovery"
                            );
                            rejected_stored_payloads.insert(payload_hash);
                            self.amendment_store.delete_amendment(&hash)?;
                        }
                    }
                }
            }
            if !self.is_stark_compression_source(&hash, &std::collections::HashMap::new())? {
                continue;
            }
            let Some(block) = self.chain_store.get_block_by_hash(&hash)? else {
                continue;
            };
            let entries: Vec<SigBatchEntry> = stark_sources::block_to_sig_batch_entries(&block);
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            let original_size = self.stark_source_original_size(&hash, &block, entries.len())?;
            if !entries.is_empty() {
                seeded_entries = seeded_entries.saturating_add(entries.len());
            }
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
            let tasks_count = tasks.len();
            let tasks_entries: usize = tasks.iter().map(|t| t.entries.len()).sum();
            let tasks_first = tasks.first().map(|t| t.block_number).unwrap_or(0);
            let tasks_last = tasks.last().map(|t| t.block_number).unwrap_or(0);
            let mut backlog = self.proof_backlog.lock();
            let layer = tasks[0].layer;
            let min_existing = backlog.min_block_number_for_layer(layer);
            let max_existing = backlog.max_block_number_for_layer(layer);
            info!(
                tasks = tasks_count,
                entries = tasks_entries,
                first_block = tasks_first,
                last_block = tasks_last,
                backlog_min = min_existing,
                backlog_max = max_existing,
                "STARK seeding: inserting tasks into backlog"
            );

            // Insert before any already-queued live tip tasks. A global-tail
            // append test cannot fill a historical hole once tip blocks are in
            // the queue and previously caused the prover to misclassify that
            // recoverable hole as a permanent canonical gap.
            backlog.insert_ordered_batch(tasks);
        }
        Ok(queued)
    }

    fn load_stored_stark_amendment_for_recovery(
        &self,
        source_hash: ShellHash,
        source_block: u64,
        bytes: &[u8],
    ) -> Result<ProofAmendment, NodeError> {
        match StoredProofArtifact::from_json(bytes).map_err(|error| {
            NodeError::Startup(format!("malformed stored STARK artifact: {error}"))
        })? {
            StoredProofArtifact::Amendment(amendment) => {
                if amendment.block_hash != source_hash {
                    return Err(NodeError::Startup(format!(
                        "stored STARK amendment target {} does not match storage key {source_hash}",
                        amendment.block_hash
                    )));
                }
                Ok(amendment)
            }
            StoredProofArtifact::Pointer(pointer) => {
                if pointer.source_hash != source_hash
                    || pointer.source_block != source_block
                    || pointer.start_block > source_block
                    || pointer.end_block < source_block
                    || pointer.end_block != pointer.target_block
                {
                    return Err(NodeError::Startup(
                        "stored STARK proof pointer metadata does not match its canonical source"
                            .into(),
                    ));
                }
                let target_bytes = self
                    .amendment_store
                    .get_amendment(&pointer.target_hash)?
                    .ok_or_else(|| {
                        NodeError::Startup(format!(
                            "stored STARK proof pointer target {} is missing",
                            pointer.target_hash
                        ))
                    })?;
                let StoredProofArtifact::Amendment(amendment) =
                    StoredProofArtifact::from_json(&target_bytes).map_err(|error| {
                        NodeError::Startup(format!(
                            "stored STARK proof pointer target is malformed: {error}"
                        ))
                    })?
                else {
                    return Err(NodeError::Startup(
                        "stored STARK proof pointer target is not a full amendment".into(),
                    ));
                };
                let covered_index = source_block
                    .checked_sub(pointer.start_block)
                    .and_then(|offset| usize::try_from(offset).ok())
                    .ok_or_else(|| {
                        NodeError::Startup("stored STARK proof pointer range overflows".into())
                    })?;
                if amendment.block_hash != pointer.target_hash
                    || amendment.block_number != pointer.target_block
                    || amendment.range_start_block() != Some(pointer.start_block)
                    || amendment.layer != pointer.layer
                    || amendment.settlement_tx_hash != pointer.settlement_tx_hash
                    || amendment.covered_hashes().get(covered_index) != Some(&source_hash)
                {
                    return Err(NodeError::Startup(
                        "stored STARK proof pointer does not match its target amendment".into(),
                    ));
                }
                Ok(amendment)
            }
        }
    }

    pub(crate) fn delete_stored_stark_amendment_artifacts(
        &self,
        amendment: &ProofAmendment,
        stored_key: ShellHash,
    ) -> Result<(), NodeError> {
        self.amendment_store.delete_amendment(&stored_key)?;
        for source_hash in amendment
            .covered_hashes()
            .into_iter()
            .filter(|source_hash| *source_hash != stored_key)
        {
            let Some(bytes) = self.amendment_store.get_amendment(&source_hash)? else {
                continue;
            };
            let belongs_to_amendment = match StoredProofArtifact::from_json(&bytes) {
                Ok(StoredProofArtifact::Amendment(stored)) => {
                    source_hash == amendment.block_hash && stored.block_hash == amendment.block_hash
                }
                Ok(StoredProofArtifact::Pointer(pointer)) => {
                    pointer.source_hash == source_hash
                        && pointer.target_hash == amendment.block_hash
                }
                Err(_) => false,
            };
            if belongs_to_amendment {
                self.amendment_store.delete_amendment(&source_hash)?;
            }
        }
        Ok(())
    }

    fn wall_clock_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
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

fn body_backfill_next_start(
    first_gap: Option<u64>,
    last_stored: Option<u64>,
    batch_start: Option<u64>,
) -> Option<u64> {
    if let Some(gap) = first_gap {
        return Some(gap);
    }
    if let Some(stored) = last_stored {
        return stored.checked_add(1);
    }
    batch_start
        .and_then(|start| start.checked_add(crate::historical_sync::BODY_BACKFILL_BATCH_SIZE))
}

fn track_body_response_sequence(
    expected_next: &mut Option<u64>,
    first_gap: &mut Option<u64>,
    block_number: u64,
) {
    if let Some(expected) = *expected_next {
        if block_number > expected {
            first_gap.get_or_insert(expected);
        }
        if block_number >= expected {
            *expected_next = block_number.checked_add(1);
        }
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

    #[test]
    fn body_backfill_next_start_does_not_wrap_after_max_stored_block() {
        assert_eq!(
            body_backfill_next_start(None, Some(u64::MAX), Some(u64::MAX - 1)),
            None
        );
    }

    #[test]
    fn body_backfill_next_start_does_not_repeat_max_bad_batch() {
        assert_eq!(body_backfill_next_start(None, None, Some(u64::MAX)), None);
    }

    #[test]
    fn body_backfill_next_start_prefers_gap_and_advances_normal_batches() {
        assert_eq!(
            body_backfill_next_start(Some(9), Some(10), Some(1)),
            Some(9)
        );
        assert_eq!(body_backfill_next_start(None, Some(10), Some(1)), Some(11));
        assert_eq!(body_backfill_next_start(None, None, Some(10)), Some(138));
    }

    #[test]
    fn body_response_sequence_tracks_first_omitted_block() {
        let mut expected_next = Some(10);
        let mut first_gap = None;

        track_body_response_sequence(&mut expected_next, &mut first_gap, 10);
        track_body_response_sequence(&mut expected_next, &mut first_gap, 12);
        track_body_response_sequence(&mut expected_next, &mut first_gap, 13);

        assert_eq!(first_gap, Some(11));
        assert_eq!(expected_next, Some(14));
    }

    #[test]
    fn body_response_sequence_does_not_wrap_after_max_block() {
        let mut expected_next = Some(u64::MAX);
        let mut first_gap = None;

        track_body_response_sequence(&mut expected_next, &mut first_gap, u64::MAX);

        assert_eq!(first_gap, None);
        assert_eq!(expected_next, None);
    }

    #[test]
    fn body_response_import_rejects_oversized_responses() {
        assert!(!body_response_import_allowed(0));
        assert!(body_response_import_allowed(1));
        assert!(body_response_import_allowed(
            crate::historical_sync::BODY_BACKFILL_BATCH_SIZE as usize
        ));
        assert!(!body_response_import_allowed(
            crate::historical_sync::BODY_BACKFILL_BATCH_SIZE as usize + 1
        ));
    }

    #[test]
    fn body_response_requires_the_active_request_nonce_and_start() {
        let request = Some(BodyRequestState {
            nonce: 7,
            start_number: 42,
        });

        assert!(body_response_matches_request(request, 7, Some(42)));
        assert!(!body_response_matches_request(None, 7, Some(42)));
        assert!(!body_response_matches_request(request, 8, Some(42)));
        assert!(!body_response_matches_request(request, 7, Some(43)));
        assert!(!body_response_matches_request(request, 7, None));
    }

    #[test]
    fn bounded_request_numbers_includes_terminal_height() {
        let numbers: Vec<_> = bounded_request_numbers(u64::MAX, 4, 128).collect();
        assert_eq!(numbers, vec![u64::MAX]);
    }

    #[test]
    fn bounded_request_numbers_stops_at_height_overflow() {
        let numbers: Vec<_> = bounded_request_numbers(u64::MAX - 1, 4, 128).collect();
        assert_eq!(numbers, vec![u64::MAX - 1, u64::MAX]);
    }

    #[test]
    fn fork_adoption_retry_backs_off_and_caps_delay() {
        let head = ShellHash::from([0x11; 32]);
        let start = std::time::Instant::now();
        let mut retry = ForkAdoptionRetry::default();

        assert!(retry.permits(head, start));
        assert_eq!(
            retry.record_failure(head, start),
            std::time::Duration::from_secs(5)
        );
        assert!(!retry.permits(head, start + std::time::Duration::from_secs(4)));
        assert!(retry.permits(head, start + std::time::Duration::from_secs(5)));

        assert_eq!(
            retry.record_failure(head, start),
            std::time::Duration::from_secs(10)
        );
        assert_eq!(
            retry.record_failure(head, start),
            std::time::Duration::from_secs(20)
        );
        assert_eq!(
            retry.record_failure(head, start),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            retry.record_failure(head, start),
            std::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn fork_adoption_retry_allows_changed_head_immediately() {
        let first_head = ShellHash::from([0x11; 32]);
        let next_head = ShellHash::from([0x22; 32]);
        let start = std::time::Instant::now();
        let mut retry = ForkAdoptionRetry::default();

        retry.record_failure(first_head, start);

        assert!(retry.permits(next_head, start));
        assert_eq!(retry.preferred_head, Some(next_head));
        assert_eq!(retry.attempts, 0);
        assert_eq!(retry.retry_at, None);
    }

    #[test]
    fn bounded_request_numbers_caps_peer_count() {
        let numbers: Vec<_> = bounded_request_numbers(10, 4, 2).collect();
        assert_eq!(numbers, vec![10, 11]);
    }

    #[test]
    fn next_block_sync_request_start_advances_imported_height() {
        assert_eq!(next_block_sync_request_start(0), Some(1));
        assert_eq!(next_block_sync_request_start(41), Some(42));
    }

    #[test]
    fn next_block_sync_request_start_stops_at_terminal_height() {
        assert_eq!(next_block_sync_request_start(u64::MAX), None);
    }

    #[test]
    fn proof_amendment_envelope_binds_hash_and_block_number() {
        let hash = ShellHash::from([0x11; 32]);
        let other_hash = ShellHash::from([0x22; 32]);

        assert!(proof_amendment_envelope_matches(hash, 7, hash, 7));
        assert!(!proof_amendment_envelope_matches(hash, 7, other_hash, 7));
        assert!(!proof_amendment_envelope_matches(hash, 6, hash, 7));
    }

    fn challenge_response_payload(block_hash: ShellHash) -> Vec<u8> {
        ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash,
            block_number: 7,
            start_block: None,
            proof: shell_stark_prover::proof::SigBatchProof::commitment_only([0; 32], 0),
            prover: Address::ZERO,
            prover_signature: Bytes::new(),
            layer: 1,
            source_hashes: Vec::new(),
            original_size: Some(100),
            compressed_size: Some(10),
            settlement_tx_hash: None,
        }
        .to_json()
        .unwrap()
    }

    #[test]
    fn challenge_response_decodes_stored_amendment_payload() {
        let block_hash = ShellHash::from([0x33; 32]);
        let payload = challenge_response_payload(block_hash);

        let amendment = decode_challenge_response_amendment(block_hash, &payload).unwrap();

        assert_eq!(amendment.block_hash, block_hash);
        assert_eq!(amendment.block_number, 7);
    }

    #[test]
    fn challenge_response_rejects_mismatched_amendment_target() {
        let response_hash = ShellHash::from([0x44; 32]);
        let payload = challenge_response_payload(ShellHash::from([0x55; 32]));

        assert!(decode_challenge_response_amendment(response_hash, &payload).is_err());
    }

    #[test]
    fn challenge_response_rejects_bare_sig_batch_proof() {
        let block_hash = ShellHash::from([0x66; 32]);
        let payload = shell_stark_prover::proof::SigBatchProof::commitment_only([0; 32], 0)
            .to_json()
            .unwrap();

        assert!(decode_challenge_response_amendment(block_hash, &payload).is_err());
    }

    #[test]
    fn block_response_import_allows_bounded_responses() {
        assert!(block_response_import_allowed(0, 0));
        assert!(block_response_import_allowed(
            MAX_BLOCK_SYNC_RESPONSE_BLOCKS,
            MAX_BLOCK_SYNC_RESPONSE_BLOCKS
        ));
    }

    #[test]
    fn block_response_import_rejects_oversized_responses() {
        assert!(!block_response_import_allowed(
            MAX_BLOCK_SYNC_RESPONSE_BLOCKS + 1,
            0
        ));
        assert!(!block_response_import_allowed(1, 2));
    }

    #[test]
    fn block_response_requires_the_active_request_nonce_and_start() {
        assert!(block_response_matches_request(
            true,
            Some(7),
            Some(42),
            7,
            Some(42)
        ));
        assert!(block_response_matches_request(
            true,
            Some(7),
            Some(42),
            7,
            None
        ));
        assert!(!block_response_matches_request(
            false,
            Some(7),
            Some(42),
            7,
            Some(42)
        ));
        assert!(!block_response_matches_request(
            true,
            None,
            Some(42),
            7,
            Some(42)
        ));
        assert!(!block_response_matches_request(
            true,
            Some(8),
            Some(42),
            7,
            Some(42)
        ));
        assert!(!block_response_matches_request(
            true,
            Some(7),
            None,
            7,
            Some(42)
        ));
        assert!(!block_response_matches_request(
            true,
            Some(7),
            Some(42),
            7,
            Some(43)
        ));
    }

    #[test]
    fn matching_empty_block_response_exhausts_sync_request() {
        assert!(matching_empty_block_response_exhausts_request(true, true));
        assert!(!matching_empty_block_response_exhausts_request(false, true));
        assert!(!matching_empty_block_response_exhausts_request(true, false));
    }
}
