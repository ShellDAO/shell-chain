use super::*;

const SYSTEM_EXTRA_PREFIX: &[u8] = b"shell:system-extra:v1:";
const BASE_STARK_MINT_WEI: u128 = 100_000_000_000_000_000_000;
const ESTIMATED_DILITHIUM3_SIG_BYTES: u64 = 3_309;
const ESTIMATED_REFERENCE_WITNESS_RLP_OVERHEAD_BYTES: u64 = 8;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SystemExtraEnvelope {
    stark_proofs: Vec<ProofAmendment>,
}

impl<S: KvStore + 'static> Node<S> {
    #[cfg(test)]
    pub(crate) fn encode_system_extra(stark_proofs: &[ProofAmendment]) -> Result<Bytes, NodeError> {
        if stark_proofs.is_empty() {
            return Ok(Bytes::default());
        }
        let envelope = SystemExtraEnvelope {
            stark_proofs: stark_proofs.to_vec(),
        };
        let mut bytes = SYSTEM_EXTRA_PREFIX.to_vec();
        bytes.extend(
            serde_json::to_vec(&envelope)
                .map_err(|e| NodeError::Startup(format!("encode system extra: {e}")))?,
        );
        Ok(Bytes::from(bytes))
    }

    pub(crate) fn decode_system_extra(
        extra_data: &Bytes,
    ) -> Result<Vec<ProofAmendment>, NodeError> {
        if extra_data.is_empty() {
            return Ok(vec![]);
        }
        let bytes = extra_data.as_ref();
        if !bytes.starts_with(SYSTEM_EXTRA_PREFIX) {
            return Ok(vec![]);
        }
        let payload = &bytes[SYSTEM_EXTRA_PREFIX.len()..];
        let envelope: SystemExtraEnvelope = serde_json::from_slice(payload)
            .map_err(|e| NodeError::Startup(format!("decode system extra: {e}")))?;
        Ok(envelope.stark_proofs)
    }

    pub(crate) fn stark_reward_value(
        &self,
        _reward_block_number: u64,
        amendment: &ProofAmendment,
    ) -> Result<U256, NodeError> {
        if !amendment.has_valid_embedded_compression() {
            return Err(NodeError::Startup(
                "STARK reward claim does not satisfy strict compression threshold".into(),
            ));
        }
        if amendment.layer == 1
            && amendment.proof.n_sigs != 0
            && amendment.proof.n_sigs < MIN_L1_STARK_TXS
        {
            return Err(NodeError::Startup(format!(
                "STARK L1 reward claim covers {} tx entries; minimum is {MIN_L1_STARK_TXS}",
                amendment.proof.n_sigs
            )));
        }

        let covered_hashes = amendment.covered_hashes();
        let mut mint = U256::from(BASE_STARK_MINT_WEI);
        for _ in 0..amendment.layer {
            mint /= U256::from(2u8);
        }

        let source_count = if amendment.layer == 1 {
            // For L1 proofs, base mint counts only covered source blocks that have
            // user transactions.  0tx canonical blocks are included in source_hashes
            // for continuity but must not inflate the reward — they contribute no
            // witness entries and earn no base mint multiplier.
            let mut non_empty_count = 0usize;
            for source_hash in &covered_hashes {
                let Some(source_block) = self.chain_store.get_block_by_hash(source_hash)? else {
                    return Err(NodeError::Startup(format!(
                        "STARK reward source block not found: {source_hash}"
                    )));
                };
                if !source_block.transactions.is_empty() {
                    non_empty_count += 1;
                }
            }
            // At least 1 so a qualifying proof (n_sigs >= MIN_L1_STARK_TXS) always
            // earns some base mint even if all tx blocks are covered by a single block.
            non_empty_count.max(1)
        } else {
            // For L2+ proofs, source_hashes are lower-layer proof artifacts, not
            // raw block hashes.  Count all covered sources for the base mint.
            covered_hashes.len().max(1)
        };

        mint = mint.saturating_mul(U256::from(source_count));
        Ok(mint)
    }

    pub(crate) fn build_stark_reward_tx(
        &self,
        block_number: u64,
        tx_index: u32,
        amendment: &ProofAmendment,
    ) -> Result<SystemTransaction, NodeError> {
        let original_size = amendment
            .original_size
            .ok_or_else(|| NodeError::Startup("STARK reward claim missing original_size".into()))?;
        let compressed_size = amendment
            .compressed_size
            .unwrap_or(amendment.size_bytes() as u64);
        Ok(SystemTransaction::stark_reward(
            shell_core::StarkRewardParams {
                chain_id: self.config.chain_id,
                block_number,
                tx_index,
                recipient: amendment.prover,
                value: self.stark_reward_value(block_number, amendment)?,
                source_hash: amendment.block_hash,
                layer: amendment.layer,
                original_size,
                compressed_size,
                proof_payload: Bytes::from(amendment.to_json().map_err(|e| {
                    NodeError::Startup(format!("serialize STARK reward proof payload: {e}"))
                })?),
            },
        ))
    }

    pub(crate) fn stark_source_original_size(
        &self,
        source_hash: &ShellHash,
        source_block: &Block,
        entry_count: usize,
    ) -> Result<Option<u64>, NodeError> {
        if entry_count == 0 {
            return Ok(Some(0));
        }
        // Prefer the canonical witness blob from storage when available.
        if let Some(size) = self.witness_store.bundle_size(source_hash)? {
            return Ok(Some(size));
        }

        // Blocks reconstructed after witness pruning carry stub signatures
        // (empty signature bytes for each tx). Splitting those stubs would
        // fabricate a tiny "witness bundle" and undercount original_size.
        let has_real_witness_material = source_block
            .transactions
            .iter()
            .any(|tx| !tx.signature.data.is_empty());
        if has_real_witness_material {
            let (_, witness_bundle) = shell_core::StrippedBlock::split(source_block);
            if !witness_bundle.is_empty() {
                let witness_bytes = alloy_rlp::encode(&witness_bundle);
                return Ok(Some(witness_bytes.len() as u64));
            }
        }

        // If a full node pruned the raw witness before the prover caught up, the
        // exact bytes are gone. Use a conservative reference-witness estimate so
        // the ordered STARK frontier can still advance instead of wedging forever.
        Ok(Some(
            source_block.transactions.len().max(entry_count) as u64
                * (ESTIMATED_DILITHIUM3_SIG_BYTES + ESTIMATED_REFERENCE_WITNESS_RLP_OVERHEAD_BYTES),
        ))
    }

    /// Cryptographically verify that a [`ProofAmendment`] is bound to the
    /// canonical source entries it claims to cover.
    ///
    /// This is a **separate, more expensive check** from
    /// [`validate_stark_amendment_ordering`].  Call it after ordering passes,
    /// at gossip-receipt and settlement-import time (not for locally-generated
    /// proofs, which are already valid by construction).
    ///
    /// For L1 amendments the check reconstructs every [`SigBatchEntry`] from
    /// the covered source blocks and verifies:
    ///
    /// 1. `proof.n_sigs == entries.len()` — declared entry count matches
    ///    canonical transaction count in the covered range.
    /// 2. `proof.batch_root_bytes == compute_batch_root(entries)` — the
    ///    declared batch root is the true accumulator for those entries.
    /// 3. `verify_sig_batch(&proof)` — the Winterfell STARK proof is valid
    ///    for the declared (batch_root, n_sigs) public inputs.
    ///
    /// For L2 amendments the check:
    ///
    /// 1. Loads each covered source L1 [`ProofAmendment`] from the amendment
    ///    store.
    /// 2. Verifies every source is a settled L1 amendment (`layer == 1`).
    /// 3. Computes `expected_aggregate_root = compute_aggregate_root(l1_roots)`
    ///    and compares to `amendment.proof.batch_root_bytes`.
    /// 4. Verifies `amendment.proof.n_sigs == l1_source_count`.
    /// 5. Attempts recursive proof verification via [`get_recursive_prover()`].
    ///    Until the recursive feature is enabled this returns a clear log that
    ///    verification was skipped rather than silently accepting.
    pub(crate) fn validate_stark_amendment_authentication(
        &self,
        amendment: &ProofAmendment,
    ) -> Result<(), NodeError> {
        amendment.verify_prover_authentication().map_err(|e| {
            NodeError::Startup(format!("STARK amendment prover authentication failed: {e}"))
        })
    }

    pub(crate) fn validate_stark_proof_source_binding(
        &self,
        amendment: &ProofAmendment,
    ) -> Result<(), NodeError> {
        if amendment.layer == 1 {
            return self.validate_l1_proof_source_binding(amendment);
        }
        if amendment.layer == 2 {
            return self.validate_l2_proof_source_binding(amendment);
        }
        // layer > 2: not yet defined — reject rather than silently accept.
        Err(NodeError::Startup(format!(
            "STARK amendment layer {} is not supported (max layer == 2)",
            amendment.layer
        )))
    }

    fn validate_l1_proof_source_binding(
        &self,
        amendment: &ProofAmendment,
    ) -> Result<(), NodeError> {
        // Reconstruct canonical entries from all covered source blocks.
        let covered = amendment.covered_hashes();
        let mut all_entries: Vec<shell_stark_prover::prover::SigBatchEntry> = Vec::new();
        for source_hash in &covered {
            let block = self
                .chain_store
                .get_block_by_hash(source_hash)?
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "STARK proof binding: source block {source_hash} not found"
                    ))
                })?;
            all_entries.extend(stark_sources::block_to_sig_batch_entries(&block));
        }

        // Check 1: declared n_sigs must match the actual canonical entry count.
        if all_entries.len() != amendment.proof.n_sigs {
            self.metrics.stark_settlements_rejected.inc();
            return Err(NodeError::Startup(format!(
                "STARK proof n_sigs {} does not match reconstructed entry count {} \
                 for source range #{}..=#{}",
                amendment.proof.n_sigs,
                all_entries.len(),
                amendment
                    .range_start_block()
                    .unwrap_or(amendment.block_number),
                amendment.block_number,
            )));
        }

        // Check 2: recompute the batch root and compare.
        let expected_root = shell_stark_prover::prover::compute_batch_root(&all_entries);
        if expected_root != amendment.proof.batch_root_bytes {
            self.metrics.stark_settlements_rejected.inc();
            return Err(NodeError::Startup(format!(
                "STARK proof batch_root_bytes mismatch for source range #{}..=#{}",
                amendment
                    .range_start_block()
                    .unwrap_or(amendment.block_number),
                amendment.block_number,
            )));
        }

        // Check 3: full Winterfell STARK verification. Empty source ranges have
        // no signature batch to prove; the canonical entry count and empty root
        // checks above are the complete binding for that case.
        if all_entries.is_empty() {
            if !amendment.proof.proof_bytes.is_empty() {
                self.metrics.stark_settlements_rejected.inc();
                return Err(NodeError::Startup(format!(
                    "empty STARK source range for block #{} must not carry proof bytes",
                    amendment.block_number
                )));
            }
            return Ok(());
        }

        // Check 4: non-empty ranges must carry and verify a full Winterfell
        // proof for the reconstructed public inputs.
        verify_sig_batch(&amendment.proof).map_err(|e| {
            self.metrics.stark_settlements_rejected.inc();
            NodeError::Startup(format!(
                "STARK proof verification failed for block #{}: {e}",
                amendment.block_number
            ))
        })?;

        Ok(())
    }

    fn validate_l2_proof_source_binding(
        &self,
        amendment: &ProofAmendment,
    ) -> Result<(), NodeError> {
        debug_assert_eq!(amendment.layer, 2);

        let covered = amendment.covered_hashes();

        // Load each source L1 amendment and collect batch roots.
        let mut l1_roots: Vec<u128> = Vec::with_capacity(covered.len());
        for source_hash in &covered {
            let bytes = self
                .amendment_store
                .get_amendment(source_hash)?
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "STARK L2 proof binding: source L1 amendment for {source_hash} not found"
                    ))
                })?;
            let source_amendment: ProofAmendment = serde_json::from_slice(&bytes).map_err(|e| {
                NodeError::Startup(format!(
                    "STARK L2 proof binding: failed to deserialise source amendment \
                         for {source_hash}: {e}"
                ))
            })?;

            // Every source must be a settled L1 amendment.
            if source_amendment.layer != 1 {
                self.metrics.stark_settlements_rejected.inc();
                return Err(NodeError::Startup(format!(
                    "STARK L2 amendment source {source_hash} is layer {} (expected L1)",
                    source_amendment.layer
                )));
            }

            // Verify canonical/settled status: the L1 source must have been included
            // in a StarkReward settlement transaction on the canonical chain.
            // This prevents L2 aggregations from referencing orphaned or
            // not-yet-settled L1 proofs.
            if !self
                .settled_stark_sources
                .lock()
                .contains(&(1, *source_hash))
            {
                self.metrics.stark_settlements_rejected.inc();
                return Err(NodeError::Startup(format!(
                    "STARK L2 amendment source {source_hash} is not yet settled on L1 canonical chain"
                )));
            }

            // Extract the L1 batch root lo-half as a u128 for L2 aggregate computation.
            // batch_root_bytes is [lo:16 ‖ hi:16]; the L2 recursive circuit operates on u128.
            let root_bytes = source_amendment.proof.batch_root_bytes;
            let root = u128::from_le_bytes(root_bytes[0..16].try_into().unwrap());
            l1_roots.push(root);
        }

        // Check 1: declared n_sigs (= number of L1 proofs) must match.
        if amendment.proof.n_sigs != l1_roots.len() {
            self.metrics.stark_settlements_rejected.inc();
            return Err(NodeError::Startup(format!(
                "STARK L2 amendment n_sigs {} does not match source L1 proof count {}",
                amendment.proof.n_sigs,
                l1_roots.len()
            )));
        }

        // Check 2: aggregate root must match compute_aggregate_root(l1_roots).
        let expected_agg_root =
            shell_stark_prover::recursive_air::compute_aggregate_root(&l1_roots);
        // batch_root_bytes is [lo:16 ‖ hi:16]; L2 aggregate root lives in the lo half.
        let declared_agg_root =
            u128::from_le_bytes(amendment.proof.batch_root_bytes[0..16].try_into().unwrap());
        if expected_agg_root != declared_agg_root {
            self.metrics.stark_settlements_rejected.inc();
            return Err(NodeError::Startup(format!(
                "STARK L2 amendment aggregate_root mismatch: expected {expected_agg_root}, \
                 got {declared_agg_root}"
            )));
        }

        // Check 3: recursive proof verification.
        // H-1: Both soft-pass paths (decode error, NotImplemented) are now hard
        // errors by default. They are only permitted when compiled with the
        // `stub-l2-verifier` feature, which MUST NOT be enabled in production.
        let pub_inputs = shell_stark_prover::RecursivePublicInputs {
            l1_roots,
            aggregate_root: expected_agg_root,
            start_block: amendment
                .range_start_block()
                .unwrap_or(amendment.block_number),
            end_block: amendment.block_number,
        };
        let prover = shell_stark_prover::get_recursive_prover();
        if let Ok(rec_proof) = serde_json::from_slice::<shell_stark_prover::RecursiveProof>(
            &amendment.proof.proof_bytes,
        ) {
            match prover.verify_aggregation(&rec_proof, &pub_inputs) {
                Ok(()) => {}
                Err(shell_stark_prover::RecursiveProverError::NotImplemented) => {
                    // H-1: recursive verifier not implemented.
                    #[cfg(feature = "stub-l2-verifier")]
                    {
                        tracing::debug!(
                            block_hash = %amendment.block_hash,
                            "STARK L2 recursive proof verifier not active (stub-l2-verifier) — \
                             source-binding checks passed, soft-accepting"
                        );
                    }
                    #[cfg(not(feature = "stub-l2-verifier"))]
                    {
                        self.metrics.stark_settlements_rejected.inc();
                        return Err(NodeError::Startup(format!(
                            "STARK L2 recursive proof verifier is not implemented \
                             (block #{}). Enable feature `stub-l2-verifier` only in \
                             non-production environments to bypass this check.",
                            amendment.block_number
                        )));
                    }
                }
                Err(e) => {
                    self.metrics.stark_settlements_rejected.inc();
                    return Err(NodeError::Startup(format!(
                        "STARK L2 recursive proof verification failed: {e}"
                    )));
                }
            }
        } else {
            // H-1: proof_bytes cannot be decoded as a RecursiveProof — hard error
            // unless the stub-l2-verifier feature is enabled.
            #[cfg(not(feature = "stub-l2-verifier"))]
            {
                self.metrics.stark_settlements_rejected.inc();
                return Err(NodeError::Startup(format!(
                    "STARK L2 proof_bytes for block #{} cannot be decoded as a \
                     RecursiveProof. Enable feature `stub-l2-verifier` only in \
                     non-production environments to bypass this check.",
                    amendment.block_number
                )));
            }
            #[cfg(feature = "stub-l2-verifier")]
            {
                tracing::warn!(
                    block_hash = %amendment.block_hash,
                    "STARK L2 proof_bytes are not a valid RecursiveProof — \
                     soft-accepting because stub-l2-verifier feature is enabled"
                );
            }
        }

        Ok(())
    }

    pub(crate) fn validate_stark_amendment_ordering(
        &self,
        amendment: &ProofAmendment,
    ) -> Result<(), NodeError> {
        // Include pending (queued-but-unsettled) settlements in the overlay so that
        // consecutive amendments pass the frontier ordering check even when the
        // preceding range hasn't yet been mined into a canonical block.
        let mut overlay: HashMap<ShellHash, u32> = HashMap::new();
        {
            let pending = self.pending_stark_settlements.lock();
            for pending_amendment in pending.iter() {
                for source in pending_amendment.covered_hashes() {
                    overlay.insert(source, pending_amendment.layer);
                }
            }
        }
        self.validate_stark_amendment_ordering_with_overlay(amendment, &overlay)
            .inspect_err(|_| self.metrics.stark_settlements_rejected.inc())
    }

    pub(crate) fn validate_stark_settlement_sequence(
        &self,
        amendments: &[ProofAmendment],
    ) -> Result<(), NodeError> {
        let mut overlay = HashMap::new();
        for amendment in amendments {
            self.validate_stark_amendment_ordering_with_overlay(amendment, &overlay)
                .inspect_err(|_| self.metrics.stark_settlements_rejected.inc())?;
            for source in amendment.covered_hashes() {
                overlay.insert(source, amendment.layer);
            }
        }
        Ok(())
    }

    /// Feed canonical L1 STARK settlements into the L2 aggregation scheduler.
    ///
    /// Called after each block's settlements are committed and recorded.
    /// For each L1 amendment in `settlements`:
    ///  - builds a [`SettledL1Input`] and feeds it to `aggregation_scheduler`;
    ///  - if the amendment creates a gap, logs it and updates the gap metric;
    ///  - after all amendments, ticks the scheduler's block clock with
    ///    `on_block(current_block)` to check interval / epoch triggers.
    ///
    /// When any trigger fires, creates and durably stores an [`L2AggregationJob`]
    /// so restart safety and observability are immediate.
    pub(crate) fn feed_l2_scheduler_from_settlements(
        &self,
        settlements: &[ProofAmendment],
        current_block: u64,
    ) {
        if !self.config.l2_stark_mode.is_enabled() {
            self.metrics.stark_l2_blocked_gap_start.set(0);
            self.metrics.stark_l2_pending_inputs.set(0);
            self.metrics.stark_l2_ready_jobs.set(0);
            return;
        }

        let l1_amendments: Vec<&ProofAmendment> =
            settlements.iter().filter(|a| a.layer == 1).collect();

        if l1_amendments.is_empty() {
            // Still tick on_block so interval/epoch triggers can fire.
            let trigger = self.aggregation_scheduler.lock().on_block(current_block);
            if let Some(t) = trigger {
                self.create_l2_job_from_trigger(t, current_block);
            }
            return;
        }

        for amendment in &l1_amendments {
            let start_block = amendment
                .range_start_block()
                .unwrap_or(amendment.block_number);
            // batch_root_bytes is [lo:16 ‖ hi:16]; SettledL1Input uses the lo half (u128).
            let batch_root =
                u128::from_le_bytes(amendment.proof.batch_root_bytes[0..16].try_into().unwrap());
            let input = SettledL1Input {
                start_block,
                end_block: amendment.block_number,
                batch_root,
                source_hash: *amendment.block_hash.as_bytes(),
            };

            match self
                .aggregation_scheduler
                .lock()
                .on_settled_l1_amendment(input)
            {
                Ok(()) => {
                    // Input accepted; no trigger yet (trigger fires on on_block).
                    self.metrics.stark_l2_blocked_gap_start.set(0);
                }
                Err(gap) => {
                    warn!(
                        expected = gap.expected_start,
                        received = gap.received_start,
                        "L2 scheduler blocked: L1 proof gap detected; waiting for source"
                    );
                    self.metrics
                        .stark_l2_blocked_gap_start
                        .set(gap.expected_start as i64);
                }
            }
        }

        // Tick block clock for interval / epoch triggers.
        let trigger = self.aggregation_scheduler.lock().on_block(current_block);
        if let Some(t) = trigger {
            self.metrics
                .stark_l2_last_trigger_block
                .set(current_block as i64);
            self.create_l2_job_from_trigger(t, current_block);
        }

        // Update pending-inputs metric.
        let pending = self.aggregation_scheduler.lock().pending_proof_count() as i64;
        self.metrics.stark_l2_pending_inputs.set(pending);
    }

    fn create_l2_job_from_trigger(&self, trigger: AggregationTrigger, current_block: u64) {
        let l1_source_hashes: Vec<ShellHash> = trigger
            .inputs
            .iter()
            .map(|i| ShellHash::from(i.source_hash))
            .collect();
        let l1_batch_roots: Vec<[u8; 32]> = trigger
            .inputs
            .iter()
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[..16].copy_from_slice(&i.batch_root.to_le_bytes());
                arr
            })
            .collect();
        let start_block = trigger
            .inputs
            .first()
            .map(|i| i.start_block)
            .unwrap_or(current_block);
        let end_block = trigger
            .inputs
            .last()
            .map(|i| i.end_block)
            .unwrap_or(current_block);

        let id = L2AggregationJob::compute_id(&l1_source_hashes);

        // Skip if a job with this ID already exists (idempotent).
        match self.l2_job_store.get(&id) {
            Ok(Some(existing)) => {
                debug!(
                    job_id = %id,
                    status = ?existing.status,
                    "L2 scheduler trigger: job already exists, skipping"
                );
                return;
            }
            Err(e) => {
                warn!("L2 scheduler trigger: failed to check existing job {id}: {e}");
                return;
            }
            Ok(None) => {}
        }

        let job = L2AggregationJob {
            id,
            status: L2JobStatus::Ready,
            l1_source_hashes,
            start_block,
            end_block,
            l1_batch_roots,
            aggregate_root: None,
            retry_count: 0,
            last_error: None,
            created_at_block: current_block,
            updated_at_block: current_block,
        };

        if let Err(e) = self.l2_job_store.put(&job) {
            warn!("L2 scheduler trigger: failed to store job {}: {e}", job.id);
            return;
        }

        // Update ready-jobs metric.
        let ready = self
            .l2_job_store
            .jobs_with_status(L2JobStatus::Ready)
            .map(|v| v.len())
            .unwrap_or(0) as i64;
        self.metrics.stark_l2_ready_jobs.set(ready);

        info!(
            job_id = %job.id,
            start_block = job.start_block,
            end_block = job.end_block,
            n_l1_proofs = job.l1_batch_roots.len(),
            "L2 aggregation job created and stored"
        );
    }

    pub(crate) fn store_stark_artifacts(
        &self,
        amendment: &ProofAmendment,
        settlement_tx_hash: Option<ShellHash>,
    ) -> Result<usize, NodeError> {
        let artifacts = amendment
            .storage_artifacts_with_settlement(settlement_tx_hash)
            .map_err(|e| {
                NodeError::Startup(format!(
                    "serialize STARK proof artifacts for block #{}: {e}",
                    amendment.block_number
                ))
            })?;
        let stored = artifacts.len();
        self.amendment_store.put_amendments_atomic(artifacts)?;
        Ok(stored)
    }

    pub(crate) fn stark_artifacts(
        amendment: &ProofAmendment,
        settlement_tx_hash: Option<ShellHash>,
    ) -> Result<Vec<(ShellHash, Vec<u8>)>, NodeError> {
        amendment
            .storage_artifacts_with_settlement(settlement_tx_hash)
            .map_err(|e| {
                NodeError::Startup(format!(
                    "serialize STARK proof artifacts for block #{}: {e}",
                    amendment.block_number
                ))
            })
    }

    fn validate_stark_amendment_ordering_with_overlay(
        &self,
        amendment: &ProofAmendment,
        overlay_layers: &HashMap<ShellHash, u32>,
    ) -> Result<(), NodeError> {
        if amendment.layer == 0 {
            return Err(NodeError::Startup(
                "STARK amendment layer must be at least 1".into(),
            ));
        }

        if !amendment.has_valid_embedded_compression() {
            return Err(NodeError::Startup(
                "STARK amendment does not satisfy strict embedded compression threshold".into(),
            ));
        }

        if amendment.layer == 1
            && amendment.proof.n_sigs != 0
            && amendment.proof.n_sigs < MIN_L1_STARK_TXS
        {
            return Err(NodeError::Startup(format!(
                "STARK L1 amendment covers {} tx entries; minimum is {MIN_L1_STARK_TXS}",
                amendment.proof.n_sigs
            )));
        }

        let covered = amendment.covered_hashes();
        if covered.is_empty() {
            return Err(NodeError::Startup(
                "STARK amendment covers no canonical sources".into(),
            ));
        }
        if covered.last() != Some(&amendment.block_hash) {
            return Err(NodeError::Startup(format!(
                "STARK amendment final source hash must match proof target {}",
                amendment.block_hash
            )));
        }

        let start_block = amendment.range_start_block().ok_or_else(|| {
            NodeError::Startup(format!(
                "STARK amendment range ending at #{} is shorter than its source count {}",
                amendment.block_number,
                covered.len()
            ))
        })?;
        let expected_end = start_block
            .checked_add(covered.len() as u64)
            .and_then(|end_plus_one| end_plus_one.checked_sub(1))
            .ok_or_else(|| NodeError::Startup("STARK amendment range overflows u64".into()))?;
        if expected_end != amendment.block_number {
            return Err(NodeError::Startup(format!(
                "STARK amendment range #{}..=#{expected_end} does not end at declared block #{}",
                start_block, amendment.block_number
            )));
        }

        for (offset, source_hash) in covered.iter().enumerate() {
            let number = start_block.saturating_add(offset as u64);
            let canonical_hash = self
                .chain_store
                .get_block_hash_by_number(number)?
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "STARK amendment references missing canonical block #{number}"
                    ))
                })?;
            if canonical_hash != *source_hash {
                return Err(NodeError::Startup(format!(
                    "STARK amendment source #{number} is not canonical: expected {canonical_hash}, got {source_hash}"
                )));
            }

            if !self.is_stark_compression_source(source_hash, overlay_layers)? {
                return Err(NodeError::Startup(format!(
                    "STARK amendment source #{number} has no compressible witness/proof payload"
                )));
            }

            let current_layer = self.compression_layer_for_source(source_hash, overlay_layers)?;
            if current_layer >= amendment.layer {
                return Err(NodeError::Startup(format!(
                    "STARK amendment overlaps block #{number} already compressed at layer {current_layer}"
                )));
            }
            if amendment.layer > 1 && current_layer + 1 != amendment.layer {
                return Err(NodeError::Startup(format!(
                    "STARK L{} amendment requires block #{number} to be compressed at L{}, found L{}",
                    amendment.layer,
                    amendment.layer - 1,
                    current_layer
                )));
            }
        }

        let expected_start =
            self.first_canonical_block_below_layer(amendment.layer, overlay_layers)?;
        if start_block != expected_start {
            return Err(NodeError::Startup(format!(
                "STARK L{} amendment must start at frontier #{expected_start}, got #{start_block}",
                amendment.layer
            )));
        }

        Ok(())
    }

    pub(crate) fn first_canonical_block_below_layer(
        &self,
        layer: u32,
        overlay_layers: &HashMap<ShellHash, u32>,
    ) -> Result<u64, NodeError> {
        let head = self
            .chain_store
            .get_head_block()?
            .map(|block| block.number())
            .unwrap_or(0);

        // Counts are not a frontier: old chains and reorg recovery can contain
        // settled hashes after an earlier gap. Start from the cached contiguous
        // frontier and advance only across canonical settled or pending sources.
        let mut number = self
            .settled_stark_frontiers
            .lock()
            .get(&layer)
            .copied()
            .unwrap_or(0);
        while number <= head {
            let Some(hash) = self.chain_store.get_block_hash_by_number(number)? else {
                number = number.saturating_add(1);
                continue;
            };
            if !self.is_stark_compression_source(&hash, overlay_layers)? {
                number = number.saturating_add(1);
                continue;
            }
            if self.compression_layer_for_source(&hash, overlay_layers)? < layer {
                return Ok(number);
            }
            number = number.saturating_add(1);
        }
        Ok(head.saturating_add(1))
    }

    fn compression_layer_for_source(
        &self,
        source_hash: &ShellHash,
        overlay_layers: &HashMap<ShellHash, u32>,
    ) -> Result<u32, NodeError> {
        if let Some(layer) = overlay_layers.get(source_hash) {
            return Ok(*layer);
        }
        // Check layers 1, 2, 3 from highest to lowest for the given source_hash.
        // The in-memory set is always authoritative; the index is the durable backup.
        let settled_layer = {
            let lock = self.settled_stark_sources.lock();
            (1u32..=3)
                .rev()
                .find(|&l| lock.contains(&(l, *source_hash)))
                .unwrap_or(0)
        };
        if settled_layer > 0 {
            return Ok(settled_layer);
        }
        Ok(0)
    }

    pub(crate) fn is_stark_compression_source(
        &self,
        source_hash: &ShellHash,
        overlay_layers: &HashMap<ShellHash, u32>,
    ) -> Result<bool, NodeError> {
        if overlay_layers.contains_key(source_hash) {
            return Ok(true);
        }
        if self.amendment_store.get_amendment(source_hash)?.is_some() {
            return Ok(true);
        }
        if self.witness_store.has_bundle(source_hash)? {
            return Ok(true);
        }
        Ok(self.chain_store.get_header_by_hash(source_hash)?.is_some())
    }
}
