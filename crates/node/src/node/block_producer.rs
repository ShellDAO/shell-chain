use super::*;

pub(crate) fn sort_stark_settlements_for_inclusion(settlements: &mut [ProofAmendment]) {
    settlements.sort_by(|a, b| {
        let a_start = a.range_start_block().unwrap_or(a.block_number);
        let b_start = b.range_start_block().unwrap_or(b.block_number);
        a.layer
            .cmp(&b.layer)
            .then_with(|| a_start.cmp(&b_start))
            // If multiple proofs cover the same frontier start, settle the
            // widest range first so short overlapping proofs cannot starve
            // historical catch-up.
            .then_with(|| b.block_number.cmp(&a.block_number))
            .then_with(|| a.block_hash.as_bytes().cmp(b.block_hash.as_bytes()))
            .then_with(|| a.prover.0.as_slice().cmp(b.prover.0.as_slice()))
    });
}

impl<S: KvStore + 'static> Node<S> {
    /// Produce a block from pending mempool transactions.
    ///
    /// Collects up to `max_txs` transactions, executes each through the EVM,
    /// commits state changes after every transaction (so subsequent txs see
    /// prior updates), assembles a block, and commits it to storage.
    pub fn produce_block(&self, signer: &dyn Signer, max_txs: usize) -> Result<Block, NodeError> {
        let block_store = self.block_store();
        let consensus = self.consensus_manager();
        let prover = self.prover_orchestrator();
        let mem_pool = self.mem_pool();

        let head = block_store.head_block()?.ok_or(NodeError::NoGenesis)?;
        let head_hash = head.hash();
        let next_number = ChainStateMachine::next_block_number(head.number())?;

        let proposer_addr = self.config.proposer_address.ok_or(NodeError::NotProposer)?;
        consensus.ensure_local_proposer(next_number, proposer_addr)?;

        let (finalized_number, finalized_hash) = consensus.finalized_cursor();
        ChainStateMachine::ensure_production_parent(
            head.number(),
            head_hash,
            next_number,
            block_store.block_exists(next_number)?,
            finalized_number,
            finalized_hash,
        )?;

        // Calculate EIP-1559 base fee from parent block before selecting
        // candidates so underpriced transactions do not consume the limit.
        let base_fee = calculate_base_fee(
            head.header.gas_used,
            head.header.gas_limit,
            head.header.base_fee_per_gas,
        );
        let excess_blob_gas =
            calc_excess_blob_gas(head.header.excess_blob_gas, head.header.blob_gas_used);
        let blob_base_fee = calc_blob_gas_price(excess_blob_gas);
        // Candidate validation and execution can still reject transactions
        // after mempool selection. Inspect the bounded pool snapshot so skipped
        // entries do not consume the block's inclusion limit.
        let candidate_limit = if max_txs == 0 { 0 } else { usize::MAX };
        let candidates = mem_pool.pending_for_block(candidate_limit, base_fee, blob_base_fee);

        // Keep trie writes and address-keyed execution metadata private until
        // the block and its receipts can be published in the same batch.
        let current_root = block_store.current_state_root()?;
        let execution_store = Arc::new(OverlayStore::new(self.store.clone()));
        let execution_state = WorldState::at_root(execution_store.clone(), &current_root)?;
        let state_db = ShellStateDb::new(execution_state, ChainStore::new(execution_store.clone()));
        let mut evm = ShellPqvm::new(state_db, self.config.chain_id);
        let mut algorithm_registry_rollback = AlgorithmRegistryRollback::new();

        let now = self.current_block_timestamp(head.header.timestamp);

        // Build a preliminary header for EVM context.
        let mut header = BlockHeader {
            parent_hash: head_hash,
            state_root: ShellHash::default(),
            transactions_root: ShellHash::default(),
            receipts_root: ShellHash::default(),
            logs_bloom: Bytes::default(),
            number: next_number,
            gas_limit: head.header.gas_limit,
            gas_used: 0,
            timestamp: now,
            extra_data: Bytes::default(),
            proposer: proposer_addr,
            sig_aggregate_proof: None,
            base_fee_per_gas: base_fee,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas,
            witness_root: None,
        };

        let candidate_capacity = candidates.len();
        let mut included_txs: Vec<SignedTransaction> = Vec::with_capacity(candidate_capacity);
        let mut receipts = Vec::with_capacity(candidate_capacity);
        let mut cumulative_gas: u64 = 0;
        let mut total_effective_fees = U256::ZERO;

        // F-302: Create the ChainStore wrapper once and reuse it for all per-tx
        // re-validations. ChainStore is a thin Arc-clone wrapper, so creating it
        // inside the loop was an unnecessary per-iteration allocation.
        let import_cs = ChainStore::new(execution_store);

        for tx in &candidates {
            if included_txs.len() >= max_txs {
                break;
            }
            if cumulative_gas >= header.gas_limit {
                break;
            }
            if !tx_fits_remaining_block_gas(tx, cumulative_gas, header.gas_limit) {
                debug!(
                    tx_hash = %tx.tx.hash(),
                    gas_limit = tx.tx.gas_limit,
                    cumulative_gas,
                    block_gas_limit = header.gas_limit,
                    "produce_block: skipping tx that exceeds remaining block gas"
                );
                continue;
            }
            // EIP-1559: skip transactions that cannot afford the base fee.
            if tx.tx.max_fee_per_gas < base_fee {
                continue;
            }
            let tx_blob_gas = tx.tx.blob_gas();
            let Some(next_blob_gas) =
                checked_cumulative_blob_gas(header.blob_gas_used, tx_blob_gas)
            else {
                debug!(
                    tx_hash = %tx.tx.hash(),
                    tx_blob_gas,
                    block_blob_gas = header.blob_gas_used,
                    max_blob_gas = MAX_BLOB_GAS_PER_BLOCK,
                    "produce_block: skipping tx that exceeds remaining block blob gas"
                );
                continue;
            };
            if tx.tx.tx_type == 3 && tx.tx.max_fee_per_blob_gas.unwrap_or_default() < blob_base_fee
            {
                continue;
            }
            // F-302: Re-validate before execution (algorithm restrictions may have
            // changed since admission). Uses import-path validator (checks nonce,
            // skips balance because execution enforces spendability).
            let pre_verifier = PreVerified;
            if let Err(e) = validate_tx_for_import(
                tx,
                evm.state_db_mut().world_state_mut(),
                &import_cs,
                &pre_verifier,
                self.config.chain_id,
            ) {
                debug!(
                    tx_hash = %tx.tx.hash(),
                    error = %e,
                    "produce_block: skipping tx that failed re-validation"
                );
                continue;
            }

            let pre_tx_root = evm.state_db_mut().world_state_mut().state_root()?;
            let is_aa = tx.is_aa_bundle();
            let tx_index = included_txs.len() as u32;
            let exec_result = if is_aa {
                evm.execute_aa_bundle(tx, &header, tx_index, cumulative_gas)
            } else {
                evm.execute_tx(tx, &header, tx_index, cumulative_gas)
            };
            match exec_result {
                Ok(result) => {
                    let price = effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        base_fee,
                    );
                    if is_aa {
                        // The AA dispatcher already mutated the isolated block
                        // state in place, including atomic rollback on failure.
                    } else if result.is_system_tx {
                        // Native system-contract effects are already staged in
                        // the isolated world and chain stores.
                        Self::validate_system_contract_effects(
                            evm.state_db().world_state(),
                            &result.system_contract_effects,
                        )?;
                    } else {
                        // Normal PQVM tx: commit the revm state changeset.
                        if let Err(e) = commit_pqvm_state(&result, evm.state_db_mut()) {
                            if let Err(rollback_err) = evm
                                .state_db_mut()
                                .world_state_mut()
                                .rollback_to_root(&pre_tx_root)
                            {
                                warn!(
                                    tx_hash = %tx.hash(),
                                    error = %rollback_err,
                                    target_root = %pre_tx_root,
                                    "produce_block: failed to roll back isolated state after tx commit error"
                                );
                            }
                            warn!(
                                tx_hash = %tx.hash(),
                                from = %tx.from,
                                to = ?tx.tx.to,
                                nonce = tx.tx.nonce,
                                error = %e,
                                "produce_block: skipping tx after state commit error"
                            );
                            if is_unrecoverable_executor_error(&e) {
                                let removed = self.tx_pool.remove_with_descendants(&tx.hash());
                                warn!(
                                    tx_hash = %tx.hash(),
                                    removed,
                                    "produce_block: removed tx and descendants with unrecoverable state error from mempool"
                                );
                            }
                            continue;
                        }
                    }
                    let Some(next_cumulative_gas) = checked_cumulative_block_gas(
                        cumulative_gas,
                        result.gas_used,
                        header.gas_limit,
                    ) else {
                        if let Err(rollback_err) = evm
                            .state_db_mut()
                            .world_state_mut()
                            .rollback_to_root(&pre_tx_root)
                        {
                            warn!(
                                tx_hash = %tx.hash(),
                                error = %rollback_err,
                                target_root = %pre_tx_root,
                                "produce_block: failed to roll back isolated state after gas accounting overflow"
                            );
                        }
                        warn!(
                            tx_hash = %tx.hash(),
                            gas_used = result.gas_used,
                            cumulative_gas,
                            block_gas_limit = header.gas_limit,
                            "produce_block: skipping tx after invalid gas accounting"
                        );
                        continue;
                    };
                    if let shell_core::PubkeyMode::Embedded(pubkey) = &tx.pubkey_mode {
                        // Execution may have rotated this key through the
                        // account manager. Preserve that staged value instead
                        // of restoring the transaction's signing key.
                        if import_cs.get_pubkey(&tx.from)?.is_none() {
                            import_cs.put_pubkey(&tx.from, pubkey)?;
                        }
                    }
                    cumulative_gas = next_cumulative_gas;
                    header.blob_gas_used = next_blob_gas;
                    total_effective_fees = total_effective_fees.saturating_add(
                        U256::from(result.gas_used).saturating_mul(U256::from(price)),
                    );
                    receipts.push(result.receipt);
                    included_txs.push(tx.as_ref().clone());
                }
                Err(e) => {
                    if let Err(rollback_err) = evm
                        .state_db_mut()
                        .world_state_mut()
                        .rollback_to_root(&pre_tx_root)
                    {
                        warn!(
                            tx_hash = %tx.hash(),
                            error = %rollback_err,
                            target_root = %pre_tx_root,
                            "produce_block: failed to roll back isolated state after tx execution error"
                        );
                    }
                    warn!(
                        tx_hash = %tx.hash(),
                        from = %tx.from,
                        to = ?tx.tx.to,
                        nonce = tx.tx.nonce,
                        error = %e,
                        "produce_block: skipping tx after execution error"
                    );
                    if is_unrecoverable_executor_error(&e) {
                        let removed = self.tx_pool.remove_with_descendants(&tx.hash());
                        warn!(
                            tx_hash = %tx.hash(),
                            removed,
                            "produce_block: removed tx and descendants with unrecoverable state error from mempool"
                        );
                    }
                    continue;
                }
            }
        }

        header.gas_used = cumulative_gas;

        let mut system_txs = Vec::new();
        // Block producer receives 100% of effective gas fees.
        let producer_reward = total_effective_fees;
        if !included_txs.is_empty() && producer_reward > U256::ZERO {
            evm.state_db_mut()
                .world_state_mut()
                .add_balance(&proposer_addr, producer_reward)?;
            let tx_index = included_txs.len() as u32;
            let reward_tx = SystemTransaction::block_gas_reward(
                self.config.chain_id,
                next_number,
                tx_index,
                proposer_addr,
                producer_reward,
                head_hash,
            );
            receipts.push(TransactionReceipt {
                tx_hash: reward_tx.hash(),
                block_number: next_number,
                tx_index,
                status: 1,
                gas_used: 0,
                cumulative_gas_used: cumulative_gas,
                contract_address: None,
                logs_bloom: Bytes::default(),
                logs: vec![],
            });
            system_txs.push(reward_tx);
        }

        let mut drained_stark_settlements = prover.take_pending_stark_settlements();
        sort_stark_settlements_for_inclusion(&mut drained_stark_settlements);
        let mut settled_stark_proofs = Vec::new();
        let mut settled_stark_artifacts = Vec::new();
        let mut seen_stark_sources = HashSet::new();
        for amendment in drained_stark_settlements.iter().cloned() {
            let settlement_keys: Vec<(u32, ShellHash)> = amendment
                .covered_hashes()
                .into_iter()
                .map(|source| (amendment.layer, source))
                .collect();
            if settlement_keys
                .iter()
                .any(|key| seen_stark_sources.contains(key))
            {
                continue;
            }
            if settlement_keys
                .iter()
                .any(|key| prover.has_settled_source(*key))
            {
                continue;
            }
            // Optimistic push: validate with the new amendment included, then pop
            // on failure. This avoids the O(n²) settled_stark_proofs.clone() that
            // the previous candidate_settlements pattern caused.
            settled_stark_proofs.push(amendment.clone());
            if let Err(e) = self.validate_stark_settlement_sequence(&settled_stark_proofs) {
                settled_stark_proofs.pop();
                warn!(
                    block = next_number,
                    source = %amendment.block_hash,
                    layer = amendment.layer,
                    "skipping out-of-order STARK reward settlement: {e}"
                );
                continue;
            }
            if let Err(e) = self.validate_stark_amendment_authentication(&amendment) {
                settled_stark_proofs.pop();
                warn!(
                    block = next_number,
                    source = %amendment.block_hash,
                    layer = amendment.layer,
                    "skipping STARK reward settlement with invalid prover authentication: {e}"
                );
                continue;
            }
            if let Err(e) = self.validate_stark_proof_source_binding(&amendment) {
                settled_stark_proofs.pop();
                warn!(
                    block = next_number,
                    source = %amendment.block_hash,
                    layer = amendment.layer,
                    "skipping STARK reward settlement with invalid proof-source binding: {e}"
                );
                continue;
            }
            seen_stark_sources.extend(settlement_keys.iter().copied());
            let tx_index = included_txs.len().saturating_add(system_txs.len()) as u32;
            let reward_tx = match self.build_stark_reward_tx(next_number, tx_index, &amendment) {
                Ok(tx) if tx.value > U256::ZERO => tx,
                Ok(_) => {
                    settled_stark_proofs.pop();
                    continue;
                }
                Err(e) => {
                    settled_stark_proofs.pop();
                    warn!(
                        block = next_number,
                        source = %amendment.block_hash,
                        "skipping invalid STARK reward settlement: {e}"
                    );
                    continue;
                }
            };
            evm.state_db_mut()
                .world_state_mut()
                .add_balance(&reward_tx.to, reward_tx.value)?;
            receipts.push(TransactionReceipt {
                tx_hash: reward_tx.hash(),
                block_number: next_number,
                tx_index,
                status: 1,
                gas_used: 0,
                cumulative_gas_used: cumulative_gas,
                contract_address: None,
                logs_bloom: Bytes::default(),
                logs: vec![],
            });
            let reward_hash = reward_tx.hash();
            system_txs.push(reward_tx);
            settled_stark_artifacts.push((amendment, reward_hash));
            // settled_stark_proofs already holds the amendment (optimistic push above).
        }
        header.extra_data = Bytes::default();

        // Compute block-level logs bloom by OR-ing all receipt blooms.
        {
            let block_bloom = shell_pqvm::bloom::bloom_union_bytes(
                receipts.iter().map(|receipt| receipt.logs_bloom.as_ref()),
            );
            header.logs_bloom = Bytes::from(block_bloom.to_vec());
        }

        // Apply algorithm activations whose timelock has elapsed (WP §6.5).
        // Must run BEFORE state_root so activations are committed to the Merkle root.
        let activation_result = {
            let mut registry = AlgorithmRegistry::global_mut();
            apply_pending_activations(
                header.number,
                evm.state_db_mut().world_state_mut(),
                &mut registry,
                "production",
            )
        };
        if let Err(err) = activation_result {
            prover.restore_pending_stark_settlements(drained_stark_settlements);
            return Err(err);
        }

        // Compute state root from the updated world state (includes any activations above).
        header.state_root = evm.state_db_mut().world_state_mut().state_root()?;

        let mut block = Block {
            header,
            transactions: included_txs,
            system_transactions: system_txs,
            proposer_seal: None,
        };

        // C3: If STARK aggregation is enabled, collect sig batch entries and
        // compute the 32-byte commitment synchronously so it can be embedded
        // in the header (and thus covered by the block hash / proposer seal).
        // The full STARK proof is generated asynchronously; nodes that receive
        // a commitment-only header will skip full STARK verification until a
        // ProofAmendment arrives.
        let stark_entries: Option<Vec<SigBatchEntry>> = if self.stark_aggregation {
            Some(stark_sources::entries_from_txs(&block.transactions))
        } else {
            None
        };

        // Embed the batch-root commitment in the header before signing.
        if let Some(entries) = stark_entries.as_ref() {
            if !entries.is_empty() {
                let batch_root = compute_batch_root(entries);
                let commitment = SigBatchProof::commitment_only(batch_root, entries.len());
                block.header.sig_aggregate_proof = commitment.to_json().ok().map(Into::into);
            }
        }

        // Sign the block with the proposer's key.
        consensus.sign_block(&mut block, signer)?;

        // Register the signer's pubkey so we can verify our own blocks on re-import.
        consensus.register_authority_pubkey(proposer_addr, signer.public_key().to_vec());

        // Commit to storage.
        let block_hash = block.hash();
        // Prepare proof task with the real block hash; enqueue only after
        // canonical commit succeeds so backlog never references non-canonical blocks.
        let pending_proof_task = if let Some(entries) = stark_entries {
            let block_num = block.header.number;
            let hash_bytes: [u8; 32] = *block_hash.as_bytes();
            let original_size =
                self.stark_source_original_size(&block_hash, &block, entries.len())?;
            Some((
                ProofTask::with_sources(
                    hash_bytes,
                    block_num,
                    entries,
                    1,
                    vec![block_hash],
                    original_size,
                ),
                block_num,
                original_size,
            ))
        } else {
            None
        };
        if let Err(err) = import_cs.commit_canonical_overlay(&block, Some(receipts.as_slice())) {
            prover.restore_pending_stark_settlements(drained_stark_settlements);
            return Err(err.into());
        }
        algorithm_registry_rollback.commit();
        let committed_world_state =
            WorldState::at_root(self.store.clone(), &block.header.state_root)?;
        block_store.replace_world_state(committed_world_state);

        if let Some((task, block_num, original_size)) = pending_proof_task {
            prover.queue_task(task);
            debug!(
                block = block_num,
                original_size, "G4: proof task queued in backlog (async proving)"
            );
        }
        let queued = self.enqueue_stark_frontier_backlog(64)?;
        if queued > 0 {
            debug!(
                queued,
                "queued additional historical STARK frontier proof tasks after block production"
            );
        }
        prover.record_accepted_settlements(settled_stark_proofs.len());
        for (amendment, settlement_tx_hash) in &settled_stark_artifacts {
            self.store_stark_artifacts(amendment, Some(*settlement_tx_hash))?;
        }
        prover.record_settled_sources(&settled_stark_proofs);
        if !settled_stark_proofs.is_empty() {
            let l1_frontier = self
                .settled_stark_frontiers
                .lock()
                .get(&1)
                .copied()
                .unwrap_or(0) as i64;
            let lag = (block.number() as i64 + 1)
                .saturating_sub(l1_frontier)
                .max(0);
            self.metrics.stark_frontier_lag.set(lag);
        }
        self.feed_l2_scheduler_from_settlements(&settled_stark_proofs, block.number());
        block_store.schedule_settled_witness_deletes(
            &settled_stark_proofs,
            block.number(),
            self.config.pruning.proof_replacement_grace,
        );
        block_store.prune_grace_witnesses(block.number());
        consensus.register_fork_choice_block(block_hash, block.header.parent_hash, block.number());

        // Remove included transactions from mempool.
        let tx_hashes: Vec<ShellHash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        let pruned = mem_pool.remove_committed_hashes(&tx_hashes);
        if pruned > 0 {
            debug!(
                count = pruned,
                "pruned stale nonce-too-low transactions after production"
            );
        }

        // Update canonical aggregate counters for shell_* stats RPCs.
        let visible_tx_count = block
            .transactions
            .len()
            .saturating_add(block.system_transactions.len());
        block_store.update_chain_totals(
            block.number(),
            visible_tx_count as u64,
            block.header.gas_used,
        )?;

        // Track the new state root for pruning decisions.
        self.record_canonical_state_root(block.number(), block.header.state_root);

        // Update offline-slash tracker with this freshly proposed block.
        self.last_proposed_by
            .lock()
            .insert(block.header.proposer, block.number());
        self.reload_authorities_if_boundary(block.number())?;
        if self.config.node_role.runs_prover() {
            let queued = self.enqueue_stark_frontier_backlog(8)?;
            if queued > 0 {
                debug!(
                    queued,
                    "queued ordered STARK frontier proof tasks after block production"
                );
            }
        }

        Ok(block)
    }
}

fn is_unrecoverable_executor_error(error: &shell_pqvm::ExecutorError) -> bool {
    matches!(
        error,
        shell_pqvm::ExecutorError::Storage(shell_storage::StorageError::Trie(_))
            | shell_pqvm::ExecutorError::StateDb(shell_pqvm::StateDbError::Storage(
                shell_storage::StorageError::Trie(_),
            ))
    )
}
