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

        // Collect pending transactions from mempool.
        let candidates = mem_pool.pending_for_block(max_txs);

        // Create an isolated EVM instance at the current state root.
        let (state_db, current_root) = block_store.isolated_state_db()?;
        let mut evm = ShellPqvm::new(state_db, self.config.chain_id);

        let now = self.current_block_timestamp(head.header.timestamp);

        // Calculate EIP-1559 base fee from parent block.
        let base_fee = calculate_base_fee(
            head.header.gas_used,
            head.header.gas_limit,
            head.header.base_fee_per_gas,
        );

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
            excess_blob_gas: 0,
            witness_root: None,
        };

        let mut included_txs: Vec<SignedTransaction> = Vec::with_capacity(256);
        let mut receipts = Vec::with_capacity(256);
        let mut cumulative_gas: u64 = 0;
        let mut total_effective_fees = U256::ZERO;

        // F-302: Create the ChainStore wrapper once and reuse it for all per-tx
        // re-validations. ChainStore is a thin Arc-clone wrapper, so creating it
        // inside the loop was an unnecessary per-iteration allocation.
        let import_cs = ChainStore::new(self.store.clone());

        for (idx, tx) in candidates.iter().enumerate() {
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
            let exec_result = if is_aa {
                evm.execute_aa_bundle(tx, &header, idx as u32, cumulative_gas)
            } else {
                evm.execute_tx(tx, &header, idx as u32, cumulative_gas)
            };
            match exec_result {
                Ok(result) => {
                    let price = effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        base_fee,
                    );
                    if is_aa {
                        // AA dispatcher already mutated evm.state_db.world_state
                        // in place (including atomic rollback on failure). Mirror
                        // to the node's persistent world_state by reopening it at
                        // the post-bundle root. Both world_states share the same
                        // KV-backed trie store, so this is a constant-time op.
                        let new_root = evm.state_db_mut().world_state_mut().state_root()?;
                        block_store.rollback_world_state(&new_root)?;
                    } else if result.is_system_tx {
                        self.sync_system_contract_state(
                            evm.state_db_mut().world_state_mut(),
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
                                let removed = self.tx_pool.remove(&tx.hash());
                                warn!(
                                    tx_hash = %tx.hash(),
                                    removed,
                                    "produce_block: removed tx with unrecoverable state error from mempool"
                                );
                            }
                            continue;
                        }
                    }
                    cumulative_gas += result.gas_used;
                    total_effective_fees = total_effective_fees.saturating_add(
                        U256::from(result.gas_used).saturating_mul(U256::from(price)),
                    );
                    receipts.push(result.receipt);
                    included_txs.push(tx.clone());
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
                        let removed = self.tx_pool.remove(&tx.hash());
                        warn!(
                            tx_hash = %tx.hash(),
                            removed,
                            "produce_block: removed tx with unrecoverable state error from mempool"
                        );
                    }
                    continue;
                }
            }
        }

        header.gas_used = cumulative_gas;

        // The EVM executes against an isolated WorldState opened at the parent
        // root. Normal transaction commits must not be applied a second time to
        // the live WorldState: both handles share the same trie KV store, and a
        // second write from the old storage root can race with nodes removed by
        // the first persistent trie update. Re-open the live state at the
        // isolated post-transaction root once instead.
        let post_tx_root = evm.state_db_mut().world_state_mut().state_root()?;
        block_store.rollback_world_state(&post_tx_root)?;

        let mut system_txs = Vec::new();
        // Block producer receives 100% of effective gas fees.
        let producer_reward = total_effective_fees;
        if !included_txs.is_empty() && producer_reward > U256::ZERO {
            block_store.add_balance(&proposer_addr, producer_reward)?;
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
            block_store.add_balance(&reward_tx.to, reward_tx.value)?;
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
            let receipt_blooms: Vec<shell_pqvm::bloom::Bloom> = receipts
                .iter()
                .map(|r| {
                    let mut bloom = [0u8; shell_pqvm::bloom::BLOOM_SIZE];
                    let bytes = r.logs_bloom.as_ref();
                    let len = bytes.len().min(shell_pqvm::bloom::BLOOM_SIZE);
                    bloom[..len].copy_from_slice(&bytes[..len]);
                    bloom
                })
                .collect();
            let block_bloom = shell_pqvm::bloom::bloom_union(&receipt_blooms);
            header.logs_bloom = Bytes::from(block_bloom.to_vec());
        }

        // Apply algorithm activations whose timelock has elapsed (WP §6.5).
        // Must run BEFORE state_root so activations are committed to the Merkle root.
        {
            let mut ws = self.world_state.write();
            let mut registry = AlgorithmRegistry::global_mut();
            if let Err(e) = process_pending_activations(header.number, &mut *ws, &mut registry) {
                warn!(
                    block = header.number,
                    "process_pending_activations failed during production: {e}"
                );
            }
        }

        // Compute state root from the updated world state (includes any activations above).
        {
            let mut ws = self.world_state.write();
            header.state_root = ws.state_root()?;
        }

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
        if let Err(err) = block_store.commit_canonical_block(&block, Some(receipts.as_slice())) {
            prover.restore_pending_stark_settlements(drained_stark_settlements);
            if let Err(rollback_err) = block_store.rollback_world_state(&current_root) {
                warn!(
                    error = %rollback_err,
                    target_root = %current_root,
                    "produce_block: failed to roll back world state after storage commit error"
                );
            }
            return Err(err);
        }

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
            let l1_count = self
                .settled_stark_sources
                .lock()
                .iter()
                .filter(|(l, _)| *l == 1)
                .count() as i64;
            let lag = (block.number() as i64 + 1).saturating_sub(l1_count).max(0);
            self.metrics.stark_frontier_lag.set(lag);
        }
        self.feed_l2_scheduler_from_settlements(&settled_stark_proofs, block.number());
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
