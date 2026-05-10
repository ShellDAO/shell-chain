use super::*;

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
        let next_number = head.number() + 1;

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
        let mut evm = ShellEvm::new(state_db, self.config.chain_id);

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

        for (idx, tx) in candidates.iter().enumerate() {
            // EIP-1559: skip transactions that cannot afford the base fee.
            if tx.tx.max_fee_per_gas < base_fee {
                continue;
            }

            // F-302: Re-validate mempool txs before execution. Security checks
            // may have changed since the tx was originally admitted (e.g. new
            // algorithm restrictions, pubkey conflicts). Uses the import-path
            // validator which skips nonce/balance (EVM handles those).
            let import_cs = ChainStore::new(self.store.clone());
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

            let is_aa = tx.is_aa_bundle();
            let exec_result = if is_aa {
                evm.execute_aa_bundle(tx, &header, idx as u32, cumulative_gas)
            } else {
                evm.execute_tx(tx, &header, idx as u32, cumulative_gas)
            };
            match exec_result {
                Ok(result) => {
                    cumulative_gas += result.gas_used;
                    let price = effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        base_fee,
                    );
                    total_effective_fees = total_effective_fees.saturating_add(
                        U256::from(result.gas_used).saturating_mul(U256::from(price)),
                    );
                    receipts.push(result.receipt);
                    included_txs.push(tx.clone());

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
                        // Normal EVM tx: commit EvmState changeset.
                        commit_evm_state(
                            &result.state_changes,
                            evm.state_db_mut().world_state_mut(),
                            &self.chain_store,
                        )?;

                        // Commit to the node's persistent WorldState.
                        {
                            let mut ws = self.world_state.write();
                            commit_evm_state(&result.state_changes, &mut ws, &self.chain_store)?;
                        }
                    }
                }
                Err(_) => {
                    // Skip failed transactions.
                    continue;
                }
            }

            if cumulative_gas >= header.gas_limit {
                break;
            }
        }

        header.gas_used = cumulative_gas;

        let mut system_txs = Vec::new();
        let producer_reward = total_effective_fees / U256::from(2u8);
        if !included_txs.is_empty() && producer_reward > U256::ZERO {
            evm.state_db_mut()
                .world_state_mut()
                .add_balance(&proposer_addr, producer_reward)?;
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
        drained_stark_settlements.sort_by(|a, b| {
            (
                a.layer,
                a.block_number,
                a.block_hash.as_bytes(),
                a.prover.0.as_slice(),
            )
                .cmp(&(
                    b.layer,
                    b.block_number,
                    b.block_hash.as_bytes(),
                    b.prover.0.as_slice(),
                ))
        });
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
            let mut candidate_settlements = settled_stark_proofs.clone();
            candidate_settlements.push(amendment.clone());
            if let Err(e) = self.validate_stark_settlement_sequence(&candidate_settlements) {
                warn!(
                    block = next_number,
                    source = %amendment.block_hash,
                    layer = amendment.layer,
                    "skipping out-of-order STARK reward settlement: {e}"
                );
                continue;
            }
            seen_stark_sources.extend(settlement_keys.iter().copied());
            let tx_index = included_txs.len().saturating_add(system_txs.len()) as u32;
            let reward_tx = match self.build_stark_reward_tx(next_number, tx_index, &amendment) {
                Ok(tx) if tx.value > U256::ZERO => tx,
                Ok(_) => continue,
                Err(e) => {
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
            settled_stark_artifacts.push((amendment.clone(), reward_hash));
            settled_stark_proofs.push(amendment);
        }
        header.extra_data = Bytes::default();

        // Compute block-level logs bloom by OR-ing all receipt blooms.
        {
            let receipt_blooms: Vec<shell_evm::bloom::Bloom> = receipts
                .iter()
                .map(|r| {
                    let mut bloom = [0u8; shell_evm::bloom::BLOOM_SIZE];
                    let bytes = r.logs_bloom.as_ref();
                    let len = bytes.len().min(shell_evm::bloom::BLOOM_SIZE);
                    bloom[..len].copy_from_slice(&bytes[..len]);
                    bloom
                })
                .collect();
            let block_bloom = shell_evm::bloom::bloom_union(&receipt_blooms);
            header.logs_bloom = Bytes::from(block_bloom.to_vec());
        }

        // Compute state root from the updated world state.
        {
            let mut ws = self.world_state.write();
            header.state_root = ws.state_root()?;
        }

        let mut block = Block {
            header,
            transactions: included_txs.clone(),
            system_transactions: system_txs.clone(),
            proposer_seal: None,
        };

        // C3: If STARK aggregation is enabled, collect sig batch entries now.
        // G4: ProofTask pushed to backlog AFTER signing so we have the real block hash.
        let stark_entries: Option<Vec<SigBatchEntry>> = if self.stark_aggregation {
            Some(stark_sources::entries_from_txs(&included_txs))
        } else {
            None
        };

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
        self.feed_l2_scheduler_from_settlements(&settled_stark_proofs, block.number());
        consensus.register_fork_choice_block(block_hash, block.header.parent_hash, block.number());

        // Remove included transactions from mempool.
        let tx_hashes: Vec<ShellHash> = included_txs.iter().map(|tx| tx.hash()).collect();
        let pruned = mem_pool.remove_committed_hashes(&tx_hashes);
        if pruned > 0 {
            debug!(
                count = pruned,
                "pruned stale nonce-too-low transactions after production"
            );
        }

        // Update canonical aggregate counters for shell_* stats RPCs.
        block_store.update_chain_totals(
            block.number(),
            included_txs.len() as u64,
            block.header.gas_used,
        )?;

        // Track the new state root for pruning decisions.
        self.record_finalized_state_root(block.number(), block.header.state_root);
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
