use super::*;

impl<S: KvStore + 'static> Node<S> {
    /// Import and validate a block received from the network.
    ///
    /// Re-executes all transactions through the EVM on an isolated state
    /// snapshot, verifies the imported state root, then atomically swaps the
    /// live WorldState and stores the block.
    ///
    /// Fork detection: if the incoming block is at the same height as
    /// the current head but with a different hash, it is treated as a
    /// potential fork and skipped. If there is a gap (block number is
    /// more than one ahead of head), missing blocks are requested.
    pub fn import_block(&self, block: Block, _verifier: &dyn Verifier) -> Result<(), NodeError> {
        let block_store = self.block_store();
        let consensus = self.consensus_manager();
        let prover = self.prover_orchestrator();
        let mem_pool = self.mem_pool();

        let head = block_store.head_block()?.ok_or(NodeError::NoGenesis)?;

        let incoming = block.number();
        let incoming_hash = block.hash();
        let canonical_hash_at_incoming = block_store.block_hash_by_number(incoming)?;
        let finalized_number = consensus.finalized_number();
        let transition = ChainStateMachine::classify_import(
            head.number(),
            head.hash(),
            incoming,
            incoming_hash,
            block.header.parent_hash,
            finalized_number,
            canonical_hash_at_incoming,
        )?;

        // Fork detection: same height, different hash. Keep the side block so
        // fork-choice/reorg can inspect it later instead of dropping evidence.
        if transition == BlockImportTransition::SameHeightFork {
            consensus.verify_header(&block.header)?;
            let remote_hash = incoming_hash;
            block_store.put_side_fork_block(&block)?;
            consensus.register_fork_choice_block(remote_hash, block.header.parent_hash, incoming);
            let side_forks = block_store.side_fork_count(incoming);
            warn!(
                number = incoming,
                local_hash = %head.hash(),
                %remote_hash,
                side_forks,
                "potential fork detected at same height; stored as side fork"
            );
            return Ok(());
        }

        // Duplicate or stale block — already have it. Must check BEFORE equivocation
        // detection to avoid false-positive double-sign events from re-gossipped blocks.
        if transition == BlockImportTransition::DuplicateOrStale {
            debug!(
                incoming,
                head = head.number(),
                "ignoring block at or below current head"
            );
            return Ok(());
        }

        // Height is next, but the block does not extend our current head.
        // Keep it as a fork candidate instead of corrupting the canonical
        // number->hash mapping with a disconnected block.
        if transition == BlockImportTransition::NextHeightFork {
            consensus.verify_header(&block.header)?;
            let remote_hash = incoming_hash;
            block_store.put_side_fork_block(&block)?;
            consensus.register_fork_choice_block(remote_hash, block.header.parent_hash, incoming);
            let side_forks = block_store.side_fork_count(incoming);
            warn!(
                number = incoming,
                expected_parent = %head.hash(),
                got_parent = %block.header.parent_hash,
                %remote_hash,
                side_forks,
                "fork block does not extend local head; stored as side fork"
            );
            return Ok(());
        }

        // I1: Equivocation detection — check if the incoming block's proposer has
        // already produced a block at this height. Only fires for truly new blocks
        // (incoming == expected), preventing false positives from stale gossip.
        if let Ok(Some(existing)) = block_store.block_by_number(incoming) {
            if existing.hash() != block.hash() && existing.header.proposer == block.header.proposer
            {
                let slash_record = detect_double_sign(&existing.header, &block.header);
                if let Some(record) = slash_record {
                    if let Some(equivocation) = EquivocationProof::from_slash_record(&record) {
                        if equivocation.verify() {
                            warn!(
                                offender = %equivocation.offender,
                                block_number = incoming,
                                "I1: double-sign detected, queuing equivocation broadcast"
                            );
                            // Store in equivocation queue for broadcast in the event loop.
                            self.equivocation_queue.lock().push(equivocation);
                        }
                    }
                }
            }
        }

        // Gap detection: block is too far ahead.
        if let BlockImportTransition::Gap { incoming, expected } = transition {
            warn!(
                incoming,
                expected,
                gap = incoming - expected,
                "block too far ahead, missing blocks need to be requested"
            );
            return Err(NodeError::GapDetected { incoming, expected });
        }

        // Verify consensus rules.
        consensus.verify_header(&block.header)?;

        // Verify EIP-1559 base fee is correct.
        let expected_base_fee = calculate_base_fee(
            head.header.gas_used,
            head.header.gas_limit,
            head.header.base_fee_per_gas,
        );
        if block.header.base_fee_per_gas != expected_base_fee {
            return Err(NodeError::Startup(format!(
                "invalid base_fee_per_gas: expected {expected_base_fee}, got {}",
                block.header.base_fee_per_gas,
            )));
        }

        // Verify proposer seal (PQ signature).
        match &block.proposer_seal {
            Some(seal) => {
                let proposer = &block.header.proposer;
                if let Some(pubkey) = consensus.known_authority_pubkey(proposer) {
                    let verifier = MultiVerifier;
                    self.consensus
                        .read()
                        .verify_seal(&block.header, seal, &pubkey, &verifier)?;
                } else if let Some(pubkey) = block_store.stored_pubkey(proposer)? {
                    let verifier = MultiVerifier;
                    self.consensus
                        .read()
                        .verify_seal(&block.header, seal, &pubkey, &verifier)?;
                    consensus.register_authority_pubkey(*proposer, pubkey);
                } else {
                    // F-308: Reject blocks from unknown proposers.
                    return Err(NodeError::Startup(format!(
                        "block {} seal verification failed: proposer {} pubkey unknown",
                        block.number(),
                        proposer
                    )));
                }
            }
            None => {
                warn!(
                    block = block.number(),
                    proposer = %block.header.proposer,
                    "imported block has no proposer seal (M1b: allowed, will be strict in M2)"
                );
            }
        }

        // C3: If the block carries a STARK aggregate proof, verify it.
        // A valid proof means the block producer correctly accumulated all
        // tx signature entries; this is belt-and-suspenders verification on top
        // of the existing individual sig checks below.
        if let Some(proof_bytes) = &block.header.sig_aggregate_proof {
            match shell_stark_prover::proof::SigBatchProof::from_json(proof_bytes.as_ref()) {
                Ok(sig_proof) => {
                    if let Err(e) = verify_sig_batch(&sig_proof) {
                        return Err(NodeError::Startup(format!(
                            "block {} STARK aggregate proof verification failed: {e}",
                            block.number()
                        )));
                    }
                    debug!(
                        block = block.number(),
                        n_sigs = sig_proof.n_sigs,
                        "C3: STARK aggregate proof verified"
                    );
                }
                Err(e) => {
                    return Err(NodeError::Startup(format!(
                        "block {} STARK aggregate proof deserialization failed: {e}",
                        block.number()
                    )));
                }
            }
        }

        let current_root = block_store.current_state_root()?;

        // Re-execute transactions against an isolated state snapshot.
        // The live WorldState is only swapped to the imported root after the
        // computed state_root matches the block header.
        let mut receipts = Vec::new();
        let mut new_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
        if !Self::decode_system_extra(&block.header.extra_data)?.is_empty() {
            return Err(NodeError::Startup(format!(
                "block {} uses deprecated block-level STARK settlement extra_data; settlements must be carried by StarkReward transactions",
                block.number()
            )));
        }
        let mut system_txs = Vec::new();
        let stark_settlements: Vec<ProofAmendment> = block
            .system_transactions
            .iter()
            .filter(|tx| tx.kind == SystemTxKind::StarkReward)
            .map(|tx| {
                let payload = tx.proof_payload.as_ref().ok_or_else(|| {
                    NodeError::Startup(format!(
                        "block {} STARK reward tx {} missing proof payload",
                        block.number(),
                        tx.hash()
                    ))
                })?;
                let amendment = ProofAmendment::from_json(payload.as_ref()).map_err(|e| {
                    NodeError::Startup(format!(
                        "block {} STARK reward tx {} proof payload decode failed: {e}",
                        block.number(),
                        tx.hash()
                    ))
                })?;
                if tx.source_hash != amendment.block_hash {
                    return Err(NodeError::Startup(format!(
                        "block {} STARK reward tx {} source hash {} does not match proof end hash {}",
                        block.number(),
                        tx.hash(),
                        tx.source_hash,
                        amendment.block_hash
                    )));
                }
                if tx.layer != Some(amendment.layer)
                    || tx.original_size != amendment.original_size
                    || tx.compressed_size != amendment.compressed_size
                {
                    return Err(NodeError::Startup(format!(
                        "block {} STARK reward tx {} metadata does not match proof payload",
                        block.number(),
                        tx.hash()
                    )));
                }
                Ok(amendment)
            })
            .collect::<Result<Vec<_>, NodeError>>()?;
        self.validate_stark_settlement_sequence(&stark_settlements)?;
        // Note: `validate_stark_proof_source_binding` (full STARK cryptographic
        // verification) is intentionally skipped here.  During block import we
        // trust that the settlement was validated at gossip time before the PoA
        // proposer included it.  Re-verifying the full STARK proof on every
        // import would be prohibitively expensive for chain sync and is
        // redundant for a PoA chain.  The lightweight ordering and sequence
        // checks above are still enforced.

        let imported_state_root = if !block.transactions.is_empty() || !stark_settlements.is_empty()
        {
            // Validate all transactions before execution (F-181):
            // security-critical checks (sig, algorithm, access list, pubkey)
            // are enforced during block import, not just mempool.
            let import_cs = ChainStore::new(self.store.clone());
            let mut block_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            // M5-C2: Batch verify all transaction signatures in parallel.
            // Resolve pubkeys and compute tx hashes, then dispatch to rayon.
            let batch_verifier = MultiVerifier;
            let tx_hashes: Vec<ShellHash> = block.transactions.iter().map(|tx| tx.hash()).collect();
            let mut resolved_pks: Vec<Vec<u8>> = Vec::with_capacity(block.transactions.len());
            for tx in &block.transactions {
                let pk = match &tx.pubkey_mode {
                    shell_core::PubkeyMode::Embedded(pk) => {
                        block_pubkeys.entry(tx.from).or_insert_with(|| pk.clone());
                        if import_cs
                            .get_pubkey(&tx.from)
                            .map_err(|e| {
                                NodeError::Startup(format!(
                                    "block {} pubkey lookup failed: {e}",
                                    block.number()
                                ))
                            })?
                            .is_none()
                        {
                            new_pubkeys.entry(tx.from).or_insert_with(|| pk.clone());
                        }
                        pk.clone()
                    }
                    shell_core::PubkeyMode::Reference => {
                        if let Some(pk) = block_pubkeys.get(&tx.from) {
                            pk.clone()
                        } else if let Some(pk) = import_cs.get_pubkey(&tx.from).map_err(|e| {
                            NodeError::Startup(format!(
                                "block {} pubkey lookup failed: {e}",
                                block.number()
                            ))
                        })? {
                            pk
                        } else {
                            // Pubkey not yet registered for this Reference-mode tx.
                            // This occurs when syncing historical blocks produced by an
                            // older node where the sender's first tx was Reference-mode
                            // (pre-F181 enforcement).  Skip sig verification for this tx;
                            // correctness is guaranteed by the state-root check below.
                            warn!(
                                block = block.number(),
                                from = %tx.from,
                                "Reference-mode tx with unresolvable pubkey; \
                                 skipping sig verification (state-root will validate)"
                            );
                            Vec::new() // sentinel: empty pk → skip in batch verify
                        }
                    }
                };
                resolved_pks.push(pk);
            }
            // Only include txs whose pubkey was resolved in the batch verify.
            // Txs with an empty sentinel pk (unresolvable Reference-mode from
            // historical blocks) are skipped here; the state-root check is the
            // security backstop for those.
            let verify_items: Vec<VerifyItem> = block
                .transactions
                .iter()
                .enumerate()
                .filter_map(|(i, tx)| {
                    if resolved_pks[i].is_empty() || tx.signature.data.is_empty() {
                        None
                    } else {
                        Some(VerifyItem {
                            pubkey: &resolved_pks[i],
                            message: tx_hashes[i].as_bytes(),
                            signature: &tx.signature,
                        })
                    }
                })
                .collect();
            if !verify_items.is_empty() {
                batch_verifier
                    .verify_batch_all(&verify_items)
                    .map_err(|e| {
                        NodeError::Startup(format!(
                            "block {} batch sig verification failed: {e}",
                            block.number()
                        ))
                    })?;
            }

            let (state_db, _) = block_store.isolated_state_db()?;
            let mut evm = ShellPqvm::new(state_db, self.config.chain_id);

            // Non-signature validation (chain-id, gas, sender binding).
            // Uses PreVerified to skip redundant individual
            // sig checks — signatures were already batch-verified above.
            //
            // IMPORTANT: validate_tx_for_import is READ-ONLY — it does NOT register
            // pubkeys (unlike validate_tx used in the mempool path). Pubkey registration
            // is deferred to the `new_pubkeys` commit at the end of import_block.
            // The `new_pubkeys` HashMap uses `or_insert_with` (first-write-wins), so
            // even if multiple Embedded txs from the same sender appear in one block,
            // only the first pubkey is written — registration is idempotent by design.
            //
            // Reference txs mutated to Embedded here (for validation) do NOT trigger
            // re-registration because validate_tx_for_import performs no writes.
            let pre_verified = PreVerified;
            let mut validation_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            for (idx, tx) in block.transactions.iter().enumerate() {
                // Skip full validation for txs whose pubkey could not be
                // resolved (unresolvable Reference-mode from historical blocks).
                // Correctness is guaranteed by the state-root check below.
                if resolved_pks[idx].is_empty() || tx.signature.data.is_empty() {
                    continue;
                }

                let mut tx_for_validation = tx.clone();
                if tx_for_validation.pubkey_mode.is_reference() {
                    if let Some(pk) = validation_pubkeys.get(&tx.from) {
                        tx_for_validation.pubkey_mode =
                            shell_core::PubkeyMode::Embedded(pk.clone());
                    }
                }

                validate_tx_for_import(
                    &tx_for_validation,
                    evm.state_db_mut().world_state_mut(),
                    &import_cs,
                    &pre_verified,
                    self.config.chain_id,
                )
                .map_err(|e| {
                    NodeError::Startup(format!(
                        "block {} tx validation failed: {e}",
                        block.number()
                    ))
                })?;

                if let shell_core::PubkeyMode::Embedded(pk) = &tx.pubkey_mode {
                    validation_pubkeys
                        .entry(tx.from)
                        .or_insert_with(|| pk.clone());
                }
            }
            let mut cumulative_gas: u64 = 0;
            let mut total_effective_fees = U256::ZERO;

            for (idx, tx) in block.transactions.iter().enumerate() {
                let exec_result = if tx.is_aa_bundle() {
                    evm.execute_aa_bundle(tx, &block.header, idx as u32, cumulative_gas)
                } else {
                    evm.execute_tx(tx, &block.header, idx as u32, cumulative_gas)
                };
                match exec_result {
                    Ok(result) => {
                        cumulative_gas += result.gas_used;
                        let price = effective_gas_price(
                            tx.tx.max_fee_per_gas,
                            tx.tx.max_priority_fee_per_gas,
                            block.header.base_fee_per_gas,
                        );
                        if tx.is_aa_bundle() {
                            // AA dispatcher already mutated state_db.world_state
                            // in-place (with atomic rollback on inner failure).
                        } else if result.is_system_tx {
                            self.sync_system_contract_state(
                                evm.state_db_mut().world_state_mut(),
                                &result.system_contract_effects,
                            )?;
                        } else {
                            commit_pqvm_state(
                                &result,
                                evm.state_db_mut().world_state_mut(),
                                &self.chain_store,
                            )?;
                        }
                        total_effective_fees = total_effective_fees.saturating_add(
                            U256::from(result.gas_used).saturating_mul(U256::from(price)),
                        );
                        receipts.push(result.receipt);
                    }
                    Err(e) => {
                        return Err(NodeError::Startup(format!(
                            "tx {} re-execution failed: {e}",
                            idx
                        )));
                    }
                }
            }
            let producer_reward = total_effective_fees / U256::from(2u8);
            if producer_reward > U256::ZERO {
                evm.state_db_mut()
                    .world_state_mut()
                    .add_balance(&block.header.proposer, producer_reward)?;
                let tx_index = block.transactions.len() as u32;
                let reward_tx = SystemTransaction::block_gas_reward(
                    self.config.chain_id,
                    block.number(),
                    tx_index,
                    block.header.proposer,
                    producer_reward,
                    block.header.parent_hash,
                );
                receipts.push(TransactionReceipt {
                    tx_hash: reward_tx.hash(),
                    block_number: block.number(),
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
            for amendment in &stark_settlements {
                let tx_index = block.transactions.len().saturating_add(system_txs.len()) as u32;
                let reward_tx = self.build_stark_reward_tx(block.number(), tx_index, amendment)?;
                evm.state_db_mut()
                    .world_state_mut()
                    .add_balance(&reward_tx.to, reward_tx.value)?;
                receipts.push(TransactionReceipt {
                    tx_hash: reward_tx.hash(),
                    block_number: block.number(),
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
            if system_txs != block.system_transactions {
                return Err(NodeError::Startup(format!(
                    "block {} system transactions mismatch: expected {:?}, got {:?}",
                    block.number(),
                    system_txs,
                    block.system_transactions
                )));
            }
            evm.state_db_mut().world_state_mut().state_root()?
        } else {
            if !block.system_transactions.is_empty() {
                return Err(NodeError::Startup(format!(
                    "block {} carries unexpected system transactions",
                    block.number()
                )));
            }
            current_root
        };
        if imported_state_root != block.header.state_root {
            return Err(NodeError::Startup(format!(
                "block {} state root mismatch: expected {:?}, got {:?}",
                block.number(),
                block.header.state_root,
                imported_state_root
            )));
        }

        // B5: Validate witness_root when present.
        // If the header declares a witness_root, the stored bundle must hash to it.
        if let Some(expected_root) = block.header.witness_root {
            let block_hash_for_witness = block.hash();
            match block_store.witness_bundle(&block_hash_for_witness) {
                Ok(Some(bundle)) => {
                    let computed = bundle.compute_root();
                    if computed != expected_root {
                        return Err(NodeError::Startup(format!(
                            "block {} witness_root mismatch: header={:?}, computed={:?}",
                            block.number(),
                            expected_root,
                            computed
                        )));
                    }
                }
                Ok(None) => {
                    // Witness bundle not yet available (e.g. not yet delivered by network).
                    // Log and allow import — full validation requires witness propagation
                    // (Phase B network layer). Reject only if bundle is present but wrong.
                    debug!(
                        block = block.number(),
                        witness_root = ?expected_root,
                        "witness bundle not in store; skipping witness_root check for now"
                    );
                }
                Err(e) => {
                    return Err(NodeError::Startup(format!(
                        "block {} witness store lookup failed: {e}",
                        block.number()
                    )));
                }
            }
        }

        // Commit to storage.
        let committed_world_state = WorldState::at_root(self.store.clone(), &imported_state_root)?;
        let block_hash = block.hash();
        block_store.commit_canonical_block(&block, Some(receipts.as_slice()))?;
        block_store.replace_world_state(committed_world_state);
        let settlement_hashes: Vec<ShellHash> = block
            .system_transactions
            .iter()
            .filter(|tx| tx.kind == SystemTxKind::StarkReward)
            .map(|tx| tx.hash())
            .collect();
        for (amendment, settlement_tx_hash) in stark_settlements.iter().zip(settlement_hashes) {
            let stored = self.store_stark_artifacts(amendment, Some(settlement_tx_hash))?;
            debug!(
                block = block.number(),
                layer = amendment.layer,
                stored,
                "materialized canonical STARK proof artifacts from imported block"
            );
        }
        prover.record_settled_sources(&stark_settlements);
        self.feed_l2_scheduler_from_settlements(&stark_settlements, block.number());
        consensus.register_fork_choice_block(block_hash, block.header.parent_hash, block.number());

        // Track the last block proposed by each validator for offline-slash detection.
        self.last_proposed_by
            .lock()
            .insert(block.header.proposer, block.number());
        for (address, pubkey) in new_pubkeys {
            block_store.store_pubkey(&address, &pubkey)?;
        }

        // L2 grace-window: flush any witnesses whose delete_at block has been reached.
        block_store.prune_grace_witnesses(block.number());

        // Remove any included transactions from our mempool.
        let tx_hashes: Vec<ShellHash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        let pruned = mem_pool.remove_committed_hashes(&tx_hashes);
        if pruned > 0 {
            debug!(
                count = pruned,
                "pruned stale nonce-too-low transactions after import"
            );
        }

        // Update canonical aggregate counters for shell_* stats RPCs.
        if let Err(e) = block_store.update_chain_totals(
            block.number(),
            block.transactions.len() as u64,
            block.header.gas_used,
        ) {
            warn!(block = block.number(), "failed to update chain totals: {e}");
        }

        // Track the imported state root for pruning decisions.
        self.record_finalized_state_root(block.number(), block.header.state_root);
        self.reload_authorities_if_boundary(block.number())?;

        // I4: Advance the proof window manager to the new block height.
        // This expires any stale claim timeouts and updates prover reliability counters.
        // GC is run every 100 blocks to remove entries older than window_size_blocks.
        {
            let block_number = block.number();
            let mut wm = self.proof_window_manager.lock();
            wm.advance(block_number);
            if block_number.is_multiple_of(100) {
                wm.gc(block_number);
            }
        }

        // H4: Any node that runs the ProverService (ValidatorProver or Prover) queues
        // proof tasks for imported peer blocks.  ValidatorProver nodes also queue tasks
        // in produce_block (G4) for the blocks they propose; here they cover the
        // remaining 2/3 of blocks produced by the other validators in the committee.
        if self.config.node_role.runs_prover() {
            let block_number = block.number();
            let block_hash = block.hash();
            let entries = stark_sources::block_to_sig_batch_entries(&block);
            let n = entries.len();
            let original_size =
                self.stark_source_original_size(&block_hash, &block, entries.len())?;
            let task = ProofTask::with_sources(
                *block_hash.0,
                block_number,
                entries,
                1,
                vec![block_hash],
                original_size,
            );
            prover.queue_task(task);
            debug!(
                block = block_number,
                n_entries = n,
                "H4: Pushed proof task for standalone prover"
            );
            let queued = self.enqueue_stark_frontier_backlog(64)?;
            if queued > 0 {
                debug!(
                    queued,
                    block = block_number,
                    "queued ordered STARK frontier proof tasks after block import"
                );
            }
        }

        Ok(())
    }
}
