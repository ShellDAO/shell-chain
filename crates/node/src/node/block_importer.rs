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
        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;

        let expected = head.number() + 1;
        let incoming = block.number();

        // Fork detection: same height, different hash.
        if incoming == head.number() && block.hash() != head.hash() {
            warn!(
                number = incoming,
                local_hash = %head.hash(),
                remote_hash = %block.hash(),
                "potential fork detected at same height, skipping import"
            );
            return Ok(());
        }

        // I1: Equivocation detection — check if the incoming block's proposer has
        // already produced a block at this height. If so, this is a double-sign event.
        // We detect by comparing against the block we have at `incoming` number.
        if let Ok(Some(existing)) = self.chain_store.get_block_by_number(incoming) {
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

        // Duplicate of current head — already have it.
        if incoming <= head.number() {
            debug!(
                incoming,
                head = head.number(),
                "ignoring block at or below current head"
            );
            return Ok(());
        }

        // Gap detection: block is too far ahead.
        if incoming > expected {
            warn!(
                incoming,
                expected,
                gap = incoming - expected,
                "block too far ahead, missing blocks need to be requested"
            );
            return Err(NodeError::GapDetected { incoming, expected });
        }

        // Verify consensus rules.
        self.consensus.read().verify_header(&block.header)?;

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
                let known = self.known_authorities.read();
                if let Some(pubkey) = known.get(proposer) {
                    let verifier = MultiVerifier;
                    self.consensus
                        .read()
                        .verify_seal(&block.header, seal, pubkey, &verifier)?;
                } else {
                    // Try chain store as fallback.
                    drop(known);
                    if let Ok(Some(pubkey)) = self.chain_store.get_pubkey(proposer) {
                        let verifier = MultiVerifier;
                        self.consensus.read().verify_seal(
                            &block.header,
                            seal,
                            &pubkey,
                            &verifier,
                        )?;
                        // Cache for future lookups.
                        self.known_authorities.write().insert(*proposer, pubkey);
                    } else {
                        // F-308: Reject blocks from unknown proposers.
                        return Err(NodeError::Startup(format!(
                            "block {} seal verification failed: proposer {} pubkey unknown",
                            block.number(),
                            proposer
                        )));
                    }
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

        let current_root = {
            let mut ws = self.world_state.write();
            ws.state_root()?
        };

        // Re-execute transactions against an isolated state snapshot.
        // The live WorldState is only swapped to the imported root after the
        // computed state_root matches the block header.
        let mut receipts = Vec::new();
        let mut new_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
        let imported_state_root = if !block.transactions.is_empty() {
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
                        } else {
                            import_cs
                                .get_pubkey(&tx.from)
                                .map_err(|e| {
                                    NodeError::Startup(format!(
                                        "block {} pubkey lookup failed: {e}",
                                        block.number()
                                    ))
                                })?
                                .ok_or_else(|| {
                                    NodeError::Startup(format!(
                                        "block {} missing pubkey for {}",
                                        block.number(),
                                        tx.from
                                    ))
                                })?
                        }
                    }
                };
                resolved_pks.push(pk);
            }
            let verify_items: Vec<VerifyItem> = block
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| VerifyItem {
                    pubkey: &resolved_pks[i],
                    message: tx_hashes[i].as_bytes(),
                    signature: &tx.signature,
                })
                .collect();
            batch_verifier
                .verify_batch_all(&verify_items)
                .map_err(|e| {
                    NodeError::Startup(format!(
                        "block {} batch sig verification failed: {e}",
                        block.number()
                    ))
                })?;

            let ws = WorldState::at_root(self.store.clone(), &current_root)?;
            let cs = ChainStore::new(self.store.clone());
            let state_db = ShellStateDb::new(ws, cs);
            let mut evm = ShellEvm::new(state_db, self.config.chain_id);

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
            for tx in &block.transactions {
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

            for (idx, tx) in block.transactions.iter().enumerate() {
                let exec_result = if tx.is_aa_bundle() {
                    evm.execute_aa_bundle(tx, &block.header, idx as u32, cumulative_gas)
                } else {
                    evm.execute_tx(tx, &block.header, idx as u32, cumulative_gas)
                };
                match exec_result {
                    Ok(result) => {
                        cumulative_gas += result.gas_used;
                        receipts.push(result.receipt);

                        if tx.is_aa_bundle() {
                            // AA dispatcher already mutated state_db.world_state
                            // in-place (with atomic rollback on inner failure).
                        } else if result.is_system_tx {
                            self.sync_system_contract_state(
                                evm.state_db_mut().world_state_mut(),
                                &result.system_contract_effects,
                            )?;
                        } else {
                            commit_evm_state(
                                &result.state_changes,
                                evm.state_db_mut().world_state_mut(),
                                &self.chain_store,
                            )?;
                        }
                    }
                    Err(e) => {
                        return Err(NodeError::Startup(format!(
                            "tx {} re-execution failed: {e}",
                            idx
                        )));
                    }
                }
            }
            evm.state_db_mut().world_state_mut().state_root()?
        } else {
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
            match self.witness_store.get_bundle(&block_hash_for_witness) {
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

        let committed_world_state = WorldState::at_root(self.store.clone(), &imported_state_root)?;
        {
            let mut live_ws = self.world_state.write();
            *live_ws = committed_world_state;
        }

        // Commit to storage.
        let block_hash = block.hash();
        self.chain_store.put_block(&block)?;
        if !receipts.is_empty() {
            self.chain_store.put_receipts(&block_hash, &receipts)?;
        }
        self.chain_store
            .set_canonical(block.number(), &block_hash)?;
        self.chain_store.set_head(&block_hash)?;
        for (address, pubkey) in new_pubkeys {
            self.chain_store.put_pubkey(&address, &pubkey)?;
        }

        // L2 grace-window: flush any witnesses whose delete_at block has been reached.
        {
            let current_head = block.number();
            let mut grace_map = self.pending_grace_deletes.lock();
            grace_map.retain(|hash, delete_at| {
                if current_head >= *delete_at {
                    match self.chain_store.delete_witness_bundle(hash) {
                        Ok(()) => info!(
                            block = *delete_at,
                            "L2: grace-window expired, witness bundle deleted"
                        ),
                        Err(e) => warn!(block = *delete_at, "L2: grace-window delete failed: {e}"),
                    }
                    false // remove from map
                } else {
                    true // keep pending
                }
            });
        }

        // Remove any included transactions from our mempool.
        let tx_hashes: Vec<ShellHash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        self.tx_pool.remove_batch(&tx_hashes);

        // Update global transaction counter for shell_transactionCount RPC.
        let imported_tx_count = block.transactions.len() as u64;
        if imported_tx_count > 0 {
            let _ = self.chain_store.increment_tx_count(imported_tx_count);
        }

        // Track the imported state root for pruning decisions.
        self.record_finalized_state_root(block.number(), block.header.state_root);

        // I4: Advance the proof window manager to the new block height.
        // This expires any stale claim timeouts and updates prover reliability counters.
        // GC is run every 100 blocks to remove entries older than window_size_blocks.
        {
            let block_number = block.number();
            let mut wm = self.proof_window_manager.lock();
            wm.advance(block_number);
            if block_number % 100 == 0 {
                wm.gc(block_number);
            }
        }

        // H4: Standalone Prover node — extract sig batch entries from imported block
        // and push them to the proof backlog for async proving.
        // Validators handle this in produce_block (G4); Prover nodes do it here.
        if self.config.node_role == NodeRole::Prover {
            let block_number = block.number();
            let block_hash = block.hash();
            let entries: Vec<shell_stark_prover::prover::SigBatchEntry> = block
                .transactions
                .iter()
                .map(|tx| {
                    let tx_hash = tx.hash();
                    let sender = tx.sender();
                    let mut pk_hash = [0u8; 32];
                    pk_hash[..20].copy_from_slice(sender.0.as_slice());
                    shell_stark_prover::prover::SigBatchEntry {
                        msg_hash: *tx_hash.0,
                        pk_hash,
                    }
                })
                .collect();
            if !entries.is_empty() {
                let n = entries.len();
                let task = ProofTask {
                    block_hash: *block_hash.0,
                    block_number,
                    entries,
                };
                self.proof_backlog.lock().push(task);
                debug!(
                    block = block_number,
                    n_entries = n,
                    "H4: Pushed proof task for standalone prover"
                );
            }
        }

        Ok(())
    }
}
