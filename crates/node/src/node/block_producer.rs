use super::*;

impl<S: KvStore + 'static> Node<S> {
    /// Produce a block from pending mempool transactions.
    ///
    /// Collects up to `max_txs` transactions, executes each through the EVM,
    /// commits state changes after every transaction (so subsequent txs see
    /// prior updates), assembles a block, and commits it to storage.
    pub fn produce_block(&self, signer: &dyn Signer, max_txs: usize) -> Result<Block, NodeError> {
        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let head_hash = head.hash();
        let next_number = head.number() + 1;

        let proposer_addr = self.config.proposer_address.ok_or(NodeError::NotProposer)?;

        if !self
            .consensus
            .read()
            .is_proposer(next_number, &proposer_addr)
        {
            return Err(NodeError::NotProposer);
        }

        // Collect pending transactions from mempool.
        let candidates = self.tx_pool.pending(max_txs);

        // Create an isolated EVM instance at the current state root.
        let current_root = {
            let mut ws = self.world_state.write();
            ws.state_root()?
        };
        let ws = WorldState::at_root(self.store.clone(), &current_root)?;
        let cs = ChainStore::new(self.store.clone());
        let state_db = ShellStateDb::new(ws, cs);
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

        let mut included_txs: Vec<SignedTransaction> = Vec::new();
        let mut receipts = Vec::new();
        let mut cumulative_gas: u64 = 0;

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

            match evm.execute_tx(tx, &header, idx as u32, cumulative_gas) {
                Ok(result) => {
                    cumulative_gas += result.gas_used;
                    receipts.push(result.receipt);
                    included_txs.push(tx.clone());

                    if result.is_system_tx {
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
            header.state_root = ws.state_root().unwrap_or_default();
        }

        let mut block = Block {
            header,
            transactions: included_txs.clone(),
            proposer_seal: None,
        };

        // C3: If STARK aggregation is enabled, generate a batch commitment proof
        // over all transactions that carry embedded pubkeys (the source of bloat).
        // G4: Collect signature entries and push to the proof backlog for async proving.
        // Block production is no longer blocked waiting for a STARK proof.
        // The background ProverService will generate the proof and store a ProofAmendment.
        if self.stark_aggregation {
            let entries: Vec<SigBatchEntry> = included_txs
                .iter()
                .filter_map(|tx| {
                    if let shell_core::PubkeyMode::Embedded(ref pk) = tx.pubkey_mode {
                        let mut msg_hash = [0u8; 32];
                        msg_hash.copy_from_slice(tx.hash().as_bytes());
                        let mut pk_hash = [0u8; 32];
                        let copy_len = pk.len().min(32);
                        pk_hash[..copy_len].copy_from_slice(&pk[..copy_len]);
                        Some(SigBatchEntry { msg_hash, pk_hash })
                    } else {
                        None
                    }
                })
                .collect();

            if !entries.is_empty() {
                let block_num = block.header.number;
                let mut hash_bytes = [0u8; 32];
                // Use a placeholder hash — real hash assigned after signing below.
                // The backlog task is updated by the ProverService on pop.
                hash_bytes[..8].copy_from_slice(&block_num.to_be_bytes());
                let mut backlog = self.proof_backlog.lock();
                backlog.push(ProofTask::new(hash_bytes, block_num, entries));
                debug!(
                    block = block_num,
                    "G4: proof task queued in backlog (async proving)"
                );
            }
        }

        // Sign the block with the proposer's key.
        self.consensus.read().sign_block(&mut block, signer)?;

        // Register the signer's pubkey so we can verify our own blocks on re-import.
        self.register_authority_pubkey(proposer_addr, signer.public_key().to_vec());

        // Commit to storage.
        let block_hash = block.hash();
        self.chain_store.put_block(&block)?;
        self.chain_store.put_receipts(&block_hash, &receipts)?;
        self.chain_store
            .set_canonical(block.number(), &block_hash)?;
        self.chain_store.set_head(&block_hash)?;

        // Remove included transactions from mempool.
        let tx_hashes: Vec<ShellHash> = included_txs.iter().map(|tx| tx.hash()).collect();
        self.tx_pool.remove_batch(&tx_hashes);

        // Update global transaction counter for shell_transactionCount RPC.
        let new_tx_count = included_txs.len() as u64;
        if new_tx_count > 0 {
            self.chain_store.increment_tx_count(new_tx_count)?;
        }

        // Track the new state root for pruning decisions.
        self.record_finalized_state_root(block.number(), block.header.state_root);

        Ok(block)
    }
}
