use super::*;
use std::borrow::Cow;

fn tx_for_import_validation<'a, S: KvStore>(
    tx: &'a SignedTransaction,
    validation_pubkeys: &HashMap<Address, Vec<u8>>,
    chain_store: &ChainStore<S>,
) -> Result<Cow<'a, SignedTransaction>, shell_storage::StorageError> {
    let shell_core::PubkeyMode::Reference = &tx.pubkey_mode else {
        return Ok(Cow::Borrowed(tx));
    };
    if chain_store.get_pubkey(&tx.from)?.is_some() {
        return Ok(Cow::Borrowed(tx));
    }
    let Some(pubkey) = validation_pubkeys.get(&tx.from) else {
        return Ok(Cow::Borrowed(tx));
    };

    let mut resolved = tx.clone();
    resolved.pubkey_mode = shell_core::PubkeyMode::Embedded(pubkey.clone());
    Ok(Cow::Owned(resolved))
}

fn validate_import_tx_in_current_state<S: KvStore + 'static>(
    tx: &SignedTransaction,
    validation_pubkeys: &HashMap<Address, Vec<u8>>,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    chain_id: u64,
    validation_header: &BlockHeader,
) -> Result<(), TxValidationError> {
    let tx_for_validation = tx_for_import_validation(tx, validation_pubkeys, chain_store)?;
    validate_tx_for_import_at_block(
        tx_for_validation.as_ref(),
        world_state,
        chain_store,
        &MultiVerifier,
        chain_id,
        None,
        validation_header,
    )
}

fn batch_signing_pubkey(
    block_number: u64,
    tx: &SignedTransaction,
    root_pubkey: &[u8],
) -> Result<Vec<u8>, NodeError> {
    if tx.signature.data.is_empty() {
        return Err(NodeError::Startup(format!(
            "block {} tx {} has empty signature",
            block_number,
            tx.hash()
        )));
    }

    let Some(session_auth) = tx
        .aa_bundle()
        .and_then(|bundle| bundle.session_auth.as_ref())
    else {
        return Ok(root_pubkey.to_vec());
    };

    if infer_signature_type_from_address(root_pubkey, &tx.from).is_none() {
        return Err(NodeError::Startup(format!(
            "block {} tx {} sender {} does not match resolved root pubkey",
            block_number,
            tx.hash(),
            tx.from,
        )));
    }
    if tx.signature.sig_type.as_u8() != session_auth.session_algo
        || tx.signature.data.as_slice() != session_auth.session_signature.as_ref()
    {
        return Err(NodeError::Startup(format!(
            "block {} tx {} session signature does not match outer signature",
            block_number,
            tx.hash(),
        )));
    }
    let auth_hash = session_auth.auth_hash(tx.tx.chain_id);
    let root_valid = ALLOWED_ALGORITHMS.iter().copied().any(|algorithm| {
        let signature = PQSignature::new(algorithm, session_auth.root_signature.as_ref().to_vec());
        MultiVerifier
            .verify(root_pubkey, auth_hash.as_bytes(), &signature)
            .unwrap_or(false)
    });
    if !root_valid {
        return Err(NodeError::Startup(format!(
            "block {} tx {} session root signature is invalid",
            block_number,
            tx.hash(),
        )));
    }

    Ok(session_auth.session_pubkey.as_ref().to_vec())
}

impl<S: KvStore + 'static> Node<S> {
    fn invalid_fork(block_hash: ShellHash, error: impl std::fmt::Display) -> NodeError {
        NodeError::InvalidFork {
            block_hash,
            reason: error.to_string(),
        }
    }

    fn classify_fork_error(block_hash: ShellHash, error: NodeError) -> NodeError {
        match error {
            NodeError::Storage(_) | NodeError::Network(_) => error,
            NodeError::Pqvm(
                ExecutorError::Storage(_) | ExecutorError::StateDb(StateDbError::Storage(_)),
            ) => error,
            error => Self::invalid_fork(block_hash, error),
        }
    }

    fn wall_clock_secs_for_import() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn parent_for_import(&self, block: &Block) -> Result<Block, NodeError> {
        if block.number() == 0 {
            return Err(NodeError::Startup(
                "network import of genesis block is not supported".into(),
            ));
        }
        self.chain_store
            .get_block_by_hash(&block.header.parent_hash)?
            .ok_or_else(|| {
                NodeError::Startup(format!(
                    "parent block {} not found for imported block {}",
                    block.header.parent_hash,
                    block.number()
                ))
            })
    }

    fn verify_import_consensus(
        &self,
        block: &Block,
        parent: &Block,
        finalized_import: bool,
    ) -> Result<(), NodeError> {
        let max_transactions = self.config.network_type.default_params().max_tx_per_block;
        if block.transactions.len() > max_transactions {
            return Err(NodeError::Startup(format!(
                "block {} contains {} transactions, exceeding the network limit of {}",
                block.number(),
                block.transactions.len(),
                max_transactions,
            )));
        }

        let seal = block.proposer_seal.as_ref().ok_or_else(|| {
            NodeError::Startup(format!("block {} missing proposer seal", block.number()))
        })?;

        {
            let consensus = self.consensus.read();
            if finalized_import {
                consensus.verify_header_for_finalized_import(&block.header, &parent.header)?;
            } else {
                consensus.verify_header(&block.header)?;
            }
            let cfg = consensus.poa_config();
            let max_allowed =
                Self::wall_clock_secs_for_import().saturating_add(cfg.max_future_secs);
            if block.header.timestamp > max_allowed {
                return Err(NodeError::Startup(format!(
                    "block {} timestamp {} exceeds current time + max_future {}",
                    block.number(),
                    block.header.timestamp,
                    cfg.max_future_secs
                )));
            }
            if block.header.timestamp < parent.header.timestamp.saturating_add(cfg.block_time_secs)
            {
                return Err(NodeError::Startup(format!(
                    "block {} timestamp {} < parent {} + block_time {}",
                    block.number(),
                    block.header.timestamp,
                    parent.header.timestamp,
                    cfg.block_time_secs
                )));
            }
            let expected_number = ChainStateMachine::next_block_number(parent.header.number)?;
            if block.header.number != expected_number {
                return Err(NodeError::Startup(format!(
                    "block number {} != parent {} + 1",
                    block.header.number, parent.header.number
                )));
            }
            if block.header.parent_hash != parent.hash() {
                return Err(NodeError::Startup(
                    "parent_hash does not match parent block".into(),
                ));
            }
        }

        let proposer = &block.header.proposer;
        let pubkey = self.authority_pubkey(proposer)?.ok_or_else(|| {
            NodeError::Startup(format!(
                "block {} seal verification failed: proposer {} pubkey unknown",
                block.number(),
                proposer
            ))
        })?;

        let verifier = MultiVerifier;
        self.consensus
            .read()
            .verify_seal(&block.header, seal, &pubkey, &verifier)?;
        self.known_authorities
            .write()
            .entry(*proposer)
            .or_insert(pubkey);
        Ok(())
    }

    pub(super) fn authority_pubkey(
        &self,
        authority: &Address,
    ) -> Result<Option<Vec<u8>>, NodeError> {
        if let Some(pubkey) = self.known_authorities.read().get(authority).cloned() {
            return Ok(Some(pubkey));
        }
        Ok(self.chain_store.get_pubkey(authority)?)
    }

    fn queue_signed_equivocation_if_valid(
        &self,
        existing: &Block,
        candidate: &Block,
    ) -> Result<(), NodeError> {
        let Some(equivocation) = EquivocationProof::from_blocks(existing, candidate) else {
            return Ok(());
        };
        let Some(pubkey) = self.authority_pubkey(&equivocation.offender)? else {
            warn!(
                offender = %equivocation.offender,
                block_number = equivocation.header_a.number,
                "I1: double-sign candidate ignored because offender pubkey is unknown"
            );
            return Ok(());
        };
        let verifier = MultiVerifier;
        if !equivocation.verify_signed(&pubkey, &verifier) {
            warn!(
                offender = %equivocation.offender,
                block_number = equivocation.header_a.number,
                "I1: double-sign candidate ignored because proposer seals do not verify"
            );
            return Ok(());
        }
        warn!(
            offender = %equivocation.offender,
            block_number = equivocation.header_a.number,
            "I1: signed double-sign detected, queuing equivocation broadcast"
        );
        self.equivocation_queue.lock().push(equivocation);
        Ok(())
    }

    fn verify_incoming_witness_root(&self, block: &Block) -> Result<(), NodeError> {
        let Some(expected_root) = block.header.witness_root else {
            return Ok(());
        };
        let computed = WitnessBundle::compute_root_from_transactions(&block.transactions);
        if computed != expected_root {
            return Err(NodeError::Startup(format!(
                "block {} witness_root mismatch: header={:?}, computed={:?}",
                block.number(),
                expected_root,
                computed
            )));
        }
        Ok(())
    }

    fn verify_import_sig_aggregate_proof(&self, block: &Block) -> Result<(), NodeError> {
        let Some(proof_bytes) = &block.header.sig_aggregate_proof else {
            return Ok(());
        };
        let sig_proof =
            match shell_stark_prover::proof::SigBatchProof::from_json(proof_bytes.as_ref()) {
                Ok(sig_proof) => sig_proof,
                Err(error) => {
                    return Err(NodeError::Startup(format!(
                        "block {} STARK aggregate proof deserialization failed: {error}",
                        block.number()
                    )));
                }
            };
        if sig_proof.has_proof() {
            verify_sig_batch(&sig_proof).map_err(|error| {
                NodeError::Startup(format!(
                    "block {} STARK aggregate proof verification failed: {error}",
                    block.number()
                ))
            })?;
            debug!(
                block = block.number(),
                n_sigs = sig_proof.n_sigs,
                "C3: STARK aggregate proof verified"
            );
        } else {
            debug!(
                block = block.number(),
                n_sigs = sig_proof.n_sigs,
                "C3: commitment-only sig_aggregate_proof accepted; full proof pending ProofAmendment"
            );
        }
        Ok(())
    }

    fn verify_import_logs_bloom(
        &self,
        block: &Block,
        receipts: &[TransactionReceipt],
    ) -> Result<(), NodeError> {
        let mut expected = [0u8; shell_pqvm::bloom::BLOOM_SIZE];
        for receipt in receipts {
            for (combined, byte) in expected.iter_mut().zip(receipt.logs_bloom.as_ref().iter()) {
                *combined |= *byte;
            }
        }

        let actual = block.header.logs_bloom.as_ref();
        let legacy_empty = actual.is_empty() && expected.iter().all(|byte| *byte == 0);
        if !legacy_empty && actual != expected {
            return Err(NodeError::Startup(format!(
                "block {} logs_bloom mismatch",
                block.number()
            )));
        }
        Ok(())
    }

    fn validate_side_fork_transactions(
        &self,
        block: &Block,
        parent: &Block,
    ) -> Result<(), NodeError> {
        let import_store = Arc::new(shell_storage::OverlayStore::new(self.store.clone()));
        let import_cs = ChainStore::new(import_store.clone());
        import_cs.set_head(&parent.hash())?;
        let mut world_state = WorldState::at_root(import_store, &parent.header.state_root)?;
        let verifier = MultiVerifier;
        let mut validation_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
        let mut validation_nonces: HashMap<Address, u64> = HashMap::new();

        for tx in &block.transactions {
            let tx_for_validation = tx_for_import_validation(tx, &validation_pubkeys, &import_cs)?;
            let expected_nonce = match validation_nonces.get(&tx.from) {
                Some(next_nonce) => *next_nonce,
                None => world_state.get_nonce(&tx.from)?,
            };

            validate_tx_for_import_at_block(
                tx_for_validation.as_ref(),
                &mut world_state,
                &import_cs,
                &verifier,
                self.config.chain_id,
                Some(expected_nonce),
                &block.header,
            )
            .map_err(|error| {
                NodeError::Startup(format!(
                    "block {} side-fork tx validation failed: {error}",
                    block.number()
                ))
            })?;

            let next_nonce = expected_nonce.checked_add(1).ok_or_else(|| {
                NodeError::Startup(format!(
                    "block {} side-fork tx validation exhausted nonce space for {}",
                    block.number(),
                    tx.from
                ))
            })?;
            validation_nonces.insert(tx.from, next_nonce);

            if let shell_core::PubkeyMode::Embedded(pubkey) = &tx.pubkey_mode {
                validation_pubkeys
                    .entry(tx.from)
                    .or_insert_with(|| pubkey.clone());
            }
        }

        Ok(())
    }

    fn verify_import_economics(&self, block: &Block, parent: &Block) -> Result<(), NodeError> {
        let expected_base_fee = calculate_base_fee(
            parent.header.gas_used,
            parent.header.gas_limit,
            parent.header.base_fee_per_gas,
        );
        if block.header.base_fee_per_gas != expected_base_fee {
            return Err(NodeError::Startup(format!(
                "invalid base_fee_per_gas: expected {expected_base_fee}, got {}",
                block.header.base_fee_per_gas,
            )));
        }

        let expected_excess_blob_gas =
            calc_excess_blob_gas(parent.header.excess_blob_gas, parent.header.blob_gas_used);
        if block.header.excess_blob_gas != expected_excess_blob_gas {
            return Err(NodeError::Startup(format!(
                "invalid excess_blob_gas: expected {expected_excess_blob_gas}, got {}",
                block.header.excess_blob_gas,
            )));
        }

        let mut expected_blob_gas_used = 0u64;
        let blob_base_fee = calc_blob_gas_price(expected_excess_blob_gas);
        for (idx, tx) in block.transactions.iter().enumerate() {
            expected_blob_gas_used =
                checked_cumulative_blob_gas(expected_blob_gas_used, tx.tx.blob_gas()).ok_or_else(
                    || {
                        NodeError::Startup(format!(
                            "block {} tx {} exceeds maximum blob gas {}",
                            block.number(),
                            idx,
                            MAX_BLOB_GAS_PER_BLOCK,
                        ))
                    },
                )?;
            if tx.tx.tx_type == 3 && tx.tx.max_fee_per_blob_gas.unwrap_or_default() < blob_base_fee
            {
                return Err(NodeError::Startup(format!(
                    "block {} tx {} max fee per blob gas is below blob base fee {}",
                    block.number(),
                    idx,
                    blob_base_fee,
                )));
            }
        }
        if block.header.blob_gas_used != expected_blob_gas_used {
            return Err(NodeError::Startup(format!(
                "block {} blob_gas_used mismatch: expected {}, got {}",
                block.number(),
                expected_blob_gas_used,
                block.header.blob_gas_used,
            )));
        }

        Ok(())
    }

    fn replay_preferred_fork_block(
        &self,
        block: &Block,
        parent_state_root: ShellHash,
        replay_store: Arc<shell_storage::OverlayStore<S>>,
    ) -> Result<(Vec<TransactionReceipt>, Vec<ProofAmendment>), NodeError> {
        let replay_cs = ChainStore::new(replay_store.clone());
        let metadata_checkpoint = replay_cs.address_metadata_checkpoint()?;
        if !Self::decode_system_extra(&block.header.extra_data)
            .map_err(|error| Self::classify_fork_error(block.hash(), error))?
            .is_empty()
        {
            return Err(Self::invalid_fork(
                block.hash(),
                format!(
                    "block {} uses deprecated block-level STARK settlement extra_data",
                    block.number()
                ),
            ));
        }

        let stark_settlements = block
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
                let amendment = ProofAmendment::from_json(payload.as_ref()).map_err(|error| {
                    NodeError::Startup(format!(
                        "block {} STARK reward tx {} proof payload decode failed: {error}",
                        block.number(),
                        tx.hash()
                    ))
                })?;
                if tx.source_hash != amendment.block_hash
                    || tx.layer != Some(amendment.layer)
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
            .collect::<Result<Vec<_>, NodeError>>()
            .map_err(|error| Self::invalid_fork(block.hash(), error))?;
        self.validate_stark_settlement_sequence(&stark_settlements)
            .map_err(|error| Self::classify_fork_error(block.hash(), error))?;
        for amendment in &stark_settlements {
            self.validate_stark_amendment_authentication(amendment)
                .map_err(|error| Self::classify_fork_error(block.hash(), error))?;
            self.validate_stark_proof_source_binding(amendment)
                .map_err(|error| Self::classify_fork_error(block.hash(), error))?;
        }

        let mut receipts = Vec::new();
        let mut new_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
        let imported_state_root = if !block.transactions.is_empty() || !stark_settlements.is_empty()
        {
            let mut block_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            let batch_verifier = MultiVerifier;
            let signature_state = WorldState::at_root(replay_store.clone(), &parent_state_root)?;
            let tx_hashes = block
                .transactions
                .iter()
                .map(SignedTransaction::sender_signing_hash)
                .collect::<Vec<_>>();
            let mut signing_pubkeys = Vec::with_capacity(block.transactions.len());
            for tx in &block.transactions {
                let uses_custom_validator = signature_state
                    .get_account(&tx.from)?
                    .and_then(|account| account.validation_code_hash)
                    .is_some();
                if uses_custom_validator {
                    signing_pubkeys.push(None);
                    continue;
                }

                let root_pubkey = match &tx.pubkey_mode {
                    shell_core::PubkeyMode::Embedded(pubkey) => {
                        block_pubkeys
                            .entry(tx.from)
                            .or_insert_with(|| pubkey.clone());
                        if replay_cs.get_pubkey(&tx.from)?.is_none() {
                            new_pubkeys.entry(tx.from).or_insert_with(|| pubkey.clone());
                        }
                        pubkey.clone()
                    }
                    shell_core::PubkeyMode::Reference => {
                        if let Some(pubkey) = block_pubkeys.get(&tx.from) {
                            pubkey.clone()
                        } else if let Some(pubkey) = replay_cs.get_pubkey(&tx.from)? {
                            pubkey
                        } else {
                            return Err(Self::invalid_fork(
                                block.hash(),
                                format!(
                                    "block {} tx {} references an unavailable public key",
                                    block.number(),
                                    tx.hash()
                                ),
                            ));
                        }
                    }
                };
                signing_pubkeys.push(Some(
                    batch_signing_pubkey(block.number(), tx, &root_pubkey)
                        .map_err(|error| Self::classify_fork_error(block.hash(), error))?,
                ));
            }
            let verify_items = block
                .transactions
                .iter()
                .enumerate()
                .filter_map(|(index, tx)| {
                    signing_pubkeys[index].as_deref().map(|pubkey| VerifyItem {
                        pubkey,
                        message: tx_hashes[index].as_bytes(),
                        signature: &tx.signature,
                    })
                })
                .collect::<Vec<_>>();
            batch_verifier
                .verify_batch_all(&verify_items)
                .map_err(|error| {
                    Self::invalid_fork(
                        block.hash(),
                        format!(
                            "block {} batch signature verification failed: {error}",
                            block.number()
                        ),
                    )
                })?;

            let replay_ws = WorldState::at_root(replay_store.clone(), &parent_state_root)?;
            let state_db = ShellStateDb::new(replay_ws, ChainStore::new(replay_store.clone()));
            let mut evm = ShellPqvm::new(state_db, self.config.chain_id);
            let pre_verified = PreVerified;
            let mut validation_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            let mut validation_nonces: HashMap<Address, u64> = HashMap::new();
            for tx in &block.transactions {
                let tx_for_validation =
                    tx_for_import_validation(tx, &validation_pubkeys, &replay_cs)?;
                let world_state = evm.state_db_mut().world_state_mut();
                let expected_nonce = validation_nonces
                    .get(&tx.from)
                    .copied()
                    .unwrap_or(world_state.get_nonce(&tx.from)?);
                validate_tx_for_import_at_block(
                    tx_for_validation.as_ref(),
                    world_state,
                    &replay_cs,
                    &pre_verified,
                    self.config.chain_id,
                    Some(expected_nonce),
                    &block.header,
                )
                .map_err(|error| match error {
                    TxValidationError::Storage(error) => NodeError::Storage(error),
                    error => Self::invalid_fork(
                        block.hash(),
                        format!(
                            "block {} transaction validation failed: {error}",
                            block.number()
                        ),
                    ),
                })?;
                validation_nonces.insert(
                    tx.from,
                    expected_nonce.checked_add(1).ok_or_else(|| {
                        Self::invalid_fork(
                            block.hash(),
                            format!(
                                "block {} transaction nonce exhausted for {}",
                                block.number(),
                                tx.from
                            ),
                        )
                    })?,
                );
                if let shell_core::PubkeyMode::Embedded(pubkey) = &tx.pubkey_mode {
                    validation_pubkeys
                        .entry(tx.from)
                        .or_insert_with(|| pubkey.clone());
                }
            }

            let mut cumulative_gas = 0u64;
            let mut total_effective_fees = U256::ZERO;
            for (index, tx) in block.transactions.iter().enumerate() {
                if !tx_fits_remaining_block_gas(tx, cumulative_gas, block.header.gas_limit) {
                    return Err(Self::invalid_fork(
                        block.hash(),
                        format!(
                            "block {} tx {} exceeds remaining block gas",
                            block.number(),
                            index
                        ),
                    ));
                }
                // Earlier transactions can rotate keys or change account and
                // paymaster policy. Revalidate against their resulting state
                // before trusting the parent-state batch verification.
                validate_import_tx_in_current_state(
                    tx,
                    &validation_pubkeys,
                    evm.state_db_mut().world_state_mut(),
                    &replay_cs,
                    self.config.chain_id,
                    &block.header,
                )
                .map_err(|error| {
                    Self::invalid_fork(
                        block.hash(),
                        format!(
                            "block {} transaction {} failed sequential validation: {error}",
                            block.number(),
                            index,
                        ),
                    )
                })?;
                let result = if tx.is_aa_bundle() {
                    evm.execute_aa_bundle(tx, &block.header, index as u32, cumulative_gas)
                } else {
                    evm.execute_tx(tx, &block.header, index as u32, cumulative_gas)
                }
                .map_err(|error| match error {
                    ExecutorError::Storage(error)
                    | ExecutorError::StateDb(StateDbError::Storage(error)) => {
                        NodeError::Storage(error)
                    }
                    error => Self::invalid_fork(
                        block.hash(),
                        format!("block {} tx {index} replay failed: {error}", block.number()),
                    ),
                })?;
                cumulative_gas = checked_cumulative_block_gas(
                    cumulative_gas,
                    result.gas_used,
                    block.header.gas_limit,
                )
                .ok_or_else(|| {
                    Self::invalid_fork(
                        block.hash(),
                        format!("block {} tx {index} gas overflow", block.number()),
                    )
                })?;
                let price = effective_gas_price(
                    tx.tx.max_fee_per_gas,
                    tx.tx.max_priority_fee_per_gas,
                    block.header.base_fee_per_gas,
                );
                if !tx.is_aa_bundle() && !result.is_system_tx {
                    commit_pqvm_state(&result, evm.state_db_mut())?;
                }
                total_effective_fees = total_effective_fees
                    .saturating_add(U256::from(result.gas_used).saturating_mul(U256::from(price)));
                receipts.push(result.receipt);
            }
            if cumulative_gas != block.header.gas_used {
                return Err(Self::invalid_fork(
                    block.hash(),
                    format!(
                        "block {} gas_used mismatch: expected {}, got {}",
                        block.number(),
                        block.header.gas_used,
                        cumulative_gas
                    ),
                ));
            }

            let mut system_txs = Vec::new();
            if total_effective_fees > U256::ZERO {
                evm.state_db_mut()
                    .world_state_mut()
                    .add_balance(&block.header.proposer, total_effective_fees)?;
                let tx_index = block.transactions.len() as u32;
                let reward_tx = SystemTransaction::block_gas_reward(
                    self.config.chain_id,
                    block.number(),
                    tx_index,
                    block.header.proposer,
                    total_effective_fees,
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
                return Err(Self::invalid_fork(
                    block.hash(),
                    format!("block {} system transactions mismatch", block.number()),
                ));
            }
            {
                let mut registry = AlgorithmRegistry::global_mut();
                apply_pending_activations(
                    block.number(),
                    evm.state_db_mut().world_state_mut(),
                    &mut registry,
                    "preferred-fork replay",
                )?;
            }
            evm.state_db_mut().world_state_mut().state_root()?
        } else {
            if block.header.gas_used != 0 || !block.system_transactions.is_empty() {
                return Err(Self::invalid_fork(
                    block.hash(),
                    format!(
                        "block {} has inconsistent empty-block fields",
                        block.number()
                    ),
                ));
            }
            let mut world_state = WorldState::at_root(replay_store.clone(), &parent_state_root)?;
            {
                let mut registry = AlgorithmRegistry::global_mut();
                apply_pending_activations(
                    block.number(),
                    &mut world_state,
                    &mut registry,
                    "preferred-fork empty-block replay",
                )?;
            }
            world_state.state_root()?
        };

        self.verify_import_logs_bloom(block, &receipts)
            .map_err(|error| Self::invalid_fork(block.hash(), error))?;
        if imported_state_root != block.header.state_root {
            return Err(Self::invalid_fork(
                block.hash(),
                format!(
                    "block {} state root mismatch after deterministic replay: expected {}, got {}",
                    block.number(),
                    block.header.state_root,
                    imported_state_root
                ),
            ));
        }
        for (address, pubkey) in new_pubkeys {
            if replay_cs.get_pubkey(&address)?.is_none() {
                replay_cs.put_pubkey(&address, &pubkey)?;
            }
        }
        let settlement_hashes = block
            .system_transactions
            .iter()
            .filter(|tx| tx.kind == SystemTxKind::StarkReward)
            .map(SystemTransaction::hash);
        for (amendment, settlement_hash) in stark_settlements.iter().zip(settlement_hashes) {
            replay_cs
                .put_proof_amendments(Self::stark_artifacts(amendment, Some(settlement_hash))?)?;
        }
        replay_cs.stage_address_metadata_undo(&block.hash(), &metadata_checkpoint)?;

        Ok((receipts, stark_settlements))
    }

    pub(super) fn reinsert_reverted_transactions(
        &self,
        reverted_txs: &[SignedTransaction],
    ) -> (usize, usize) {
        let mut inserted = 0usize;
        let mut rejected = 0usize;
        let mut world_state = self.world_state.write();

        for tx in reverted_txs {
            match self.tx_pool.insert(
                tx.clone(),
                &mut world_state,
                self.chain_store.as_ref(),
                &MultiVerifier,
            ) {
                Ok(_) => inserted = inserted.saturating_add(1),
                Err(error) => {
                    rejected = rejected.saturating_add(1);
                    warn!(
                        tx_hash = %tx.hash(),
                        error_kind = error.kind_str(),
                        "rejected reverted transaction during fork adoption"
                    );
                }
            }
        }

        (inserted, rejected)
    }

    /// Rewind a persisted unfinalized suffix before this process joins the network.
    ///
    /// wPoA votes are process-local until a commit certificate is persisted. After
    /// a restart, retaining blocks above the durable finalized cursor can strand
    /// validators on incompatible suffixes that cannot be authenticated by block
    /// sync. The block records remain available by hash, while canonical state,
    /// indexes, and address metadata are restored atomically to the finalized tip.
    pub(super) fn recover_unfinalized_head(&self) -> Result<usize, NodeError> {
        let Some(finalized_number) = self.chain_store.get_finalized_number()? else {
            return Ok(0);
        };
        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        if head.number() <= finalized_number {
            return Ok(0);
        }

        let finalized_hash = self
            .chain_store
            .get_block_hash_by_number(finalized_number)?
            .ok_or_else(|| {
                NodeError::Startup(format!(
                    "cannot recover unfinalized head: canonical finalized block #{finalized_number} is missing"
                ))
            })?;
        let finalized_block = self
            .chain_store
            .get_block_by_hash(&finalized_hash)?
            .ok_or_else(|| {
                NodeError::Startup(format!(
                    "cannot recover unfinalized head: finalized block {finalized_hash} is unavailable"
                ))
            })?;
        if finalized_block.number() != finalized_number || finalized_block.hash() != finalized_hash
        {
            return Err(NodeError::Startup(format!(
                "cannot recover unfinalized head: finalized block metadata does not match canonical checkpoint #{finalized_number} ({finalized_hash})"
            )));
        }
        let mut old_hashes = Vec::with_capacity(
            usize::try_from(head.number().saturating_sub(finalized_number)).unwrap_or(usize::MAX),
        );
        for number in finalized_number.saturating_add(1)..=head.number() {
            let block_hash = self
                .chain_store
                .get_block_hash_by_number(number)?
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "cannot recover unfinalized head: canonical mapping for block #{number} is missing"
                    ))
                })?;
            old_hashes.push(block_hash);
        }
        let old_chain = self.load_fork_segment(
            "startup recovery canonical suffix",
            finalized_hash,
            finalized_number,
            &old_hashes,
            true,
        )?;

        // Preflight the finalized state and algorithm registry before committing
        // the canonical rollback. A malformed or pruned state root must leave the
        // existing canonical metadata untouched.
        let mut restored_state =
            WorldState::at_root(self.store.clone(), &finalized_block.header.state_root)?;
        restored_state.validate()?;
        let restored_registry = load_algorithm_registry(&restored_state).map_err(|error| {
            NodeError::Startup(format!(
                "failed to restore algorithm registry at finalized block #{finalized_number}: {error}"
            ))
        })?;

        let overlay = Arc::new(OverlayStore::new(self.store.clone()));
        let overlay_chain_store = ChainStore::new(overlay);
        overlay_chain_store.restore_address_metadata(&old_chain)?;
        let stale_canonical_numbers =
            (finalized_number.saturating_add(1)..=head.number()).collect::<Vec<_>>();
        overlay_chain_store.commit_reorg_overlay(
            &old_chain,
            &[],
            &stale_canonical_numbers,
            &[],
            &finalized_hash,
            None,
        )?;

        *self.world_state.write() = restored_state;
        *AlgorithmRegistry::global_mut() = restored_registry;
        *self.fork_choice.write() = restore_fork_choice(
            self.chain_store.as_ref(),
            finalized_number,
            finalized_hash,
            finalized_number,
        );
        self.prover_orchestrator()
            .rewind_settled_frontiers(finalized_number);
        self.last_proposed_by
            .lock()
            .retain(|_, number| *number <= finalized_number);

        for block in &old_chain {
            let mut reverted_settlements = Self::decode_system_extra(&block.header.extra_data)?;
            reverted_settlements.extend(
                block
                    .system_transactions
                    .iter()
                    .filter(|tx| tx.kind == SystemTxKind::StarkReward)
                    .filter_map(|tx| {
                        ProofAmendment::from_json(tx.proof_payload.as_ref()?.as_ref()).ok()
                    }),
            );
            self.block_store()
                .cancel_settled_witness_deletes(&reverted_settlements);
        }

        if self
            .chain_store
            .get_chain_totals_head()?
            .is_some_and(|totals_head| totals_head != finalized_number)
        {
            self.chain_store.rebuild_chain_totals(finalized_number)?;
        }
        let reverted_txs = unique_reverted_transactions(&old_chain, &[]);
        let (reinserted, rejected) = self.reinsert_reverted_transactions(&reverted_txs);
        self.metrics.block_height.set(finalized_number as i64);
        self.metrics
            .update_finality(finalized_number, finalized_number);

        warn!(
            old_head = head.number(),
            finalized_number,
            rolled_back = old_chain.len(),
            mempool_reinserted = reinserted,
            mempool_rejected = rejected,
            "recovered canonical state by rewinding an unfinalized startup suffix"
        );
        Ok(old_chain.len())
    }

    pub(super) fn adopt_preferred_fork(&self, plan: &ForkAdoptionPlan) -> Result<(), NodeError> {
        let current_head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        if current_head.number() != plan.canonical_number
            || current_head.hash()
                != plan
                    .old_chain
                    .last()
                    .map(Block::hash)
                    .unwrap_or(plan.ancestor_hash)
        {
            return Err(NodeError::Startup(
                "preferred-fork plan is stale relative to the canonical head".into(),
            ));
        }
        if *self.fork_choice.read().head() != plan.preferred_hash {
            return Err(NodeError::Startup(
                "preferred-fork plan is stale relative to fork choice".into(),
            ));
        }

        let (finalized_number, finalized_hash) = {
            let finality = self.finality.read();
            (
                finality.last_finalized_number(),
                *finality.last_finalized_hash(),
            )
        };
        if plan.ancestor_number < finalized_number
            || (finalized_number > 0
                && plan.ancestor_number == finalized_number
                && plan.ancestor_hash != finalized_hash)
        {
            return Err(NodeError::InvalidFork {
                block_hash: plan.preferred_hash,
                reason: format!(
                "preferred fork {} crosses finalized block #{finalized_number} ({finalized_hash})",
                plan.preferred_hash
                ),
            });
        }

        let ancestor = self
            .chain_store
            .get_block_by_hash(&plan.ancestor_hash)?
            .ok_or_else(|| {
                NodeError::Startup(format!(
                    "preferred-fork ancestor block not found: {}",
                    plan.ancestor_hash
                ))
            })?;
        if ancestor.number() != plan.ancestor_number
            || self
                .chain_store
                .get_block_hash_by_number(plan.ancestor_number)?
                != Some(plan.ancestor_hash)
        {
            return Err(NodeError::Startup(
                "preferred-fork ancestor is no longer canonical".into(),
            ));
        }
        let ancestor_state_root = ancestor.header.state_root;

        let mut state = WorldState::at_root(self.store.clone(), &ancestor_state_root)?;
        state.validate()?;
        let ancestor_registry = load_algorithm_registry(&state).map_err(|error| {
            NodeError::Startup(format!(
                "failed to load algorithm registry at preferred-fork ancestor: {error}"
            ))
        })?;
        let mut algorithm_registry_rollback = AlgorithmRegistryRollback::new();
        *AlgorithmRegistry::global_mut() = ancestor_registry;

        let overlay = Arc::new(shell_storage::OverlayStore::new(self.store.clone()));
        let overlay_chain_store = ChainStore::new(overlay.clone());
        overlay_chain_store.restore_address_metadata(&plan.old_chain)?;
        let mut parent = ancestor;
        let mut parent_state_root = ancestor_state_root;
        let mut receipts = Vec::with_capacity(plan.new_chain.len());
        let mut settlements = Vec::with_capacity(plan.new_chain.len());
        for block in &plan.new_chain {
            let block_hash = block.hash();
            self.verify_import_consensus(block, &parent, false)
                .map_err(|error| Self::classify_fork_error(block_hash, error))?;
            self.verify_import_economics(block, &parent)
                .map_err(|error| Self::classify_fork_error(block_hash, error))?;
            self.verify_incoming_witness_root(block)
                .map_err(|error| Self::classify_fork_error(block_hash, error))?;
            self.verify_import_sig_aggregate_proof(block)
                .map_err(|error| Self::classify_fork_error(block_hash, error))?;
            let (block_receipts, block_settlements) =
                self.replay_preferred_fork_block(block, parent_state_root, overlay.clone())?;
            parent_state_root = block.header.state_root;
            receipts.push(block_receipts);
            settlements.push(block_settlements);
            parent = block.clone();
        }
        if parent.hash() != plan.preferred_hash || parent.number() != plan.preferred_number {
            return Err(NodeError::InvalidFork {
                block_hash: plan.preferred_hash,
                reason: "preferred-fork plan does not terminate at the selected head".into(),
            });
        }

        let stale_canonical_numbers = if plan.canonical_number > plan.preferred_number {
            (plan.preferred_number + 1..=plan.canonical_number).collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let total_weight = self
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        let mut finality = self.finality.write();
        let finalizes_preferred = finality.can_finalize_weighted(
            &plan.preferred_hash,
            plan.preferred_number,
            total_weight,
        );
        overlay_chain_store.commit_reorg_overlay(
            &plan.old_chain,
            &plan.new_chain,
            &stale_canonical_numbers,
            &receipts,
            &plan.preferred_hash,
            finalizes_preferred.then_some(plan.preferred_number),
        )?;
        algorithm_registry_rollback.commit();

        if finalizes_preferred {
            let finalized = finality.check_finality_weighted(
                &plan.preferred_hash,
                plan.preferred_number,
                total_weight,
            );
            debug_assert!(finalized, "prechecked preferred-fork finality must apply");
            drop(finality);
            tracing::info!(
                block = plan.preferred_number,
                hash = %plan.preferred_hash,
                "canonicalized attested block finalized"
            );
            self.advance_fork_choice_finality(plan.preferred_number, plan.preferred_hash);
        } else {
            drop(finality);
        }

        self.prover_orchestrator()
            .rewind_settled_frontiers(plan.ancestor_number);

        state = WorldState::at_root(self.store.clone(), &parent_state_root)?;
        let block_store = self.block_store();
        block_store.replace_world_state(state);
        for block in &plan.old_chain {
            let mut reverted_settlements = Self::decode_system_extra(&block.header.extra_data)?;
            reverted_settlements.extend(
                block
                    .system_transactions
                    .iter()
                    .filter(|tx| tx.kind == SystemTxKind::StarkReward)
                    .filter_map(|tx| {
                        ProofAmendment::from_json(tx.proof_payload.as_ref()?.as_ref()).ok()
                    }),
            );
            block_store.cancel_settled_witness_deletes(&reverted_settlements);
        }
        for (block, block_settlements) in plan.new_chain.iter().zip(settlements) {
            self.prover_orchestrator()
                .record_settled_sources(&block_settlements);
            self.prover_orchestrator()
                .remove_settled_pending(&block_settlements);
            self.feed_l2_scheduler_from_settlements(&block_settlements, block.number());
            block_store.schedule_settled_witness_deletes(
                &block_settlements,
                block.number(),
                self.config.pruning.proof_replacement_grace,
            );
        }
        block_store.prune_grace_witnesses(finalized_number);
        let adopted_tx_hashes = plan
            .new_chain
            .iter()
            .flat_map(|block| block.transactions.iter().map(SignedTransaction::hash))
            .collect::<Vec<_>>();
        let pruned = self.mem_pool().remove_committed_hashes(&adopted_tx_hashes);
        let (reinserted, rejected) = self.reinsert_reverted_transactions(&plan.reverted_txs);
        match self.chain_store.get_chain_totals_head() {
            Ok(Some(_)) => {
                if let Err(error) = self.chain_store.rebuild_chain_totals(plan.preferred_number) {
                    warn!(
                        preferred_number = plan.preferred_number,
                        %error,
                        "failed to rebuild canonical totals after fork adoption"
                    );
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!(
                    preferred_number = plan.preferred_number,
                    %error,
                    "failed to inspect canonical totals after fork adoption"
                );
            }
        }
        for block in &plan.new_chain {
            self.record_canonical_state_root(block.number(), block.header.state_root);
            self.last_proposed_by
                .lock()
                .insert(block.header.proposer, block.number());
        }
        info!(
            preferred_hash = %plan.preferred_hash,
            preferred_number = plan.preferred_number,
            ancestor_hash = %plan.ancestor_hash,
            ancestor_number = plan.ancestor_number,
            rollback = plan.old_chain.len(),
            apply = plan.new_chain.len(),
            mempool_pruned = pruned,
            mempool_reinserted = reinserted,
            mempool_rejected = rejected,
            "adopted quorum-preferred fork after deterministic replay"
        );
        Ok(())
    }

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
        self.import_block_inner(block, false)
    }

    /// Import a block whose commit certificate has already been verified by
    /// the network sync path. The certificate permits historical validation of
    /// a proposer selected after a transient wPoA view change.
    pub(crate) fn import_finalized_block(
        &self,
        block: Block,
        _verifier: &dyn Verifier,
    ) -> Result<(), NodeError> {
        self.import_block_inner(block, true)
    }

    fn import_block_inner(&self, block: Block, finalized_import: bool) -> Result<(), NodeError> {
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
            let parent = self.parent_for_import(&block)?;
            self.verify_import_consensus(&block, &parent, finalized_import)?;
            self.verify_import_economics(&block, &parent)?;
            self.verify_incoming_witness_root(&block)?;
            self.verify_import_sig_aggregate_proof(&block)?;
            self.validate_side_fork_transactions(&block, &parent)?;
            if let Some(existing) = block_store.block_by_number(incoming)? {
                self.queue_signed_equivocation_if_valid(&existing, &block)?;
            }
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
            let parent = self.parent_for_import(&block)?;
            self.verify_import_consensus(&block, &parent, finalized_import)?;
            self.verify_import_economics(&block, &parent)?;
            self.verify_incoming_witness_root(&block)?;
            self.verify_import_sig_aggregate_proof(&block)?;
            self.validate_side_fork_transactions(&block, &parent)?;
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
        if let Some(existing) = block_store.block_by_number(incoming)? {
            if existing.hash() != block.hash() && existing.header.proposer == block.header.proposer
            {
                self.queue_signed_equivocation_if_valid(&existing, &block)?;
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

        // Verify consensus rules, including parent linkage, timestamp bounds,
        // and proposer seal.
        let parent = self.parent_for_import(&block)?;
        self.verify_import_consensus(&block, &parent, finalized_import)?;
        self.verify_import_economics(&block, &parent)?;
        self.verify_incoming_witness_root(&block)?;
        self.verify_import_sig_aggregate_proof(&block)?;

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
        for amendment in &stark_settlements {
            self.validate_stark_amendment_authentication(amendment)?;
            self.validate_stark_proof_source_binding(amendment)?;
        }

        let mut algorithm_registry_rollback = AlgorithmRegistryRollback::new();
        let import_store = Arc::new(shell_storage::OverlayStore::new(self.store.clone()));
        let imported_state_root = if !block.transactions.is_empty() || !stark_settlements.is_empty()
        {
            // Validate all transactions before execution (F-181):
            // security-critical checks (sig, algorithm, access list, pubkey)
            // are enforced during block import, not just mempool.
            let import_cs = ChainStore::new(import_store.clone());
            let mut block_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            // M5-C2: Batch verify built-in and session-key signatures in
            // parallel. Custom validators own their signature policy and are
            // executed in the read-only validation pass below.
            let batch_verifier = MultiVerifier;
            let signature_state = WorldState::at_root(import_store.clone(), &current_root)?;
            let tx_hashes: Vec<ShellHash> = block
                .transactions
                .iter()
                .map(SignedTransaction::sender_signing_hash)
                .collect();
            let mut signing_pubkeys: Vec<Option<Vec<u8>>> =
                Vec::with_capacity(block.transactions.len());
            for tx in &block.transactions {
                let uses_custom_validator = signature_state
                    .get_account(&tx.from)?
                    .and_then(|account| account.validation_code_hash)
                    .is_some();
                if uses_custom_validator {
                    signing_pubkeys.push(None);
                    continue;
                }

                let root_pubkey = match &tx.pubkey_mode {
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
                            return Err(NodeError::Startup(format!(
                                "block {} tx {} uses Reference pubkey mode but sender {} has no registered or earlier embedded pubkey",
                                block.number(),
                                tx.hash(),
                                tx.from
                            )));
                        }
                    }
                };
                signing_pubkeys.push(Some(batch_signing_pubkey(
                    block.number(),
                    tx,
                    &root_pubkey,
                )?));
            }
            let verify_items: Vec<VerifyItem> = block
                .transactions
                .iter()
                .enumerate()
                .filter_map(|(index, tx)| {
                    signing_pubkeys[index].as_deref().map(|pubkey| VerifyItem {
                        pubkey,
                        message: tx_hashes[index].as_bytes(),
                        signature: &tx.signature,
                    })
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

            let import_ws = WorldState::at_root(import_store.clone(), &current_root)?;
            let state_db = ShellStateDb::new(import_ws, ChainStore::new(import_store.clone()));
            let mut evm = ShellPqvm::new(state_db, self.config.chain_id);

            // Complete transaction-policy validation (chain-id, gas, sender
            // binding, AA restrictions, and custom validation contracts).
            // Uses PreVerified only for built-in signature checks already
            // covered by the batch pass above; custom validators still execute.
            //
            // IMPORTANT: import validation is READ-ONLY — it does NOT register
            // pubkeys (unlike validate_tx used in the mempool path). Pubkey registration
            // is deferred to the `new_pubkeys` commit at the end of import_block.
            // The `new_pubkeys` HashMap uses `or_insert_with` (first-write-wins), so
            // even if multiple Embedded txs from the same sender appear in one block,
            // only the first pubkey is written — registration is idempotent by design.
            //
            // Reference txs mutated to Embedded here (for validation) do NOT trigger
            // re-registration because import validation performs no writes.
            let pre_verified = PreVerified;
            let mut validation_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            let mut validation_nonces: HashMap<Address, u64> = HashMap::new();
            for tx in &block.transactions {
                let tx_for_validation =
                    tx_for_import_validation(tx, &validation_pubkeys, &import_cs)?;

                let world_state = evm.state_db_mut().world_state_mut();
                let expected_nonce = match validation_nonces.get(&tx.from) {
                    Some(next_nonce) => *next_nonce,
                    None => world_state.get_nonce(&tx.from)?,
                };

                validate_tx_for_import_at_block(
                    tx_for_validation.as_ref(),
                    world_state,
                    &import_cs,
                    &pre_verified,
                    self.config.chain_id,
                    Some(expected_nonce),
                    &block.header,
                )
                .map_err(|e| {
                    NodeError::Startup(format!(
                        "block {} tx validation failed: {e}",
                        block.number()
                    ))
                })?;
                let next_nonce = expected_nonce.checked_add(1).ok_or_else(|| {
                    NodeError::Startup(format!(
                        "block {} tx validation exhausted nonce space for {}",
                        block.number(),
                        tx.from
                    ))
                })?;
                validation_nonces.insert(tx.from, next_nonce);

                if let shell_core::PubkeyMode::Embedded(pk) = &tx.pubkey_mode {
                    validation_pubkeys
                        .entry(tx.from)
                        .or_insert_with(|| pk.clone());
                }
            }
            let mut cumulative_gas: u64 = 0;
            let mut total_effective_fees = U256::ZERO;

            for (idx, tx) in block.transactions.iter().enumerate() {
                if !tx_fits_remaining_block_gas(tx, cumulative_gas, block.header.gas_limit) {
                    return Err(NodeError::Startup(format!(
                        "block {} tx {} gas_limit {} exceeds remaining block gas {}",
                        block.number(),
                        idx,
                        tx.tx.gas_limit,
                        block.header.gas_limit.saturating_sub(cumulative_gas)
                    )));
                }
                // Re-run policy validation against the state produced by prior
                // transactions in this block. This makes key revocation and
                // validator/paymaster policy changes effective immediately.
                validate_import_tx_in_current_state(
                    tx,
                    &validation_pubkeys,
                    evm.state_db_mut().world_state_mut(),
                    &import_cs,
                    self.config.chain_id,
                    &block.header,
                )
                .map_err(|error| {
                    NodeError::Startup(format!(
                        "block {} tx {} failed sequential validation: {error}",
                        block.number(),
                        idx,
                    ))
                })?;
                let exec_result = if tx.is_aa_bundle() {
                    evm.execute_aa_bundle(tx, &block.header, idx as u32, cumulative_gas)
                } else {
                    evm.execute_tx(tx, &block.header, idx as u32, cumulative_gas)
                };
                match exec_result {
                    Ok(result) => {
                        let Some(next_cumulative_gas) = checked_cumulative_block_gas(
                            cumulative_gas,
                            result.gas_used,
                            block.header.gas_limit,
                        ) else {
                            return Err(NodeError::Startup(format!(
                                "block {} tx {} gas_used {} exceeds remaining block gas {}",
                                block.number(),
                                idx,
                                result.gas_used,
                                block.header.gas_limit.saturating_sub(cumulative_gas)
                            )));
                        };
                        cumulative_gas = next_cumulative_gas;
                        let price = effective_gas_price(
                            tx.tx.max_fee_per_gas,
                            tx.tx.max_priority_fee_per_gas,
                            block.header.base_fee_per_gas,
                        );
                        if tx.is_aa_bundle() {
                            // AA dispatcher already mutated state_db.world_state
                            // in-place (with atomic rollback on inner failure).
                        } else if result.is_system_tx {
                            // Native system contracts mutate the isolated world state directly.
                            // The overlay keeps those changes private until block validation succeeds.
                        } else {
                            commit_pqvm_state(&result, evm.state_db_mut())?;
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
            if cumulative_gas != block.header.gas_used {
                return Err(NodeError::Startup(format!(
                    "block {} gas_used mismatch: expected {}, got {}",
                    block.number(),
                    block.header.gas_used,
                    cumulative_gas
                )));
            }
            // Block producer receives 100% of effective gas fees.
            let producer_reward = total_effective_fees;
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
            // Apply algorithm activations whose timelock has elapsed (WP §6.5).
            // Must run BEFORE state_root so activations are committed to the Merkle root.
            {
                let mut registry = AlgorithmRegistry::global_mut();
                apply_pending_activations(
                    block.number(),
                    evm.state_db_mut().world_state_mut(),
                    &mut registry,
                    "import",
                )?;
            }
            evm.state_db_mut().world_state_mut().state_root()?
        } else {
            if block.header.gas_used != 0 {
                return Err(NodeError::Startup(format!(
                    "block {} gas_used mismatch: expected {}, got 0",
                    block.number(),
                    block.header.gas_used
                )));
            }
            if !block.system_transactions.is_empty() {
                return Err(NodeError::Startup(format!(
                    "block {} carries unexpected system transactions",
                    block.number()
                )));
            }
            // Empty blocks still need to apply timelock activations before computing
            // state_root — a producer at this height will have already applied them.
            let mut ws = WorldState::at_root(import_store.clone(), &current_root)
                .map_err(|e| NodeError::Startup(format!("world_state at root: {e}")))?;
            {
                let mut registry = AlgorithmRegistry::global_mut();
                apply_pending_activations(
                    block.number(),
                    &mut ws,
                    &mut registry,
                    "empty-block import",
                )?;
            }
            ws.state_root()
                .map_err(|e| NodeError::Startup(format!("state_root for empty block: {e}")))?
        };
        self.verify_import_logs_bloom(&block, &receipts)?;
        if imported_state_root != block.header.state_root {
            return Err(NodeError::Startup(format!(
                "block {} state root mismatch: expected {:?}, got {:?}",
                block.number(),
                block.header.state_root,
                imported_state_root
            )));
        }

        let import_cs = ChainStore::new(import_store.clone());
        for (address, pubkey) in &new_pubkeys {
            // Execution may have changed the key through the account manager.
            // Preserve that staged value instead of restoring the transaction's
            // pre-execution embedded key.
            if import_cs.get_pubkey(address)?.is_none() {
                import_cs.put_pubkey(address, pubkey)?;
            }
        }
        import_cs.commit_canonical_overlay(&block, Some(receipts.as_slice()))?;

        // Commit to storage.
        let committed_world_state = WorldState::at_root(self.store.clone(), &imported_state_root)?;
        let block_hash = block.hash();
        algorithm_registry_rollback.commit();
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
        prover.remove_settled_pending(&stark_settlements);
        self.feed_l2_scheduler_from_settlements(&stark_settlements, block.number());
        consensus.register_fork_choice_block(block_hash, block.header.parent_hash, block.number());

        // Track the last block proposed by each validator for offline-slash detection.
        self.last_proposed_by
            .lock()
            .insert(block.header.proposer, block.number());
        // Witness replacement begins only after the proof is in a canonical
        // settlement block. Peer gossip alone must never make source data
        // unavailable. The grace period is measured from settlement inclusion.
        block_store.schedule_settled_witness_deletes(
            &stark_settlements,
            block.number(),
            self.config.pruning.proof_replacement_grace,
        );
        let finalized_number = self.finality.read().last_finalized_number();
        block_store.prune_grace_witnesses(finalized_number);

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
        let visible_tx_count = block
            .transactions
            .len()
            .saturating_add(block.system_transactions.len());
        if let Err(e) = block_store.update_chain_totals(
            block.number(),
            visible_tx_count as u64,
            block.header.gas_used,
        ) {
            warn!(block = block.number(), "failed to update chain totals: {e}");
        }

        // Track the imported state root for pruning decisions.
        self.record_canonical_state_root(block.number(), block.header.state_root);
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
        if self.config.node_role.runs_prover()
            && self.prover_ready.load(std::sync::atomic::Ordering::Acquire)
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{Account, PubkeyMode, Transaction};
    use shell_crypto::{DilithiumSigner, SignatureType, Signer};
    use shell_storage::{MemoryDb, StorageError};

    fn transaction() -> Transaction {
        Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0x22; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    }

    #[test]
    fn import_validation_borrows_transactions_unless_reference_needs_in_block_key() {
        let chain_store = ChainStore::new(Arc::new(MemoryDb::new()));
        let sender = Address::from([0x11; 20]);
        let signature = PQSignature::new(SignatureType::Dilithium3, vec![0x33; 64]);
        let embedded = SignedTransaction::with_pubkey(
            sender,
            transaction(),
            signature.clone(),
            vec![0x44; 1_952],
        );
        let reference = SignedTransaction::new(sender, transaction(), signature);
        let mut validation_pubkeys = HashMap::new();

        assert!(matches!(
            tx_for_import_validation(&embedded, &validation_pubkeys, &chain_store).unwrap(),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            tx_for_import_validation(&reference, &validation_pubkeys, &chain_store).unwrap(),
            Cow::Borrowed(_)
        ));

        validation_pubkeys.insert(sender, vec![0x55; 1_952]);
        let resolved =
            tx_for_import_validation(&reference, &validation_pubkeys, &chain_store).unwrap();
        assert!(matches!(&resolved, Cow::Owned(_)));
        assert_eq!(
            resolved.pubkey_mode,
            PubkeyMode::Embedded(vec![0x55; 1_952])
        );

        chain_store.put_pubkey(&sender, &vec![0x66; 1_952]).unwrap();
        let resolved =
            tx_for_import_validation(&reference, &validation_pubkeys, &chain_store).unwrap();
        assert!(
            matches!(resolved, Cow::Borrowed(_)),
            "the current registry must override the parent-state fallback"
        );
    }

    #[test]
    fn sequential_import_validation_rejects_signature_from_rotated_key() {
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store.clone());
        let mut world_state = WorldState::new(store);
        let old_signer = DilithiumSigner::generate();
        let new_signer = DilithiumSigner::generate();
        let sender =
            Address::from_public_key(old_signer.public_key(), old_signer.sig_type().as_u8());
        world_state
            .set_account(
                &sender,
                &Account {
                    pq_pubkey_hash: shell_primitives::blake3_hash(new_signer.public_key()),
                    nonce: 1,
                    balance: U256::from(1_000_000u64),
                    validation_code_hash: None,
                    code_hash: None,
                    storage_root: ShellHash::ZERO,
                },
            )
            .unwrap();
        chain_store
            .put_pubkey(&sender, new_signer.public_key())
            .unwrap();

        let mut tx = transaction();
        tx.nonce = 1;
        let signature = old_signer
            .sign(tx.signing_hash(old_signer.sig_type().as_u8()).as_bytes())
            .unwrap();
        let stale = SignedTransaction::new(sender, tx, signature);
        let mut parent_pubkeys = HashMap::new();
        parent_pubkeys.insert(sender, old_signer.public_key().to_vec());

        let error = validate_import_tx_in_current_state(
            &stale,
            &parent_pubkeys,
            &mut world_state,
            &chain_store,
            1337,
            &BlockHeader {
                number: 1,
                ..BlockHeader::default()
            },
        )
        .unwrap_err();
        assert!(matches!(error, TxValidationError::SignatureInvalid));
    }

    #[test]
    fn fork_error_classification_preserves_transient_storage_failures() {
        let block_hash = ShellHash::from([0x44; 32]);
        let storage = Node::<MemoryDb>::classify_fork_error(
            block_hash,
            NodeError::Storage(StorageError::Database("temporary read failure".into())),
        );
        let deterministic = Node::<MemoryDb>::classify_fork_error(
            block_hash,
            NodeError::Startup("invalid commitment".into()),
        );

        assert!(matches!(storage, NodeError::Storage(_)));
        assert!(matches!(
            deterministic,
            NodeError::InvalidFork {
                block_hash: rejected,
                ..
            } if rejected == block_hash
        ));
    }
}
