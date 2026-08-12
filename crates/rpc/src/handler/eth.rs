use super::*;

const MAX_FEE_HISTORY_REWARD_PERCENTILES: usize = 100;

fn rpc_logs_from_core(logs: Vec<shell_core::Log>) -> Vec<RpcLog> {
    logs.into_iter()
        .map(|log| {
            let data = hex_bytes(log.data.as_ref());
            RpcLog {
                address: log.address,
                topics: log.topics,
                data,
            }
        })
        .collect()
}

struct FilterReorg {
    ancestor: FilterCursor,
    /// Old canonical blocks ordered from the previous tip back toward the ancestor.
    removed_blocks: Vec<(u64, ShellHash)>,
}

fn find_filter_reorg<S: KvStore + 'static>(
    chain_store: &ChainStore<S>,
    cursor: FilterCursor,
    latest: u64,
) -> Result<Option<FilterReorg>, ErrorObjectOwned> {
    let Some(mut old_hash) = cursor.block_hash else {
        return Ok(None);
    };

    let canonical_at_cursor = if cursor.block_number <= latest {
        chain_store
            .get_block_hash_by_number(cursor.block_number)
            .map_err(internal_err)?
    } else {
        None
    };
    if canonical_at_cursor == Some(old_hash) {
        return Ok(None);
    }

    let mut old_number = cursor.block_number;
    let mut removed_blocks = Vec::new();
    loop {
        let canonical_hash = if old_number <= latest {
            chain_store
                .get_block_hash_by_number(old_number)
                .map_err(internal_err)?
        } else {
            None
        };
        if canonical_hash == Some(old_hash) {
            return Ok(Some(FilterReorg {
                ancestor: FilterCursor {
                    block_number: old_number,
                    block_hash: Some(old_hash),
                },
                removed_blocks,
            }));
        }

        if removed_blocks.len() >= MAX_BLOCK_RANGE as usize {
            return Err(limit_exceeded(format!(
                "filter reorganization exceeds the {MAX_BLOCK_RANGE}-block poll limit"
            )));
        }

        let old_header = chain_store
            .get_header_by_hash(&old_hash)
            .map_err(internal_err)?
            .ok_or_else(|| {
                internal_err(format!(
                    "previous canonical header {old_hash} is unavailable during filter poll"
                ))
            })?;
        if old_header.number != old_number {
            return Err(internal_err(format!(
                "previous canonical header {old_hash} has height {}, expected {old_number}",
                old_header.number
            )));
        }

        removed_blocks.push((old_number, old_hash));
        if old_number == 0 {
            return Err(internal_err(
                "filter cursor has no common ancestor with the canonical chain",
            ));
        }
        old_number -= 1;
        old_hash = old_header.parent_hash;
    }
}

fn append_filter_logs<S: KvStore + 'static>(
    chain_store: &ChainStore<S>,
    filter: &crate::filter::LogFilter,
    block_number: u64,
    block_hash: ShellHash,
    removed: bool,
    results: &mut Vec<RpcLogWithMeta>,
) -> Result<(), ErrorObjectOwned> {
    let header = chain_store
        .get_header_by_hash(&block_hash)
        .map_err(internal_err)?
        .ok_or_else(|| {
            internal_err(format!(
                "block header {block_hash} missing during log filter poll"
            ))
        })?;
    if header.number != block_number {
        return Err(internal_err(format!(
            "block header {block_hash} has height {}, expected {block_number}",
            header.number
        )));
    }
    if !filter.matches_bloom(header.logs_bloom.as_ref()) {
        return Ok(());
    }

    let receipts = match chain_store
        .get_receipts(&block_hash)
        .map_err(internal_err)?
    {
        Some(receipts) => receipts,
        None if header.logs_bloom.as_ref().iter().all(|byte| *byte == 0) => Vec::new(),
        None => {
            return Err(internal_err(format!(
                "receipts for block {block_hash} are unavailable during filter poll"
            )));
        }
    };
    let mut global_log_index: u64 = 0;
    for (tx_idx, receipt) in receipts.into_iter().enumerate() {
        let tx_hash = receipt.tx_hash;
        for log in receipt.logs {
            if filter.matches_log(&log) {
                if results.len() >= MAX_LOG_RESULTS {
                    return Err(limit_exceeded(format!(
                        "filter poll returned more than {MAX_LOG_RESULTS} logs; narrow the filter"
                    )));
                }
                results.push(RpcLogWithMeta {
                    address: log.address,
                    topics: log.topics,
                    data: hex_bytes(log.data.as_ref()),
                    block_number: hex_u64(block_number),
                    block_hash,
                    transaction_hash: tx_hash,
                    transaction_index: hex_u64(tx_idx as u64),
                    log_index: hex_u64(global_log_index),
                    removed,
                });
            }
            global_log_index += 1;
        }
    }
    Ok(())
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> EthApiServer for RpcHandler<S> {
    async fn block_number(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let num = head.map(|b| b.number()).unwrap_or(0);
        Ok(hex_u64(num))
    }

    async fn chain_id(&self) -> Result<String, ErrorObjectOwned> {
        Ok(hex_u64(self.chain_id))
    }

    async fn syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Shell-chain has no sync protocol yet; always report "not syncing".
        Ok(serde_json::Value::Bool(false))
    }

    async fn mining(&self) -> Result<bool, ErrorObjectOwned> {
        // Return true if the node is configured as a validator.
        Ok(self.proposer_signer.is_some())
    }

    async fn hashrate(&self) -> Result<String, ErrorObjectOwned> {
        // PoA consensus — no mining, hashrate is always zero.
        Ok("0x0".to_string())
    }

    async fn accounts(&self) -> Result<Vec<Address>, ErrorObjectOwned> {
        // Node does not manage user accounts.
        Ok(vec![])
    }

    async fn sign(&self, _address: Address, _data: String) -> Result<String, ErrorObjectOwned> {
        Err(method_not_found(
            "eth_sign is not supported: node does not hold private keys",
        ))
    }

    async fn sign_transaction(&self, _tx: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        Err(method_not_found(
            "eth_signTransaction is not supported: node does not hold private keys",
        ))
    }

    async fn get_compilers(&self) -> Result<Vec<String>, ErrorObjectOwned> {
        // Legacy Ethereum method; always returns an empty array.
        Ok(vec![])
    }

    async fn protocol_version(&self) -> Result<String, ErrorObjectOwned> {
        // Protocol version 69 (Cancun-compatible).
        Ok("0x45".to_string())
    }

    async fn get_block_by_number(
        &self,
        number: String,
        full_txs: bool,
    ) -> Result<Option<RpcBlock>, ErrorObjectOwned> {
        let tag = parse_block_tag(&number)?;
        match tag {
            BlockTag::Finalized => {
                let n = *self.finalized_number.read();
                let block = self
                    .chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?;
                Ok(block.as_ref().map(|b| {
                    let mut rpc = block_to_rpc(b, full_txs);
                    self.fill_stark_proof(&b.hash(), &mut rpc);
                    self.attach_system_txs(
                        b,
                        &mut rpc,
                        if full_txs {
                            BlockTxDetail::Full
                        } else {
                            BlockTxDetail::Hashes
                        },
                    );
                    rpc
                }))
            }
            BlockTag::Number(n) => {
                let block = self
                    .chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?;
                Ok(block.as_ref().map(|b| {
                    let mut rpc = block_to_rpc(b, full_txs);
                    self.fill_stark_proof(&b.hash(), &mut rpc);
                    self.attach_system_txs(
                        b,
                        &mut rpc,
                        if full_txs {
                            BlockTxDetail::Full
                        } else {
                            BlockTxDetail::Hashes
                        },
                    );
                    rpc
                }))
            }
            BlockTag::Latest => {
                let block = self.chain_store.get_head_block().map_err(internal_err)?;
                Ok(block.as_ref().map(|b| {
                    let mut rpc = block_to_rpc(b, full_txs);
                    self.fill_stark_proof(&b.hash(), &mut rpc);
                    self.attach_system_txs(
                        b,
                        &mut rpc,
                        if full_txs {
                            BlockTxDetail::Full
                        } else {
                            BlockTxDetail::Hashes
                        },
                    );
                    rpc
                }))
            }
            BlockTag::Pending => {
                // F-075: construct a pseudo-block from the mempool.
                let head = self.chain_store.get_head_block().map_err(internal_err)?;
                let head = match head {
                    Some(b) => b,
                    None => return Ok(None),
                };
                let Some(pending_number) = head.header.number.checked_add(1) else {
                    return Ok(None);
                };
                let base_fee_per_gas = shell_core::calculate_base_fee(
                    head.header.gas_used,
                    head.header.gas_limit,
                    head.header.base_fee_per_gas,
                );
                let excess_blob_gas = shell_core::calc_excess_blob_gas(
                    head.header.excess_blob_gas,
                    head.header.blob_gas_used,
                );
                let blob_base_fee = shell_core::calc_blob_gas_price(excess_blob_gas);
                let all_pending =
                    self.tx_pool
                        .pending_for_block_at_fees(1000, base_fee_per_gas, blob_base_fee);
                // F-101: cap pending block candidates by gas_limit to prevent
                // oversized pseudo-blocks.
                let gas_limit = head.header.gas_limit;
                let mut cumulative_gas: u64 = 0;
                let pending_txs: Vec<_> = all_pending
                    .into_iter()
                    .filter(|tx| {
                        let remaining = gas_limit.saturating_sub(cumulative_gas);
                        if tx.tx.gas_limit > remaining {
                            return false;
                        }
                        cumulative_gas = cumulative_gas.saturating_add(tx.tx.gas_limit);
                        true
                    })
                    .collect();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let tx_size: usize = pending_txs.iter().map(|tx| tx.length()).sum();
                let header_size = head.header.length();
                let size = header_size + tx_size;

                let transactions = if full_txs {
                    serde_json::to_value(
                        pending_txs
                            .iter()
                            .map(|tx| tx_to_rpc(tx, None, Some(pending_number), None, None))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default()
                } else {
                    serde_json::to_value(
                        pending_txs
                            .iter()
                            .map(|tx| tx.hash())
                            .collect::<Vec<ShellHash>>(),
                    )
                    .unwrap_or_default()
                };

                let pending_block = RpcBlock {
                    hash: ShellHash::ZERO,
                    parent_hash: head.hash(),
                    number: hex_u64(pending_number),
                    timestamp: hex_u64(now),
                    gas_limit: hex_u64(head.header.gas_limit),
                    gas_used: hex_u64(cumulative_gas),
                    miner: head.header.proposer,
                    state_root: head.header.state_root,
                    transactions_root: ShellHash::ZERO,
                    receipts_root: ShellHash::ZERO,
                    transactions,
                    size: hex_u64(size as u64),
                    base_fee_per_gas: hex_u64(base_fee_per_gas),
                    total_difficulty: "0x1".into(),
                    sha3_uncles: crate::types::EMPTY_OMMER_HASH.into(),
                    uncles: vec![],
                    nonce: "0x0000000000000000".into(),
                    difficulty: "0x1".into(),
                    mix_hash: ShellHash::ZERO,
                    extra_data: "0x".into(),
                    logs_bloom: format!("0x{}", "00".repeat(BLOOM_SIZE)),
                    withdrawals_root: ShellHash::ZERO.to_string(),
                    parent_beacon_block_root: ShellHash::ZERO.to_string(),
                    blob_gas_used: hex_u64(0),
                    excess_blob_gas: hex_u64(excess_blob_gas),
                    sig_aggregate_proof: None,
                    sig_aggregate_proof_size: None,
                    compression_layer: 0,
                    pruning_status: "pending".into(),
                };
                Ok(Some(pending_block))
            }
        }
    }

    async fn get_block_by_hash(
        &self,
        hash: ShellHash,
        full_txs: bool,
    ) -> Result<Option<RpcBlock>, ErrorObjectOwned> {
        let block = self
            .chain_store
            .get_block_by_hash(&hash)
            .map_err(internal_err)?;
        Ok(block.as_ref().map(|b| {
            let mut rpc = block_to_rpc(b, full_txs);
            self.fill_stark_proof(&hash, &mut rpc);
            self.attach_system_txs(
                b,
                &mut rpc,
                if full_txs {
                    BlockTxDetail::Full
                } else {
                    BlockTxDetail::Hashes
                },
            );
            rpc
        }))
    }

    async fn get_transaction_by_hash(
        &self,
        hash: ShellHash,
    ) -> Result<Option<RpcTransaction>, ErrorObjectOwned> {
        // Check mempool first
        if let Some(pending_tx) = self.tx_pool.get_shared(&hash) {
            return Ok(Some(tx_to_rpc(&pending_tx, None, None, None, None)));
        }

        // Then check on-chain index
        let location = self
            .chain_store
            .get_tx_location(&hash)
            .map_err(internal_err)?;

        if let Some((block_hash, tx_index)) = location {
            let block = self
                .chain_store
                .get_block_by_hash(&block_hash)
                .map_err(internal_err)?;
            if let Some(block) = block {
                if let Some(tx) = block.transactions.get(tx_index as usize) {
                    return Ok(Some(tx_to_rpc(
                        tx,
                        Some(block_hash),
                        Some(block.number()),
                        Some(tx_index),
                        Some(block.header.base_fee_per_gas),
                    )));
                }
            }
        }

        if let Some(system_tx) = self
            .chain_store
            .get_system_transaction_by_hash(&hash)
            .map_err(internal_err)?
        {
            let block_hash = self
                .chain_store
                .get_tx_location(&hash)
                .map_err(internal_err)?
                .map(|(h, _)| h);
            return Ok(Some(system_tx_to_rpc(&system_tx, block_hash)));
        }

        Ok(None)
    }

    async fn get_transaction_receipt(
        &self,
        hash: ShellHash,
    ) -> Result<Option<RpcReceipt>, ErrorObjectOwned> {
        let location = self
            .chain_store
            .get_tx_location(&hash)
            .map_err(internal_err)?;

        if let Some((block_hash, tx_index)) = location {
            let block = self
                .chain_store
                .get_block_by_hash(&block_hash)
                .map_err(internal_err)?;
            let receipts = self
                .chain_store
                .get_receipts(&block_hash)
                .map_err(internal_err)?;
            if let (Some(block), Some(receipts)) = (block, receipts) {
                if let Some(receipt) = receipts.get(tx_index as usize).cloned() {
                    // F-067: populate from/to/effective_gas_price from the transaction.
                    let (from, to, eff_gas_price, tx_type_val, shell_type, reward_kind) =
                        if let Some(tx) = block.transactions.get(tx_index as usize) {
                            let price = shell_core::effective_gas_price(
                                tx.tx.max_fee_per_gas,
                                tx.tx.max_priority_fee_per_gas,
                                block.header.base_fee_per_gas,
                            );
                            let shell_type = if tx.is_aa_bundle() {
                                "aaBatch"
                            } else if tx.tx.to.is_none() {
                                "contractCreate"
                            } else if !tx.tx.data.is_empty() {
                                "contractCall"
                            } else {
                                "transfer"
                            };
                            (
                                tx.sender(),
                                tx.tx.to,
                                price,
                                tx.tx.tx_type,
                                Some(shell_type.into()),
                                None,
                            )
                        } else if let Some(system_tx) = self
                            .chain_store
                            .get_system_transaction_by_hash(&hash)
                            .map_err(internal_err)?
                        {
                            (
                                system_tx.from,
                                Some(system_tx.to),
                                0,
                                0x80u8,
                                Some(system_tx.kind.as_str().into()),
                                Some(system_tx.kind.as_str().into()),
                            )
                        } else {
                            (Address::ZERO, None, 0, 2u8, None, None)
                        };

                    return Ok(Some(RpcReceipt {
                        transaction_hash: receipt.tx_hash,
                        block_hash,
                        block_number: hex_u64(receipt.block_number),
                        transaction_index: hex_u64(tx_index as u64),
                        from,
                        to,
                        status: hex_u64(receipt.status as u64),
                        gas_used: hex_u64(receipt.gas_used),
                        cumulative_gas_used: hex_u64(receipt.cumulative_gas_used),
                        effective_gas_price: hex_u64(eff_gas_price),
                        contract_address: receipt.contract_address,
                        logs: rpc_logs_from_core(receipt.logs),
                        logs_bloom: hex_bytes(receipt.logs_bloom.as_ref()),
                        tx_type: format!("{:#x}", tx_type_val),
                        shell_type,
                        reward_kind,
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn get_block_receipts(&self, block: String) -> Result<Vec<RpcReceipt>, ErrorObjectOwned> {
        // Resolve block identifier (number, tag, or hash)
        let block_obj = if block.starts_with("0x") && block.len() == 66 {
            let hex_str = block.strip_prefix("0x").unwrap_or(&block);
            let hash_bytes = hex::decode(hex_str)
                .map_err(|e| invalid_params_err(format!("invalid block hash hex: {e}")))?;
            let hash = ShellHash::try_from_slice(&hash_bytes)
                .map_err(|e| invalid_params_err(format!("invalid block hash: {e}")))?;
            self.chain_store
                .get_block_by_hash(&hash)
                .map_err(internal_err)?
        } else {
            match parse_block_tag(&block)? {
                BlockTag::Pending => None,
                BlockTag::Latest => self.chain_store.get_head_block().map_err(internal_err)?,
                BlockTag::Finalized => {
                    let num = *self.finalized_number.read();
                    self.chain_store
                        .get_block_by_number(num)
                        .map_err(internal_err)?
                }
                BlockTag::Number(num) => self
                    .chain_store
                    .get_block_by_number(num)
                    .map_err(internal_err)?,
            }
        };

        let block_obj = match block_obj {
            Some(b) => b,
            None => return Ok(vec![]),
        };

        let block_hash = block_obj.hash();
        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .unwrap_or_default();
        let system_txs_by_index: std::collections::HashMap<usize, SystemTransaction> = self
            .chain_store
            .get_system_transactions(&block_hash)
            .map_err(internal_err)?
            .into_iter()
            .map(|tx| (tx.tx_index as usize, tx))
            .collect();

        let mut rpc_receipts = Vec::with_capacity(receipts.len());
        for (i, receipt) in receipts.into_iter().enumerate() {
            let (from, to, eff_gas_price, tx_type_val, shell_type, reward_kind) =
                if let Some(tx) = block_obj.transactions.get(i) {
                    let price = shell_core::effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        block_obj.header.base_fee_per_gas,
                    );
                    let shell_type = if tx.is_aa_bundle() {
                        "aaBatch"
                    } else if tx.tx.to.is_none() {
                        "contractCreate"
                    } else if !tx.tx.data.is_empty() {
                        "contractCall"
                    } else {
                        "transfer"
                    };
                    (
                        tx.sender(),
                        tx.tx.to,
                        price,
                        tx.tx.tx_type,
                        Some(shell_type.into()),
                        None,
                    )
                } else if let Some(system_tx) = system_txs_by_index.get(&i) {
                    (
                        system_tx.from,
                        Some(system_tx.to),
                        0,
                        0x80u8,
                        Some(system_tx.kind.as_str().into()),
                        Some(system_tx.kind.as_str().into()),
                    )
                } else {
                    (Address::ZERO, None, 0, 2u8, None, None)
                };

            rpc_receipts.push(RpcReceipt {
                transaction_hash: receipt.tx_hash,
                block_hash,
                block_number: hex_u64(receipt.block_number),
                transaction_index: hex_u64(i as u64),
                from,
                to,
                status: hex_u64(receipt.status as u64),
                gas_used: hex_u64(receipt.gas_used),
                cumulative_gas_used: hex_u64(receipt.cumulative_gas_used),
                effective_gas_price: hex_u64(eff_gas_price),
                contract_address: receipt.contract_address,
                logs: rpc_logs_from_core(receipt.logs),
                logs_bloom: hex_bytes(receipt.logs_bloom.as_ref()),
                tx_type: format!("{:#x}", tx_type_val),
                shell_type,
                reward_kind,
            });
        }

        Ok(rpc_receipts)
    }

    async fn get_balance(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_state_block_is_latest(tag)?;
        }
        let ws = self.world_state.read();
        let balance = ws.get_balance(&address).map_err(internal_err)?;
        Ok(hex_u256(balance))
    }

    async fn get_transaction_count(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let include_pending = matches!(block.as_deref(), Some("pending"));
        if let Some(ref tag) = block {
            validate_state_block_is_latest(tag)?;
        }
        let ws = self.world_state.read();
        let mut nonce = ws.get_nonce(&address).map_err(internal_err)?;
        drop(ws);
        if include_pending {
            nonce = self.tx_pool.pending_nonce(&address, nonce);
        }
        Ok(hex_u64(nonce))
    }

    async fn gas_price(&self) -> Result<String, ErrorObjectOwned> {
        // Return the base fee from the latest block, or INITIAL_BASE_FEE if no blocks exist.
        let base_fee = self
            .chain_store
            .get_head_block()
            .map_err(internal_err)?
            .map(|head| head.header.base_fee_per_gas)
            .filter(|fee| *fee > 0)
            .unwrap_or(shell_core::INITIAL_BASE_FEE);
        Ok(hex_u64(base_fee))
    }

    async fn max_priority_fee_per_gas(&self) -> Result<String, ErrorObjectOwned> {
        // PoA chain: no fee market competition, priority fee is always 0.
        Ok(hex_u64(0))
    }

    async fn fee_history(
        &self,
        block_count: String,
        newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let latest = match self.parse_block_number(&newest_block)? {
            Some(n) => n,
            None => {
                // "latest" — get head block number
                self.chain_store
                    .get_head_block()
                    .map_err(internal_err)?
                    .map(|head| head.header.number)
                    .unwrap_or(0)
            }
        };

        let count = parse_hex_u64(&block_count)?;
        if count == 0 {
            return Err(invalid_params_err(
                "feeHistory blockCount must be at least 1",
            ));
        }
        if count > 1024 {
            return Err(invalid_params_err(
                "feeHistory blockCount must be at most 1024",
            ));
        }
        if let Some(percentiles) = reward_percentiles.as_deref() {
            if percentiles.len() > MAX_FEE_HISTORY_REWARD_PERCENTILES {
                return Err(invalid_params_err(format!(
                    "feeHistory reward percentiles must contain at most {MAX_FEE_HISTORY_REWARD_PERCENTILES} entries"
                )));
            }
            validate_reward_percentiles(percentiles)?;
        }

        let oldest = latest.saturating_sub(count.saturating_sub(1));

        let mut base_fee_per_gas = Vec::new();
        let mut gas_used_ratio = Vec::new();
        let mut reward = reward_percentiles
            .as_ref()
            .filter(|percentiles| !percentiles.is_empty())
            .map(|_| Vec::with_capacity((latest.saturating_sub(oldest) + 1) as usize));

        for num in oldest..=latest {
            match self.chain_store.get_block_by_number(num) {
                Ok(Some(block)) => {
                    let h = &block.header;
                    base_fee_per_gas.push(hex_u64(h.base_fee_per_gas));
                    let ratio = if h.gas_limit > 0 {
                        h.gas_used as f64 / h.gas_limit as f64
                    } else {
                        0.0
                    };
                    gas_used_ratio.push(ratio);
                }
                Ok(None) => {
                    base_fee_per_gas.push(hex_u64(0));
                    gas_used_ratio.push(0.0);
                }
                Err(error) => return Err(internal_err(error)),
            }
            if let (Some(reward), Some(percentiles)) = (&mut reward, reward_percentiles.as_ref()) {
                reward.push(vec![hex_u64(0); percentiles.len()]);
            }
        }

        // Append next block's predicted base fee (one more entry than gas_used_ratio).
        if let Some(head) = self
            .chain_store
            .get_block_by_number(latest)
            .map_err(internal_err)?
        {
            let next = shell_core::fee::calculate_base_fee(
                head.header.gas_used,
                head.header.gas_limit,
                head.header.base_fee_per_gas,
            );
            base_fee_per_gas.push(hex_u64(next));
        } else {
            base_fee_per_gas.push(hex_u64(shell_core::INITIAL_BASE_FEE));
        }

        Ok(serde_json::json!({
            "oldestBlock": hex_u64(oldest),
            "baseFeePerGas": base_fee_per_gas,
            "gasUsedRatio": gas_used_ratio,
            "reward": reward.unwrap_or_default()
        }))
    }

    async fn send_raw_transaction(&self, data: String) -> Result<ShellHash, ErrorObjectOwned> {
        // Decode hex payload: "0x" + hex-encoded transaction bytes.
        let Some(raw) = data.strip_prefix("0x") else {
            return Err(invalid_params_err(
                "raw transaction data must be 0x-prefixed",
            ));
        };
        if raw.len() > shell_mempool::MAX_TX_SIZE.saturating_mul(2) {
            return Err(invalid_params_err(format!(
                "raw transaction exceeds maximum size of {} bytes",
                shell_mempool::MAX_TX_SIZE
            )));
        }
        let bytes =
            hex::decode(raw).map_err(|e| invalid_params_err(format!("invalid hex: {e}")))?;

        // Try RLP decoding first (standard Ethereum format), then JSON (legacy).
        let signed_tx: SignedTransaction = {
            let mut slice = bytes.as_slice();
            match alloy_rlp::Decodable::decode(&mut slice) {
                Ok(tx) if slice.is_empty() => tx,
                Ok(_) => {
                    // RLP decoded but trailing bytes remain — reject per Geth behavior.
                    return Err(invalid_params_err(
                        "invalid transaction: RLP has trailing bytes",
                    ));
                }
                Err(_) => serde_json::from_slice::<SignedTransaction>(&bytes).map_err(|e| {
                    invalid_params_err(format!("invalid transaction: not valid RLP or JSON ({e})"))
                })?,
            }
        };

        self.submit_tx(signed_tx)
    }

    async fn call(
        &self,
        tx: crate::types::CallRequest,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_state_block_is_latest(tag)?;
        }
        let (output, _gas_used) = self.execute_call(&tx)?;
        Ok(hex_bytes(&output))
    }

    async fn estimate_gas(
        &self,
        tx: crate::types::CallRequest,
    ) -> Result<String, ErrorObjectOwned> {
        let (_output, gas_used) = self.execute_call(&tx)?;
        // Add a 20% buffer to the estimated gas, with a minimum of 21000.
        let estimate = buffered_gas_estimate(gas_used, 21_000);
        Ok(hex_u64(estimate))
    }

    async fn create_access_list(
        &self,
        tx: crate::types::CallRequest,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_state_block_is_latest(tag)?;
        }
        let (_output, gas_used) = self.execute_call(&tx)?;
        // Simplified implementation: return the provided access list (or empty)
        // and the estimated gas.
        let access_list = tx
            .access_list
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                serde_json::json!({
                    "address": item.address,
                    "storageKeys": item.storage_keys,
                })
            })
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "accessList": access_list,
            "gasUsed": hex_u64(gas_used),
        }))
    }

    async fn get_code(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_state_block_is_latest(tag)?;
        }
        let ws = self.world_state.read();
        let code_hash = ws.get_code_hash(&address).map_err(internal_err)?;
        match code_hash {
            Some(hash) => {
                let code = self.chain_store.get_code(&hash).map_err(internal_err)?;
                match code {
                    Some(bytes) => Ok(hex_bytes(&bytes)),
                    None => Ok("0x".into()),
                }
            }
            None => Ok("0x".into()),
        }
    }

    async fn get_storage_at(
        &self,
        address: Address,
        position: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_state_block_is_latest(tag)?;
        }
        let key_u256 = parse_hex_u256(&position)?;
        let key = ShellHash::from(alloy_primitives::B256::from(key_u256));
        let ws = self.world_state.read();
        let value = ws.get_storage(&address, &key).map_err(internal_err)?;
        // Return as zero-padded 32-byte hex string.
        Ok(format!("0x{}", hex::encode(value.as_bytes())))
    }

    async fn get_logs(
        &self,
        raw_filter: RawLogFilter,
    ) -> Result<Vec<RpcLogWithMeta>, ErrorObjectOwned> {
        // Resolve "latest" block number.
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.map(|b| b.number()).unwrap_or(0);
        let finalized = *self.finalized_number.read();

        let filter = raw_filter
            .into_filter(latest, finalized)
            .map_err(invalid_params)?;

        let from = filter.from_block.unwrap_or(latest);
        let to = filter.to_block.unwrap_or(latest);

        if from > to {
            return Ok(vec![]);
        }

        // Cap range to prevent DoS.
        if to.saturating_sub(from).saturating_add(1) > MAX_BLOCK_RANGE {
            return Err(limit_exceeded(format!(
                "query returned more than {} blocks; cap the range",
                MAX_BLOCK_RANGE
            )));
        }

        let mut results = Vec::new();

        for block_num in from..=to {
            let block = match self
                .chain_store
                .get_block_by_number(block_num)
                .map_err(internal_err)?
            {
                Some(b) => b,
                None => continue,
            };

            // Fast path: check block-level bloom filter.
            if !filter.matches_bloom(block.header.logs_bloom.as_ref()) {
                continue;
            }

            let block_hash = block.hash();

            let receipts = match self
                .chain_store
                .get_receipts(&block_hash)
                .map_err(internal_err)?
            {
                Some(receipts) => receipts,
                None if block
                    .header
                    .logs_bloom
                    .as_ref()
                    .iter()
                    .all(|byte| *byte == 0) =>
                {
                    Vec::new()
                }
                None => {
                    return Err(internal_err(format!(
                        "receipts for block {block_hash} are unavailable during log query"
                    )));
                }
            };

            // F-073: track bloom false positives — count results before this block.
            let results_before = results.len();

            // Global log index across all receipts in this block.
            let mut global_log_index: u64 = 0;

            for (tx_idx, receipt) in receipts.into_iter().enumerate() {
                // Per-receipt bloom fast path.
                if receipt.logs_bloom.len() == BLOOM_SIZE
                    && !filter.matches_bloom(receipt.logs_bloom.as_ref())
                {
                    global_log_index += receipt.logs.len() as u64;
                    continue;
                }

                let tx_hash = receipt.tx_hash;
                for log in receipt.logs {
                    if filter.matches_log(&log) {
                        let data = hex_bytes(log.data.as_ref());
                        if results.len() >= MAX_LOG_RESULTS {
                            return Err(limit_exceeded(format!(
                                "query returned more than {MAX_LOG_RESULTS} logs; narrow the filter"
                            )));
                        }
                        results.push(RpcLogWithMeta {
                            address: log.address,
                            topics: log.topics,
                            data,
                            block_number: hex_u64(block_num),
                            block_hash,
                            transaction_hash: tx_hash,
                            transaction_index: hex_u64(tx_idx as u64),
                            log_index: hex_u64(global_log_index),
                            removed: false,
                        });
                    }
                    global_log_index += 1;
                }
            }

            // F-073: bloom passed but no logs matched → false positive.
            if results.len() == results_before {
                self.bloom_false_positives.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(results)
    }

    async fn new_filter(&self, mut filter: RawLogFilter) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let head_hash = head.as_ref().map(Block::hash);
        let finalized = *self.finalized_number.read();
        let resolved = filter
            .clone()
            .into_filter(latest, finalized)
            .map_err(invalid_params)?;
        let initial_block = latest.min(resolved.to_block.unwrap_or(latest));
        let initial_hash = if initial_block == latest {
            head_hash
        } else {
            self.chain_store
                .get_block_hash_by_number(initial_block)
                .map_err(internal_err)?
        };
        // Resolve fromBlock at creation so dynamic tags cannot skip blocks
        // between polls and get_filter_logs has a stable lower bound.
        filter.from_block = Some(format!("0x{:x}", resolved.from_block.unwrap_or(latest)));
        let id = self
            .filter_registry
            .new_filter_at(FilterKind::Log(filter), initial_block, initial_hash)
            .ok_or_else(|| internal_err("filter limit reached"))?;
        Ok(id)
    }

    async fn new_block_filter(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let head_hash = head.as_ref().map(Block::hash);
        let id = self
            .filter_registry
            .new_filter_at(FilterKind::Block, latest, head_hash)
            .ok_or_else(|| internal_err("filter limit reached"))?;
        Ok(id)
    }

    async fn get_filter_changes(&self, id: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (is_log, cursor) = self
            .filter_registry
            .get_filter_cursor(&id)
            .ok_or_else(|| not_found("filter not found"))?;

        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let log_poll = if is_log {
            let raw = self
                .filter_registry
                .get_log_filter(&id)
                .ok_or_else(|| not_found("filter not found"))?;
            let removed_to_block_is_unbounded = matches!(
                raw.to_block.as_deref(),
                None | Some("latest") | Some("pending")
            );
            let finalized = *self.finalized_number.read();
            let filter = raw.into_filter(latest, finalized).map_err(internal_err)?;
            let removed_to_block = if removed_to_block_is_unbounded {
                u64::MAX
            } else {
                filter.to_block.unwrap_or(latest)
            };
            Some((filter, removed_to_block))
        } else {
            None
        };
        let canonical_latest = log_poll
            .as_ref()
            .and_then(|(filter, _)| filter.to_block)
            .map_or(latest, |to_block| latest.min(to_block));
        let reorg = find_filter_reorg(&self.chain_store, cursor, latest)?;
        let (base_cursor, removed_blocks) = match reorg {
            Some(reorg) => (reorg.ancestor, reorg.removed_blocks),
            None => (cursor, Vec::new()),
        };
        let remaining_blocks = MAX_BLOCK_RANGE.saturating_sub(removed_blocks.len() as u64);
        let canonical_from = if base_cursor.block_number == 0 && base_cursor.block_hash.is_none() {
            // A cursor without a hash represents a filter installed before the
            // chain had a head. Block zero is new to that filter once it exists.
            Some(base_cursor.block_number)
        } else {
            base_cursor.block_number.checked_add(1)
        }
        .filter(|from| remaining_blocks > 0 && *from <= canonical_latest);
        let canonical_to = canonical_from.map(|from| {
            canonical_latest.min(from.saturating_add(remaining_blocks.saturating_sub(1)))
        });
        let mut new_cursor = base_cursor;
        let mut canonical_blocks = Vec::new();
        let mut expected_parent = base_cursor.block_hash;
        if let (Some(from), Some(to)) = (canonical_from, canonical_to) {
            for block_number in from..=to {
                let block = self
                    .chain_store
                    .get_block_by_number(block_number)
                    .map_err(internal_err)?
                    .ok_or_else(|| {
                        internal_err(format!(
                            "canonical block {block_number} missing during filter poll"
                        ))
                    })?;
                if let Some(expected_parent) = expected_parent {
                    if block.header.parent_hash != expected_parent {
                        return Err(internal_err(format!(
                            "canonical block {block_number} changed during filter poll"
                        )));
                    }
                }
                let block_hash = block.hash();
                canonical_blocks.push((block_number, block_hash));
                expected_parent = Some(block_hash);
                new_cursor = FilterCursor {
                    block_number,
                    block_hash: Some(block_hash),
                };
            }
        }

        if let Some((filter, removed_to_block)) = log_poll {
            let mut results = Vec::new();

            for (block_number, block_hash) in removed_blocks {
                if block_number >= filter.from_block.unwrap_or(0)
                    && block_number <= removed_to_block
                {
                    append_filter_logs(
                        &self.chain_store,
                        &filter,
                        block_number,
                        block_hash,
                        true,
                        &mut results,
                    )?;
                }
            }

            for (block_number, block_hash) in canonical_blocks {
                if block_number >= filter.from_block.unwrap_or(0)
                    && block_number <= filter.to_block.unwrap_or(latest)
                {
                    append_filter_logs(
                        &self.chain_store,
                        &filter,
                        block_number,
                        block_hash,
                        false,
                        &mut results,
                    )?;
                }
            }

            if !self.filter_registry.update_cursor(&id, cursor, new_cursor) {
                return Err(internal_err(
                    "filter cursor changed during poll; retry the request",
                ));
            }
            Ok(serde_json::to_value(&results).unwrap_or(serde_json::json!([])))
        } else {
            let hashes = canonical_blocks
                .into_iter()
                .map(|(_, block_hash)| block_hash)
                .collect::<Vec<_>>();

            if !self.filter_registry.update_cursor(&id, cursor, new_cursor) {
                return Err(internal_err(
                    "filter cursor changed during poll; retry the request",
                ));
            }
            Ok(serde_json::to_value(&hashes).unwrap_or(serde_json::json!([])))
        }
    }

    async fn get_filter_logs(&self, id: String) -> Result<Vec<RpcLogWithMeta>, ErrorObjectOwned> {
        // Only valid for log filters — re-query all matching logs.
        let raw = self
            .filter_registry
            .get_log_filter(&id)
            .ok_or_else(|| not_found("filter not found"))?;
        self.get_logs(raw).await
    }

    async fn uninstall_filter(&self, id: String) -> Result<bool, ErrorObjectOwned> {
        Ok(self.filter_registry.uninstall(&id))
    }

    async fn blob_base_fee(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let excess = head.map(|b| b.header.excess_blob_gas).unwrap_or(0);
        let price = shell_core::calc_blob_gas_price(excess);
        Ok(hex_u64(price))
    }
}

fn validate_reward_percentiles(percentiles: &[f64]) -> Result<(), ErrorObjectOwned> {
    let mut previous = None;
    for percentile in percentiles {
        if !percentile.is_finite() {
            return Err(invalid_params_err(
                "feeHistory reward percentiles must be finite",
            ));
        }
        if !(0.0..=100.0).contains(percentile) {
            return Err(invalid_params_err(
                "feeHistory reward percentiles must be between 0 and 100",
            ));
        }
        if previous.is_some_and(|previous| *percentile < previous) {
            return Err(invalid_params_err(
                "feeHistory reward percentiles must be non-decreasing",
            ));
        }
        previous = Some(*percentile);
    }
    Ok(())
}
