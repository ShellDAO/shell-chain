use super::*;

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
        Err(ErrorObjectOwned::owned(
            -32601,
            "eth_sign is not supported: node does not hold private keys",
            None::<()>,
        ))
    }

    async fn sign_transaction(&self, _tx: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        Err(ErrorObjectOwned::owned(
            -32601,
            "eth_signTransaction is not supported: node does not hold private keys",
            None::<()>,
        ))
    }

    async fn get_compilers(&self) -> Result<Vec<String>, ErrorObjectOwned> {
        // Deprecated method; always returns an empty array.
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
                Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
            }
            BlockTag::Number(n) => {
                let block = self
                    .chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?;
                Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
            }
            BlockTag::Latest => {
                let block = self.chain_store.get_head_block().map_err(internal_err)?;
                Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
            }
            BlockTag::Pending => {
                // F-075: construct a pseudo-block from the mempool.
                let head = self.chain_store.get_head_block().map_err(internal_err)?;
                let head = match head {
                    Some(b) => b,
                    None => return Ok(None),
                };
                let all_pending = self.tx_pool.pending(1000);
                // F-101: cap pending txs by gas_limit to prevent oversized pseudo-blocks.
                let gas_limit = head.header.gas_limit;
                let mut cumulative_gas: u64 = 0;
                let pending_txs: Vec<_> = all_pending
                    .into_iter()
                    .take_while(|tx| {
                        cumulative_gas = cumulative_gas.saturating_add(tx.tx.gas_limit);
                        cumulative_gas <= gas_limit
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
                            .map(|tx| tx_to_rpc(tx, None, Some(head.header.number + 1), None, None))
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
                    number: hex_u64(head.header.number + 1),
                    timestamp: hex_u64(now),
                    gas_limit: hex_u64(head.header.gas_limit),
                    gas_used: hex_u64(0),
                    miner: head.header.proposer,
                    state_root: head.header.state_root,
                    transactions_root: ShellHash::ZERO,
                    receipts_root: ShellHash::ZERO,
                    transactions,
                    size: hex_u64(size as u64),
                    base_fee_per_gas: hex_u64(head.header.base_fee_per_gas),
                    total_difficulty: "0x1".into(),
                    sha3_uncles: crate::types::EMPTY_OMMER_HASH.into(),
                    uncles: vec![],
                    nonce: "0x0000000000000000".into(),
                    difficulty: "0x1".into(),
                    mix_hash: ShellHash::ZERO,
                    extra_data: "0x".into(),
                    logs_bloom: format!("0x{}", "00".repeat(BLOOM_SIZE)),
                    withdrawals_root: format!("{:?}", ShellHash::ZERO),
                    parent_beacon_block_root: format!("{:?}", ShellHash::ZERO),
                    blob_gas_used: hex_u64(0),
                    excess_blob_gas: hex_u64(0),
                    sig_aggregate_proof: None,
                    sig_aggregate_proof_size: None,
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
        Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
    }

    async fn get_transaction_by_hash(
        &self,
        hash: ShellHash,
    ) -> Result<Option<RpcTransaction>, ErrorObjectOwned> {
        // Check mempool first
        if let Some(pending_tx) = self.tx_pool.get(&hash) {
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
                if let Some(receipt) = receipts.get(tx_index as usize) {
                    // F-067: populate from/to/effective_gas_price from the transaction.
                    let (from, to, eff_gas_price, tx_type_val) =
                        if let Some(tx) = block.transactions.get(tx_index as usize) {
                            let price = shell_core::effective_gas_price(
                                tx.tx.max_fee_per_gas,
                                tx.tx.max_priority_fee_per_gas,
                                block.header.base_fee_per_gas,
                            );
                            (tx.sender(), tx.tx.to, price, tx.tx.tx_type)
                        } else {
                            (Address::ZERO, None, 0, 2u8)
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
                        logs: receipt
                            .logs
                            .iter()
                            .map(|log| RpcLog {
                                address: log.address,
                                topics: log.topics.clone(),
                                data: hex_bytes(log.data.as_ref()),
                            })
                            .collect(),
                        logs_bloom: hex_bytes(receipt.logs_bloom.as_ref()),
                        tx_type: format!("{:#x}", tx_type_val),
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
                .map_err(|e| internal_err(format!("invalid block hash hex: {e}")))?;
            let hash = ShellHash::try_from_slice(&hash_bytes)
                .map_err(|e| internal_err(format!("invalid block hash: {e}")))?;
            self.chain_store
                .get_block_by_hash(&hash)
                .map_err(internal_err)?
        } else {
            match self.parse_block_number(&block)? {
                Some(num) => self
                    .chain_store
                    .get_block_by_number(num)
                    .map_err(internal_err)?,
                None => self.chain_store.get_head_block().map_err(internal_err)?,
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

        let mut rpc_receipts = Vec::with_capacity(receipts.len());
        for (i, receipt) in receipts.iter().enumerate() {
            let (from, to, eff_gas_price, tx_type_val) =
                if let Some(tx) = block_obj.transactions.get(i) {
                    let price = shell_core::effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        block_obj.header.base_fee_per_gas,
                    );
                    (tx.sender(), tx.tx.to, price, tx.tx.tx_type)
                } else {
                    (Address::ZERO, None, 0, 2u8)
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
                logs: receipt
                    .logs
                    .iter()
                    .map(|log| RpcLog {
                        address: log.address,
                        topics: log.topics.clone(),
                        data: hex_bytes(log.data.as_ref()),
                    })
                    .collect(),
                logs_bloom: hex_bytes(receipt.logs_bloom.as_ref()),
                tx_type: format!("{:#x}", tx_type_val),
            });
        }

        Ok(rpc_receipts)
    }

    async fn get_balance(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        // F-100: validate block parameter — reject malformed block tags.
        if let Some(ref tag) = block {
            validate_block_is_latest(tag)?;
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
        if let Some(ref tag) = block {
            validate_block_is_latest(tag)?;
        }
        let ws = self.world_state.read();
        let nonce = ws.get_nonce(&address).map_err(internal_err)?;
        Ok(hex_u64(nonce))
    }

    async fn gas_price(&self) -> Result<String, ErrorObjectOwned> {
        // Return the base fee from the latest block, or INITIAL_BASE_FEE if no blocks exist.
        let base_fee = match self.chain_store.get_head_block() {
            Ok(Some(head)) if head.header.base_fee_per_gas > 0 => head.header.base_fee_per_gas,
            _ => shell_core::INITIAL_BASE_FEE,
        };
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
        _reward_percentiles: Option<Vec<f64>>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let latest = match self.parse_block_number(&newest_block)? {
            Some(n) => n,
            None => {
                // "latest" — get head block number
                match self.chain_store.get_head_block() {
                    Ok(Some(head)) => head.header.number,
                    _ => 0,
                }
            }
        };

        let count = parse_hex_u64(&block_count)?.min(1024);

        let oldest = latest.saturating_sub(count.saturating_sub(1));

        let mut base_fee_per_gas = Vec::new();
        let mut gas_used_ratio = Vec::new();

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
                _ => {
                    base_fee_per_gas.push(hex_u64(0));
                    gas_used_ratio.push(0.0);
                }
            }
        }

        // Append next block's predicted base fee (one more entry than gas_used_ratio).
        if let Ok(Some(head)) = self.chain_store.get_block_by_number(latest) {
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
            "reward": []
        }))
    }

    async fn send_raw_transaction(&self, data: String) -> Result<ShellHash, ErrorObjectOwned> {
        // Decode hex payload: "0x" + hex-encoded transaction bytes.
        let raw = data.strip_prefix("0x").unwrap_or(&data);
        let bytes = hex::decode(raw).map_err(|e| internal_err(format!("invalid hex: {e}")))?;

        // Try RLP decoding first (standard Ethereum format), then JSON (legacy).
        let signed_tx: SignedTransaction = {
            let mut slice = bytes.as_slice();
            match alloy_rlp::Decodable::decode(&mut slice) {
                Ok(tx) if slice.is_empty() => tx,
                Ok(_) => {
                    // RLP decoded but trailing bytes remain — reject per Geth behavior.
                    return Err(internal_err(
                        "invalid transaction: RLP has trailing bytes".to_string(),
                    ));
                }
                Err(_) => serde_json::from_slice::<SignedTransaction>(&bytes).map_err(|e| {
                    internal_err(format!("invalid transaction: not valid RLP or JSON ({e})"))
                })?,
            }
        };

        self.submit_tx(signed_tx)
    }

    async fn call(
        &self,
        tx: crate::types::CallRequest,
        _block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let (output, _gas_used) = self.execute_call(&tx)?;
        Ok(hex_bytes(&output))
    }

    async fn estimate_gas(
        &self,
        tx: crate::types::CallRequest,
    ) -> Result<String, ErrorObjectOwned> {
        let (_output, gas_used) = self.execute_call(&tx)?;
        // Add a 20% buffer to the estimated gas, with a minimum of 21000.
        let estimate = std::cmp::max((gas_used as f64 * 1.2) as u64, 21_000);
        Ok(hex_u64(estimate))
    }

    async fn create_access_list(
        &self,
        tx: crate::types::CallRequest,
        _block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
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
            validate_block_is_latest(tag)?;
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
            validate_block_is_latest(tag)?;
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

        let filter = raw_filter.into_filter(latest);

        let from = filter.from_block.unwrap_or(latest);
        let to = filter.to_block.unwrap_or(latest);

        if from > to {
            return Ok(vec![]);
        }

        // Cap range to prevent DoS.
        if to - from + 1 > MAX_BLOCK_RANGE {
            return Err(ErrorObjectOwned::owned(
                -32005,
                format!(
                    "query returned more than {} blocks; cap the range",
                    MAX_BLOCK_RANGE
                ),
                None::<()>,
            ));
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

            let receipts = self
                .chain_store
                .get_receipts(&block_hash)
                .map_err(internal_err)?
                .unwrap_or_default();

            // F-073: track bloom false positives — count results before this block.
            let results_before = results.len();

            // Global log index across all receipts in this block.
            let mut global_log_index: u64 = 0;

            for (tx_idx, receipt) in receipts.iter().enumerate() {
                // Per-receipt bloom fast path.
                if receipt.logs_bloom.len() == BLOOM_SIZE
                    && !filter.matches_bloom(receipt.logs_bloom.as_ref())
                {
                    global_log_index += receipt.logs.len() as u64;
                    continue;
                }

                for log in &receipt.logs {
                    if filter.matches_log(log) {
                        results.push(RpcLogWithMeta {
                            address: log.address,
                            topics: log.topics.clone(),
                            data: hex_bytes(log.data.as_ref()),
                            block_number: hex_u64(block_num),
                            block_hash,
                            transaction_hash: receipt.tx_hash,
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
        let latest = head.map(|b| b.number()).unwrap_or(0);
        // F-125: resolve from_block at creation time so get_filter_logs
        // does not re-scan from block 0 on every call.
        if filter.from_block.is_none() {
            filter.from_block = Some(format!("0x{:x}", latest));
        }
        let id = self
            .filter_registry
            .new_filter(FilterKind::Log(filter), latest)
            .ok_or_else(|| internal_err("filter limit reached"))?;
        Ok(id)
    }

    async fn new_block_filter(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.map(|b| b.number()).unwrap_or(0);
        let id = self
            .filter_registry
            .new_filter(FilterKind::Block, latest)
            .ok_or_else(|| internal_err("filter limit reached"))?;
        Ok(id)
    }

    async fn get_filter_changes(&self, id: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Determine filter type and last polled block.
        let (is_log, last_poll_block) = self
            .filter_registry
            .get_filter_info(&id)
            .ok_or_else(|| ErrorObjectOwned::owned(-32000, "filter not found", None::<()>))?;

        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.map(|b| b.number()).unwrap_or(0);

        if is_log {
            // Log filter: query logs from (last_poll_block + 1) to latest.
            let from = last_poll_block.saturating_add(1);
            if from > latest {
                self.filter_registry.update_last_poll(&id, latest);
                return Ok(serde_json::json!([]));
            }

            // Retrieve the original filter criteria.
            let raw = self
                .filter_registry
                .get_log_filter(&id)
                .ok_or_else(|| ErrorObjectOwned::owned(-32000, "filter not found", None::<()>))?;
            let filter = raw.into_filter(latest);

            let mut results = Vec::new();
            let actual_to = latest.min(from + MAX_BLOCK_RANGE - 1);

            for block_num in from..=actual_to {
                let block = match self
                    .chain_store
                    .get_block_by_number(block_num)
                    .map_err(internal_err)?
                {
                    Some(b) => b,
                    None => continue,
                };

                if !filter.matches_bloom(block.header.logs_bloom.as_ref()) {
                    continue;
                }

                let block_hash = block.hash();
                let receipts = self
                    .chain_store
                    .get_receipts(&block_hash)
                    .map_err(internal_err)?
                    .unwrap_or_default();

                let mut global_log_index: u64 = 0;
                for (tx_idx, receipt) in receipts.iter().enumerate() {
                    for log in &receipt.logs {
                        if filter.matches_log(log) {
                            results.push(RpcLogWithMeta {
                                address: log.address,
                                topics: log.topics.clone(),
                                data: hex_bytes(log.data.as_ref()),
                                block_number: hex_u64(block_num),
                                block_hash,
                                transaction_hash: receipt.tx_hash,
                                transaction_index: hex_u64(tx_idx as u64),
                                log_index: hex_u64(global_log_index),
                                removed: false,
                            });
                        }
                        global_log_index += 1;
                    }
                }
            }

            self.filter_registry.update_last_poll(&id, actual_to);
            Ok(serde_json::to_value(&results).unwrap_or(serde_json::json!([])))
        } else {
            // Block filter: collect hashes of blocks since last poll.
            let from = last_poll_block.saturating_add(1);
            if from > latest {
                self.filter_registry.update_last_poll(&id, latest);
                return Ok(serde_json::json!([]));
            }

            let mut hashes = Vec::new();
            for block_num in from..=latest {
                if let Some(block) = self
                    .chain_store
                    .get_block_by_number(block_num)
                    .map_err(internal_err)?
                {
                    hashes.push(block.hash());
                }
            }

            self.filter_registry.update_last_poll(&id, latest);
            Ok(serde_json::to_value(&hashes).unwrap_or(serde_json::json!([])))
        }
    }

    async fn get_filter_logs(&self, id: String) -> Result<Vec<RpcLogWithMeta>, ErrorObjectOwned> {
        // Only valid for log filters — re-query all matching logs.
        let raw = self
            .filter_registry
            .get_log_filter(&id)
            .ok_or_else(|| ErrorObjectOwned::owned(-32000, "filter not found", None::<()>))?;
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
