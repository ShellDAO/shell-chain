use super::*;

const MAX_EXACT_ADDRESS_TOTAL_BLOCK_RANGE: u64 = 10_000;
const MAX_LEGACY_ADDRESS_TX_OFFSET: u64 = 10_000;
const DEFAULT_VALIDATOR_SNAPSHOT_PROPOSER_WINDOW: u64 = 200;
const MAX_VALIDATOR_SNAPSHOT_PROPOSER_WINDOW: u64 = 1000;
const MAX_OPTIONAL_RPC_BYTE_FIELD_LEN: usize = 32 * 1024;

fn ensure_exact_address_total_allowed(
    from_block: u64,
    to_block: u64,
) -> Result<(), ErrorObjectOwned> {
    if from_block > to_block {
        return Ok(());
    }
    let range = to_block.saturating_sub(from_block).saturating_add(1);
    if range > MAX_EXACT_ADDRESS_TOTAL_BLOCK_RANGE {
        return Err(invalid_params_err(format!(
            "exact address transaction totals are limited to {MAX_EXACT_ADDRESS_TOTAL_BLOCK_RANGE} blocks; use cursor pagination with includeTotal=false for wider ranges"
        )));
    }
    Ok(())
}

fn normalize_validator_snapshot_proposer_window(
    proposer_window: Option<u64>,
) -> Result<u64, ErrorObjectOwned> {
    let proposer_window = proposer_window.unwrap_or(DEFAULT_VALIDATOR_SNAPSHOT_PROPOSER_WINDOW);
    if proposer_window == 0 {
        return Err(invalid_params_err(
            "validator snapshot proposerWindow must be at least 1",
        ));
    }
    Ok(proposer_window.min(MAX_VALIDATOR_SNAPSHOT_PROPOSER_WINDOW))
}

impl<S: KvStore + 'static> RpcHandler<S> {
    fn resolve_block_number_for_v2(&self, value: &str) -> Result<u64, ErrorObjectOwned> {
        match parse_block_tag(value)? {
            BlockTag::Latest | BlockTag::Pending => Ok(self
                .chain_store
                .get_head_block()
                .map_err(internal_err)?
                .map(|b| b.number())
                .unwrap_or(0)),
            BlockTag::Finalized => Ok(*self.finalized_number.read()),
            BlockTag::Number(n) => Ok(n),
        }
    }

    fn light_block(
        &self,
        block: &Block,
        detail: BlockTxDetail,
        tx_limit: Option<usize>,
    ) -> RpcBlock {
        let mut rpc = block_to_rpc_with_detail(block, detail);
        self.fill_stark_metadata(&block.hash(), &mut rpc);
        self.attach_system_txs(block, &mut rpc, detail);
        if let Some(limit) = tx_limit {
            if let serde_json::Value::Array(ref mut txs) = rpc.transactions {
                txs.truncate(limit);
            }
        }
        rpc
    }

    fn avg_block_time(&self, head_number: u64) -> Result<f64, ErrorObjectOwned> {
        if head_number == 0 {
            return Ok(0.0);
        }
        let window = std::cmp::min(head_number, 10);
        if window == 0 {
            return Ok(0.0);
        }
        let recent = self
            .chain_store
            .get_block_by_number(head_number)
            .map_err(internal_err)?;
        let older = self
            .chain_store
            .get_block_by_number(head_number - window)
            .map_err(internal_err)?;
        Ok(match (recent, older) {
            (Some(recent), Some(older)) => {
                recent
                    .header
                    .timestamp
                    .saturating_sub(older.header.timestamp) as f64
                    / window as f64
            }
            _ => 0.0,
        })
    }

    fn address_transactions_v2(
        &self,
        address: Address,
        options: RpcAddressTransactionsV2Options,
    ) -> Result<RpcAddressTransactionsV2Page, ErrorObjectOwned> {
        let to_block = match options.to_block {
            Some(to_block) => to_block,
            None => self
                .chain_store
                .get_head_block()
                .map_err(internal_err)?
                .map(|b| b.number())
                .unwrap_or(0),
        };
        let from_block = options.from_block.unwrap_or(0);
        let limit = options.limit.unwrap_or(20).clamp(1, 100);
        let descending = matches!(options.direction, RpcListDirection::Desc);
        let (entries, has_more) = self
            .chain_store
            .get_txs_by_address_cursor(
                &address,
                from_block,
                to_block,
                options.cursor.as_deref(),
                limit as usize,
                descending,
            )
            .map_err(|e| match e {
                shell_storage::StorageError::InvalidInput(msg) => invalid_params(msg),
                other => internal_err(other),
            })?;
        let mut items = Vec::with_capacity(entries.len());
        for entry in &entries {
            let Some((block_hash, tx_index)) = self
                .chain_store
                .get_tx_location(&entry.tx_hash)
                .map_err(internal_err)?
            else {
                continue;
            };
            let Some(block) = self
                .chain_store
                .get_block_by_hash(&block_hash)
                .map_err(internal_err)?
            else {
                continue;
            };
            if let Some(mut value) = self.tx_value_for_location(
                &entry.tx_hash,
                &block,
                block_hash,
                tx_index,
                options.detail,
            )? {
                if let serde_json::Value::Object(ref mut object) = value {
                    object.insert(
                        "timestamp".into(),
                        serde_json::json!(hex_u64(block.header.timestamp)),
                    );
                    if let Some(receipt) = self
                        .chain_store
                        .get_receipt_by_tx_hash(&entry.tx_hash)
                        .map_err(internal_err)?
                    {
                        object.insert(
                            "status".into(),
                            serde_json::json!(hex_u64(receipt.status as u64)),
                        );
                        object.insert(
                            "gasUsed".into(),
                            serde_json::json!(hex_u64(receipt.gas_used)),
                        );
                        object.insert("logCount".into(), serde_json::json!(receipt.logs.len()));
                    }
                    object.insert("cursor".into(), serde_json::json!(entry.cursor));
                }
                items.push(value);
            }
        }
        let total = if options.include_total.unwrap_or(false) {
            ensure_exact_address_total_allowed(from_block, to_block)?;
            Some(
                self.chain_store
                    .count_txs_by_address(&address, from_block, to_block)
                    .map_err(internal_err)?,
            )
        } else {
            None
        };
        Ok(RpcAddressTransactionsV2Page {
            address,
            from_block: hex_u64(from_block),
            to_block: hex_u64(to_block),
            limit,
            direction: options.direction,
            total,
            next_cursor: has_more
                .then(|| entries.last().map(|entry| entry.cursor.clone()))
                .flatten(),
            has_more,
            items,
        })
    }

    fn tx_value_for_location(
        &self,
        hash: &ShellHash,
        block: &Block,
        block_hash: ShellHash,
        tx_index: u32,
        detail: RpcV2TxDetail,
    ) -> Result<Option<serde_json::Value>, ErrorObjectOwned> {
        if matches!(detail, RpcV2TxDetail::Hashes) {
            return Ok(Some(serde_json::json!(hash)));
        }
        if let Some(tx) = block.transactions.get(tx_index as usize) {
            let value = match detail {
                RpcV2TxDetail::Full => serde_json::to_value(tx_to_rpc(
                    tx,
                    Some(block_hash),
                    Some(block.number()),
                    Some(tx_index),
                    Some(block.header.base_fee_per_gas),
                )),
                RpcV2TxDetail::None | RpcV2TxDetail::Hashes | RpcV2TxDetail::Summary => {
                    serde_json::to_value(tx_to_rpc_summary(
                        tx,
                        Some(block_hash),
                        Some(block.number()),
                        Some(tx_index),
                    ))
                }
            }
            .map_err(|e| internal_err(format!("serialize tx: {e}")))?;
            return Ok(Some(value));
        }
        let system_tx = self
            .chain_store
            .get_system_transaction_by_hash(hash)
            .map_err(internal_err)?;
        let Some(system_tx) = system_tx else {
            return Ok(None);
        };
        let value = match detail {
            RpcV2TxDetail::Full => {
                serde_json::to_value(system_tx_to_rpc(&system_tx, Some(block_hash)))
            }
            RpcV2TxDetail::None | RpcV2TxDetail::Hashes | RpcV2TxDetail::Summary => {
                serde_json::to_value(system_tx_to_rpc_summary(&system_tx, Some(block_hash)))
            }
        }
        .map_err(|e| internal_err(format!("serialize system tx: {e}")))?;
        Ok(Some(value))
    }

    fn receipt_for_location(
        &self,
        hash: &ShellHash,
        block: &Block,
        block_hash: ShellHash,
        tx_index: u32,
    ) -> Result<Option<RpcReceipt>, shell_storage::StorageError> {
        let Some(receipt) = self.chain_store.get_receipt_by_tx_hash(hash)? else {
            return Ok(None);
        };
        let (from, to, effective_gas_price, tx_type, shell_type, reward_kind) =
            if let Some(tx) = block.transactions.get(tx_index as usize) {
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
                    shell_core::effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        block.header.base_fee_per_gas,
                    ),
                    tx.tx.tx_type,
                    Some(shell_type.into()),
                    None,
                )
            } else if let Some(system_tx) = self.chain_store.get_system_transaction_by_hash(hash)? {
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
        Ok(Some(RpcReceipt {
            transaction_hash: receipt.tx_hash,
            block_hash,
            block_number: hex_u64(receipt.block_number),
            transaction_index: hex_u64(tx_index as u64),
            from,
            to,
            status: hex_u64(receipt.status as u64),
            gas_used: hex_u64(receipt.gas_used),
            cumulative_gas_used: hex_u64(receipt.cumulative_gas_used),
            effective_gas_price: hex_u64(effective_gas_price),
            contract_address: receipt.contract_address,
            logs: receipt
                .logs
                .into_iter()
                .map(|log| RpcLog {
                    address: log.address,
                    topics: log.topics,
                    data: hex_bytes(log.data.as_ref()),
                })
                .collect(),
            logs_bloom: hex_bytes(receipt.logs_bloom.as_ref()),
            tx_type: format!("{:#x}", tx_type),
            shell_type,
            reward_kind,
        }))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> ShellApiServer for RpcHandler<S> {
    async fn get_pq_pubkey(&self, address: Address) -> Result<Option<String>, ErrorObjectOwned> {
        let pk = self
            .chain_store
            .get_pubkey(&address)
            .map_err(internal_err)?;
        Ok(pk.map(|bytes| hex_bytes(&bytes)))
    }

    async fn pending_count(&self) -> Result<String, ErrorObjectOwned> {
        Ok(hex_u64(self.tx_pool.len() as u64))
    }

    async fn shell_get_block_by_number(
        &self,
        number: String,
        tx_detail: Option<String>,
    ) -> Result<Option<RpcBlock>, ErrorObjectOwned> {
        let detail = parse_block_tx_detail(tx_detail.as_deref())?;
        let tag = parse_block_tag(&number)?;
        let block = match tag {
            BlockTag::Finalized => {
                let n = *self.finalized_number.read();
                self.chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?
            }
            BlockTag::Number(n) => self
                .chain_store
                .get_block_by_number(n)
                .map_err(internal_err)?,
            BlockTag::Latest | BlockTag::Pending => {
                self.chain_store.get_head_block().map_err(internal_err)?
            }
        };

        Ok(block.as_ref().map(|b| {
            let mut rpc = block_to_rpc_with_detail(b, detail);
            if detail.include_stark_proof() {
                self.fill_stark_proof(&b.hash(), &mut rpc);
            } else {
                self.fill_stark_metadata(&b.hash(), &mut rpc);
            }
            self.attach_system_txs(b, &mut rpc, detail);
            rpc
        }))
    }

    async fn shell_get_block_by_hash(
        &self,
        hash: ShellHash,
        tx_detail: Option<String>,
    ) -> Result<Option<RpcBlock>, ErrorObjectOwned> {
        let detail = parse_block_tx_detail(tx_detail.as_deref())?;
        let block = self
            .chain_store
            .get_block_by_hash(&hash)
            .map_err(internal_err)?;

        Ok(block.as_ref().map(|b| {
            let mut rpc = block_to_rpc_with_detail(b, detail);
            if detail.include_stark_proof() {
                self.fill_stark_proof(&hash, &mut rpc);
            } else {
                self.fill_stark_metadata(&hash, &mut rpc);
            }
            self.attach_system_txs(b, &mut rpc, detail);
            rpc
        }))
    }

    async fn rpc_capabilities(&self) -> Result<RpcCapabilities, ErrorObjectOwned> {
        Ok(RpcCapabilities {
            rpc_version: "shell-rpc-v2".into(),
            methods: vec![
                "shell_rpcCapabilities".into(),
                "shell_getChainSnapshot".into(),
                "shell_getBlocksRange".into(),
                "shell_getAddressSummary".into(),
                "shell_getTransactionsByAddressV2".into(),
                "shell_getTransactionSummary".into(),
                "shell_getValidatorSnapshot".into(),
            ],
            max_page_size: 100,
            max_blocks_range: 100,
            max_tx_summary_per_block: 100,
            supports_cursor_pagination: true,
            supports_address_history_index: true,
            witness_store: self.witness_store.is_some(),
            storage_profile: self.storage_profile.clone(),
            fallback_methods: vec![
                "shell_getBlockByNumber".into(),
                "shell_getTransactionsByAddress".into(),
                "shell_getChainStats".into(),
                "shell_getNodeInfo".into(),
            ],
        })
    }

    async fn get_chain_snapshot(
        &self,
        _options: Option<serde_json::Value>,
    ) -> Result<RpcChainSnapshot, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let head_number = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let finalized_number = *self.finalized_number.read();
        let finalized = self
            .chain_store
            .get_block_by_number(finalized_number)
            .map_err(internal_err)?;
        let base_fee = match &head {
            Some(h) if h.header.base_fee_per_gas > 0 => h.header.base_fee_per_gas,
            _ => INITIAL_BASE_FEE,
        };
        let (total_transactions, gas_used_total) = if head.is_some() {
            self.chain_store
                .get_chain_totals(head_number)
                .map_err(internal_err)?
        } else {
            (0, U256::ZERO)
        };

        let avg_block_time = self.avg_block_time(head_number)?;
        let consensus = ShellApiServer::consensus_info(self).await?;
        let validators = consensus
            .get("validators")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        Ok(RpcChainSnapshot {
            chain_id: hex_u64(self.chain_id),
            head: head
                .as_ref()
                .map(|b| self.light_block(b, BlockTxDetail::Summary, Some(100))),
            finalized: finalized
                .as_ref()
                .map(|b| self.light_block(b, BlockTxDetail::Summary, Some(100))),
            finality_lag: head_number.saturating_sub(finalized_number),
            pending_transactions: hex_u64(self.tx_pool.len() as u64),
            peer_count: self.peer_count.load(Ordering::Relaxed) as u64,
            is_mining: self.proposer_signer.is_some(),
            uptime: self.start_time.elapsed().as_secs(),
            base_fee: hex_u64(base_fee),
            gas_price: hex_u64(base_fee),
            total_transactions,
            gas_used_total: hex_u256(gas_used_total),
            avg_block_time,
            consensus,
            validators,
            storage_profile: self.storage_profile.clone(),
        })
    }

    async fn get_blocks_range(
        &self,
        start: String,
        options: Option<RpcBlocksRangeOptions>,
    ) -> Result<RpcBlocksRange, ErrorObjectOwned> {
        let options = options.unwrap_or_default();
        let limit = options.limit.unwrap_or(20).clamp(1, 100);
        let tx_limit = options.tx_limit.map(|n| n.min(100) as usize);
        let detail = match options.tx_detail {
            RpcV2TxDetail::None | RpcV2TxDetail::Hashes => BlockTxDetail::Hashes,
            RpcV2TxDetail::Summary => BlockTxDetail::Summary,
            RpcV2TxDetail::Full => BlockTxDetail::Full,
        };
        let mut current = self.resolve_block_number_for_v2(&start)?;
        let mut blocks = Vec::new();
        let mut has_next_candidate = false;
        for _ in 0..limit {
            let Some(block) = self
                .chain_store
                .get_block_by_number(current)
                .map_err(internal_err)?
            else {
                break;
            };
            let mut rpc = self.light_block(&block, detail, tx_limit);
            if matches!(options.tx_detail, RpcV2TxDetail::None) {
                rpc.transactions = serde_json::json!([]);
            }
            blocks.push(rpc);
            match options.direction {
                RpcListDirection::Desc if current == 0 => {
                    has_next_candidate = false;
                    break;
                }
                RpcListDirection::Desc => {
                    current = current.saturating_sub(1);
                    has_next_candidate = true;
                }
                RpcListDirection::Asc if current == u64::MAX => {
                    has_next_candidate = false;
                    break;
                }
                RpcListDirection::Asc => {
                    current = current.saturating_add(1);
                    has_next_candidate = true;
                }
            }
        }
        let next_start = if blocks.len() as u64 == limit && has_next_candidate {
            self.chain_store
                .get_block_by_number(current)
                .map_err(internal_err)?
                .map(|_| hex_u64(current))
        } else {
            None
        };
        Ok(RpcBlocksRange {
            start,
            direction: options.direction,
            limit,
            blocks,
            next_start,
        })
    }

    async fn get_address_summary(
        &self,
        address: Address,
        options: Option<RpcAddressSummaryOptions>,
    ) -> Result<RpcAddressSummary, ErrorObjectOwned> {
        let options = options.unwrap_or_default();
        let recent_limit = options.recent_limit.unwrap_or(10).clamp(0, 100);
        let tx_options = RpcAddressTransactionsV2Options {
            limit: Some(recent_limit),
            include_total: options.include_total,
            ..RpcAddressTransactionsV2Options::default()
        };
        let recent_transactions = self.address_transactions_v2(address, tx_options)?;
        let ws = self.world_state.read();
        let balance = ws.get_balance(&address).map_err(internal_err)?;
        let nonce = ws.get_nonce(&address).map_err(internal_err)?;
        let exists = ws.exists(&address).map_err(internal_err)?;
        let code_hash = ws.get_code_hash(&address).map_err(internal_err)?;
        drop(ws);
        let pq_pubkey_registered = self
            .chain_store
            .get_pubkey(&address)
            .map_err(internal_err)?
            .is_some();
        Ok(RpcAddressSummary {
            address,
            balance: hex_u256(balance),
            nonce: hex_u64(nonce),
            exists,
            has_code: code_hash.is_some(),
            code_hash,
            pq_pubkey_registered,
            total_transactions: recent_transactions.total,
            recent_transactions,
        })
    }

    async fn get_transactions_by_address_v2(
        &self,
        address: Address,
        options: Option<RpcAddressTransactionsV2Options>,
    ) -> Result<RpcAddressTransactionsV2Page, ErrorObjectOwned> {
        self.address_transactions_v2(address, options.unwrap_or_default())
    }

    async fn get_transaction_summary(
        &self,
        hash: ShellHash,
        options: Option<RpcTransactionSummaryOptions>,
    ) -> Result<RpcTransactionSummaryResult, ErrorObjectOwned> {
        let include_receipt = options.unwrap_or_default().include_receipt.unwrap_or(false);
        let Some((block_hash, tx_index)) = self
            .chain_store
            .get_tx_location(&hash)
            .map_err(internal_err)?
        else {
            return Ok(RpcTransactionSummaryResult {
                transaction: None,
                receipt: None,
                status: None,
                gas_used: None,
                log_count: None,
                timestamp: None,
            });
        };
        let block = self
            .chain_store
            .get_block_by_hash(&block_hash)
            .map_err(internal_err)?;
        let Some(block) = block else {
            return Ok(RpcTransactionSummaryResult {
                transaction: None,
                receipt: None,
                status: None,
                gas_used: None,
                log_count: None,
                timestamp: None,
            });
        };
        let transaction = self
            .tx_value_for_location(&hash, &block, block_hash, tx_index, RpcV2TxDetail::Summary)?
            .map(|mut value| {
                if let serde_json::Value::Object(ref mut object) = value {
                    object.insert(
                        "timestamp".into(),
                        serde_json::json!(hex_u64(block.header.timestamp)),
                    );
                }
                value
            });
        let receipt = self
            .receipt_for_location(&hash, &block, block_hash, tx_index)
            .map_err(internal_err)?;
        let status = receipt.as_ref().map(|r| r.status.clone());
        let gas_used = receipt.as_ref().map(|r| r.gas_used.clone());
        let log_count = receipt.as_ref().map(|r| r.logs.len() as u64);
        Ok(RpcTransactionSummaryResult {
            transaction,
            receipt: if include_receipt { receipt } else { None },
            status,
            gas_used,
            log_count,
            timestamp: Some(hex_u64(block.header.timestamp)),
        })
    }

    async fn get_validator_snapshot(
        &self,
        options: Option<RpcValidatorSnapshotOptions>,
    ) -> Result<RpcValidatorSnapshot, ErrorObjectOwned> {
        let proposer_window = normalize_validator_snapshot_proposer_window(
            options.unwrap_or_default().proposer_window,
        )?;
        let consensus = ShellApiServer::consensus_info(self).await?;
        let head_number = consensus
            .get("block_number")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let from = head_number.saturating_sub(proposer_window.saturating_sub(1));
        let mut counts = std::collections::BTreeMap::<String, (u64, u64)>::new();
        for number in from..=head_number {
            if let Some(block) = self
                .chain_store
                .get_block_by_number(number)
                .map_err(internal_err)?
            {
                let key = block.header.proposer.to_string();
                let entry = counts.entry(key).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = entry.1.max(number);
            }
        }
        let proposer_stats = counts
            .into_iter()
            .map(|(address, (blocks, last_seen_block))| {
                serde_json::json!({
                    "address": address,
                    "blocksProposed": blocks,
                    "lastSeenBlock": last_seen_block,
                })
            })
            .collect();
        Ok(RpcValidatorSnapshot {
            validators: consensus
                .get("validators")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            stake_derived_weights: consensus
                .get("stakeDerivedWeights")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            current_proposer: consensus
                .get("current_proposer")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            block_number: head_number,
            epoch: consensus
                .get("epoch")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            epoch_length: consensus
                .get("epoch_length")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            epoch_progress: consensus
                .get("epoch_progress")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            proposer_window,
            proposer_stats,
        })
    }

    async fn send_transaction(&self, tx: SignedTransaction) -> Result<ShellHash, ErrorObjectOwned> {
        self.submit_tx(tx)
    }

    async fn get_validators(&self) -> Result<Vec<Address>, ErrorObjectOwned> {
        let ws = self.world_state.read();
        ws.get_validators().map_err(internal_err)
    }

    async fn add_validator(&self, _address: String) -> Result<bool, ErrorObjectOwned> {
        // DISABLED (F-039/F-040): Direct WorldState mutation via RPC causes
        // split-brain — validator changes must go through a system contract
        // transaction so all nodes compute the same state_root deterministically.
        // Use shell_proposeAddValidator instead.
        Err(method_not_found(
            "shell_addValidator is disabled: use shell_proposeAddValidator instead",
        ))
    }

    async fn remove_validator(&self, _address: String) -> Result<bool, ErrorObjectOwned> {
        // DISABLED (F-039/F-040): See add_validator rationale.
        // Use shell_proposeRemoveValidator instead.
        Err(method_not_found(
            "shell_removeValidator is disabled: use shell_proposeRemoveValidator instead",
        ))
    }

    async fn encode_add_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_pqvm::encode_add_validator_calldata(&addr);
        Ok(format!("0x{}", hex::encode(calldata)))
    }

    async fn encode_remove_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_pqvm::encode_remove_validator_calldata(&addr);
        Ok(format!("0x{}", hex::encode(calldata)))
    }

    async fn encode_set_validator_stake(
        &self,
        address: String,
        stake: String,
    ) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let stake = parse_hex_u256(&stake)?;
        let calldata = shell_pqvm::encode_set_validator_stake_calldata(&addr, stake);
        Ok(format!("0x{}", hex::encode(calldata)))
    }

    async fn propose_add_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_pqvm::encode_add_validator_calldata(&addr);
        let hash = self.propose_validator_tx(calldata)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    async fn propose_remove_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_pqvm::encode_remove_validator_calldata(&addr);
        let hash = self.propose_validator_tx(calldata)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    async fn propose_set_validator_weight(
        &self,
        address: String,
        weight: u64,
    ) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_pqvm::encode_set_validator_weight_calldata(&addr, weight);
        let hash = self.propose_validator_tx(calldata)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    async fn propose_set_validator_stake(
        &self,
        address: String,
        stake: String,
    ) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let stake = parse_hex_u256(&stake)?;
        let calldata = shell_pqvm::encode_set_validator_stake_calldata(&addr, stake);
        let hash = self.propose_validator_tx(calldata)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    async fn get_validator_status(
        &self,
        address: Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let ws = self.world_state.read();
        let validators = ws.get_validators().map_err(internal_err)?;
        let is_validator = validators.contains(&address);
        let weight = ws.get_validator_weight(&address).map_err(internal_err)?;
        let stake = ws.get_validator_stake(&address).map_err(internal_err)?;
        Ok(serde_json::json!({
            "address": address,
            "isValidator": is_validator,
            "weight": weight,
            "stake": hex_u256(stake),
        }))
    }

    async fn get_governance_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let ws = self.world_state.read();
        let validators = ws.get_validators().map_err(internal_err)?;
        let total_supply = ws.get_total_supply().map_err(internal_err)?;
        let total_staked = ws.get_total_staked().map_err(internal_err)?;
        let staking_enabled = ws.staking_enabled().map_err(internal_err)?;
        Ok(serde_json::json!({
            "validatorCount": validators.len(),
            "validators": validators,
            "systemContractAddress": shell_pqvm::registry_address(),
            "proposalGasLimit": 100_000,
            "stakingEnabled": staking_enabled,
            "totalSupply": hex_u256(total_supply),
            "totalStaked": hex_u256(total_staked),
        }))
    }

    async fn estimate_governance_gas(&self, operation: String) -> Result<String, ErrorObjectOwned> {
        let gas = match operation.as_str() {
            "addValidator" | "removeValidator" | "setValidatorStake" => {
                shell_pqvm::SYSTEM_CALL_BASE_GAS + shell_pqvm::SYSTEM_CALL_OP_GAS
            }
            "getValidators" | "isValidator" => shell_pqvm::SYSTEM_CALL_BASE_GAS,
            _ => {
                return Err(invalid_params(format!(
                    "unknown governance operation: {operation}"
                )));
            }
        };
        Ok(hex_u64(gas))
    }

    async fn get_node_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let block_height = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let base_fee = match &head {
            Some(h) if h.header.base_fee_per_gas > 0 => h.header.base_fee_per_gas,
            _ => shell_core::INITIAL_BASE_FEE,
        };
        let peer_count = self.peer_count.load(Ordering::Relaxed);
        let version = format!("ShellChain/v{}/rust", env!("CARGO_PKG_VERSION"));

        Ok(serde_json::json!({
            "version": version,
            "chain_id": self.chain_id.to_string(),
            "block_height": block_height,
            "peer_id": self.admin_peer_id.clone(),
            "peer_count": peer_count,
            "chainId": self.chain_id,
            "blockHeight": block_height,
            "peerCount": peer_count,
            "txPoolSize": self.tx_pool.len(),
            "isMining": self.proposer_signer.is_some(),
            "uptime": self.start_time.elapsed().as_secs(),
            "baseFee": hex_u64(base_fee),
        }))
    }

    async fn get_network_stats(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let peer_count = self.peer_count.load(Ordering::Relaxed);
        let listen_addr = if self.admin_p2p_listen.is_empty() {
            "/ip4/0.0.0.0/tcp/30303".to_string()
        } else {
            self.admin_p2p_listen.clone()
        };
        Ok(serde_json::json!({
            "peerCount": peer_count,
            "protocolVersion": "shell/1.0.0",
            "listeningAddress": listen_addr,
            "protocols": ["gossipsub", "kademlia", "mdns"],
        }))
    }

    async fn get_chain_stats(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let block_height = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let base_fee = match &head {
            Some(h) if h.header.base_fee_per_gas > 0 => h.header.base_fee_per_gas,
            _ => shell_core::INITIAL_BASE_FEE,
        };

        let mut avg_block_time: f64 = 0.0;
        let (total_txs, gas_used_total) = match head {
            Some(_) => self
                .chain_store
                .get_chain_totals(block_height)
                .map_err(internal_err)?,
            None => (0, U256::ZERO),
        };

        if block_height > 0 {
            let window = std::cmp::min(block_height, 10);
            if window >= 1 {
                let recent = self
                    .chain_store
                    .get_block_by_number(block_height)
                    .map_err(internal_err)?;
                let older = self
                    .chain_store
                    .get_block_by_number(block_height - window)
                    .map_err(internal_err)?;
                if let (Some(recent), Some(older)) = (recent, older) {
                    let dt = recent
                        .header
                        .timestamp
                        .saturating_sub(older.header.timestamp);
                    avg_block_time = dt as f64 / window as f64;
                }
            }
        }

        Ok(serde_json::json!({
            "blockHeight": block_height,
            "totalTransactions": total_txs,
            "avgBlockTime": avg_block_time,
            "gasUsedTotal": hex_u256(gas_used_total),
            "latestBaseFee": hex_u64(base_fee),
        }))
    }

    async fn get_finality_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (finalized, finalized_hash) = {
            let f = self.finality.read();
            (
                f.last_finalized_number(),
                f.last_finalized_hash().to_string(),
            )
        };
        let current_head = self
            .chain_store
            .get_head_block()
            .map_err(internal_err)?
            .map(|b| b.number())
            .unwrap_or(0);
        let pending = self.finality.read().total_pending_attestations();

        Ok(serde_json::json!({
            "lastFinalizedBlock": hex_u64(finalized),
            "lastFinalizedHash": finalized_hash,
            "currentHead": hex_u64(current_head),
            "finalityLag": current_head.saturating_sub(finalized),
            "pendingAttestations": pending,
        }))
    }

    async fn finality_proof(
        &self,
        block_hash: ShellHash,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let cert = self
            .chain_store
            .get_commit_certificate(&block_hash)
            .map_err(internal_err)?;

        match cert {
            Some(bytes) => {
                let decoded: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|e| internal_err(e.to_string()))?;
                Ok(serde_json::json!({
                    "blockHash": block_hash.to_string(),
                    "certificate": decoded,
                }))
            }
            None => Ok(serde_json::json!({
                "blockHash": block_hash.to_string(),
                "certificate": null,
            })),
        }
    }

    async fn consensus_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        use shell_consensus::EngineType;

        let head_number = self
            .chain_store
            .get_head_block()
            .map_err(internal_err)?
            .map(|b| b.number())
            .unwrap_or(0);

        let Some(ref engine_lock) = self.consensus_engine else {
            return Ok(serde_json::json!({
                "engine": "unknown",
                "validators": [],
                "current_proposer": null,
                "block_number": head_number,
                "epoch": null,
                "epoch_length": null,
                "epoch_progress": null,
            }));
        };

        let (engine_name, weights, poa_cfg) = {
            let engine = engine_lock.read();
            let engine_name = match engine.engine_type() {
                EngineType::PoA => "poa",
                EngineType::WPoA => "wpoa",
                EngineType::BFT => "bft",
            };
            (
                engine_name,
                engine.validator_weights(),
                engine.poa_config().clone(),
            )
        };

        let (staking_enabled, mut validators) = {
            let world_state = self.world_state.read();
            let staking_enabled = world_state.staking_enabled().map_err(internal_err)?;
            let validators: Vec<serde_json::Value> = weights
                .iter()
                .map(|(addr, w)| {
                    let stake = world_state.get_validator_stake(addr).unwrap_or(U256::ZERO);
                    serde_json::json!({
                        "address": format!("{addr}"),
                        "weight": w,
                        "stake": hex_u256(stake),
                    })
                })
                .collect();
            (staking_enabled, validators)
        };
        validators.sort_by_key(|v| v["address"].as_str().unwrap_or("").to_string());

        let epoch_length = poa_cfg.epoch_length;
        let (current_proposer, epoch, epoch_progress) = match head_number.checked_add(1) {
            Some(next_number) => {
                let proposer = poa_cfg.proposer_for_block(next_number);
                let epoch = poa_cfg.epoch_of(next_number);
                let epoch_progress = if epoch_length == 0 {
                    serde_json::Value::Null
                } else {
                    serde_json::json!(next_number % epoch_length)
                };
                (
                    serde_json::json!(format!("{proposer}")),
                    serde_json::json!(epoch),
                    epoch_progress,
                )
            }
            None => (
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
            ),
        };

        Ok(serde_json::json!({
            "engine": engine_name,
            "validators": validators,
            "stakeDerivedWeights": staking_enabled,
            "current_proposer": current_proposer,
            "block_number": head_number,
            "epoch": epoch,
            "epoch_length": epoch_length,
            "epoch_progress": epoch_progress,
        }))
    }

    async fn set_balance(
        &self,
        address: Address,
        balance: String,
    ) -> Result<bool, ErrorObjectOwned> {
        // Require dev mode — shell_setBalance is a state-mutation endpoint.
        self.dev_control
            .as_ref()
            .ok_or_else(|| dev_mode_required("shell_setBalance requires dev mode"))?;
        let value = parse_hex_u256(&balance)?;
        let mut ws = self.world_state.write();
        ws.set_balance(&address, value).map_err(internal_err)?;
        Ok(true)
    }

    async fn transaction_count(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let count = match head {
            Some(head) => {
                self.chain_store
                    .get_chain_totals(head.number())
                    .map_err(internal_err)?
                    .0
            }
            None => 0,
        };
        Ok(hex_u64(count))
    }

    async fn get_transactions_by_address(
        &self,
        address: Address,
        from_block: Option<u64>,
        to_block: Option<u64>,
        page: Option<u64>,
        limit: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let from = from_block.unwrap_or(0);
        let to = match to_block {
            Some(to_block) => to_block,
            None => self
                .chain_store
                .get_head_block()
                .map_err(internal_err)?
                .map(|b| b.number())
                .unwrap_or(0),
        };
        let page = page.unwrap_or(0);
        let limit = limit.unwrap_or(20).clamp(1, 100);
        let offset = page
            .checked_mul(limit)
            .ok_or_else(|| invalid_params_err("page * limit overflow"))?;
        if offset > MAX_LEGACY_ADDRESS_TX_OFFSET {
            return Err(invalid_params_err(format!(
                "legacy address transaction pagination offset is limited to {MAX_LEGACY_ADDRESS_TX_OFFSET}; use shell_getTransactionsByAddressV2 cursor pagination"
            )));
        }
        ensure_exact_address_total_allowed(from, to)?;
        let total = self
            .chain_store
            .count_txs_by_address(&address, from, to)
            .map_err(internal_err)?;

        let tx_hashes = self
            .chain_store
            .get_txs_by_address(&address, from, to, offset as usize, limit as usize)
            .map_err(internal_err)?;

        // Resolve each tx hash to a full RPC transaction.
        let mut txs = Vec::with_capacity(tx_hashes.len());
        for hash in &tx_hashes {
            let location = self
                .chain_store
                .get_tx_location(hash)
                .map_err(internal_err)?;
            if let Some((block_hash, tx_index)) = location {
                let block = self
                    .chain_store
                    .get_block_by_hash(&block_hash)
                    .map_err(internal_err)?;
                if let Some(block) = block {
                    let mut value = if let Some(tx) = block.transactions.get(tx_index as usize) {
                        serde_json::to_value(tx_to_rpc(
                            tx,
                            Some(block_hash),
                            Some(block.number()),
                            Some(tx_index),
                            Some(block.header.base_fee_per_gas),
                        ))
                        .map_err(|e| internal_err(format!("serialize tx: {e}")))?
                    } else if let Some(system_tx) = self
                        .chain_store
                        .get_system_transaction_by_hash(hash)
                        .map_err(internal_err)?
                    {
                        serde_json::to_value(system_tx_to_rpc(&system_tx, Some(block_hash)))
                            .map_err(|e| internal_err(format!("serialize system tx: {e}")))?
                    } else {
                        continue;
                    };
                    if let serde_json::Value::Object(ref mut object) = value {
                        object.insert(
                            "timestamp".into(),
                            serde_json::json!(hex_u64(block.header.timestamp)),
                        );
                    }
                    txs.push(value);
                }
            }
        }

        Ok(serde_json::json!({
            "address": address,
            "fromBlock": hex_u64(from),
            "toBlock": hex_u64(to),
            "page": page,
            "limit": limit,
            "total": total,
            "transactions": txs,
        }))
    }

    async fn get_block_witnesses(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let Some((block_hash, header)) = resolve_witness_block(self, &block)? else {
            return Ok(serde_json::Value::Null);
        };
        let witness_root = witness_root_value(Some(&header));

        // Look up the witness bundle if a store is wired.
        let Some(ws) = &self.witness_store else {
            return Ok(serde_json::json!({
                "blockHash": block_hash,
                "witnessRoot": witness_root,
                "witnessCount": null,
                "witnesses": null,
                "error": "witness store not available on this node",
            }));
        };

        let bundle = ws.get_bundle(&block_hash).map_err(internal_err)?;
        let Some(bundle) = bundle else {
            return Ok(serde_json::json!({
                "blockHash": block_hash,
                "witnessRoot": witness_root,
                "witnessCount": 0,
                "witnesses": [],
            }));
        };

        let witnesses: Vec<serde_json::Value> = bundle
            .witnesses
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let sig_type = format!("{:?}", w.signature.sig_type);
                let mut obj = serde_json::json!({
                    "txIndex": i,
                    "sigType": sig_type,
                    "signature": format!("0x{}", hex::encode(&w.signature.data)),
                });
                if let Some(pk) = &w.pubkey {
                    obj["pubkey"] = serde_json::Value::String(format!("0x{}", hex::encode(pk)));
                }
                obj
            })
            .collect();

        // OPS-2: verify computed root vs header's witness_root.
        let computed_root = bundle.compute_root();
        let root_verified = header.witness_root.map(|hr| hr == computed_root);

        Ok(serde_json::json!({
            "blockHash": block_hash,
            "witnessRoot": witness_root,
            "witnessRootVerified": root_verified,
            "witnessCount": witnesses.len(),
            "witnesses": witnesses,
        }))
    }

    async fn get_witness(&self, block: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let Some((block_hash, header)) = resolve_witness_block(self, &block)? else {
            return Ok(serde_json::Value::Null);
        };
        let Some(ws) = &self.witness_store else {
            return Ok(serde_json::Value::Null);
        };
        let Some(bundle) = ws.get_bundle(&block_hash).map_err(internal_err)? else {
            return Ok(serde_json::Value::Null);
        };

        let block_number = header.number;
        let state_root = format!("0x{}", hex::encode(header.state_root.as_bytes()));
        let timestamp = header.timestamp;

        let witnesses: Vec<serde_json::Value> = bundle
            .witnesses
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let sig_type = format!("{:?}", w.signature.sig_type);
                let mut obj = serde_json::json!({
                    "tx_index": i,
                    "sig_type": sig_type,
                    "signature": format!("0x{}", hex::encode(&w.signature.data)),
                });
                if let Some(pk) = &w.pubkey {
                    obj["public_key"] = serde_json::Value::String(format!("0x{}", hex::encode(pk)));
                }
                obj
            })
            .collect();

        // OPS-2: verify computed root vs header's witness_root.
        let computed_root = bundle.compute_root();
        let witness_root_verified = header.witness_root.map(|hr| hr == computed_root);

        Ok(serde_json::json!({
            "block_hash": format!("0x{}", hex::encode(block_hash.as_bytes())),
            "block_number": block_number,
            "state_root": state_root,
            "timestamp": timestamp,
            "witness_root": witness_root_value(Some(&header)),
            "witness_root_verified": witness_root_verified,
            "witness_count": witnesses.len(),
            "witnesses": witnesses,
        }))
    }

    async fn verify_witness_root(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let Some((block_hash, header)) = resolve_witness_block(self, &block)? else {
            return Ok(serde_json::json!({
                "blockHash": serde_json::Value::Null,
                "verified": serde_json::Value::Null,
                "reason": "block not found",
            }));
        };

        let Some(expected_root) = header.witness_root else {
            return Ok(serde_json::json!({
                "blockHash": block_hash,
                "verified": serde_json::Value::Null,
                "reason": "block header has no witness_root (pre-B2 block or genesis)",
            }));
        };

        let Some(ws) = &self.witness_store else {
            return Ok(serde_json::json!({
                "blockHash": block_hash,
                "verified": serde_json::Value::Null,
                "reason": "witness store not available on this node",
            }));
        };

        let Some(bundle) = ws.get_bundle(&block_hash).map_err(internal_err)? else {
            return Ok(serde_json::json!({
                "blockHash": block_hash,
                "verified": serde_json::Value::Null,
                "reason": "witness bundle not stored (pruned or never written)",
            }));
        };

        let computed_root = bundle.compute_root();
        let verified = computed_root == expected_root;
        Ok(serde_json::json!({
            "blockHash": block_hash,
            "expectedRoot": expected_root,
            "computedRoot": computed_root,
            "verified": verified,
        }))
    }

    async fn estimate_batch(
        &self,
        req: crate::types::BatchEstimateRequest,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        use shell_core::{AA_INNER_CALL_INTRINSIC_GAS, MAX_INNER_CALLS};

        if req.inner_calls.is_empty() {
            return Err(invalid_params(
                "estimateBatch: inner_calls must not be empty",
            ));
        }
        if req.inner_calls.len() > MAX_INNER_CALLS {
            return Err(invalid_params(format!(
                "estimateBatch: inner_calls exceeds MAX_INNER_CALLS ({MAX_INNER_CALLS})"
            )));
        }

        const PER_INNER_DEFAULT_FLOOR: u64 = 21_000;
        let from = req.from.unwrap_or(Address::ZERO);

        let mut per_inner = Vec::with_capacity(req.inner_calls.len());
        let mut inner_sum: u64 = 0;
        for (idx, call) in req.inner_calls.iter().enumerate() {
            let _ = call.value.as_deref().map(parse_hex_u256).transpose()?;
            let _ = parse_optional_hex_bytes(
                call.data.as_deref(),
                &format!("estimateBatch: inner[{idx}] data"),
                shell_mempool::MAX_TX_SIZE,
            )?;
            let (gas_limit, simulated) = match call.gas_limit.as_deref() {
                Some(hex) => (parse_hex_u64(hex)?, false),
                None => {
                    let call_req = crate::types::CallRequest {
                        from: Some(from),
                        to: call.to,
                        data: call.data.clone(),
                        value: call.value.clone(),
                        gas: None,
                        access_list: None,
                    };
                    let (_out, used) = self.execute_call(&call_req).map_err(|e| {
                        if e.code() == -32602 {
                            e
                        } else {
                            server_error(format!(
                                "estimateBatch: simulation for inner[{idx}] failed: {e}"
                            ))
                        }
                    })?;
                    (buffered_gas_estimate(used, PER_INNER_DEFAULT_FLOOR), true)
                }
            };
            if gas_limit == 0 {
                return Err(invalid_params(format!(
                    "estimateBatch: inner[{idx}] gas_limit must be > 0"
                )));
            }
            inner_sum = inner_sum
                .checked_add(gas_limit)
                .ok_or_else(|| invalid_params("estimateBatch: inner gas total overflow"))?;
            per_inner.push(serde_json::json!({
                "gas_limit": hex_u64(gas_limit),
                "simulated": simulated,
            }));
        }

        let outer_intrinsic: u64 = 21_000;
        let extra_inners = (req.inner_calls.len() as u64).saturating_sub(1);
        let intrinsic_surcharge = extra_inners.saturating_mul(AA_INNER_CALL_INTRINSIC_GAS);
        let total = outer_intrinsic
            .checked_add(inner_sum)
            .and_then(|v| v.checked_add(intrinsic_surcharge))
            .ok_or_else(|| invalid_params("estimateBatch: total gas overflow"))?;

        Ok(serde_json::json!({
            "total_gas": hex_u64(total),
            "outer_intrinsic": hex_u64(outer_intrinsic),
            "inner_sum": hex_u64(inner_sum),
            "intrinsic_surcharge": hex_u64(intrinsic_surcharge),
            "per_inner": per_inner,
            "paymaster": req.paymaster,
        }))
    }

    async fn estimate_paymaster_gas(
        &self,
        req: crate::types::PaymasterGasEstimateRequest,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        use shell_pqvm::PAYMASTER_VALIDATE_GAS_CAP;

        let inner_calls_data = parse_optional_hex_bytes(
            req.inner_calls_data.as_deref(),
            "estimatePaymasterGas: inner_calls_data",
            MAX_OPTIONAL_RPC_BYTE_FIELD_LEN,
        )?;
        let max_fee_per_gas: u64 = match req.max_fee_per_gas.as_deref() {
            Some(hex) => parse_hex_u64(hex)?,
            None => 1_000_000_000, // 1 gwei default
        };
        let paymaster_context = parse_optional_hex_bytes(
            req.paymaster_context.as_deref(),
            "estimatePaymasterGas: paymaster_context",
            shell_core::MAX_PAYMASTER_CONTEXT,
        )?;

        // Current RPC handlers do not yet expose the full EVM staticcall
        // executor needed to run validatePaymasterOp from this read-only path.
        // Return an explicit cap-only response so clients can gate sponsored
        // flows without mistaking this for a successful contract simulation.
        let _ = (inner_calls_data, max_fee_per_gas, paymaster_context); // used in full impl

        Ok(serde_json::json!({
            "paymaster": req.paymaster,
            "sender": req.sender,
            "validation_gas": serde_json::Value::Null,
            "paymaster_gas_cap": hex_u64(PAYMASTER_VALIDATE_GAS_CAP),
            "within_cap": serde_json::Value::Null,
            "simulation_status": "cap_only",
            "simulation_version": 1u64,
            "capability": "paymaster_cap_only",
            "reason": "validatePaymasterOp staticcall simulation is not exposed by this RPC handler yet",
            "note": "Current response reports the protocol gas cap only. Use shell_estimateBatch for bundle gas estimation and gate contract-paymaster UX on simulation_status.",
        }))
    }

    async fn get_paymaster_policy(
        &self,
        address: Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let pubkey = self
            .chain_store
            .get_pubkey(&address)
            .map_err(internal_err)?;
        let balance = {
            let ws = self.world_state.read();
            ws.get_balance(&address).map_err(internal_err)?
        };

        Ok(serde_json::json!({
            "address": address,
            "has_pq_pubkey": pubkey.is_some(),
            "pubkey_bytes": pubkey.as_ref().map(|b| b.len() as u64),
            "balance": hex_u256(balance),
            "policy": "eoa-open",
            "max_gas_sponsorship": serde_json::Value::Null,
        }))
    }

    async fn is_sponsored(
        &self,
        tx_hash: ShellHash,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let describe = |tx: &SignedTransaction, location: &str| {
            let is_bundle = tx.is_aa_bundle();
            let (paymaster, inner_count) = tx
                .aa_bundle()
                .map(|b| (b.paymaster, b.inner_calls.len() as u64))
                .unwrap_or((None, 0));
            let sponsored = is_bundle && paymaster.map(|p| p != tx.from).unwrap_or(false);
            serde_json::json!({
                "found": true,
                "location": location,
                "is_aa_bundle": is_bundle,
                "sponsored": sponsored,
                "paymaster": paymaster,
                "sender": tx.from,
                "inner_call_count": if is_bundle { Some(inner_count) } else { None },
            })
        };

        if let Some(pending) = self.tx_pool.get_shared(&tx_hash) {
            return Ok(describe(&pending, "mempool"));
        }

        let location = self
            .chain_store
            .get_tx_location(&tx_hash)
            .map_err(internal_err)?;
        if let Some((block_hash, tx_index)) = location {
            if let Some(block) = self
                .chain_store
                .get_block_by_hash(&block_hash)
                .map_err(internal_err)?
            {
                if let Some(tx) = block.transactions.get(tx_index as usize) {
                    return Ok(describe(tx, "chain"));
                }
            }
        }

        Ok(serde_json::json!({
            "found": false,
            "location": serde_json::Value::Null,
            "is_aa_bundle": false,
            "sponsored": false,
            "paymaster": serde_json::Value::Null,
            "sender": serde_json::Value::Null,
            "inner_call_count": serde_json::Value::Null,
        }))
    }

    async fn get_storage_profile(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        match &self.storage_profile {
            Some(info) => serde_json::to_value(info).map_err(|e| internal_err(e.to_string())),
            None => Err(feature_not_enabled(
                "storage profile not configured on this node",
            )),
        }
    }

    async fn get_proof_amendment(
        &self,
        block_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let store = match &self.proof_amendment_store {
            Some(s) => s,
            None => return Ok(serde_json::Value::Null),
        };

        let hash = if block_hash.starts_with("0x") && block_hash.len() == 66 {
            let bytes = hex::decode(&block_hash[2..])
                .map_err(|e| invalid_params(format!("invalid block hash hex: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| invalid_params("block hash must be 32 bytes"))?;
            ShellHash::from(arr)
        } else {
            return Err(invalid_params(
                "block_hash must be a 0x-prefixed 32-byte hex string",
            ));
        };

        let bytes = match store.get_amendment(&hash).map_err(internal_err)? {
            Some(b) => b,
            None => return Ok(serde_json::Value::Null),
        };

        let artifact = shell_stark_prover::StoredProofArtifact::from_json(&bytes)
            .map_err(|e| server_error(format!("failed to decode proof amendment: {e}")))?;

        self.stark_amendments_queried_total
            .fetch_add(1, Ordering::Relaxed);

        match artifact {
            shell_stark_prover::StoredProofArtifact::Amendment(amendment) => {
                let source_count = amendment.covered_hashes().len();
                Ok(serde_json::json!({
                    "block_hash": amendment.block_hash.to_string(),
                    "block_number": amendment.block_number,
                    "start_block": amendment.range_start_block(),
                    "end_block": amendment.range_end_block(),
                    "source_count": source_count,
                    "layer": amendment.layer,
                    "proof_entries": amendment.proof.n_sigs,
                    "original_size": amendment.original_size,
                    "compressed_size": amendment.compressed_size,
                    "proof_version": amendment.version,
                    "prover": amendment.prover,
                    "settlement_tx_hash": amendment.settlement_tx_hash.map(|hash| hash.to_string()),
                    "proof": hex_bytes(&amendment.proof.proof_bytes),
                }))
            }
            shell_stark_prover::StoredProofArtifact::Pointer(pointer) => Ok(serde_json::json!({
                "source_hash": pointer.source_hash.to_string(),
                "source_block": pointer.source_block,
                "target_hash": pointer.target_hash.to_string(),
                "target_block": pointer.target_block,
                "start_block": pointer.start_block,
                "end_block": pointer.end_block,
                "source_count": pointer.end_block.saturating_sub(pointer.start_block).saturating_add(1),
                "layer": pointer.layer,
                "settlement_tx_hash": pointer.settlement_tx_hash.map(|hash| hash.to_string()),
                "proof": serde_json::Value::Null,
            })),
        }
    }

    async fn get_algorithm_registry(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        use shell_crypto::AlgorithmRegistry;
        let reg = AlgorithmRegistry::global();
        let entries: Vec<serde_json::Value> = reg
            .get_all_entries()
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "algo": format!("{:?}", entry.algo),
                    "status": entry.status.to_string(),
                    "description": entry.description,
                })
            })
            .collect();
        Ok(serde_json::Value::Array(entries))
    }
}

fn parse_optional_hex_bytes(
    value: Option<&str>,
    field: &str,
    max_len: usize,
) -> Result<Vec<u8>, ErrorObjectOwned> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    if value == "0x" {
        return Ok(vec![]);
    }
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(invalid_params(format!("{field} must be 0x-prefixed")));
    };
    if hex.len() > max_len.saturating_mul(2) {
        return Err(invalid_params(format!(
            "{field} exceeds maximum size of {max_len} bytes"
        )));
    }
    hex::decode(hex).map_err(|e| invalid_params(format!("{field} invalid hex: {e}")))
}

fn resolve_witness_block<S: KvStore + 'static>(
    handler: &RpcHandler<S>,
    block: &str,
) -> Result<Option<(ShellHash, BlockHeader)>, ErrorObjectOwned> {
    let block_hash = if block.starts_with("0x") && block.len() == 66 {
        let bytes = hex::decode(&block[2..])
            .map_err(|e| invalid_params(format!("invalid block hash hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| invalid_params("block hash must be 32 bytes"))?;
        ShellHash::from(arr)
    } else {
        let tag = parse_block_tag(block)?;
        let blk = match tag {
            BlockTag::Latest | BlockTag::Pending => {
                handler.chain_store.get_head_block().map_err(internal_err)?
            }
            BlockTag::Finalized => {
                let finalized = *handler.finalized_number.read();
                handler
                    .chain_store
                    .get_block_by_number(finalized)
                    .map_err(internal_err)?
            }
            BlockTag::Number(n) => handler
                .chain_store
                .get_block_by_number(n)
                .map_err(internal_err)?,
        };
        match blk {
            None => return Ok(None),
            Some(b) => b.hash(),
        }
    };

    let Some(header) = handler
        .chain_store
        .get_header_by_hash(&block_hash)
        .map_err(internal_err)?
    else {
        return Ok(None);
    };

    Ok(Some((block_hash, header)))
}

fn witness_root_value(header: Option<&BlockHeader>) -> serde_json::Value {
    header
        .and_then(|h| h.witness_root)
        .map(|r| serde_json::Value::String(format!("0x{}", hex::encode(r.as_bytes()))))
        .unwrap_or(serde_json::Value::Null)
}
