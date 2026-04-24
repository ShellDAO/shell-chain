use super::*;

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
        let calldata = shell_evm::encode_add_validator_calldata(&addr);
        Ok(format!("0x{}", hex::encode(calldata)))
    }

    async fn encode_remove_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_evm::encode_remove_validator_calldata(&addr);
        Ok(format!("0x{}", hex::encode(calldata)))
    }

    async fn propose_add_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_evm::encode_add_validator_calldata(&addr);
        let hash = self.propose_validator_tx(calldata)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    async fn propose_remove_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_evm::encode_remove_validator_calldata(&addr);
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
        Ok(serde_json::json!({
            "address": address,
            "isValidator": is_validator,
        }))
    }

    async fn get_governance_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let ws = self.world_state.read();
        let validators = ws.get_validators().map_err(internal_err)?;
        Ok(serde_json::json!({
            "validatorCount": validators.len(),
            "validators": validators,
            "systemContractAddress": shell_evm::registry_address(),
            "proposalGasLimit": 100_000,
        }))
    }

    async fn estimate_governance_gas(&self, operation: String) -> Result<String, ErrorObjectOwned> {
        let gas = match operation.as_str() {
            "addValidator" | "removeValidator" => {
                shell_evm::SYSTEM_CALL_BASE_GAS + shell_evm::SYSTEM_CALL_OP_GAS
            }
            "getValidators" | "isValidator" => shell_evm::SYSTEM_CALL_BASE_GAS,
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
        Ok(serde_json::json!({
            "peerCount": 0,
            "protocolVersion": "shell/1.0.0",
            "listeningAddress": "/ip4/0.0.0.0/tcp/30303",
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

        let mut total_txs: u64 = 0;
        let mut gas_used_total = U256::ZERO;
        let mut avg_block_time: f64 = 0.0;

        // Cap scan to last 1000 blocks to prevent O(N) DoS on large chains.
        const MAX_SCAN: u64 = 1000;
        let scan_start = block_height.saturating_sub(MAX_SCAN);

        if block_height > 0 {
            for n in scan_start..=block_height {
                if let Ok(Some(blk)) = self.chain_store.get_block_by_number(n) {
                    total_txs = total_txs.saturating_add(blk.transactions.len() as u64);
                    gas_used_total = gas_used_total.saturating_add(U256::from(blk.header.gas_used));
                }
            }

            let window = std::cmp::min(block_height, 10);
            if window >= 1 {
                if let (Ok(Some(recent)), Ok(Some(older))) = (
                    self.chain_store.get_block_by_number(block_height),
                    self.chain_store.get_block_by_number(block_height - window),
                ) {
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
        let finalized = *self.finalized_number.read();
        let current_head = self
            .chain_store
            .get_head_block()
            .map_err(internal_err)?
            .map(|b| b.number())
            .unwrap_or(0);
        let pending = self.finality.read().total_pending_attestations();

        Ok(serde_json::json!({
            "lastFinalizedBlock": hex_u64(finalized),
            "currentHead": hex_u64(current_head),
            "pendingAttestations": pending,
        }))
    }

    async fn set_balance(
        &self,
        address: Address,
        balance: String,
    ) -> Result<bool, ErrorObjectOwned> {
        // Require dev mode — shell_setBalance is a state-mutation endpoint.
        self.dev_control.as_ref().ok_or_else(|| {
            dev_mode_required("shell_setBalance requires dev mode")
        })?;
        let value = if let Some(hex_str) = balance.strip_prefix("0x") {
            U256::from_str_radix(hex_str, 16)
                .map_err(|e| internal_err(format!("invalid hex balance: {e}")))?
        } else {
            balance
                .parse::<U256>()
                .map_err(|e| internal_err(format!("invalid balance: {e}")))?
        };
        let mut ws = self.world_state.write();
        ws.set_balance(&address, value).map_err(internal_err)?;
        Ok(true)
    }

    async fn transaction_count(&self) -> Result<String, ErrorObjectOwned> {
        let count = self
            .chain_store
            .get_total_tx_count()
            .map_err(internal_err)?;
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
        let to = to_block.unwrap_or_else(|| {
            self.chain_store
                .get_head_block()
                .ok()
                .flatten()
                .map(|b| b.number())
                .unwrap_or(0)
        });
        let page = page.unwrap_or(0);
        let limit = limit.unwrap_or(20).min(100);
        let offset = page
            .checked_mul(limit)
            .ok_or_else(|| invalid_params_err("page * limit overflow"))?;
        if offset > MAX_ADDRESS_TX_HISTORY_OFFSET as u64 {
            return Err(invalid_params_err(format!(
                "page/limit offset {} exceeds max {} entries",
                offset, MAX_ADDRESS_TX_HISTORY_OFFSET
            )));
        }
        let total = self
            .chain_store
            .count_txs_by_address(&address, from, to)
            .map_err(internal_err)?;

        let tx_hashes = self
            .chain_store
            .get_txs_by_address(&address, from, to, offset as usize, limit as usize)
            .map_err(internal_err)?;

        // Resolve each tx hash to a full RPC transaction
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
                    if let Some(tx) = block.transactions.get(tx_index as usize) {
                        txs.push(serde_json::json!({
                            "hash": hash,
                            "blockNumber": hex_u64(block.number()),
                            "blockHash": block_hash,
                            "transactionIndex": hex_u64(tx_index as u64),
                            "from": tx.sender(),
                            "to": tx.tx.to,
                            "value": hex_u256(tx.tx.value),
                            "gasLimit": hex_u64(tx.tx.gas_limit),
                            "nonce": hex_u64(tx.tx.nonce),
                        }));
                    }
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
            return Err(invalid_params("estimateBatch: inner_calls must not be empty"));
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
                        server_error(format!(
                            "estimateBatch: simulation for inner[{idx}] failed: {e}"
                        ))
                    })?;
                    let buffered = ((used as f64) * 1.2) as u64;
                    (std::cmp::max(buffered, PER_INNER_DEFAULT_FLOOR), true)
                }
            };
            if gas_limit == 0 {
                return Err(invalid_params(format!(
                    "estimateBatch: inner[{idx}] gas_limit must be > 0"
                )));
            }
            inner_sum = inner_sum
                .checked_add(gas_limit)
                .ok_or_else(|| internal_err("estimateBatch: inner_sum overflow"))?;
            per_inner.push(serde_json::json!({
                "gasLimit": hex_u64(gas_limit),
                "simulated": simulated,
            }));
        }

        let outer_intrinsic: u64 = 21_000;
        let extra_inners = (req.inner_calls.len() as u64).saturating_sub(1);
        let intrinsic_surcharge = extra_inners.saturating_mul(AA_INNER_CALL_INTRINSIC_GAS);
        let total = outer_intrinsic
            .checked_add(inner_sum)
            .and_then(|v| v.checked_add(intrinsic_surcharge))
            .ok_or_else(|| internal_err("estimateBatch: totalGas overflow"))?;

        Ok(serde_json::json!({
            "totalGas": hex_u64(total),
            "outerIntrinsic": hex_u64(outer_intrinsic),
            "innerSum": hex_u64(inner_sum),
            "intrinsicSurcharge": hex_u64(intrinsic_surcharge),
            "perInner": per_inner,
            "paymaster": req.paymaster,
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
            "hasPqPubkey": pubkey.is_some(),
            "pubkeyBytes": pubkey.as_ref().map(|b| b.len() as u64),
            "balance": hex_u256(balance),
            "policy": "eoa-open",
            "maxGasSponsorship": serde_json::Value::Null,
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
            let sponsored = is_bundle
                && paymaster
                    .map(|p| p != tx.from)
                    .unwrap_or(false);
            serde_json::json!({
                "found": true,
                "location": location,
                "isAaBundle": is_bundle,
                "sponsored": sponsored,
                "paymaster": paymaster,
                "sender": tx.from,
                "innerCallCount": if is_bundle { Some(inner_count) } else { None },
            })
        };

        if let Some(pending) = self.tx_pool.get(&tx_hash) {
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
            "isAaBundle": false,
            "sponsored": false,
            "paymaster": serde_json::Value::Null,
            "sender": serde_json::Value::Null,
            "innerCallCount": serde_json::Value::Null,
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
}

fn resolve_witness_block<S: KvStore + 'static>(
    handler: &RpcHandler<S>,
    block: &str,
) -> Result<Option<(ShellHash, BlockHeader)>, ErrorObjectOwned> {
    let block_hash = if block.starts_with("0x") && block.len() == 66 {
        let bytes = hex::decode(&block[2..])
            .map_err(|e| internal_err(format!("invalid block hash hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| internal_err("block hash must be 32 bytes"))?;
        ShellHash::from(arr)
    } else {
        let tag = parse_block_tag(block)?;
        let blk = match tag {
            BlockTag::Latest | BlockTag::Finalized | BlockTag::Pending => {
                handler.chain_store.get_head_block().map_err(internal_err)?
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
