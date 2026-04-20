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
        Err(ErrorObjectOwned::owned(
            -32601,
            "shell_addValidator is disabled: use shell_proposeAddValidator instead",
            None::<()>,
        ))
    }

    async fn remove_validator(&self, _address: String) -> Result<bool, ErrorObjectOwned> {
        // DISABLED (F-039/F-040): See add_validator rationale.
        // Use shell_proposeRemoveValidator instead.
        Err(ErrorObjectOwned::owned(
            -32601,
            "shell_removeValidator is disabled: use shell_proposeRemoveValidator instead",
            None::<()>,
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
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    format!("unknown governance operation: {operation}"),
                    None::<()>,
                ));
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

        Ok(serde_json::json!({
            "version": "ShellChain/v0.6.0/rust",
            "chainId": self.chain_id,
            "blockHeight": block_height,
            "peerCount": 0,
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
            ErrorObjectOwned::owned(-32601, "shell_setBalance requires dev mode", None::<()>)
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
            "total": txs.len(),
            "transactions": txs,
        }))
    }

    async fn get_block_witnesses(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Resolve block hash from tag or hash string.
        let block_hash = if block.starts_with("0x") && block.len() == 66 {
            // 32-byte hex hash
            let bytes = hex::decode(&block[2..])
                .map_err(|e| internal_err(format!("invalid block hash hex: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| internal_err("block hash must be 32 bytes"))?;
            ShellHash::from(arr)
        } else {
            // Block number / tag → look up canonical hash
            let tag = parse_block_tag(&block)?;
            let blk = match tag {
                BlockTag::Latest | BlockTag::Finalized | BlockTag::Pending => {
                    self.chain_store.get_head_block().map_err(internal_err)?
                }
                BlockTag::Number(n) => self
                    .chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?,
            };
            match blk {
                None => return Ok(serde_json::Value::Null),
                Some(b) => b.hash(),
            }
        };

        // Retrieve the block header for witness_root.
        let header = self
            .chain_store
            .get_header_by_hash(&block_hash)
            .map_err(internal_err)?;
        let witness_root = header
            .as_ref()
            .and_then(|h| h.witness_root)
            .map(|r| format!("0x{}", hex::encode(r.as_bytes())))
            .unwrap_or_else(|| "null".into());

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

        Ok(serde_json::json!({
            "blockHash": block_hash,
            "witnessRoot": witness_root,
            "witnessCount": witnesses.len(),
            "witnesses": witnesses,
        }))
    }
}

