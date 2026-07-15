use super::*;

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> Web3ApiServer for RpcHandler<S> {
    async fn client_version(&self) -> Result<String, ErrorObjectOwned> {
        Ok(format!("shell-chain/{}", env!("CARGO_PKG_VERSION")))
    }

    async fn sha3(&self, data: String) -> Result<String, ErrorObjectOwned> {
        let Some(raw) = data.strip_prefix("0x") else {
            return Err(invalid_params_err("web3_sha3 data must be 0x-prefixed"));
        };
        // Limit input to 32 KB to prevent DoS via large allocations.
        const MAX_HEX_LEN: usize = 32 * 1024 * 2; // 32 KB decoded = 64 KB hex
        if raw.len() > MAX_HEX_LEN {
            return Err(invalid_params_err("input too large (max 32 KB)"));
        }
        let bytes =
            hex::decode(raw).map_err(|e| invalid_params_err(format!("invalid hex: {e}")))?;
        let hash = shell_primitives::keccak256(&bytes);
        Ok(format!("0x{}", hex::encode(hash.0)))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> NetApiServer for RpcHandler<S> {
    async fn version(&self) -> Result<String, ErrorObjectOwned> {
        Ok(self.chain_id.to_string())
    }

    async fn listening(&self) -> Result<bool, ErrorObjectOwned> {
        Ok(true)
    }

    async fn peer_count(&self) -> Result<String, ErrorObjectOwned> {
        let count = self.peer_count.load(std::sync::atomic::Ordering::Relaxed);
        Ok(hex_u64(count as u64))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> DebugApiServer for RpcHandler<S> {
    async fn trace_transaction(
        &self,
        tx_hash: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let _trace_opts = parse_trace_options(opts)?;

        let (_block, tx, receipt, _tx_index) = self.lookup_tx_with_block(&tx_hash)?;

        let to_addr = tx.tx.to.unwrap_or(Address::ZERO);
        let call_type = if tx.tx.to.is_none() { "CREATE" } else { "CALL" };

        let mut frame = shell_pqvm::CallFrame::new(
            call_type,
            tx.sender(),
            to_addr,
            tx.tx.gas_limit,
            tx.tx.data.clone(),
        );
        if !tx.tx.value.is_zero() {
            frame = frame.with_value(tx.tx.value);
        }
        frame.gas_used = receipt.gas_used;

        if receipt.succeeded() {
            frame.output = Some(Bytes::default());
        } else {
            frame.error = Some("execution reverted".to_string());
        }

        // Populate output/revert_reason from contract address if CREATE
        if tx.tx.to.is_none() {
            if let Some(addr) = receipt.contract_address {
                frame.to = addr;
            }
        }

        let trace = shell_pqvm::TraceResult {
            frame,
            failed: !receipt.succeeded(),
        };

        serde_json::to_value(&trace).map_err(|e| internal_err(format!("serialization error: {e}")))
    }

    async fn trace_block_by_number(
        &self,
        block_number: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let _trace_opts = parse_trace_options(opts)?;

        let block = self.resolve_block(&block_number)?;
        let block_hash = block.hash();

        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .unwrap_or_default();

        let mut traces = Vec::with_capacity(block.transactions.len());
        for (i, tx) in block.transactions.iter().enumerate() {
            let receipt = receipts.get(i);
            let to_addr = tx.tx.to.unwrap_or(Address::ZERO);
            let call_type = if tx.tx.to.is_none() { "CREATE" } else { "CALL" };

            let mut frame = shell_pqvm::CallFrame::new(
                call_type,
                tx.sender(),
                to_addr,
                tx.tx.gas_limit,
                tx.tx.data.clone(),
            );
            if !tx.tx.value.is_zero() {
                frame = frame.with_value(tx.tx.value);
            }

            if let Some(r) = receipt {
                frame.gas_used = r.gas_used;
                if r.succeeded() {
                    frame.output = Some(Bytes::default());
                } else {
                    frame.error = Some("execution reverted".to_string());
                }
                if tx.tx.to.is_none() {
                    if let Some(addr) = r.contract_address {
                        frame.to = addr;
                    }
                }
            }

            let failed = receipt.map(|r| !r.succeeded()).unwrap_or(true);
            let trace = shell_pqvm::TraceResult { frame, failed };
            traces.push(trace);
        }

        serde_json::to_value(&traces).map_err(|e| internal_err(format!("serialization error: {e}")))
    }
}

fn parse_trace_options(opts: Option<serde_json::Value>) -> Result<TraceOptions, ErrorObjectOwned> {
    let opts: TraceOptions = opts
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| invalid_params_err("invalid trace options"))
        .map(|opts| opts.unwrap_or_default())?;
    if let Some(tracer) = opts.tracer.as_deref() {
        if tracer != "callTracer" {
            return Err(invalid_params_err(
                "unsupported tracer; only callTracer is supported",
            ));
        }
    }
    Ok(opts)
}
