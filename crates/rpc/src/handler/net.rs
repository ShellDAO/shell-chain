use super::*;

const MAX_CONCURRENT_TRACE_REPLAYS: usize = 2;
pub(super) const MAX_TRACE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum TraceFormat {
    Debug,
    OpenEthereum,
}

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
        let options = parse_trace_options(opts)?;
        let (block, _, _, tx_index) = self.lookup_tx_with_block(&tx_hash)?;
        let mut traces = self
            .replay_traces(block, Some(tx_index as usize), options, TraceFormat::Debug)
            .await?;
        traces
            .pop()
            .ok_or_else(|| internal_err("transaction trace missing"))
    }

    async fn trace_block_by_number(
        &self,
        block_number: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let options = parse_trace_options(opts)?;
        let block = self.resolve_block(&block_number)?;
        Ok(serde_json::Value::Array(
            self.replay_traces(block, None, options, TraceFormat::Debug)
                .await?,
        ))
    }
}

impl<S: KvStore + 'static> RpcHandler<S> {
    pub(super) async fn replay_traces(
        &self,
        block: Block,
        target: Option<usize>,
        options: TraceOptions,
        format: TraceFormat,
    ) -> Result<Vec<serde_json::Value>, ErrorObjectOwned> {
        static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
        let permit = SLOTS
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TRACE_REPLAYS)))
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| server_error("trace replay unavailable"))?;
        let chain = Arc::clone(&self.chain_store);
        let chain_id = self.chain_id;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            replay_block_traces(chain, chain_id, block, target, options, format)
        })
        .await
        .map_err(|error| internal_err(format!("trace task failed: {error}")))?
    }
}

fn replay_block_traces<S: KvStore + 'static>(
    chain: Arc<ChainStore<S>>,
    chain_id: u64,
    block: Block,
    target: Option<usize>,
    options: TraceOptions,
    format: TraceFormat,
) -> Result<Vec<serde_json::Value>, ErrorObjectOwned> {
    if block.transactions.is_empty() {
        return Ok(Vec::new());
    }
    let parent = chain
        .get_header_by_hash(&block.header.parent_hash)
        .map_err(internal_err)?
        .ok_or_else(|| server_error("trace parent header unavailable"))?;
    let overlay = Arc::new(shell_storage::OverlayStore::new(Arc::clone(chain.store())));
    let state = WorldState::at_root(Arc::clone(&overlay), &parent.state_root)
        .map_err(|error| server_error(format!("trace parent state unavailable: {error}")))?;
    let registry = shell_pqvm::load_algorithm_registry(&state).map_err(internal_err)?;
    let receipts = chain
        .get_receipts(&block.hash())
        .map_err(internal_err)?
        .ok_or_else(|| server_error("trace receipts unavailable"))?;
    let mut executor = ShellPqvm::new(ShellStateDb::new(state, ChainStore::new(overlay)), chain_id);
    let config = shell_pqvm::TraceConfig {
        disable_stack: options.disable_stack.unwrap_or(false),
        disable_memory: options.disable_memory.unwrap_or(false),
        disable_storage: options.disable_storage.unwrap_or(false),
    };
    // No commit of the overlay, and registry changes stay on this worker thread.
    // Historical signatures have already been verified during canonical import.
    shell_crypto::with_algorithm_registry_override(&registry, || {
        let mut traces = Vec::new();
        let mut cumulative = 0;
        let mut response_bytes = 0usize;
        for (index, tx) in block.transactions.iter().enumerate() {
            if target.is_some_and(|target| index > target) {
                break;
            }
            // Rotation and clearing validation code read only trie state. Rotation
            // writes the public key into this private overlay without reading the
            // current address-keyed value. Other native methods may read guardian
            // metadata or the live chain head, so still require historical context.
            let state_only_native = tx.tx.to == Some(shell_pqvm::account_manager_address())
                && tx.tx.data.as_ref().get(..4).is_some_and(|selector| {
                    selector == shell_pqvm::system_contracts::ROTATE_KEY_SELECTOR
                        || selector == shell_pqvm::system_contracts::CLEAR_VALIDATION_CODE_SELECTOR
                });
            if tx
                .tx
                .to
                .as_ref()
                .is_some_and(shell_pqvm::is_system_contract)
                && !tx.is_aa_bundle()
                && !state_only_native
            {
                return Err(server_error(
                    "native system-contract tracing requires historical address metadata",
                ));
            }
            let selected = target.is_none_or(|target| target == index);
            let (result, trace) = if selected {
                let (result, trace) = executor
                    .trace_transaction(tx, &block.header, index as u32, cumulative, config)
                    .map_err(|error| server_error(format!("trace replay failed: {error}")))?;
                (result, Some(trace))
            } else {
                let result = if tx.is_aa_bundle() {
                    executor.execute_aa_bundle(tx, &block.header, index as u32, cumulative)
                } else {
                    executor.execute_tx(tx, &block.header, index as u32, cumulative)
                }
                .map_err(|error| server_error(format!("trace prefix replay failed: {error}")))?;
                (result, None)
            };
            if receipts.get(index) != Some(&result.receipt) {
                return Err(server_error("trace replay disagrees with stored receipt"));
            }
            cumulative = result.receipt.cumulative_gas_used;
            if !result.is_system_tx {
                shell_pqvm::commit_pqvm_state(&result, executor.state_db_mut())
                    .map_err(internal_err)?;
            }
            if let Some(trace) = trace {
                let values = match format {
                    TraceFormat::Debug => vec![serde_json::to_value(trace).map_err(internal_err)?],
                    TraceFormat::OpenEthereum => super::debug::flatten_oe_trace(
                        trace.result.frame,
                        block.header.number,
                        block.hash(),
                        tx.hash(),
                        index as u64,
                    )?,
                };
                for value in values {
                    response_bytes = response_bytes
                        .saturating_add(serde_json::to_vec(&value).map_err(internal_err)?.len());
                    if response_bytes > MAX_TRACE_RESPONSE_BYTES {
                        return Err(server_error("trace response exceeds 16 MiB limit"));
                    }
                    traces.push(value);
                }
            }
        }
        Ok(traces)
    })
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
