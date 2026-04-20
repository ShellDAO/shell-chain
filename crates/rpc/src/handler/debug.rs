use super::*;

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> TraceApiServer for RpcHandler<S> {
    async fn trace_block(
        &self,
        block_number: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let block = self.resolve_block(&block_number)?;
        let block_hash = block.hash();
        let block_num = block.header.number;

        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .unwrap_or_default();

        let mut traces = Vec::with_capacity(block.transactions.len());
        for (i, tx) in block.transactions.iter().enumerate() {
            let receipt = receipts.get(i);
            let trace = self.build_oe_trace(tx, receipt, block_num, block_hash, i as u64);
            traces.push(trace);
        }

        serde_json::to_value(&traces).map_err(|e| internal_err(format!("serialization error: {e}")))
    }

    async fn trace_oe_transaction(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (block, tx, receipt, tx_index) = self.lookup_tx_with_block(&tx_hash)?;
        let block_hash = block.hash();
        let block_num = block.header.number;

        let trace =
            self.build_oe_trace(&tx, Some(&receipt), block_num, block_hash, tx_index as u64);
        let traces = vec![trace];

        serde_json::to_value(&traces).map_err(|e| internal_err(format!("serialization error: {e}")))
    }
}
