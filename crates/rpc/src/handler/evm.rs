use super::*;

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> EvmApiServer for RpcHandler<S> {
    async fn mine(&self, blocks: Option<u64>) -> Result<serde_json::Value, ErrorObjectOwned> {
        let count = blocks.unwrap_or(1).max(1);
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("evm namespace not enabled on this node")
        })?;
        dev.mine_blocks(count).map_err(internal_err)?;
        Ok(serde_json::json!({
            "blocksMined": hex_u64(count),
        }))
    }

    async fn set_next_block_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("evm namespace not enabled on this node")
        })?;
        let applied = dev
            .set_next_block_timestamp(timestamp)
            .map_err(internal_err)?;
        Ok(serde_json::json!(hex_u64(applied)))
    }

    async fn increase_time(&self, seconds: u64) -> Result<serde_json::Value, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("evm namespace not enabled on this node")
        })?;
        let total = dev.increase_time(seconds).map_err(internal_err)?;
        Ok(serde_json::json!(hex_u64(total)))
    }

    async fn snapshot(&self) -> Result<String, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("evm namespace not enabled on this node")
        })?;
        dev.snapshot().map_err(internal_err)
    }

    async fn revert(&self, snapshot_id: String) -> Result<bool, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("evm namespace not enabled on this node")
        })?;
        dev.revert(&snapshot_id).map_err(internal_err)
    }
}
