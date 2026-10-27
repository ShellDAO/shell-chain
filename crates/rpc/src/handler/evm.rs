use super::*;

const MAX_EVM_MINE_BLOCKS: u64 = 256;

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> LegacyEvmApiServer for RpcHandler<S> {
    async fn mine(&self, blocks: Option<u64>) -> Result<serde_json::Value, ErrorObjectOwned> {
        let count = blocks.unwrap_or(1).max(1);
        if count > MAX_EVM_MINE_BLOCKS {
            return Err(invalid_params_err(format!(
                "evm_mine blocks must be at most {MAX_EVM_MINE_BLOCKS}"
            )));
        }
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("legacy evm dev namespace not enabled on this node")
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
            feature_not_enabled("legacy evm dev namespace not enabled on this node")
        })?;
        let applied = dev
            .set_next_block_timestamp(timestamp)
            .map_err(internal_err)?;
        Ok(serde_json::json!(hex_u64(applied)))
    }

    async fn increase_time(&self, seconds: u64) -> Result<serde_json::Value, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("legacy evm dev namespace not enabled on this node")
        })?;
        let total = dev.increase_time(seconds).map_err(internal_err)?;
        Ok(serde_json::json!(hex_u64(total)))
    }

    async fn snapshot(&self) -> Result<String, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("legacy evm dev namespace not enabled on this node")
        })?;
        dev.snapshot().map_err(internal_err)
    }

    async fn revert(&self, snapshot_id: String) -> Result<bool, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            feature_not_enabled("legacy evm dev namespace not enabled on this node")
        })?;
        let reverted = dev.revert(&snapshot_id).map_err(internal_err)?;
        if reverted {
            let finalized = self.finality.read().last_finalized_number();
            *self.finalized_number.write() = finalized;
        }
        Ok(reverted)
    }
}
