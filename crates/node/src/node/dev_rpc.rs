use super::*;

impl<S: KvStore + 'static> DevRpcControl for Node<S> {
    fn mine_blocks(&self, blocks: u64) -> Result<(), String> {
        let signer = self
            .runtime_signer
            .read()
            .clone()
            .ok_or_else(|| "node signer is not initialized".to_string())?;
        for _ in 0..blocks.max(1) {
            self.produce_block(signer.as_ref(), 500)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn set_next_block_timestamp(&self, timestamp: u64) -> Result<u64, String> {
        let head = self
            .chain_store
            .get_head_block()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "missing head block".to_string())?;
        let min_timestamp = head.header.timestamp.saturating_add(1);
        if timestamp < min_timestamp {
            return Err(format!(
                "timestamp must be >= next valid block timestamp {min_timestamp}"
            ));
        }
        self.dev_state.write().next_block_timestamp = Some(timestamp);
        Ok(timestamp)
    }

    fn increase_time(&self, seconds: u64) -> Result<u64, String> {
        let head = self
            .chain_store
            .get_head_block()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "missing head block".to_string())?;
        let mut dev = self.dev_state.write();
        let base_timestamp = dev
            .next_block_timestamp
            .unwrap_or(head.header.timestamp)
            .max(head.header.timestamp);
        let next_timestamp = base_timestamp.saturating_add(seconds);
        dev.next_block_timestamp = Some(next_timestamp);
        Ok(next_timestamp.saturating_sub(head.header.timestamp))
    }

    fn snapshot(&self) -> Result<String, String> {
        self.snapshot_inner().map_err(|e| e.to_string())
    }

    fn revert(&self, snapshot_id: &str) -> Result<bool, String> {
        self.revert_inner(snapshot_id).map_err(|e| e.to_string())
    }
}
