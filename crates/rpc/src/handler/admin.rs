use super::*;

// ---------------------------------------------------------------------------
// Admin namespace
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> AdminApiServer for RpcHandler<S> {
    async fn create_snapshot(&self) -> Result<CheckpointInfo, ErrorObjectOwned> {
        let directory = self
            .backup_directory
            .clone()
            .ok_or_else(|| server_error("physical checkpoint directory is not configured"))?;
        let permit = Arc::clone(&self.checkpoint_limit)
            .try_acquire_owned()
            .map_err(|_| server_error("a physical checkpoint is already in progress"))?;
        let store = Arc::clone(self.chain_store.store());
        tokio::task::spawn_blocking(move || {
            // Retain the permit even if the HTTP caller disconnects: blocking
            // checkpoint work must still count against the one-operation bound.
            let _permit = permit;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(internal_err)?;
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let destination = directory.join(format!(
                "checkpoint-{}-{}",
                now.as_nanos(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            store
                .create_checkpoint(&destination)
                .map_err(internal_err)?;
            let path = destination.canonicalize().map_err(internal_err)?;
            Ok(CheckpointInfo {
                backup_path: path.to_string_lossy().into_owned(),
                timestamp: now.as_secs(),
            })
        })
        .await
        .map_err(internal_err)?
    }

    async fn node_info(&self) -> Result<NodeInfo, ErrorObjectOwned> {
        let block_height = self
            .chain_store
            .get_head_block()
            .map_err(internal_err)?
            .map(|b| b.header.number)
            .unwrap_or(0);

        let uptime_seconds = self.start_time.elapsed().as_secs();
        let peer_count = self.peer_count.load(Ordering::Relaxed);
        let tx_pool_size = self.tx_pool.len() as u64;

        let name = format!("shell-node/{}", env!("CARGO_PKG_VERSION"));

        let local_info = self.local_node_info.read().map_err(internal_err)?;

        Ok(NodeInfo {
            name,
            id: local_info.peer_id.clone(),
            listen_addr: local_info
                .listen_addresses
                .first()
                .cloned()
                .unwrap_or_default(),
            rpc_addr: self.admin_rpc_addr.clone(),
            chain_id: self.chain_id,
            uptime_seconds,
            block_height,
            tx_pool_size,
            peer_count,
        })
    }

    async fn peers(&self) -> Result<Vec<PeerInfo>, ErrorObjectOwned> {
        // The RPC handler receives only an atomic peer count from the network
        // layer; full per-peer detail (remote addr, client version) requires
        // a richer network snapshot channel. Do not synthesize peer IDs here:
        // fake rows mislead operators and monitoring systems.
        Err(crate::error::method_not_found(
            "admin_peers requires network peer detail snapshots; use admin_nodeInfo.peer_count for now",
        ))
    }

    async fn add_peer(&self, _multiaddr: String) -> Result<bool, ErrorObjectOwned> {
        // Dynamic peer dialling requires a command channel to the network layer.
        // Stubbed for Batch 4; full implementation in Batch 5 (P2P observability).
        Err(crate::error::method_not_found(
            "admin_addPeer not yet implemented; use --bootnodes at startup",
        ))
    }
}
