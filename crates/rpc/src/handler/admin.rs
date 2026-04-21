use super::*;

// ---------------------------------------------------------------------------
// Admin namespace
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> AdminApiServer for RpcHandler<S> {
    async fn node_info(&self) -> Result<NodeInfo, ErrorObjectOwned> {
        let block_height = self
            .chain_store
            .get_head_block()
            .ok()
            .flatten()
            .map(|b| b.header.number)
            .unwrap_or(0);

        let uptime_seconds = self.start_time.elapsed().as_secs();
        let peer_count = self.peer_count.load(Ordering::Relaxed);
        let tx_pool_size = self.tx_pool.len() as u64;

        let name = format!("shell-node/{}", env!("CARGO_PKG_VERSION"));

        Ok(NodeInfo {
            name,
            id: self.admin_peer_id.clone(),
            listen_addr: self.admin_p2p_listen.clone(),
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
        // a richer channel which is wired in Batch 5 network observability.
        // For now, return a count-accurate summary with placeholder per-peer
        // data so `admin_peers` is callable and returns valid JSON.
        let count = self.peer_count.load(Ordering::Relaxed);
        let peers = (0..count)
            .map(|i| PeerInfo {
                id: format!("peer-{i}"),
                remote_addr: String::new(),
                client_version: String::new(),
                block_height: 0,
                connected_seconds: 0,
            })
            .collect();
        Ok(peers)
    }

    async fn add_peer(&self, _multiaddr: String) -> Result<bool, ErrorObjectOwned> {
        // Dynamic peer dialling requires a command channel to the network layer.
        // Stubbed for Batch 4; full implementation in Batch 5 (P2P observability).
        Err(ErrorObjectOwned::owned(
            jsonrpsee::types::error::METHOD_NOT_FOUND_CODE,
            "admin_addPeer not yet implemented; use --bootnodes at startup",
            None::<()>,
        ))
    }
}
