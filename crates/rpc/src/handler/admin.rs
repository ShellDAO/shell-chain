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
            .map_err(internal_err)?
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
