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

    async fn add_peer(&self, multiaddr: String) -> Result<bool, ErrorObjectOwned> {
        let dialer = self
            .peer_dialer
            .as_ref()
            .ok_or_else(|| crate::error::feature_not_enabled("P2P peer dialing is unavailable"))?;
        dialer
            .dial_peer(multiaddr)
            .await
            .map_err(|error| match error {
                shell_network::NetworkError::InvalidPeerAddress(message) => {
                    crate::error::invalid_params(message)
                }
                error => crate::error::server_error(error.to_string()),
            })
    }
}
