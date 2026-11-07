use super::*;

// ---------------------------------------------------------------------------
// Admin namespace
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> AdminApiServer for RpcHandler<S> {
    async fn canonical_proof_admission(
        &self,
        block: ShellHash,
    ) -> Result<Option<serde_json::Value>, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .admission(block)
            .map_err(proof_error)
    }
    async fn canonical_proof_production(
        &self,
        block: ShellHash,
    ) -> Result<Option<serde_json::Value>, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .production(block)
            .map_err(proof_error)
    }
    async fn fetch_canonical_proof(
        &self,
        peer: String,
        manifest: shell_storage::CanonicalProofManifest,
    ) -> Result<shell_storage::CanonicalProofFetchStatus, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .fetch(peer, manifest)
            .map_err(proof_error)
    }
    async fn canonical_proof_fetch_status(
        &self,
        id: ShellHash,
        generation: Option<u64>,
    ) -> Result<Option<shell_storage::CanonicalProofFetchStatus>, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .fetch_status(id, generation)
            .map_err(proof_error)
    }
    async fn canonical_proof_attempt_status(
        &self,
        id: ShellHash,
        generation: u64,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .attempt_status(id, generation)
            .map_err(proof_error)
    }
    async fn get_canonical_proof_attempt_chunk(
        &self,
        id: ShellHash,
        generation: u64,
        index: u32,
    ) -> Result<Bytes, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .attempt_chunk(id, generation, index)
            .map_err(proof_error)
    }
    async fn begin_canonical_proof(
        &self,
        manifest: shell_storage::CanonicalProofManifest,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .begin(manifest)
            .map_err(proof_error)
    }
    async fn append_canonical_proof(
        &self,
        id: ShellHash,
        index: u32,
        chunk: Bytes,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .append(id, index, chunk)
            .map_err(proof_error)
    }
    async fn canonical_proof_status(
        &self,
        id: ShellHash,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .status(id)
            .map_err(proof_error)
    }
    async fn get_canonical_proof_chunk(
        &self,
        id: ShellHash,
        index: u32,
    ) -> Result<Bytes, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .chunk(id, index)
            .map_err(proof_error)
    }
    async fn verify_canonical_proof(
        &self,
        id: ShellHash,
        recheck: Option<bool>,
    ) -> Result<shell_storage::CanonicalProofUploadStatus, ErrorObjectOwned> {
        self.canonical_proof_backend()?
            .verify(id, recheck.unwrap_or(false))
            .map_err(proof_error)
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

impl<S: KvStore + 'static> RpcHandler<S> {
    fn canonical_proof_backend(&self) -> Result<crate::DynCanonicalProofControl, ErrorObjectOwned> {
        self.canonical_proof_control.clone().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "canonical proof intake unavailable", None::<()>)
        })
    }
}
fn proof_error(error: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, error, None::<()>)
}
