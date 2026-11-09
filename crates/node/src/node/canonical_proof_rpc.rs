use super::*;
use shell_rpc::CanonicalProofControl;
use shell_storage::{CanonicalProofManifest, CanonicalProofUploadStatus};

impl<S: KvStore + 'static> Node<S> {
    pub(super) fn validate_proof_upload_source(
        &self,
        manifest: &CanonicalProofManifest,
    ) -> Result<(), String> {
        manifest.validate().map_err(|e| e.to_string())?;
        let config = self
            .chain_store
            .get_chain_config()
            .map_err(|e| e.to_string())?
            .ok_or("canonical proof chain configuration unavailable")?;
        if manifest.chain_id != self.config.chain_id
            || config.chain_id != manifest.chain_id
            || config.genesis_hash != manifest.genesis_hash
            || self
                .chain_store
                .get_block_hash_by_number(0)
                .map_err(|e| e.to_string())?
                != Some(manifest.genesis_hash)
        {
            return Err("canonical proof chain/genesis identity mismatch".into());
        }
        if self.pending_manifest_source(manifest)? {
            return Ok(());
        }
        if self.production_manifest_source(manifest)? {
            return Ok(());
        }
        let block = self
            .chain_store
            .get_block_by_hash(&manifest.block_hash)
            .map_err(|e| e.to_string())?
            .ok_or("canonical proof source block unavailable")?;
        if block.hash() != manifest.block_hash
            || self
                .chain_store
                .get_block_hash_by_number(block.number())
                .map_err(|e| e.to_string())?
                != Some(manifest.block_hash)
        {
            return Err("canonical proof source is no longer canonical".into());
        }
        if config
            .block_commitment_height
            .is_none_or(|height| block.number() < height)
            || block.transactions.is_empty()
            || block.transactions.len()
                > shell_stark_prover::canonical_batch::MAX_CANONICAL_SIGNATURE_BATCH
            || block.transactions.iter().any(|tx| {
                tx.tx.tx_type > 3
                    || tx.aa_bundle.is_some()
                    || !matches!(
                        tx.signature.sig_type,
                        shell_crypto::SignatureType::MlDsa65
                            | shell_crypto::SignatureType::Dilithium3
                    )
                    || tx.signature.data.len() != 3309
            })
            || block
                .system_transactions
                .iter()
                .any(|tx| tx.kind != SystemTxKind::BlockGasReward)
        {
            return Err("canonical proof source profile inactive or unsupported".into());
        }
        self.chain_store
            .verify_block_body_commitment(&block)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    fn verify_uploaded_canonical_proof(&self, id: ShellHash) -> Result<serde_json::Value, String> {
        let status = self
            .canonical_proof_uploads
            .status(&id)
            .map_err(|e| e.to_string())?;
        self.validate_proof_upload_source(&status.manifest)?;
        let payload = self
            .canonical_proof_uploads
            .payload(&id)
            .map_err(|e| e.to_string())?;
        let proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof =
            shell_stark_prover::compact_canonical::decode_payload(&payload)
                .map_err(|e| format!("canonical proof payload decode: {e}"))?;
        let tip = self
            .chain_store
            .get_head_hash()
            .map_err(|e| e.to_string())?
            .ok_or("canonical proof current tip unavailable")?;
        let result = self
            .replay_canonical_transactions_with_proof(tip, status.manifest.block_hash, &proof)
            .map_err(|e| e.to_string())?;
        self.validate_proof_upload_source(&status.manifest)?;
        serde_json::to_value(result).map_err(|e| e.to_string())
    }
}
impl<S: KvStore + 'static> CanonicalProofControl for Node<S> {
    fn admission(&self, block: ShellHash) -> Result<Option<serde_json::Value>, String> {
        self.canonical_admission_status(block)
    }
    fn production(&self, block: ShellHash) -> Result<Option<serde_json::Value>, String> {
        self.canonical_production_status(block)
    }
    fn fetch(
        &self,
        peer: String,
        manifest: CanonicalProofManifest,
    ) -> Result<shell_storage::CanonicalProofFetchStatus, String> {
        self.start_canonical_proof_fetch(peer, manifest)
    }
    fn fetch_status(
        &self,
        id: ShellHash,
        generation: Option<u64>,
    ) -> Result<Option<shell_storage::CanonicalProofFetchStatus>, String> {
        self.canonical_proof_fetch_status(id, generation)
    }
    fn attempt_status(
        &self,
        id: ShellHash,
        generation: u64,
    ) -> Result<CanonicalProofUploadStatus, String> {
        self.canonical_proof_uploads
            .attempt_status(&id, generation)
            .map_err(|e| e.to_string())
    }
    fn attempt_chunk(&self, id: ShellHash, generation: u64, index: u32) -> Result<Bytes, String> {
        self.canonical_proof_uploads
            .attempt_chunk(&id, generation, index)
            .map(Bytes::from)
            .map_err(|e| e.to_string())
    }
    fn begin(
        &self,
        manifest: CanonicalProofManifest,
    ) -> Result<CanonicalProofUploadStatus, String> {
        self.validate_proof_upload_source(&manifest)?;
        self.canonical_proof_uploads
            .begin(manifest)
            .map_err(|e| e.to_string())
    }
    fn append(
        &self,
        id: ShellHash,
        index: u32,
        chunk: Bytes,
    ) -> Result<CanonicalProofUploadStatus, String> {
        self.validate_proof_upload_source(
            &self
                .canonical_proof_uploads
                .status(&id)
                .map_err(|e| e.to_string())?
                .manifest,
        )?;
        self.canonical_proof_uploads
            .append(&id, index, chunk.as_ref())
            .map_err(|e| e.to_string())
    }
    fn status(&self, id: ShellHash) -> Result<CanonicalProofUploadStatus, String> {
        let status = self
            .canonical_proof_uploads
            .status(&id)
            .map_err(|e| e.to_string())?;
        self.validate_proof_upload_source(&status.manifest)?;
        Ok(status)
    }
    fn chunk(&self, id: ShellHash, index: u32) -> Result<Bytes, String> {
        self.validate_proof_upload_source(
            &self
                .canonical_proof_uploads
                .status(&id)
                .map_err(|e| e.to_string())?
                .manifest,
        )?;
        self.canonical_proof_uploads
            .chunk(&id, index)
            .map(Bytes::from)
            .map_err(|e| e.to_string())
    }
    fn verify(
        self: Arc<Self>,
        id: ShellHash,
        recheck: bool,
    ) -> Result<CanonicalProofUploadStatus, String> {
        self.validate_proof_upload_source(
            &self
                .canonical_proof_uploads
                .status(&id)
                .map_err(|e| e.to_string())?
                .manifest,
        )?;
        if self.has_live_manifest(id) {
            return Err("live candidate verification belongs to the canonical event loop".into());
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "canonical proof verification requires a runtime")?;
        let (status, claimed) = self
            .canonical_proof_uploads
            .claim(&id, recheck)
            .map_err(|e| e.to_string())?;
        if claimed {
            drop(runtime.spawn_blocking(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.verify_uploaded_canonical_proof(id)))
                    .unwrap_or_else(|_| Err("canonical proof verification worker panicked".into()));
                if let Err(error) = self.canonical_proof_uploads.complete(&id,result) {
                    warn!(%id, %error, "canonical proof result persistence failed; retained upload can be retried");
                }
            }));
        }
        Ok(status)
    }
}
