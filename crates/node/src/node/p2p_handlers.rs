use super::*;

impl<S: KvStore + 'static> Node<S> {
    /// Handle a transaction received from the network.
    pub fn handle_incoming_tx(
        &self,
        tx: SignedTransaction,
        _verifier: &dyn Verifier,
    ) -> Result<ShellHash, NodeError> {
        let chain_store = &self.chain_store;
        let mut world_state_guard = self.world_state.write();

        let dv = MultiVerifier;
        let hash = self
            .tx_pool
            .insert(tx, &mut world_state_guard, chain_store.as_ref(), &dv)
            .map_err(|e| NodeError::Startup(e.to_string()))?;

        Ok(hash)
    }

    /// Process an incoming attestation from the network.
    pub fn handle_attestation(
        &self,
        attestation: Attestation,
        verifier: &dyn Verifier,
    ) -> Result<(), NodeError> {
        let block_hash = attestation.block_hash;
        let block_number = attestation.block_number;
        let validator = attestation.validator;

        // F-087: Verify the attested block exists in our local chain store.
        // If unknown, log and skip — the block may arrive later via sync.
        match self.chain_store.get_block_by_hash(&block_hash) {
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!(
                    %block_hash,
                    block_number,
                    %validator,
                    "attestation for unknown block — skipping (may arrive via sync)"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    %block_hash,
                    error = %e,
                    "failed to check block existence for attestation"
                );
                return Ok(());
            }
        }

        // Verify the attesting validator is a known authority.
        let known = self.known_authorities.read();
        let pubkey = known.get(&validator).ok_or_else(|| {
            NodeError::Startup(format!("unknown attestation validator: {:?}", validator))
        })?;

        // Verify the attestation signature.
        let msg = Attestation::signing_message(&block_hash, block_number);
        let sig = shell_crypto::PQSignature::new(
            shell_crypto::SignatureType::Dilithium3,
            attestation.signature.clone(),
        );
        let valid = verifier
            .verify(pubkey, &msg, &sig)
            .map_err(|_| NodeError::Startup("invalid attestation signature".into()))?;
        if !valid {
            return Err(NodeError::Startup(
                "attestation signature verification failed".into(),
            ));
        }

        // Check for equivocation.
        let mut finality = self.finality.write();
        if let Some(conflicting) =
            finality.detect_equivocation(&block_hash, block_number, &validator)
        {
            tracing::error!(
                %validator,
                %block_hash,
                %conflicting,
                height = block_number,
                "equivocation detected — rejecting attestation"
            );
            return Err(NodeError::Startup(format!(
                "equivocation: validator {validator:?} already attested to {conflicting:?} at height {block_number}"
            )));
        }

        // Record the attestation.
        if !finality.record_attestation(attestation) {
            return Ok(()); // duplicate, already recorded
        }

        // Check if this block reached finality.
        let total_validators = self.consensus.read().config().authorities.len();
        if finality.check_finality(&block_hash, block_number, total_validators) {
            tracing::info!(
                block = block_number,
                hash = %block_hash,
                "block finalized"
            );
            let _ = self.chain_store.set_finalized_number(block_number);
            // F-088: Prune fork choice data for old blocks to prevent unbounded growth.
            let mut fc = self.fork_choice.write();
            fc.mark_finalized(&block_hash);
            fc.prune_below(block_number);
        }

        Ok(())
    }

    /// Create and return an attestation for a block (called after producing/importing a block).
    pub fn create_attestation(
        &self,
        block_hash: ShellHash,
        block_number: u64,
        signer: &dyn Signer,
    ) -> Result<Attestation, NodeError> {
        let proposer_addr = self.config.proposer_address.ok_or(NodeError::NotProposer)?;

        let msg = Attestation::signing_message(&block_hash, block_number);
        let sig = signer
            .sign(&msg)
            .map_err(|e| NodeError::Startup(format!("failed to sign attestation: {e}")))?;

        Ok(Attestation::new(
            block_hash,
            block_number,
            proposer_addr,
            sig.data,
        ))
    }
}
