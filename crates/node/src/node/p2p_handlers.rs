use super::*;

/// Decode every claimed signer before a map can discard duplicate JSON names
/// or different historical spellings of the same address.
struct CertificateSignatures<T>(HashMap<Address, T>);

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for CertificateSignatures<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignaturesVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for SignaturesVisitor<T> {
            type Value = CertificateSignatures<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a certificate with unique signer addresses")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut signatures = HashMap::new();
                while let Some(raw) = map.next_key::<String>()? {
                    let name = raw
                        .strip_prefix("Address(")
                        .and_then(|s| s.strip_suffix(')'))
                        .unwrap_or(&raw);
                    let address = name.parse::<Address>().map_err(|_| {
                        <M::Error as serde::de::Error>::custom("invalid certificate signer")
                    })?;
                    match signatures.entry(address) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(map.next_value::<T>()?);
                        }
                        std::collections::hash_map::Entry::Occupied(_) => {
                            return Err(<M::Error as serde::de::Error>::custom(
                                "duplicate certificate signer",
                            ));
                        }
                    }
                }
                Ok(CertificateSignatures(signatures))
            }
        }
        deserializer.deserialize_map(SignaturesVisitor(std::marker::PhantomData))
    }
}

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
            // Use kind_str() so NodeError::Startup never carries account-state
            // values (nonce, balance) that would be logged as cleartext.
            .map_err(|e| NodeError::Startup(e.kind_str().to_string()))?;

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
        let stored_block = match self.chain_store.get_block_by_hash(&block_hash) {
            Ok(Some(block)) => block,
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
        };

        // Bind the signed target metadata to the locally stored header. Without
        // this check, one validator can poison this block hash's pending entry
        // with a false height or parent before honest attestations arrive.
        if block_number != stored_block.header.number
            || attestation.parent_hash != stored_block.header.parent_hash
        {
            return Err(NodeError::Startup(format!(
                "attestation target does not match stored block header for {block_hash}"
            )));
        }

        // Reject cross-network attestations: chain_id must match our own.
        if attestation.chain_id != self.config.chain_id {
            return Err(NodeError::Startup(format!(
                "attestation chain_id {} does not match local chain_id {}",
                attestation.chain_id, self.config.chain_id
            )));
        }

        // Verify the attesting validator is a known authority.
        let pubkey = self
            .known_authorities
            .read()
            .get(&validator)
            .cloned()
            .ok_or_else(|| {
                NodeError::Startup(format!("unknown attestation validator: {:?}", validator))
            })?;

        // Verify the attestation signature using the payload that was signed.
        let msg = attestation.own_signing_message();
        let sig_type = shell_crypto::infer_signature_type_from_address(&pubkey, &validator)
            .ok_or_else(|| {
                NodeError::Startup(format!(
                    "unknown attestation signature algorithm for validator {validator:?}"
                ))
            })?;
        if !shell_crypto::is_algorithm_allowed(sig_type) {
            return Err(NodeError::Startup(format!(
                "attestation signature algorithm {sig_type:?} not allowed"
            )));
        }
        let sig = shell_crypto::PQSignature::new(sig_type, attestation.signature.clone());
        let valid = verifier
            .verify(&pubkey, &msg, &sig)
            .map_err(|e| NodeError::Startup(format!("invalid attestation signature: {e}")))?;
        if !valid {
            return Err(NodeError::Startup(
                "attestation signature verification failed".into(),
            ));
        }

        let validator_weights = self.consensus.read().validator_weights();
        let attester_weight = validator_weights.get(&validator).copied().ok_or_else(|| {
            NodeError::Startup(format!(
                "unknown active attestation validator: {validator:?}"
            ))
        })?;
        let total_weight: u64 = validator_weights.values().copied().sum();
        let is_canonical = self
            .chain_store
            .get_block_hash_by_number(block_number)?
            .is_some_and(|canonical_hash| canonical_hash == block_hash);
        let (attested_weight, finalized) = {
            // Check for equivocation, record the attestation, and evaluate
            // finality under one finality write lock to avoid lock-order cycles
            // with fork_choice.
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
            let already_attested = finality.has_attested(&block_hash, &validator);
            if !finality.record_attestation_weighted(attestation, attester_weight)
                && !already_attested
            {
                return Ok(());
            }
            let attested_weight = finality.attested_weight(&block_hash);
            let can_finalize = is_canonical
                && finality.can_finalize_weighted(&block_hash, block_number, total_weight);
            if can_finalize {
                // Persist first so a failed write cannot leave volatile finality
                // ahead of the restart-safe finalized cursor. Keeping the
                // attestation pending allows the same message to retry the write.
                self.chain_store.set_finalized_number(block_number)?;
            }
            let finalized = can_finalize
                && finality.check_finality_weighted(&block_hash, block_number, total_weight);
            (attested_weight, finalized)
        };

        if self.fork_choice.read().contains(&block_hash) {
            self.fork_choice
                .write()
                .update_attested_weight(&block_hash, attested_weight);
        }

        if finalized {
            tracing::info!(
                block = block_number,
                hash = %block_hash,
                "block finalized"
            );
            self.advance_fork_choice_finality(block_number, block_hash);
        }

        Ok(())
    }

    pub(super) fn advance_fork_choice_finality(&self, block_number: u64, block_hash: ShellHash) {
        let mut fork_choice = self.fork_choice.write();
        fork_choice.mark_finalized(&block_hash);
        if fork_choice
            .score(&block_hash)
            .is_some_and(|score| score.is_finalized == 1)
        {
            // F-088: Prune old and incompatible branches after every finality path.
            fork_choice.prune_below(block_number);
        } else {
            warn!(
                block_number,
                %block_hash,
                "finalized block is missing from fork choice"
            );
        }
    }

    /// Create and return an attestation for a block (called after producing/importing a block).
    pub fn create_attestation(
        &self,
        block_hash: ShellHash,
        block_number: u64,
        signer: &dyn Signer,
    ) -> Result<Attestation, NodeError> {
        let proposer_addr = self.config.proposer_address.ok_or(NodeError::NotProposer)?;

        // Look up the parent hash so the signing payload binds to the specific fork.
        // Return an error if the header is missing — signing with ZERO parent_hash would
        // produce an invalid payload that misses the intended fork-binding guarantee.
        let parent_hash = self
            .chain_store
            .get_header_by_hash(&block_hash)
            .map_err(|e| NodeError::Startup(format!("failed to look up header for attestation parent_hash: {e}")))?
            .ok_or_else(|| NodeError::Startup(format!(
                "header not found for block {block_hash} — cannot create attestation with correct parent_hash"
            )))?
            .parent_hash;

        let chain_id = self.config.chain_id;
        // round = 0 for standard PoA; wPoA round is embedded per-block in Phase 2.
        let round: u64 = 0;
        let msg =
            Attestation::signing_message(chain_id, &parent_hash, &block_hash, block_number, round);
        let sig = signer
            .sign(&msg)
            .map_err(|e| NodeError::Startup(format!("failed to sign attestation: {e}")))?;

        Ok(Attestation::new(
            chain_id,
            parent_hash,
            block_hash,
            block_number,
            proposer_addr,
            round,
            sig.data,
        ))
    }

    /// W.5: Handle an incoming wPoA vote from a peer.
    ///
    /// Reconstructs the PQ signature, validates the voter, records the vote,
    /// and logs when quorum is reached.
    pub fn handle_wpoa_vote(
        &self,
        voter: Address,
        block_hash: ShellHash,
        block_number: u64,
        sig: shell_crypto::PQSignature,
    ) -> Option<Vec<u8>> {
        // Reject unknown identities before any score record can be created.
        let pubkey = {
            let known = self.known_authorities.read();
            match known.get(&voter) {
                Some(pk) => pk.clone(),
                None => {
                    tracing::warn!(
                        %voter,
                        "C-3: WPoA vote from unknown validator — rejecting"
                    );
                    return None;
                }
            }
        };

        // FF.6: Drop votes for blocks that have already been finalized at a different hash
        // (stale or conflicting vote). Penalise the sender.
        {
            let finality = self.finality.read();
            let fin_number = finality.last_finalized_number();
            if fin_number > 0 && block_number <= fin_number {
                // Check if the vote is for the same hash as the finalized block.
                let fin_hash_at_height = self
                    .chain_store
                    .get_block_by_number(block_number)
                    .ok()
                    .flatten()
                    .map(|b| b.hash());
                if fin_hash_at_height.as_ref() != Some(&block_hash) {
                    tracing::warn!(
                        block_number,
                        %block_hash,
                        fin_number,
                        %voter,
                        "FF.6: vote for finalized block with wrong hash — dropping and penalising"
                    );
                    let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
                    self.peer_scorer
                        .lock()
                        .record_event(&peer_id, shell_consensus::PeerEvent::InvalidProofPayload);
                    return None;
                }
            }
        }

        // C-3: Verify the vote's PQ signature before dispatching into consensus.
        // The signing pre-image is the raw block hash bytes (mirrors event_loop.rs).
        // Mirrors the same pattern used in handle_wpoa_view_change.
        {
            let sig_type = match shell_crypto::infer_signature_type_from_address(&pubkey, &voter) {
                Some(t) if shell_crypto::is_algorithm_allowed(t) => t,
                Some(t) => {
                    tracing::warn!(
                        %voter,
                        algorithm = ?t,
                        "C-3: WPoA vote uses disallowed signature algorithm — rejecting"
                    );
                    let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
                    self.peer_scorer
                        .lock()
                        .record_event(&peer_id, shell_consensus::PeerEvent::InvalidProofPayload);
                    return None;
                }
                None => {
                    tracing::warn!(
                        %voter,
                        "C-3: cannot infer signature algorithm for WPoA voter — rejecting"
                    );
                    let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
                    self.peer_scorer
                        .lock()
                        .record_event(&peer_id, shell_consensus::PeerEvent::InvalidProofPayload);
                    return None;
                }
            };

            // Security: reject votes whose sender-controlled sig_type tag does
            // not match the canonical algorithm inferred from the voter's address.
            // Accepting a mismatched tag would allow an attacker to store a
            // commit certificate whose algorithm label differs from the one used
            // during verification (algorithm-tag confusion).
            if sig.sig_type != sig_type {
                tracing::warn!(
                    voter = %voter,
                    claimed = ?sig.sig_type,
                    expected = ?sig_type,
                    "vote sig_type mismatch: claimed={:?} expected={:?} — rejecting",
                    sig.sig_type,
                    sig_type,
                );
                let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
                self.peer_scorer
                    .lock()
                    .record_event(&peer_id, shell_consensus::PeerEvent::InvalidProofPayload);
                return None;
            }

            let typed_sig = shell_crypto::PQSignature::new(sig_type, sig.data.clone());
            let verifier = MultiVerifier;
            match verifier.verify(&pubkey, block_hash.as_bytes(), &typed_sig) {
                Ok(true) => {} // valid — proceed to consensus
                Ok(false) => {
                    tracing::warn!(
                        %voter,
                        "C-3: WPoA vote signature verification failed (possible forgery) — dropping"
                    );
                    let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
                    self.peer_scorer
                        .lock()
                        .record_event(&peer_id, shell_consensus::PeerEvent::InvalidProofPayload);
                    return None;
                }
                Err(e) => {
                    tracing::warn!(
                        %voter,
                        error = %e,
                        "C-3: WPoA vote signature verification error — dropping"
                    );
                    let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
                    self.peer_scorer
                        .lock()
                        .record_event(&peer_id, shell_consensus::PeerEvent::InvalidProofPayload);
                    return None;
                }
            }
        }

        let mut guard = self.wpoa_round.lock();
        if let Some(ref mut round) = *guard {
            if round.block_number != block_number {
                tracing::debug!(
                    block_number,
                    expected = round.block_number,
                    "W.5: WPoaVote for unexpected block number, ignoring"
                );
                return None;
            }
            let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
            let events = round.on_vote(voter, block_hash, sig);
            for event in events {
                match event {
                    WPoaEvent::BlockCommitted {
                        block_hash,
                        quorum_signatures,
                    } => {
                        let current_weights = self.consensus.read().validator_weights();
                        let current_total_weight = current_weights
                            .values()
                            .copied()
                            .fold(0u64, u64::saturating_add);
                        let current_signed_weight = quorum_signatures
                            .keys()
                            .filter_map(|signer| current_weights.get(signer).copied())
                            .fold(0u64, u64::saturating_add);
                        if !FinalityState::has_weighted_quorum(
                            current_signed_weight,
                            current_total_weight,
                        ) {
                            let round_number = round.round;
                            let mut refreshed =
                                WPoaRound::new(block_number, round_number, current_weights);
                            let _ = refreshed.on_block_proposed(block_hash, voter);
                            for (signer, signature) in &quorum_signatures {
                                let _ = refreshed.on_vote(*signer, block_hash, signature.clone());
                            }
                            *round = refreshed;
                            tracing::warn!(
                                block_number,
                                %block_hash,
                                current_signed_weight,
                                current_total_weight,
                                "W.5: validator weights changed before commit; refreshed round without finalizing"
                            );
                            return None;
                        }
                        tracing::info!(
                            %block_hash,
                            block_number,
                            signers = quorum_signatures.len(),
                            "W.5: block committed with quorum"
                        );
                        // PS.1: reward all quorum signers.
                        {
                            let mut scorer = self.peer_scorer.lock();
                            for signer in quorum_signatures.keys() {
                                let signer_id =
                                    shell_consensus::ScoringPeerId::from(format!("{signer:?}"));
                                scorer.record_event(
                                    &signer_id,
                                    shell_consensus::PeerEvent::ValidProofDelivered,
                                );
                            }
                        }
                        // FF.1 / FF.3: Advance finality and persist.
                        // The round state machine already verified weight-based quorum,
                        // so BlockCommitted IS the finality signal.  Verify the block
                        // is locally canonical before finalizing (safety guard).
                        let locally_canonical = self
                            .chain_store
                            .get_block_by_number(block_number)
                            .ok()
                            .flatten()
                            .map(|b| b.hash() == block_hash)
                            .unwrap_or(false);

                        if locally_canonical {
                            let encoded = match Self::encode_commit_certificate(&quorum_signatures)
                            {
                                Ok(encoded) => encoded,
                                Err(e) => {
                                    tracing::warn!(
                                        %block_hash,
                                        error = %e,
                                        "FF.2: failed to encode commit certificate"
                                    );
                                    return None;
                                }
                            };
                            let signer_evidence =
                                self.commit_signer_evidence(&quorum_signatures, block_hash);
                            let advanced = {
                                let mut finality = self.finality.write();
                                let already_finalized =
                                    block_number <= finality.last_finalized_number();
                                let persist_result = if already_finalized {
                                    self.chain_store.set_commit_certificate_with_signers(
                                        &block_hash,
                                        &encoded,
                                        &signer_evidence,
                                    )
                                } else {
                                    self.chain_store.set_finalized_with_certificate_and_signers(
                                        block_number,
                                        &block_hash,
                                        &encoded,
                                        &signer_evidence,
                                    )
                                };
                                if let Err(e) = persist_result {
                                    let round_number = round.round;
                                    let mut retry_round =
                                        WPoaRound::new(block_number, round_number, current_weights);
                                    let _ = retry_round.on_block_proposed(block_hash, voter);
                                    for (signer, signature) in &quorum_signatures {
                                        if *signer != voter {
                                            let _ = retry_round.on_vote(
                                                *signer,
                                                block_hash,
                                                signature.clone(),
                                            );
                                        }
                                    }
                                    *round = retry_round;
                                    tracing::warn!(
                                        block_number,
                                        error = %e,
                                        "FF: failed to persist finality certificate; restored voting round for retry"
                                    );
                                    return None;
                                }
                                if already_finalized {
                                    false
                                } else {
                                    finality.set_finalized_direct(block_number, block_hash)
                                }
                            };
                            if advanced {
                                self.advance_fork_choice_finality(block_number, block_hash);
                                let current_head = self
                                    .chain_store
                                    .get_head_block()
                                    .ok()
                                    .flatten()
                                    .map(|b| b.number())
                                    .unwrap_or(block_number);
                                self.metrics.update_finality(current_head, block_number);
                                tracing::info!(
                                    block_number,
                                    %block_hash,
                                    "FF: block finalized"
                                );
                            }
                            return Some(encoded);
                        } else {
                            tracing::warn!(
                                block_number,
                                %block_hash,
                                "FF: BlockCommitted but block not locally canonical — \
                                 finality deferred until block is imported"
                            );
                        }
                    }
                    WPoaEvent::DuplicateVote { voter } => {
                        tracing::warn!(%voter, "W.5: duplicate vote rejected");
                        // PS.1: penalise duplicate voter.
                        self.peer_scorer
                            .lock()
                            .record_event(&peer_id, shell_consensus::PeerEvent::DuplicateMessage);
                    }
                    WPoaEvent::WrongBlockHash { expected, got } => {
                        tracing::warn!(%expected, %got, "W.5: vote for wrong block hash rejected");
                        // PS.1: penalise invalid payload.
                        self.peer_scorer.lock().record_event(
                            &peer_id,
                            shell_consensus::PeerEvent::InvalidProofPayload,
                        );
                    }
                    _ => {}
                }
            }
        }
        None
    }

    pub fn encode_commit_certificate(
        quorum_signatures: &HashMap<Address, shell_crypto::PQSignature>,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let cert: HashMap<String, shell_crypto::PQSignature> = quorum_signatures
            .iter()
            .map(|(addr, sig)| (addr.to_string(), sig.clone()))
            .collect();
        serde_json::to_vec(&cert)
    }

    fn decode_commit_certificate(
        cert: &[u8],
    ) -> Option<HashMap<Address, shell_crypto::PQSignature>> {
        if let Ok(raw) =
            serde_json::from_slice::<CertificateSignatures<shell_crypto::PQSignature>>(cert)
        {
            return Some(raw.0);
        }

        // Legacy sidecars encoded {Address(...) -> sig_hex} and implicitly used Dilithium3.
        let raw = serde_json::from_slice::<CertificateSignatures<String>>(cert).ok()?;
        raw.0
            .into_iter()
            .map(|(addr, sig_hex)| {
                let data = hex::decode(sig_hex).ok()?;
                Some((
                    addr,
                    shell_crypto::PQSignature::new(shell_crypto::SignatureType::Dilithium3, data),
                ))
            })
            .collect()
    }

    fn commit_signer_evidence(
        &self,
        signatures: &HashMap<Address, shell_crypto::PQSignature>,
        block_hash: ShellHash,
    ) -> Vec<shell_core::BlockSignerEvidence> {
        self.commit_signer_evidence_using(signatures, block_hash, &MultiVerifier)
    }

    fn commit_signer_evidence_using(
        &self,
        signatures: &HashMap<Address, shell_crypto::PQSignature>,
        block_hash: ShellHash,
        verifier: &dyn Verifier,
    ) -> Vec<shell_core::BlockSignerEvidence> {
        signatures
            .iter()
            .filter_map(|(address, signature)| {
                let public_key = self.authority_pubkey(address).ok().flatten()?;
                if !verifier
                    .verify(&public_key, block_hash.as_bytes(), signature)
                    .unwrap_or(false)
                {
                    return None;
                }
                Some(shell_core::BlockSignerEvidence {
                    address: *address,
                    public_key,
                    signature: signature.clone(),
                })
            })
            .collect()
    }

    /// Verify a commit certificate independently of local canonical storage.
    /// Block sync uses this before importing a view-changed finalized block;
    /// finalization performs the canonical-target checks separately.
    pub(crate) fn verify_commit_certificate(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
    ) -> bool {
        self.verify_commit_certificate_using(block_number, block_hash, cert, None, &MultiVerifier)
    }

    fn verify_commit_certificate_using(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
        weights: Option<&HashMap<Address, u64>>,
        verifier: &dyn Verifier,
    ) -> bool {
        let Some(signatures) = Self::decode_commit_certificate(cert) else {
            warn!(block_number, %block_hash, "FF.7: invalid commit certificate encoding");
            return false;
        };
        // Preserve the ordinary path's sampling order: decode first, then
        // obtain current weights. The proof path supplies its locked snapshot.
        let current_weights = weights
            .is_none()
            .then(|| self.consensus.read().validator_weights());
        let weights = weights
            .or(current_weights.as_ref())
            .expect("current or locked weights");
        let total_weight = weights.values().copied().fold(0u64, u64::saturating_add);
        if total_weight == 0 {
            warn!(block_number, %block_hash, "FF.7: certificate cannot be verified without active validator weight");
            return false;
        }
        let quorum = FinalityState::strict_quorum_weight(total_weight);
        let mut signed_weight = 0u64;

        for (signer, sig) in signatures {
            let Some(weight) = weights.get(&signer).copied() else {
                warn!(block_number, %block_hash, %signer, "FF.7: certificate contains non-validator signer");
                return false;
            };
            let pubkey = self
                .known_authorities
                .read()
                .get(&signer)
                .cloned()
                .or_else(|| self.chain_store.get_pubkey(&signer).ok().flatten());
            let Some(pubkey) = pubkey else {
                warn!(block_number, %block_hash, %signer, "FF.7: certificate signer pubkey unknown");
                return false;
            };
            let Some(sig_type) = shell_crypto::infer_signature_type_from_address(&pubkey, &signer)
            else {
                warn!(block_number, %block_hash, %signer, "FF.7: certificate signer algorithm unknown");
                return false;
            };
            if !shell_crypto::is_algorithm_allowed(sig_type) {
                warn!(block_number, %block_hash, %signer, algorithm = ?sig_type, "FF.7: certificate signer algorithm not allowed");
                return false;
            }
            if sig.sig_type != sig_type {
                warn!(
                    block_number,
                    %block_hash,
                    %signer,
                    claimed = ?sig.sig_type,
                    expected = ?sig_type,
                    "FF.7: certificate signature algorithm mismatch"
                );
                return false;
            }
            match verifier.verify(&pubkey, block_hash.as_bytes(), &sig) {
                Ok(true) => signed_weight = signed_weight.saturating_add(weight),
                Ok(false) => {
                    warn!(block_number, %block_hash, %signer, "FF.7: invalid certificate signature");
                    return false;
                }
                Err(e) => {
                    warn!(block_number, %block_hash, %signer, error = %e, "FF.7: certificate signature verification failed");
                    return false;
                }
            }
        }

        if signed_weight < quorum {
            warn!(
                block_number,
                %block_hash,
                signed_weight,
                quorum,
                "FF.7: certificate below quorum"
            );
            return false;
        }
        true
    }

    /// Replay an authenticated side branch before the canonical-only finality path runs.
    pub(super) fn adopt_certified_fork(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
    ) -> Result<Option<ForkAdoptionPlan>, NodeError> {
        if block_number <= self.finality.read().last_finalized_number()
            || self.chain_store.get_block_hash_by_number(block_number)? == Some(block_hash)
        {
            return Ok(None);
        }
        let Some(header) = self.chain_store.get_header_by_hash(&block_hash)? else {
            return Ok(None);
        };
        if header.number != block_number
            || !self.verify_commit_certificate(block_number, block_hash, cert)
        {
            return Ok(None);
        }
        let signatures =
            Self::decode_commit_certificate(cert).expect("verified certificate encoding");
        let evidence = self.commit_signer_evidence(&signatures, block_hash);
        self.chain_store
            .set_commit_certificate_with_signers(&block_hash, cert, &evidence)?;
        let weights = self.consensus.read().validator_weights();
        let signed_weight = signatures
            .keys()
            .filter_map(|signer| weights.get(signer).copied())
            .fold(0u64, u64::saturating_add);
        self.fork_choice
            .write()
            .update_attested_weight(&block_hash, signed_weight);
        let Some(plan) = self.preferred_fork_plan()? else {
            return Ok(None);
        };
        if plan.preferred_hash != block_hash {
            return Ok(None);
        }
        if let Err(error) = self.adopt_preferred_fork(&plan) {
            if let NodeError::InvalidFork { block_hash, .. } = &error {
                self.fork_choice.write().remove_subtree(block_hash);
            }
            return Err(error);
        }
        Ok(Some(plan))
    }

    pub fn fast_finalize_with_certificate(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
    ) -> bool {
        self.fast_finalize_with_certificate_using(
            block_number,
            block_hash,
            cert,
            &MultiVerifier,
            None,
        )
    }

    /// Capture the current Native authority context independently of an offline
    /// proof. This is not authenticated historical penalty context.
    pub fn commit_quorum_source(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
    ) -> Result<shell_stark_prover::commit_quorum::CommitQuorumSource, String> {
        let weights = self.consensus.read().validator_weights();
        self.commit_quorum_source_using(block_number, block_hash, cert, &weights)
    }

    fn commit_quorum_source_using(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
        weights: &HashMap<Address, u64>,
    ) -> Result<shell_stark_prover::commit_quorum::CommitQuorumSource, String> {
        use shell_stark_prover::{
            commit_quorum::CommitQuorumSource,
            weighted_quorum::{AuthorityWeight, QuorumWeightContext},
        };
        let header = self
            .chain_store
            .get_header_by_hash(&block_hash)
            .map_err(|e| e.to_string())?
            .ok_or("commit proof header missing")?;
        if header.number != block_number
            || self
                .chain_store
                .get_block_hash_by_number(block_number)
                .map_err(|e| e.to_string())?
                != Some(block_hash)
        {
            return Err("commit proof target is not the canonical stored header".into());
        }
        let signatures =
            Self::decode_commit_certificate(cert).ok_or("invalid commit certificate")?;
        let mut entries = Vec::with_capacity(signatures.len());
        for (address, signature) in signatures {
            let public_key = self
                .authority_pubkey(&address)
                .map_err(|e| e.to_string())?
                .ok_or("commit signer key unknown")?;
            entries.push(shell_core::BlockSignerEvidence {
                address,
                public_key,
                signature,
            });
        }
        entries.sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
        let mut authorities: Vec<_> = weights
            .iter()
            .map(|(&address, &weight)| AuthorityWeight { address, weight })
            .collect();
        authorities.sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
        Ok(CommitQuorumSource {
            context: QuorumWeightContext {
                chain_id: self.config.chain_id,
                parent_hash: header.parent_hash,
                block_hash,
                block_number,
                authorities,
                signers: entries.iter().map(|e| e.address).collect(),
            },
            signatures: entries,
        })
    }

    /// Explicit source-only proof path; ordinary wire formats and activation
    /// remain unchanged. Full signature and weight proofs must pass first.
    pub fn fast_finalize_with_certificate_proof(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
        proof: &shell_stark_prover::commit_quorum::CommitQuorumProof,
    ) -> bool {
        let Ok(source) = self.commit_quorum_source(block_number, block_hash, cert) else {
            return false;
        };
        let Ok(verified) = shell_stark_prover::commit_quorum::verify_commit_quorum(proof, &source)
        else {
            return false;
        };
        self.fast_finalize_with_certificate_using(
            block_number,
            block_hash,
            cert,
            &verified,
            Some(&verified),
        )
    }

    fn fast_finalize_with_certificate_using(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
        verifier: &dyn Verifier,
        proof: Option<&shell_stark_prover::commit_quorum::VerifiedCommitQuorum>,
    ) -> bool {
        // Keep weight changes outside the final context check and atomic Native
        // commit. The slow proof verification happened before acquiring this lock.
        let consensus = proof.map(|_| self.consensus.read());
        let weights = consensus.as_ref().map(|guard| guard.validator_weights());
        if let Some(proof) = proof {
            let Ok(current) = self.commit_quorum_source_using(
                block_number,
                block_hash,
                cert,
                weights.as_ref().expect("proof context lock"),
            ) else {
                return false;
            };
            if !proof.matches_source(&current) {
                return false;
            }
        }
        let canonical_hash = match self.chain_store.get_block_hash_by_number(block_number) {
            Ok(Some(hash)) => hash,
            Ok(None) => {
                warn!(block_number, %block_hash, "FF.7: certificate target is not canonical");
                return false;
            }
            Err(e) => {
                warn!(block_number, %block_hash, error = %e, "FF.7: failed to resolve canonical certificate target");
                return false;
            }
        };
        if canonical_hash != block_hash {
            warn!(
                block_number,
                %block_hash,
                %canonical_hash,
                "FF.7: certificate target does not match canonical block"
            );
            return false;
        }
        match self.chain_store.get_header_by_hash(&block_hash) {
            Ok(Some(header)) if header.number == block_number => {}
            Ok(Some(header)) => {
                warn!(
                    block_number,
                    %block_hash,
                    stored_number = header.number,
                    "FF.7: certificate target height does not match stored header"
                );
                return false;
            }
            Ok(None) => {
                warn!(block_number, %block_hash, "FF.7: certificate target header is missing");
                return false;
            }
            Err(e) => {
                warn!(block_number, %block_hash, error = %e, "FF.7: failed to load certificate target header");
                return false;
            }
        }

        if !self.verify_commit_certificate_using(
            block_number,
            block_hash,
            cert,
            weights.as_ref(),
            verifier,
        ) {
            return false;
        }

        let signatures =
            Self::decode_commit_certificate(cert).expect("verified certificate encoding");
        let signer_evidence = self.commit_signer_evidence_using(&signatures, block_hash, verifier);
        if signer_evidence.len() != signatures.len() {
            return false;
        }

        let advanced = {
            let mut finality = self.finality.write();
            if block_number <= finality.last_finalized_number() {
                if let Err(e) = self.chain_store.set_commit_certificate_with_signers(
                    &block_hash,
                    cert,
                    &signer_evidence,
                ) {
                    warn!(block_number, %block_hash, error = %e, "FF.7: failed to persist commit certificate");
                    return false;
                }
                false
            } else {
                if let Err(e) = self.chain_store.set_finalized_with_certificate_and_signers(
                    block_number,
                    &block_hash,
                    cert,
                    &signer_evidence,
                ) {
                    warn!(block_number, %block_hash, error = %e, "FF.7: failed to persist finality");
                    return false;
                }
                finality.set_finalized_direct(block_number, block_hash)
            }
        };
        drop(consensus);
        if advanced {
            self.advance_fork_choice_finality(block_number, block_hash);
            let current_head = self
                .chain_store
                .get_head_block()
                .ok()
                .flatten()
                .map(|b| b.number())
                .unwrap_or(block_number);
            self.metrics.update_finality(current_head, block_number);
            info!(block_number, %block_hash, "FF.7: fast-finalized block via commit certificate");
        }
        true
    }

    /// PS.2: Flush wPoA peer scorer to the network-level ban list.
    ///
    /// Any peer whose score has fallen below `disconnect_threshold` is
    /// recorded as a violation in the `PeerBanList`. After `ban_threshold`
    /// violations the network layer will refuse connections from that peer.
    /// Called from the event loop after each wPoA vote round completes.
    pub fn flush_scorer_bans(&self) {
        let scorer = self.peer_scorer.lock();
        let to_disconnect = scorer.peers_to_disconnect();
        if to_disconnect.is_empty() {
            return;
        }
        let mut ban_list = self.peer_ban_list.lock();
        for scoring_peer in to_disconnect {
            let net_peer = shell_network::PeerId(scoring_peer.0.clone());
            let was_banned = ban_list.record_violation(&net_peer);
            if was_banned {
                tracing::warn!(
                    peer = %scoring_peer.0,
                    "PS.2: peer score below threshold — recorded ban violation (now banned)"
                );
            } else {
                tracing::debug!(
                    peer = %scoring_peer.0,
                    "PS.2: peer score below threshold — recorded violation"
                );
            }
        }
    }

    /// W.5: Handle an incoming signed wPoA view-change message from a peer.
    pub fn handle_wpoa_view_change(
        &self,
        msg: ViewChangeMessage,
        verifier: &dyn Verifier,
    ) -> Result<bool, NodeError> {
        // Reject view-change messages for heights other than the current
        // timed-out height (head + 1) to prevent stale / replayed messages
        // from incorrectly rotating proposer selection.
        let expected_block = self
            .chain_store
            .get_head_block()?
            .map(|b| ChainStateMachine::next_block_number(b.number()))
            .unwrap_or(Ok(1))?;
        if msg.block_number != expected_block {
            return Err(NodeError::Startup(format!(
                "view-change block_number {} does not match expected height {}",
                msg.block_number, expected_block
            )));
        }

        // Reject cross-chain view-change injection.
        if msg.chain_id != self.config.chain_id {
            return Err(NodeError::Startup(format!(
                "view-change chain_id {} does not match local chain_id {}",
                msg.chain_id, self.config.chain_id
            )));
        }

        let pubkey = self
            .known_authorities
            .read()
            .get(&msg.validator)
            .cloned()
            .ok_or_else(|| {
                NodeError::Startup(format!(
                    "unknown view-change validator: {:?}",
                    msg.validator
                ))
            })?;

        let signing_message = msg.own_signing_message();
        let sig_type = shell_crypto::infer_signature_type_from_address(&pubkey, &msg.validator)
            .ok_or_else(|| {
                NodeError::Startup(format!(
                    "unknown view-change signature algorithm for validator {}",
                    msg.validator
                ))
            })?;
        if !shell_crypto::is_algorithm_allowed(sig_type) {
            return Err(NodeError::Startup(format!(
                "view-change signature algorithm {sig_type:?} not allowed"
            )));
        }
        let sig = shell_crypto::PQSignature::new(sig_type, msg.signature.clone());
        let valid = verifier
            .verify(&pubkey, &signing_message, &sig)
            .map_err(|e| NodeError::Startup(format!("invalid view-change signature: {e}")))?;
        if !valid {
            return Err(NodeError::Startup(
                "view-change signature verification failed".into(),
            ));
        }

        let total_weight: u64 = self
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .sum();
        Ok(self
            .consensus
            .write()
            .handle_view_change_message(msg, total_weight))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::{PQSignature, SignatureType};
    use shell_storage::MemoryDb;

    #[test]
    fn commit_certificate_codec_preserves_unique_formats_and_tags() {
        // Codec compatibility only: these short byte strings are not
        // claimed to be valid signatures or accepted Native certificates.
        let first = Address::from([1; 32]);
        let second = Address::from([2; 32]);
        for kind in [
            SignatureType::Dilithium3,
            SignatureType::MlDsa65,
            SignatureType::SphincsSha2256f,
        ] {
            let signatures = HashMap::from([
                (first, PQSignature::new(kind, vec![3, 4])),
                (second, PQSignature::new(kind, vec![5, 6])),
            ]);
            let bytes = Node::<MemoryDb>::encode_commit_certificate(&signatures).unwrap();
            assert_eq!(
                Node::<MemoryDb>::decode_commit_certificate(&bytes),
                Some(signatures.clone())
            );
            let aliases = serde_json::to_vec(&HashMap::from([
                (format!("Address({first})"), signatures[&first].clone()),
                (second.to_string(), signatures[&second].clone()),
            ]))
            .unwrap();
            assert_eq!(
                Node::<MemoryDb>::decode_commit_certificate(&aliases),
                Some(signatures)
            );
            let mut trailing = bytes;
            trailing.extend_from_slice(b"{}");
            assert!(Node::<MemoryDb>::decode_commit_certificate(&trailing).is_none());
        }
        let legacy = serde_json::to_vec(&HashMap::from([
            (format!("Address({first})"), "0304"),
            (second.to_string(), "0506"),
        ]))
        .unwrap();
        assert_eq!(
            Node::<MemoryDb>::decode_commit_certificate(&legacy),
            Some(HashMap::from([
                (
                    first,
                    PQSignature::new(SignatureType::Dilithium3, vec![3, 4])
                ),
                (
                    second,
                    PQSignature::new(SignatureType::Dilithium3, vec![5, 6])
                ),
            ]))
        );
        let mixed = serde_json::to_vec(&serde_json::json!({
            first.to_string(): serde_json::to_value(
                PQSignature::new(SignatureType::Dilithium3, vec![3,4])
            ).unwrap(),
            second.to_string(): "0506"
        }))
        .unwrap();
        assert!(Node::<MemoryDb>::decode_commit_certificate(&mixed).is_none());
        for invalid in [b"[]".as_slice(), b"null", b"{\"invalid\":\"0304\"}"] {
            assert!(Node::<MemoryDb>::decode_commit_certificate(invalid).is_none());
        }
        assert_eq!(
            Node::<MemoryDb>::decode_commit_certificate(b"{}"),
            Some(HashMap::new())
        );
    }
}
