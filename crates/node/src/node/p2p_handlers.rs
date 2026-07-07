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

        // Reject cross-network attestations: chain_id must match our own.
        if attestation.chain_id != self.config.chain_id {
            return Err(NodeError::Startup(format!(
                "attestation chain_id {} does not match local chain_id {}",
                attestation.chain_id, self.config.chain_id
            )));
        }

        // Verify the attesting validator is a known authority.
        let known = self.known_authorities.read();
        let pubkey = known.get(&validator).ok_or_else(|| {
            NodeError::Startup(format!("unknown attestation validator: {:?}", validator))
        })?;

        // Verify the attestation signature using the payload that was signed.
        let msg = attestation.own_signing_message();
        let sig_type = shell_crypto::infer_signature_type_from_address(pubkey, &validator)
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
            .verify(pubkey, &msg, &sig)
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
            if !finality.record_attestation_weighted(attestation, attester_weight) {
                return Ok(()); // duplicate, already recorded
            }
            let attested_weight = finality.attested_weight(&block_hash);
            let finalized =
                finality.check_finality_weighted(&block_hash, block_number, total_weight);
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
    ) {
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
                    return;
                }
            }
        }

        // C-3: Verify the vote's PQ signature before dispatching into consensus.
        // The signing pre-image is the raw block hash bytes (mirrors event_loop.rs).
        // Mirrors the same pattern used in handle_wpoa_view_change.
        {
            let known = self.known_authorities.read();
            let pubkey = match known.get(&voter) {
                Some(pk) => pk.clone(),
                None => {
                    tracing::warn!(
                        %voter,
                        "C-3: WPoA vote from unknown validator — rejecting"
                    );
                    return;
                }
            };
            drop(known); // release read lock before potential peer_scorer lock

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
                    return;
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
                    return;
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
                return;
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
                    return;
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
                    return;
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
                return;
            }
            let peer_id = shell_consensus::ScoringPeerId::from(format!("{voter:?}"));
            let events = round.on_vote(voter, block_hash, sig);
            for event in events {
                match event {
                    WPoaEvent::BlockCommitted {
                        block_hash,
                        quorum_signatures,
                    } => {
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
                            let advanced = self
                                .finality
                                .write()
                                .set_finalized_direct(block_number, block_hash);
                            if advanced {
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
                                if let Err(e) = self.chain_store.set_finalized_number(block_number)
                                {
                                    tracing::warn!(
                                        block_number,
                                        error = %e,
                                        "FF: failed to persist finalized number"
                                    );
                                }
                                // FF.2: Store commit certificate sidecar.
                                match Self::encode_commit_certificate(&quorum_signatures) {
                                    Ok(encoded) => {
                                        if let Err(e) = self
                                            .chain_store
                                            .set_commit_certificate(&block_hash, &encoded)
                                        {
                                            tracing::warn!(
                                                %block_hash,
                                                error = %e,
                                                "FF.2: failed to store commit certificate"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            %block_hash,
                                            error = %e,
                                            "FF.2: failed to encode commit certificate"
                                        );
                                    }
                                }
                            }
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

    fn parse_certificate_signer(raw: &str) -> Option<Address> {
        if let Some(inner) = raw
            .strip_prefix("Address(")
            .and_then(|s| s.strip_suffix(')'))
        {
            inner.parse().ok()
        } else {
            raw.parse().ok()
        }
    }

    fn decode_commit_certificate(
        cert: &[u8],
    ) -> Option<HashMap<Address, shell_crypto::PQSignature>> {
        if let Ok(raw) = serde_json::from_slice::<HashMap<String, shell_crypto::PQSignature>>(cert)
        {
            return Some(
                raw.into_iter()
                    .filter_map(|(addr, sig)| {
                        Self::parse_certificate_signer(&addr).map(|a| (a, sig))
                    })
                    .collect(),
            );
        }

        // Legacy sidecars encoded {Address(...) -> sig_hex} and implicitly used Dilithium3.
        let raw = serde_json::from_slice::<HashMap<String, String>>(cert).ok()?;
        Some(
            raw.into_iter()
                .filter_map(|(addr, sig_hex)| {
                    let addr = Self::parse_certificate_signer(&addr)?;
                    let data = hex::decode(sig_hex).ok()?;
                    Some((
                        addr,
                        shell_crypto::PQSignature::new(
                            shell_crypto::SignatureType::Dilithium3,
                            data,
                        ),
                    ))
                })
                .collect(),
        )
    }

    pub fn fast_finalize_with_certificate(
        &self,
        block_number: u64,
        block_hash: ShellHash,
        cert: &[u8],
    ) -> bool {
        let Some(signatures) = Self::decode_commit_certificate(cert) else {
            warn!(block_number, %block_hash, "FF.7: invalid commit certificate encoding");
            return false;
        };
        let weights = self.consensus.read().validator_weights();
        let total_weight: u64 = weights.values().sum();
        let quorum = (2 * total_weight).div_ceil(3);
        let verifier = MultiVerifier;
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
            match verifier.verify(&pubkey, block_hash.as_bytes(), &sig) {
                Ok(true) => signed_weight += weight,
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

        if let Err(e) = self.chain_store.set_commit_certificate(&block_hash, cert) {
            warn!(block_number, %block_hash, error = %e, "FF.7: failed to persist commit certificate");
            return false;
        }
        let advanced = self
            .finality
            .write()
            .set_finalized_direct(block_number, block_hash);
        if advanced {
            if let Err(e) = self.chain_store.set_finalized_number(block_number) {
                warn!(block_number, %block_hash, error = %e, "FF.7: failed to persist finalized number");
                return false;
            }
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
            .get_head_block()
            .ok()
            .flatten()
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

        let known = self.known_authorities.read();
        let pubkey = known.get(&msg.validator).ok_or_else(|| {
            NodeError::Startup(format!(
                "unknown view-change validator: {:?}",
                msg.validator
            ))
        })?;

        let signing_message = msg.own_signing_message();
        let sig_type = shell_crypto::infer_signature_type_from_address(pubkey, &msg.validator)
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
            .verify(pubkey, &signing_message, &sig)
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
