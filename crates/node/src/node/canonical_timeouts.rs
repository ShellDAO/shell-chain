use super::*;
use shell_consensus::{TimeoutCertificate, WPoaConfig, WPoaEngine};

const TIMEOUT_EXTRA_PREFIX: &[u8] = b"shell:timeout-evidence:v1:";
const PENDING_TIMEOUT_CERTIFICATES: &[u8] = b"meta:pending_timeout_certificates_v1";
const MAX_TIMEOUT_EVIDENCE_BYTES: usize = shell_network::message::MAX_CONSENSUS_MESSAGE_SIZE;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeoutEnvelope {
    view: u64,
    certificates: Vec<TimeoutCertificate>,
}

impl<S: KvStore + 'static> Node<S> {
    /// The active proof commits the actual canonical parent, including genesis.
    /// Never label an unfinalized head as the highest QC.
    pub(crate) fn timeout_vote_qc(&self, height: u64) -> Result<ShellHash, NodeError> {
        if !self.offline_accounting_active(height)? {
            return Ok(*self.finality.read().last_finalized_hash());
        }
        let parent = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        if parent.number().checked_add(1) != Some(height) {
            return Err(NodeError::Startup("stale timeout height".into()));
        }
        if parent.number() > 0 {
            let finality = self.finality.read();
            if finality.last_finalized_number() != parent.number()
                || *finality.last_finalized_hash() != parent.hash()
            {
                return Err(NodeError::Startup(
                    "certified timeout requires finalized parent".into(),
                ));
            }
        }
        Ok(parent.hash())
    }

    /// Idle demand is not an assigned failed proposal. Give newly available
    /// work a fresh window while retaining any already certified view history.
    pub(crate) fn note_idle_proposal_window(
        &self,
        parent_number: u64,
        now_ms: u64,
    ) -> Result<(), NodeError> {
        let height = ChainStateMachine::next_block_number(parent_number)?;
        if self.offline_accounting_active(height)? {
            self.consensus.write().note_proposal_idle(now_ms);
        }
        Ok(())
    }

    pub(crate) fn offline_accounting_active(&self, height: u64) -> Result<bool, NodeError> {
        Ok(self
            .chain_store
            .get_chain_config()?
            .and_then(|config| config.offline_accounting_height)
            .is_some_and(|activation| height >= activation))
    }

    /// Retain the complete current-height sequence, bounded by the existing
    /// consensus-message budget. Failure leaves the previous journal intact.
    pub(crate) fn retain_pending_timeout(
        &self,
        certificate: &TimeoutCertificate,
    ) -> Result<(), NodeError> {
        let first = certificate
            .votes
            .first()
            .ok_or_else(|| NodeError::Startup("empty timeout certificate".into()))?;
        if !self.offline_accounting_active(first.block_number)? {
            return Ok(());
        }
        let mut certificates: Vec<TimeoutCertificate> = self
            .chain_store
            .store()
            .get(PENDING_TIMEOUT_CERTIFICATES)?
            .map(|bytes| {
                if bytes.len() > MAX_TIMEOUT_EVIDENCE_BYTES {
                    return Err(NodeError::Startup(
                        "oversized stored timeout sequence".into(),
                    ));
                }
                serde_json::from_slice(&bytes)
                    .map_err(|error| NodeError::Startup(error.to_string()))
            })
            .transpose()?
            .unwrap_or_default();
        if certificates
            .first()
            .and_then(|certificate| certificate.votes.first())
            .is_some_and(|old| {
                old.block_number != first.block_number
                    || old.highest_qc_hash != first.highest_qc_hash
            })
        {
            certificates.clear();
        }
        if certificates.iter().any(|old| {
            old.votes
                .first()
                .is_some_and(|vote| vote.view == first.view)
        }) {
            self.chain_store.store().flush()?;
            return Ok(());
        }
        if first.view != certificates.len() as u64 {
            return Err(NodeError::Startup(
                "nonsequential pending timeout proof".into(),
            ));
        }
        certificates.push(certificate.clone());
        certificates.sort_by_key(|certificate| certificate.votes.first().map(|vote| vote.view));
        let bytes = serde_json::to_vec(&certificates)
            .map_err(|error| NodeError::Startup(error.to_string()))?;
        let envelope_size = serde_json::to_vec(&TimeoutEnvelope {
            view: certificates.len() as u64,
            certificates,
        })
        .map_err(|error| NodeError::Startup(error.to_string()))?
        .len()
            + TIMEOUT_EXTRA_PREFIX.len();
        if envelope_size > MAX_TIMEOUT_EVIDENCE_BYTES {
            return Err(NodeError::Startup(
                "timeout evidence exceeds consensus message budget".into(),
            ));
        }
        self.chain_store
            .store()
            .put(PENDING_TIMEOUT_CERTIFICATES, &bytes)?;
        self.chain_store.store().flush()?;
        Ok(())
    }

    /// Restore only the verified complete sequence for the current finalized
    /// parent. Stale journals cannot change a new round or canonical state.
    pub(crate) fn restore_pending_timeouts(&self) -> Result<(), NodeError> {
        let Some(parent) = self.chain_store.get_head_block()? else {
            return Ok(());
        };
        let height = ChainStateMachine::next_block_number(parent.number())?;
        if !self.offline_accounting_active(height)? {
            return Ok(());
        }
        let Some(bytes) = self.chain_store.store().get(PENDING_TIMEOUT_CERTIFICATES)? else {
            return Ok(());
        };
        if bytes.len() > MAX_TIMEOUT_EVIDENCE_BYTES {
            return Err(NodeError::Startup(
                "oversized stored timeout sequence".into(),
            ));
        }
        let certificates: Vec<TimeoutCertificate> =
            serde_json::from_slice(&bytes).map_err(|error| {
                NodeError::Startup(format!("invalid stored timeout sequence: {error}"))
            })?;
        let encoded_size = TIMEOUT_EXTRA_PREFIX.len()
            + serde_json::to_vec(
                &serde_json::json!({"view":certificates.len(),"certificates":&certificates}),
            )
            .map_err(|error| NodeError::Startup(error.to_string()))?
            .len();
        if encoded_size > MAX_TIMEOUT_EVIDENCE_BYTES {
            return Err(NodeError::Startup(
                "stored timeout envelope exceeds consensus message budget".into(),
            ));
        }
        let Some(first) = certificates
            .first()
            .and_then(|certificate| certificate.votes.first())
        else {
            return Ok(());
        };
        if first.block_number != height || first.highest_qc_hash != parent.hash() {
            return Ok(());
        }
        let highest_qc = self.timeout_vote_qc(height)?;
        let keys = self.known_authorities.read().clone();
        let mut consensus = self.consensus.write();
        if consensus.engine_type() != EngineType::WPoA {
            return Err(NodeError::Startup(
                "offline accounting requires WPoA".into(),
            ));
        }
        let weights = consensus.validator_weights();
        for (view, certificate) in certificates.iter().enumerate() {
            if !certificate.verify(
                self.config.chain_id,
                height,
                view as u64,
                highest_qc,
                &weights,
                &keys,
                &MultiVerifier,
            ) {
                return Err(NodeError::Startup(
                    "invalid persisted timeout quorum sequence".into(),
                ));
            }
        }
        if consensus.current_view() == certificates.len() as u64 {
            return Ok(());
        }
        if consensus.current_view() != 0 {
            return Err(NodeError::Startup(
                "cannot restore over a different timeout view".into(),
            ));
        }
        consensus.set_strict_timeout_quorum(true);
        let total_weight = weights.values().copied().sum();
        for certificate in certificates {
            let before = consensus.current_view();
            for vote in certificate.votes {
                consensus.handle_view_change_message(vote, total_weight);
            }
            if consensus.current_view() != before + 1 {
                return Err(NodeError::Startup(
                    "persisted timeout view could not be restored".into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn timeout_extra_for_production(&self, height: u64) -> Result<Bytes, NodeError> {
        if !self.offline_accounting_active(height)? {
            return Ok(Bytes::default());
        }
        let view = self.consensus.read().current_view();
        if view == 0 {
            return Ok(Bytes::default());
        }
        let certificates = self
            .chain_store
            .store()
            .get(PENDING_TIMEOUT_CERTIFICATES)?
            .ok_or_else(|| NodeError::Startup("missing certified timeout sequence".into()))?;
        if certificates.len() > MAX_TIMEOUT_EVIDENCE_BYTES {
            return Err(NodeError::Startup(
                "oversized stored timeout sequence".into(),
            ));
        }
        let certificates: Vec<TimeoutCertificate> = serde_json::from_slice(&certificates)
            .map_err(|error| NodeError::Startup(error.to_string()))?;
        let mut bytes = TIMEOUT_EXTRA_PREFIX.to_vec();
        bytes.extend(
            serde_json::to_vec(&TimeoutEnvelope { view, certificates })
                .map_err(|error| NodeError::Startup(error.to_string()))?,
        );
        if bytes.len() > MAX_TIMEOUT_EVIDENCE_BYTES {
            return Err(NodeError::Startup(
                "timeout envelope exceeds consensus message budget".into(),
            ));
        }
        Ok(Bytes::from(bytes))
    }

    /// Resolve identities and effective voting weights at the target block's
    /// epoch, including uncommitted side-branch state. Legacy behavior is kept.
    pub(super) fn authority_context_for_block(
        &self,
        block: &Block,
    ) -> Result<BlockAuthorityContext, NodeError> {
        let mut public_keys = self.known_authorities.read().clone();
        let (weights, context) = if self.offline_accounting_active(block.number())? {
            let context = self.branch_state_store(block)?;
            let (epoch_length, penalties) = {
                let consensus = self.consensus.read();
                (
                    consensus.poa_config().epoch_length,
                    consensus.penalty_state(),
                )
            };
            let (validators, weights) =
                self.epoch_authorities_for_parent(context.clone(), &block.header, epoch_length)?;
            let mut engine = WPoaEngine::new(
                WPoaConfig::with_weights(
                    shell_consensus::PoaConfig::new(
                        validators,
                        self.config.block_time_ms.div_ceil(1000),
                    ),
                    weights,
                ),
                Arc::new(MultiVerifier),
            );
            engine.restore_penalty_state(&penalties);
            (engine.validator_weights(), Some(context))
        } else {
            (self.consensus.read().validator_weights(), None)
        };
        if let Some(store) = context {
            let chain = ChainStore::new(store);
            for address in weights.keys() {
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    public_keys.entry(*address)
                {
                    if let Some(key) = chain.get_pubkey(address)? {
                        entry.insert(key);
                    }
                }
            }
        }
        Ok(BlockAuthorityContext {
            weights,
            public_keys,
        })
    }

    /// Read authorities from the parent's own epoch, following noncanonical
    /// ancestry until its boundary rather than using the live branch's indexes.
    pub(crate) fn epoch_authorities_for_parent<T: KvStore + 'static>(
        &self,
        store: Arc<T>,
        parent: &BlockHeader,
        epoch_length: u64,
    ) -> Result<(Vec<Address>, Vec<u64>), NodeError> {
        let chain = ChainStore::new(store.clone());
        let boundary = authority_reload_height(parent.number, epoch_length);
        // A preferred fork is not published in canonical height indexes yet.
        // Follow its ancestry until the boundary or a shared canonical ancestor.
        let mut boundary_header = parent.clone();
        while boundary_header.number > boundary {
            if chain.get_block_hash_by_number(boundary_header.number)?
                == Some(boundary_header.hash())
            {
                let hash = chain.get_block_hash_by_number(boundary)?.ok_or_else(|| {
                    NodeError::Startup(format!(
                        "authority recovery: canonical epoch boundary #{boundary} is unavailable"
                    ))
                })?;
                boundary_header = chain.get_header_by_hash(&hash)?.ok_or_else(|| {
                    NodeError::Startup(format!(
                        "authority recovery: epoch boundary #{boundary} header is unavailable"
                    ))
                })?;
                if boundary_header.number != boundary || boundary_header.hash() != hash {
                    return Err(NodeError::Startup(
                        format!("authority recovery: epoch boundary #{boundary} header does not match canonical history"),
                    ));
                }
                break;
            }
            let hash = boundary_header.parent_hash;
            let previous = chain
                .get_header_by_hash(&hash)?
                .ok_or_else(|| NodeError::Startup("timeout fork ancestry unavailable".into()))?;
            if previous.hash() != hash
                || previous.number.checked_add(1) != Some(boundary_header.number)
            {
                return Err(NodeError::Startup("timeout fork ancestry mismatch".into()));
            }
            boundary_header = previous;
        }
        let mut roster = WorldState::at_root_with_cache_mb(
            store,
            &boundary_header.state_root,
            self.config.state_cache_size_mb,
        )?;
        roster.validate().map_err(|error| NodeError::Startup(format!("authority recovery: state at epoch boundary #{boundary} is unavailable; restore a snapshot retaining that epoch state: {error}")))?;
        let authorities = if self.offline_accounting_active(boundary_header.number)? {
            roster.get_participating_validators()?
        } else {
            roster.get_validators()?
        };
        if authorities.is_empty() {
            return Err(NodeError::Startup(format!(
                "authority recovery: epoch boundary #{boundary} has an empty Registry"
            )));
        }
        let weights: Vec<u64> = authorities
            .iter()
            .map(|address| roster.get_validator_weight(address))
            .collect::<Result<_, _>>()?;
        Ok((authorities, weights))
    }

    /// Verify the parent branch's complete proof without publishing state.
    pub(crate) fn verify_canonical_timeouts<T: KvStore + 'static>(
        &self,
        store: Arc<T>,
        header: &BlockHeader,
    ) -> Result<Option<(Vec<Address>, u64)>, NodeError> {
        let reserved = header.extra_data.as_ref().starts_with(TIMEOUT_EXTRA_PREFIX);
        if !self.offline_accounting_active(header.number)? {
            // Legacy headers permit opaque extra_data. Do not reinterpret or
            // reject historical bytes merely because a new prefix now exists.
            return Ok(None);
        }
        if self.consensus.read().engine_type() != EngineType::WPoA {
            return Err(NodeError::Startup(
                "offline accounting requires WPoA".into(),
            ));
        }
        let envelope = if reserved {
            if header.extra_data.len() > MAX_TIMEOUT_EVIDENCE_BYTES {
                return Err(NodeError::Startup("oversized timeout envelope".into()));
            }
            serde_json::from_slice::<TimeoutEnvelope>(
                &header.extra_data.as_ref()[TIMEOUT_EXTRA_PREFIX.len()..],
            )
            .map_err(|error| NodeError::Startup(format!("invalid timeout envelope: {error}")))?
        } else {
            TimeoutEnvelope {
                view: 0,
                certificates: Vec::new(),
            }
        };
        if u64::try_from(envelope.certificates.len()).ok() != Some(envelope.view)
            || (reserved && envelope.view == 0)
        {
            return Err(NodeError::Startup(
                "incomplete or noncanonical timeout sequence".into(),
            ));
        }
        let chain = ChainStore::new(store.clone());
        let parent = chain
            .get_header_by_hash(&header.parent_hash)?
            .ok_or_else(|| NodeError::Startup("timeout canonical parent unavailable".into()))?;
        if parent.hash() != header.parent_hash
            || parent.number.checked_add(1) != Some(header.number)
        {
            return Err(NodeError::Startup(
                "timeout parent identity mismatch".into(),
            ));
        }
        let (epoch_length, penalties) = {
            let consensus = self.consensus.read();
            (
                consensus.poa_config().epoch_length,
                consensus.penalty_state(),
            )
        };
        let (authorities, weights) =
            self.epoch_authorities_for_parent(store, &parent, epoch_length)?;
        let mut engine = WPoaEngine::new(
            WPoaConfig::with_weights(
                shell_consensus::PoaConfig::new(
                    authorities,
                    self.config.block_time_ms.div_ceil(1000),
                ),
                weights,
            ),
            Arc::new(MultiVerifier),
        );
        // Compose accounting with the existing absolute voting penalties.
        // Registered scheduling weights and economic state remain unchanged.
        engine.restore_penalty_state(&penalties);
        if engine.proposer_for_block_in_view(header.number, envelope.view) != header.proposer {
            return Err(NodeError::Startup(
                "timeout envelope proposer mismatch".into(),
            ));
        }
        let weights = engine.validator_weights();
        let mut public_keys = self.known_authorities.read().clone();
        for address in weights.keys() {
            if let std::collections::hash_map::Entry::Vacant(entry) = public_keys.entry(*address) {
                if let Some(key) = chain.get_pubkey(address)? {
                    entry.insert(key);
                }
            }
        }
        let highest_qc = parent.hash();
        let elapsed_ms = u128::from(header.timestamp.saturating_sub(parent.timestamp)) * 1000;
        let required_ms = u128::from(envelope.view)
            * u128::from(self.config.block_time_ms.max(VIEW_CHANGE_TIMEOUT_MS));
        if elapsed_ms < required_ms {
            return Err(NodeError::Startup(
                "timeout certificate sequence predates protocol delay".into(),
            ));
        }
        for (view, certificate) in envelope.certificates.iter().enumerate() {
            if !certificate.verify(
                self.config.chain_id,
                header.number,
                view as u64,
                highest_qc,
                &weights,
                &public_keys,
                &MultiVerifier,
            ) {
                return Err(NodeError::Startup(
                    "invalid parent-bound timeout quorum certificate".into(),
                ));
            }
        }
        let missed = (0..envelope.view)
            .map(|view| engine.proposer_for_block_in_view(header.number, view))
            .collect();
        Ok(Some((missed, epoch_length)))
    }

    /// The caller supplies a private execution overlay; failed import or
    /// production discards all counter and availability changes.
    pub(crate) fn apply_canonical_timeouts<T: KvStore + 'static>(
        &self,
        state: &mut WorldState<T>,
        header: &BlockHeader,
    ) -> Result<(), NodeError> {
        let Some((missed, epoch_length)) =
            self.verify_canonical_timeouts(state.store().clone(), header)?
        else {
            return Ok(());
        };
        for address in missed {
            state.record_validator_assigned_miss(&address)?;
        }
        state.set_validator_assigned_misses(&header.proposer, 0)?;
        if epoch_length == 0 || header.number.is_multiple_of(epoch_length) {
            state.apply_validator_offline_epoch()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::DilithiumSigner;
    use shell_storage::MemoryDb;

    fn setup(keys: &[DilithiumSigner], activation: Option<u64>) -> Node<MemoryDb> {
        setup_weighted(keys, activation, vec![3, 1])
    }

    fn setup_weighted(
        keys: &[DilithiumSigner],
        activation: Option<u64>,
        weights: Vec<u64>,
    ) -> Node<MemoryDb> {
        setup_store(Arc::new(MemoryDb::new()), keys, activation, weights)
    }

    fn setup_store<S: KvStore + 'static>(
        store: Arc<S>,
        keys: &[DilithiumSigner],
        activation: Option<u64>,
        weights: Vec<u64>,
    ) -> Node<S> {
        let mut node = super::super::timeout_evidence::tests::node(store, keys, weights.clone());
        node.consensus.write().poa_config_mut().epoch_length = 5;
        if let crate::config::ConsensusEngineConfig::WPoa(config) = &mut node.config.consensus {
            config.poa.epoch_length = 5;
        }
        let validators = keys
            .iter()
            .map(|key| Address::from_public_key(key.public_key(), key.sig_type().as_u8()))
            .collect::<Vec<_>>();
        let root = {
            let mut state = node.world_state.write();
            state.set_validators(&validators).unwrap();
            state.set_validator_weights(&validators, &weights).unwrap();
            for (address, key) in validators.iter().zip(keys) {
                node.chain_store
                    .put_pubkey(address, key.public_key())
                    .unwrap();
                state
                    .set_account(
                        address,
                        &shell_core::Account::new_user_account(
                            shell_primitives::blake3_hash(key.public_key()),
                            U256::from(10u128.pow(22)),
                        ),
                    )
                    .unwrap();
                state.set_validator_stake(address, U256::from(123)).unwrap();
            }
            state.state_root().unwrap()
        };
        let genesis = Block {
            header: BlockHeader {
                state_root: root,
                gas_limit: 30_000_000,
                timestamp: 1_700_000_000,
                proposer: validators[0],
                ..BlockHeader::default()
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        node.chain_store.put_block(&genesis).unwrap();
        node.chain_store.set_canonical(0, &genesis.hash()).unwrap();
        node.chain_store.set_head(&genesis.hash()).unwrap();
        node.chain_store.put_chain_config(&serde_json::from_value(serde_json::json!({
            "chain_id":1337,"genesis_hash":genesis.hash(),"offline_accounting_height":activation
        })).unwrap()).unwrap();
        node
    }

    fn advance<S: KvStore + 'static>(node: &Node<S>, key: &dyn Signer, height: u64, view: u64) {
        let qc = *node.finality.read().last_finalized_hash();
        let signature = key
            .sign(&ViewChangeMessage::signing_message(1337, height, view, &qc))
            .unwrap();
        let message = ViewChangeMessage::new(
            1337,
            height,
            view,
            qc,
            Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
            signature.data,
        );
        assert!(node
            .handle_wpoa_view_change(message, &MultiVerifier)
            .unwrap());
    }

    fn attest<S: KvStore + 'static>(node: &Node<S>, key: &dyn Signer, block: &Block, view: u64) {
        let signature = key
            .sign(&Attestation::signing_message(
                1337,
                &block.header.parent_hash,
                &block.hash(),
                block.number(),
                view,
            ))
            .unwrap();
        node.handle_attestation(
            Attestation::new(
                1337,
                block.header.parent_hash,
                block.hash(),
                block.number(),
                Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
                view,
                signature.data,
            ),
            &MultiVerifier,
        )
        .unwrap();
    }

    fn finalize<S: KvStore + 'static>(node: &Node<S>, key: &dyn Signer, block: &Block, view: u64) {
        attest(node, key, block, view);
        assert_eq!(node.finality.read().last_finalized_number(), block.number());
        // Match the real event loop's post-block transient view/clock hook.
        node.consensus.write().note_block_progress(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
    }

    fn produce<S: KvStore + 'static>(node: &Node<S>, key: &dyn Signer) -> Block {
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        // Bounded deterministic source execution: no wall-clock timeout claim.
        node.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 30);
        node.produce_block(key, 0).unwrap()
    }

    #[test]
    fn canonical_timeouts_production_import_commit_100_assigned_misses() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        lifecycle(
            setup(&keys, Some(0)),
            setup(&keys, Some(0)),
            &keys,
            &mut |_, _| {},
        );
    }

    fn lifecycle<S: KvStore + 'static>(
        mut leader: Node<S>,
        follower: Node<S>,
        keys: &[DilithiumSigner],
        checkpoint: &mut dyn FnMut(&Node<S>, u64),
    ) {
        let absent = Address::from_public_key(keys[1].public_key(), keys[1].sig_type().as_u8());
        let initial_balance = leader.world_state.read().get_balance(&absent).unwrap();
        let mut historical = None;
        for height in 1..=400 {
            let view = u64::from(height % 4 == 3);
            if view == 1 {
                advance(&leader, &keys[0], height, 0);
                // Receiver has not observed transient timeout votes.
            }
            let block = produce(&leader, &keys[0]);
            if height == 3 {
                let snapshot = follower.store.scan_prefix(b"").unwrap();
                for duplicate in [false, true] {
                    let mut invalid = block.clone();
                    let mut envelope: TimeoutEnvelope = serde_json::from_slice(
                        &invalid.header.extra_data.as_ref()[TIMEOUT_EXTRA_PREFIX.len()..],
                    )
                    .unwrap();
                    if duplicate {
                        let vote = envelope.certificates[0].votes[0].clone();
                        envelope.certificates[0].votes.push(vote);
                    } else {
                        envelope.certificates[0].votes[0].signature[0] ^= 1;
                    }
                    let mut bytes = TIMEOUT_EXTRA_PREFIX.to_vec();
                    bytes.extend(serde_json::to_vec(&envelope).unwrap());
                    invalid.header.extra_data = Bytes::from(bytes);
                    leader
                        .consensus
                        .read()
                        .sign_block(&mut invalid, &keys[0])
                        .unwrap();
                    assert!(follower.import_block(invalid, &MultiVerifier).is_err());
                    assert_eq!(
                        follower.store.scan_prefix(b"").unwrap(),
                        snapshot,
                        "invalid proof must not leak trie/metadata changes"
                    );
                }
                historical = Some(block.header.state_root);
            }
            follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            finalize(&leader, &keys[0], &block, view);
            finalize(&follower, &keys[0], &block, view);
            let expected = (height + 1) / 4;
            assert_eq!(
                leader
                    .world_state
                    .read()
                    .get_validator_assigned_misses(&absent)
                    .unwrap(),
                expected
            );
            assert_eq!(
                follower
                    .world_state
                    .read()
                    .get_validator_assigned_misses(&absent)
                    .unwrap(),
                expected
            );
            assert_eq!(
                leader.world_state.write().state_root().unwrap(),
                follower.world_state.write().state_root().unwrap()
            );
            if height == 399 || height == 400 {
                checkpoint(&leader, height);
            }
        }
        assert!(
            !leader
                .consensus
                .read()
                .validator_weights()
                .contains_key(&absent),
            "100 assigned misses must suspend effective participation at common boundary400"
        );
        let snapshot = leader.store.scan_prefix(b"").unwrap();
        let history = WorldState::at_root(leader.store.clone(), &historical.unwrap()).unwrap();
        assert_eq!(history.get_validator_assigned_misses(&absent).unwrap(), 1);
        assert_eq!(leader.store.scan_prefix(b"").unwrap(), snapshot);
        let suspended_root = leader.world_state.write().state_root().unwrap();
        for node in [&leader, &follower] {
            let state = node.world_state.read();
            assert_eq!(state.get_validator_offline_flags(&absent).unwrap(), 2);
            assert_eq!(
                state.get_validator_suspension_generation(&absent).unwrap(),
                1
            );
            assert_eq!(state.get_validator_stake(&absent).unwrap(), U256::from(123));
            assert_eq!(state.get_balance(&absent).unwrap(), initial_balance);
            assert_eq!(state.get_validator_weight(&absent).unwrap(), 1);
            assert!(state.get_validators().unwrap().contains(&absent));
            assert!(!node
                .consensus
                .read()
                .validator_weights()
                .contains_key(&absent));
        }
        // A suspended registered validator retains its existing governance vote,
        // but weight1 cannot authorize recovery against total registered weight4.
        for height in 401..=407 {
            if height == 401 || height == 402 {
                let voter = if height == 401 { &keys[1] } else { &keys[0] };
                let sender = Address::from_public_key(voter.public_key(), voter.sig_type().as_u8());
                super::super::tests::submit_signed_tx(
                    &leader,
                    voter,
                    sender,
                    shell_core::Transaction {
                        chain_id: 1337,
                        nonce: 0,
                        to: Some(shell_pqvm::registry_address()),
                        value: U256::ZERO,
                        data: Bytes::from(
                            shell_pqvm::system_contracts::encode_recover_offline_validator_calldata(
                                &absent, 1,
                            ),
                        ),
                        gas_limit: 100_000,
                        max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                        max_priority_fee_per_gas: 0,
                        access_list: None,
                        tx_type: 2,
                        max_fee_per_blob_gas: None,
                        blob_versioned_hashes: None,
                    },
                );
            }
            let voter = if height == 407 { &keys[1] } else { &keys[0] };
            // Weighted schedule A,A,A,B repeats after recovery at405.
            let proposer = Address::from_public_key(voter.public_key(), voter.sig_type().as_u8());
            let parent = leader.chain_store.get_head_block().unwrap().unwrap();
            leader.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 30);
            leader.config.proposer_address = Some(proposer);
            let block = leader.produce_block(voter, 100).unwrap();
            follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            finalize(&leader, &keys[0], &block, 0);
            finalize(&follower, &keys[0], &block, 0);
            if height <= 402 {
                assert_eq!(block.transactions.len(), 1);
                let receipts = leader
                    .chain_store
                    .get_receipts(&block.hash())
                    .unwrap()
                    .unwrap();
                assert_eq!(receipts[0].status, 1);
            }
            let flags = if height == 401 {
                2
            } else if height < 405 {
                6
            } else {
                0
            };
            for node in [&leader, &follower] {
                let state = node.world_state.read();
                assert_eq!(state.get_validator_offline_flags(&absent).unwrap(), flags);
                assert_eq!(
                    state.get_validator_assigned_misses(&absent).unwrap(),
                    if height < 405 { 100 } else { 0 }
                );
                assert_eq!(
                    node.consensus
                        .read()
                        .validator_weights()
                        .contains_key(&absent),
                    height >= 405
                );
            }
            assert_eq!(
                leader.world_state.write().state_root().unwrap(),
                follower.world_state.write().state_root().unwrap()
            );
            if [402, 405, 407].contains(&height) {
                checkpoint(&leader, height);
            }
        }
        let before_history = leader.store.scan_prefix(b"").unwrap();
        let old = WorldState::at_root(leader.store.clone(), &suspended_root).unwrap();
        assert_eq!(old.get_validator_assigned_misses(&absent).unwrap(), 100);
        assert_eq!(old.get_validator_offline_flags(&absent).unwrap(), 2);
        assert_eq!(leader.store.scan_prefix(b"").unwrap(), before_history);
        println!("400 imported/finalized blocks prove100 assigned misses and epoch suspension without balance/stake/weight loss; real signed1/4 governance vote cannot recover, quorum recovers at405, historical suspension remains.");
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn canonical_timeouts_physical_lifecycle_and_trusted_snapshot_recovery() {
        const DIRECTORY: &str = "SHELL_TEST_OFFLINE_LIFECYCLE_DIRECTORY";
        if let Some(directory) = std::env::var_os(DIRECTORY) {
            let directory = std::path::PathBuf::from(directory);
            let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
            let leader_db =
                shell_storage::RocksDbStore::open_all(directory.join("leader"), None).unwrap();
            let follower_db =
                shell_storage::RocksDbStore::open_all(directory.join("follower"), None).unwrap();
            let leader = setup_store(Arc::new(leader_db.state), &keys, Some(0), vec![3, 1]);
            let follower = setup_store(Arc::new(follower_db.state), &keys, Some(0), vec![3, 1]);
            // A separate local trust anchor is established at genesis, before
            // any exported snapshot; it is never read from snapshot metadata.
            let trusted = leader.chain_store.get_chain_config().unwrap().unwrap();
            std::fs::write(
                directory.join("trusted-config.json"),
                serde_json::to_vec(&trusted).unwrap(),
            )
            .unwrap();
            lifecycle(leader, follower, &keys, &mut |node, height| {
                let head = node.chain_store.get_head_block().unwrap().unwrap();
                let file =
                    std::fs::File::create(directory.join(format!("state-{height}.jsonl"))).unwrap();
                node.chain_store
                    .export_snapshot(
                        shell_storage::SnapshotMetadata::new(
                            1337,
                            height,
                            head.hash(),
                            head.header.state_root,
                            trusted.genesis_hash,
                        ),
                        file,
                    )
                    .unwrap();
            });
            // Fresh parent process must reopen actual WAL data, not this handle.
            std::process::exit(0);
        }
        let directory = if let Some(directory) =
            std::env::var_os("SHELL_TEST_OFFLINE_LIFECYCLE_REUSE")
        {
            std::path::PathBuf::from(directory)
        } else {
            let directory = std::env::temp_dir().join(format!(
                "shell-offline-lifecycle-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&directory).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","node::canonical_timeouts::tests::canonical_timeouts_physical_lifecycle_and_trusted_snapshot_recovery","--nocapture"])
                .env(DIRECTORY,&directory).status().unwrap();
            assert!(status.success());
            directory
        };
        let run_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let trusted: shell_storage::ChainConfig =
            serde_json::from_slice(&std::fs::read(directory.join("trusted-config.json")).unwrap())
                .unwrap();
        let check = |store: Arc<shell_storage::RocksDbStore>, height: u64| {
            let chain = ChainStore::new(store.clone());
            let head = chain.get_head_block().unwrap().unwrap();
            let snapshot = WorldState::at_root(store.clone(), &head.header.state_root).unwrap();
            let validators = snapshot.get_validators().unwrap();
            let absent = validators[1];
            let mut config = NodeConfig::dev(validators[0]);
            if let crate::config::ConsensusEngineConfig::WPoa(c) = &mut config.consensus {
                c.poa.epoch_length = 5;
            }
            let before = store.scan_prefix(b"").unwrap();
            let (node, _) = crate::NodeBuilder::new(config, store.clone())
                .build()
                .unwrap();
            for address in &validators {
                node.register_authority_pubkey(
                    *address,
                    chain.get_pubkey(address).unwrap().unwrap(),
                );
            }
            node.restore_pending_timeouts().unwrap();
            assert_eq!(head.number(), height);
            assert_eq!(node.finality.read().last_finalized_number(), height);
            assert_eq!(node.finality.read().last_finalized_hash(), &head.hash());
            let expected_flags = match height {
                399 => 1,
                400 => 2,
                402 => 6,
                405 | 407 => 0,
                _ => panic!("unexpected checkpoint"),
            };
            let state = node.world_state.read();
            assert_eq!(
                state.get_validator_offline_flags(&absent).unwrap(),
                expected_flags
            );
            assert_eq!(
                state.get_validator_assigned_misses(&absent).unwrap(),
                if height < 405 { 100 } else { 0 }
            );
            assert_eq!(
                state.get_validator_suspension_generation(&absent).unwrap(),
                1
            );
            assert_eq!(state.get_validator_weight(&absent).unwrap(), 1);
            assert_eq!(state.get_validator_stake(&absent).unwrap(), U256::from(123));
            assert_eq!(
                node.consensus
                    .read()
                    .validator_weights()
                    .contains_key(&absent),
                height == 399 || height >= 405
            );
            if height >= 400 {
                let old = chain.get_block_by_number(400).unwrap().unwrap();
                let history = WorldState::at_root(store.clone(), &old.header.state_root).unwrap();
                assert_eq!(history.get_validator_assigned_misses(&absent).unwrap(), 100);
                assert_eq!(history.get_validator_offline_flags(&absent).unwrap(), 2);
            }
            assert_eq!(
                store.scan_prefix(b"").unwrap(),
                before,
                "startup/history must not rewrite the persisted business state"
            );
        };
        let reopened =
            shell_storage::RocksDbStore::open_all(directory.join("leader"), None).unwrap();
        let source_store = Arc::new(reopened.state);
        check(source_store.clone(), 407);
        for height in [399, 400, 402, 405, 407] {
            let bytes = std::fs::read(directory.join(format!("state-{height}.jsonl"))).unwrap();
            let rejected = Arc::new(MemoryDb::new());
            let mut wrong = trusted.clone();
            wrong.offline_accounting_height = None;
            assert!(ChainStore::new(rejected.clone())
                .import_snapshot_with_config(std::io::Cursor::new(&bytes), &wrong)
                .is_err());
            assert!(rejected.scan_prefix(b"").unwrap().is_empty());
            let destination = shell_storage::RocksDbStore::open_all(
                directory.join(format!("restored-{height}-{run_id}")),
                None,
            )
            .unwrap();
            let store = Arc::new(destination.state);
            ChainStore::new(store.clone())
                .import_snapshot_with_config(std::io::Cursor::new(bytes), &trusted)
                .unwrap();
            check(store, height);
        }
        // A syncing replica may receive valid signed blocks before their
        // finality attestations. Recovering its unfinalized epoch suffix must
        // undo both the state transition and the effective authority change.
        let destination = shell_storage::RocksDbStore::open_all(
            directory.join(format!("rollback-{run_id}")),
            None,
        )
        .unwrap();
        let store = Arc::new(destination.state);
        let chain = Arc::new(ChainStore::new(store.clone()));
        chain
            .import_snapshot_with_config(
                std::io::Cursor::new(std::fs::read(directory.join("state-402.jsonl")).unwrap()),
                &trusted,
            )
            .unwrap();
        let header = chain.get_head_block().unwrap().unwrap().header;
        let state = WorldState::at_root(store.clone(), &header.state_root).unwrap();
        let validators = state.get_validators().unwrap();
        let absent = validators[1];
        let mut config = NodeConfig::dev(validators[0]);
        if let crate::config::ConsensusEngineConfig::WPoa(c) = &mut config.consensus {
            c.poa.epoch_length = 5;
        }
        let build = || {
            let (node, _) = crate::NodeBuilder::new(config.clone(), store.clone())
                .build()
                .unwrap();
            for address in &validators {
                node.register_authority_pubkey(
                    *address,
                    chain.get_pubkey(address).unwrap().unwrap(),
                );
            }
            node
        };
        {
            let node = build();
            let source = ChainStore::new(source_store.clone());
            for height in 403..=405 {
                node.import_block(
                    source.get_block_by_number(height).unwrap().unwrap(),
                    &MultiVerifier,
                )
                .unwrap();
            }
            assert_eq!(node.finality.read().last_finalized_number(), 402);
            assert!(node
                .consensus
                .read()
                .validator_weights()
                .contains_key(&absent));
        }
        // Missing epoch trie state is injected only into a disposable overlay;
        // the physical fixture remains intact and rollback must not partially commit.
        let epoch = chain.get_block_by_number(400).unwrap().unwrap();
        let faulty = Arc::new(OverlayStore::new(store.clone()));
        faulty.delete(epoch.header.state_root.as_bytes()).unwrap();
        let (blocked, _) = crate::NodeBuilder::new(config.clone(), faulty.clone())
            .build()
            .unwrap();
        let checkpoint = faulty.scan_prefix(b"").unwrap();
        assert!(blocked.recover_unfinalized_head().is_err());
        assert_eq!(faulty.scan_prefix(b"").unwrap(), checkpoint);
        assert_eq!(
            ChainStore::new(faulty)
                .get_head_block()
                .unwrap()
                .unwrap()
                .number(),
            405
        );
        assert!(blocked
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));

        let restarted = build();
        let penalties = shell_consensus::PenaltyState {
            slashed: vec![absent],
            reductions: vec![(absent, 1)],
        };
        restarted
            .consensus
            .write()
            .restore_penalty_state(&penalties);
        assert_eq!(restarted.recover_unfinalized_head().unwrap(), 3);
        assert_eq!(
            restarted.consensus.read().penalty_state(),
            penalties,
            "authority recovery must retain unrelated absolute challenge penalties"
        );
        assert_eq!(chain.get_head_block().unwrap().unwrap().number(), 402);
        assert_eq!(
            restarted
                .world_state
                .read()
                .get_validator_offline_flags(&absent)
                .unwrap(),
            6
        );
        assert!(!restarted.consensus.read().validator_weights().contains_key(&absent),
            "rewinding an unfinalized recovery boundary must restore the last finalized epoch roster");
    }

    #[test]
    fn canonical_timeouts_preferred_recovery_fork_restores_branch_epoch_roster() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let leader = setup(&keys, Some(0));
        let absent = Address::from_public_key(keys[1].public_key(), keys[1].sig_type().as_u8());
        for height in 1..=399 {
            let view = u64::from(height % 4 == 3);
            if view == 1 {
                advance(&leader, &keys[0], height, 0);
            }
            let block = produce(&leader, &keys[0]);
            finalize(&leader, &keys[0], &block, view);
        }
        assert_eq!(
            leader
                .world_state
                .read()
                .get_validator_assigned_misses(&absent)
                .unwrap(),
            100
        );
        let head = leader.chain_store.get_head_block().unwrap().unwrap();
        let trusted = leader.chain_store.get_chain_config().unwrap().unwrap();
        let mut snapshot = Vec::new();
        leader
            .chain_store
            .export_snapshot(
                shell_storage::SnapshotMetadata::new(
                    1337,
                    399,
                    head.hash(),
                    head.header.state_root,
                    trusted.genesis_hash,
                ),
                &mut snapshot,
            )
            .unwrap();
        let restore = || {
            let store = Arc::new(MemoryDb::new());
            ChainStore::new(store.clone())
                .import_snapshot_with_config(std::io::Cursor::new(&snapshot), &trusted)
                .unwrap();
            let (node, _) = crate::NodeBuilder::new(leader.config.clone(), store)
                .build()
                .unwrap();
            for key in &keys {
                node.register_authority_pubkey(
                    Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
                    key.public_key().to_vec(),
                );
            }
            node
        };
        let receiver = restore();
        let mut fork = restore();
        let canonical = produce(&leader, &keys[0]);
        receiver
            .import_block(canonical.clone(), &MultiVerifier)
            .unwrap();
        assert!(!receiver
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));
        assert_eq!(receiver.finality.read().last_finalized_number(), 399);

        let sender = Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8());
        super::super::tests::submit_signed_tx(
            &fork,
            &keys[0],
            sender,
            shell_core::Transaction {
                chain_id: 1337,
                nonce: 0,
                to: Some(shell_pqvm::registry_address()),
                value: U256::ZERO,
                data: Bytes::from(
                    shell_pqvm::system_contracts::encode_recover_offline_validator_calldata(
                        &absent, 1,
                    ),
                ),
                gas_limit: 100_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
        );
        super::super::tests::submit_signed_tx(
            &fork,
            &keys[0],
            sender,
            shell_core::Transaction {
                chain_id: 1337,
                nonce: 1,
                to: Some(shell_pqvm::registry_address()),
                value: U256::ZERO,
                data: Bytes::from(shell_pqvm::encode_set_validator_weight_calldata(&sender, 2)),
                gas_limit: 100_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
        );
        advance(&fork, &keys[0], 400, 0);
        fork.config.proposer_address = Some(absent);
        fork.dev_state.write().next_block_timestamp = Some(head.header.timestamp + 30);
        let side400 = fork.produce_block(&keys[1], 100).unwrap();
        attest(&fork, &keys[0], &side400, 1);
        finalize(&fork, &keys[1], &side400, 1);
        assert_eq!(
            fork.world_state
                .read()
                .get_validator_offline_flags(&absent)
                .unwrap(),
            0
        );
        // The weight update changes the new epoch schedule to A,A,B.
        fork.config.proposer_address = Some(absent);
        let side401 = produce(&fork, &keys[1]);
        attest(&fork, &keys[0], &side401, 0);
        finalize(&fork, &keys[1], &side401, 0);
        for duplicate in [false, true] {
            let mut invalid = side400.clone();
            let mut envelope: TimeoutEnvelope = serde_json::from_slice(
                &invalid.header.extra_data.as_ref()[TIMEOUT_EXTRA_PREFIX.len()..],
            )
            .unwrap();
            if duplicate {
                let vote = envelope.certificates[0].votes[0].clone();
                envelope.certificates[0].votes.push(vote);
            } else {
                envelope.certificates[0].votes[0].signature[0] ^= 1;
            }
            let mut bytes = TIMEOUT_EXTRA_PREFIX.to_vec();
            bytes.extend(serde_json::to_vec(&envelope).unwrap());
            invalid.header.extra_data = Bytes::from(bytes);
            invalid.proposer_seal = Some(keys[1].sign(invalid.header.hash().as_bytes()).unwrap());
            let before = receiver.store.scan_prefix(b"").unwrap();
            assert!(receiver.import_block(invalid, &MultiVerifier).is_err());
            assert_eq!(
                receiver.store.scan_prefix(b"").unwrap(),
                before,
                "invalid side proof must not publish metadata"
            );
        }
        receiver
            .import_block(side400.clone(), &MultiVerifier)
            .unwrap();
        receiver
            .import_block(side401.clone(), &MultiVerifier)
            .unwrap();
        let mut signatures = HashMap::new();
        signatures.insert(sender, keys[0].sign(side401.hash().as_bytes()).unwrap());
        let partial = Node::<MemoryDb>::encode_commit_certificate(&signatures).unwrap();
        assert!(
            !receiver.verify_commit_certificate(401, side401.hash(), &partial),
            "A2 certificate is exactly2/3"
        );
        signatures.insert(absent, keys[1].sign(side401.hash().as_bytes()).unwrap());
        let certificate = Node::<MemoryDb>::encode_commit_certificate(&signatures).unwrap();
        assert!(receiver.verify_commit_certificate(401, side401.hash(), &certificate));
        let certified = restore();
        for block in [&canonical, &side400, &side401] {
            certified
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
        }
        let before = certified.store.scan_prefix(b"").unwrap();
        assert!(certified
            .adopt_certified_fork(401, side401.hash(), &partial)
            .unwrap()
            .is_none());
        assert_eq!(certified.store.scan_prefix(b"").unwrap(), before);
        assert!(certified
            .adopt_certified_fork(401, side401.hash(), &certificate)
            .unwrap()
            .is_some());
        assert!(certified.fast_finalize_with_certificate(401, side401.hash(), &certificate));
        assert_eq!(certified.finality.read().last_finalized_number(), 401);
        assert_eq!(
            certified.consensus.read().validator_weights().get(&sender),
            Some(&2)
        );
        assert!(certified
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));
        let attestation = Attestation::new(
            1337,
            side401.header.parent_hash,
            side401.hash(),
            401,
            sender,
            0,
            keys[0]
                .sign(&Attestation::signing_message(
                    1337,
                    &side401.header.parent_hash,
                    &side401.hash(),
                    401,
                    0,
                ))
                .unwrap()
                .data,
        );
        receiver
            .handle_attestation(attestation, &MultiVerifier)
            .unwrap();
        assert_eq!(receiver.finality.read().attested_weight(&side401.hash()),2,
            "attestation weight must come from the proposed branch epoch, not live canonical weight3");
        assert!(
            receiver.preferred_fork_plan().unwrap().is_none(),
            "A2 is exactly2/3 of the recovery branch and cannot authorize adoption alone"
        );
        attest(&receiver, &keys[1], &side401, 0);
        let plan = receiver
            .preferred_fork_plan()
            .unwrap()
            .expect("genuine quorum must prefer recovery branch");
        receiver.adopt_preferred_fork(&plan).unwrap();
        assert_eq!(
            receiver.chain_store.get_head_hash().unwrap(),
            Some(side401.hash())
        );
        assert_eq!(
            receiver.chain_store.get_block_hash_by_number(400).unwrap(),
            Some(side400.hash())
        );
        assert_eq!(receiver.finality.read().last_finalized_number(), 401);
        assert_eq!(
            receiver.world_state.write().state_root().unwrap(),
            fork.world_state.write().state_root().unwrap()
        );
        assert!(receiver.consensus.read().validator_weights().contains_key(&absent),
            "preferred branch recovery at400 must restore B even though live canonical400 suspended it");
        assert_eq!(
            receiver
                .world_state
                .read()
                .get_validator_assigned_misses(&absent)
                .unwrap(),
            0
        );
        assert_eq!(
            receiver.consensus.read().validator_weights().get(&sender),
            Some(&2)
        );
        assert_eq!(receiver.world_state.read().get_nonce(&sender).unwrap(), 2);
        let receipts = receiver
            .chain_store
            .get_receipts(&side400.hash())
            .unwrap()
            .unwrap();
        assert_eq!(side400.transactions.len(), 2);
        assert_eq!(
            receipts.len(),
            side400.transactions.len() + side400.system_transactions.len()
        );
        assert!(receipts.iter().all(|receipt| receipt.status == 1));

        let old =
            WorldState::at_root(receiver.store.clone(), &canonical.header.state_root).unwrap();
        assert_eq!(old.get_validator_offline_flags(&absent).unwrap(), 2);
        assert_eq!(old.get_validator_assigned_misses(&absent).unwrap(), 100);
        for height in 402..=404 {
            let key = if height == 404 { &keys[1] } else { &keys[0] };
            fork.config.proposer_address = Some(Address::from_public_key(
                key.public_key(),
                key.sig_type().as_u8(),
            ));
            let block = produce(&fork, key);
            receiver
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            attest(&fork, &keys[0], &block, 0);
            finalize(&fork, &keys[1], &block, 0);
            attest(&receiver, &keys[0], &block, 0);
            finalize(&receiver, &keys[1], &block, 0);
            assert_eq!(
                receiver.world_state.write().state_root().unwrap(),
                fork.world_state.write().state_root().unwrap()
            );
        }
    }

    #[test]
    fn canonical_timeouts_preserve_existing_sanctioned_proposer_and_quorum_basis() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let absent = Address::from_public_key(keys[1].public_key(), keys[1].sig_type().as_u8());
        for activation in [None, Some(0)] {
            let leader = setup_weighted(&keys, activation, vec![2, 1]);
            let receiver = setup_weighted(&keys, activation, vec![2, 1]);
            let penalties = shell_consensus::PenaltyState {
                slashed: vec![absent],
                reductions: vec![(absent, 1)],
            };
            for node in [&leader, &receiver] {
                node.consensus.write().restore_penalty_state(&penalties);
            }
            let first = produce(&leader, &keys[0]);
            receiver
                .import_block(first.clone(), &MultiVerifier)
                .unwrap();
            finalize(&leader, &keys[0], &first, 0);
            finalize(&receiver, &keys[0], &first, 0);
            // Existing WPoA assigns B at2 using registered scheduling weights,
            // while the existing absolute sanction reduces its voting weight0.
            // A's genuine weight2 vote is all effective weight, not just2/3.
            advance(&leader, &keys[0], 2, 0);
            if activation.is_none() {
                advance(&receiver, &keys[0], 2, 0);
            }
            let block = produce(&leader, &keys[0]);
            receiver
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            finalize(&leader, &keys[0], &block, 1);
            finalize(&receiver, &keys[0], &block, 1);
            for node in [&leader, &receiver] {
                assert_eq!(
                    node.world_state
                        .read()
                        .get_validator_assigned_misses(&absent)
                        .unwrap(),
                    u64::from(activation.is_some())
                );
                assert_eq!(
                    node.world_state
                        .read()
                        .get_validator_weight(&absent)
                        .unwrap(),
                    1
                );
                assert_eq!(
                    node.consensus.read().validator_weights().get(&absent),
                    Some(&0)
                );
                assert_eq!(node.consensus.read().penalty_state(), penalties);
            }
            assert_eq!(
                leader.world_state.write().state_root().unwrap(),
                receiver.world_state.write().state_root().unwrap()
            );
        }
    }

    #[test]
    fn canonical_timeouts_finalized_certificate_survives_later_penalty() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let leader = setup_weighted(&keys, Some(0), vec![3, 1]);
        leader.consensus.write().poa_config_mut().slash_weight_bps = 5000;
        let authority = Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8());
        let first = produce(&leader, &keys[0]);
        let signed = Node::<MemoryDb>::encode_commit_certificate(&HashMap::from([(
            authority,
            keys[0].sign(first.hash().as_bytes()).unwrap(),
        )]))
        .unwrap();
        assert!(leader.fast_finalize_with_certificate(first.number(), first.hash(), &signed));
        let certificate = leader
            .chain_store
            .get_commit_certificate(&first.hash())
            .unwrap()
            .unwrap();
        assert!(leader.verify_commit_certificate(first.number(), first.hash(), &certificate));
        let finalized = {
            let state = leader.finality.read();
            (state.last_finalized_number(), *state.last_finalized_hash())
        };
        let root = leader.world_state.write().state_root().unwrap();
        leader.consensus.write().slash_authority(&authority);
        assert_eq!(leader.consensus.read().validator_weights()[&authority], 2);
        assert!(
            leader.verify_commit_certificate(first.number(), first.hash(), &certificate),
            "later evidence cannot retroactively change a finalized block's quorum"
        );
        assert_eq!(leader.finality.read().last_finalized_number(), finalized.0);
        assert_eq!(*leader.finality.read().last_finalized_hash(), finalized.1);
        assert_eq!(leader.world_state.write().state_root().unwrap(), root);
        let unchanged = leader.store.scan_prefix(b"").unwrap();
        assert!(leader.verify_commit_certificate(first.number(), first.hash(), &certificate));
        assert_eq!(leader.store.scan_prefix(b"").unwrap(), unchanged);

        // Reload existing durable finality, signer evidence and later penalties into
        // a new node instance. No live authority-key cache is needed for this proof.
        {
            let mut lifecycle = leader.challenge_lifecycle.lock();
            lifecycle.penalties = Some(leader.consensus.read().penalty_state());
            lifecycle.persist(leader.store.as_ref()).unwrap();
        }
        let restarted =
            super::super::timeout_evidence::tests::node(leader.store.clone(), &keys, vec![3, 1]);
        restarted.known_authorities.write().clear();
        assert_eq!(restarted.finality.read().last_finalized_number(), 1);
        assert_eq!(
            restarted.consensus.read().validator_weights()[&authority],
            2
        );
        let before = restarted.store.scan_prefix(b"").unwrap();
        assert!(restarted.verify_commit_certificate(1, first.hash(), &certificate));
        assert_eq!(restarted.store.scan_prefix(b"").unwrap(), before);

        // Exact stored bytes still require genuine address-bound signatures.
        let mut corrupted = keys[0].sign(first.hash().as_bytes()).unwrap();
        corrupted.data[0] ^= 1;
        let corrupted =
            Node::<MemoryDb>::encode_commit_certificate(&HashMap::from([(authority, corrupted)]))
                .unwrap();
        leader
            .chain_store
            .set_commit_certificate(&first.hash(), &corrupted)
            .unwrap();
        assert!(!leader.verify_commit_certificate(1, first.hash(), &corrupted));
        leader
            .chain_store
            .set_commit_certificate(&first.hash(), &certificate)
            .unwrap();
        let evidence = leader.chain_store.get_block_signers(&first.hash()).unwrap();
        let mut wrong_key = evidence
            .iter()
            .find(|entry| entry.address == authority)
            .unwrap()
            .clone();
        wrong_key.public_key = keys[1].public_key().to_vec();
        leader
            .chain_store
            .put_block_signers(&first.hash(), &[wrong_key])
            .unwrap();
        assert!(!leader.verify_commit_certificate(1, first.hash(), &certificate));
        leader
            .chain_store
            .put_block_signers(&first.hash(), &evidence)
            .unwrap();
        leader.chain_store.set_finalized_number(0).unwrap();
        assert!(
            !leader.verify_commit_certificate(1, first.hash(), &certificate),
            "volatile finality alone cannot authorize a retained proof"
        );
        leader.chain_store.set_finalized_number(1).unwrap();

        // Even a complete certificate/signers record is insufficient for a new
        // block: current A2/B1 requires3, so A alone cannot advance finality.
        let second = produce(&leader, &keys[0]);
        let signature = keys[0].sign(second.hash().as_bytes()).unwrap();
        let candidate = Node::<MemoryDb>::encode_commit_certificate(&HashMap::from([(
            authority,
            signature.clone(),
        )]))
        .unwrap();
        leader
            .chain_store
            .set_commit_certificate_with_signers(
                &second.hash(),
                &candidate,
                &[shell_core::BlockSignerEvidence {
                    address: authority,
                    public_key: keys[0].public_key().to_vec(),
                    signature,
                }],
            )
            .unwrap();
        assert!(!leader.verify_commit_certificate(2, second.hash(), &candidate));
        assert!(!leader.fast_finalize_with_certificate(2, second.hash(), &candidate));
        assert_eq!(leader.finality.read().last_finalized_number(), 1);
        assert_eq!(leader.chain_store.get_finalized_number().unwrap(), Some(1));
    }

    #[test]
    fn canonical_timeouts_sequence_byte_budget_preserves_progress_and_recovery() {
        const BUDGET: usize = 2 * 1024 * 1024;
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let node = setup_weighted(&keys, Some(0), vec![3, 1]);
        let receiver = setup_weighted(&keys, Some(0), vec![3, 1]);
        let voter = Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8());
        let first = produce(&node, &keys[0]);
        let first_certificate = Node::<MemoryDb>::encode_commit_certificate(&HashMap::from([(
            voter,
            keys[0].sign(first.hash().as_bytes()).unwrap(),
        )]))
        .unwrap();
        assert!(node.fast_finalize_with_certificate(1, first.hash(), &first_certificate));
        receiver
            .import_block(first.clone(), &MultiVerifier)
            .unwrap();
        assert!(receiver.fast_finalize_with_certificate(1, first.hash(), &first_certificate));
        let root = node.world_state.write().state_root().unwrap();
        let mut overflow = None;
        for view in 0..512u64 {
            let before = node.store.get(PENDING_TIMEOUT_CERTIFICATES).unwrap();
            let mut candidate: Vec<TimeoutCertificate> = before
                .as_deref()
                .map(|bytes| serde_json::from_slice(bytes).unwrap())
                .unwrap_or_default();
            let vote = ViewChangeMessage::new(
                1337,
                2,
                view,
                first.hash(),
                voter,
                keys[0]
                    .sign(&ViewChangeMessage::signing_message(
                        1337,
                        2,
                        view,
                        &first.hash(),
                    ))
                    .unwrap()
                    .data,
            );
            candidate.push(TimeoutCertificate {
                votes: vec![vote.clone()],
            });
            let journal = serde_json::to_vec(&candidate).unwrap();
            let mut wire = TIMEOUT_EXTRA_PREFIX.to_vec();
            wire.extend(
                serde_json::to_vec(&TimeoutEnvelope {
                    view: view + 1,
                    certificates: candidate,
                })
                .unwrap(),
            );
            let advanced = node.handle_wpoa_view_change(vote, &MultiVerifier).unwrap();
            if wire.len() > BUDGET {
                assert!(
                    !advanced,
                    "oversized complete proof cannot authorize view advance"
                );
                assert_eq!(node.consensus.read().current_view(), view);
                assert_eq!(
                    node.store.get(PENDING_TIMEOUT_CERTIFICATES).unwrap(),
                    before
                );
                overflow = Some((view, journal, wire.len(), before.unwrap()));
                break;
            }
            assert!(advanced, "a fitting genuine quorum must remain usable");
            assert_eq!(node.consensus.read().current_view(), view + 1);
            assert_eq!(node.world_state.write().state_root().unwrap(), root);
        }
        let (views, oversized_journal, rejected_bytes, retained) =
            overflow.expect("bounded journal must reject before512 genuine proofs");
        assert!(views > 0);
        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().hash(),
            first.hash()
        );
        assert_eq!(node.finality.read().last_finalized_number(), 1);
        assert_eq!(node.world_state.write().state_root().unwrap(), root);
        let fitting = node.timeout_extra_for_production(2).unwrap();
        assert!(fitting.len() <= BUDGET);
        let (restored, _) = crate::NodeBuilder::new(node.config.clone(), node.store.clone())
            .build()
            .unwrap();
        for key in &keys {
            restored.register_authority_pubkey(
                Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
                key.public_key().to_vec(),
            );
        }
        let before_view = restored.consensus.read().current_view();
        node.store
            .put(PENDING_TIMEOUT_CERTIFICATES, &oversized_journal)
            .unwrap();
        assert!(restored.restore_pending_timeouts().is_err());
        assert_eq!(restored.consensus.read().current_view(), before_view);
        node.store
            .put(PENDING_TIMEOUT_CERTIFICATES, &retained)
            .unwrap();
        restored.restore_pending_timeouts().unwrap();
        assert_eq!(restored.consensus.read().current_view(), views);
        assert_eq!(restored.timeout_extra_for_production(2).unwrap(), fitting);
        assert_eq!(restored.world_state.write().state_root().unwrap(), root);

        // Explicit Dev time proves encoded-size behavior, not elapsed network time.
        let timeout_secs = node
            .config
            .block_time_ms
            .max(VIEW_CHANGE_TIMEOUT_MS)
            .div_ceil(1000);
        node.dev_state.write().next_block_timestamp =
            Some(first.header.timestamp + views * timeout_secs + 1);
        let proposer = &keys[(views % 2) as usize]; // height2 starts at A, then A/B rotate by view.
        let second = node.produce_block(proposer, 0).unwrap();
        assert_eq!(second.header.extra_data, fitting);
        let mut oversized = second.clone();
        let mut padded = fitting.as_ref().to_vec();
        padded.resize(BUDGET + 1, b' '); // valid JSON semantics, only byte budget differs.
        oversized.header.extra_data = Bytes::from(padded);
        oversized.proposer_seal = Some(proposer.sign(oversized.header.hash().as_bytes()).unwrap());
        let unchanged = receiver.store.scan_prefix(b"").unwrap();
        assert!(receiver.import_block(oversized, &MultiVerifier).is_err());
        assert_eq!(receiver.store.scan_prefix(b"").unwrap(), unchanged);
        receiver
            .import_block(second.clone(), &MultiVerifier)
            .unwrap();
        assert_eq!(
            receiver.world_state.write().state_root().unwrap(),
            second.header.state_root
        );
        let second_certificate = Node::<MemoryDb>::encode_commit_certificate(&HashMap::from([(
            voter,
            keys[0].sign(second.hash().as_bytes()).unwrap(),
        )]))
        .unwrap();
        assert!(node.fast_finalize_with_certificate(2, second.hash(), &second_certificate));
        assert!(receiver.fast_finalize_with_certificate(2, second.hash(), &second_certificate));
        for imported in [&node, &receiver] {
            assert_eq!(imported.finality.read().last_finalized_number(), 2);
            assert_eq!(
                *imported.finality.read().last_finalized_hash(),
                second.hash()
            );
            assert_eq!(
                imported.chain_store.get_finalized_number().unwrap(),
                Some(2)
            );
            let winner =
                Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
            assert_eq!(
                imported
                    .world_state
                    .read()
                    .get_validator_assigned_misses(&winner)
                    .unwrap(),
                0
            );
            if views < 200 {
                // This pre-threshold profile has alternating A/B assignments;
                // the successful proposer resets, the other retains ceil(N/2).
                let other = &keys[((views + 1) % 2) as usize];
                let other = Address::from_public_key(other.public_key(), other.sig_type().as_u8());
                assert_eq!(
                    imported
                        .world_state
                        .read()
                        .get_validator_assigned_misses(&other)
                        .unwrap(),
                    views.div_ceil(2)
                );
            }
        }
        node.consensus.write().note_block_progress(0);
        let next = ViewChangeMessage::new(
            1337,
            3,
            0,
            second.hash(),
            voter,
            keys[0]
                .sign(&ViewChangeMessage::signing_message(
                    1337,
                    3,
                    0,
                    &second.hash(),
                ))
                .unwrap()
                .data,
        );
        assert!(node.handle_wpoa_view_change(next, &MultiVerifier).unwrap());
        let next: Vec<TimeoutCertificate> = serde_json::from_slice(
            &node
                .store
                .get(PENDING_TIMEOUT_CERTIFICATES)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].votes[0].block_number, 3);
        assert_eq!(next[0].votes[0].highest_qc_hash, second.hash());
        println!("timeout proof budget: accepted_views={views}, fitting_bytes={}, rejected_candidate_bytes={rejected_bytes}, independent_finality=2, next_height=3", fitting.len());
    }

    #[test]
    fn canonical_timeouts_active_write_failure_keeps_view_retryable() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let store = Arc::new(super::super::tests::FailingBatchDb::new());
        let node = setup_store(store.clone(), &keys, Some(0), vec![3, 1]);
        let parent = node.chain_store.get_head_hash().unwrap().unwrap();
        let vote = ViewChangeMessage::new(
            1337,
            1,
            0,
            parent,
            Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8()),
            keys[0]
                .sign(&ViewChangeMessage::signing_message(1337, 1, 0, &parent))
                .unwrap()
                .data,
        );
        let before = store.scan_prefix(b"").unwrap();
        store.fail_next_put();
        assert!(
            !node
                .handle_wpoa_view_change(vote.clone(), &MultiVerifier)
                .unwrap(),
            "activated view must not advance if its required canonical proof was not retained"
        );
        assert_eq!(node.consensus.read().current_view(), 0);
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        assert!(node.handle_wpoa_view_change(vote, &MultiVerifier).unwrap());
        assert_eq!(node.consensus.read().current_view(), 1);
        let expected = node.timeout_extra_for_production(1).unwrap();
        assert!(!expected.is_empty());
        let (restored, _) = crate::NodeBuilder::new(node.config.clone(), store.clone())
            .build()
            .unwrap();
        for key in &keys {
            restored.register_authority_pubkey(
                Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
                key.public_key().to_vec(),
            );
        }
        let checkpoint = store.scan_prefix(b"").unwrap();
        restored.restore_pending_timeouts().unwrap();
        restored.restore_pending_timeouts().unwrap();
        assert_eq!(restored.consensus.read().current_view(), 1);
        assert_eq!(restored.timeout_extra_for_production(1).unwrap(), expected);
        assert_eq!(store.scan_prefix(b"").unwrap(), checkpoint);
        // Corrupted persisted proof is rejected before any transient view change.
        let mut certificates: Vec<TimeoutCertificate> =
            serde_json::from_slice(&store.get(PENDING_TIMEOUT_CERTIFICATES).unwrap().unwrap())
                .unwrap();
        certificates[0].votes[0].signature[0] ^= 1;
        store
            .put(
                PENDING_TIMEOUT_CERTIFICATES,
                &serde_json::to_vec(&certificates).unwrap(),
            )
            .unwrap();
        restored.consensus.write().note_block_progress(0);
        assert!(restored.restore_pending_timeouts().is_err());
        assert_eq!(restored.consensus.read().current_view(), 0);
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn canonical_timeouts_pending_sequence_survives_physical_process_reopen() {
        const DIRECTORY: &str = "SHELL_TEST_PENDING_TIMEOUT_DIRECTORY";
        if let Some(directory) = std::env::var_os(DIRECTORY) {
            let directory = std::path::PathBuf::from(directory);
            let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
            let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
            let node = setup_store(Arc::new(stores.state), &keys, Some(0), vec![3, 1]);
            let parent = node.chain_store.get_head_hash().unwrap().unwrap();
            for view in 0..2 {
                let signature = keys[0]
                    .sign(&ViewChangeMessage::signing_message(1337, 1, view, &parent))
                    .unwrap();
                assert!(node
                    .handle_wpoa_view_change(
                        ViewChangeMessage::new(
                            1337,
                            1,
                            view,
                            parent,
                            Address::from_public_key(
                                keys[0].public_key(),
                                keys[0].sig_type().as_u8()
                            ),
                            signature.data
                        ),
                        &MultiVerifier
                    )
                    .unwrap());
            }
            std::fs::write(
                directory.join("envelope.json"),
                node.timeout_extra_for_production(1).unwrap().as_ref(),
            )
            .unwrap();
            // Leave actual WAL recovery to a separate process; never export private keys.
            std::process::exit(0);
        }
        let directory = std::env::temp_dir().join(format!(
            "shell-pending-timeout-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "node::canonical_timeouts::tests::canonical_timeouts_pending_sequence_survives_physical_process_reopen", "--nocapture"])
            .env(DIRECTORY, &directory).status().unwrap();
        assert!(status.success());
        let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
        let store = Arc::new(stores.state);
        let chain = ChainStore::new(store.clone());
        let header = chain.get_head_block().unwrap().unwrap().header;
        let snapshot = WorldState::at_root(store.clone(), &header.state_root).unwrap();
        let validators = snapshot.get_validators().unwrap();
        let (node, _) = crate::NodeBuilder::new(NodeConfig::dev(validators[0]), store.clone())
            .build()
            .unwrap();
        for address in validators {
            node.register_authority_pubkey(address, chain.get_pubkey(&address).unwrap().unwrap());
        }
        let before = store.scan_prefix(b"").unwrap();
        node.restore_pending_timeouts().unwrap();
        assert_eq!(node.consensus.read().current_view(), 2);
        assert_eq!(
            node.timeout_extra_for_production(1).unwrap().as_ref(),
            std::fs::read(directory.join("envelope.json")).unwrap()
        );
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(header.hash())
        );
    }

    #[test]
    fn canonical_timeouts_valid_assigned_proposal_resets_before_threshold() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let mut node = setup(&keys, Some(0));
        let absent = Address::from_public_key(keys[1].public_key(), keys[1].sig_type().as_u8());
        for height in 1..=11 {
            let reset = height == 11;
            let view = u64::from(height % 4 == 3 && !reset);
            if view == 1 {
                advance(&node, &keys[0], height, 0);
            }
            node.config.proposer_address = Some(if reset {
                absent
            } else {
                Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8())
            });
            let block = produce(&node, if reset { &keys[1] } else { &keys[0] });
            finalize(&node, &keys[0], &block, view);
            assert_eq!(
                node.world_state
                    .read()
                    .get_validator_assigned_misses(&absent)
                    .unwrap(),
                if reset { 0 } else { (height + 1) / 4 }
            );
        }
    }

    #[test]
    fn canonical_timeouts_active_quorum_is_strict_and_genesis_is_parent_bound() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let mut node = setup_weighted(&keys, Some(0), vec![2, 1]);
        let genesis = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        assert_eq!(node.timeout_vote_qc(1).unwrap(), genesis);
        let signed = |key: &dyn Signer, qc| {
            ViewChangeMessage::new(
                1337,
                1,
                0,
                qc,
                Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
                key.sign(&ViewChangeMessage::signing_message(1337, 1, 0, &qc))
                    .unwrap()
                    .data,
            )
        };
        assert!(!node
            .handle_wpoa_view_change(signed(&keys[0], ShellHash::ZERO), &MultiVerifier)
            .unwrap());
        assert!(!node
            .handle_wpoa_view_change(signed(&keys[0], genesis), &MultiVerifier)
            .unwrap());
        assert!(!node
            .handle_wpoa_view_change(signed(&keys[0], genesis), &MultiVerifier)
            .unwrap());
        assert_eq!(
            node.consensus.read().current_view(),
            0,
            "exact2/3 must not advance active timeout view"
        );
        assert!(node.latest_timeout_certificate().unwrap().is_none());
        assert!(node
            .handle_wpoa_view_change(signed(&keys[1], genesis), &MultiVerifier)
            .unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(
            !node
                .consensus
                .read()
                .check_view_change_timeout(now, node.config.block_time_ms),
            "activated next view gets a fresh timeout window"
        );
        let proposer = Address::from_public_key(keys[1].public_key(), keys[1].sig_type().as_u8());
        node.config.proposer_address = Some(proposer);
        let block = produce(&node, &keys[1]);
        assert_eq!(block.header.proposer, proposer);
        let missed = Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8());
        assert_eq!(
            node.world_state
                .read()
                .get_validator_assigned_misses(&missed)
                .unwrap(),
            1
        );
    }

    #[test]
    fn canonical_timeouts_multi_view_sequence_counts_only_assigned_opportunities() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let leader = setup(&keys, Some(0));
        let follower = setup(&keys, Some(0));
        for _ in 0..2 {
            let block = produce(&leader, &keys[0]);
            follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            finalize(&leader, &keys[0], &block, 0);
            finalize(&follower, &keys[0], &block, 0);
        }
        for view in 0..3 {
            advance(&leader, &keys[0], 3, view);
        }
        let parent = leader.chain_store.get_head_block().unwrap().unwrap();
        leader.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 90);
        let block = leader.produce_block(&keys[0], 0).unwrap();
        let mut invalid = block.clone();
        let mut envelope: TimeoutEnvelope = serde_json::from_slice(
            &invalid.header.extra_data.as_ref()[TIMEOUT_EXTRA_PREFIX.len()..],
        )
        .unwrap();
        assert_eq!(envelope.certificates.len(), 3);
        envelope.certificates.remove(1);
        let mut bytes = TIMEOUT_EXTRA_PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(&envelope).unwrap());
        invalid.header.extra_data = Bytes::from(bytes);
        leader
            .consensus
            .read()
            .sign_block(&mut invalid, &keys[0])
            .unwrap();
        let snapshot = follower.store.scan_prefix(b"").unwrap();
        assert!(follower.import_block(invalid, &MultiVerifier).is_err());
        assert_eq!(follower.store.scan_prefix(b"").unwrap(), snapshot);
        follower
            .import_block(block.clone(), &MultiVerifier)
            .unwrap();
        for node in [&leader, &follower] {
            let strong = Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8());
            let weak = Address::from_public_key(keys[1].public_key(), keys[1].sig_type().as_u8());
            // At height3, views0/2 assign B; view1 assigns A; valid A at3 resets A.
            assert_eq!(
                node.world_state
                    .read()
                    .get_validator_assigned_misses(&weak)
                    .unwrap(),
                2
            );
            assert_eq!(
                node.world_state
                    .read()
                    .get_validator_assigned_misses(&strong)
                    .unwrap(),
                0
            );
        }
        assert_eq!(
            leader.world_state.write().state_root().unwrap(),
            follower.world_state.write().state_root().unwrap()
        );
    }

    #[test]
    fn canonical_timeouts_idle_demand_refreshes_only_activated_timer_without_state_effects() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        for activation in [None, Some(9), Some(0)] {
            let node = setup(&keys, activation);
            node.consensus.write().note_block_progress(0);
            let checkpoint = node.store.scan_prefix(b"").unwrap();
            node.note_idle_proposal_window(0, 1_000_000).unwrap();
            assert_eq!(node.consensus.read().current_view(), 0);
            assert_eq!(
                node.consensus
                    .read()
                    .check_view_change_timeout(1_000_001, node.config.block_time_ms),
                activation != Some(0)
            );
            assert_eq!(node.store.scan_prefix(b"").unwrap(), checkpoint);
        }
    }

    #[test]
    fn canonical_timeouts_default_off_preserves_legacy_opaque_extra_data() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let mut legacy_hash = None;
        for activation in [None, Some(9)] {
            let node = setup(&keys, activation);
            let block = produce(&node, &keys[0]);
            assert!(block.header.extra_data.is_empty());
            if let Some(hash) = legacy_hash {
                assert_eq!(
                    block.hash(),
                    hash,
                    "preactivation header hash matches legacy behavior"
                );
            } else {
                legacy_hash = Some(block.hash());
            }
            let root = node.world_state.write().state_root().unwrap();
            let overlay = Arc::new(OverlayStore::new(node.store.clone()));
            let mut state = WorldState::at_root(overlay, &root).unwrap();
            let mut header = block.header;
            header.extra_data = Bytes::from(TIMEOUT_EXTRA_PREFIX.to_vec());
            node.apply_canonical_timeouts(&mut state, &header).unwrap();
            assert_eq!(state.state_root().unwrap(), root);
            assert_eq!(node.world_state.write().state_root().unwrap(), root);
        }
    }
}
