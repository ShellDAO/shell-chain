//! Certified timeout admission, durable quorum collection and native execution.
//! Work is validated in an isolated canonical parent state. Callers supply that
//! parent's ordered effective authorities and historical runtime policy.
use crate::NodeError;
use shell_core::{OfflineState, SystemTransaction, TimeoutContext};
use shell_crypto::Verifier;
use shell_primitives::Address;
use shell_storage::{KvStore, WorldState};

/// Independently validated work/heartbeat context. It records eligibility, not
/// a missed opportunity; only a separately authenticated quorum can do that.
pub struct AdmittedOpportunity {
    pub context: TimeoutContext,
    pub eligible_at: u64,
    pub profile: shell_storage::OfflineEnforcement,
}

/// Validate durable work against a canonical parent's isolated execution state.
/// The caller supplies the ordered effective consensus set for that parent;
/// historical callers must also restore its algorithm/address metadata policy.
/// No writes or mempool insertions are published by this admission pass.
pub fn admit_timeout_opportunity<S: KvStore + 'static, V: Verifier>(
    chain: &shell_storage::ChainStore<S>,
    parent: &shell_core::BlockHeader,
    view: u64,
    authorities: &[(Address, u64)],
    opportunity: &shell_core::TimeoutOpportunity,
    observed_at: u64,
    verifier: &V,
) -> Result<AdmittedOpportunity, NodeError> {
    use shell_core::{BlockHeader, TimeoutOpportunity};
    let config = chain
        .get_chain_config()?
        .ok_or_else(|| NodeError::Startup("missing timeout chain configuration".into()))?;
    let profile = config
        .offline_enforcement
        .ok_or_else(|| NodeError::Startup("certified offline rule is disabled".into()))?;
    profile.validate()?;
    let number = parent
        .number
        .checked_add(1)
        .ok_or_else(|| NodeError::Startup("timeout height overflow".into()))?;
    if !profile.is_active(number)
        || parent.hash() == shell_primitives::ShellHash::ZERO
        || chain.get_block_hash_by_number(parent.number)? != Some(parent.hash())
    {
        return Err(NodeError::Startup(
            "timeout parent is not canonical or rule is not active".into(),
        ));
    }
    let context = TimeoutContext {
        chain_id: config.chain_id,
        block_number: number,
        view,
        parent_hash: parent.hash(),
        epoch: profile.epoch_at(number)?,
        authority_set_hash: shell_consensus::timeout::timeout_authority_set_hash(authorities)?,
        proposer: shell_consensus::timeout::timeout_proposer(number, view, authorities)?,
        opportunity_hash: opportunity
            .commitment(parent, config.chain_id, profile.heartbeat_interval_secs)
            .ok_or_else(|| NodeError::Startup("timeout opportunity overflow".into()))?,
    };
    let eligible_at = match opportunity {
        TimeoutOpportunity::Heartbeat => parent
            .timestamp
            .checked_add(profile.heartbeat_interval_secs)
            .ok_or_else(|| NodeError::Startup("heartbeat eligibility overflow".into()))?,
        TimeoutOpportunity::Work {
            transaction,
            admitted_at,
        } => {
            let earliest = parent
                .timestamp
                .checked_add(profile.block_time_secs)
                .ok_or_else(|| NodeError::Startup("work eligibility overflow".into()))?;
            if *admitted_at < earliest || *admitted_at > observed_at {
                return Err(NodeError::Startup(
                    "work witness admission time is ineligible".into(),
                ));
            }
            let base_fee = shell_core::calculate_base_fee(
                parent.gas_used,
                parent.gas_limit,
                parent.base_fee_per_gas,
            );
            let excess =
                shell_core::calc_excess_blob_gas(parent.excess_blob_gas, parent.blob_gas_used);
            if alloy_rlp::encode(transaction.as_ref()).len() > shell_mempool::MAX_TX_SIZE
                || transaction.tx.gas_limit > parent.gas_limit
                || transaction.tx.max_fee_per_gas < base_fee
                || transaction
                    .tx
                    .max_fee_per_blob_gas
                    .is_some_and(|fee| fee < shell_core::calc_blob_gas_price(excess))
            {
                return Err(NodeError::Startup(
                    "work witness exceeds size/gas limits or cannot pay block fees".into(),
                ));
            }
            let header = BlockHeader {
                number,
                parent_hash: parent.hash(),
                timestamp: *admitted_at,
                gas_limit: parent.gas_limit,
                base_fee_per_gas: base_fee,
                excess_blob_gas: excess,
                proposer: context.proposer,
                ..Default::default()
            };
            let overlay =
                std::sync::Arc::new(shell_storage::OverlayStore::new(chain.store().clone()));
            let local_chain = shell_storage::ChainStore::new(overlay.clone());
            let mut state = WorldState::at_root(overlay, &parent.state_root)?;
            shell_pqvm::validate_tx_at_block(
                transaction,
                &mut state,
                &local_chain,
                verifier,
                config.chain_id,
                &header,
            )
            .map_err(|error| {
                NodeError::Startup(format!("timeout work rejected: {}", error.kind_str()))
            })?;
            *admitted_at
        }
    };
    if eligible_at > observed_at {
        return Err(NodeError::Startup(
            "timeout opportunity is not eligible yet".into(),
        ));
    }
    Ok(AdmittedOpportunity {
        context,
        eligible_at,
        profile,
    })
}

fn ledger<S: KvStore + 'static>(state: &WorldState<S>) -> Result<OfflineState, NodeError> {
    let mut offline = state.load_offline_state()?;
    // The first active block initializes from its trusted registry. Thereafter
    // canonical epoch transitions own membership; pending raw governance edits
    // must not erase counters or create a fresh join before consensus reloads.
    if offline.cursor().is_none() && offline.validators().is_empty() {
        let members = state.get_validators()?;
        if members.is_empty() {
            return Err(NodeError::Startup(
                "offline execution requires canonical registry membership".into(),
            ));
        }
        offline
            .sync_membership(&members)
            .map_err(NodeError::Startup)?;
    }
    Ok(offline)
}

/// Verify a certificate, update exactly one assigned miss and publish the whole
/// native ledger through the account-trie root. All rejected proofs leave state
/// unchanged. Call before user governance can change the parent's membership.
pub fn execute_timeout_evidence<S: KvStore + 'static>(
    state: &mut WorldState<S>,
    tx: &SystemTransaction,
    index: u32,
    expected: &TimeoutContext,
    authorities: &[(Address, u64)],
    verifier: &dyn Verifier,
) -> Result<(), NodeError> {
    let mut offline = ledger(state)?;
    shell_consensus::timeout::apply_timeout_system_transaction(
        &mut offline,
        tx,
        index,
        expected,
        authorities,
        verifier,
    )?;
    state.save_offline_state(&offline)?;
    Ok(())
}

/// Decode an exact evidence envelope, independently admit its durable work or
/// heartbeat and verify quorum before publishing any native counter state.
/// Canonical callers execute evidence before user governance and require its
/// source to be the importing block's parent. Historical policy is caller-scoped.
pub fn execute_admitted_timeout_evidence<S: KvStore + 'static, V: Verifier>(
    state: &mut WorldState<S>,
    chain: &shell_storage::ChainStore<S>,
    tx: &SystemTransaction,
    index: u32,
    authorities: &[(Address, u64)],
    observed_at: u64,
    verifier: &V,
) -> Result<(), NodeError> {
    let certificate = shell_core::TimeoutCertificate::from_system_transaction(tx, index)
        .map_err(NodeError::Startup)?;
    let witness = certificate.opportunity.as_ref().ok_or_else(|| {
        NodeError::Startup("timeout certificate has no durable opportunity witness".into())
    })?;
    let parent = chain
        .get_header_by_hash(&tx.source_hash)?
        .ok_or_else(|| NodeError::Startup("timeout parent header unavailable".into()))?;
    if parent.hash() != tx.source_hash {
        return Err(NodeError::Startup(
            "timeout parent header hash mismatch".into(),
        ));
    }
    let admitted = admit_timeout_opportunity(
        chain,
        &parent,
        certificate.context.view,
        authorities,
        witness,
        observed_at,
        verifier,
    )?;
    if admitted
        .eligible_at
        .checked_add(admitted.profile.timeout_secs())
        .is_none_or(|deadline| observed_at < deadline)
    {
        return Err(NodeError::Startup(
            "timeout evidence precedes opportunity deadline".into(),
        ));
    }
    execute_timeout_evidence(state, tx, index, &admitted.context, authorities, verifier)
}

/// Finish only a proposal whose seal and canonical header were already checked.
/// Successful proposals reset their own consecutive counter, not other members'.
pub fn finish_timeout_proposal<S: KvStore + 'static>(
    state: &mut WorldState<S>,
    context: &TimeoutContext,
    authorities: &[(Address, u64)],
) -> Result<(), NodeError> {
    if context.parent_hash == shell_primitives::ShellHash::ZERO
        || context.block_number == 0
        || context.authority_set_hash
            != shell_consensus::timeout::timeout_authority_set_hash(authorities)?
        || context.proposer
            != shell_consensus::timeout::timeout_proposer(
                context.block_number,
                context.view,
                authorities,
            )?
    {
        return Err(NodeError::Startup(
            "offline proposal assignment mismatch".into(),
        ));
    }
    let mut offline = ledger(state)?;
    offline
        .record_verified_proposal(context)
        .map_err(NodeError::Startup)?;
    state.save_offline_state(&offline)?;
    Ok(())
}

impl<S: KvStore + 'static> super::Node<S> {
    /// Admit a bound peer vote, persist its full work witness and retain a
    /// verified weighted quorum. This does not execute a canonical miss or
    /// rotate the engine; canonical proposal execution consumes the certificate.
    pub fn handle_certified_timeout_vote(
        &self,
        message: shell_core::TimeoutVoteMessage,
        verifier: &shell_crypto::MultiVerifier,
    ) -> Result<Option<shell_core::TimeoutCertificate>, NodeError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| NodeError::Startup("clock precedes UNIX epoch".into()))?
            .as_secs();
        self.handle_certified_timeout_vote_at(message, now, verifier)
    }

    pub(crate) fn handle_certified_timeout_vote_at(
        &self,
        message: shell_core::TimeoutVoteMessage,
        now: u64,
        verifier: &shell_crypto::MultiVerifier,
    ) -> Result<Option<shell_core::TimeoutCertificate>, NodeError> {
        let parent = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let engine = self.consensus.read();
        if engine.engine_type() != shell_consensus::EngineType::WPoA
            || engine.current_view() != message.vote.context.view
        {
            return Err(NodeError::Startup(
                "timeout vote does not match active wPoA view".into(),
            ));
        }
        let weights = engine.validator_weights();
        let authorities: Vec<_> = engine
            .poa_config()
            .authorities
            .iter()
            .filter_map(|address| {
                weights
                    .get(address)
                    .copied()
                    .filter(|weight| *weight > 0)
                    .map(|weight| (*address, weight))
            })
            .collect();
        let admitted = admit_timeout_opportunity(
            &self.chain_store,
            &parent.header,
            message.vote.context.view,
            &authorities,
            &message.opportunity,
            now,
            verifier,
        )?;
        if admitted.context.chain_id != self.config.chain_id
            || admitted
                .eligible_at
                .checked_add(admitted.profile.timeout_secs())
                .is_none_or(|deadline| now < deadline)
        {
            return Err(NodeError::Startup(
                "timeout opportunity has not reached its deadline".into(),
            ));
        }
        shell_consensus::timeout::verify_timeout_vote(
            &message.vote,
            &admitted.context,
            &authorities,
            &message.public_key,
            verifier,
        )?;
        self.chain_store.put_timeout_vote(&message)?;
        let votes = self.chain_store.get_timeout_votes(&admitted.context)?;
        let mut signed = 0u128;
        let total: u128 = authorities
            .iter()
            .map(|(_, weight)| u128::from(*weight))
            .sum();
        let mut signers = Vec::new();
        for stored in votes {
            if stored.opportunity != message.opportunity {
                return Err(NodeError::Startup("timeout journal work mismatch".into()));
            }
            shell_consensus::timeout::verify_timeout_vote(
                &stored.vote,
                &admitted.context,
                &authorities,
                &stored.public_key,
                verifier,
            )?;
            signed += u128::from(weights[&stored.vote.validator]);
            signers.push(shell_core::BlockSignerEvidence {
                address: stored.vote.validator,
                public_key: stored.public_key,
                signature: stored.vote.signature,
            });
        }
        if signed < (2 * total).div_ceil(3) {
            return Ok(None);
        }
        let certificate = shell_core::TimeoutCertificate {
            opportunity: Some(message.opportunity),
            context: admitted.context,
            signers,
        };
        shell_consensus::timeout::verify_timeout_certificate(
            &certificate,
            &certificate.context,
            &authorities,
            verifier,
        )?;
        let retained = self.chain_store.retain_timeout_certificate(&certificate)?;
        if retained.opportunity != certificate.opportunity {
            return Err(NodeError::Startup("retained timeout work mismatch".into()));
        }
        shell_consensus::timeout::verify_timeout_certificate(
            &retained,
            &certificate.context,
            &authorities,
            verifier,
        )?;
        Ok(Some(retained))
    }
}

/// Volatile observation state belongs to one running event loop. Durable signed
/// votes remain in ChainStore; restart may rebroadcast them without resigning.
#[derive(Default)]
pub(crate) struct TimeoutObservation {
    scope: Option<(
        shell_primitives::ShellHash,
        u64,
        u64,
        shell_primitives::ShellHash,
    )>,
    pending: Option<(
        AdmittedOpportunity,
        shell_core::TimeoutOpportunity,
        std::time::Instant,
    )>,
    broadcasted: std::collections::HashSet<shell_primitives::ShellHash>,
}
impl TimeoutObservation {
    fn key(context: &TimeoutContext) -> shell_primitives::ShellHash {
        shell_primitives::keccak256(&context.signing_message(&Address::ZERO))
    }
    pub(crate) fn request_rebroadcast(&mut self) {
        self.broadcasted.clear();
    }
    pub(crate) fn note_broadcast(&mut self, context: &TimeoutContext) {
        self.broadcasted.insert(Self::key(context));
    }
}

impl<S: KvStore + 'static> super::Node<S> {
    pub(crate) fn certified_timeout_profile_active(&self) -> Result<bool, NodeError> {
        let Some(profile) = self
            .chain_store
            .get_chain_config()?
            .and_then(|c| c.offline_enforcement)
        else {
            return Ok(false);
        };
        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let next = head
            .number()
            .checked_add(1)
            .ok_or_else(|| NodeError::Startup("timeout height overflow".into()))?;
        Ok(profile.is_active(next))
    }

    /// Called through block_in_place by the event loop, so PQ signing and work
    /// validation cannot monopolize its async worker. No local timer changes
    /// canonical counters or advances consensus.
    pub(crate) fn prepare_certified_timeout_vote(
        &self,
        signer: &dyn shell_crypto::Signer,
        observation: &mut TimeoutObservation,
        now: u64,
        instant: std::time::Instant,
    ) -> Result<Option<shell_core::TimeoutVoteMessage>, NodeError> {
        use shell_core::{TimeoutOpportunity, TimeoutVote, TimeoutVoteMessage};
        if !self.certified_timeout_profile_active()? {
            *observation = TimeoutObservation::default();
            return Ok(None);
        }
        let parent = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let number = parent
            .number()
            .checked_add(1)
            .ok_or_else(|| NodeError::Startup("timeout height overflow".into()))?;
        let validator = self.config.proposer_address.ok_or(NodeError::NotProposer)?;
        let (view, authorities) = {
            let engine = self.consensus.read();
            if engine.engine_type() != shell_consensus::EngineType::WPoA {
                return Ok(None);
            }
            let weights = engine.validator_weights();
            (
                engine.current_view(),
                engine
                    .poa_config()
                    .authorities
                    .iter()
                    .filter_map(|a| weights.get(a).copied().filter(|w| *w > 0).map(|w| (*a, w)))
                    .collect::<Vec<_>>(),
            )
        };
        if !authorities.iter().any(|(a, _)| *a == validator) {
            return Ok(None);
        }
        if Address::from_public_key(signer.public_key(), signer.sig_type().as_u8()) != validator {
            return Err(NodeError::Startup(
                "timeout signer is not the configured active validator".into(),
            ));
        }
        let scope = (
            parent.hash(),
            number,
            view,
            shell_consensus::timeout::timeout_authority_set_hash(&authorities)?,
        );
        if observation.scope.as_ref() != Some(&scope) {
            *observation = TimeoutObservation {
                scope: Some(scope),
                ..Default::default()
            };
        }
        let records = self.chain_store.get_timeout_slot_votes(
            &parent.hash(),
            self.config.chain_id,
            number,
            view,
        )?;
        let mut own = std::collections::HashSet::new();
        for m in records.iter().filter(|m| {
            m.vote.validator == validator && m.vote.context.authority_set_hash == scope.3
        }) {
            let admitted = admit_timeout_opportunity(
                &self.chain_store,
                &parent.header,
                view,
                &authorities,
                &m.opportunity,
                now,
                &shell_crypto::MultiVerifier,
            )?;
            shell_consensus::timeout::verify_timeout_vote(
                &m.vote,
                &admitted.context,
                &authorities,
                &m.public_key,
                &shell_crypto::MultiVerifier,
            )?;
            let key = TimeoutObservation::key(&m.vote.context);
            own.insert(key);
            if !observation.broadcasted.contains(&key) {
                self.handle_certified_timeout_vote_at(
                    m.clone(),
                    now,
                    &shell_crypto::MultiVerifier,
                )?;
                return Ok(Some(m.clone()));
            }
        }
        if observation.pending.is_none() {
            // A received witness may use a different admission timestamp. Adopt
            // it only after fresh validation at first observation, then wait a
            // full interval of our own rather than inheriting its old deadline.
            let mut peers: Vec<_> = records
                .iter()
                .filter(|m| !own.contains(&TimeoutObservation::key(&m.vote.context)))
                .collect();
            peers.sort_by_key(|m| *TimeoutObservation::key(&m.vote.context).as_bytes());
            let candidates: Vec<_> = if peers.is_empty() && own.is_empty() {
                let mut v: Vec<_> = self
                    .tx_pool
                    .pending_for_block(64)
                    .into_iter()
                    .map(|tx| TimeoutOpportunity::Work {
                        transaction: Box::new(tx),
                        admitted_at: now,
                    })
                    .collect();
                v.push(TimeoutOpportunity::Heartbeat);
                v
            } else {
                peers.into_iter().map(|m| m.opportunity.clone()).collect()
            };
            for witness in candidates {
                let fresh = match &witness {
                    TimeoutOpportunity::Work { transaction, .. } => TimeoutOpportunity::Work {
                        transaction: transaction.clone(),
                        admitted_at: now,
                    },
                    TimeoutOpportunity::Heartbeat => TimeoutOpportunity::Heartbeat,
                };
                if admit_timeout_opportunity(
                    &self.chain_store,
                    &parent.header,
                    view,
                    &authorities,
                    &fresh,
                    now,
                    &shell_crypto::MultiVerifier,
                )
                .is_err()
                {
                    continue;
                }
                if let Ok(admitted) = admit_timeout_opportunity(
                    &self.chain_store,
                    &parent.header,
                    view,
                    &authorities,
                    &witness,
                    now,
                    &shell_crypto::MultiVerifier,
                ) {
                    observation.pending = Some((admitted, witness, instant));
                    break;
                }
            }
        }
        let Some((admitted, witness, first_seen)) = &observation.pending else {
            return Ok(None);
        };
        // Expiry or a policy change during observation must not turn an old
        // witness into a new miss. Recheck current eligibility at each poll;
        // the certificate still binds the original witnessed environment.
        let fresh = match witness {
            TimeoutOpportunity::Work { transaction, .. } => TimeoutOpportunity::Work {
                transaction: transaction.clone(),
                admitted_at: now,
            },
            TimeoutOpportunity::Heartbeat => TimeoutOpportunity::Heartbeat,
        };
        if let Err(error) = admit_timeout_opportunity(
            &self.chain_store,
            &parent.header,
            view,
            &authorities,
            &fresh,
            now,
            &shell_crypto::MultiVerifier,
        ) {
            observation.pending = None;
            return match error {
                NodeError::Storage(_) => Err(error),
                _ => Ok(None),
            };
        }
        if instant.saturating_duration_since(*first_seen)
            < std::time::Duration::from_secs(admitted.profile.timeout_secs())
        {
            return Ok(None);
        }
        let signature = signer
            .sign(&admitted.context.signing_message(&validator))
            .map_err(|e| NodeError::Startup(format!("timeout signing failed: {e}")))?;
        let message = TimeoutVoteMessage {
            vote: TimeoutVote {
                context: admitted.context.clone(),
                validator,
                signature,
            },
            public_key: signer.public_key().to_vec(),
            opportunity: witness.clone(),
        };
        self.handle_certified_timeout_vote_at(message.clone(), now, &shell_crypto::MultiVerifier)?;
        observation.pending = None;
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{BlockSignerEvidence, TimeoutCertificate};
    use shell_crypto::{MlDsaSigner, MultiVerifier, Signer};
    use shell_primitives::{ShellHash, U256};
    use shell_storage::MemoryDb;
    use std::sync::Arc;
    #[test]
    fn offline_enforcement_executes_signed_proof_to_native_root_and_historical_state() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let addresses = keys
            .iter()
            .map(|key| Address::from_public_key(key.public_key(), key.sig_type().as_u8()))
            .collect::<Vec<_>>();
        let set = vec![(addresses[0], 1), (addresses[1], 3)];
        let db = Arc::new(MemoryDb::new());
        let mut state = WorldState::new(Arc::clone(&db));
        state.set_validators(&addresses).unwrap();
        state.set_validator_weights(&addresses, &[1, 3]).unwrap();
        state.add_balance(&addresses[0], U256::from(123)).unwrap();
        state
            .set_validator_stake(&addresses[0], U256::from(50))
            .unwrap();
        let mut context = TimeoutContext {
            chain_id: 1337,
            block_number: 4,
            view: 0,
            parent_hash: ShellHash::from([1; 32]),
            epoch: 1,
            authority_set_hash: shell_consensus::timeout::timeout_authority_set_hash(&set).unwrap(),
            proposer: addresses[0],
            opportunity_hash: ShellHash::from([2; 32]),
        };
        let proof = TimeoutCertificate {
            opportunity: None,
            context: context.clone(),
            signers: vec![BlockSignerEvidence {
                address: addresses[1],
                public_key: keys[1].public_key().to_vec(),
                signature: keys[1]
                    .sign(&context.signing_message(&addresses[1]))
                    .unwrap(),
            }],
        };
        let tx = proof.system_transaction(0).unwrap();
        let before = state.state_root().unwrap();
        execute_timeout_evidence(&mut state, &tx, 0, &context, &set, &MultiVerifier).unwrap();
        let missed = state.state_root().unwrap();
        assert_ne!(before, missed);
        assert_eq!(
            state
                .load_offline_state()
                .unwrap()
                .validator(&addresses[0])
                .unwrap()
                .consecutive_misses,
            1
        );
        assert!(
            execute_timeout_evidence(&mut state, &tx, 0, &context, &set, &MultiVerifier).is_err()
        );
        assert_eq!(state.state_root().unwrap(), missed);
        let mut bad = proof.clone();
        bad.signers[0].signature.data[0] ^= 1;
        assert!(execute_timeout_evidence(
            &mut state,
            &bad.system_transaction(0).unwrap(),
            0,
            &context,
            &set,
            &MultiVerifier
        )
        .is_err());
        assert_eq!(state.state_root().unwrap(), missed);
        context.view = 1;
        context.proposer = addresses[1];
        finish_timeout_proposal(&mut state, &context, &set).unwrap();
        for height in 5..=8 {
            context.block_number = height;
            context.epoch = height / 4;
            context.view = 0;
            context.parent_hash = ShellHash::from([height as u8; 32]);
            context.proposer = shell_consensus::timeout::timeout_proposer(height, 0, &set).unwrap();
            finish_timeout_proposal(&mut state, &context, &set).unwrap();
        }
        let current = state.state_root().unwrap();
        assert_eq!(
            state
                .load_offline_state()
                .unwrap()
                .validator(&addresses[0])
                .unwrap()
                .consecutive_misses,
            0
        );
        assert_eq!(state.get_balance(&addresses[0]).unwrap(), U256::from(123));
        assert_eq!(
            state.get_validator_stake(&addresses[0]).unwrap(),
            U256::from(50)
        );
        let historical = WorldState::at_root(Arc::clone(&db), &missed).unwrap();
        assert_eq!(
            historical
                .load_offline_state()
                .unwrap()
                .validator(&addresses[0])
                .unwrap()
                .consecutive_misses,
            1
        );
        let reopened = WorldState::at_root(Arc::clone(&db), &current).unwrap();
        assert_eq!(
            reopened
                .load_offline_state()
                .unwrap()
                .validator(&addresses[0])
                .unwrap()
                .consecutive_misses,
            0
        );
        assert_eq!(state.state_root().unwrap(), current);
        WorldState::validate_snapshot_nodes(db.as_ref(), current).unwrap();
    }
}
#[cfg(test)]
mod opportunity_tests {
    use super::*;
    use crate::config::ConsensusEngineConfig;
    use crate::{NodeBuilder, NodeConfig};
    use shell_consensus::{PoaConfig, WPoaConfig};
    use shell_core::{
        Block, BlockHeader, SignedTransaction, TimeoutOpportunity, TimeoutVote, TimeoutVoteMessage,
        Transaction,
    };
    use shell_crypto::{MlDsaSigner, MultiVerifier, Signer};
    use shell_primitives::{Bytes, ShellHash, U256};
    use shell_storage::{ChainStore, MemoryDb, OfflineEnforcement};
    use std::sync::Arc;

    fn address(key: &MlDsaSigner) -> Address {
        Address::from_public_key(key.public_key(), key.sig_type().as_u8())
    }
    fn setup<S: KvStore + 'static>(
        store: Arc<S>,
        keys: &[MlDsaSigner; 2],
        sender: &MlDsaSigner,
        policy: bool,
    ) -> super::super::Node<S> {
        setup_profile(store, keys, sender, policy, Some(1))
    }
    fn setup_profile<S: KvStore + 'static>(
        store: Arc<S>,
        keys: &[MlDsaSigner; 2],
        sender: &MlDsaSigner,
        policy: bool,
        activation: Option<u64>,
    ) -> super::super::Node<S> {
        let policy_code = policy.then(|| {
            vec![
                0x42, 0x60, 102, 0x14, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
            ]
        });
        setup_profile_code(store, keys, sender, policy_code, activation)
    }
    fn setup_profile_code<S: KvStore + 'static>(
        store: Arc<S>,
        keys: &[MlDsaSigner; 2],
        sender: &MlDsaSigner,
        policy_code: Option<Vec<u8>>,
        activation: Option<u64>,
    ) -> super::super::Node<S> {
        let authorities = keys.iter().map(address).collect::<Vec<_>>();
        let chain = ChainStore::new(store.clone());
        let mut state = WorldState::new(store.clone());
        state.set_validators(&authorities).unwrap();
        state.set_validator_weights(&authorities, &[1, 3]).unwrap();
        for (i, validator) in authorities.iter().enumerate() {
            state.set_balance(validator, U256::from(123u64)).unwrap();
            state
                .set_validator_stake(validator, U256::from(if i == 0 { 25u64 } else { 75 }))
                .unwrap();
        }
        let from = address(sender);
        state.set_balance(&from, U256::from(10_000_000u64)).unwrap();
        if let Some(code) = policy_code {
            let hash = shell_primitives::keccak256(&code);
            chain.put_code(&hash, &code).unwrap();
            let mut account = state.get_account(&from).unwrap().unwrap();
            account.validation_code_hash = Some(hash);
            state.set_account(&from, &account).unwrap();
        }
        let block = Block {
            header: BlockHeader {
                number: 0,
                timestamp: 100,
                gas_limit: 30_000_000,
                base_fee_per_gas: 7,
                state_root: state.state_root().unwrap(),
                ..Default::default()
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        chain.put_block(&block).unwrap();
        chain.set_canonical(0, &block.hash()).unwrap();
        chain.set_head(&block.hash()).unwrap();
        chain.put_chain_config(&serde_json::from_value(serde_json::json!({"chain_id":1337,"genesis_hash":block.hash(),"offline_enforcement":activation.map(|activation_height|OfflineEnforcement{activation_height,epoch_length:10,block_time_secs:2,heartbeat_interval_secs:600})})).unwrap()).unwrap();
        let mut config = NodeConfig::dev(authorities[0]);
        config.consensus = ConsensusEngineConfig::WPoa(WPoaConfig::with_weights(
            PoaConfig::new(authorities, 2).with_epoch_length(10),
            vec![1, 3],
        ));
        NodeBuilder::new(config, store).build().unwrap().0
    }
    fn signed(sender: &MlDsaSigner, nonce: u64, value: u64, aa: bool) -> SignedTransaction {
        let from = address(sender);
        let tx = Transaction {
            chain_id: 1337,
            nonce,
            to: Some(Address::from([9; 32])),
            value: U256::from(value),
            data: Bytes::new(),
            gas_limit: 100_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: if aa { shell_core::AA_BUNDLE_TX_TYPE } else { 2 },
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let mut signed = if aa {
            SignedTransaction::with_aa_bundle(
                from,
                tx,
                shell_crypto::PQSignature::new(sender.sig_type(), vec![]),
                shell_core::PubkeyMode::Embedded(sender.public_key().to_vec()),
                shell_core::AaBundle {
                    inner_calls: vec![shell_core::InnerCall {
                        to: Some(Address::from([9; 32])),
                        value: U256::from(value),
                        data: Bytes::new(),
                        gas_limit: 21_000,
                    }],
                    ..Default::default()
                },
            )
            .unwrap()
        } else {
            SignedTransaction::with_pubkey(
                from,
                tx,
                shell_crypto::PQSignature::new(sender.sig_type(), vec![]),
                sender.public_key().to_vec(),
            )
        };
        signed.signature = sender
            .sign(signed.sender_signing_hash().as_bytes())
            .unwrap();
        signed
    }
    fn set(keys: &[MlDsaSigner; 2]) -> Vec<(Address, u64)> {
        vec![(address(&keys[0]), 1), (address(&keys[1]), 3)]
    }
    fn work(sender: &MlDsaSigner) -> TimeoutOpportunity {
        TimeoutOpportunity::Work {
            transaction: Box::new(signed(sender, 0, 5, false)),
            admitted_at: 102,
        }
    }
    fn message<S: KvStore + 'static>(
        node: &super::super::Node<S>,
        keys: &[MlDsaSigner; 2],
        witness: &TimeoutOpportunity,
        voter: usize,
        now: u64,
    ) -> TimeoutVoteMessage {
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let admitted = admit_timeout_opportunity(
            &node.chain_store,
            &parent.header,
            0,
            &set(keys),
            witness,
            now,
            &MultiVerifier,
        )
        .unwrap();
        let validator = address(&keys[voter]);
        let signature = keys[voter]
            .sign(&admitted.context.signing_message(&validator))
            .unwrap();
        TimeoutVoteMessage {
            vote: TimeoutVote {
                context: admitted.context,
                validator,
                signature,
            },
            public_key: keys[voter].public_key().to_vec(),
            opportunity: witness.clone(),
        }
    }
    #[test]
    fn timeout_work_admission_checks_real_signatures_balances_aa_and_no_writeback() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let before = store.scan_prefix(b"").unwrap();
        let root = node.world_state.write().state_root().unwrap();
        for aa in [false, true] {
            let witness = TimeoutOpportunity::Work {
                transaction: Box::new(signed(&sender, 0, 5, aa)),
                admitted_at: 102,
            };
            let admitted = admit_timeout_opportunity(
                &node.chain_store,
                &parent.header,
                0,
                &set(&keys),
                &witness,
                112,
                &MultiVerifier,
            )
            .unwrap();
            assert_eq!(
                admitted.context.opportunity_hash,
                witness.commitment(&parent.header, 1337, 600).unwrap()
            );
            assert_eq!(admitted.eligible_at, 102);
            for (nonce, value) in [(1, 5), (0, 10_000_001)] {
                let invalid = TimeoutOpportunity::Work {
                    transaction: Box::new(signed(&sender, nonce, value, aa)),
                    admitted_at: 102,
                };
                assert!(admit_timeout_opportunity(
                    &node.chain_store,
                    &parent.header,
                    0,
                    &set(&keys),
                    &invalid,
                    112,
                    &MultiVerifier
                )
                .is_err());
            }
        }
        let mut tx = signed(&sender, 0, 5, false);
        tx.signature.data[0] ^= 1;
        let bad = TimeoutOpportunity::Work {
            transaction: Box::new(tx),
            admitted_at: 102,
        };
        assert!(admit_timeout_opportunity(
            &node.chain_store,
            &parent.header,
            0,
            &set(&keys),
            &bad,
            112,
            &MultiVerifier
        )
        .is_err());
        for time in [101, 113] {
            let invalid = TimeoutOpportunity::Work {
                transaction: Box::new(signed(&sender, 0, 5, false)),
                admitted_at: time,
            };
            assert!(admit_timeout_opportunity(
                &node.chain_store,
                &parent.header,
                0,
                &set(&keys),
                &invalid,
                112,
                &MultiVerifier
            )
            .is_err());
        }
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        assert_eq!(node.world_state.write().state_root().unwrap(), root);
        assert!(node.tx_pool.is_empty());
        assert!(node
            .chain_store
            .get_pubkey(&address(&sender))
            .unwrap()
            .is_none());
    }
    #[test]
    fn timeout_work_admission_uses_witnessed_aa_header_and_refuses_future_policy() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, true);
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let before = store.scan_prefix(b"").unwrap();
        let valid = work(&sender);
        admit_timeout_opportunity(
            &node.chain_store,
            &parent.header,
            0,
            &set(&keys),
            &valid,
            112,
            &MultiVerifier,
        )
        .unwrap();
        let invalid = TimeoutOpportunity::Work {
            transaction: Box::new(signed(&sender, 0, 5, false)),
            admitted_at: 103,
        };
        assert!(admit_timeout_opportunity(
            &node.chain_store,
            &parent.header,
            0,
            &set(&keys),
            &invalid,
            112,
            &MultiVerifier
        )
        .is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
    }
    #[test]
    fn certified_timeout_vote_network_path_retains_weighted_quorum_without_canonical_penalty() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let witness = work(&sender);
        let low = message(&node, &keys, &witness, 0, 112);
        let high = message(&node, &keys, &witness, 1, 112);
        let root = node.world_state.write().state_root().unwrap();
        let head = node.chain_store.get_head_hash().unwrap();
        let before = store.scan_prefix(b"").unwrap();
        let mut corrupt = high.clone();
        corrupt.vote.signature.data[0] ^= 1;
        assert!(node
            .handle_certified_timeout_vote_at(corrupt, 112, &MultiVerifier)
            .is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        let mut legacy = high.clone();
        legacy.vote.signature = keys[1]
            .sign(&shell_consensus::ViewChangeMessage::signing_message(
                1337,
                1,
                0,
                &ShellHash::ZERO,
            ))
            .unwrap();
        assert!(node
            .handle_certified_timeout_vote_at(legacy, 112, &MultiVerifier)
            .is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        let mut forged = high.clone();
        forged.vote.context.parent_hash = ShellHash::ZERO;
        assert!(node
            .handle_certified_timeout_vote_at(forged, 112, &MultiVerifier)
            .is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        assert!(node
            .handle_certified_timeout_vote_at(high.clone(), 111, &MultiVerifier)
            .is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        let encoded = shell_network::message::serialize_checked(
            &shell_network::NetworkMessage::CertifiedTimeoutVote(Box::new(low.clone())),
            shell_network::message::MAX_MESSAGE_SIZE,
        )
        .unwrap();
        let decoded = shell_network::message::deserialize_checked(
            &encoded,
            shell_network::message::MAX_MESSAGE_SIZE,
        )
        .unwrap();
        assert_eq!(
            decoded.topic(),
            shell_network::message::NetworkTopic::Attestation
        );
        let mut oversized = high.clone();
        oversized
            .public_key
            .resize(shell_network::message::MAX_CONSENSUS_MESSAGE_SIZE, 0);
        let oversized = shell_network::NetworkMessage::CertifiedTimeoutVote(Box::new(oversized));
        assert!(shell_network::message::serialize_checked(
            &oversized,
            shell_network::message::MAX_MESSAGE_SIZE
        )
        .is_err());
        assert!(shell_network::message::deserialize_checked(
            &serde_json::to_vec(&oversized).unwrap(),
            shell_network::message::MAX_MESSAGE_SIZE
        )
        .is_err());
        let shell_network::NetworkMessage::CertifiedTimeoutVote(received) = decoded else {
            panic!("wrong timeout wire variant")
        };
        assert!(node
            .handle_certified_timeout_vote_at(*received, 112, &MultiVerifier)
            .unwrap()
            .is_none());
        assert!(node
            .handle_certified_timeout_vote_at(low.clone(), 112, &MultiVerifier)
            .unwrap()
            .is_none());
        assert_eq!(
            node.chain_store
                .get_timeout_votes(&low.vote.context)
                .unwrap()
                .len(),
            1
        );
        let certificate = node
            .handle_certified_timeout_vote_at(high.clone(), 112, &MultiVerifier)
            .unwrap()
            .unwrap();
        assert_eq!(certificate.signers.len(), 2);
        assert_eq!(certificate.opportunity, Some(witness));
        assert_eq!(
            node.chain_store
                .get_timeout_certificate(&high.vote.context)
                .unwrap(),
            Some(certificate.clone())
        );
        let reopened = ChainStore::new(store.clone());
        assert_eq!(
            reopened
                .get_timeout_votes(&high.vote.context)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            reopened
                .get_timeout_certificate(&high.vote.context)
                .unwrap(),
            Some(certificate)
        );
        assert_eq!(node.world_state.write().state_root().unwrap(), root);
        assert_eq!(node.chain_store.get_head_hash().unwrap(), head);
        assert_eq!(node.consensus.read().current_view(), 0);
        assert!(node
            .world_state
            .read()
            .load_offline_state()
            .unwrap()
            .validators()
            .is_empty());
        let mut other = low;
        other.opportunity = TimeoutOpportunity::Heartbeat;
        assert!(reopened.put_timeout_vote(&other).is_err());
    }
    #[test]
    fn timeout_heartbeat_requires_frozen_eligibility_and_certified_deadline() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let node = setup(Arc::new(MemoryDb::new()), &keys, &sender, false);
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let witness = TimeoutOpportunity::Heartbeat;
        assert!(admit_timeout_opportunity(
            &node.chain_store,
            &parent.header,
            0,
            &set(&keys),
            &witness,
            699,
            &MultiVerifier
        )
        .is_err());
        let admitted = admit_timeout_opportunity(
            &node.chain_store,
            &parent.header,
            0,
            &set(&keys),
            &witness,
            700,
            &MultiVerifier,
        )
        .unwrap();
        assert_eq!(admitted.eligible_at, 700);
        let high = message(&node, &keys, &witness, 1, 710);
        assert!(node
            .handle_certified_timeout_vote_at(high.clone(), 709, &MultiVerifier)
            .is_err());
        assert!(node
            .handle_certified_timeout_vote_at(high, 710, &MultiVerifier)
            .unwrap()
            .is_some());
        assert!(node
            .world_state
            .read()
            .load_offline_state()
            .unwrap()
            .validators()
            .is_empty());
    }
    #[test]
    fn timeout_work_admission_is_disabled_or_future_only_without_writeback() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        for activation in [None, Some(2)] {
            let store = Arc::new(MemoryDb::new());
            let node = setup_profile(store.clone(), &keys, &sender, false, activation);
            let parent = node.chain_store.get_head_block().unwrap().unwrap();
            let before = store.scan_prefix(b"").unwrap();
            assert!(admit_timeout_opportunity(
                &node.chain_store,
                &parent.header,
                0,
                &set(&keys),
                &work(&sender),
                112,
                &MultiVerifier
            )
            .is_err());
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
    }
    #[test]
    fn timeout_work_admission_reads_parent_root_after_current_balance_and_nonce_change() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        {
            let mut state = node.world_state.write();
            state.set_balance(&address(&sender), U256::ZERO).unwrap();
            state.increment_nonce(&address(&sender)).unwrap();
            state.state_root().unwrap();
        }
        let before = store.scan_prefix(b"").unwrap();
        let current = node.world_state.write().state_root().unwrap();
        assert_ne!(current, parent.header.state_root);
        admit_timeout_opportunity(
            &node.chain_store,
            &parent.header,
            0,
            &set(&keys),
            &work(&sender),
            112,
            &MultiVerifier,
        )
        .unwrap();
        assert_eq!(node.world_state.write().state_root().unwrap(), current);
        assert_eq!(
            node.world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            1
        );
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
    }
    #[test]
    fn certified_timeout_vote_put_and_flush_failure_never_publish_quorum_early() {
        use crate::node::tests::FailingBatchDb;
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(FailingBatchDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let witness = work(&sender);
        let high = message(&node, &keys, &witness, 1, 112);
        let root = node.world_state.write().state_root().unwrap();
        store.arm_timeout_put_failure();
        assert!(node
            .handle_certified_timeout_vote_at(high.clone(), 112, &MultiVerifier)
            .is_err());
        assert!(node
            .chain_store
            .get_timeout_votes(&high.vote.context)
            .unwrap()
            .is_empty());
        assert!(node
            .chain_store
            .get_timeout_certificate(&high.vote.context)
            .unwrap()
            .is_none());
        store.arm_timeout_flush_failure();
        assert!(node
            .handle_certified_timeout_vote_at(high.clone(), 112, &MultiVerifier)
            .is_err());
        assert_eq!(
            node.chain_store
                .get_timeout_votes(&high.vote.context)
                .unwrap()
                .len(),
            1
        );
        assert!(node
            .chain_store
            .get_timeout_certificate(&high.vote.context)
            .unwrap()
            .is_none());
        store.arm_timeout_flush_failure();
        assert!(node
            .handle_certified_timeout_vote_at(high.clone(), 112, &MultiVerifier)
            .is_err());
        assert!(node
            .chain_store
            .get_timeout_certificate(&high.vote.context)
            .unwrap()
            .is_none());
        assert!(node
            .handle_certified_timeout_vote_at(high.clone(), 112, &MultiVerifier)
            .unwrap()
            .is_some());
        let mut resigned = high.clone();
        resigned.vote.signature = keys[1]
            .sign(&high.vote.context.signing_message(&high.vote.validator))
            .unwrap();
        assert!(node
            .handle_certified_timeout_vote_at(resigned, 112, &MultiVerifier)
            .unwrap()
            .is_some());
        assert_eq!(
            node.chain_store
                .get_timeout_votes(&high.vote.context)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(node.world_state.write().state_root().unwrap(), root);
        assert_eq!(node.consensus.read().current_view(), 0);
    }
    #[test]
    fn timeout_work_admission_rejects_block_gas_fee_and_size_limits() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let before = store.scan_prefix(b"").unwrap();
        for case in 0..3 {
            let mut unsigned = signed(&sender, 0, 5, false).tx;
            match case {
                0 => unsigned.gas_limit = parent.header.gas_limit + 1,
                1 => unsigned.max_fee_per_gas = 4,
                _ => unsigned.data = Bytes::from(vec![1; shell_mempool::MAX_TX_SIZE]),
            }
            let signature = sender
                .sign(unsigned.signing_hash(sender.sig_type().as_u8()).as_bytes())
                .unwrap();
            let tx = SignedTransaction::with_pubkey(
                address(&sender),
                unsigned,
                signature,
                sender.public_key().to_vec(),
            );
            let witness = TimeoutOpportunity::Work {
                transaction: Box::new(tx),
                admitted_at: 102,
            };
            let error = admit_timeout_opportunity(
                &node.chain_store,
                &parent.header,
                0,
                &set(&keys),
                &witness,
                112,
                &MultiVerifier,
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("size/gas limits"));
        }
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
    }
    #[test]
    fn certified_timeout_vote_executes_admitted_work_to_native_root_and_refuses_replay() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let vote = message(&node, &keys, &work(&sender), 1, 112);
        let certificate = node
            .handle_certified_timeout_vote_at(vote, 112, &MultiVerifier)
            .unwrap()
            .unwrap();
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let original = parent.header.state_root;
        let mut state = WorldState::at_root(store.clone(), &original).unwrap();
        let tx = certificate.system_transaction(3).unwrap();
        let mut missing = certificate.clone();
        missing.opportunity = None;
        assert!(execute_admitted_timeout_evidence(
            &mut state,
            &node.chain_store,
            &missing.system_transaction(3).unwrap(),
            3,
            &set(&keys),
            112,
            &MultiVerifier
        )
        .is_err());
        assert_eq!(state.state_root().unwrap(), original);
        assert!(execute_admitted_timeout_evidence(
            &mut state,
            &node.chain_store,
            &tx,
            3,
            &set(&keys),
            111,
            &MultiVerifier
        )
        .is_err());
        assert_eq!(state.state_root().unwrap(), original);
        execute_admitted_timeout_evidence(
            &mut state,
            &node.chain_store,
            &tx,
            3,
            &set(&keys),
            112,
            &MultiVerifier,
        )
        .unwrap();
        let root = state.state_root().unwrap();
        assert_ne!(root, original);
        let ledger = state.load_offline_state().unwrap();
        assert_eq!(
            ledger
                .validator(&certificate.context.proposer)
                .unwrap()
                .consecutive_misses,
            1
        );
        assert_eq!(
            state.get_balance(&address(&sender)).unwrap(),
            U256::from(10_000_000u64)
        );
        assert_eq!(state.get_nonce(&address(&sender)).unwrap(), 0);
        assert!(execute_admitted_timeout_evidence(
            &mut state,
            &node.chain_store,
            &tx,
            3,
            &set(&keys),
            112,
            &MultiVerifier
        )
        .is_err());
        assert_eq!(state.state_root().unwrap(), root);
        let reopened = WorldState::at_root(store.clone(), &root).unwrap();
        assert_eq!(reopened.load_offline_state().unwrap(), ledger);
        assert!(WorldState::at_root(store, &original)
            .unwrap()
            .load_offline_state()
            .unwrap()
            .validators()
            .is_empty());
        assert_eq!(node.world_state.write().state_root().unwrap(), original);
    }
    fn event_node<S: KvStore + 'static>(
        store: Arc<S>,
        authorities: Vec<Address>,
        weights: Vec<u64>,
        own: usize,
        sender: &MlDsaSigner,
        timestamp: u64,
    ) -> super::super::Node<S> {
        event_node_at_activation(store, authorities, weights, own, sender, timestamp, 1)
    }
    fn event_node_at_activation<S: KvStore + 'static>(
        store: Arc<S>,
        authorities: Vec<Address>,
        weights: Vec<u64>,
        own: usize,
        sender: &MlDsaSigner,
        timestamp: u64,
        activation: u64,
    ) -> super::super::Node<S> {
        event_node_at_profile(
            store,
            authorities,
            weights,
            own,
            sender,
            timestamp,
            (activation, None),
        )
    }
    fn event_node_at_profile<S: KvStore + 'static>(
        store: Arc<S>,
        authorities: Vec<Address>,
        weights: Vec<u64>,
        own: usize,
        sender: &MlDsaSigner,
        timestamp: u64,
        policy: (u64, Option<u64>),
    ) -> super::super::Node<S> {
        let (activation, prover_registry_height) = policy;
        let chain = ChainStore::new(store.clone());
        let mut state = WorldState::new(store.clone());
        state.set_validators(&authorities).unwrap();
        state.set_validator_weights(&authorities, &weights).unwrap();
        for (validator, weight) in authorities.iter().zip(&weights) {
            state.set_balance(validator, U256::from(123u64)).unwrap();
            state
                .set_validator_stake(validator, U256::from(*weight * 25))
                .unwrap();
        }
        state
            .set_balance(&address(sender), U256::from(10_000_000u64))
            .unwrap();
        let block = Block {
            header: BlockHeader {
                timestamp,
                gas_limit: 30_000_000,
                base_fee_per_gas: 7,
                state_root: state.state_root().unwrap(),
                ..Default::default()
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        chain.put_block(&block).unwrap();
        chain.set_canonical(0, &block.hash()).unwrap();
        chain.set_head(&block.hash()).unwrap();
        chain.put_chain_config(&serde_json::from_value(serde_json::json!({"chain_id":1337,"genesis_hash":block.hash(),"fee_accounting_activation_height":1,"prover_registry_height":prover_registry_height,"offline_enforcement":OfflineEnforcement{activation_height:activation,epoch_length:10,block_time_secs:2,heartbeat_interval_secs:600}})).unwrap()).unwrap();
        let mut config = NodeConfig::dev(authorities[own]);
        config.consensus = ConsensusEngineConfig::WPoa(WPoaConfig::with_weights(
            PoaConfig::new(authorities, 2).with_epoch_length(10),
            weights,
        ));
        config.block_time_ms = 100;
        config.max_idle_interval_ms = u64::MAX;
        config.rpc_enabled = false;
        config.metrics.enabled = false;
        config.node_role = crate::NodeRole::Validator;
        NodeBuilder::new(config, store).build().unwrap().0
    }
    async fn next_bound_vote(
        network: &mut shell_network::ChannelNetwork,
        duration: std::time::Duration,
    ) -> Result<TimeoutVoteMessage, String> {
        use shell_network::{NetworkEvent, NetworkMessage, NetworkService};
        tokio::time::timeout(duration, async {
            loop {
                match network.next_event().await {
                    Some(NetworkEvent::MessageReceived {
                        message: NetworkMessage::CertifiedTimeoutVote(m),
                        ..
                    }) => return Ok(*m),
                    Some(NetworkEvent::MessageReceived {
                        message: NetworkMessage::WPoaViewChange(_),
                        ..
                    }) => return Err("active profile emitted legacy view-change vote".into()),
                    Some(NetworkEvent::MessageReceived {
                        peer,
                        message: NetworkMessage::BlockRequest { nonce, .. },
                    }) => {
                        network
                            .send_to_peer(
                                &peer,
                                NetworkMessage::BlockResponse {
                                    blocks: vec![],
                                    commit_certificates: vec![],
                                    nonce,
                                },
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    None => return Err("network closed".into()),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "timeout".to_string())?
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn certified_timeout_event_loop_waits_for_late_work_and_reuses_durable_signature() {
        use shell_network::{NetworkBus, NetworkConfig};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        struct ObservedSigner {
            inner: MlDsaSigner,
            count: Arc<AtomicUsize>,
            progressed: Arc<AtomicBool>,
            first: std::sync::Mutex<
                Option<(
                    tokio::sync::oneshot::Sender<()>,
                    std::sync::mpsc::Receiver<()>,
                )>,
            >,
        }
        impl Signer for ObservedSigner {
            fn sign(
                &self,
                payload: &[u8],
            ) -> Result<shell_crypto::PQSignature, shell_crypto::CryptoError> {
                if payload.starts_with(b"SHELL_TIMEOUT_V1") {
                    self.count.fetch_add(1, Ordering::SeqCst);
                    if let Some((started, progress)) = self.first.lock().unwrap().take() {
                        let _ = started.send(());
                        self.progressed.store(
                            progress.recv_timeout(Duration::from_secs(2)).is_ok(),
                            Ordering::SeqCst,
                        );
                    }
                }
                self.inner.sign(payload)
            }
            fn public_key(&self) -> &[u8] {
                self.inner.public_key()
            }
            fn sig_type(&self) -> shell_crypto::SignatureType {
                self.inner.sig_type()
            }
        }
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let authorities = keys.iter().map(address).collect::<Vec<_>>();
        let store = Arc::new(MemoryDb::new());
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60;
        let node = Arc::new(event_node(
            store.clone(),
            authorities,
            vec![1, 3],
            0,
            &sender,
            timestamp,
        ));
        let config = node.config.clone();
        let head = node.chain_store.get_head_hash().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let progressed = Arc::new(AtomicBool::new(false));
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (progress, progress_rx) = std::sync::mpsc::channel();
        let [own, _other] = keys;
        let signer = Arc::new(ObservedSigner {
            inner: own,
            count: count.clone(),
            progressed: progressed.clone(),
            first: std::sync::Mutex::new(Some((started, progress_rx))),
        });
        let watcher = tokio::spawn(async move {
            if started_rx.await.is_ok() {
                let _ = progress.send(());
            }
        });
        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());
        let mut peer = bus.join(&NetworkConfig::default());
        let task = tokio::spawn({
            let node = node.clone();
            let signer = signer.clone();
            async move { node.run(signer, &mut network).await }
        });
        let idle = next_bound_vote(&mut peer, Duration::from_secs(2)).await;
        node.handle_incoming_tx(signed(&sender, 0, 5, false), &MultiVerifier)
            .unwrap();
        let began = Instant::now();
        let early = next_bound_vote(&mut peer, Duration::from_millis(9500)).await;
        let result = next_bound_vote(&mut peer, Duration::from_secs(4)).await;
        let elapsed = began.elapsed();
        node.shutdown();
        task.await.unwrap().unwrap();
        watcher.abort();
        assert_eq!(idle, Err("timeout".into()));
        assert_eq!(early, Err("timeout".into()));
        let first = result.unwrap();
        assert!(elapsed >= Duration::from_secs(10));
        assert!(progressed.load(Ordering::SeqCst));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            node.chain_store
                .get_timeout_votes(&first.vote.context)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(node.chain_store.get_head_hash().unwrap(), head);
        assert!(node
            .world_state
            .read()
            .load_offline_state()
            .unwrap()
            .validators()
            .is_empty());
        let restored = Arc::new(NodeBuilder::new(config, store).build().unwrap().0);
        let mut network = bus.join(&NetworkConfig::default());
        let task = tokio::spawn({
            let node = restored.clone();
            let signer = signer.clone();
            async move { node.run(signer, &mut network).await }
        });
        let result = next_bound_vote(&mut peer, Duration::from_secs(4)).await;
        restored.shutdown();
        task.await.unwrap().unwrap();
        assert_eq!(result.unwrap(), first);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn certified_timeout_event_loops_converge_different_work_witnesses_without_double_miss() {
        use shell_network::{NetworkBus, NetworkConfig};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let a = MlDsaSigner::generate();
        let absent = MlDsaSigner::generate();
        let b = MlDsaSigner::generate();
        let sender = MlDsaSigner::generate();
        let authorities = vec![address(&a), address(&absent), address(&b)];
        let weights = vec![1, 1, 3];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60;
        let left = Arc::new(event_node(
            Arc::new(MemoryDb::new()),
            authorities.clone(),
            weights.clone(),
            0,
            &sender,
            timestamp,
        ));
        let right = Arc::new(event_node(
            Arc::new(MemoryDb::new()),
            authorities.clone(),
            weights.clone(),
            2,
            &sender,
            timestamp,
        ));
        assert_eq!(
            left.chain_store.get_head_hash().unwrap(),
            right.chain_store.get_head_hash().unwrap()
        );
        for node in [&left, &right] {
            for key in [&a, &absent, &b] {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
        }
        let original_root = left.world_state.write().state_root().unwrap();
        let bus = NetworkBus::new(128);
        let mut left_net = bus.join(&NetworkConfig::default());
        let mut right_net = bus.join(&NetworkConfig::default());
        let mut peer = bus.join(&NetworkConfig::default());
        let left_task = tokio::spawn({
            let node = left.clone();
            async move { node.run(Arc::new(a), &mut left_net).await }
        });
        let right_task = tokio::spawn({
            let node = right.clone();
            async move { node.run(Arc::new(b), &mut right_net).await }
        });
        tokio::time::sleep(Duration::from_secs(3)).await;
        let transaction = signed(&sender, 0, 5, false);
        left.handle_incoming_tx(transaction.clone(), &MultiVerifier)
            .unwrap();
        let began = Instant::now();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        right
            .handle_incoming_tx(transaction, &MultiVerifier)
            .unwrap();
        let observed = tokio::time::timeout(Duration::from_secs(30), async {
            use shell_network::{NetworkEvent, NetworkMessage, NetworkService};
            let mut contexts = std::collections::HashMap::new();
            let block = loop {
                match peer.next_event().await {
                    Some(NetworkEvent::MessageReceived {
                        message: NetworkMessage::CertifiedTimeoutVote(m),
                        ..
                    }) => {
                        contexts
                            .entry(TimeoutObservation::key(&m.vote.context))
                            .or_insert(m.vote.context);
                    }
                    Some(NetworkEvent::MessageReceived {
                        message: NetworkMessage::NewBlock(block),
                        ..
                    }) if block.number() == 1 => break *block,
                    Some(NetworkEvent::MessageReceived {
                        peer: who,
                        message: NetworkMessage::BlockRequest { nonce, .. },
                    }) => {
                        peer.send_to_peer(
                            &who,
                            NetworkMessage::BlockResponse {
                                blocks: vec![],
                                commit_certificates: vec![],
                                nonce,
                            },
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    }
                    Some(NetworkEvent::MessageReceived {
                        message: NetworkMessage::WPoaViewChange(_),
                        ..
                    }) => return Err("active node emitted legacy view change".to_string()),
                    None => return Err("network closed".to_string()),
                    _ => {}
                }
            };
            loop {
                if left
                    .chain_store
                    .get_finalized_number()
                    .unwrap()
                    .is_some_and(|h| h >= 1)
                    && right
                        .chain_store
                        .get_finalized_number()
                        .unwrap()
                        .is_some_and(|h| h >= 1)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, String>((block, contexts))
        })
        .await;
        left.shutdown();
        right.shutdown();
        left_task.await.unwrap().unwrap();
        right_task.await.unwrap().unwrap();
        let (block, contexts) = observed.unwrap().unwrap();
        assert!(began.elapsed() >= Duration::from_secs(20));
        assert!(
            contexts.len() >= 2,
            "different admission environments must not split honest validators permanently"
        );
        assert_eq!(
            left.chain_store.get_head_hash().unwrap(),
            Some(block.hash())
        );
        assert_eq!(
            right.chain_store.get_head_hash().unwrap(),
            Some(block.hash())
        );
        assert_eq!(left.consensus.read().current_view(), 0);
        assert_eq!(right.consensus.read().current_view(), 0);
        assert_eq!(block.transactions.len(), 1);
        // EIP-1559 downward rounding: 7 / 8 is zero. The signed
        // transaction pays the unchanged base fee plus its priority fee.
        assert_eq!(block.header.base_fee_per_gas, 7);
        let fee = U256::from(block.header.gas_used) * U256::from(8u64);
        for node in [&left, &right] {
            let state = node.world_state.read();
            assert_eq!(
                state
                    .load_offline_state()
                    .unwrap()
                    .validator(&address(&absent))
                    .unwrap()
                    .consecutive_misses,
                1
            );
            assert_eq!(
                state.get_balance(&address(&absent)).unwrap(),
                U256::from(123u64)
            );
            assert_eq!(
                state.get_validator_stake(&address(&absent)).unwrap(),
                U256::from(25u64)
            );
            assert_eq!(
                state.get_balance(&address(&sender)).unwrap(),
                U256::from(10_000_000u64) - U256::from(5u64) - fee
            );
            assert_eq!(state.get_nonce(&address(&sender)).unwrap(), 1);
            assert_eq!(
                state.get_balance(&Address::from([9; 32])).unwrap(),
                U256::from(5u64)
            );
        }
        assert_eq!(
            block
                .system_transactions
                .iter()
                .filter(|t| t.kind == shell_core::SystemTxKind::TimeoutEvidence)
                .count(),
            1
        );
        let receipts = left
            .chain_store
            .get_receipts(&block.hash())
            .unwrap()
            .unwrap();
        assert_eq!(
            receipts.len(),
            block.transactions.len() + block.system_transactions.len()
        );
        let evidence = block.system_transactions.last().unwrap();
        let receipt = receipts.last().unwrap();
        assert_eq!(receipt.tx_hash, evidence.hash());
        assert_eq!(receipt.tx_index, evidence.tx_index);
        assert_eq!(receipt.status, 1);
        assert_eq!(receipt.gas_used, 0);
        assert_eq!(evidence.value, U256::ZERO);
        let before = left.store.scan_prefix(b"").unwrap();
        let old = WorldState::at_root(left.store.clone(), &original_root).unwrap();
        assert!(old.load_offline_state().unwrap().validators().is_empty());
        assert_eq!(old.get_nonce(&address(&sender)).unwrap(), 0);
        assert_eq!(left.store.scan_prefix(b"").unwrap(), before);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn certified_timeout_heartbeat_event_loop_observes_full_interval() {
        use shell_network::{NetworkBus, NetworkConfig};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let authorities = keys.iter().map(address).collect::<Vec<_>>();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 601;
        let node = Arc::new(event_node(
            Arc::new(MemoryDb::new()),
            authorities,
            vec![1, 3],
            0,
            &sender,
            timestamp,
        ));
        let head = node.chain_store.get_head_hash().unwrap();
        let [signer, _other] = keys;
        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());
        let mut peer = bus.join(&NetworkConfig::default());
        let began = Instant::now();
        let task = tokio::spawn({
            let node = node.clone();
            async move { node.run(Arc::new(signer), &mut network).await }
        });
        let early = next_bound_vote(&mut peer, Duration::from_millis(9500)).await;
        let result = next_bound_vote(&mut peer, Duration::from_secs(4)).await;
        let elapsed = began.elapsed();
        node.shutdown();
        task.await.unwrap().unwrap();
        assert_eq!(early, Err("timeout".into()));
        let message = result.unwrap();
        assert_eq!(message.opportunity, TimeoutOpportunity::Heartbeat);
        assert!(elapsed >= Duration::from_secs(10));
        assert_eq!(node.chain_store.get_head_hash().unwrap(), head);
        assert_eq!(
            node.chain_store
                .get_timeout_votes(&message.vote.context)
                .unwrap()
                .len(),
            1
        );
        assert!(node
            .world_state
            .read()
            .load_offline_state()
            .unwrap()
            .validators()
            .is_empty());
    }
    #[test]
    fn certified_timeout_profile_rejects_real_legacy_peer_vote_before_rotation() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let context =
            shell_consensus::ViewChangeMessage::signing_message(1337, 1, 0, &ShellHash::ZERO);
        let message = shell_consensus::ViewChangeMessage::new(
            1337,
            1,
            0,
            ShellHash::ZERO,
            address(&keys[1]),
            keys[1].sign(&context).unwrap().data,
        );
        node.register_authority_pubkey(address(&keys[1]), keys[1].public_key().to_vec());
        let before = store.scan_prefix(b"").unwrap();
        assert!(node
            .handle_wpoa_view_change(message, &MultiVerifier)
            .is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        assert_eq!(node.consensus.read().current_view(), 0);
    }
    #[test]
    fn certified_timeout_observation_discards_expired_aa_work_without_a_vote() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        // Accept the canonical-head environment (100) and initial witnessed
        // environment (102), then reject at 103 and at the timeout deadline.
        let code = vec![
            0x42, 0x60, 100, 0x14, 0x42, 0x60, 102, 0x14, 0x17, 0x60, 0, 0x52, 0x60, 32, 0x60, 0,
            0xf3,
        ];
        let node = setup_profile_code(store.clone(), &keys, &sender, Some(code), Some(1));
        node.handle_incoming_tx(signed(&sender, 0, 5, false), &MultiVerifier)
            .unwrap();
        let mut observation = TimeoutObservation::default();
        let instant = std::time::Instant::now();
        let before = store.scan_prefix(b"").unwrap();
        assert!(node
            .prepare_certified_timeout_vote(&keys[0], &mut observation, 102, instant)
            .unwrap()
            .is_none());
        assert!(observation.pending.is_some());
        assert!(node
            .prepare_certified_timeout_vote(
                &keys[0],
                &mut observation,
                103,
                instant + std::time::Duration::from_secs(1)
            )
            .unwrap()
            .is_none());
        assert!(observation.pending.is_none());
        assert!(node
            .prepare_certified_timeout_vote(
                &keys[0],
                &mut observation,
                112,
                instant + std::time::Duration::from_secs(10)
            )
            .unwrap()
            .is_none());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        assert_eq!(node.consensus.read().current_view(), 0);
    }
    #[test]
    fn canonical_offline_forward_block_rejects_tampered_proofs_and_preserves_atomic_state() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let producer = setup(Arc::new(MemoryDb::new()), &keys, &sender, false);
        let witness = work(&sender);
        let vote = message(&producer, &keys, &witness, 1, 112);
        producer
            .handle_certified_timeout_vote_at(vote, 112, &MultiVerifier)
            .unwrap()
            .unwrap();
        let TimeoutOpportunity::Work { transaction, .. } = witness else {
            unreachable!()
        };
        producer
            .handle_incoming_tx(*transaction, &MultiVerifier)
            .unwrap();
        let block = producer.produce_block(&keys[0], 500).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(
            producer
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&address(&keys[1]))
                .unwrap()
                .consecutive_misses,
            1
        );
        assert_eq!(
            producer
                .world_state
                .read()
                .get_balance(&address(&keys[1]))
                .unwrap(),
            U256::from(123u64)
        );
        assert_eq!(
            producer
                .world_state
                .read()
                .get_validator_stake(&address(&keys[1]))
                .unwrap(),
            U256::from(75u64)
        );
        let make_follower = || {
            let store = Arc::new(MemoryDb::new());
            let node = setup(store.clone(), &keys, &sender, false);
            node.register_authority_pubkey(address(&keys[0]), keys[0].public_key().to_vec());
            (node, store)
        };
        for case in 0..5 {
            let (follower, store) = make_follower();
            let before = store.scan_prefix(b"").unwrap();
            let head = follower.chain_store.get_head_hash().unwrap();
            let root = follower.world_state.write().state_root().unwrap();
            let mut bad = block.clone();
            match case {
                0 => {
                    bad.system_transactions.pop();
                }
                1 => bad.system_transactions.last_mut().unwrap().tx_index = 0,
                2 => {
                    let last = bad.system_transactions.last().unwrap();
                    let mut proof = shell_core::TimeoutCertificate::from_system_transaction(
                        last,
                        last.tx_index,
                    )
                    .unwrap();
                    proof.signers[0].signature.data[0] ^= 1;
                    *bad.system_transactions.last_mut().unwrap() =
                        proof.system_transaction(last.tx_index).unwrap();
                }
                3 => {
                    let last = bad.system_transactions.last().unwrap();
                    let proof = shell_core::TimeoutCertificate::from_system_transaction(
                        last,
                        last.tx_index,
                    )
                    .unwrap();
                    bad.system_transactions
                        .push(proof.system_transaction(last.tx_index + 1).unwrap());
                }
                _ => {
                    bad.header.state_root = ShellHash::ZERO;
                    bad.proposer_seal = Some(keys[0].sign(bad.header.hash().as_bytes()).unwrap());
                }
            }
            assert!(
                follower.import_block(bad, &MultiVerifier).is_err(),
                "tamper case {case}"
            );
            assert_eq!(follower.chain_store.get_head_hash().unwrap(), head);
            assert_eq!(follower.world_state.write().state_root().unwrap(), root);
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
        let (follower, _) = make_follower();
        assert_eq!(follower.consensus.read().current_view(), 0);
        follower
            .import_block(block.clone(), &MultiVerifier)
            .unwrap();
        assert_eq!(
            follower.chain_store.get_head_hash().unwrap(),
            Some(block.hash())
        );
        assert_eq!(
            follower.world_state.write().state_root().unwrap(),
            block.header.state_root
        );
        assert_eq!(
            follower.world_state.read().load_offline_state().unwrap(),
            producer.world_state.read().load_offline_state().unwrap()
        );
    }
    #[test]
    fn canonical_offline_failed_publication_retries_without_double_miss_or_value() {
        use crate::node::tests::FailingBatchDb;
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(FailingBatchDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let witness = work(&sender);
        let vote = message(&node, &keys, &witness, 1, 112);
        node.handle_certified_timeout_vote_at(vote, 112, &MultiVerifier)
            .unwrap()
            .unwrap();
        let TimeoutOpportunity::Work { transaction, .. } = witness else {
            unreachable!()
        };
        node.handle_incoming_tx(*transaction, &MultiVerifier)
            .unwrap();
        let head = node.chain_store.get_head_hash().unwrap();
        let root = node.world_state.write().state_root().unwrap();
        store.arm_canonical_head_failure();
        assert!(node.produce_block(&keys[0], 500).is_err());
        assert_eq!(node.chain_store.get_head_hash().unwrap(), head);
        assert_eq!(node.world_state.write().state_root().unwrap(), root);
        assert_eq!(
            node.world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            0
        );
        assert!(node
            .world_state
            .read()
            .load_offline_state()
            .unwrap()
            .validators()
            .is_empty());
        store.clear_canonical_head_failure();
        let block = node.produce_block(&keys[0], 500).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(
            node.world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            1
        );
        assert_eq!(
            node.world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&address(&keys[1]))
                .unwrap()
                .consecutive_misses,
            1
        );
        assert_eq!(
            node.world_state
                .read()
                .get_balance(&Address::from([9; 32]))
                .unwrap(),
            U256::from(5u64)
        );
        assert_eq!(node.consensus.read().current_view(), 0);
    }
    #[test]
    fn canonical_offline_work_certificate_restores_transaction_after_rebuild() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let config = node.config.clone();
        let witness = work(&sender);
        let TimeoutOpportunity::Work { transaction, .. } = &witness else {
            unreachable!()
        };
        let hash = transaction.hash();
        let low = message(&node, &keys, &witness, 0, 112);
        node.handle_certified_timeout_vote_at(low, 112, &MultiVerifier)
            .unwrap();
        drop(node);
        let node = NodeBuilder::new(config.clone(), store.clone())
            .build()
            .unwrap()
            .0;
        node.recover_certified_timeout_view().unwrap();
        assert_eq!(node.consensus.read().current_view(), 0);
        assert!(
            node.tx_pool.is_empty(),
            "a partial vote is not a certificate"
        );
        let high = message(&node, &keys, &witness, 1, 112);
        node.handle_certified_timeout_vote_at(high, 112, &MultiVerifier)
            .unwrap()
            .unwrap();
        drop(node);
        let node = NodeBuilder::new(config.clone(), store.clone())
            .build()
            .unwrap()
            .0;
        let head = node.chain_store.get_head_hash().unwrap();
        let root = node.world_state.write().state_root().unwrap();
        for _ in 0..2 {
            node.recover_certified_timeout_view().unwrap();
            assert_eq!(node.consensus.read().current_view(), 1);
            assert!(node.tx_pool.contains(&hash));
            assert_eq!(node.tx_pool.len(), 1);
            assert_eq!(node.chain_store.get_head_hash().unwrap(), head);
            assert_eq!(node.world_state.write().state_root().unwrap(), root);
            assert_eq!(
                node.world_state
                    .read()
                    .get_nonce(&address(&sender))
                    .unwrap(),
                0
            );
        }
        let block = node.produce_block(&keys[0], 500).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].hash(), hash);
        assert!(!node.tx_pool.contains(&hash));
        assert_eq!(
            node.world_state
                .read()
                .get_balance(&Address::from([9; 32]))
                .unwrap(),
            U256::from(5)
        );
        assert_eq!(
            node.world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            1
        );
        drop(node);
        let node = NodeBuilder::new(config, store).build().unwrap().0;
        node.recover_certified_timeout_view().unwrap();
        assert_eq!(node.consensus.read().current_view(), 0);
        assert!(
            node.tx_pool.is_empty(),
            "committed work is not requeued at a new parent"
        );
        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(block.hash())
        );
        assert_eq!(
            node.world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            1
        );
    }
    #[test]
    fn canonical_offline_heartbeat_only_block_restores_durable_view_after_rebuild() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let config = node.config.clone();
        let vote = message(&node, &keys, &TimeoutOpportunity::Heartbeat, 1, 710);
        node.handle_certified_timeout_vote_at(vote, 710, &MultiVerifier)
            .unwrap()
            .unwrap();
        assert_eq!(node.consensus.read().current_view(), 0);
        let head = node.chain_store.get_head_hash().unwrap();
        drop(node);
        let node = NodeBuilder::new(config, store).build().unwrap().0;
        node.recover_certified_timeout_view().unwrap();
        assert_eq!(node.consensus.read().current_view(), 1);
        assert_eq!(node.chain_store.get_head_hash().unwrap(), head);
        assert!(node
            .world_state
            .read()
            .load_offline_state()
            .unwrap()
            .validators()
            .is_empty());
        let block = node.produce_block(&keys[0], 500).unwrap();
        assert!(block.transactions.is_empty());
        assert_eq!(block.system_transactions.len(), 1);
        assert_eq!(
            block.system_transactions[0].kind,
            shell_core::SystemTxKind::TimeoutEvidence
        );
        assert_eq!(block.system_transactions[0].tx_index, 0);
        assert_eq!(block.header.gas_used, 0);
        let follower = setup(Arc::new(MemoryDb::new()), &keys, &sender, false);
        follower.register_authority_pubkey(address(&keys[0]), keys[0].public_key().to_vec());
        let parent = follower.chain_store.get_head_block().unwrap().unwrap();
        let mut early = block.clone();
        early.transactions.clear();
        early.system_transactions.clear();
        early.header.timestamp = 699;
        assert!(follower
            .offline_plan_for_import(&parent.header, &early)
            .is_err());
        follower
            .import_block(block.clone(), &MultiVerifier)
            .unwrap();
        assert_eq!(
            follower.chain_store.get_head_hash().unwrap(),
            Some(block.hash())
        );
        assert_eq!(
            follower.world_state.write().state_root().unwrap(),
            block.header.state_root
        );
        for node in [&node, &follower] {
            let state = node.world_state.read();
            assert_eq!(
                state
                    .load_offline_state()
                    .unwrap()
                    .validator(&address(&keys[1]))
                    .unwrap()
                    .consecutive_misses,
                1
            );
            assert_eq!(
                state.get_balance(&address(&keys[1])).unwrap(),
                U256::from(123u64)
            );
            assert_eq!(
                state.get_validator_stake(&address(&keys[1])).unwrap(),
                U256::from(75u64)
            );
            assert_eq!(state.get_nonce(&address(&sender)).unwrap(), 0);
            assert_eq!(
                state.get_balance(&address(&sender)).unwrap(),
                U256::from(10_000_000u64)
            );
            assert_eq!(node.consensus.read().current_view(), 0);
            let receipts = node
                .chain_store
                .get_receipts(&block.hash())
                .unwrap()
                .unwrap();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].tx_hash, block.system_transactions[0].hash());
            assert_eq!(receipts[0].status, 1);
            assert_eq!(receipts[0].gas_used, 0);
        }
    }
    #[test]
    fn canonical_offline_historical_body_replay_uses_sealed_authorities_after_later_changes() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let node = setup(store.clone(), &keys, &sender, false);
        let witness = work(&sender);
        let vote = message(&node, &keys, &witness, 1, 112);
        node.handle_certified_timeout_vote_at(vote, 112, &MultiVerifier)
            .unwrap()
            .unwrap();
        let TimeoutOpportunity::Work { transaction, .. } = witness else {
            unreachable!()
        };
        node.handle_incoming_tx(*transaction, &MultiVerifier)
            .unwrap();
        let first = node.produce_block(&keys[0], 500).unwrap();
        let first_root = first.header.state_root;
        let mut config = node.config.clone();
        config.proposer_address = Some(address(&keys[1]));
        // This fixture uses a large enough configured equivocation reduction
        // to change a base weight of three after integer rounding.
        if let ConsensusEngineConfig::WPoa(ref mut poa) = config.consensus {
            poa.poa.slash_weight_bps = 5_000;
        }
        drop(node);
        let node = NodeBuilder::new(config, store.clone()).build().unwrap().0;
        node.handle_incoming_tx(signed(&sender, 1, 7, false), &MultiVerifier)
            .unwrap();
        let second = node.produce_block(&keys[1], 500).unwrap();
        assert_ne!(first_root, second.header.state_root);
        assert_eq!(
            node.world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            2
        );
        assert_eq!(
            node.world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&address(&keys[1]))
                .unwrap()
                .consecutive_misses,
            0
        );
        node.consensus.write().slash_authority(&address(&keys[1]));
        let effective = node.timeout_authorities();
        assert_ne!(effective, set(&keys));
        let before = store.scan_prefix(b"").unwrap();
        node.validate_legacy_backfill_witness(&first).unwrap();
        assert_eq!(node.timeout_authorities(), effective);
        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(second.hash())
        );
        assert_eq!(
            node.world_state.write().state_root().unwrap(),
            second.header.state_root
        );
        assert_eq!(
            node.world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            2
        );
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        // Exercise the same atomic body/witness entry and callback used by the
        // network response handler, including a legacy missing-witness record.
        assert!(first
            .header
            .witness_root
            .is_none_or(|r| r == ShellHash::ZERO));
        node.chain_store.delete_body(&first.hash()).unwrap();
        let witness_key = [b"w/".as_ref(), first.hash().as_bytes()].concat();
        store.delete(&witness_key).unwrap();
        assert!(!node.chain_store.has_body(&first.hash()).unwrap());
        assert!(!node.chain_store.has_witness_bundle(&first.hash()).unwrap());
        let pruned = store.scan_prefix(b"").unwrap();
        let mut bad = first.clone();
        bad.transactions[0].signature.data[0] ^= 1;
        assert!(node
            .chain_store
            .put_backfill_block_with_validation(&bad, true, |candidate| {
                node.validate_legacy_backfill_witness(candidate)
                    .map_err(|e| shell_storage::StorageError::InvalidInput(e.to_string()))
            })
            .is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), pruned);
        let calls = std::cell::Cell::new(0);
        node.chain_store
            .put_backfill_block_with_validation(&first, true, |candidate| {
                calls.set(calls.get() + 1);
                node.validate_legacy_backfill_witness(candidate)
                    .map_err(|e| shell_storage::StorageError::InvalidInput(e.to_string()))
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(
            node.chain_store.get_block_by_hash(&first.hash()).unwrap(),
            Some(first.clone())
        );
        assert!(node.chain_store.has_witness_bundle(&first.hash()).unwrap());
        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(second.hash())
        );
        assert_eq!(
            node.world_state.write().state_root().unwrap(),
            second.header.state_root
        );
        assert_eq!(node.timeout_authorities(), effective);
        let genesis = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let meta = shell_storage::SnapshotMetadata::new(
            1337,
            2,
            second.hash(),
            second.header.state_root,
            genesis,
        );
        let mut bytes = Vec::new();
        node.chain_store
            .export_snapshot(meta, std::io::Cursor::new(&mut bytes))
            .unwrap();
        let restored = Arc::new(MemoryDb::new());
        let chain = ChainStore::new(restored.clone());
        chain
            .put_chain_config(&node.chain_store.get_chain_config().unwrap().unwrap())
            .unwrap();
        chain
            .import_snapshot(std::io::Cursor::new(bytes), 1337, &genesis)
            .unwrap();
        let state = WorldState::at_root(restored, &second.header.state_root).unwrap();
        assert_eq!(state.load_offline_authorities().unwrap(), set(&keys));
        assert_eq!(
            state.load_offline_state().unwrap(),
            node.world_state.read().load_offline_state().unwrap()
        );
        assert_eq!(state.get_nonce(&address(&sender)).unwrap(), 2);
    }
    #[test]
    fn canonical_offline_preferred_fork_replays_parent_weights_without_erasing_later_penalty() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let seed = setup(store.clone(), &keys, &sender, false);
        let witness = work(&sender);
        seed.handle_certified_timeout_vote_at(
            message(&seed, &keys, &witness, 1, 112),
            112,
            &MultiVerifier,
        )
        .unwrap()
        .unwrap();
        let TimeoutOpportunity::Work { transaction, .. } = witness else {
            unreachable!()
        };
        seed.handle_incoming_tx(*transaction, &MultiVerifier)
            .unwrap();
        seed.dev_state.write().next_block_timestamp = Some(112);
        let common = seed.produce_block(&keys[0], 500).unwrap();
        let mut local_config = seed.config.clone();
        local_config.proposer_address = Some(address(&keys[1]));
        if let ConsensusEngineConfig::WPoa(ref mut c) = local_config.consensus {
            c.poa.slash_weight_bps = 5_000;
        }
        drop(seed);
        let local = NodeBuilder::new(local_config, store.clone())
            .build()
            .unwrap()
            .0;
        let remote = setup(Arc::new(MemoryDb::new()), &keys, &sender, false);
        for node in [&local, &remote] {
            for key in &keys {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
        }
        remote.import_block(common.clone(), &MultiVerifier).unwrap();
        local
            .handle_incoming_tx(signed(&sender, 1, 7, false), &MultiVerifier)
            .unwrap();
        local.dev_state.write().next_block_timestamp = Some(116);
        let old = local.produce_block(&keys[1], 500).unwrap();
        let transaction = signed(&sender, 1, 11, false);
        let witness = TimeoutOpportunity::Work {
            transaction: Box::new(transaction.clone()),
            admitted_at: 114,
        };
        let admitted = admit_timeout_opportunity(
            &remote.chain_store,
            &common.header,
            0,
            &set(&keys),
            &witness,
            124,
            &MultiVerifier,
        )
        .unwrap();
        let vote = TimeoutVoteMessage {
            vote: TimeoutVote {
                context: admitted.context.clone(),
                validator: address(&keys[1]),
                signature: keys[1]
                    .sign(&admitted.context.signing_message(&address(&keys[1])))
                    .unwrap(),
            },
            public_key: keys[1].public_key().to_vec(),
            opportunity: witness,
        };
        remote
            .handle_certified_timeout_vote_at(vote, 124, &MultiVerifier)
            .unwrap()
            .unwrap();
        remote
            .handle_incoming_tx(transaction, &MultiVerifier)
            .unwrap();
        remote.dev_state.write().next_block_timestamp = Some(124);
        let side = remote.produce_block(&keys[0], 500).unwrap();
        local.consensus.write().slash_authority(&address(&keys[1]));
        let penalties = local.consensus.read().penalty_state();
        assert_eq!(
            local.timeout_authorities(),
            vec![(address(&keys[0]), 1), (address(&keys[1]), 2)]
        );
        assert!(
            WorldState::validate_snapshot_nodes(store.as_ref(), side.header.state_root).is_err()
        );
        let before = store.scan_prefix(b"").unwrap();
        let mut bad_root = side.clone();
        bad_root.header.state_root = ShellHash::from([0xab; 32]);
        bad_root.proposer_seal = Some(keys[0].sign(bad_root.header.hash().as_bytes()).unwrap());
        let mut bad_signature = side.clone();
        let last = bad_signature.system_transactions.last_mut().unwrap();
        let mut c =
            shell_core::TimeoutCertificate::from_system_transaction(last, last.tx_index).unwrap();
        c.signers[0].signature.data[0] ^= 1;
        *last = c.system_transaction(last.tx_index).unwrap();
        let mut self_authorized = side.clone();
        let last = self_authorized.system_transactions.last_mut().unwrap();
        let mut c =
            shell_core::TimeoutCertificate::from_system_transaction(last, last.tx_index).unwrap();
        let fake_set = vec![(address(&keys[0]), 1)];
        c.context.authority_set_hash =
            shell_consensus::timeout::timeout_authority_set_hash(&fake_set).unwrap();
        c.context.proposer = address(&keys[0]);
        c.signers = vec![shell_core::BlockSignerEvidence {
            address: address(&keys[0]),
            public_key: keys[0].public_key().to_vec(),
            signature: keys[0]
                .sign(&c.context.signing_message(&address(&keys[0])))
                .unwrap(),
        }];
        shell_consensus::timeout::verify_timeout_certificate(
            &c,
            &c.context,
            &fake_set,
            &MultiVerifier,
        )
        .unwrap();
        *last = c.system_transaction(last.tx_index).unwrap();
        for invalid in [bad_root, bad_signature, self_authorized] {
            assert!(local.import_block(invalid, &MultiVerifier).is_err());
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
            assert_eq!(
                local.world_state.write().state_root().unwrap(),
                old.header.state_root
            );
            assert_eq!(local.consensus.read().penalty_state(), penalties);
        }
        local.import_block(side.clone(), &MultiVerifier).unwrap();
        assert!(
            WorldState::validate_snapshot_nodes(store.as_ref(), side.header.state_root).is_err()
        );
        let mut config = remote.config.clone();
        config.proposer_address = Some(address(&keys[1]));
        let remote_store = remote.store.clone();
        drop(remote);
        let remote = NodeBuilder::new(config, remote_store).build().unwrap().0;
        remote
            .handle_incoming_tx(signed(&sender, 2, 13, false), &MultiVerifier)
            .unwrap();
        remote.dev_state.write().next_block_timestamp = Some(126);
        let tip = remote.produce_block(&keys[1], 500).unwrap();
        local.import_block(tip.clone(), &MultiVerifier).unwrap();
        // Retain a genuine pending timeout on the abandoned parent. Adoption
        // must reset its volatile view and not execute that unrelated miss.
        let witness = TimeoutOpportunity::Work {
            transaction: Box::new(signed(&sender, 2, 1, false)),
            admitted_at: 118,
        };
        let admitted = admit_timeout_opportunity(
            &local.chain_store,
            &old.header,
            0,
            &local.timeout_authorities(),
            &witness,
            128,
            &MultiVerifier,
        )
        .unwrap();
        let vote = TimeoutVoteMessage {
            vote: TimeoutVote {
                context: admitted.context.clone(),
                validator: address(&keys[1]),
                signature: keys[1]
                    .sign(&admitted.context.signing_message(&address(&keys[1])))
                    .unwrap(),
            },
            public_key: keys[1].public_key().to_vec(),
            opportunity: witness,
        };
        local
            .handle_certified_timeout_vote_at(vote, 128, &MultiVerifier)
            .unwrap()
            .unwrap();
        local.recover_certified_timeout_view().unwrap();
        assert_eq!(local.consensus.read().current_view(), 1);

        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
        assert_eq!(
            local.world_state.write().state_root().unwrap(),
            old.header.state_root
        );
        for key in &keys {
            let payload = shell_consensus::Attestation::signing_message(
                1337,
                &side.hash(),
                &tip.hash(),
                3,
                0,
            );
            let signature = key.sign(&payload).unwrap();
            let attestation = shell_consensus::Attestation::new(
                1337,
                side.hash(),
                tip.hash(),
                3,
                address(key),
                0,
                signature.data,
            );
            local
                .handle_attestation(attestation, &MultiVerifier)
                .unwrap();
        }
        let plan = local.preferred_fork_plan().unwrap().unwrap();
        local.adopt_preferred_fork(&plan).unwrap();
        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(tip.hash()));
        assert_eq!(
            local.chain_store.get_block_hash_by_number(2).unwrap(),
            Some(side.hash())
        );
        assert_eq!(
            local.world_state.write().state_root().unwrap(),
            tip.header.state_root
        );
        assert_eq!(
            local.world_state.read().load_offline_state().unwrap(),
            remote.world_state.read().load_offline_state().unwrap()
        );
        assert_eq!(
            local
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&address(&keys[1]))
                .unwrap()
                .consecutive_misses,
            0
        );
        assert_eq!(
            local
                .world_state
                .read()
                .get_balance(&Address::from([9; 32]))
                .unwrap(),
            U256::from(29u64)
        );
        assert_eq!(
            local
                .world_state
                .read()
                .get_nonce(&address(&sender))
                .unwrap(),
            3
        );
        assert_eq!(local.consensus.read().current_view(), 0);
        local.recover_certified_timeout_view().unwrap();
        assert_eq!(local.consensus.read().current_view(), 0);
        assert_eq!(local.chain_store.get_finalized_number().unwrap(), Some(3));
        let middle = WorldState::at_root(store.clone(), &side.header.state_root).unwrap();
        assert_eq!(
            middle
                .load_offline_state()
                .unwrap()
                .validator(&address(&keys[1]))
                .unwrap()
                .consecutive_misses,
            2
        );
        assert_eq!(local.consensus.read().penalty_state(), penalties);
        assert_eq!(
            local.chain_store.get_receipts(&tip.hash()).unwrap(),
            remote.chain_store.get_receipts(&tip.hash()).unwrap()
        );
    }
    #[test]
    fn canonical_offline_activation_fork_uses_an_accepted_same_parent_slot_anchor() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let sender = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let seed = setup(store.clone(), &keys, &sender, false);
        let mut cfg = seed.config.clone();
        cfg.proposer_address = Some(address(&keys[1]));
        if let ConsensusEngineConfig::WPoa(ref mut c) = cfg.consensus {
            c.poa.slash_weight_bps = 5_000;
        }
        drop(seed);
        let local = NodeBuilder::new(cfg, store.clone()).build().unwrap().0;
        local
            .handle_incoming_tx(signed(&sender, 0, 7, false), &MultiVerifier)
            .unwrap();
        local.dev_state.write().next_block_timestamp = Some(112);
        let old = local.produce_block(&keys[1], 500).unwrap();
        let remote = setup(Arc::new(MemoryDb::new()), &keys, &sender, false);
        let witness = work(&sender);
        remote
            .handle_certified_timeout_vote_at(
                message(&remote, &keys, &witness, 1, 112),
                112,
                &MultiVerifier,
            )
            .unwrap()
            .unwrap();
        let TimeoutOpportunity::Work { transaction, .. } = witness else {
            unreachable!()
        };
        remote
            .handle_incoming_tx(*transaction, &MultiVerifier)
            .unwrap();
        remote.dev_state.write().next_block_timestamp = Some(112);
        let side = remote.produce_block(&keys[0], 500).unwrap();
        assert_eq!(old.header.parent_hash, side.header.parent_hash);
        for key in &keys {
            local.register_authority_pubkey(address(key), key.public_key().to_vec());
        }
        local.consensus.write().slash_authority(&address(&keys[1]));
        let penalties = local.consensus.read().penalty_state();
        local.import_block(side.clone(), &MultiVerifier).unwrap();
        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
        for key in &keys {
            let payload = shell_consensus::Attestation::signing_message(
                1337,
                &side.header.parent_hash,
                &side.hash(),
                1,
                0,
            );
            let sig = key.sign(&payload).unwrap();
            local
                .handle_attestation(
                    shell_consensus::Attestation::new(
                        1337,
                        side.header.parent_hash,
                        side.hash(),
                        1,
                        address(key),
                        0,
                        sig.data,
                    ),
                    &MultiVerifier,
                )
                .unwrap();
        }
        let plan = local.preferred_fork_plan().unwrap().unwrap();
        local.adopt_preferred_fork(&plan).unwrap();
        assert_eq!(
            local.chain_store.get_head_hash().unwrap(),
            Some(side.hash())
        );
        assert_eq!(
            local.world_state.write().state_root().unwrap(),
            side.header.state_root
        );
        assert_eq!(
            local
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&address(&keys[1]))
                .unwrap()
                .consecutive_misses,
            1
        );
        assert_eq!(
            local
                .world_state
                .read()
                .get_balance(&Address::from([9; 32]))
                .unwrap(),
            U256::from(5u64)
        );
        assert_eq!(local.consensus.read().penalty_state(), penalties);
        assert_eq!(local.chain_store.get_finalized_number().unwrap(), Some(1));
    }
    #[test]
    fn canonical_offline_one_hundred_real_assigned_misses_suspend_at_common_epoch() {
        actual_suspension_flow(false);
    }
    #[test]
    fn canonical_offline_recovery_preserves_inherited_economic_reduction() {
        actual_suspension_flow(true);
    }
    fn actual_suspension_flow(reduced: bool) {
        let keys = [
            MlDsaSigner::generate(),
            MlDsaSigner::generate(),
            MlDsaSigner::generate(),
        ];
        let sender = MlDsaSigner::generate();
        let authorities = keys.iter().map(address).collect::<Vec<_>>();
        use crate::node::tests::FailingBatchDb;
        let producer_store = Arc::new(FailingBatchDb::new());
        let mut producer = event_node(
            producer_store.clone(),
            authorities.clone(),
            vec![1, if reduced { 2 } else { 1 }, 3],
            0,
            &sender,
            100,
        );
        let follower_store = Arc::new(FailingBatchDb::new());
        let follower = event_node(
            follower_store.clone(),
            authorities.clone(),
            vec![1, if reduced { 2 } else { 1 }, 3],
            0,
            &sender,
            100,
        );
        for node in [&producer, &follower] {
            for key in &keys {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
        }
        let absent = address(&keys[1]);
        if reduced {
            // A shared accepted pre-anchor economic control. The real signed
            // history commits effective 1 against native base 2; this does not
            // create or claim a new canonical misconduct event.
            let penalties = shell_consensus::PenaltyState {
                slashed: vec![absent],
                reductions: vec![(absent, 1)],
            };
            for node in [&producer, &follower] {
                node.consensus.write().restore_penalty_state(&penalties);
                let mut lifecycle = node.challenge_lifecycle.lock();
                lifecycle.penalties = Some(penalties.clone());
                lifecycle.persist(node.store.as_ref()).unwrap();
            }
        }
        let genesis = producer
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let chain_config = producer.chain_store.get_chain_config().unwrap().unwrap();
        let mut pending_snapshot = None;
        let mut masked_snapshot = None;
        for number in 1..=501 {
            let parent = producer.chain_store.get_head_block().unwrap().unwrap();
            let (proposer, mut timestamp) = if number < 500 {
                (
                    if number % 5 == 0 { 0 } else { 2 },
                    parent.header.timestamp + 600,
                )
            } else {
                (
                    if number % 4 == 0 { 0 } else { 2 },
                    parent.header.timestamp + 600,
                )
            };
            if number < 500 && number % 5 == 1 {
                timestamp += 10;
                let witness = TimeoutOpportunity::Heartbeat;
                let set = vec![(address(&keys[0]), 1), (absent, 1), (address(&keys[2]), 3)];
                let admitted = admit_timeout_opportunity(
                    &producer.chain_store,
                    &parent.header,
                    0,
                    &set,
                    &witness,
                    timestamp,
                    &MultiVerifier,
                )
                .unwrap();
                for voter in [0, 2] {
                    let vote = TimeoutVoteMessage {
                        vote: TimeoutVote {
                            context: admitted.context.clone(),
                            validator: address(&keys[voter]),
                            signature: keys[voter]
                                .sign(&admitted.context.signing_message(&address(&keys[voter])))
                                .unwrap(),
                        },
                        public_key: keys[voter].public_key().to_vec(),
                        opportunity: witness.clone(),
                    };
                    let result = producer
                        .handle_certified_timeout_vote_at(vote, timestamp, &MultiVerifier)
                        .unwrap();
                    assert_eq!(result.is_some(), voter == 2);
                }
            }
            producer.config.proposer_address = Some(address(&keys[proposer]));
            producer.dev_state.write().next_block_timestamp = Some(timestamp);
            if number == 499 {
                let before = producer_store.scan_prefix(b"").unwrap();
                let head = producer.chain_store.get_head_hash().unwrap();
                producer_store.arm_canonical_head_failure();
                assert!(producer.produce_block(&keys[proposer], 500).is_err());
                assert_eq!(producer_store.scan_prefix(b"").unwrap(), before);
                assert_eq!(producer.chain_store.get_head_hash().unwrap(), head);
                assert!(producer
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&absent));
                producer_store.clear_canonical_head_failure();
                producer.dev_state.write().next_block_timestamp = Some(timestamp);
            }
            let block = producer.produce_block(&keys[proposer], 500).unwrap();
            assert_eq!(block.number(), number);
            follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            assert_eq!(
                follower.world_state.write().state_root().unwrap(),
                block.header.state_root
            );
            assert_eq!(
                producer.world_state.read().load_offline_state().unwrap(),
                follower.world_state.read().load_offline_state().unwrap()
            );
            if [491, 495, 496, 499, 500, 501].contains(&number) {
                let ws = producer.world_state.read();
                let ledger = ws.load_offline_state().unwrap();
                let entry = ledger.validator(&absent).unwrap();
                assert_eq!(
                    entry.consecutive_misses,
                    if number < 496 { 99 } else { 100 }
                );
                assert_eq!(
                    entry.suspend_at_epoch,
                    if number < 496 { None } else { Some(50) }
                );
                assert_eq!(
                    ledger
                        .validator(&address(&keys[0]))
                        .unwrap()
                        .consecutive_misses,
                    0
                );
                for (i, key) in keys.iter().enumerate() {
                    assert_eq!(ws.get_balance(&address(key)).unwrap(), U256::from(123u64));
                    assert_eq!(
                        ws.get_validator_stake(&address(key)).unwrap(),
                        U256::from(if i == 2 {
                            75u64
                        } else if reduced && i == 1 {
                            50
                        } else {
                            25
                        })
                    );
                    assert_eq!(
                        ws.get_validator_weight(&address(key)).unwrap(),
                        if i == 2 {
                            3
                        } else if reduced && i == 1 {
                            2
                        } else {
                            1
                        }
                    );
                }
                assert_eq!(
                    producer
                        .consensus
                        .read()
                        .validator_weights()
                        .contains_key(&absent),
                    number < 499
                );
                assert_eq!(
                    follower
                        .consensus
                        .read()
                        .validator_weights()
                        .contains_key(&absent),
                    number < 499
                );
                eprintln!(
                    "native offline boundary height={number} misses={} pending={:?}",
                    entry.consecutive_misses, entry.suspend_at_epoch
                );
            }
            if number == 496 {
                let meta = shell_storage::SnapshotMetadata::new(
                    1337,
                    number,
                    block.hash(),
                    block.header.state_root,
                    genesis,
                );
                let mut bytes = Vec::new();
                producer
                    .chain_store
                    .export_snapshot(meta, std::io::Cursor::new(&mut bytes))
                    .unwrap();
                pending_snapshot = Some((bytes, producer.config.clone()));
            }
            if reduced && number == 500 {
                let mut bytes = Vec::new();
                producer
                    .chain_store
                    .export_snapshot(
                        shell_storage::SnapshotMetadata::new(
                            1337,
                            number,
                            block.hash(),
                            block.header.state_root,
                            genesis,
                        ),
                        std::io::Cursor::new(&mut bytes),
                    )
                    .unwrap();
                masked_snapshot = Some((bytes, producer.config.clone()));
            }
            if number == 499 {
                let config = producer.config.clone();
                drop(producer);
                producer = NodeBuilder::new(config, producer_store.clone())
                    .build()
                    .unwrap()
                    .0;
                for key in &keys {
                    producer.register_authority_pubkey(address(key), key.public_key().to_vec());
                }
                assert!(!producer
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&absent));
            }
        }
        let recovery_fork_prefix = producer_store.scan_prefix(b"").unwrap();
        let recovery_fork_config = producer.config.clone();
        assert_eq!(
            producer.timeout_authorities(),
            vec![(address(&keys[0]), 1), (address(&keys[2]), 3)]
        );
        assert_eq!(
            producer.consensus.read().poa_config().authority_weights,
            vec![1, if reduced { 2 } else { 1 }, 3]
        );
        if reduced {
            for (height, (bytes, config)) in [
                (496, pending_snapshot.take().unwrap()),
                (500, masked_snapshot.take().unwrap()),
            ] {
                let db = Arc::new(MemoryDb::new());
                let chain = ChainStore::new(db.clone());
                chain.put_chain_config(&chain_config).unwrap();
                chain
                    .import_snapshot(std::io::Cursor::new(bytes), 1337, &genesis)
                    .unwrap();
                let restored = NodeBuilder::new(config, db.clone()).build().unwrap().0;
                for key in &keys {
                    restored.register_authority_pubkey(address(key), key.public_key().to_vec());
                }
                assert_eq!(restored.head_number(), height);
                assert_eq!(
                    restored
                        .world_state
                        .read()
                        .get_validator_weight(&absent)
                        .unwrap(),
                    2
                );
                assert_eq!(
                    restored
                        .world_state
                        .read()
                        .get_validator_stake(&absent)
                        .unwrap(),
                    U256::from(50)
                );
                assert_eq!(
                    restored.world_state.read().get_balance(&absent).unwrap(),
                    U256::from(123)
                );
                let ledger = restored.world_state.read().load_offline_state().unwrap();
                assert_eq!(ledger.validator(&absent).unwrap().consecutive_misses, 100);
                assert_eq!(
                    ledger.validator(&absent).unwrap().suspend_at_epoch,
                    Some(50)
                );
                assert_eq!(
                    restored.consensus.read().poa_config().authority_weights,
                    vec![1, 2, 3]
                );
                assert_eq!(
                    restored.timeout_authorities(),
                    if height == 496 {
                        vec![(address(&keys[0]), 1), (absent, 1), (address(&keys[2]), 3)]
                    } else {
                        vec![(address(&keys[0]), 1), (address(&keys[2]), 3)]
                    }
                );
                assert_eq!(
                    restored.consensus.read().penalty_state().reductions,
                    vec![(absent, 1)]
                );
                for number in height + 1..=501 {
                    let block = producer
                        .chain_store
                        .get_block_by_number(number)
                        .unwrap()
                        .unwrap();
                    restored
                        .import_block(block.clone(), &MultiVerifier)
                        .unwrap();
                    assert_eq!(
                        restored.world_state.write().state_root().unwrap(),
                        block.header.state_root
                    );
                }
                let rows = db.scan_prefix(b"").unwrap();
                recovery_registry_fork(&rows, &restored.config, &keys, &sender, false, false, 2);
            }
            for certified in [false, true] {
                for reweighted in [false, true] {
                    recovery_registry_fork(
                        &recovery_fork_prefix,
                        &recovery_fork_config,
                        &keys,
                        &sender,
                        certified,
                        reweighted,
                        2,
                    );
                }
            }
            return;
        }
        let before = producer_store.scan_prefix(b"").unwrap();
        let head = producer.chain_store.get_head_hash().unwrap();
        producer.config.proposer_address = Some(absent);
        assert!(producer.produce_block(&keys[1], 500).is_err());
        assert_eq!(producer_store.scan_prefix(b"").unwrap(), before);
        assert_eq!(producer.chain_store.get_head_hash().unwrap(), head);
        let parent = producer.chain_store.get_head_block().unwrap().unwrap();
        let witness = TimeoutOpportunity::Heartbeat;
        let observed = parent.header.timestamp + 610;
        let admitted = admit_timeout_opportunity(
            &producer.chain_store,
            &parent.header,
            0,
            &producer.timeout_authorities(),
            &witness,
            observed,
            &MultiVerifier,
        )
        .unwrap();
        let vote = TimeoutVoteMessage {
            vote: TimeoutVote {
                context: admitted.context.clone(),
                validator: absent,
                signature: keys[1]
                    .sign(&admitted.context.signing_message(&absent))
                    .unwrap(),
            },
            public_key: keys[1].public_key().to_vec(),
            opportunity: witness,
        };
        assert!(producer
            .handle_certified_timeout_vote_at(vote, observed, &MultiVerifier)
            .is_err());
        let payload = shell_consensus::Attestation::signing_message(
            1337,
            &parent.header.parent_hash,
            &parent.hash(),
            501,
            0,
        );
        let signature = keys[1].sign(&payload).unwrap();
        assert!(producer
            .handle_attestation(
                shell_consensus::Attestation::new(
                    1337,
                    parent.header.parent_hash,
                    parent.hash(),
                    501,
                    absent,
                    0,
                    signature.data
                ),
                &MultiVerifier
            )
            .is_err());
        assert_eq!(producer_store.scan_prefix(b"").unwrap(), before);
        let follower_before = follower_store.scan_prefix(b"").unwrap();
        let mut forged = parent.clone();
        forged.header.parent_hash = parent.hash();
        forged.header.number = 502;
        forged.header.timestamp += 600;
        forged.header.proposer = absent;
        forged.proposer_seal = Some(keys[1].sign(forged.header.hash().as_bytes()).unwrap());
        assert!(follower.import_block(forged, &MultiVerifier).is_err());
        assert_eq!(follower_store.scan_prefix(b"").unwrap(), follower_before);
        // Restore the real pending-threshold snapshot twice. Returning activity
        // before the boundary resets the counter but must retain suspension.
        let (bytes, config) = pending_snapshot.unwrap();
        let restore = |bytes: &[u8], config: NodeConfig| {
            let db = Arc::new(MemoryDb::new());
            let chain = ChainStore::new(db.clone());
            chain.put_chain_config(&chain_config).unwrap();
            chain
                .import_snapshot(std::io::Cursor::new(bytes), 1337, &genesis)
                .unwrap();
            let node = NodeBuilder::new(config, db).build().unwrap().0;
            for key in &keys {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
            node
        };
        let mut returning = restore(&bytes, config.clone());
        let returning_follower = restore(&bytes, config.clone());
        assert_eq!(
            returning
                .chain_store
                .get_head_block()
                .unwrap()
                .unwrap()
                .number(),
            496
        );
        assert!(returning
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));
        let parent = returning.chain_store.get_head_block().unwrap().unwrap();
        let set = vec![(address(&keys[0]), 1), (absent, 1), (address(&keys[2]), 3)];
        for view in 0..2 {
            let observed = parent.header.timestamp + 610 + view * 10;
            let admitted = admit_timeout_opportunity(
                &returning.chain_store,
                &parent.header,
                view,
                &set,
                &TimeoutOpportunity::Heartbeat,
                observed,
                &MultiVerifier,
            )
            .unwrap();
            for voter in [1, 2] {
                let vote = TimeoutVoteMessage {
                    vote: TimeoutVote {
                        context: admitted.context.clone(),
                        validator: address(&keys[voter]),
                        signature: keys[voter]
                            .sign(&admitted.context.signing_message(&address(&keys[voter])))
                            .unwrap(),
                    },
                    public_key: keys[voter].public_key().to_vec(),
                    opportunity: TimeoutOpportunity::Heartbeat,
                };
                returning
                    .handle_certified_timeout_vote_at(vote, observed, &MultiVerifier)
                    .unwrap();
            }
            returning.recover_certified_timeout_view().unwrap();
            assert_eq!(returning.consensus.read().current_view(), view + 1);
        }
        returning.config.proposer_address = Some(absent);
        returning.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 620);
        let block = returning.produce_block(&keys[1], 500).unwrap();
        returning_follower
            .import_block(block.clone(), &MultiVerifier)
            .unwrap();
        assert_eq!(
            returning
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&absent)
                .unwrap()
                .consecutive_misses,
            0
        );
        assert_eq!(
            returning
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&absent)
                .unwrap()
                .suspend_at_epoch,
            Some(50)
        );
        assert!(returning
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));
        for number in 498..=500 {
            let parent = returning.chain_store.get_head_block().unwrap().unwrap();
            let who = if number == 500 { 0 } else { 2 };
            returning.config.proposer_address = Some(address(&keys[who]));
            returning.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 600);
            let block = returning.produce_block(&keys[who], 500).unwrap();
            returning_follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            assert_eq!(
                returning_follower.world_state.write().state_root().unwrap(),
                block.header.state_root
            );
        }
        assert!(!returning
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));
        assert!(!returning_follower
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));
        let tip = returning.chain_store.get_head_block().unwrap().unwrap();
        let mut bytes = Vec::new();
        returning
            .chain_store
            .export_snapshot(
                shell_storage::SnapshotMetadata::new(
                    1337,
                    500,
                    tip.hash(),
                    tip.header.state_root,
                    genesis,
                ),
                std::io::Cursor::new(&mut bytes),
            )
            .unwrap();
        let restored = restore(&bytes, config);
        assert!(!restored
            .consensus
            .read()
            .validator_weights()
            .contains_key(&absent));
        assert_eq!(
            restored
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&absent)
                .unwrap()
                .consecutive_misses,
            0
        );
        assert_eq!(
            restored
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&absent)
                .unwrap()
                .suspend_at_epoch,
            Some(50)
        );
        // Continue the actual suspension history through signed native
        // governance, publication rollback, next epoch and a real B proposal.
        let committee = producer.timeout_authorities();
        let committee_hash = shell_core::timeout_authority_set_hash(&committee).unwrap();
        let recovery_call = || {
            let mut bytes = shell_pqvm::system_contracts::RECOVER_VALIDATOR_SELECTOR.to_vec();
            bytes.extend_from_slice(absent.as_bytes());
            bytes.extend_from_slice(&[0; 31]);
            bytes.push(50);
            bytes.extend_from_slice(committee_hash.as_bytes());
            Bytes::from(bytes)
        };
        let mut pending_recovery_snapshot = None;
        let mut minority_root = None;
        for number in 502..=511 {
            if number == 502 {
                for (nonce, who) in [(0, 0usize), (1, 2usize)] {
                    let mut funding = signed(&sender, nonce, 1_000_000, false);
                    funding.tx.to = Some(address(&keys[who]));
                    funding.signature = sender
                        .sign(funding.sender_signing_hash().as_bytes())
                        .unwrap();
                    producer
                        .handle_incoming_tx(funding, &MultiVerifier)
                        .unwrap();
                }
            }
            if number == 503 || number == 504 {
                let who = if number == 503 { 0 } else { 2 };
                let mut vote = signed(&keys[who], 0, 0, false);
                vote.tx.to = Some(shell_storage::validator_registry_addr());
                vote.tx.data = recovery_call();
                vote.signature = keys[who]
                    .sign(vote.sender_signing_hash().as_bytes())
                    .unwrap();
                producer.handle_incoming_tx(vote, &MultiVerifier).unwrap();
            }
            let parent = producer.chain_store.get_head_block().unwrap().unwrap();
            let who = if number < 510 {
                if number % 4 == 0 {
                    0
                } else {
                    2
                }
            } else if number == 510 {
                0
            } else {
                1
            };
            producer.config.proposer_address = Some(address(&keys[who]));
            producer.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 600);
            if number == 504 {
                let before = producer_store.scan_prefix(b"").unwrap();
                producer_store.arm_canonical_head_failure();
                assert!(producer.produce_block(&keys[who], 500).is_err());
                assert_eq!(producer_store.scan_prefix(b"").unwrap(), before);
                assert_eq!(
                    producer
                        .world_state
                        .read()
                        .load_offline_state()
                        .unwrap()
                        .validator(&absent)
                        .unwrap()
                        .recover_at_epoch,
                    None
                );
                producer_store.clear_canonical_head_failure();
                producer.dev_state.write().next_block_timestamp =
                    Some(parent.header.timestamp + 600);
            }
            let block = producer.produce_block(&keys[who], 500).unwrap();
            follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            assert_eq!(
                follower.world_state.write().state_root().unwrap(),
                block.header.state_root
            );
            let ledger = producer.world_state.read().load_offline_state().unwrap();
            assert_eq!(
                follower.world_state.read().load_offline_state().unwrap(),
                ledger
            );
            let entry = ledger.validator(&absent).unwrap();
            assert_eq!(
                entry.recover_at_epoch,
                if (504..510).contains(&number) {
                    Some(51)
                } else {
                    None
                }
            );
            assert_eq!(
                entry.suspend_at_epoch,
                if number < 510 { Some(50) } else { None }
            );
            assert_eq!(entry.consecutive_misses, if number < 510 { 100 } else { 0 });
            assert_eq!(
                producer
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&absent),
                number >= 509
            );
            assert_eq!(
                follower
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&absent),
                number >= 509
            );
            if number == 503 {
                minority_root = Some(block.header.state_root);
            }
            if number == 504 {
                let historic =
                    WorldState::at_root(producer_store.clone(), &minority_root.unwrap()).unwrap();
                assert_eq!(
                    historic
                        .load_offline_state()
                        .unwrap()
                        .validator(&absent)
                        .unwrap()
                        .recover_at_epoch,
                    None
                );
                let mut bytes = Vec::new();
                producer
                    .chain_store
                    .export_snapshot(
                        shell_storage::SnapshotMetadata::new(
                            1337,
                            number,
                            block.hash(),
                            block.header.state_root,
                            genesis,
                        ),
                        std::io::Cursor::new(&mut bytes),
                    )
                    .unwrap();
                let pending = restore(&bytes, producer.config.clone());
                assert!(!pending
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&absent));
                assert_eq!(
                    pending.world_state.read().load_offline_state().unwrap(),
                    ledger
                );
                pending_recovery_snapshot = Some(bytes);
            }
            if number == 509 {
                let config = producer.config.clone();
                drop(producer);
                producer = NodeBuilder::new(config, producer_store.clone())
                    .build()
                    .unwrap()
                    .0;
                for key in &keys {
                    producer.register_authority_pubkey(address(key), key.public_key().to_vec());
                }
                assert!(producer
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&absent));
            }
            if (503..=504).contains(&number) {
                let receipts = producer
                    .chain_store
                    .get_receipts(&block.hash())
                    .unwrap()
                    .unwrap();
                assert_eq!(block.transactions.len(), 1);
                assert_eq!(receipts[0].status, 1);
                assert_eq!(
                    producer
                        .world_state
                        .read()
                        .get_nonce(&address(&keys[if number == 503 { 0 } else { 2 }]))
                        .unwrap(),
                    1
                );
            }
        }
        assert!(pending_recovery_snapshot.is_some());
        for node in [&producer, &follower] {
            let state = node.world_state.read();
            assert_eq!(state.get_balance(&absent).unwrap(), U256::from(123));
            assert_eq!(state.get_validator_stake(&absent).unwrap(), U256::from(25));
            assert_eq!(state.get_validator_weight(&absent).unwrap(), 1);
            assert_eq!(
                node.consensus.read().poa_config().authority_weights,
                vec![1, 1, 3]
            );
        }
        for certified in [false, true] {
            for reweighted in [false, true] {
                recovery_registry_fork(
                    &recovery_fork_prefix,
                    &recovery_fork_config,
                    &keys,
                    &sender,
                    certified,
                    reweighted,
                    1,
                );
            }
        }
    }
    // Continue the genuine suspension prefix in independent stores. Native
    // recovery changes participation, while historical economic input and a
    // later observer penalty remain separate.
    fn recovery_registry_fork(
        prefix: &[(Vec<u8>, Vec<u8>)],
        config: &NodeConfig,
        keys: &[MlDsaSigner; 3],
        sender: &MlDsaSigner,
        certified: bool,
        reweighted: bool,
        prior_base: u64,
    ) {
        use crate::node::tests::FailingBatchDb;
        let members = keys.iter().map(address).collect::<Vec<_>>();
        let zeroed = prior_base == 2 && reweighted;
        let target = if zeroed { 521 } else { 511 };
        let expected_base = if zeroed {
            1
        } else if reweighted {
            2
        } else {
            prior_base
        };

        let build = |mut config: NodeConfig, observer: bool| {
            let db = Arc::new(FailingBatchDb::new());
            for (key, value) in prefix {
                db.put(key, value).unwrap();
            }
            if observer {
                if let ConsensusEngineConfig::WPoa(ref mut c) = config.consensus {
                    c.poa.slash_weight_bps = 5_000;
                }
            }
            let node = NodeBuilder::new(config, db.clone()).build().unwrap().0;
            for key in keys {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
            assert_eq!(node.head_number(), 501);
            assert_eq!(
                node.world_state
                    .read()
                    .get_validator_weight(&members[1])
                    .unwrap(),
                prior_base
            );
            assert_eq!(
                node.timeout_authorities(),
                vec![(members[0], 1), (members[2], 3)]
            );
            (node, db)
        };
        let (mut local, store) = build(config.clone(), true);
        let (mut remote, _) = build(config.clone(), false);
        for number in 502..target {
            if number == 502 {
                local
                    .handle_incoming_tx(signed(sender, 0, 7, false), &MultiVerifier)
                    .unwrap();
            }
            let parent = local.chain_store.get_head_block().unwrap().unwrap();
            let who = if number % 4 == 0 { 0 } else { 2 };
            local.config.proposer_address = Some(members[who]);
            local.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 600);
            local.produce_block(&keys[who], 500).unwrap();
        }
        let old = local.chain_store.get_head_block().unwrap().unwrap();
        local.consensus.write().slash_authority(&members[2]);
        let penalties = local.consensus.read().penalty_state();
        {
            let mut lifecycle = local.challenge_lifecycle.lock();
            lifecycle.penalties = Some(penalties.clone());
            lifecycle.persist(store.as_ref()).unwrap();
        }
        let observer = vec![(members[0], 1), (members[2], 2)];
        assert_eq!(local.timeout_authorities(), observer);
        let committee = remote.timeout_authorities();
        let committee_hash = shell_core::timeout_authority_set_hash(&committee).unwrap();
        let mut branch = Vec::new();
        for number in 502..=target {
            if number == 502 {
                for (nonce, who) in [(0, 0usize), (1, 2usize)]
                    .into_iter()
                    .chain(zeroed.then_some((2, 1usize)))
                {
                    let mut funding = signed(sender, nonce, 1_000_000, false);
                    funding.tx.to = Some(members[who]);
                    funding.signature = sender
                        .sign(funding.sender_signing_hash().as_bytes())
                        .unwrap();
                    remote.handle_incoming_tx(funding, &MultiVerifier).unwrap();
                }
            }
            if number == 503 || number == 504 {
                let who = if number == 503 { 0 } else { 2 };
                let mut vote = signed(&keys[who], 0, 0, false);
                vote.tx.to = Some(shell_storage::validator_registry_addr());
                let mut data = shell_pqvm::system_contracts::RECOVER_VALIDATOR_SELECTOR.to_vec();
                data.extend_from_slice(members[1].as_bytes());
                data.extend_from_slice(&[0; 31]);
                data.push(50);
                data.extend_from_slice(committee_hash.as_bytes());
                vote.tx.data = data.into();
                vote.signature = keys[who]
                    .sign(vote.sender_signing_hash().as_bytes())
                    .unwrap();
                remote.handle_incoming_tx(vote, &MultiVerifier).unwrap();
            }
            if reweighted && prior_base == 1 && (505..=506).contains(&number) {
                let voter = if number == 505 { 2 } else { 0 };
                let mut weight = signed(&keys[voter], 1, 0, false);
                weight.tx.to = Some(shell_storage::validator_registry_addr());
                weight.tx.data =
                    shell_pqvm::system_contracts::encode_set_validator_weight_calldata(
                        &members[1],
                        2,
                    )
                    .into();
                weight.signature = keys[voter]
                    .sign(weight.sender_signing_hash().as_bytes())
                    .unwrap();
                remote.handle_incoming_tx(weight, &MultiVerifier).unwrap();
            }
            if zeroed && (511..=512).contains(&number) {
                // B is genuinely restored before it votes; C completes the
                // strict registered-base quorum (2 + 3 > two thirds of 6).
                let voter = if number == 511 { 1 } else { 2 };
                let mut weight = signed(&keys[voter], if voter == 1 { 0 } else { 1 }, 0, false);
                weight.tx.to = Some(shell_storage::validator_registry_addr());
                weight.tx.data =
                    shell_pqvm::system_contracts::encode_set_validator_weight_calldata(
                        &members[1],
                        1,
                    )
                    .into();
                weight.signature = keys[voter]
                    .sign(weight.sender_signing_hash().as_bytes())
                    .unwrap();
                remote.handle_incoming_tx(weight, &MultiVerifier).unwrap();
            }
            let parent = remote.chain_store.get_head_block().unwrap().unwrap();
            let who = if number < 510 || (zeroed && number > 520) {
                if number % 4 == 0 {
                    0
                } else {
                    2
                }
            } else {
                match number % 5 {
                    0 => 0,
                    1 => 1,
                    _ => 2,
                }
            };
            remote.config.proposer_address = Some(members[who]);
            remote.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 600);
            let block = remote.produce_block(&keys[who], 500).unwrap();
            if reweighted && prior_base == 1 && (505..=506).contains(&number) {
                // General weight governance counts all registered base weight:
                // C3 alone is below the strict threshold of the total 5.
                assert_eq!(
                    remote
                        .world_state
                        .read()
                        .get_validator_weight(&members[1])
                        .unwrap(),
                    if number == 505 { 1 } else { 2 }
                );
            }
            if zeroed && (511..=512).contains(&number) {
                assert_eq!(
                    remote
                        .world_state
                        .read()
                        .get_validator_weight(&members[1])
                        .unwrap(),
                    if number == 511 { 2 } else { 1 }
                );
            }
            let ledger = remote.world_state.read().load_offline_state().unwrap();
            let entry = ledger.validator(&members[1]).unwrap();
            assert_eq!(entry.consecutive_misses, if number < 510 { 100 } else { 0 });
            assert_eq!(
                entry.recover_at_epoch,
                if (504..510).contains(&number) {
                    Some(51)
                } else {
                    None
                }
            );
            assert_eq!(
                entry.suspend_at_epoch,
                if number < 510 { Some(50) } else { None }
            );
            let input = remote.attestation_weights(&block).unwrap();
            assert_eq!(
                input.get(&members[1]),
                if number < 510 || (zeroed && number > 520) {
                    None
                } else if number == 510 || !reweighted || prior_base == 2 {
                    Some(&1)
                } else {
                    Some(&2)
                }
            );
            if number == 510 {
                let checkpoint = remote
                    .chain_store
                    .get_block_hash_by_number(499)
                    .unwrap()
                    .unwrap();
                let key = [b"h/".as_slice(), checkpoint.as_bytes()].concat();
                let original = store.get(&key).unwrap().unwrap();
                let other = remote
                    .chain_store
                    .get_block_hash_by_number(498)
                    .unwrap()
                    .unwrap();
                let wrong = store
                    .get(&[b"h/".as_slice(), other.as_bytes()].concat())
                    .unwrap()
                    .unwrap();
                for replacement in [None, Some(wrong)] {
                    match replacement {
                        None => store.delete(&key).unwrap(),
                        Some(bytes) => store.put(&key, &bytes).unwrap(),
                    }
                    let before = store.scan_prefix(b"").unwrap();
                    assert!(local.import_block(block.clone(), &MultiVerifier).is_err());
                    assert_eq!(store.scan_prefix(b"").unwrap(), before);
                    assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
                    assert_eq!(local.timeout_authorities(), observer);
                    assert_eq!(local.consensus.read().penalty_state(), penalties);
                    store.put(&key, &original).unwrap();
                }
            }
            if zeroed && number == target {
                let before = store.scan_prefix(b"").unwrap();
                let mut wrong = block.clone();
                wrong.header.proposer = members[1];
                wrong.proposer_seal = Some(keys[1].sign(wrong.header.hash().as_bytes()).unwrap());
                assert!(local.import_block(wrong, &MultiVerifier).is_err());
                assert_eq!(store.scan_prefix(b"").unwrap(), before);
            }
            if number == 509 || (zeroed && number == target) {
                local.import_block(block.clone(), &MultiVerifier).unwrap();
                let message = shell_consensus::Attestation::signing_message(
                    1337,
                    &block.header.parent_hash,
                    &block.hash(),
                    number,
                    0,
                );
                let before = store.scan_prefix(b"").unwrap();
                let vote = shell_consensus::Attestation::new(
                    1337,
                    block.header.parent_hash,
                    block.hash(),
                    number,
                    members[1],
                    0,
                    keys[1].sign(&message).unwrap().data,
                );
                assert!(local.handle_attestation(vote, &MultiVerifier).is_err());
                assert_eq!(store.scan_prefix(b"").unwrap(), before);
            } else {
                local.import_block(block.clone(), &MultiVerifier).unwrap();
            }
            branch.push(block);
        }
        let tip = branch.last().unwrap();
        assert_eq!(tip.header.proposer, members[if zeroed { 2 } else { 1 }]);
        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
        let quorum = if zeroed {
            vec![2usize]
        } else {
            vec![1usize, 2]
        };
        let signatures = quorum
            .iter()
            .map(|i| (members[*i], keys[*i].sign(tip.hash().as_bytes()).unwrap()))
            .collect();
        let certificate =
            super::super::Node::<FailingBatchDb>::encode_commit_certificate(&signatures).unwrap();
        let minority_voter = if zeroed { 1 } else { 2 };
        let minority = super::super::Node::<FailingBatchDb>::encode_commit_certificate(
            &std::collections::HashMap::from([(
                members[minority_voter],
                keys[minority_voter].sign(tip.hash().as_bytes()).unwrap(),
            )]),
        )
        .unwrap();
        assert!(local.verify_commit_certificate(target, tip.hash(), &certificate));
        assert!(!local.verify_commit_certificate(target, tip.hash(), &minority));
        if certified {
            let before = store.scan_prefix(b"").unwrap();
            assert!(local
                .adopt_certified_fork(target, tip.hash(), &minority)
                .unwrap()
                .is_none());
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
            assert!(local
                .adopt_certified_fork(target, tip.hash(), &certificate)
                .unwrap()
                .is_some());
        } else {
            for i in quorum {
                let message = shell_consensus::Attestation::signing_message(
                    1337,
                    &tip.header.parent_hash,
                    &tip.hash(),
                    target,
                    0,
                );
                let vote = shell_consensus::Attestation::new(
                    1337,
                    tip.header.parent_hash,
                    tip.hash(),
                    target,
                    members[i],
                    0,
                    keys[i].sign(&message).unwrap().data,
                );
                local.handle_attestation(vote, &MultiVerifier).unwrap();
            }
            let plan = local.preferred_fork_plan().unwrap().unwrap();
            let before = store.scan_prefix(b"").unwrap();
            store.arm_canonical_head_failure();
            assert!(local.adopt_preferred_fork(&plan).is_err());
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
            assert_eq!(local.timeout_authorities(), observer);
            assert_eq!(local.consensus.read().penalty_state(), penalties);
            assert_eq!(
                local.consensus.read().poa_config().authority_weights,
                vec![1, prior_base, 3]
            );
            store.clear_canonical_head_failure();
            local.adopt_preferred_fork(&plan).unwrap();
        }
        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(tip.hash()));
        assert_eq!(
            local.world_state.write().state_root().unwrap(),
            tip.header.state_root
        );
        assert_eq!(
            local
                .world_state
                .read()
                .get_nonce(&address(sender))
                .unwrap(),
            if zeroed { 3 } else { 2 }
        );
        let balance = local.world_state.read().get_balance(&members[1]).unwrap();
        if zeroed {
            // One million funded B; its sole value-zero vote can consume at
            // most its 100000 gas limit times max fee 10, before producer fees.
            assert!(balance >= U256::from(123));
        } else {
            assert_eq!(balance, U256::from(123));
        }
        assert_eq!(
            local
                .world_state
                .read()
                .get_validator_stake(&members[1])
                .unwrap(),
            U256::from(prior_base * 25)
        );
        assert_eq!(
            local
                .world_state
                .read()
                .get_validator_weight(&members[1])
                .unwrap(),
            expected_base
        );
        let mut expected = vec![(members[0], 1)];
        if !zeroed {
            expected.push((
                members[1],
                if prior_base == 1 && reweighted { 2 } else { 1 },
            ));
        }
        expected.push((members[2], 2));
        assert_eq!(
            local.consensus.read().poa_config().authority_weights,
            vec![1, expected_base, 3]
        );
        let current = local.world_state.read().load_offline_state().unwrap();
        assert_eq!(
            current.validator(&members[1]).unwrap().suspend_at_epoch,
            None
        );
        assert_eq!(
            current.validator(&members[1]).unwrap().recover_at_epoch,
            None
        );
        assert_eq!(local.timeout_authorities(), expected);
        assert_eq!(local.consensus.read().penalty_state(), penalties);
        for block in &branch {
            assert_eq!(
                local
                    .chain_store
                    .get_block_hash_by_number(block.number())
                    .unwrap(),
                Some(block.hash())
            );
            assert_eq!(
                local.chain_store.get_receipts(&block.hash()).unwrap(),
                remote.chain_store.get_receipts(&block.hash()).unwrap()
            );
        }
        let before = store.scan_prefix(b"").unwrap();
        let old_ledger = WorldState::at_root(store.clone(), &branch[7].header.state_root)
            .unwrap()
            .load_offline_state()
            .unwrap();
        assert_eq!(
            old_ledger
                .validator(&members[1])
                .unwrap()
                .consecutive_misses,
            100
        );
        assert_eq!(
            old_ledger.validator(&members[1]).unwrap().recover_at_epoch,
            Some(51)
        );
        assert_eq!(
            local
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&members[1])
                .unwrap()
                .consecutive_misses,
            0
        );
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        let config = local.config.clone();
        drop(local);
        let restored = NodeBuilder::new(config, store).build().unwrap().0;
        assert_eq!(restored.timeout_authorities(), expected);
        assert_eq!(restored.consensus.read().penalty_state(), penalties);
        assert_eq!(
            restored.world_state.write().state_root().unwrap(),
            tip.header.state_root
        );
    }
    #[test]
    fn canonical_offline_governed_membership_uses_effective_epoch_roster() {
        use crate::node::tests::FailingBatchDb;
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let members = keys.iter().map(address).collect::<Vec<_>>();
        let store = Arc::new(FailingBatchDb::new());
        let mut producer = event_node(store.clone(), members.clone(), vec![1, 3], 0, &keys[0], 100);
        let follower = event_node(
            Arc::new(FailingBatchDb::new()),
            members.clone(),
            vec![1, 3],
            0,
            &keys[0],
            100,
        );
        for node in [&producer, &follower] {
            for key in &keys {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
        }
        let genesis = producer
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let config = producer.chain_store.get_chain_config().unwrap().unwrap();
        let mut history = None;
        for number in 1..=23 {
            if number == 1 {
                let mut tx = signed(&keys[0], 0, 4_000_000, false);
                tx.tx.to = Some(members[1]);
                tx.signature = keys[0].sign(tx.sender_signing_hash().as_bytes()).unwrap();
                producer.handle_incoming_tx(tx, &MultiVerifier).unwrap();
            }
            if [5, 6, 7, 11].contains(&number) {
                let mut tx = signed(
                    &keys[1],
                    match number {
                        5 => 0,
                        6 => 1,
                        7 => 2,
                        _ => 3,
                    },
                    0,
                    false,
                );
                tx.tx.to = Some(shell_storage::validator_registry_addr());
                tx.tx.data = if number == 5 || number == 7 {
                    shell_pqvm::system_contracts::encode_remove_validator_calldata(&members[0])
                } else {
                    shell_pqvm::system_contracts::encode_add_validator_calldata(&members[0])
                }
                .into();
                tx.signature = keys[1].sign(tx.sender_signing_hash().as_bytes()).unwrap();
                producer.handle_incoming_tx(tx, &MultiVerifier).unwrap();
            }
            let parent = producer.chain_store.get_head_block().unwrap().unwrap();
            let mut timestamp = parent.header.timestamp + 600;
            let who = if number == 4 || number == 9 {
                for view in 0..if number == 4 { 1 } else { 2 } {
                    timestamp += 10;
                    let admitted = admit_timeout_opportunity(
                        &producer.chain_store,
                        &parent.header,
                        view,
                        &producer.timeout_authorities(),
                        &TimeoutOpportunity::Heartbeat,
                        timestamp,
                        &MultiVerifier,
                    )
                    .unwrap();
                    assert_eq!(
                        admitted.context.proposer,
                        members[if number == 9 && view == 0 { 1 } else { 0 }]
                    );
                    producer
                        .handle_certified_timeout_vote_at(
                            TimeoutVoteMessage {
                                vote: TimeoutVote {
                                    context: admitted.context.clone(),
                                    validator: members[1],
                                    signature: keys[1]
                                        .sign(&admitted.context.signing_message(&members[1]))
                                        .unwrap(),
                                },
                                public_key: keys[1].public_key().to_vec(),
                                opportunity: TimeoutOpportunity::Heartbeat,
                            },
                            timestamp,
                            &MultiVerifier,
                        )
                        .unwrap()
                        .unwrap();
                    producer.recover_certified_timeout_view().unwrap();
                    assert_eq!(producer.consensus.read().current_view(), view + 1);
                }
                1
            } else if number == 8 || number == 23 {
                0
            } else {
                1
            };
            producer.config.proposer_address = Some(members[who]);
            producer.dev_state.write().next_block_timestamp = Some(timestamp);
            if number == 10 || number == 20 {
                let before = store.scan_prefix(b"").unwrap();
                store.arm_canonical_head_failure();
                assert!(producer.produce_block(&keys[who], 500).is_err());
                assert_eq!(store.scan_prefix(b"").unwrap(), before);
                assert_eq!(
                    producer
                        .world_state
                        .read()
                        .load_offline_state()
                        .unwrap()
                        .validator(&members[0])
                        .is_some(),
                    number == 10
                );
                store.clear_canonical_head_failure();
                producer.dev_state.write().next_block_timestamp = Some(timestamp);
            }
            let block = producer.produce_block(&keys[who], 500).unwrap();
            follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            assert_eq!(
                follower.world_state.write().state_root().unwrap(),
                block.header.state_root
            );
            let ledger = producer.world_state.read().load_offline_state().unwrap();
            assert_eq!(
                follower.world_state.read().load_offline_state().unwrap(),
                ledger
            );
            let active = !(10..20).contains(&number);
            assert_eq!(
                ledger.validator(&members[0]).is_some(),
                active,
                "native membership at{number}"
            );
            if let Some(entry) = ledger.validator(&members[0]) {
                assert_eq!(
                    entry.consecutive_misses,
                    if (4..8).contains(&number) || number == 9 {
                        1
                    } else {
                        0
                    },
                    "native misses at{number}"
                );
                assert_eq!(entry.suspend_at_epoch, None);
            }
            assert_eq!(
                producer
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&members[0]),
                active
            );
            assert_eq!(
                follower
                    .consensus
                    .read()
                    .validator_weights()
                    .contains_key(&members[0]),
                active
            );
            if [5, 6, 7, 11].contains(&number) {
                assert_eq!(block.transactions.len(), 1);
                assert_eq!(
                    producer
                        .chain_store
                        .get_receipts(&block.hash())
                        .unwrap()
                        .unwrap()[0]
                        .status,
                    1
                );
            }
            if number == 4 {
                history = Some(block.header.state_root);
            }
            if number == 5 || number == 11 {
                let mut bytes = Vec::new();
                producer
                    .chain_store
                    .export_snapshot(
                        shell_storage::SnapshotMetadata::new(
                            1337,
                            number,
                            block.hash(),
                            block.header.state_root,
                            genesis,
                        ),
                        std::io::Cursor::new(&mut bytes),
                    )
                    .unwrap();
                let target = Arc::new(MemoryDb::new());
                let chain = ChainStore::new(target.clone());
                chain.put_chain_config(&config).unwrap();
                chain
                    .import_snapshot(std::io::Cursor::new(bytes), 1337, &genesis)
                    .unwrap();
                let restored = NodeBuilder::new(producer.config.clone(), target)
                    .build()
                    .unwrap()
                    .0;
                assert_eq!(
                    restored.world_state.read().load_offline_state().unwrap(),
                    ledger
                );
                assert_eq!(
                    restored
                        .consensus
                        .read()
                        .validator_weights()
                        .contains_key(&members[0]),
                    active
                );
            }
            if number == 7 || number == 12 {
                let config = producer.config.clone();
                drop(producer);
                producer = NodeBuilder::new(config, store.clone()).build().unwrap().0;
                for key in &keys {
                    producer.register_authority_pubkey(address(key), key.public_key().to_vec());
                }
                assert_eq!(
                    producer
                        .consensus
                        .read()
                        .validator_weights()
                        .contains_key(&members[0]),
                    active
                );
            }
        }
        let historical = WorldState::at_root(store, &history.unwrap()).unwrap();
        assert_eq!(
            historical
                .load_offline_state()
                .unwrap()
                .validator(&members[0])
                .unwrap()
                .consecutive_misses,
            1
        );
        assert_eq!(
            producer
                .world_state
                .read()
                .load_offline_state()
                .unwrap()
                .validator(&members[0])
                .unwrap()
                .consecutive_misses,
            0
        );
    }
    #[test]
    fn canonical_offline_future_activation_uses_verified_epoch_base() {
        for activation in [8, 10, 11] {
            let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
            let members = keys.iter().map(address).collect::<Vec<_>>();
            let store = Arc::new(MemoryDb::new());
            let mut producer = event_node_at_activation(
                store.clone(),
                members.clone(),
                vec![1, 3],
                0,
                &keys[0],
                100,
                activation,
            );
            let follower = event_node_at_activation(
                Arc::new(MemoryDb::new()),
                members.clone(),
                vec![1, 3],
                0,
                &keys[0],
                100,
                activation,
            );
            for node in [&producer, &follower] {
                for key in &keys {
                    node.register_authority_pubkey(address(key), key.public_key().to_vec());
                }
            }
            let genesis = producer
                .chain_store
                .get_block_hash_by_number(0)
                .unwrap()
                .unwrap();
            let chain_config = producer.chain_store.get_chain_config().unwrap().unwrap();
            let mut snapshot_peer = None;
            let mut first = None;
            let mut legacy = None;
            for number in 1..=12 {
                if number == 1 {
                    let mut tx = signed(&keys[0], 0, 2_000_000, false);
                    tx.tx.to = Some(members[1]);
                    tx.signature = keys[0].sign(tx.sender_signing_hash().as_bytes()).unwrap();
                    producer.handle_incoming_tx(tx, &MultiVerifier).unwrap();
                }
                if number == 5 {
                    let mut tx = signed(&keys[1], 0, 0, false);
                    tx.tx.to = Some(shell_storage::validator_registry_addr());
                    tx.tx.data =
                        shell_pqvm::system_contracts::encode_remove_validator_calldata(&members[0])
                            .into();
                    tx.signature = keys[1].sign(tx.sender_signing_hash().as_bytes()).unwrap();
                    producer.handle_incoming_tx(tx, &MultiVerifier).unwrap();
                }
                let parent = producer.chain_store.get_head_block().unwrap().unwrap();
                let mut timestamp = parent.header.timestamp + 600;
                let who = if number == 10 && activation == 10 {
                    for view in 0..2 {
                        timestamp += 10;
                        let admitted = admit_timeout_opportunity(
                            &producer.chain_store,
                            &parent.header,
                            view,
                            &producer.timeout_authorities(),
                            &TimeoutOpportunity::Heartbeat,
                            timestamp,
                            &MultiVerifier,
                        )
                        .unwrap();
                        assert_eq!(
                            admitted.context.proposer,
                            members[if view == 0 { 1 } else { 0 }]
                        );
                        producer
                            .handle_certified_timeout_vote_at(
                                TimeoutVoteMessage {
                                    vote: TimeoutVote {
                                        context: admitted.context.clone(),
                                        validator: members[1],
                                        signature: keys[1]
                                            .sign(&admitted.context.signing_message(&members[1]))
                                            .unwrap(),
                                    },
                                    public_key: keys[1].public_key().to_vec(),
                                    opportunity: TimeoutOpportunity::Heartbeat,
                                },
                                timestamp,
                                &MultiVerifier,
                            )
                            .unwrap()
                            .unwrap();
                        producer.recover_certified_timeout_view().unwrap();
                    }
                    1
                } else if number == 4 || number == 8 {
                    0
                } else {
                    1
                };
                producer.config.proposer_address = Some(members[who]);
                producer.dev_state.write().next_block_timestamp = Some(timestamp);
                if number == activation && activation == 8 {
                    let key = [b"h/".as_slice(), genesis.as_bytes()].concat();
                    let original = store.get(&key).unwrap().unwrap();
                    let first_hash = producer
                        .chain_store
                        .get_block_hash_by_number(1)
                        .unwrap()
                        .unwrap();
                    let wrong = store
                        .get(&[b"h/".as_slice(), first_hash.as_bytes()].concat())
                        .unwrap()
                        .unwrap();
                    for replacement in [None, Some(wrong)] {
                        match replacement {
                            None => store.delete(&key).unwrap(),
                            Some(bytes) => store.put(&key, &bytes).unwrap(),
                        };
                        let before = store.scan_prefix(b"").unwrap();
                        assert!(producer.produce_block(&keys[who], 500).is_err());
                        assert_eq!(store.scan_prefix(b"").unwrap(), before);
                        assert!(producer
                            .world_state
                            .read()
                            .load_offline_state()
                            .unwrap()
                            .cursor()
                            .is_none());
                        store.put(&key, &original).unwrap();
                        producer.dev_state.write().next_block_timestamp = Some(timestamp);
                    }
                }
                let block = producer.produce_block(&keys[who], 500).unwrap();
                follower
                    .import_block(block.clone(), &MultiVerifier)
                    .unwrap();
                assert_eq!(
                    follower.world_state.write().state_root().unwrap(),
                    block.header.state_root
                );
                if let Some(peer) = &snapshot_peer {
                    let peer: &super::super::Node<MemoryDb> = peer;
                    peer.import_block(block.clone(), &MultiVerifier).unwrap();
                    assert_eq!(
                        peer.world_state.write().state_root().unwrap(),
                        block.header.state_root
                    );
                }
                if number == activation {
                    first = Some(block.clone());
                }
                if number == 4 {
                    legacy = Some(block.clone());
                }
                let ledger = producer.world_state.read().load_offline_state().unwrap();
                assert_eq!(
                    follower.world_state.read().load_offline_state().unwrap(),
                    ledger
                );
                if number < activation {
                    assert!(ledger.cursor().is_none());
                    assert!(ledger.validators().is_empty());
                } else {
                    assert_eq!(
                        ledger.validator(&members[0]).is_some(),
                        number < 10,
                        "activation{activation} number{number}"
                    );
                    assert_eq!(ledger.cursor().unwrap().context.block_number, number);
                }
                if number == 5 {
                    assert_eq!(
                        producer
                            .chain_store
                            .get_receipts(&block.hash())
                            .unwrap()
                            .unwrap()[0]
                            .status,
                        1
                    );
                    assert_eq!(
                        producer.world_state.read().get_validators().unwrap(),
                        vec![members[1]]
                    );
                }
                if number == 7 || number == activation {
                    let mut bytes = Vec::new();
                    producer
                        .chain_store
                        .export_snapshot(
                            shell_storage::SnapshotMetadata::new(
                                1337,
                                number,
                                block.hash(),
                                block.header.state_root,
                                genesis,
                            ),
                            std::io::Cursor::new(&mut bytes),
                        )
                        .unwrap();
                    let target = Arc::new(MemoryDb::new());
                    let chain = ChainStore::new(target.clone());
                    chain.put_chain_config(&chain_config).unwrap();
                    chain
                        .import_snapshot(std::io::Cursor::new(bytes), 1337, &genesis)
                        .unwrap();
                    let restored = NodeBuilder::new(producer.config.clone(), target)
                        .build()
                        .unwrap()
                        .0;
                    for key in &keys {
                        restored.register_authority_pubkey(address(key), key.public_key().to_vec());
                    }
                    assert_eq!(
                        restored.world_state.read().load_offline_state().unwrap(),
                        ledger
                    );
                    assert_eq!(
                        restored.timeout_authorities(),
                        producer.timeout_authorities()
                    );
                    if number == 7 {
                        snapshot_peer = Some(restored);
                    }
                }
                if number == 7 {
                    let config = producer.config.clone();
                    drop(producer);
                    producer = NodeBuilder::new(config, store.clone()).build().unwrap().0;
                    for key in &keys {
                        producer.register_authority_pubkey(address(key), key.public_key().to_vec());
                    }
                }
            }
            let first = first.unwrap();
            let tip = producer.chain_store.get_head_hash().unwrap();
            let root = producer.world_state.write().state_root().unwrap();
            let before = store.scan_prefix(b"").unwrap();
            producer
                .validate_legacy_backfill_witness(&legacy.unwrap())
                .unwrap();
            producer.validate_legacy_backfill_witness(&first).unwrap();
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
            producer.chain_store.delete_body(&first.hash()).unwrap();
            store
                .delete(&[b"w/".as_slice(), first.hash().as_bytes()].concat())
                .unwrap();
            producer
                .chain_store
                .put_backfill_block_with_validation(&first, true, |candidate| {
                    producer
                        .validate_legacy_backfill_witness(candidate)
                        .map_err(|e| shell_storage::StorageError::InvalidInput(e.to_string()))
                })
                .unwrap();
            assert_eq!(
                producer
                    .chain_store
                    .get_block_by_hash(&first.hash())
                    .unwrap(),
                Some(first)
            );
            assert_eq!(producer.chain_store.get_head_hash().unwrap(), tip);
            assert_eq!(producer.world_state.write().state_root().unwrap(), root);
        }
    }
    async fn check_equivocation_role<S: KvStore + 'static>(
        node: Arc<super::super::Node<S>>,
        outsider: &MlDsaSigner,
        member: &MlDsaSigner,
        anchor: Block,
        new_member_block: Option<Block>,
    ) -> Result<(), String> {
        use shell_network::{NetworkBus, NetworkConfig, NetworkMessage, NetworkService};
        use std::time::Duration;
        let proof_for = |key: &MlDsaSigner, block: &Block| {
            let mut a = block.clone();
            a.header.proposer = address(key);
            a.proposer_seal = Some(key.sign(a.hash().as_bytes()).unwrap());
            let mut b = a.clone();
            b.header.state_root = ShellHash::from([0xaf; 32]);
            b.proposer_seal = Some(key.sign(b.hash().as_bytes()).unwrap());
            let proof = shell_consensus::EquivocationProof::from_blocks(&a, &b).unwrap();
            assert!(proof.verify_signed(key.public_key(), &MultiVerifier));
            proof
        };
        let invalid = proof_for(outsider, &anchor);
        let valid = proof_for(member, &anchor);
        let later = new_member_block.map(|block| proof_for(outsider, &block));
        let mut invalid_pending = Vec::new();
        if later.is_some() {
            for number in [12, 20] {
                let block = node
                    .chain_store
                    .get_block_by_number(number)
                    .unwrap()
                    .unwrap();
                invalid_pending.push(proof_for(outsider, &block));
            }
        }
        let outsider_address = address(outsider);
        let member_address = address(member);
        node.register_authority_pubkey(outsider_address, outsider.public_key().to_vec());
        node.register_authority_pubkey(member_address, member.public_key().to_vec());
        let before_weights = node.consensus.read().validator_weights();
        let root = node.world_state.write().state_root().unwrap();
        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());
        let peer = bus.join(&NetworkConfig::default());
        let task = tokio::spawn({
            let node = node.clone();
            async move {
                node.run(Arc::new(MlDsaSigner::generate()), &mut network)
                    .await
            }
        });
        let observed = tokio::time::timeout(Duration::from_secs(5), async {
            peer.broadcast(NetworkMessage::EquivocationEvidence(Box::new(invalid)))
                .await
                .map_err(|e| e.to_string())?;
            for proof in invalid_pending {
                peer.broadcast(NetworkMessage::EquivocationEvidence(Box::new(proof)))
                    .await
                    .map_err(|error| error.to_string())?;
            }
            // A valid historical member is a FIFO processing marker; accepting
            // only registered current keys would incorrectly admit the outsider.
            peer.broadcast(NetworkMessage::EquivocationEvidence(Box::new(valid)))
                .await
                .map_err(|e| e.to_string())?;
            while node
                .consensus
                .read()
                .validator_weights()
                .get(&member_address)
                .copied()
                != Some(0)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let penalties = node.consensus.read().penalty_state();
            if penalties
                .reductions
                .iter()
                .any(|(address, _)| *address == outsider_address)
                || node
                    .consensus
                    .read()
                    .validator_weights()
                    .get(&outsider_address)
                    != before_weights.get(&outsider_address)
            {
                return Err("pre-membership signed evidence changed economic penalties".to_string());
            }
            if let Some(proof) = later {
                peer.broadcast(NetworkMessage::EquivocationEvidence(Box::new(proof)))
                    .await
                    .map_err(|e| e.to_string())?;
                while node
                    .consensus
                    .read()
                    .validator_weights()
                    .get(&outsider_address)
                    .copied()
                    != Some(0)
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            if node.world_state.write().state_root().unwrap() != root {
                return Err("economic evidence rewrote native account state".to_string());
            }
            let persisted = super::super::ChallengeLifecycle::load(node.store.as_ref())
                .map_err(|error| error.to_string())?;
            if persisted.penalties != Some(node.consensus.read().penalty_state()) {
                return Err("economic evidence did not persist its penalty journal".to_string());
            }
            Ok(())
        })
        .await;
        node.shutdown();
        task.await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        observed.map_err(|e| e.to_string())?
    }
    #[tokio::test]
    async fn canonical_offline_equivocation_rejects_never_admitted_signer() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let outsider = MlDsaSigner::generate();
        let store = Arc::new(MemoryDb::new());
        let mut producer = event_node(
            store.clone(),
            keys.iter().map(address).collect(),
            vec![1, 3],
            0,
            &keys[0],
            100,
        );
        for key in &keys {
            producer.register_authority_pubkey(address(key), key.public_key().to_vec());
        }
        producer.config.proposer_address = Some(address(&keys[1]));
        producer.dev_state.write().next_block_timestamp = Some(700);
        let block = producer.produce_block(&keys[1], 500).unwrap();
        let mut config = producer.config.clone();
        config.node_role = crate::NodeRole::Validator;
        config.proposer_address = None;
        if let ConsensusEngineConfig::WPoa(ref mut c) = config.consensus {
            c.poa.slash_weight_bps = 10_000;
        }
        drop(producer);
        let node = Arc::new(NodeBuilder::new(config, store).build().unwrap().0);
        check_equivocation_role(node, &outsider, &keys[1], block, None)
            .await
            .unwrap();
    }
    #[test]
    fn canonical_offline_equivocation_checks_activate_for_the_next_slot() {
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let outsider = MlDsaSigner::generate();
        let mut node = event_node_at_activation(
            Arc::new(MemoryDb::new()),
            keys.iter().map(address).collect(),
            vec![1, 3],
            0,
            &keys[0],
            100,
            3,
        );
        for key in &keys {
            node.register_authority_pubkey(address(key), key.public_key().to_vec());
        }
        node.config.proposer_address = Some(address(&keys[1]));
        node.dev_state.write().next_block_timestamp = Some(700);
        let block = node.produce_block(&keys[1], 500).unwrap();
        let mut a = block.clone();
        a.header.proposer = address(&outsider);
        a.proposer_seal = Some(outsider.sign(a.hash().as_bytes()).unwrap());
        let mut b = a.clone();
        b.header.state_root = ShellHash::from([0xee; 32]);
        b.proposer_seal = Some(outsider.sign(b.hash().as_bytes()).unwrap());
        let proof = shell_consensus::EquivocationProof::from_blocks(&a, &b).unwrap();
        assert!(proof.verify_signed(outsider.public_key(), &MultiVerifier));
        // The legacy validation route remains selected before activation.
        assert_eq!(
            node.admits_equivocation_authority(&proof, outsider.public_key())
                .unwrap(),
            None
        );
        node.dev_state.write().next_block_timestamp = Some(1300);
        node.produce_block(&keys[1], 500).unwrap();
        assert_eq!(
            node.admits_equivocation_authority(&proof, outsider.public_key())
                .unwrap(),
            Some(false)
        );
        let mut other = block.clone();
        other.header.state_root = ShellHash::from([0xed; 32]);
        other.proposer_seal = Some(keys[1].sign(other.hash().as_bytes()).unwrap());
        let valid = shell_consensus::EquivocationProof::from_blocks(&block, &other).unwrap();
        assert_eq!(
            node.admits_equivocation_authority(&valid, keys[1].public_key())
                .unwrap(),
            Some(true)
        );
    }
    #[tokio::test]
    async fn canonical_offline_fresh_member_does_not_assume_no_legacy_penalties() {
        use shell_network::{NetworkBus, NetworkConfig, NetworkMessage, NetworkService};
        use std::time::Duration;
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let outsider = MlDsaSigner::generate();
        let member = address(&outsider);
        let store = Arc::new(MemoryDb::new());
        let mut producer = event_node_at_profile(
            store.clone(),
            keys.iter().map(address).collect(),
            vec![1, 3],
            0,
            &keys[0],
            100,
            (3, Some(0)),
        );
        producer.register_authority_pubkey(address(&keys[1]), keys[1].public_key().to_vec());
        producer.config.proposer_address = Some(address(&keys[1]));
        producer.dev_state.write().next_block_timestamp = Some(700);
        let block = producer.produce_block(&keys[1], 500).unwrap();
        let mut a = block;
        a.header.proposer = member;
        a.proposer_seal = Some(outsider.sign(a.hash().as_bytes()).unwrap());
        let mut b = a.clone();
        b.header.state_root = ShellHash::from([0xec; 32]);
        b.proposer_seal = Some(outsider.sign(b.hash().as_bytes()).unwrap());
        let proof = shell_consensus::EquivocationProof::from_blocks(&a, &b).unwrap();
        assert!(proof.verify_signed(outsider.public_key(), &MultiVerifier));
        let mut config = producer.config.clone();
        config.proposer_address = None;
        if let ConsensusEngineConfig::WPoa(ref mut c) = config.consensus {
            c.poa.slash_weight_bps = 10_000;
        }
        drop(producer);
        let node = Arc::new(NodeBuilder::new(config, store.clone()).build().unwrap().0);
        node.register_authority_pubkey(member, outsider.public_key().to_vec());
        let root = node.world_state.write().state_root().unwrap();
        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());
        let peer = bus.join(&NetworkConfig::default());
        let task = tokio::spawn({
            let node = node.clone();
            async move {
                node.run(Arc::new(MlDsaSigner::generate()), &mut network)
                    .await
            }
        });
        let observed = tokio::time::timeout(Duration::from_secs(5), async {
            peer.broadcast(NetworkMessage::EquivocationEvidence(Box::new(proof)))
                .await
                .unwrap();
            while !node
                .consensus
                .read()
                .penalty_state()
                .reductions
                .contains(&(member, 1))
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        node.shutdown();
        task.await.unwrap().unwrap();
        observed.unwrap();
        // The legacy route produced hidden economic metadata before activation;
        // neither validator nor prover role absence in native state proves zero.
        assert_eq!(node.world_state.write().state_root().unwrap(), root);
        let mut config = node.config.clone();
        config.proposer_address = Some(address(&keys[1]));
        drop(node);
        let node = NodeBuilder::new(config, store).build().unwrap().0;
        node.register_authority_pubkey(address(&keys[1]), keys[1].public_key().to_vec());
        for timestamp in [1300, 1900] {
            node.dev_state.write().next_block_timestamp = Some(timestamp);
            node.produce_block(&keys[1], 500).unwrap();
        }
        let config = node.chain_store.get_chain_config().unwrap().unwrap();
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        assert!(!node
            .world_state
            .read()
            .get_validators()
            .unwrap()
            .contains(&member));
        assert!(node
            .world_state
            .read()
            .get_registered_prover(&member)
            .unwrap()
            .is_none());
        let result = super::super::canonical_offline::historical_member_weight(
            &node.chain_store,
            &parent.header,
            &member,
            1,
            config.offline_enforcement.as_ref().unwrap(),
            config.genesis_hash,
        );
        assert!(
            result.is_err(),
            "native absence cannot erase an observed legacy economic reduction"
        );
    }
    #[test]
    fn canonical_offline_unanchored_pending_registry_fork_uses_effective_epoch_base() {
        pending_registry_fork(4, false, false, None, false, false, false);
    }
    #[test]
    fn canonical_offline_unanchored_actual_epoch_exit_reloads_adopted_base() {
        for certified in [false, true] {
            pending_registry_fork(11, certified, false, None, false, false, false);
        }
    }
    #[test]
    fn canonical_offline_unanchored_returning_member_restores_epoch_input() {
        for reduced_returner in [false, true] {
            for certified in [false, true] {
                pending_registry_fork(21, certified, reduced_returner, None, false, false, false);
            }
        }
    }
    #[test]
    fn canonical_offline_unanchored_reweighted_survivor_preserves_economic_reduction() {
        for certified in [false, true] {
            pending_registry_fork(11, certified, false, Some(7), false, false, false);
        }
    }
    #[test]
    fn canonical_offline_unanchored_reweighted_returner_preserves_economic_reduction() {
        for certified in [false, true] {
            pending_registry_fork(21, certified, true, Some(3), false, false, false);
        }
    }
    #[test]
    fn canonical_offline_unanchored_returning_weight_can_remain_zero() {
        for certified in [false, true] {
            pending_registry_fork(21, certified, true, Some(1), false, false, false);
        }
    }
    #[test]
    fn canonical_offline_unanchored_new_member_with_bounded_provers_makes_first_proposal() {
        for certified in [false, true] {
            pending_registry_fork(23, certified, false, None, true, false, false);
        }
    }
    #[test]
    fn canonical_offline_new_member_does_not_erase_unbounded_economic_history() {
        pending_registry_fork(23, false, false, None, false, false, false);
    }
    #[test]
    fn canonical_offline_new_member_does_not_erase_prior_prover_context() {
        pending_registry_fork(23, false, false, None, true, true, false);
    }
    #[test]
    fn canonical_offline_unanchored_governed_reorder_uses_new_assigned_slot() {
        for certified in [false, true] {
            for reweight in [None, Some(7)] {
                pending_registry_fork(11, certified, false, reweight, false, false, true);
            }
        }
    }
    fn pending_registry_fork(
        target_height: u64,
        certified: bool,
        reduced_returner: bool,
        reweight: Option<u64>,
        bounded_provers: bool,
        prior_prover: bool,
        reordered_survivors: bool,
    ) {
        use crate::node::tests::FailingBatchDb;
        let keys = [MlDsaSigner::generate(), MlDsaSigner::generate()];
        let members = keys.iter().map(address).collect::<Vec<_>>();
        let new_identity = target_height == 23;
        let new_key = MlDsaSigner::generate();
        let joining = if new_identity {
            address(&new_key)
        } else {
            members[0]
        };
        let reweighted = reweight.is_some();
        let returned_weight = match reweight {
            Some(1) => 0,
            Some(3) => 2,
            _ => 1,
        };
        let reweighted_survivor = reweighted && target_height == 11;
        let initial_weights = vec![
            if reduced_returner { 2 } else { 1 },
            if reweighted_survivor { 5 } else { 3 },
        ];
        let store = Arc::new(FailingBatchDb::new());
        let local = event_node_at_profile(
            store.clone(),
            members.clone(),
            initial_weights.clone(),
            0,
            &keys[0],
            100,
            (1, if bounded_provers { Some(0) } else { None }),
        );
        let mut remote = event_node_at_profile(
            Arc::new(FailingBatchDb::new()),
            members.clone(),
            initial_weights,
            0,
            &keys[0],
            100,
            (1, if bounded_provers { Some(0) } else { None }),
        );
        let mut observer_config = local.config.clone();
        if let ConsensusEngineConfig::WPoa(ref mut c) = observer_config.consensus {
            c.poa.slash_weight_bps = 5_000;
        }
        drop(local);
        let mut local = NodeBuilder::new(observer_config, store.clone())
            .build()
            .unwrap()
            .0;
        if reduced_returner || reweighted_survivor {
            let mut source_config = remote.config.clone();
            if let ConsensusEngineConfig::WPoa(ref mut c) = source_config.consensus {
                c.poa.slash_weight_bps = 5_000;
            }
            let source_store = remote.store.clone();
            drop(remote);
            remote = NodeBuilder::new(source_config, source_store)
                .build()
                .unwrap()
                .0;
            // Shared accepted economic fixture: A base2/effective1 or C
            // base5/effective3. Reload must retain the existing reduction;
            // this does not create new canonical misconduct evidence.
            for node in [&local, &remote] {
                node.consensus
                    .write()
                    .slash_authority(&members[if reduced_returner { 0 } else { 1 }]);
            }
        }
        for node in [&local, &remote] {
            for key in &keys {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
        }
        if new_identity {
            for node in [&local, &remote] {
                node.register_authority_pubkey(joining, new_key.public_key().to_vec());
                assert_eq!(
                    node.world_state.read().get_balance(&joining).unwrap(),
                    U256::ZERO
                );
                assert!(!node
                    .world_state
                    .read()
                    .get_validators()
                    .unwrap()
                    .contains(&joining));
            }
        }
        let mut funding = signed(
            &keys[0],
            0,
            if prior_prover { 6_000_000 } else { 4_000_000 },
            false,
        );
        funding.tx.to = Some(members[1]);
        funding.signature = keys[0]
            .sign(funding.sender_signing_hash().as_bytes())
            .unwrap();
        remote.handle_incoming_tx(funding, &MultiVerifier).unwrap();
        remote.config.proposer_address = Some(members[1]);
        remote.dev_state.write().next_block_timestamp = Some(700);
        let common = remote.produce_block(&keys[1], 500).unwrap();
        local.import_block(common, &MultiVerifier).unwrap();
        let mut old = None;
        for number in 2..=if target_height == 4 {
            4
        } else {
            target_height - 1
        } {
            if number == 2 {
                local
                    .handle_incoming_tx(signed(&keys[0], 1, 7, false), &MultiVerifier)
                    .unwrap();
            }
            let who = if number % 4 == 0 { 0 } else { 1 };
            local.config.proposer_address = Some(members[who]);
            local.dev_state.write().next_block_timestamp = Some(100 + number * 600);
            old = Some(local.produce_block(&keys[who], 500).unwrap());
        }
        let old = old.unwrap();
        // Observer-only later economic state must not replace historical input.
        local.consensus.write().slash_authority(&members[1]);
        let penalties = local.consensus.read().penalty_state();
        // Persist the observer fixture using the existing restart journal. This
        // is not a new canonical misconduct event on either branch.
        {
            let mut lifecycle = local.challenge_lifecycle.lock();
            lifecycle.penalties = Some(penalties.clone());
            lifecycle.persist(store.as_ref()).unwrap();
        }
        let observer_set = vec![(members[0], 1), (members[1], 2)];
        assert_eq!(local.timeout_authorities(), observer_set);

        remote
            .handle_incoming_tx(signed(&keys[0], 1, 11, false), &MultiVerifier)
            .unwrap();
        remote.dev_state.write().next_block_timestamp = Some(1300);
        let side2 = remote.produce_block(&keys[1], 500).unwrap();
        local.import_block(side2, &MultiVerifier).unwrap();
        let mut remove = signed(&keys[1], 0, 0, false);
        remove.tx.to = Some(shell_storage::validator_registry_addr());
        remove.tx.data =
            shell_pqvm::system_contracts::encode_remove_validator_calldata(&members[0]).into();
        remove.signature = keys[1]
            .sign(remove.sender_signing_hash().as_bytes())
            .unwrap();
        remote.handle_incoming_tx(remove, &MultiVerifier).unwrap();
        remote.dev_state.write().next_block_timestamp = Some(1900);
        let side3 = remote.produce_block(&keys[1], 500).unwrap();
        assert_eq!(
            remote.world_state.read().get_validators().unwrap(),
            vec![members[1]]
        );
        local.import_block(side3.clone(), &MultiVerifier).unwrap();
        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
        let set = remote.timeout_authorities();
        assert_eq!(set, vec![(members[0], 1), (members[1], 3)]);
        let admitted = admit_timeout_opportunity(
            &remote.chain_store,
            &side3.header,
            0,
            &set,
            &TimeoutOpportunity::Heartbeat,
            2510,
            &MultiVerifier,
        )
        .unwrap();
        assert_eq!(admitted.context.proposer, members[0]);
        remote
            .handle_certified_timeout_vote_at(
                TimeoutVoteMessage {
                    vote: TimeoutVote {
                        context: admitted.context.clone(),
                        validator: members[1],
                        signature: keys[1]
                            .sign(&admitted.context.signing_message(&members[1]))
                            .unwrap(),
                    },
                    public_key: keys[1].public_key().to_vec(),
                    opportunity: TimeoutOpportunity::Heartbeat,
                },
                2510,
                &MultiVerifier,
            )
            .unwrap()
            .unwrap();
        remote.dev_state.write().next_block_timestamp = Some(2510);
        let mut joining_balance_before_proposal = None;
        let mut tip = remote.produce_block(&keys[1], 500).unwrap();
        if target_height > 4 {
            local.import_block(tip.clone(), &MultiVerifier).unwrap();
            for number in 5..=target_height {
                if reordered_survivors && number == 5 {
                    let mut readd = signed(&keys[1], 1, 0, false);
                    readd.tx.to = Some(shell_storage::validator_registry_addr());
                    readd.tx.data =
                        shell_pqvm::system_contracts::encode_add_validator_calldata(&members[0])
                            .into();
                    readd.signature = keys[1]
                        .sign(readd.sender_signing_hash().as_bytes())
                        .unwrap();
                    remote.handle_incoming_tx(readd, &MultiVerifier).unwrap();
                }
                if new_identity && number == 5 {
                    let mut fund = signed(&keys[1], 1, 1_500_000, false);
                    fund.tx.to = Some(joining);
                    fund.signature = keys[1].sign(fund.sender_signing_hash().as_bytes()).unwrap();
                    remote.handle_incoming_tx(fund, &MultiVerifier).unwrap();
                }
                if new_identity && number == 6 {
                    // A real first-use transaction persists the embedded key;
                    // an in-memory peer key is not registry admission metadata.
                    let mut first = signed(&new_key, 0, 0, false);
                    first.tx.to = Some(joining);
                    first.signature = new_key
                        .sign(first.sender_signing_hash().as_bytes())
                        .unwrap();
                    remote.handle_incoming_tx(first, &MultiVerifier).unwrap();
                }
                if prior_prover && number == 7 {
                    let mut register = signed(&keys[1], 2, 0, false);
                    register.tx.to = Some(shell_storage::validator_registry_addr());
                    register.tx.gas_limit = 200_000;
                    register.tx.data =
                        shell_pqvm::system_contracts::encode_register_prover_calldata(
                            new_key.public_key(),
                            new_key.sig_type().as_u8(),
                        )
                        .into();
                    register.signature = keys[1]
                        .sign(register.sender_signing_hash().as_bytes())
                        .unwrap();
                    remote.handle_incoming_tx(register, &MultiVerifier).unwrap();
                }
                if reweighted_survivor && number == if reordered_survivors { 6 } else { 5 } {
                    let mut weight =
                        signed(&keys[1], if reordered_survivors { 2 } else { 1 }, 0, false);
                    weight.tx.to = Some(shell_storage::validator_registry_addr());
                    weight.tx.data =
                        shell_pqvm::system_contracts::encode_set_validator_weight_calldata(
                            &members[1],
                            reweight.unwrap(),
                        )
                        .into();
                    weight.signature = keys[1]
                        .sign(weight.sender_signing_hash().as_bytes())
                        .unwrap();
                    remote.handle_incoming_tx(weight, &MultiVerifier).unwrap();
                }
                if target_height > 11 && number == 11 {
                    let mut rejoin = signed(
                        &keys[1],
                        if prior_prover {
                            3
                        } else if new_identity {
                            2
                        } else {
                            1
                        },
                        0,
                        false,
                    );
                    rejoin.tx.to = Some(shell_storage::validator_registry_addr());
                    rejoin.tx.data =
                        shell_pqvm::system_contracts::encode_add_validator_calldata(&joining)
                            .into();
                    rejoin.signature = keys[1]
                        .sign(rejoin.sender_signing_hash().as_bytes())
                        .unwrap();
                    remote.handle_incoming_tx(rejoin, &MultiVerifier).unwrap();
                }
                if reduced_returner && number == 12 {
                    let mut weight = signed(&keys[1], 2, 0, false);
                    weight.tx.to = Some(shell_storage::validator_registry_addr());
                    weight.tx.data =
                        shell_pqvm::system_contracts::encode_set_validator_weight_calldata(
                            &members[0],
                            reweight.unwrap_or(2),
                        )
                        .into();
                    weight.signature = keys[1]
                        .sign(weight.sender_signing_hash().as_bytes())
                        .unwrap();
                    remote.handle_incoming_tx(weight, &MultiVerifier).unwrap();
                }
                let parent = remote.chain_store.get_head_block().unwrap().unwrap();
                let mut timestamp = parent.header.timestamp + 600;
                let mut who = if number == 8 { 0 } else { 1 };
                if (target_height > 11 || reordered_survivors) && number == 8 {
                    timestamp += 10;
                    let admitted = admit_timeout_opportunity(
                        &remote.chain_store,
                        &parent.header,
                        0,
                        &remote.timeout_authorities(),
                        &TimeoutOpportunity::Heartbeat,
                        timestamp,
                        &MultiVerifier,
                    )
                    .unwrap();
                    assert_eq!(admitted.context.proposer, members[0]);
                    remote
                        .handle_certified_timeout_vote_at(
                            TimeoutVoteMessage {
                                vote: TimeoutVote {
                                    context: admitted.context.clone(),
                                    validator: members[1],
                                    signature: keys[1]
                                        .sign(&admitted.context.signing_message(&members[1]))
                                        .unwrap(),
                                },
                                public_key: keys[1].public_key().to_vec(),
                                opportunity: TimeoutOpportunity::Heartbeat,
                            },
                            timestamp,
                            &MultiVerifier,
                        )
                        .unwrap()
                        .unwrap();
                    who = 1;
                }
                if new_identity && number == 23 {
                    // Empty proposals have no fee reward. A real C transfer
                    // exercises the newly assigned producer's fee credit.
                    remote
                        .handle_incoming_tx(signed(&keys[1], 3, 5, false), &MultiVerifier)
                        .unwrap();
                    joining_balance_before_proposal =
                        Some(remote.world_state.read().get_balance(&joining).unwrap());
                }
                let signer = if reordered_survivors && number == 11 {
                    &keys[0]
                } else if new_identity && number == 23 {
                    &new_key
                } else {
                    &keys[who]
                };
                remote.config.proposer_address = Some(address(signer));
                remote.dev_state.write().next_block_timestamp = Some(timestamp);
                tip = remote.produce_block(signer, 500).unwrap();
                if reordered_survivors && [5, 9, 10].contains(&number) {
                    let ledger = remote.world_state.read().load_offline_state().unwrap();
                    assert_eq!(
                        ledger.validator(&members[0]).unwrap().consecutive_misses,
                        if number == 5 { 1 } else { 2 }
                    );
                    assert_eq!(
                        remote.world_state.read().get_validators().unwrap(),
                        vec![members[1], members[0]]
                    );
                    if number == 5 {
                        assert_eq!(
                            remote.timeout_authorities(),
                            vec![(members[0], 1), (members[1], 3)]
                        );
                    }
                }
                if prior_prover && number == 7 {
                    assert!(remote
                        .world_state
                        .read()
                        .get_registered_prover(&joining)
                        .unwrap()
                        .is_some());
                }
                if target_height > 11 {
                    let ledger = remote.world_state.read().load_offline_state().unwrap();
                    if number == 9 {
                        assert_eq!(ledger.validator(&members[0]).unwrap().consecutive_misses, 2);
                    }
                    if (10..20).contains(&number) {
                        assert!(ledger.validator(&members[0]).is_none());
                    }
                    if number >= 20 {
                        assert_eq!(ledger.validator(&joining).unwrap().consecutive_misses, 0);
                        if new_identity {
                            assert!(ledger.validator(&members[0]).is_none());
                        }
                    }
                }
                if new_identity && (!bounded_provers || prior_prover) && number == 21 {
                    let before = store.scan_prefix(b"").unwrap();
                    let error = local.import_block(tip, &MultiVerifier).unwrap_err();
                    assert!(error.to_string().contains(if prior_prover {
                        "new member has prior prover economic context"
                    } else {
                        "new member economic history requires reconstruction"
                    }));
                    assert_eq!(store.scan_prefix(b"").unwrap(), before);
                    assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
                    return;
                }
                if number < target_height {
                    local.import_block(tip.clone(), &MultiVerifier).unwrap();
                }
            }
            let input = if reordered_survivors {
                vec![
                    (members[1], if reweighted_survivor { 5 } else { 3 }),
                    (members[0], 1),
                ]
            } else if target_height == 11 {
                vec![(members[1], if reweighted_survivor { 5 } else { 3 })]
            } else {
                let mut input = vec![(members[1], 3)];
                if returned_weight > 0 {
                    input.push((joining, returned_weight));
                }
                input
            };
            assert_eq!(remote.timeout_authorities(), input);
        }
        assert_eq!(tip.number(), target_height);
        assert_ne!(tip.header.parent_hash, old.header.parent_hash);
        assert!(
            WorldState::validate_snapshot_nodes(store.as_ref(), tip.header.state_root).is_err()
        );
        let before = store.scan_prefix(b"").unwrap();
        let mut bad_root = tip.clone();
        bad_root.header.state_root = ShellHash::from([0xab; 32]);
        let tip_signer = if reordered_survivors {
            &keys[0]
        } else if new_identity {
            &new_key
        } else {
            &keys[1]
        };
        bad_root.proposer_seal = Some(tip_signer.sign(bad_root.header.hash().as_bytes()).unwrap());
        let mut invalids = vec![bad_root];
        if target_height == 4 {
            let mut bad_signature = tip.clone();
            let tail = bad_signature.system_transactions.last_mut().unwrap();
            let mut proof =
                shell_core::TimeoutCertificate::from_system_transaction(tail, tail.tx_index)
                    .unwrap();
            proof.signers[0].signature.data[0] ^= 1;
            *tail = proof.system_transaction(tail.tx_index).unwrap();
            let mut self_authorized = tip.clone();
            let tail = self_authorized.system_transactions.last_mut().unwrap();
            let mut proof =
                shell_core::TimeoutCertificate::from_system_transaction(tail, tail.tx_index)
                    .unwrap();
            let fake_set = vec![(members[1], 3)];
            let fake = admit_timeout_opportunity(
                &remote.chain_store,
                &side3.header,
                0,
                &fake_set,
                &TimeoutOpportunity::Heartbeat,
                2510,
                &MultiVerifier,
            )
            .unwrap();
            proof.context = fake.context;
            proof.signers = vec![shell_core::BlockSignerEvidence {
                address: members[1],
                public_key: keys[1].public_key().to_vec(),
                signature: keys[1]
                    .sign(&proof.context.signing_message(&members[1]))
                    .unwrap(),
            }];
            shell_consensus::timeout::verify_timeout_certificate(
                &proof,
                &proof.context,
                &fake_set,
                &MultiVerifier,
            )
            .unwrap();
            *tail = proof.system_transaction(tail.tx_index).unwrap();
            invalids.extend([bad_signature, self_authorized]);
        } else {
            let mut removed_proposer = tip.clone();
            let wrong_slot = if reordered_survivors { 1 } else { 0 };
            removed_proposer.header.proposer = members[wrong_slot];
            removed_proposer.proposer_seal = Some(
                keys[wrong_slot]
                    .sign(removed_proposer.header.hash().as_bytes())
                    .unwrap(),
            );
            invalids.push(removed_proposer);
            if new_identity {
                let mut wrong_key = tip.clone();
                wrong_key.proposer_seal =
                    Some(keys[0].sign(wrong_key.header.hash().as_bytes()).unwrap());
                invalids.push(wrong_key);
            }
        }
        for invalid in invalids {
            assert!(local.import_block(invalid, &MultiVerifier).is_err());
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
            assert_eq!(
                local.world_state.write().state_root().unwrap(),
                old.header.state_root
            );
            assert_eq!(local.consensus.read().penalty_state(), penalties);
        }
        if target_height >= 21 {
            let checkpoint = remote
                .chain_store
                .get_block_hash_by_number(10)
                .unwrap()
                .unwrap();
            let key = [b"h/".as_slice(), checkpoint.as_bytes()].concat();
            let original = store.get(&key).unwrap().unwrap();
            let other = remote
                .chain_store
                .get_block_hash_by_number(9)
                .unwrap()
                .unwrap();
            let wrong = store
                .get(&[b"h/".as_slice(), other.as_bytes()].concat())
                .unwrap()
                .unwrap();
            for replacement in [None, Some(wrong)] {
                match replacement {
                    None => store.delete(&key).unwrap(),
                    Some(bytes) => store.put(&key, &bytes).unwrap(),
                };
                let before = store.scan_prefix(b"").unwrap();
                assert!(local.import_block(tip.clone(), &MultiVerifier).is_err());
                assert_eq!(store.scan_prefix(b"").unwrap(), before);
                assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
                assert_eq!(local.timeout_authorities(), observer_set);
                store.put(&key, &original).unwrap();
            }
        }
        local.import_block(tip.clone(), &MultiVerifier).unwrap();
        assert!(
            WorldState::validate_snapshot_nodes(store.as_ref(), tip.header.state_root).is_err()
        );

        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
        let quorum_keys = &keys[if returned_weight == 2 && target_height == 21 {
            0
        } else {
            1
        }..];
        let signatures = quorum_keys
            .iter()
            .map(|key| (address(key), key.sign(tip.hash().as_bytes()).unwrap()))
            .collect();
        let certificate =
            super::super::Node::<FailingBatchDb>::encode_commit_certificate(&signatures).unwrap();
        assert!(local.verify_commit_certificate(target_height, tip.hash(), &certificate));
        assert!(!local.verify_commit_certificate(0, tip.hash(), &certificate));
        assert!(!local.verify_commit_certificate(target_height + 1, tip.hash(), &certificate));
        let minority = super::super::Node::<FailingBatchDb>::encode_commit_certificate(
            &std::collections::HashMap::from([(
                members[0],
                keys[0].sign(tip.hash().as_bytes()).unwrap(),
            )]),
        )
        .unwrap();
        assert!(!local.verify_commit_certificate(target_height, tip.hash(), &minority));
        if (target_height == 11 && !reordered_survivors)
            || new_identity
            || (target_height == 21 && returned_weight == 0)
        {
            let payload = shell_consensus::Attestation::signing_message(
                1337,
                &tip.header.parent_hash,
                &tip.hash(),
                target_height,
                0,
            );
            let removed = shell_consensus::Attestation::new(
                1337,
                tip.header.parent_hash,
                tip.hash(),
                target_height,
                members[0],
                0,
                keys[0].sign(&payload).unwrap().data,
            );
            let before = store.scan_prefix(b"").unwrap();
            assert!(local.handle_attestation(removed, &MultiVerifier).is_err());
            assert_eq!(local.finality.read().attested_weight(&tip.hash()), 0);
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
        if !certified {
            for key in &keys[if target_height == 4 || (returned_weight == 2 && target_height == 21)
            {
                0
            } else {
                1
            }..]
            {
                let payload = shell_consensus::Attestation::signing_message(
                    1337,
                    &tip.header.parent_hash,
                    &tip.hash(),
                    target_height,
                    0,
                );
                let attestation = shell_consensus::Attestation::new(
                    1337,
                    tip.header.parent_hash,
                    tip.hash(),
                    target_height,
                    address(key),
                    0,
                    key.sign(&payload).unwrap().data,
                );
                local
                    .handle_attestation(attestation, &MultiVerifier)
                    .unwrap();
            }
            let plan = local.preferred_fork_plan().unwrap().unwrap();
            let before = store.scan_prefix(b"").unwrap();
            store.arm_canonical_head_failure();
            assert!(local.adopt_preferred_fork(&plan).is_err());
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
            assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(old.hash()));
            assert_eq!(
                local.world_state.write().state_root().unwrap(),
                old.header.state_root
            );
            assert_eq!(local.timeout_authorities(), observer_set);
            assert_eq!(local.consensus.read().penalty_state(), penalties);
            store.clear_canonical_head_failure();
            local.adopt_preferred_fork(&plan).unwrap();
        } else {
            let before = store.scan_prefix(b"").unwrap();
            assert!(local
                .adopt_certified_fork(target_height, tip.hash(), &minority)
                .unwrap()
                .is_none());
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
            assert!(local
                .adopt_certified_fork(target_height, tip.hash(), &certificate)
                .unwrap()
                .is_some());
        }
        assert_eq!(local.chain_store.get_head_hash().unwrap(), Some(tip.hash()));
        assert_eq!(
            local.world_state.write().state_root().unwrap(),
            tip.header.state_root
        );
        assert_eq!(
            local.world_state.read().load_offline_state().unwrap(),
            remote.world_state.read().load_offline_state().unwrap()
        );
        assert_eq!(
            local
                .world_state
                .read()
                .get_balance(&Address::from([9; 32]))
                .unwrap(),
            U256::from(if new_identity { 16 } else { 11 })
        );
        let ledger = local.world_state.read().load_offline_state().unwrap();
        if target_height == 4 {
            assert_eq!(ledger.validator(&members[0]).unwrap().consecutive_misses, 1);
        } else if target_height == 11 && !reordered_survivors {
            assert!(ledger.validator(&members[0]).is_none());
        } else {
            assert_eq!(ledger.validator(&joining).unwrap().consecutive_misses, 0);
            if new_identity {
                assert!(ledger.validator(&members[0]).is_none());
            }
        }
        assert_eq!(local.world_state.read().get_nonce(&members[0]).unwrap(), 2);
        assert_eq!(
            local.world_state.read().get_validators().unwrap(),
            if target_height <= 11 && !reordered_survivors {
                vec![members[1]]
            } else {
                vec![members[1], joining]
            }
        );
        let expected = if target_height == 4 {
            observer_set
        } else if target_height == 11 && !reordered_survivors {
            vec![(members[1], if reweighted_survivor { 4 } else { 2 })]
        } else {
            let mut expected = vec![(members[1], if reweighted_survivor { 4 } else { 2 })];
            if returned_weight > 0 {
                expected.push((joining, returned_weight));
            }
            expected
        };
        assert_eq!(local.timeout_authorities(), expected);
        assert_eq!(local.consensus.read().penalty_state(), penalties);
        for number in 2..=target_height {
            let hash = remote
                .chain_store
                .get_block_hash_by_number(number)
                .unwrap()
                .unwrap();
            assert_eq!(
                local.chain_store.get_block_hash_by_number(number).unwrap(),
                Some(hash)
            );
            assert_eq!(
                local.chain_store.get_receipts(&hash).unwrap(),
                remote.chain_store.get_receipts(&hash).unwrap()
            );
        }
        if target_height == 11 && !reordered_survivors {
            assert_eq!(
                local.consensus.read().poa_config().authorities,
                vec![members[1]]
            );
            assert_eq!(
                local.consensus.read().poa_config().authority_weights,
                vec![reweight.unwrap_or(3)]
            );
            let historical = remote.chain_store.get_block_by_number(4).unwrap().unwrap();
            let before = store.scan_prefix(b"").unwrap();
            let weights = local.attestation_weights(&historical).unwrap();
            assert_eq!(weights.get(&members[0]), Some(&1));
            assert_eq!(weights.get(&members[1]), Some(&3));
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
        if target_height >= 21 || reordered_survivors {
            assert_eq!(
                local.consensus.read().poa_config().authorities,
                vec![members[1], joining]
            );
            assert_eq!(
                local.consensus.read().poa_config().authority_weights,
                vec![
                    if reweighted_survivor {
                        reweight.unwrap()
                    } else {
                        3
                    },
                    if reduced_returner {
                        reweight.unwrap_or(2)
                    } else {
                        1
                    }
                ]
            );
            let historical = remote.chain_store.get_block_by_number(9).unwrap().unwrap();
            let before = store.scan_prefix(b"").unwrap();
            assert_eq!(
                local
                    .attestation_weights(&historical)
                    .unwrap()
                    .get(&members[0]),
                Some(&1)
            );
            assert_eq!(
                WorldState::at_root(store.clone(), &historical.header.state_root)
                    .unwrap()
                    .load_offline_state()
                    .unwrap()
                    .validator(&members[0])
                    .unwrap()
                    .consecutive_misses,
                2
            );
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
        if new_identity {
            assert_eq!(tip.header.proposer, joining);
            assert!(
                local.world_state.read().get_balance(&joining).unwrap()
                    > joining_balance_before_proposal.unwrap()
            );
            assert_eq!(local.world_state.read().get_nonce(&joining).unwrap(), 1);
        }
        let config = local.config.clone();
        drop(local);
        let restored = NodeBuilder::new(config, store.clone()).build().unwrap().0;
        assert_eq!(
            restored.chain_store.get_head_hash().unwrap(),
            Some(tip.hash())
        );
        assert_eq!(
            restored.world_state.write().state_root().unwrap(),
            tip.header.state_root
        );
        assert_eq!(restored.timeout_authorities(), expected);
        assert_eq!(restored.consensus.read().penalty_state(), penalties);
        if new_identity {
            let mut config = restored.config.clone();
            config.node_role = crate::NodeRole::Validator;
            config.proposer_address = None;
            if let ConsensusEngineConfig::WPoa(ref mut c) = config.consensus {
                c.poa.slash_weight_bps = 10_000;
            }
            drop(restored);
            let node = Arc::new(NodeBuilder::new(config, store).build().unwrap().0);
            let anchor = node.chain_store.get_block_by_number(2).unwrap().unwrap();
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(check_equivocation_role(
                    node,
                    &new_key,
                    &keys[1],
                    anchor,
                    Some(tip),
                ))
                .unwrap();
        }
    }
    #[test]
    fn canonical_offline_low_weight_validator_is_not_suspended_by_global_block_gap() {
        let keys = [
            MlDsaSigner::generate(),
            MlDsaSigner::generate(),
            MlDsaSigner::generate(),
        ];
        let sender = MlDsaSigner::generate();
        let authorities = keys.iter().map(address).collect::<Vec<_>>();
        let mut producer = event_node(
            Arc::new(MemoryDb::new()),
            authorities.clone(),
            vec![1, 1, 1000],
            0,
            &sender,
            100,
        );
        let follower = event_node(
            Arc::new(MemoryDb::new()),
            authorities,
            vec![1, 1, 1000],
            0,
            &sender,
            100,
        );
        for node in [&producer, &follower] {
            for key in &keys {
                node.register_authority_pubkey(address(key), key.public_key().to_vec());
            }
        }
        for number in 1..=151 {
            // With total1002 and this order, height1 belongs to the low-weight
            // validator; all following150 heights belong to the third member.
            let who = if number == 1 { 1 } else { 2 };
            let parent = producer.chain_store.get_head_block().unwrap().unwrap();
            producer.config.proposer_address = Some(address(&keys[who]));
            producer.dev_state.write().next_block_timestamp = Some(parent.header.timestamp + 600);
            let block = producer.produce_block(&keys[who], 500).unwrap();
            assert_eq!(block.header.proposer, address(&keys[who]));
            assert!(block.system_transactions.is_empty());
            follower
                .import_block(block.clone(), &MultiVerifier)
                .unwrap();
            assert_eq!(
                follower.world_state.write().state_root().unwrap(),
                block.header.state_root
            );
        }
        for node in [&producer, &follower] {
            let state = node.world_state.read();
            let ledger = state.load_offline_state().unwrap();
            for key in &keys {
                let entry = ledger.validator(&address(key)).unwrap();
                assert_eq!(entry.consecutive_misses, 0);
                assert_eq!(entry.suspend_at_epoch, None);
            }
            assert_eq!(
                node.timeout_authorities(),
                vec![
                    (address(&keys[0]), 1),
                    (address(&keys[1]), 1),
                    (address(&keys[2]), 1000)
                ]
            );
        }
    }
}
