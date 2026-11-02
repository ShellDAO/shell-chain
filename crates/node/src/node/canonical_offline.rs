//! Canonical execution of certified offline opportunities. Accepted history
//! reuses sealed native authority context; unaccepted forks need parent admission.
use super::*;
use shell_core::{TimeoutCertificate, TimeoutContext};

pub(super) struct OfflineBlockPlan {
    certificates: Vec<TimeoutCertificate>,
    authorities: Vec<(Address, u64)>,
    proposal: TimeoutContext,
    epoch_length: u64,
    initial_members: Option<Vec<Address>>,
}
pub(super) struct OfflineAuthorityTransition {
    base: Option<Vec<(Address, u64)>>,
    suspended: Vec<Address>,
}
impl OfflineAuthorityTransition {
    pub(super) fn apply(self, engine: &mut dyn ConsensusEngine) {
        if let Some(base) = self.base {
            let (validators, weights) = base.into_iter().unzip();
            engine.set_authorities_with_weights(validators, weights);
        }
        engine.set_certified_participation(true, self.suspended);
    }
}
impl OfflineBlockPlan {
    pub(super) fn authorities(&self) -> &[(Address, u64)] {
        &self.authorities
    }

    /// Read all participation/base inputs in the same private state as the
    /// block. Publication is followed only by infallible engine updates.
    pub(super) fn stage_authorities<S: KvStore + 'static>(
        &self,
        state: &WorldState<S>,
    ) -> Result<OfflineAuthorityTransition, NodeError> {
        let height =
            self.proposal.block_number.checked_add(1).ok_or_else(|| {
                NodeError::Startup("offline participation height overflow".into())
            })?;
        let ledger = state.load_offline_state()?;
        let epoch = height / self.epoch_length;
        let suspended = ledger
            .validators()
            .iter()
            .filter(|v| ledger.is_suspended(&v.address, epoch))
            .map(|v| v.address)
            .collect();
        let base = if self.proposal.block_number.is_multiple_of(self.epoch_length) {
            let base = registry_weights(state)?;
            (!base.is_empty()).then_some(base)
        } else {
            None
        };
        Ok(OfflineAuthorityTransition { base, suspended })
    }
    pub(super) fn execute<S: KvStore + 'static>(
        &self,
        state: &mut WorldState<S>,
    ) -> Result<(), NodeError> {
        // The transcript commits canonical proof_payload, not receipt position.
        // Imported envelopes were checked at their actual final indices; a
        // producer checks those after final user/reward/STARK selection.
        let mut ledger = state.load_offline_state()?;
        if let Some(members) = &self.initial_members {
            if ledger != shell_core::OfflineState::default() {
                return Err(NodeError::Startup(
                    "offline ledger exists before first activation".into(),
                ));
            }
            ledger
                .sync_membership(members)
                .map_err(NodeError::Startup)?;
        } else if ledger.cursor().is_none() {
            return Err(NodeError::Startup(
                "active offline ledger context missing".into(),
            ));
        }
        ledger.activate_recoveries(self.proposal.epoch);
        state.save_offline_state(&ledger)?;
        for certificate in &self.certificates {
            let tx = certificate
                .system_transaction(0)
                .map_err(|e| NodeError::Startup(e.to_string()))?;
            super::offline_enforcement::execute_timeout_evidence(
                state,
                &tx,
                0,
                &certificate.context,
                &self.authorities,
                &MultiVerifier,
            )?;
        }
        super::offline_enforcement::finish_timeout_proposal(
            state,
            &self.proposal,
            &self.authorities,
        )?;
        state.save_offline_authorities(&self.authorities)?;
        Ok(())
    }
    pub(super) fn append_receipts(
        &self,
        chain_id: u64,
        number: u64,
        user_count: usize,
        gas: u64,
        system: &mut Vec<SystemTransaction>,
        receipts: &mut Vec<TransactionReceipt>,
    ) -> Result<(), NodeError> {
        for certificate in &self.certificates {
            let index = user_count
                .checked_add(system.len())
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| NodeError::Startup("timeout receipt index overflow".into()))?;
            let tx = certificate
                .system_transaction(index)
                .map_err(|e| NodeError::Startup(e.to_string()))?;
            if tx.chain_id != chain_id || tx.block_number != number {
                return Err(NodeError::Startup(
                    "timeout receipt chain/height mismatch".into(),
                ));
            }
            receipts.push(TransactionReceipt {
                tx_hash: tx.hash(),
                block_number: number,
                tx_index: index,
                status: 1,
                gas_used: 0,
                cumulative_gas_used: gas,
                contract_address: None,
                logs_bloom: Bytes::default(),
                logs: vec![],
            });
            system.push(tx);
        }
        Ok(())
    }
    pub(super) fn sync_membership<S: KvStore + 'static>(
        &self,
        state: &mut WorldState<S>,
    ) -> Result<(), NodeError> {
        if !self.proposal.block_number.is_multiple_of(self.epoch_length) {
            return Ok(());
        }
        let members = state.get_validators()?;
        // Match the existing base-authority reload's empty-registry fallback.
        if members.is_empty() {
            return Ok(());
        }
        let mut ledger = state.load_offline_state()?;
        ledger
            .sync_membership(&members)
            .map_err(NodeError::Startup)?;
        state.save_offline_state(&ledger)?;
        Ok(())
    }
}

fn profile<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    height: u64,
) -> Result<Option<shell_storage::OfflineEnforcement>, NodeError> {
    let p = chain
        .get_chain_config()?
        .and_then(|c| c.offline_enforcement)
        .filter(|p| p.is_active(height));
    if let Some(p) = p {
        p.validate()?;
    }
    Ok(p)
}
/// Prospective participation comes from the committed native ledger. Merely
/// observing a timeout or changing a local timer cannot populate this mask.
pub(super) fn certified_participation<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    state: &WorldState<S>,
    head: u64,
) -> Result<(bool, Vec<Address>), NodeError> {
    let Some(p) = chain
        .get_chain_config()?
        .and_then(|c| c.offline_enforcement)
    else {
        return Ok((false, Vec::new()));
    };
    let height = head
        .checked_add(1)
        .ok_or_else(|| NodeError::Startup("offline participation height overflow".into()))?;
    if !p.is_active(height) {
        return Ok((false, Vec::new()));
    }
    let epoch = p.epoch_at(height)?;
    let ledger = state.load_offline_state()?;
    let suspended = ledger
        .validators()
        .iter()
        .filter(|v| ledger.is_suspended(&v.address, epoch))
        .map(|v| v.address)
        .collect();
    Ok((true, suspended))
}

fn verify_certificate<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    certificate: &TimeoutCertificate,
    view: u64,
    authorities: &[(Address, u64)],
    timestamp: u64,
) -> Result<(), NodeError> {
    if certificate.context.view != view {
        return Err(NodeError::Startup(
            "non-contiguous timeout certificate views".into(),
        ));
    }
    let witness = certificate.opportunity.as_ref().ok_or_else(|| {
        NodeError::Startup("timeout certificate has no opportunity witness".into())
    })?;
    let admitted = super::offline_enforcement::admit_timeout_opportunity(
        chain,
        parent,
        view,
        authorities,
        witness,
        timestamp,
        &MultiVerifier,
    )?;
    if admitted
        .eligible_at
        .checked_add(admitted.profile.timeout_secs())
        .is_none_or(|deadline| timestamp < deadline)
    {
        return Err(NodeError::Startup(
            "block precedes certified timeout deadline".into(),
        ));
    }
    shell_consensus::timeout::verify_timeout_certificate(
        certificate,
        &admitted.context,
        authorities,
        &MultiVerifier,
    )?;
    Ok(())
}
fn proposal_opportunity_hash(header: &BlockHeader, view: u64) -> ShellHash {
    let mut digest = b"shell:canonical-proposal:v1".to_vec();
    digest.extend_from_slice(header.parent_hash.as_bytes());
    digest.extend_from_slice(&header.number.to_be_bytes());
    digest.extend_from_slice(&view.to_be_bytes());
    digest.extend_from_slice(header.proposer.as_bytes());
    digest.extend_from_slice(&header.timestamp.to_be_bytes());
    shell_primitives::keccak256(&digest)
}

fn plan<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    header: &BlockHeader,
    certificates: Vec<TimeoutCertificate>,
    authorities: Vec<(Address, u64)>,
) -> Result<OfflineBlockPlan, NodeError> {
    let number = parent
        .number
        .checked_add(1)
        .ok_or_else(|| NodeError::Startup("offline block height overflow".into()))?;
    let p = profile(chain, number)?
        .ok_or_else(|| NodeError::Startup("offline plan requires activation".into()))?;
    if header.number != number || header.parent_hash != parent.hash() {
        return Err(NodeError::Startup(
            "offline block parent/height mismatch".into(),
        ));
    }
    for (view, c) in certificates.iter().enumerate() {
        verify_certificate(
            chain,
            parent,
            c,
            view as u64,
            &authorities,
            header.timestamp,
        )?;
    }
    let view = u64::try_from(certificates.len())
        .map_err(|_| NodeError::Startup("offline view overflow".into()))?;
    if header.proposer != shell_consensus::timeout::timeout_proposer(number, view, &authorities)? {
        return Err(NodeError::Startup(
            "proposal does not match certified final view".into(),
        ));
    }
    let config = chain
        .get_chain_config()?
        .ok_or_else(|| NodeError::Startup("missing offline chain configuration".into()))?;
    let proposal = TimeoutContext {
        chain_id: config.chain_id,
        block_number: number,
        view,
        parent_hash: parent.hash(),
        epoch: p.epoch_at(number)?,
        authority_set_hash: shell_consensus::timeout::timeout_authority_set_hash(&authorities)?,
        proposer: header.proposer,
        opportunity_hash: proposal_opportunity_hash(header, view),
    };
    let initial_members = if !p.is_active(parent.number) {
        Some(initial_epoch_members(
            chain,
            parent,
            p.epoch_length,
            config.genesis_hash,
            &authorities,
        )?)
    } else {
        None
    };
    Ok(OfflineBlockPlan {
        certificates,
        authorities,
        proposal,
        epoch_length: p.epoch_length,
        initial_members,
    })
}

pub(super) fn imported_plan<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    block: &Block,
    authorities: Vec<(Address, u64)>,
) -> Result<Option<OfflineBlockPlan>, NodeError> {
    let Some(p) = profile(chain, block.number())? else {
        return Ok(None);
    };
    let mut certificates = Vec::new();
    let mut tail = false;
    for (offset, tx) in block.system_transactions.iter().enumerate() {
        if tx.kind == SystemTxKind::TimeoutEvidence {
            tail = true;
            let index = block
                .transactions
                .len()
                .checked_add(offset)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| NodeError::Startup("timeout import index overflow".into()))?;
            if tx.source_hash != block.header.parent_hash || tx.block_number != block.number() {
                return Err(NodeError::Startup(
                    "timeout envelope does not bind its enclosing block".into(),
                ));
            }
            certificates.push(
                TimeoutCertificate::from_system_transaction(tx, index)
                    .map_err(NodeError::Startup)?,
            );
        } else if tail {
            return Err(NodeError::Startup(
                "timeout evidence must follow other system transactions".into(),
            ));
        }
    }
    if block.transactions.is_empty()
        && block.system_transactions.is_empty()
        && block.header.timestamp
            < parent
                .timestamp
                .checked_add(p.heartbeat_interval_secs)
                .ok_or_else(|| NodeError::Startup("offline heartbeat overflow".into()))?
    {
        return Err(NodeError::Startup(
            "empty proposal precedes frozen heartbeat eligibility".into(),
        ));
    }
    plan(chain, parent, &block.header, certificates, authorities).map(Some)
}

/// Replay only previously accepted canonical history using the ordered set
/// committed by its sealed native root. A received fork's claimed post-state is
/// not an authority source; that path requires independent parent reconstruction.
pub(super) fn historical_plan<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    block: &Block,
) -> Result<Option<OfflineBlockPlan>, NodeError> {
    if profile(chain, block.number())?.is_none() {
        return Ok(None);
    }
    if chain.get_block_hash_by_number(block.number())? != Some(block.hash()) {
        return Err(NodeError::Startup(
            "offline fork requires independently reconstructed parent authorities".into(),
        ));
    }
    let sealed = WorldState::at_root(chain.store().clone(), &block.header.state_root)?;
    let authorities = sealed.load_offline_authorities()?;
    if authorities.is_empty() {
        return Err(NodeError::Startup(
            "sealed offline authority context unavailable".into(),
        ));
    }
    let ledger = sealed.load_offline_state()?;
    let plan = imported_plan(chain, parent, block, authorities)?
        .ok_or_else(|| NodeError::Startup("missing historical offline plan".into()))?;
    if !ledger
        .cursor()
        .is_some_and(|c| c.proposed && c.context == plan.proposal)
    {
        return Err(NodeError::Startup(
            "sealed offline context does not bind historical block".into(),
        ));
    }
    Ok(Some(plan))
}

fn registry_weights<S: KvStore + 'static>(
    state: &WorldState<S>,
) -> Result<Vec<(Address, u64)>, NodeError> {
    state
        .get_validators()?
        .into_iter()
        .map(|a| Ok((a, state.get_validator_weight(&a)?)))
        .collect()
}

/// Follow the already authenticated parent branch, never a candidate post-root
/// or a mutable canonical height index that could point at another branch.
fn initial_epoch_members<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    epoch_length: u64,
    genesis: ShellHash,
    effective: &[(Address, u64)],
) -> Result<Vec<Address>, NodeError> {
    let base = epoch_base_weights(chain, parent, epoch_length, genesis)?;
    if effective.iter().any(|(address, weight)| {
        !base
            .iter()
            .any(|(member, raw)| member == address && weight <= raw)
    }) {
        return Err(NodeError::Startup(
            "offline activation effective committee differs from epoch base".into(),
        ));
    }
    Ok(base.into_iter().map(|(address, _)| address).collect())
}
fn epoch_base_weights<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    epoch_length: u64,
    genesis: ShellHash,
) -> Result<Vec<(Address, u64)>, NodeError> {
    let boundary = super::authority_reload_height(parent.number, epoch_length);
    let mut header = parent.clone();
    while header.number > boundary {
        let expected = header.parent_hash;
        let previous = chain
            .get_header_by_hash(&expected)?
            .ok_or_else(|| NodeError::Startup("offline epoch ancestor unavailable".into()))?;
        if previous.hash() != expected || previous.number.checked_add(1) != Some(header.number) {
            return Err(NodeError::Startup("offline epoch ancestry mismatch".into()));
        }
        header = previous;
    }
    if header.number != boundary || (boundary == 0 && header.hash() != genesis) {
        return Err(NodeError::Startup(
            "offline epoch boundary identity mismatch".into(),
        ));
    }
    let mut state = WorldState::at_root(chain.store().clone(), &header.state_root)?;
    state.validate()?;
    let base = registry_weights(&state)?;
    if base.is_empty() {
        return Err(NodeError::Startup(
            "offline epoch base registry is empty".into(),
        ));
    }
    Ok(base)
}

/// Stage the adopted head's next-slot base before publishing the replacement.
pub(super) fn fork_head_base<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    head: &BlockHeader,
) -> Result<Option<Vec<(Address, u64)>>, NodeError> {
    let next = head
        .number
        .checked_add(1)
        .ok_or_else(|| NodeError::Startup("offline participation height overflow".into()))?;
    let Some(p) = profile(chain, next)? else {
        return Ok(None);
    };
    let genesis = chain
        .get_chain_config()?
        .ok_or_else(|| NodeError::Startup("missing offline chain config".into()))?
        .genesis_hash;
    epoch_base_weights(chain, head, p.epoch_length, genesis).map(Some)
}

fn sealed_authorities<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    header: &BlockHeader,
) -> Result<Vec<(Address, u64)>, NodeError> {
    let p = profile(chain, header.number)?
        .ok_or_else(|| NodeError::Startup("sealed authority anchor precedes activation".into()))?;
    let state = WorldState::at_root(chain.store().clone(), &header.state_root)?;
    let authorities = state.load_offline_authorities()?;
    let ledger = state.load_offline_state()?;
    let chain_id = chain
        .get_chain_config()?
        .ok_or_else(|| NodeError::Startup("missing offline chain config".into()))?
        .chain_id;
    let c = ledger.cursor().filter(|c| c.proposed).ok_or_else(|| {
        NodeError::Startup("offline fork parent has no final proposal context".into())
    })?;
    if c.context.chain_id != chain_id
        || c.context.block_number != header.number
        || c.context.parent_hash != header.parent_hash
        || c.context.proposer != header.proposer
        || c.context.epoch != p.epoch_at(header.number)?
        || c.context.opportunity_hash != proposal_opportunity_hash(header, c.context.view)
        || c.context.proposer
            != shell_consensus::timeout::timeout_proposer(
                header.number,
                c.context.view,
                &authorities,
            )?
    {
        return Err(NodeError::Startup(
            "offline fork parent context does not bind its header".into(),
        ));
    }
    Ok(authorities)
}

/// Carry a known identity's authenticated reduction into its new base.
/// A fresh identity also needs complete absence of prior economic roles;
/// unavailable or unbounded history is never an assumed zero reduction.
pub(super) fn historical_member_weight<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    address: &Address,
    base_weight: u64,
    profile: &shell_storage::OfflineEnforcement,
    genesis: ShellHash,
) -> Result<u64, NodeError> {
    let mut header = parent.clone();
    while header.number > 0 {
        let previous = chain
            .get_header_by_hash(&header.parent_hash)?
            .ok_or_else(|| {
                NodeError::Startup("offline returning member history unavailable".into())
            })?;
        if previous.hash() != header.parent_hash
            || previous.number.checked_add(1) != Some(header.number)
        {
            return Err(NodeError::Startup(
                "offline returning member ancestry mismatch".into(),
            ));
        }
        let base = epoch_base_weights(chain, &previous, profile.epoch_length, genesis)?;
        if let Some((_, prior_weight)) = base.iter().find(|(a, _)| a == address) {
            if header.number < profile.activation_height {
                return Err(NodeError::Startup(
                    "offline legacy member effective input unavailable".into(),
                ));
            }
            let prior_weight = *prior_weight;
            if let Some((_, effective)) = sealed_authorities(chain, &header)?
                .into_iter()
                .find(|(a, _)| a == address)
            {
                if effective > prior_weight {
                    return Err(NodeError::Startup(
                        "offline returning member effective input exceeds base".into(),
                    ));
                }
                return Ok(base_weight.saturating_sub(prior_weight - effective));
            }
            // A participation mask is not an economic reduction. Its absence
            // is justified only by the verified input parent's native ledger.
            let state = WorldState::at_root(chain.store().clone(), &previous.state_root)?;
            if state
                .load_offline_state()?
                .is_suspended(address, profile.epoch_at(header.number)?)
            {
                header = previous;
                continue;
            }
            return Err(NodeError::Startup(
                "offline returning member effective input unavailable".into(),
            ));
        }
        header = previous;
    }
    if header.hash() != genesis
        || epoch_base_weights(chain, &header, profile.epoch_length, genesis)?
            .iter()
            .any(|(member, _)| member == address)
    {
        return Err(NodeError::Startup(
            "offline new member genesis history mismatch".into(),
        ));
    }
    // Standalone provers can also receive economic reductions. Validator
    // absence alone therefore cannot initialize a fresh weight on a chain
    // whose historical prover admission was unbounded, or whose legacy
    // pre-activation evidence route could create a nonmember reduction.
    if profile.activation_height != 1
        || chain
            .get_chain_config()?
            .and_then(|config| config.prover_registry_height)
            != Some(0)
    {
        return Err(NodeError::Startup(
            "offline new member economic history requires reconstruction".into(),
        ));
    }
    let mut header = parent.clone();
    loop {
        let state = WorldState::at_root(chain.store().clone(), &header.state_root)?;
        if state.get_registered_prover(address)?.is_some() {
            return Err(NodeError::Startup(
                "offline new member has prior prover economic context".into(),
            ));
        }
        if header.number == 0 {
            if header.hash() != genesis {
                return Err(NodeError::Startup(
                    "offline economic history genesis mismatch".into(),
                ));
            }
            break;
        }
        let previous = chain
            .get_header_by_hash(&header.parent_hash)?
            .ok_or_else(|| NodeError::Startup("offline economic history unavailable".into()))?;
        if previous.hash() != header.parent_hash
            || previous.number.checked_add(1) != Some(header.number)
        {
            return Err(NodeError::Startup(
                "offline economic history ancestry mismatch".into(),
            ));
        }
        header = previous;
    }
    Ok(base_weight)
}

/// Derive a foreign child from a previously verified parent's native state,
/// never the child's claimed post-state or the current live penalty map.
/// Transitions whose historical source is not yet represented fail closed.
fn derived_parent_authorities<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    number: u64,
) -> Result<Vec<(Address, u64)>, NodeError> {
    let p = profile(chain, number)?
        .ok_or_else(|| NodeError::Startup("inactive offline fork profile".into()))?;
    if parent.number < p.activation_height {
        return Err(NodeError::Startup(
            "offline fork activation authority transition requires reconstruction".into(),
        ));
    }
    let state = WorldState::at_root(chain.store().clone(), &parent.state_root)?;
    let authorities = sealed_authorities(chain, parent)?;
    let previous = chain
        .get_header_by_hash(&parent.parent_hash)?
        .ok_or_else(|| {
            NodeError::Startup("offline fork parent registry history unavailable".into())
        })?;
    if previous.hash() != parent.parent_hash
        || previous.number.checked_add(1) != Some(parent.number)
    {
        return Err(NodeError::Startup(
            "offline fork parent ancestry mismatch".into(),
        ));
    }
    let genesis = chain
        .get_chain_config()?
        .ok_or_else(|| NodeError::Startup("missing offline chain config".into()))?
        .genesis_hash;
    let base = epoch_base_weights(chain, parent, p.epoch_length, genesis)?;
    let prior_base = epoch_base_weights(chain, &previous, p.epoch_length, genesis)?;
    if authorities
        .iter()
        .any(|(a, w)| !prior_base.iter().any(|(b, base)| a == b && w <= base))
    {
        return Err(NodeError::Startup(
            "offline fork effective authority exceeds canonical base".into(),
        ));
    }
    let epoch = p.epoch_at(number)?;
    let ledger = state.load_offline_state()?;
    let parent_epoch = p.epoch_at(parent.number)?;
    // The verified reload state determines the new order. Reductions belong
    // to identities, so retain them by address while traversing that order;
    // an old vector position cannot authorize the next proposer slot.
    let mut next_authorities = Vec::new();
    for (address, weight) in &base {
        let effective =
            if let Some((_, prior_weight)) = prior_base.iter().find(|(a, _)| a == address) {
                if let Some((_, effective)) = authorities.iter().find(|(a, _)| a == address) {
                    Some(weight.saturating_sub(prior_weight - effective))
                } else if ledger.is_suspended(address, parent_epoch)
                    && !ledger.is_suspended(address, epoch)
                {
                    // Native quorum recovery restores participation from the
                    // last eligible economic input, not an assumed raw weight.
                    Some(historical_member_weight(
                        chain, parent, address, *weight, &p, genesis,
                    )?)
                } else if prior_weight != weight {
                    return Err(NodeError::Startup(
                        "offline reweighted member effective input unavailable".into(),
                    ));
                } else {
                    None
                }
            } else {
                Some(historical_member_weight(
                    chain, parent, address, *weight, &p, genesis,
                )?)
            };
        if let Some(effective) = effective.filter(|weight| *weight > 0) {
            next_authorities.push((*address, effective));
        }
    }
    let authorities = next_authorities
        .into_iter()
        .filter(|(a, _)| !ledger.is_suspended(a, epoch))
        .collect::<Vec<_>>();
    shell_consensus::timeout::timeout_authority_set_hash(&authorities)?;
    Ok(authorities)
}

pub(super) fn replay_plan<S: KvStore + 'static>(
    chain: &ChainStore<S>,
    parent: &BlockHeader,
    block: &Block,
) -> Result<Option<OfflineBlockPlan>, NodeError> {
    if profile(chain, block.number())?.is_none() {
        return Ok(None);
    }
    if chain.get_block_hash_by_number(block.number())? == Some(block.hash()) {
        historical_plan(chain, parent, block)
    } else {
        // An already accepted block at this exact parent/height authenticates
        // the slot input set, even at activation or an epoch boundary. Never
        // use the received child's own claimed post-state as that anchor.
        let anchor = chain
            .get_block_hash_by_number(block.number())?
            .map(|hash| chain.get_header_by_hash(&hash))
            .transpose()?
            .flatten()
            .filter(|header| header.parent_hash == parent.hash());
        let authorities = if let Some(anchor) = anchor {
            sealed_authorities(chain, &anchor)?
        } else {
            derived_parent_authorities(chain, parent, block.number())?
        };
        imported_plan(chain, parent, block, authorities)
    }
}

impl<S: KvStore + 'static> Node<S> {
    /// A known signing key is not historical validator membership. The
    /// configured profile binds both alleged proposal slots to verified parent
    /// epoch bases; present membership cannot authorize a pre-admission header.
    pub(super) fn admits_equivocation_authority(
        &self,
        proof: &shell_consensus::EquivocationProof,
        pubkey: &[u8],
    ) -> Result<Option<bool>, NodeError> {
        let Some(config) = self.chain_store.get_chain_config()? else {
            return Ok(None);
        };
        let Some(profile) = config.offline_enforcement else {
            return Ok(None);
        };
        profile.validate()?;
        let next = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?
            .number()
            .checked_add(1)
            .ok_or_else(|| NodeError::Startup("offline authority height overflow".into()))?;
        if !profile.is_active(next) {
            return Ok(None);
        }

        let Some(kind) = shell_crypto::infer_signature_type_from_address(pubkey, &proof.offender)
        else {
            return Ok(Some(false));
        };
        if !proof
            .seal_a
            .as_ref()
            .is_some_and(|seal| seal.sig_type == kind)
            || !proof
                .seal_b
                .as_ref()
                .is_some_and(|seal| seal.sig_type == kind)
        {
            return Ok(Some(false));
        }
        for header in [&proof.header_a, &proof.header_b] {
            let Some(parent) = self.chain_store.get_header_by_hash(&header.parent_hash)? else {
                return Ok(Some(false));
            };
            if parent.hash() != header.parent_hash
                || parent.number.checked_add(1) != Some(header.number)
            {
                return Ok(Some(false));
            }
            let base = epoch_base_weights(
                &self.chain_store,
                &parent,
                profile.epoch_length,
                config.genesis_hash,
            )?;
            if !base.iter().any(|(address, _)| *address == proof.offender) {
                return Ok(Some(false));
            }
        }
        Ok(Some(true))
    }
    /// The signed target's verified input committee determines its quorum.
    /// Later local penalties and the observer's other branch are not that input.
    pub(super) fn attestation_weights(
        &self,
        block: &Block,
    ) -> Result<HashMap<Address, u64>, NodeError> {
        if profile(&self.chain_store, block.number())?.is_none() {
            return Ok(self.consensus.read().validator_weights());
        }
        let authorities =
            if self.chain_store.get_block_hash_by_number(block.number())? == Some(block.hash()) {
                sealed_authorities(&self.chain_store, &block.header)?
            } else {
                let parent = self
                    .chain_store
                    .get_header_by_hash(&block.header.parent_hash)?
                    .ok_or_else(|| {
                        NodeError::Startup("offline attestation parent unavailable".into())
                    })?;
                self.offline_plan_for_import(&parent, block)?
                    .ok_or_else(|| {
                        NodeError::Startup("offline attestation context unavailable".into())
                    })?
                    .authorities
            };
        Ok(authorities.into_iter().collect())
    }
    pub(super) fn certificate_weights(
        &self,
        number: u64,
        hash: ShellHash,
    ) -> Result<HashMap<Address, u64>, NodeError> {
        let block = self.chain_store.get_block_by_hash(&hash)?;
        if block
            .as_ref()
            .is_some_and(|block| block.number() != number || block.hash() != hash)
        {
            return Err(NodeError::Startup(
                "certificate target identity mismatch".into(),
            ));
        }
        if profile(&self.chain_store, number)?.is_none() {
            return Ok(self.consensus.read().validator_weights());
        }
        let block = block
            .ok_or_else(|| NodeError::Startup("offline certificate target unavailable".into()))?;
        self.attestation_weights(&block)
    }
    pub(super) fn timeout_authorities(&self) -> Vec<(Address, u64)> {
        let engine = self.consensus.read();
        let weights = engine.validator_weights();
        engine
            .poa_config()
            .authorities
            .iter()
            .filter_map(|a| weights.get(a).copied().filter(|w| *w > 0).map(|w| (*a, w)))
            .collect()
    }
    pub(super) fn offline_plan_for_import(
        &self,
        parent: &BlockHeader,
        block: &Block,
    ) -> Result<Option<OfflineBlockPlan>, NodeError> {
        if profile(&self.chain_store, block.number())?.is_none() {
            return Ok(None);
        }
        if self.chain_store.get_head_hash()? == Some(parent.hash()) {
            return imported_plan(&self.chain_store, parent, block, self.timeout_authorities());
        }
        let parent_block = self
            .chain_store
            .get_block_by_hash(&parent.hash())?
            .ok_or_else(|| NodeError::Startup("offline fork parent body unavailable".into()))?;
        let store = self.side_fork_parent_store(&parent_block)?;
        let chain = ChainStore::new(store.clone());
        chain.set_head(&parent.hash())?;
        let state = WorldState::at_root(store, &parent.state_root)?;
        let registry = load_algorithm_registry(&state)
            .map_err(|e| NodeError::Startup(format!("offline fork parent registry: {e}")))?;
        with_algorithm_registry_override(&registry, || replay_plan(&chain, parent, block))
    }
    fn retained_timeout_chain(
        &self,
        parent: &BlockHeader,
        timestamp: u64,
    ) -> Result<Vec<TimeoutCertificate>, NodeError> {
        let number = parent
            .number
            .checked_add(1)
            .ok_or_else(|| NodeError::Startup("timeout height overflow".into()))?;
        let set = self.timeout_authorities();
        let mut grouped = std::collections::BTreeMap::<u64, TimeoutCertificate>::new();
        for c in self.chain_store.get_timeout_certificates(
            &parent.hash(),
            self.config.chain_id,
            number,
        )? {
            grouped.entry(c.context.view).or_insert(c);
        }
        let mut chain = Vec::new();
        while let Some(c) = grouped.remove(&(chain.len() as u64)) {
            verify_certificate(
                &self.chain_store,
                parent,
                &c,
                chain.len() as u64,
                &set,
                timestamp,
            )?;
            chain.push(c);
        }
        Ok(chain)
    }
    /// Restore only a complete independently reverified durable chain. A raw
    /// timer, journal count or unflushed vote cannot advance the live view.
    pub(crate) fn recover_certified_timeout_view(&self) -> Result<(), NodeError> {
        if !self.certified_timeout_profile_active()? {
            return Ok(());
        }
        let parent = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let chain = self.retained_timeout_chain(&parent.header, Self::wall_clock_secs())?;
        let view = chain.len() as u64;
        let mut engine = self.consensus.write();
        if engine.current_view() > view {
            return Err(NodeError::Startup(
                "live certified view lacks durable evidence".into(),
            ));
        }
        if view > engine.current_view() {
            engine.set_certified_view(view)?;
        }
        Ok(())
    }
    pub(super) fn offline_plan_for_production(
        &self,
        parent: &BlockHeader,
        header: &BlockHeader,
    ) -> Result<Option<OfflineBlockPlan>, NodeError> {
        if profile(&self.chain_store, header.number)?.is_none() {
            return Ok(None);
        }
        let certificates = self.retained_timeout_chain(parent, header.timestamp)?;
        let view = self.consensus.read().current_view();
        if certificates.len() as u64 != view {
            return Err(NodeError::Startup(
                "production view does not match durable certificate chain".into(),
            ));
        }
        plan(
            &self.chain_store,
            parent,
            header,
            certificates,
            self.timeout_authorities(),
        )
        .map(Some)
    }
}
