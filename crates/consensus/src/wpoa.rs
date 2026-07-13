//! Weighted Proof-of-Authority (wPoA) consensus engine.
//!
//! Extends the basic PoA round-robin with per-validator weights so that
//! validators with a higher stake/reputation are elected to propose more
//! blocks proportionally.
//!
//! Proposer selection uses **weighted round-robin**:
//!   - `total_weight` = sum of active validator weights.
//!   - `slot = block_number % total_weight`.
//!   - The validator whose cumulative-weight window contains `slot` is elected.
//!
//! For signature verification and block sealing, `WPoaEngine` delegates to
//! the existing `PoaEngine` logic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use shell_core::{Block, BlockHeader};
use shell_crypto::{PQSignature, Signer, Verifier};
use shell_primitives::Address;

use crate::poa::PoaEngine;
use crate::validator::{ValidatorSet, ValidatorSetConfig};
use crate::{
    ConsensusEngine, ConsensusError, EngineType, PoaConfig, ViewChangeMessage, ViewChangeState,
};

/// Configuration for the weighted PoA engine.
#[derive(Debug, Clone)]
pub struct WPoaConfig {
    /// Base PoA configuration (authority list, block time, etc.).
    pub poa: PoaConfig,
    /// Initial validator weights indexed by position in `poa.authorities`.
    ///
    /// If shorter than `authorities`, missing entries default to weight 1.
    pub weights: Vec<u64>,
    /// Validator set lifecycle parameters.
    pub validator_set_config: ValidatorSetConfig,
    /// Chain ID used to reject cross-chain view-change messages.
    /// 0 means unconfigured (no chain-ID enforcement in `ViewChangeState`).
    pub chain_id: u64,
}

impl WPoaConfig {
    /// Create a `WPoaConfig` from a `PoaConfig` with uniform weights.
    pub fn from_poa(poa: PoaConfig) -> Self {
        let n = poa.authorities.len();
        Self {
            poa,
            weights: vec![1u64; n],
            validator_set_config: ValidatorSetConfig::default(),
            chain_id: 0,
        }
    }

    /// Create a `WPoaConfig` with explicit per-validator weights.
    ///
    /// `weights` is aligned with `poa.authorities` by index. Missing entries
    /// default to weight 1.
    pub fn with_weights(poa: PoaConfig, weights: Vec<u64>) -> Self {
        Self {
            weights,
            poa,
            validator_set_config: ValidatorSetConfig::default(),
            chain_id: 0,
        }
    }
}

/// Weighted Proof-of-Authority consensus engine.
///
/// Delegates seal verification to `PoaEngine` and overrides proposer
/// selection with weighted round-robin via `ValidatorSet`.
pub struct WPoaEngine {
    inner: PoaEngine,
    validator_set: ValidatorSet,
    validator_set_config: ValidatorSetConfig,
    slash_weights: HashMap<Address, u64>,
    view_change_state: Mutex<ViewChangeState>,
    signer: Option<Arc<dyn Signer>>,
}

impl WPoaEngine {
    fn view_change_state(&self) -> MutexGuard<'_, ViewChangeState> {
        self.view_change_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Construct a `WPoaEngine` from a `WPoaConfig`.
    pub fn new(config: WPoaConfig, _verifier: Arc<dyn Verifier>) -> Self {
        let mut poa = config.poa;
        let weights: Vec<u64> = poa
            .authorities
            .iter()
            .enumerate()
            .map(|(i, _)| {
                config
                    .weights
                    .get(i)
                    .copied()
                    .unwrap_or(1)
                    .clamp(1, shell_primitives::MAX_VALIDATOR_WEIGHT)
            })
            .collect();
        poa.authority_weights = weights.clone();

        let entries = poa.authorities.iter().copied().zip(weights);

        let validator_set =
            ValidatorSet::from_genesis(entries, config.validator_set_config.clone());

        let mut view_change_state = ViewChangeState::new();
        if config.chain_id != 0 {
            view_change_state.set_chain_id(config.chain_id);
        }

        Self {
            inner: PoaEngine::new(poa),
            validator_set,
            validator_set_config: config.validator_set_config,
            slash_weights: HashMap::new(),
            view_change_state: Mutex::new(view_change_state),
            signer: None,
        }
    }

    /// Attach a signer so this engine can seal blocks.
    pub fn with_signer(mut self, signer: Arc<dyn Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Access the underlying `ValidatorSet`.
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Mutable access to the `ValidatorSet` (for epoch boundary updates).
    pub fn validator_set_mut(&mut self) -> &mut ValidatorSet {
        &mut self.validator_set
    }

    /// Return the expected proposer for `block_number` under the current view.
    pub fn proposer_for_block(&self, block_number: u64) -> Address {
        let view = self.current_view();
        self.proposer_for_block_in_view(block_number, view)
    }

    fn base_proposer_for_block(&self, block_number: u64) -> Address {
        self.validator_set
            .weighted_proposer(block_number)
            .unwrap_or_else(|| self.inner.config().proposer_for_block(block_number))
    }

    fn proposer_for_block_in_view(&self, block_number: u64, view: u64) -> Address {
        if view == 0 {
            return self.base_proposer_for_block(block_number);
        }

        let authorities = &self.inner.config().authorities;
        if authorities.is_empty() {
            return self.base_proposer_for_block(block_number);
        }

        let base = self.base_proposer_for_block(block_number);
        let base_index = authorities
            .iter()
            .position(|candidate| *candidate == base)
            .unwrap_or(0);
        let rotated: Vec<Address> = authorities[base_index..]
            .iter()
            .chain(authorities[..base_index].iter())
            .copied()
            .collect();

        ViewChangeState::select_proposer(view, &rotated)
    }

    pub fn handle_view_change_message(
        &mut self,
        msg: ViewChangeMessage,
        total_weight: u64,
    ) -> bool {
        let validator_weights = self.validator_weights();
        let mut state = self.view_change_state();

        if msg.view != state.current_view {
            return false;
        }

        state.configure_quorum(validator_weights, total_weight);
        if state.record_view_change(msg) {
            state.advance_view();
            true
        } else {
            false
        }
    }

    fn reset_view_change_state(&mut self, now_ms: u64) {
        self.view_change_state().reset_for_block(now_ms);
    }

    fn current_view(&self) -> u64 {
        self.view_change_state().current_view
    }

    fn base_weight_for(&self, authority: &Address) -> Option<u64> {
        self.validator_set
            .get(authority)
            .map(|validator| validator.weight)
            .or_else(|| {
                let idx = self
                    .inner
                    .config()
                    .authorities
                    .iter()
                    .position(|candidate| candidate == authority)?;
                Some(
                    self.inner
                        .config()
                        .authority_weights
                        .get(idx)
                        .copied()
                        .unwrap_or(1)
                        .max(1),
                )
            })
    }

    fn effective_weight_for(&self, authority: &Address) -> Option<u64> {
        self.base_weight_for(authority).map(|base_weight| {
            let reduction = self.slash_weights.get(authority).copied().unwrap_or(0);
            base_weight.saturating_sub(reduction)
        })
    }

    fn apply_slash(&mut self, offender: &Address) {
        self.inner.config_mut().slash_authority(offender);

        let current_weight = self.effective_weight_for(offender).unwrap_or(1);
        let slash_amount = ((current_weight as u128)
            * (self.inner.config().slash_weight_bps as u128)
            / 10_000u128) as u64;
        let base_weight = self.base_weight_for(offender).unwrap_or(1);
        let cumulative = self.slash_weights.get(offender).copied().unwrap_or(0);
        let updated = cumulative.saturating_add(slash_amount).min(base_weight);
        self.slash_weights.insert(*offender, updated);
    }
}

#[async_trait]
impl ConsensusEngine for WPoaEngine {
    fn verify_header(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Check proposer is in the active set.
        if !self.validator_set.is_active(&header.proposer) {
            return Err(ConsensusError::UnknownProposer(header.proposer));
        }

        // Check weighted proposer assignment.
        let expected = self.proposer_for_block(header.number);
        if header.proposer != expected {
            return Err(ConsensusError::InvalidProposer {
                expected,
                got: header.proposer,
            });
        }

        // NOTE: `verify_header` only receives a `BlockHeader`, which does not
        // carry the proposer seal (`Block::proposer_seal`). Full PQ-signature
        // seal verification requires both the header hash and the seal bytes
        // from the enclosing `Block`, as well as a public-key lookup against
        // `ChainStore`. That verification is the responsibility of the block
        // import pipeline (e.g. `verify_header_with_parent` / `import_block`),
        // not this method.
        //
        // This method intentionally limits itself to the structural checks that
        // can be performed without ChainStore access:
        //   1. Proposer is in the active validator set (checked above).
        //   2. Proposer matches the weighted round-robin slot (checked above).
        Ok(())
    }

    async fn seal_block(&self, block: &mut Block) -> Result<(), ConsensusError> {
        let signer = self.signer.as_ref().ok_or(ConsensusError::NoSigner)?;

        let expected = self.proposer_for_block(block.header.number);
        if block.header.proposer != expected {
            return Err(ConsensusError::InvalidProposer {
                expected,
                got: block.header.proposer,
            });
        }

        let header_hash = block.header.hash();
        let seal = signer
            .sign(header_hash.as_bytes())
            .map_err(|e| ConsensusError::SigningError(e.to_string()))?;
        block.proposer_seal = Some(seal);
        Ok(())
    }

    fn is_proposer(&self, block_number: u64, address: &Address) -> bool {
        self.proposer_for_block(block_number) == *address
    }

    fn engine_type(&self) -> EngineType {
        EngineType::WPoA
    }

    fn poa_config(&self) -> &crate::PoaConfig {
        self.inner.config()
    }

    fn poa_config_mut(&mut self) -> &mut crate::PoaConfig {
        self.inner.config_mut()
    }

    fn sign_block(&self, block: &mut Block, signer: &dyn Signer) -> Result<(), ConsensusError> {
        let expected = self.proposer_for_block(block.header.number);
        if block.header.proposer != expected {
            return Err(ConsensusError::InvalidProposer {
                expected,
                got: block.header.proposer,
            });
        }
        let header_hash = block.header.hash();
        let sig = signer
            .sign(header_hash.as_bytes())
            .map_err(|e| ConsensusError::SealingFailed(e.to_string()))?;
        block.proposer_seal = Some(sig);
        Ok(())
    }

    fn verify_seal(
        &self,
        header: &BlockHeader,
        seal: &PQSignature,
        proposer_pubkey: &[u8],
        verifier: &dyn Verifier,
    ) -> Result<(), ConsensusError> {
        let header_hash = header.hash();
        let valid = verifier
            .verify(proposer_pubkey, header_hash.as_bytes(), seal)
            .map_err(|_| ConsensusError::InvalidSignature)?;
        if !valid {
            return Err(ConsensusError::InvalidSignature);
        }
        Ok(())
    }

    fn slash_authority(&mut self, offender: &Address) {
        self.apply_slash(offender);
    }

    fn set_authorities(&mut self, authorities: Vec<Address>) {
        let current_weights = self.validator_weights();
        let weights: Vec<u64> = authorities
            .iter()
            .map(|addr| current_weights.get(addr).copied().unwrap_or(1))
            .collect();
        self.set_authorities_with_weights(authorities, weights);
    }

    fn set_authorities_with_weights(&mut self, authorities: Vec<Address>, weights: Vec<u64>) {
        assert!(!authorities.is_empty(), "authority set must not be empty");
        let weights: Vec<u64> = (0..authorities.len())
            .map(|idx| {
                weights
                    .get(idx)
                    .copied()
                    .unwrap_or(1)
                    .clamp(1, shell_primitives::MAX_VALIDATOR_WEIGHT)
            })
            .collect();

        {
            let config = self.inner.config_mut();
            config.authorities = authorities.clone();
            config.authority_weights = weights.clone();
        }
        self.validator_set = ValidatorSet::from_genesis(
            authorities.into_iter().zip(weights),
            self.validator_set_config.clone(),
        );
    }

    fn validator_weights(&self) -> HashMap<Address, u64> {
        self.validator_set
            .active_validators()
            .into_iter()
            .map(|validator| {
                (
                    validator.address,
                    self.effective_weight_for(&validator.address)
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    fn handle_view_change_message(&mut self, msg: ViewChangeMessage, total_weight: u64) -> bool {
        WPoaEngine::handle_view_change_message(self, msg, total_weight)
    }

    fn current_view(&self) -> u64 {
        WPoaEngine::current_view(self)
    }

    fn check_view_change_timeout(&self, now_ms: u64, block_time_ms: u64) -> bool {
        self.view_change_state()
            .check_timeout(now_ms, block_time_ms)
    }

    fn note_block_progress(&mut self, now_ms: u64) {
        self.reset_view_change_state(now_ms);
    }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{poa::PoaConfig, VIEW_CHANGE_TIMEOUT_MS};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::ShellHash;

    fn addr(n: u8) -> Address {
        Address::from([n; 20])
    }

    struct MockVerifier;
    impl Verifier for MockVerifier {
        fn verify(
            &self,
            _pk: &[u8],
            _msg: &[u8],
            _sig: &PQSignature,
        ) -> Result<bool, shell_crypto::CryptoError> {
            Ok(true)
        }

        fn sig_type(&self) -> SignatureType {
            SignatureType::Dilithium3
        }
    }

    fn engine(authorities: Vec<Address>, weights: Vec<u64>) -> WPoaEngine {
        engine_with_slash_bps(authorities, weights, 1_000)
    }

    fn engine_with_slash_bps(
        authorities: Vec<Address>,
        weights: Vec<u64>,
        slash_weight_bps: u64,
    ) -> WPoaEngine {
        let mut poa = PoaConfig::new(authorities, 2);
        poa.slash_weight_bps = slash_weight_bps;
        let config = WPoaConfig::with_weights(poa, weights);
        WPoaEngine::new(config, Arc::new(MockVerifier))
    }

    #[test]
    fn proposer_uniform_weights() {
        let e = engine(vec![addr(1), addr(2), addr(3)], vec![1, 1, 1]);
        assert_eq!(e.proposer_for_block(0), addr(1));
        assert_eq!(e.proposer_for_block(1), addr(2));
        assert_eq!(e.proposer_for_block(2), addr(3));
        assert_eq!(e.proposer_for_block(3), addr(1));
    }

    #[test]
    fn proposer_non_uniform_weights() {
        // A:2, B:1 → A gets blocks 0,1; B gets block 2; wraps
        let e = engine(vec![addr(1), addr(2)], vec![2, 1]);
        assert_eq!(e.proposer_for_block(0), addr(1));
        assert_eq!(e.proposer_for_block(1), addr(1));
        assert_eq!(e.proposer_for_block(2), addr(2));
        assert_eq!(e.proposer_for_block(3), addr(1));
    }

    #[test]
    fn is_proposer_returns_correct_result() {
        let e = engine(vec![addr(1), addr(2)], vec![1, 1]);
        assert!(e.is_proposer(0, &addr(1)));
        assert!(!e.is_proposer(0, &addr(2)));
        assert!(e.is_proposer(1, &addr(2)));
    }

    #[test]
    fn engine_type_is_wpoa() {
        let e = engine(vec![addr(1)], vec![1]);
        assert_eq!(e.engine_type(), EngineType::WPoA);
    }

    #[test]
    fn poa_config_metadata_uses_wpoa_weights() {
        let e = engine(vec![addr(1), addr(2)], vec![2, 1]);

        assert_eq!(e.proposer_for_block(0), addr(1));
        assert_eq!(e.poa_config().proposer_for_block(0), addr(1));
        assert_eq!(e.proposer_for_block(1), addr(1));
        assert_eq!(e.poa_config().proposer_for_block(1), addr(1));
        assert_eq!(e.proposer_for_block(2), addr(2));
        assert_eq!(e.poa_config().proposer_for_block(2), addr(2));
    }

    #[test]
    fn set_authorities_updates_wpoa_validator_set() {
        let mut e = engine(vec![addr(1), addr(2)], vec![2, 1]);

        e.set_authorities(vec![addr(1), addr(3)]);

        assert!(e.validator_set().is_active(&addr(1)));
        assert!(!e.validator_set().is_active(&addr(2)));
        assert!(e.validator_set().is_active(&addr(3)));
        assert_eq!(e.validator_weights().get(&addr(1)), Some(&2));
        assert_eq!(e.validator_weights().get(&addr(3)), Some(&1));
        assert_eq!(e.proposer_for_block(0), addr(1));
        assert_eq!(e.proposer_for_block(1), addr(1));
        assert_eq!(e.proposer_for_block(2), addr(3));
    }

    #[test]
    fn set_authorities_with_weights_uses_canonical_weights() {
        let mut e = engine(vec![addr(1), addr(2)], vec![1, 1]);

        e.set_authorities_with_weights(vec![addr(1), addr(3)], vec![4, 2]);

        assert_eq!(e.validator_weights().get(&addr(1)), Some(&4));
        assert_eq!(e.validator_weights().get(&addr(3)), Some(&2));
        assert_eq!(e.poa_config().authority_weights, vec![4, 2]);
        assert_eq!(e.proposer_for_block(0), addr(1));
        assert_eq!(e.proposer_for_block(3), addr(1));
        assert_eq!(e.proposer_for_block(4), addr(3));
    }

    #[test]
    fn slash_reduces_weight_by_bps() {
        let mut e = engine_with_slash_bps(vec![addr(1), addr(2)], vec![100, 50], 1_000);

        e.slash_authority(&addr(1));

        let weights = e.validator_weights();
        assert_eq!(weights.get(&addr(1)), Some(&90));
        assert_eq!(weights.get(&addr(2)), Some(&50));
    }

    #[test]
    fn multiple_slashes_are_cumulative() {
        let mut e = engine_with_slash_bps(vec![addr(1)], vec![100], 1_000);

        e.slash_authority(&addr(1));
        e.slash_authority(&addr(1));

        assert_eq!(e.validator_weights().get(&addr(1)), Some(&81));
    }

    #[test]
    fn slash_weight_floors_at_zero() {
        let mut e = engine_with_slash_bps(vec![addr(1)], vec![10], 10_000);

        e.slash_authority(&addr(1));
        e.slash_authority(&addr(1));

        assert_eq!(e.validator_weights().get(&addr(1)), Some(&0));
    }

    #[test]
    fn unslashed_validators_are_unaffected() {
        let mut e = engine_with_slash_bps(vec![addr(1), addr(2)], vec![40, 60], 2_500);

        e.slash_authority(&addr(2));

        let weights = e.validator_weights();
        assert_eq!(weights.get(&addr(1)), Some(&40));
        assert_eq!(weights.get(&addr(2)), Some(&45));
    }

    #[test]
    fn view_change_quorum_advances_view() {
        let mut e = engine(vec![addr(1), addr(2), addr(3)], vec![1, 1, 1]);

        assert!(!e.handle_view_change_message(
            ViewChangeMessage::new(0, 7, 0, ShellHash::ZERO, addr(1), vec![1]),
            3,
        ));
        assert!(e.handle_view_change_message(
            ViewChangeMessage::new(0, 7, 0, ShellHash::ZERO, addr(2), vec![2]),
            3,
        ));
        assert_eq!(e.current_view(), 1);
        assert_eq!(e.proposer_for_block(0), addr(2));
    }

    #[test]
    fn note_block_progress_resets_view_change_state() {
        let mut e = engine(vec![addr(1), addr(2), addr(3)], vec![1, 1, 1]);

        assert!(!e.handle_view_change_message(
            ViewChangeMessage::new(0, 9, 0, ShellHash::ZERO, addr(1), vec![1]),
            3,
        ));
        assert!(e.handle_view_change_message(
            ViewChangeMessage::new(0, 9, 0, ShellHash::ZERO, addr(2), vec![2]),
            3,
        ));
        assert_eq!(e.current_view(), 1);

        e.note_block_progress(42);

        assert_eq!(e.current_view(), 0);
        assert!(!e.check_view_change_timeout(42 + VIEW_CHANGE_TIMEOUT_MS - 1, 1_000));
    }

    #[test]
    fn poisoned_view_change_lock_does_not_halt_consensus() {
        let mut e = engine(vec![addr(1)], vec![1]);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = e.view_change_state.lock().unwrap();
            panic!("poison view-change state for test");
        }));

        assert_eq!(e.current_view(), 0);
        assert!(!e.check_view_change_timeout(1, 1_000));
        e.note_block_progress(1);
    }
}
