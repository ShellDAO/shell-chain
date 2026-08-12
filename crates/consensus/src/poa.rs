use std::collections::{HashMap, HashSet};

use shell_core::{Block, BlockHeader};
use shell_crypto::{PQSignature, Signer, Verifier};
use shell_primitives::{keccak256, Address};

use crate::{round_robin_index, ConsensusEngine, ConsensusError, EngineType};

/// PoA configuration: authority list and block timing.
#[derive(Debug, Clone)]
pub struct PoaConfig {
    /// Ordered list of authority addresses. Position determines round-robin slot.
    pub authorities: Vec<Address>,
    /// Optional per-authority weights. When non-empty, `authorities` and `authority_weights`
    /// must have the same length. Zero-weight authorities are treated as weight 1.
    /// When empty, all authorities are assigned equal weight (standard round-robin).
    pub authority_weights: Vec<u64>,
    /// Minimum seconds between consecutive blocks.
    pub block_time_secs: u64,
    /// Maximum seconds a block timestamp may be ahead of the current wall-clock.
    /// Prevents miners from pre-dating blocks to gain proposer slots.
    pub max_future_secs: u64,
    /// Number of blocks per epoch. 0 means no epochs (legacy behavior).
    pub epoch_length: u64,
    /// Authorities that have been slashed for equivocation. The set records
    /// offenses for observability; economic penalties are tracked in-engine.
    pub slashed: HashSet<Address>,
    /// Weight reduction applied per slash, in basis points.
    pub slash_weight_bps: u64,
}

/// Default maximum future timestamp tolerance (60 seconds).
const DEFAULT_MAX_FUTURE_SECS: u64 = 60;

impl PoaConfig {
    pub fn new(authorities: Vec<Address>, block_time_secs: u64) -> Self {
        Self {
            authorities,
            authority_weights: Vec::new(),
            block_time_secs,
            max_future_secs: DEFAULT_MAX_FUTURE_SECS,
            epoch_length: 0,
            slashed: HashSet::new(),
            slash_weight_bps: 1_000,
        }
    }

    pub fn with_max_future_secs(mut self, secs: u64) -> Self {
        self.max_future_secs = secs;
        self
    }

    pub fn with_epoch_length(mut self, epoch_length: u64) -> Self {
        self.epoch_length = epoch_length;
        self
    }

    /// Attach per-authority weights for weighted proposer rotation.
    ///
    /// `weights` must have the same length as `authorities`. Zero-weight
    /// entries are normalised to 1. Panics if lengths differ.
    pub fn with_weights(mut self, weights: Vec<u64>) -> Self {
        assert_eq!(
            weights.len(),
            self.authorities.len(),
            "authority_weights length must equal authorities length"
        );
        self.authority_weights = weights
            .into_iter()
            .map(|weight| weight.clamp(1, shell_primitives::MAX_VALIDATOR_WEIGHT))
            .collect();
        self
    }

    /// Returns the epoch number for a given block.
    pub fn epoch_of(&self, block_number: u64) -> u64 {
        if self.epoch_length == 0 {
            return 0;
        }
        block_number.checked_div(self.epoch_length).unwrap_or(0)
    }

    /// Returns true if `block_number` is the first block of a new epoch.
    pub fn is_epoch_boundary(&self, block_number: u64) -> bool {
        if self.epoch_length == 0 {
            return false;
        }
        block_number.is_multiple_of(self.epoch_length)
    }

    /// Return the expected proposer for a given block number.
    ///
    /// If `authority_weights` is non-empty, delegates to
    /// [`weighted_proposer_for_block`]; otherwise uses simple round-robin.
    pub fn proposer_for_block(&self, block_number: u64) -> Address {
        let n = self.authorities.len();
        if n == 0 {
            return Address::default();
        }
        if !self.authority_weights.is_empty() {
            return self.weighted_proposer_for_block(block_number);
        }
        let idx = if self.epoch_length > 0 {
            round_robin_index(block_number.checked_rem(self.epoch_length).unwrap_or(0), n)
        } else {
            round_robin_index(block_number, n)
        }
        .unwrap_or(0);
        self.authorities
            .get(idx)
            .copied()
            .unwrap_or_else(|| unreachable!("idx < authorities.len()"))
    }

    /// Weighted proposer selection for a given block number.
    ///
    /// Uses a deterministic hash-based virtual-lottery to map a block number to
    /// a proposer slot weighted by `authority_weights`. Authorities with higher
    /// weight receive proportionally more slots.
    ///
    /// Algorithm:
    /// 1. Compute `seed = keccak256(block_number_le_bytes)`.
    /// 2. Convert the first 8 bytes of the seed to a `u64`.
    /// 3. `ticket = seed_u64 % total_weight`.
    /// 4. Walk the authorities in order, accumulating weight; select the first
    ///    authority whose cumulative weight exceeds `ticket`.
    ///
    /// Guarantees determinism: same `block_number` always yields the same proposer
    /// regardless of which node evaluates it.
    pub fn weighted_proposer_for_block(&self, block_number: u64) -> Address {
        debug_assert_eq!(
            self.authority_weights.len(),
            self.authorities.len(),
            "weights/authorities length mismatch"
        );
        let n = self.authorities.len();
        if n == 0 {
            return Address::default();
        }

        // Sum with overflow check; saturate to u64::MAX if weights are extreme (prevents
        // wraparound that would cause biased selection or division-by-zero risks).
        let total_weight: u64 = self
            .authority_weights
            .iter()
            .map(|&weight| weight.clamp(1, shell_primitives::MAX_VALIDATOR_WEIGHT))
            .try_fold(0u64, |acc, weight| acc.checked_add(weight))
            .unwrap_or(u64::MAX);

        // Deterministic seed from block number.
        let seed_bytes = keccak256(&block_number.to_le_bytes());
        let seed_u64 =
            u64::from_le_bytes(seed_bytes.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
        let ticket = seed_u64 % total_weight;

        let mut cumulative: u64 = 0;
        for (i, &weight) in self.authority_weights.iter().enumerate() {
            cumulative =
                cumulative.saturating_add(weight.clamp(1, shell_primitives::MAX_VALIDATOR_WEIGHT));
            if ticket < cumulative {
                return self.authorities[i];
            }
        }
        // Fallback (unreachable if total_weight > 0).
        self.authorities[n - 1]
    }

    pub fn is_authority(&self, address: &Address) -> bool {
        self.authorities.contains(address)
    }

    /// Record an in-memory slash for `offender`.
    pub fn slash_authority(&mut self, offender: &Address) {
        self.slashed.insert(*offender);
    }

    /// Replace the authority set. Panics if the new set is empty.
    pub fn set_authorities(&mut self, new_authorities: Vec<Address>) {
        assert!(
            !new_authorities.is_empty(),
            "authority set must not be empty"
        );
        self.authority_weights.clear();
        self.authorities = new_authorities;
    }
}

/// Proof-of-Authority consensus engine.
///
/// Round-robin proposer selection based on `block_number % authority_count`.
/// Each block must be sealed with the proposer's PQ signature.
pub struct PoaEngine {
    config: PoaConfig,
    slash_weights: HashMap<Address, u64>,
}

impl PoaEngine {
    pub fn new(config: PoaConfig) -> Self {
        Self {
            config,
            slash_weights: HashMap::new(),
        }
    }

    pub fn config(&self) -> &PoaConfig {
        &self.config
    }

    /// Mutable access to the consensus configuration (e.g. for validator set updates).
    pub fn config_mut(&mut self) -> &mut PoaConfig {
        &mut self.config
    }

    fn base_weight_at(&self, index: usize) -> u64 {
        self.config
            .authority_weights
            .get(index)
            .copied()
            .unwrap_or(1)
            .max(1)
    }

    fn base_weight_for(&self, authority: &Address) -> Option<u64> {
        let idx = self
            .config
            .authorities
            .iter()
            .position(|candidate| candidate == authority)?;
        Some(self.base_weight_at(idx))
    }

    fn effective_weight_at(&self, index: usize) -> u64 {
        let authority = self.config.authorities[index];
        let reduction = self.slash_weights.get(&authority).copied().unwrap_or(0);
        self.base_weight_at(index).saturating_sub(reduction)
    }

    fn effective_weight_for(&self, authority: &Address) -> Option<u64> {
        let index = self
            .config
            .authorities
            .iter()
            .position(|candidate| candidate == authority)?;
        Some(self.effective_weight_at(index))
    }

    /// Determine the expected proposer for `block_number` after applying current
    /// slash state. Authorities with effective weight `0` are excluded.
    fn expected_proposer_for_block(&self, block_number: u64) -> Address {
        if self.config.authorities.is_empty() {
            return Address::default();
        }

        let mut active_count = 0usize;
        let mut total_weight = 0u64;
        for index in 0..self.config.authorities.len() {
            let weight = self.effective_weight_at(index);
            if weight > 0 {
                active_count = active_count.saturating_add(1);
                total_weight = total_weight.saturating_add(weight);
            }
        }

        if active_count == 0 {
            return Address::default();
        }

        if self.config.authority_weights.is_empty() {
            let idx = if self.config.epoch_length > 0 {
                round_robin_index(
                    block_number
                        .checked_rem(self.config.epoch_length)
                        .unwrap_or(0),
                    active_count,
                )
            } else {
                round_robin_index(block_number, active_count)
            }
            .unwrap_or(0);
            return self
                .config
                .authorities
                .iter()
                .enumerate()
                .filter(|(index, _)| self.effective_weight_at(*index) > 0)
                .nth(idx)
                .map(|(_, authority)| *authority)
                .unwrap_or_default();
        }

        let seed_bytes = keccak256(&block_number.to_le_bytes());
        let seed_u64 =
            u64::from_le_bytes(seed_bytes.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
        let ticket = seed_u64 % total_weight;

        let mut cumulative = 0u64;
        let mut last_active = Address::default();
        for (index, authority) in self.config.authorities.iter().enumerate() {
            let weight = self.effective_weight_at(index);
            if weight == 0 {
                continue;
            }
            last_active = *authority;
            cumulative = cumulative.saturating_add(weight);
            if ticket < cumulative {
                return *authority;
            }
        }

        last_active
    }

    /// Slash an authority for equivocation.
    pub fn slash_authority(&mut self, offender: &Address) {
        self.config.slash_authority(offender);

        let current_weight = self.effective_weight_for(offender).unwrap_or(1);
        let slash_amount =
            ((current_weight as u128) * (self.config.slash_weight_bps as u128) / 10_000u128) as u64;
        let base_weight = self.base_weight_for(offender).unwrap_or(1);
        let cumulative = self.slash_weights.get(offender).copied().unwrap_or(0);
        let updated = cumulative.saturating_add(slash_amount).min(base_weight);
        self.slash_weights.insert(*offender, updated);
    }

    fn verify_proposer(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        if self.effective_weight_for(&header.proposer).unwrap_or(0) == 0 {
            return Err(ConsensusError::UnknownProposer(header.proposer));
        }

        let expected = self.expected_proposer_for_block(header.number);
        if header.proposer != expected {
            return Err(ConsensusError::InvalidProposer {
                expected,
                got: header.proposer,
            });
        }
        Ok(())
    }

    fn verify_timestamp(
        &self,
        header: &BlockHeader,
        parent: Option<&BlockHeader>,
        current_time: u64,
    ) -> Result<(), ConsensusError> {
        // F-011: Reject blocks with timestamps too far in the future
        let max_allowed = current_time.saturating_add(self.config.max_future_secs);
        if header.timestamp > max_allowed {
            return Err(ConsensusError::InvalidTimestamp(format!(
                "block {} timestamp {} exceeds current_time {} + max_future {}",
                header.number, header.timestamp, current_time, self.config.max_future_secs,
            )));
        }

        if let Some(parent) = parent {
            if header.timestamp < parent.timestamp.saturating_add(self.config.block_time_secs) {
                return Err(ConsensusError::InvalidTimestamp(format!(
                    "block {} timestamp {} < parent {} + block_time {}",
                    header.number, header.timestamp, parent.timestamp, self.config.block_time_secs,
                )));
            }
            let Some(expected_number) = parent.number.checked_add(1) else {
                return Err(ConsensusError::InvalidTimestamp(format!(
                    "parent block number {} cannot advance",
                    parent.number,
                )));
            };
            if header.number != expected_number {
                return Err(ConsensusError::InvalidTimestamp(format!(
                    "block number {} != parent {} + 1",
                    header.number, parent.number,
                )));
            }
            if header.parent_hash != parent.hash() {
                return Err(ConsensusError::Internal(
                    "parent_hash does not match parent header".into(),
                ));
            }
        }
        Ok(())
    }

    /// Verify a proposer seal (PQ signature over header hash).
    pub fn verify_seal(
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
}

#[async_trait::async_trait]
impl ConsensusEngine for PoaEngine {
    fn verify_header(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        self.verify_proposer(header)?;
        // Note: parent verification requires the parent header, which the caller
        // should provide via verify_header_with_parent for full validation.
        Ok(())
    }

    async fn seal_block(&self, block: &mut Block) -> Result<(), ConsensusError> {
        // Sealing requires a Signer which is injected externally.
        // The caller is responsible for signing — this validates the block is
        // sealable by checking the proposer slot.
        let expected = self.expected_proposer_for_block(block.header.number);
        if block.header.proposer != expected {
            return Err(ConsensusError::InvalidProposer {
                expected,
                got: block.header.proposer,
            });
        }
        Ok(())
    }

    fn is_proposer(&self, slot: u64, address: &Address) -> bool {
        self.expected_proposer_for_block(slot) == *address
    }

    fn engine_type(&self) -> EngineType {
        EngineType::PoA
    }

    fn poa_config(&self) -> &PoaConfig {
        self.config()
    }

    fn poa_config_mut(&mut self) -> &mut PoaConfig {
        self.config_mut()
    }

    fn sign_block(
        &self,
        block: &mut Block,
        signer: &dyn shell_crypto::Signer,
    ) -> Result<(), ConsensusError> {
        let expected = self.expected_proposer_for_block(block.header.number);
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
        seal: &shell_crypto::PQSignature,
        proposer_pubkey: &[u8],
        verifier: &dyn shell_crypto::Verifier,
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
        PoaEngine::slash_authority(self, offender);
    }

    fn validator_weights(&self) -> HashMap<Address, u64> {
        self.config
            .authorities
            .iter()
            .enumerate()
            .map(|(index, authority)| (*authority, self.effective_weight_at(index)))
            .collect()
    }
}

impl PoaEngine {
    /// Full header verification including parent checks and seal.
    ///
    /// `current_time` is the wall-clock Unix timestamp (seconds) used to
    /// reject blocks with timestamps too far in the future.
    pub fn verify_header_with_parent(
        &self,
        header: &BlockHeader,
        parent: &BlockHeader,
        seal: &PQSignature,
        proposer_pubkey: &[u8],
        verifier: &dyn Verifier,
        current_time: u64,
    ) -> Result<(), ConsensusError> {
        self.verify_proposer(header)?;
        self.verify_timestamp(header, Some(parent), current_time)?;
        self.verify_seal(header, seal, proposer_pubkey, verifier)?;
        Ok(())
    }

    /// Sign a block header with the proposer's key.
    pub fn sign_block(&self, block: &mut Block, signer: &dyn Signer) -> Result<(), ConsensusError> {
        let expected = self.expected_proposer_for_block(block.header.number);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::{DilithiumSigner, DilithiumVerifier, Signer};
    use shell_primitives::{Bytes, ShellHash};

    fn test_config() -> (PoaConfig, Address, DilithiumSigner) {
        let signer = DilithiumSigner::generate();
        let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let config = PoaConfig::new(vec![addr], 1);
        (config, addr, signer)
    }

    fn sample_header(number: u64, proposer: Address, timestamp: u64) -> BlockHeader {
        BlockHeader {
            parent_hash: ShellHash::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            logs_bloom: Bytes::new(),
            number,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp,
            extra_data: Bytes::new(),
            proposer,
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        }
    }

    #[test]
    fn proposer_round_robin() {
        let a1 = Address::from_public_key(shell_primitives::keccak256(b"a1").as_bytes(), 0);
        let a2 = Address::from_public_key(shell_primitives::keccak256(b"a2").as_bytes(), 0);
        let a3 = Address::from_public_key(shell_primitives::keccak256(b"a3").as_bytes(), 0);
        let config = PoaConfig::new(vec![a1, a2, a3], 1);

        assert_eq!(config.proposer_for_block(0), a1);
        assert_eq!(config.proposer_for_block(1), a2);
        assert_eq!(config.proposer_for_block(2), a3);
        assert_eq!(config.proposer_for_block(3), a1); // wraps around
    }

    #[test]
    fn verify_header_valid() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config);
        let header = sample_header(0, addr, 1000);

        assert!(engine.verify_header(&header).is_ok());
    }

    #[test]
    fn verify_header_wrong_proposer() {
        let (config, _, _) = test_config();
        let engine = PoaEngine::new(config);
        let wrong =
            Address::from_public_key(shell_primitives::keccak256(b"intruder").as_bytes(), 0);
        let header = sample_header(0, wrong, 1000);

        let err = engine.verify_header(&header).unwrap_err();
        assert!(matches!(err, ConsensusError::UnknownProposer(_)));
    }

    #[test]
    fn verify_timestamp_too_early() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config);

        let parent = sample_header(0, addr, 1000);
        let child = sample_header(1, addr, 1000); // same timestamp, needs +1

        let result = engine.verify_timestamp(&child, Some(&parent), 2000);
        assert!(result.is_err());
    }

    #[test]
    fn verify_timestamp_valid() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config);

        let parent = sample_header(0, addr, 1000);
        let mut child = sample_header(1, addr, 1001);
        child.parent_hash = parent.hash();

        let result = engine.verify_timestamp(&child, Some(&parent), 2000);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_timestamp_rejects_terminal_parent_height() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config);

        let parent = sample_header(u64::MAX, addr, 1000);
        let mut child = sample_header(u64::MAX, addr, 1001);
        child.parent_hash = parent.hash();

        let err = engine
            .verify_timestamp(&child, Some(&parent), 2000)
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot advance"),
            "expected terminal parent rejection, got {err}"
        );
    }

    #[test]
    fn verify_timestamp_future_rejected() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config);

        // Block timestamp 100 seconds in the future (max_future_secs = 60)
        let header = sample_header(0, addr, 2100);
        let result = engine.verify_timestamp(&header, None, 2000);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("exceeds current_time"));
    }

    #[test]
    fn verify_timestamp_within_future_tolerance() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config);

        // Block timestamp exactly at max_future_secs boundary (60s)
        let header = sample_header(0, addr, 2060);
        let result = engine.verify_timestamp(&header, None, 2000);
        assert!(result.is_ok());

        // 1 second over → rejected
        let header_over = sample_header(0, addr, 2061);
        let result_over = engine.verify_timestamp(&header_over, None, 2000);
        assert!(result_over.is_err());
    }

    #[test]
    fn with_max_future_secs_overrides_default() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config.with_max_future_secs(5));

        let header = sample_header(0, addr, 2005);
        assert!(engine.verify_timestamp(&header, None, 2000).is_ok());

        let header_over = sample_header(0, addr, 2006);
        assert!(engine.verify_timestamp(&header_over, None, 2000).is_err());
    }

    #[test]
    fn sign_and_verify_seal() {
        let (config, addr, signer) = test_config();
        let engine = PoaEngine::new(config);

        let header = sample_header(0, addr, 1000);
        let mut block = Block {
            header,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };

        engine.sign_block(&mut block, &signer).unwrap();
        assert!(block.proposer_seal.is_some());

        let verifier = DilithiumVerifier;
        let seal = block.proposer_seal.as_ref().unwrap();
        assert!(engine
            .verify_seal(&block.header, seal, signer.public_key(), &verifier)
            .is_ok());
    }

    #[test]
    fn is_proposer_check() {
        let (config, addr, _) = test_config();
        let engine = PoaEngine::new(config);

        assert!(engine.is_proposer(0, &addr));
        // With single authority, all slots map to same address
        assert!(engine.is_proposer(1, &addr));
    }

    #[test]
    fn engine_type_is_poa() {
        let (config, _, _) = test_config();
        let engine = PoaEngine::new(config);
        assert_eq!(engine.engine_type(), EngineType::PoA);
    }

    // ---- Epoch tests ----

    fn make_addrs(n: usize) -> Vec<Address> {
        (0..n)
            .map(|i| {
                Address::from_public_key(
                    shell_primitives::keccak256(format!("auth{i}").as_bytes()).as_bytes(),
                    0,
                )
            })
            .collect()
    }

    #[test]
    fn epoch_of_disabled() {
        let config = PoaConfig::new(make_addrs(3), 1);
        assert_eq!(config.epoch_length, 0);
        for b in 0..20 {
            assert_eq!(
                config.epoch_of(b),
                0,
                "epoch_of should always be 0 when disabled"
            );
        }
    }

    #[test]
    fn epoch_of_enabled() {
        let config = PoaConfig::new(make_addrs(3), 1).with_epoch_length(10);
        assert_eq!(config.epoch_of(0), 0);
        assert_eq!(config.epoch_of(9), 0);
        assert_eq!(config.epoch_of(10), 1);
        assert_eq!(config.epoch_of(19), 1);
        assert_eq!(config.epoch_of(20), 2);
        assert_eq!(config.epoch_of(100), 10);
    }

    #[test]
    fn is_epoch_boundary_disabled() {
        let config = PoaConfig::new(make_addrs(3), 1);
        for b in 0..20 {
            assert!(
                !config.is_epoch_boundary(b),
                "no boundaries when epoch disabled"
            );
        }
    }

    #[test]
    fn is_epoch_boundary_enabled() {
        let config = PoaConfig::new(make_addrs(3), 1).with_epoch_length(5);
        assert!(config.is_epoch_boundary(0));
        assert!(!config.is_epoch_boundary(1));
        assert!(!config.is_epoch_boundary(4));
        assert!(config.is_epoch_boundary(5));
        assert!(config.is_epoch_boundary(10));
        assert!(!config.is_epoch_boundary(11));
    }

    #[test]
    fn proposer_for_block_no_epoch_backward_compat() {
        let addrs = make_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 1);
        // Must match the old block_number % authority_count behavior exactly.
        for b in 0u64..12 {
            let expected_idx = b as usize % addrs.len();
            assert_eq!(config.proposer_for_block(b), addrs[expected_idx]);
        }
    }

    #[test]
    fn proposer_for_block_handles_full_block_number_range() {
        let addrs = make_addrs(7);
        let config = PoaConfig::new(addrs.clone(), 1);
        assert_eq!(config.proposer_for_block(u64::MAX), addrs[1]);
    }

    #[test]
    fn proposer_for_block_with_epoch() {
        let addrs = make_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 1).with_epoch_length(5);

        // Within epoch 0 (blocks 0..5): idx = block % 5 % 3
        assert_eq!(config.proposer_for_block(0), addrs[0]); // 0%5=0, 0%3=0
        assert_eq!(config.proposer_for_block(1), addrs[1]); // 1%5=1, 1%3=1
        assert_eq!(config.proposer_for_block(2), addrs[2]); // 2%5=2, 2%3=2
        assert_eq!(config.proposer_for_block(3), addrs[0]); // 3%5=3, 3%3=0
        assert_eq!(config.proposer_for_block(4), addrs[1]); // 4%5=4, 4%3=1

        // Epoch 1 starts at block 5 — proposer cycle resets
        assert_eq!(config.proposer_for_block(5), addrs[0]); // 5%5=0, 0%3=0
        assert_eq!(config.proposer_for_block(6), addrs[1]); // 6%5=1, 1%3=1
        assert_eq!(config.proposer_for_block(7), addrs[2]); // 7%5=2, 2%3=2
    }

    #[test]
    fn proposer_epoch_length_equals_authority_count() {
        let addrs = make_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 1).with_epoch_length(3);

        // Each authority gets exactly one slot per epoch.
        for epoch in 0..4u64 {
            for slot in 0..3u64 {
                let block = epoch * 3 + slot;
                assert_eq!(config.proposer_for_block(block), addrs[slot as usize]);
            }
        }
    }

    #[test]
    fn set_authorities_updates_list() {
        let addrs = make_addrs(3);
        let mut config = PoaConfig::new(addrs.clone(), 1).with_epoch_length(10);
        assert_eq!(config.authorities, addrs);

        let new_addrs = make_addrs(2);
        config.set_authorities(new_addrs.clone());
        assert_eq!(config.authorities, new_addrs);
        assert_eq!(config.authorities.len(), 2);
    }

    #[test]
    fn set_authorities_clears_stale_weights() {
        let addrs = make_addrs(2);
        let mut config = PoaConfig::new(addrs, 1).with_weights(vec![3, 1]);

        let new_addrs = make_addrs(2);
        config.set_authorities(new_addrs);

        assert!(config.authority_weights.is_empty());
    }

    #[test]
    #[should_panic(expected = "authority set must not be empty")]
    fn set_authorities_panics_on_empty() {
        let mut config = PoaConfig::new(make_addrs(1), 1);
        config.set_authorities(vec![]);
    }

    #[test]
    fn with_epoch_length_builder() {
        let config = PoaConfig::new(make_addrs(1), 2).with_epoch_length(100);
        assert_eq!(config.epoch_length, 100);
        assert_eq!(config.block_time_secs, 2);
    }

    #[test]
    fn epoch_length_one() {
        let addrs = make_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 1).with_epoch_length(1);
        // Every block is an epoch boundary, proposer is always addrs[0].
        for b in 0..10u64 {
            assert!(config.is_epoch_boundary(b));
            assert_eq!(config.epoch_of(b), b);
            assert_eq!(config.proposer_for_block(b), addrs[0]); // b%1=0, 0%3=0
        }
    }

    // ---- Additional comprehensive tests ----

    #[test]
    fn round_robin_seven_validators() {
        let addrs = make_addrs(7);
        let config = PoaConfig::new(addrs.clone(), 1);

        // Verify full cycle and wrap-around
        for block in 0u64..21 {
            let expected = addrs[block as usize % 7];
            assert_eq!(
                config.proposer_for_block(block),
                expected,
                "block {block} should map to validator {}",
                block as usize % 7
            );
        }
    }

    #[test]
    fn non_proposer_authority_rejected() {
        // A valid authority at the wrong slot yields InvalidProposer (not UnknownProposer).
        let addrs = make_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 1);
        let engine = PoaEngine::new(config);

        // Block 0 expects addrs[0]; submit header with addrs[1]
        let header = sample_header(0, addrs[1], 1000);
        let err = engine.verify_header(&header).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidProposer { .. }),
            "expected InvalidProposer, got {err:?}"
        );
    }

    #[test]
    fn invalid_seal_wrong_signer() {
        let (config, addr, _correct_signer) = test_config();
        let engine = PoaEngine::new(config);

        let header = sample_header(0, addr, 1000);
        let mut block = Block {
            header,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };

        // Sign with a different signer
        let wrong_signer = DilithiumSigner::generate();
        engine.sign_block(&mut block, &wrong_signer).unwrap();

        // Verify with the wrong signer's public key should succeed (key matches sig)
        // but verify with the correct signer's public key should fail
        let verifier = DilithiumVerifier;
        let seal = block.proposer_seal.as_ref().unwrap();
        let result =
            engine.verify_seal(&block.header, seal, _correct_signer.public_key(), &verifier);
        assert!(
            result.is_err(),
            "seal signed by wrong key should fail verification with correct key"
        );
    }

    #[test]
    fn corrupted_seal_rejected() {
        let (config, addr, signer) = test_config();
        let engine = PoaEngine::new(config);

        let header = sample_header(0, addr, 1000);
        let mut block = Block {
            header,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };

        engine.sign_block(&mut block, &signer).unwrap();

        // Corrupt the seal data
        let mut corrupted_seal = block.proposer_seal.clone().unwrap();
        if !corrupted_seal.data.is_empty() {
            corrupted_seal.data[0] ^= 0xFF;
        }

        let verifier = DilithiumVerifier;
        let result = engine.verify_seal(
            &block.header,
            &corrupted_seal,
            signer.public_key(),
            &verifier,
        );
        assert!(result.is_err(), "corrupted seal should fail verification");
    }

    #[test]
    fn sign_block_rejects_non_proposer() {
        let addrs = make_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 1);
        let engine = PoaEngine::new(config);
        let signer = DilithiumSigner::generate();

        // Block 0 expects addrs[0]; set proposer to addrs[1]
        let header = sample_header(0, addrs[1], 1000);
        let mut block = Block {
            header,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };

        let err = engine.sign_block(&mut block, &signer).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidProposer { .. }));
    }

    #[test]
    fn verify_header_with_parent_full_roundtrip() {
        let (config, addr, signer) = test_config();
        let engine = PoaEngine::new(config);

        let parent = sample_header(0, addr, 1000);
        let mut child_header = sample_header(1, addr, 1001);
        child_header.parent_hash = parent.hash();

        let mut block = Block {
            header: child_header,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        engine.sign_block(&mut block, &signer).unwrap();

        let verifier = DilithiumVerifier;
        let seal = block.proposer_seal.as_ref().unwrap();
        let result = engine.verify_header_with_parent(
            &block.header,
            &parent,
            seal,
            signer.public_key(),
            &verifier,
            2000, // current time well in the future
        );
        assert!(
            result.is_ok(),
            "full header verification should pass: {result:?}"
        );
    }

    #[test]
    fn authority_rotation_across_epoch() {
        let addrs_v1 = make_addrs(3);
        let mut config = PoaConfig::new(addrs_v1.clone(), 1).with_epoch_length(5);

        // Epoch 0: original authorities
        assert_eq!(config.proposer_for_block(0), addrs_v1[0]);
        assert_eq!(config.proposer_for_block(2), addrs_v1[2]);

        // Rotate authorities at epoch boundary
        let addrs_v2: Vec<Address> = (10..12)
            .map(|i| {
                Address::from_public_key(
                    shell_primitives::keccak256(format!("new_auth{i}").as_bytes()).as_bytes(),
                    0,
                )
            })
            .collect();
        config.set_authorities(addrs_v2.clone());

        // Epoch 1 uses new authorities
        assert_eq!(config.proposer_for_block(5), addrs_v2[0]);
        assert_eq!(config.proposer_for_block(6), addrs_v2[1]);
        assert_eq!(config.proposer_for_block(7), addrs_v2[0]); // wraps with 2 authorities
    }

    #[test]
    fn single_validator_all_slots() {
        let signer = DilithiumSigner::generate();
        let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let config = PoaConfig::new(vec![addr], 1);
        let engine = PoaEngine::new(config);

        for block_num in 0..50u64 {
            assert!(
                engine.is_proposer(block_num, &addr),
                "single validator should be proposer for every slot"
            );

            let header = sample_header(block_num, addr, 1000 + block_num);
            assert!(
                engine.verify_header(&header).is_ok(),
                "single validator header should always be valid"
            );
        }
    }

    // ── F4: Network-type block time propagation ───────────────────────────────

    fn make_signed_block(
        signer: &DilithiumSigner,
        addr: Address,
        number: u64,
        timestamp: u64,
        parent: &BlockHeader,
    ) -> (BlockHeader, shell_crypto::PQSignature) {
        let mut h = sample_header(number, addr, timestamp);
        h.parent_hash = parent.hash();
        let mut block = Block {
            header: h,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let config = PoaConfig::new(vec![addr], 1);
        let engine = PoaEngine::new(config);
        engine.sign_block(&mut block, signer).unwrap();
        let seal = block.proposer_seal.unwrap();
        (block.header, seal)
    }

    #[test]
    fn poa_config_dev_block_time() {
        let config = PoaConfig::new(make_addrs(1), 30);
        assert_eq!(config.block_time_secs, 30);
    }

    #[test]
    fn poa_config_testnet_block_time() {
        let config = PoaConfig::new(make_addrs(3), 30);
        assert_eq!(config.block_time_secs, 30);
    }

    #[test]
    fn poa_config_mainnet_block_time() {
        let config = PoaConfig::new(make_addrs(5), 2);
        assert_eq!(config.block_time_secs, 2);
    }

    #[test]
    fn poa_engine_accepts_30s_block_on_dev_network() {
        let signer = DilithiumSigner::generate();
        let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let config = PoaConfig::new(vec![addr], 30);
        let engine = PoaEngine::new(config);
        let parent = sample_header(0, addr, 1_000);
        let (child, seal) = make_signed_block(&signer, addr, 1, 1_030, &parent);
        let verifier = DilithiumVerifier;
        assert!(engine
            .verify_header_with_parent(
                &child,
                &parent,
                &seal,
                signer.public_key(),
                &verifier,
                10_000
            )
            .is_ok());
    }

    #[test]
    fn poa_engine_rejects_block_too_early_for_30s_network() {
        let signer = DilithiumSigner::generate();
        let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let config = PoaConfig::new(vec![addr], 30);
        let engine = PoaEngine::new(config);
        let parent = sample_header(0, addr, 1_000);
        let (child, seal) = make_signed_block(&signer, addr, 1, 1_015, &parent); // only +15s
        let verifier = DilithiumVerifier;
        assert!(engine
            .verify_header_with_parent(
                &child,
                &parent,
                &seal,
                signer.public_key(),
                &verifier,
                10_000
            )
            .is_err());
    }

    #[test]
    fn poa_engine_accepts_mainnet_2s_block() {
        let signer = DilithiumSigner::generate();
        let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let config = PoaConfig::new(vec![addr], 2);
        let engine = PoaEngine::new(config);
        let parent = sample_header(0, addr, 1_000);
        let (child, seal) = make_signed_block(&signer, addr, 1, 1_002, &parent); // exactly +2s
        let verifier = DilithiumVerifier;
        assert!(engine
            .verify_header_with_parent(
                &child,
                &parent,
                &seal,
                signer.public_key(),
                &verifier,
                10_000
            )
            .is_ok());
    }

    #[test]
    fn poa_engine_rejects_mainnet_block_only_1s_apart() {
        let signer = DilithiumSigner::generate();
        let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let config = PoaConfig::new(vec![addr], 2);
        let engine = PoaEngine::new(config);
        let parent = sample_header(0, addr, 1_000);
        let (child, seal) = make_signed_block(&signer, addr, 1, 1_001, &parent); // only +1s
        let verifier = DilithiumVerifier;
        assert!(engine
            .verify_header_with_parent(
                &child,
                &parent,
                &seal,
                signer.public_key(),
                &verifier,
                10_000
            )
            .is_err());
    }

    // ── H1: Weighted proposer rotation ───────────────────────────────────────

    fn make_weighted_addrs(n: usize) -> Vec<Address> {
        (0..n)
            .map(|i| {
                Address::from_public_key(
                    shell_primitives::keccak256(format!("w_auth{i}").as_bytes()).as_bytes(),
                    0,
                )
            })
            .collect()
    }

    #[test]
    fn weighted_proposer_no_weights_falls_back_to_round_robin() {
        let addrs = make_weighted_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 2);
        // Without weights, should behave identically to proposer_for_block.
        for block in 0u64..9 {
            assert_eq!(
                config.proposer_for_block(block),
                addrs[(block as usize) % 3]
            );
        }
    }

    #[test]
    fn weighted_proposer_equal_weights_distributes_roughly_uniformly() {
        let addrs = make_weighted_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![1, 1, 1]);
        let mut counts = [0u32; 3];
        for block in 0u64..300 {
            let proposer = config.proposer_for_block(block);
            let idx = addrs.iter().position(|a| a == &proposer).unwrap();
            counts[idx] += 1;
        }
        for &c in &counts {
            assert!(c > 80 && c < 120, "uneven distribution: {:?}", counts);
        }
    }

    #[test]
    fn weighted_proposer_higher_weight_gets_more_slots() {
        let addrs = make_weighted_addrs(2);
        // auth0 has 3× weight of auth1 → ~75% vs ~25%.
        let config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![3, 1]);
        let mut counts = [0u32; 2];
        for block in 0u64..1000 {
            let proposer = config.proposer_for_block(block);
            let idx = addrs.iter().position(|a| a == &proposer).unwrap();
            counts[idx] += 1;
        }
        assert!(
            counts[0] > 700 && counts[0] < 800,
            "expected ~750, got {:?}",
            counts
        );
        assert!(
            counts[1] > 200 && counts[1] < 300,
            "expected ~250, got {:?}",
            counts
        );
    }

    #[test]
    fn weighted_proposer_single_authority_always_wins() {
        let addrs = make_weighted_addrs(1);
        let config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![42]);
        for block in 0u64..20 {
            assert_eq!(config.proposer_for_block(block), addrs[0]);
        }
    }

    #[test]
    fn weighted_proposer_zero_weight_normalised_to_one() {
        let addrs = make_weighted_addrs(2);
        let config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![0, 0]);
        let mut counts = [0u32; 2];
        for block in 0u64..200 {
            let proposer = config.proposer_for_block(block);
            let idx = addrs.iter().position(|a| a == &proposer).unwrap();
            counts[idx] += 1;
        }
        for &c in &counts {
            assert!(
                c > 60 && c < 140,
                "zero-weight normalisation failed: {:?}",
                counts
            );
        }
    }

    #[test]
    fn weighted_proposer_is_deterministic() {
        let addrs = make_weighted_addrs(3);
        let config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![5, 3, 2]);
        for block in 0u64..50 {
            let p1 = config.proposer_for_block(block);
            let p2 = config.proposer_for_block(block);
            assert_eq!(p1, p2, "non-deterministic at block {block}");
        }
    }

    #[test]
    fn with_weights_builder_sets_field() {
        let addrs = make_weighted_addrs(2);
        let config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![10, 5]);
        assert_eq!(config.authority_weights, vec![10, 5]);
    }

    #[test]
    fn slash_reduces_weight_by_bps() {
        let addrs = make_weighted_addrs(2);
        let mut config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![100, 50]);
        config.slash_weight_bps = 1_000;
        let mut engine = PoaEngine::new(config);

        engine.slash_authority(&addrs[0]);

        let weights = engine.validator_weights();
        assert_eq!(weights.get(&addrs[0]), Some(&90));
        assert_eq!(weights.get(&addrs[1]), Some(&50));
    }

    #[test]
    fn multiple_slashes_are_cumulative() {
        let addrs = make_weighted_addrs(1);
        let mut config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![100]);
        config.slash_weight_bps = 1_000;
        let mut engine = PoaEngine::new(config);

        engine.slash_authority(&addrs[0]);
        engine.slash_authority(&addrs[0]);

        assert_eq!(engine.validator_weights().get(&addrs[0]), Some(&81));
    }

    #[test]
    fn slash_weight_floors_at_zero() {
        let addrs = make_weighted_addrs(1);
        let mut config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![10]);
        config.slash_weight_bps = 10_000;
        let mut engine = PoaEngine::new(config);

        engine.slash_authority(&addrs[0]);
        engine.slash_authority(&addrs[0]);

        assert_eq!(engine.validator_weights().get(&addrs[0]), Some(&0));
    }

    #[test]
    fn slashed_zero_weight_authority_is_excluded_from_slot_selection() {
        let addrs = make_weighted_addrs(2);
        let mut config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![10, 10]);
        config.slash_weight_bps = 10_000;
        let mut engine = PoaEngine::new(config);

        engine.slash_authority(&addrs[0]);
        assert_eq!(engine.validator_weights().get(&addrs[0]), Some(&0));
        assert_eq!(engine.validator_weights().get(&addrs[1]), Some(&10));

        for block in 0u64..32 {
            assert_eq!(
                engine.expected_proposer_for_block(block),
                addrs[1],
                "slashed validator selected at block {block}"
            );
        }
    }

    #[test]
    fn verify_header_accepts_remaining_active_validator_after_full_slash() {
        let addrs = make_weighted_addrs(2);
        let mut config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![10, 10]);
        config.slash_weight_bps = 10_000;
        let mut engine = PoaEngine::new(config);
        engine.slash_authority(&addrs[0]);

        let header = sample_header(0, addrs[1], 1000);
        assert!(engine.verify_header(&header).is_ok());
    }

    #[test]
    fn unslashed_validators_are_unaffected() {
        let addrs = make_weighted_addrs(2);
        let mut config = PoaConfig::new(addrs.clone(), 2).with_weights(vec![40, 60]);
        config.slash_weight_bps = 2_500;
        let mut engine = PoaEngine::new(config);

        engine.slash_authority(&addrs[1]);

        let weights = engine.validator_weights();
        assert_eq!(weights.get(&addrs[0]), Some(&40));
        assert_eq!(weights.get(&addrs[1]), Some(&45));
    }
}
