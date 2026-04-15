use shell_core::{Block, BlockHeader};
use shell_crypto::{PQSignature, Signer, Verifier};
use shell_primitives::Address;

use crate::{ConsensusEngine, ConsensusError, EngineType};

/// PoA configuration: authority list and block timing.
#[derive(Debug, Clone)]
pub struct PoaConfig {
    /// Ordered list of authority addresses. Position determines round-robin slot.
    pub authorities: Vec<Address>,
    /// Minimum seconds between consecutive blocks.
    pub block_time_secs: u64,
    /// Maximum seconds a block timestamp may be ahead of the current wall-clock.
    /// Prevents miners from pre-dating blocks to gain proposer slots.
    pub max_future_secs: u64,
    /// Number of blocks per epoch. 0 means no epochs (legacy behavior).
    pub epoch_length: u64,
}

/// Default maximum future timestamp tolerance (60 seconds).
const DEFAULT_MAX_FUTURE_SECS: u64 = 60;

impl PoaConfig {
    pub fn new(authorities: Vec<Address>, block_time_secs: u64) -> Self {
        Self {
            authorities,
            block_time_secs,
            max_future_secs: DEFAULT_MAX_FUTURE_SECS,
            epoch_length: 0,
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
    pub fn proposer_for_block(&self, block_number: u64) -> Address {
        let n = self.authorities.len();
        if n == 0 {
            // SAFETY: set_authorities ensures the authority set is non-empty.
            // This branch is unreachable in normal operation.
            return Address::default();
        }
        let idx = if self.epoch_length > 0 {
            (block_number.checked_rem(self.epoch_length).unwrap_or(0) as usize)
                .checked_rem(n)
                .unwrap_or(0)
        } else {
            (block_number as usize).checked_rem(n).unwrap_or(0)
        };
        self.authorities
            .get(idx)
            .copied()
            .unwrap_or_else(|| unreachable!("idx < authorities.len()"))
    }

    pub fn is_authority(&self, address: &Address) -> bool {
        self.authorities.contains(address)
    }

    /// Replace the authority set. Panics if the new set is empty.
    pub fn set_authorities(&mut self, new_authorities: Vec<Address>) {
        assert!(
            !new_authorities.is_empty(),
            "authority set must not be empty"
        );
        self.authorities = new_authorities;
    }
}

/// Proof-of-Authority consensus engine.
///
/// Round-robin proposer selection based on `block_number % authority_count`.
/// Each block must be sealed with the proposer's PQ signature.
pub struct PoaEngine {
    config: PoaConfig,
}

impl PoaEngine {
    pub fn new(config: PoaConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &PoaConfig {
        &self.config
    }

    /// Mutable access to the consensus configuration (e.g. for validator set updates).
    pub fn config_mut(&mut self) -> &mut PoaConfig {
        &mut self.config
    }

    fn verify_proposer(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        if !self.config.is_authority(&header.proposer) {
            return Err(ConsensusError::UnknownProposer(header.proposer));
        }

        let expected = self.config.proposer_for_block(header.number);
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
            if header.number != parent.number.saturating_add(1) {
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
        let expected = self.config.proposer_for_block(block.header.number);
        if block.header.proposer != expected {
            return Err(ConsensusError::InvalidProposer {
                expected,
                got: block.header.proposer,
            });
        }
        Ok(())
    }

    fn is_proposer(&self, slot: u64, address: &Address) -> bool {
        self.config.proposer_for_block(slot) == *address
    }

    fn engine_type(&self) -> EngineType {
        EngineType::PoA
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
        let expected = self.config.proposer_for_block(block.header.number);
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
}
