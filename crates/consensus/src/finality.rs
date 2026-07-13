use serde::{Deserialize, Serialize};
use shell_crypto::{
    infer_signature_type_from_address, is_algorithm_allowed, BatchVerifier, CryptoError,
    PQSignature, VerifyItem,
};
use shell_primitives::{Address, ShellHash};
use std::collections::{HashMap, HashSet};

/// Maximum number of distinct block hashes tracked in pending attestations.
/// Limits memory exposure from attestation flood attacks: each entry is a
/// `ShellHash → HashSet<Address>` mapping, bounded at this many unique block hashes.
const MAX_PENDING_ATTESTATION_BLOCKS: usize = 512;

/// Number of blocks per attestation epoch. Used to derive the epoch field
/// in the attestation signing payload (WP §attestation binding).
pub const ATTESTATION_EPOCH_BLOCKS: u64 = 1000;

/// Domain tag for the attestation signing payload.
/// Prevents cross-protocol message reuse.
const ATTEST_DOMAIN: &[u8; 16] = b"SHELL_ATTEST_V1\0";

/// An attestation is a validator's signed confirmation that they accept a block.
/// Validators broadcast attestations after importing a valid block.
/// When attesting weight exceeds 2/3 of total validator weight, the block becomes finalized.
///
/// Signing payload (WP §1568-1582):
///   SHELL_ATTEST_V1\0 || chain_id(8 BE) || epoch(8 BE) || parent_hash(32)
///   || block_hash(32) || block_number(8 BE) || round(8 BE)
///
/// `chain_id`, `parent_hash`, and `round` are tagged `#[serde(default)]` so that
/// messages produced by pre-Phase-1 nodes still deserialise without panicking;
/// their signatures will fail verification against the new payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Chain ID — binds the attestation to a specific network.
    #[serde(default)]
    pub chain_id: u64,
    /// Hash of the parent block — prevents cross-fork replays.
    #[serde(default)]
    pub parent_hash: ShellHash,
    /// Hash of the attested block.
    pub block_hash: ShellHash,
    /// Number of the attested block.
    pub block_number: u64,
    /// Address of the attesting validator.
    pub validator: Address,
    /// Consensus round (view) in which this block was produced.
    /// Always 0 for standard PoA; set to the wPoA view after a view-change.
    #[serde(default)]
    pub round: u64,
    /// PQ signature over the signing payload.
    pub signature: Vec<u8>,
}

impl Attestation {
    /// Create a new attestation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        parent_hash: ShellHash,
        block_hash: ShellHash,
        block_number: u64,
        validator: Address,
        round: u64,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            chain_id,
            parent_hash,
            block_hash,
            block_number,
            validator,
            round,
            signature,
        }
    }

    /// Derive the epoch from a block number.
    pub fn epoch_of(block_number: u64) -> u64 {
        block_number / ATTESTATION_EPOCH_BLOCKS
    }

    /// The canonical signing payload (WP §1568-1582):
    ///   SHELL_ATTEST_V1\0 || chain_id(8 BE) || epoch(8 BE) || parent_hash(32)
    ///   || block_hash(32) || block_number(8 BE) || round(8 BE)
    pub fn signing_message(
        chain_id: u64,
        parent_hash: &ShellHash,
        block_hash: &ShellHash,
        block_number: u64,
        round: u64,
    ) -> Vec<u8> {
        let epoch = Self::epoch_of(block_number);
        let mut msg = Vec::with_capacity(112);
        msg.extend_from_slice(ATTEST_DOMAIN);
        msg.extend_from_slice(&chain_id.to_be_bytes());
        msg.extend_from_slice(&epoch.to_be_bytes());
        msg.extend_from_slice(parent_hash.as_bytes());
        msg.extend_from_slice(block_hash.as_bytes());
        msg.extend_from_slice(&block_number.to_be_bytes());
        msg.extend_from_slice(&round.to_be_bytes());
        msg
    }

    /// Reconstruct the signing message from this attestation's own fields.
    pub fn own_signing_message(&self) -> Vec<u8> {
        Self::signing_message(
            self.chain_id,
            &self.parent_hash,
            &self.block_hash,
            self.block_number,
            self.round,
        )
    }
}

/// Tracks finality state: which blocks have been finalized and pending attestations.
#[derive(Debug, Clone)]
pub struct FinalityState {
    /// The highest finalized block number.
    last_finalized_number: u64,
    /// The hash of the highest finalized block.
    last_finalized_hash: ShellHash,
    /// Pending attestations per block hash: maps block_hash -> set of validator addresses.
    pending_attestations: HashMap<ShellHash, HashSet<Address>>,
    /// Aggregate attesting weight per block hash.
    pending_attested_weight: HashMap<ShellHash, u64>,
    /// Full attestation objects stored per block hash for verification.
    attestation_store: HashMap<ShellHash, Vec<Attestation>>,
    /// First attested block per (height, validator), used for constant-time equivocation checks.
    attested_block_by_height: HashMap<(u64, Address), ShellHash>,
}

impl FinalityState {
    /// Create a new finality state starting from genesis.
    pub fn new() -> Self {
        Self {
            last_finalized_number: 0,
            last_finalized_hash: ShellHash::ZERO,
            pending_attestations: HashMap::new(),
            pending_attested_weight: HashMap::new(),
            attestation_store: HashMap::new(),
            attested_block_by_height: HashMap::new(),
        }
    }

    /// Create a finality state restored from persistent storage.
    pub fn with_finalized(number: u64, hash: ShellHash) -> Self {
        Self {
            last_finalized_number: number,
            last_finalized_hash: hash,
            pending_attestations: HashMap::new(),
            pending_attested_weight: HashMap::new(),
            attestation_store: HashMap::new(),
            attested_block_by_height: HashMap::new(),
        }
    }

    /// Record an attestation with the attester's canonical validator weight.
    /// Returns true if this is a new (non-duplicate) attestation.
    /// Returns false for duplicates and when the pending attestation block-set is at capacity
    /// (to prevent memory exhaustion from attestation flood attacks).
    pub fn record_attestation_weighted(
        &mut self,
        attestation: Attestation,
        attester_weight: u64,
    ) -> bool {
        if attester_weight == 0 || attestation.block_number <= self.last_finalized_number {
            return false;
        }

        // Reject attestations for unknown blocks when at capacity.
        if !self
            .pending_attestations
            .contains_key(&attestation.block_hash)
            && self.pending_attestations.len() >= MAX_PENDING_ATTESTATION_BLOCKS
        {
            return false;
        }
        let block_hash = attestation.block_hash;
        let block_number = attestation.block_number;
        let validator = attestation.validator;
        let validators = self.pending_attestations.entry(block_hash).or_default();
        let is_new = validators.insert(validator);
        if is_new {
            self.pending_attested_weight
                .entry(block_hash)
                .and_modify(|weight| *weight = weight.saturating_add(attester_weight))
                .or_insert(attester_weight);
            self.attestation_store
                .entry(block_hash)
                .or_default()
                .push(attestation);
            self.attested_block_by_height
                .entry((block_number, validator))
                .or_insert(block_hash);
        }
        is_new
    }

    /// Record an attestation using the default unit weight.
    pub fn record_attestation(&mut self, attestation: Attestation) -> bool {
        self.record_attestation_weighted(attestation, 1)
    }

    /// Check if a block has reached weighted finality.
    /// White-paper quorum requires attesting weight to be strictly greater than 2/3.
    pub fn check_finality_weighted(
        &mut self,
        block_hash: &ShellHash,
        block_number: u64,
        total_weight: u64,
    ) -> bool {
        let attested_weight = self.attested_weight(block_hash);

        if Self::has_weighted_quorum(attested_weight, total_weight)
            && block_number > self.last_finalized_number
        {
            self.last_finalized_number = block_number;
            self.last_finalized_hash = *block_hash;
            // Prune attestations for blocks at or below the newly finalized block
            self.prune_below(block_number);
            true
        } else {
            false
        }
    }

    /// Return true when attesting weight is strictly greater than 2/3 of total weight.
    pub fn has_weighted_quorum(attested_weight: u64, total_weight: u64) -> bool {
        if total_weight == 0 {
            return false;
        }
        (attested_weight as u128).saturating_mul(3) > (total_weight as u128).saturating_mul(2)
    }

    /// Calculate the quorum threshold for BFT consensus: ceil(2N/3).
    /// Tolerates up to f Byzantine validators where 2f+1 = ceil(2N/3).
    /// Special case: N <= 1 returns 1.
    pub fn quorum_threshold(total_validators: usize) -> usize {
        if total_validators <= 1 {
            return 1;
        }
        // Use u128 intermediate to prevent overflow when total_validators is very large;
        // saturating_mul caps at u128::MAX rather than wrapping.
        let n = total_validators as u128;
        usize::try_from(n.saturating_mul(2).div_ceil(3)).unwrap_or(total_validators)
    }

    /// Last finalized block number.
    pub fn last_finalized_number(&self) -> u64 {
        self.last_finalized_number
    }

    /// Last finalized block hash.
    pub fn last_finalized_hash(&self) -> &ShellHash {
        &self.last_finalized_hash
    }

    /// Total attesting weight recorded for a specific block.
    pub fn attested_weight(&self, block_hash: &ShellHash) -> u64 {
        self.pending_attested_weight
            .get(block_hash)
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct attestations for a specific block.
    pub fn attestation_count(&self, block_hash: &ShellHash) -> usize {
        self.pending_attestations
            .get(block_hash)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Get all attestations for a block.
    pub fn get_attestations(&self, block_hash: &ShellHash) -> Option<&Vec<Attestation>> {
        self.attestation_store.get(block_hash)
    }

    /// Total number of pending attestations across all blocks.
    pub fn total_pending_attestations(&self) -> usize {
        self.pending_attestations.values().map(|s| s.len()).sum()
    }

    /// Check if a validator has already attested to a block.
    pub fn has_attested(&self, block_hash: &ShellHash, validator: &Address) -> bool {
        self.pending_attestations
            .get(block_hash)
            .map(|s| s.contains(validator))
            .unwrap_or(false)
    }

    /// Detect equivocation: a validator attesting to two different blocks at the same height.
    /// Returns the conflicting block hash if equivocation is found.
    pub fn detect_equivocation(
        &self,
        block_hash: &ShellHash,
        block_number: u64,
        validator: &Address,
    ) -> Option<ShellHash> {
        self.attested_block_by_height
            .get(&(block_number, *validator))
            .copied()
            .filter(|hash| hash != block_hash)
    }

    /// Batch verify all stored attestation signatures for a block using
    /// parallel verification. Returns per-attestation results.
    ///
    /// `authorities` maps validator addresses to their public keys.
    /// Attestations from unknown validators produce a `VerificationFailed` error.
    pub fn batch_verify_attestations(
        &self,
        block_hash: &ShellHash,
        authorities: &HashMap<Address, Vec<u8>>,
        verifier: &dyn BatchVerifier,
    ) -> Result<Vec<bool>, CryptoError> {
        let attestations = match self.attestation_store.get(block_hash) {
            Some(atts) => atts,
            None => return Ok(vec![]),
        };

        let messages: Vec<Vec<u8>> = attestations
            .iter()
            .map(|att| att.own_signing_message())
            .collect();

        let sigs: Vec<PQSignature> = attestations
            .iter()
            .map(|att| {
                let pubkey = authorities
                    .get(&att.validator)
                    .ok_or(CryptoError::VerificationFailed)?;
                let sig_type = infer_signature_type_from_address(pubkey, &att.validator)
                    .ok_or(CryptoError::VerificationFailed)?;
                if !is_algorithm_allowed(sig_type) {
                    return Err(CryptoError::UnsupportedSignatureType(sig_type));
                }
                Ok(PQSignature::new(sig_type, att.signature.clone()))
            })
            .collect::<Result<_, _>>()?;

        let mut items = Vec::with_capacity(attestations.len());
        for (i, att) in attestations.iter().enumerate() {
            let pk = authorities
                .get(&att.validator)
                .ok_or(CryptoError::VerificationFailed)?;
            items.push(VerifyItem {
                pubkey: pk.as_slice(),
                message: messages
                    .get(i)
                    .unwrap_or_else(|| unreachable!("i < attestations.len() == messages.len()")),
                signature: sigs
                    .get(i)
                    .unwrap_or_else(|| unreachable!("i < attestations.len() == sigs.len()")),
            });
        }

        verifier.verify_batch(&items)
    }

    /// Directly mark a block as finalized.
    ///
    /// Used by the wPoA fast path: when `BlockCommitted` fires (quorum already
    /// verified by the round state machine), we skip the attestation-collection
    /// path and directly advance `last_finalized`.  Only advances finality —
    /// never goes backwards.
    pub fn set_finalized_direct(&mut self, block_number: u64, block_hash: ShellHash) -> bool {
        if block_number > self.last_finalized_number {
            self.last_finalized_number = block_number;
            self.last_finalized_hash = block_hash;
            self.prune_below(block_number);
            true
        } else {
            false
        }
    }

    /// Remove attestation data for blocks at or below the given number.
    fn prune_below(&mut self, finalized_number: u64) {
        let hashes_to_remove: Vec<ShellHash> = self
            .attestation_store
            .iter()
            .filter_map(|(hash, atts)| {
                atts.first()
                    .filter(|a| a.block_number <= finalized_number)
                    .map(|_| *hash)
            })
            .collect();

        for hash in hashes_to_remove {
            self.pending_attestations.remove(&hash);
            self.pending_attested_weight.remove(&hash);
            self.attestation_store.remove(&hash);
        }
        self.attested_block_by_height
            .retain(|(block_number, _), _| *block_number > finalized_number);
    }
}

impl Default for FinalityState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(n: u8) -> ShellHash {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        ShellHash::from(bytes)
    }

    fn make_addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address::from(bytes)
    }

    /// Test helper: build an Attestation with zero values for chain_id, parent_hash,
    /// and round. Tests that only verify quorum logic (not signature binding) use this.
    fn make_att(
        block_hash: ShellHash,
        block_number: u64,
        validator: Address,
        sig: Vec<u8>,
    ) -> Attestation {
        Attestation::new(
            0,
            ShellHash::ZERO,
            block_hash,
            block_number,
            validator,
            0,
            sig,
        )
    }

    fn strict_quorum_weight(total_weight: u64) -> u64 {
        if total_weight == 0 {
            return 0;
        }
        total_weight.saturating_mul(2) / 3 + 1
    }

    #[test]
    fn test_attestation_new() {
        let hash = make_hash(1);
        let addr = make_addr(1);
        let att = make_att(hash, 10, addr, vec![1, 2, 3]);
        assert_eq!(att.block_hash, hash);
        assert_eq!(att.block_number, 10);
        assert_eq!(att.validator, addr);
        assert_eq!(att.signature, vec![1, 2, 3]);
    }

    #[test]
    fn test_signing_message() {
        let hash = make_hash(42);
        let parent = ShellHash::ZERO;
        let chain_id: u64 = 1337;
        let block_number: u64 = 100;
        let round: u64 = 0;
        let epoch = Attestation::epoch_of(block_number);
        let msg = Attestation::signing_message(chain_id, &parent, &hash, block_number, round);
        // Domain (16) + chain_id (8) + epoch (8) + parent_hash (32) + block_hash (32) + height (8) + round (8)
        assert_eq!(msg.len(), 112);
        assert_eq!(&msg[..16], b"SHELL_ATTEST_V1\0");
        assert_eq!(&msg[16..24], &chain_id.to_be_bytes());
        assert_eq!(&msg[24..32], &epoch.to_be_bytes());
        assert_eq!(&msg[32..64], parent.as_bytes());
        assert_eq!(&msg[64..96], hash.as_bytes());
        assert_eq!(&msg[96..104], &block_number.to_be_bytes());
        assert_eq!(&msg[104..112], &round.to_be_bytes());
    }

    #[test]
    fn test_quorum_threshold() {
        // BFT quorum: ceil(2N/3) = (2N+2)/3 (integer division)
        assert_eq!(FinalityState::quorum_threshold(1), 1);
        assert_eq!(FinalityState::quorum_threshold(2), 2);
        assert_eq!(FinalityState::quorum_threshold(3), 2); // ceil(6/3) = 2
        assert_eq!(FinalityState::quorum_threshold(4), 3); // ceil(8/3) = 3
        assert_eq!(FinalityState::quorum_threshold(5), 4); // ceil(10/3) = 4
        assert_eq!(FinalityState::quorum_threshold(7), 5); // ceil(14/3) = 5
        assert_eq!(FinalityState::quorum_threshold(10), 7); // ceil(20/3) = 7
    }

    #[test]
    fn test_record_attestation_dedup() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);
        let addr = make_addr(1);
        let att1 = make_att(hash, 10, addr, vec![1]);
        let att2 = make_att(hash, 10, addr, vec![2]);

        assert!(state.record_attestation(att1));
        assert!(!state.record_attestation(att2)); // duplicate validator
        assert_eq!(state.attestation_count(&hash), 1);
    }

    #[test]
    fn test_finality_not_reached() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);

        // 1 of 3 validators
        state.record_attestation(make_att(hash, 10, make_addr(1), vec![]));
        assert!(!state.check_finality_weighted(&hash, 10, 3));
        assert_eq!(state.last_finalized_number(), 0);
    }

    #[test]
    fn test_finality_reached() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);

        // 3 of 3 validators is the minimum strict supermajority for uniform weights.
        state.record_attestation(make_att(hash, 10, make_addr(1), vec![]));
        state.record_attestation(make_att(hash, 10, make_addr(2), vec![]));
        state.record_attestation(make_att(hash, 10, make_addr(3), vec![]));
        assert!(state.check_finality_weighted(&hash, 10, 3));
        assert_eq!(state.last_finalized_number(), 10);
        assert_eq!(state.last_finalized_hash(), &hash);
    }

    #[test]
    fn weighted_quorum_rejects_exact_two_thirds() {
        let mut state = FinalityState::new();
        let hash = make_hash(9);

        state.record_attestation_weighted(make_att(hash, 10, make_addr(1), vec![]), 2);
        state.record_attestation_weighted(make_att(hash, 10, make_addr(2), vec![]), 2);
        assert_eq!(state.attested_weight(&hash), 4);
        assert!(!state.check_finality_weighted(&hash, 10, 6));
    }

    #[test]
    fn weighted_quorum_accepts_heavy_supermajority() {
        let mut state = FinalityState::new();
        let hash = make_hash(10);

        state.record_attestation_weighted(make_att(hash, 10, make_addr(1), vec![]), 4);
        state.record_attestation_weighted(make_att(hash, 10, make_addr(2), vec![]), 1);
        assert_eq!(state.attestation_count(&hash), 2);
        assert_eq!(state.attested_weight(&hash), 5);
        assert!(state.check_finality_weighted(&hash, 10, 6));
    }

    #[test]
    fn zero_weight_attestation_is_not_recorded() {
        let mut state = FinalityState::new();
        let hash = make_hash(12);
        let validator = make_addr(1);

        assert!(!state.record_attestation_weighted(make_att(hash, 10, validator, vec![]), 0));
        assert_eq!(state.attestation_count(&hash), 0);
        assert_eq!(state.attested_weight(&hash), 0);
        assert!(!state.has_attested(&hash, &validator));
    }

    #[test]
    fn single_validator_weighted_finalizes() {
        let mut state = FinalityState::new();
        let hash = make_hash(11);

        state.record_attestation_weighted(make_att(hash, 1, make_addr(1), vec![]), 1);
        assert!(state.check_finality_weighted(&hash, 1, 1));
        assert_eq!(state.last_finalized_hash(), &hash);
    }

    #[test]
    fn test_finality_requires_higher_block() {
        let mut state = FinalityState::with_finalized(20, make_hash(2));
        let hash = make_hash(1);

        // Even with weighted quorum, block 10 < finalized 20 → no update
        state.record_attestation(make_att(hash, 10, make_addr(1), vec![]));
        state.record_attestation(make_att(hash, 10, make_addr(2), vec![]));
        state.record_attestation(make_att(hash, 10, make_addr(3), vec![]));
        assert!(!state.check_finality_weighted(&hash, 10, 3));
        assert_eq!(state.last_finalized_number(), 20);
    }

    #[test]
    fn test_has_attested() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);
        let addr = make_addr(1);

        assert!(!state.has_attested(&hash, &addr));
        state.record_attestation(make_att(hash, 10, addr, vec![]));
        assert!(state.has_attested(&hash, &addr));
    }

    #[test]
    fn test_equivocation_detection() {
        let mut state = FinalityState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let validator = make_addr(1);

        state.record_attestation(make_att(hash1, 10, validator, vec![]));

        // Same validator, same height, different hash → equivocation
        let conflict = state.detect_equivocation(&hash2, 10, &validator);
        assert_eq!(conflict, Some(hash1));
    }

    #[test]
    fn test_no_equivocation_different_height() {
        let mut state = FinalityState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let validator = make_addr(1);

        state.record_attestation(make_att(hash1, 10, validator, vec![]));

        // Different height → not equivocation
        let conflict = state.detect_equivocation(&hash2, 11, &validator);
        assert_eq!(conflict, None);
    }

    #[test]
    fn test_prune_below() {
        let mut state = FinalityState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        state.record_attestation(make_att(hash1, 5, make_addr(1), vec![]));
        state.record_attestation(make_att(hash2, 15, make_addr(1), vec![]));

        // Finalize at block 15 → prune block 5 attestations
        state.record_attestation(make_att(hash2, 15, make_addr(2), vec![]));
        state.record_attestation(make_att(hash2, 15, make_addr(3), vec![]));
        assert!(state.check_finality_weighted(&hash2, 15, 3));

        assert_eq!(state.attestation_count(&hash1), 0); // pruned
        assert_eq!(state.attested_weight(&hash1), 0);
        assert!(state.attested_block_by_height.is_empty());
        assert_eq!(
            state.detect_equivocation(&make_hash(3), 5, &make_addr(1)),
            None
        );
        // hash2 also pruned since it's <= finalized (15)
    }

    #[test]
    fn test_five_of_seven_quorum() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);

        // 7 validators, BFT quorum = ceil(14/3) = 5
        for i in 0..4 {
            state.record_attestation(make_att(hash, 10, make_addr(i), vec![]));
        }
        assert!(!state.check_finality_weighted(&hash, 10, 7)); // 4 < 5

        state.record_attestation(make_att(hash, 10, make_addr(4), vec![]));
        assert!(state.check_finality_weighted(&hash, 10, 7)); // 5 >= 5
    }

    #[test]
    fn test_default_state() {
        let state = FinalityState::default();
        assert_eq!(state.last_finalized_number(), 0);
        assert_eq!(state.last_finalized_hash(), &ShellHash::ZERO);
    }

    // ---- Additional comprehensive tests ----

    #[test]
    fn quorum_exactly_at_threshold() {
        // Verify strict >2/3 quorum detection for various uniform validator sets.
        for total in [3u64, 4, 5, 6, 7, 10, 13, 20] {
            let quorum = strict_quorum_weight(total);
            let hash = make_hash(total as u8);
            let mut state = FinalityState::new();

            // Add one weight less than quorum → should NOT finalize.
            for i in 0..(quorum - 1) {
                state.record_attestation(make_att(hash, 100, make_addr(i as u8), vec![]));
            }
            assert!(
                !state.check_finality_weighted(&hash, 100, total),
                "W={total}: weight {} should NOT finalize",
                quorum - 1
            );

            let mut state2 = FinalityState::new();
            for i in 0..quorum {
                state2.record_attestation(make_att(hash, 100, make_addr(i as u8), vec![]));
            }
            assert!(
                state2.check_finality_weighted(&hash, 100, total),
                "W={total}: weight {quorum} should finalize"
            );
        }
    }

    #[test]
    fn below_quorum_does_not_finalize() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);

        // 5 of 10 validators → quorum is 6
        for i in 0..5 {
            state.record_attestation(make_att(hash, 50, make_addr(i), vec![]));
        }
        assert!(!state.check_finality_weighted(&hash, 50, 10));
        assert_eq!(
            state.last_finalized_number(),
            0,
            "should not have advanced finality"
        );
    }

    #[test]
    fn multiple_finalization_rounds() {
        let mut state = FinalityState::new();

        // Round 1: finalize block 10
        let hash10 = make_hash(10);
        for i in 0..3 {
            state.record_attestation(make_att(hash10, 10, make_addr(i), vec![]));
        }
        assert!(state.check_finality_weighted(&hash10, 10, 4)); // quorum = 3 for N=4
        assert_eq!(state.last_finalized_number(), 10);

        // Round 2: finalize block 20
        let hash20 = make_hash(20);
        for i in 0..3 {
            state.record_attestation(make_att(hash20, 20, make_addr(100 + i), vec![]));
        }
        assert!(state.check_finality_weighted(&hash20, 20, 4));
        assert_eq!(state.last_finalized_number(), 20);
        assert_eq!(state.last_finalized_hash(), &hash20);

        // Round 3: finalize block 30
        let hash30 = make_hash(30);
        for i in 0..3 {
            state.record_attestation(make_att(hash30, 30, make_addr(200 + i), vec![]));
        }
        assert!(state.check_finality_weighted(&hash30, 30, 4));
        assert_eq!(state.last_finalized_number(), 30);
    }

    #[test]
    fn large_validator_set_quorum() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);
        let total: u64 = 100;
        let quorum = strict_quorum_weight(total);

        assert_eq!(quorum, 67);

        // Add 66 attestations → not enough
        for i in 0..66u8 {
            state.record_attestation(make_att(hash, 500, make_addr(i), vec![]));
        }
        assert!(!state.check_finality_weighted(&hash, 500, total));

        // Add 1 more → exactly 67 → quorum
        state.record_attestation(make_att(hash, 500, make_addr(66), vec![]));
        assert!(state.check_finality_weighted(&hash, 500, total));
        assert_eq!(state.last_finalized_number(), 500);
    }

    #[test]
    fn finalization_monotonically_advances() {
        let mut state = FinalityState::new();

        // Finalize block 20 first
        let hash20 = make_hash(20);
        for i in 0..3 {
            state.record_attestation(make_att(hash20, 20, make_addr(i), vec![]));
        }
        assert!(state.check_finality_weighted(&hash20, 20, 4));
        assert_eq!(state.last_finalized_number(), 20);

        // Try to finalize block 15 (lower) — should fail
        let hash15 = make_hash(15);
        for i in 10..13 {
            state.record_attestation(make_att(hash15, 15, make_addr(i), vec![]));
        }
        assert!(!state.check_finality_weighted(&hash15, 15, 4));
        assert_eq!(
            state.last_finalized_number(),
            20,
            "finality must not go backwards"
        );

        // Finalize block 25 (higher) — should succeed
        let hash25 = make_hash(25);
        for i in 20..23 {
            state.record_attestation(make_att(hash25, 25, make_addr(i), vec![]));
        }
        assert!(state.check_finality_weighted(&hash25, 25, 4));
        assert_eq!(state.last_finalized_number(), 25);
    }

    #[test]
    fn prune_preserves_above_finalized() {
        let mut state = FinalityState::new();
        let hash_low = make_hash(1);
        let hash_high = make_hash(2);
        let hash_future = make_hash(3);

        // Attestation at height 5
        state.record_attestation(make_att(hash_low, 5, make_addr(1), vec![]));
        // Attestation at height 10
        state.record_attestation(make_att(hash_high, 10, make_addr(2), vec![]));
        state.record_attestation(make_att(hash_high, 10, make_addr(3), vec![]));
        state.record_attestation(make_att(hash_high, 10, make_addr(4), vec![]));
        // Attestation at height 20
        state.record_attestation(make_att(hash_future, 20, make_addr(5), vec![]));

        // Finalize at height 10 → prune heights <= 10
        assert!(state.check_finality_weighted(&hash_high, 10, 3));

        // Height 5 should be pruned
        assert_eq!(state.attestation_count(&hash_low), 0);
        // Height 10 also pruned (it's <= finalized)
        assert_eq!(state.attestation_count(&hash_high), 0);
        // Height 20 should survive
        assert_eq!(state.attestation_count(&hash_future), 1);
    }

    #[test]
    fn total_pending_attestations_tracking() {
        let mut state = FinalityState::new();
        assert_eq!(state.total_pending_attestations(), 0);

        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        state.record_attestation(make_att(hash1, 10, make_addr(1), vec![]));
        assert_eq!(state.total_pending_attestations(), 1);

        state.record_attestation(make_att(hash1, 10, make_addr(2), vec![]));
        assert_eq!(state.total_pending_attestations(), 2);

        state.record_attestation(make_att(hash2, 11, make_addr(3), vec![]));
        assert_eq!(state.total_pending_attestations(), 3);

        // Duplicate should not increase count
        state.record_attestation(make_att(hash1, 10, make_addr(1), vec![]));
        assert_eq!(state.total_pending_attestations(), 3);
    }

    #[test]
    fn with_finalized_constructor() {
        let hash = make_hash(42);
        let state = FinalityState::with_finalized(100, hash);
        assert_eq!(state.last_finalized_number(), 100);
        assert_eq!(state.last_finalized_hash(), &hash);
        assert_eq!(state.total_pending_attestations(), 0);
    }

    #[test]
    fn finalized_or_stale_attestations_are_rejected() {
        let mut state = FinalityState::with_finalized(10, make_hash(10));

        assert!(!state.record_attestation(make_att(make_hash(9), 9, make_addr(1), vec![],)));
        assert!(!state.record_attestation(make_att(make_hash(10), 10, make_addr(2), vec![],)));

        let future_hash = make_hash(11);
        assert!(state.record_attestation(make_att(future_hash, 11, make_addr(3), vec![],)));
        assert_eq!(state.total_pending_attestations(), 1);
        assert_eq!(state.attestation_count(&future_hash), 1);
    }

    #[test]
    fn equivocation_not_detected_same_hash() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);
        let validator = make_addr(1);

        state.record_attestation(make_att(hash, 10, validator, vec![]));

        // Same hash, same validator — not equivocation (just a duplicate)
        let conflict = state.detect_equivocation(&hash, 10, &validator);
        assert_eq!(conflict, None, "same hash should not be equivocation");
    }

    #[test]
    fn concurrent_blocks_at_same_height() {
        let mut state = FinalityState::new();
        let hash_a = make_hash(1);
        let hash_b = make_hash(2);

        // Different validators attest to different blocks at height 10.
        state.record_attestation_weighted(make_att(hash_a, 10, make_addr(1), vec![]), 4);
        state.record_attestation_weighted(make_att(hash_a, 10, make_addr(2), vec![]), 1);
        state.record_attestation_weighted(make_att(hash_b, 10, make_addr(3), vec![]), 1);

        assert_eq!(state.attestation_count(&hash_a), 2);
        assert_eq!(state.attested_weight(&hash_a), 5);
        assert_eq!(state.attested_weight(&hash_b), 1);

        // Total validator weight is 6, so hash_a's weight 5 crosses the strict quorum.
        assert!(state.check_finality_weighted(&hash_a, 10, 6));
        assert_eq!(state.last_finalized_hash(), &hash_a);
    }

    #[test]
    fn finality_requires_quorum_not_just_any_count() {
        let mut state = FinalityState::new();
        let hash = make_hash(1);

        // 1 of 10 validators
        state.record_attestation(make_att(hash, 10, make_addr(1), vec![]));
        assert!(!state.check_finality_weighted(&hash, 10, 10)); // BFT quorum = 7

        // 6 of 10 validators
        for i in 2..=6 {
            state.record_attestation(make_att(hash, 10, make_addr(i), vec![]));
        }
        assert!(!state.check_finality_weighted(&hash, 10, 10)); // still only 6 < 7

        // 7 of 10 validators → exactly quorum
        state.record_attestation(make_att(hash, 10, make_addr(7), vec![]));
        assert!(state.check_finality_weighted(&hash, 10, 10));
    }

    #[test]
    fn attestation_with_real_dilithium_signature() {
        use shell_crypto::{DilithiumSigner, DilithiumVerifier, Signer, Verifier};
        use shell_primitives::Address;

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let validator_addr = Address::from_public_key(&pubkey, signer.sig_type().as_u8());
        let block_hash = make_hash(42);
        let block_number: u64 = 100;

        // Sign the attestation message with a real Dilithium key.
        let chain_id: u64 = 0;
        let parent_hash = ShellHash::ZERO;
        let round: u64 = 0;
        let msg =
            Attestation::signing_message(chain_id, &parent_hash, &block_hash, block_number, round);
        let sig = signer.sign(&msg).expect("signing must succeed");
        assert!(!sig.data.is_empty(), "signature must not be empty");

        // Verify the signature using the Dilithium verifier.
        let verifier = DilithiumVerifier;
        let valid = verifier
            .verify(&pubkey, &msg, &sig)
            .expect("verify must succeed");
        assert!(valid, "real Dilithium signature must verify");

        // Record the attestation with the real signature.
        let attestation = make_att(block_hash, block_number, validator_addr, sig.data.clone());
        let mut state = FinalityState::new();
        assert!(state.record_attestation(attestation));
        assert_eq!(state.attestation_count(&block_hash), 1);
        assert_eq!(state.attested_weight(&block_hash), 1);

        // Verify the stored attestation signature is valid.
        let stored = state.get_attestations(&block_hash).unwrap();
        assert_eq!(stored.len(), 1);
        let stored_sig = shell_crypto::PQSignature::new(
            shell_crypto::SignatureType::Dilithium3,
            stored[0].signature.clone(),
        );
        let stored_valid = verifier.verify(&pubkey, &msg, &stored_sig).unwrap();
        assert!(stored_valid, "stored attestation signature must verify");

        // Verify a tampered message does not pass.
        let wrong_msg = Attestation::signing_message(
            chain_id,
            &parent_hash,
            &block_hash,
            block_number + 1,
            round,
        );
        let wrong_valid = verifier.verify(&pubkey, &wrong_msg, &stored_sig).unwrap();
        assert!(!wrong_valid, "signature must not verify for wrong message");
    }
}
