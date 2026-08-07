use std::collections::HashMap;

use async_trait::async_trait;
use shell_core::{Block, BlockHeader};
use shell_crypto::{PQSignature, Signer, Verifier};
use shell_primitives::Address;

use crate::{ConsensusError, PoaConfig, ViewChangeMessage};

/// Consensus engine type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineType {
    /// Proof of Authority — Phase 1 consensus.
    PoA,
    /// Weighted Proof of Authority — Phase 1.5 consensus.
    WPoA,
    /// Byzantine Fault Tolerant — reserved for Phase 2 upgrade.
    BFT,
}

/// Pluggable consensus engine interface.
///
/// Implementations provide block validation, sealing, and proposer selection.
/// The trait is designed for extensibility: adding a new consensus algorithm
/// (e.g., BFT) requires only a new implementation, no changes to existing code.
#[async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// Validate a block header against consensus rules.
    ///
    /// Checks: proposer is authorized, timestamp is valid, signature is correct.
    fn verify_header(&self, header: &BlockHeader) -> Result<(), ConsensusError>;

    /// Validate proposer selection for a finalized block received from the
    /// network with a verified commit certificate.
    ///
    /// The default is identical to [`Self::verify_header`]. Consensus engines
    /// with view changes may override this because a restarting node does not
    /// retain the in-memory view that was active when an older block was sealed.
    fn verify_header_for_finalized_import(
        &self,
        header: &BlockHeader,
        _parent: &BlockHeader,
    ) -> Result<(), ConsensusError> {
        self.verify_header(header)
    }

    /// Seal a block by signing and finalizing it for broadcast.
    ///
    /// The implementation should set `block.proposer_seal` with a valid
    /// PQ signature over the block header.
    async fn seal_block(&self, block: &mut Block) -> Result<(), ConsensusError>;

    /// Check whether the given address is the proposer for the given slot.
    ///
    /// Slot is typically `timestamp / block_interval`.
    fn is_proposer(&self, slot: u64, address: &Address) -> bool;

    /// Return the engine type identifier.
    fn engine_type(&self) -> EngineType;

    /// Return the underlying PoA configuration.
    fn poa_config(&self) -> &PoaConfig;

    /// Return a mutable reference to the underlying PoA configuration.
    fn poa_config_mut(&mut self) -> &mut PoaConfig;

    /// Replace the active authority set from canonical chain state.
    fn set_authorities(&mut self, authorities: Vec<Address>) {
        self.poa_config_mut().set_authorities(authorities);
    }

    /// Replace the active authority set and aligned weights from canonical chain state.
    fn set_authorities_with_weights(&mut self, authorities: Vec<Address>, _weights: Vec<u64>) {
        self.set_authorities(authorities);
    }

    /// Sign a block header with the proposer's key.
    fn sign_block(&self, block: &mut Block, signer: &dyn Signer) -> Result<(), ConsensusError>;

    /// Verify a proposer seal (PQ signature over header hash).
    fn verify_seal(
        &self,
        header: &BlockHeader,
        seal: &PQSignature,
        proposer_pubkey: &[u8],
        verifier: &dyn Verifier,
    ) -> Result<(), ConsensusError>;

    /// Slash a misbehaving authority, reducing its effective economic weight.
    fn slash_authority(&mut self, offender: &Address);

    /// Return the active validator set with per-validator weights.
    ///
    /// Used by the wPoA state machine to initialize quorum tracking.
    fn validator_weights(&self) -> HashMap<Address, u64>;

    /// Record a view-change vote and return true when quorum advances the view.
    fn handle_view_change_message(&mut self, _msg: ViewChangeMessage, _total_weight: u64) -> bool {
        false
    }

    /// Return the active view for the next in-flight block.
    fn current_view(&self) -> u64 {
        0
    }

    /// Return true when the proposer timeout has elapsed for the current height.
    fn check_view_change_timeout(&self, _now_ms: u64, _block_time_ms: u64) -> bool {
        false
    }

    /// Reset the view-change timeout window after a block is produced or imported.
    fn note_block_progress(&mut self, _now_ms: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_type_poa_eq() {
        assert_eq!(EngineType::PoA, EngineType::PoA);
    }

    #[test]
    fn engine_type_bft_eq() {
        assert_eq!(EngineType::BFT, EngineType::BFT);
    }

    #[test]
    fn engine_type_poa_ne_bft() {
        assert_ne!(EngineType::PoA, EngineType::BFT);
    }

    #[test]
    fn engine_type_clone() {
        let e = EngineType::PoA;
        let cloned = e;
        assert_eq!(e, cloned);
    }

    #[test]
    fn engine_type_debug_format() {
        assert_eq!(format!("{:?}", EngineType::PoA), "PoA");
        assert_eq!(format!("{:?}", EngineType::BFT), "BFT");
    }

    #[test]
    fn engine_type_copy_semantics() {
        let a = EngineType::BFT;
        let b = a; // Copy
        assert_eq!(a, b);
    }
}
