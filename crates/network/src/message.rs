//! Network message types for block and transaction propagation.

use serde::{Deserialize, Serialize};
use shell_consensus::{Attestation, ChallengeResponse, EquivocationProof, ProofChallenge};
use shell_core::{Block, SignedTransaction};
use shell_primitives::ShellHash;

use crate::error::NetworkError;

/// Default maximum message size: 4 MiB.
///
/// This matches the GossipSub `max_transmit_size` and prevents memory
/// exhaustion from oversized payloads before deserialization is attempted.
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Unique identifier for a network peer.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Messages exchanged between nodes on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Announce a newly produced or received block.
    NewBlock(Box<Block>),
    /// Announce a new transaction for mempool inclusion.
    NewTransaction(Box<SignedTransaction>),
    /// Announce a block attestation (validator confirmation).
    NewAttestation(Box<Attestation>),
    /// Request a range of blocks by number.
    BlockRequest { start_number: u64, count: u64 },
    /// Response to a block request.
    BlockResponse { blocks: Vec<Block> },
    /// Ping to check liveness.
    Ping,
    /// Pong response to ping.
    Pong,
    /// G5: Broadcast a STARK proof amendment for a previously sealed block.
    ///
    /// Sent by the `ProverService` after completing async proof generation.
    /// Receivers verify the amendment and store it via `ProofAmendmentStore`.
    /// Topic: `/shell/proofs/1`
    ProofAmendment {
        /// Hash of the block this proof covers.
        block_hash: ShellHash,
        /// The block number (for routing/filtering without full deserialization).
        block_number: u64,
        /// Serialized `ProofAmendment` bytes (JSON). Typically 10–20 KB.
        payload: Vec<u8>,
    },
    /// G5: Acknowledgement that a node has stored a proof amendment.
    ///
    /// Used for proof availability tracking (K1).
    ProofAck {
        /// Hash of the block whose proof was acknowledged.
        block_hash: ShellHash,
        /// Address of the acknowledging node.
        holder: shell_primitives::Address,
    },
    /// I1: Broadcast equivocation evidence when a double-sign is detected.
    ///
    /// Sent immediately when `import_block` detects two conflicting headers
    /// from the same proposer at the same height. Receiving peers independently
    /// verify the proof before applying slashing.
    EquivocationEvidence(Box<EquivocationProof>),
    /// I2: Challenge a STARK proof amendment that failed local verification.
    ///
    /// Broadcast by a node that cannot verify a received `ProofAmendment`.
    /// Any node holding the raw proof may respond with `ProofChallengeResponse`.
    ProofChallenge(Box<ProofChallenge>),
    /// I2: Response to a `ProofChallenge` — provides raw proof bytes for re-verification.
    ProofChallengeResponse(Box<ChallengeResponse>),
    /// Advertise this node's storage capability to a newly connected peer.
    ///
    /// Sent once after a peer connection is established.  Receivers use this
    /// information to prefer archive/full peers when requesting historical data.
    StorageCapability {
        /// Human-readable profile name: "archive", "full", or "light".
        profile: String,
        /// Lowest block number whose body (`b/<hash>`) is still available locally.
        /// `0` means all blocks from genesis are available.
        oldest_body_block: u64,
    },
    /// Request missing block bodies (TX detail) for a range of block numbers.
    ///
    /// Used for historical body back-fill after a node upgrades its storage profile.
    BodyRequest { start_number: u64, count: u64 },
    /// Response carrying block bodies for a `BodyRequest`.
    BodyResponse { blocks: Vec<Block> },
}

/// Events produced by the network layer for the node to process.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A message was received from a peer.
    MessageReceived {
        peer: PeerId,
        message: NetworkMessage,
    },
    /// A new peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// Kademlia routing table was updated.
    RoutingTableUpdated {
        /// Number of peers in the routing table.
        peer_count: usize,
    },
}

/// F-069: Validate that raw message bytes do not exceed the size limit.
///
/// Call this *before* deserializing to avoid allocating memory for
/// oversized payloads. Returns `Ok(())` if within bounds or an error
/// containing the actual and allowed sizes.
pub fn validate_message_size(data: &[u8], limit: usize) -> Result<(), NetworkError> {
    if data.len() > limit {
        return Err(NetworkError::MessageTooLarge {
            size: data.len(),
            limit,
        });
    }
    Ok(())
}

/// F-069: Deserialize a `NetworkMessage` from raw bytes after validating size.
///
/// Combines size validation and JSON deserialization in a single call.
pub fn deserialize_checked(data: &[u8], limit: usize) -> Result<NetworkMessage, NetworkError> {
    validate_message_size(data, limit)?;
    serde_json::from_slice(data).map_err(|e| NetworkError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{Block, BlockHeader, SignedTransaction, Transaction};
    use shell_crypto::PQSignature;
    use shell_primitives::{Address, Bytes, ShellHash, U256};

    fn test_block(number: u64) -> Block {
        Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000 + number,
                extra_data: Bytes::default(),
                proposer: Address::from_public_key(b"test-proposer", 0),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            proposer_seal: None,
        }
    }

    fn test_signed_tx() -> SignedTransaction {
        SignedTransaction::new(
            Address::from_public_key(b"sender-key", 0),
            Transaction {
                chain_id: 1,
                nonce: 0,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000_000,
                gas_limit: 21_000,
                to: None,
                value: U256::ZERO,
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]),
        )
    }

    #[test]
    fn peer_id_from_string() {
        let id = PeerId::from("node-1".to_string());
        assert_eq!(id.0, "node-1");
    }

    #[test]
    fn peer_id_from_str() {
        let id = PeerId::from("node-2");
        assert_eq!(id.0, "node-2");
    }

    #[test]
    fn peer_id_display() {
        let id = PeerId("peer-abc".into());
        assert_eq!(format!("{id}"), "peer-abc");
    }

    #[test]
    fn peer_id_equality_and_hash() {
        use std::collections::HashSet;
        let a = PeerId::from("same");
        let b = PeerId::from("same");
        let c = PeerId::from("other");
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn serde_roundtrip_ping() {
        let msg = NetworkMessage::Ping;
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        assert!(matches!(decoded, NetworkMessage::Ping));
    }

    #[test]
    fn serde_roundtrip_pong() {
        let msg = NetworkMessage::Pong;
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        assert!(matches!(decoded, NetworkMessage::Pong));
    }

    #[test]
    fn serde_roundtrip_block_request() {
        let msg = NetworkMessage::BlockRequest {
            start_number: 10,
            count: 5,
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::BlockRequest {
                start_number,
                count,
            } => {
                assert_eq!(start_number, 10);
                assert_eq!(count, 5);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn serde_roundtrip_block_response() {
        let blocks = vec![test_block(1), test_block(2)];
        let msg = NetworkMessage::BlockResponse {
            blocks: blocks.clone(),
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::BlockResponse {
                blocks: decoded_blocks,
            } => {
                assert_eq!(decoded_blocks.len(), 2);
                assert_eq!(decoded_blocks[0].header.number, 1);
                assert_eq!(decoded_blocks[1].header.number, 2);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn serde_roundtrip_new_block() {
        let msg = NetworkMessage::NewBlock(Box::new(test_block(42)));
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::NewBlock(b) => assert_eq!(b.header.number, 42),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn serde_roundtrip_new_transaction() {
        let msg = NetworkMessage::NewTransaction(Box::new(test_signed_tx()));
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        assert!(matches!(decoded, NetworkMessage::NewTransaction(_)));
    }

    #[test]
    fn network_event_variants_constructable() {
        let peer = PeerId::from("test-peer");

        let _connected = NetworkEvent::PeerConnected(peer.clone());
        let _disconnected = NetworkEvent::PeerDisconnected(peer.clone());
        let _routing = NetworkEvent::RoutingTableUpdated { peer_count: 10 };
        let _msg = NetworkEvent::MessageReceived {
            peer,
            message: NetworkMessage::Ping,
        };
    }

    #[test]
    fn peer_id_clone() {
        let original = PeerId::from("cloneable");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn serde_roundtrip_new_attestation() {
        let attestation = Attestation {
            block_hash: ShellHash::default(),
            block_number: 99,
            validator: Address::from_public_key(b"validator-key", 0),
            signature: vec![1, 2, 3, 4],
        };
        let msg = NetworkMessage::NewAttestation(Box::new(attestation));
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::NewAttestation(a) => {
                assert_eq!(a.block_number, 99);
                assert_eq!(a.signature, vec![1, 2, 3, 4]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    // ---- F-069: message size validation tests ----

    #[test]
    fn validate_message_size_within_limit() {
        let data = vec![0u8; 100];
        assert!(validate_message_size(&data, 100).is_ok());
        assert!(validate_message_size(&data, 200).is_ok());
    }

    #[test]
    fn validate_message_size_over_limit() {
        let data = vec![0u8; 101];
        let err = validate_message_size(&data, 100);
        assert!(err.is_err());
        match err.unwrap_err() {
            NetworkError::MessageTooLarge { size, limit } => {
                assert_eq!(size, 101);
                assert_eq!(limit, 100);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn validate_message_size_empty() {
        assert!(validate_message_size(&[], 0).is_ok());
        assert!(validate_message_size(&[], 100).is_ok());
    }

    #[test]
    fn deserialize_checked_rejects_oversized() {
        let msg = NetworkMessage::Ping;
        let json = serde_json::to_vec(&msg).unwrap();
        // Set limit smaller than serialized size.
        let err = deserialize_checked(&json, 1);
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            NetworkError::MessageTooLarge { .. }
        ));
    }

    #[test]
    fn deserialize_checked_accepts_valid() {
        let msg = NetworkMessage::Ping;
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap();
        assert!(matches!(decoded, NetworkMessage::Ping));
    }

    #[test]
    fn deserialize_checked_rejects_invalid_json() {
        let bad_data = b"not-json";
        let err = deserialize_checked(bad_data, MAX_MESSAGE_SIZE);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), NetworkError::Serialization(_)));
    }

    #[test]
    fn max_message_size_constant() {
        assert_eq!(MAX_MESSAGE_SIZE, 4 * 1024 * 1024);
    }
}
