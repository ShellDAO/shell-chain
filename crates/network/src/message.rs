//! Network message types for block and transaction propagation.

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer as _, Serialize};
use shell_consensus::{
    Attestation, ChallengeResponse, EquivocationProof, ProofChallenge, ViewChangeMessage,
};
use shell_core::{Block, SignedTransaction};
use shell_crypto::PQSignature;
use shell_primitives::ShellHash;

use crate::error::NetworkError;

/// Absolute raw-message ceiling before deserialization.
///
/// PQ-signed block/body sync responses can exceed 4 MiB, so the raw transport
/// ceiling remains high. After decoding, each message variant is checked
/// against a tighter type-specific limit via [`NetworkMessage::max_serialized_size`].
pub const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;
pub const MAX_TX_GOSSIP_SIZE: usize = 1024 * 1024;
pub const MAX_CONSENSUS_MESSAGE_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_CONTROL_MESSAGE_SIZE: usize = 64 * 1024;
/// Maximum number of blocks accepted in a single sync response.
pub const MAX_RESPONSE_BLOCKS: usize = 128;

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
    /// `nonce` is a millisecond timestamp added so that each retry has unique
    /// content and therefore a unique GossipSub message_id, bypassing the
    /// seen-message deduplication cache that would otherwise drop identical
    /// retries.
    BlockRequest {
        start_number: u64,
        count: u64,
        #[serde(default)]
        nonce: u64,
    },
    /// Response to a block request. `nonce` mirrors the same anti-dedup
    /// strategy used in `BlockRequest`: the responder stamps current time in
    /// milliseconds so that repeated responses carrying the same blocks (due
    /// to multiple requesters or retries) get distinct GossipSub message_ids
    /// and are not silently dropped by the seen-message cache.
    BlockResponse {
        blocks: Vec<Block>,
        /// Commit certificate sidecars keyed by block hash.
        ///
        /// Kept out of block headers so old block hashes remain stable.
        #[serde(default)]
        commit_certificates: Vec<(ShellHash, Vec<u8>)>,
        #[serde(default)]
        nonce: u64,
    },
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
    BodyRequest {
        start_number: u64,
        count: u64,
        #[serde(default)]
        nonce: u64,
    },
    /// Response carrying block bodies for a `BodyRequest`.
    BodyResponse {
        blocks: Vec<Block>,
        #[serde(default)]
        nonce: u64,
    },
    /// W.5: wPoA consensus vote for a proposed block.
    ///
    /// Broadcast by each validator after receiving a proposed block.
    /// Quorum (⌈2/3 × total_weight⌉) of votes commits the block.
    WPoaVote {
        /// Hash of the block being voted on.
        block_hash: ShellHash,
        /// Block number (for routing/filtering).
        block_number: u64,
        /// Address of the voting validator.
        voter: shell_primitives::Address,
        /// PQ signature over the block hash.
        signature: PQSignature,
    },
    /// W.5: Signed wPoA view-change vote for a timed-out proposer view.
    WPoaViewChange(Box<ViewChangeMessage>),
}

/// High-level topic classification for network message propagation.
///
/// Keeping this mapping alongside `NetworkMessage` makes it much harder for
/// new variants to be silently unrouted by transport-specific code (e.g. libp2p).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTopic {
    /// Block and block-body propagation traffic.
    Blocks,
    /// Transaction gossip traffic.
    Transactions,
    /// Attestation and wPoA vote traffic.
    Attestation,
    /// STARK proof amendment and challenge traffic.
    Proofs,
}

impl NetworkMessage {
    /// Maximum serialized size allowed for this specific message kind.
    pub fn max_serialized_size(&self) -> usize {
        match self {
            Self::NewBlock(_) | Self::BlockResponse { .. } | Self::BodyResponse { .. } => {
                MAX_MESSAGE_SIZE
            }
            Self::NewTransaction(_) => MAX_TX_GOSSIP_SIZE,
            Self::NewAttestation(_)
            | Self::ProofAmendment { .. }
            | Self::ProofAck { .. }
            | Self::EquivocationEvidence(_)
            | Self::ProofChallenge(_)
            | Self::ProofChallengeResponse(_)
            | Self::WPoaVote { .. }
            | Self::WPoaViewChange(_) => MAX_CONSENSUS_MESSAGE_SIZE,
            Self::BlockRequest { .. }
            | Self::BodyRequest { .. }
            | Self::Ping
            | Self::Pong
            | Self::StorageCapability { .. } => MAX_CONTROL_MESSAGE_SIZE,
        }
    }

    /// Returns the propagation topic for this message type.
    pub fn topic(&self) -> NetworkTopic {
        match self {
            Self::NewBlock(_)
            | Self::BlockRequest { .. }
            | Self::BlockResponse { .. }
            | Self::Ping
            | Self::Pong
            | Self::StorageCapability { .. }
            | Self::BodyRequest { .. }
            | Self::BodyResponse { .. } => NetworkTopic::Blocks,
            Self::NewTransaction(_) => NetworkTopic::Transactions,
            Self::NewAttestation(_) | Self::WPoaVote { .. } | Self::WPoaViewChange(_) => {
                NetworkTopic::Attestation
            }
            Self::ProofAmendment { .. }
            | Self::ProofAck { .. }
            | Self::EquivocationEvidence(_)
            | Self::ProofChallenge(_)
            | Self::ProofChallengeResponse(_) => NetworkTopic::Proofs,
        }
    }
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
    if let Some(limit) = serialized_message_size_limit(data) {
        validate_message_size(data, limit)?;
    }
    validate_response_block_count(data)?;
    let msg: NetworkMessage =
        serde_json::from_slice(data).map_err(|e| NetworkError::Serialization(e.to_string()))?;
    validate_message_size(data, msg.max_serialized_size())?;
    msg.validate_semantics()?;
    Ok(msg)
}

impl NetworkMessage {
    fn validate_semantics(&self) -> Result<(), NetworkError> {
        match self {
            Self::BlockRequest { count, .. } | Self::BodyRequest { count, .. }
                if !(1..=MAX_RESPONSE_BLOCKS as u64).contains(count) =>
            {
                Err(NetworkError::Serialization(format!(
                    "request count must be between 1 and {MAX_RESPONSE_BLOCKS}"
                )))
            }
            Self::BlockResponse {
                blocks,
                commit_certificates,
                ..
            } if commit_certificates.len() > blocks.len() => Err(NetworkError::Serialization(
                "commit certificate count exceeds block count".to_string(),
            )),
            Self::StorageCapability { profile, .. }
                if !matches!(
                    profile.to_ascii_lowercase().as_str(),
                    "archive" | "full" | "pruned" | "rolling" | "light"
                ) =>
            {
                Err(NetworkError::Serialization(
                    "unknown storage capability profile".to_string(),
                ))
            }
            _ => Ok(()),
        }
    }
}

fn validate_response_block_count(data: &[u8]) -> Result<(), NetworkError> {
    if !matches!(
        serialized_message_variant(data),
        Some("BlockResponse" | "BodyResponse")
    ) {
        return Ok(());
    }

    serde_json::Deserializer::from_slice(data)
        .deserialize_map(ResponseVisitor)
        .map_err(|error| {
            NetworkError::Serialization(format!("invalid response structure: {error}"))
        })
}

struct ResponseVisitor;

impl<'de> Visitor<'de> for ResponseVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an externally tagged network response")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let Some(variant) = map.next_key::<String>()? else {
            return Ok(());
        };
        let response_kind = match variant.as_str() {
            "BlockResponse" => Some(ResponseKind::Block),
            "BodyResponse" => Some(ResponseKind::Body),
            _ => None,
        };
        map.next_value_seed(ResponsePayloadSeed { response_kind })
    }
}

#[derive(Clone, Copy)]
enum ResponseKind {
    Block,
    Body,
}

struct ResponsePayloadSeed {
    response_kind: Option<ResponseKind>,
}

impl<'de> DeserializeSeed<'de> for ResponsePayloadSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if let Some(response_kind) = self.response_kind {
            deserializer.deserialize_map(ResponsePayloadVisitor { response_kind })
        } else {
            deserializer.deserialize_any(IgnoredAny).map(|_| ())
        }
    }
}

struct ResponsePayloadVisitor {
    response_kind: ResponseKind,
}

impl<'de> Visitor<'de> for ResponsePayloadVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a response payload")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "blocks" {
                map.next_value_seed(BoundedResponseArraySeed {
                    item_name: "blocks",
                })?;
            } else if key == "commit_certificates"
                && matches!(self.response_kind, ResponseKind::Block)
            {
                map.next_value_seed(BoundedResponseArraySeed {
                    item_name: "commit certificates",
                })?;
            } else {
                let _: IgnoredAny = map.next_value()?;
            }
        }
        Ok(())
    }
}

struct BoundedResponseArraySeed {
    item_name: &'static str,
}

impl<'de> DeserializeSeed<'de> for BoundedResponseArraySeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedResponseArrayVisitor {
            item_name: self.item_name,
        })
    }
}

struct BoundedResponseArrayVisitor {
    item_name: &'static str,
}

impl<'de> Visitor<'de> for BoundedResponseArrayVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "a bounded response {} array", self.item_name)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut count = 0;
        while sequence.next_element::<IgnoredAny>()?.is_some() {
            count += 1;
            if count > MAX_RESPONSE_BLOCKS {
                return Err(de::Error::custom(format!(
                    "response contains more than {MAX_RESPONSE_BLOCKS} {}",
                    self.item_name
                )));
            }
        }
        Ok(())
    }
}

fn serialized_message_size_limit(data: &[u8]) -> Option<usize> {
    let variant = serialized_message_variant(data)?;
    Some(match variant {
        "NewBlock" | "BlockResponse" | "BodyResponse" => MAX_MESSAGE_SIZE,
        "NewTransaction" => MAX_TX_GOSSIP_SIZE,
        "NewAttestation"
        | "ProofAmendment"
        | "ProofAck"
        | "EquivocationEvidence"
        | "ProofChallenge"
        | "ProofChallengeResponse"
        | "WPoaVote"
        | "WPoaViewChange" => MAX_CONSENSUS_MESSAGE_SIZE,
        "BlockRequest" | "BodyRequest" | "Ping" | "Pong" | "StorageCapability" => {
            MAX_CONTROL_MESSAGE_SIZE
        }
        // Unknown variants will be rejected during deserialization, so cap them
        // at the control-message budget instead of spending the full raw limit.
        _ => MAX_CONTROL_MESSAGE_SIZE,
    })
}

#[cfg(any(test, feature = "libp2p"))]
pub(crate) fn serialized_message_uses_sequence_scoped_id(data: &[u8]) -> bool {
    matches!(
        serialized_message_variant(data),
        Some(
            "BlockRequest"
                | "BlockResponse"
                | "BodyRequest"
                | "BodyResponse"
                | "StorageCapability"
                | "Ping"
                | "Pong"
        )
    )
}

fn serialized_message_variant(data: &[u8]) -> Option<&str> {
    let data = trim_json_ws(data);
    match data.first()? {
        b'"' => quoted_json_str(data),
        b'{' => {
            let rest = trim_json_ws(data.get(1..)?);
            quoted_json_str(rest)
        }
        _ => None,
    }
}

fn quoted_json_str(data: &[u8]) -> Option<&str> {
    let rest = data.strip_prefix(b"\"")?;
    let end = rest.iter().position(|byte| *byte == b'"')?;
    std::str::from_utf8(&rest[..end]).ok()
}

fn trim_json_ws(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(data.len());
    let end = data
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &data[start..end]
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
            system_transactions: vec![],
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
            nonce: 0,
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::BlockRequest {
                start_number,
                count,
                ..
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
            commit_certificates: vec![],
            nonce: 0,
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::BlockResponse {
                blocks: decoded_blocks,
                ..
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
    fn network_message_topic_classifies_routed_variants() {
        assert_eq!(NetworkMessage::Ping.topic(), NetworkTopic::Blocks);
        assert_eq!(
            NetworkMessage::StorageCapability {
                profile: "full".to_string(),
                oldest_body_block: 3,
            }
            .topic(),
            NetworkTopic::Blocks
        );
        assert_eq!(
            NetworkMessage::NewTransaction(Box::new(test_signed_tx())).topic(),
            NetworkTopic::Transactions
        );
        assert_eq!(
            NetworkMessage::WPoaVote {
                block_hash: ShellHash::ZERO,
                block_number: 1,
                voter: Address::ZERO,
                signature: PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]),
            }
            .topic(),
            NetworkTopic::Attestation
        );
        assert_eq!(
            NetworkMessage::ProofAck {
                block_hash: ShellHash::ZERO,
                holder: Address::ZERO,
            }
            .topic(),
            NetworkTopic::Proofs
        );
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
            chain_id: 1,
            parent_hash: ShellHash::ZERO,
            block_hash: ShellHash::default(),
            block_number: 99,
            round: 0,
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
    fn deserialize_checked_rejects_out_of_range_sync_request_counts() {
        for msg in [
            NetworkMessage::BlockRequest {
                start_number: 1,
                count: 0,
                nonce: 0,
            },
            NetworkMessage::BodyRequest {
                start_number: 1,
                count: MAX_RESPONSE_BLOCKS as u64 + 1,
                nonce: 0,
            },
        ] {
            let json = serde_json::to_vec(&msg).unwrap();
            let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();
            assert!(
                matches!(err, NetworkError::Serialization(message) if message.contains("request count must be between"))
            );
        }
    }

    #[test]
    fn body_sync_nonces_default_for_legacy_messages() {
        let request: NetworkMessage =
            serde_json::from_str(r#"{"BodyRequest":{"start_number":1,"count":1}}"#).unwrap();
        assert!(matches!(
            request,
            NetworkMessage::BodyRequest { nonce: 0, .. }
        ));

        let response: NetworkMessage =
            serde_json::from_str(r#"{"BodyResponse":{"blocks":[]}}"#).unwrap();
        assert!(matches!(
            response,
            NetworkMessage::BodyResponse { nonce: 0, .. }
        ));
    }

    #[test]
    fn deserialize_checked_rejects_excess_commit_certificates() {
        let msg = NetworkMessage::BlockResponse {
            blocks: vec![],
            commit_certificates: vec![(ShellHash::default(), vec![])],
            nonce: 0,
        };
        let json = serde_json::to_vec(&msg).unwrap();

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();

        assert!(
            matches!(err, NetworkError::Serialization(message) if message.contains("certificate count exceeds block count"))
        );
    }

    #[test]
    fn deserialize_checked_rejects_unknown_storage_profile() {
        let msg = NetworkMessage::StorageCapability {
            profile: "untrusted-profile".to_string(),
            oldest_body_block: 0,
        };
        let json = serde_json::to_vec(&msg).unwrap();

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();

        assert!(
            matches!(err, NetworkError::Serialization(message) if message.contains("unknown storage capability profile"))
        );
    }

    #[test]
    fn deserialize_checked_accepts_storage_profile_alias_case_insensitively() {
        let msg = NetworkMessage::StorageCapability {
            profile: "Rolling".to_string(),
            oldest_body_block: 10,
        };
        let json = serde_json::to_vec(&msg).unwrap();

        assert!(deserialize_checked(&json, MAX_MESSAGE_SIZE).is_ok());
    }

    #[test]
    fn deserialize_checked_rejects_oversized_block_response_before_decode() {
        let msg = NetworkMessage::BlockResponse {
            blocks: (0..=MAX_RESPONSE_BLOCKS)
                .map(|n| test_block(n as u64))
                .collect(),
            commit_certificates: vec![],
            nonce: 0,
        };
        let json = serde_json::to_vec(&msg).unwrap();

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();

        assert!(
            matches!(err, NetworkError::Serialization(message) if message.contains("more than 128 blocks"))
        );
    }

    #[test]
    fn deserialize_checked_rejects_oversized_commit_certificate_array_before_decode() {
        let msg = NetworkMessage::BlockResponse {
            blocks: vec![],
            commit_certificates: (0..=MAX_RESPONSE_BLOCKS)
                .map(|_| (ShellHash::default(), vec![]))
                .collect(),
            nonce: 0,
        };
        let json = serde_json::to_vec(&msg).unwrap();

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();

        assert!(
            matches!(err, NetworkError::Serialization(message) if message.contains("more than 128 commit certificates"))
        );
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
        assert_eq!(MAX_MESSAGE_SIZE, 50 * 1024 * 1024);
    }

    #[test]
    fn deserialize_checked_rejects_oversized_transaction_gossip() {
        let mut signed = test_signed_tx();
        signed.tx.data = Bytes::from(vec![0xAA; MAX_TX_GOSSIP_SIZE + 1]);
        let msg = NetworkMessage::NewTransaction(Box::new(signed));
        let json = serde_json::to_vec(&msg).unwrap();
        assert!(json.len() < MAX_MESSAGE_SIZE);

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();
        assert!(matches!(
            err,
            NetworkError::MessageTooLarge {
                limit: MAX_TX_GOSSIP_SIZE,
                ..
            }
        ));
    }

    #[test]
    fn deserialize_checked_rejects_oversized_variant_before_full_decode() {
        let mut json = br#"{"NewTransaction":"#.to_vec();
        json.extend(std::iter::repeat_n(b' ', MAX_TX_GOSSIP_SIZE + 1));
        json.push(b'}');
        assert!(json.len() < MAX_MESSAGE_SIZE);

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();

        assert!(matches!(
            err,
            NetworkError::MessageTooLarge {
                limit: MAX_TX_GOSSIP_SIZE,
                ..
            }
        ));
    }

    #[test]
    fn deserialize_checked_prechecks_control_message_size() {
        let mut json = br#"{"BlockRequest":"#.to_vec();
        json.extend(std::iter::repeat_n(b' ', MAX_CONTROL_MESSAGE_SIZE + 1));
        json.push(b'}');
        assert!(json.len() < MAX_MESSAGE_SIZE);

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();

        assert!(matches!(
            err,
            NetworkError::MessageTooLarge {
                limit: MAX_CONTROL_MESSAGE_SIZE,
                ..
            }
        ));
    }

    #[test]
    fn deserialize_checked_prechecks_unknown_variant_size() {
        let mut json = br#"{"FutureLargeVariant":"#.to_vec();
        json.extend(std::iter::repeat_n(b' ', MAX_CONTROL_MESSAGE_SIZE + 1));
        json.push(b'}');
        assert!(json.len() < MAX_MESSAGE_SIZE);

        let err = deserialize_checked(&json, MAX_MESSAGE_SIZE).unwrap_err();

        assert!(matches!(
            err,
            NetworkError::MessageTooLarge {
                limit: MAX_CONTROL_MESSAGE_SIZE,
                ..
            }
        ));
    }

    #[test]
    fn serialized_message_variant_detects_unit_and_object_variants() {
        let ping = serde_json::to_vec(&NetworkMessage::Ping).unwrap();
        assert_eq!(serialized_message_variant(&ping), Some("Ping"));

        let request = serde_json::to_vec(&NetworkMessage::BlockRequest {
            start_number: 7,
            count: 1,
            nonce: 9,
        })
        .unwrap();
        assert_eq!(serialized_message_variant(&request), Some("BlockRequest"));

        assert_eq!(serialized_message_variant(b"not-json"), None);
    }

    #[test]
    fn serialized_message_uses_sequence_scoped_id_without_decoding_payload() {
        let ping = serde_json::to_vec(&NetworkMessage::Ping).unwrap();
        assert!(serialized_message_uses_sequence_scoped_id(&ping));

        let body_response = serde_json::to_vec(&NetworkMessage::BodyResponse {
            blocks: Vec::new(),
            nonce: 0,
        })
        .unwrap();
        assert!(serialized_message_uses_sequence_scoped_id(&body_response));

        let tx = serde_json::to_vec(&NetworkMessage::NewTransaction(Box::new(test_signed_tx())))
            .unwrap();
        assert!(!serialized_message_uses_sequence_scoped_id(&tx));
        assert!(!serialized_message_uses_sequence_scoped_id(
            b"{\"Unknown\":{}}"
        ));
    }

    #[test]
    fn serde_roundtrip_wpoa_vote() {
        let msg = NetworkMessage::WPoaVote {
            block_hash: ShellHash::default(),
            block_number: 7,
            voter: Address::from_public_key(b"voter-key", 0),
            signature: PQSignature::new(
                shell_crypto::SignatureType::Dilithium3,
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::WPoaVote {
                block_number,
                signature,
                ..
            } => {
                assert_eq!(block_number, 7);
                assert_eq!(signature.data, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn serde_roundtrip_wpoa_view_change() {
        let msg = NetworkMessage::WPoaViewChange(Box::new(ViewChangeMessage::new(
            1,
            42,
            3,
            ShellHash::ZERO,
            Address::from_public_key(b"voter-key", 0),
            vec![1, 2, 3],
        )));
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: NetworkMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            NetworkMessage::WPoaViewChange(view_change) => {
                assert_eq!(view_change.view, 3);
                assert_eq!(view_change.block_number, 42);
                assert_eq!(view_change.signature, vec![1, 2, 3]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
