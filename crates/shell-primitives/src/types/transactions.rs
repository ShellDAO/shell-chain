use crate::errors::{PrimitiveError, UnsupportedPayloadVariant};
use crate::ssz;
use crate::traits::{ProtocolObject, TransactionMetadata};
use crate::types::{
    BasicFeesPerGas, Bytes4, ChainId, ExecutionAddress, MockProgressiveByteList,
    MockProgressiveList, Root, TxValue,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BasicTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub to: ExecutionAddress,
    pub value: TxValue,
    pub input: MockProgressiveByteList,
    pub access_commitment: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub value: TxValue,
    pub initcode: MockProgressiveByteList,
    pub access_commitment: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authorization {
    pub scheme_id: u8,
    pub payload_root: Root,
    pub signature: MockProgressiveByteList,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SigningData {
    pub object_root: Root,
    pub domain_type: Bytes4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionPayload {
    Basic(BasicTransactionPayload),
    Create(CreateTransactionPayload),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionPayloadSsz(TransactionPayload);

impl TransactionPayloadSsz {
    pub const TAG_BASIC: u8 = 0;
    pub const TAG_CREATE: u8 = 1;

    pub fn new(payload: TransactionPayload) -> Self {
        Self(payload)
    }

    pub fn payload(&self) -> &TransactionPayload {
        &self.0
    }

    pub fn into_payload(self) -> TransactionPayload {
        self.0
    }

    pub fn protocol_tag(&self) -> u8 {
        match &self.0 {
            TransactionPayload::Basic(_) => Self::TAG_BASIC,
            TransactionPayload::Create(_) => Self::TAG_CREATE,
        }
    }

    pub fn ensure_supported_tag(tag: u8) -> Result<(), UnsupportedPayloadVariant> {
        match tag {
            Self::TAG_BASIC | Self::TAG_CREATE => Ok(()),
            _ => Err(UnsupportedPayloadVariant { tag }),
        }
    }

    pub fn hash_tree_root(&self) -> Result<Root, PrimitiveError> {
        ssz::hash_tree_root(self)
    }

    /// Encodes to canonical wire bytes: `[tag_byte] || SSZ_encode(inner_payload)`.
    ///
    /// This is the only correct encoding path; see `specs/data-types.md §3.1`.
    pub fn to_wire_bytes(&self) -> Result<crate::types::MockProgressiveByteList, PrimitiveError> {
        crate::codec::encode_payload(self)
    }

    /// Decodes from canonical wire bytes.
    ///
    /// Rejects unknown tags as [`PrimitiveError::UnsupportedPayloadVariant`] and
    /// structurally invalid bytes as [`PrimitiveError::MalformedSsz`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        crate::codec::decode_payload(bytes)
    }
}

impl Default for TransactionPayloadSsz {
    fn default() -> Self {
        Self::new(TransactionPayload::Basic(BasicTransactionPayload::default()))
    }
}

impl From<TransactionPayload> for TransactionPayloadSsz {
    fn from(value: TransactionPayload) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionEnvelope {
    pub payload: TransactionPayloadSsz,
    pub authorizations: MockProgressiveList<Authorization>,
}

impl TransactionEnvelope {
    pub fn payload_root(&self) -> Result<Root, PrimitiveError> {
        self.payload.hash_tree_root()
    }

    /// Encodes to canonical SSZ bytes with the payload delegated through
    /// `TransactionPayloadSsz` and the authorization list encoded as the sole
    /// closed list path for this repository state.
    pub fn to_wire_bytes(&self) -> Result<crate::types::MockProgressiveByteList, PrimitiveError> {
        crate::codec::encode_envelope(self)
    }

    /// Decodes from canonical SSZ bytes using the single shared envelope path.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        crate::codec::decode_envelope(bytes)
    }
}

impl ProtocolObject for TransactionPayloadSsz {
    fn canonical_root(&self) -> Result<Root, PrimitiveError> {
        self.hash_tree_root()
    }
}

impl ProtocolObject for TransactionEnvelope {
    fn canonical_root(&self) -> Result<Root, PrimitiveError> {
        ssz::hash_tree_root(self)
    }
}

impl ProtocolObject for SigningData {
    fn canonical_root(&self) -> Result<Root, PrimitiveError> {
        ssz::hash_tree_root(self)
    }
}

impl TransactionMetadata for BasicTransactionPayload {
    fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
}

impl TransactionMetadata for CreateTransactionPayload {
    fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
}
