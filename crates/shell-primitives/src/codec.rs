//! Wire-level encode / decode for [`TransactionPayloadSsz`].
//!
//! This is the **only** correct path for constructing or parsing
//! `TransactionPayload` wire bytes.  See `specs/data-types.md §3.1`.
//!
//! Wire format:
//! ```text
//! [tag_byte (u8)] || SSZ_encode(inner_payload)
//! ```
//! The tag byte is the frozen discriminant:
//! - `0x00` → `BasicTransactionPayload`
//! - `0x01` → `CreateTransactionPayload`

use alloc::vec::Vec;

use crate::errors::{MalformedSszError, PrimitiveError};
use crate::types::{
    Authorization, BasicFeesPerGas, BasicTransactionPayload, ChainId, CreateTransactionPayload,
    ExecutionAddress, GasPrice, MockProgressiveByteList, Root, TransactionEnvelope,
    TransactionPayload, TransactionPayloadSsz, TxValue, U256,
};

// ─── Fixed serialized sizes (inner payload, without the leading tag byte) ───

/// Fixed-part byte size of `BasicTransactionPayload`:
/// chain_id(32) + nonce(8) + gas_limit(8) + fees(96) + to(20) + value(32)
///   + input_offset(4) + access_commitment(32) = 232
pub const BASIC_FIXED_SIZE: usize = 32 + 8 + 8 + 96 + 20 + 32 + 4 + 32;

/// Fixed-part byte size of `CreateTransactionPayload`:
/// chain_id(32) + nonce(8) + gas_limit(8) + fees(96) + value(32)
///   + initcode_offset(4) + access_commitment(32) = 212
pub const CREATE_FIXED_SIZE: usize = 32 + 8 + 8 + 96 + 32 + 4 + 32;

/// Fixed-part byte size of `Authorization`:
/// scheme_id(1) + payload_root(32) + signature_offset(4) = 37
pub const AUTHORIZATION_FIXED_SIZE: usize = 1 + 32 + 4;

/// Fixed-part byte size of `TransactionEnvelope`:
/// payload_offset(4) + authorizations_offset(4) = 8
pub const ENVELOPE_FIXED_SIZE: usize = 4 + 4;

// ─── Encode ──────────────────────────────────────────────────────────────────

/// Encodes a [`TransactionPayloadSsz`] to canonical wire bytes.
///
/// Returns `[tag_byte] || SSZ_encode(inner_payload)`.
pub fn encode_payload(payload: &TransactionPayloadSsz) -> Result<Vec<u8>, PrimitiveError> {
    let tag = payload.protocol_tag();
    let mut out = Vec::new();
    out.push(tag);
    match payload.payload() {
        TransactionPayload::Basic(p) => encode_basic(p, &mut out),
        TransactionPayload::Create(p) => encode_create(p, &mut out),
    }
    Ok(out)
}

fn push_u256(bytes: &[u8; 32], out: &mut Vec<u8>) {
    out.extend_from_slice(bytes);
}

fn push_u64(v: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_address(addr: &ExecutionAddress, out: &mut Vec<u8>) {
    out.extend_from_slice(addr);
}

fn push_fees(fees: &BasicFeesPerGas, out: &mut Vec<u8>) {
    push_u256(&fees.regular.0 .0, out);
    push_u256(&fees.max_priority_fee_per_gas.0 .0, out);
    push_u256(&fees.max_witness_priority_fee.0 .0, out);
}

fn encode_basic(p: &BasicTransactionPayload, out: &mut Vec<u8>) {
    push_u256(&p.chain_id.0 .0, out); // 32  offset 0
    push_u64(p.nonce, out); // 8   offset 32
    push_u64(p.gas_limit, out); // 8   offset 40
    push_fees(&p.fees, out); // 96  offset 48
    push_address(&p.to, out); // 20  offset 144
    push_u256(&p.value.0 .0, out); // 32  offset 164
    out.extend_from_slice(&(BASIC_FIXED_SIZE as u32).to_le_bytes()); // 4 offset 196
    out.extend_from_slice(&p.access_commitment); // 32  offset 200
    out.extend_from_slice(&p.input); // variable
}

fn encode_create(p: &CreateTransactionPayload, out: &mut Vec<u8>) {
    push_u256(&p.chain_id.0 .0, out); // 32  offset 0
    push_u64(p.nonce, out); // 8   offset 32
    push_u64(p.gas_limit, out); // 8   offset 40
    push_fees(&p.fees, out); // 96  offset 48
    push_u256(&p.value.0 .0, out); // 32  offset 144
    out.extend_from_slice(&(CREATE_FIXED_SIZE as u32).to_le_bytes()); // 4 offset 176
    out.extend_from_slice(&p.access_commitment); // 32  offset 180
    out.extend_from_slice(&p.initcode); // variable
}

// ─── Decode ──────────────────────────────────────────────────────────────────

/// Decodes a [`TransactionPayloadSsz`] from canonical wire bytes.
///
/// - Rejects unknown tags as [`PrimitiveError::UnsupportedPayloadVariant`].
/// - Rejects structurally invalid bytes as [`PrimitiveError::MalformedSsz`].
pub fn decode_payload(bytes: &[u8]) -> Result<TransactionPayloadSsz, PrimitiveError> {
    if bytes.is_empty() {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "TransactionPayload wire bytes must not be empty",
        }));
    }
    let tag = bytes[0];
    TransactionPayloadSsz::ensure_supported_tag(tag)
        .map_err(PrimitiveError::UnsupportedPayloadVariant)?;
    let inner = &bytes[1..];
    match tag {
        TransactionPayloadSsz::TAG_BASIC => {
            decode_basic(inner).map(|p| TransactionPayloadSsz::new(TransactionPayload::Basic(p)))
        }
        TransactionPayloadSsz::TAG_CREATE => {
            decode_create(inner).map(|p| TransactionPayloadSsz::new(TransactionPayload::Create(p)))
        }
        _ => unreachable!("tag already validated above"),
    }
}

/// Encodes an [`Authorization`] to canonical SSZ bytes.
pub fn encode_authorization(authorization: &Authorization) -> Result<Vec<u8>, PrimitiveError> {
    let mut out = Vec::with_capacity(AUTHORIZATION_FIXED_SIZE + authorization.signature.len());
    out.push(authorization.scheme_id);
    out.extend_from_slice(&authorization.payload_root);
    push_u32(AUTHORIZATION_FIXED_SIZE as u32, &mut out);
    out.extend_from_slice(&authorization.signature);
    Ok(out)
}

/// Decodes an [`Authorization`] from canonical SSZ bytes.
pub fn decode_authorization(bytes: &[u8]) -> Result<Authorization, PrimitiveError> {
    if bytes.len() < AUTHORIZATION_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "Authorization too short for fixed fields",
        }));
    }

    let scheme_id = bytes[0];
    let payload_root = read_bytes32(bytes, 1)?;
    let signature_offset = read_u32(bytes, 33)? as usize;

    if signature_offset != AUTHORIZATION_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "Authorization: signature offset must equal the fixed-part size",
        }));
    }

    Ok(Authorization {
        scheme_id,
        payload_root,
        signature: bytes[AUTHORIZATION_FIXED_SIZE..].to_vec(),
    })
}

fn encode_authorization_list(authorizations: &[Authorization]) -> Result<Vec<u8>, PrimitiveError> {
    let fixed_size = authorizations
        .len()
        .checked_mul(4)
        .ok_or(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "Authorization list offset table overflowed usize",
        }))?;
    let mut out = Vec::new();
    let mut variable_parts = Vec::with_capacity(authorizations.len());
    let mut next_offset = fixed_size;

    for authorization in authorizations {
        let encoded = encode_authorization(authorization)?;
        let offset = u32::try_from(next_offset).map_err(|_| {
            PrimitiveError::MalformedSsz(MalformedSszError {
                context: "Authorization list offset exceeds u32::MAX",
            })
        })?;
        push_u32(offset, &mut out);
        next_offset =
            next_offset
                .checked_add(encoded.len())
                .ok_or(PrimitiveError::MalformedSsz(MalformedSszError {
                    context: "Authorization list byte length overflowed usize",
                }))?;
        variable_parts.push(encoded);
    }

    for encoded in variable_parts {
        out.extend_from_slice(&encoded);
    }

    Ok(out)
}

fn decode_authorization_list(bytes: &[u8]) -> Result<Vec<Authorization>, PrimitiveError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let first_offset = read_u32(bytes, 0)? as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "Authorization list first offset must equal the offset-table size",
        }));
    }
    if first_offset > bytes.len() {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "Authorization list offset table extends past the available bytes",
        }));
    }

    let count = first_offset / 4;
    let mut offsets = Vec::with_capacity(count);
    for index in 0..count {
        let offset = read_u32(bytes, index * 4)? as usize;
        if offset < first_offset || offset > bytes.len() {
            return Err(PrimitiveError::MalformedSsz(MalformedSszError {
                context: "Authorization list element offset points outside the variable section",
            }));
        }
        offsets.push(offset);
    }

    let mut authorizations = Vec::with_capacity(count);
    for index in 0..count {
        let start = offsets[index];
        let end = offsets.get(index + 1).copied().unwrap_or(bytes.len());
        if end < start {
            return Err(PrimitiveError::MalformedSsz(MalformedSszError {
                context: "Authorization list element offsets must be monotonic",
            }));
        }
        authorizations.push(decode_authorization(&bytes[start..end])?);
    }

    Ok(authorizations)
}

/// Encodes a [`TransactionEnvelope`] to canonical SSZ bytes.
pub fn encode_envelope(envelope: &TransactionEnvelope) -> Result<Vec<u8>, PrimitiveError> {
    let payload_bytes = encode_payload(&envelope.payload)?;
    let authorizations_bytes = encode_authorization_list(&envelope.authorizations)?;
    let authorizations_offset = ENVELOPE_FIXED_SIZE.checked_add(payload_bytes.len()).ok_or(
        PrimitiveError::MalformedSsz(MalformedSszError {
            context: "TransactionEnvelope variable section overflowed usize",
        }),
    )?;

    let mut out =
        Vec::with_capacity(ENVELOPE_FIXED_SIZE + payload_bytes.len() + authorizations_bytes.len());
    push_u32(ENVELOPE_FIXED_SIZE as u32, &mut out);
    push_u32(
        u32::try_from(authorizations_offset).map_err(|_| {
            PrimitiveError::MalformedSsz(MalformedSszError {
                context: "TransactionEnvelope authorizations offset exceeds u32::MAX",
            })
        })?,
        &mut out,
    );
    out.extend_from_slice(&payload_bytes);
    out.extend_from_slice(&authorizations_bytes);
    Ok(out)
}

/// Decodes a [`TransactionEnvelope`] from canonical SSZ bytes.
pub fn decode_envelope(bytes: &[u8]) -> Result<TransactionEnvelope, PrimitiveError> {
    if bytes.len() < ENVELOPE_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "TransactionEnvelope too short for fixed fields",
        }));
    }

    let payload_offset = read_u32(bytes, 0)? as usize;
    let authorizations_offset = read_u32(bytes, 4)? as usize;

    if payload_offset != ENVELOPE_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "TransactionEnvelope: payload offset must equal the fixed-part size",
        }));
    }
    if authorizations_offset < payload_offset || authorizations_offset > bytes.len() {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context:
                "TransactionEnvelope: authorizations offset must point into the variable section",
        }));
    }

    Ok(TransactionEnvelope {
        payload: decode_payload(&bytes[payload_offset..authorizations_offset])?,
        authorizations: decode_authorization_list(&bytes[authorizations_offset..])?,
    })
}

// ─── Low-level read helpers ──────────────────────────────────────────────────

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PrimitiveError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "truncated u64 field",
        }))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PrimitiveError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "truncated u32 offset field",
        }))
}

fn read_bytes32(bytes: &[u8], offset: usize) -> Result<[u8; 32], PrimitiveError> {
    let slice = bytes
        .get(offset..offset + 32)
        .ok_or(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "truncated 32-byte field",
        }))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn read_address(bytes: &[u8], offset: usize) -> Result<ExecutionAddress, PrimitiveError> {
    let slice = bytes
        .get(offset..offset + 20)
        .ok_or(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "truncated ExecutionAddress field",
        }))?;
    let mut arr = [0u8; 20];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn read_fees(bytes: &[u8], offset: usize) -> Result<BasicFeesPerGas, PrimitiveError> {
    Ok(BasicFeesPerGas {
        regular: GasPrice(U256(read_bytes32(bytes, offset)?)),
        max_priority_fee_per_gas: GasPrice(U256(read_bytes32(bytes, offset + 32)?)),
        max_witness_priority_fee: GasPrice(U256(read_bytes32(bytes, offset + 64)?)),
    })
}

// ─── Payload decoders ────────────────────────────────────────────────────────

fn decode_basic(bytes: &[u8]) -> Result<BasicTransactionPayload, PrimitiveError> {
    if bytes.len() < BASIC_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "BasicTransactionPayload too short for fixed fields",
        }));
    }
    let chain_id = ChainId(U256(read_bytes32(bytes, 0)?)); // 0..32
    let nonce = read_u64(bytes, 32)?; // 32..40
    let gas_limit = read_u64(bytes, 40)?; // 40..48
    let fees = read_fees(bytes, 48)?; // 48..144
    let to: ExecutionAddress = read_address(bytes, 144)?; // 144..164
    let value = TxValue(U256(read_bytes32(bytes, 164)?)); // 164..196
    let input_offset = read_u32(bytes, 196)? as usize; // 196..200
    let access_commitment: Root = read_bytes32(bytes, 200)?; // 200..232

    if input_offset != BASIC_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "BasicTransactionPayload: input offset must equal the fixed-part size",
        }));
    }
    let input: MockProgressiveByteList = bytes[BASIC_FIXED_SIZE..].to_vec();

    Ok(BasicTransactionPayload {
        chain_id,
        nonce,
        gas_limit,
        fees,
        to,
        value,
        input,
        access_commitment,
    })
}

fn decode_create(bytes: &[u8]) -> Result<CreateTransactionPayload, PrimitiveError> {
    if bytes.len() < CREATE_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "CreateTransactionPayload too short for fixed fields",
        }));
    }
    let chain_id = ChainId(U256(read_bytes32(bytes, 0)?)); // 0..32
    let nonce = read_u64(bytes, 32)?; // 32..40
    let gas_limit = read_u64(bytes, 40)?; // 40..48
    let fees = read_fees(bytes, 48)?; // 48..144
    let value = TxValue(U256(read_bytes32(bytes, 144)?)); // 144..176
    let initcode_offset = read_u32(bytes, 176)? as usize; // 176..180
    let access_commitment: Root = read_bytes32(bytes, 180)?; // 180..212

    if initcode_offset != CREATE_FIXED_SIZE {
        return Err(PrimitiveError::MalformedSsz(MalformedSszError {
            context: "CreateTransactionPayload: initcode offset must equal the fixed-part size",
        }));
    }
    let initcode: MockProgressiveByteList = bytes[CREATE_FIXED_SIZE..].to_vec();

    Ok(CreateTransactionPayload {
        chain_id,
        nonce,
        gas_limit,
        fees,
        value,
        initcode,
        access_commitment,
    })
}
