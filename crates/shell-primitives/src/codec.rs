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
    BasicFeesPerGas, BasicTransactionPayload, ChainId, CreateTransactionPayload, ExecutionAddress,
    GasPrice, MockProgressiveByteList, Root, TransactionPayload, TransactionPayloadSsz, TxValue,
    U256,
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
