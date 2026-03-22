use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::errors::PrimitiveError;
use crate::types::{
    BasicFeesPerGas, BasicTransactionPayload, CreateTransactionPayload, Root, SigningData,
    TransactionEnvelope, TransactionPayload, TransactionPayloadSsz,
    MOCK_PROGRESSIVE_BYTE_LIST_LIMIT,
};

// ─── SHA-256 and Merkle helpers ──────────────────────────────────────────────

pub(crate) fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left.as_ref());
    h.update(right.as_ref());
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Returns the Merkle root of a virtual complete zero-subtree with `2^depth` leaves.
pub(crate) fn zero_hash(depth: usize) -> [u8; 32] {
    let mut h = [0u8; 32];
    for _ in 0..depth {
        h = sha256_pair(&h, &h);
    }
    h
}

/// Merkleizes `chunks` against a virtual tree padded to `limit` zero-chunks.
///
/// `limit` must be a power of two and >= `chunks.len()`.  An empty tree
/// (`limit == 0`) returns the all-zero chunk.
pub(crate) fn merkleize(chunks: &[[u8; 32]], limit: usize) -> [u8; 32] {
    debug_assert!(limit == 0 || limit.is_power_of_two());
    debug_assert!(chunks.len() <= limit);

    match limit {
        0 => [0u8; 32],
        1 => chunks.first().copied().unwrap_or([0u8; 32]),
        _ => {
            let half = limit >> 1;
            let left = merkleize(&chunks[..chunks.len().min(half)], half);
            let right = if chunks.len() > half {
                merkleize(&chunks[half..], half)
            } else {
                // Right sub-tree is entirely zero; depth = log2(half).
                zero_hash(half.trailing_zeros() as usize)
            };
            sha256_pair(&left, &right)
        }
    }
}

/// Packs a byte slice into 32-byte chunks, zero-padding the last chunk.
pub(crate) fn pack_bytes(bytes: &[u8]) -> Vec<[u8; 32]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let num_chunks = (bytes.len() + 31) / 32;
    let mut chunks = Vec::with_capacity(num_chunks);
    for i in 0..num_chunks {
        let mut chunk = [0u8; 32];
        let start = i * 32;
        let end = (start + 32).min(bytes.len());
        chunk[..end - start].copy_from_slice(&bytes[start..end]);
        chunks.push(chunk);
    }
    chunks
}

/// `mix_in_length`: mixes the serialized list length into the Merkle root of
/// its chunks (SSZ list hash_tree_root = mix_in_length(merkleize(chunks, limit), len)).
pub(crate) fn mix_in_length(root: [u8; 32], length: usize) -> [u8; 32] {
    let mut len_chunk = [0u8; 32];
    len_chunk[..8].copy_from_slice(&(length as u64).to_le_bytes());
    sha256_pair(&root, &len_chunk)
}

/// `mix_in_selector`: used for SSZ union hash_tree_root – mixes the discriminant
/// tag into the inner value's root.
pub(crate) fn mix_in_selector(root: [u8; 32], selector: u8) -> [u8; 32] {
    let mut sel_chunk = [0u8; 32];
    sel_chunk[0] = selector;
    sha256_pair(&root, &sel_chunk)
}

// ─── Field-level hash_tree_root helpers ─────────────────────────────────────

pub(crate) fn htr_u64(v: u64) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&v.to_le_bytes());
    chunk
}

/// hash_tree_root for a uint256 stored as 32 LE bytes (U256 / ChainId / TxValue / GasPrice).
#[inline]
pub(crate) fn htr_u256(bytes: &[u8; 32]) -> [u8; 32] {
    *bytes
}

/// hash_tree_root for ExecutionAddress (Vector<u8, 20>): one 32-byte chunk, right-zero-padded.
pub(crate) fn htr_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[..20].copy_from_slice(addr);
    chunk
}

/// hash_tree_root for BasicFeesPerGas (container with 3 GasPrice/uint256 fields).
pub(crate) fn htr_fees(fees: &BasicFeesPerGas) -> [u8; 32] {
    let f1 = htr_u256(&fees.regular.0 .0);
    let f2 = htr_u256(&fees.max_priority_fee_per_gas.0 .0);
    let f3 = htr_u256(&fees.max_witness_priority_fee.0 .0);
    // 3 fields → pad to next power of 2 = 4
    merkleize(&[f1, f2, f3, [0u8; 32]], 4)
}

/// hash_tree_root for MockProgressiveByteList (List<u8, MOCK_PROGRESSIVE_BYTE_LIST_LIMIT>).
pub(crate) fn htr_byte_list(bytes: &[u8]) -> [u8; 32] {
    // chunk_count for List<u8, 1_048_576> = 1_048_576 / 32 = 32_768 = 2^15.
    const CHUNK_LIMIT: usize = MOCK_PROGRESSIVE_BYTE_LIST_LIMIT / 32;
    let chunks = pack_bytes(bytes);
    let tree_root = merkleize(&chunks, CHUNK_LIMIT);
    mix_in_length(tree_root, bytes.len())
}

/// hash_tree_root for BasicTransactionPayload (8 fields → power-of-2 tree).
pub(crate) fn htr_basic_payload(p: &BasicTransactionPayload) -> [u8; 32] {
    let f1 = htr_u256(&p.chain_id.0 .0);
    let f2 = htr_u64(p.nonce);
    let f3 = htr_u64(p.gas_limit);
    let f4 = htr_fees(&p.fees);
    let f5 = htr_address(&p.to);
    let f6 = htr_u256(&p.value.0 .0);
    let f7 = htr_byte_list(&p.input);
    let f8 = p.access_commitment; // Root = [u8;32] is its own hash
                                  // 8 fields — already a power of 2
    merkleize(&[f1, f2, f3, f4, f5, f6, f7, f8], 8)
}

/// hash_tree_root for CreateTransactionPayload (7 fields → padded to 8).
pub(crate) fn htr_create_payload(p: &CreateTransactionPayload) -> [u8; 32] {
    let f1 = htr_u256(&p.chain_id.0 .0);
    let f2 = htr_u64(p.nonce);
    let f3 = htr_u64(p.gas_limit);
    let f4 = htr_fees(&p.fees);
    let f5 = htr_u256(&p.value.0 .0);
    let f6 = htr_byte_list(&p.initcode);
    let f7 = p.access_commitment;
    // 7 fields → next power of 2 = 8; pad with a zero chunk
    merkleize(&[f1, f2, f3, f4, f5, f6, f7, [0u8; 32]], 8)
}

// ─── CanonicalSsz trait ──────────────────────────────────────────────────────

pub trait CanonicalSsz {
    fn encode_ssz(&self) -> Result<Vec<u8>, PrimitiveError>;
    fn hash_tree_root(&self) -> Result<Root, PrimitiveError>;
}

pub fn encode<T>(value: &T) -> Result<Vec<u8>, PrimitiveError>
where
    T: CanonicalSsz + ?Sized,
{
    value.encode_ssz()
}

pub fn hash_tree_root<T>(value: &T) -> Result<Root, PrimitiveError>
where
    T: CanonicalSsz + ?Sized,
{
    value.hash_tree_root()
}

pub fn signing_root(signing_data: &SigningData) -> Result<Root, PrimitiveError> {
    hash_tree_root(signing_data)
}

// ─── CanonicalSsz implementations ───────────────────────────────────────────

impl CanonicalSsz for TransactionPayloadSsz {
    fn encode_ssz(&self) -> Result<Vec<u8>, PrimitiveError> {
        crate::codec::encode_payload(self)
    }

    fn hash_tree_root(&self) -> Result<Root, PrimitiveError> {
        let (inner_root, tag) = match self.payload() {
            TransactionPayload::Basic(p) => {
                (htr_basic_payload(p), TransactionPayloadSsz::TAG_BASIC)
            }
            TransactionPayload::Create(p) => {
                (htr_create_payload(p), TransactionPayloadSsz::TAG_CREATE)
            }
        };
        Ok(mix_in_selector(inner_root, tag))
    }
}

impl CanonicalSsz for TransactionEnvelope {
    fn encode_ssz(&self) -> Result<Vec<u8>, PrimitiveError> {
        Err(PrimitiveError::Unimplemented(
            "TransactionEnvelope SSZ encoding requires Authorization list codec (not yet closed)",
        ))
    }

    fn hash_tree_root(&self) -> Result<Root, PrimitiveError> {
        Err(PrimitiveError::Unimplemented(
            "TransactionEnvelope hash_tree_root requires Authorization list encoding (not yet closed)",
        ))
    }
}

impl CanonicalSsz for SigningData {
    /// SSZ encode: SigningData has only fixed-size fields → object_root (32) || domain_type (4).
    fn encode_ssz(&self) -> Result<Vec<u8>, PrimitiveError> {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&self.object_root);
        bytes.extend_from_slice(&self.domain_type);
        Ok(bytes)
    }

    /// hash_tree_root: merkleize([object_root, domain_type_padded_to_32], 2).
    fn hash_tree_root(&self) -> Result<Root, PrimitiveError> {
        let f1 = self.object_root;
        let f2 = {
            // domain_type = Bytes4 = [u8; 4] → Vector<u8, 4> → right-zero-padded to 32 bytes
            let mut chunk = [0u8; 32];
            chunk[..4].copy_from_slice(&self.domain_type);
            chunk
        };
        Ok(merkleize(&[f1, f2], 2))
    }
}
