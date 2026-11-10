//! Complete byte-message SHA2 certificates over the compression AIR.
//!
//! Verification binds the standard IV, exact caller bytes, FIPS 180-4 padding,
//! every chaining edge and canonical chunk order without computing native SHA.
use crate::sha2_compression::{
    compression_witness_output, prove_compression_batch, verify_compression_batch,
    CompressionInput, Sha2Algorithm, Sha2CompressionProof, MAX_SHA2_BATCH, SHA256_INITIAL_STATE,
    SHA512_INITIAL_STATE,
};
use serde::{Deserialize, Serialize};

/// A proving profile bound, sufficient for SHA2-256f's largest T input.
/// This does not alter a transaction, protocol or global proof-store limit.
pub const MAX_SHA2_MESSAGE_BYTES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sha2DigestProof {
    pub version: u8,
    pub algorithm: Sha2Algorithm,
    /// Consecutive padded-message blocks, in canonical groups of sixteen.
    pub chunks: Vec<Sha2CompressionProof>,
}

fn initial(a: Sha2Algorithm) -> [u64; 8] {
    match a {
        Sha2Algorithm::Sha256 => SHA256_INITIAL_STATE,
        Sha2Algorithm::Sha512 => SHA512_INITIAL_STATE,
    }
}

fn blocks(a: Sha2Algorithm, message: &[u8]) -> Result<Vec<[u64; 16]>, String> {
    if message.len() > MAX_SHA2_MESSAGE_BYTES {
        return Err("SHA2 message exceeds digest profile".into());
    }
    let (size, length_size) = match a {
        Sha2Algorithm::Sha256 => (64, 8),
        Sha2Algorithm::Sha512 => (128, 16),
    };
    let padded_len = (message.len() + 1 + length_size).div_ceil(size) * size;
    let mut bytes = vec![0; padded_len];
    bytes[..message.len()].copy_from_slice(message);
    bytes[message.len()] = 0x80;
    // The bounded byte-message profile fits in 64 bits; SHA512's upper length
    // word stays zero. FIPS 180-4 requires a big-endian length in bits.
    bytes[padded_len - 8..].copy_from_slice(&((message.len() as u64) * 8).to_be_bytes());
    Ok(bytes
        .chunks_exact(size)
        .map(|block| match a {
            Sha2Algorithm::Sha256 => std::array::from_fn(|i| {
                u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().expect("word")) as u64
            }),
            Sha2Algorithm::Sha512 => std::array::from_fn(|i| {
                u64::from_be_bytes(block[8 * i..8 * i + 8].try_into().expect("word"))
            }),
        })
        .collect())
}

fn output_bytes(a: Sha2Algorithm, words: [u64; 8]) -> Vec<u8> {
    match a {
        Sha2Algorithm::Sha256 => words
            .iter()
            .flat_map(|&x| (x as u32).to_be_bytes())
            .collect(),
        Sha2Algorithm::Sha512 => words.iter().flat_map(|x| x.to_be_bytes()).collect(),
    }
}

/// Prove the full digest. Native compression is used only to construct witnesses.
pub fn prove_digest(a: Sha2Algorithm, message: &[u8]) -> Result<Sha2DigestProof, String> {
    let blocks = blocks(a, message)?;
    let mut state = initial(a);
    let mut chunks = Vec::new();
    for batch in blocks.chunks(MAX_SHA2_BATCH) {
        let mut inputs = Vec::with_capacity(batch.len());
        for &block in batch {
            let input = CompressionInput {
                chaining_value: state,
                block,
            };
            state = compression_witness_output(a, &input);
            inputs.push(input);
        }
        chunks.push(prove_compression_batch(a, &inputs)?);
    }
    Ok(Sha2DigestProof {
        version: 1,
        algorithm: a,
        chunks,
    })
}

/// Return a digest only after every compression and caller-bound edge verifies.
/// No intermediate digest or certificate-supplied message is trusted.
pub fn verify_digest(
    proof: &Sha2DigestProof,
    a: Sha2Algorithm,
    expected_message: &[u8],
) -> Result<Vec<u8>, String> {
    let blocks = blocks(a, expected_message)?;
    if proof.version != 1
        || proof.algorithm != a
        || proof.chunks.len() != blocks.len().div_ceil(MAX_SHA2_BATCH)
        || proof
            .chunks
            .iter()
            .zip(blocks.chunks(MAX_SHA2_BATCH))
            .any(|(p, b)| p.inputs.len() != b.len())
    {
        return Err("invalid SHA2 digest version/algorithm/chunk layout".into());
    }
    let mut state = initial(a);
    for (chunk, batch) in proof.chunks.iter().zip(blocks.chunks(MAX_SHA2_BATCH)) {
        // The AIR authenticates these compression outputs. The following loop
        // independently binds every input to the caller's padded message and
        // preceding authenticated output, including across chunk boundaries.
        let outputs = verify_compression_batch(chunk, a, &chunk.inputs)?;
        for ((input, block), output) in chunk.inputs.iter().zip(batch).zip(outputs) {
            if input.block != *block || input.chaining_value != state {
                return Err("SHA2 digest IV/padding/message/chaining mismatch".into());
            }
            state = output;
        }
    }
    Ok(output_bytes(a, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha512};

    fn reference(a: Sha2Algorithm, m: &[u8]) -> Vec<u8> {
        match a {
            Sha2Algorithm::Sha256 => Sha256::digest(m).to_vec(),
            Sha2Algorithm::Sha512 => Sha512::digest(m).to_vec(),
        }
    }

    #[test]
    fn complete_digest_padding_boundaries_and_multiple_chunks() {
        for a in [Sha2Algorithm::Sha256, Sha2Algorithm::Sha512] {
            let boundary = if a == Sha2Algorithm::Sha256 { 56 } else { 112 };
            let size = if a == Sha2Algorithm::Sha256 { 64 } else { 128 };
            for len in [
                0,
                3,
                boundary - 1,
                boundary,
                size - 1,
                size,
                size + 1,
                MAX_SHA2_MESSAGE_BYTES,
            ] {
                let m = if len == 3 {
                    b"abc".to_vec()
                } else {
                    (0..len).map(|i| (i * 73 + 17) as u8).collect::<Vec<_>>()
                };
                let p = prove_digest(a, &m).unwrap();
                assert_eq!(verify_digest(&p, a, &m).unwrap(), reference(a, &m));
                if len == MAX_SHA2_MESSAGE_BYTES {
                    assert!(p.chunks.len() > 1);
                    let mut reordered = p.clone();
                    reordered.chunks.swap(0, 1);
                    assert!(verify_digest(&reordered, a, &m).is_err());
                    let mut missing = p.clone();
                    missing.chunks.pop();
                    assert!(verify_digest(&missing, a, &m).is_err());
                    let mut wrong_edge = p.clone();
                    let mut inputs = wrong_edge.chunks[1].inputs.clone();
                    inputs[0].chaining_value[0] ^= 1;
                    wrong_edge.chunks[1] = prove_compression_batch(a, &inputs).unwrap();
                    assert!(verify_digest(&wrong_edge, a, &m).is_err());
                }
            }
        }
        assert!(prove_digest(Sha2Algorithm::Sha256, &vec![0; MAX_SHA2_MESSAGE_BYTES + 1]).is_err());
    }

    #[test]
    fn digest_rejects_valid_compressions_with_false_routing() {
        for a in [Sha2Algorithm::Sha256, Sha2Algorithm::Sha512] {
            let m = vec![0xab; 128];
            let p = prove_digest(a, &m).unwrap();
            let mut changed = m.clone();
            changed[0] ^= 1;
            assert!(verify_digest(&p, a, &changed).is_err());
            for kind in 0..4 {
                let mut wrong = p.clone();
                let mut inputs = wrong.chunks[0].inputs.clone();
                match kind {
                    0 => inputs[0].chaining_value[0] ^= 1,
                    1 => inputs[1].chaining_value[0] ^= 1,
                    2 => {
                        let n = inputs.len() - 1;
                        inputs[n].block[15] ^= 8;
                    }
                    _ => inputs.swap(0, 1),
                }
                // These are genuine valid STARKs of different compression
                // statements, not just corrupted bytes that fail decoding.
                wrong.chunks[0] = prove_compression_batch(a, &inputs).unwrap();
                assert!(verify_digest(&wrong, a, &m).is_err());
            }
            let mut bad = p.clone();
            bad.version = 2;
            assert!(verify_digest(&bad, a, &m).is_err());
            let mut bad = p.clone();
            bad.chunks[0].proof_bytes[0] ^= 1;
            assert!(verify_digest(&bad, a, &m).is_err());
            assert!(verify_digest(
                &p,
                if a == Sha2Algorithm::Sha256 {
                    Sha2Algorithm::Sha512
                } else {
                    Sha2Algorithm::Sha256
                },
                &m
            )
            .is_err());
            let mut bytes = Vec::new();
            ciborium::into_writer(&p, &mut bytes).unwrap();
            let restored: Sha2DigestProof = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(verify_digest(&restored, a, &m).unwrap(), reference(a, &m));
        }
    }
}
