//! Complete SHA2-256f WOTS+ and four-level XMSS layer certificates.
//!
//! F hashes share one authenticated seed-prefix state and use canonical batches
//! of at most sixteen suffix compressions in version one, or sixty-four in the
//! explicit version-two profile. The verifier derives every chain
//! step from independently supplied message/checksum digits. This proves one
//! XMSS layer; a full signature must also bind FORS and all17 layer transitions.
use crate::{
    sha2_compression::{
        prove_compression_batch, verify_compression_batch, verify_wide_sha256_batch,
        CompressionInput, Sha2Algorithm, Sha2CompressionProof, MAX_SHA2_BATCH,
        MAX_WIDE_SHA256_BATCH, SHA256_INITIAL_STATE,
    },
    slh_sha2::{prove_slh_sha2, verify_slh_sha2, SlhSha2Address, SlhSha2Proof, SlhSha2Request},
};
use serde::{Deserialize, Serialize};

pub const SLH_XMSS_SIGNATURE_BYTES: usize = (67 + 4) * 32;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhXmssInputs {
    pub public_seed: [u8; 32],
    pub message: [u8; 32],
    pub layer: u8,
    pub tree: u64,
    pub leaf: u32,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhXmssProof {
    pub version: u8,
    pub inputs: SlhXmssInputs,
    pub prefix: Sha2CompressionProof,
    /// Ascending hash-step waves and chain indices; groups<=16 (v1) or64 (v2).
    pub chains: Vec<Sha2CompressionProof>,
    pub wots_public_key: SlhSha2Proof,
    pub authentication: Vec<SlhSha2Proof>,
}

fn validate(input: &SlhXmssInputs) -> Result<(), String> {
    if input.signature.len() != SLH_XMSS_SIGNATURE_BYTES || input.layer >= 17 || input.leaf >= 16 {
        return Err("wrong SHA2-256f XMSS signature/layer/leaf profile".into());
    }
    Ok(())
}
fn digits(message: &[u8; 32]) -> [u8; 67] {
    let mut result = [0; 67];
    let mut checksum = 0u16;
    for (i, &byte) in message.iter().enumerate() {
        result[2 * i] = byte >> 4;
        result[2 * i + 1] = byte & 15;
        checksum += 30 - u16::from(byte >> 4) - u16::from(byte & 15);
    }
    // FIPS205 len2=3: checksum<<4, two big-endian bytes, first3 nibbles.
    result[64] = (checksum >> 8) as u8;
    result[65] = ((checksum >> 4) & 15) as u8;
    result[66] = (checksum & 15) as u8;
    result
}
fn batches(message: &[u8; 32], max: usize) -> usize {
    let digits = digits(message);
    (0..15)
        .map(|step| digits.iter().filter(|&&x| x <= step).count().div_ceil(max))
        .sum()
}
fn words(bytes: &[u8; 64]) -> [u64; 16] {
    std::array::from_fn(|i| {
        u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("word")) as u64
    })
}
fn prefix(seed: &[u8; 32]) -> CompressionInput {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(seed);
    CompressionInput {
        chaining_value: SHA256_INITIAL_STATE,
        block: words(&bytes),
    }
}
fn suffix(
    input: &SlhXmssInputs,
    cv: [u64; 8],
    chain: usize,
    step: u8,
    node: &[u8; 32],
) -> Result<CompressionInput, String> {
    let address = SlhSha2Address {
        layer: input.layer,
        tree: input.tree,
        kind: 0,
        key_pair: input.leaf,
        chain_or_height: chain as u32,
        hash_or_index: u32::from(step),
    }
    .compressed()?;
    let mut bytes = [0; 64];
    bytes[..22].copy_from_slice(&address);
    bytes[22..54].copy_from_slice(node);
    bytes[54] = 0x80;
    bytes[56..].copy_from_slice(&(118u64 * 8).to_be_bytes());
    Ok(CompressionInput {
        chaining_value: cv,
        block: words(&bytes),
    })
}
fn output(words: [u64; 8]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (i, &word) in words.iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&(word as u32).to_be_bytes());
    }
    bytes
}
fn chains(
    input: &SlhXmssInputs,
    cv: [u64; 8],
    max: usize,
    mut compress: impl FnMut(&[CompressionInput]) -> Result<Vec<[u64; 8]>, String>,
) -> Result<Vec<[u8; 32]>, String> {
    let digits = digits(&input.message);
    let mut nodes = input.signature[..67 * 32]
        .chunks_exact(32)
        .map(|x| x.try_into().expect("node"))
        .collect::<Vec<[u8; 32]>>();
    for step in 0..15 {
        let active = (0..67).filter(|&i| digits[i] <= step).collect::<Vec<_>>();
        for group in active.chunks(max) {
            let inputs = group
                .iter()
                .map(|&i| suffix(input, cv, i, step, &nodes[i]))
                .collect::<Result<Vec<_>, _>>()?;
            let values = compress(&inputs)?;
            if values.len() != group.len() {
                return Err("wrong WOTS compression result count".into());
            }
            for (&i, value) in group.iter().zip(values) {
                nodes[i] = output(value);
            }
        }
    }
    Ok(nodes)
}
fn finish(
    input: &SlhXmssInputs,
    nodes: Vec<[u8; 32]>,
    mut hash: impl FnMut(usize, &SlhSha2Request) -> Result<Vec<u8>, String>,
) -> Result<[u8; 32], String> {
    let address = SlhSha2Address {
        layer: input.layer,
        tree: input.tree,
        kind: 1,
        key_pair: input.leaf,
        chain_or_height: 0,
        hash_or_index: 0,
    };
    let mut current: [u8; 32] = hash(
        0,
        &SlhSha2Request::WotsPublicKey {
            public_seed: input.public_seed,
            address,
            nodes,
        },
    )?
    .try_into()
    .map_err(|_| "wrong WOTS public key hash size")?;
    for level in 0..4 {
        let sibling = input.signature[(67 + level) * 32..(68 + level) * 32]
            .try_into()
            .expect("validated XMSS auth");
        let (left, right) = if (input.leaf >> level) & 1 == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        let address = SlhSha2Address {
            layer: input.layer,
            tree: input.tree,
            kind: 2,
            key_pair: 0,
            chain_or_height: (level + 1) as u32,
            hash_or_index: input.leaf >> (level + 1),
        };
        current = hash(
            level + 1,
            &SlhSha2Request::H {
                public_seed: input.public_seed,
                address,
                left,
                right,
            },
        )?
        .try_into()
        .map_err(|_| "wrong XMSS authentication hash size")?;
    }
    Ok(current)
}

pub fn prove_xmss(input: &SlhXmssInputs) -> Result<SlhXmssProof, String> {
    prove_xmss_using(
        input,
        |_, inputs| prove_compression_batch(Sha2Algorithm::Sha256, inputs),
        |_, request| prove_slh_sha2(request),
    )
}
/// Ordinal0 is the shared seed prefix; remaining compression ordinals are the
/// canonical F batches. Hash ordinals0..4 are WOTS T and four XMSS H requests.
/// Every returned checkpoint is verified before any output is consumed.
pub fn prove_xmss_using(
    input: &SlhXmssInputs,
    compression: impl FnMut(usize, &[CompressionInput]) -> Result<Sha2CompressionProof, String>,
    hash: impl FnMut(usize, &SlhSha2Request) -> Result<SlhSha2Proof, String>,
) -> Result<SlhXmssProof, String> {
    prove_xmss_profile_using(false, input, compression, hash)
}
pub(crate) fn prove_xmss_profile_using(
    wide: bool,
    input: &SlhXmssInputs,
    mut compression: impl FnMut(usize, &[CompressionInput]) -> Result<Sha2CompressionProof, String>,
    mut hash: impl FnMut(usize, &SlhSha2Request) -> Result<SlhSha2Proof, String>,
) -> Result<SlhXmssProof, String> {
    let max = if wide {
        MAX_WIDE_SHA256_BATCH
    } else {
        MAX_SHA2_BATCH
    };
    validate(input)?;
    let expected = [prefix(&input.public_seed)];
    let prefix = compression(0, &expected)?;
    let cv = verify_compression_batch(&prefix, Sha2Algorithm::Sha256, &expected)?[0];
    let mut proofs = Vec::with_capacity(batches(&input.message, max));
    let nodes = chains(input, cv, max, |inputs| {
        let proof = compression(proofs.len() + 1, inputs)?;
        let values = verify_chain(wide, &proof, inputs)?;
        proofs.push(proof);
        Ok(values)
    })?;
    let mut hashes = Vec::with_capacity(5);
    finish(input, nodes, |at, request| {
        let proof = hash(at, request)?;
        let value = verify_slh_sha2(&proof, request)?;
        hashes.push(proof);
        Ok(value)
    })?;
    let wots_public_key = hashes.remove(0);
    Ok(SlhXmssProof {
        version: if wide { 2 } else { 1 },
        inputs: input.clone(),
        prefix,
        chains: proofs,
        wots_public_key,
        authentication: hashes,
    })
}
/// Return one complete XMSS layer root. This does not bind all17 layers or
/// independently authorize a Native signature/canonical source.
pub fn verify_xmss(proof: &SlhXmssProof, expected: &SlhXmssInputs) -> Result<[u8; 32], String> {
    verify_xmss_profile(false, proof, expected)
}
fn verify_chain(
    wide: bool,
    proof: &Sha2CompressionProof,
    inputs: &[CompressionInput],
) -> Result<Vec<[u64; 8]>, String> {
    if wide {
        let full = crate::compact_canonical::witness::materialize_wide(proof)?;
        verify_wide_sha256_batch(&full, inputs)
    } else {
        verify_compression_batch(proof, Sha2Algorithm::Sha256, inputs)
    }
}
pub(crate) fn verify_xmss_profile(
    wide: bool,
    proof: &SlhXmssProof,
    expected: &SlhXmssInputs,
) -> Result<[u8; 32], String> {
    let max = if wide {
        MAX_WIDE_SHA256_BATCH
    } else {
        MAX_SHA2_BATCH
    };
    validate(expected)?;
    if proof.version != if wide { 2 } else { 1 }
        || proof.inputs != *expected
        || proof.chains.len() != batches(&expected.message, max)
        || proof.authentication.len() != 4
    {
        return Err("invalid XMSS version/inputs/canonical batch/authentication count".into());
    }
    let cv = verify_compression_batch(
        &proof.prefix,
        Sha2Algorithm::Sha256,
        &[prefix(&expected.public_seed)],
    )?[0];
    let mut at = 0;
    let nodes = chains(expected, cv, max, |inputs| {
        let values = verify_chain(wide, &proof.chains[at], inputs)?;
        at += 1;
        Ok(values)
    })?;
    if at != proof.chains.len() {
        return Err("unused WOTS batch certificates".into());
    }
    finish(expected, nodes, |at, request| {
        verify_slh_sha2(
            if at == 0 {
                &proof.wots_public_key
            } else {
                &proof.authentication[at - 1]
            },
            request,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn input() -> SlhXmssInputs {
        SlhXmssInputs {
            public_seed: [0xab; 32],
            message: [0; 32],
            layer: 16,
            tree: u64::MAX,
            leaf: 15,
            signature: vec![0; 2272],
        }
    }
    #[test]
    fn shared_prefix_suffix_is_complete_fips205_f() {
        let input = input();
        let pref = prefix(&input.public_seed);
        let proof =
            prove_compression_batch(Sha2Algorithm::Sha256, std::slice::from_ref(&pref)).unwrap();
        let cv = verify_compression_batch(&proof, Sha2Algorithm::Sha256, &[pref]).unwrap()[0];
        let mut expected = Vec::new();
        let mut inputs = Vec::new();
        for (chain, step, node) in [(0, 0, [0; 32]), (66, 14, [255; 32])] {
            inputs.push(suffix(&input, cv, chain, step, &node).unwrap());
            let address = SlhSha2Address {
                layer: 16,
                tree: u64::MAX,
                kind: 0,
                key_pair: 15,
                chain_or_height: chain as u32,
                hash_or_index: u32::from(step),
            }
            .compressed()
            .unwrap();
            let mut bytes = input.public_seed.to_vec();
            bytes.extend_from_slice(&[0; 32]);
            bytes.extend_from_slice(&address);
            bytes.extend_from_slice(&node);
            expected.push(Sha256::digest(bytes).to_vec());
        }
        let proof = prove_compression_batch(Sha2Algorithm::Sha256, &inputs).unwrap();
        let values = verify_compression_batch(&proof, Sha2Algorithm::Sha256, &inputs).unwrap();
        assert_eq!(
            values
                .into_iter()
                .map(|x| output(x).to_vec())
                .collect::<Vec<_>>(),
            expected
        );
        let mut wrong = inputs.clone();
        wrong[0].block[15] ^= 8;
        assert!(verify_compression_batch(&proof, Sha2Algorithm::Sha256, &wrong).is_err());
    }
    #[test]
    fn wots_digits_checksum_and_wave_bounds() {
        for message in [[0; 32], [255; 32], [0x12; 32], [0x8f; 32]] {
            let got = digits(&message);
            let hex = message
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>();
            let mut expected = hex
                .chars()
                .map(|x| x.to_digit(16).unwrap() as u8)
                .collect::<Vec<_>>();
            let checksum = expected.iter().map(|&x| 15 - u16::from(x)).sum::<u16>();
            expected.extend(
                format!("{checksum:03x}")
                    .chars()
                    .map(|x| x.to_digit(16).unwrap() as u8),
            );
            assert_eq!(got.as_slice(), expected);
            assert!(batches(&message, MAX_SHA2_BATCH) <= 75);
            assert!(batches(&message, MAX_WIDE_SHA256_BATCH) <= 30);
            assert!(batches(&message, MAX_WIDE_SHA256_BATCH) <= batches(&message, MAX_SHA2_BATCH));
            let calls = got.iter().map(|&x| usize::from(15 - x)).sum::<usize>();
            assert!((45..=990).contains(&calls));
        }
        assert_eq!(
            digits(&[0; 32])
                .iter()
                .map(|&x| usize::from(15 - x))
                .sum::<usize>(),
            990
        );
    }
    #[test]
    fn xmss_profile_guards_precede_proving() {
        let mut bad = input();
        bad.leaf = 16;
        assert!(prove_xmss(&bad).unwrap_err().contains("profile"));
        bad.leaf = 0;
        bad.layer = 17;
        assert!(prove_xmss(&bad).is_err());
        bad.layer = 0;
        bad.signature.pop();
        assert!(prove_xmss(&bad).is_err());
    }
}
