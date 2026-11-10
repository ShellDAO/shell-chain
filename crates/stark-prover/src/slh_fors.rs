//! Complete fixed-parameter SHA2-256f FORS verification over real hash AIRs.
//!
//! This establishes the FORS public key, not the WOTS+/hypertree relation to the
//! SLH public root. Callers supply the exact original public input envelope.
use crate::slh_sha2::{
    prove_slh_sha2, verify_slh_sha2, SlhSha2Address, SlhSha2Proof, SlhSha2Request,
};
use serde::{Deserialize, Serialize};

pub const SLH_SHA2_256F_SIGNATURE_BYTES: usize = 49_856;
pub const SLH_FORS_HASHES: usize = 1 + 35 * 10 + 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhForsInputs {
    pub public_seed: [u8; 32],
    pub public_root: [u8; 32],
    pub message: [u8; 32],
    /// Exact full signature envelope. The hypertree tail is bound by equality
    /// to the expected input, but its mathematical relation is not proved here.
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhForsProof {
    pub version: u8,
    pub inputs: SlhForsInputs,
    pub hashes: Vec<SlhSha2Proof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhForsOutput {
    pub message_digest: Vec<u8>,
    pub tree: u64,
    pub leaf: u32,
    pub indices: Vec<u32>,
    pub fors_public_key: [u8; 32],
}

fn validate(input: &SlhForsInputs) -> Result<(), String> {
    if input.signature.len() != SLH_SHA2_256F_SIGNATURE_BYTES {
        return Err("wrong SHA2-256f signature envelope length".into());
    }
    Ok(())
}

fn indices(digest: &[u8]) -> Result<([u32; 35], u64, u32), String> {
    if digest.len() != 49 {
        return Err("wrong SHA2-256f H_msg length".into());
    }
    // FIPS 205 base_2b consumes the first 315 bits MSB first. The unused low
    // five bits of byte39 are not indices; tree starts at byte40, leaf at48.
    let indices = std::array::from_fn(|i| {
        (0..9).fold(0u32, |v, bit| {
            let at = i * 9 + bit;
            (v << 1) | u32::from((digest[at / 8] >> (7 - at % 8)) & 1)
        })
    });
    Ok((
        indices,
        u64::from_be_bytes(digest[40..48].try_into().expect("eight bytes")),
        u32::from(digest[48] & 15),
    ))
}

fn node(bytes: Vec<u8>) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "wrong FORS hash output length".into())
}

fn route(
    input: &SlhForsInputs,
    mut hash: impl FnMut(&SlhSha2Request) -> Result<Vec<u8>, String>,
) -> Result<SlhForsOutput, String> {
    validate(input)?;
    let digest = hash(&SlhSha2Request::Message {
        randomizer: input.signature[..32]
            .try_into()
            .expect("validated signature"),
        public_seed: input.public_seed,
        public_root: input.public_root,
        message: input.message,
    })?;
    let (indices, tree, leaf) = indices(&digest)?;
    let mut roots = Vec::with_capacity(35);
    for (i, &index) in indices.iter().enumerate() {
        let offset = 32 + i * 320;
        let mut global_index = ((i as u32) << 9) + index;
        let mut address = SlhSha2Address {
            layer: 0,
            tree,
            kind: 3,
            key_pair: leaf,
            chain_or_height: 0,
            hash_or_index: global_index,
        };
        let mut current = node(hash(&SlhSha2Request::F {
            public_seed: input.public_seed,
            address: address.clone(),
            node: input.signature[offset..offset + 32]
                .try_into()
                .expect("validated FORS offset"),
        })?)?;
        for level in 0..9 {
            let offset = offset + (level + 1) * 32;
            let sibling = input.signature[offset..offset + 32]
                .try_into()
                .expect("validated authentication offset");
            let (left, right) = if (index >> level) & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            global_index >>= 1;
            address.chain_or_height = (level + 1) as u32;
            address.hash_or_index = global_index;
            current = node(hash(&SlhSha2Request::H {
                public_seed: input.public_seed,
                address: address.clone(),
                left,
                right,
            })?)?;
        }
        roots.push(current);
    }
    let key = node(hash(&SlhSha2Request::ForsRoots {
        public_seed: input.public_seed,
        address: SlhSha2Address {
            layer: 0,
            tree,
            kind: 4,
            key_pair: leaf,
            chain_or_height: 0,
            hash_or_index: 0,
        },
        nodes: roots,
    })?)?;
    Ok(SlhForsOutput {
        message_digest: digest,
        tree,
        leaf,
        indices: indices.to_vec(),
        fors_public_key: key,
    })
}

/// Generate a full fixed35-tree/9-level certificate, with no signature signing.
pub fn prove_fors(input: &SlhForsInputs) -> Result<SlhForsProof, String> {
    prove_fors_using(input, |_, request| prove_slh_sha2(request))
}

/// Supply new or retained per-step certificates for resumable proving. Every
/// supplied certificate is fully verified against its independently routed
/// request before its output can feed the next step. Never trust a cache hit.
pub fn prove_fors_using(
    input: &SlhForsInputs,
    mut certificate: impl FnMut(usize, &SlhSha2Request) -> Result<SlhSha2Proof, String>,
) -> Result<SlhForsProof, String> {
    validate(input)?;
    let mut hashes = Vec::with_capacity(SLH_FORS_HASHES);
    route(input, |request| {
        let proof = certificate(hashes.len(), request)?;
        let output = verify_slh_sha2(&proof, request)?;
        hashes.push(proof);
        Ok(output)
    })?;
    if hashes.len() != SLH_FORS_HASHES {
        return Err("wrong FORS hash routing count".into());
    }
    Ok(SlhForsProof {
        version: 1,
        inputs: input.clone(),
        hashes,
    })
}

/// Verify all35 FORS trees, every address/branch/global index, and root
/// compression. No native hash or native signature verification is called.
pub fn verify_fors(
    proof: &SlhForsProof,
    expected: &SlhForsInputs,
) -> Result<SlhForsOutput, String> {
    validate(expected)?;
    if proof.version != 1 || proof.inputs != *expected || proof.hashes.len() != SLH_FORS_HASHES {
        return Err("invalid FORS version/input/hash count".into());
    }
    let mut at = 0;
    let output = route(expected, |request| {
        let output = verify_slh_sha2(&proof.hashes[at], request)?;
        at += 1;
        Ok(output)
    })?;
    if at != SLH_FORS_HASHES {
        return Err("unused FORS certificates".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fors_digest_bit_boundaries_are_fips205_indices() {
        for digest in [
            vec![0; 49],
            vec![255; 49],
            (0..49).map(|i| (i * 73 + 11) as u8).collect(),
        ] {
            let (got, tree, leaf) = indices(&digest).unwrap();
            let bits = digest[..40]
                .iter()
                .map(|x| format!("{x:08b}"))
                .collect::<String>();
            let expected = (0..35)
                .map(|i| u32::from_str_radix(&bits[i * 9..i * 9 + 9], 2).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(got.as_slice(), expected);
            assert_eq!(
                tree,
                u64::from_str_radix(
                    &digest[40..48]
                        .iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<String>(),
                    16
                )
                .unwrap()
            );
            assert_eq!(leaf, u32::from(digest[48] % 16));
            let mut padding = digest.clone();
            padding[39] ^= 31;
            assert_eq!(indices(&padding).unwrap().0, got);
        }
        assert!(indices(&[0; 48]).is_err());
        assert!(indices(&[0; 50]).is_err());
    }

    #[test]
    fn fors_shapes_and_input_binding_precede_cryptographic_work() {
        let mut input = SlhForsInputs {
            public_seed: [0; 32],
            public_root: [0; 32],
            message: [0; 32],
            signature: vec![0; 49_856],
        };
        let proof = SlhForsProof {
            version: 1,
            inputs: input.clone(),
            hashes: Vec::new(),
        };
        assert!(verify_fors(&proof, &input)
            .unwrap_err()
            .contains("hash count"));
        input.signature.pop();
        assert!(prove_fors(&input).unwrap_err().contains("length"));
        assert!(verify_fors(&proof, &input).unwrap_err().contains("length"));
        // Real full-forest STARKs, cold persistence and adversarial certificates
        // run through tests/e2e/slh-fors.sh; this fast test asserts only guards.
    }
}
