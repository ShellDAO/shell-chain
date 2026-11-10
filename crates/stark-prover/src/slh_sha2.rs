//! Public verification-hash routing for FIPS 205 SLH-DSA-SHA2-256f.
//!
//! These certificates establish H_msg/MGF1, F, H and T hashes only. A signature
//! verifier must independently bind tree positions, nodes, message and key and
//! check the complete FORS/WOTS+/hypertree structure. No native SHA or signature
//! verifier participates in certificate acceptance.
use crate::{
    sha2_compression::Sha2Algorithm,
    sha2_digest::{prove_digest, verify_digest, Sha2DigestProof},
};
use serde::{Deserialize, Serialize};

/// Lossless supported SHA2-256f address coordinates (FIPS 205 section 4.3).
/// The caller binds the expected address; this type does not prove tree traversal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhSha2Address {
    pub layer: u8,
    pub tree: u64,
    pub kind: u8,
    pub key_pair: u32,
    pub chain_or_height: u32,
    pub hash_or_index: u32,
}

impl SlhSha2Address {
    /// SHA2 compresses the zero high words, layer and type to 22 bytes.
    pub fn compressed(&self) -> Result<[u8; 22], String> {
        if self.layer >= 17 || self.kind > 6 {
            return Err("unsupported SHA2-256f address layer/type".into());
        }
        let mut bytes = [0; 22];
        bytes[0] = self.layer;
        bytes[1..9].copy_from_slice(&self.tree.to_be_bytes());
        bytes[9] = self.kind;
        bytes[10..14].copy_from_slice(&self.key_pair.to_be_bytes());
        bytes[14..18].copy_from_slice(&self.chain_or_height.to_be_bytes());
        bytes[18..22].copy_from_slice(&self.hash_or_index.to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum SlhSha2Request {
    /// Native messages are 32-byte signing hashes, pure mode with empty context.
    Message {
        randomizer: [u8; 32],
        public_seed: [u8; 32],
        public_root: [u8; 32],
        message: [u8; 32],
    },
    F {
        public_seed: [u8; 32],
        address: SlhSha2Address,
        node: [u8; 32],
    },
    H {
        public_seed: [u8; 32],
        address: SlhSha2Address,
        left: [u8; 32],
        right: [u8; 32],
    },
    WotsPublicKey {
        public_seed: [u8; 32],
        address: SlhSha2Address,
        nodes: Vec<[u8; 32]>,
    },
    ForsRoots {
        public_seed: [u8; 32],
        address: SlhSha2Address,
        nodes: Vec<[u8; 32]>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhSha2Proof {
    pub version: u8,
    /// One digest for F/H/T, two for H_msg followed by its fixed MGF1 output.
    pub digests: Vec<Sha2DigestProof>,
}

fn first_input(request: &SlhSha2Request) -> Result<(Sha2Algorithm, Vec<u8>), String> {
    use SlhSha2Request::*;
    if let Message {
        randomizer,
        public_seed,
        public_root,
        message,
    } = request
    {
        let mut input = Vec::with_capacity(130);
        input.extend_from_slice(randomizer);
        input.extend_from_slice(public_seed);
        input.extend_from_slice(public_root);
        input.extend_from_slice(&[0, 0]); // pure domain, zero-length context
        input.extend_from_slice(message);
        return Ok((Sha2Algorithm::Sha512, input));
    }
    let (seed, address, algorithm, kinds): (&[u8; 32], &SlhSha2Address, _, &[u8]) = match request {
        F {
            public_seed,
            address,
            ..
        } => (public_seed, address, Sha2Algorithm::Sha256, &[0, 3]),
        H {
            public_seed,
            address,
            ..
        } => (public_seed, address, Sha2Algorithm::Sha512, &[2, 3]),
        WotsPublicKey {
            public_seed,
            address,
            nodes,
        } if nodes.len() == 67 => (public_seed, address, Sha2Algorithm::Sha512, &[1]),
        ForsRoots {
            public_seed,
            address,
            nodes,
        } if nodes.len() == 35 => (public_seed, address, Sha2Algorithm::Sha512, &[4]),
        _ => return Err("wrong SHA2-256f verification hash node count".into()),
    };
    if !kinds.contains(&address.kind) {
        return Err("wrong SHA2-256f verification hash address domain".into());
    }
    let compressed = address.compressed()?;
    let prefix_size = if algorithm == Sha2Algorithm::Sha256 {
        64
    } else {
        128
    };
    let mut input = vec![0; prefix_size];
    input[..32].copy_from_slice(seed);
    input.extend_from_slice(&compressed);
    match request {
        F { node, .. } => input.extend_from_slice(node),
        H { left, right, .. } => {
            input.extend_from_slice(left);
            input.extend_from_slice(right);
        }
        WotsPublicKey { nodes, .. } | ForsRoots { nodes, .. } => {
            for node in nodes {
                input.extend_from_slice(node);
            }
        }
        Message { .. } => unreachable!(),
    }
    Ok((algorithm, input))
}

fn mgf_input(request: &SlhSha2Request, digest: &[u8]) -> Vec<u8> {
    let SlhSha2Request::Message {
        randomizer,
        public_seed,
        ..
    } = request
    else {
        unreachable!()
    };
    let mut input = Vec::with_capacity(132);
    input.extend_from_slice(randomizer);
    input.extend_from_slice(public_seed);
    input.extend_from_slice(digest);
    // SHA2-256f requires m=49 bytes, so exactly one SHA512 MGF1 block.
    input.extend_from_slice(&0u32.to_be_bytes());
    input
}

/// Prove the requested verification hash, including complete padding/chaining.
pub fn prove_slh_sha2(request: &SlhSha2Request) -> Result<SlhSha2Proof, String> {
    let (a, bytes) = first_input(request)?;
    let first = prove_digest(a, &bytes)?;
    let mut digests = vec![first];
    if matches!(request, SlhSha2Request::Message { .. }) {
        let digest = verify_digest(&digests[0], a, &bytes)?;
        digests.push(prove_digest(
            Sha2Algorithm::Sha512,
            &mgf_input(request, &digest),
        )?);
    }
    Ok(SlhSha2Proof {
        version: 1,
        digests,
    })
}

/// Verify an independently supplied request; return 49 H_msg bytes or 32 F/H/T
/// bytes. Hash acceptance alone never establishes a signature or canonical source.
pub fn verify_slh_sha2(proof: &SlhSha2Proof, expected: &SlhSha2Request) -> Result<Vec<u8>, String> {
    let (a, bytes) = first_input(expected)?;
    let message = matches!(expected, SlhSha2Request::Message { .. });
    if proof.version != 1 || proof.digests.len() != if message { 2 } else { 1 } {
        return Err("invalid SHA2-256f verification hash certificate layout".into());
    }
    let first = verify_digest(&proof.digests[0], a, &bytes)?;
    if message {
        Ok(verify_digest(
            &proof.digests[1],
            Sha2Algorithm::Sha512,
            &mgf_input(expected, &first),
        )?[..49]
            .to_vec())
    } else {
        Ok(first[..32].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha512};

    fn address(kind: u8) -> SlhSha2Address {
        SlhSha2Address {
            layer: 16,
            tree: 0xfedcba9876543210,
            kind,
            key_pair: 15,
            chain_or_height: 7,
            hash_or_index: 9,
        }
    }

    // Separate byte-by-byte reference construction, rather than calling routing
    // helpers from the implementation under test.
    fn reference(request: &SlhSha2Request) -> Vec<u8> {
        use SlhSha2Request::*;
        if let Message {
            randomizer,
            public_seed,
            public_root,
            message,
        } = request
        {
            let mut hash = Sha512::new();
            hash.update(randomizer);
            hash.update(public_seed);
            hash.update(public_root);
            hash.update([0, 0]);
            hash.update(message);
            let mut mgf = Sha512::new();
            mgf.update(randomizer);
            mgf.update(public_seed);
            mgf.update(hash.finalize());
            mgf.update([0; 4]);
            return mgf.finalize()[..49].to_vec();
        }
        let (seed, addr) = match request {
            F {
                public_seed,
                address,
                ..
            }
            | H {
                public_seed,
                address,
                ..
            }
            | WotsPublicKey {
                public_seed,
                address,
                ..
            }
            | ForsRoots {
                public_seed,
                address,
                ..
            } => (public_seed, address),
            _ => unreachable!(),
        };
        let mut adrs = [0u8; 32];
        adrs[3] = addr.layer;
        adrs[8..16].copy_from_slice(&addr.tree.to_be_bytes());
        adrs[19] = addr.kind;
        adrs[20..24].copy_from_slice(&addr.key_pair.to_be_bytes());
        adrs[24..28].copy_from_slice(&addr.chain_or_height.to_be_bytes());
        adrs[28..32].copy_from_slice(&addr.hash_or_index.to_be_bytes());
        let mut bytes = seed.to_vec();
        bytes.resize(if matches!(request, F { .. }) { 64 } else { 128 }, 0);
        bytes.push(adrs[3]);
        bytes.extend_from_slice(&adrs[8..16]);
        bytes.push(adrs[19]);
        bytes.extend_from_slice(&adrs[20..]);
        match request {
            F { node, .. } => bytes.extend_from_slice(node),
            H { left, right, .. } => {
                bytes.extend_from_slice(left);
                bytes.extend_from_slice(right);
            }
            WotsPublicKey { nodes, .. } | ForsRoots { nodes, .. } => {
                for node in nodes {
                    bytes.extend_from_slice(node);
                }
            }
            _ => unreachable!(),
        }
        if matches!(request, F { .. }) {
            Sha256::digest(bytes).to_vec()
        } else {
            Sha512::digest(bytes)[..32].to_vec()
        }
    }

    #[test]
    fn fips205_sha2_256f_verification_hashes_and_public_binding() {
        let requests = [
            SlhSha2Request::Message {
                randomizer: [0xab; 32],
                public_seed: [0xcd; 32],
                public_root: [0xef; 32],
                message: [0x13; 32],
            },
            SlhSha2Request::F {
                public_seed: [0xcd; 32],
                address: address(0),
                node: [0x23; 32],
            },
            SlhSha2Request::H {
                public_seed: [0xcd; 32],
                address: address(2),
                left: [0x23; 32],
                right: [0x45; 32],
            },
            SlhSha2Request::WotsPublicKey {
                public_seed: [0xcd; 32],
                address: address(1),
                nodes: (0..67).map(|i| [i as u8; 32]).collect(),
            },
            SlhSha2Request::ForsRoots {
                public_seed: [0xcd; 32],
                address: address(4),
                nodes: (0..35).map(|i| [i as u8; 32]).collect(),
            },
        ];
        for request in requests {
            let proof = prove_slh_sha2(&request).unwrap();
            assert_eq!(
                verify_slh_sha2(&proof, &request).unwrap(),
                reference(&request)
            );
            let mut wrong = request.clone();
            match &mut wrong {
                SlhSha2Request::Message { message, .. } => message[0] ^= 1,
                SlhSha2Request::F { address, .. }
                | SlhSha2Request::H { address, .. }
                | SlhSha2Request::WotsPublicKey { address, .. }
                | SlhSha2Request::ForsRoots { address, .. } => address.tree ^= 1,
            }
            assert!(verify_slh_sha2(&proof, &wrong).is_err());
            let mut wrong = request.clone();
            match &mut wrong {
                SlhSha2Request::Message { public_root, .. } => public_root[31] ^= 1,
                SlhSha2Request::F { node, .. } => node[0] ^= 1,
                SlhSha2Request::H { left, right, .. } => std::mem::swap(left, right),
                SlhSha2Request::WotsPublicKey { nodes, .. }
                | SlhSha2Request::ForsRoots { nodes, .. } => nodes.swap(0, 1),
            }
            assert!(verify_slh_sha2(&proof, &wrong).is_err());
            let mut wrong = request.clone();
            match &mut wrong {
                SlhSha2Request::Message { public_seed, .. }
                | SlhSha2Request::F { public_seed, .. }
                | SlhSha2Request::H { public_seed, .. }
                | SlhSha2Request::WotsPublicKey { public_seed, .. }
                | SlhSha2Request::ForsRoots { public_seed, .. } => public_seed[0] ^= 1,
            }
            assert!(verify_slh_sha2(&proof, &wrong).is_err());
            let mut bad = proof.clone();
            bad.version = 2;
            assert!(verify_slh_sha2(&bad, &request).is_err());
            let mut bad = proof.clone();
            bad.digests.push(bad.digests[0].clone());
            assert!(verify_slh_sha2(&bad, &request).is_err());
            if proof.digests.len() == 2 {
                let mut bad = proof.clone();
                bad.digests.swap(0, 1);
                assert!(verify_slh_sha2(&bad, &request).is_err());
                let (a, bytes) = first_input(&request).unwrap();
                let digest = verify_digest(&proof.digests[0], a, &bytes).unwrap();
                let mut counter_one = mgf_input(&request, &digest);
                *counter_one.last_mut().unwrap() = 1;
                let mut bad = proof.clone();
                bad.digests[1] = prove_digest(Sha2Algorithm::Sha512, &counter_one).unwrap();
                assert!(verify_slh_sha2(&bad, &request).is_err());
            }
        }
    }

    #[test]
    fn fips205_hash_domains_and_node_counts_are_strict() {
        let mut a = address(7);
        assert!(a.compressed().is_err());
        a.kind = 1;
        a.layer = 17;
        assert!(a.compressed().is_err());
        let wrong_domain = SlhSha2Request::F {
            public_seed: [0; 32],
            address: address(5),
            node: [0; 32],
        };
        assert!(prove_slh_sha2(&wrong_domain).is_err());
        for n in [0, 35, 66, 68, 4096] {
            assert!(prove_slh_sha2(&SlhSha2Request::WotsPublicKey {
                public_seed: [0; 32],
                address: address(1),
                nodes: vec![[0; 32]; n]
            })
            .is_err());
        }
        for n in [0, 34, 36, 67] {
            assert!(prove_slh_sha2(&SlhSha2Request::ForsRoots {
                public_seed: [0; 32],
                address: address(4),
                nodes: vec![[0; 32]; n]
            })
            .is_err());
        }
    }
}
