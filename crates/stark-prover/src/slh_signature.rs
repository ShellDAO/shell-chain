//! Full pure, empty-context SHA2-256f signature composition over hash AIRs.
//!
//! The manifest is metadata, never sufficient evidence. Verify the exact FORS
//! certificate and every one of the seventeen XMSS certificates against routed
//! public inputs, then compare the last proved root with the public key root.
use crate::{
    slh_fors::{verify_fors, SlhForsInputs, SlhForsProof, SLH_SHA2_256F_SIGNATURE_BYTES},
    slh_xmss::{verify_xmss, SlhXmssInputs, SlhXmssProof, SLH_XMSS_SIGNATURE_BYTES},
};
use serde::{Deserialize, Serialize};

pub const SLH_HYPERTREE_LAYERS: u8 = 17;
const HYPERTREE_OFFSET: usize = 11_232;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhSignatureManifest {
    pub version: u8,
    pub inputs: SlhForsInputs,
    pub layers: u8,
}
impl SlhSignatureManifest {
    pub fn new(inputs: SlhForsInputs) -> Self {
        Self {
            version: 1,
            inputs,
            layers: SLH_HYPERTREE_LAYERS,
        }
    }
    pub fn validate(&self, expected: &SlhForsInputs) -> Result<(), String> {
        if self.version != 1
            || self.layers != SLH_HYPERTREE_LAYERS
            || self.inputs != *expected
            || expected.signature.len() != SLH_SHA2_256F_SIGNATURE_BYTES
        {
            return Err("invalid full SLH manifest version/inputs/layer count/profile".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlhSignatureOutput {
    pub root: [u8; 32],
    pub layer_roots: Vec<[u8; 32]>,
}

fn layer_input(
    input: &SlhForsInputs,
    message: [u8; 32],
    layer: u8,
    tree: u64,
    leaf: u32,
) -> SlhXmssInputs {
    let start = HYPERTREE_OFFSET + usize::from(layer) * SLH_XMSS_SIGNATURE_BYTES;
    SlhXmssInputs {
        public_seed: input.public_seed,
        message,
        layer,
        tree,
        leaf,
        signature: input.signature[start..start + SLH_XMSS_SIGNATURE_BYTES].to_vec(),
    }
}

/// Stream concrete certificates so a verifier holds only FORS and one XMSS
/// layer at a time. Providers may read retained certificates or generate them;
/// they never supply trusted outputs. No native hash/signature verifier is used.
/// Success establishes the full mathematical signature for the supplied key,
/// signature and 32-byte signing message; canonical source admission is separate.
pub fn verify_slh_signature_using(
    manifest: &SlhSignatureManifest,
    expected: &SlhForsInputs,
    fors: &SlhForsProof,
    mut certificate: impl FnMut(u8, &SlhXmssInputs) -> Result<SlhXmssProof, String>,
) -> Result<SlhSignatureOutput, String> {
    manifest.validate(expected)?;
    let forest = verify_fors(fors, expected)?;
    let mut current = forest.fors_public_key;
    let mut tree = forest.tree;
    let mut leaf = forest.leaf;
    let mut roots = Vec::with_capacity(usize::from(SLH_HYPERTREE_LAYERS));
    for layer in 0..SLH_HYPERTREE_LAYERS {
        if layer != 0 {
            leaf = (tree & 15) as u32;
            tree >>= 4;
        }
        let input = layer_input(expected, current, layer, tree, leaf);
        let proof = certificate(layer, &input)?;
        current = verify_xmss(&proof, &input)?;
        roots.push(current);
    }
    if tree != 0 || current != expected.public_root {
        return Err("full SLH hypertree does not reach the expected public root".into());
    }
    Ok(SlhSignatureOutput {
        root: current,
        layer_roots: roots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> SlhForsInputs {
        SlhForsInputs {
            public_seed: [1; 32],
            public_root: [2; 32],
            message: [3; 32],
            signature: (0..SLH_SHA2_256F_SIGNATURE_BYTES)
                .map(|i| (i % 251) as u8)
                .collect(),
        }
    }
    #[test]
    fn all_original_slices_and_sixty_four_tree_bits_are_consumed() {
        let input = input();
        let original_tree = 0x0123_4567_89ab_cdefu64;
        let mut tree = original_tree;
        let mut leaf = 5;
        let mut slices = Vec::new();
        for layer in 0..17 {
            if layer != 0 {
                leaf = (tree & 15) as u32;
                tree >>= 4;
            }
            let expected_leaf = if layer == 0 {
                5
            } else {
                ((original_tree >> (4 * (layer - 1))) & 15) as u32
            };
            let expected_tree = if layer == 16 {
                0
            } else {
                original_tree >> (4 * layer)
            };
            let got = layer_input(&input, [layer; 32], layer, tree, leaf);
            assert_eq!(
                (got.layer, got.tree, got.leaf),
                (layer, expected_tree, expected_leaf)
            );
            assert_eq!(got.message, [layer; 32]);
            assert_eq!(got.public_seed, input.public_seed);
            slices.extend(got.signature);
        }
        assert_eq!(slices, input.signature[HYPERTREE_OFFSET..]);
        assert_eq!(tree, 0);
    }
    #[test]
    fn manifest_cannot_substitute_scope_or_replace_public_inputs() {
        let input = input();
        let mut manifest = SlhSignatureManifest::new(input.clone());
        manifest.validate(&input).unwrap();
        for layers in [0, 1, 16, 18, 255] {
            manifest.layers = layers;
            assert!(manifest.validate(&input).is_err());
        }
        manifest.layers = 17;
        manifest.version = 2;
        assert!(manifest.validate(&input).is_err());
        manifest.version = 1;
        for at in [0, HYPERTREE_OFFSET, SLH_SHA2_256F_SIGNATURE_BYTES - 1] {
            let mut wrong = input.clone();
            wrong.signature[at] ^= 1;
            assert!(manifest.validate(&wrong).is_err());
        }
        let mut wrong = input.clone();
        wrong.signature.pop();
        manifest.inputs = wrong.clone();
        assert!(manifest.validate(&wrong).is_err());
        assert!(
            serde_json::from_str::<SlhSignatureManifest>("{\"version\":1,\"unknown\":true}")
                .is_err()
        );
    }
}
