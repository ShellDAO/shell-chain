//! Inverse ML-DSA NTT certificates using the complete forward-NTT AIR.
//!
//! FIPS 204 §2.5 makes the forward transform a bijection over canonical
//! polynomials. Thus F(output) = input proves the unique, normalized inverse.
//! The prover uses Algorithm 42 only to construct a witness. Verification
//! reuses every existing forward butterfly/range constraint with reversed
//! endpoints; it does not execute native inverse arithmetic.

use crate::mldsa_ntt::{prove_ntt, verify_ntt, NttProof, NTT_DEGREE, NTT_MODULUS};
use serde::{Deserialize, Serialize};

/// Public relational certificate, not a new inverse-stage trace or a signature.
/// The inner proof intentionally retains its forward-NTT domain and format.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InverseNttProof {
    pub version: u8,
    pub forward: NttProof,
}

fn power(mut base: u64, mut exponent: u32) -> u32 {
    let q = u64::from(NTT_MODULUS);
    let mut out = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            out = out * base % q;
        }
        base = base * base % q;
        exponent >>= 1;
    }
    out as u32
}

// Algorithm 42 in ordinary canonical residues, not Montgomery representation.
// This is witness construction only; verify_inverse_ntt never calls it.
fn inverse(input: &[u32; NTT_DEGREE]) -> Result<[u32; NTT_DEGREE], String> {
    if input.iter().any(|&v| v >= NTT_MODULUS) {
        return Err("inverse NTT input is not canonical".into());
    }
    let q = u64::from(NTT_MODULUS);
    let mut out = *input;
    let mut m = 256u16;
    let mut len = 1;
    while len < NTT_DEGREE {
        for start in (0..NTT_DEGREE).step_by(2 * len) {
            m -= 1;
            let zeta = q - u64::from(power(1753, u32::from((m as u8).reverse_bits())));
            for j in start..start + len {
                let x = u64::from(out[j]);
                let y = u64::from(out[j + len]);
                out[j] = ((x + y) % q) as u32;
                out[j + len] = (zeta * (x + q - y) % q) as u32;
            }
        }
        len *= 2;
    }
    for value in &mut out {
        *value = (u64::from(*value) * 8_347_681 % q) as u32;
    }
    Ok(out)
}

/// Construct an Algorithm 42 witness and prove its complete forward relation.
pub fn prove_inverse_ntt(input: &[u32; NTT_DEGREE]) -> Result<InverseNttProof, String> {
    let output = inverse(input)?;
    let forward = prove_ntt(&output)?;
    if forward.stages.last().map(Vec::as_slice) != Some(input.as_slice()) {
        return Err("inverse NTT witness does not invert the specified transform".into());
    }
    Ok(InverseNttProof {
        version: 1,
        forward,
    })
}

/// Verify F(expected_output) = expected_input with the actual forward AIR.
/// All 256 coefficients and the inherited canonical/range constraints bind.
pub fn verify_inverse_ntt(
    proof: &InverseNttProof,
    expected_input: &[u32; NTT_DEGREE],
    expected_output: &[u32; NTT_DEGREE],
) -> Result<(), String> {
    if proof.version != 1 {
        return Err("unsupported inverse NTT certificate version".into());
    }
    verify_ntt(&proof.forward, expected_output, expected_input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn input() -> [u32; NTT_DEGREE] {
        core::array::from_fn(|i| (7919 * i as u32 + 19) % NTT_MODULUS)
    }

    // Direct interpolation at all roots of X^256+1, independent of Algorithm 42.
    fn reference(input: &[u32; NTT_DEGREE]) -> [u32; NTT_DEGREE] {
        let q = u64::from(NTT_MODULUS);
        let mut sums = [0u64; NTT_DEGREE];
        for (i, &value) in input.iter().enumerate() {
            let exponent = 2 * u32::from((i as u8).reverse_bits()) + 1;
            let inverse_root = u64::from(power(u64::from(power(1753, exponent)), NTT_MODULUS - 2));
            let mut term = u64::from(value);
            for sum in &mut sums {
                *sum = (*sum + term) % q;
                term = term * inverse_root % q;
            }
        }
        // Compute 256^-1 independently rather than borrowing witness scaling.
        let scale = u64::from(power(256, NTT_MODULUS - 2));
        sums.map(|v| (v * scale % q) as u32)
    }

    fn sample() -> &'static InverseNttProof {
        static SAMPLE: OnceLock<InverseNttProof> = OnceLock::new();
        SAMPLE.get_or_init(|| prove_inverse_ntt(&input()).unwrap())
    }

    #[test]
    fn algorithm42_matches_independent_interpolation_and_normalization() {
        let mut basis = [0; NTT_DEGREE];
        basis[255] = 1;
        for input in [
            input(),
            [0; NTT_DEGREE],
            [NTT_MODULUS - 1; NTT_DEGREE],
            basis,
        ] {
            assert_eq!(inverse(&input).unwrap(), reference(&input));
        }
        assert_eq!(power(1753, 256), NTT_MODULUS - 1);
        assert_eq!(power(1753, 512), 1);
        assert_eq!(power(256, NTT_MODULUS - 2), 8_347_681);
        let roots: std::collections::BTreeSet<_> =
            (0..256).map(|i| power(1753, 2 * i + 1)).collect();
        assert_eq!(roots.len(), 256);
    }

    #[test]
    fn real_certificate_json_binds_every_inverse_coefficient() {
        let proof = sample();
        verify_inverse_ntt(proof, &input(), &reference(&input())).unwrap();
        let restored: InverseNttProof =
            serde_json::from_slice(&serde_json::to_vec(proof).unwrap()).unwrap();
        verify_inverse_ntt(&restored, &input(), &reference(&input())).unwrap();
    }

    #[test]
    fn forward_certificate_reuse_requires_reversed_endpoints() {
        let proof = sample();
        let output = reference(&input());
        verify_ntt(&proof.forward, &output, &input()).unwrap();
        assert!(verify_inverse_ntt(proof, &output, &input()).is_err());
        let reused = InverseNttProof {
            version: 1,
            forward: proof.forward.clone(),
        };
        verify_inverse_ntt(&reused, &input(), &output).unwrap();
    }

    #[test]
    fn valid_forward_proof_of_unscaled_candidate_is_not_an_inverse() {
        let q = u64::from(NTT_MODULUS);
        let wrong = reference(&input()).map(|v| (u64::from(v) * 256 % q) as u32);
        let certificate = InverseNttProof {
            version: 1,
            forward: prove_ntt(&wrong).unwrap(),
        };
        assert!(verify_inverse_ntt(&certificate, &input(), &wrong).is_err());
        let scaled_input = input().map(|v| (u64::from(v) * 256 % q) as u32);
        verify_inverse_ntt(&certificate, &scaled_input, &wrong).unwrap();
    }

    #[test]
    fn states_endpoints_version_layout_and_truncation_reject() {
        let proof = sample();
        let output = reference(&input());
        let mut changed = proof.clone();
        changed.forward.stages[4][17] ^= 1;
        assert!(verify_inverse_ntt(&changed, &input(), &output).is_err());
        let mut bad_input = input();
        bad_input[255] ^= 1;
        assert!(verify_inverse_ntt(proof, &bad_input, &output).is_err());
        let mut bad_output = output;
        bad_output[255] ^= 1;
        assert!(verify_inverse_ntt(proof, &input(), &bad_output).is_err());
        let mut changed = proof.clone();
        changed.version = 2;
        assert!(verify_inverse_ntt(&changed, &input(), &output).is_err());
        let mut changed = proof.clone();
        changed.forward.proof_bytes.truncate(10);
        assert!(verify_inverse_ntt(&changed, &input(), &output).is_err());
        let mut changed = proof.clone();
        changed.forward.stages.pop();
        assert!(verify_inverse_ntt(&changed, &input(), &output).is_err());
        let mut changed = proof.clone();
        changed.forward.proof_bytes = crate::prove_sig_batch(&[crate::SigBatchEntry {
            msg_hash: [1; 32],
            pk_hash: [2; 32],
        }])
        .unwrap()
        .proof_bytes;
        assert!(verify_inverse_ntt(&changed, &input(), &output)
            .unwrap_err()
            .contains("trace layout"));
    }

    #[test]
    fn canonical_domain_is_required_before_proving_and_verifying() {
        let mut bad = input();
        bad[0] = NTT_MODULUS;
        assert!(prove_inverse_ntt(&bad).is_err());
        let mut changed = sample().clone();
        changed.forward.stages[0][0] = NTT_MODULUS;
        assert!(verify_inverse_ntt(&changed, &input(), &reference(&input())).is_err());
    }
}
