//! Persist and verify a standalone forward NTT proof with independent endpoints.

use shell_stark_prover::mldsa_ntt::{prove_ntt, verify_ntt, NttProof, NTT_DEGREE, NTT_MODULUS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: mldsa-ntt prove|verify artifact.json".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("mode must be prove or verify".into());
    }
    let input = core::array::from_fn(|i| (7919 * i as u32 + 19) % NTT_MODULUS);
    // Independent direct evaluation at the roots specified by FIPS 204 §2.5.
    let output: [u32; NTT_DEGREE] = core::array::from_fn(|i| {
        let exponent = 2 * u32::from((i as u8).reverse_bits()) + 1;
        let root = (0..exponent).fold(1u64, |v, _| v * 1753 % u64::from(NTT_MODULUS));
        input.iter().rev().fold(0u64, |v, &c| {
            (v * root + u64::from(c)) % u64::from(NTT_MODULUS)
        }) as u32
    });
    if mode == "prove" {
        let proof = prove_ntt(&input)?;
        verify_ntt(&proof, &input, &output)?;
        // A caller-owned path is required; an existing file is never overwritten.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        serde_json::to_writer(&mut file, &proof)?;
        file.sync_all()?;
    }
    let loaded: NttProof = serde_json::from_reader(std::fs::File::open(path)?)?;
    verify_ntt(&loaded, &input, &output)?;
    let mut changed = loaded.clone();
    changed.stages[4][17] ^= 1;
    assert!(verify_ntt(&changed, &input, &output).is_err());
    let mut wrong_output = output;
    wrong_output[255] ^= 1;
    assert!(verify_ntt(&loaded, &input, &wrong_output).is_err());
    let mut truncated = loaded.clone();
    truncated
        .proof_bytes
        .truncate(truncated.proof_bytes.len() / 2);
    assert!(verify_ntt(&truncated, &input, &output).is_err());
    println!(
        "{}",
        serde_json::json!({
            "mode": mode.to_string_lossy(),
            "coefficients": NTT_DEGREE,
            "stages": loaded.stages.len(),
            "butterflies": 1024,
            "proof_bytes": loaded.proof_bytes.len(),
            "artifact_bytes": std::fs::metadata(path)?.len(),
            "independent_endpoints_verified": true,
            "persisted_reload_verified": true,
            "middle_state_tamper_rejected": true,
            "output_tamper_rejected": true,
            "truncated_proof_rejected": true
        })
    );
    Ok(())
}
