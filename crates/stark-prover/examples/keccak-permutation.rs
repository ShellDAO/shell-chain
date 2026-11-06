//! Full Keccak-f1600 proof persisted and reloaded in a separate invocation.

use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use shell_stark_prover::keccak_permutation::{
    prove_keccak_permutation, verify_keccak_permutation, KeccakPermutationProof,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    message: Vec<u8>,
    expected_output: [u64; 25],
    permutation: KeccakPermutationProof,
}

fn input(message: &[u8]) -> Result<[u64; 25], Box<dyn std::error::Error>> {
    if message.len() >= 136 {
        return Err("example supports one SHAKE256 absorb block only".into());
    }
    let mut bytes = [0u8; 200];
    bytes[..message.len()].copy_from_slice(message);
    bytes[message.len()] ^= 0x1f;
    bytes[135] ^= 0x80;
    Ok(core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("8 bytes"))
    }))
}
fn verify(artifact: &Artifact) -> Result<(), Box<dyn std::error::Error>> {
    verify_keccak_permutation(
        &artifact.permutation,
        &input(&artifact.message)?,
        &artifact.expected_output,
    )?;
    // Independent native oracle for the first output rate block only.
    // The padding/sponge itself is not included in this permutation AIR.
    let mut h = Shake256::default();
    h.update(&artifact.message);
    let mut expected = [0u8; 136];
    h.finalize_xof().read(&mut expected);
    let output: Vec<_> = artifact
        .expected_output
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    if output[..136] != expected {
        return Err("native SHAKE256 output control failed".into());
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: keccak-permutation prove|verify artifact.json".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("mode must be prove or verify".into());
    }
    if mode == "prove" {
        let message = b"Keccak-f1600 permutation AIR example".to_vec();
        let permutation = prove_keccak_permutation(&input(&message)?)?;
        let expected_output = permutation.rounds.last().ok_or("missing round")?.output;
        let artifact = Artifact {
            message,
            expected_output,
            permutation,
        };
        verify(&artifact)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        serde_json::to_writer(&mut file, &artifact)?;
        file.sync_all()?;
    }
    let artifact: Artifact = serde_json::from_reader(std::fs::File::open(path)?)?;
    verify(&artifact)?;
    let mut changed = artifact.permutation.clone();
    changed.rounds[11].theta[24] ^= 1u64 << 63;
    assert!(verify_keccak_permutation(
        &changed,
        &input(&artifact.message)?,
        &artifact.expected_output
    )
    .is_err());
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"rounds":24,"state_bits":1600,"permutation_proof_bytes":artifact.permutation.proof_bytes.len(),"native_shake256_rate_control":true,"persisted_reload_verified":true,"middle_theta_tamper_rejected":true,"sponge_air_proved":false})
    );
    Ok(())
}
