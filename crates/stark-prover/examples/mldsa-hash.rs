//! Genuine ML-DSA key hash and default-context message representative proofs.

use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_stark_prover::shake_sponge::{prove_shake, verify_shake, ShakeKind, ShakeProof};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    key_hash: ShakeProof,
    message_hash: ShakeProof,
}
fn native(message: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(message);
    let mut out = vec![0; 64];
    h.finalize_xof().read(&mut out);
    out
}
fn message_input(tr: &[u8], message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if tr.len() != 64 {
        return Err("ML-DSA tr must be 64 bytes".into());
    }
    let mut input = tr.to_vec();
    input.extend([0, 0]);
    input.extend(message);
    Ok(input)
}
fn verify(a: &Artifact) -> Result<(), Box<dyn std::error::Error>> {
    if a.public_key.len() != 1952
        || a.key_hash.output.len() != 64
        || a.message_hash.output.len() != 64
    {
        return Err("ML-DSA-65 hash shape".into());
    }
    let sig = PQSignature::new(SignatureType::MlDsa65, a.signature.clone());
    if !MlDsaVerifier.verify(&a.public_key, &a.message, &sig)? {
        return Err("native signature control failed".into());
    }
    verify_shake(
        &a.key_hash,
        ShakeKind::Shake256,
        &a.public_key,
        &a.key_hash.output,
    )?;
    let input = message_input(&a.key_hash.output, &a.message)?;
    verify_shake(
        &a.message_hash,
        ShakeKind::Shake256,
        &input,
        &a.message_hash.output,
    )?;
    if a.key_hash.output != native(&a.public_key) || a.message_hash.output != native(&input) {
        return Err("independent SHAKE256 controls failed".into());
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: mldsa-hash prove|verify hashes.json".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("mode must be prove or verify".into());
    }
    if mode == "prove" {
        let signer = MlDsaSigner::generate();
        let message = b"ML-DSA default-context hash AIR example".to_vec();
        let signature = signer.sign(&message)?;
        eprintln!("Proving the complete public-key hash...");
        let key_hash = prove_shake(ShakeKind::Shake256, signer.public_key(), 64)?;
        eprintln!("Proving the message representative...");
        let message_hash = prove_shake(
            ShakeKind::Shake256,
            &message_input(&key_hash.output, &message)?,
            64,
        )?;
        let a = Artifact {
            public_key: signer.public_key().to_vec(),
            message,
            signature: signature.data,
            key_hash,
            message_hash,
        };
        verify(&a)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        serde_json::to_writer(&mut file, &a)?;
        file.sync_all()?;
    }
    let a: Artifact = serde_json::from_reader(std::fs::File::open(path)?)?;
    verify(&a)?;
    let mut bad = a.key_hash.clone();
    bad.permutations[1].input[24] ^= 1u64 << 63;
    assert!(verify_shake(&bad, ShakeKind::Shake256, &a.public_key, &bad.output).is_err());
    let mut wrong_message = a.message.clone();
    wrong_message.push(1);
    let sig = PQSignature::new(SignatureType::MlDsa65, a.signature.clone());
    assert!(!MlDsaVerifier.verify(&a.public_key, &wrong_message, &sig)?);
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"public_key_bytes":a.public_key.len(),"tr_bytes":a.key_hash.output.len(),"mu_bytes":a.message_hash.output.len(),"key_hash_permutations":a.key_hash.permutations.len(),"message_hash_permutations":a.message_hash.permutations.len(),"sponge_proof_bytes":[a.key_hash.sponge_proof_bytes.len(),a.message_hash.sponge_proof_bytes.len()],"permutation_proof_bytes":a.key_hash.permutations.iter().chain(&a.message_hash.permutations).map(|p|p.proof_bytes.len()).sum::<usize>(),"native_signature_control":true,"native_wrong_message_rejected":true,"independent_shake_controls":true,"persisted_reload_verified":true,"capacity_tamper_rejected":true,"full_signature_air_proved":false})
    );
    Ok(())
}
