//! Genuine signature commitment prefix to a persisted SampleInBall proof.

use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_stark_prover::mldsa_challenge::{prove_challenge, verify_challenge, ChallengeProof};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    challenge: ChallengeProof,
}
fn expected(seed: &[u8]) -> Vec<i8> {
    let mut h = Shake256::default();
    h.update(seed);
    let mut reader = h.finalize_xof();
    let mut bytes = [0; 8];
    reader.read(&mut bytes);
    let mut signs = u64::from_le_bytes(bytes);
    let mut c = vec![0; 256];
    for i in 207..256 {
        let mut byte = [0; 1];
        loop {
            reader.read(&mut byte);
            if usize::from(byte[0]) <= i {
                break;
            }
        }
        let j = usize::from(byte[0]);
        c[i] = c[j];
        c[j] = if signs & 1 == 0 { 1 } else { -1 };
        signs >>= 1;
    }
    c
}
fn verify(a: &Artifact) -> Result<(), Box<dyn std::error::Error>> {
    if a.public_key.len() != 1952 || a.signature.len() != 3309 {
        return Err("ML-DSA-65 key/signature shape".into());
    }
    let sig = PQSignature::new(SignatureType::MlDsa65, a.signature.clone());
    if !MlDsaVerifier.verify(&a.public_key, &a.message, &sig)? {
        return Err("native signature control failed".into());
    }
    verify_challenge(
        &a.challenge,
        &a.signature[..48],
        &expected(&a.signature[..48]),
    )?;
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: mldsa-challenge prove|verify challenge.json".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("mode must be prove or verify".into());
    }
    if mode == "prove" {
        let signer = MlDsaSigner::generate();
        let message = b"ML-DSA signature challenge AIR example".to_vec();
        let signature = signer.sign(&message)?;
        let challenge = prove_challenge(&signature.data[..48])?;
        let a = Artifact {
            public_key: signer.public_key().to_vec(),
            message,
            signature: signature.data,
            challenge,
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
    let c = a.challenge.challenge().ok_or("missing challenge")?;
    let mut bad = a.challenge.clone();
    bad.indices[0] ^= 1;
    assert!(verify_challenge(&bad, &a.signature[..48], c).is_err());
    let mut wrong_message = a.message.clone();
    wrong_message.push(1);
    let sig = PQSignature::new(SignatureType::MlDsa65, a.signature.clone());
    assert!(!MlDsaVerifier.verify(&a.public_key, &wrong_message, &sig)?);
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"seed_bytes":48,"coefficients":c.len(),"nonzero_coefficients":c.iter().filter(|&&v|v!=0).count(),"attempts":a.challenge.counts.len()-1,"rejected_bytes":a.challenge.counts.len()-1-49,"xof_bytes":a.challenge.xof.output.len(),"challenge_proof_bytes":a.challenge.proof_bytes.len(),"sponge_proof_bytes":a.challenge.xof.sponge_proof_bytes.len(),"permutations":a.challenge.xof.permutations.len(),"native_signature_control":true,"native_wrong_message_rejected":true,"independent_sampling_oracle":true,"persisted_reload_verified":true,"index_tamper_rejected":true,"full_signature_air_proved":false})
    );
    Ok(())
}
