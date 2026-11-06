//! Genuine public-key decoding proof and the first scaled t1 polynomial's NTT.

use serde::{Deserialize, Serialize};
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_stark_prover::{
    mldsa_key::{prove_public_key_decode, verify_public_key_decode, PublicKeyDecodeProof},
    mldsa_ntt::{prove_ntt, verify_ntt, NttProof, NTT_MODULUS},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    key_decoding: PublicKeyDecodeProof,
    first_scaled_t1_ntt: NttProof,
}

fn expected_ntt(input: &[u32; 256]) -> [u32; 256] {
    core::array::from_fn(|i| {
        let exponent = 2 * u32::from((i as u8).reverse_bits()) + 1;
        let root = (0..exponent).fold(1u64, |v, _| v * 1753 % u64::from(NTT_MODULUS));
        input.iter().rev().fold(0u64, |v, &c| {
            (v * root + u64::from(c)) % u64::from(NTT_MODULUS)
        }) as u32
    })
}

fn scaled_input(proof: &PublicKeyDecodeProof) -> Result<[u32; 256], &'static str> {
    proof.decoded.t1[0]
        .iter()
        .map(|&v| u32::from(v) << 13)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "t1 polynomial length")
}

fn verify(artifact: &Artifact) -> Result<(), Box<dyn std::error::Error>> {
    let signature = PQSignature::new(SignatureType::MlDsa65, artifact.signature.clone());
    if !MlDsaVerifier.verify(&artifact.public_key, &artifact.message, &signature)? {
        return Err("native ML-DSA signature validation failed".into());
    }
    verify_public_key_decode(&artifact.key_decoding, &artifact.public_key)?;
    let input = scaled_input(&artifact.key_decoding)?;
    verify_ntt(&artifact.first_scaled_t1_ntt, &input, &expected_ntt(&input))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: mldsa-key prove|verify artifact.json".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("mode must be prove or verify".into());
    }
    if mode == "prove" {
        // The temporary private key remains in zeroizing signer memory;
        // only public key/signature/proof data is written to the artifact.
        let signer = MlDsaSigner::generate();
        let message = b"ML-DSA key decoding and first scaled-t1 NTT example".to_vec();
        let signature = signer.sign(&message)?;
        assert!(MlDsaVerifier.verify(signer.public_key(), &message, &signature)?);
        let key_decoding = prove_public_key_decode(signer.public_key())?;
        verify_public_key_decode(&key_decoding, signer.public_key())?;
        let input = scaled_input(&key_decoding)?;
        let first_scaled_t1_ntt = prove_ntt(&input)?;
        let artifact = Artifact {
            public_key: signer.public_key().to_vec(),
            message,
            signature: signature.data,
            key_decoding,
            first_scaled_t1_ntt,
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
    let mut changed = artifact.key_decoding.clone();
    changed.decoded.t1[0][0] ^= 1;
    assert!(verify_public_key_decode(&changed, &artifact.public_key).is_err());
    let mut wrong_message = artifact.message.clone();
    wrong_message.push(1);
    let signature = PQSignature::new(SignatureType::MlDsa65, artifact.signature.clone());
    assert!(!MlDsaVerifier.verify(&artifact.public_key, &wrong_message, &signature)?);
    println!(
        "{}",
        serde_json::json!({
            "mode": mode.to_string_lossy(), "native_signature_verified": true,
            "public_key_bytes": artifact.public_key.len(), "rho_bytes": artifact.key_decoding.decoded.rho.len(),
            "t1_coefficients": artifact.key_decoding.decoded.t1.iter().flatten().count(),
            "key_proof_bytes": artifact.key_decoding.proof_bytes.len(),
            "first_scaled_t1_ntt_proof_bytes": artifact.first_scaled_t1_ntt.proof_bytes.len(),
            "independent_ntt_output_verified": true, "persisted_reload_verified": true,
            "changed_t1_rejected": true, "native_wrong_message_rejected": true
        })
    );
    Ok(())
}
