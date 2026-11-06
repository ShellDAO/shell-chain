//! Genuine signature encoding proof composed with the first z polynomial's NTT.

use serde::{Deserialize, Serialize};
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_stark_prover::{
    mldsa_decode::{prove_signature_decode, verify_signature_decode, SignatureDecodeProof},
    mldsa_ntt::{prove_ntt, verify_ntt, NttProof, NTT_MODULUS},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    decoding: SignatureDecodeProof,
    first_polynomial_ntt: NttProof,
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

fn verify(artifact: &Artifact) -> Result<(), Box<dyn std::error::Error>> {
    let signature = PQSignature::new(SignatureType::MlDsa65, artifact.signature.clone());
    if !MlDsaVerifier.verify(&artifact.public_key, &artifact.message, &signature)? {
        return Err("native ML-DSA signature validation failed".into());
    }
    verify_signature_decode(&artifact.decoding, &artifact.signature)?;
    let input: [u32; 256] = artifact.decoding.decoded.z[0]
        .clone()
        .try_into()
        .map_err(|_| "z polynomial length")?;
    verify_ntt(
        &artifact.first_polynomial_ntt,
        &input,
        &expected_ntt(&input),
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: mldsa-decode prove|verify artifact.json".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("mode must be prove or verify".into());
    }
    if mode == "prove" {
        // Only the public key and signature are persisted. The temporary
        // private key stays in the signer's zeroizing in-memory storage.
        let signer = MlDsaSigner::generate();
        let message = b"ML-DSA decoding and first-polynomial NTT example".to_vec();
        let signature = signer.sign(&message)?;
        assert!(MlDsaVerifier.verify(signer.public_key(), &message, &signature)?);
        let decoding = prove_signature_decode(&signature.data)?;
        verify_signature_decode(&decoding, &signature.data)?;
        let input: [u32; 256] = decoding.decoded.z[0]
            .clone()
            .try_into()
            .map_err(|_| "z polynomial length")?;
        let first_polynomial_ntt = prove_ntt(&input)?;
        let artifact = Artifact {
            public_key: signer.public_key().to_vec(),
            message,
            signature: signature.data,
            decoding,
            first_polynomial_ntt,
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
    let mut wrong_z = artifact.decoding.clone();
    wrong_z.decoded.z[0][0] = (wrong_z.decoded.z[0][0] + 1) % NTT_MODULUS;
    assert!(verify_signature_decode(&wrong_z, &artifact.signature).is_err());
    let mut wrong_message = artifact.message.clone();
    wrong_message.push(1);
    let signature = PQSignature::new(SignatureType::MlDsa65, artifact.signature.clone());
    assert!(!MlDsaVerifier.verify(&artifact.public_key, &wrong_message, &signature)?);
    println!(
        "{}",
        serde_json::json!({
            "mode": mode.to_string_lossy(), "native_signature_verified": true,
            "signature_bytes": artifact.signature.len(), "decoded_z_coefficients": 1280,
            "hint_polynomials": artifact.decoding.decoded.hints.len(),
            "decoder_proof_bytes": artifact.decoding.proof_bytes.len(),
            "first_polynomial_ntt_proof_bytes": artifact.first_polynomial_ntt.proof_bytes.len(),
            "independent_ntt_output_verified": true, "persisted_reload_verified": true,
            "changed_z_rejected": true, "native_wrong_message_rejected": true
        })
    );
    Ok(())
}
