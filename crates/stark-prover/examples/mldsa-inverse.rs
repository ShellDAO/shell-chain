//! Persist and verify one genuine matrix polynomial followed by inverse NTT.

use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_stark_prover::{
    mldsa_inverse::{prove_inverse_ntt, verify_inverse_ntt, InverseNttProof},
    mldsa_matrix::{prove_matrix_polynomial, verify_matrix_polynomial, MatrixPolynomialProof},
    mldsa_ntt::{NTT_DEGREE, NTT_MODULUS},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    version: u8,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    matrix: MatrixPolynomialProof,
    inverse: InverseNttProof,
}

fn matrix_oracle(rho: &[u8]) -> [u32; NTT_DEGREE] {
    let mut h = Shake128::default();
    h.update(rho);
    h.update(&[0, 0]);
    let mut reader = h.finalize_xof();
    let mut values = Vec::new();
    while values.len() < NTT_DEGREE {
        let mut b = [0; 3];
        reader.read(&mut b);
        let value = u32::from_le_bytes([b[0], b[1], b[2], 0]) & 0x7fffff;
        if value < NTT_MODULUS {
            values.push(value);
        }
    }
    values.try_into().expect("256 coefficients")
}

fn power(mut base: u64, mut exponent: u32) -> u64 {
    let q = u64::from(NTT_MODULUS);
    let mut value = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = value * base % q;
        }
        base = base * base % q;
        exponent >>= 1;
    }
    value
}

// Independent direct interpolation, not the Algorithm 42 witness constructor.
fn interpolation(input: &[u32; NTT_DEGREE]) -> [u32; NTT_DEGREE] {
    let q = u64::from(NTT_MODULUS);
    let mut out = [0u64; NTT_DEGREE];
    for (i, &value) in input.iter().enumerate() {
        let root = power(1753, 2 * u32::from((i as u8).reverse_bits()) + 1);
        let inverse_root = power(root, NTT_MODULUS - 2);
        let mut term = u64::from(value);
        for coefficient in &mut out {
            *coefficient = (*coefficient + term) % q;
            term = term * inverse_root % q;
        }
    }
    let scale = power(256, NTT_MODULUS - 2);
    out.map(|value| (value * scale % q) as u32)
}

fn verify(artifact: &Artifact) -> Result<(), Box<dyn std::error::Error>> {
    if artifact.version != 1
        || artifact.public_key.len() != 1952
        || artifact.signature.len() != 3309
    {
        return Err("invalid ML-DSA-65 artifact shape/version".into());
    }
    let signature = PQSignature::new(SignatureType::MlDsa65, artifact.signature.clone());
    if !MlDsaVerifier.verify(&artifact.public_key, &artifact.message, &signature)? {
        return Err("native signature control failed".into());
    }
    let rho = &artifact.public_key[..32];
    let input = matrix_oracle(rho);
    verify_matrix_polynomial(&artifact.matrix, rho, 0, 0, &input)?;
    verify_inverse_ntt(&artifact.inverse, &input, &interpolation(&input))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: mldsa-inverse prove|verify artifact.json".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("invalid mode".into());
    }
    if mode == "prove" {
        if std::path::Path::new(path).try_exists()? {
            return Err("artifact already exists".into());
        }
        let signer = MlDsaSigner::generate();
        let message = b"ML-DSA matrix inverse NTT certificate".to_vec();
        let signature = signer.sign(&message)?;
        let public_key = signer.public_key().to_vec();
        let input = matrix_oracle(&public_key[..32]);
        let artifact = Artifact {
            version: 1,
            matrix: prove_matrix_polynomial(&public_key[..32], 0, 0)?,
            inverse: prove_inverse_ntt(&input)?,
            public_key,
            message,
            signature: signature.data,
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        serde_json::to_writer(&mut file, &artifact)?;
        file.sync_all()?;
    }
    let artifact: Artifact = serde_json::from_reader(std::fs::File::open(path)?)?;
    verify(&artifact)?;
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"coefficients":256,"matrix_coordinates":1,"permutations":artifact.matrix.xof.permutations.len(),"forward_butterflies":1024,"inverse_proof_bytes":artifact.inverse.forward.proof_bytes.len(),"sampler_proof_bytes":artifact.matrix.proof_bytes.len(),"artifact_bytes":std::fs::metadata(path)?.len(),"native_signature_control":true,"matrix_sampling_proof_verified":true,"inverse_relation_verified":true,"independent_interpolation_verified":true,"saved_reload_verified":true,"full_matrix_verified":false,"full_signature_air_proved":false})
    );
    Ok(())
}
