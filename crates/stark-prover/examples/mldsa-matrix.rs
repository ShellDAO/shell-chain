//! Complete ML-DSA-65 ExpandA matrix with resumable verified coordinate files.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_stark_prover::mldsa_matrix::{
    prove_matrix_polynomial, verify_matrix, verify_matrix_polynomial, MatrixPolynomialProof,
    MatrixProof, MATRIX_COLUMNS, MATRIX_ROWS,
};
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u8,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}
fn write<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer(&mut f, value)?;
    f.sync_all()?;
    Ok(())
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}
fn expected(rho: &[u8], row: u8, column: u8) -> Vec<u32> {
    let mut h = Shake128::default();
    h.update(rho);
    h.update(&[column]);
    h.update(&[row]);
    let mut reader = h.finalize_xof();
    let mut out = Vec::new();
    while out.len() < 256 {
        let mut bytes = [0; 3];
        reader.read(&mut bytes);
        let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) & 0x7fffff;
        if v < 8380417 {
            out.push(v);
        }
    }
    out
}
fn identity(path: &Path, proving: bool) -> Result<Identity, Box<dyn std::error::Error>> {
    if proving && !path.try_exists()? {
        std::fs::create_dir(path)?;
        let signer = MlDsaSigner::generate();
        let message = b"ML-DSA full matrix AIR example".to_vec();
        let signature = signer.sign(&message)?;
        let id = Identity {
            version: 1,
            public_key: signer.public_key().to_vec(),
            message,
            signature: signature.data,
        };
        write(&path.join("identity.json"), &id)?;
    }
    let id: Identity = read(&path.join("identity.json"))?;
    if id.version != 1 || id.public_key.len() != 1952 || id.signature.len() != 3309 {
        return Err("ML-DSA-65 identity shape/version".into());
    }
    let sig = PQSignature::new(SignatureType::MlDsa65, id.signature.clone());
    if !MlDsaVerifier.verify(&id.public_key, &id.message, &sig)? {
        return Err("native signature control failed".into());
    }
    Ok(id)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (mode, directory, limit) =
        match args.as_slice() {
            [mode, path] => (mode, path, 30usize),
            [mode, path, limit] if mode == "prove" => (
                mode,
                path,
                limit.to_str().ok_or("invalid batch count")?.parse()?,
            ),
            _ => return Err(
                "usage: mldsa-matrix prove matrix-dir [max-new-polynomials] | verify matrix-dir"
                    .into(),
            ),
        };
    if (mode != "prove" && mode != "verify") || !(1..=30).contains(&limit) {
        return Err("invalid mode or batch count (1..30)".into());
    }
    let path = Path::new(directory);
    let id = identity(path, mode == "prove")?;
    let rho = &id.public_key[..32];
    let mut polynomials = Vec::new();
    let mut native = Vec::new();
    let mut added = 0;
    let mut reused = 0;
    for row in 0..MATRIX_ROWS {
        for column in 0..MATRIX_COLUMNS {
            let file = path.join(format!("a-{row}-{column}.json"));
            let exists = file.try_exists()?;
            if mode == "prove" && !exists {
                eprintln!("Proving matrix coordinate ({row}, {column})...");
                let proof = prove_matrix_polynomial(rho, row as u8, column as u8)?;
                write(&file, &proof)?;
                added += 1;
            }
            let proof: MatrixPolynomialProof = read(&file)?;
            let output = expected(rho, row as u8, column as u8);
            if mode == "prove" {
                verify_matrix_polynomial(&proof, rho, row as u8, column as u8, &output)?;
                eprintln!("Verified saved coordinate ({row}, {column})");
            } else {
                eprintln!("Loaded coordinate ({row}, {column})");
            }
            if exists {
                reused += 1;
            }
            polynomials.push(proof);
            native.push(output);
            if mode == "prove" && added == limit {
                break;
            }
        }
        if mode == "prove" && added == limit {
            break;
        }
    }
    let complete = polynomials.len() == 30;
    let matrix = MatrixProof {
        version: 1,
        rho: rho.to_vec(),
        polynomials,
    };
    if mode == "verify" {
        if !complete {
            return Err("incomplete 6x5 matrix".into());
        }
        verify_matrix(&matrix, rho, &native)?;
    }
    let rejected: usize = matrix
        .polynomials
        .iter()
        .map(|p| p.counts.len() - 1 - 256)
        .sum();
    let sampler_bytes: usize = matrix.polynomials.iter().map(|p| p.proof_bytes.len()).sum();
    let permutations: usize = matrix
        .polynomials
        .iter()
        .map(|p| p.xof.permutations.len())
        .sum();
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"rows":6,"columns":5,"polynomials":matrix.polynomials.len(),"coefficients":matrix.polynomials.len()*256,"newly_proved":added,"reused":reused,"rejected_triples":rejected,"sampler_proof_bytes":sampler_bytes,"permutations":permutations,"independent_native_matrix_oracle":true,"native_signature_control":true,"saved_coordinates_reloaded_verified":true,"full_matrix_verified":complete,"full_signature_air_proved":false})
    );
    Ok(())
}
