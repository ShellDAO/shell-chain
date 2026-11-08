//! Persist and verify the full public ML-DSA-65 matrix-equation pipeline.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};
use shell_crypto::{MlDsaVerifier, PQSignature, SignatureType, Verifier};
use shell_stark_prover::{
    mldsa_challenge::{prove_challenge, verify_challenge, ChallengeProof},
    mldsa_decode::{prove_signature_decode, verify_signature_decode, SignatureDecodeProof},
    mldsa_equation::{prove_equation, verify_equation, EquationInputs, EquationProof},
    mldsa_inverse::{prove_inverse_ntt, verify_inverse_ntt, InverseNttProof},
    mldsa_key::{prove_public_key_decode, verify_public_key_decode, PublicKeyDecodeProof},
    mldsa_matrix::{verify_matrix, MatrixPolynomialProof, MatrixProof},
    mldsa_ntt::{prove_ntt, verify_ntt, NttProof, NTT_MODULUS},
};
use std::{
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u8,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_reader(BufReader::new(
        std::fs::File::open(path)?,
    ))?)
}
fn write<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, value)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}
fn checkpoint<T: Serialize + DeserializeOwned>(
    path: &Path,
    proving: bool,
    new: &mut usize,
    reused: &mut usize,
    generate: impl FnOnce() -> Result<T, String>,
) -> Result<T, Box<dyn std::error::Error>> {
    if path.try_exists()? {
        *reused += 1;
    } else if proving {
        eprintln!(
            "Proving {}",
            path.file_name()
                .ok_or("missing filename")?
                .to_string_lossy()
        );
        write(path, &generate()?)?;
        *new += 1;
    }
    read(path)
}
fn array(values: &[u32]) -> Result<[u32; 256], String> {
    values
        .try_into()
        .map_err(|_| "expected 256 coefficients".into())
}
fn last(proof: &NttProof) -> Result<[u32; 256], String> {
    array(proof.stages.last().ok_or("missing NTT endpoint")?)
}
fn output_directory(
    matrix: &Path,
    out: &Path,
    proving: bool,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let canonical = if out.try_exists()? {
        out.canonicalize()?
    } else {
        let parent = out
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        parent
            .canonicalize()?
            .join(out.file_name().ok_or("missing output directory name")?)
    };
    if canonical.starts_with(matrix) {
        return Err("equation output must be outside the read-only matrix directory".into());
    }
    if proving && !canonical.try_exists()? {
        std::fs::create_dir(&canonical)?;
    }
    Ok(canonical)
}
fn matrix_oracle(rho: &[u8], row: u8, column: u8) -> Vec<u32> {
    let mut h = Shake128::default();
    h.update(rho);
    h.update(&[column, row]);
    let mut reader = h.finalize_xof();
    let mut out = Vec::new();
    while out.len() < 256 {
        let mut b = [0; 3];
        reader.read(&mut b);
        let v = u32::from_le_bytes([b[0], b[1], b[2], 0]) & 0x7fffff;
        if v < NTT_MODULUS {
            out.push(v);
        }
    }
    out
}
fn challenge_oracle(seed: &[u8]) -> Vec<i8> {
    let mut h = Shake256::default();
    h.update(seed);
    let mut reader = h.finalize_xof();
    let mut b = [0; 8];
    reader.read(&mut b);
    let mut signs = u64::from_le_bytes(b);
    let mut out = vec![0; 256];
    for i in 207..256 {
        let j = loop {
            let mut b = [0];
            reader.read(&mut b);
            if usize::from(b[0]) <= i {
                break usize::from(b[0]);
            }
        };
        out[i] = out[j];
        out[j] = if signs & 1 == 0 { 1 } else { -1 };
        signs >>= 1;
    }
    out
}
fn equation_oracle(x: &EquationInputs) -> Vec<Vec<u32>> {
    (0..6)
        .map(|row| {
            (0..256)
                .map(|i| {
                    let positive = (0..5)
                        .map(|col| {
                            i128::from(x.matrix_ntt[row * 5 + col][i]) * i128::from(x.z_ntt[col][i])
                        })
                        .sum::<i128>();
                    (positive
                        - i128::from(x.challenge_ntt[i]) * i128::from(x.t1_scaled_ntt[row][i]))
                    .rem_euclid(i128::from(NTT_MODULUS)) as u32
                })
                .collect()
        })
        .collect()
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
fn interpolation(input: &[u32; 256]) -> Vec<u32> {
    let q = u64::from(NTT_MODULUS);
    let mut sums = [0u64; 256];
    for (i, &v) in input.iter().enumerate() {
        let inverse_root = power(
            power(1753, 2 * u32::from((i as u8).reverse_bits()) + 1),
            NTT_MODULUS - 2,
        );
        let mut term = u64::from(v);
        for sum in &mut sums {
            *sum = (*sum + term) % q;
            term = term * inverse_root % q;
        }
    }
    let scale = power(256, NTT_MODULUS - 2);
    sums.iter().map(|&v| (v * scale % q) as u32).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, matrix_path, output_path] = args.as_slice() else {
        return Err("usage: mldsa-equation prove|verify matrix-dir equation-dir".into());
    };
    if mode != "prove" && mode != "verify" {
        return Err("invalid mode".into());
    }
    let proving = mode == "prove";
    let matrix_dir = Path::new(matrix_path).canonicalize()?;
    let out = output_directory(&matrix_dir, Path::new(output_path), proving)?;
    let id: Identity = read(&matrix_dir.join("identity.json"))?;
    if id.version != 1 || id.public_key.len() != 1952 || id.signature.len() != 3309 {
        return Err("invalid ML-DSA-65 identity".into());
    }
    if !MlDsaVerifier.verify(
        &id.public_key,
        &id.message,
        &PQSignature::new(SignatureType::MlDsa65, id.signature.clone()),
    )? {
        return Err("native signature control failed".into());
    }
    let saved_id = out.join("identity.json");
    if proving && !saved_id.try_exists()? {
        write(&saved_id, &id)?;
    }
    if read::<Identity>(&saved_id)? != id {
        return Err("equation identity differs from matrix input".into());
    }
    let mut added = 0;
    let mut reused = 0;
    let key: PublicKeyDecodeProof = checkpoint(
        &out.join("key.json"),
        proving,
        &mut added,
        &mut reused,
        || prove_public_key_decode(&id.public_key),
    )?;
    verify_public_key_decode(&key, &id.public_key)?;
    eprintln!("Verified key.json");
    let signature: SignatureDecodeProof = checkpoint(
        &out.join("signature.json"),
        proving,
        &mut added,
        &mut reused,
        || prove_signature_decode(&id.signature),
    )?;
    verify_signature_decode(&signature, &id.signature)?;
    eprintln!("Verified signature.json");
    let rho = &key.decoded.rho;
    let mut polynomials = Vec::new();
    let mut expected_matrix = Vec::new();
    eprintln!("Verifying complete existing 6x5 matrix (read-only)...");
    for row in 0..6 {
        for column in 0..5 {
            polynomials.push(read::<MatrixPolynomialProof>(
                &matrix_dir.join(format!("a-{row}-{column}.json")),
            )?);
            expected_matrix.push(matrix_oracle(rho, row, column));
        }
    }
    let matrix_permutations: usize = polynomials.iter().map(|p| p.xof.permutations.len()).sum();
    verify_matrix(
        &MatrixProof {
            batches: None,
            version: 1,
            rho: rho.clone(),
            polynomials,
        },
        rho,
        &expected_matrix,
    )?;
    eprintln!("Verified complete matrix");
    let c = challenge_oracle(&signature.decoded.challenge);
    let challenge: ChallengeProof = checkpoint(
        &out.join("challenge.json"),
        proving,
        &mut added,
        &mut reused,
        || prove_challenge(&signature.decoded.challenge),
    )?;
    verify_challenge(&challenge, &signature.decoded.challenge, &c)?;
    eprintln!("Verified challenge.json");
    let mut z_ntt = Vec::new();
    for col in 0..5 {
        let input = array(&signature.decoded.z[col])?;
        let p: NttProof = checkpoint(
            &out.join(format!("z-{col}.json")),
            proving,
            &mut added,
            &mut reused,
            || prove_ntt(&input),
        )?;
        let output = last(&p)?;
        verify_ntt(&p, &input, &output)?;
        z_ntt.push(output.to_vec());
        eprintln!("Verified z-{col}.json");
    }
    let mut t1_scaled_ntt = Vec::new();
    for row in 0..6 {
        let input = array(
            &key.decoded.t1[row]
                .iter()
                .map(|&v| u32::from(v) * 8192)
                .collect::<Vec<_>>(),
        )?;
        let p: NttProof = checkpoint(
            &out.join(format!("t-{row}.json")),
            proving,
            &mut added,
            &mut reused,
            || prove_ntt(&input),
        )?;
        let output = last(&p)?;
        verify_ntt(&p, &input, &output)?;
        t1_scaled_ntt.push(output.to_vec());
        eprintln!("Verified t-{row}.json");
    }
    let c_input = array(
        &c.iter()
            .map(|&v| {
                if v < 0 {
                    NTT_MODULUS - u32::from(v.unsigned_abs())
                } else {
                    v as u32
                }
            })
            .collect::<Vec<_>>(),
    )?;
    let c_ntt: NttProof = checkpoint(
        &out.join("c-ntt.json"),
        proving,
        &mut added,
        &mut reused,
        || prove_ntt(&c_input),
    )?;
    let c_output = last(&c_ntt)?;
    verify_ntt(&c_ntt, &c_input, &c_output)?;
    eprintln!("Verified c-ntt.json");
    let inputs = EquationInputs {
        matrix_ntt: expected_matrix,
        z_ntt,
        challenge_ntt: c_output.to_vec(),
        t1_scaled_ntt,
    };
    let equation: EquationProof = checkpoint(
        &out.join("equation.json"),
        proving,
        &mut added,
        &mut reused,
        || prove_equation(&inputs),
    )?;
    verify_equation(&equation, &inputs, &equation.output)?;
    eprintln!("Verified equation.json");
    if equation.output != equation_oracle(&inputs) {
        return Err("independent signed equation control differs".into());
    }
    let mut w_approx = Vec::new();
    for row in 0..6 {
        let input = array(&equation.output[row])?;
        let p: InverseNttProof = checkpoint(
            &out.join(format!("inverse-{row}.json")),
            proving,
            &mut added,
            &mut reused,
            || prove_inverse_ntt(&input),
        )?;
        let output = array(p.forward.stages.first().ok_or("missing inverse output")?)?;
        verify_inverse_ntt(&p, &input, &output)?;
        if output.as_slice() != interpolation(&input) {
            return Err("independent inverse interpolation differs".into());
        }
        w_approx.push(output.to_vec());
        eprintln!("Verified inverse-{row}.json");
    }
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"matrix_polynomials":30,"matrix_permutations":matrix_permutations,"encoding_certificates":2,"ntt_certificates":12,"inverse_certificates":6,"equation_coefficients":1536,"inverse_coefficients":1536,"newly_proved":added,"reused_component_proofs":reused,"existing_matrix_proofs_reused":30,"matrix_read_only":true,"saved_reload_verified":true,"native_signature_control":true,"full_equation_verified":true,"all_components_linked":true,"independent_signed_equation_verified":true,"independent_inverse_interpolation_verified":true,"w_approx_first_coefficients":w_approx.iter().map(|row|row[..4].to_vec()).collect::<Vec<_>>(),"norms_hints_final_challenge_checked":false,"full_signature_air_proved":false,"node_integrated":false})
    );
    Ok(())
}
