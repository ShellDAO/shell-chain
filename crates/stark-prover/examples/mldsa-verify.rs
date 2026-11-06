//! Persist, reload and verify a complete public ML-DSA-65 signature certificate.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shell_crypto::{MlDsaVerifier, PQSignature, SignatureType, Verifier};
use shell_stark_prover::{
    mldsa_decode::{prove_signature_decode, SignatureDecodeProof},
    mldsa_finish::{prove_finish, FinishProof},
    mldsa_matrix::{MatrixPolynomialProof, MatrixProof},
    mldsa_verification::{
        verify_completion, verify_equation_pipeline, verify_mldsa65, CompletionProof,
        EquationPipeline, Mldsa65VerificationProof, MAX_MESSAGE_BYTES,
    },
    shake_sponge::{prove_shake, verify_shake, ShakeKind, ShakeProof},
};
use std::{
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};
type Error = Box<dyn std::error::Error>;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u8,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_reader(BufReader::new(
        std::fs::File::open(path)?,
    ))?)
}
fn write<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
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
    generate: impl FnOnce() -> Result<T, String>,
) -> Result<T, Error> {
    if !path.try_exists()? && proving {
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
fn output_directory(inputs: &[&Path], out: &Path, proving: bool) -> Result<PathBuf, Error> {
    let canonical = if out.try_exists()? {
        out.canonicalize()?
    } else {
        out.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?
            .join(out.file_name().ok_or("missing output name")?)
    };
    if inputs
        .iter()
        .any(|input| canonical.starts_with(input) || input.starts_with(&canonical))
    {
        return Err("output must be separate from the read-only input directories".into());
    }
    if proving && !canonical.try_exists()? {
        std::fs::create_dir(&canonical)?;
    }
    Ok(canonical)
}
fn identity(dir: &Path) -> Result<Identity, Error> {
    let id: Identity = read(&dir.join("identity.json"))?;
    if id.version != 1
        || id.public_key.len() != 1952
        || id.signature.len() != 3309
        || id.message.len() > MAX_MESSAGE_BYTES
    {
        return Err("unsupported ML-DSA-65 identity or message size".into());
    }
    Ok(id)
}
fn load_pipeline(matrix: &Path, equation: &Path) -> Result<EquationPipeline, Error> {
    let key =
        read::<shell_stark_prover::mldsa_key::PublicKeyDecodeProof>(&equation.join("key.json"))?;
    let mut polynomials = Vec::new();
    for row in 0..6 {
        for column in 0..5 {
            polynomials.push(read::<MatrixPolynomialProof>(
                &matrix.join(format!("a-{row}-{column}.json")),
            )?);
        }
    }
    Ok(EquationPipeline {
        matrix: MatrixProof {
            version: 1,
            rho: key.decoded.rho.clone(),
            polynomials,
        },
        key,
        signature: read(&equation.join("signature.json"))?,
        challenge: read(&equation.join("challenge.json"))?,
        z_ntt: (0..5)
            .map(|i| read(&equation.join(format!("z-{i}.json"))))
            .collect::<Result<_, _>>()?,
        t1_ntt: (0..6)
            .map(|i| read(&equation.join(format!("t-{i}.json"))))
            .collect::<Result<_, _>>()?,
        c_ntt: read(&equation.join("c-ntt.json"))?,
        equation: read(&equation.join("equation.json"))?,
        inverse: (0..6)
            .map(|i| read(&equation.join(format!("inverse-{i}.json"))))
            .collect::<Result<_, _>>()?,
    })
}
fn completion(out: &Path) -> Result<CompletionProof, Error> {
    Ok(CompletionProof {
        finish: read(&out.join("finish.json"))?,
        tr: read(&out.join("tr.json"))?,
        mu: read(&out.join("mu.json"))?,
        commitment: read(&out.join("commitment.json"))?,
    })
}
fn native(id: &Identity) -> Result<bool, Error> {
    Ok(MlDsaVerifier.verify(
        &id.public_key,
        &id.message,
        &PQSignature::new(SignatureType::MlDsa65, id.signature.clone()),
    )?)
}
fn check_rejections(pipeline: &EquationPipeline, id: &Identity, out: &Path) -> Result<(), Error> {
    let token = verify_equation_pipeline(pipeline, &id.public_key, &id.signature)?;
    let good = completion(out)?;
    verify_completion(&token, &id.message, &good)?;
    let mut rejected = Vec::new();
    for case in 0..8 {
        let mut p = good.clone();
        let mut message = id.message.clone();
        let (name, phase) = match case {
            0 => {
                p.finish.inputs.hints[5][255] ^= 1;
                ("authenticated_hint", "finish constraints:")
            }
            1 => {
                p.finish.inputs.z[4][255] ^= 1;
                ("authenticated_z", "finish constraints:")
            }
            2 => {
                p.finish.w1[5][255] ^= 1;
                ("last_hint_output", "finish constraints:")
            }
            3 => {
                p.finish.encoded[767] ^= 1;
                ("last_packed_byte", "finish constraints:")
            }
            4 => {
                p.tr.output[63] ^= 1;
                ("tr_hash", "tr hash:")
            }
            5 => {
                p.mu.output[63] ^= 1;
                ("mu_hash", "mu hash:")
            }
            6 => {
                message.push(0);
                ("expected_message", "mu hash:")
            }
            _ => {
                p.commitment.sponge_proof_bytes.truncate(10);
                ("final_hash_proof", "final commitment:")
            }
        };
        let error = verify_completion(&token, &message, &p)
            .err()
            .ok_or("tampered completion was accepted")?;
        if !error.starts_with(phase) {
            return Err(format!("{name}: unexpected phase: {error}").into());
        }
        rejected.push(serde_json::json!({"case":name,"error":error}));
    }
    let mut key = id.public_key.clone();
    key[0] ^= 1;
    let error = verify_equation_pipeline(pipeline, &key, &id.signature)
        .err()
        .ok_or("foreign expected key accepted")?;
    if !error.starts_with("public key:") {
        return Err(error.into());
    }
    rejected.push(serde_json::json!({"case":"expected_key","error":error}));
    let mut signature = id.signature.clone();
    signature[0] ^= 1;
    let error = verify_equation_pipeline(pipeline, &id.public_key, &signature)
        .err()
        .ok_or("foreign expected signature accepted")?;
    if !error.starts_with("signature encoding:") {
        return Err(error.into());
    }
    rejected.push(serde_json::json!({"case":"expected_signature","error":error}));
    let p = Mldsa65VerificationProof {
        version: 1,
        equation: pipeline.clone(),
        completion: good,
    };
    let error = verify_mldsa65(
        &p,
        &id.public_key,
        &vec![0; MAX_MESSAGE_BYTES + 1],
        &id.signature,
    )
    .err()
    .ok_or("oversized message accepted")?;
    rejected.push(serde_json::json!({"case":"oversized_message","error":error}));
    println!(
        "{}",
        serde_json::json!({"mode":"check-rejections","valid_prefix_and_completion_verified":true,"rejected":rejected,"proofs_generated":0,"input_directories_read_only":true})
    );
    Ok(())
}
fn reject_hint(
    mut pipeline: EquationPipeline,
    id: &Identity,
    good: &Path,
    out: &Path,
) -> Result<(), Error> {
    let mut bad = id.clone();
    let mut hints = pipeline.signature.decoded.hints.clone();
    if let Some(index) = hints.iter().flatten().position(|&h| h == 1) {
        hints[index / 256][index % 256] = 0;
    } else {
        hints[0][0] = 1;
    }
    // Preserve canonical sparse hint encoding: sorted indices and cumulative ends.
    let mut indices = Vec::new();
    let mut ends = Vec::new();
    for row in &hints {
        for (i, &h) in row.iter().enumerate() {
            if h == 1 {
                indices.push(i as u8);
            }
        }
        ends.push(indices.len() as u8);
    }
    if indices.len() > 55 {
        return Err("hint alteration exceeded weight limit".into());
    }
    indices.resize(55, 0);
    indices.extend_from_slice(&ends);
    bad.signature[3248..].copy_from_slice(&indices);
    if !out.join("identity.json").try_exists()? {
        write(&out.join("identity.json"), &bad)?;
    }
    if identity(out)? != bad {
        return Err("altered-hint checkpoint identity differs".into());
    }
    let mut new = 0;
    pipeline.signature =
        checkpoint::<SignatureDecodeProof>(&out.join("signature.json"), true, &mut new, || {
            prove_signature_decode(&bad.signature)
        })?;
    eprintln!("Verifying valid altered-hint equation prefix");
    let token = verify_equation_pipeline(&pipeline, &bad.public_key, &bad.signature)?;
    let finish: FinishProof = checkpoint(&out.join("finish.json"), true, &mut new, || {
        prove_finish(token.finish_inputs())
    })?;
    let good = completion(good)?;
    if finish.encoded == good.finish.encoded {
        return Err("hint alteration did not change w1".into());
    }
    let mut input = good.mu.output.clone();
    input.extend_from_slice(&finish.encoded);
    let commitment: ShakeProof = checkpoint(&out.join("commitment.json"), true, &mut new, || {
        prove_shake(ShakeKind::Shake256, &input, 48)
    })?;
    // Prove the altered computation honestly, then require the original c-tilde.
    verify_shake(&commitment, ShakeKind::Shake256, &input, &commitment.output)?;
    if commitment.output == token.challenge_seed() {
        return Err("unexpected challenge collision".into());
    }
    let p = CompletionProof {
        finish,
        tr: good.tr,
        mu: good.mu,
        commitment,
    };
    let error = verify_completion(&token, &bad.message, &p)
        .expect_err("altered hint must fail the original final commitment");
    if !error.starts_with("final commitment:") {
        return Err(format!("unexpected rejection phase: {error}").into());
    }
    // Independent native control is evaluated after the production proof path.
    if native(&bad)? {
        return Err("native altered-hint control unexpectedly accepted".into());
    }
    println!(
        "{}",
        serde_json::json!({"mode":"reject-hint-tamper","canonical_encoding_proved":true,"entire_equation_prefix_verified":true,"new_hint_and_norm_air_verified":true,"honest_changed_hash_certificate_verified":true,"original_challenge_rejected":true,"rejection":error,"native_control_rejected":true,"newly_proved":new,"input_directories_read_only":true})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 && args.len() != 5 {
        return Err("usage: mldsa-verify prove|verify matrix-dir equation-dir signature-dir; mldsa-verify reject-hint-tamper matrix-dir equation-dir signature-dir rejection-dir".into());
    }
    let mode = &args[0];
    if mode != "prove"
        && mode != "verify"
        && mode != "reject-hint-tamper"
        && mode != "check-rejections"
    {
        return Err("invalid mode".into());
    }
    if (mode == "reject-hint-tamper") != (args.len() == 5) {
        return Err("invalid mode arguments".into());
    }
    let proving = mode == "prove";
    let matrix = Path::new(&args[1]).canonicalize()?;
    let equation = Path::new(&args[2]).canonicalize()?;
    let out = output_directory(&[&matrix, &equation], Path::new(&args[3]), proving)?;
    let id = identity(&matrix)?;
    if identity(&equation)? != id {
        return Err("matrix and equation identities differ".into());
    }
    let pipeline = load_pipeline(&matrix, &equation)?;
    if mode == "reject-hint-tamper" {
        if identity(&out)? != id {
            return Err("completion identity differs".into());
        }
        let rejection = output_directory(&[&matrix, &equation, &out], Path::new(&args[4]), true)?;
        return reject_hint(pipeline, &id, &out, &rejection);
    }
    if proving && !out.join("identity.json").try_exists()? {
        write(&out.join("identity.json"), &id)?;
    }
    if identity(&out)? != id {
        return Err("completion identity differs".into());
    }
    if mode == "check-rejections" {
        return check_rejections(&pipeline, &id, &out);
    }
    let mut new = 0;
    let p = if proving {
        eprintln!("Verifying existing complete equation prefix (read-only)");
        let token = verify_equation_pipeline(&pipeline, &id.public_key, &id.signature)?;
        let finish: FinishProof = checkpoint(&out.join("finish.json"), true, &mut new, || {
            prove_finish(token.finish_inputs())
        })?;
        let tr: ShakeProof = checkpoint(&out.join("tr.json"), true, &mut new, || {
            prove_shake(ShakeKind::Shake256, token.public_key(), 64)
        })?;
        let mut mu_input = tr.output.clone();
        mu_input.extend_from_slice(&[0, 0]);
        mu_input.extend_from_slice(&id.message);
        let mu: ShakeProof = checkpoint(&out.join("mu.json"), true, &mut new, || {
            prove_shake(ShakeKind::Shake256, &mu_input, 64)
        })?;
        let mut input = mu.output.clone();
        input.extend_from_slice(&finish.encoded);
        let commitment: ShakeProof =
            checkpoint(&out.join("commitment.json"), true, &mut new, || {
                prove_shake(ShakeKind::Shake256, &input, 48)
            })?;
        let p = CompletionProof {
            finish,
            tr,
            mu,
            commitment,
        };
        verify_completion(&token, &id.message, &p)?;
        p
    } else {
        let p = Mldsa65VerificationProof {
            version: 1,
            equation: pipeline,
            completion: completion(&out)?,
        };
        verify_mldsa65(&p, &id.public_key, &id.message, &id.signature)?;
        p.completion
    };
    if !native(&id)? {
        return Err("independent native signature control failed".into());
    }
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"algorithm":"ML-DSA-65","context_bytes":0,"message_bytes":id.message.len(),"max_message_bytes":MAX_MESSAGE_BYTES,"newly_proved":new,"completion_files":5,"reused_matrix_certificates":30,"reused_equation_certificates":22,"completion_keccak_permutations":p.tr.permutations.len()+p.mu.permutations.len()+p.commitment.permutations.len(),"all_norms_hints_encoding_hashes_verified":true,"full_signature_air_proved":true,"saved_reload_verified":true,"independent_native_control":true,"inputs_read_only":true,"public_states":true,"canonical_source_proved":false,"private_witness":false,"node_integrated":false})
    );
    Ok(())
}
