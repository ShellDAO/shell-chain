//! Immutable streamed full SHA2-256f signature certificates.
#[path = "support/slh_persistence.rs"]
mod persistence;
use persistence::{decode, encode, persist_xmss, read, write};
use shell_stark_prover::{
    sha2_compression::Sha2CompressionProof,
    slh_fors::{verify_fors, SlhForsInputs, SlhForsProof},
    slh_signature::{verify_slh_signature_using, SlhSignatureManifest, SlhSignatureOutput},
    slh_xmss::{verify_xmss, SlhXmssInputs, SlhXmssProof},
};
use std::{error::Error, path::Path};

fn layer(dir: &Path, at: u8) -> Result<SlhXmssProof, String> {
    decode(
        &read(
            &dir.join(format!("layer-{at:02}/xmss.cbor")),
            64 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
fn verify(
    manifest: &SlhSignatureManifest,
    input: &SlhForsInputs,
    fors: &SlhForsProof,
    dir: &Path,
) -> Result<SlhSignatureOutput, String> {
    verify_slh_signature_using(manifest, input, fors, |at, _| layer(dir, at))
}
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 3 {
        return Err("usage: slh-signature init input.json directory fors.cbor [layer0.cbor]; prove|resume|verify|refusals input.json directory".into());
    }
    let input: SlhForsInputs = serde_json::from_slice(&read(Path::new(&args[1]), 524_288)?)?;
    let dir = Path::new(&args[2]);
    let frozen = serde_json::to_vec(&input)?;
    if args[0] == "init" && matches!(args.len(), 4 | 5) {
        let bytes = read(Path::new(&args[3]), 128 * 1024 * 1024)?;
        let fors: SlhForsProof = decode(&bytes)?;
        let forest = verify_fors(&fors, &input)?;
        let imported = if args.len() == 5 {
            let bytes = read(Path::new(&args[4]), 64 * 1024 * 1024)?;
            let proof: SlhXmssProof = decode(&bytes)?;
            let expected = SlhXmssInputs {
                public_seed: input.public_seed,
                message: forest.fors_public_key,
                layer: 0,
                tree: forest.tree,
                leaf: forest.leaf,
                signature: input.signature[11_232..13_504].to_vec(),
            };
            verify_xmss(&proof, &expected)?;
            Some((bytes, proof))
        } else {
            None
        };
        std::fs::create_dir(dir)?;
        write(&dir.join("inputs.json"), &frozen)?;
        write(&dir.join("fors.cbor"), &bytes)?;
        if let Some((bytes, proof)) = imported {
            let target = dir.join("layer-00");
            std::fs::create_dir(&target)?;
            write(
                &target.join("inputs.json"),
                &serde_json::to_vec(&proof.inputs)?,
            )?;
            write(&target.join("xmss.cbor"), &bytes)?;
            write(&dir.join("seed-prefix.cbor"), &encode(&proof.prefix)?)?;
        }
        println!(
            "{}",
            serde_json::json!({"initialized":true,"FORS_verified":true,"imported_layer0":args.len()==5,"new_signing":false,"full_signature_verified":false})
        );
        return Ok(());
    }
    if args.len() != 3 || !matches!(args[0].as_str(), "prove" | "resume" | "verify" | "refusals") {
        return Err("invalid full SLH command or arguments".into());
    }
    if read(&dir.join("inputs.json"), 524_288)? != frozen {
        return Err("retained full SLH inputs differ; refusing replacement".into());
    }
    let fors: SlhForsProof = decode(&read(&dir.join("fors.cbor"), 128 * 1024 * 1024)?)?;
    let final_path = dir.join("signature.cbor");
    let mut generated_steps = 0usize;
    let mut recovered_steps = 0usize;
    let mut recovered_layers = 0usize;
    let manifest = if final_path.exists() {
        if args[0] == "prove" {
            return Err("original full SLH certificate exists; use resume".into());
        }
        decode::<SlhSignatureManifest>(&read(&final_path, 524_288)?)?
    } else {
        if !matches!(args[0].as_str(), "prove" | "resume") {
            return Err("full SLH manifest missing".into());
        }
        SlhSignatureManifest::new(input.clone())
    };
    if args[0] == "refusals" {
        verify(&manifest, &input, &fors, dir)?;
        let mut cases = Vec::new();
        for kind in 0..5 {
            let mut wrong = manifest.clone();
            match kind {
                0 => wrong.version = 2,
                1 => wrong.layers = 0,
                2 => wrong.layers = 16,
                3 => wrong.layers = 18,
                _ => wrong.inputs.message[0] ^= 1,
            }
            let error = verify(&wrong, &input, &fors, dir)
                .err()
                .ok_or("invalid manifest accepted")?;
            cases.push(serde_json::json!({"case":format!("manifest_{kind}"),"error":error}));
        }
        for field in 0..9 {
            let mut wrong = input.clone();
            match field {
                0 => wrong.message[0] ^= 1,
                1 => wrong.public_seed[0] ^= 1,
                2 => wrong.public_root[0] ^= 1,
                3 => wrong.signature[0] ^= 1,
                4 => wrong.signature[32] ^= 1,
                5 => wrong.signature[11_232] ^= 1,
                6 => wrong.signature[11_232 + 8 * 2272] ^= 1,
                7 => wrong.signature[49_855] ^= 1,
                _ => {
                    wrong.signature.pop();
                }
            }
            let mut rebound = fors.clone();
            rebound.inputs = wrong.clone();
            let error = verify(
                &SlhSignatureManifest::new(wrong.clone()),
                &wrong,
                &rebound,
                dir,
            )
            .err()
            .ok_or("rebound full signature accepted")?;
            cases.push(
                serde_json::json!({"case":format!("rebound_original_input_{field}"),"error":error}),
            );
        }
        for mode in 0..6 {
            let error = verify_slh_signature_using(&manifest, &input, &fors, |at, expected| {
                if mode == 0 && at == 16 {
                    return Err("missing last layer".into());
                }
                let mut proof = layer(
                    dir,
                    if (mode == 1 || mode == 2) && at == 1 {
                        2
                    } else {
                        at
                    },
                )?;
                if mode == 2 && at == 1 {
                    proof.inputs = expected.clone();
                }
                if mode == 3 && at == 8 {
                    proof.prefix.proof_bytes[0] ^= 1;
                }
                if mode == 4 && at == 16 {
                    proof.chains[0].proof_bytes[0] ^= 1;
                }
                if mode == 5 && at == 16 {
                    proof.authentication.swap(0, 1);
                }
                Ok(proof)
            })
            .err()
            .ok_or("invalid layer composition accepted")?;
            cases.push(
                serde_json::json!({"case":format!("layer_composition_{mode}"),"error":error}),
            );
        }
        println!(
            "{}",
            serde_json::json!({"refusals":cases,"canonical_admission":false})
        );
        return Ok(());
    }
    let output = if matches!(args[0].as_str(), "prove" | "resume") {
        let prefix_path = dir.join("seed-prefix.cbor");
        let mut prefix = if prefix_path.exists() {
            Some(decode::<Sha2CompressionProof>(&read(
                &prefix_path,
                8 * 1024 * 1024,
            )?)?)
        } else {
            None
        };
        let result = verify_slh_signature_using(&manifest, &input, &fors, |at, expected| {
            let target = dir.join(format!("layer-{at:02}"));
            let proof = if target.join("xmss.cbor").exists() {
                if read(&target.join("inputs.json"), 32_768).map_err(|e| e.to_string())?
                    != serde_json::to_vec(expected).map_err(|e| e.to_string())?
                {
                    return Err("retained layer inputs differ".into());
                }
                recovered_layers += 1;
                layer(dir, at)?
            } else {
                let (proof, new, old) = persist_xmss(expected, &target, true, prefix.as_ref())
                    .map_err(|e| e.to_string())?;
                generated_steps += new;
                recovered_steps += old;
                proof
            };
            // Authenticate an imported prefix against the derived first layer
            // before retaining it for other layers. The outer verifier repeats
            // the complete layer check before using its root in a transition.
            if prefix.is_none() {
                verify_xmss(&proof, expected)?;
                write(
                    &prefix_path,
                    &encode(&proof.prefix).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                prefix = Some(proof.prefix.clone());
            }
            eprintln!("layer {at}: certificate available; generated_steps={generated_steps}, recovered_steps={recovered_steps}, recovered_layers={recovered_layers}");
            Ok(proof)
        })?;
        let bytes = encode(&manifest)?;
        if final_path.exists() {
            if read(&final_path, 524_288)? != bytes {
                return Err("retained full SLH manifest differs".into());
            }
        } else {
            write(&final_path, &bytes)?;
        }
        result
    } else {
        verify(&manifest, &input, &fors, dir)?
    };
    println!(
        "{}",
        serde_json::json!({"root":output.root,"layer_roots":output.layer_roots,"layers":17,"generated_steps":generated_steps,"recovered_steps":recovered_steps,"recovered_layers":recovered_layers,"full_signature_verified":true,"canonical_admission":false,"new_signing":false})
    );
    Ok(())
}
