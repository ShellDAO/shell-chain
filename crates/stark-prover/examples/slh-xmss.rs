//! Persistent WOTS+/XMSS layer proofs with verified shared-prefix batches.
use shell_stark_prover::{
    sha2_compression::{
        prove_compression_batch, verify_compression_batch, Sha2Algorithm, Sha2CompressionProof,
    },
    slh_fors::{verify_fors, SlhForsInputs, SlhForsProof},
    slh_sha2::{prove_slh_sha2, verify_slh_sha2, SlhSha2Proof},
    slh_xmss::{prove_xmss_using, verify_xmss, SlhXmssInputs, SlhXmssProof},
};
use std::{
    error::Error,
    fs::OpenOptions,
    io::{Cursor, Read, Write},
    path::Path,
};
fn read(path: &Path, max: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let f = std::fs::File::open(path)?;
    if f.metadata()?.len() > max {
        return Err("XMSS input resource bound exceeded".into());
    }
    let mut bytes = Vec::new();
    f.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("XMSS input resource bound exceeded".into());
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err("trailing XMSS certificate data".into());
    }
    Ok(value)
}
fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 4 && args[0] == "from-fors" {
        let input: SlhForsInputs = serde_json::from_slice(&read(Path::new(&args[1]), 524_288)?)?;
        let proof: SlhForsProof = decode(&read(Path::new(&args[2]), 128 * 1024 * 1024)?)?;
        let output = verify_fors(&proof, &input)?;
        let layer = SlhXmssInputs {
            public_seed: input.public_seed,
            message: output.fors_public_key,
            layer: 0,
            tree: output.tree,
            leaf: output.leaf,
            signature: input.signature[11_232..13_504].to_vec(),
        };
        write(Path::new(&args[3]), &serde_json::to_vec(&layer)?)?;
        println!(
            "{}",
            serde_json::json!({"FORS_mathematical_proof_verified":true,"new_signing":false,"layer":0,"full_signature_verified":false})
        );
        return Ok(());
    }
    if args.len() != 3 || !matches!(args[0].as_str(), "prove" | "resume" | "verify" | "refusals") {
        return Err("usage: slh-xmss from-fors input.json fors.cbor layer.json; prove|resume layer.json directory; verify|refusals layer.json proof.cbor".into());
    }
    let input: SlhXmssInputs = serde_json::from_slice(&read(Path::new(&args[1]), 32_768)?)?;
    if args[0] == "refusals" {
        let mut proof: SlhXmssProof = decode(&read(Path::new(&args[2]), 64 * 1024 * 1024)?)?;
        verify_xmss(&proof, &input)?;
        let mut cases = Vec::new();
        macro_rules! refuse{($name:expr,$expected:expr)=>{{let error=verify_xmss(&proof,$expected).err().ok_or("invalid XMSS certificate accepted")?;cases.push(serde_json::json!({"case":$name,"error":error}));}};}
        proof.version = 2;
        refuse!("version", &input);
        proof.version = 1;
        let last = proof.chains.pop().ok_or("missing chain batches")?;
        refuse!("missing_chain_batch", &input);
        proof.chains.push(last);
        proof.chains.swap(0, 1);
        refuse!("genuine_foreign_ordered_F_batch", &input);
        proof.chains.swap(0, 1);
        proof.authentication.swap(0, 1);
        refuse!("genuine_foreign_authentication_hash", &input);
        proof.authentication.swap(0, 1);
        let auth = proof.authentication.pop().ok_or("missing auth")?;
        refuse!("missing_authentication", &input);
        proof.authentication.push(auth);
        for field in 0..8 {
            let mut wrong = input.clone();
            match field {
                0 => wrong.message[0] ^= 1,
                1 => wrong.public_seed[0] ^= 1,
                2 => wrong.tree ^= 1,
                3 => wrong.leaf ^= 1,
                4 => wrong.layer = (wrong.layer + 1) % 17,
                5 => wrong.signature[0] ^= 1,
                6 => wrong.signature[67 * 32] ^= 1,
                _ => wrong.signature[2271] ^= 1,
            };
            proof.inputs = wrong.clone();
            refuse!(format!("rebound_input_field_{field}"), &wrong);
            proof.inputs = input.clone();
        }
        proof.prefix.proof_bytes[0] ^= 1;
        refuse!("corrupt_prefix_air", &input);
        proof.prefix.proof_bytes[0] ^= 1;
        proof.chains[0].proof_bytes[0] ^= 1;
        refuse!("corrupt_chain_air", &input);
        println!(
            "{}",
            serde_json::json!({"refusals":cases,"full_signature_verified":false})
        );
        return Ok(());
    }
    let mut generated = 0usize;
    let mut recovered = 0usize;
    let proof = if matches!(args[0].as_str(), "prove" | "resume") {
        let dir = Path::new(&args[2]);
        let final_path = dir.join("xmss.cbor");
        if args[0] == "prove" && final_path.exists() {
            return Err("original XMSS proof exists; use resume to recheck".into());
        }
        std::fs::create_dir_all(dir)?;
        let frozen = dir.join("inputs.json");
        let bytes = serde_json::to_vec(&input)?;
        if frozen.exists() {
            if read(&frozen, 32_768)? != bytes {
                return Err("retained XMSS inputs differ; refusing replacement".into());
            }
        } else {
            if std::fs::read_dir(dir)?.next().is_some() {
                return Err("unowned nonempty XMSS output directory".into());
            }
            write(&frozen, &bytes)?;
        }
        // Separate counters avoid sharing mutable state between the providers.
        let mut c_new = 0usize;
        let mut c_old = 0usize;
        let mut h_new = 0usize;
        let mut h_old = 0usize;
        let proof = prove_xmss_using(
            &input,
            |at, inputs| {
                let path = dir.join(format!("compression-{at:03}.cbor"));
                if path.exists() {
                    c_old += 1;
                    return decode::<Sha2CompressionProof>(
                        &read(&path, 8 * 1024 * 1024).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string());
                }
                let proof = prove_compression_batch(Sha2Algorithm::Sha256, inputs)?;
                verify_compression_batch(&proof, Sha2Algorithm::Sha256, inputs)?;
                write(&path, &encode(&proof).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                c_new += 1;
                Ok(proof)
            },
            |at, request| {
                let path = dir.join(format!("hash-{at:03}.cbor"));
                if path.exists() {
                    h_old += 1;
                    return decode::<SlhSha2Proof>(
                        &read(&path, 16 * 1024 * 1024).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string());
                }
                let proof = prove_slh_sha2(request)?;
                verify_slh_sha2(&proof, request)?;
                write(&path, &encode(&proof).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                h_new += 1;
                Ok(proof)
            },
        )?;
        generated = c_new + h_new;
        recovered = c_old + h_old;
        verify_xmss(&proof, &input)?;
        let bytes = encode(&proof)?;
        if final_path.exists() {
            if read(&final_path, 64 * 1024 * 1024)? != bytes {
                return Err("retained XMSS certificate differs; refusing replacement".into());
            }
        } else {
            write(&final_path, &bytes)?;
        }
        proof
    } else {
        decode(&read(Path::new(&args[2]), 64 * 1024 * 1024)?)?
    };
    let root = verify_xmss(&proof, &input)?;
    println!(
        "{}",
        serde_json::json!({"root":root,"layer":input.layer,"F_batches":proof.chains.len(),"generated_steps":generated,"recovered_steps":recovered,"verified":true,"full_signature_verified":false,"canonical_admission":false})
    );
    Ok(())
}
