//! Persistent full SHA2-256f FORS certificates with immutable verified steps.
use shell_core::SignedTransaction;
use shell_crypto::{MultiVerifier, SignatureType, Signer, SphincsSigner, Verifier};
use shell_stark_prover::{
    slh_fors::{prove_fors_using, verify_fors, SlhForsInputs, SlhForsProof},
    slh_sha2::{prove_slh_sha2, verify_slh_sha2, SlhSha2Proof},
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
        return Err("FORS input resource bound exceeded".into());
    }
    let mut bytes = Vec::new();
    f.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("FORS input resource bound exceeded".into());
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let mut reader = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut reader)?;
    if reader.position() != bytes.len() as u64 {
        return Err("trailing FORS certificate data".into());
    }
    Ok(value)
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    Ok(())
}
fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}
fn inputs(path: &Path) -> Result<SlhForsInputs, Box<dyn Error>> {
    Ok(serde_json::from_slice(&read(path, 524_288)?)?)
}
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 2 && args[0] == "sample" {
        if Path::new(&args[1]).exists() {
            return Err("original FORS inputs already exist".into());
        }
        let signer = SphincsSigner::generate();
        let message = *blake3::hash(b"SLH FORS standalone public regression").as_bytes();
        let sig = signer.sign(&message)?;
        let key = signer.public_key();
        if !MultiVerifier.verify(key, &message, &sig)? {
            return Err("sample signature refused".into());
        }
        let input = SlhForsInputs {
            public_seed: key[..32].try_into()?,
            public_root: key[32..].try_into()?,
            message,
            signature: sig.data,
        };
        write(Path::new(&args[1]), &serde_json::to_vec(&input)?)?;
        println!(
            "{}",
            serde_json::json!({"genuine_signature":true,"private_keys_persisted":false,"sample_is_not_native_chain_execution":true})
        );
        return Ok(());
    }
    if args.len() == 4 && args[0] == "native-input" {
        let tx: SignedTransaction = serde_json::from_slice(&read(Path::new(&args[1]), 262_144)?)?;
        let key: Vec<u8> = serde_json::from_slice(&read(Path::new(&args[2]), 4096)?)?;
        if key.len() != 64
            || tx.signature.sig_type != SignatureType::SphincsSha2256f
            || tx.signature.data.len() != 49_856
            || !MultiVerifier.verify(&key, tx.sender_signing_hash().as_bytes(), &tx.signature)?
        {
            return Err("invalid retained Native SLH inputs".into());
        }
        let input = SlhForsInputs {
            public_seed: key[..32].try_into()?,
            public_root: key[32..].try_into()?,
            message: *tx.sender_signing_hash().as_bytes(),
            signature: tx.signature.data,
        };
        write(Path::new(&args[3]), &serde_json::to_vec(&input)?)?;
        println!(
            "{}",
            serde_json::json!({"native_signature_inputs_verified":true,"signing_performed":false})
        );
        return Ok(());
    }
    if args.len() != 3 || !matches!(args[0].as_str(), "prove" | "resume" | "verify" | "refusals") {
        return Err("usage: slh-fors sample input.json; native-input signed.json public-key.json input.json; prove|resume input.json directory; verify|refusals input.json proof.cbor".into());
    }
    let input = inputs(Path::new(&args[1]))?;
    if args[0] == "refusals" {
        let mut proof: SlhForsProof = decode(&read(Path::new(&args[2]), 128 * 1024 * 1024)?)?;
        verify_fors(&proof, &input)?;
        let mut cases = Vec::new();
        macro_rules! refuse {($name:expr,$expected:expr)=>{{let error=verify_fors(&proof,$expected).err().ok_or("invalid FORS certificate accepted")?;cases.push(serde_json::json!({"case":$name,"error":error}));}};}
        proof.version = 2;
        refuse!("version", &input);
        proof.version = 1;
        let last = proof.hashes.pop().ok_or("empty FORS hashes")?;
        refuse!("missing_final_root_hash", &input);
        proof.hashes.push(last);
        proof.hashes.swap(1, 11);
        refuse!("genuine_foreign_tree_leaf_certificate", &input);
        proof.hashes.swap(1, 11);
        proof.hashes.swap(2, 3);
        refuse!("genuine_reordered_authentication_certificates", &input);
        proof.hashes.swap(2, 3);
        for (name, offset) in [
            ("randomizer", 0),
            ("FORS_secret", 32),
            ("first_authentication_node", 64),
            ("last_tree_last_authentication_node", 32 + 34 * 320 + 9 * 32),
            ("unproved_tail_envelope", 49_855),
        ] {
            let mut changed = input.clone();
            changed.signature[offset] ^= 1;
            refuse!(name, &changed);
            if name != "unproved_tail_envelope" {
                proof.inputs = changed.clone();
                refuse!(format!("{name}_with_rebound_envelope"), &changed);
                proof.inputs = input.clone();
            }
        }
        for field in 0..3 {
            let mut changed = input.clone();
            match field {
                0 => changed.message[0] ^= 1,
                1 => changed.public_seed[0] ^= 1,
                _ => changed.public_root[0] ^= 1,
            };
            proof.inputs = changed.clone();
            refuse!(format!("message_or_key_field_{field}"), &changed);
            proof.inputs = input.clone();
        }
        proof.hashes[1].digests[0].chunks[0].proof_bytes[0] ^= 1;
        refuse!("corrupt_compression_air", &input);
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
        let final_path = dir.join("fors.cbor");
        if args[0] == "prove" && final_path.exists() {
            return Err("original FORS proof already exists; use resume to recheck".into());
        }
        std::fs::create_dir_all(dir)?;
        let frozen = dir.join("inputs.json");
        let bytes = serde_json::to_vec(&input)?;
        if frozen.exists() {
            if read(&frozen, 524_288)? != bytes {
                return Err("retained FORS inputs differ; refusing replacement".into());
            }
        } else {
            if std::fs::read_dir(dir)?.next().is_some() {
                return Err("unowned nonempty FORS output directory".into());
            }
            write(&frozen, &bytes)?;
        }
        let proof = prove_fors_using(&input, |at, request| {
            let path = dir.join(format!("step-{at:03}.cbor"));
            let proof = if path.exists() {
                recovered += 1;
                decode::<SlhSha2Proof>(&read(&path, 16 * 1024 * 1024).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?
            } else {
                let proof = prove_slh_sha2(request)?;
                verify_slh_sha2(&proof, request)?;
                write(&path, &encode(&proof).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                generated += 1;
                proof
            };
            Ok(proof)
        })?;
        verify_fors(&proof, &input)?;
        let bytes = encode(&proof)?;
        if final_path.exists() {
            if read(&final_path, 128 * 1024 * 1024)? != bytes {
                return Err("retained full FORS certificate differs; refusing replacement".into());
            }
        } else {
            write(&final_path, &bytes)?;
        }
        proof
    } else {
        decode(&read(Path::new(&args[2]), 128 * 1024 * 1024)?)?
    };
    let output = verify_fors(&proof, &input)?;
    println!(
        "{}",
        serde_json::json!({"output":output,"generated_steps":generated,"recovered_steps":recovered,"verified":true,"full_signature_verified":false,"FORS_only_not_canonical_admission":true})
    );
    Ok(())
}
