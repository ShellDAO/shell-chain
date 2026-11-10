//! Persistent FIPS205 verification-hash certificates; not full signature proofs.
use shell_core::SignedTransaction;
use shell_crypto::{MultiVerifier, SignatureType, Verifier};
use shell_stark_prover::slh_sha2::{prove_slh_sha2, verify_slh_sha2, SlhSha2Proof, SlhSha2Request};
use std::{
    error::Error,
    fs::OpenOptions,
    io::{Cursor, Read, Write},
    path::Path,
};

fn read(path: &str, max: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = std::fs::File::open(Path::new(path))?;
    if file.metadata()?.len() > max {
        return Err("SLH SHA2 input resource bound exceeded".into());
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("SLH SHA2 input resource bound exceeded".into());
    }
    Ok(bytes)
}

fn exclusive_write(path: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 4 && args[0] == "native-hmsg" {
        // Read-only export from retained public inputs. No signer, secret key,
        // randomness or replacement signature is created. Native verification
        // here validates export inputs; hash-proof acceptance below never calls it.
        let tx: SignedTransaction = serde_json::from_slice(&read(&args[1], 262_144)?)?;
        let key: Vec<u8> = serde_json::from_slice(&read(&args[2], 4096)?)?;
        if key.len() != 64
            || tx.signature.sig_type != SignatureType::SphincsSha2256f
            || tx.signature.data.len() != 49_856
            || !MultiVerifier.verify(&key, tx.sender_signing_hash().as_bytes(), &tx.signature)?
        {
            return Err("invalid retained Native SLH public inputs".into());
        }
        let request = SlhSha2Request::Message {
            randomizer: tx.signature.data[..32].try_into()?,
            public_seed: key[..32].try_into()?,
            public_root: key[32..].try_into()?,
            message: *tx.sender_signing_hash().as_bytes(),
        };
        exclusive_write(&args[3], &serde_json::to_vec_pretty(&request)?)?;
        println!(
            "{}",
            serde_json::json!({"native_inputs_verified":true,"hash_request_only_not_signature_proof":true})
        );
        return Ok(());
    }
    if args.len() != 3 || !matches!(args[0].as_str(), "prove" | "verify") {
        return Err("usage: slh-sha2 prove|verify request.json proof.cbor; slh-sha2 native-hmsg signed.json public-key.json request.json".into());
    }
    let request: SlhSha2Request = serde_json::from_slice(&read(&args[1], 65_536)?)?;
    let proof = if args[0] == "prove" {
        prove_slh_sha2(&request)?
    } else {
        let bytes = read(&args[2], 16 * 1024 * 1024)?;
        let mut reader = Cursor::new(bytes.as_slice());
        let proof: SlhSha2Proof = ciborium::from_reader(&mut reader)?;
        if reader.position() != bytes.len() as u64 {
            return Err("trailing SLH SHA2 certificate data".into());
        }
        proof
    };
    let digest = verify_slh_sha2(&proof, &request)?;
    if args[0] == "prove" {
        let mut bytes = Vec::new();
        ciborium::into_writer(&proof, &mut bytes)?;
        exclusive_write(&args[2], &bytes)?;
    }
    println!(
        "{}",
        serde_json::json!({"digest":digest,"verified":true,"hash_only_not_signature_admission":true})
    );
    Ok(())
}
