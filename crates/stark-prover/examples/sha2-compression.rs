//! Persistent complete SHA2 compression certificates with independently bound inputs.
use serde::Deserialize;
use shell_stark_prover::sha2_compression::{
    prove_compression_batch, verify_compression_batch, CompressionInput, Sha2Algorithm,
    Sha2CompressionProof,
};
use std::{
    error::Error,
    fs::OpenOptions,
    io::{Cursor, Read, Write},
    path::Path,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    algorithm: Sha2Algorithm,
    inputs: Vec<CompressionInput>,
}

fn bounded_read(path: &Path, max: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > max {
        return Err("SHA2 certificate input resource bound exceeded".into());
    }
    // Bound the actual read as well, including a file concurrently enlarged.
    let mut bytes = Vec::new();
    std::io::Read::take(file, max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("SHA2 certificate input resource bound exceeded".into());
    }
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 || !matches!(args[0].as_str(), "prove" | "verify") {
        return Err("usage: sha2-compression prove|verify inputs.json proof.cbor".into());
    }
    let inputs: Inputs = serde_json::from_slice(&bounded_read(Path::new(&args[1]), 65_536)?)?;
    let proof = if args[0] == "prove" {
        prove_compression_batch(inputs.algorithm, &inputs.inputs)?
    } else {
        let bytes = bounded_read(Path::new(&args[2]), 8 * 1024 * 1024)?;
        let mut reader = Cursor::new(bytes.as_slice());
        let proof: Sha2CompressionProof = ciborium::from_reader(&mut reader)?;
        if reader.position() != bytes.len() as u64 {
            return Err("trailing SHA2 certificate data".into());
        }
        proof
    };
    let outputs = verify_compression_batch(&proof, inputs.algorithm, &inputs.inputs)?;
    if args[0] == "prove" {
        // Never replace an original certificate or create output before proving.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[2])?;
        ciborium::into_writer(&proof, &mut file)?;
        file.flush()?;
        file.sync_all()?;
    }
    println!(
        "{}",
        serde_json::json!({"algorithm":inputs.algorithm,"outputs":outputs,"verified":true,"compression_only_not_signature_admission":true})
    );
    Ok(())
}
