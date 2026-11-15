//! Separate arithmetic component production; never a Native finality certificate.
use serde::{de::DeserializeOwned, Serialize};
use shell_primitives::{Address, ShellHash};
use shell_stark_prover::weighted_quorum::{
    prove_quorum_weight_persistent, verify_quorum_weight, AuthorityWeight, QuorumWeightContext,
    QuorumWeightProof,
};
use shell_storage::RocksDbStore;
use std::{
    error::Error,
    io::{Read, Write},
    path::Path,
};

fn read<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T, Box<dyn Error>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("input exceeds arithmetic artifact bound".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn write(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    let bytes = serde_json::to_vec(value)?;
    if path.exists() {
        let mut existing = Vec::new();
        std::fs::File::open(path)?
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut existing)?;
        if existing == bytes {
            return Ok(());
        }
        return Err("refusing conflicting existing arithmetic output".into());
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sample") if args.len() == 2 => {
            let context = QuorumWeightContext {
                chain_id: 10, parent_hash: ShellHash::from([1; 32]),
                block_hash: ShellHash::from([2; 32]), block_number: 1,
                authorities: [2, 1, 1].into_iter().enumerate().map(|(i, weight)| AuthorityWeight { address: Address::from([i as u8 + 1; 32]), weight }).collect(),
                signers: vec![Address::from([1; 32]), Address::from([2; 32])],
            };
            write(Path::new(&args[1]), &context)?;
            println!("Public arithmetic sample only; no keys, signatures or Native block created.");
        }
        Some("prove") if args.len() == 4 => {
            let context: QuorumWeightContext = read(Path::new(&args[1]), 256 * 1024)?;
            let output = Path::new(&args[3]);
            // Check an existing output before opening any mutable job store.
            if output.exists() {
                let proof: QuorumWeightProof = read(output, 4 * 1024 * 1024)?;
                verify_quorum_weight(&proof, &context)?;
            }
            let stores = RocksDbStore::open_all(Path::new(&args[2]), None)?;
            let mut store = stores.chain;
            let (proof, progress) = prove_quorum_weight_persistent(&mut store, &context)?;
            let verified = verify_quorum_weight(&proof, &context)?;
            write(output, &proof)?;
            println!("{}", serde_json::json!({"arithmeticVerified":true,"nativeAuthorization":false,"total":verified.total(),"signed":verified.signed(),"progress":progress}));
        }
        Some("verify") if args.len() == 3 => {
            let context: QuorumWeightContext = read(Path::new(&args[1]), 256 * 1024)?;
            let proof: QuorumWeightProof = read(Path::new(&args[2]), 4 * 1024 * 1024)?;
            let verified = verify_quorum_weight(&proof, &context)?;
            println!("{}", serde_json::json!({"arithmeticVerified":true,"nativeAuthorization":false,"total":verified.total(),"signed":verified.signed()}));
        }
        _ => return Err("usage: weighted-quorum sample <context.json> | prove <context.json> <separate-job-db> <proof.json> | verify <context.json> <proof.json>".into()),
    }
    Ok(())
}
