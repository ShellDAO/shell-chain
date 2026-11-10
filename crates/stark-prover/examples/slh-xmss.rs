//! Persistent WOTS+/XMSS layer proofs with verified shared-prefix batches.
#[path = "support/slh_persistence.rs"]
mod persistence;
use persistence::{decode, persist_xmss, read, write};
use shell_stark_prover::{
    slh_fors::{verify_fors, SlhForsInputs, SlhForsProof},
    slh_xmss::{verify_xmss, SlhXmssInputs, SlhXmssProof},
};
use std::{error::Error, path::Path};
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
        let (proof, new, old) =
            persist_xmss(&input, Path::new(&args[2]), args[0] == "resume", None)?;
        generated = new;
        recovered = old;
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
