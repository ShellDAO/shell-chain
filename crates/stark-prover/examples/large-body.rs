//! Complete original large native envelope, small signing hash and stable ID.
#[path = "support/certificate_io.rs"]
mod io;
use io::{decode, encode, read, write};
use serde::{Deserialize, Serialize};
use shell_core::{
    block_body_leaf_message, block_body_root, Block, BlockHeader, PubkeyMode, SignedTransaction,
    Transaction, PQTX_ID_DOMAIN,
};
use shell_crypto::{MultiVerifier, Signer, SphincsSigner, Verifier};
use shell_primitives::{Address, Bytes, ShellHash, U256};
use shell_stark_prover::{
    blake3_hash::{
        prove_compression, prove_hash, prove_large_body_hash_using, verify_compression,
        verify_hash, verify_large_body_hash, Blake3HashProof, CompressionProof,
    },
    body_membership::{
        prove_large_transaction_body_using, verify_large_transaction_envelope,
        verify_transaction_body, LargeTransactionEnvelopeProof,
    },
};
use std::{error::Error, path::Path};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    block: Block,
    index: usize,
    transaction_id: ShellHash,
}
fn checked(input: &Inputs) -> Result<&SignedTransaction, Box<dyn Error>> {
    let tx = input
        .block
        .transactions
        .get(input.index)
        .ok_or("ordinary target absent")?;
    if tx.tx.tx_type > 3 || tx.aa_bundle.is_some() {
        return Err("unsupported envelope signing profile".into());
    }
    Ok(tx)
}
fn identity(tx: &SignedTransaction, signing: &[u8; 32]) -> Vec<u8> {
    let mut bytes = PQTX_ID_DOMAIN.to_vec();
    bytes.extend_from_slice(tx.from.as_bytes());
    bytes.extend_from_slice(signing);
    bytes
}
fn verify(proof: &LargeTransactionEnvelopeProof, input: &Inputs) -> Result<(), Box<dyn Error>> {
    verify_large_transaction_envelope(
        proof,
        &input.block.header,
        checked(input)?,
        input.index as u64,
        &input.transaction_id,
    )?;
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 2 && args[0] == "sample" {
        if Path::new(&args[1]).exists() {
            return Err("original inputs exist".into());
        }
        let signer = SphincsSigner::generate();
        let tx = Transaction {
            chain_id: 10,
            nonce: 0,
            to: Some(Address::from([2; 32])),
            value: U256::from(1),
            data: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 0,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let key = signer.public_key().to_vec();
        let signature = signer.sign(tx.signing_hash(signer.sig_type().as_u8()).as_bytes())?;
        if !MultiVerifier.verify(
            &key,
            tx.signing_hash(signature.sig_type.as_u8()).as_bytes(),
            &signature,
        )? {
            return Err("genuine sample refused".into());
        }
        let mut tagged = vec![signature.sig_type.as_u8()];
        tagged.extend_from_slice(&key);
        let sender = Address::from(*blake3::hash(&tagged).as_bytes());
        let signed = SignedTransaction::with_pubkey(sender, tx, signature, key);
        let transaction_id = signed.uncached_hash();
        let transactions = vec![signed];
        let header = BlockHeader {
            number: 1,
            transactions_root: block_body_root(&transactions, &[])?,
            ..Default::default()
        };
        let input = Inputs {
            block: Block {
                header,
                transactions,
                system_transactions: vec![],
                proposer_seal: None,
            },
            index: 0,
            transaction_id,
        };
        write(Path::new(&args[1]), &serde_json::to_vec(&input)?)?;
        println!(
            "{}",
            serde_json::json!({"genuine_signature":true,"private_keys_persisted":false,"native_chain_execution":false})
        );
        return Ok(());
    }
    if args.len() == 4 && args[0] == "export" {
        let block: Block = serde_json::from_slice(&read(Path::new(&args[1]), 1_048_576)?)?;
        let index = args[2].parse::<usize>()?;
        let tx = block
            .transactions
            .get(index)
            .ok_or("ordinary target absent")?;
        let transaction_id = tx.uncached_hash();
        if block_body_root(&block.transactions, &block.system_transactions)?
            != block.header.transactions_root
        {
            return Err("original body/header root mismatch".into());
        }
        let input = Inputs {
            block,
            index,
            transaction_id,
        };
        checked(&input)?;
        write(Path::new(&args[3]), &serde_json::to_vec(&input)?)?;
        println!(
            "{}",
            serde_json::json!({"exported":true,"new_signing":false,"transaction_id":transaction_id})
        );
        return Ok(());
    }
    if args.len() == 2 && args[0] == "inspect" {
        let input: Inputs = serde_json::from_slice(&read(Path::new(&args[1]), 1_048_576)?)?;
        let tx = checked(&input)?;
        let bytes = block_body_leaf_message(tx, input.index as u64);
        println!(
            "{}",
            serde_json::json!({"native_reference_only":true,"AIR_verified":false,"transaction_id":tx.uncached_hash(),"signing_hash":tx.sender_signing_hash(),"leaf_hash":blake3::hash(&bytes).as_bytes(),"leaf_bytes":bytes.len(),"signing_bytes":tx.tx.signing_payload(tx.signature.sig_type.as_u8()).len(),"identity_bytes":identity(tx,tx.sender_signing_hash().as_bytes()).len(),"body_root":input.block.header.transactions_root})
        );
        return Ok(());
    }
    if args.len() != 3 || !matches!(args[0].as_str(), "prove" | "resume" | "verify" | "refusals") {
        return Err("usage: large-body sample input.json; export block.json index input.json; prove|resume|verify|refusals input.json directory".into());
    }
    let input: Inputs = serde_json::from_slice(&read(Path::new(&args[1]), 1_048_576)?)?;
    let tx = checked(&input)?;
    let dir = Path::new(&args[2]);
    let final_path = dir.join("envelope.cbor");
    if args[0] == "refusals" {
        let mut proof: LargeTransactionEnvelopeProof =
            decode(&read(&final_path, 512 * 1024 * 1024)?)?;
        verify(&proof, &input)?;
        if tx.signature.data.is_empty() || proof.body.leaf.compressions.len() < 2 {
            return Err(
                "refusal controls require a signature witness and multiple leaf compressions"
                    .into(),
            );
        }
        let mut cases = Vec::new();
        macro_rules! refuse{($name:expr,$expected:expr)=>{{let error=verify(&proof,$expected).err().ok_or("invalid envelope accepted")?;cases.push(serde_json::json!({"case":$name,"error":error.to_string()}));}};}
        proof.version = 2;
        refuse!("envelope_version", &input);
        proof.version = 1;
        proof.body.version = 1;
        refuse!("legacy_body_profile", &input);
        proof.body.version = 2;
        proof.body.leaf.version = 2;
        refuse!("legacy_leaf_hash_profile", &input);
        proof.body.leaf.version = 3;
        if verify_transaction_body(&proof.body, &input.block.header, tx, input.index as u64).is_ok()
        {
            return Err("legacy membership accepted large profile".into());
        }
        cases.push(serde_json::json!({"case":"large_refused_by_legacy_membership","error":"explicit version/size guard"}));
        for field in 0..9 {
            let mut wrong = input.clone();
            match field {
                0 => wrong.block.transactions[wrong.index].signature.data[0] ^= 1,
                1 => {
                    *wrong.block.transactions[wrong.index]
                        .signature
                        .data
                        .last_mut()
                        .ok_or("empty signature witness")? ^= 1
                }
                2 => wrong.block.transactions[wrong.index].from.0[0] ^= 1,
                3 => wrong.block.transactions[wrong.index].tx.nonce ^= 1,
                4 => wrong.block.header.transactions_root.0[0] ^= 1,
                5 => wrong.transaction_id.0[0] ^= 1,
                6 => wrong.index += 1,
                7 => {
                    let mode = &mut wrong.block.transactions[wrong.index].pubkey_mode;
                    match mode {
                        PubkeyMode::Reference => *mode = PubkeyMode::Embedded(vec![4; 64]),
                        PubkeyMode::Embedded(bytes) => {
                            if bytes.is_empty() {
                                bytes.push(1);
                            } else {
                                bytes[0] ^= 1;
                            }
                        }
                    }
                }
                _ => wrong.block.transactions[wrong.index].tx.value ^= U256::from(1),
            };
            refuse!(format!("original_field_{field}"), &wrong);
        }
        proof.body.path.index ^= 1;
        refuse!("path_index", &input);
        proof.body.path.index ^= 1;
        proof.body.path.total += 1;
        refuse!("path_total", &input);
        proof.body.path.total -= 1;
        if let Some(sibling) = proof.body.path.siblings.first_mut() {
            let old = *sibling;
            sibling.0[0] ^= 1;
            refuse!("sibling", &input);
            proof.body.path.siblings[0] = old;
        }
        let last = proof
            .body
            .leaf
            .compressions
            .pop()
            .ok_or("missing leaf compression")?;
        refuse!("missing_last_compression", &input);
        proof.body.leaf.compressions.push(last);
        proof.body.leaf.compressions.swap(0, 1);
        refuse!("genuine_reordered_compressions", &input);
        proof.body.leaf.compressions.swap(0, 1);
        proof.body.leaf.compressions[0].proof_bytes[0] ^= 1;
        refuse!("corrupt_compression_air", &input);
        proof.body.leaf.compressions[0].proof_bytes[0] ^= 1;
        proof.transaction_id = proof.signing_hash.clone();
        refuse!("genuine_foreign_identity_proof", &input);
        println!(
            "{}",
            serde_json::json!({"refusals":cases,"canonical_admission":false})
        );
        return Ok(());
    }
    let mut generated = 0usize;
    let mut recovered = 0usize;
    let proof = if matches!(args[0].as_str(), "prove" | "resume") {
        if args[0] == "prove" && final_path.exists() {
            return Err("original envelope exists; use resume".into());
        }
        std::fs::create_dir_all(dir)?;
        let frozen = dir.join("inputs.json");
        let bytes = serde_json::to_vec(&input)?;
        if frozen.exists() {
            if read(&frozen, 1_048_576)? != bytes {
                return Err("retained envelope inputs differ".into());
            }
        } else {
            if std::fs::read_dir(dir)?.next().is_some() {
                return Err("unowned nonempty envelope directory".into());
            }
            write(&frozen, &bytes)?;
        }
        let body =
            prove_large_transaction_body_using(&input.block, input.index, |at, bytes, leaf| {
                let path = dir.join(format!("hash-{at:03}.cbor"));
                if path.exists() {
                    recovered += 1;
                    return decode::<Blake3HashProof>(
                        &read(&path, 512 * 1024 * 1024).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string());
                }
                let proof = if leaf {
                    prove_large_body_hash_using(bytes, |step, expected| {
                        let path = dir.join(format!("leaf-{step:04}.cbor"));
                        if path.exists() {
                            recovered += 1;
                            return decode::<CompressionProof>(
                                &read(&path, 2 * 1024 * 1024).map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string());
                        }
                        let proof = prove_compression(expected)?;
                        verify_compression(
                            &proof,
                            expected,
                            &proof.output().ok_or("missing compression output")?,
                        )?;
                        write(&path, &encode(&proof).map_err(|e| e.to_string())?)
                            .map_err(|e| e.to_string())?;
                        generated += 1;
                        Ok(proof)
                    })?
                } else {
                    prove_hash(bytes)?
                };
                if leaf {
                    verify_large_body_hash(&proof, bytes, &proof.output)?;
                } else {
                    verify_hash(&proof, bytes, &proof.output)?;
                    generated += 1;
                }
                write(&path, &encode(&proof).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                Ok(proof)
            })?;
        let mut small = |name: &str, message: &[u8]| -> Result<Blake3HashProof, Box<dyn Error>> {
            let path = dir.join(name);
            if path.exists() {
                let proof: Blake3HashProof = decode(&read(&path, 16 * 1024 * 1024)?)?;
                verify_hash(&proof, message, &proof.output)?;
                recovered += 1;
                Ok(proof)
            } else {
                let proof = prove_hash(message)?;
                verify_hash(&proof, message, &proof.output)?;
                write(&path, &encode(&proof)?)?;
                generated += 1;
                Ok(proof)
            }
        };
        let signing_hash = small(
            "signing.cbor",
            &tx.tx.signing_payload(tx.signature.sig_type.as_u8()),
        )?;
        let transaction_id = small("identity.cbor", &identity(tx, &signing_hash.output))?;
        let proof = LargeTransactionEnvelopeProof {
            version: 1,
            body,
            signing_hash,
            transaction_id,
        };
        verify(&proof, &input)?;
        let bytes = encode(&proof)?;
        if final_path.exists() {
            if read(&final_path, 512 * 1024 * 1024)? != bytes {
                return Err("retained envelope differs; refusing replacement".into());
            }
        } else {
            write(&final_path, &bytes)?;
        }
        proof
    } else {
        decode(&read(&final_path, 512 * 1024 * 1024)?)?
    };
    verify(&proof, &input)?;
    println!(
        "{}",
        serde_json::json!({"body_membership_verified":true,"canonical_admission":false,"signature_verified":false,"index":input.index,"leaf_bytes":block_body_leaf_message(tx,input.index as u64).len(),"leaf_compressions":proof.body.leaf.compressions.len(),"body_hash_profile":proof.body.leaf.version,"membership_profile":proof.body.version,"transaction_id":proof.transaction_id.output,"signing_hash":proof.signing_hash.output,"body_root":proof.body.root.output,"generated_steps":generated,"recovered_steps":recovered,"new_signing":false})
    );
    Ok(())
}
