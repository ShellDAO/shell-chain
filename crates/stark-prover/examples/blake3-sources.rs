//! Persist real canonical outer-transaction and full public-key hash proofs.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shell_core::Transaction;
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_primitives::{Address, Bytes, U256};
use shell_stark_prover::blake3_hash::{
    prove_hash, prove_transaction_signing_hash, verify_hash, verify_transaction_signing_hash,
    Blake3HashProof,
};
use std::{
    io::{BufReader, BufWriter, Write},
    path::Path,
};
type Error = Box<dyn std::error::Error>;

// Compatible with the matrix/equation/signature source examples. The private
// key exists only during generation and is never serialized or printed.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u8,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    version: u8,
    transaction: Transaction,
    sig_type: u8,
    public_key_hash: [u8; 32],
}
fn read<T: DeserializeOwned>(p: &Path) -> Result<T, Error> {
    Ok(serde_json::from_reader(BufReader::new(
        std::fs::File::open(p)?,
    ))?)
}
fn write<T: Serialize>(p: &Path, v: &T) -> Result<(), Error> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer(&mut w, v)?;
    w.flush()?;
    w.get_ref().sync_all()?;
    Ok(())
}
fn generate(dir: &Path) -> Result<(), Error> {
    std::fs::create_dir(dir)?;
    let signer = MlDsaSigner::generate();
    let public_key = signer.public_key().to_vec();
    let transaction = Transaction {
        chain_id: 10,
        nonce: 0,
        to: Some(Address::from([0x11; 32])),
        value: U256::from(1u64),
        data: Bytes::from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8]),
        gas_limit: 100000,
        max_fee_per_gas: 2,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 0,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let sig_type = SignatureType::MlDsa65.as_u8();
    let message = transaction.signing_hash(sig_type).as_bytes().to_vec();
    let signature = signer.sign(&message)?.data;
    let source = Source {
        version: 1,
        transaction,
        sig_type,
        public_key_hash: *blake3::hash(&public_key).as_bytes(),
    };
    write(
        &dir.join("identity.json"),
        &Identity {
            version: 1,
            public_key,
            message,
            signature,
        },
    )?;
    write(&dir.join("source.json"), &source)?;
    Ok(())
}
fn checkpoint(
    path: &Path,
    proving: bool,
    new: &mut usize,
    f: impl FnOnce() -> Result<Blake3HashProof, String>,
) -> Result<Blake3HashProof, Error> {
    if proving && !path.try_exists()? {
        eprintln!(
            "Proving {}",
            path.file_name()
                .ok_or("missing filename")?
                .to_string_lossy()
        );
        write(path, &f()?)?;
        *new += 1;
    }
    read(path)
}
fn check(
    source: &Source,
    id: &Identity,
    tx: &Blake3HashProof,
    key: &Blake3HashProof,
) -> Result<(), Error> {
    let hash: [u8; 32] = id
        .message
        .as_slice()
        .try_into()
        .map_err(|_| "expected 32-byte signing message")?;
    verify_transaction_signing_hash(tx, &source.transaction, source.sig_type, &hash)?;
    verify_hash(key, &id.public_key, &source.public_key_hash)?;
    Ok(())
}
fn rejections(
    source: &Source,
    id: &Identity,
    tx: &Blake3HashProof,
    key: &Blake3HashProof,
) -> Result<(), Error> {
    check(source, id, tx, key)?;
    let hash: [u8; 32] = id.message.as_slice().try_into()?;
    let mut cases = Vec::new();
    let mut changed = source.transaction.clone();
    changed.nonce += 1;
    let error = verify_transaction_signing_hash(tx, &changed, source.sig_type, &hash)
        .err()
        .ok_or("changed nonce accepted")?;
    cases.push(serde_json::json!({"case":"canonical_nonce","error":error}));
    let error =
        verify_transaction_signing_hash(tx, &source.transaction, source.sig_type ^ 1, &hash)
            .err()
            .ok_or("changed algorithm accepted")?;
    cases.push(serde_json::json!({"case":"signature_algorithm_tag","error":error}));
    let mut pk = id.public_key.clone();
    pk[1951] ^= 1;
    let error = verify_hash(key, &pk, &source.public_key_hash)
        .err()
        .ok_or("foreign key accepted")?;
    cases.push(serde_json::json!({"case":"last_raw_key_byte","error":error}));
    for i in 0..8 {
        let mut p = key.clone();
        let end = p.compressions.len() - 1;
        let name = match i {
            0 => {
                p.compressions[16].input.counter ^= 1u64 << 40;
                "chunk_counter_high"
            }
            1 => {
                p.compressions[end].input.flags ^= 8;
                "root_domain"
            }
            2 => {
                p.compressions.pop();
                "missing_parent"
            }
            3 => {
                p.compressions.swap(0, 1);
                "block_order"
            }
            4 => {
                p.output[31] ^= 1;
                "digest_last_byte"
            }
            5 => {
                p.compressions[0].operations[447] ^= 1;
                "last_round_operation"
            }
            6 => {
                p.compressions[end].operations[463] ^= 1;
                "last_feedforward_word"
            }
            _ => {
                p.compressions[30].input.block[15] ^= 1;
                "final_chunk_padding"
            }
        };
        let error = verify_hash(&p, &id.public_key, &p.output)
            .err()
            .ok_or("changed hash proof accepted")?;
        cases.push(serde_json::json!({"case":name,"error":error}));
    }
    println!(
        "{}",
        serde_json::json!({"mode":"check-rejections","valid_sources_verified":true,"rejected":cases,"proofs_generated":0,"inputs_read_only":true})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: blake3-sources prove|verify|check-rejections source-dir".into());
    };
    if mode != "prove" && mode != "verify" && mode != "check-rejections" {
        return Err("invalid mode".into());
    }
    let dir = Path::new(path);
    let proving = mode == "prove";
    if proving && !dir.try_exists()? {
        generate(dir)?;
    }
    let id: Identity = read(&dir.join("identity.json"))?;
    let source: Source = read(&dir.join("source.json"))?;
    if id.version != 1
        || source.version != 1
        || id.public_key.len() != 1952
        || id.signature.len() != 3309
        || id.message.len() != 32
        || source.sig_type != SignatureType::MlDsa65.as_u8()
    {
        return Err("invalid source identity/algorithm/shape".into());
    }
    let mut new = 0;
    let tx = checkpoint(
        &dir.join("transaction-hash.json"),
        proving,
        &mut new,
        || prove_transaction_signing_hash(&source.transaction, source.sig_type),
    )?;
    let key = checkpoint(&dir.join("public-key-hash.json"), proving, &mut new, || {
        prove_hash(&id.public_key)
    })?;
    check(&source, &id, &tx, &key)?;
    if mode == "check-rejections" {
        return rejections(&source, &id, &tx, &key);
    }
    // Independent controls occur after actual proof verification. This example
    // has not generated a new complete ML-DSA STARK graph for this identity.
    if source.transaction.signing_hash(source.sig_type).as_bytes() != &tx.output
        || blake3::hash(&id.public_key).as_bytes() != &key.output
        || !MlDsaVerifier.verify(
            &id.public_key,
            &id.message,
            &PQSignature::new(SignatureType::MlDsa65, id.signature.clone()),
        )?
    {
        return Err("independent native controls differ".into());
    }
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"new_hash_certificates":new,"transaction_payload_bytes":tx.message.len(),"public_key_bytes":key.message.len(),"transaction_compressions":tx.compressions.len(),"public_key_compressions":key.compressions.len(),"saved_reload_verified":true,"canonical_outer_payload_and_raw_key_hash_proved":true,"native_signature_control":true,"signature_message_bytes":32,"full_signature_air_proved":false,"canonical_history_proved":false,"account_authority_proved":false,"private_witness":false,"AA_sender_wrapper_proved":false,"node_integrated":false})
    );
    Ok(())
}
