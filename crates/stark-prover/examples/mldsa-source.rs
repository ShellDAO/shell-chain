//! Verify a complete same-identity public transaction-source/signature graph.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shell_core::{PubkeyMode, SignedTransaction, Transaction};
use shell_crypto::{PQSignature, SignatureType};
use shell_primitives::Address;
use shell_stark_prover::{
    blake3_hash::{prove_hash, verify_hash},
    mldsa_key::PublicKeyDecodeProof,
    mldsa_matrix::{MatrixPolynomialProof, MatrixProof},
    mldsa_source::{
        verify_derived_sender_signature, verify_transaction_signature, DerivedSenderSignatureProof,
        TransactionSignatureProof,
    },
    mldsa_verification::{CompletionProof, EquationPipeline, Mldsa65VerificationProof},
};
use std::{
    io::{BufReader, BufWriter, Write},
    path::Path,
};
type Error = Box<dyn std::error::Error>;
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u8,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    version: u8,
    transaction: Transaction,
    sig_type: u8,
    public_key_hash: [u8; 32],
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_reader(BufReader::new(
        std::fs::File::open(path)?,
    ))?)
}
fn equation(source: &Path, dir: &Path) -> Result<EquationPipeline, Error> {
    let key: PublicKeyDecodeProof = read(&dir.join("key.json"))?;
    let mut polynomials = Vec::new();
    for row in 0..6 {
        for column in 0..5 {
            polynomials.push(read::<MatrixPolynomialProof>(
                &source.join(format!("a-{row}-{column}.json")),
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
        signature: read(&dir.join("signature.json"))?,
        challenge: read(&dir.join("challenge.json"))?,
        z_ntt: (0..5)
            .map(|i| read(&dir.join(format!("z-{i}.json"))))
            .collect::<Result<_, _>>()?,
        t1_ntt: (0..6)
            .map(|i| read(&dir.join(format!("t-{i}.json"))))
            .collect::<Result<_, _>>()?,
        c_ntt: read(&dir.join("c-ntt.json"))?,
        equation: read(&dir.join("equation.json"))?,
        inverse: (0..6)
            .map(|i| read(&dir.join(format!("inverse-{i}.json"))))
            .collect::<Result<_, _>>()?,
    })
}
fn completion(dir: &Path) -> Result<CompletionProof, Error> {
    Ok(CompletionProof {
        finish: read(&dir.join("finish.json"))?,
        tr: read(&dir.join("tr.json"))?,
        mu: read(&dir.join("mu.json"))?,
        commitment: read(&dir.join("commitment.json"))?,
    })
}
fn verify(p: &TransactionSignatureProof, s: &Source, id: &Identity) -> Result<(), String> {
    verify_transaction_signature(
        p,
        &s.transaction,
        &id.public_key,
        &id.signature,
        &s.public_key_hash,
    )
}
fn rejections(
    p: &TransactionSignatureProof,
    s: &Source,
    id: &Identity,
    bad_dir: &Path,
) -> Result<(), Error> {
    let mut cases = Vec::new();
    for i in 0..8 {
        let mut tx = s.transaction.clone();
        let mut key = id.public_key.clone();
        let mut signature = id.signature.clone();
        let mut key_hash = s.public_key_hash;
        let (name, phase) = match i {
            0 => {
                tx.nonce += 1;
                ("expected_nonce", "transaction source:")
            }
            1 => {
                tx.chain_id += 1;
                ("expected_chain_id", "transaction source:")
            }
            2 => {
                tx.data = shell_primitives::Bytes::from(vec![0xff]);
                ("expected_data", "transaction source:")
            }
            3 => {
                key[1951] ^= 1;
                ("last_raw_key_byte", "public key source:")
            }
            4 => {
                signature[3308] ^= 1;
                ("expected_signature", "signature:")
            }
            5 => {
                key_hash[31] ^= 1;
                ("expected_full_key_hash", "public key source:")
            }
            6 => {
                tx.tx_type = 0x7e;
                ("AA_sender_wrapper", "unsupported outer")
            }
            _ => {
                tx.tx_type = 255;
                ("unknown_transaction_type", "unsupported outer")
            }
        };
        let error = verify_transaction_signature(p, &tx, &key, &signature, &key_hash)
            .err()
            .ok_or("changed source accepted")?;
        if !error.starts_with(phase) {
            return Err(format!("{name}: unexpected rejection: {error}").into());
        }
        cases.push(serde_json::json!({"case":name,"error":error}));
    }
    let mut changed = p.clone();
    changed.version = 2;
    let error = verify(&changed, s, id)
        .err()
        .ok_or("foreign proof version accepted")?;
    cases.push(serde_json::json!({"case":"version","error":error}));
    let mut changed = p.clone();
    changed.signing_hash.output[31] ^= 1;
    let error = verify(&changed, s, id)
        .err()
        .ok_or("foreign signing digest accepted")?;
    cases.push(serde_json::json!({"case":"signing_digest","error":error}));
    // The existing negative producer proves a canonical altered hint honestly:
    // both source hashes, the raw decoding/equation prefix, the new hint result
    // and the changed final SHAKE computation remain mathematically valid.
    let bad: Identity = read(&bad_dir.join("identity.json"))?;
    if bad.version != 1
        || bad.public_key.len() != 1952
        || bad.signature.len() != 3309
        || bad.message.len() != 32
        || bad.public_key != id.public_key
        || bad.message != id.message
        || bad.signature == id.signature
        || bad.signature[..3248] != id.signature[..3248]
    {
        return Err("invalid altered-hint control identity".into());
    }
    let mut changed = p.clone();
    changed.signature.equation.signature = read(&bad_dir.join("signature.json"))?;
    changed.signature.completion.finish = read(&bad_dir.join("finish.json"))?;
    changed.signature.completion.commitment = read(&bad_dir.join("commitment.json"))?;
    let error = verify(&changed, s, &bad)
        .err()
        .ok_or("honestly proved altered-hint signature accepted")?;
    if !error.starts_with("signature: final commitment:") {
        return Err(format!("unexpected altered-hint phase: {error}").into());
    }
    cases.push(serde_json::json!({"case":"honest_invalid_same_message_hint","error":error}));
    println!(
        "{}",
        serde_json::json!({"mode":"check-rejections","full_joint_positive_verified":true,"rejected":cases,"proofs_generated":0,"input_files_read_only":true})
    );
    Ok(())
}
fn write<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut out = BufWriter::new(f);
    serde_json::to_writer(&mut out, value)?;
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(())
}
fn derived_sender(
    p: TransactionSignatureProof,
    s: &Source,
    id: &Identity,
    dir: &Path,
    mode: &std::ffi::OsStr,
) -> Result<(), Error> {
    let proving = mode == "prove-derived";
    let mut generated = 0;
    if proving {
        std::fs::create_dir_all(dir)?;
        // Independent native producer control only. The production predicate
        // below authenticates this address using the actual BLAKE3 certificate.
        let expected = SignedTransaction::with_pubkey(
            Address::from_public_key(&id.public_key, s.sig_type),
            s.transaction.clone(),
            PQSignature::new(SignatureType::MlDsa65, id.signature.clone()),
            id.public_key.clone(),
        );
        let path = dir.join("sender.json");
        if !path.try_exists()? {
            write(&path, &expected)?;
        }
        if read::<SignedTransaction>(&path)? != expected {
            return Err("saved sender differs from native producer control".into());
        }
        let path = dir.join("sender-address.json");
        if !path.try_exists()? {
            let mut preimage = vec![s.sig_type];
            preimage.extend_from_slice(&id.public_key);
            eprintln!("Proving sender-address.json");
            write(&path, &prove_hash(&preimage)?)?;
            generated += 1;
        }
    }
    // sender.json is an explicit public caller expectation, not a from address
    // supplied by the certificate. The library accepts this envelope directly.
    let expected: SignedTransaction = read(&dir.join("sender.json"))?;
    let proof = DerivedSenderSignatureProof {
        version: 1,
        sender_address: read(&dir.join("sender-address.json"))?,
        transaction: p,
    };
    verify_derived_sender_signature(&proof, &expected, &s.public_key_hash)?;
    if mode == "check-derived-rejections" {
        let mut cases = Vec::new();
        for i in 0..9 {
            let mut changed = expected.clone();
            let mut key_hash = s.public_key_hash;
            let (name, phase) = match i {
                0 => {
                    changed.from.0[31] ^= 1;
                    ("expected_from", "sender address source:")
                }
                1 => {
                    let mut key = id.public_key.clone();
                    key[1951] ^= 1;
                    changed.pubkey_mode = PubkeyMode::Embedded(key);
                    ("last_embedded_key_byte", "sender address source:")
                }
                2 => {
                    changed.signature.sig_type = SignatureType::Dilithium3;
                    ("algorithm", "invalid derived sender")
                }
                3 => {
                    changed.pubkey_mode = PubkeyMode::Reference;
                    ("Reference_registry_required", "derived sender requires")
                }
                4 => {
                    changed.tx.tx_type = 0x7e;
                    ("AA_sender", "unsupported derived sender")
                }
                5 => {
                    changed.tx.nonce += 1;
                    ("nonce", "transaction source:")
                }
                6 => {
                    changed.signature.data[3308] ^= 1;
                    ("signature", "signature:")
                }
                7 => {
                    key_hash[31] ^= 1;
                    ("raw_key_hash", "public key source:")
                }
                _ => {
                    changed.signature.data.clear();
                    ("short_signature", "invalid derived sender")
                }
            };
            let error = verify_derived_sender_signature(&proof, &changed, &key_hash)
                .err()
                .ok_or("changed sender/source accepted")?;
            if !error.starts_with(phase) {
                return Err(format!("{name}: {error}").into());
            }
            cases.push(serde_json::json!({"case":name,"error":error}));
        }
        // An honest raw-key hash certificate is valid for its own unprefixed
        // input. Even setting from to that digest cannot make it an address.
        verify_hash(
            &proof.transaction.public_key_hash,
            &id.public_key,
            &s.public_key_hash,
        )?;
        let mut changed = proof.clone();
        changed.sender_address = proof.transaction.public_key_hash.clone();
        let mut raw_sender = expected.clone();
        raw_sender.from = Address::from(s.public_key_hash);
        let error = verify_derived_sender_signature(&changed, &raw_sender, &s.public_key_hash)
            .err()
            .ok_or("honest raw-key hash substituted for address")?;
        if !error.starts_with("sender address source:") {
            return Err(error.into());
        }
        cases.push(serde_json::json!({"case":"honest_unprefixed_key_certificate","error":error}));
        for i in 0..7 {
            let mut changed = proof.clone();
            let name = match i {
                0 => {
                    changed.version = 2;
                    "wrapper_version"
                }
                1 => {
                    changed.sender_address.version = 2;
                    "address_version"
                }
                2 => {
                    changed.sender_address.message[0] ^= 1;
                    "algorithm_prefix"
                }
                3 => {
                    changed.sender_address.output[31] ^= 1;
                    "address_digest"
                }
                4 => {
                    changed.sender_address.compressions.pop();
                    "missing_compression"
                }
                5 => {
                    changed
                        .sender_address
                        .compressions
                        .push(changed.sender_address.compressions[0].clone());
                    "extra_compression"
                }
                _ => {
                    changed.sender_address.compressions[0].operations[0] ^= 1;
                    "compression_arithmetic"
                }
            };
            let error = verify_derived_sender_signature(&changed, &expected, &s.public_key_hash)
                .err()
                .ok_or("changed address proof accepted")?;
            if i != 0 && !error.starts_with("sender address source:") {
                return Err(error.into());
            }
            cases.push(serde_json::json!({"case":name,"error":error}));
        }
        println!(
            "{}",
            serde_json::json!({"mode":"check-derived-rejections","positive_full_graph_verified":true,"rejected":cases,"proofs_generated":0,"input_files_read_only":true})
        );
        return Ok(());
    }
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"derived_Embedded_sender_full_graph_verified":true,"from":expected.from,"address_preimage_bytes":proof.sender_address.message.len(),"address_compressions":proof.sender_address.compressions.len(),"new_hash_certificates":generated,"source_signature_graph_reused":true,"expected_signed_transaction_file":"sender.json","native_address_producer_control":proving,"native_acceptance_fallback":false,"registry_absence_proved":false,"account_authority_proved":false,"registered_rotated_accounts_proved":false,"canonical_history_proved":false,"private_witness":false,"node_integrated":false})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 && args.len() != 5 {
        return Err("usage: mldsa-source verify source-dir equation-dir signature-dir; mldsa-source check-rejections source-dir equation-dir signature-dir rejection-dir; mldsa-source prove-derived|verify-derived|check-derived-rejections source-dir equation-dir signature-dir sender-dir".into());
    }
    let mode = &args[0];
    let derived =
        mode == "prove-derived" || mode == "verify-derived" || mode == "check-derived-rejections";
    if (mode != "verify" && mode != "check-rejections" && !derived)
        || ((mode == "check-rejections" || derived) != (args.len() == 5))
    {
        return Err("invalid mode arguments".into());
    }
    let source = Path::new(&args[1]);
    let eq = Path::new(&args[2]);
    let sig = Path::new(&args[3]);
    let id: Identity = read(&source.join("identity.json"))?;
    let s: Source = read(&source.join("source.json"))?;
    if id.version != 1
        || s.version != 1
        || id.public_key.len() != 1952
        || id.signature.len() != 3309
        || id.message.len() != 32
        || s.sig_type != SignatureType::MlDsa65.as_u8()
    {
        return Err("invalid source identity/shape/algorithm".into());
    }
    if read::<Identity>(&eq.join("identity.json"))? != id
        || read::<Identity>(&sig.join("identity.json"))? != id
    {
        return Err("source/equation/signature identities differ".into());
    }
    let p = TransactionSignatureProof {
        version: 1,
        signing_hash: read(&source.join("transaction-hash.json"))?,
        public_key_hash: read(&source.join("public-key-hash.json"))?,
        signature: Mldsa65VerificationProof {
            version: 1,
            equation: equation(source, eq)?,
            completion: completion(sig)?,
        },
    };
    if p.signing_hash.output.as_slice() != id.message {
        return Err("saved signature message differs from the source signing digest".into());
    }
    if derived {
        return derived_sender(p, &s, &id, Path::new(&args[4]), mode);
    }
    verify(&p, &s, &id)?;
    if mode == "check-rejections" {
        return rejections(&p, &s, &id, Path::new(&args[4]));
    }
    println!(
        "{}",
        serde_json::json!({"mode":"verify","full_joint_graph_verified":true,"same_canonical_outer_transaction_hash_and_signature":true,"full_rawkey_digest_bound":true,"matrix_certificates":30,"equation_certificates":22,"signature_completion_certificates":4,"BLAKE3_source_compressions":p.signing_hash.compressions.len()+p.public_key_hash.compressions.len(),"algorithm":"ML-DSA-65","context_bytes":0,"signature_message_bytes":32,"proofs_generated":0,"native_hash_or_signature_acceptance_fallback":false,"input_files_read_only":true,"account_authority_proved":false,"canonical_history_proved":false,"private_witness":false,"AA_sender_wrapper_proved":false,"node_integrated":false})
    );
    Ok(())
}
