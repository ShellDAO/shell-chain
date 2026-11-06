//! Verify a complete same-identity public transaction-source/signature graph.

use shell_core::{PubkeyMode, SignedTransaction};
use shell_crypto::{PQSignature, SignatureType};
use shell_primitives::Address;
use shell_stark_prover::{
    blake3_hash::{prove_hash, verify_hash},
    mldsa_source::{
        verify_derived_sender_signature, verify_identified_sender_signature,
        verify_signature_entry, verify_transaction_signature, DerivedSenderSignatureProof,
        IdentifiedSenderSignatureProof, SignatureEntryProof, TransactionSignatureProof,
    },
    SigBatchEntry,
};
use std::path::Path;
#[path = "common/mldsa_source.rs"]
mod source;
use source::{load_transaction_proof, read, write, EntrySource, Error, IdSource, Identity, Source};
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
fn identified_sender(
    p: TransactionSignatureProof,
    s: &Source,
    id: &Identity,
    args: &[std::ffi::OsString],
) -> Result<(), Error> {
    let mode = &args[0];
    let sender_dir = Path::new(&args[4]);
    let dir = Path::new(&args[5]);
    let expected: SignedTransaction = read(&sender_dir.join("sender.json"))?;
    let sender = DerivedSenderSignatureProof {
        version: 1,
        sender_address: read(&sender_dir.join("sender-address.json"))?,
        transaction: p,
    };
    let proving = mode == "prove-identified";
    let mut generated = 0;
    if proving {
        std::fs::create_dir_all(dir)?;
        // Freshly deserialized native envelope: this is an independent producer
        // control, never an acceptance path in the production verifier.
        let control = IdSource {
            version: 1,
            transaction_id: *expected.hash().as_bytes(),
        };
        let path = dir.join("id-source.json");
        if !path.try_exists()? {
            write(&path, &control)?;
        }
        if read::<IdSource>(&path)? != control {
            return Err("saved ID differs from native producer control".into());
        }
        let path = dir.join("id-hash.json");
        if !path.try_exists()? {
            let mut preimage = shell_core::PQTX_ID_DOMAIN.to_vec();
            preimage.extend_from_slice(expected.from.as_bytes());
            preimage.extend_from_slice(&sender.transaction.signing_hash.output);
            eprintln!("Proving id-hash.json");
            write(&path, &prove_hash(&preimage)?)?;
            generated += 1;
        }
    }
    let source: IdSource = read(&dir.join("id-source.json"))?;
    if source.version != 1 {
        return Err("invalid expected ID source version".into());
    }
    let proof = IdentifiedSenderSignatureProof {
        version: 1,
        transaction_id: read(&dir.join("id-hash.json"))?,
        sender,
    };
    let verify = |p: &IdentifiedSenderSignatureProof, tx: &SignedTransaction, hash: &[u8; 32]| {
        verify_identified_sender_signature(p, tx, &s.public_key_hash, hash)
    };
    verify(&proof, &expected, &source.transaction_id)?;
    if mode == "check-identified-rejections" {
        let mut cases = Vec::new();
        let mut rejected =
            |name: &str, result: Result<(), String>, phase: &str| -> Result<(), Error> {
                let error = result
                    .err()
                    .ok_or_else(|| format!("{name}: changed identity accepted"))?;
                if !error.starts_with(phase) {
                    return Err(format!("{name}: {error}").into());
                }
                cases.push(serde_json::json!({"case":name,"error":error}));
                Ok(())
            };
        for i in 0..7 {
            let mut changed = proof.clone();
            let name = match i {
                0 => {
                    changed.version = 2;
                    "wrapper_version"
                }
                1 => {
                    changed.transaction_id.version = 2;
                    "ID_version"
                }
                2 => {
                    changed.transaction_id.message[0] ^= 1;
                    "ID_domain"
                }
                3 => {
                    changed.transaction_id.output[31] ^= 1;
                    "ID_digest"
                }
                4 => {
                    changed.transaction_id.compressions.pop();
                    "missing_compression"
                }
                5 => {
                    changed
                        .transaction_id
                        .compressions
                        .push(changed.transaction_id.compressions[0].clone());
                    "extra_compression"
                }
                _ => {
                    changed.transaction_id.compressions[0].operations[0] ^= 1;
                    "compression_arithmetic"
                }
            };
            rejected(
                name,
                verify(&changed, &expected, &source.transaction_id),
                if i == 0 {
                    "invalid identified sender"
                } else {
                    "transaction ID source:"
                },
            )?;
        }
        let mut hash = source.transaction_id;
        hash[31] ^= 1;
        rejected(
            "expected_ID",
            verify(&proof, &expected, &hash),
            "transaction ID source:",
        )?;
        let mut changed = expected.clone();
        changed.from.0[0] ^= 1;
        rejected(
            "full_width_from_preserving_last20bytes",
            verify(&proof, &changed, &source.transaction_id),
            "transaction ID source:",
        )?;
        let mut changed = proof.clone();
        changed.sender.transaction.signing_hash.output[31] ^= 1;
        rejected(
            "sender_signing_digest",
            verify(&changed, &expected, &source.transaction_id),
            "transaction ID source:",
        )?;
        let honest = &proof.sender.transaction.signing_hash;
        verify_hash(honest, &honest.message, &honest.output)?;
        let mut changed = proof.clone();
        changed.transaction_id = honest.clone();
        rejected(
            "honest_signing_hash_is_not_canonical_ID",
            verify(&changed, &expected, &honest.output),
            "transaction ID source:",
        )?;
        // Demonstrate why a cached native ID cannot replace source verification.
        let mut cached = expected.clone();
        let old = cached.hash();
        cached.tx.nonce += 1;
        if cached.hash() != old {
            return Err("native cache control unexpectedly changed".into());
        }
        rejected(
            "changed_nonce_after_native_hash_cached",
            verify(&proof, &cached, &source.transaction_id),
            "transaction source:",
        )?;
        let reference = SignedTransaction::new(
            expected.from,
            expected.tx.clone(),
            expected.signature.clone(),
        );
        if reference.hash().as_bytes() != &source.transaction_id {
            return Err("native Embedded/Reference ID changed".into());
        }
        rejected(
            "same_ID_Reference_still_requires_registry",
            verify(&proof, &reference, &source.transaction_id),
            "derived sender requires",
        )?;
        // Authentication witnesses are excluded from the ID. Honest altered-hint
        // computation keeps that valid ID but must fail full signature checking.
        let bad_dir = Path::new(&args[6]);
        let bad: Identity = read(&bad_dir.join("identity.json"))?;
        if bad.version != 1
            || bad.public_key != id.public_key
            || bad.message != id.message
            || bad.signature.len() != 3309
            || bad.signature == id.signature
            || bad.signature[..3248] != id.signature[..3248]
        {
            return Err("invalid honest altered-hint identity".into());
        }
        let altered = SignedTransaction::with_pubkey(
            expected.from,
            expected.tx.clone(),
            PQSignature::new(SignatureType::MlDsa65, bad.signature),
            id.public_key.clone(),
        );
        if altered.hash().as_bytes() != &source.transaction_id {
            return Err("witness change unexpectedly altered canonical ID".into());
        }
        let mut changed = proof.clone();
        changed.sender.transaction.signature.equation.signature =
            read(&bad_dir.join("signature.json"))?;
        changed.sender.transaction.signature.completion.finish =
            read(&bad_dir.join("finish.json"))?;
        changed.sender.transaction.signature.completion.commitment =
            read(&bad_dir.join("commitment.json"))?;
        rejected(
            "honest_invalid_signature_retains_valid_ID",
            verify(&changed, &altered, &source.transaction_id),
            "signature: final commitment:",
        )?;
        println!(
            "{}",
            serde_json::json!({"mode":"check-identified-rejections","positive_full_graph_verified":true,"rejected":cases,"proofs_generated":0,"input_files_read_only":true,"native_witness_exclusion_control":true,"native_Embedded_Reference_ID_stability_control":true,"native_stale_cache_control":true})
        );
        return Ok(());
    }
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"canonical_ID_sender_full_graph_verified":true,"transaction_id":source.transaction_id,"ID_preimage_bytes":proof.transaction_id.message.len(),"ID_compressions":proof.transaction_id.compressions.len(),"new_hash_certificates":generated,"prior_graph_reused":true,"native_ID_producer_control":proving,"native_acceptance_fallback":false,"registry_absence_proved":false,"account_authority_proved":false,"Reference_authority_proved":false,"canonical_chain_membership_proved":false,"private_witness":false,"node_integrated":false})
    );
    Ok(())
}
fn signature_entry(
    p: TransactionSignatureProof,
    s: &Source,
    id: &Identity,
    args: &[std::ffi::OsString],
) -> Result<(), Error> {
    let mode = &args[0];
    let sender_dir = Path::new(&args[4]);
    let id_dir = Path::new(&args[5]);
    let dir = Path::new(&args[6]);
    let expected: SignedTransaction = read(&sender_dir.join("sender.json"))?;
    let id_source: IdSource = read(&id_dir.join("id-source.json"))?;
    if id_source.version != 1 {
        return Err("invalid expected ID source version".into());
    }
    let identified = IdentifiedSenderSignatureProof {
        version: 1,
        transaction_id: read(&id_dir.join("id-hash.json"))?,
        sender: DerivedSenderSignatureProof {
            version: 1,
            sender_address: read(&sender_dir.join("sender-address.json"))?,
            transaction: p,
        },
    };
    let proving = mode == "prove-entry";
    let mut generated = 0;
    if proving {
        std::fs::create_dir_all(dir)?;
        // The node and producer share this unchanged native mapper. It is an
        // independent control, never a production proof-verification fallback.
        let entry = SigBatchEntry::from_signed_transaction(&expected);
        let control = EntrySource {
            version: 1,
            msg_hash: entry.msg_hash,
            pk_hash: entry.pk_hash,
            leaf: entry.to_leaf_bytes(),
        };
        let path = dir.join("entry-source.json");
        if !path.try_exists()? {
            write(&path, &control)?;
        }
        if read::<EntrySource>(&path)? != control {
            return Err("saved entry differs from native producer control".into());
        }
        let path = dir.join("entry-leaf.json");
        if !path.try_exists()? {
            let mut preimage = entry.msg_hash.to_vec();
            preimage.extend_from_slice(&entry.pk_hash);
            eprintln!("Proving entry-leaf.json");
            write(&path, &prove_hash(&preimage)?)?;
            generated += 1;
        }
    }
    let source: EntrySource = read(&dir.join("entry-source.json"))?;
    if source.version != 1 {
        return Err("invalid expected entry source version".into());
    }
    let entry = SigBatchEntry {
        msg_hash: source.msg_hash,
        pk_hash: source.pk_hash,
    };
    let proof = SignatureEntryProof {
        version: 1,
        leaf: read(&dir.join("entry-leaf.json"))?,
        identified,
    };
    let verified = verify_signature_entry(
        &proof,
        &expected,
        &s.public_key_hash,
        &id_source.transaction_id,
        &entry,
        &source.leaf,
    )?;
    if verified.entry().msg_hash != entry.msg_hash
        || verified.entry().pk_hash != entry.pk_hash
        || verified.leaf_bytes() != &source.leaf
        || verified.transaction_id() != &id_source.transaction_id
    {
        return Err("verified entry snapshot differs from expectations".into());
    }
    if mode == "check-entry-rejections" {
        let verify = |p: &SignatureEntryProof,
                      tx: &SignedTransaction,
                      e: &SigBatchEntry,
                      leaf: &[u8; 32]| {
            verify_signature_entry(
                p,
                tx,
                &s.public_key_hash,
                &id_source.transaction_id,
                e,
                leaf,
            )
            .map(|_| ())
        };
        let mut cases = Vec::new();
        let mut rejected =
            |name: &str, result: Result<(), String>, phase: &str| -> Result<(), Error> {
                let error = result
                    .err()
                    .ok_or_else(|| format!("{name}: changed entry accepted"))?;
                if !error.starts_with(phase) {
                    return Err(format!("{name}: {error}").into());
                }
                cases.push(serde_json::json!({"case":name,"error":error}));
                Ok(())
            };
        for i in 0..7 {
            let mut changed = proof.clone();
            let name = match i {
                0 => {
                    changed.version = 2;
                    "wrapper_version"
                }
                1 => {
                    changed.leaf.version = 2;
                    "leaf_version"
                }
                2 => {
                    changed.leaf.output[31] ^= 1;
                    "leaf_digest"
                }
                3 => {
                    changed.leaf.message[0] ^= 1;
                    "leaf_message"
                }
                4 => {
                    changed.leaf.compressions.pop();
                    "missing_compression"
                }
                5 => {
                    changed
                        .leaf
                        .compressions
                        .push(changed.leaf.compressions[0].clone());
                    "extra_compression"
                }
                _ => {
                    changed.leaf.compressions[0].operations[0] ^= 1;
                    "compression_arithmetic"
                }
            };
            rejected(
                name,
                verify(&changed, &expected, &entry, &source.leaf),
                if i == 0 {
                    "invalid signature entry proof"
                } else {
                    "signature entry leaf:"
                },
            )?;
        }
        let mut changed = entry.clone();
        changed.msg_hash = id_source.transaction_id;
        rejected(
            "canonical_ID_is_not_entry_message",
            verify(&proof, &expected, &changed, &source.leaf),
            "invalid signature entry message",
        )?;
        let mut changed = entry.clone();
        changed.pk_hash = s.public_key_hash;
        rejected(
            "full_key_hash_is_not_legacy_key_identifier",
            verify(&proof, &expected, &changed, &source.leaf),
            "invalid signature entry message",
        )?;
        let mut changed = entry.clone();
        changed.pk_hash = *expected.from.as_bytes();
        rejected(
            "address_is_not_Embedded_key_identifier",
            verify(&proof, &expected, &changed, &source.leaf),
            "invalid signature entry message",
        )?;
        let mut changed = source.leaf;
        changed[31] ^= 1;
        rejected(
            "expected_leaf",
            verify(&proof, &expected, &entry, &changed),
            "signature entry leaf:",
        )?;
        let honest = &proof.identified.transaction_id;
        verify_hash(honest, &honest.message, &honest.output)?;
        let mut changed = proof.clone();
        changed.leaf = honest.clone();
        rejected(
            "honest_ID_certificate_is_not_entry_leaf",
            verify(&changed, &expected, &entry, &honest.output),
            "signature entry leaf:",
        )?;
        let mut changed = expected.clone();
        let mut key = id.public_key.clone();
        key[1951] ^= 1;
        changed.pubkey_mode = PubkeyMode::Embedded(key);
        let control = SigBatchEntry::from_signed_transaction(&changed);
        if control.msg_hash != entry.msg_hash
            || control.pk_hash != entry.pk_hash
            || control.to_leaf_bytes() != source.leaf
        {
            return Err("last-key-byte control unexpectedly changed legacy entry/leaf".into());
        }
        rejected(
            "full_key_tamper_retains_valid_legacy_leaf",
            verify(&proof, &changed, &entry, &source.leaf),
            "sender address source:",
        )?;
        let reference = SignedTransaction::new(
            expected.from,
            expected.tx.clone(),
            expected.signature.clone(),
        );
        rejected(
            "Reference_needs_canonical_registry",
            verify(&proof, &reference, &entry, &source.leaf),
            "signature entry requires",
        )?;
        let bad_dir = Path::new(&args[7]);
        let bad: Identity = read(&bad_dir.join("identity.json"))?;
        if bad.version != 1
            || bad.public_key != id.public_key
            || bad.message != id.message
            || bad.signature.len() != 3309
            || bad.signature == id.signature
            || bad.signature[..3248] != id.signature[..3248]
        {
            return Err("invalid honest altered-hint identity".into());
        }
        let altered = SignedTransaction::with_pubkey(
            expected.from,
            expected.tx.clone(),
            PQSignature::new(SignatureType::MlDsa65, bad.signature),
            id.public_key.clone(),
        );
        let control = SigBatchEntry::from_signed_transaction(&altered);
        if control.msg_hash != entry.msg_hash
            || control.pk_hash != entry.pk_hash
            || control.to_leaf_bytes() != source.leaf
            || altered.hash().as_bytes() != &id_source.transaction_id
        {
            return Err("altered signature changed native entry/leaf/ID".into());
        }
        let mut changed = proof.clone();
        changed
            .identified
            .sender
            .transaction
            .signature
            .equation
            .signature = read(&bad_dir.join("signature.json"))?;
        changed
            .identified
            .sender
            .transaction
            .signature
            .completion
            .finish = read(&bad_dir.join("finish.json"))?;
        changed
            .identified
            .sender
            .transaction
            .signature
            .completion
            .commitment = read(&bad_dir.join("commitment.json"))?;
        rejected(
            "honest_invalid_signature_retains_valid_entry_leaf_ID",
            verify(&changed, &altered, &entry, &source.leaf),
            "signature: final commitment:",
        )?;
        println!(
            "{}",
            serde_json::json!({"mode":"check-entry-rejections","positive_full_graph_verified":true,"rejected":cases,"proofs_generated":0,"input_files_read_only":true,"native_tail_key_preserves_legacy_leaf_control":true,"native_invalid_signature_preserves_entry_leaf_ID_control":true})
        );
        return Ok(());
    }
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"authenticated_entry_leaf_full_graph_verified":true,"verified_entry_snapshot":true,"msg_hash":verified.entry().msg_hash,"legacy_pk_identifier":verified.entry().pk_hash,"leaf":verified.leaf_bytes(),"transaction_id":verified.transaction_id(),"leaf_preimage_bytes":proof.leaf.message.len(),"leaf_compressions":proof.leaf.compressions.len(),"new_hash_certificates":generated,"prior_graph_reused":true,"native_entry_and_leaf_producer_control":proving,"native_acceptance_fallback":false,"registry_absence_proved":false,"account_authority_proved":false,"ordered_batch_proved":false,"canonical_chain_membership_proved":false,"private_witness":false,"node_integrated":false})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mode = args.first().ok_or("missing mode")?;
    let entry = mode == "prove-entry" || mode == "verify-entry" || mode == "check-entry-rejections";
    let identified = mode == "prove-identified"
        || mode == "verify-identified"
        || mode == "check-identified-rejections";
    let derived =
        mode == "prove-derived" || mode == "verify-derived" || mode == "check-derived-rejections";
    let expected_len = if mode == "check-entry-rejections" {
        8
    } else if entry || mode == "check-identified-rejections" {
        7
    } else if identified {
        6
    } else if derived || mode == "check-rejections" {
        5
    } else if mode == "verify" {
        4
    } else {
        return Err("unknown mode".into());
    };
    if args.len() != expected_len {
        return Err("usage: mldsa-source verify source-dir equation-dir signature-dir; check-rejections source-dir equation-dir signature-dir rejection-dir; prove-derived|verify-derived|check-derived-rejections source-dir equation-dir signature-dir sender-dir; prove-identified|verify-identified source-dir equation-dir signature-dir sender-dir ID-dir; check-identified-rejections source-dir equation-dir signature-dir sender-dir ID-dir rejection-dir; prove-entry|verify-entry source-dir equation-dir signature-dir sender-dir ID-dir entry-dir; check-entry-rejections source-dir equation-dir signature-dir sender-dir ID-dir entry-dir rejection-dir".into());
    }
    let (p, s, id) = load_transaction_proof(
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    )?;
    if entry {
        return signature_entry(p, &s, &id, &args);
    }
    if identified {
        return identified_sender(p, &s, &id, &args);
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
