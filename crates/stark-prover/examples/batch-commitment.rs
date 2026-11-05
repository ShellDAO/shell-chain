//! Demonstrate the current batch-commitment statement and its verification boundaries.

use shell_crypto::{MlDsaSigner, MlDsaVerifier, Signer, Verifier};
use shell_stark_prover::{
    compute_batch_root, prove_sig_batch, verify_sig_batch, SigBatchEntry, SigBatchProof,
};

fn main() {
    // This temporary key never leaves memory. These messages are examples,
    // not transactions or canonical source-block metadata.
    let signer = MlDsaSigner::generate();
    let verifier = MlDsaVerifier;
    let pk_hash = *blake3::hash(signer.public_key()).as_bytes();
    let mut entries = Vec::new();
    let mut signatures = Vec::new();
    for message in [
        b"batch-commitment-first".as_slice(),
        b"batch-commitment-second",
    ] {
        let msg_hash = *blake3::hash(message).as_bytes();
        let signature = signer.sign(&msg_hash).expect("sign example message");
        assert!(
            verifier
                .verify(signer.public_key(), &msg_hash, &signature)
                .expect("decode valid native signature"),
            "native ML-DSA verification must precede commitment generation"
        );
        entries.push(SigBatchEntry { msg_hash, pk_hash });
        signatures.push(signature);
    }

    let expected_root = compute_batch_root(&entries);
    let proof = prove_sig_batch(&entries).expect("generate actual Winterfell proof");
    assert!(proof.has_proof());
    assert_eq!(proof.n_sigs, entries.len());
    assert_eq!(proof.batch_root_bytes, expected_root);
    verify_sig_batch(&proof).expect("verify the batch-commitment STARK");

    let json = serde_json::to_vec(&proof).expect("serialize proof");
    let decoded: SigBatchProof = serde_json::from_slice(&json).expect("parse proof");
    assert_eq!(decoded.batch_root_bytes, expected_root);
    assert_eq!(decoded.proof_bytes, proof.proof_bytes);
    verify_sig_batch(&decoded).expect("verify parsed proof");

    let mut bad_signature = signatures[0].clone();
    bad_signature.data[0] ^= 1;
    let signature_rejected = !verifier
        .verify(signer.public_key(), &entries[0].msg_hash, &bad_signature)
        .expect("verify altered signature with unchanged encoding lengths");
    assert!(signature_rejected);
    let mut wrong_message = entries[0].msg_hash;
    wrong_message[0] ^= 1;
    let message_rejected = !verifier
        .verify(signer.public_key(), &wrong_message, &signatures[0])
        .expect("verify altered message");
    assert!(message_rejected);

    // SigBatchEntry contains message/key hashes, not raw signatures. Changing
    // a signature does not change these entries or invalidate this proof:
    // native signature validity is not a constraint of the current AIR.
    assert_eq!(compute_batch_root(&entries), expected_root);
    verify_sig_batch(&proof).expect("unchanged commitment still verifies");

    let mut wrong_entries = entries.clone();
    wrong_entries[0].msg_hash = wrong_message;
    let source_mismatch = compute_batch_root(&wrong_entries) != proof.batch_root_bytes;
    assert!(
        source_mismatch,
        "bind the proof to the expected source entries"
    );

    let mut bad_root = proof.clone();
    bad_root.batch_root_bytes[0] ^= 1;
    let root_rejected = verify_sig_batch(&bad_root).is_err();
    assert!(root_rejected);
    let mut bad_count = proof.clone();
    bad_count.n_sigs += 1;
    let count_rejected = verify_sig_batch(&bad_count).is_err();
    assert!(count_rejected);
    let mut bad_bytes = proof.clone();
    bad_bytes
        .proof_bytes
        .truncate(bad_bytes.proof_bytes.len() / 2);
    let bytes_rejected = verify_sig_batch(&bad_bytes).is_err();
    assert!(bytes_rejected);
    let commitment = SigBatchProof::commitment_only(expected_root, entries.len());
    let commitment_only_rejected = verify_sig_batch(&commitment).is_err();
    assert!(commitment_only_rejected);

    println!(
        "{}",
        serde_json::json!({
            "native_signatures_verified": signatures.len(),
            "proof_version": proof.version,
            "stark_bytes": proof.proof_bytes.len(),
            "native_signature_tamper_rejected": signature_rejected,
            "native_message_tamper_rejected": message_rejected,
            "source_entries_mismatch_detected": source_mismatch,
            "proof_root_tamper_rejected": root_rejected,
            "proof_count_tamper_rejected": count_rejected,
            "proof_bytes_tamper_rejected": bytes_rejected,
            "commitment_only_rejected": commitment_only_rejected
        })
    );
}
