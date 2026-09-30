//! Fresh transaction inputs and independent verification for the prover E2E driver.
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{MlDsaSigner, Signer};
use shell_primitives::{Address, Bytes, U256};
use shell_stark_prover::{verify_sig_batch, ProofAmendment};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("inputs") => {
            let signer = MlDsaSigner::generate();
            let address = Address::from_public_key(signer.public_key(), 1);
            let transactions: Vec<_> = (0..512)
                .map(|nonce| {
                    let tx = Transaction {
                        chain_id: 1337,
                        nonce,
                        to: Some(Address::from([0xab; 32])),
                        value: U256::from(1),
                        data: Bytes::default(),
                        gas_limit: 21_000,
                        max_fee_per_gas: 1_000_000_000,
                        max_priority_fee_per_gas: 0,
                        access_list: None,
                        tx_type: 2,
                        max_fee_per_blob_gas: None,
                        blob_versioned_hashes: None,
                    };
                    let signature = signer
                        .sign(tx.signing_hash(1).as_bytes())
                        .expect("sign transfer");
                    let signed = SignedTransaction::with_pubkey(
                        address,
                        tx,
                        signature,
                        signer.public_key().to_vec(),
                    );
                    format!("0x{}", hex::encode(alloy_rlp::encode(&signed)))
                })
                .collect();
            std::fs::write(
                &args[2],
                serde_json::to_vec(
                    &serde_json::json!({"address": address, "transactions": transactions}),
                )?,
            )?;
        }
        Some("verify") => {
            let bytes = std::fs::read(&args[2])?;
            let amendment = ProofAmendment::from_json(&bytes)?;
            assert!(amendment.proof.n_sigs >= 512);
            assert!(!amendment.proof.proof_bytes.is_empty());
            amendment.verify_prover_authentication()?;
            verify_sig_batch(&amendment.proof)?;
            let mut altered = amendment.clone();
            let last = altered.proof.proof_bytes.len() - 1;
            altered.proof.proof_bytes[last] ^= 1;
            assert!(verify_sig_batch(&altered.proof).is_err());
            assert!(altered.verify_prover_authentication().is_err());
            let mut altered = amendment.clone();
            altered.block_number += 1;
            assert!(altered.verify_prover_authentication().is_err());
            let mut altered = amendment.clone();
            altered.proof.batch_root_bytes[0] ^= 1;
            assert!(verify_sig_batch(&altered.proof).is_err());
            assert!(altered.verify_prover_authentication().is_err());
            println!("STARK proof, prover authentication, and tamper rejection verified");
        }
        _ => return Err("usage: prover-acceptance inputs|verify FILE".into()),
    }
    Ok(())
}
