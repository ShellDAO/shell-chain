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
        #[cfg(feature = "rocksdb")]
        Some("l2-state") => {
            let stores = shell_storage::RocksDbStore::open_all(&args[2], None)?;
            let store = std::sync::Arc::new(stores.state);
            let jobs = shell_storage::L2JobStore::new(store.clone()).all_jobs()?;
            let inputs = shell_storage::L2InputIndex::new(store.clone()).all_hashes()?;
            let chain = shell_storage::ChainStore::new(store);
            let head = chain.get_head_block()?.map(|b| b.number()).unwrap_or(0);
            let mut canonical_l1_inputs = Vec::new();
            for height in 0..=head {
                if let Some(block) = chain.get_block_by_number(height)? {
                    for tx in &block.system_transactions {
                        if tx.kind != shell_core::SystemTxKind::StarkReward {
                            continue;
                        }
                        let Some(payload) = tx.proof_payload.as_ref() else {
                            continue;
                        };
                        let amendment = ProofAmendment::from_json(payload.as_ref())?;
                        if amendment.layer != 1 {
                            continue;
                        }
                        amendment.verify_prover_authentication()?;
                        verify_sig_batch(&amendment.proof)?;
                        canonical_l1_inputs.push(serde_json::json!({
                            "hash": amendment.block_hash, "start": amendment.range_start_block(),
                            "end": amendment.block_number, "root": amendment.proof.batch_root_bytes,
                            "settlement_block": height
                        }));
                    }
                }
            }
            std::fs::write(
                &args[3],
                serde_json::to_vec_pretty(&serde_json::json!({
                    "jobs": jobs, "inputs": inputs, "canonical_l1_inputs": canonical_l1_inputs
                }))?,
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
        _ => {
            return Err(
                "usage: prover-acceptance inputs|verify FILE, or l2-state DB OUTPUT (rocksdb)"
                    .into(),
            )
        }
    }
    Ok(())
}
