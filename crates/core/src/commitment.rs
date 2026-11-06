//! Native block-commitment-v1. See `docs/block-commitments.md` for the byte format.
use alloy_rlp::Encodable;
use shell_primitives::{blake3_hash, ShellHash};

use crate::{SignedTransaction, SystemTransaction, TransactionReceipt};

const BODY_DOMAIN: &[u8] = b"SHELL_BODY_V1\0";
const RECEIPT_DOMAIN: &[u8] = b"SHELL_RECEIPTS_V1\0";

fn leaf(domain: &[u8], index: usize, kind: u8, value: &impl Encodable) -> ShellHash {
    let mut bytes = Vec::with_capacity(domain.len() + 10 + value.length());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&(index as u64).to_be_bytes());
    bytes.push(kind);
    value.encode(&mut bytes);
    blake3_hash(&bytes)
}

fn root(domain: &[u8], mut leaves: Vec<ShellHash>) -> ShellHash {
    let count = leaves.len() as u64;
    let mut bytes = Vec::with_capacity(domain.len() + 65);
    while leaves.len() > 1 {
        let next_len = leaves.len().div_ceil(2);
        for index in 0..next_len {
            let left = leaves[index * 2];
            leaves[index] = match leaves.get(index * 2 + 1) {
                Some(right) => {
                    bytes.clear();
                    bytes.extend_from_slice(domain);
                    bytes.push(1);
                    bytes.extend_from_slice(left.as_bytes());
                    bytes.extend_from_slice(right.as_bytes());
                    blake3_hash(&bytes)
                }
                None => left,
            };
        }
        leaves.truncate(next_len);
    }
    bytes.clear();
    bytes.extend_from_slice(domain);
    bytes.push(2);
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(leaves.first().unwrap_or(&ShellHash::ZERO).as_bytes());
    blake3_hash(&bytes)
}

/// Commit to exact canonical signed transaction RLP, followed by system wire byte-string RLP.
/// Includes sender, authentication mode, key, signature and any AA bundle;
/// deliberately does not use the witness-independent, potentially cached tx ID.
pub fn block_body_root(
    transactions: &[SignedTransaction],
    system_transactions: &[SystemTransaction],
) -> Result<ShellHash, serde_json::Error> {
    let mut leaves: Vec<_> = transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| leaf(BODY_DOMAIN, i, 0, tx))
        .collect();
    for (i, tx) in system_transactions.iter().enumerate() {
        // System transactions use the existing RLP byte-string envelope around
        // their deterministic struct JSON wire encoding, exactly as Block does.
        let wire = tx.to_wire_bytes()?;
        leaves.push(leaf(BODY_DOMAIN, transactions.len() + i, 1, &wire));
    }
    Ok(root(BODY_DOMAIN, leaves))
}

/// Commit to all native receipts in execution order, including system receipts.
/// The native receipt RLP contains no block hash, avoiding a header hash cycle.
pub fn block_receipts_root(receipts: &[TransactionReceipt]) -> ShellHash {
    root(
        RECEIPT_DOMAIN,
        receipts
            .iter()
            .enumerate()
            .map(|(i, receipt)| leaf(RECEIPT_DOMAIN, i, 0, receipt))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PubkeyMode, Transaction};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::{Address, Bytes, U256};

    fn signed() -> SignedTransaction {
        SignedTransaction::with_pubkey(
            Address::from([1; 32]),
            Transaction {
                chain_id: 10,
                nonce: 0,
                to: Some(Address::from([2; 32])),
                value: U256::from(3),
                data: Bytes::from(vec![4, 5]),
                gas_limit: 100_000,
                max_fee_per_gas: 7,
                max_priority_fee_per_gas: 1,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            PQSignature {
                sig_type: SignatureType::MlDsa65,
                data: vec![6; 3309],
            },
            vec![7; 1952],
        )
    }

    #[test]
    fn independent_vectors_and_odd_tree_shape() {
        assert_eq!(
            block_body_root(&[], &[]).unwrap().to_string(),
            "0x35663fcbda4edd6cfbedf6883dfe44b91c97511dd8f35de92ec70bc64857fe31"
        );
        assert_eq!(
            block_receipts_root(&[]).to_string(),
            "0xba4f27658e4517bfee40f574ae48e56aa0175cf08531dc0d034c9794212f3129"
        );
        let leaves = (1u64..=3)
            .enumerate()
            .map(|(i, n)| leaf(BODY_DOMAIN, i, 0, &n))
            .collect();
        assert_eq!(
            root(BODY_DOMAIN, leaves).to_string(),
            "0x906fed710d30aafb3fa0883cb231eb315f58e7a4762441146a8d8ac44da302ff"
        );
        let tx = signed();
        let a = block_body_root(&[tx.clone(), tx.clone(), tx.clone()], &[]).unwrap();
        let b = block_body_root(&[tx.clone(), tx.clone(), tx.clone(), tx], &[]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn body_binds_witness_sender_order_and_system_option_presence() {
        let tx = signed();
        let id = tx.hash();
        let expected = block_body_root(std::slice::from_ref(&tx), &[]).unwrap();
        for mutation in 0..5 {
            let mut changed = tx.clone();
            match mutation {
                0 => changed.signature.data[0] ^= 1,
                1 => changed.pubkey_mode = PubkeyMode::Reference,
                2 => {
                    if let PubkeyMode::Embedded(ref mut key) = changed.pubkey_mode {
                        key[0] ^= 1;
                    }
                }
                3 => changed.from = Address::from([8; 32]),
                _ => changed.tx.nonce = 99,
            }
            assert_eq!(changed.hash(), id, "fixture must retain the cached ID");
            assert_ne!(block_body_root(&[changed], &[]).unwrap(), expected);
        }
        let mut second = tx.clone();
        second.tx.nonce = 1;
        assert_ne!(
            block_body_root(&[tx.clone(), second.clone()], &[]).unwrap(),
            block_body_root(&[second, tx.clone()], &[]).unwrap()
        );
        let reward = SystemTransaction::block_gas_reward(
            10,
            1,
            1,
            Address::from([9; 32]),
            U256::from(10),
            ShellHash::ZERO,
        );
        let mut changed = reward.clone();
        changed.layer = Some(0);
        assert_eq!(
            reward.hash(),
            changed.hash(),
            "legacy ID collapses this option"
        );
        assert_ne!(
            block_body_root(std::slice::from_ref(&tx), &[reward]).unwrap(),
            block_body_root(&[tx], &[changed]).unwrap()
        );
    }

    #[test]
    fn receipts_bind_status_gas_address_bloom_logs_and_order() {
        let receipt = TransactionReceipt {
            tx_hash: signed().hash(),
            block_number: 2,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: None,
            logs_bloom: Bytes::from(vec![0; 256]),
            logs: vec![],
        };
        let expected = block_receipts_root(std::slice::from_ref(&receipt));
        for mutation in 0..8 {
            let mut changed = receipt.clone();
            match mutation {
                0 => changed.status = 0,
                1 => changed.gas_used += 1,
                2 => changed.cumulative_gas_used += 1,
                3 => changed.contract_address = Some(Address::from([3; 32])),
                4 => changed.logs_bloom = Bytes::from(vec![1; 256]),
                5 => changed.block_number += 1,
                6 => changed.tx_index += 1,
                _ => changed.logs.push(crate::Log {
                    address: Address::from([3; 32]),
                    topics: vec![ShellHash::from([4; 32])],
                    data: Bytes::from(vec![5]),
                }),
            }
            assert_ne!(block_receipts_root(&[changed.clone()]), expected);
            assert_ne!(
                block_receipts_root(&[receipt.clone(), changed.clone()]),
                block_receipts_root(&[changed, receipt.clone()])
            );
        }
    }
}
