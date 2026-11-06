//! Native block-commitment-v1. See `docs/block-commitments.md` for the byte format.
use alloy_rlp::Encodable;
use shell_primitives::{blake3_hash, ShellHash};

use crate::{SignedTransaction, SystemTransaction, TransactionReceipt};

const BODY_DOMAIN: &[u8] = b"SHELL_BODY_V1\0";
const RECEIPT_DOMAIN: &[u8] = b"SHELL_RECEIPTS_V1\0";

fn leaf_message(domain: &[u8], index: u64, kind: u8, value: &impl Encodable) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + 10 + value.length());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.push(kind);
    value.encode(&mut bytes);
    bytes
}
fn leaf(domain: &[u8], index: usize, kind: u8, value: &impl Encodable) -> ShellHash {
    blake3_hash(&leaf_message(domain, index as u64, kind, value))
}
fn branch_message(domain: &[u8], left: ShellHash, right: ShellHash, bytes: &mut Vec<u8>) {
    bytes.clear();
    bytes.extend_from_slice(domain);
    bytes.push(1);
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
}
fn count_message(domain: &[u8], count: u64, top: ShellHash, bytes: &mut Vec<u8>) {
    bytes.clear();
    bytes.extend_from_slice(domain);
    bytes.push(2);
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(top.as_bytes());
}
fn reduce_level(domain: &[u8], leaves: &mut Vec<ShellHash>, bytes: &mut Vec<u8>) {
    let next_len = leaves.len().div_ceil(2);
    for index in 0..next_len {
        let left = leaves[index * 2];
        leaves[index] = match leaves.get(index * 2 + 1) {
            Some(right) => {
                branch_message(domain, left, *right, bytes);
                blake3_hash(bytes)
            }
            None => left,
        };
    }
    leaves.truncate(next_len);
}
fn root(domain: &[u8], mut leaves: Vec<ShellHash>) -> ShellHash {
    let count = leaves.len() as u64;
    let mut bytes = Vec::with_capacity(domain.len() + 65);
    while leaves.len() > 1 {
        reduce_level(domain, &mut leaves, &mut bytes);
    }
    count_message(
        domain,
        count,
        leaves.first().copied().unwrap_or(ShellHash::ZERO),
        &mut bytes,
    );
    blake3_hash(&bytes)
}
fn body_leaves(
    transactions: &[SignedTransaction],
    system_transactions: &[SystemTransaction],
) -> Result<Vec<ShellHash>, serde_json::Error> {
    let mut leaves: Vec<_> = transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| leaf(BODY_DOMAIN, i, 0, tx))
        .collect();
    for (i, tx) in system_transactions.iter().enumerate() {
        let wire = tx.to_wire_bytes()?;
        leaves.push(leaf(BODY_DOMAIN, transactions.len() + i, 1, &wire));
    }
    Ok(leaves)
}
/// Commit to exact signed transaction RLP, followed by system wire byte-string RLP.
/// The witness-independent, potentially cached transaction ID is not used.
pub fn block_body_root(
    transactions: &[SignedTransaction],
    system_transactions: &[SystemTransaction],
) -> Result<ShellHash, serde_json::Error> {
    Ok(root(
        BODY_DOMAIN,
        body_leaves(transactions, system_transactions)?,
    ))
}

/// Ordered native v1 path; unpaired nodes are carried without a sibling.
/// This is path data, not a verified result or proof of consensus.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyMembershipPath {
    pub index: u64,
    pub total: u64,
    pub siblings: Vec<ShellHash>,
}
/// Construct a path for an ordinary transaction in the complete native body.
pub fn block_body_membership_path(
    transactions: &[SignedTransaction],
    system_transactions: &[SystemTransaction],
    index: usize,
) -> Result<BodyMembershipPath, String> {
    if index >= transactions.len() {
        return Err("ordinary transaction index outside body".into());
    }
    let mut leaves = body_leaves(transactions, system_transactions).map_err(|e| e.to_string())?;
    let total = leaves.len() as u64;
    let mut cursor = index;
    let mut siblings = Vec::new();
    let mut bytes = Vec::new();
    while leaves.len() > 1 {
        if cursor % 2 == 1 {
            siblings.push(leaves[cursor - 1]);
        } else if cursor + 1 < leaves.len() {
            siblings.push(leaves[cursor + 1]);
        }
        reduce_level(BODY_DOMAIN, &mut leaves, &mut bytes);
        cursor /= 2;
    }
    Ok(BodyMembershipPath {
        index: index as u64,
        total,
        siblings,
    })
}
/// Exact native v1 ordinary signed-leaf bytes, shared with the block producer.
pub fn block_body_leaf_message(transaction: &SignedTransaction, index: u64) -> Vec<u8> {
    leaf_message(BODY_DOMAIN, index, 0, transaction)
}
/// Exact native v1 internal-node bytes.
pub fn block_body_parent_message(left: ShellHash, right: ShellHash) -> Vec<u8> {
    let mut bytes = Vec::new();
    branch_message(BODY_DOMAIN, left, right, &mut bytes);
    bytes
}
/// Exact native v1 final count-binding bytes.
pub fn block_body_root_message(total: u64, top: ShellHash) -> Vec<u8> {
    let mut bytes = Vec::new();
    count_message(BODY_DOMAIN, total, top, &mut bytes);
    bytes
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
