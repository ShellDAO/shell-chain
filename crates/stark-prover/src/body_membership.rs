//! Complete BLAKE3 AIR membership of an exact public native signed envelope.
//! A caller must authenticate the expected header; membership alone proves no consensus.
use crate::blake3_hash::{
    prove_body_hash, prove_hash, verify_body_hash, verify_hash, Blake3HashProof,
    MAX_BODY_HASH_BYTES,
};
use alloy_rlp::Encodable;
use serde::{Deserialize, Serialize};
use shell_core::{
    block_body_leaf_message, block_body_membership_path, block_body_parent_message,
    block_body_root, block_body_root_message, Block, BlockHeader, BodyMembershipPath,
    SignedTransaction,
};
use shell_primitives::ShellHash;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionBodyProof {
    pub version: u8,
    pub path: BodyMembershipPath,
    pub leaf: Blake3HashProof,
    pub parents: Vec<Blake3HashProof>,
    pub root: Blake3HashProof,
}
/// Immutable verified membership, without a public constructor or Deserialize.
#[derive(Clone, Debug)]
pub struct VerifiedBodyMembership {
    block_hash: ShellHash,
    index: u64,
    total: u64,
}
impl VerifiedBodyMembership {
    pub fn block_hash(&self) -> ShellHash {
        self.block_hash
    }
    pub fn index(&self) -> u64 {
        self.index
    }
    pub fn total(&self) -> u64 {
        self.total
    }
}
fn check_path(path: &BodyMembershipPath) -> Result<(), String> {
    if path.total == 0 || path.index >= path.total || path.siblings.len() > 64 {
        return Err("invalid native body path bounds".into());
    }
    Ok(())
}
fn walk(
    path: &BodyMembershipPath,
    mut digest: ShellHash,
    mut hash: impl FnMut(Vec<u8>) -> Result<ShellHash, String>,
) -> Result<ShellHash, String> {
    check_path(path)?;
    let (mut width, mut index, mut cursor) = (path.total, path.index, 0);
    while width > 1 {
        if index % 2 == 1 || index < width - 1 {
            let sibling = *path
                .siblings
                .get(cursor)
                .ok_or("missing native body sibling")?;
            let (left, right) = if index % 2 == 1 {
                (sibling, digest)
            } else {
                (digest, sibling)
            };
            digest = hash(block_body_parent_message(left, right))?;
            cursor += 1;
        }
        index /= 2;
        width = width / 2 + width % 2;
    }
    if cursor != path.siblings.len() {
        return Err("extra native body siblings".into());
    }
    Ok(digest)
}
/// Generate real compression certificates for the full envelope and every path hash.
/// System siblings are included by the native body path; only ordinary leaves are targets.
pub fn prove_transaction_body(block: &Block, index: usize) -> Result<TransactionBodyProof, String> {
    let transaction = block
        .transactions
        .get(index)
        .ok_or("ordinary body transaction absent")?;
    if transaction.length() > MAX_BODY_HASH_BYTES {
        return Err("native body leaf exceeds proof resource bound".into());
    }
    let message = block_body_leaf_message(transaction, index as u64);
    if message.len() > MAX_BODY_HASH_BYTES {
        return Err("native body leaf exceeds proof resource bound".into());
    }
    if block_body_root(&block.transactions, &block.system_transactions)
        .map_err(|e| e.to_string())?
        != block.header.transactions_root
    {
        return Err("native body/header root mismatch".into());
    }
    let path = block_body_membership_path(&block.transactions, &block.system_transactions, index)?;
    let leaf = prove_body_hash(&message)?;
    let mut parents = Vec::new();
    let top = walk(&path, ShellHash::from(leaf.output), |bytes| {
        let proof = prove_hash(&bytes)?;
        let output = ShellHash::from(proof.output);
        parents.push(proof);
        Ok(output)
    })?;
    let root = prove_hash(&block_body_root_message(path.total, top))?;
    if root.output != *block.header.transactions_root.as_bytes() {
        return Err("proved native body root mismatch".into());
    }
    Ok(TransactionBodyProof {
        version: 1,
        path,
        leaf,
        parents,
        root,
    })
}
/// Verify every actual AIR certificate and public byte/chaining/tree route.
/// Native BLAKE3 is never an acceptance fallback. Header hashing here only labels
/// the result; the caller must authenticate the selected header and activation.
pub fn verify_transaction_body(
    proof: &TransactionBodyProof,
    header: &BlockHeader,
    transaction: &SignedTransaction,
    expected_index: u64,
) -> Result<VerifiedBodyMembership, String> {
    check_path(&proof.path)?;
    if proof.version != 1
        || proof.path.index != expected_index
        || proof.parents.len() > 64
        || proof.root.output != *header.transactions_root.as_bytes()
    {
        return Err("native body proof version/index/header binding mismatch".into());
    }
    if transaction.length() > MAX_BODY_HASH_BYTES {
        return Err("native body leaf exceeds proof resource bound".into());
    }
    let message = block_body_leaf_message(transaction, expected_index);
    verify_body_hash(&proof.leaf, &message, &proof.leaf.output)?;
    let mut index = 0;
    let top = walk(&proof.path, ShellHash::from(proof.leaf.output), |bytes| {
        let child = proof
            .parents
            .get(index)
            .ok_or("missing native body parent certificate")?;
        verify_hash(child, &bytes, &child.output)?;
        index += 1;
        Ok(ShellHash::from(child.output))
    })?;
    if index != proof.parents.len() {
        return Err("extra native body parent certificates".into());
    }
    verify_hash(
        &proof.root,
        &block_body_root_message(proof.path.total, top),
        header.transactions_root.as_bytes(),
    )?;
    Ok(VerifiedBodyMembership {
        block_hash: header.hash(),
        index: expected_index,
        total: proof.path.total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{PubkeyMode, Transaction};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::{Address, Bytes, U256};
    fn tx(nonce: u64) -> SignedTransaction {
        SignedTransaction::with_pubkey(
            Address::from([1; 32]),
            Transaction {
                chain_id: 10,
                nonce,
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
            },
            PQSignature {
                sig_type: SignatureType::MlDsa65,
                data: vec![3; 8],
            },
            vec![4; 8],
        )
    }
    fn block() -> Block {
        // Small routing fixtures are not claimed as valid signature/execution cases.
        let transactions = vec![tx(0), tx(1), tx(2)];
        let header = BlockHeader {
            transactions_root: block_body_root(&transactions, &[]).unwrap(),
            number: 1,
            ..Default::default()
        };
        Block {
            header,
            transactions,
            system_transactions: vec![],
            proposer_seal: None,
        }
    }
    #[test]
    fn native_paths_cover_odd_carry_and_count_for_every_position() {
        for count in 1..=7 {
            let transactions: Vec<_> = (0..count).map(tx).collect();
            let expected = block_body_root(&transactions, &[]).unwrap();
            for index in 0..count as usize {
                let path = block_body_membership_path(&transactions, &[], index).unwrap();
                let digest = shell_primitives::blake3_hash(&block_body_leaf_message(
                    &transactions[index],
                    index as u64,
                ));
                let top = walk(&path, digest, |m| Ok(shell_primitives::blake3_hash(&m))).unwrap();
                assert_eq!(
                    shell_primitives::blake3_hash(&block_body_root_message(path.total, top)),
                    expected
                );
            }
        }
        assert!(block_body_membership_path(&[], &[], 0).is_err());
        assert!(block_body_membership_path(&[tx(0)], &[], 1).is_err());
    }
    #[test]
    fn real_air_membership_json_and_mutation_refusals() {
        let block = block();
        let proof = prove_transaction_body(&block, 2).unwrap();
        assert_eq!(proof.path.siblings.len(), 1); // odd leaf carries, then joins left subtree
        let proof: TransactionBodyProof =
            serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
        let token =
            verify_transaction_body(&proof, &block.header, &block.transactions[2], 2).unwrap();
        assert_eq!(token.block_hash(), block.hash());
        assert_eq!(token.total(), 3);
        for kind in 0..11 {
            let mut changed = proof.clone();
            match kind {
                0 => changed.version = 2,
                1 => changed.path.total = 0,
                2 => changed.path.index = 1,
                3 => changed.path.total = 4,
                4 => changed.path.siblings.clear(),
                5 => changed.path.siblings.push(ShellHash::ZERO),
                6 => changed.parents.clear(),
                7 => changed.parents.push(changed.parents[0].clone()),
                8 => changed.leaf.version = 1,
                9 => changed.root.version = 2,
                _ => changed.leaf.compressions[0].input.counter += 1,
            }
            assert!(
                verify_transaction_body(&changed, &block.header, &block.transactions[2], 2)
                    .is_err(),
                "kind {kind}"
            );
        }
        let mut changed = block.transactions[2].clone();
        let cached = changed.hash();
        changed.signature.data[0] ^= 1;
        assert_eq!(changed.hash(), cached);
        assert!(verify_transaction_body(&proof, &block.header, &changed, 2).is_err());
        changed.pubkey_mode = PubkeyMode::Reference;
        assert!(verify_transaction_body(&proof, &block.header, &changed, 2).is_err());
        let mut wrong = block.header.clone();
        wrong.transactions_root = ShellHash::ZERO;
        assert!(verify_transaction_body(&proof, &wrong, &block.transactions[2], 2).is_err());
    }
}
