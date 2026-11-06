//! Bounded AIR proof of the exact native header hash, including nested hashes.
//! The independently expected hash still requires consensus authentication.
use crate::blake3_hash::{prove_hash, verify_hash, Blake3HashProof, MAX_HASH_BYTES};
use serde::{Deserialize, Serialize};
use shell_core::BlockHeader;
use shell_primitives::ShellHash;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeaderProof {
    pub version: u8,
    pub logs_bloom: Blake3HashProof,
    pub extra_data: Blake3HashProof,
    pub sig_aggregate_proof: Option<Blake3HashProof>,
    pub canonical: Blake3HashProof,
}

/// Verified native hash, without a public constructor or Deserialize.
#[derive(Clone, Debug)]
pub struct VerifiedHeaderHash(ShellHash);
impl VerifiedHeaderHash {
    pub fn hash(&self) -> ShellHash {
        self.0
    }
}

fn check_bounds(header: &BlockHeader) -> Result<(), String> {
    if header.logs_bloom.len() > MAX_HASH_BYTES
        || header.extra_data.len() > MAX_HASH_BYTES
        || header
            .sig_aggregate_proof
            .as_ref()
            .is_some_and(|p| p.len() > MAX_HASH_BYTES)
    {
        return Err("native header field exceeds development proof bound".into());
    }
    Ok(())
}

/// Produce real v1 compression certificates without changing native encoding.
pub fn prove_header_hash(header: &BlockHeader) -> Result<BlockHeaderProof, String> {
    check_bounds(header)?;
    let logs_bloom = prove_hash(header.logs_bloom.as_ref())?;
    let extra_data = prove_hash(header.extra_data.as_ref())?;
    let sig_aggregate_proof = header
        .sig_aggregate_proof
        .as_ref()
        .map(|p| prove_hash(p.as_ref()))
        .transpose()?;
    let canonical = prove_hash(
        &header.canonical_encode_with_field_hashes(
            logs_bloom.output.into(),
            extra_data.output.into(),
            sig_aggregate_proof
                .as_ref()
                .map_or(ShellHash::ZERO, |p| p.output.into()),
        ),
    )?;
    Ok(BlockHeaderProof {
        version: 1,
        logs_bloom,
        extra_data,
        sig_aggregate_proof,
        canonical,
    })
}

/// Authenticate all nested hashes and every byte of the native 424-byte layout.
/// There is no call to native BLAKE3 in verification. None/Some(empty) aggregate
/// commitments differ; an absent witness root equals a present zero root, as
/// required by the native hash encoding (not by serialized-header equality).
pub fn verify_header_hash(
    proof: &BlockHeaderProof,
    header: &BlockHeader,
    expected_hash: &ShellHash,
) -> Result<VerifiedHeaderHash, String> {
    check_bounds(header)?;
    if proof.version != 1
        || proof.sig_aggregate_proof.is_some() != header.sig_aggregate_proof.is_some()
    {
        return Err("native header proof version or optional aggregate mismatch".into());
    }
    let message = header.canonical_encode_with_field_hashes(
        proof.logs_bloom.output.into(),
        proof.extra_data.output.into(),
        proof
            .sig_aggregate_proof
            .as_ref()
            .map_or(ShellHash::ZERO, |p| p.output.into()),
    );
    // Refuse changed fixed fields/digests before expensive certificate checks.
    if proof.canonical.message != message || proof.canonical.output != *expected_hash.as_bytes() {
        return Err("native header fixed bytes or expected hash mismatch".into());
    }
    verify_hash(
        &proof.logs_bloom,
        header.logs_bloom.as_ref(),
        &proof.logs_bloom.output,
    )?;
    verify_hash(
        &proof.extra_data,
        header.extra_data.as_ref(),
        &proof.extra_data.output,
    )?;
    if let (Some(p), Some(bytes)) = (&proof.sig_aggregate_proof, &header.sig_aggregate_proof) {
        verify_hash(p, bytes.as_ref(), &p.output)?;
    }
    verify_hash(&proof.canonical, &message, expected_hash.as_bytes())?;
    Ok(VerifiedHeaderHash(*expected_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::{Address, Bytes};

    #[test]
    fn header_air_binds_fields_optional_commitments_and_json() {
        let header = BlockHeader {
            parent_hash: [1; 32].into(),
            state_root: [2; 32].into(),
            transactions_root: [3; 32].into(),
            receipts_root: [4; 32].into(),
            logs_bloom: Bytes::from(vec![5; 65]),
            number: 0x0102030405060708,
            gas_limit: 0x1112131415161718,
            gas_used: 19,
            timestamp: 20,
            extra_data: Bytes::from(vec![6; 65]),
            proposer: Address::from([7; 32]),
            sig_aggregate_proof: Some(Bytes::new()),
            base_fee_per_gas: 21,
            withdrawals_root: [8; 32].into(),
            parent_beacon_block_root: [9; 32].into(),
            blob_gas_used: 22,
            excess_blob_gas: 23,
            witness_root: Some([10; 32].into()),
        };
        // Independent fixed-layout BLAKE3 vector, pinned across encoder changes.
        assert_eq!(
            header.hash().to_string(),
            "0xa8e93ead4c8f6e05585364a0e7144f7d51dfd6d72a6012718600ac7df2734743"
        );
        let proof = prove_header_hash(&header).unwrap();
        let hash = header.hash();
        let encoded = serde_json::to_value(&proof).unwrap();
        let decoded: BlockHeaderProof = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(
            verify_header_hash(&decoded, &header, &hash).unwrap().hash(),
            hash
        );
        assert_eq!(proof.canonical.message, header.canonical_encode());
        assert_eq!(
            &proof.canonical.message[176..184],
            &header.number.to_le_bytes()
        );
        assert!(verify_header_hash(&proof, &header, &ShellHash::ZERO).is_err());
        for field in 0..18 {
            let mut h = header.clone();
            match field {
                0 => h.parent_hash = ShellHash::ZERO,
                1 => h.state_root = ShellHash::ZERO,
                2 => h.transactions_root = ShellHash::ZERO,
                3 => h.receipts_root = ShellHash::ZERO,
                4 => h.logs_bloom = Bytes::new(),
                5 => h.number += 1,
                6 => h.gas_limit += 1,
                7 => h.gas_used += 1,
                8 => h.timestamp += 1,
                9 => h.extra_data = Bytes::new(),
                10 => h.proposer = Address::ZERO,
                11 => h.sig_aggregate_proof = None,
                12 => h.base_fee_per_gas += 1,
                13 => h.withdrawals_root = ShellHash::ZERO,
                14 => h.parent_beacon_block_root = ShellHash::ZERO,
                15 => h.blob_gas_used += 1,
                16 => h.excess_blob_gas += 1,
                _ => h.witness_root = None,
            }
            assert!(
                verify_header_hash(&proof, &h, &hash).is_err(),
                "field {field}"
            );
        }
        for kind in 0..10 {
            let mut p = proof.clone();
            match kind {
                0 => p.version += 1,
                1 => p.canonical.version += 1,
                2 => p.logs_bloom.version = 2,
                3 => p.extra_data.compressions.clear(),
                4 => {
                    p.canonical.compressions.pop();
                }
                5 => p.sig_aggregate_proof = None,
                6 => p.canonical.compressions[0].input.counter += 1,
                7 => p.logs_bloom.compressions[0].input.block_len += 1,
                8 => p.extra_data.compressions[0].operations[0] ^= 1,
                _ => p.canonical.compressions[0].proof_bytes[0] ^= 1,
            }
            assert!(
                verify_header_hash(&p, &header, &hash).is_err(),
                "proof {kind}"
            );
        }
        let mut unknown = encoded;
        unknown["fallback"] = true.into();
        assert!(serde_json::from_value::<BlockHeaderProof>(unknown).is_err());
        for field in 0..3 {
            let mut h = header.clone();
            let too_large = Bytes::from(vec![0; MAX_HASH_BYTES + 1]);
            match field {
                0 => h.logs_bloom = too_large,
                1 => h.extra_data = too_large,
                _ => h.sig_aggregate_proof = Some(too_large),
            }
            assert!(prove_header_hash(&h).is_err());
            assert!(verify_header_hash(&proof, &h, &hash).is_err());
        }
    }

    #[test]
    fn header_air_preserves_native_absence_and_zero_normalization() {
        let mut header = BlockHeader::default();
        let proof = prove_header_hash(&header).unwrap();
        let hash = header.hash();
        header.witness_root = Some(ShellHash::ZERO);
        verify_header_hash(&proof, &header, &hash).unwrap();
        header.sig_aggregate_proof = Some(Default::default());
        assert_ne!(header.hash(), hash);
        assert!(verify_header_hash(&proof, &header, &hash).is_err());
    }
}
