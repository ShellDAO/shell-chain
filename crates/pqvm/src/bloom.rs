//! Ethereum logs bloom filter (EIP-2028 compatible).
//!
//! A 2048-bit (256-byte) Bloom filter used for efficient log filtering.
//! Each log entry's address and topics are inserted into the filter using
//! three bit positions derived from the Keccak-256 hash of the item.

use sha3::{Digest, Keccak256};
use shell_core::Log;

/// Bloom filter size in bytes (2048 bits).
pub const BLOOM_SIZE: usize = 256;

/// A 2048-bit Bloom filter.
pub type Bloom = [u8; BLOOM_SIZE];

/// Compute the bloom filter for a set of logs.
///
/// For each log, the address and every topic are inserted into the filter.
pub fn logs_bloom(logs: &[Log]) -> Bloom {
    let mut bloom = [0u8; BLOOM_SIZE];
    for log in logs {
        bloom_insert(&mut bloom, log.address.as_bytes());
        for topic in &log.topics {
            bloom_insert(&mut bloom, topic.as_bytes());
        }
    }
    bloom
}

/// Insert a single item (address or topic bytes) into a bloom filter.
///
/// Algorithm: Keccak-256 hash the data, then take three pairs of bytes
/// at positions [0,1], [2,3], [4,5]. Each pair yields a bit index
/// `(b0 << 8 | b1) & 0x7FF` (mod 2048), which is set in the filter.
fn bloom_insert(bloom: &mut Bloom, data: &[u8]) {
    let hash = Keccak256::digest(data);
    let hash_bytes: &[u8] = hash.as_ref();
    for i in 0..3usize {
        let i2 = i.saturating_mul(2);
        let b0 = hash_bytes
            .get(i2)
            .copied()
            .unwrap_or_else(|| unreachable!("Keccak256 is 32 bytes; i < 3 so i*2 < 6"));
        let b1 = hash_bytes
            .get(i2.saturating_add(1))
            .copied()
            .unwrap_or_else(|| unreachable!("Keccak256 is 32 bytes; i < 3 so i*2+1 < 6"));
        let bit_index = ((b0 as usize) << 8 | b1 as usize) & 0x7FF;
        let byte_index = bit_index.checked_div(8).unwrap_or(0);
        let bit_position = 7usize.saturating_sub(bit_index.checked_rem(8).unwrap_or(0));
        if let Some(byte) = bloom.get_mut(byte_index) {
            *byte |= 1u8 << bit_position;
        }
    }
}

/// Check whether the bloom filter may contain an item.
///
/// Returns `true` if all three bit positions for `data` are set in `bloom`.
/// A `true` result is a "maybe" — false positives are possible.
/// A `false` result is definitive — the item was never inserted.
pub fn bloom_contains(bloom: &Bloom, data: &[u8]) -> bool {
    let hash = Keccak256::digest(data);
    let hash_bytes: &[u8] = hash.as_ref();
    for i in 0..3usize {
        let i2 = i.saturating_mul(2);
        let b0 = hash_bytes
            .get(i2)
            .copied()
            .unwrap_or_else(|| unreachable!("Keccak256 is 32 bytes; i < 3 so i*2 < 6"));
        let b1 = hash_bytes
            .get(i2.saturating_add(1))
            .copied()
            .unwrap_or_else(|| unreachable!("Keccak256 is 32 bytes; i < 3 so i*2+1 < 6"));
        let bit_index = ((b0 as usize) << 8 | b1 as usize) & 0x7FF;
        let byte_index = bit_index.checked_div(8).unwrap_or(0);
        let bit_position = 7usize.saturating_sub(bit_index.checked_rem(8).unwrap_or(0));
        if bloom
            .get(byte_index)
            .map(|b| b & (1u8 << bit_position) == 0)
            .unwrap_or(true)
        {
            return false;
        }
    }
    true
}

/// Combine multiple bloom filters with bitwise OR.
///
/// Used to build the block-level bloom from individual receipt blooms.
pub fn bloom_union(blooms: &[Bloom]) -> Bloom {
    let mut result = [0u8; BLOOM_SIZE];
    for b in blooms {
        for (i, byte) in b.iter().enumerate() {
            if let Some(r) = result.get_mut(i) {
                *r |= byte;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::{Address, Bytes, ShellHash};

    #[test]
    fn empty_logs_produce_zero_bloom() {
        let bloom = logs_bloom(&[]);
        assert_eq!(bloom, [0u8; BLOOM_SIZE]);
    }

    #[test]
    fn known_address_sets_bits() {
        let addr = Address::from([0xAA; 20]);
        let log = Log::new(addr, vec![], Bytes::new()).unwrap();
        let bloom = logs_bloom(&[log]);
        // The bloom must be non-zero since we inserted an address.
        assert_ne!(bloom, [0u8; BLOOM_SIZE]);
    }

    #[test]
    fn bloom_contains_inserted_address() {
        let addr = Address::from([0x42; 20]);
        let log = Log::new(addr, vec![], Bytes::new()).unwrap();
        let bloom = logs_bloom(&[log]);
        assert!(bloom_contains(&bloom, addr.as_bytes()));
    }

    #[test]
    fn bloom_contains_inserted_topic() {
        let addr = Address::from([0x01; 20]);
        let topic = ShellHash::from_slice(&[0xBB; 32]);
        let log = Log::new(addr, vec![topic], Bytes::new()).unwrap();
        let bloom = logs_bloom(&[log]);
        assert!(bloom_contains(&bloom, addr.as_bytes()));
        assert!(bloom_contains(&bloom, topic.as_bytes()));
    }

    #[test]
    fn bloom_does_not_contain_non_inserted_item() {
        let addr = Address::from([0x01; 20]);
        let log = Log::new(addr, vec![], Bytes::new()).unwrap();
        let bloom = logs_bloom(&[log]);
        let other = [0xFF; 32];
        // While false positives are possible, this specific case should not match.
        // If it does, the test data should be changed.
        assert!(!bloom_contains(&bloom, &other));
    }

    #[test]
    fn bloom_union_combines_filters() {
        let addr1 = Address::from([0x11; 20]);
        let addr2 = Address::from([0x22; 20]);
        let log1 = Log::new(addr1, vec![], Bytes::new()).unwrap();
        let log2 = Log::new(addr2, vec![], Bytes::new()).unwrap();
        let b1 = logs_bloom(&[log1]);
        let b2 = logs_bloom(&[log2]);
        let combined = bloom_union(&[b1, b2]);
        assert!(bloom_contains(&combined, addr1.as_bytes()));
        assert!(bloom_contains(&combined, addr2.as_bytes()));
    }

    #[test]
    fn multiple_logs_bloom() {
        let addr1 = Address::from([0x10; 20]);
        let addr2 = Address::from([0x20; 20]);
        let topic = ShellHash::from_slice(&[0xCC; 32]);
        let log1 = Log::new(addr1, vec![topic], Bytes::new()).unwrap();
        let log2 = Log::new(addr2, vec![], Bytes::new()).unwrap();
        let bloom = logs_bloom(&[log1, log2]);
        assert!(bloom_contains(&bloom, addr1.as_bytes()));
        assert!(bloom_contains(&bloom, addr2.as_bytes()));
        assert!(bloom_contains(&bloom, topic.as_bytes()));
    }

    #[test]
    fn bloom_size_is_256_bytes() {
        let bloom = logs_bloom(&[]);
        assert_eq!(bloom.len(), 256);
    }
}
