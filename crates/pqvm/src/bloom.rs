//! Height-selected log Bloom bit ordering with unchanged legacy encoding.
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

/// Byte and bit order committed by a block's receipts and header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BloomFormat {
    Legacy,
    Standard,
}

impl BloomFormat {
    /// Choose by the executed or queried block, never by the current tip.
    pub fn at_height(activation: Option<u64>, number: u64) -> Self {
        if activation.is_some_and(|height| number >= height) {
            Self::Standard
        } else {
            Self::Legacy
        }
    }

    fn bit_location(self, index: usize) -> (usize, usize) {
        match self {
            Self::Legacy => (index / 8, 7 - index % 8),
            Self::Standard => (BLOOM_SIZE - 1 - index / 8, index % 8),
        }
    }
}

/// Compute the legacy bloom filter for a set of logs.
///
/// For each log, the address and every topic are inserted into the filter.
pub fn logs_bloom(logs: &[Log]) -> Bloom {
    logs_bloom_with_format(logs, BloomFormat::Legacy)
}

/// Compute a Bloom using the selected order and full 32-byte Shell addresses.
pub fn logs_bloom_with_format(logs: &[Log], format: BloomFormat) -> Bloom {
    let mut bloom = [0u8; BLOOM_SIZE];
    for log in logs {
        bloom_insert(&mut bloom, log.address.as_bytes(), format);
        for topic in &log.topics {
            bloom_insert(&mut bloom, topic.as_bytes(), format);
        }
    }
    bloom
}

/// Insert a single item (address or topic bytes) into a bloom filter.
///
/// Algorithm: Keccak-256 hash the data, then take three pairs of bytes
/// at positions [0,1], [2,3], [4,5]. Each pair yields a bit index
/// `(b0 << 8 | b1) & 0x7FF` (mod 2048), which is set in the filter.
fn bloom_insert(bloom: &mut Bloom, data: &[u8], format: BloomFormat) {
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
        let (byte_index, bit_position) = format.bit_location(bit_index);
        if let Some(byte) = bloom.get_mut(byte_index) {
            *byte |= 1u8 << bit_position;
        }
    }
}

/// Check whether a legacy bloom filter may contain an item.
///
/// Returns `true` if all three bit positions for `data` are set in `bloom`.
/// A `true` result is a "maybe" — false positives are possible.
/// A `false` result is definitive — the item was never inserted.
pub fn bloom_contains(bloom: &Bloom, data: &[u8]) -> bool {
    bloom_contains_with_format(bloom, data, BloomFormat::Legacy)
}

/// Check membership using the order committed at the queried block height.
pub fn bloom_contains_with_format(bloom: &Bloom, data: &[u8], format: BloomFormat) -> bool {
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
        let (byte_index, bit_position) = format.bit_location(bit_index);
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
    bloom_union_bytes(blooms.iter().map(Bloom::as_slice))
}

/// Combine byte slices with bitwise OR, truncating each input to bloom size.
///
/// This supports receipt blooms without first copying each one into a fixed-size
/// array. Inputs shorter than [`BLOOM_SIZE`] leave the remaining bytes unset.
pub fn bloom_union_bytes<'a>(blooms: impl IntoIterator<Item = &'a [u8]>) -> Bloom {
    let mut result = [0u8; BLOOM_SIZE];
    for b in blooms {
        for (r, byte) in result.iter_mut().zip(b) {
            *r |= byte;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::{Address, Bytes, ShellHash};

    #[test]
    fn bloom_activation_preserves_legacy_and_matches_independent_vectors() {
        let topic = [0x11; 32];
        for (format, entries) in [
            (BloomFormat::Legacy, [(67, 4), (173, 64), (229, 4)]),
            (BloomFormat::Standard, [(26, 32), (82, 2), (188, 32)]),
        ] {
            let mut expected = [0; BLOOM_SIZE];
            for (index, byte) in entries {
                expected[index] = byte;
            }
            let mut actual = [0; BLOOM_SIZE];
            bloom_insert(&mut actual, &topic, format);
            assert_eq!(actual, expected);
            assert!(bloom_contains_with_format(&actual, &topic, format));
        }
        let address = Address::from([0x42; 32]);
        let log = Log::new(address, vec![ShellHash::from(topic)], Bytes::new()).unwrap();
        let mut reference = alloy_primitives::Bloom::ZERO;
        reference.m3_2048(address.as_bytes());
        reference.m3_2048(&topic);
        assert_eq!(
            logs_bloom_with_format(&[log], BloomFormat::Standard).as_slice(),
            reference.as_slice()
        );
        assert_eq!(BloomFormat::at_height(None, u64::MAX), BloomFormat::Legacy);
        assert_eq!(BloomFormat::at_height(Some(2), 1), BloomFormat::Legacy);
        assert_eq!(BloomFormat::at_height(Some(2), 2), BloomFormat::Standard);
    }

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
    fn bloom_union_bytes_handles_variable_length_inputs() {
        let oversized = vec![0x80; BLOOM_SIZE + 1];
        let combined = bloom_union_bytes([&[0x01, 0x02][..], &oversized]);

        assert_eq!(combined[0], 0x81);
        assert_eq!(combined[1], 0x82);
        assert!(combined[2..].iter().all(|byte| *byte == 0x80));
    }

    #[test]
    fn bloom_union_bytes_of_empty_input_is_zeroed() {
        let combined = bloom_union_bytes(std::iter::empty());
        assert_eq!(combined, [0u8; BLOOM_SIZE]);
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
