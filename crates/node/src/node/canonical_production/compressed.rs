//! Lossless local storage for legacy JSON certificates; decoding grants no authority.
use super::{error, StorageError, MAX_BYTES};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use shell_primitives::blake3_hash;

pub(super) const PREFIX: &[u8] = b"\0canonical-json/zlib/v1/";
const HEADER: usize = PREFIX.len() + 8 + 32;

pub(super) fn eligible(bytes: &[u8]) -> bool {
    bytes.len() >= 4096 && matches!(bytes.first(), Some(b'{' | b'['))
}
pub(super) fn pack(bytes: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
    if !eligible(bytes) {
        return Ok(None);
    }
    if bytes.len() > MAX_BYTES as usize {
        return Err(error("legacy certificate byte limit"));
    }
    // Bound the encoder's output allocation and require a real physical saving.
    let mut payload = vec![0; bytes.len() - HEADER - 64];
    let mut codec = Compress::new(Compression::fast(), true);
    let status = codec
        .compress(bytes, &mut payload, FlushCompress::Finish)
        .map_err(error)?;
    if status != Status::StreamEnd || codec.total_in() != bytes.len() as u64 {
        return Ok(None);
    }
    payload.truncate(codec.total_out() as usize);
    let mut encoded = Vec::with_capacity(HEADER + payload.len());
    encoded.extend_from_slice(PREFIX);
    encoded.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(blake3_hash(bytes).as_bytes());
    encoded.extend_from_slice(&payload);
    Ok(Some(encoded))
}
pub(super) fn restore(bytes: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    if !bytes.starts_with(PREFIX) {
        return Ok(bytes);
    }
    if bytes.len() <= HEADER || bytes.len() > MAX_BYTES as usize {
        return Err(error("compressed certificate framing/byte limit"));
    }
    let size = u64::from_be_bytes(bytes[PREFIX.len()..PREFIX.len() + 8].try_into().unwrap());
    if !(4096..=MAX_BYTES).contains(&size) {
        return Err(error("compressed certificate expansion limit"));
    }
    let payload = &bytes[HEADER..];
    let mut restored = vec![0; size as usize + 1];
    let mut codec = Decompress::new(true);
    let status = codec
        .decompress(payload, &mut restored, FlushDecompress::Finish)
        .map_err(error)?;
    if status != Status::StreamEnd
        || codec.total_out() != size
        || codec.total_in() != payload.len() as u64
    {
        return Err(error("compressed certificate stream/length mismatch"));
    }
    restored.truncate(size as usize);
    if !eligible(&restored) || blake3_hash(&restored).as_bytes() != &bytes[PREFIX.len() + 8..HEADER]
    {
        return Err(error("compressed certificate hash mismatch"));
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original() -> Vec<u8> {
        // Storage-only bytes with deliberate property order and whitespace.
        format!(
            "{{ \"z\": [{}], \"a\": 7 }}",
            "17,".repeat(4096).trim_end_matches(',')
        )
        .into_bytes()
    }
    #[test]
    fn restores_exact_legacy_bytes_without_reordering_or_changing_other_formats() {
        let raw = original();
        let packed = pack(&raw).unwrap().unwrap();
        assert!(packed.len() < raw.len());
        assert_eq!(restore(packed).unwrap(), raw);
        let opaque = b"\0canonical-component/cbor/v1/opaque".to_vec();
        assert!(pack(&opaque).unwrap().is_none());
        assert_eq!(restore(opaque.clone()).unwrap(), opaque);
    }
    #[test]
    fn rejects_changed_hash_truncated_trailing_and_oversized_streams() {
        let packed = pack(&original()).unwrap().unwrap();
        let mut bad = packed.clone();
        bad[PREFIX.len() + 8] ^= 1;
        assert!(restore(bad).is_err());
        for cut in [1, 4] {
            assert!(restore(packed[..packed.len() - cut].to_vec()).is_err());
        }
        let mut bad = packed.clone();
        bad.push(0);
        assert!(restore(bad).is_err());
        let mut bad = packed.clone();
        bad[PREFIX.len()..PREFIX.len() + 8].copy_from_slice(&(MAX_BYTES + 1).to_be_bytes());
        assert!(restore(bad).is_err());
        let mut bad = packed;
        bad[PREFIX.len()..PREFIX.len() + 8].copy_from_slice(&1u64.to_be_bytes());
        assert!(restore(bad).is_err());
    }
}
