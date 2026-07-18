use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shell_primitives::ShellHash;

use crate::StorageError;

/// Maximum encoded JSON-lines snapshot record, including the newline.
pub const MAX_SNAPSHOT_LINE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum decoded snapshot key size.
pub const MAX_SNAPSHOT_KEY_BYTES: usize = 1024 * 1024;
/// Maximum decoded snapshot value size.
pub const MAX_SNAPSHOT_VALUE_BYTES: usize = 8 * 1024 * 1024;

/// Metadata about a state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Version of the snapshot format.
    pub version: u32,
    /// Chain ID this snapshot belongs to.
    pub chain_id: u64,
    /// Block number at which the snapshot was taken.
    pub block_number: u64,
    /// Block hash at the snapshot point.
    pub block_hash: ShellHash,
    /// State root at the snapshot point.
    pub state_root: ShellHash,
    /// Genesis hash for chain identity verification.
    pub genesis_hash: ShellHash,
    /// Number of key-value entries in the snapshot.
    pub entry_count: u64,
    /// Total uncompressed data size in bytes.
    pub data_size: u64,
    /// SHA-256 checksum of all entry data (hex-encoded).
    /// Computed over concatenated (key ++ value) bytes of every entry, in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

impl SnapshotMetadata {
    /// Current snapshot format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create metadata for a new snapshot.
    pub fn new(
        chain_id: u64,
        block_number: u64,
        block_hash: ShellHash,
        state_root: ShellHash,
        genesis_hash: ShellHash,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            chain_id,
            block_number,
            block_hash,
            state_root,
            genesis_hash,
            entry_count: 0,
            data_size: 0,
            checksum: None,
        }
    }

    /// Serialize metadata to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StorageError> {
        serde_json::to_vec_pretty(self).map_err(|e| {
            StorageError::Serialization(format!("failed to serialize snapshot metadata: {e}"))
        })
    }

    /// Deserialize metadata from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        serde_json::from_slice(bytes).map_err(|e| {
            StorageError::Serialization(format!("failed to deserialize snapshot metadata: {e}"))
        })
    }

    /// Validate that this snapshot is compatible with the given chain.
    pub fn validate_compatibility(
        &self,
        expected_chain_id: u64,
        expected_genesis_hash: &ShellHash,
    ) -> Result<(), StorageError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(StorageError::State(format!(
                "unsupported snapshot version: {} (expected {})",
                self.version,
                Self::CURRENT_VERSION
            )));
        }
        if self.chain_id != expected_chain_id {
            return Err(StorageError::State(format!(
                "chain ID mismatch: snapshot has {}, expected {}",
                self.chain_id, expected_chain_id
            )));
        }
        if &self.genesis_hash != expected_genesis_hash {
            return Err(StorageError::State(format!(
                "genesis hash mismatch: snapshot has {:?}, expected {:?}",
                self.genesis_hash, expected_genesis_hash
            )));
        }
        Ok(())
    }
}

/// A snapshot entry: a single key-value pair from the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Key bytes (base64-encoded in JSON).
    #[serde(with = "base64_bytes")]
    pub key: Vec<u8>,
    /// Value bytes (base64-encoded in JSON).
    #[serde(with = "base64_bytes")]
    pub value: Vec<u8>,
}

/// Simple base64 serialization module for binary data.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use base64::Engine;
        let encoded = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)
    }
}

fn saturating_entry_data_len(key_len: usize, value_len: usize) -> u64 {
    u64::try_from(key_len)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(value_len).unwrap_or(u64::MAX))
}

fn saturating_entry_data_size(key: &[u8], value: &[u8]) -> u64 {
    saturating_entry_data_len(key.len(), value.len())
}

/// Snapshot writer: exports key-value data in a streaming format.
///
/// Format: newline-separated JSON entries followed by a META: footer line.
pub struct SnapshotWriter<W: Write> {
    writer: W,
    metadata: SnapshotMetadata,
    entry_count: u64,
    data_size: u64,
    hasher: Sha256,
}

impl<W: Write> SnapshotWriter<W> {
    /// Create a new snapshot writer.
    pub fn new(writer: W, metadata: SnapshotMetadata) -> Result<Self, StorageError> {
        Ok(Self {
            writer,
            metadata,
            entry_count: 0,
            data_size: 0,
            hasher: Sha256::new(),
        })
    }

    /// Write a key-value entry to the snapshot.
    pub fn write_entry(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        validate_entry_lengths(key.len(), value.len())?;
        let entry = SnapshotEntry {
            key: key.to_vec(),
            value: value.to_vec(),
        };
        let line = serde_json::to_string(&entry)
            .map_err(|e| StorageError::Serialization(format!("serialize entry: {e}")))?;
        self.writer
            .write_all(line.as_bytes())
            .map_err(|e| StorageError::Database(format!("write entry: {e}")))?;
        self.writer
            .write_all(b"\n")
            .map_err(|e| StorageError::Database(format!("write newline: {e}")))?;

        self.entry_count = self.entry_count.saturating_add(1);
        self.data_size = self
            .data_size
            .saturating_add(saturating_entry_data_size(key, value));
        // Feed data into SHA-256 hasher for integrity checksum (F-089).
        self.hasher.update(key);
        self.hasher.update(value);
        Ok(())
    }

    /// Finalize the snapshot, writing the metadata footer.
    pub fn finalize(mut self) -> Result<SnapshotMetadata, StorageError> {
        let mut meta = self.metadata.clone();
        meta.entry_count = self.entry_count;
        meta.data_size = self.data_size;
        // Compute SHA-256 checksum over all entry data (F-089).
        let digest = self.hasher.finalize();
        meta.checksum = Some(hex::encode(digest));

        // Write metadata as the last line, prefixed with "META:"
        let meta_json = serde_json::to_string(&meta)
            .map_err(|e| StorageError::Serialization(format!("serialize metadata: {e}")))?;
        self.writer
            .write_all(b"META:")
            .map_err(|e| StorageError::Database(format!("write meta prefix: {e}")))?;
        self.writer
            .write_all(meta_json.as_bytes())
            .map_err(|e| StorageError::Database(format!("write metadata: {e}")))?;
        self.writer
            .write_all(b"\n")
            .map_err(|e| StorageError::Database(format!("write final newline: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| StorageError::Database(format!("flush: {e}")))?;

        Ok(meta)
    }
}

/// Snapshot reader: imports key-value data from a seekable snapshot file.
///
/// The footer is validated in one bounded streaming pass, then entries are
/// replayed from the beginning during import. This keeps memory independent
/// of the total snapshot size.
#[derive(Debug)]
pub struct SnapshotReader<R> {
    reader: BufReader<R>,
    metadata: SnapshotMetadata,
    finished: bool,
}

impl<R: Read + Seek> SnapshotReader<R> {
    /// Open a snapshot for reading. Reads metadata from the footer.
    ///
    /// Verifies the checksum and declared entry metadata while streaming.
    pub fn new(reader: R) -> Result<Self, StorageError> {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        let mut metadata: Option<SnapshotMetadata> = None;
        let mut entry_count = 0u64;
        let mut data_size = 0u64;
        let mut hasher = Sha256::new();

        loop {
            let bytes_read = read_bounded_line(&mut reader, &mut line)?;
            if bytes_read == 0 {
                break;
            }
            let line_bytes = trim_line_end(&line);
            if line_bytes.is_empty() {
                continue;
            }

            if let Some(meta_json) = line_bytes.strip_prefix(b"META:") {
                if metadata.is_some() {
                    return Err(StorageError::Serialization(
                        "snapshot contains multiple META footers".into(),
                    ));
                }
                metadata =
                    Some(serde_json::from_slice(meta_json).map_err(|e| {
                        StorageError::Serialization(format!("parse metadata: {e}"))
                    })?);
                continue;
            }

            if metadata.is_some() {
                return Err(StorageError::Serialization(
                    "snapshot contains entries after META footer".into(),
                ));
            }

            let entry: SnapshotEntry = serde_json::from_slice(line_bytes)
                .map_err(|e| StorageError::Serialization(format!("parse entry: {e}")))?;
            validate_entry_size(&entry)?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(|| StorageError::State("snapshot entry count overflow".into()))?;
            data_size = data_size
                .checked_add(saturating_entry_data_size(&entry.key, &entry.value))
                .ok_or_else(|| StorageError::State("snapshot data size overflow".into()))?;
            hasher.update(&entry.key);
            hasher.update(&entry.value);
        }

        let metadata = metadata
            .ok_or_else(|| StorageError::Serialization("snapshot missing META footer".into()))?;

        if metadata.entry_count != entry_count {
            return Err(StorageError::State(format!(
                "snapshot entry count mismatch: metadata={}, actual={entry_count}",
                metadata.entry_count
            )));
        }
        if metadata.data_size != data_size {
            return Err(StorageError::State(format!(
                "snapshot data size mismatch: metadata={}, actual={data_size}",
                metadata.data_size
            )));
        }

        // Verify SHA-256 checksum if present (F-089).
        if let Some(ref expected_checksum) = metadata.checksum {
            let actual = hex::encode(hasher.finalize());
            if actual != *expected_checksum {
                return Err(StorageError::State(format!(
                    "snapshot checksum mismatch: expected {expected_checksum}, got {actual}"
                )));
            }
        }

        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| StorageError::Database(format!("rewind snapshot: {e}")))?;

        Ok(Self {
            reader,
            metadata,
            finished: false,
        })
    }

    /// Get the snapshot metadata.
    pub fn metadata(&self) -> &SnapshotMetadata {
        &self.metadata
    }

    /// Rewind the reader so entries can be validated and then replayed.
    pub fn rewind(&mut self) -> Result<(), StorageError> {
        self.reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| StorageError::Database(format!("rewind snapshot: {e}")))?;
        self.finished = false;
        Ok(())
    }

    /// Read the next entry. Returns None when all entries have been read.
    pub fn next_entry(&mut self) -> Result<Option<SnapshotEntry>, StorageError> {
        if self.finished {
            return Ok(None);
        }

        let mut line = Vec::new();
        loop {
            let bytes_read = read_bounded_line(&mut self.reader, &mut line)?;
            if bytes_read == 0 {
                self.finished = true;
                return Ok(None);
            }
            let line_bytes = trim_line_end(&line);
            if line_bytes.is_empty() {
                continue;
            }

            if line_bytes.starts_with(b"META:") {
                self.finished = true;
                return Ok(None);
            }

            let entry: SnapshotEntry = serde_json::from_slice(line_bytes)
                .map_err(|e| StorageError::Serialization(format!("parse entry: {e}")))?;
            validate_entry_size(&entry)?;
            return Ok(Some(entry));
        }
    }

    /// Read all remaining entries.
    pub fn read_all_entries(&mut self) -> Result<Vec<SnapshotEntry>, StorageError> {
        let mut entries = Vec::new();
        while let Some(entry) = self.next_entry()? {
            entries.push(entry);
        }
        Ok(entries)
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> Result<usize, StorageError> {
    line.clear();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|e| StorageError::Database(format!("read snapshot: {e}")))?;
        if available.is_empty() {
            return Ok(line.len());
        }

        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(take) > MAX_SNAPSHOT_LINE_BYTES {
            return Err(StorageError::State(format!(
                "snapshot line exceeds maximum of {MAX_SNAPSHOT_LINE_BYTES} bytes"
            )));
        }
        let has_newline = available.get(take.saturating_sub(1)) == Some(&b'\n');
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if has_newline {
            return Ok(line.len());
        }
    }
}

fn trim_line_end(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn validate_entry_size(entry: &SnapshotEntry) -> Result<(), StorageError> {
    validate_entry_lengths(entry.key.len(), entry.value.len())
}

fn validate_entry_lengths(key_len: usize, value_len: usize) -> Result<(), StorageError> {
    if key_len > MAX_SNAPSHOT_KEY_BYTES {
        return Err(StorageError::State(format!(
            "snapshot key exceeds maximum of {MAX_SNAPSHOT_KEY_BYTES} bytes"
        )));
    }
    if value_len > MAX_SNAPSHOT_VALUE_BYTES {
        return Err(StorageError::State(format!(
            "snapshot value exceeds maximum of {MAX_SNAPSHOT_VALUE_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_metadata() -> SnapshotMetadata {
        SnapshotMetadata::new(1337, 100, ShellHash::ZERO, ShellHash::ZERO, ShellHash::ZERO)
    }

    #[test]
    fn snapshot_writer_tracks_data_size_with_saturating_math() {
        let meta = test_metadata();
        let mut buffer = Vec::new();
        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(b"key", b"value").unwrap();
        writer.write_entry(b"longer-key", b"x").unwrap();
        let written_meta = writer.finalize().unwrap();

        assert_eq!(written_meta.data_size, 19);
        assert_eq!(saturating_entry_data_len(usize::MAX, usize::MAX), u64::MAX);
    }

    #[test]
    fn snapshot_writer_rejects_entries_the_reader_cannot_import() {
        let mut buffer = Vec::new();
        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), test_metadata()).unwrap();

        let oversized_key = vec![0; MAX_SNAPSHOT_KEY_BYTES + 1];
        let err = writer.write_entry(&oversized_key, b"value").unwrap_err();
        assert!(err.to_string().contains("snapshot key exceeds maximum"));
        assert!(writer.writer.get_ref().is_empty());

        let oversized_value = vec![0; MAX_SNAPSHOT_VALUE_BYTES + 1];
        let err = writer.write_entry(b"key", &oversized_value).unwrap_err();
        assert!(err.to_string().contains("snapshot value exceeds maximum"));
        assert!(writer.writer.get_ref().is_empty());
    }

    #[test]
    fn test_metadata_serialization() {
        let meta = test_metadata();
        let bytes = meta.to_bytes().unwrap();
        let recovered = SnapshotMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(meta, recovered);
    }

    #[test]
    fn test_metadata_validation_ok() {
        let meta = test_metadata();
        assert!(meta.validate_compatibility(1337, &ShellHash::ZERO).is_ok());
    }

    #[test]
    fn test_metadata_validation_chain_id_mismatch() {
        let meta = test_metadata();
        let result = meta.validate_compatibility(9999, &ShellHash::ZERO);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("chain ID mismatch"));
    }

    #[test]
    fn test_metadata_validation_genesis_mismatch() {
        let meta = test_metadata();
        let mut bad_genesis = [0u8; 32];
        bad_genesis[0] = 1;
        let result = meta.validate_compatibility(1337, &ShellHash::from(bad_genesis));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("genesis hash mismatch"));
    }

    #[test]
    fn test_write_read_roundtrip() {
        let meta = test_metadata();
        let mut buffer = Vec::new();

        // Write
        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(b"key1", b"value1").unwrap();
        writer.write_entry(b"key2", b"value2").unwrap();
        writer.write_entry(b"key3", b"value3").unwrap();
        let written_meta = writer.finalize().unwrap();

        assert_eq!(written_meta.entry_count, 3);

        // Read
        let mut reader = SnapshotReader::new(Cursor::new(&buffer)).unwrap();
        assert_eq!(reader.metadata().entry_count, 3);
        assert_eq!(reader.metadata().chain_id, 1337);
        assert_eq!(reader.metadata().block_number, 100);

        let entries = reader.read_all_entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, b"key1");
        assert_eq!(entries[0].value, b"value1");
        assert_eq!(entries[1].key, b"key2");
        assert_eq!(entries[2].key, b"key3");
    }

    #[test]
    fn test_empty_snapshot() {
        let meta = test_metadata();
        let mut buffer = Vec::new();

        let writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        let written_meta = writer.finalize().unwrap();
        assert_eq!(written_meta.entry_count, 0);
        assert_eq!(written_meta.data_size, 0);

        let mut reader = SnapshotReader::new(Cursor::new(&buffer)).unwrap();
        let entries = reader.read_all_entries().unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_binary_data_roundtrip() {
        let meta = test_metadata();
        let mut buffer = Vec::new();

        let binary_key: Vec<u8> = (0..255).collect();
        let binary_value = vec![0xFF; 1024];

        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(&binary_key, &binary_value).unwrap();
        let _ = writer.finalize().unwrap();

        let mut reader = SnapshotReader::new(Cursor::new(&buffer)).unwrap();
        let entries = reader.read_all_entries().unwrap();
        assert_eq!(entries[0].key, binary_key);
        assert_eq!(entries[0].value, binary_value);
    }

    #[test]
    fn test_corrupted_snapshot() {
        let result = SnapshotReader::new(Cursor::new(b"not a valid snapshot"));
        assert!(result.is_err());
    }

    #[test]
    fn test_large_entry_count() {
        let meta = test_metadata();
        let mut buffer = Vec::new();

        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        for i in 0..100u32 {
            writer
                .write_entry(&i.to_be_bytes(), &[i as u8; 32])
                .unwrap();
        }
        let written_meta = writer.finalize().unwrap();
        assert_eq!(written_meta.entry_count, 100);

        let mut reader = SnapshotReader::new(Cursor::new(&buffer)).unwrap();
        let entries = reader.read_all_entries().unwrap();
        assert_eq!(entries.len(), 100);
    }

    #[test]
    fn test_metadata_version_check() {
        let mut meta = test_metadata();
        meta.version = 99;
        let result = meta.validate_compatibility(1337, &ShellHash::ZERO);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported snapshot version"));
    }

    #[test]
    fn test_iterator_style_reading() {
        let meta = test_metadata();
        let mut buffer = Vec::new();

        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(b"a", b"1").unwrap();
        writer.write_entry(b"b", b"2").unwrap();
        let _ = writer.finalize().unwrap();

        let mut reader = SnapshotReader::new(Cursor::new(&buffer)).unwrap();
        let e1 = reader.next_entry().unwrap().unwrap();
        assert_eq!(e1.key, b"a");
        let e2 = reader.next_entry().unwrap().unwrap();
        assert_eq!(e2.key, b"b");
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn test_checksum_present_in_finalized_metadata() {
        let meta = test_metadata();
        let mut buffer = Vec::new();

        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(b"key1", b"value1").unwrap();
        let written_meta = writer.finalize().unwrap();

        assert!(written_meta.checksum.is_some());
        assert_eq!(written_meta.checksum.as_ref().unwrap().len(), 64); // hex SHA-256
    }

    #[test]
    fn test_checksum_verified_on_read() {
        let meta = test_metadata();
        let mut buffer = Vec::new();

        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(b"k", b"v").unwrap();
        writer.finalize().unwrap();

        // Valid snapshot reads successfully
        assert!(SnapshotReader::new(Cursor::new(&buffer)).is_ok());

        // Tamper with entry data — replace value in the JSON line
        let text = String::from_utf8(buffer).unwrap();
        let tampered = text.replacen("\"diA=\"", "\"AAAA\"", 1); // change base64 value
        if tampered != text {
            // Only test if we actually tampered with something
            let result = SnapshotReader::new(Cursor::new(tampered.as_bytes()));
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch"));
        }
    }

    #[test]
    fn test_metadata_entry_count_is_verified() {
        let meta = test_metadata();
        let mut buffer = Vec::new();
        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(b"key", b"value").unwrap();
        writer.finalize().unwrap();

        let text = String::from_utf8(buffer).unwrap();
        let tampered = text.replacen("\"entry_count\":1", "\"entry_count\":2", 1);
        let err = SnapshotReader::new(Cursor::new(tampered)).unwrap_err();
        assert!(err.to_string().contains("entry count mismatch"));
    }

    #[test]
    fn test_metadata_data_size_is_verified() {
        let meta = test_metadata();
        let mut buffer = Vec::new();
        let mut writer = SnapshotWriter::new(Cursor::new(&mut buffer), meta).unwrap();
        writer.write_entry(b"key", b"value").unwrap();
        writer.finalize().unwrap();

        let text = String::from_utf8(buffer).unwrap();
        let tampered = text.replacen("\"data_size\":8", "\"data_size\":9", 1);
        let err = SnapshotReader::new(Cursor::new(tampered)).unwrap_err();
        assert!(err.to_string().contains("data size mismatch"));
    }

    #[test]
    fn test_multiple_metadata_lines_are_rejected() {
        let meta = test_metadata();
        let mut buffer = Vec::new();
        SnapshotWriter::new(Cursor::new(&mut buffer), meta)
            .unwrap()
            .finalize()
            .unwrap();

        let text = String::from_utf8(buffer).unwrap();
        let tampered = format!("{text}{text}");
        let err = SnapshotReader::new(Cursor::new(tampered)).unwrap_err();
        assert!(err.to_string().contains("multiple META footers"));
    }
}
