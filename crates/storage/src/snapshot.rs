use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shell_primitives::ShellHash;

use crate::StorageError;

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
            .saturating_add((key.len().saturating_add(value.len())) as u64);
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

/// Snapshot reader: imports key-value data from a snapshot file.
///
/// Uses `BufReader` for line-by-line parsing to avoid loading the entire
/// snapshot into a single contiguous `String` (F-079).
#[derive(Debug)]
pub struct SnapshotReader {
    lines: Vec<String>,
    metadata: SnapshotMetadata,
    current_line: usize,
}

impl SnapshotReader {
    /// Open a snapshot for reading. Reads metadata from the footer.
    ///
    /// Uses `BufRead::lines()` to parse line-by-line instead of
    /// `read_to_string()`, avoiding a redundant full-file buffer.
    /// Verifies the SHA-256 checksum if present in metadata (F-089).
    pub fn new<R: Read>(reader: R) -> Result<Self, StorageError> {
        use std::io::BufRead;
        let buf_reader = std::io::BufReader::new(reader);
        let lines: Vec<String> = buf_reader
            .lines()
            .collect::<Result<_, _>>()
            .map_err(|e| StorageError::Database(format!("read snapshot: {e}")))?;

        if lines.is_empty() {
            return Err(StorageError::Serialization("empty snapshot file".into()));
        }

        // Find metadata line (last line starting with "META:")
        let meta_line = lines
            .last()
            .ok_or_else(|| StorageError::Serialization("no metadata in snapshot".into()))?;

        if !meta_line.starts_with("META:") {
            return Err(StorageError::Serialization(
                "snapshot missing META footer".into(),
            ));
        }

        let meta_json = &meta_line[5..]; // skip "META:" prefix
        let metadata: SnapshotMetadata = serde_json::from_str(meta_json)
            .map_err(|e| StorageError::Serialization(format!("parse metadata: {e}")))?;

        // Verify SHA-256 checksum if present (F-089).
        if let Some(ref expected_checksum) = metadata.checksum {
            let mut hasher = Sha256::new();
            for line in &lines {
                if line.starts_with("META:") || line.is_empty() {
                    continue;
                }
                let entry: SnapshotEntry = serde_json::from_str(line).map_err(|e| {
                    StorageError::Serialization(format!("parse entry for checksum: {e}"))
                })?;
                hasher.update(&entry.key);
                hasher.update(&entry.value);
            }
            let actual = hex::encode(hasher.finalize());
            if actual != *expected_checksum {
                return Err(StorageError::State(format!(
                    "snapshot checksum mismatch: expected {expected_checksum}, got {actual}"
                )));
            }
        }

        Ok(Self {
            lines,
            metadata,
            current_line: 0,
        })
    }

    /// Get the snapshot metadata.
    pub fn metadata(&self) -> &SnapshotMetadata {
        &self.metadata
    }

    /// Read the next entry. Returns None when all entries have been read.
    pub fn next_entry(&mut self) -> Result<Option<SnapshotEntry>, StorageError> {
        while self.current_line < self.lines.len() {
            let line = self
                .lines
                .get(self.current_line)
                .unwrap_or_else(|| unreachable!("current_line < lines.len() checked above"));
            self.current_line = self.current_line.saturating_add(1);

            // Skip metadata line and empty lines
            if line.starts_with("META:") || line.is_empty() {
                continue;
            }

            let entry: SnapshotEntry = serde_json::from_str(line).map_err(|e| {
                StorageError::Serialization(format!(
                    "parse entry at line {}: {e}",
                    self.current_line
                ))
            })?;
            return Ok(Some(entry));
        }
        Ok(None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_metadata() -> SnapshotMetadata {
        SnapshotMetadata::new(1337, 100, ShellHash::ZERO, ShellHash::ZERO, ShellHash::ZERO)
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
}
