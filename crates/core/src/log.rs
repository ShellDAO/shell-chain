use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_primitives::{Address, Bytes, ShellHash};

/// Maximum number of indexed topics per EVM log (EVM spec limit).
pub const MAX_LOG_TOPICS: usize = 4;

/// An EVM event log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Log {
    /// Address of the contract that emitted this log.
    pub address: Address,
    /// Indexed topic hashes (up to [`MAX_LOG_TOPICS`]).
    pub topics: Vec<ShellHash>,
    /// Non-indexed log data.
    pub data: Bytes,
}

impl Log {
    /// Create a new log entry, validating topic count ≤ [`MAX_LOG_TOPICS`].
    pub fn new(address: Address, topics: Vec<ShellHash>, data: Bytes) -> Result<Self, LogError> {
        if topics.len() > MAX_LOG_TOPICS {
            return Err(LogError::TooManyTopics {
                got: topics.len(),
                max: MAX_LOG_TOPICS,
            });
        }
        Ok(Self {
            address,
            topics,
            data,
        })
    }
}

impl Encodable for Log {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_fields_len(),
        };
        header.encode(out);
        self.address.encode(out);
        let topics_payload: usize = self.topics.iter().map(|t| t.length()).sum();
        alloy_rlp::Header {
            list: true,
            payload_length: topics_payload,
        }
        .encode(out);
        for topic in &self.topics {
            topic.encode(out);
        }
        self.data.encode(out);
    }

    fn length(&self) -> usize {
        let payload = self.rlp_fields_len();
        alloy_rlp::Header {
            list: true,
            payload_length: payload,
        }
        .length()
        .saturating_add(payload)
    }
}

impl Decodable for Log {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let address = Address::decode(buf)?;

        let topics_header = alloy_rlp::Header::decode(buf)?;
        if !topics_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut topics = Vec::new();
        let topics_end = buf.len().saturating_sub(topics_header.payload_length);
        while buf.len() > topics_end {
            topics.push(ShellHash::decode(buf)?);
        }

        let data = Bytes::decode(buf)?;

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            address,
            topics,
            data,
        })
    }
}

impl Log {
    fn rlp_fields_len(&self) -> usize {
        let topics_payload: usize = self.topics.iter().map(|t| t.length()).sum();
        let topics_list_len = alloy_rlp::Header {
            list: true,
            payload_length: topics_payload,
        }
        .length()
        .saturating_add(topics_payload);
        self.address
            .length()
            .saturating_add(topics_list_len)
            .saturating_add(self.data.length())
    }
}

/// Errors related to log construction.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("too many topics: got {got}, max {max}")]
    TooManyTopics { got: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_new_valid() {
        let log = Log::new(Address::default(), vec![ShellHash::ZERO; 4], Bytes::new());
        assert!(log.is_ok());
        assert_eq!(log.unwrap().topics.len(), 4);
    }

    #[test]
    fn log_new_empty_topics() {
        let log = Log::new(Address::default(), vec![], Bytes::new());
        assert!(log.is_ok());
    }

    #[test]
    fn log_new_too_many_topics() {
        let log = Log::new(Address::default(), vec![ShellHash::ZERO; 5], Bytes::new());
        assert!(log.is_err());
        let err = log.unwrap_err();
        assert!(err.to_string().contains("too many topics"));
    }

    #[test]
    fn log_rlp_roundtrip() {
        let log = Log {
            address: Address::from([0xAB; 20]),
            topics: vec![ShellHash::ZERO, ShellHash::from([0xFF; 32])],
            data: Bytes::from(vec![1, 2, 3, 4]),
        };
        let mut buf = Vec::new();
        log.encode(&mut buf);
        let decoded = Log::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(log, decoded);
    }

    #[test]
    fn log_rlp_roundtrip_empty() {
        let log = Log {
            address: Address::default(),
            topics: vec![],
            data: Bytes::new(),
        };
        let mut buf = Vec::new();
        log.encode(&mut buf);
        let decoded = Log::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(log, decoded);
    }
}
