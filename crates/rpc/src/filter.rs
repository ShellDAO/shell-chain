//! Log filter for `eth_getLogs` — supports address, topic, and bloom-based filtering.

use serde::Deserialize;
use shell_pqvm::bloom::{bloom_contains, Bloom, BLOOM_SIZE};
use shell_primitives::{Address, ShellHash};

/// Maximum number of blocks that can be queried in a single `eth_getLogs` call.
pub const MAX_BLOCK_RANGE: u64 = 10_000;
/// Maximum matching logs returned by a single log query or filter poll.
pub const MAX_LOG_RESULTS: usize = 10_000;
/// Maximum addresses accepted in a single log filter.
pub const MAX_LOG_FILTER_ADDRESSES: usize = 128;
/// Maximum topic alternatives accepted per topic position.
pub const MAX_LOG_TOPIC_VALUES_PER_POSITION: usize = 128;

/// Ethereum-compatible log filter used by `eth_getLogs`.
///
/// Topic matching follows standard Ethereum rules:
/// - `topics[i] = None`        -> any value at position i
/// - `topics[i] = Some([])`    -> no accepted values at position i
/// - `topics[i] = Some([A])`   -> topic at position i must equal A
/// - `topics[i] = Some([A,B])` -> topic at position i must equal A **or** B
#[derive(Debug, Clone)]
pub struct LogFilter {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub address: Option<Vec<Address>>,
    pub topics: [Option<Vec<ShellHash>>; 4],
}

impl LogFilter {
    /// Fast check using a block-level or receipt-level bloom filter.
    ///
    /// Returns `false` only when the bloom *definitely* does not contain
    /// any of the filter's addresses/topics — in that case the block/receipt
    /// can be skipped entirely.
    pub fn matches_bloom(&self, bloom_bytes: &[u8]) -> bool {
        if bloom_bytes.len() != BLOOM_SIZE {
            // Malformed or empty bloom — fall through to exact matching.
            return true;
        }
        let Ok(bloom): Result<&Bloom, _> = bloom_bytes.try_into() else {
            return true; // malformed bloom — fall through to exact matching
        };

        // Every filtered address must have at least one bloom hit.
        if let Some(addrs) = &self.address {
            if addrs.is_empty() {
                return false;
            }
            let any_match = addrs.iter().any(|a| bloom_contains(bloom, a.as_bytes()));
            if !any_match {
                return false;
            }
        }

        // Each topic position that has a filter must have at least one bloom hit.
        for hashes in self.topics.iter().flatten() {
            if hashes.is_empty() {
                return false;
            }

            let any_match = hashes.iter().any(|h| bloom_contains(bloom, h.as_bytes()));
            if !any_match {
                return false;
            }
        }

        true
    }

    /// Exact check against a specific log entry.
    pub fn matches_log(&self, log: &shell_core::Log) -> bool {
        // Address filter
        if let Some(addrs) = &self.address {
            if addrs.is_empty() || !addrs.contains(&log.address) {
                return false;
            }
        }

        // Topic filters — positional
        for (i, slot) in self.topics.iter().enumerate() {
            if let Some(hashes) = slot {
                if hashes.is_empty() {
                    return false;
                }
                match log.topics.get(i) {
                    Some(log_topic) => {
                        if !hashes.contains(log_topic) {
                            return false;
                        }
                    }
                    // Log has fewer topics than the filter position requires.
                    None => return false,
                }
            }
        }

        true
    }
}

// ── JSON deserialization for the RPC parameter ──────────────────

/// Raw JSON representation received from the client.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawLogFilter {
    pub from_block: Option<String>,
    pub to_block: Option<String>,
    /// Single address or array of addresses.
    #[serde(default, deserialize_with = "deserialize_address_filter")]
    pub address: Option<Vec<Address>>,
    /// Up to 4 topic slots; each slot is either null, a single hash, or an array.
    #[serde(default)]
    pub topics: Option<Vec<Option<TopicEntry>>>,
}

/// A topic entry is either a single hash or an array of hashes.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum TopicEntry {
    Single(ShellHash),
    Multiple(Vec<ShellHash>),
}

impl TopicEntry {
    fn into_vec(self) -> Vec<ShellHash> {
        match self {
            TopicEntry::Single(h) => vec![h],
            TopicEntry::Multiple(v) => v,
        }
    }
}

/// Deserializes `"address"` as either a single string or an array of strings.
fn deserialize_address_filter<'de, D>(deserializer: D) -> Result<Option<Vec<Address>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum AddrOrList {
        Single(Address),
        Multiple(Vec<Address>),
    }

    let opt: Option<AddrOrList> = Option::deserialize(deserializer)?;
    let addresses = opt.map(|a| match a {
        AddrOrList::Single(addr) => vec![addr],
        AddrOrList::Multiple(addrs) => addrs,
    });
    if let Some(addresses) = &addresses {
        if addresses.len() > MAX_LOG_FILTER_ADDRESSES {
            return Err(serde::de::Error::custom(format!(
                "address filter supports at most {MAX_LOG_FILTER_ADDRESSES} entries"
            )));
        }
    }
    Ok(addresses)
}

impl RawLogFilter {
    fn into_topics(
        raw_topics: Option<Vec<Option<TopicEntry>>>,
    ) -> Result<[Option<Vec<ShellHash>>; 4], String> {
        let mut topics: [Option<Vec<ShellHash>>; 4] = Default::default();
        if let Some(raw_topics) = raw_topics {
            if raw_topics.len() > 4 {
                return Err("topics must contain at most 4 entries".to_string());
            }
            for (i, entry) in raw_topics.into_iter().enumerate() {
                let values = entry.map(|e| e.into_vec());
                if let Some(values) = &values {
                    if values.len() > MAX_LOG_TOPIC_VALUES_PER_POSITION {
                        return Err(format!(
                            "topic position {i} supports at most {MAX_LOG_TOPIC_VALUES_PER_POSITION} values"
                        ));
                    }
                }
                topics[i] = values;
            }
        }
        Ok(topics)
    }

    /// Convert to a resolved `LogFilter`, resolving block tags to numbers.
    pub fn into_filter(self, latest_block: u64, finalized_block: u64) -> Result<LogFilter, String> {
        let RawLogFilter {
            from_block: from_block_tag,
            to_block: to_block_tag,
            address,
            topics: raw_topics,
        } = self;
        let topics = Self::into_topics(raw_topics)?;

        let resolve = |field: &str, tag: &str| -> Result<u64, String> {
            match tag {
                "latest" | "pending" => Ok(latest_block),
                "safe" | "finalized" => Ok(finalized_block),
                "earliest" => Ok(0),
                hex => {
                    let Some(hex) = hex.strip_prefix("0x") else {
                        return Err(format!(
                            "{field} must be a block tag or 0x-prefixed quantity"
                        ));
                    };
                    if hex.is_empty() {
                        return Err(format!("{field} must not be an empty quantity"));
                    }
                    if hex.len() > 1 && hex.starts_with('0') {
                        return Err(format!("{field} quantity must not have leading zeroes"));
                    }
                    if !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
                        return Err(format!(
                            "{field} has invalid hex quantity: contains non-hex characters"
                        ));
                    }
                    if hex.len() > 16 {
                        return Err(format!(
                            "{field} hex quantity is too long for u64: {} chars (max 16)",
                            hex.len()
                        ));
                    }
                    u64::from_str_radix(hex, 16)
                        .map_err(|_| format!("{field} has invalid hex quantity"))
                }
            }
        };

        let from_block = match from_block_tag.as_deref() {
            Some(tag) => Some(resolve("fromBlock", tag)?),
            None => Some(latest_block),
        };
        let to_block = match to_block_tag.as_deref() {
            Some(tag) => Some(resolve("toBlock", tag)?),
            None => Some(latest_block),
        };

        Ok(LogFilter {
            from_block,
            to_block,
            address,
            topics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_pqvm::bloom::logs_bloom;
    use shell_primitives::Bytes;

    fn make_log(addr: Address, topics: Vec<ShellHash>, data: &[u8]) -> shell_core::Log {
        shell_core::Log::new(addr, topics, Bytes::copy_from_slice(data)).unwrap()
    }

    // ── Empty range → empty result ──────────────────────────────

    #[test]
    fn empty_filter_matches_any_log() {
        let filter = LogFilter {
            from_block: Some(0),
            to_block: Some(0),
            address: None,
            topics: Default::default(),
        };
        let log = make_log(Address::from([0x01; 20]), vec![], b"");
        assert!(filter.matches_log(&log));
    }

    // ── Address filtering ───────────────────────────────────────

    #[test]
    fn filter_matches_specific_address() {
        let target = Address::from([0xAA; 20]);
        let filter = LogFilter {
            from_block: Some(0),
            to_block: Some(10),
            address: Some(vec![target]),
            topics: Default::default(),
        };

        let matching = make_log(target, vec![], b"");
        let other = make_log(Address::from([0xBB; 20]), vec![], b"");
        assert!(filter.matches_log(&matching));
        assert!(!filter.matches_log(&other));
    }

    #[test]
    fn filter_matches_one_of_multiple_addresses() {
        let a = Address::from([0xAA; 20]);
        let b = Address::from([0xBB; 20]);
        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: Some(vec![a, b]),
            topics: Default::default(),
        };

        assert!(filter.matches_log(&make_log(a, vec![], b"")));
        assert!(filter.matches_log(&make_log(b, vec![], b"")));
        assert!(!filter.matches_log(&make_log(Address::from([0xCC; 20]), vec![], b"")));
    }

    #[test]
    fn empty_address_array_matches_no_logs() {
        let log = make_log(Address::from([0xAA; 20]), vec![], b"");
        let bloom = logs_bloom(std::slice::from_ref(&log));
        let raw: RawLogFilter = serde_json::from_str(r#"{"address":[]}"#).unwrap();
        let filter = raw.into_filter(100, 90).unwrap();

        assert_eq!(filter.address, Some(vec![]));
        assert!(!filter.matches_log(&log));
        assert!(!filter.matches_bloom(&bloom));
    }

    // ── Topic filtering ─────────────────────────────────────────

    #[test]
    fn filter_topic_exact_match() {
        let topic = ShellHash::from_slice(&[0x11; 32]);
        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: None,
            topics: [Some(vec![topic]), None, None, None],
        };

        let matching = make_log(Address::from([0x01; 20]), vec![topic], b"");
        let wrong = make_log(
            Address::from([0x01; 20]),
            vec![ShellHash::from_slice(&[0x22; 32])],
            b"",
        );
        assert!(filter.matches_log(&matching));
        assert!(!filter.matches_log(&wrong));
    }

    #[test]
    fn filter_topic_or_match() {
        let a = ShellHash::from_slice(&[0x11; 32]);
        let b = ShellHash::from_slice(&[0x22; 32]);
        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: None,
            topics: [Some(vec![a, b]), None, None, None],
        };

        assert!(filter.matches_log(&make_log(Address::ZERO, vec![a], b"")));
        assert!(filter.matches_log(&make_log(Address::ZERO, vec![b], b"")));
        assert!(!filter.matches_log(&make_log(
            Address::ZERO,
            vec![ShellHash::from_slice(&[0x33; 32])],
            b""
        )));
    }

    #[test]
    fn empty_topic_alternative_array_matches_no_logs() {
        let topic = ShellHash::from_slice(&[0x11; 32]);
        let log = make_log(Address::ZERO, vec![topic], b"");
        let bloom = logs_bloom(std::slice::from_ref(&log));
        let raw: RawLogFilter = serde_json::from_str(r#"{"topics":[[]]}"#).unwrap();
        let filter = raw.into_filter(100, 90).unwrap();

        assert_eq!(filter.topics[0], Some(vec![]));
        assert!(!filter.matches_log(&log));
        assert!(!filter.matches_bloom(&bloom));
    }

    #[test]
    fn filter_topic_position_matters() {
        let t0 = ShellHash::from_slice(&[0xAA; 32]);
        let t1 = ShellHash::from_slice(&[0xBB; 32]);
        // Filter requires topic[1] == t1 (topic[0] is any).
        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: None,
            topics: [None, Some(vec![t1]), None, None],
        };

        let ok = make_log(Address::ZERO, vec![t0, t1], b"");
        let wrong_pos = make_log(Address::ZERO, vec![t1, t0], b"");
        let too_few = make_log(Address::ZERO, vec![t0], b"");
        assert!(filter.matches_log(&ok));
        assert!(!filter.matches_log(&wrong_pos));
        assert!(!filter.matches_log(&too_few));
    }

    // ── Bloom fast-path ─────────────────────────────────────────

    #[test]
    fn bloom_rejects_unmatched_address() {
        let addr = Address::from([0xAA; 20]);
        let other = Address::from([0xBB; 20]);
        let log = make_log(other, vec![], b"");
        let bloom = logs_bloom(&[log]);

        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: Some(vec![addr]),
            topics: Default::default(),
        };

        // Bloom for `other` should not match filter for `addr`.
        assert!(!filter.matches_bloom(&bloom));
    }

    #[test]
    fn bloom_accepts_matching_address() {
        let addr = Address::from([0xAA; 20]);
        let log = make_log(addr, vec![], b"");
        let bloom = logs_bloom(&[log]);

        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: Some(vec![addr]),
            topics: Default::default(),
        };

        assert!(filter.matches_bloom(&bloom));
    }

    #[test]
    fn bloom_rejects_unmatched_topic() {
        let topic = ShellHash::from_slice(&[0x11; 32]);
        let other = ShellHash::from_slice(&[0x22; 32]);
        let log = make_log(Address::ZERO, vec![other], b"");
        let bloom = logs_bloom(&[log]);

        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: None,
            topics: [Some(vec![topic]), None, None, None],
        };

        assert!(!filter.matches_bloom(&bloom));
    }

    #[test]
    fn empty_bloom_is_permissive() {
        // An empty (zero-length) bloom should not reject anything.
        let filter = LogFilter {
            from_block: None,
            to_block: None,
            address: Some(vec![Address::from([0x01; 20])]),
            topics: Default::default(),
        };
        assert!(filter.matches_bloom(&[]));
    }

    // ── JSON deserialization ────────────────────────────────────

    #[test]
    fn raw_filter_single_address() {
        let json = serde_json::json!({
            "fromBlock": "0x1",
            "toBlock": "0x5",
            "address": Address::from([0x01; 20]),
        });
        let raw: RawLogFilter = serde_json::from_value(json).unwrap();
        let filter = raw.into_filter(100, 90).unwrap();
        assert_eq!(filter.from_block, Some(1));
        assert_eq!(filter.to_block, Some(5));
        assert_eq!(filter.address.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn raw_filter_array_address() {
        let json = serde_json::json!({
            "address": [
                Address::from([0x01; 20]).to_string(),
                Address::from([0x02; 20]).to_string()
            ]
        });
        let raw: RawLogFilter = serde_json::from_value(json).unwrap();
        let filter = raw.into_filter(100, 90).unwrap();
        assert_eq!(filter.address.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn raw_filter_rejects_too_many_addresses() {
        let addresses = vec![Address::from([0x01; 20]).to_string(); MAX_LOG_FILTER_ADDRESSES + 1];
        let json = serde_json::json!({ "address": addresses });

        let err = serde_json::from_value::<RawLogFilter>(json).unwrap_err();

        assert!(err.to_string().contains("address filter supports at most"));
    }

    #[test]
    fn raw_filter_topics() {
        let json = r#"{"topics":[null,"0x0000000000000000000000000000000000000000000000000000000000000001"]}"#;
        let raw: RawLogFilter = serde_json::from_str(json).unwrap();
        let filter = raw.into_filter(100, 90).unwrap();
        assert!(filter.topics[0].is_none());
        assert!(filter.topics[1].is_some());
        assert_eq!(filter.topics[1].as_ref().unwrap().len(), 1);
    }

    #[test]
    fn raw_filter_rejects_more_than_four_topic_slots() {
        let json = r#"{
            "topics": [
                null,
                null,
                null,
                null,
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ]
        }"#;
        let raw: RawLogFilter = serde_json::from_str(json).unwrap();
        let err = raw.into_filter(100, 90).unwrap_err();
        assert!(err.contains("at most 4"));
    }

    #[test]
    fn raw_filter_rejects_too_many_topic_values() {
        let topics = vec![ShellHash::from([0x11; 32]); MAX_LOG_TOPIC_VALUES_PER_POSITION + 1];
        let raw: RawLogFilter = serde_json::from_value(serde_json::json!({
            "topics": [topics]
        }))
        .unwrap();

        let err = raw.into_filter(100, 90).unwrap_err();

        assert!(err.contains("supports at most"));
    }

    #[test]
    fn raw_filter_defaults_to_latest() {
        let json = r#"{}"#;
        let raw: RawLogFilter = serde_json::from_str(json).unwrap();
        let filter = raw.into_filter(42, 7).unwrap();
        assert_eq!(filter.from_block, Some(42));
        assert_eq!(filter.to_block, Some(42));
    }

    #[test]
    fn raw_filter_resolves_finality_block_tags() {
        let raw: RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"safe","toBlock":"finalized"}"#).unwrap();
        let filter = raw.into_filter(42, 7).unwrap();
        assert_eq!(filter.from_block, Some(7));
        assert_eq!(filter.to_block, Some(7));
    }

    #[test]
    fn raw_filter_rejects_invalid_block_tags() {
        let raw: RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"not-a-block","toBlock":"0x1"}"#).unwrap();
        let err = raw.into_filter(42, 7).unwrap_err();
        assert!(err.contains("fromBlock"));

        let raw: RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x1","toBlock":"0x"}"#).unwrap();
        let err = raw.into_filter(42, 7).unwrap_err();
        assert!(err.contains("toBlock"));

        let raw: RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x01","toBlock":"0x1"}"#).unwrap();
        let err = raw.into_filter(42, 7).unwrap_err();
        assert!(err.contains("fromBlock"));

        let raw: RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x1","toBlock":"0x0g"}"#).unwrap();
        let err = raw.into_filter(42, 7).unwrap_err();
        assert!(err.contains("toBlock"));

        let raw: RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x10000000000000000","toBlock":"0x1"}"#).unwrap();
        let err = raw.into_filter(42, 7).unwrap_err();
        assert!(err.contains("fromBlock"));
        assert!(err.contains("too long"));

        let invalid = format!(
            r#"{{"fromBlock":"0x{}z","toBlock":"0x1"}}"#,
            "f".repeat(512)
        );
        let raw: RawLogFilter = serde_json::from_str(&invalid).unwrap();
        let err = raw.into_filter(42, 7).unwrap_err();
        assert!(err.contains("non-hex characters"));
        assert!(
            !err.contains(&"f".repeat(128)),
            "error should not reflect large invalid quantities"
        );
    }
}
