use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_primitives::{Address, Bytes, ShellHash};

use crate::log::Log;

/// Result of executing a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash.
    pub tx_hash: ShellHash,
    /// Block number where this transaction was included.
    pub block_number: u64,
    /// Index of the transaction within the block.
    pub tx_index: u32,
    /// Whether the transaction succeeded (1) or reverted (0).
    pub status: u8,
    /// Gas consumed by this transaction.
    pub gas_used: u64,
    /// Cumulative gas used in the block up to and including this tx.
    pub cumulative_gas_used: u64,
    /// Contract address created, if any.
    pub contract_address: Option<Address>,
    /// Bloom filter for fast log filtering (2048-bit / 256 bytes).
    /// Populated by the PQVM/revm execution adapter; empty until execution.
    pub logs_bloom: Bytes,
    /// Event logs emitted during execution.
    pub logs: Vec<Log>,
}

impl TransactionReceipt {
    pub fn succeeded(&self) -> bool {
        self.status == 1
    }

    fn rlp_fields_len(&self) -> usize {
        let addr_len = match &self.contract_address {
            Some(addr) => addr.length(),
            None => 1, // 0x80
        };
        let logs_payload: usize = self.logs.iter().map(|l| l.length()).sum();
        let logs_list_len = alloy_rlp::Header {
            list: true,
            payload_length: logs_payload,
        }
        .length()
        .saturating_add(logs_payload);
        self.tx_hash
            .length()
            .saturating_add(self.block_number.length())
            .saturating_add(self.tx_index.length())
            .saturating_add(self.status.length())
            .saturating_add(self.gas_used.length())
            .saturating_add(self.cumulative_gas_used.length())
            .saturating_add(addr_len)
            .saturating_add(self.logs_bloom.length())
            .saturating_add(logs_list_len)
    }
}

impl Encodable for TransactionReceipt {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_fields_len(),
        };
        header.encode(out);
        self.tx_hash.encode(out);
        self.block_number.encode(out);
        self.tx_index.encode(out);
        self.status.encode(out);
        self.gas_used.encode(out);
        self.cumulative_gas_used.encode(out);
        match &self.contract_address {
            Some(addr) => addr.encode(out),
            None => {
                let empty: &[u8] = &[];
                empty.encode(out);
            }
        }
        self.logs_bloom.encode(out);
        let logs_payload: usize = self.logs.iter().map(|l| l.length()).sum();
        alloy_rlp::Header {
            list: true,
            payload_length: logs_payload,
        }
        .encode(out);
        for log in &self.logs {
            log.encode(out);
        }
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

impl Decodable for TransactionReceipt {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let tx_hash = ShellHash::decode(buf)?;
        let block_number = u64::decode(buf)?;
        let tx_index = u32::decode(buf)?;
        let status = u8::decode(buf)?;
        let gas_used = u64::decode(buf)?;
        let cumulative_gas_used = u64::decode(buf)?;

        let addr_bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        let contract_address = if addr_bytes.is_empty() {
            None
        } else if addr_bytes.len() == 32 {
            Some(
                Address::try_from_slice(addr_bytes)
                    .map_err(|_| alloy_rlp::Error::Custom("invalid contract address bytes"))?,
            )
        } else if addr_bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(addr_bytes);
            Some(Address::from(arr))
        } else {
            return Err(alloy_rlp::Error::Custom("invalid contract address length"));
        };

        let logs_bloom = Bytes::decode(buf)?;

        let logs_header = alloy_rlp::Header::decode(buf)?;
        if !logs_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut logs = Vec::new();
        let logs_end = crate::rlp_payload_end(buf.len(), logs_header.payload_length)?;
        while buf.len() > logs_end {
            logs.push(Log::decode(buf)?);
        }

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            tx_hash,
            block_number,
            tx_index,
            status,
            gas_used,
            cumulative_gas_used,
            contract_address,
            logs_bloom,
            logs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::keccak256;

    #[test]
    fn receipt_success_check() {
        let receipt = TransactionReceipt {
            tx_hash: keccak256(b"tx1"),
            block_number: 1,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: None,
            logs_bloom: Bytes::new(),
            logs: vec![],
        };
        assert!(receipt.succeeded());
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let receipt = TransactionReceipt {
            tx_hash: keccak256(b"tx"),
            block_number: 42,
            tx_index: 3,
            status: 0,
            gas_used: 50000,
            cumulative_gas_used: 100000,
            contract_address: Some(Address::from([0xAB; 20])),
            logs_bloom: Bytes::new(),
            logs: vec![Log {
                address: Address::from([0xCD; 20]),
                topics: vec![keccak256(b"Transfer(address,address,uint256)")],
                data: shell_primitives::Bytes::from(vec![1, 2, 3]),
            }],
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let receipt2: TransactionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, receipt2);
    }

    #[test]
    fn receipt_rlp_roundtrip() {
        let receipt = TransactionReceipt {
            tx_hash: keccak256(b"tx"),
            block_number: 42,
            tx_index: 3,
            status: 0,
            gas_used: 50000,
            cumulative_gas_used: 100000,
            contract_address: Some(Address::from([0xAB; 20])),
            logs_bloom: Bytes::new(),
            logs: vec![Log {
                address: Address::from([0xCD; 20]),
                topics: vec![keccak256(b"Transfer(address,address,uint256)")],
                data: shell_primitives::Bytes::from(vec![1, 2, 3]),
            }],
        };
        let mut buf = Vec::new();
        receipt.encode(&mut buf);
        let decoded = TransactionReceipt::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn receipt_rlp_roundtrip_no_contract() {
        let receipt = TransactionReceipt {
            tx_hash: keccak256(b"tx2"),
            block_number: 1,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: None,
            logs_bloom: Bytes::new(),
            logs: vec![],
        };
        let mut buf = Vec::new();
        receipt.encode(&mut buf);
        let decoded = TransactionReceipt::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(receipt, decoded);
    }
}
