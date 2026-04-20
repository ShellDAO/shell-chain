use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_primitives::{ShellHash, U256};

/// Account with native Account Abstraction support.
///
/// Every account can optionally specify custom validation logic via
/// `validation_code_hash`, enabling signature scheme upgrades without
/// a hard fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Hash of the PQ public key used for default signature verification.
    pub pq_pubkey_hash: ShellHash,
    /// Transaction count.
    pub nonce: u64,
    /// Balance in native token (wei-equivalent).
    pub balance: U256,
    /// Custom validation logic code hash (None = default Dilithium).
    /// Enables Account Abstraction: users can upgrade their signature scheme.
    pub validation_code_hash: Option<ShellHash>,
    /// Contract code hash (None = account without EVM bytecode).
    pub code_hash: Option<ShellHash>,
    /// Root of the account's storage trie.
    pub storage_root: ShellHash,
}

impl Account {
    /// Create a new user account with built-in Dilithium validation.
    pub fn new_user_account(pq_pubkey_hash: ShellHash, balance: U256) -> Self {
        Self {
            pq_pubkey_hash,
            nonce: 0,
            balance,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        }
    }

    pub fn is_contract(&self) -> bool {
        self.code_hash.is_some()
    }

    pub fn has_custom_validation(&self) -> bool {
        self.validation_code_hash.is_some()
    }
}

fn encode_optional_hash(hash: &Option<ShellHash>, out: &mut dyn alloy_rlp::BufMut) {
    match hash {
        Some(h) => h.encode(out),
        None => {
            let empty: &[u8] = &[];
            empty.encode(out);
        }
    }
}

fn optional_hash_len(hash: &Option<ShellHash>) -> usize {
    match hash {
        Some(h) => h.length(),
        None => 1, // 0x80
    }
}

impl Encodable for Account {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        self.pq_pubkey_hash.encode(out);
        self.nonce.encode(out);
        self.balance.encode(out);
        encode_optional_hash(&self.validation_code_hash, out);
        encode_optional_hash(&self.code_hash, out);
        self.storage_root.encode(out);
    }

    fn length(&self) -> usize {
        let payload = self.fields_len();
        alloy_rlp::Header {
            list: true,
            payload_length: payload,
        }
        .length()
        .saturating_add(payload)
    }
}

impl Account {
    fn fields_len(&self) -> usize {
        self.pq_pubkey_hash
            .length()
            .saturating_add(self.nonce.length())
            .saturating_add(self.balance.length())
            .saturating_add(optional_hash_len(&self.validation_code_hash))
            .saturating_add(optional_hash_len(&self.code_hash))
            .saturating_add(self.storage_root.length())
    }
}

fn decode_optional_hash(buf: &mut &[u8]) -> alloy_rlp::Result<Option<ShellHash>> {
    if buf.is_empty() {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    // 0x80 = RLP encoding of empty bytes → None
    if buf.first().copied().unwrap_or(0) == 0x80 {
        // buf.is_empty() was checked above, so &buf[1..] is always valid here.
        *buf = &buf[1..];
        Ok(None)
    } else {
        Ok(Some(ShellHash::decode(buf)?))
    }
}

impl Decodable for Account {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();

        let pq_pubkey_hash = ShellHash::decode(buf)?;
        let nonce = u64::decode(buf)?;
        let balance = U256::decode(buf)?;
        let validation_code_hash = decode_optional_hash(buf)?;
        let code_hash = decode_optional_hash(buf)?;
        let storage_root = ShellHash::decode(buf)?;

        let consumed = remaining.saturating_sub(buf.len());
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            pq_pubkey_hash,
            nonce,
            balance,
            validation_code_hash,
            code_hash,
            storage_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::keccak256;

    #[test]
    fn new_user_account() {
        let pubkey_hash = keccak256(b"dilithium-pubkey");
        let acct = Account::new_user_account(pubkey_hash, U256::from(1000));
        assert!(!acct.is_contract());
        assert!(!acct.has_custom_validation());
        assert_eq!(acct.nonce, 0);
    }

    #[test]
    fn serde_roundtrip() {
        let acct = Account::new_user_account(keccak256(b"test"), U256::from(42));
        let json = serde_json::to_string(&acct).unwrap();
        let acct2: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(acct, acct2);
    }

    #[test]
    fn account_rlp_roundtrip() {
        let acct = Account::new_user_account(keccak256(b"rlp-test"), U256::from(999));
        let mut buf = Vec::new();
        acct.encode(&mut buf);
        assert!(!buf.is_empty());

        let decoded = Account::decode(&mut &buf[..]).unwrap();
        assert_eq!(acct, decoded);
    }

    #[test]
    fn account_with_custom_validation_rlp() {
        let mut acct = Account::new_user_account(keccak256(b"aa-test"), U256::from(0));
        acct.validation_code_hash = Some(keccak256(b"custom-validator"));
        acct.code_hash = Some(keccak256(b"contract-code"));

        let mut buf = Vec::new();
        acct.encode(&mut buf);

        let decoded = Account::decode(&mut &buf[..]).unwrap();
        assert_eq!(acct, decoded);
    }
}
