use core::{fmt, str::FromStr};

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{PrimitivesError, ShellHash};

/// 32-byte PQ-native address derived as BLAKE3(algo_id || pubkey).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub const ZERO: Self = Self([0u8; 32]);

    /// Derive address: BLAKE3(algo_id || pubkey) — full 32-byte output, no version byte.
    pub fn from_public_key(pubkey: &[u8], algo_id: u8) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[algo_id]);
        hasher.update(pubkey);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::try_from_slice(slice)
            .expect("Address::from_slice: slice must be exactly 32 bytes")
    }

    pub fn try_from_slice(slice: &[u8]) -> Result<Self, PrimitivesError> {
        if slice.len() != 32 {
            return Err(PrimitivesError::InvalidSliceLength {
                expected: 32,
                got: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse "0x" + 64 lowercase hex.
    pub fn parse(s: &str) -> Result<Self, PrimitivesError> {
        s.parse()
    }

    /// Convert from 20-byte alloy address (zero-pad left: [0;12] ++ 20 bytes).
    pub fn from_alloy(a: alloy_primitives::Address) -> Self {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(a.as_slice());
        Self(bytes)
    }

    /// Convert to 20-byte alloy address (take last 20 bytes).
    pub fn to_alloy(&self) -> alloy_primitives::Address {
        alloy_primitives::Address::from_slice(&self.0[12..])
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl FromStr for Address {
    type Err = PrimitivesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_str = s.strip_prefix("0x").ok_or_else(|| {
            PrimitivesError::HexDecode(hex::FromHexError::InvalidHexCharacter {
                c: s.chars().next().unwrap_or('?'),
                index: 0,
            })
        })?;
        if hex_str.len() != 64 {
            return Err(PrimitivesError::InvalidLength {
                expected: 64,
                got: hex_str.len(),
            });
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl From<[u8; 32]> for Address {
    fn from(arr: [u8; 32]) -> Self {
        Self(arr)
    }
}

impl From<[u8; 20]> for Address {
    fn from(arr: [u8; 20]) -> Self {
        Self::from_alloy(alloy_primitives::Address::from(arr))
    }
}

impl From<alloy_primitives::Address> for Address {
    fn from(a: alloy_primitives::Address) -> Self {
        Self::from_alloy(a)
    }
}

impl From<Address> for alloy_primitives::Address {
    fn from(a: Address) -> Self {
        a.to_alloy()
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<ShellHash> for Address {
    fn from(hash: ShellHash) -> Self {
        Self(*hash.as_bytes())
    }
}

impl alloy_rlp::Encodable for Address {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.0.as_slice().encode(out);
    }

    fn length(&self) -> usize {
        alloy_rlp::Encodable::length(&self.0.as_slice())
    }
}

impl alloy_rlp::Decodable for Address {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = <[u8; 32]>::decode(buf)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse::<Self>().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_from_public_key() {
        let fake_pubkey = [0xABu8; 64];
        let addr = Address::from_public_key(&fake_pubkey, 0);
        assert_eq!(addr.as_bytes().len(), 32);
        assert_eq!(addr, Address::from_public_key(&fake_pubkey, 0));
    }

    #[test]
    fn address_derivation_binds_algorithm() {
        let fake_pubkey = [0xABu8; 64];
        let dilithium = Address::from_public_key(&fake_pubkey, 0);
        let sphincs = Address::from_public_key(&fake_pubkey, 2);

        assert_ne!(dilithium, sphincs);
    }

    #[test]
    fn address_display() {
        let addr = Address::from([0x01; 32]);
        let rendered = addr.to_string();
        assert!(rendered.starts_with("0x"));
        assert_eq!(rendered.len(), 66);
        assert_eq!(Address::from_str(&rendered).unwrap(), addr);
    }

    #[test]
    fn address_debug_uses_0x() {
        let addr = Address::from([0x01; 32]);
        let dbg = format!("{addr:?}");
        assert!(dbg.starts_with("Address(0x"), "expected 0x in debug: {dbg}");
    }

    #[test]
    fn address_parse_rejects_bare_hex() {
        let addr = Address::from([0x22; 32]);
        assert_eq!(Address::parse(&addr.to_string()).unwrap(), addr);
        assert!(Address::parse(&hex::encode(addr.as_bytes())).is_err());
    }

    #[test]
    fn address_parse_rejects_wrong_length() {
        assert!(Address::parse("0x1234").is_err());
        assert!(Address::parse("0x0000000000000000000000000000000000000001").is_err());
    }

    #[test]
    fn address_from_hash() {
        let hash = crate::keccak256(b"some-pubkey-data");
        let addr = Address::from(hash);
        assert_eq!(addr.as_bytes(), hash.as_bytes());
    }

    #[test]
    fn address_serde_roundtrip() {
        let addr = Address::from([0xDE; 32]);
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, format!("\"{}\"", addr));
        let addr2: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn address_rlp_roundtrip() {
        use alloy_rlp::{Decodable, Encodable};
        let addr = Address::from([0x42; 32]);
        let mut buf = Vec::new();
        addr.encode(&mut buf);
        let addr2 = Address::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn try_from_slice_valid() {
        let data = [0x42u8; 32];
        let addr = Address::try_from_slice(&data).unwrap();
        assert_eq!(addr.as_bytes(), &data);
    }

    #[test]
    fn try_from_slice_wrong_length() {
        assert!(Address::try_from_slice(&[0u8; 31]).is_err());
        assert!(Address::try_from_slice(&[0u8; 33]).is_err());
        assert!(Address::try_from_slice(&[]).is_err());
    }

    #[test]
    fn alloy_boundary_roundtrip() {
        let evm = alloy_primitives::Address::from([0xAB; 20]);
        let addr = Address::from_alloy(evm);
        assert_eq!(&addr.as_bytes()[12..], evm.as_slice());
        assert_eq!(addr.to_alloy(), evm);
    }
}
