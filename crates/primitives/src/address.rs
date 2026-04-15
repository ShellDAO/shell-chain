use core::{fmt, str::FromStr};

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{PrimitivesError, ShellHash};

/// 20-byte address, identical raw layout to EVM addresses.
///
/// Shell user accounts are derived from PQ public keys via
/// `blake3(version || algo_id || pubkey)[0..20]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address(pub alloy_primitives::Address);

impl Address {
    pub const ZERO: Self = Self(alloy_primitives::Address::ZERO);
    pub const DERIVATION_VERSION_V1: u8 = 0x01;
    pub const BECH32_HRP: &str = "pq";

    pub fn from_slice(slice: &[u8]) -> Self {
        Self(alloy_primitives::Address::from_slice(slice))
    }

    /// Derive an address from a raw public key:
    /// `blake3(version || algo_id || pubkey)[0..20]`.
    pub fn from_public_key(pubkey: &[u8], algo_id: u8) -> Self {
        Self::from_public_key_with_version(pubkey, Self::DERIVATION_VERSION_V1, algo_id)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        self.0.as_ref()
    }

    pub fn to_bech32m(&self, version: u8) -> String {
        let mut data = [0u8; 21];
        data[0] = version;
        data[1..].copy_from_slice(self.as_bytes());

        let hrp = Hrp::parse(Self::BECH32_HRP)
            .unwrap_or_else(|_| unreachable!("static bech32 hrp must be valid"));
        bech32::encode::<Bech32m>(hrp, &data)
            .unwrap_or_else(|_| unreachable!("fixed-size address payload must encode"))
    }

    pub fn from_bech32m(s: &str) -> Result<(Self, u8), PrimitivesError> {
        let parsed = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| PrimitivesError::Bech32(e.to_string()))?;

        let hrp = parsed.hrp();
        if hrp.to_lowercase() != Self::BECH32_HRP {
            return Err(PrimitivesError::InvalidAddressHrp {
                expected: Self::BECH32_HRP,
                got: hrp.to_string(),
            });
        }

        let data: Vec<u8> = parsed.byte_iter().collect();
        if data.len() != 21 {
            return Err(PrimitivesError::InvalidLength {
                expected: 21,
                got: data.len(),
            });
        }

        let (version, raw_addr) = data
            .split_first()
            .unwrap_or_else(|| unreachable!("validated fixed-size bech32 payload"));
        Ok((Self::try_from_slice(raw_addr)?, *version))
    }

    /// Parse a user-facing address string.
    ///
    /// Accepts the canonical `pq1...` Bech32m format and legacy hex strings
    /// (`0x...` or bare 40-hex form) during the migration window.
    pub fn parse(s: &str) -> Result<Self, PrimitivesError> {
        if Self::looks_like_bech32m(s) {
            let (addr, _) = Self::from_bech32m(s)?;
            return Ok(addr);
        }

        Self::from_hex(s)
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn from_hex(s: &str) -> Result<Self, PrimitivesError> {
        let trimmed = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let bytes = hex::decode(trimmed)?;
        Self::try_from_slice(&bytes)
    }

    /// Try to construct from a byte slice, returning an error if length ≠ 20.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, PrimitivesError> {
        if slice.len() != 20 {
            return Err(PrimitivesError::InvalidSliceLength {
                expected: 20,
                got: slice.len(),
            });
        }
        Ok(Self(alloy_primitives::Address::from_slice(slice)))
    }

    fn from_public_key_with_version(pubkey: &[u8], version: u8, algo_id: u8) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[version, algo_id]);
        hasher.update(pubkey);

        let hash = hasher.finalize();
        Self::from_slice(&hash.as_bytes()[..20])
    }

    fn looks_like_bech32m(s: &str) -> bool {
        s.to_ascii_lowercase()
            .starts_with(&format!("{}1", Self::BECH32_HRP))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(0x{})", hex::encode(self.0))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bech32m(Self::DERIVATION_VERSION_V1))
    }
}

impl FromStr for Address {
    type Err = PrimitivesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, _) = Self::from_bech32m(s)?;
        Ok(addr)
    }
}

impl From<[u8; 20]> for Address {
    fn from(arr: [u8; 20]) -> Self {
        Self(alloy_primitives::Address::from(arr))
    }
}

impl From<alloy_primitives::Address> for Address {
    fn from(a: alloy_primitives::Address) -> Self {
        Self(a)
    }
}

impl From<Address> for alloy_primitives::Address {
    fn from(a: Address) -> Self {
        a.0
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<ShellHash> for Address {
    fn from(hash: ShellHash) -> Self {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash.as_bytes()[12..]);
        Self(alloy_primitives::Address::from(addr))
    }
}

impl alloy_rlp::Encodable for Address {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let bytes: [u8; 20] = self.0.into_array();
        bytes.as_slice().encode(out);
    }

    fn length(&self) -> usize {
        let bytes: [u8; 20] = self.0.into_array();
        alloy_rlp::Encodable::length(&bytes.as_slice())
    }
}

impl alloy_rlp::Decodable for Address {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = <[u8; 20]>::decode(buf)?;
        Ok(Self(alloy_primitives::Address::from(bytes)))
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
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_from_public_key() {
        let fake_pubkey = [0xABu8; 64];
        let addr = Address::from_public_key(&fake_pubkey, 0);
        assert_eq!(addr.as_bytes().len(), 20);
        // Deterministic
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
    fn address_derivation_binds_version() {
        let fake_pubkey = [0xCDu8; 64];
        let current = Address::from_public_key(&fake_pubkey, 0);
        let future = Address::from_public_key_with_version(&fake_pubkey, 2, 0);

        assert_ne!(current, future);
    }

    #[test]
    fn address_display() {
        let addr = Address::from([0x01; 20]);
        let rendered = addr.to_string();
        assert!(rendered.starts_with("pq1"));
        assert_eq!(Address::from_str(&rendered).unwrap(), addr);
    }

    #[test]
    fn address_bech32m_roundtrip() {
        let addr = Address::from([0xEF; 20]);
        let encoded = addr.to_bech32m(Address::DERIVATION_VERSION_V1);
        let (decoded, version) = Address::from_bech32m(&encoded).unwrap();

        assert_eq!(version, Address::DERIVATION_VERSION_V1);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn address_bech32m_rejects_wrong_hrp() {
        let encoded = bech32::encode::<Bech32m>(Hrp::parse("sh").unwrap(), &[1u8; 21]).unwrap();
        assert!(matches!(
            Address::from_bech32m(&encoded),
            Err(PrimitivesError::InvalidAddressHrp { .. })
        ));
    }

    #[test]
    fn address_hex_helpers_roundtrip() {
        let addr = Address::from([0x34; 20]);
        let encoded = addr.to_hex();

        assert_eq!(Address::from_hex(&encoded).unwrap(), addr);
        assert_eq!(
            Address::from_hex(encoded.trim_start_matches("0x")).unwrap(),
            addr
        );
    }

    #[test]
    fn address_from_hash() {
        let hash = crate::keccak256(b"some-pubkey-data");
        let addr = Address::from(hash);
        assert_eq!(addr.as_bytes(), &hash.as_bytes()[12..]);
    }

    #[test]
    fn address_serde_roundtrip() {
        let addr = Address::from([0xDE; 20]);
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, format!("\"{}\"", addr));
        let addr2: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn address_serde_accepts_legacy_hex() {
        let addr: Address =
            serde_json::from_str("\"0x0101010101010101010101010101010101010101\"").unwrap();
        assert_eq!(addr, Address::from([0x01; 20]));
    }

    #[test]
    fn address_parse_accepts_bech32_and_legacy_hex() {
        let addr = Address::from([0x22; 20]);

        assert_eq!(Address::parse(&addr.to_string()).unwrap(), addr);
        assert_eq!(Address::parse(&addr.to_hex()).unwrap(), addr);
        assert_eq!(
            Address::parse(addr.to_hex().trim_start_matches("0x")).unwrap(),
            addr
        );
    }

    #[test]
    fn address_rlp_roundtrip() {
        use alloy_rlp::{Decodable, Encodable};
        let addr = Address::from([0x42; 20]);
        let mut buf = Vec::new();
        addr.encode(&mut buf);
        let addr2 = Address::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn try_from_slice_valid() {
        let data = [0x42u8; 20];
        let addr = Address::try_from_slice(&data).unwrap();
        assert_eq!(addr.as_bytes(), &data);
    }

    #[test]
    fn try_from_slice_wrong_length() {
        assert!(Address::try_from_slice(&[0u8; 19]).is_err());
        assert!(Address::try_from_slice(&[0u8; 21]).is_err());
        assert!(Address::try_from_slice(&[]).is_err());
    }
}
