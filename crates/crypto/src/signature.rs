use alloy_rlp::Encodable;
use serde::de::Error as DeError;
use serde::{Deserialize, Serialize};

/// Currently accepted PQ signature algorithms.
///
/// Transactions using algorithms not in this list will be rejected by
/// the validation pipeline.
pub const ALLOWED_ALGORITHMS: &[SignatureType] = &[
    SignatureType::Dilithium3,
    SignatureType::MlDsa65,
    SignatureType::SphincsSha2256f,
];

/// Maximum allowed signature size in bytes.
/// SPHINCS+-SHA2-256f produces ~49856 bytes; we allow some headroom.
pub const MAX_SIGNATURE_BYTES: usize = 51_200;

/// Maximum allowed ML-DSA-65 signature size (3309 bytes + headroom).
pub const MAX_ML_DSA_65_SIG_BYTES: usize = 4_096;

/// Identifies which PQ signature algorithm was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureType {
    /// CRYSTALS-Dilithium3 (pre-FIPS, `pqcrypto-dilithium 0.5`).
    /// Based on the Round 3 submission, NOT the final FIPS 204 ML-DSA-65.
    Dilithium3,
    /// FIPS 204 ML-DSA-65. Primary signing algorithm.
    MlDsa65,
    /// SPHINCS+-SHA2-256f-simple (stateless hash-based, 256-bit PQ security).
    SphincsSha2256f,
}

impl SignatureType {
    pub fn as_u8(&self) -> u8 {
        match self {
            SignatureType::Dilithium3 => 0,
            SignatureType::MlDsa65 => 1,
            SignatureType::SphincsSha2256f => 2,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(SignatureType::Dilithium3),
            1 => Some(SignatureType::MlDsa65),
            2 => Some(SignatureType::SphincsSha2256f),
            _ => None,
        }
    }
}

/// Container for a post-quantum signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PQSignature {
    pub sig_type: SignatureType,
    pub data: Vec<u8>,
}

/// Serde helper for deserializing PQSignature with size validation (F-157).
impl<'de> Deserialize<'de> for PQSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            sig_type: SignatureType,
            data: Vec<u8>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let sig = PQSignature {
            sig_type: raw.sig_type,
            data: raw.data,
        };
        sig.validate_size().map_err(D::Error::custom)?;
        Ok(sig)
    }
}

impl PQSignature {
    pub fn new(sig_type: SignatureType, data: Vec<u8>) -> Self {
        Self { sig_type, data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Encodable for PQSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = alloy_rlp::Header {
            list: true,
            payload_length: self.fields_len(),
        };
        header.encode(out);
        self.sig_type.as_u8().encode(out);
        self.data.as_slice().encode(out);
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

impl alloy_rlp::Decodable for PQSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        // Restrict decoding to the declared payload length to prevent
        // malicious RLP from reading beyond the list boundary.
        let mut payload = buf
            .get(..header.payload_length)
            .unwrap_or_else(|| unreachable!("RLP header payload_length validated by decode"));
        let sig_type_u8 = u8::decode(&mut payload)?;
        let sig_type = SignatureType::from_u8(sig_type_u8)
            .ok_or(alloy_rlp::Error::Custom("unknown signature type"))?;
        let data = alloy_rlp::Header::decode_bytes(&mut payload, false)?.to_vec();
        *buf = buf
            .get(header.payload_length..)
            .unwrap_or_else(|| unreachable!("RLP header payload_length validated by decode"));
        let sig = Self { sig_type, data };
        // F-157: Reject oversized signatures during deserialization.
        sig.validate_size()
            .map_err(|_| alloy_rlp::Error::Custom("signature exceeds size limit"))?;
        Ok(sig)
    }
}

impl PQSignature {
    fn fields_len(&self) -> usize {
        self.sig_type
            .as_u8()
            .length()
            .saturating_add(self.data.as_slice().length())
    }

    /// Validate that the signature size is within acceptable bounds.
    pub fn validate_size(&self) -> Result<(), String> {
        let max = match self.sig_type {
            SignatureType::Dilithium3 | SignatureType::MlDsa65 => MAX_ML_DSA_65_SIG_BYTES,
            SignatureType::SphincsSha2256f => MAX_SIGNATURE_BYTES,
        };
        if self.data.len() > max {
            return Err(format!(
                "signature too large: {} bytes (max {} for {:?})",
                self.data.len(),
                max,
                self.sig_type
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_size_validation() {
        let small = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 3309]);
        assert!(small.validate_size().is_ok());

        let big = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 5000]);
        assert!(big.validate_size().is_err());

        let sphincs = PQSignature::new(SignatureType::SphincsSha2256f, vec![0u8; 49856]);
        assert!(sphincs.validate_size().is_ok());

        let too_big = PQSignature::new(SignatureType::SphincsSha2256f, vec![0u8; 60000]);
        assert!(too_big.validate_size().is_err());
    }

    // ── F-157: RLP/JSON deserialization size bounds ──────────────

    #[test]
    fn rlp_decode_rejects_oversized_dilithium_signature() {
        use alloy_rlp::Decodable;
        // Build an oversized signature manually without going through PQSignature::new
        // (which doesn't enforce size at construction).
        let oversized = PQSignature {
            sig_type: SignatureType::Dilithium3,
            data: vec![0u8; 5000],
        };
        let mut encoded = Vec::new();
        oversized.encode(&mut encoded);

        let result = PQSignature::decode(&mut encoded.as_slice());
        assert!(
            result.is_err(),
            "RLP decode should reject oversized Dilithium sig"
        );
    }

    #[test]
    fn rlp_decode_accepts_valid_size() {
        use alloy_rlp::Decodable;
        let valid = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 3309]);
        let mut encoded = Vec::new();
        valid.encode(&mut encoded);

        let decoded = PQSignature::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, valid);
    }

    #[test]
    fn json_decode_rejects_oversized_signature() {
        // Manually construct JSON with an oversized data field
        let oversized_data: Vec<u8> = vec![0u8; 5000];
        let json = format!(
            r#"{{"sig_type":"Dilithium3","data":{}}}"#,
            serde_json::to_string(&oversized_data).unwrap()
        );
        let result: Result<PQSignature, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "JSON decode should reject oversized Dilithium sig"
        );
    }

    #[test]
    fn json_decode_accepts_valid_size() {
        let valid = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 3309]);
        let json = serde_json::to_string(&valid).unwrap();
        let decoded: PQSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, valid);
    }

    // ── F-170: Algorithm allowlist ──────────────────────────────

    #[test]
    fn allowed_algorithms_contains_expected() {
        assert!(ALLOWED_ALGORITHMS.contains(&SignatureType::Dilithium3));
        assert!(ALLOWED_ALGORITHMS.contains(&SignatureType::SphincsSha2256f));
        assert!(ALLOWED_ALGORITHMS.contains(&SignatureType::MlDsa65));
    }
}
