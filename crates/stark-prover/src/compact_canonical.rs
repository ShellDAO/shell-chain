//! Bounded, lossless certificate availability encoding. Decoding grants no authority.
//! Legacy JSON remains byte-for-byte available; native callers still verify full AIR.
mod slh;
mod witness;
use crate::canonical_batch::{CanonicalSignatureBatchProof, MAX_CANONICAL_SIGNATURE_BATCH};
use ciborium::Value as Cbor;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use shell_primitives::{blake3_hash, ShellHash};
use std::{
    collections::HashMap,
    io::{Cursor, Write},
};

const PAYLOAD: &[u8] = b"\0canonical-proof/cbor/v2/";
const HASH_PAYLOAD: &[u8] = b"\0canonical-proof/cbor/v3/";
const SLH_PROPOSER_PAYLOAD: &[u8] = b"\0canonical-proof/cbor/v5/";
const SLH_FIRST_USE_PROPOSER_PAYLOAD: &[u8] = b"\0canonical-proof/cbor/v6/";
const SLH_PAYLOAD: &[u8] = b"\0canonical-proof/cbor/v4/";
const WITNESS_COMPONENT: &[u8] = b"\0canonical-component/cbor/v2/";
const COMPONENT: &[u8] = b"\0canonical-component/cbor/v1/";
const REF: &str = "$certificate";
const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CERTIFICATES: usize = 2048;
const MAX_TEMPLATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_REFERENCES: usize = 32 * 1024;
const MAX_POOL_JSON: usize = 4 * MAX_BYTES;

struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("compact certificate byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn cbor<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Bounded {
        bytes: Vec::new(),
        limit,
    };
    ciborium::ser::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out.bytes)
}
fn uncbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let mut reader = Cursor::new(bytes);
    let value = ciborium::de::from_reader_with_recursion_limit(&mut reader, MAX_DEPTH)
        .map_err(|e| e.to_string())?;
    if reader.position() != bytes.len() as u64 {
        return Err("trailing compact certificate bytes".into());
    }
    Ok(value)
}
fn byte_field(key: &str) -> bool {
    key == "proof_bytes" || key.ends_with("_proof_bytes")
}
fn depth(n: usize) -> Result<usize, String> {
    n.checked_sub(1)
        .ok_or_else(|| "compact certificate nesting limit".into())
}
fn to_cbor(v: Value, key: &str, remaining: usize) -> Result<Cbor, String> {
    let next = depth(remaining)?;
    Ok(match v {
        Value::Null => Cbor::Null,
        Value::Bool(v) => Cbor::Bool(v),
        Value::String(v) => Cbor::Text(v),
        Value::Number(v) => {
            if let Some(v) = v.as_u64() {
                Cbor::Integer(v.into())
            } else if let Some(v) = v.as_i64() {
                Cbor::Integer(v.into())
            } else {
                return Err("floating point certificate input unsupported".into());
            }
        }
        Value::Array(v) if byte_field(key) => Cbor::Bytes(
            v.into_iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| "invalid proof byte vector".to_string())
                })
                .collect::<Result<_, _>>()?,
        ),
        Value::Array(v) => Cbor::Array(
            v.into_iter()
                .map(|v| to_cbor(v, "", next))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(v) => Cbor::Map(
            v.into_iter()
                .map(|(k, v)| Ok((Cbor::Text(k.clone()), to_cbor(v, &k, next)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}
fn from_cbor(v: Cbor, key: &str, remaining: usize) -> Result<Value, String> {
    let next = depth(remaining)?;
    Ok(match v {
        Cbor::Null => Value::Null,
        Cbor::Bool(v) => Value::Bool(v),
        Cbor::Text(v) => Value::String(v),
        Cbor::Integer(v) => {
            let n: i128 = v.into();
            if let Ok(n) = u64::try_from(n) {
                Value::from(n)
            } else if let Ok(n) = i64::try_from(n) {
                Value::from(n)
            } else {
                return Err("compact integer width limit".into());
            }
        }
        Cbor::Bytes(v) if byte_field(key) => Value::Array(v.into_iter().map(Value::from).collect()),
        Cbor::Array(v) => Value::Array(
            v.into_iter()
                .map(|v| from_cbor(v, "", next))
                .collect::<Result<_, _>>()?,
        ),
        Cbor::Map(v) => {
            let mut map = Map::new();
            for (k, v) in v {
                let Cbor::Text(k) = k else {
                    return Err("compact map key must be text".into());
                };
                let value = from_cbor(v, &k, next)?;
                if map.insert(k, value).is_some() {
                    return Err("duplicate compact map key".into());
                }
            }
            Value::Object(map)
        }
        _ => return Err("unsupported compact certificate value".into()),
    })
}
fn encode_value(v: Value, limit: usize) -> Result<Vec<u8>, String> {
    cbor(&to_cbor(v, "", MAX_DEPTH)?, limit)
}
fn decode_value(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err("compact certificate size limit".into());
    }
    let value = from_cbor(uncbor(bytes)?, "", MAX_DEPTH)?;
    if encode_value(value.clone(), MAX_CERTIFICATE_BYTES)? != bytes {
        return Err("noncanonical compact certificate".into());
    }
    Ok(value)
}
/// A new checkpoint encoding, with no change to old JSON checkpoint readers.
pub fn encode_component<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes = encode_value(
        serde_json::to_value(value).map_err(|e| e.to_string())?,
        MAX_CERTIFICATE_BYTES,
    )?;
    Ok([COMPONENT, bytes.as_slice()].concat())
}
/// Explicit component v2 omits deterministic SHA2 witness words only after
/// checking exact reconstruction. Its decoder still grants no authority.
pub fn encode_slh_component<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes = witness::encode(serde_json::to_value(value).map_err(|e| e.to_string())?)?;
    Ok([WITNESS_COMPONENT, bytes.as_slice()].concat())
}
pub fn decode_component<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if let Some(bytes) = bytes.strip_prefix(WITNESS_COMPONENT) {
        serde_json::from_value(witness::decode(bytes)?).map_err(|e| e.to_string())
    } else if let Some(bytes) = bytes.strip_prefix(COMPONENT) {
        serde_json::from_value(decode_value(bytes)?).map_err(|e| e.to_string())
    } else {
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    }
}

#[derive(Clone)]
struct Bytes(Vec<u8>);
impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Bytes;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded CBOR certificate bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                if v.len() > MAX_CERTIFICATE_BYTES {
                    return Err(E::custom("certificate byte limit"));
                }
                Ok(Bytes(v.to_vec()))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                if v.len() > MAX_CERTIFICATE_BYTES {
                    return Err(E::custom("certificate byte limit"));
                }
                Ok(Bytes(v))
            }
        }
        d.deserialize_byte_buf(Visitor)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    hash: ShellHash,
    data: Bytes,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    format_version: u8,
    proof_version: u8,
    #[serde(deserialize_with = "bounded_transactions")]
    transactions: Vec<Bytes>,
    proposer: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slh_proposer: Option<Bytes>,
    #[serde(deserialize_with = "bounded_certificates")]
    certificates: Vec<Certificate>,
}
fn bounded_vec<'de, D, T, const MAX: usize>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const MAX: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> serde::de::Visitor<'de> for Visitor<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded compact list")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            if seq.size_hint().is_some_and(|n| n > MAX) {
                return Err(serde::de::Error::custom("compact list count limit"));
            }
            let mut result = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while let Some(value) = seq.next_element()? {
                if result.len() == MAX {
                    return Err(serde::de::Error::custom("compact list count limit"));
                }
                result.push(value);
            }
            Ok(result)
        }
    }
    d.deserialize_seq(Visitor::<T, MAX>(std::marker::PhantomData))
}
fn bounded_transactions<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Bytes>, D::Error> {
    bounded_vec::<D, Bytes, MAX_CANONICAL_SIGNATURE_BATCH>(d)
}
fn bounded_certificates<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<Certificate>, D::Error> {
    bounded_vec::<D, Certificate, MAX_CERTIFICATES>(d)
}
fn template(v: &Value) -> Result<Bytes, String> {
    Ok(Bytes(
        crate::production_store::bounded_json(v, MAX_TEMPLATE_BYTES).map_err(|e| e.to_string())?,
    ))
}
fn has_reference(v: &Value) -> bool {
    match v {
        Value::Object(v) => v.contains_key(REF) || v.values().any(has_reference),
        Value::Array(v) => v.iter().any(has_reference),
        _ => false,
    }
}
fn hash_container(v: &Map<String, Value>) -> bool {
    v.len() == 4
        && v.contains_key("version")
        && ["compressions", "message", "output"]
            .iter()
            .all(|k| v.get(*k).is_some_and(Value::is_array))
}
fn compression_group(v: &Map<String, Value>) -> bool {
    v.len() == 1
        && v.get("compression_group")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                !items.is_empty()
                    && items.len() <= 16
                    && items.iter().all(|p| {
                        p.as_object().is_some_and(|p| {
                            p.contains_key("proof_bytes")
                                && p.contains_key("input")
                                && p.contains_key("operations")
                        })
                    })
            })
}
#[derive(Default)]
struct Packer {
    certificates: Vec<Certificate>,
    indexed: HashMap<ShellHash, usize>,
    witnesses: bool,
}
impl Packer {
    fn reference(&mut self, bytes: Vec<u8>) -> Result<Value, String> {
        let hash = blake3_hash(&bytes);
        let index = if let Some(index) = self.indexed.get(&hash) {
            if self.certificates[*index].data.0 != bytes {
                return Err("certificate hash collision".into());
            }
            *index
        } else {
            if self.certificates.len() >= MAX_CERTIFICATES {
                return Err("certificate pool count limit".into());
            }
            let index = self.certificates.len();
            self.certificates.push(Certificate {
                hash,
                data: Bytes(bytes),
            });
            self.indexed.insert(hash, index);
            index
        };
        Ok(serde_json::json!({(REF):index}))
    }
    fn pack(&mut self, v: Value, remaining: usize) -> Result<Value, String> {
        let next = depth(remaining)?;
        match v {
            Value::Object(v) if v.contains_key(REF) => {
                Err("reserved certificate reference field".into())
            }
            Value::Object(v) if v.keys().any(|k| byte_field(k)) => {
                if v.values().any(has_reference) {
                    return Err("reserved nested certificate reference".into());
                }
                self.reference(if self.witnesses {
                    witness::encode(Value::Object(v))?
                } else {
                    encode_value(Value::Object(v), MAX_CERTIFICATE_BYTES)?
                })
            }
            Value::Object(v) => {
                // A bounded complete hash shares one pool slot, retaining every
                // original compression certificate and its exact public inputs.
                // Larger body hashes retain the original per-child framing.
                if hash_container(&v) {
                    if v.values().any(has_reference) {
                        return Err("reserved nested certificate reference".into());
                    }
                    match encode_value(Value::Object(v.clone()), MAX_CERTIFICATE_BYTES) {
                        Ok(bytes) => return self.reference(bytes),
                        Err(error) if error.contains("byte limit") => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(Value::Object(
                    v.into_iter()
                        .map(|(k, v)| Ok((k, self.pack(v, next)?)))
                        .collect::<Result<_, String>>()?,
                ))
            }
            Value::Array(v) => Ok(Value::Array(
                v.into_iter()
                    .map(|v| self.pack(v, next))
                    .collect::<Result<_, _>>()?,
            )),
            v => Ok(v),
        }
    }
}
struct Counter(usize);
impl Write for Counter {
    fn write(&mut self, v: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(v.len())
            .ok_or_else(|| std::io::Error::other("expanded certificate overflow"))?;
        Ok(v.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn json_size(v: &Value) -> Result<usize, String> {
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, v).map_err(|e| e.to_string())?;
    Ok(count.0)
}
struct Unpacker<'a> {
    certificates: &'a [Certificate],
    decoded_sizes: Vec<Option<usize>>,
    uses: Vec<bool>,
    references: usize,
    pool_json: usize,
    hash_containers: bool,
    grouped: bool,
}
impl<'a> Unpacker<'a> {
    fn new(certificates: &'a [Certificate], hash_containers: bool) -> Result<Self, String> {
        if certificates.len() > MAX_CERTIFICATES {
            return Err("certificate pool count limit".into());
        }
        let mut hashes = std::collections::HashSet::new();
        for c in certificates {
            if !hashes.insert(c.hash) || blake3_hash(&c.data.0) != c.hash {
                return Err("duplicate or changed compact certificate".into());
            }
        }
        Ok(Self {
            certificates,
            decoded_sizes: vec![None; certificates.len()],
            uses: vec![false; certificates.len()],
            references: 0,
            pool_json: 0,
            hash_containers,
            grouped: false,
        })
    }
    fn expand(&mut self, v: Value, budget: &mut usize, remaining: usize) -> Result<Value, String> {
        let next = depth(remaining)?;
        match v {
            Value::Object(v) if v.contains_key(REF) => {
                if v.len() != 1 {
                    return Err("malformed compact reference".into());
                }
                let index = v[REF]
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|n| *n < self.certificates.len())
                    .ok_or("missing compact certificate")?;
                self.references += 1;
                if self.references > MAX_REFERENCES {
                    return Err("compact reference count limit".into());
                }
                // Retain only size metadata, never inflated JSON certificate trees.
                // Each recipient gets a freshly decoded untrusted value and full AIR.
                let value = if self.grouped {
                    witness::decode(&self.certificates[index].data.0)?
                } else {
                    decode_value(&self.certificates[index].data.0)?
                };
                if has_reference(&value)
                    || !value.as_object().is_some_and(|v| {
                        v.keys().any(|k| byte_field(k))
                            || self.hash_containers && hash_container(v)
                            || self.grouped && compression_group(v)
                    })
                {
                    return Err("chained or invalid compact certificate".into());
                }
                let bytes = if let Some(bytes) = self.decoded_sizes[index] {
                    bytes
                } else {
                    let bytes = json_size(&value)?;
                    self.pool_json = self
                        .pool_json
                        .checked_add(bytes)
                        .ok_or("compact expansion overflow")?;
                    if self.pool_json > MAX_POOL_JSON {
                        return Err("compact expanded pool byte limit".into());
                    }
                    self.decoded_sizes[index] = Some(bytes);
                    bytes
                };
                *budget = budget
                    .checked_sub(bytes)
                    .ok_or("compact expanded transaction byte limit")?;
                self.uses[index] = true;
                Ok(value)
            }
            Value::Object(v) => Ok(Value::Object(
                v.into_iter()
                    .map(|(k, v)| Ok((k, self.expand(v, budget, next)?)))
                    .collect::<Result<_, String>>()?,
            )),
            Value::Array(v) => Ok(Value::Array(
                v.into_iter()
                    .map(|v| self.expand(v, budget, next))
                    .collect::<Result<_, _>>()?,
            )),
            v => Ok(v),
        }
    }
    fn finish(&self) -> Result<(), String> {
        if self.uses.iter().any(|used| !*used) {
            Err("unreferenced compact certificate".into())
        } else {
            Ok(())
        }
    }
}
/// Compact framing is selected for new large jobs; old profiles keep exact JSON.
pub fn encode_payload(
    proof: &CanonicalSignatureBatchProof,
    limit: usize,
    compact: bool,
) -> Result<Vec<u8>, String> {
    if matches!(proof.version, 4 | 5) {
        if proof.proposer.is_some()
            || proof.slh_transactions.is_some()
            || proof.transactions.len() != 1
        {
            return Err("SLH proposer compact profile/count mismatch".into());
        }
        let mut packer = Packer {
            witnesses: true,
            ..Default::default()
        };
        let transactions = proof
            .transactions
            .iter()
            .map(|p| {
                packer
                    .pack(
                        serde_json::to_value(p).map_err(|e| e.to_string())?,
                        MAX_DEPTH,
                    )
                    .and_then(|v| template(&v))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let proposer = slh::encode_proposer(
            &mut packer,
            proof
                .slh_proposer
                .as_ref()
                .ok_or("SLH proposer proof absent")?,
        )?;
        let (format_version, prefix) = if proof.version == 5 {
            (6, SLH_FIRST_USE_PROPOSER_PAYLOAD)
        } else {
            (5, SLH_PROPOSER_PAYLOAD)
        };
        let frame = Frame {
            format_version,
            proof_version: proof.version,
            transactions,
            proposer: None,
            slh_proposer: Some(proposer),
            certificates: packer.certificates,
        };
        template_bound(&frame)?;
        let body = cbor(
            &frame,
            limit
                .min(MAX_BYTES)
                .checked_sub(prefix.len())
                .ok_or("compact payload byte limit")?,
        )?;
        return Ok([prefix, body.as_slice()].concat());
    }
    if proof.slh_proposer.is_some() {
        return Err("legacy compact profile cannot contain SLH proposer".into());
    }
    if proof.version == 3 {
        if !proof.transactions.is_empty()
            || proof.proposer.is_none()
            || proof.slh_transactions.as_ref().is_none_or(|v| v.len() != 1)
        {
            return Err("compact SLH profile/count mismatch".into());
        }
        let mut packer = Packer {
            witnesses: true,
            ..Default::default()
        };
        let sender = slh::encode(
            &mut packer,
            &proof.slh_transactions.as_ref().ok_or("SLH source absent")?[0],
        )?;
        let proposer = packer.pack(
            serde_json::to_value(proof.proposer.as_ref().ok_or("SLH proposer absent")?)
                .map_err(|e| e.to_string())?,
            MAX_DEPTH,
        )?;
        let frame = Frame {
            slh_proposer: None,
            format_version: 4,
            proof_version: 3,
            transactions: vec![sender],
            proposer: Some(template(&proposer)?),
            certificates: packer.certificates,
        };
        template_bound(&frame)?;
        let body = cbor(
            &frame,
            limit
                .min(MAX_BYTES)
                .checked_sub(SLH_PAYLOAD.len())
                .ok_or("compact payload byte limit")?,
        )?;
        return Ok([SLH_PAYLOAD, body.as_slice()].concat());
    }
    if proof.slh_transactions.is_some() {
        return Err("legacy compact profile cannot contain SLH senders".into());
    }
    let limit = limit.min(MAX_BYTES);
    if !compact {
        return crate::production_store::bounded_json(proof, limit).map_err(|e| e.to_string());
    }
    if proof.transactions.is_empty()
        || proof.transactions.len() > MAX_CANONICAL_SIGNATURE_BATCH
        || !matches!(
            (proof.version, proof.proposer.is_some()),
            (1, false) | (2, true)
        )
    {
        return Err("compact canonical profile/count mismatch".into());
    }
    let mut packer = Packer::default();
    let transactions = proof
        .transactions
        .iter()
        .map(|v| {
            packer
                .pack(
                    serde_json::to_value(v).map_err(|e| e.to_string())?,
                    MAX_DEPTH,
                )
                .and_then(|v| template(&v))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let proposer = proof
        .proposer
        .as_ref()
        .map(|v| {
            packer
                .pack(
                    serde_json::to_value(v).map_err(|e| e.to_string())?,
                    MAX_DEPTH,
                )
                .and_then(|v| template(&v))
        })
        .transpose()?;
    let frame = Frame {
        slh_proposer: None,
        format_version: 3,
        proof_version: proof.version,
        transactions,
        proposer,
        certificates: packer.certificates,
    };
    template_bound(&frame)?;
    let bytes = cbor(
        &frame,
        limit
            .checked_sub(HASH_PAYLOAD.len())
            .ok_or("compact payload byte limit")?,
    )?;
    Ok([HASH_PAYLOAD, bytes.as_slice()].concat())
}
/// Lossless component dictionary for local checkpoint storage. No proof is
/// accepted here; restoration is followed by the producer's full AIR checks.
pub struct CheckpointParts {
    pub template: String,
    pub certificates: Vec<Vec<u8>>,
}
pub fn split_checkpoint(bytes: &[u8]) -> Result<Option<CheckpointParts>, String> {
    let Some(body) = bytes.strip_prefix(COMPONENT) else {
        return Ok(None);
    };
    if body.len() > MAX_CERTIFICATE_BYTES {
        return Err("checkpoint component byte limit".into());
    }
    let value = decode_value(body)?;
    if encode_value(value.clone(), MAX_CERTIFICATE_BYTES)? != body {
        return Err("noncanonical checkpoint component".into());
    }
    let mut packer = Packer::default();
    let packed = packer.pack(value, MAX_DEPTH)?;
    if packer.certificates.len() < 2 {
        return Ok(None);
    }
    Ok(Some(CheckpointParts {
        template: String::from_utf8(template(&packed)?.0).map_err(|e| e.to_string())?,
        certificates: packer.certificates.into_iter().map(|c| c.data.0).collect(),
    }))
}
pub fn restore_checkpoint(template: &str, certificates: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if template.len() > MAX_TEMPLATE_BYTES || certificates.len() > MAX_CERTIFICATES {
        return Err("checkpoint dictionary template/count limit".into());
    }
    let mut total = 0usize;
    for part in certificates {
        total = total
            .checked_add(part.len())
            .ok_or("checkpoint dictionary size overflow")?;
        if part.len() > MAX_CERTIFICATE_BYTES
            || total > MAX_CERTIFICATE_BYTES + MAX_CERTIFICATES * 64
        {
            return Err("checkpoint dictionary certificate byte limit".into());
        }
    }
    let value: Value = serde_json::from_str(template).map_err(|e| e.to_string())?;
    let pool: Vec<_> = certificates
        .iter()
        .map(|data| Certificate {
            hash: blake3_hash(data),
            data: Bytes(data.clone()),
        })
        .collect();
    let mut unpacker = Unpacker::new(&pool, true)?;
    let mut budget = 4 * MAX_CERTIFICATE_BYTES;
    let value = unpacker.expand(value, &mut budget, MAX_DEPTH)?;
    unpacker.finish()?;
    let body = encode_value(value, MAX_CERTIFICATE_BYTES)?;
    Ok([COMPONENT, body.as_slice()].concat())
}

fn template_bound(frame: &Frame) -> Result<(), String> {
    let bytes = frame
        .transactions
        .iter()
        .chain(frame.proposer.iter())
        .chain(frame.slh_proposer.iter())
        .try_fold(0usize, |n, v| {
            n.checked_add(v.0.len())
                .ok_or("compact template size overflow")
        })?;
    if bytes > MAX_TEMPLATE_BYTES {
        return Err("compact template byte limit".into());
    }
    Ok(())
}
/// Availability decoding only: callers must run the complete native-context verifier.
pub fn decode_payload(bytes: &[u8]) -> Result<CanonicalSignatureBatchProof, String> {
    if bytes.len() > MAX_BYTES {
        return Err("canonical payload byte limit".into());
    }
    let (bytes, version) = if let Some(bytes) = bytes.strip_prefix(SLH_FIRST_USE_PROPOSER_PAYLOAD) {
        (bytes, 6)
    } else if let Some(bytes) = bytes.strip_prefix(SLH_PROPOSER_PAYLOAD) {
        (bytes, 5)
    } else if let Some(bytes) = bytes.strip_prefix(SLH_PAYLOAD) {
        (bytes, 4)
    } else if let Some(bytes) = bytes.strip_prefix(HASH_PAYLOAD) {
        (bytes, 3)
    } else if let Some(bytes) = bytes.strip_prefix(PAYLOAD) {
        (bytes, 2)
    } else {
        return serde_json::from_slice(bytes).map_err(|e| e.to_string());
    };
    let frame: Frame = uncbor(bytes)?;
    if frame.format_version != version
        || frame.transactions.is_empty()
        || frame.transactions.len() > MAX_CANONICAL_SIGNATURE_BATCH
        || (!matches!(version, 5 | 6) && frame.slh_proposer.is_some())
        || (if matches!(version, 5 | 6) {
            frame.proof_version != if version == 6 { 5 } else { 4 }
                || frame.transactions.len() != 1
                || frame.proposer.is_some()
                || frame.slh_proposer.is_none()
        } else if version == 4 {
            frame.proof_version != 3 || frame.transactions.len() != 1 || frame.proposer.is_none()
        } else {
            !matches!(
                (frame.proof_version, frame.proposer.is_some()),
                (1, false) | (2, true)
            )
        })
    {
        return Err("compact canonical profile/count mismatch".into());
    }
    template_bound(&frame)?;
    if cbor(&frame, MAX_BYTES)? != bytes {
        return Err("noncanonical compact frame".into());
    }
    let mut unpacker = Unpacker::new(&frame.certificates, version >= 3)?;
    unpacker.grouped = version >= 4;
    let mut slh_transactions = (version == 4).then(Vec::new);
    let mut slh_budget = MAX_POOL_JSON;
    let mut transactions = Vec::with_capacity(frame.transactions.len());
    for bytes in frame.transactions {
        if let Some(slh) = &mut slh_transactions {
            slh.push(slh::decode(&mut unpacker, bytes, &mut slh_budget)?);
        } else {
            if version >= 5 {
                slh_budget = slh_budget
                    .checked_sub(bytes.0.len())
                    .ok_or("SLH proposer sender template expansion limit")?;
            }
            let value: Value = serde_json::from_slice(&bytes.0).map_err(|e| e.to_string())?;
            let mut budget = MAX_BYTES - bytes.0.len();
            let value = unpacker.expand(
                value,
                if version >= 5 {
                    &mut slh_budget
                } else {
                    &mut budget
                },
                MAX_DEPTH,
            )?;
            transactions.push(serde_json::from_value(value).map_err(|e| e.to_string())?);
        }
    }
    let proposer = frame
        .proposer
        .map(|bytes| {
            let value: Value = serde_json::from_slice(&bytes.0).map_err(|e| e.to_string())?;
            let mut budget = MAX_BYTES - bytes.0.len();
            serde_json::from_value(unpacker.expand(
                value,
                if version == 4 {
                    &mut slh_budget
                } else {
                    &mut budget
                },
                MAX_DEPTH,
            )?)
            .map_err(|e| e.to_string())
        })
        .transpose()?;
    let slh_proposer = frame
        .slh_proposer
        .map(|bytes| slh::decode_proposer(&mut unpacker, bytes, &mut slh_budget))
        .transpose()?;
    unpacker.finish()?;
    Ok(CanonicalSignatureBatchProof {
        slh_proposer,
        slh_transactions,
        version: frame.proof_version,
        transactions,
        proposer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn slh_group_certificates_cannot_enter_old_frame_or_chain_references() {
        let group = json!({"compression_group":[{"proof_bytes":[1,2],"input":{},"operations":[]}]});
        let mut packer = Packer::default();
        let reference = packer
            .reference(encode_value(group.clone(), MAX_CERTIFICATE_BYTES).unwrap())
            .unwrap();
        let mut old = Unpacker::new(&packer.certificates, true).unwrap();
        assert!(old
            .expand(reference.clone(), &mut { MAX_BYTES }, MAX_DEPTH)
            .is_err());
        let mut current = Unpacker::new(&packer.certificates, true).unwrap();
        current.grouped = true;
        assert_eq!(
            current
                .expand(reference, &mut { MAX_BYTES }, MAX_DEPTH)
                .unwrap(),
            group
        );
        current.finish().unwrap();
        let mut packer = Packer::default();
        let reference=packer.reference(encode_value(json!({"compression_group":[{"proof_bytes":[1],"input":{},"operations":[],"nested":{"$certificate":0}}]}),MAX_CERTIFICATE_BYTES).unwrap()).unwrap();
        let mut current = Unpacker::new(&packer.certificates, true).unwrap();
        current.grouped = true;
        assert!(current
            .expand(reference, &mut { MAX_BYTES }, MAX_DEPTH)
            .is_err());
    }
    #[test]
    fn checkpoint_dictionary_restores_exact_bytes_and_rejects_missing_or_unused_parts() {
        let value = json!({"version":1,"address_hash":{"proof_bytes":[1,2]},
            "nodes":[{"proof_bytes":[3,4]}, {"proof_bytes":[1,2]}]});
        let original = encode_component(&value).unwrap();
        let parts = split_checkpoint(&original).unwrap().unwrap();
        assert_eq!(parts.certificates.len(), 2);
        assert_eq!(
            restore_checkpoint(&parts.template, &parts.certificates).unwrap(),
            original
        );
        assert!(restore_checkpoint(&parts.template, &parts.certificates[..1]).is_err());
        let mut extra = parts.certificates.clone();
        extra.push(encode_value(json!({"proof_bytes":[7]}), MAX_CERTIFICATE_BYTES).unwrap());
        assert!(restore_checkpoint(&parts.template, &extra).is_err());
        assert!(split_checkpoint(br#"{"version":1}"#).unwrap().is_none());
        assert!(
            split_checkpoint(&encode_component(&json!({"proof_bytes":[1]})).unwrap())
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn bounded_hash_containers_pool_without_losing_compressions_or_legacy_readability() {
        // Codec-only values; successful decoding never grants cryptographic authority.
        let children: Vec<_> = (0..32)
            .map(|i| json!({"version":1,"input":i,"operations":[i,7],"proof_bytes":[i,42]}))
            .collect();
        let value =
            json!({"version":1,"message":[1,2],"output":vec![3;32],"compressions":children});
        let mut current = Packer::default();
        let packed = current.pack(value.clone(), MAX_DEPTH).unwrap();
        assert_eq!(current.certificates.len(), 1);
        assert_eq!(current.pack(value.clone(), MAX_DEPTH).unwrap(), packed);
        let mut old_reader = Unpacker::new(&current.certificates, false).unwrap();
        let mut old_budget = MAX_BYTES;
        assert!(old_reader
            .expand(packed.clone(), &mut old_budget, MAX_DEPTH)
            .is_err());
        let mut reader = Unpacker::new(&current.certificates, true).unwrap();
        let mut budget = MAX_BYTES;
        assert_eq!(
            reader.expand(packed, &mut budget, MAX_DEPTH).unwrap(),
            value
        );
        reader.finish().unwrap();
        let mut legacy = Packer::default();
        let mut template = value.clone();
        for child in template["compressions"].as_array_mut().unwrap() {
            *child = legacy.pack(child.clone(), MAX_DEPTH).unwrap();
        }
        assert_eq!(legacy.certificates.len(), 32);
        let mut reader = Unpacker::new(&legacy.certificates, false).unwrap();
        let mut budget = MAX_BYTES;
        assert_eq!(
            reader.expand(template, &mut budget, MAX_DEPTH).unwrap(),
            value
        );
        reader.finish().unwrap();
        let reserved = json!({"compressions":[{"proof_bytes":[1],"nested":{(REF):0}}],"message":[],"output":[]});
        assert!(Packer::default()
            .pack(reserved, MAX_DEPTH)
            .unwrap_err()
            .contains("reserved"));
    }
    #[test]
    fn oversized_hash_container_keeps_bounded_child_framing() {
        let value = json!({"version":2,"message":[],"output":[],"compressions":[
            {"input":0,"operations":vec![u64::MAX;500_000],"proof_bytes":[1]},
            {"input":1,"operations":vec![u64::MAX;500_000],"proof_bytes":[2]}]});
        let mut packer = Packer::default();
        let template = packer.pack(value.clone(), MAX_DEPTH).unwrap();
        assert!(template.get("compressions").is_some());
        assert_eq!(packer.certificates.len(), 2);
        assert!(packer
            .certificates
            .iter()
            .all(|c| c.data.0.len() <= MAX_CERTIFICATE_BYTES));
        let mut reader = Unpacker::new(&packer.certificates, false).unwrap();
        let mut budget = MAX_BYTES;
        assert_eq!(
            reader.expand(template, &mut budget, MAX_DEPTH).unwrap(),
            value
        );
        reader.finish().unwrap();
    }
    #[test]
    fn template_bytes_and_list_limits_precede_untrusted_tree_expansion() {
        let frames = [
            Frame {
                slh_proposer: None,
                format_version: 2,
                proof_version: 1,
                transactions: (0..17).map(|_| Bytes(b"null".to_vec())).collect(),
                proposer: None,
                certificates: vec![],
            },
            Frame {
                slh_proposer: None,
                format_version: 2,
                proof_version: 1,
                transactions: vec![Bytes(vec![b' '; MAX_TEMPLATE_BYTES + 1])],
                proposer: None,
                certificates: vec![],
            },
        ];
        for (frame, message) in frames
            .into_iter()
            .zip(["count limit", "template byte limit"])
        {
            let bytes = [PAYLOAD, cbor(&frame, MAX_BYTES).unwrap().as_slice()].concat();
            assert!(decode_payload(&bytes).unwrap_err().contains(message));
        }
    }
    #[test]
    fn slh_proposer_frame_relabeling_cannot_hide_or_add_a_mandatory_role() {
        for (prefix, format, proof, small, slh, count) in [
            (SLH_FIRST_USE_PROPOSER_PAYLOAD, 6, 5, false, false, 1),
            (SLH_FIRST_USE_PROPOSER_PAYLOAD, 6, 4, false, true, 1),
            (SLH_FIRST_USE_PROPOSER_PAYLOAD, 6, 5, false, true, 2),
            (SLH_PROPOSER_PAYLOAD, 5, 5, false, true, 1),
            (SLH_PROPOSER_PAYLOAD, 5, 4, false, false, 1),
            (SLH_PROPOSER_PAYLOAD, 5, 4, true, true, 1),
            (SLH_PROPOSER_PAYLOAD, 5, 4, false, true, 2),
            (SLH_PROPOSER_PAYLOAD, 5, 3, false, true, 1),
            (SLH_PAYLOAD, 4, 3, true, true, 1),
            (HASH_PAYLOAD, 3, 2, true, true, 1),
            (PAYLOAD, 2, 2, true, true, 1),
        ] {
            // Deliberately invalid templates must never be expanded when the
            // declared role/count/version is already incompatible.
            let frame = Frame {
                format_version: format,
                proof_version: proof,
                transactions: (0..count).map(|_| Bytes(vec![0xff])).collect(),
                proposer: small.then(|| Bytes(vec![0xff])),
                slh_proposer: slh.then(|| Bytes(vec![0xff])),
                certificates: vec![],
            };
            let bytes = [prefix, cbor(&frame, MAX_BYTES).unwrap().as_slice()].concat();
            assert!(decode_payload(&bytes)
                .unwrap_err()
                .contains("profile/count mismatch"));
        }
    }
    #[test]
    fn component_roundtrip_is_lossless_and_legacy_json_stays_readable() {
        let v = json!({"version":1,"proof_bytes":[0,23,24,255],"nested":{"sponge_proof_bytes":[255,0]},"wide":u64::MAX,"negative":-9,"message":[1,255]});
        let compact = encode_component(&v).unwrap();
        assert_eq!(decode_component::<Value>(&compact).unwrap(), v);
        assert_eq!(
            decode_component::<Value>(&serde_json::to_vec(&v).unwrap()).unwrap(),
            v
        );
        let mut trailing = compact;
        trailing.push(0);
        assert!(decode_component::<Value>(&trailing).is_err());
        assert!(encode_component(&json!({"proof_bytes":[256]})).is_err());
        assert!(decode_value(&[0xa2, 0x61, b'x', 0, 0x61, b'x', 1]).is_err());
    }
    #[test]
    fn exact_pool_inputs_share_without_granting_authority() {
        let v = json!({"version":1,"proof_bytes":vec![42;1024],"input":[1,2,3]});
        let mut p = Packer::default();
        let a = p.pack(v.clone(), MAX_DEPTH).unwrap();
        let b = p.pack(v.clone(), MAX_DEPTH).unwrap();
        assert_eq!(a, b);
        assert_eq!(p.certificates.len(), 1);
        let mut u = Unpacker::new(&p.certificates, false).unwrap();
        let mut budget = MAX_BYTES;
        assert_eq!(u.expand(a, &mut budget, MAX_DEPTH).unwrap(), v);
        u.finish().unwrap();
        let frame = Frame {
            slh_proposer: None,
            format_version: 2,
            proof_version: 2,
            transactions: vec![template(&b).unwrap()],
            proposer: Some(template(&json!({"version":1,"header":{},"signature":{}})).unwrap()),
            certificates: p.certificates,
        };
        let bytes = [PAYLOAD, cbor(&frame, MAX_BYTES).unwrap().as_slice()].concat();
        assert!(
            decode_payload(&bytes).is_err(),
            "framing alone is not a typed proof"
        );
    }
    #[test]
    fn changed_duplicate_missing_chained_and_unused_certificates_refuse() {
        let v = json!({"version":1,"proof_bytes":[1,2,3]});
        let mut p = Packer::default();
        let a = p.pack(v, MAX_DEPTH).unwrap();
        let mut budget = MAX_BYTES;
        assert!(Unpacker::new(&p.certificates, false)
            .unwrap()
            .expand(json!({(REF):99}), &mut budget, MAX_DEPTH)
            .is_err());
        assert!(Unpacker::new(&p.certificates, false)
            .unwrap()
            .finish()
            .is_err());
        let mut u = Unpacker::new(&p.certificates, false).unwrap();
        assert!(u.expand(a.clone(), &mut 0, MAX_DEPTH).is_err());
        p.certificates[0].data.0.push(0);
        assert!(Unpacker::new(&p.certificates, false).is_err());
        p.certificates[0].data.0.pop();
        p.certificates.push(Certificate {
            hash: p.certificates[0].hash,
            data: p.certificates[0].data.clone(),
        });
        assert!(Unpacker::new(&p.certificates, false).is_err());
        let mut p = Packer::default();
        assert!(p.pack(json!({(REF):0}), MAX_DEPTH).is_err());
        let bytes = encode_value(
            json!({"proof_bytes":[],"child":{(REF):0}}),
            MAX_CERTIFICATE_BYTES,
        )
        .unwrap();
        let c = vec![Certificate {
            hash: blake3_hash(&bytes),
            data: Bytes(bytes),
        }];
        assert!(Unpacker::new(&c, false)
            .unwrap()
            .expand(a, &mut budget, MAX_DEPTH)
            .is_err());
    }
}
