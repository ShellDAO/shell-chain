//! Lossless deterministic witness compression, without proof acceptance.
//! A decoder reconstructs only public statement words; every consumer still
//! verifies the unchanged proof bytes and complete AIR before using outputs.
use super::*;
use crate::sha2_compression::{compression_witness, CompressionInput, Sha2Algorithm};
const MARKER: &str = "$sha2_witness";
fn words(map: &Map<String, Value>) -> Result<(Value, Value), String> {
    let algorithm: Sha2Algorithm = serde_json::from_value(
        map.get("algorithm")
            .cloned()
            .ok_or("missing SHA2 algorithm")?,
    )
    .map_err(|e| e.to_string())?;
    let inputs: Vec<CompressionInput> =
        serde_json::from_value(map.get("inputs").cloned().ok_or("missing SHA2 inputs")?)
            .map_err(|e| e.to_string())?;
    let (operations, carries) = compression_witness(algorithm, &inputs)?;
    Ok((
        serde_json::to_value(operations).map_err(|e| e.to_string())?,
        serde_json::to_value(carries).map_err(|e| e.to_string())?,
    ))
}
fn shrink(value: Value, remaining: usize) -> Result<Value, String> {
    let next = depth(remaining)?;
    Ok(match value {
        Value::Object(mut v) => {
            if v.contains_key(MARKER) {
                return Err("reserved SHA2 witness marker".into());
            }
            let shape = v.len() == 6
                && [
                    "version",
                    "algorithm",
                    "inputs",
                    "operations",
                    "carries",
                    "proof_bytes",
                ]
                .iter()
                .all(|k| v.contains_key(*k));
            if shape {
                if v.get("version").and_then(Value::as_u64) != Some(1) {
                    return Err("unsupported SHA2 witness version".into());
                }
                let (operations, carries) = words(&v)?;
                if v.get("operations") != Some(&operations) || v.get("carries") != Some(&carries) {
                    return Err("noncanonical SHA2 witness cannot be omitted".into());
                }
                v.remove("operations");
                v.remove("carries");
                v.insert(MARKER.into(), Value::from(1));
                Value::Object(v)
            } else {
                Value::Object(
                    v.into_iter()
                        .map(|(k, v)| Ok((k, shrink(v, next)?)))
                        .collect::<Result<_, String>>()?,
                )
            }
        }
        Value::Array(v) => Value::Array(
            v.into_iter()
                .map(|v| shrink(v, next))
                .collect::<Result<_, _>>()?,
        ),
        value => value,
    })
}
fn expand(value: Value, remaining: usize) -> Result<Value, String> {
    let next = depth(remaining)?;
    Ok(match value {
        Value::Object(mut v) if v.contains_key(MARKER) => {
            if v.len() != 5
                || v.get(MARKER).and_then(Value::as_u64) != Some(1)
                || v.get("version").and_then(Value::as_u64) != Some(1)
                || !["version", "algorithm", "inputs", "proof_bytes"]
                    .iter()
                    .all(|k| v.contains_key(*k))
            {
                return Err("invalid compressed SHA2 witness shape/version".into());
            }
            let (operations, carries) = words(&v)?;
            v.remove(MARKER);
            v.insert("operations".into(), operations);
            v.insert("carries".into(), carries);
            Value::Object(v)
        }
        Value::Object(v) => Value::Object(
            v.into_iter()
                .map(|(k, v)| Ok((k, expand(v, next)?)))
                .collect::<Result<_, String>>()?,
        ),
        Value::Array(v) => Value::Array(
            v.into_iter()
                .map(|v| expand(v, next))
                .collect::<Result<_, _>>()?,
        ),
        value => value,
    })
}
pub(super) fn encode(value: Value) -> Result<Vec<u8>, String> {
    // Preserve the old full-component ceiling as well as the smaller wire bound.
    encode_value(value.clone(), MAX_CERTIFICATE_BYTES)?;
    encode_value(shrink(value, MAX_DEPTH)?, MAX_CERTIFICATE_BYTES)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Value, String> {
    let compressed = decode_value(bytes)?;
    let expanded = expand(compressed, MAX_DEPTH)?;
    encode_value(expanded.clone(), MAX_CERTIFICATE_BYTES)?;
    Ok(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2_compression::{
        prove_compression_batch, verify_compression_batch, SHA256_INITIAL_STATE,
    };
    use serde_json::json;
    #[test]
    fn exact_words_restore_but_no_invalid_proof_or_altered_statement_gains_authority() {
        let input = CompressionInput {
            chaining_value: SHA256_INITIAL_STATE,
            block: [0; 16],
        };
        let proof =
            prove_compression_batch(Sha2Algorithm::Sha256, std::slice::from_ref(&input)).unwrap();
        let original = serde_json::to_value(&proof).unwrap();
        let bytes = encode(original.clone()).unwrap();
        assert!(
            bytes.len()
                < encode_value(original.clone(), MAX_CERTIFICATE_BYTES)
                    .unwrap()
                    .len()
        );
        assert_eq!(decode(&bytes).unwrap(), original);
        let mut wrong = original.clone();
        wrong["operations"][0] = json!(7);
        assert!(encode(wrong).is_err());
        let mut compressed = decode_value(&bytes).unwrap();
        compressed["inputs"][0]["block"][0] = json!(1);
        let changed = encode_value(compressed, MAX_CERTIFICATE_BYTES).unwrap();
        let restored: crate::sha2_compression::Sha2CompressionProof =
            serde_json::from_value(decode(&changed).unwrap()).unwrap();
        assert!(verify_compression_batch(&restored, Sha2Algorithm::Sha256, &[input]).is_err());
        assert!(
            verify_compression_batch(&restored, Sha2Algorithm::Sha256, &restored.inputs).is_err()
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
}
