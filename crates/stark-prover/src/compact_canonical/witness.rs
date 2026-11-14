//! Lossless deterministic witness compression, without proof acceptance.
//! A decoder reconstructs only public statement words; every consumer still
//! verifies the unchanged proof bytes and complete AIR before using outputs.
use super::*;
use crate::sha2_compression::{
    compression_witness, compression_witness_profile, CompressionInput, Sha2Algorithm,
    Sha2CompressionProof,
};
use std::borrow::Cow;
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
    let version = map
        .get("version")
        .and_then(Value::as_u64)
        .filter(|v| matches!(v, 1 | 2))
        .ok_or("unsupported SHA2 witness version")? as u8;
    let (operations, carries) = if version == 1 {
        compression_witness(algorithm, &inputs)?
    } else {
        compression_witness_profile(version, algorithm, &inputs)?
    };
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
                if !matches!(v.get("version").and_then(Value::as_u64), Some(1 | 2)) {
                    return Err("unsupported SHA2 witness version".into());
                }
                let (operations, carries) = words(&v)?;
                let deferred = v["version"] == 2
                    && v["operations"].as_array().is_some_and(Vec::is_empty)
                    && v["carries"].as_array().is_some_and(Vec::is_empty);
                if deferred {
                    let mut full = v.clone();
                    full.insert("operations".into(), operations);
                    full.insert("carries".into(), carries);
                    encode_value(Value::Object(full), MAX_CERTIFICATE_BYTES)?;
                } else if v.get("operations") != Some(&operations)
                    || v.get("carries") != Some(&carries)
                {
                    return Err("noncanonical SHA2 witness cannot be omitted".into());
                }
                v.remove("operations");
                v.remove("carries");
                v.insert(MARKER.into(), v["version"].clone());
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
                || !matches!(v.get(MARKER).and_then(Value::as_u64), Some(1 | 2))
                || v.get(MARKER) != v.get("version")
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

/// Frame11 retains deterministic wide public words on demand, rather than in
/// every layer simultaneously. Check the full component ceiling first. Only a
/// standalone wide certificate qualifies; nested containers use the old path.
pub(super) fn decode_deferred_wide(bytes: &[u8]) -> Result<Value, String> {
    let compressed = decode_value(bytes)?;
    let deferred = compressed.as_object().is_some_and(|map| {
        map.get(MARKER) == Some(&Value::from(2)) && map.get("version") == Some(&Value::from(2))
    });
    let mut value = expand(compressed, MAX_DEPTH)?;
    encode_value(value.clone(), MAX_CERTIFICATE_BYTES)?;
    if deferred {
        let map = value.as_object_mut().ok_or("missing wide witness object")?;
        map.insert("operations".into(), Value::Array(Vec::new()));
        map.insert("carries".into(), Value::Array(Vec::new()));
    } else if value.as_object().is_some_and(|map| {
        map.len() == 6
            && map.get("version") == Some(&Value::from(2))
            && map.contains_key("proof_bytes")
            && map.contains_key("algorithm")
            && map.contains_key("inputs")
            && (map
                .get("operations")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
                || map
                    .get("carries")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty))
    }) {
        return Err("unmarked deferred wide witness".into());
    }
    Ok(value)
}

/// Availability reconstruction only. The strict compression verifier still
/// receives and verifies the complete original statement before any output is
/// consumed. No proof byte, input, transcript domain or security option changes.
pub(crate) fn materialize_wide(
    proof: &Sha2CompressionProof,
) -> Result<Cow<'_, Sha2CompressionProof>, String> {
    if proof.version != 2 || proof.algorithm != Sha2Algorithm::Sha256 {
        return Err("invalid deferred wide witness profile".into());
    }
    match (proof.operations.is_empty(), proof.carries.is_empty()) {
        (false, false) => Ok(Cow::Borrowed(proof)),
        (true, true) => {
            let (operations, carries) =
                compression_witness_profile(2, proof.algorithm, &proof.inputs)?;
            let mut full = proof.clone();
            full.operations = operations;
            full.carries = carries;
            encode_value(
                serde_json::to_value(&full).map_err(|e| e.to_string())?,
                MAX_CERTIFICATE_BYTES,
            )?;
            Ok(Cow::Owned(full))
        }
        _ => Err("partially omitted wide witness".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2_compression::{
        prove_compression_batch, verify_compression_batch, SHA256_INITIAL_STATE,
    };
    use serde_json::json;
    #[test]
    fn deferred_wide_words_preserve_wire_and_require_the_original_full_air() {
        use crate::sha2_compression::{
            prove_wide_sha256_batch, verify_wide_sha256_batch, Sha2CompressionProof,
        };
        let input = CompressionInput {
            chaining_value: SHA256_INITIAL_STATE,
            block: [0; 16],
        };
        let expected = [input];
        let proof = prove_wide_sha256_batch(&expected).unwrap();
        let original = serde_json::to_value(&proof).unwrap();
        let bytes = encode(original.clone()).unwrap();
        let deferred = decode_deferred_wide(&bytes).unwrap();
        assert!(deferred["operations"].as_array().unwrap().is_empty());
        assert!(deferred["carries"].as_array().unwrap().is_empty());
        assert_eq!(encode(deferred.clone()).unwrap(), bytes);
        assert_eq!(decode(&bytes).unwrap(), original);
        assert_eq!(
            decode_deferred_wide(&encode_value(original.clone(), MAX_CERTIFICATE_BYTES).unwrap())
                .unwrap(),
            original
        );
        assert!(decode_deferred_wide(
            &encode_value(deferred.clone(), MAX_CERTIFICATE_BYTES).unwrap()
        )
        .is_err());
        let lazy: Sha2CompressionProof = serde_json::from_value(deferred).unwrap();
        assert!(verify_wide_sha256_batch(&lazy, &expected).is_err());
        let full = materialize_wide(&lazy).unwrap();
        assert_eq!(full.operations, proof.operations);
        assert_eq!(full.carries, proof.carries);
        assert_eq!(full.proof_bytes, proof.proof_bytes);
        assert_eq!(
            verify_wide_sha256_batch(&full, &expected).unwrap(),
            verify_wide_sha256_batch(&proof, &expected).unwrap()
        );
        let mut bad = lazy.clone();
        bad.proof_bytes[0] ^= 1;
        assert!(verify_wide_sha256_batch(&materialize_wide(&bad).unwrap(), &expected).is_err());
        bad = lazy.clone();
        bad.inputs[0].block[0] ^= 1;
        assert!(verify_wide_sha256_batch(&materialize_wide(&bad).unwrap(), &bad.inputs).is_err());
        bad = lazy.clone();
        bad.carries.push(0);
        assert!(materialize_wide(&bad).is_err());
        assert!(encode(serde_json::to_value(&bad).unwrap()).is_err());
        bad = lazy;
        bad.version = 1;
        assert!(materialize_wide(&bad).is_err());
        let nested = json!({"compression_group":[original]});
        assert_eq!(
            decode_deferred_wide(&encode(nested.clone()).unwrap()).unwrap(),
            nested
        );

        let mut packer = Packer {
            witnesses: true,
            ..Default::default()
        };
        let reference = packer
            .pack(serde_json::to_value(&proof).unwrap(), MAX_DEPTH)
            .unwrap();
        let size =
            json_size(&decode_deferred_wide(&packer.certificates[0].data.0).unwrap()).unwrap();
        let mut old = Unpacker::new(&packer.certificates, true).unwrap();
        old.grouped = true;
        let mut old_budget = size;
        assert!(old
            .expand(reference.clone(), &mut old_budget, MAX_DEPTH)
            .is_err());
        let mut reader = Unpacker::new(&packer.certificates, true).unwrap();
        reader.grouped = true;
        reader.deferred_wide = true;
        let mut budget = size;
        reader
            .expand(reference.clone(), &mut budget, MAX_DEPTH)
            .unwrap();
        assert_eq!(budget, 0);
        assert_eq!(reader.pool_json, size);
        assert!(reader.expand(reference, &mut budget, MAX_DEPTH).is_err());
        reader.finish().unwrap();
    }
    #[test]
    fn wide_witness_marker_is_lossless_and_cannot_change_the_proof_domain() {
        let input = CompressionInput {
            chaining_value: SHA256_INITIAL_STATE,
            block: [0; 16],
        };
        let proof =
            crate::sha2_compression::prove_wide_sha256_batch(std::slice::from_ref(&input)).unwrap();
        let original = serde_json::to_value(&proof).unwrap();
        let bytes = encode(original.clone()).unwrap();
        assert_eq!(decode(&bytes).unwrap(), original);
        let mut compressed = decode_value(&bytes).unwrap();
        assert_eq!(compressed[MARKER], json!(2));
        compressed[MARKER] = json!(1);
        assert!(decode(&encode_value(compressed.clone(), MAX_CERTIFICATE_BYTES).unwrap()).is_err());
        compressed["version"] = json!(1);
        let relabeled: crate::sha2_compression::Sha2CompressionProof = serde_json::from_value(
            decode(&encode_value(compressed, MAX_CERTIFICATE_BYTES).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(verify_compression_batch(&relabeled, Sha2Algorithm::Sha256, &[input]).is_err());
    }
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
