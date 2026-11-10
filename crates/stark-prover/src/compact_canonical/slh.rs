//! Stream the large sender graph through bounded certificate values. In particular,
//! never expand every proof byte into one monolithic JSON number tree.
use super::*;
use crate::{
    blake3_hash::{Blake3HashProof, CompressionProof},
    body_membership::{LargeTransactionEnvelopeProof, TransactionBodyProof},
    canonical_slh::CanonicalSlhTransactionProof,
    slh_fors::{SlhForsInputs, SlhForsProof},
    slh_signature::SlhSignatureManifest,
    slh_xmss::{SlhXmssInputs, SlhXmssProof},
};
use shell_core::BodyMembershipPath;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parts {
    version: u8,
    account: Value,
    public_key_hash: Value,
    tagged_key: Option<Value>,
    envelope: Envelope,
    leaf: Value,
    manifest: SlhSignatureManifest,
    fors: Fors,
    #[serde(deserialize_with = "layers")]
    layers: Vec<Xmss>,
}
fn layers<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Xmss>, D::Error> {
    bounded_vec::<D, Xmss, 17>(d)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    body: Body,
    signing_hash: Value,
    transaction_id: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    version: u8,
    path: BodyMembershipPath,
    leaf: Hash,
    parents: Vec<Value>,
    root: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hash {
    version: u8,
    message: Vec<u8>,
    output: [u8; 32],
    groups: Vec<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fors {
    version: u8,
    inputs: SlhForsInputs,
    hashes: Vec<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Xmss {
    version: u8,
    inputs: SlhXmssInputs,
    prefix: Value,
    chains: Vec<Value>,
    wots_public_key: Value,
    authentication: Vec<Value>,
}
fn pack<T: Serialize>(packer: &mut Packer, value: &T) -> Result<Value, String> {
    packer.pack(
        serde_json::to_value(value).map_err(|e| e.to_string())?,
        MAX_DEPTH,
    )
}
fn pack_many<T: Serialize>(packer: &mut Packer, values: &[T]) -> Result<Vec<Value>, String> {
    values.iter().map(|v| pack(packer, v)).collect()
}
pub(super) fn encode(
    packer: &mut Packer,
    proof: &CanonicalSlhTransactionProof,
) -> Result<Bytes, String> {
    let body = &proof.envelope.body;
    let groups = body
        .leaf
        .compressions
        .chunks(16)
        .map(|group| {
            packer.reference(encode_value(
                serde_json::json!({"compression_group":group}),
                MAX_CERTIFICATE_BYTES,
            )?)
        })
        .collect::<Result<_, String>>()?;
    let body = Body {
        version: body.version,
        path: body.path.clone(),
        leaf: Hash {
            version: body.leaf.version,
            message: body.leaf.message.clone(),
            output: body.leaf.output,
            groups,
        },
        parents: pack_many(packer, &body.parents)?,
        root: pack(packer, &body.root)?,
    };
    let mut layers = Vec::new();
    for layer in &proof.layers {
        layers.push(Xmss {
            version: layer.version,
            inputs: layer.inputs.clone(),
            prefix: pack(packer, &layer.prefix)?,
            chains: pack_many(packer, &layer.chains)?,
            wots_public_key: pack(packer, &layer.wots_public_key)?,
            authentication: pack_many(packer, &layer.authentication)?,
        });
    }
    let parts = Parts {
        version: proof.version,
        account: pack(packer, &proof.account)?,
        public_key_hash: pack(packer, &proof.public_key_hash)?,
        tagged_key: proof
            .tagged_key
            .as_ref()
            .map(|v| pack(packer, v))
            .transpose()?,
        envelope: Envelope {
            version: proof.envelope.version,
            body,
            signing_hash: pack(packer, &proof.envelope.signing_hash)?,
            transaction_id: pack(packer, &proof.envelope.transaction_id)?,
        },
        leaf: pack(packer, &proof.leaf)?,
        manifest: proof.manifest.clone(),
        fors: Fors {
            version: proof.fors.version,
            inputs: proof.fors.inputs.clone(),
            hashes: pack_many(packer, &proof.fors.hashes)?,
        },
        layers,
    };
    template(&serde_json::to_value(parts).map_err(|e| e.to_string())?)
}
fn expand<T: DeserializeOwned>(
    unpacker: &mut Unpacker<'_>,
    value: Value,
    budget: &mut usize,
) -> Result<T, String> {
    serde_json::from_value(unpacker.expand(value, budget, MAX_DEPTH)?).map_err(|e| e.to_string())
}
fn many<T: DeserializeOwned>(
    unpacker: &mut Unpacker<'_>,
    values: Vec<Value>,
    budget: &mut usize,
) -> Result<Vec<T>, String> {
    values
        .into_iter()
        .map(|v| expand(unpacker, v, budget))
        .collect()
}
pub(super) fn decode(
    unpacker: &mut Unpacker<'_>,
    bytes: Bytes,
    budget: &mut usize,
) -> Result<CanonicalSlhTransactionProof, String> {
    *budget = budget
        .checked_sub(bytes.0.len())
        .ok_or("SLH template expansion limit")?;
    let p: Parts = serde_json::from_slice(&bytes.0).map_err(|e| e.to_string())?;
    if p.layers.len() != 17
        || p.fors.hashes.len() != crate::slh_fors::SLH_FORS_HASHES
        || p.envelope.body.leaf.message.len() > crate::blake3_hash::MAX_LARGE_BODY_HASH_BYTES
        || p.envelope.body.leaf.groups.is_empty()
        || p.envelope.body.leaf.groups.len() > 69
    {
        return Err("compact SLH graph resource/profile mismatch".into());
    }
    let mut compressions = Vec::new();
    let count = p.envelope.body.leaf.groups.len();
    for (at, group) in p.envelope.body.leaf.groups.into_iter().enumerate() {
        if !group
            .as_object()
            .is_some_and(|v| v.len() == 1 && v.contains_key(REF))
        {
            return Err("SLH group must reference a certificate".into());
        }
        let mut value = unpacker.expand(group, budget, MAX_DEPTH)?;
        let values = value
            .as_object_mut()
            .filter(|v| v.len() == 1)
            .and_then(|v| v.remove("compression_group"))
            .ok_or("invalid SLH compression group")?;
        let group: Vec<CompressionProof> =
            serde_json::from_value(values).map_err(|e| e.to_string())?;
        if group.is_empty() || group.len() > 16 || (at + 1 != count && group.len() != 16) {
            return Err("noncanonical SLH compression group size".into());
        }
        compressions.extend(group);
    }
    let hash = Blake3HashProof {
        version: p.envelope.body.leaf.version,
        message: p.envelope.body.leaf.message,
        output: p.envelope.body.leaf.output,
        compressions,
    };
    let body = TransactionBodyProof {
        version: p.envelope.body.version,
        path: p.envelope.body.path,
        leaf: hash,
        parents: many(unpacker, p.envelope.body.parents, budget)?,
        root: expand(unpacker, p.envelope.body.root, budget)?,
    };
    let mut layers = Vec::new();
    for layer in p.layers {
        if layer.chains.len() > 64 || layer.authentication.len() != 4 {
            return Err("compact SLH layer resource/profile mismatch".into());
        }
        layers.push(SlhXmssProof {
            version: layer.version,
            inputs: layer.inputs,
            prefix: expand(unpacker, layer.prefix, budget)?,
            chains: many(unpacker, layer.chains, budget)?,
            wots_public_key: expand(unpacker, layer.wots_public_key, budget)?,
            authentication: many(unpacker, layer.authentication, budget)?,
        });
    }
    Ok(CanonicalSlhTransactionProof {
        version: p.version,
        account: expand(unpacker, p.account, budget)?,
        public_key_hash: expand(unpacker, p.public_key_hash, budget)?,
        tagged_key: p
            .tagged_key
            .map(|v| expand(unpacker, v, budget))
            .transpose()?,
        envelope: LargeTransactionEnvelopeProof {
            version: p.envelope.version,
            body,
            signing_hash: expand(unpacker, p.envelope.signing_hash, budget)?,
            transaction_id: expand(unpacker, p.envelope.transaction_id, budget)?,
        },
        leaf: expand(unpacker, p.leaf, budget)?,
        manifest: p.manifest,
        fors: SlhForsProof {
            version: p.fors.version,
            inputs: p.fors.inputs,
            hashes: many(unpacker, p.fors.hashes, budget)?,
        },
        layers,
    })
}
