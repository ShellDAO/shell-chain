//! Public checkpoint records and exact source/signature graph loading shared
//! by the source and ordered-batch development entries.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shell_core::Transaction;
use shell_crypto::SignatureType;
use shell_stark_prover::{
    mldsa_key::PublicKeyDecodeProof,
    mldsa_matrix::{MatrixPolynomialProof, MatrixProof},
    mldsa_source::TransactionSignatureProof,
    mldsa_verification::{CompletionProof, EquationPipeline, Mldsa65VerificationProof},
};
use std::{
    io::{BufReader, BufWriter, Write},
    path::Path,
};
pub type Error = Box<dyn std::error::Error>;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub version: u8,
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub version: u8,
    pub transaction: Transaction,
    pub sig_type: u8,
    pub public_key_hash: [u8; 32],
}
pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_reader(BufReader::new(
        std::fs::File::open(path)?,
    ))?)
}
fn equation(source: &Path, dir: &Path) -> Result<EquationPipeline, Error> {
    let key: PublicKeyDecodeProof = read(&dir.join("key.json"))?;
    let mut polynomials = Vec::new();
    for row in 0..6 {
        for column in 0..5 {
            polynomials.push(read::<MatrixPolynomialProof>(
                &source.join(format!("a-{row}-{column}.json")),
            )?);
        }
    }
    Ok(EquationPipeline {
        matrix: MatrixProof {
            batches: None,
            version: 1,
            rho: key.decoded.rho.clone(),
            polynomials,
        },
        key,
        signature: read(&dir.join("signature.json"))?,
        challenge: read(&dir.join("challenge.json"))?,
        z_ntt: (0..5)
            .map(|i| read(&dir.join(format!("z-{i}.json"))))
            .collect::<Result<_, _>>()?,
        t1_ntt: (0..6)
            .map(|i| read(&dir.join(format!("t-{i}.json"))))
            .collect::<Result<_, _>>()?,
        c_ntt: read(&dir.join("c-ntt.json"))?,
        equation: read(&dir.join("equation.json"))?,
        inverse: (0..6)
            .map(|i| read(&dir.join(format!("inverse-{i}.json"))))
            .collect::<Result<_, _>>()?,
    })
}
fn completion(dir: &Path) -> Result<CompletionProof, Error> {
    Ok(CompletionProof {
        finish: read(&dir.join("finish.json"))?,
        tr: read(&dir.join("tr.json"))?,
        mu: read(&dir.join("mu.json"))?,
        commitment: read(&dir.join("commitment.json"))?,
    })
}
pub fn write<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut out = BufWriter::new(f);
    serde_json::to_writer(&mut out, value)?;
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(())
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdSource {
    pub version: u8,
    pub transaction_id: [u8; 32],
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntrySource {
    pub version: u8,
    pub msg_hash: [u8; 32],
    pub pk_hash: [u8; 32],
    pub leaf: [u8; 32],
}

/// Load the raw-message signature graph, independently of transaction framing.
pub fn load_signature_proof(
    matrix: &Path,
    eq: &Path,
    sig: &Path,
) -> Result<(Mldsa65VerificationProof, Identity), Error> {
    let id: Identity = read(&matrix.join("identity.json"))?;
    if id.version != 1
        || id.public_key.len() != 1952
        || id.signature.len() != 3309
        || id.message.len() > shell_stark_prover::mldsa_verification::MAX_MESSAGE_BYTES
    {
        return Err("invalid signature identity/shape".into());
    }
    if read::<Identity>(&eq.join("identity.json"))? != id
        || read::<Identity>(&sig.join("identity.json"))? != id
    {
        return Err("source/equation/signature identities differ".into());
    }
    Ok((
        Mldsa65VerificationProof {
            version: 1,
            equation: equation(matrix, eq)?,
            completion: completion(sig)?,
        },
        id,
    ))
}

pub fn load_transaction_proof(
    source: &Path,
    eq: &Path,
    sig: &Path,
) -> Result<(TransactionSignatureProof, Source, Identity), Error> {
    let id: Identity = read(&source.join("identity.json"))?;
    let s: Source = read(&source.join("source.json"))?;
    if id.version != 1
        || id.public_key.len() != 1952
        || id.signature.len() != 3309
        || s.version != 1
        || id.message.len() != 32
        || s.sig_type != SignatureType::MlDsa65.as_u8()
    {
        return Err("invalid source identity/shape/algorithm".into());
    }
    let (signature, verified_id) = load_signature_proof(source, eq, sig)?;
    if verified_id != id {
        return Err("source identity changed while loading".into());
    }
    let p = TransactionSignatureProof {
        version: 1,
        signing_hash: read(&source.join("transaction-hash.json"))?,
        public_key_hash: read(&source.join("public-key-hash.json"))?,
        signature,
    };
    if p.signing_hash.output.as_slice() != id.message {
        return Err("saved signature message differs from the source signing digest".into());
    }
    Ok((p, s, id))
}
