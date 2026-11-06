use crate::source::{load_transaction_proof, read, EntrySource, Error, IdSource, Identity};
use serde::Deserialize;
use shell_core::SignedTransaction;
use shell_stark_prover::{
    mldsa_source::{
        verify_signature_entry, DerivedSenderSignatureProof, IdentifiedSenderSignatureProof,
        SignatureEntryProof, VerifiedSignatureEntry,
    },
    SigBatchEntry,
};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphPaths {
    pub version: u8,
    pub source: PathBuf,
    pub equation: PathBuf,
    pub signature: PathBuf,
    pub sender: PathBuf,
    pub id: PathBuf,
    pub entry: PathBuf,
    pub rejection: PathBuf,
}
pub fn paths(path: &Path) -> Result<GraphPaths, Error> {
    if path.is_dir() {
        return Ok(GraphPaths {
            version: 1,
            source: path.join("source"),
            equation: path.join("equation"),
            signature: path.join("signature"),
            sender: path.join("sender"),
            id: path.join("id"),
            entry: path.join("entry"),
            rejection: path.join("rejection"),
        });
    }
    let mut p: GraphPaths = read(path)?;
    if p.version != 1 {
        return Err("invalid graph path manifest version".into());
    }
    let base = path.parent().ok_or("missing manifest parent")?;
    for field in [
        &mut p.source,
        &mut p.equation,
        &mut p.signature,
        &mut p.sender,
        &mut p.id,
        &mut p.entry,
        &mut p.rejection,
    ] {
        *field = base.join(&*field);
    }
    Ok(p)
}
pub struct LoadedEntry {
    pub proof: SignatureEntryProof,
    pub expected: SignedTransaction,
    pub key_hash: [u8; 32],
    pub id: [u8; 32],
    pub entry: SigBatchEntry,
    pub leaf: [u8; 32],
}
impl LoadedEntry {
    pub fn verify(&self) -> Result<VerifiedSignatureEntry, String> {
        verify_signature_entry(
            &self.proof,
            &self.expected,
            &self.key_hash,
            &self.id,
            &self.entry,
            &self.leaf,
        )
    }
}
pub fn load(path: &Path) -> Result<(LoadedEntry, Identity, GraphPaths), Error> {
    let p = paths(path)?;
    let (transaction, s, identity) = load_transaction_proof(&p.source, &p.equation, &p.signature)?;
    let expected = read(&p.sender.join("sender.json"))?;
    let id: IdSource = read(&p.id.join("id-source.json"))?;
    let entry: EntrySource = read(&p.entry.join("entry-source.json"))?;
    if id.version != 1 || entry.version != 1 {
        return Err("invalid expected ID/entry version".into());
    }
    Ok((
        LoadedEntry {
            proof: SignatureEntryProof {
                version: 1,
                leaf: read(&p.entry.join("entry-leaf.json"))?,
                identified: IdentifiedSenderSignatureProof {
                    version: 1,
                    transaction_id: read(&p.id.join("id-hash.json"))?,
                    sender: DerivedSenderSignatureProof {
                        version: 1,
                        sender_address: read(&p.sender.join("sender-address.json"))?,
                        transaction,
                    },
                },
            },
            expected,
            key_hash: s.public_key_hash,
            id: id.transaction_id,
            entry: SigBatchEntry {
                msg_hash: entry.msg_hash,
                pk_hash: entry.pk_hash,
            },
            leaf: entry.leaf,
        },
        identity,
        p,
    ))
}
