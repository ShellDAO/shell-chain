//! Public native account-MPT witnesses with every Keccak hash proved.
//!
//! An independently expected state root authenticates account membership or
//! absence. It does not authenticate the separate public-key KV registry, root
//! canonicality, account authorization, execution, or a custom validator.

use alloy_rlp::{Decodable, Encodable, Header};
use serde::{Deserialize, Serialize};
use shell_core::Account;

use crate::{
    mldsa_source::{verify_authenticated_sig_batch, VerifiedSignatureEntry},
    shake_sponge::{prove_keccak256, verify_keccak256, ShakeProof, MAX_SHAKE_MESSAGE_BYTES},
    SigBatchProof,
};

pub const MAX_ACCOUNT_PROOF_NODES: usize = 65;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStateProof {
    pub version: u8,
    pub address_hash: ShakeProof,
    /// Root first, followed by exactly the referenced hashed nodes on the path.
    /// Embedded nodes are consumed from their parent, not additional witnesses.
    pub nodes: Vec<ShakeProof>,
}

/// Immutable verified state snapshot; not a declaration of account authority.
#[derive(Clone, Debug)]
pub struct VerifiedAccountState {
    root: [u8; 32],
    address: [u8; 32],
    account: Option<Account>,
}
impl VerifiedAccountState {
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }
    pub fn address(&self) -> &[u8; 32] {
        &self.address
    }
    pub fn account(&self) -> Option<&Account> {
        self.account.as_ref()
    }
}

#[derive(Clone, Copy)]
struct Item<'a> {
    raw: &'a [u8],
    payload: &'a [u8],
    list: bool,
}
fn take<'a>(rest: &mut &'a [u8]) -> Result<Item<'a>, String> {
    let raw = *rest;
    let header = Header::decode(rest).map_err(|e| format!("invalid account trie RLP: {e}"))?;
    let prefix = raw.len() - rest.len();
    let payload = &rest[..header.payload_length];
    *rest = &rest[header.payload_length..];
    Ok(Item {
        raw: &raw[..prefix + header.payload_length],
        payload,
        list: header.list,
    })
}
fn compact(bytes: &[u8]) -> Result<(bool, Vec<u8>), String> {
    let first = *bytes.first().ok_or("empty account trie compact path")?;
    let flag = first >> 4;
    if flag > 3 || (flag & 1 == 0 && first & 15 != 0) {
        return Err("invalid account trie compact path flags".into());
    }
    let mut path = Vec::new();
    if flag & 1 != 0 {
        path.push(first & 15);
    }
    for &byte in &bytes[1..] {
        path.extend([byte >> 4, byte & 15]);
    }
    if path.len() > 64 || (flag < 2 && path.is_empty()) {
        return Err("invalid account trie compact path length".into());
    }
    Ok((flag >= 2, path))
}
fn account_bytes(bytes: &[u8]) -> Result<(), String> {
    let mut rest = bytes;
    let account = Account::decode(&mut rest).map_err(|e| format!("invalid trie account: {e}"))?;
    let mut encoded = Vec::new();
    account.encode(&mut encoded);
    if !rest.is_empty() || encoded != bytes {
        return Err("noncanonical trie account encoding".into());
    }
    Ok(())
}
fn child(item: Item<'_>, depth: usize) -> Result<(), String> {
    if item.list {
        if item.raw.len() >= 32 {
            return Err("oversized inline account trie child".into());
        }
        node(item.raw, depth + 1)?;
    } else if !item.payload.is_empty() && item.payload.len() != 32 {
        return Err("invalid account trie child reference width".into());
    }
    Ok(())
}
fn node(bytes: &[u8], depth: usize) -> Result<Vec<Item<'_>>, String> {
    if depth > 64 || bytes.len() > MAX_SHAKE_MESSAGE_BYTES {
        return Err("account trie node resource bound exceeded".into());
    }
    let mut rest = bytes;
    let outer = take(&mut rest)?;
    if !rest.is_empty() {
        return Err("trailing account trie RLP bytes".into());
    }
    if !outer.list {
        if outer.payload.is_empty() {
            return Ok(Vec::new());
        }
        return Err("account trie node must be a list or empty root".into());
    }
    let mut rest = outer.payload;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        if fields.len() == 17 {
            return Err("too many account trie node fields".into());
        }
        fields.push(take(&mut rest)?);
    }
    match fields.len() {
        2 => {
            if fields[0].list {
                return Err("account trie path must be bytes".into());
            }
            let (leaf, _) = compact(fields[0].payload)?;
            if leaf {
                if fields[1].list || fields[1].payload.is_empty() {
                    return Err("invalid account trie leaf value".into());
                }
                account_bytes(fields[1].payload)?;
            } else {
                child(fields[1], depth)?;
                if !fields[1].list && fields[1].payload.is_empty() {
                    return Err("empty account trie extension child".into());
                }
            }
        }
        17 => {
            for &field in &fields[..16] {
                child(field, depth)?;
            }
            if fields[16].list {
                return Err("account trie branch value must be bytes".into());
            }
            if !fields[16].payload.is_empty() {
                account_bytes(fields[16].payload)?;
            }
        }
        _ => return Err("invalid account trie node arity".into()),
    }
    Ok(fields)
}

/// Prove existing native `get_proof` nodes. An empty native trie has no nodes;
/// its canonical empty RLP root is explicitly proved instead of assumed.
pub fn prove_account_state(
    address: &[u8; 32],
    nodes: &[Vec<u8>],
) -> Result<AccountStateProof, String> {
    if nodes.len() > MAX_ACCOUNT_PROOF_NODES {
        return Err("account proof node resource bound exceeded".into());
    }
    for bytes in nodes {
        node(bytes, 0)?;
    }
    let raw = if nodes.is_empty() {
        vec![vec![0x80]]
    } else {
        nodes.to_vec()
    };
    Ok(AccountStateProof {
        version: 1,
        address_hash: prove_keccak256(address)?,
        nodes: raw
            .iter()
            .map(|bytes| prove_keccak256(bytes))
            .collect::<Result<_, _>>()?,
    })
}

/// Verify exact root/address/account and complete, canonical path coverage.
/// Every hash relation is a Keccak AIR proof; RLP and path routing are public
/// deterministic checks. No native hash or native trie verifier is called.
pub fn verify_account_state(
    proof: &AccountStateProof,
    expected_root: &[u8; 32],
    expected_address: &[u8; 32],
    expected_account: Option<&Account>,
) -> Result<VerifiedAccountState, String> {
    if proof.version != 1
        || proof.nodes.is_empty()
        || proof.nodes.len() > MAX_ACCOUNT_PROOF_NODES
        || proof
            .nodes
            .iter()
            .any(|n| n.message.len() > MAX_SHAKE_MESSAGE_BYTES)
    {
        return Err("invalid account state proof version, coverage or resource bound".into());
    }
    let key: [u8; 32] = proof
        .address_hash
        .output
        .as_slice()
        .try_into()
        .map_err(|_| "invalid account address hash width")?;
    verify_keccak256(&proof.address_hash, expected_address, &key)
        .map_err(|e| format!("account address hash: {e}"))?;
    let path: Vec<_> = key.iter().flat_map(|b| [b >> 4, b & 15]).collect();
    let mut expected_value = Vec::new();
    if let Some(account) = expected_account {
        account.encode(&mut expected_value);
    }
    let mut pointer = expected_root.to_vec();
    let mut inline = false;
    let mut consumed = 0;
    let mut offset = 0;
    for _ in 0..=64 {
        let bytes = if inline {
            pointer.clone()
        } else {
            let p = proof
                .nodes
                .get(consumed)
                .ok_or("missing account trie node")?;
            let hash = pointer
                .as_slice()
                .try_into()
                .map_err(|_| "invalid account trie hash width")?;
            verify_keccak256(p, &p.message, hash)
                .map_err(|e| format!("account trie node {consumed}: {e}"))?;
            if consumed > 0 && p.message.len() < 32 {
                return Err("noncanonical hashed short account trie child".into());
            }
            consumed += 1;
            p.message.clone()
        };
        let fields = node(&bytes, 0)?;
        let (value, next) = match fields.len() {
            0 => {
                if consumed != 1 || inline || offset != 0 {
                    return Err("empty account trie node below root".into());
                }
                (Some(None), None)
            }
            2 => {
                let (leaf, part) = compact(fields[0].payload)?;
                if offset + part.len() > 64 || (leaf && offset + part.len() != 64) {
                    return Err("account trie path is not a full32byte key".into());
                }
                if path[offset..offset + part.len()] != part {
                    (Some(None), None)
                } else {
                    offset += part.len();
                    if leaf {
                        (Some(Some(fields[1].payload)), None)
                    } else {
                        (None, Some(fields[1]))
                    }
                }
            }
            17 => {
                if offset == 64 {
                    let value = fields[16].payload;
                    (Some((!value.is_empty()).then_some(value)), None)
                } else {
                    let next = fields[path[offset] as usize];
                    offset += 1;
                    if !next.list && next.payload.is_empty() {
                        (Some(None), None)
                    } else {
                        (None, Some(next))
                    }
                }
            }
            _ => unreachable!("node arity checked"),
        };
        if let Some(value) = value {
            if consumed != proof.nodes.len()
                || value != expected_account.map(|_| expected_value.as_slice())
            {
                return Err("account state value or exact node coverage mismatch".into());
            }
            return Ok(VerifiedAccountState {
                root: *expected_root,
                address: *expected_address,
                account: expected_account.cloned(),
            });
        }
        let next = next.ok_or("missing account trie child")?;
        inline = next.list;
        pointer = if inline { next.raw } else { next.payload }.to_vec();
    }
    Err("account trie path resource bound exceeded".into())
}

/// Join actual fully verified signature snapshots/native batch with account
/// witnesses for those same senders at one independently expected root. The
/// returned account records do not establish registry state or authorization.
pub fn verify_account_bound_sig_batch(
    batch: &SigBatchProof,
    entries: &[VerifiedSignatureEntry],
    expected_ids: &[[u8; 32]],
    expected_batch_root: &[u8; 32],
    accounts: &[AccountStateProof],
    expected_state_root: &[u8; 32],
    expected_accounts: &[Option<Account>],
) -> Result<Vec<VerifiedAccountState>, String> {
    if accounts.len() != entries.len() || expected_accounts.len() != entries.len() {
        return Err("account-bound batch source count mismatch".into());
    }
    verify_authenticated_sig_batch(batch, entries, expected_ids, expected_batch_root)?;
    accounts
        .iter()
        .zip(entries)
        .zip(expected_accounts)
        .map(|((proof, entry), account)| {
            verify_account_state(proof, expected_state_root, entry.sender(), account.as_ref())
        })
        .collect()
}
