//! Native persisted account-state witnesses joined to two real signed graphs.
#[path = "common/mldsa_batch.rs"]
mod graph;
#[path = "common/mldsa_source.rs"]
mod source;

use alloy_rlp::{Encodable, Header};
use serde::{Deserialize, Serialize};
use shell_core::Account;
use shell_primitives::{keccak256, Address, ShellHash, U256};
use shell_stark_prover::{
    account_state::{
        prove_account_state, verify_account_bound_sig_batch, verify_account_state,
        AccountStateProof,
    },
    mldsa_source::verify_authenticated_sig_batch,
    shake_sponge::{
        prove_keccak256, prove_shake, verify_keccak256, verify_shake, ShakeKind, ShakeProof,
    },
    SigBatchProof,
};
use shell_storage::{KvStore, MemoryDb, MerkleTrie, RocksDbStore, WorldState};
use source::{read, write, Error};
use std::{path::Path, sync::Arc};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Query {
    role: String,
    root: [u8; 32],
    address: [u8; 32],
    account: Option<Account>,
    nodes: Vec<Vec<u8>>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Context {
    version: u8,
    state_root: [u8; 32],
    current_root: [u8; 32],
    batch_root: [u8; 32],
    transaction_ids: Vec<[u8; 32]>,
    current_first: Account,
    queries: Vec<Query>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchSource {
    version: u8,
    transaction_ids: Vec<[u8; 32]>,
    batch_root: [u8; 32],
}
fn context(dir: &Path) -> Result<Context, Error> {
    let c: Context = read(&dir.join("state-source.json"))?;
    if c.version != 1 || c.queries.len() != 5 || c.transaction_ids.len() != 2 {
        return Err("invalid native state source shape/version".into());
    }
    for (q, role) in c.queries.iter().zip([
        "first-account",
        "second-account",
        "branch-absence",
        "leaf-absence",
        "empty-root",
    ]) {
        if q.role != role || (role != "empty-root" && q.root != c.state_root) {
            return Err("invalid native state query role/root".into());
        }
        if q.account.is_some() != role.ends_with("account") {
            return Err("invalid native state query membership".into());
        }
    }
    if c.current_root == c.state_root {
        return Err("native state mutation must change root".into());
    }
    Ok(c)
}
fn leaf(bytes: &[u8]) -> bool {
    let mut rest = bytes;
    Header::decode_bytes(&mut rest, true)
        .ok()
        .and_then(|mut list| Header::decode_bytes(&mut list, false).ok())
        .and_then(|p| p.first().copied())
        .is_some_and(|v| v >> 4 >= 2)
}
fn address_search(mut accepts: impl FnMut(&[u8; 32], &[u8; 32]) -> bool) -> [u8; 32] {
    for n in 1u64..1_000_000 {
        let mut address = [0x51; 32];
        address[24..].copy_from_slice(&n.to_be_bytes());
        let hash = keccak256(&address);
        if accepts(&address, hash.as_bytes()) {
            return address;
        }
    }
    panic!("deterministic native fixture address search exhausted")
}
fn query(
    db: &Arc<shell_storage::RocksDbStore>,
    root: [u8; 32],
    address: [u8; 32],
    account: Option<Account>,
    role: &str,
) -> Result<Query, Error> {
    let key = keccak256(&address);
    let mut trie = MerkleTrie::at_root(Arc::clone(db), &root)?;
    let nodes = trie.get_proof(key.as_bytes())?;
    let actual = MerkleTrie::<MemoryDb>::verify_proof(
        Arc::new(MemoryDb::new()),
        &root,
        key.as_bytes(),
        nodes.clone(),
    )?;
    let expected = account.as_ref().map(|a| {
        let mut bytes = Vec::new();
        a.encode(&mut bytes);
        bytes
    });
    if actual != expected {
        return Err("native independent account trie control failed".into());
    }
    Ok(Query {
        role: role.into(),
        root,
        address,
        account,
        nodes,
    })
}
fn init(first: &Path, second: &Path, batch: &Path, dir: &Path) -> Result<(), Error> {
    let (first, _, _) = graph::load(first)?;
    let (second, _, _) = graph::load(second)?;
    let tokens = vec![first.verify()?, second.verify()?];
    let expected: BatchSource = read(&batch.join("batch-source.json"))?;
    let proof: SigBatchProof = read(&batch.join("batch-proof.json"))?;
    if expected.version != 1 {
        return Err("invalid batch source version".into());
    }
    verify_authenticated_sig_batch(
        &proof,
        &tokens,
        &expected.transaction_ids,
        &expected.batch_root,
    )?;
    std::fs::create_dir_all(dir)?;
    if dir.join("state-source.json").try_exists()? {
        let c = context(dir)?;
        if c.transaction_ids != expected.transaction_ids
            || c.batch_root != expected.batch_root
            || c.queries[0].address != *tokens[0].sender()
            || c.queries[1].address != *tokens[1].sender()
        {
            return Err("saved state source differs from verified batch".into());
        }
        native_reopen(dir)?;
        println!(
            "{}",
            serde_json::json!({"mode":"init","new_native_fixture":false,"new_proofs":0})
        );
        return Ok(());
    }
    if dir.join("native-db").try_exists()? {
        return Err("partial native fixture exists; refusing to overwrite".into());
    }
    let c = {
        let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
        let db = Arc::new(stores.state.clone());
        let mut world = WorldState::new(Arc::clone(&db));
        let empty_root = *world.state_root()?.as_bytes();
        let addresses = [*tokens[0].sender(), *tokens[1].sender()];
        let accounts = [
            Account::new_user_account(ShellHash::from(first.key_hash), U256::from(1_000_000u64)),
            Account::new_user_account(ShellHash::from(second.key_hash), U256::from(2_000_000u64)),
        ];
        for (address, account) in addresses.iter().zip(&accounts) {
            world.set_account(&Address::from(*address), account)?;
        }
        let key = keccak256(&addresses[0]);
        let extra = address_search(|a, k| {
            !addresses.contains(a)
                && k[0] == key.as_bytes()[0]
                && k[1] >> 4 != key.as_bytes()[1] >> 4
        });
        world.set_account(
            &Address::from(extra),
            &Account::new_user_account(ShellHash::ZERO, U256::from(91u64)),
        )?;
        let separate = address_search(|_, k| k[0] >> 4 != key.as_bytes()[0] >> 4);
        world.set_account(
            &Address::from(separate),
            &Account::new_user_account(ShellHash::ZERO, U256::from(92u64)),
        )?;
        let root = *world.state_root()?.as_bytes();
        let roots: Vec<_> = addresses
            .iter()
            .chain([&extra, &separate])
            .map(|a| keccak256(a).as_bytes()[0] >> 4)
            .collect();
        let absent_branch = address_search(|_, k| !roots.contains(&(k[0] >> 4)));
        let absent_leaf = address_search(|a, k| {
            !addresses.contains(a)
                && *a != extra
                && k[0] == key.as_bytes()[0]
                && k[1] >> 4 == key.as_bytes()[1] >> 4
        });
        let queries = vec![
            query(
                &db,
                root,
                addresses[0],
                Some(accounts[0].clone()),
                "first-account",
            )?,
            query(
                &db,
                root,
                addresses[1],
                Some(accounts[1].clone()),
                "second-account",
            )?,
            query(&db, root, absent_branch, None, "branch-absence")?,
            query(&db, root, absent_leaf, None, "leaf-absence")?,
            query(&db, empty_root, addresses[0], None, "empty-root")?,
        ];
        if !queries[3].nodes.last().is_some_and(|n| leaf(n)) {
            return Err("native absence fixture must terminate at a mismatched leaf".into());
        }
        let mut changed = accounts[0].clone();
        changed.nonce = 7;
        changed.balance = U256::from(9u64);
        changed.validation_code_hash = Some(ShellHash::from([0x33; 32]));
        world.set_account(&Address::from(addresses[0]), &changed)?;
        let current_root = *world.state_root()?.as_bytes();
        db.flush()?;
        Context {
            version: 1,
            state_root: root,
            current_root,
            batch_root: expected.batch_root,
            transaction_ids: expected.transaction_ids,
            current_first: changed,
            queries,
        }
    };
    write(&dir.join("state-source.json"), &c)?;
    native_reopen(dir)?;
    println!(
        "{}",
        serde_json::json!({"mode":"init","new_native_fixture":true,"actual_RocksDB_closed_and_reopened":true,"native_queries":5,"account_root":c.state_root,"current_mutated_root":c.current_root,"actual_two_full_signature_graphs_verified":true,"proofs_generated":0,"registry_authority_proved":false})
    );
    Ok(())
}
fn native_reopen(dir: &Path) -> Result<(), Error> {
    let c = context(dir)?;
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let db = Arc::new(stores.state.clone());
    let before = db.scan_all()?;
    let old = WorldState::at_root(Arc::clone(&db), &ShellHash::from(c.state_root))?;
    let current = WorldState::at_root(Arc::clone(&db), &ShellHash::from(c.current_root))?;
    if current.get_account(&Address::from(c.queries[0].address))? != Some(c.current_first.clone()) {
        return Err("reopened current native state mismatch".into());
    }
    for q in &c.queries {
        let view = WorldState::at_root(Arc::clone(&db), &ShellHash::from(q.root))?;
        if view.get_account(&Address::from(q.address))? != q.account {
            return Err("reopened historical native state mismatch".into());
        }
    }
    if old.get_account(&Address::from(c.queries[0].address))? != c.queries[0].account
        || current.get_account(&Address::from(c.queries[0].address))? != Some(c.current_first)
    {
        return Err("historical read changed current native state".into());
    }
    if db.scan_all()? != before {
        return Err("historical read wrote to native state KV".into());
    }
    Ok(())
}
fn hash_checkpoint(dir: &Path, message: &[u8], generated: &mut usize) -> Result<ShakeProof, Error> {
    let expected = keccak256(message);
    let name: String = expected
        .as_bytes()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    let path = dir.join(format!("hash-{name}.json"));
    if !path.try_exists()? {
        eprintln!("Proving Keccak256 {} bytes: {name}", message.len());
        write(&path, &prove_keccak256(message)?)?;
        *generated += 1;
    }
    let p: ShakeProof = read(&path)?;
    verify_keccak256(&p, message, expected.as_bytes())?;
    Ok(p)
}
fn prove(dir: &Path) -> Result<(), Error> {
    let c = context(dir)?;
    let mut generated = 0;
    for q in &c.queries {
        let path = dir.join(format!("{}.json", q.role));
        if !path.try_exists()? {
            let raw = if q.nodes.is_empty() {
                vec![vec![0x80]]
            } else {
                q.nodes.clone()
            };
            let p = AccountStateProof {
                version: 1,
                address_hash: hash_checkpoint(dir, &q.address, &mut generated)?,
                nodes: raw
                    .iter()
                    .map(|n| hash_checkpoint(dir, n, &mut generated))
                    .collect::<Result<_, _>>()?,
            };
            verify_account_state(&p, &q.root, &q.address, q.account.as_ref())?;
            write(&path, &p)?;
        }
        let p: AccountStateProof = read(&path)?;
        verify_account_state(&p, &q.root, &q.address, q.account.as_ref())?;
    }
    println!(
        "{}",
        serde_json::json!({"mode":"prove","native_account_MPT_verified":true,"queries":5,"new_hash_certificates":generated,"prior_signature_graphs_regenerated":0,"root_state_changed_after_snapshot":true,"native_hash_acceptance_fallback":false,"account_authority_proved":false})
    );
    Ok(())
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HashControls {
    version: u8,
    messages: Vec<Vec<u8>>,
    outputs: Vec<[u8; 32]>,
    shake_output: Vec<u8>,
    malformed_output: [u8; 32],
}
fn hash_controls(dir: &Path, proving: bool) -> Result<(), Error> {
    let c = context(dir)?;
    let messages = vec![
        vec![],
        b"abc".to_vec(),
        vec![0xa5; 135],
        vec![0x12; 136],
        vec![0x34; 137],
    ];
    let source = dir.join("hash-source.json");
    let mut generated = 0;
    if proving {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Digest,
        };
        let mut outputs = Vec::new();
        for msg in &messages {
            let independent: [u8; 32] = sha3::Keccak256::digest(msg).into();
            if independent != *keccak256(msg).as_bytes() {
                return Err("independent native Keccak oracle mismatch".into());
            }
            outputs.push(independent);
        }
        let mut h = sha3::Shake256::default();
        h.update(&c.queries[0].address);
        let mut shake_output = vec![0; 32];
        h.finalize_xof().read(&mut shake_output);
        let expected = HashControls {
            version: 1,
            messages: messages.clone(),
            outputs,
            shake_output,
            malformed_output: *keccak256(&[0xc2, 0x40, 0x80]).as_bytes(),
        };
        if !source.try_exists()? {
            write(&source, &expected)?;
        }
        if read::<HashControls>(&source)? != expected {
            return Err("saved independent hash controls differ".into());
        }
        for (i, msg) in messages.iter().enumerate() {
            let path = dir.join(format!("boundary-{i}.json"));
            if !path.try_exists()? {
                write(&path, &hash_checkpoint(dir, msg, &mut generated)?)?;
            }
        }
        let path = dir.join("honest-shake-domain.json");
        if !path.try_exists()? {
            write(
                &path,
                &prove_shake(ShakeKind::Shake256, &c.queries[0].address, 32)?,
            )?;
            generated += 1;
        }
        let path = dir.join("malformed-node-hash.json");
        if !path.try_exists()? {
            write(
                &path,
                &hash_checkpoint(dir, &[0xc2, 0x40, 0x80], &mut generated)?,
            )?;
        }
        // Exercise the public empty-trie producer once; persist its address and
        // root certificates so the other queries reuse them byte-for-byte.
        let path = dir.join("empty-root.json");
        if !path.try_exists()? {
            let proof = prove_account_state(&c.queries[4].address, &[])?;
            verify_account_state(&proof, &c.queries[4].root, &c.queries[4].address, None)?;
            for p in std::iter::once(&proof.address_hash).chain(&proof.nodes) {
                let name: String = p.output.iter().map(|v| format!("{v:02x}")).collect();
                let cache = dir.join(format!("hash-{name}.json"));
                if cache.try_exists()? {
                    return Err(
                        "empty trie producer would duplicate existing hash checkpoint".into(),
                    );
                }
                write(&cache, p)?;
                generated += 1;
            }
            write(&path, &proof)?;
        }
    }
    let expected: HashControls = read(&source)?;
    if expected.version != 1
        || expected.messages != messages
        || expected.outputs.len() != 5
        || expected.shake_output.len() != 32
    {
        return Err("invalid persisted independent hash control shape".into());
    }
    for (i, msg) in messages.iter().enumerate() {
        let p: ShakeProof = read(&dir.join(format!("boundary-{i}.json")))?;
        verify_keccak256(&p, msg, &expected.outputs[i])?;
    }
    let shake: ShakeProof = read(&dir.join("honest-shake-domain.json"))?;
    verify_shake(
        &shake,
        ShakeKind::Shake256,
        &c.queries[0].address,
        &expected.shake_output,
    )?;
    let empty: AccountStateProof = read(&dir.join("empty-root.json"))?;
    let address_hash: [u8; 32] = empty.address_hash.output.as_slice().try_into()?;
    if verify_keccak256(&shake, &c.queries[0].address, &address_hash).is_ok() {
        return Err("honest SHAKE proof accepted as Keccak-256".into());
    }
    let malformed: ShakeProof = read(&dir.join("malformed-node-hash.json"))?;
    verify_keccak256(&malformed, &[0xc2, 0x40, 0x80], &expected.malformed_output)?;
    println!(
        "{}",
        serde_json::json!({"mode":"hash-controls","Keccak256_boundary_lengths":[0,3,135,136,137],"native_independent_oracles":proving,"honest_SHAKE_domain_rejected":true,"honest_malformed_RLP_hash_verified":true,"new_certificates":generated,"native_hash_acceptance_fallback":false})
    );
    Ok(())
}
fn reject<T>(
    cases: &mut Vec<serde_json::Value>,
    name: &str,
    result: Result<T, String>,
) -> Result<(), Error> {
    let error = result
        .err()
        .ok_or_else(|| format!("invalid account witness accepted: {name}"))?;
    cases.push(serde_json::json!({"case":name,"error":error}));
    Ok(())
}
fn verify(
    mode: &std::ffi::OsStr,
    first: &Path,
    second: &Path,
    batch: &Path,
    dir: &Path,
) -> Result<(), Error> {
    let c = context(dir)?;
    let (first, _, _) = graph::load(first)?;
    let (second, _, _) = graph::load(second)?;
    let tokens = vec![first.verify()?, second.verify()?];
    let native: SigBatchProof = read(&batch.join("batch-proof.json"))?;
    let proofs: Vec<AccountStateProof> = c
        .queries
        .iter()
        .map(|q| read(&dir.join(format!("{}.json", q.role))))
        .collect::<Result<_, _>>()?;
    let expected: Vec<_> = c.queries[..2].iter().map(|q| q.account.clone()).collect();
    let snapshots = verify_account_bound_sig_batch(
        &native,
        &tokens,
        &c.transaction_ids,
        &c.batch_root,
        &proofs[..2],
        &c.state_root,
        &expected,
    )?;
    for (snapshot, q) in snapshots.iter().zip(&c.queries) {
        if snapshot.address() != &q.address
            || snapshot.root() != &q.root
            || snapshot.account() != q.account.as_ref()
        {
            return Err("verified immutable account snapshot mismatch".into());
        }
    }
    for (p, q) in proofs.iter().zip(&c.queries) {
        verify_account_state(p, &q.root, &q.address, q.account.as_ref())?;
    }
    if mode == "verify" {
        println!(
            "{}",
            serde_json::json!({"mode":"verify","actual_two_signature_graphs_and_native_batch_account_root_verified":true,"account_MPT_memberships":2,"actual_native_absences":3,"proofs_generated":0,"native_hash_acceptance_fallback":false,"registry_or_account_authority_proved":false,"canonical_root_chain_membership_proved":false,"node_integrated":false})
        );
        return Ok(());
    }
    let p = &proofs[0];
    let q = &c.queries[0];
    let mut cases = Vec::new();
    let mut root = q.root;
    root[0] ^= 1;
    reject(
        &mut cases,
        "state_root",
        verify_account_state(p, &root, &q.address, q.account.as_ref()),
    )?;
    let mut address = q.address;
    address[0] ^= 1;
    reject(
        &mut cases,
        "full32_address_not_shared20byte_suffix",
        verify_account_state(p, &q.root, &address, q.account.as_ref()),
    )?;
    let mut account = q.account.clone().ok_or("missing member")?;
    account.nonce += 1;
    reject(
        &mut cases,
        "account_nonce",
        verify_account_state(p, &q.root, &q.address, Some(&account)),
    )?;
    account = q.account.clone().ok_or("missing member")?;
    account.balance += U256::from(1);
    reject(
        &mut cases,
        "account_balance",
        verify_account_state(p, &q.root, &q.address, Some(&account)),
    )?;
    account = q.account.clone().ok_or("missing member")?;
    account.pq_pubkey_hash = ShellHash::ZERO;
    reject(
        &mut cases,
        "account_key_binding",
        verify_account_state(p, &q.root, &q.address, Some(&account)),
    )?;
    account = q.account.clone().ok_or("missing member")?;
    account.validation_code_hash = Some(ShellHash::from([0x44; 32]));
    reject(
        &mut cases,
        "custom_validator_field",
        verify_account_state(p, &q.root, &q.address, Some(&account)),
    )?;
    reject(
        &mut cases,
        "member_as_absence",
        verify_account_state(p, &q.root, &q.address, None),
    )?;
    reject(
        &mut cases,
        "absence_as_member",
        verify_account_state(
            &proofs[2],
            &q.root,
            &c.queries[2].address,
            q.account.as_ref(),
        ),
    )?;
    reject(
        &mut cases,
        "old_account_under_new_current_root",
        verify_account_state(p, &c.current_root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.version += 1;
    reject(
        &mut cases,
        "version",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes.pop();
    reject(
        &mut cases,
        "missing_node",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes.push(p.nodes[0].clone());
    reject(
        &mut cases,
        "extra_node",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes.reverse();
    reject(
        &mut cases,
        "node_order",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes[0].message[0] ^= 1;
    reject(
        &mut cases,
        "RLP_node_bytes",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.address_hash = proofs[1].address_hash.clone();
    reject(
        &mut cases,
        "foreign_address_certificate",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes[0].output[0] ^= 1;
    reject(
        &mut cases,
        "node_hash_output",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes[0].sponge_proof_bytes.clear();
    reject(
        &mut cases,
        "missing_bridge",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes[0].permutations.pop();
    reject(
        &mut cases,
        "missing_permutation",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes[0].permutations[0].rounds[0].output[0] ^= 1;
    reject(
        &mut cases,
        "permutation_arithmetic",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut changed = p.clone();
    changed.nodes[0].kind = shell_stark_prover::shake_sponge::ShakeKind::Shake256;
    reject(
        &mut cases,
        "SHAKE_domain_substitution",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let h: HashControls = read(&dir.join("hash-source.json"))?;
    let malformed: ShakeProof = read(&dir.join("malformed-node-hash.json"))?;
    verify_keccak256(&malformed, &[0xc2, 0x40, 0x80], &h.malformed_output)?;
    let mut changed = p.clone();
    changed.nodes = vec![malformed];
    reject(
        &mut cases,
        "honest_hash_of_invalid_compact_RLP_path",
        verify_account_state(
            &changed,
            &h.malformed_output,
            &q.address,
            q.account.as_ref(),
        ),
    )?;
    let mut changed = p.clone();
    changed.address_hash = read(&dir.join("honest-shake-domain.json"))?;
    reject(
        &mut cases,
        "honestly_proved_SHAKE_for_same_address",
        verify_account_state(&changed, &q.root, &q.address, q.account.as_ref()),
    )?;
    let mut reversed = proofs[..2].to_vec();
    reversed.reverse();
    reject(
        &mut cases,
        "foreign_sender_account_order",
        verify_account_bound_sig_batch(
            &native,
            &tokens,
            &c.transaction_ids,
            &c.batch_root,
            &reversed,
            &c.state_root,
            &expected,
        ),
    )?;
    reject(
        &mut cases,
        "missing_sender_account",
        verify_account_bound_sig_batch(
            &native,
            &tokens,
            &c.transaction_ids,
            &c.batch_root,
            &proofs[..1],
            &c.state_root,
            &expected,
        ),
    )?;
    println!(
        "{}",
        serde_json::json!({"mode":"check-rejections","positive_native_account_batch_verified":true,"rejected":cases,"proofs_generated":0,"input_files_read_only":true,"native_hash_acceptance_fallback":false})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mode = args.first().ok_or("missing mode")?;
    if args.len() == 2 && mode == "prove" {
        return prove(Path::new(&args[1]));
    }
    if args.len() == 2 && (mode == "hash-controls" || mode == "verify-hash-controls") {
        return hash_controls(Path::new(&args[1]), mode == "hash-controls");
    }
    if args.len() == 2 && mode == "native-reopen" {
        native_reopen(Path::new(&args[1]))?;
        println!(
            "{}",
            serde_json::json!({"mode":"native-reopen","actual_RocksDB_reopened":true,"old_and_current_roots_verified":true,"historical_reads_do_not_change_current_state":true,"native_state_KV_unchanged":true})
        );
        return Ok(());
    }
    if args.len() == 5 {
        if mode == "init" {
            return init(
                Path::new(&args[1]),
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
            );
        }
        if mode == "verify" || mode == "check-rejections" {
            return verify(
                mode,
                Path::new(&args[1]),
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
            );
        }
    }
    Err("usage: mldsa-account-state init|verify|check-rejections first-graph second-graph batch-dir state-dir; prove|native-reopen state-dir".into())
}
