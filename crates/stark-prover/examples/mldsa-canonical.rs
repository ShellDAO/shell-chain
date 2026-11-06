//! Historical registered proofs over two real native transfers in local storage.
#[path = "common/mldsa_batch.rs"]
mod graph;
#[path = "common/mldsa_source.rs"]
mod source;
use graph::LoadedEntry;
use serde::{Deserialize, Serialize};
use shell_core::{Account, Block, BlockHeader, PubkeyMode, SignedTransaction, TransactionReceipt};
use shell_crypto::MultiVerifier;
use shell_pqvm::{
    commit_pqvm_state, validate_tx, validate_tx_for_import_at_block, ShellPqvm, ShellStateDb,
};
use shell_primitives::{blake3_hash, keccak256, Address, ShellHash, U256};
use shell_stark_prover::{
    account_state::{verify_account_state, AccountStateProof},
    blake3_hash::{prove_hash, verify_hash, Blake3HashProof},
    canonical_signature::verify_canonical_registered_signature,
    registered_signature::RegisteredSignatureProof,
    shake_sponge::{prove_keccak256, verify_keccak256, ShakeProof},
    SigBatchEntry,
};
use shell_storage::{
    ChainConfig, ChainStore, KvStore, MemoryDb, MerkleTrie, OverlayStore, RocksDbStore, WorldState,
};
use source::{read, write, Error};
use std::{path::Path, sync::Arc};
#[derive(Deserialize)]
struct OldContext {
    state_root: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    version: u8,
    genesis_root: [u8; 32],
    hashes: Vec<ShellHash>,
    parent_root: [u8; 32],
    current_root: [u8; 32],
    first: SignedTransaction,
    second: SignedTransaction,
    first_key: Vec<u8>,
    second_key: Vec<u8>,
    account: Account,
    nodes: Vec<Vec<u8>>,
    receipts: Vec<TransactionReceipt>,
    trie_nodes: Vec<(Vec<u8>, Vec<u8>)>,
}
fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn signed(g: &LoadedEntry, reference: bool) -> Result<SignedTransaction, Error> {
    let mut t = SignedTransaction::new(
        g.expected.from,
        g.expected.tx.clone(),
        g.expected.signature.clone(),
    );
    if !reference {
        t.pubkey_mode = PubkeyMode::Embedded(
            g.expected
                .pubkey_mode
                .pubkey_bytes()
                .ok_or("missing fixture key")?
                .to_vec(),
        );
    }
    ensure(
        t.tx.tx_type == 0 && t.aa_bundle.is_none() && t.tx.to.is_some(),
        "fixture requires ordinary type0 transfer",
    )?;
    Ok(t)
}
fn context(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    dir: &Path,
) -> Result<Context, Error> {
    let c: Context = read(&dir.join("canonical-source.json"))?;
    let root: OldContext = read(&old.join("state-source.json"))?;
    ensure(
        c.version == 1
            && c.hashes.len() == 3
            && c.receipts.len() == 2
            && c.genesis_root == root.state_root
            && c.first == signed(first, false)?
            && c.second == signed(second, true)?
            && c.first_key
                == first
                    .expected
                    .pubkey_mode
                    .pubkey_bytes()
                    .ok_or("first key absent")?
            && c.second_key
                == second
                    .expected
                    .pubkey_mode
                    .pubkey_bytes()
                    .ok_or("second key absent")?,
        "saved canonical source differs from current inputs",
    )?;
    Ok(c)
}
fn header(root: ShellHash) -> BlockHeader {
    BlockHeader {
        parent_hash: ShellHash::ZERO,
        state_root: root,
        transactions_root: ShellHash::ZERO,
        receipts_root: ShellHash::ZERO,
        logs_bloom: Default::default(),
        number: 0,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 1_000_000,
        extra_data: Default::default(),
        proposer: Address::ZERO,
        sig_aggregate_proof: None,
        base_fee_per_gas: 1,
        withdrawals_root: ShellHash::ZERO,
        parent_beacon_block_root: ShellHash::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
        witness_root: None,
    }
}
fn init(first: &LoadedEntry, second: &LoadedEntry, old: &Path, dir: &Path) -> Result<(), Error> {
    first.verify()?;
    std::fs::create_dir_all(dir)?;
    if dir.join("canonical-source.json").try_exists()? {
        context(first, second, old, dir)?;
        return reopen(dir);
    }
    ensure(
        !dir.join("native-db").try_exists()?,
        "partial canonical fixture exists; refusing overwrite",
    )?;
    let root: OldContext = read(&old.join("state-source.json"))?;
    let first_tx = signed(first, false)?;
    let second_tx = signed(second, true)?;
    let first_key = first
        .expected
        .pubkey_mode
        .pubkey_bytes()
        .ok_or("missing first key")?
        .to_vec();
    let second_key = second
        .expected
        .pubkey_mode
        .pubkey_bytes()
        .ok_or("missing second key")?
        .to_vec();
    let result;
    {
        let original = RocksDbStore::open_all(old.join("native-db"), None)?;
        let original_entries = original.state.scan_all()?;
        let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
        let db = Arc::new(stores.state.clone());
        for (k, v) in &original_entries {
            db.put(k, v)?;
        }
        let chain = ChainStore::new(Arc::clone(&db));
        let genesis = Block {
            header: header(ShellHash::from(root.state_root)),
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let config: ChainConfig = serde_json::from_value(
            serde_json::json!({"chain_id":10,"genesis_hash":genesis.hash(),"fee_accounting_activation_height":1,"native_address_context_height":1}),
        )?;
        chain.put_pubkey(&second_tx.from, &second_key)?;
        chain.commit_genesis_block(&genesis, &config)?;
        ensure(
            chain.get_pubkey(&first_tx.from)?.is_none(),
            "first key must be absent before first use",
        )?;
        let mut previous = genesis;
        let mut hashes = vec![previous.hash()];
        let mut receipts = Vec::new();
        let mut parent_root = root.state_root;
        for tx in [&first_tx, &second_tx] {
            let overlay = Arc::new(OverlayStore::new(Arc::clone(&db)));
            let cs = ChainStore::new(Arc::clone(&overlay));
            let checkpoint = cs.address_metadata_checkpoint()?;
            let mut world = WorldState::at_root(Arc::clone(&overlay), &previous.header.state_root)?;
            validate_tx(tx, &mut world, &cs, &MultiVerifier, 10)?;
            let mut h = header(previous.header.state_root);
            h.parent_hash = previous.hash();
            h.number = previous.number() + 1;
            h.timestamp = previous.header.timestamp + 1;
            let mut vm = ShellPqvm::new(ShellStateDb::new(world, cs), 10);
            let executed = vm.execute_tx(tx, &h, 0, 0)?;
            ensure(
                executed.receipt.status == 1 && executed.receipt.tx_hash == tx.hash(),
                "native transfer failed",
            )?;
            commit_pqvm_state(&executed, vm.state_db_mut())?;
            h.state_root = vm.state_db_mut().world_state_mut().state_root()?;
            h.gas_used = executed.receipt.gas_used;
            let b = Block {
                header: h,
                transactions: vec![tx.clone()],
                system_transactions: vec![],
                proposer_seal: None,
            };
            let cs = ChainStore::new(Arc::clone(&overlay));
            cs.stage_address_metadata_undo(&b.hash(), &checkpoint)?;
            cs.commit_canonical_block(&b, Some(std::slice::from_ref(&executed.receipt)))?;
            overlay.commit()?;
            if b.number() == 1 {
                parent_root = *b.header.state_root.as_bytes();
            }
            receipts.push(executed.receipt);
            hashes.push(b.hash());
            previous = b;
        }
        let view = chain.canonical_parent_view(hashes[2], hashes[1])?;
        let account = view
            .world_state()?
            .get_account(&second_tx.from)?
            .ok_or("historical second account absent")?;
        let key = keccak256(second_tx.from.as_bytes());
        let nodes =
            MerkleTrie::at_root(Arc::clone(&db), &parent_root)?.get_proof(key.as_bytes())?;
        ensure(
            account.nonce == 0
                && WorldState::at_root(Arc::clone(&db), &previous.header.state_root)?
                    .get_nonce(&second_tx.from)?
                    == 1,
            "historical nonce must differ from current",
        )?;
        db.flush()?;
        ensure(
            original_entries == original.state.scan_all()?,
            "old fixture changed",
        )?;
        result = Context {
            version: 1,
            genesis_root: root.state_root,
            hashes,
            parent_root,
            current_root: *previous.header.state_root.as_bytes(),
            first: first_tx,
            second: second_tx,
            first_key,
            second_key,
            account,
            nodes,
            receipts,
            trie_nodes: db
                .scan_all()?
                .into_iter()
                .filter(|(k, _)| k.len() == 32)
                .collect(),
        };
    }
    write(&dir.join("canonical-source.json"), &result)?;
    reopen(dir)?;
    println!(
        "{}",
        serde_json::json!({"mode":"init","actual_native_transfers":2,"actual_signature_validation":true,"first_key_registered_by_first_native_admission":true,"state_receipts_blocks_and_native_undo_persisted":true,"consensus_import_validated":false,"transaction_root_commitment_proved":false})
    );
    Ok(())
}
fn hash_checkpoint(
    old: &Path,
    registered: &Path,
    dir: &Path,
    message: &[u8],
    generated: &mut usize,
) -> Result<ShakeProof, Error> {
    let output = keccak256(message);
    let hex: String = output
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let name = format!("hash-{hex}.json");
    for parent in [old, registered, dir] {
        let p = parent.join(&name);
        if p.try_exists()? {
            let proof = read(&p)?;
            verify_keccak256(&proof, message, output.as_bytes())?;
            return Ok(proof);
        }
    }
    let proof = prove_keccak256(message)?;
    write(&dir.join(name), &proof)?;
    *generated += 1;
    Ok(proof)
}
fn prove(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    registered: &Path,
    dir: &Path,
) -> Result<(), Error> {
    let c = context(first, second, old, dir)?;
    let mut generated = 0;
    let path = dir.join("account.json");
    if !path.try_exists()? {
        let p = AccountStateProof {
            version: 1,
            address_hash: hash_checkpoint(
                old,
                registered,
                dir,
                c.second.from.as_bytes(),
                &mut generated,
            )?,
            nodes: c
                .nodes
                .iter()
                .map(|n| hash_checkpoint(old, registered, dir, n, &mut generated))
                .collect::<Result<_, _>>()?,
        };
        verify_account_state(
            &p,
            &c.parent_root,
            c.second.from.as_bytes(),
            Some(&c.account),
        )?;
        write(&path, &p)?;
    }
    let proof: AccountStateProof = read(&path)?;
    verify_account_state(
        &proof,
        &c.parent_root,
        c.second.from.as_bytes(),
        Some(&c.account),
    )?;
    let entry = SigBatchEntry::from_signed_transaction(&c.second);
    let mut bytes = entry.msg_hash.to_vec();
    bytes.extend(entry.pk_hash);
    let path = dir.join("reference-leaf.json");
    let new_leaf = !path.try_exists()?;
    if new_leaf {
        write(&path, &prove_hash(&bytes)?)?;
    }
    let p = read(&path)?;
    verify_hash(&p, &bytes, blake3_hash(&bytes).as_bytes())?;
    println!(
        "{}",
        serde_json::json!({"mode":"prove","new_keccak_certificates":generated,"new_reference_leaf":new_leaf,"signature_graphs_regenerated":0})
    );
    Ok(())
}
fn registered(g: &LoadedEntry, leaf: Blake3HashProof) -> RegisteredSignatureProof {
    RegisteredSignatureProof {
        version: 1,
        transaction: g.proof.identified.sender.transaction.clone(),
        transaction_id: g.proof.identified.transaction_id.clone(),
        leaf,
        tagged_key: None,
    }
}
fn verify(first: &LoadedEntry, second: &LoadedEntry, old: &Path, dir: &Path) -> Result<(), Error> {
    let c = context(first, second, old, dir)?;
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let db = Arc::new(stores.state.clone());
    let before = db.scan_all()?;
    let chain = ChainStore::new(Arc::clone(&db));
    let view = chain.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    let proof = registered(second, read(&dir.join("reference-leaf.json"))?);
    let account: AccountStateProof = read(&dir.join("account.json"))?;
    let token = verify_canonical_registered_signature(&view, &c.second, &account, &proof)?;
    ensure(
        token.tip() == c.hashes[2]
            && token.parent() == c.hashes[1]
            && token.signature().matches_transaction(&c.second),
        "canonical proof token context mismatch",
    )?;
    let block = chain
        .get_block_by_hash(&c.hashes[2])?
        .ok_or("source block missing")?;
    let mut world = view.world_state()?;
    let readonly = ChainStore::new(view.store());
    validate_tx_for_import_at_block(
        &c.second,
        &mut world,
        &readonly,
        token.signature(),
        view.config().chain_id,
        None,
        &block.header,
    )?;
    let mut current = WorldState::at_root(Arc::clone(&db), &ShellHash::from(c.current_root))?;
    ensure(
        validate_tx_for_import_at_block(
            &c.second,
            &mut current,
            &chain,
            token.signature(),
            10,
            None,
            &block.header,
        )
        .is_err(),
        "live advanced nonce accepted old transaction",
    )?;
    let genesis = chain.canonical_parent_view(c.hashes[2], c.hashes[0])?;
    ensure(
        genesis.registered_key(&c.first.from)?.is_none()
            && chain.get_pubkey(&c.first.from)? == Some(c.first_key.clone()),
        "first-use key leaked into historical parent",
    )?;
    let first_proof = registered(first, first.proof.leaf.clone());
    let first_account = read(&old.join("first-account.json"))?;
    ensure(
        verify_canonical_registered_signature(&genesis, &c.first, &first_account, &first_proof)
            .is_err(),
        "later key falsely authorized historical registered profile",
    )?;
    // Native first-use remains valid in its own profile; it is not reclassified as
    // an invalid consensus transaction by the registered-only proof predicate.
    let mut world = genesis.world_state()?;
    let first_block = chain
        .get_block_by_hash(&c.hashes[1])?
        .ok_or("first block absent")?;
    validate_tx_for_import_at_block(
        &c.first,
        &mut world,
        &ChainStore::new(genesis.store()),
        &MultiVerifier,
        10,
        None,
        &first_block.header,
    )?;
    ensure(
        before == db.scan_all()?,
        "historical verification wrote canonical state",
    )?;
    println!(
        "{}",
        serde_json::json!({"mode":"verify","historical_registered_Reference_proof":true,"native_import_policy_uses_proof_verifier":true,"current_nonce_replay_rejected":true,"later_first_use_key_absent_at_genesis":true,"native_first_use_separate_profile_valid":true,"base_KV_unchanged":true,"consensus_and_body_membership_proved":false})
    );
    Ok(())
}
fn rejections(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    dir: &Path,
) -> Result<(), Error> {
    let c = context(first, second, old, dir)?;
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let original = stores.state.scan_all()?;
    let proof = registered(second, read(&dir.join("reference-leaf.json"))?);
    let account: AccountStateProof = read(&dir.join("account.json"))?;
    let mut rejected = Vec::new();
    for kind in [
        "missing_key",
        "wrong_key",
        "stale_tip",
        "canonical_mapping",
        "missing_undo",
        "malformed_undo",
        "missing_body",
        "wrong_parent_root",
    ] {
        let db = Arc::new(MemoryDb::new());
        for (k, v) in &original {
            db.put(k, v)?;
        }
        let chain = ChainStore::new(Arc::clone(&db));
        let mut parent = c.hashes[1];
        match kind {
            "missing_key" => db.delete(&[b"pk/".as_slice(), c.second.from.as_bytes()].concat())?,
            "wrong_key" => chain.put_pubkey(&c.second.from, &c.first_key)?,
            "stale_tip" => chain.set_head(&c.hashes[1])?,
            "canonical_mapping" => chain.set_canonical(1, &ShellHash::ZERO)?,
            "missing_undo" => db.delete(&[b"mu/".as_slice(), c.hashes[2].as_bytes()].concat())?,
            "malformed_undo" => db.put(
                &[b"mu/".as_slice(), c.hashes[2].as_bytes()].concat(),
                b"bad",
            )?,
            "missing_body" => db.delete(&[b"b/".as_slice(), c.hashes[2].as_bytes()].concat())?,
            _ => parent = c.hashes[2],
        }
        let before = db.scan_all()?;
        let result = chain
            .canonical_parent_view(c.hashes[2], parent)
            .map_err(|e| e.to_string())
            .and_then(|view| {
                verify_canonical_registered_signature(&view, &c.second, &account, &proof)
            });
        ensure(result.is_err(), &format!("accepted {kind}"))?;
        ensure(before == db.scan_all()?, "failed context wrote base")?;
        rejected.push(kind.to_string());
    }
    let copy = Arc::new(MemoryDb::new());
    for (k, v) in &original {
        copy.put(k, v)?;
    }
    let chain = ChainStore::new(Arc::clone(&copy));
    let frozen = chain.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    chain.put_pubkey(&c.second.from, &c.first_key)?;
    chain.set_head(&c.hashes[0])?;
    copy.put(b"CFG", b"bad")?;
    let before = copy.scan_all()?;
    verify_canonical_registered_signature(&frozen, &c.second, &account, &proof)?;
    ensure(before == copy.scan_all()?, "frozen view wrote live changes")?;
    let mut changed = c.second.clone();
    changed.tx.chain_id += 1;
    ensure(
        verify_canonical_registered_signature(&frozen, &changed, &account, &proof).is_err(),
        "foreign chain accepted",
    )?;
    rejected.push("foreign_chain".into());
    let mut malformed = c.second.clone();
    malformed.tx.tx_type = 0x7e;
    ensure(
        verify_canonical_registered_signature(&frozen, &malformed, &account, &proof).is_err(),
        "AA framing accepted",
    )?;
    rejected.push("unsupported_AA_framing".into());
    let mut oversized = c.second.clone();
    oversized.tx.data = vec![0; 4097].into();
    ensure(
        verify_canonical_registered_signature(&frozen, &oversized, &account, &proof).is_err(),
        "oversized signing source accepted",
    )?;
    rejected.push("signing_source_resource_bound".into());

    ensure(
        original == stores.state.scan_all()?,
        "original canonical database changed",
    )?;
    println!(
        "{}",
        serde_json::json!({"mode":"check-rejections","rejected":rejected,"frozen_metadata_survives_live_key_head_config_changes":true,"all_base_KV_unchanged":true})
    );
    Ok(())
}
fn reopen(dir: &Path) -> Result<(), Error> {
    let c: Context = read(&dir.join("canonical-source.json"))?;
    ensure(
        c.version == 1 && c.hashes.len() == 3 && c.receipts.len() == 2,
        "invalid persisted canonical source",
    )?;
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let db = Arc::new(stores.state.clone());
    let before = db.scan_all()?;
    let chain = ChainStore::new(Arc::clone(&db));
    ensure(
        chain.get_head_hash()? == Some(c.hashes[2]),
        "saved canonical head differs",
    )?;
    for i in 0..3 {
        let block = chain
            .get_block_by_hash(&c.hashes[i])?
            .ok_or("missing persisted block")?;
        ensure(
            block.hash() == c.hashes[i]
                && block.number() == i as u64
                && chain.get_block_hash_by_number(i as u64)? == Some(c.hashes[i]),
            "saved block/header/canonical mapping mismatch",
        )?;
        if i > 0 {
            let expected = if i == 1 { &c.first } else { &c.second };
            ensure(
                block.transactions.as_slice() == std::slice::from_ref(expected)
                    && block.header.parent_hash == c.hashes[i - 1]
                    && chain.get_receipts(&c.hashes[i])? == Some(vec![c.receipts[i - 1].clone()]),
                "saved transaction/receipt/ancestry mismatch",
            )?;
        }
    }
    let old = chain.canonical_parent_view(c.hashes[2], c.hashes[0])?;
    let parent = chain.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    ensure(
        old.registered_key(&c.first.from)?.is_none()
            && parent.registered_key(&c.first.from)? == Some(c.first_key)
            && parent.world_state()?.get_account(&c.second.from)? == Some(c.account),
        "persisted historical registry/account mismatch",
    )?;
    let current = WorldState::at_root(Arc::clone(&db), &ShellHash::from(c.current_root))?;
    ensure(
        current.get_nonce(&c.first.from)? == 1
            && current.get_nonce(&c.second.from)? == 1
            && current.get_balance(&c.second.tx.to.ok_or("missing receiver")?)? == U256::from(2),
        "persisted current state mismatch",
    )?;
    ensure(
        before == db.scan_all()?,
        "reopened historical queries wrote state",
    )?;
    println!(
        "{}",
        serde_json::json!({"mode":"reopen","actual_RocksDB_closed_and_reopened":true,"canonical_header_receipt_state_and_registry_history_verified":true,"base_KV_unchanged":true})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    ensure(a.len()==6,"usage: mldsa-canonical init|prove|verify|check-rejections|reopen first-graph second-graph old-state-dir registered-dir canonical-dir")?;
    let (first, _, _) = graph::load(Path::new(&a[1]))?;
    let (second, _, _) = graph::load(Path::new(&a[2]))?;
    let old = Path::new(&a[3]);
    let registered = Path::new(&a[4]);
    let dir = Path::new(&a[5]);
    match a[0].as_str() {
        "init" => init(&first, &second, old, dir),
        "prove" => prove(&first, &second, old, registered, dir),
        "verify" => verify(&first, &second, old, dir),
        "check-rejections" => rejections(&first, &second, old, dir),
        "reopen" => reopen(dir),
        _ => Err("unknown canonical proof operation".into()),
    }
}
