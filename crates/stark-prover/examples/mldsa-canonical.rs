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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_commitment_height: Option<u64>,
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
            && matches!(c.block_commitment_height, None | Some(1))
            && c.second == signed(second, c.block_commitment_height.is_none())?
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
fn init(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    dir: &Path,
    body: bool,
) -> Result<(), Error> {
    first.verify()?;
    std::fs::create_dir_all(dir)?;
    if dir.join("canonical-source.json").try_exists()? {
        let saved = context(first, second, old, dir)?;
        ensure(
            saved.block_commitment_height == body.then_some(1),
            "fixture activation profile differs",
        )?;
        return reopen(dir);
    }
    ensure(
        !dir.join("native-db").try_exists()?,
        "partial canonical fixture exists; refusing overwrite",
    )?;
    let root: OldContext = read(&old.join("state-source.json"))?;
    let first_tx = signed(first, false)?;
    let second_tx = signed(second, !body)?;
    let first_key = first
        .expected
        .public_key()
        .ok_or("missing first key")?
        .to_vec();
    let second_key = second
        .expected
        .public_key()
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
        let config: ChainConfig = serde_json::from_value(serde_json::json!({
            "chain_id":10, "genesis_hash":genesis.hash(), "fee_accounting_activation_height":1,
            "native_address_context_height":1, "block_commitment_height":body.then_some(1)
        }))?;
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
        // The activated fixture executes both accepted genuine signatures in one
        // batch after an empty block, preserving the initial proved parent state.
        let groups = if body {
            vec![vec![], vec![&first_tx, &second_tx]]
        } else {
            vec![vec![&first_tx], vec![&second_tx]]
        };
        for group in groups {
            let overlay = Arc::new(OverlayStore::new(Arc::clone(&db)));
            let cs = ChainStore::new(Arc::clone(&overlay));
            let checkpoint = cs.address_metadata_checkpoint()?;
            let world = WorldState::at_root(Arc::clone(&overlay), &previous.header.state_root)?;
            let mut h = header(previous.header.state_root);
            h.parent_hash = previous.hash();
            h.number = previous.number() + 1;
            h.timestamp = previous.header.timestamp + 1;
            let mut vm = ShellPqvm::new(ShellStateDb::new(world, cs), 10);
            let mut block_receipts = Vec::new();
            let mut cumulative = 0;
            for (index, tx) in group.iter().enumerate() {
                let cs = ChainStore::new(Arc::clone(&overlay));
                validate_tx(
                    tx,
                    vm.state_db_mut().world_state_mut(),
                    &cs,
                    &MultiVerifier,
                    10,
                )?;
                let executed = vm.execute_tx(tx, &h, index as u32, cumulative)?;
                ensure(
                    executed.receipt.status == 1 && executed.receipt.tx_hash == tx.hash(),
                    "native transfer failed",
                )?;
                cumulative = executed.receipt.cumulative_gas_used;
                commit_pqvm_state(&executed, vm.state_db_mut())?;
                block_receipts.push(executed.receipt);
            }
            h.state_root = vm.state_db_mut().world_state_mut().state_root()?;
            h.gas_used = cumulative;
            let transactions: Vec<_> = group.into_iter().cloned().collect();
            if body {
                h.transactions_root = shell_core::block_body_root(&transactions, &[])?;
                h.receipts_root = shell_core::block_receipts_root(&block_receipts);
            }
            let b = Block {
                header: h,
                transactions,
                system_transactions: vec![],
                proposer_seal: None,
            };
            let cs = ChainStore::new(Arc::clone(&overlay));
            cs.stage_address_metadata_undo(&b.hash(), &checkpoint)?;
            cs.commit_canonical_block(&b, Some(&block_receipts))?;
            overlay.commit()?;
            if b.number() == 1 {
                parent_root = *b.header.state_root.as_bytes();
            }
            receipts.extend(block_receipts);
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
            block_commitment_height: body.then_some(1),
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
        serde_json::json!({"mode":"init", "actual_native_transfers":2,
        "actual_signature_validation":true, "native_batch":body, "native_block_commitments":body,
        "state_receipts_blocks_and_native_undo_persisted":true, "consensus_import_validated":false,
        "transaction_root_commitment_proved":false})
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
    ensure(
        c.block_commitment_height.is_none(),
        "legacy proof operation requires legacy fixture",
    )?;
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
    ensure(
        c.block_commitment_height.is_none(),
        "legacy proof operation requires legacy fixture",
    )?;
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
    ensure(
        c.block_commitment_height.is_none(),
        "legacy proof operation requires legacy fixture",
    )?;
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
            if c.block_commitment_height.is_some() {
                let expected = if i == 1 {
                    vec![]
                } else {
                    vec![c.first.clone(), c.second.clone()]
                };
                let expected_receipts = if i == 1 { vec![] } else { c.receipts.clone() };
                ensure(
                    block.transactions == expected
                        && chain.get_receipts(&c.hashes[i])? == Some(expected_receipts),
                    "saved activated native batch differs",
                )?;
                chain.verify_block_body_commitment(&block)?;
                chain.verify_block_receipts_commitment(
                    &block,
                    &chain
                        .get_receipts(&block.hash())?
                        .ok_or("missing receipts")?,
                )?;
            } else {
                let expected = if i == 1 { &c.first } else { &c.second };
                ensure(
                    block.transactions.as_slice() == std::slice::from_ref(expected)
                        && chain.get_receipts(&c.hashes[i])?
                            == Some(vec![c.receipts[i - 1].clone()]),
                    "saved transaction/receipt mismatch",
                )?;
            }
            ensure(
                block.header.parent_hash == c.hashes[i - 1],
                "saved ancestry mismatch",
            )?;
        }
    }
    ensure(
        chain
            .get_chain_config()?
            .ok_or("missing config")?
            .block_commitment_height
            == c.block_commitment_height,
        "saved activation schedule mismatch",
    )?;
    let old = chain.canonical_parent_view(c.hashes[2], c.hashes[0])?;
    let parent = chain.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    ensure(
        old.registered_key(&c.first.from)?.is_none()
            && parent.registered_key(&c.first.from)?
                == if c.block_commitment_height.is_some() {
                    None
                } else {
                    Some(c.first_key)
                }
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
fn body_inputs(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    accepted: &Path,
    dir: &Path,
) -> Result<Context, Error> {
    let c = context(first, second, old, dir)?;
    let previous = context(first, second, old, accepted)?;
    ensure(
        c.block_commitment_height == Some(1)
            && previous.block_commitment_height.is_none()
            && c.genesis_root == previous.genesis_root
            && c.current_root == previous.current_root
            && c.parent_root == c.genesis_root
            && c.second.tx == previous.second.tx
            && c.second.signature == previous.second.signature
            && c.second.from == previous.second.from,
        "activated batch differs from accepted genuine inputs or native execution roots",
    )?;
    Ok(c)
}
fn body_prove(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    accepted: &Path,
    dir: &Path,
) -> Result<(), Error> {
    use shell_stark_prover::body_membership::{
        prove_transaction_body, verify_transaction_body, TransactionBodyProof,
    };
    let c = body_inputs(first, second, old, accepted, dir)?;
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let chain = ChainStore::new(Arc::new(stores.state));
    let block = chain
        .get_block_by_hash(&c.hashes[2])?
        .ok_or("missing native batch")?;
    let message = shell_core::block_body_leaf_message(&c.second, 1);
    ensure(
        message.len() > shell_stark_prover::blake3_hash::MAX_HASH_BYTES
            && prove_hash(&message).is_err(),
        "legacy proof bound must remain closed",
    )?;
    let source_path = dir.join("body-source.json");
    let source = serde_json::json!({"version":1,"block":block,"receipts":c.receipts,
        "parent_root":c.parent_root,"current_root":c.current_root,"leaf_index":1});
    if !source_path.try_exists()? {
        write(&source_path, &source)?;
    }
    ensure(
        read::<serde_json::Value>(&source_path)? == source,
        "saved body source differs from inputs",
    )?;
    let path = dir.join("body-proof.json");
    let generated = !path.try_exists()?;
    if generated {
        write(&path, &prove_transaction_body(&block, 1)?)?;
    }
    let proof: TransactionBodyProof = read(&path)?;
    verify_transaction_body(&proof, &block.header, &c.second, 1)?;
    println!(
        "{}",
        serde_json::json!({"mode":"body-prove", "new_body_proof":generated,
        "full_signed_leaf_bytes":message.len(), "leaf_compressions":proof.leaf.compressions.len(),
        "parent_hashes":proof.parents.len(), "total_body_members":proof.path.total,
        "signature_graphs_regenerated":0, "legacy4096_profile_still_refuses":true})
    );
    Ok(())
}
fn body_verify(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    accepted: &Path,
    dir: &Path,
    refusals: bool,
    header_proof: Option<&shell_stark_prover::header_hash::BlockHeaderProof>,
) -> Result<(), Error> {
    use shell_stark_prover::{
        body_membership::{verify_transaction_body, TransactionBodyProof},
        canonical_signature::verify_body_bound_registered_signature,
    };
    let c = body_inputs(first, second, old, accepted, dir)?;
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let db = Arc::new(stores.state.clone());
    let before = db.scan_all()?;
    let chain = ChainStore::new(db.clone());
    let view = chain.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    let block = chain
        .get_block_by_hash(&c.hashes[2])?
        .ok_or("missing native batch")?;
    let body: TransactionBodyProof = read(&dir.join("body-proof.json"))?;
    let account: AccountStateProof = read(&old.join("second-account.json"))?;
    let signature = registered(second, second.proof.leaf.clone());
    if !refusals {
        let token = verify_body_bound_registered_signature(
            &view,
            &block.header,
            1,
            &c.second,
            &account,
            &signature,
            &body,
        )?;
        ensure(
            token.membership().block_hash() == block.hash()
                && token.membership().index() == 1
                && token.membership().total() == 2
                && token.signature().matches_transaction(&c.second),
            "body-bound token mismatch",
        )?;
        let anchored = header_proof
            .map(|proof| {
                shell_stark_prover::canonical_signature::bind_registered_signature_header(
                    token.clone(),
                    &block.header,
                    proof,
                    &c.hashes[2],
                )
            })
            .transpose()?;
        let verifier = anchored
            .as_ref()
            .map_or(token.signature(), |p| p.signature());
        if let Some(p) = &anchored {
            ensure(
                p.header().hash() == c.hashes[2] && p.body().membership().index() == 1,
                "header-bound token mismatch",
            )?;
            ensure(
                shell_stark_prover::canonical_signature::bind_registered_signature_header(
                    token.clone(),
                    &block.header,
                    header_proof.unwrap(),
                    &ShellHash::ZERO,
                )
                .is_err(),
                "unrelated expected header accepted",
            )?;
        }
        let mut world = view.world_state()?;
        validate_tx_for_import_at_block(
            &c.second,
            &mut world,
            &ChainStore::new(view.store()),
            verifier,
            10,
            None,
            &block.header,
        )?;
        // Re-execute the real batch with the exact body-bound verifier on its
        // second transaction. All writes stay inside a private historical overlay.
        let replay = Arc::new(OverlayStore::new(view.store()));
        let replay_chain = ChainStore::new(replay.clone());
        let world = WorldState::at_root(replay.clone(), &view.parent().state_root)?;
        let mut vm = ShellPqvm::new(ShellStateDb::new(world, replay_chain), 10);
        let mut replayed = Vec::new();
        let mut cumulative = 0;
        for (index, transaction) in [&c.first, &c.second].into_iter().enumerate() {
            let cs = ChainStore::new(replay.clone());
            if index == 0 {
                validate_tx_for_import_at_block(
                    transaction,
                    vm.state_db_mut().world_state_mut(),
                    &cs,
                    &MultiVerifier,
                    10,
                    None,
                    &block.header,
                )?;
            } else {
                validate_tx_for_import_at_block(
                    transaction,
                    vm.state_db_mut().world_state_mut(),
                    &cs,
                    verifier,
                    10,
                    None,
                    &block.header,
                )?;
            }
            let result = vm.execute_tx(transaction, &block.header, index as u32, cumulative)?;
            cumulative = result.receipt.cumulative_gas_used;
            commit_pqvm_state(&result, vm.state_db_mut())?;
            replayed.push(result.receipt);
        }
        ensure(
            replayed == c.receipts
                && cumulative == block.header.gas_used
                && vm.state_db_mut().world_state_mut().state_root()?
                    == ShellHash::from(c.current_root),
            "proof-backed native batch replay differs from persisted execution",
        )?;
        ChainStore::new(replay.clone()).verify_block_receipts_commitment(&block, &replayed)?;
        ensure(
            replay.commit().is_err(),
            "historical proof replay committed into frozen parent",
        )?;
        // Reject a second transaction after the first has already staged effects.
        let rollback = Arc::new(OverlayStore::new(view.store()));
        let cs = ChainStore::new(rollback.clone());
        let world = WorldState::at_root(rollback.clone(), &view.parent().state_root)?;
        let mut vm = ShellPqvm::new(ShellStateDb::new(world, cs), 10);
        validate_tx_for_import_at_block(
            &c.first,
            vm.state_db_mut().world_state_mut(),
            &ChainStore::new(rollback.clone()),
            &MultiVerifier,
            10,
            None,
            &block.header,
        )?;
        let result = vm.execute_tx(&c.first, &block.header, 0, 0)?;
        commit_pqvm_state(&result, vm.state_db_mut())?;
        let mut bad = c.second.clone();
        bad.tx.nonce += 1;
        ensure(
            validate_tx_for_import_at_block(
                &bad,
                vm.state_db_mut().world_state_mut(),
                &ChainStore::new(rollback.clone()),
                verifier,
                10,
                None,
                &block.header,
            )
            .is_err(),
            "invalid second batch transaction accepted",
        )?;
        drop(vm);
        drop(rollback);
        let mut current = WorldState::at_root(db.clone(), &ShellHash::from(c.current_root))?;
        ensure(
            validate_tx_for_import_at_block(
                &c.second,
                &mut current,
                &chain,
                verifier,
                10,
                None,
                &block.header,
            )
            .is_err(),
            "advanced nonce replay accepted",
        )?;
        ensure(
            before == db.scan_all()?,
            "body signature verification wrote base KV",
        )?;
        println!(
            "{}",
            serde_json::json!({"mode":"body-verify", "genuine_registered_Embedded_signature_and_body_AIR":true,
            "native_import_policy_uses_body_bound_proof_verifier":true, "native_batch_transfers":2,
            "current_nonce_replay_rejected":true, "proof_backed_native_batch_replayed":true,
            "invalid_second_transaction_rolls_back":true, "historical_replay_commit_refused":true,
            "base_KV_unchanged":true, "header_hash_AIR":anchored.is_some(), "consensus_proved":false})
        );
        return Ok(());
    }
    let mut rejected = Vec::new();
    for kind in [
        "signature",
        "embedded_key",
        "reference_mode",
        "intent",
        "wrong_index",
        "count",
        "missing_sibling",
        "extra_sibling",
        "missing_parent",
        "extra_parent",
        "leaf_version",
        "root_version",
        "compression_counter",
        "wrong_header",
        "wrong_parent",
    ] {
        let mut changed = body.clone();
        let mut signed = c.second.clone();
        let mut header = block.header.clone();
        let mut index = 1;
        match kind {
            "signature" => signed.signature.data[0] ^= 1,
            "embedded_key" => {
                if let PubkeyMode::Embedded(ref mut key) = signed.pubkey_mode {
                    key[0] ^= 1;
                }
            }
            "reference_mode" => signed.pubkey_mode = PubkeyMode::Reference,
            "intent" => signed.tx.value += U256::from(1),
            "wrong_index" => index = 0,
            "count" => changed.path.total += 1,
            "missing_sibling" => changed.path.siblings.clear(),
            "extra_sibling" => changed.path.siblings.push(ShellHash::ZERO),
            "missing_parent" => changed.parents.clear(),
            "extra_parent" => changed.parents.push(changed.parents[0].clone()),
            "leaf_version" => changed.leaf.version = 1,
            "root_version" => changed.root.version = 2,
            "compression_counter" => changed.leaf.compressions[0].input.counter += 1,
            "wrong_header" => header.receipts_root = ShellHash::ZERO,
            _ => header.parent_hash = ShellHash::ZERO,
        }
        ensure(
            verify_body_bound_registered_signature(
                &view, &header, index, &signed, &account, &signature, &changed,
            )
            .is_err(),
            &format!("accepted {kind}"),
        )?;
        rejected.push(kind);
    }
    // A mathematically valid membership proof still needs the captured activation.
    let copy = Arc::new(MemoryDb::new());
    for (k, v) in &before {
        copy.put(k, v)?;
    }
    let mutable = ChainStore::new(copy.clone());
    let mut config = mutable.get_chain_config()?.ok_or("missing config")?;
    config.block_commitment_height = None;
    copy.put(b"CFG", &serde_json::to_vec(&config)?)?;
    let unscheduled = mutable.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    verify_transaction_body(&body, &block.header, &c.second, 1)?;
    ensure(
        verify_body_bound_registered_signature(
            &unscheduled,
            &block.header,
            1,
            &c.second,
            &account,
            &signature,
            &body,
        )
        .is_err(),
        "unscheduled body profile accepted",
    )?;
    rejected.push("unscheduled_profile");
    config.block_commitment_height = Some(3);
    copy.put(b"CFG", &serde_json::to_vec(&config)?)?;
    let before_activation = mutable.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    ensure(
        verify_body_bound_registered_signature(
            &before_activation,
            &block.header,
            1,
            &c.second,
            &account,
            &signature,
            &body,
        )
        .is_err(),
        "body proof accepted before activation",
    )?;
    rejected.push("before_activation");
    config.block_commitment_height = None;
    copy.put(b"CFG", &serde_json::to_vec(&config)?)?;
    // Later live registry/configuration changes cannot replace the frozen header/context.
    let frozen = ChainStore::new(copy.clone()).canonical_parent_view(c.hashes[2], c.hashes[1])?;
    // The unscheduled frozen view remains rejected even after the live schedule changes.
    config.block_commitment_height = Some(1);
    copy.put(b"CFG", &serde_json::to_vec(&config)?)?;
    ensure(
        verify_body_bound_registered_signature(
            &frozen,
            &block.header,
            1,
            &c.second,
            &account,
            &signature,
            &body,
        )
        .is_err(),
        "live activation leaked into frozen view",
    )?;
    rejected.push("live_schedule_substitution");
    let valid = mutable.canonical_parent_view(c.hashes[2], c.hashes[1])?;
    mutable.put_pubkey(&c.second.from, &c.first_key)?;
    mutable.set_head(&c.hashes[0])?;
    copy.put(b"CFG", b"bad")?;
    copy.put(&[b"h/".as_slice(), c.hashes[2].as_bytes()].concat(), b"bad")?;
    ensure(
        mutable.get_header_by_hash(&c.hashes[2]).is_err(),
        "live header corruption control did not reach the retained header",
    )?;
    let changed_live = copy.scan_all()?;
    verify_body_bound_registered_signature(
        &valid,
        &block.header,
        1,
        &c.second,
        &account,
        &signature,
        &body,
    )?;
    ensure(
        changed_live == copy.scan_all()?,
        "frozen body verification wrote changed live state",
    )?;
    ensure(before == db.scan_all()?, "refusals wrote original KV")?;
    println!(
        "{}",
        serde_json::json!({"mode":"body-check-rejections", "rejected":rejected,
        "base_KV_unchanged":true, "signature_graphs_regenerated":0})
    );
    Ok(())
}
fn header_refusals(
    proof: &shell_stark_prover::header_hash::BlockHeaderProof,
    header: &BlockHeader,
    hash: &ShellHash,
) -> Result<(), Error> {
    use shell_stark_prover::header_hash::verify_header_hash;
    let mut rejected = Vec::new();
    ensure(
        verify_header_hash(proof, header, &ShellHash::ZERO).is_err(),
        "wrong expected header accepted",
    )?;
    rejected.push("expected_hash".to_string());
    let value = serde_json::to_value(header)?;
    let mut fields: Vec<String> = value
        .as_object()
        .ok_or("header object absent")?
        .keys()
        .cloned()
        .collect();
    if !fields.iter().any(|f| f == "witness_root") {
        fields.push("witness_root".into());
    }
    for field in fields {
        let mut changed = value.clone();
        let old = &changed[&field];
        changed[&field] = if let Some(n) = old.as_u64() {
            serde_json::json!(n ^ 1)
        } else if field == "witness_root" && old.is_null() {
            serde_json::json!(format!("0x{}", "01".repeat(32)))
        } else if let Some(bytes) = old.as_str() {
            let mut bytes = bytes.to_string();
            if bytes.len() == 2 {
                bytes.push_str("01");
            } else {
                let bit = if &bytes[2..3] == "0" { "1" } else { "0" };
                bytes.replace_range(2..3, bit);
            }
            serde_json::json!(bytes)
        } else {
            serde_json::json!("0x01")
        };
        let header: BlockHeader = serde_json::from_value(changed)?;
        ensure(
            verify_header_hash(proof, &header, hash).is_err(),
            &format!("header field {field} accepted"),
        )?;
        rejected.push(format!("field_{field}"));
    }
    for kind in [
        "version",
        "canonical_version",
        "nested_version",
        "missing_compression",
        "extra_compression",
        "counter",
        "operation",
        "proof_bytes",
        "aggregate_presence",
    ] {
        let mut p = proof.clone();
        match kind {
            "version" => p.version += 1,
            "canonical_version" => p.canonical.version += 1,
            "nested_version" => p.logs_bloom.version = 2,
            "missing_compression" => {
                p.canonical.compressions.pop();
            }
            "extra_compression" => p
                .canonical
                .compressions
                .push(p.canonical.compressions[0].clone()),
            "counter" => p.canonical.compressions[0].input.counter += 1,
            "operation" => p.extra_data.compressions[0].operations[0] ^= 1,
            "proof_bytes" => p.canonical.compressions[0].proof_bytes[0] ^= 1,
            _ => p.sig_aggregate_proof = Some(p.extra_data.clone()),
        }
        ensure(
            verify_header_hash(&p, header, hash).is_err(),
            &format!("header proof {kind} accepted"),
        )?;
        rejected.push(kind.to_string());
    }
    for field in ["logs_bloom", "extra_data", "sig_aggregate_proof"] {
        let mut changed = value.clone();
        changed[field] = serde_json::json!(format!("0x{}", "00".repeat(4097)));
        let header: BlockHeader = serde_json::from_value(changed)?;
        ensure(
            verify_header_hash(proof, &header, hash).is_err(),
            "overbound field accepted",
        )?;
        rejected.push(format!("overbound_{field}"));
    }
    println!(
        "{}",
        serde_json::json!({"mode":"header-check-rejections", "rejected":rejected,
        "certificates_regenerated":0,"consensus_proved":false})
    );
    Ok(())
}
fn header_checkpoint(
    first: &LoadedEntry,
    second: &LoadedEntry,
    old: &Path,
    accepted: &Path,
    body_dir: &Path,
    output: &Path,
    mode: &str,
) -> Result<(), Error> {
    use shell_stark_prover::header_hash::{
        prove_header_hash, verify_header_hash, BlockHeaderProof,
    };
    let c = body_inputs(first, second, old, accepted, body_dir)?;
    let stores = RocksDbStore::open_all(body_dir.join("native-db"), None)?;
    let db = Arc::new(stores.state.clone());
    let before = db.scan_all()?;
    let chain = ChainStore::new(db.clone());
    let header = chain
        .get_header_by_hash(&c.hashes[2])?
        .ok_or("missing native header")?;
    let source = serde_json::json!({"version":1,"header":header,"expected_hash":c.hashes[2]});
    let source_path = output.join("header-source.json");
    let proof_path = output.join("header-proof.json");
    let generate = mode == "header-prove";
    let generated = generate && !proof_path.try_exists()?;
    if generate {
        std::fs::create_dir_all(output)?;
        if !source_path.try_exists()? {
            write(&source_path, &source)?;
        }
        ensure(
            read::<serde_json::Value>(&source_path)? == source,
            "saved header source differs",
        )?;
        if generated {
            write(&proof_path, &prove_header_hash(&header)?)?;
        }
    }
    ensure(
        read::<serde_json::Value>(&source_path)? == source,
        "header source/hash differs from retained native fixture",
    )?;
    let proof: BlockHeaderProof = read(&proof_path)?;
    verify_header_hash(&proof, &header, &c.hashes[2])?;
    if mode == "header-check-rejections" {
        header_refusals(&proof, &header, &c.hashes[2])?;
        ensure(before == db.scan_all()?, "header refusals wrote base KV")?;
        return Ok(());
    }
    ensure(before == db.scan_all()?, "header hashing wrote base KV")?;
    // Release RocksDB before the existing native history regression opens it.
    drop(chain);
    drop(db);
    drop(stores);
    body_verify(first, second, old, accepted, body_dir, false, Some(&proof))?;
    println!(
        "{}",
        serde_json::json!({"mode":if generate {"header-prove"} else {"header-verify"},
        "new_header_proof":generated,"header_hash_AIR":true,"canonical_bytes":proof.canonical.message.len(),
        "expected_hash":c.hashes[2],"compression_certificates":proof.canonical.compressions.len()
            + proof.logs_bloom.compressions.len() + proof.extra_data.compressions.len()
            + proof.sig_aggregate_proof.as_ref().map_or(0, |p| p.compressions.len()),
        "signature_graphs_regenerated":0,"body_certificates_regenerated":0,"consensus_proved":false})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    let header = a.first().is_some_and(|mode| mode.starts_with("header-"));
    let body = header || a.first().is_some_and(|mode| mode.starts_with("body-"));
    ensure(a.len() == if header { 8 } else if body { 7 } else { 6 }, "usage: mldsa-canonical operation first-graph second-graph old-state-dir registered-dir [accepted-canonical-dir] output-dir")?;
    let (first, _, _) = graph::load(Path::new(&a[1]))?;
    let (second, _, _) = graph::load(Path::new(&a[2]))?;
    let old = Path::new(&a[3]);
    let registered = Path::new(&a[4]);
    let dir = Path::new(&a[if body { 6 } else { 5 }]);
    match a[0].as_str() {
        "init" => init(&first, &second, old, dir, false),
        "prove" => prove(&first, &second, old, registered, dir),
        "verify" => verify(&first, &second, old, dir),
        "check-rejections" => rejections(&first, &second, old, dir),
        "reopen" => reopen(dir),
        "header-prove" | "header-verify" | "header-check-rejections" => header_checkpoint(
            &first,
            &second,
            old,
            Path::new(&a[5]),
            dir,
            Path::new(&a[7]),
            &a[0],
        ),
        "header-reopen" => reopen(dir),
        "body-init" => init(&first, &second, old, dir, true),
        "body-prove" => body_prove(&first, &second, old, Path::new(&a[5]), dir),
        "body-verify" => body_verify(&first, &second, old, Path::new(&a[5]), dir, false, None),
        "body-check-rejections" => {
            body_verify(&first, &second, old, Path::new(&a[5]), dir, true, None)
        }
        "body-reopen" => reopen(dir),
        _ => Err("unknown canonical proof operation".into()),
    }
}
