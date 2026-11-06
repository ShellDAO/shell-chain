//! Registered account proofs exercised through the native transaction runtime.
#[path = "common/mldsa_batch.rs"]
mod graph;
#[path = "common/mldsa_source.rs"]
mod source;

use graph::LoadedEntry;
use serde::{Deserialize, Serialize};
use shell_core::{Account, Block, BlockHeader, PubkeyMode, SignedTransaction, TransactionReceipt};
use shell_crypto::{SignatureType, Verifier};
use shell_pqvm::{
    commit_pqvm_state, validate_tx, validate_tx_for_import_at_block, ShellPqvm, ShellStateDb,
};
use shell_primitives::{blake3_hash, keccak256, Address, ShellHash, U256};
use shell_stark_prover::{
    account_state::{verify_account_state, AccountStateProof},
    blake3_hash::{prove_hash, verify_hash, Blake3HashProof},
    registered_signature::{
        verify_registered_signature_entry, RegisteredSignatureProof, VerifiedRegisteredSignature,
    },
    shake_sponge::{prove_keccak256, verify_keccak256, ShakeProof},
    SigBatchEntry,
};
use shell_storage::{
    ChainConfig, ChainStore, KvStore, MerkleTrie, OverlayStore, RocksDbStore, WorldState,
};
use source::{read, write, Error};
use std::{path::Path, sync::Arc};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    role: String,
    root: [u8; 32],
    address: [u8; 32],
    account: Option<Account>,
    nodes: Vec<Vec<u8>>,
}
#[derive(Deserialize)]
struct OldSource {
    queries: Vec<Query>,
    current_root: [u8; 32],
    current_first: Account,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    version: u8,
    queries: Vec<Query>,
}
fn ensure(ok: bool, message: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn context(dir: &Path) -> Result<Context, Error> {
    let c: Context = read(&dir.join("registered-source.json"))?;
    ensure(
        c.version == 1 && c.queries.len() == 6,
        "invalid registered source shape",
    )?;
    for (index, (q, role)) in c
        .queries
        .iter()
        .zip([
            "raw-original",
            "raw-retained",
            "tagged-retained",
            "custom-validator",
            "unbound-account",
            "absent-account",
        ])
        .enumerate()
    {
        ensure(
            q.role == role
                && q.account.is_some() == (index < 5)
                && (index == 5 || q.address == c.queries[0].address),
            "invalid registered source roles",
        )?;
    }
    Ok(c)
}
fn init(first: &LoadedEntry, second: &LoadedEntry, old: &Path, dir: &Path) -> Result<(), Error> {
    first.verify()?;
    second.verify()?;
    ensure(
        first.expected.tx == second.expected.tx,
        "fixture requires the same ordinary signed payload",
    )?;
    std::fs::create_dir_all(dir)?;
    if dir.join("registered-source.json").try_exists()? {
        context(dir)?;
        return Ok(());
    }
    ensure(
        !dir.join("witness-db").try_exists()?,
        "partial fixture exists; refusing to overwrite",
    )?;
    let previous: OldSource = read(&old.join("state-source.json"))?;
    let original = &previous.queries[0];
    ensure(
        original.address == *first.expected.from.as_bytes(),
        "old account sender mismatch",
    )?;
    let mut queries = vec![Query {
        role: "raw-original".into(),
        ..original.clone()
    }];
    {
        let old_stores = RocksDbStore::open_all(old.join("native-db"), None)?;
        let old_before = old_stores.state.scan_all()?;
        let stores = RocksDbStore::open_all(dir.join("witness-db"), None)?;
        let db = Arc::new(stores.state.clone());
        for (key, value) in &old_before {
            db.put(key, value)?;
        }
        let mut world = WorldState::at_root(Arc::clone(&db), &ShellHash::from(original.root))?;
        for (role, hash) in [
            ("raw-retained", second.key_hash),
            ("tagged-retained", *second.expected.from.as_bytes()),
        ] {
            let mut account = original.account.clone().ok_or("old account absent")?;
            account.pq_pubkey_hash = ShellHash::from(hash);
            world.set_account(&first.expected.from, &account)?;
            let root = *world.state_root()?.as_bytes();
            let key = keccak256(first.expected.from.as_bytes());
            let nodes = MerkleTrie::at_root(Arc::clone(&db), &root)?.get_proof(key.as_bytes())?;
            queries.push(Query {
                role: role.into(),
                root,
                address: original.address,
                account: Some(account),
                nodes,
            });
        }
        let key = keccak256(first.expected.from.as_bytes());
        let custom_nodes = MerkleTrie::at_root(Arc::clone(&db), &previous.current_root)?
            .get_proof(key.as_bytes())?;
        queries.push(Query {
            role: "custom-validator".into(),
            root: previous.current_root,
            address: original.address,
            account: Some(previous.current_first),
            nodes: custom_nodes,
        });
        let mut unbound = original.account.clone().ok_or("old account absent")?;
        unbound.pq_pubkey_hash = ShellHash::ZERO;
        world.set_account(&first.expected.from, &unbound)?;
        let root = *world.state_root()?.as_bytes();
        let nodes = MerkleTrie::at_root(Arc::clone(&db), &root)?.get_proof(key.as_bytes())?;
        queries.push(Query {
            role: "unbound-account".into(),
            root,
            address: original.address,
            account: Some(unbound),
            nodes,
        });
        queries.push(Query {
            role: "absent-account".into(),
            ..previous.queries[2].clone()
        });
        db.flush()?;
        ensure(
            old_before == old_stores.state.scan_all()?,
            "old native fixture changed",
        )?;
    }
    write(
        &dir.join("registered-source.json"),
        &Context {
            version: 1,
            queries,
        },
    )?;
    println!(
        "{}",
        serde_json::json!({"mode":"init","genuine_signatures":2,"same_unsigned_payload":true,"retained_address_state_fixture":true,"rotation_transaction_lifecycle_proved":false,"old_fixture_unchanged":true})
    );
    Ok(())
}
fn hash_checkpoint(
    old: &Path,
    dir: &Path,
    message: &[u8],
    generated: &mut usize,
) -> Result<ShakeProof, Error> {
    let output = keccak256(message);
    let name: String = output
        .as_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    let filename = format!("hash-{name}.json");
    let prior = old.join(&filename);
    let path = dir.join(&filename);
    let p = if prior.try_exists()? {
        read(&prior)?
    } else {
        if !path.try_exists()? {
            write(&path, &prove_keccak256(message)?)?;
            *generated += 1;
        }
        read(&path)?
    };
    verify_keccak256(&p, message, output.as_bytes())?;
    Ok(p)
}
fn prove(first: &LoadedEntry, old: &Path, dir: &Path) -> Result<(), Error> {
    let c = context(dir)?;
    let original: AccountStateProof = read(&old.join("first-account.json"))?;
    let mut generated = 0;
    for q in &c.queries {
        let path = dir.join(format!("{}.json", q.role));
        if !path.try_exists()? {
            let proof = if q.role == "raw-original" {
                original.clone()
            } else if q.role == "absent-account" {
                read(&old.join("branch-absence.json"))?
            } else {
                AccountStateProof {
                    version: 1,
                    address_hash: hash_checkpoint(old, dir, &q.address, &mut generated)?,
                    nodes: q
                        .nodes
                        .iter()
                        .map(|n| hash_checkpoint(old, dir, n, &mut generated))
                        .collect::<Result<_, _>>()?,
                }
            };
            verify_account_state(&proof, &q.root, &q.address, q.account.as_ref())?;
            write(&path, &proof)?;
        }
        let p = read(&path)?;
        verify_account_state(&p, &q.root, &q.address, q.account.as_ref())?;
    }
    let mut preimage = first.entry.msg_hash.to_vec();
    preimage.extend_from_slice(first.expected.from.as_bytes());
    let path = dir.join("reference-leaf.json");
    let new_leaf = !path.try_exists()?;
    if new_leaf {
        write(&path, &prove_hash(&preimage)?)?;
    }
    let p = read(&path)?;
    verify_hash(&p, &preimage, blake3_hash(&preimage).as_bytes())?;
    println!(
        "{}",
        serde_json::json!({"mode":"prove","new_keccak_certificates":generated,"new_reference_leaf":new_leaf,"prior_signature_graphs_regenerated":0})
    );
    Ok(())
}
struct Case {
    signed: SignedTransaction,
    key: Vec<u8>,
    proof: RegisteredSignatureProof,
    state_proof: AccountStateProof,
    query: Query,
    entry: SigBatchEntry,
    leaf: [u8; 32],
    id: [u8; 32],
}
impl Case {
    fn verify(&self) -> Result<VerifiedRegisteredSignature, Error> {
        let state = verify_account_state(
            &self.state_proof,
            &self.query.root,
            &self.query.address,
            self.query.account.as_ref(),
        )?;
        Ok(verify_registered_signature_entry(
            &self.proof,
            &self.signed,
            &self.key,
            &state,
            &self.id,
            &self.entry,
            &self.leaf,
        )?)
    }
}
fn case(
    first: &LoadedEntry,
    second: &LoadedEntry,
    dir: &Path,
    q: &Query,
    reference: bool,
) -> Result<Case, Error> {
    let signer = if matches!(
        q.role.as_str(),
        "raw-original" | "custom-validator" | "unbound-account" | "absent-account"
    ) {
        first
    } else {
        second
    };
    let key = signer
        .expected
        .pubkey_mode
        .pubkey_bytes()
        .ok_or("missing source key")?
        .to_vec();
    let mode = if reference {
        PubkeyMode::Reference
    } else {
        PubkeyMode::Embedded(key.clone())
    };
    // Construct a fresh transaction; cloning and mutating a cached ID is unsafe.
    let mut signed = SignedTransaction::new(
        Address::from(q.address),
        signer.expected.tx.clone(),
        signer.expected.signature.clone(),
    );
    signed.pubkey_mode = mode;
    ensure(
        signed.sender_signing_hash() == signer.expected.sender_signing_hash()
            && (q.account.is_none() || signed.hash().as_bytes() == &first.id),
        "native source/identity reuse mismatch",
    )?;
    let (entry, leaf_proof, leaf) = if reference {
        let p: Blake3HashProof = read(&dir.join("reference-leaf.json"))?;
        (
            SigBatchEntry {
                msg_hash: first.entry.msg_hash,
                pk_hash: *first.expected.from.as_bytes(),
            },
            p.clone(),
            p.output,
        )
    } else {
        (signer.entry.clone(), signer.proof.leaf.clone(), signer.leaf)
    };
    let native_entry = SigBatchEntry::from_signed_transaction(&signed);
    ensure(
        native_entry.msg_hash == entry.msg_hash
            && native_entry.pk_hash == entry.pk_hash
            && native_entry.to_leaf_bytes() == leaf,
        "native batch entry or leaf mapping mismatch",
    )?;
    let proof = RegisteredSignatureProof {
        version: 1,
        transaction: signer.proof.identified.sender.transaction.clone(),
        transaction_id: first.proof.identified.transaction_id.clone(),
        leaf: leaf_proof,
        tagged_key: if q.role == "tagged-retained" {
            Some(second.proof.identified.sender.sender_address.clone())
        } else {
            None
        },
    };
    Ok(Case {
        signed,
        key,
        proof,
        state_proof: read(&dir.join(format!("{}.json", q.role)))?,
        query: q.clone(),
        entry,
        leaf,
        id: first.id,
    })
}
fn header(root: [u8; 32]) -> BlockHeader {
    BlockHeader {
        parent_hash: ShellHash::ZERO,
        state_root: ShellHash::from(root),
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
fn config(genesis: ShellHash, tagged: bool) -> Result<ChainConfig, Error> {
    Ok(serde_json::from_value(
        serde_json::json!({"chain_id":10,"genesis_hash":genesis,"registered_key_algorithm_height":if tagged {Some(1)} else {None},"native_address_context_height":1,"fee_accounting_activation_height":1}),
    )?)
}
fn native_policy<S: KvStore + 'static>(
    case: &Case,
    token: &VerifiedRegisteredSignature,
    db: Arc<S>,
    h: &BlockHeader,
    admission: bool,
) -> Result<(), Error> {
    let chain = ChainStore::new(Arc::clone(&db));
    let parent = chain
        .get_head_block()?
        .ok_or("missing trusted local parent")?;
    ensure(
        token.matches_transaction(&case.signed)
            && token.account().root() == parent.header.state_root.as_bytes()
            && h.parent_hash == parent.hash(),
        "proof/native parent transaction context mismatch",
    )?;
    let mut world = WorldState::at_root(db, &parent.header.state_root)?;
    ensure(
        world.get_account(&case.signed.from)?.as_ref() == token.account().account(),
        "proof/native account mismatch",
    )?;
    validate_tx_for_import_at_block(&case.signed, &mut world, &chain, token, 10, None, h)?;
    if admission {
        ensure(
            validate_tx(&case.signed, &mut world, &chain, token, 10)? == case.key,
            "native resolved key mismatch",
        )?;
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRecord {
    transaction: SignedTransaction,
    key: Vec<u8>,
    configuration: ChainConfig,
    root: ShellHash,
    old_root: ShellHash,
    sender: Address,
    recipient: Address,
    before: Account,
    after: Account,
    receipt_key: ShellHash,
    receipt: TransactionReceipt,
}
fn record_matches(case: &Case, r: &ExecutionRecord) -> Result<(), Error> {
    ensure(
        r.transaction == case.signed
            && r.key == case.key
            && r.old_root.as_bytes() == &case.query.root
            && r.sender == case.signed.from
            && Some(r.recipient) == case.signed.tx.to
            && Some(&r.before) == case.query.account.as_ref()
            && r.receipt.tx_hash.as_bytes() == &case.id
            && r.configuration
                == config(
                    header(case.query.root).hash(),
                    case.query.role == "tagged-retained",
                )?,
        "saved execution inputs differ from the verified case",
    )
}
fn native_execute(
    case: &Case,
    token: &VerifiedRegisteredSignature,
    witness: &Path,
    dir: &Path,
) -> Result<(), Error> {
    std::fs::create_dir_all(dir)?;
    if dir.join("execution.json").try_exists()? {
        let record: ExecutionRecord = read(&dir.join("execution.json"))?;
        record_matches(case, &record)?;
        {
            let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
            let db = Arc::new(stores.state.clone());
            let before = db.scan_all()?;
            let parent = ChainStore::new(Arc::clone(&db))
                .get_head_block()?
                .ok_or("missing saved parent")?;
            let mut h = parent.header.clone();
            h.number = 1;
            h.parent_hash = parent.hash();
            native_policy(case, token, Arc::clone(&db), &h, false)?;
            ensure(
                before == db.scan_all()?,
                "saved native import validation wrote state",
            )?;
        }
        return reopen(dir);
    }
    ensure(
        !dir.join("native-db").try_exists()?,
        "partial execution exists; refusing to overwrite",
    )?;
    let record;
    {
        let source = RocksDbStore::open_all(witness.join("witness-db"), None)?;
        let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
        // One local CF backs both stores so the overlay commits this fixture's
        // account/registry/receipt writes together. This is not node block import.
        let db = Arc::new(stores.state.clone());
        for (key, value) in source.state.scan_all()? {
            db.put(&key, &value)?;
        }
        let chain = ChainStore::new(Arc::clone(&db));
        let genesis = Block {
            header: header(case.query.root),
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let cfg = config(genesis.hash(), case.query.role == "tagged-retained")?;
        chain.put_pubkey(&case.signed.from, &case.key)?;
        chain.commit_genesis_block(&genesis, &cfg)?;
        let mut h = genesis.header.clone();
        h.number = 1;
        h.parent_hash = genesis.hash();
        h.timestamp += 1;
        let before = db.scan_all()?;
        native_policy(case, token, Arc::clone(&db), &h, true)?;
        ensure(
            before == db.scan_all()?,
            "registered native admission/import validation wrote state",
        )?;
        // Execute a valid first member, then reject its repeated nonce. Dropping
        // the shared overlay must discard all earlier account/receipt writes.
        {
            let overlay = Arc::new(OverlayStore::new(Arc::clone(&db)));
            let world = WorldState::at_root(Arc::clone(&overlay), &genesis.header.state_root)?;
            let mut vm = ShellPqvm::new(
                ShellStateDb::new(world, ChainStore::new(Arc::clone(&overlay))),
                10,
            );
            let result = vm.execute_tx(&case.signed, &h, 0, 0)?;
            ensure(
                result.receipt.status == 1,
                "rollback first transaction failed",
            )?;
            commit_pqvm_state(&result, vm.state_db_mut())?;
            vm.state_db_mut().world_state_mut().state_root()?;
            let chain = ChainStore::new(Arc::clone(&overlay));
            chain.put_receipts(&h.hash(), std::slice::from_ref(&result.receipt))?;
            let result = validate_tx(
                &case.signed,
                vm.state_db_mut().world_state_mut(),
                &chain,
                token,
                10,
            );
            ensure(result.is_err(), "repeated nonce unexpectedly admitted")?;
        }
        ensure(
            before == db.scan_all()?,
            "failed batch leaked state or receipt writes",
        )?;
        let overlay = Arc::new(OverlayStore::new(Arc::clone(&db)));
        let world = WorldState::at_root(Arc::clone(&overlay), &genesis.header.state_root)?;
        let mut vm = ShellPqvm::new(
            ShellStateDb::new(world, ChainStore::new(Arc::clone(&overlay))),
            10,
        );
        let result = vm.execute_tx(&case.signed, &h, 0, 0)?;
        ensure(
            result.receipt.status == 1 && result.receipt.tx_hash.as_bytes() == &case.id,
            "native receipt mismatch",
        )?;
        commit_pqvm_state(&result, vm.state_db_mut())?;
        let world = vm.state_db_mut().world_state_mut();
        let root = world.state_root()?;
        let initial = case
            .query
            .account
            .clone()
            .ok_or("missing initial account")?;
        let after = world
            .get_account(&case.signed.from)?
            .ok_or("missing executed sender")?;
        let recipient = case.signed.tx.to.ok_or("fixture must transfer")?;
        let recipient_account = world
            .get_account(&recipient)?
            .ok_or("missing executed recipient")?;
        let price = case
            .signed
            .tx
            .max_fee_per_gas
            .min(h.base_fee_per_gas + case.signed.tx.max_priority_fee_per_gas);
        let charge = U256::from(result.receipt.gas_used) * U256::from(price);
        ensure(
            after.nonce == initial.nonce + 1
                && after.balance == initial.balance - charge - case.signed.tx.value
                && after.pq_pubkey_hash == initial.pq_pubkey_hash
                && recipient_account.balance == case.signed.tx.value,
            "native state/fee settlement mismatch",
        )?;
        let receipt_key = h.hash();
        ChainStore::new(Arc::clone(&overlay))
            .put_receipts(&receipt_key, std::slice::from_ref(&result.receipt))?;
        overlay.commit()?;
        db.flush()?;
        record = ExecutionRecord {
            transaction: case.signed.clone(),
            key: case.key.clone(),
            configuration: cfg,
            root,
            old_root: genesis.header.state_root,
            sender: case.signed.from,
            recipient,
            before: initial,
            after,
            receipt_key,
            receipt: result.receipt,
        };
    }
    write(&dir.join("execution.json"), &record)?;
    reopen(dir)?;
    println!(
        "{}",
        serde_json::json!({"mode":"native-execute","case":case.query.role,"reference":case.signed.pubkey_mode.is_reference(),"native_admission_and_import_validation":true,"gas_used":record.receipt.gas_used,"receipt_persisted_and_reopened":true,"batch_rollback":true,"consensus_block_import":false})
    );
    Ok(())
}
fn reopen(dir: &Path) -> Result<(), Error> {
    let r: ExecutionRecord = read(&dir.join("execution.json"))?;
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let db = Arc::new(stores.state.clone());
    let before = db.scan_all()?;
    let current = WorldState::at_root(Arc::clone(&db), &r.root)?;
    let old = WorldState::at_root(Arc::clone(&db), &r.old_root)?;
    ensure(
        current.get_account(&r.sender)? == Some(r.after.clone())
            && old.get_account(&r.sender)? == Some(r.before)
            && current
                .get_account(&r.recipient)?
                .is_some_and(|a| a.balance == U256::from(1u64)),
        "reopened current/history mismatch",
    )?;
    let chain = ChainStore::new(Arc::clone(&db));
    ensure(
        chain.get_chain_config()? == Some(r.configuration.clone())
            && chain.get_pubkey(&r.sender)? == Some(r.key.clone()),
        "saved native configuration or registry mismatch",
    )?;
    ensure(
        ChainStore::new(Arc::clone(&db)).get_receipts(&r.receipt_key)? == Some(vec![r.receipt]),
        "reopened receipt mismatch",
    )?;
    ensure(before == db.scan_all()?, "historical read changed state KV")?;
    Ok(())
}
fn rejections(
    case: &Case,
    token: &VerifiedRegisteredSignature,
    second: &LoadedEntry,
    dir: &Path,
) -> Result<(), Error> {
    let mut rejected = Vec::new();
    let saved: ExecutionRecord = read(&dir.join("execution.json"))?;
    record_matches(case, &saved)?;
    for field in [
        "saved_transaction_mode",
        "saved_public_key",
        "saved_configuration",
        "saved_parent_root",
    ] {
        let mut changed = saved.clone();
        match field {
            "saved_transaction_mode" => {
                changed.transaction.pubkey_mode = if case.signed.pubkey_mode.is_reference() {
                    PubkeyMode::Embedded(case.key.clone())
                } else {
                    PubkeyMode::Reference
                }
            }
            "saved_public_key" => changed.key[0] ^= 1,
            "saved_configuration" => changed.configuration.chain_id += 1,
            _ => changed.old_root = ShellHash::ZERO,
        }
        ensure(
            record_matches(case, &changed).is_err(),
            "foreign saved execution accepted",
        )?;
        rejected.push(field.to_string());
    }
    for (name, mutated) in [
        ("signature_bytes", 0),
        ("signing_message", 1),
        ("key_bytes", 2),
        ("algorithm", 3),
    ] {
        let mut key = case.key.clone();
        let mut message = case.entry.msg_hash;
        let mut sig = case.signed.signature.clone();
        match mutated {
            0 => sig.data[0] ^= 1,
            1 => message[0] ^= 1,
            2 => key[0] ^= 1,
            _ => sig.sig_type = SignatureType::SphincsSha2256f,
        }
        ensure(
            !token.verify(&key, &message, &sig)?,
            "crypto adapter accepted foreign tuple",
        )?;
        rejected.push(name.to_string());
    }
    let mut signed = case.signed.clone();
    let cached = signed.hash();
    signed.from = second.expected.from;
    ensure(
        signed.hash() == cached && !token.matches_transaction(&signed),
        "cached ID hid sender mutation",
    )?;
    rejected.push("cached_id_sender_mutation".into());
    let state = verify_account_state(
        &case.state_proof,
        &case.query.root,
        &case.query.address,
        case.query.account.as_ref(),
    )?;
    for kind in [
        "proof_version",
        "ID",
        "leaf",
        "entry_key",
        "signature_arithmetic",
        "unsigned_value",
        "account_sender",
        "raw_key_binding",
        "witness_mode",
    ] {
        let mut proof = case.proof.clone();
        let mut signed = case.signed.clone();
        let mut id = case.id;
        let mut leaf = case.leaf;
        let mut entry = case.entry.clone();
        match kind {
            "proof_version" => proof.version += 1,
            "ID" => id[0] ^= 1,
            "leaf" => leaf[0] ^= 1,
            "entry_key" => entry.pk_hash[0] ^= 1,
            "signature_arithmetic" => signed.signature.data[0] ^= 1,
            "unsigned_value" => signed.tx.value += U256::from(1u64),
            "account_sender" => signed.from = second.expected.from,
            "raw_key_binding" => {
                proof.tagged_key = None;
                proof.transaction.public_key_hash.output[0] ^= 1;
            }
            _ => {
                signed.pubkey_mode = if signed.pubkey_mode.is_reference() {
                    PubkeyMode::Embedded(case.key.clone())
                } else {
                    PubkeyMode::Reference
                }
            }
        }
        ensure(
            verify_registered_signature_entry(
                &proof, &signed, &case.key, &state, &id, &entry, &leaf,
            )
            .is_err(),
            &format!("accepted {kind}"),
        )?;
        rejected.push(kind.to_string());
    }
    // Native policy uses the actual stored registry/config and candidate header.
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    let db = Arc::new(stores.state.clone());
    let before = db.scan_all()?;
    let genesis = ChainStore::new(Arc::clone(&db))
        .get_head_block()?
        .ok_or("missing native genesis")?;
    let mut h = genesis.header.clone();
    h.number = 1;
    h.parent_hash = genesis.hash();
    for kind in [
        "missing_registry",
        "foreign_registry",
        "wrong_parent",
        "tagged_before_activation",
    ] {
        if kind == "tagged_before_activation" && case.query.role != "tagged-retained" {
            continue;
        }
        let overlay = Arc::new(OverlayStore::new(Arc::clone(&db)));
        let chain = ChainStore::new(Arc::clone(&overlay));
        let mut candidate = h.clone();
        match kind {
            "missing_registry" => {
                let mut key = b"pk/".to_vec();
                key.extend_from_slice(case.signed.from.as_bytes());
                overlay.delete(&key)?;
            }
            "foreign_registry" => {
                chain.put_pubkey(
                    &case.signed.from,
                    &second
                        .expected
                        .pubkey_mode
                        .pubkey_bytes()
                        .ok_or("missing foreign key")?
                        .iter()
                        .map(|b| b ^ 1)
                        .collect::<Vec<_>>(),
                )?;
            }
            "wrong_parent" => candidate.parent_hash = ShellHash::ZERO,
            _ => candidate.number = 0,
        }
        let result = native_policy(case, token, Arc::clone(&overlay), &candidate, true);
        if kind == "missing_registry"
            && case.query.role == "raw-original"
            && case.signed.pubkey_mode.is_embedded()
        {
            result?;
            ensure(
                chain.get_pubkey(&case.signed.from)? == Some(case.key.clone()),
                "native first-use registration missing",
            )?;
        } else {
            ensure(result.is_err(), &format!("accepted {kind}"))?;
            rejected.push(kind.to_string());
        }
    }
    if case.query.role == "raw-original" && case.signed.pubkey_mode.is_embedded() {
        let overlay = Arc::new(OverlayStore::new(Arc::clone(&db)));
        let chain = ChainStore::new(Arc::clone(&overlay));
        let mut key = b"pk/".to_vec();
        key.extend_from_slice(case.signed.from.as_bytes());
        overlay.delete(&key)?;
        let mut world = WorldState::at_root(Arc::clone(&overlay), &genesis.header.state_root)?;
        let mut poor = case.query.account.clone().ok_or("missing account")?;
        poor.balance = U256::ZERO;
        world.set_account(&case.signed.from, &poor)?;
        ensure(
            validate_tx(&case.signed, &mut world, &chain, token, 10).is_err()
                && chain.get_pubkey(&case.signed.from)?.is_none(),
            "failed funding gate registered a key",
        )?;
        rejected.push("insufficient_funds_no_first_registration".into());
    }
    if case.query.role == "tagged-retained" {
        let isolated = Arc::new(shell_storage::MemoryDb::new());
        // Copy immutable trie data, then initialize a distinct local chain with
        // the tagged-key feature omitted. No existing chain config is changed.
        for (key, value) in db.scan_all()? {
            if key.len() == 32 {
                isolated.put(&key, &value)?;
            }
        }
        let chain = ChainStore::new(Arc::clone(&isolated));
        chain.put_pubkey(&case.signed.from, &case.key)?;
        chain.commit_genesis_block(&genesis, &config(genesis.hash(), false)?)?;
        ensure(
            native_policy(case, token, isolated, &h, true).is_err(),
            "tagged key admitted with feature disabled",
        )?;
        rejected.push("tagged_default_disabled".into());
    }
    ensure(
        before == db.scan_all()?,
        "negative native policy wrote base state",
    )?;
    println!(
        "{}",
        serde_json::json!({"mode":"check-rejections","case":case.query.role,"reference":case.signed.pubkey_mode.is_reference(),"rejected":rejected,"base_KV_unchanged":true})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure(args.len()==5,"usage: mldsa-registered init|prove|verify|check-rejections|native-execute first-graph second-graph old-state-dir registered-dir")?;
    let (first, _, _) = graph::load(Path::new(&args[1]))?;
    let (second, _, _) = graph::load(Path::new(&args[2]))?;
    let old = Path::new(&args[3]);
    let dir = Path::new(&args[4]);
    match args[0].as_str() {
        "init" => init(&first, &second, old, dir),
        "prove" => prove(&first, old, dir),
        mode @ ("verify" | "check-rejections" | "native-execute") => {
            let c = context(dir)?;
            for q in c.queries.iter().take(3) {
                for reference in [false, true] {
                    let case = case(&first, &second, dir, q, reference)?;
                    let token = case.verify()?;
                    let path = dir.join(format!(
                        "native-{}-{}",
                        q.role,
                        if reference { "reference" } else { "embedded" }
                    ));
                    match mode {
                        "native-execute" => native_execute(&case, &token, dir, &path)?,
                        "check-rejections" => rejections(&case, &token, &second, &path)?,
                        _ => {
                            ensure(
                                token.matches_transaction(&case.signed)
                                    && token.verify(
                                        &case.key,
                                        &case.entry.msg_hash,
                                        &case.signed.signature,
                                    )?,
                                "proof token binding mismatch",
                            )?;
                        }
                    }
                }
            }
            for q in c.queries.iter().skip(3) {
                let c = case(&first, &second, dir, q, false)?;
                ensure(
                    c.verify().is_err(),
                    &format!("accepted unsupported profile {}", q.role),
                )?;
            }
            println!(
                "{}",
                serde_json::json!({"mode":mode,"verified_registered_cases":6,"unsupported_profiles_rejected":3,"registry_commitment_proved":false,"network_activation":false})
            );
            Ok(())
        }
        _ => Err("unknown registered proof operation".into()),
    }
}
