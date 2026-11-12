//! Fresh raw-source producer fixture and independent native execution control.
#[path = "common/canonical_admission_runtime.rs"]
mod admission_runtime;
#[allow(dead_code)]
#[path = "common/canonical_proof_fixture.rs"]
mod fixture;
#[path = "common/canonical_production_runtime.rs"]
mod runtime;
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_source.rs"]
mod source;
use serde_json::{json, Value};
use shell_core::{Account, Block, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, MlDsaSigner, MultiVerifier, Signer};
use shell_node::{builder::NodeBuilder, ConsensusEngineConfig, NodeConfig};
use shell_primitives::{blake3_hash, Address, ShellHash, U256};
use shell_storage::{ChainConfig, ChainStore, KvStore, RocksDbStore, WorldState};
use source::{read, write, Error};
use std::{path::Path, sync::Arc};
fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn digest(db: &impl KvStore) -> Result<ShellHash, Error> {
    Ok(blake3_hash(&serde_json::to_vec(&db.scan_all()?)?))
}
fn sender_addresses(block: &Block) -> Vec<Address> {
    let mut addresses: Vec<_> = block.transactions.iter().map(|tx| tx.from).collect();
    addresses.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    addresses.dedup();
    addresses
}
fn accounts(store: Arc<RocksDbStore>, block: &Block) -> Result<Value, Error> {
    let world = WorldState::at_root(store, &block.header.state_root)?;
    let tx = block
        .transactions
        .first()
        .ok_or("fixture transaction missing")?;
    let mut rows = Vec::new();
    let mut addresses = sender_addresses(block);
    addresses.extend([tx.tx.to.ok_or("recipient missing")?, block.header.proposer]);
    for address in addresses {
        rows.push(json!({"address":address,"nonce":world.get_nonce(&address)?,"balance":world.get_balance(&address)?}));
    }
    Ok(json!(rows))
}
fn prepare(
    out: &Path,
    automatic: bool,
    capture_on_production: bool,
    full: bool,
    batch_count: usize,
    sender_count: usize,
    unbound_count: usize,
) -> Result<(), Error> {
    let first_use = unbound_count > 0;
    ensure(
        matches!(sender_count, 1 | 2 | 8 | 16)
            && unbound_count <= sender_count
            && (sender_count == 1 || batch_count == 16 && full),
        "invalid registered sender profile",
    )?;
    let batch = batch_count > 1;
    let count = if batch { batch_count as u64 } else { 1 };
    let funding = if batch_count > 2 {
        2_000_000u64
    } else {
        1_000_000u64
    };
    if out.exists() {
        ensure(
            out.is_dir() && !out.symlink_metadata()?.file_type().is_symlink(),
            "invalid fixture output",
        )?;
        for entry in std::fs::read_dir(out)? {
            let entry = entry?;
            ensure(
                entry.file_name() == "commands" && entry.file_type()?.is_dir(),
                "output contains existing source/checkpoint data; refusing replacement",
            )?;
        }
    } else {
        std::fs::create_dir(out)?;
    }
    if batch_count > 2 {
        write(&out.join("initial-funding.json"), &funding)?;
    }
    let senders: Vec<_> = (0..sender_count).map(|_| MlDsaSigner::generate()).collect();
    let sender = &senders[0];
    let proposer: Box<dyn Signer> = if full {
        Box::new(MlDsaSigner::generate())
    } else {
        Box::new(DilithiumSigner::generate())
    };
    let address = Address::from_public_key(sender.public_key(), sender.sig_type().as_u8());
    let addresses: Vec<_> = senders
        .iter()
        .map(|s| Address::from_public_key(s.public_key(), s.sig_type().as_u8()))
        .collect();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    let recipient = Address::from([0x11; 32]);
    ensure(
        addresses.iter().all(|a| *a != authority && *a != recipient)
            && addresses
                .iter()
                .enumerate()
                .all(|(i, a)| !addresses[..i].contains(a))
            && authority != recipient,
        "fixture actor collision",
    )?;
    let mut native = None;
    let mut native_checkpoint = None;
    let mut genesis_hash = None;
    let roles: &[&str] = if batch {
        &["native"]
    } else {
        &["native", "follower"]
    };
    for &role in roles {
        let stores = RocksDbStore::open_all(out.join(role).join("db"), None)?;
        let store = Arc::new(stores.state.clone());
        let mut world = WorldState::new(store.clone());
        for (index, (sender, address)) in senders.iter().zip(&addresses).enumerate() {
            world.set_account(
                address,
                &Account::new_user_account(
                    if index < unbound_count {
                        ShellHash::ZERO
                    } else {
                        blake3_hash(sender.public_key())
                    },
                    U256::from(funding),
                ),
            )?;
        }
        let genesis = Block {
            header: BlockHeader {
                state_root: world.state_root()?,
                timestamp: 1_700_000_000,
                gas_limit: 30_000_000,
                base_fee_per_gas: 1,
                proposer: authority,
                ..Default::default()
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        if let Some(hash) = genesis_hash {
            ensure(hash == genesis.hash(), "independent genesis differs")?;
        } else {
            genesis_hash = Some(genesis.hash());
        }
        let chain = ChainStore::new(store.clone());
        for (index, (sender, address)) in senders.iter().zip(&addresses).enumerate() {
            if index >= unbound_count {
                chain.put_pubkey(address, sender.public_key())?;
            }
        }
        chain.put_pubkey(&authority, proposer.public_key())?;
        let cfg: ChainConfig = serde_json::from_value(
            json!({"chain_id":10,"genesis_hash":genesis.hash(),"fee_accounting_activation_height":1,"native_address_context_height":1,"block_commitment_height":1}),
        )?;
        chain.commit_genesis_block(&genesis, &cfg)?;
        if role == "native" {
            native = Some(store);
            if batch {
                native_checkpoint = Some(stores);
            }
        } else {
            store.flush()?;
        }
    }
    let store = native.ok_or("native source missing")?;
    let mut cfg = NodeConfig::dev(authority);
    cfg.chain_id = 10;
    cfg.mempool.chain_id = 10;
    cfg.enable_stark_aggregation = false;
    cfg.rpc_enabled = false;
    if capture_on_production {
        cfg.node_role = shell_node::NodeRole::ValidatorProver;
        cfg.canonical_proof_production = true;
    }
    let poa = shell_consensus::PoaConfig::new(vec![authority], 1);
    let poa = if automatic {
        poa.with_max_future_secs(86_400)
    } else {
        poa
    };
    let mut wpoa = shell_consensus::WPoaConfig::from_poa(poa);
    wpoa.chain_id = 10;
    cfg.consensus = ConsensusEngineConfig::WPoa(wpoa);
    let (mut node, _) = NodeBuilder::new(cfg, store.clone()).build()?;
    let first_use_genesis = if first_use {
        Some(store.scan_all()?)
    } else {
        None
    };
    let tx = Transaction {
        chain_id: 10,
        nonce: 0,
        to: Some(recipient),
        value: U256::from(1),
        data: Default::default(),
        gas_limit: 21_000,
        max_fee_per_gas: 2,
        max_priority_fee_per_gas: 1,
        tx_type: 0,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    if first_use {
        let empty = MlDsaSigner::generate();
        let empty_address = Address::from_public_key(empty.public_key(), empty.sig_type().as_u8());
        let mut refusals = Vec::new();
        for mode in [
            "reference-before-registration",
            "wrong-derived-address",
            "insufficient-funds",
        ] {
            let signer = if mode == "insufficient-funds" {
                &empty
            } else {
                sender
            };
            let from = match mode {
                "wrong-derived-address" => recipient,
                "insufficient-funds" => empty_address,
                _ => address,
            };
            let signature = signer.sign(tx.signing_hash(signer.sig_type().as_u8()).as_bytes())?;
            let mut signed = SignedTransaction::new(from, tx.clone(), signature);
            if mode != "reference-before-registration" {
                signed.pubkey_mode = shell_core::PubkeyMode::Embedded(signer.public_key().to_vec());
            }
            let before = digest(store.as_ref())?;
            let error = node
                .handle_incoming_tx(signed, &MultiVerifier)
                .err()
                .ok_or("invalid first-use transaction entered the mempool")?
                .to_string();
            ensure(
                before == digest(store.as_ref())? && node.chain_store.get_pubkey(&from)?.is_none(),
                "first-use refusal wrote native data or registered a key",
            )?;
            refusals.push(
                json!({"case":mode,"error":error,"all_kv_unchanged":true,"key_registered":false}),
            );
        }
        write(
            &out.join("first-use-native-refusals.json"),
            &json!({"cases":refusals,"real_signatures":true,"private_keys_persisted":false}),
        )?;
    }
    for position in 0..count {
        let index = position as usize % senders.len();
        let sender = &senders[index];
        let mut tx = tx.clone();
        tx.nonce = position / senders.len() as u64;
        // Both priority caps produce the same effective price of two.
        tx.max_priority_fee_per_gas = (index % 2) as u64 + 1;
        if sender_count > 2 {
            // Distinct signing inputs; each transfer still consumes 21,000 gas.
            tx.gas_limit += index as u64;
        }
        let signature = sender.sign(tx.signing_hash(sender.sig_type().as_u8()).as_bytes())?;
        let mut signed = SignedTransaction::new(addresses[index], tx, signature);
        if index < unbound_count {
            signed.pubkey_mode = shell_core::PubkeyMode::Embedded(sender.public_key().to_vec());
        }
        node.handle_incoming_tx(signed, &MultiVerifier)?;
    }
    if first_use {
        for address in addresses.iter().take(unbound_count) {
            ensure(
                node.chain_store.get_pubkey(address)?.is_none(),
                "first-use mempool admission registered a key before canonical execution",
            )?;
        }
    }
    let block = node.produce_block(proposer.as_ref(), 100)?;
    if first_use {
        let parent = node
            .chain_store
            .canonical_parent_view(block.hash(), block.header.parent_hash)?;
        for (index, (sender, address)) in senders.iter().zip(&addresses).enumerate() {
            let parent_key = parent.registered_key(address)?;
            let account = parent
                .world_state()?
                .get_account(address)?
                .ok_or("parent account absent")?;
            ensure(
                (if index < unbound_count {
                    parent_key.is_none() && account.pq_pubkey_hash == ShellHash::ZERO
                } else {
                    parent_key.as_deref() == Some(sender.public_key())
                        && account.pq_pubkey_hash == blake3_hash(sender.public_key())
                }) && node.chain_store.get_pubkey(address)?.as_deref() == Some(sender.public_key()),
                "first-use parent absence or native registration mismatch",
            )?;
        }
        // This independent native control isolates key-registration rollback;
        // proof-backed wrong-root rejection is tested separately by the peer entry.
        let failed = Arc::new(shell_storage::MemoryDb::new());
        for (key, value) in first_use_genesis.ok_or("first-use genesis snapshot absent")? {
            failed.put(&key, &value)?;
        }
        let failed_node = fixture::node(failed.clone(), authority, proposer.public_key())?;
        let mut bad = block.clone();
        bad.header.state_root = ShellHash::ZERO;
        bad.proposer_seal = Some(proposer.sign(bad.hash().as_bytes())?);
        let before = failed.scan_all()?;
        let error = failed_node
            .import_block(bad, &MultiVerifier)
            .err()
            .ok_or("wrong-root first-use block was accepted")?
            .to_string();
        let unbound_keys_absent =
            addresses
                .iter()
                .take(unbound_count)
                .try_fold(true, |ok, address| {
                    Ok::<_, Error>(ok && failed_node.chain_store.get_pubkey(address)?.is_none())
                })?;
        ensure(
            error.contains("state root mismatch")
                && error.contains(&format!("{:?}", block.header.state_root))
                && before == failed.scan_all()?
                && unbound_keys_absent,
            "first-use root refusal happened before execution or leaked registration",
        )?;
        write(
            &out.join("first-use-native-root-rollback.json"),
            &json!({"error":error,"computed_root":block.header.state_root,"native_crypto_control_not_proof_admission":true,"all_kv_unchanged":true,"key_registered":false,"unbound_key_count":unbound_count,"transactions_executed_before_root_refusal":count}),
        )?;
    }
    ensure(
        block.transactions.len() == count as usize && block.system_transactions.len() == 1,
        "native production did not execute funded sender",
    )?;
    {
        let world = node.world_state.read();
        for address in &addresses {
            let transfers = count / senders.len() as u64;
            ensure(
                world.get_nonce(address)? == transfers
                    && world.get_balance(address)? == U256::from(funding - transfers * 42_001),
                "native sender nonce/balance mismatch",
            )?;
        }
        ensure(
            world.get_balance(&recipient)? == U256::from(count)
                && world.get_balance(&authority)? == U256::from(count * 42_000)
                && block.header.gas_used == count * 21_000,
            "native fresh transfer nonce/value/fee/reward control mismatch",
        )?;
    }
    let c = fixture::Context {
        version: 1,
        authority,
        authority_key: proposer.public_key().to_vec(),
        genesis_root: node
            .chain_store
            .get_header_by_hash(&genesis_hash.unwrap())?
            .ok_or("genesis header missing")?
            .state_root,
        block: block.hash(),
        tip: block.hash(),
    };
    write(&out.join("context.json"), &c)?;
    write(&out.join("candidate.json"), &block)?;
    write(
        &out.join("consensus.json"),
        &json!({"engine":"wpoa","authorities":[authority],"authority_pubkeys":[hex::encode(proposer.public_key())],"block_time_secs":1,"weights":[1]}),
    )?;
    store.flush()?;
    write(
        &out.join("control.json"),
        &json!({"native_digest":digest(store.as_ref())?,"parent":block.header.parent_hash,"block":block.hash(),"state_root":block.header.state_root,"receipts":node.chain_store.get_receipts(&block.hash())?,"accounts":accounts(store.clone(), &block)?,"raw_fresh_sender_count":senders.len(),"first_use_parent_unregistered":first_use,"unbound_sender_count":unbound_count,"unbound_sender_addresses":addresses[..unbound_count],"private_keys_persisted":false}),
    )?;
    if capture_on_production {
        let captured = node.canonical_production_status(block.hash())?;
        if first_use && captured.is_none() {
            let before = digest(store.as_ref())?;
            let error = shell_stark_prover::canonical_producer::CanonicalProductionSource::capture(
                &node.chain_store,
                block.hash(),
                block.hash(),
            )
            .err()
            .ok_or("first-use source capture differs from production hook")?;
            ensure(
                before == digest(store.as_ref())?,
                "failed capture changed native data",
            )?;
            write(
                &out.join("capture-rejection.json"),
                &json!({"block":block.hash(),"tip":block.hash(),"error":error,"native_execution_succeeded":true,"native_unchanged":true,"proofs_generated":0}),
            )?;
        }
        let captured = captured.ok_or("production hook did not capture source")?;
        ensure(
            captured["status"]["state"] == "queued"
                && captured["block"] == serde_json::to_value(&block)?,
            "production capture was not a queued matching source",
        )?;
        write(&out.join("produced-job.json"), &captured)?;
        store.flush()?;
    }
    if automatic {
        // Independent native execution control for advancement beyond historical undo retention.
        let stores = RocksDbStore::open_all(out.join("native-control/db"), None)?;
        let chain = ChainStore::new(Arc::new(stores.state.clone()));
        // Import the same genesis and block into a separate native database.
        let source_chain = ChainStore::new(store.clone());
        let genesis = source_chain
            .get_block_by_hash(&block.header.parent_hash)?
            .ok_or("genesis absent")?;
        let mut world = WorldState::new(Arc::new(stores.state.clone()));
        world.set_account(
            &address,
            &Account::new_user_account(blake3_hash(sender.public_key()), U256::from(1_000_000)),
        )?;
        ensure(
            world.state_root()? == genesis.header.state_root,
            "control genesis mismatch",
        )?;
        chain.put_pubkey(&address, sender.public_key())?;
        chain.put_pubkey(&authority, proposer.public_key())?;
        chain.commit_genesis_block(
            &genesis,
            &source_chain.get_chain_config()?.ok_or("config absent")?,
        )?;
        let mut control_cfg = node.config.clone();
        control_cfg.canonical_proof_production = false;
        let (control, _) = NodeBuilder::new(control_cfg, Arc::new(stores.state.clone())).build()?;
        control.import_block(block.clone(), &MultiVerifier)?;
        let mut tx = block.transactions[0].tx.clone();
        tx.nonce = 1;
        let signature = sender.sign(tx.signing_hash(sender.sig_type().as_u8()).as_bytes())?;
        control.handle_incoming_tx(
            SignedTransaction::new(address, tx, signature),
            &MultiVerifier,
        )?;
        let mut advance = Vec::new();
        for _ in 0..129 {
            advance.push(control.produce_block(proposer.as_ref(), 100)?);
        }
        let last = advance.last().ok_or("advance absent")?;
        let mut account_view = block.clone();
        account_view.header.state_root = last.header.state_root;
        write(&out.join("advance-blocks.json"), &advance)?;
        write(
            &out.join("advance-control.json"),
            &json!({"head":last.hash(),"height":last.number(),"root":last.header.state_root,"accounts":accounts(Arc::new(stores.state.clone()),&account_view)?,"accelerated_local_heights":true,"max_future_secs":86400}),
        )?;
        stores.state.flush()?;
    }
    if full {
        // Model the real validator loop: an authenticated quorum vote may use a
        // different randomized signature from the original block seal.
        let mut round = shell_consensus::wpoa_state::WPoaRound::new(
            block.number(),
            0,
            node.consensus.read().validator_weights(),
        );
        let _ = round.on_block_proposed(block.hash(), authority);
        *node.wpoa_round.lock() = Some(round);
        let vote = proposer.sign(block.hash().as_bytes())?;
        let certificate = node
            .handle_wpoa_vote(authority, block.hash(), block.number(), vote)
            .ok_or("full fixture genuine quorum vote did not finalize")?;
        ensure(
            !certificate.is_empty() && node.canonical_production_status(block.hash())?.is_some(),
            "full capture did not survive genuine native vote",
        )?;
        write(
            &out.join("full-vote.json"),
            &json!({"genuine_native_quorum_vote":true,"captured_seal_preserved":node.chain_store.get_block_by_hash(&block.hash())?.as_ref()==Some(&block),"capture_restored_after_vote":true}),
        )?;
        // A separately labelled ordinary native successor changes current state.
        // It is not claimed as a second proof-admitted block.
        if batch {
            std::fs::create_dir(out.join("batch-native"))?;
            store.flush()?;
            native_checkpoint
                .as_ref()
                .ok_or("batch checkpoint handle missing")?
                .create_checkpoint(out.join("batch-native/db"))?;
        }
        node.config.canonical_proof_production = false;
        for position in count..2 * count {
            let index = position as usize % senders.len();
            let sender = &senders[index];
            let mut next = tx.clone();
            next.nonce = position / senders.len() as u64;
            next.max_priority_fee_per_gas = (index % 2) as u64 + 1;
            if sender_count > 2 {
                next.gas_limit += index as u64;
            }
            let signature = sender.sign(next.signing_hash(sender.sig_type().as_u8()).as_bytes())?;
            node.handle_incoming_tx(
                SignedTransaction::new(addresses[index], next, signature),
                &MultiVerifier,
            )?;
        }
        let later = node.produce_block(proposer.as_ref(), 100)?;
        ensure(
            later.header.state_root != block.header.state_root,
            "full history control did not change state",
        )?;
        write(&out.join("later-block.json"), &later)?;
        write(
            &out.join("later-control.json"),
            &json!({"head":later.hash(),"state_root":later.header.state_root,"receipts":node.chain_store.get_receipts(&later.hash())?,"accounts":accounts(store.clone(), &later)?,"ordinary_native_successor_not_proof_admitted":true}),
        )?;
        if batch {
            let mut bad = later.clone();
            bad.header.state_root = block.header.state_root;
            bad.proposer_seal = Some(proposer.sign(bad.hash().as_bytes())?);
            write(&out.join("batch-bad-block.json"), &bad)?;
            let stores = RocksDbStore::open_all(out.join("batch-native/db"), None)?;
            let bad_store = Arc::new(stores.state);
            // Byzantine source fixture only: storage does not establish execution.
            // The actual native control above has a different, correct second root.
            let overlay = Arc::new(shell_storage::OverlayStore::new(bad_store.clone()));
            let staged = ChainStore::new(overlay.clone());
            staged
                .stage_address_metadata_undo(&bad.hash(), &staged.address_metadata_checkpoint()?)?;
            staged.put_block_signers(
                &bad.hash(),
                &[shell_core::BlockSignerEvidence {
                    address: authority,
                    public_key: proposer.public_key().to_vec(),
                    signature: bad.proposer_seal.clone().ok_or("missing bad seal")?,
                }],
            )?;
            staged.commit_canonical_block(
                &bad,
                Some(
                    node.chain_store
                        .get_receipts(&later.hash())?
                        .as_ref()
                        .ok_or("control receipts missing")?,
                ),
            )?;
            overlay.commit()?;
            let source_node = fixture::node(bad_store.clone(), authority, proposer.public_key())?;
            let mut round = shell_consensus::wpoa_state::WPoaRound::new(
                bad.number(),
                0,
                source_node.consensus.read().validator_weights(),
            );
            let _ = round.on_block_proposed(bad.hash(), authority);
            *source_node.wpoa_round.lock() = Some(round);
            source_node
                .handle_wpoa_vote(
                    authority,
                    bad.hash(),
                    bad.number(),
                    bad.proposer_seal.clone().ok_or("missing bad vote")?,
                )
                .ok_or("Byzantine same-hash quorum fixture failed")?;
            bad_store.flush()?;
            write(
                &out.join("batch-fixture.json"),
                &json!({"good1_natively_executed":true,"control2_natively_executed":true,"bad2_storage_only_byzantine_source":true,"bad2_not_execution_evidence":true,"private_keys_persisted":false,"transactions_per_block":count,"registered_sender_keys":senders.len(),"first_use_parent_unregistered":first_use,"unbound_sender_count":unbound_count}),
            )?;
        }
        store.flush()?;
    }

    Ok(())
}
fn snapshot(out: &Path, role: &str) -> Result<Value, Error> {
    let stores = RocksDbStore::open_all(out.join(role).join("db"), None)?;
    let chain = ChainStore::new(Arc::new(stores.state.clone()));
    Ok(json!({"digest":digest(&stores.state)?,"head":chain.get_head_hash()?}))
}
fn verify(out: &Path) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let control: Value = read(&out.join("control.json"))?;
    let proof = read(&out.join("job/proof.json"))?;
    let native = snapshot(out, "native")?;
    if out.join("advance-control.json").exists() {
        runtime::verify_native(out)?;
    } else {
        ensure(
            native["digest"] == control["native_digest"],
            "native source changed during production",
        )?;
    }
    let stores = RocksDbStore::open_all(out.join("follower/db"), None)?;
    let store = Arc::new(stores.state);
    let before = digest(store.as_ref())?;
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    ensure(
        node.chain_store.get_head_hash()? == Some(c.block),
        "generated proof was not imported",
    )?;
    let result = node.replay_canonical_transactions_with_proof(c.block, c.block, &proof)?;
    ensure(
        result.state_root == block.header.state_root
            && serde_json::to_value(&result.receipts)? == control["receipts"]
            && accounts(store.clone(), &block)? == control["accounts"],
        "proof import/replay differs from independent native execution",
    )?;
    ensure(
        node.chain_store.get_receipts(&c.block)?.as_ref() == Some(&result.receipts),
        "receipts not persisted",
    )?;
    ensure(
        digest(store.as_ref())? == before,
        "cold proof verification wrote native source",
    )?;
    let mut receipt = out.join("verified.json");
    let mut i = 2;
    while receipt.try_exists()? {
        receipt = out.join(format!("verified-{i}.json"));
        i += 1;
    }
    write(
        &receipt,
        &json!({"actual":result,"accounts_match_native_control":true,"native_source_unchanged":true,"cold_replay_no_writes":true}),
    )?;
    Ok(())
}
fn corrupt_cache(out: &Path, role: &str) -> Result<(), Error> {
    let copy = out.join(role);
    ensure(
        !copy.exists(),
        "negative cache exists; refusing replacement",
    )?;
    std::fs::create_dir(&copy)?;
    let source = RocksDbStore::open_all(out.join("job/db"), None)?;
    let before = digest(&source.state)?;
    source.create_checkpoint(copy.join("db"))?;
    let stores = RocksDbStore::open_all(copy.join("db"), None)?;
    let mut index: Value = serde_json::from_slice(
        &stores
            .state
            .get(b"production/index")?
            .ok_or("index absent")?,
    )?;
    let mut batch = shell_storage::WriteBatch::new();
    match role {
        "corrupt-stage" => {
            let name = "sender-0-key";
            let key = format!("production/component/{name}").into_bytes();
            let mut proof: Value =
                serde_json::from_slice(&stores.state.get(&key)?.ok_or("key certificate absent")?)?;
            let byte = proof["proof_bytes"][0]
                .as_u64()
                .ok_or("proof byte absent")?;
            proof["proof_bytes"][0] = json!(byte ^ 1);
            let bytes = serde_json::to_vec(&proof)?;
            index["components"][name]["bytes"] = json!(bytes.len());
            index["components"][name]["hash"] = json!(blake3_hash(&bytes));
            batch.put(key, bytes);
        }
        "corrupt-source" => {
            let mut bytes = stores
                .state
                .get(b"production/source")?
                .ok_or("source absent")?;
            bytes.push(b' ');
            index["source_hash"] = json!(blake3_hash(&bytes));
            index["source_bytes"] = json!(bytes.len());
            batch.put(b"production/source".to_vec(), bytes);
        }
        "over-quota" => {
            index["components"]["sender-0-key"]["bytes"] = json!(256 * 1024 * 1024);
        }
        _ => return Err("unknown negative cache".into()),
    }
    batch.put(b"production/index".to_vec(), serde_json::to_vec(&index)?);
    stores.state.write_batch(batch)?;
    stores.state.flush()?;
    ensure(
        digest(&source.state)? == before,
        "checkpoint copy altered the genuine job",
    )?;
    write(
        &out.join(format!("{role}-prepared.json")),
        &json!({"native_source_unchanged":true,"genuine_job_unchanged":true,"negative_digest":digest(&stores.state)?}),
    )?;
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 3 && args[0] == "prepare-slh-proposer-raw-bound" {
        return admission_runtime::slh_proposer::prepare_raw_bound(
            Path::new(&args[1]),
            Path::new(&args[2]),
        );
    }
    if args.len() == 3 && args[0] == "prepare-slh-proposer-sdk-reference" {
        return admission_runtime::slh_proposer::prepare_sdk_reference(
            Path::new(&args[1]),
            Path::new(&args[2]),
        );
    }
    if args.len() == 3 && args[0] == "prepare-slh-proposer-sdk-bound" {
        return admission_runtime::slh_proposer::prepare_sdk_bound(
            Path::new(&args[1]),
            Path::new(&args[2]),
        );
    }
    if args.len() == 3 && args[0] == "prepare-slh-proposer-sdk-first-use" {
        return admission_runtime::slh_proposer::prepare_sdk_first_use(
            Path::new(&args[1]),
            Path::new(&args[2]),
        );
    }
    if args.len() == 3 && args[0] == "prepare-slh-proposer-first-use" {
        return admission_runtime::slh_proposer::prepare_first_use(
            Path::new(&args[1]),
            Path::new(&args[2]),
        );
    }
    if args.len() == 4 && args[0].starts_with("slh-first-use-") {
        return admission_runtime::slh_first_use::command(
            &args[0],
            Path::new(&args[1]),
            Path::new(&args[2]),
            Path::new(&args[3]),
        );
    }
    if args.len() == 4 && args[0].starts_with("slh-peer-") {
        return admission_runtime::slh_peer::command(
            &args[0],
            Path::new(&args[1]),
            Path::new(&args[2]),
            Path::new(&args[3]),
        );
    }
    if args.first().is_some_and(|mode| mode == "compact-roundtrip") && args.len() == 3 {
        return admission_runtime::compact_roundtrip(Path::new(&args[1]), Path::new(&args[2]));
    }
    ensure(
        args.len() == 2,
        "usage: mldsa-produce-proof prepare|snapshot|follower-snapshot|verify output",
    )?;
    let out = Path::new(&args[1]);
    match args[0].as_str() {
        "prepare-dilithium" => admission_runtime::dilithium::prepare(out, true, false, false),
        "prepare-dilithium-proposer" => {
            admission_runtime::dilithium::prepare(out, false, true, false)
        }
        "prepare-slh-proposer" => admission_runtime::slh_proposer::prepare(out),
        "capture-slh-proposer" => admission_runtime::slh_proposer::capture(out),
        "pause-slh-proposer" => admission_runtime::slh_proposer::prove(out, true),
        "resume-slh-proposer" => admission_runtime::slh_proposer::prove(out, false),
        "verify-slh-proposer" => admission_runtime::slh_proposer::verify(out, false),
        "refuse-slh-proposer" => admission_runtime::slh_proposer::verify(out, true),
        "publish-slh-proposer" => admission_runtime::slh_proposer::publish(out),
        "prepare-slh" => admission_runtime::slh::prepare(out),
        "slh-recover-native" => admission_runtime::slh::recover_native(out),
        "slh-capture" => admission_runtime::slh::capture(out, false),
        "slh-capture-recovered" => admission_runtime::slh::capture(out, true),
        "prepare-dilithium-both" => admission_runtime::dilithium::prepare(out, true, true, false),
        "prepare-dilithium-both-unbound" => admission_runtime::dilithium::prepare_both_unbound(out),
        "sdk-intake-refusal" => admission_runtime::dilithium::sdk_intake_refusal(out),
        "prepare-dilithium-sdk" => admission_runtime::dilithium::prepare_sdk(out),
        "prepare-dilithium-sdk-proposer" => admission_runtime::dilithium::prepare_sdk_proposer(out),
        "prepare-dilithium-raw-sdk-proposer" => {
            admission_runtime::dilithium::prepare_raw_sdk_proposer(out)
        }
        "prepare-dilithium-raw-unbound-sdk-proposer" => {
            admission_runtime::dilithium::prepare_raw_unbound_sdk_proposer(out)
        }
        "prepare-dilithium-sdk-both" => admission_runtime::dilithium::prepare_sdk_both(out),
        "prepare-dilithium-sdk-raw-proposer" => {
            admission_runtime::dilithium::prepare_sdk_raw_proposer(out)
        }
        "prepare-dilithium-sdk-unbound-raw-proposer" => {
            admission_runtime::dilithium::prepare_sdk_unbound_raw_proposer(out)
        }
        "prepare-dilithium-sdk-both-unbound" => {
            admission_runtime::dilithium::prepare_sdk_both_unbound(out)
        }
        "prepare-dilithium-sdk-unbound" => admission_runtime::dilithium::prepare_sdk_unbound(out),
        "prepare-dilithium-unbound" => {
            admission_runtime::dilithium::prepare(out, true, false, true)
        }
        "dilithium-reference-pause" | "dilithium-reference-resume" => {
            tokio::runtime::Runtime::new()?.block_on(admission_runtime::dilithium::run(
                out,
                args[0] == "dilithium-reference-pause",
                true,
            ))
        }
        "dilithium-probe" => admission_runtime::dilithium::probe(out, true),
        "dilithium-pause" | "dilithium-resume" => tokio::runtime::Runtime::new()?.block_on(
            admission_runtime::dilithium::run(out, args[0] == "dilithium-pause", false),
        ),
        "dilithium-snapshot" => admission_runtime::dilithium::snapshot(out),
        "dilithium-verify" => admission_runtime::dilithium::verify(out, false),
        "dilithium-history" => admission_runtime::dilithium::verify(out, true),
        "dilithium-refusal" => admission_runtime::dilithium::negative(out),
        "prepare-rotation" => admission_runtime::rotation::prepare(out, true),
        "prepare-rotation-raw" => admission_runtime::rotation::prepare(out, false),
        "rotation-pause" | "rotation-resume" => tokio::runtime::Runtime::new()?.block_on(
            admission_runtime::rotation::run(out, args[0] == "rotation-pause"),
        ),
        "rotation-snapshot" => admission_runtime::rotation::snapshot(out),
        "rotation-verify" => admission_runtime::rotation::verify(out, false),
        "rotation-history" => admission_runtime::rotation::verify(out, true),
        "rotation-old-key-refusal" => admission_runtime::rotation::negative(out),
        "prepare" => prepare(out, false, false, false, 0, 1, 0),
        "prepare-full" => prepare(out, false, true, true, 0, 1, 0),
        "prepare-batch" => prepare(out, false, true, true, 2, 1, 0),
        "prepare-first-use" => prepare(out, false, true, true, 2, 1, 1),
        "prepare-wide" => prepare(out, false, true, true, 16, 1, 0),
        "prepare-mixed" => prepare(out, false, true, true, 16, 2, 0),
        "prepare-eight-keys" => prepare(out, false, true, true, 16, 8, 0),
        "prepare-sixteen-keys" => prepare(out, false, true, true, 16, 16, 0),
        "prepare-mixed-first-use" => prepare(out, false, true, true, 16, 16, 8),
        "mixed-key-swap" => admission_runtime::mixed_key_refusal(out),
        "matrix-aggregate-refusal" => admission_runtime::aggregate_refusal(out),
        "unbound-address-refusal" => admission_runtime::unbound_address_refusal(out),
        "wide-pause"
        | "wide-resume"
        | "mixed-pause"
        | "mixed-resume"
        | "eight-keys-pause"
        | "eight-keys-resume"
        | "sixteen-keys-pause"
        | "sixteen-keys-resume"
        | "mixed-first-use-pause"
        | "mixed-first-use-resume" => tokio::runtime::Runtime::new()?.block_on(
            admission_runtime::batch(out, args[0].ends_with("-pause"), true),
        ),
        "wide-snapshot"
        | "mixed-snapshot"
        | "eight-keys-snapshot"
        | "sixteen-keys-snapshot"
        | "mixed-first-use-snapshot" => admission_runtime::snapshot_wide(out),
        "wide-verify"
        | "mixed-verify"
        | "eight-keys-verify"
        | "sixteen-keys-verify"
        | "mixed-first-use-verify" => admission_runtime::verify_batch(out, false, false, true),
        "wide-history"
        | "mixed-history"
        | "eight-keys-history"
        | "sixteen-keys-history"
        | "mixed-first-use-history" => admission_runtime::verify_batch(out, true, true, true),
        "wide-history-verify"
        | "mixed-history-verify"
        | "eight-keys-history-verify"
        | "sixteen-keys-history-verify"
        | "mixed-first-use-history-verify" => {
            admission_runtime::verify_batch(out, true, false, true)
        }
        "full-pause" | "full-resume" | "full-bad-proposer" => {
            tokio::runtime::Runtime::new()?.block_on(admission_runtime::full(out, &args[0]))
        }
        "batch-pause" | "batch-resume" | "first-use-pause" | "first-use-resume" => {
            tokio::runtime::Runtime::new()?.block_on(admission_runtime::batch(
                out,
                args[0].ends_with("-pause"),
                false,
            ))
        }
        "batch-snapshot" | "first-use-snapshot" => admission_runtime::snapshot_batch(out),
        "batch-verify" | "first-use-verify" => {
            admission_runtime::verify_batch(out, false, false, false)
        }
        "batch-history" | "first-use-history" => {
            admission_runtime::verify_batch(out, true, true, false)
        }
        "batch-history-verify" | "first-use-history-verify" => {
            admission_runtime::verify_batch(out, true, false, false)
        }
        "full-verify" => admission_runtime::verify_full(out),
        "full-snapshot" => admission_runtime::snapshot_full(out),
        "consecutive-pause" | "consecutive-resume" => tokio::runtime::Runtime::new()?.block_on(
            admission_runtime::consecutive(out, args[0] == "consecutive-pause"),
        ),
        "consecutive-verify" => admission_runtime::verify_consecutive(out),
        "consecutive-snapshot" => admission_runtime::snapshot_consecutive(out),
        "consecutive-bad-reference" => tokio::runtime::Runtime::new()?
            .block_on(admission_runtime::bad_consecutive_reference(out)),
        "full-history" | "full-history-verify" => {
            admission_runtime::history_full(out, args[0] == "full-history")
        }
        "prepare-runtime" => prepare(out, true, false, false, 0, 1, 0),
        "prepare-production-hook" => prepare(out, false, true, false, 0, 1, 0),
        "runtime-pause" | "runtime-resume" => {
            tokio::runtime::Runtime::new()?.block_on(runtime::run(out, args[0] == "runtime-pause"))
        }
        "prepare-peer-admission" => admission_runtime::prepare(out),
        "peer-admission-pause" | "peer-admission-resume" => tokio::runtime::Runtime::new()?
            .block_on(admission_runtime::run(
                out,
                args[0] == "peer-admission-pause",
                false,
                false,
            )),
        "peer-admission-bad-air" => tokio::runtime::Runtime::new()?
            .block_on(admission_runtime::run(out, false, true, false)),
        "peer-admission-recheck-bad-air" => {
            tokio::runtime::Runtime::new()?.block_on(admission_runtime::run(out, false, true, true))
        }
        "peer-admission-sync" => {
            tokio::runtime::Runtime::new()?.block_on(admission_runtime::sustained_sync(out))
        }
        "peer-admission-sync-verify" => admission_runtime::verify_sync(out),
        "peer-admission-gossip" => {
            tokio::runtime::Runtime::new()?.block_on(admission_runtime::gossip(out))
        }
        "peer-admission-gossip-verify" => admission_runtime::verify_gossip(out),
        "peer-admission-verify" => admission_runtime::verify(out),
        "peer-admission-snapshot" => admission_runtime::snapshot(out),
        "runtime-snapshot" => runtime::snapshot(out),
        "runtime-native-check" => runtime::verify_native(out),
        "runtime-next-job" => tokio::runtime::Runtime::new()?.block_on(runtime::next_job(out)),
        "runtime-bad-certificate" | "runtime-bad-source" => {
            tokio::runtime::Runtime::new()?.block_on(runtime::negative(out, &args[0]))
        }
        "snapshot" => {
            println!("{}", snapshot(out, "native")?);
            Ok(())
        }
        "follower-snapshot" => {
            println!("{}", snapshot(out, "follower")?);
            Ok(())
        }
        "job-snapshot" => {
            let stores = RocksDbStore::open_all(out.join("job/db"), None)?;
            let entries = stores.state.scan_all()?;
            let rows: Vec<_> = entries
                .iter()
                .map(|(k, v)| json!({"key":hex::encode(k),"hash":blake3_hash(v),"bytes":v.len()}))
                .collect();
            println!("{}", json!({"rows":rows}));
            Ok(())
        }
        "corrupt-stage" | "corrupt-source" | "over-quota" => corrupt_cache(out, &args[0]),
        "negative-snapshot" => {
            let mut rows = serde_json::Map::new();
            for role in ["corrupt-stage", "corrupt-source", "over-quota"] {
                let stores = RocksDbStore::open_all(out.join(role).join("db"), None)?;
                rows.insert(role.into(), json!(digest(&stores.state)?));
            }
            println!("{}", Value::Object(rows));
            Ok(())
        }
        "verify" => verify(out),
        _ => Err("unknown producer fixture mode".into()),
    }
}
