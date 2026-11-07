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
fn accounts(store: Arc<RocksDbStore>, block: &Block) -> Result<Value, Error> {
    let world = WorldState::at_root(store, &block.header.state_root)?;
    let tx = block
        .transactions
        .first()
        .ok_or("fixture transaction missing")?;
    let mut rows = Vec::new();
    for address in [
        tx.from,
        tx.tx.to.ok_or("recipient missing")?,
        block.header.proposer,
    ] {
        rows.push(json!({"address":address,"nonce":world.get_nonce(&address)?,"balance":world.get_balance(&address)?}));
    }
    Ok(json!(rows))
}
fn prepare(
    out: &Path,
    automatic: bool,
    capture_on_production: bool,
    full: bool,
) -> Result<(), Error> {
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
    let sender = MlDsaSigner::generate();
    let proposer: Box<dyn Signer> = if full {
        Box::new(MlDsaSigner::generate())
    } else {
        Box::new(DilithiumSigner::generate())
    };
    let address = Address::from_public_key(sender.public_key(), sender.sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    let recipient = Address::from([0x11; 32]);
    ensure(
        address != authority && address != recipient && authority != recipient,
        "fixture actor collision",
    )?;
    let mut native = None;
    let mut genesis_hash = None;
    for role in ["native", "follower"] {
        let stores = RocksDbStore::open_all(out.join(role).join("db"), None)?;
        let store = Arc::new(stores.state);
        let mut world = WorldState::new(store.clone());
        world.set_account(
            &address,
            &Account::new_user_account(blake3_hash(sender.public_key()), U256::from(1_000_000)),
        )?;
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
        chain.put_pubkey(&address, sender.public_key())?;
        chain.put_pubkey(&authority, proposer.public_key())?;
        let cfg: ChainConfig = serde_json::from_value(
            json!({"chain_id":10,"genesis_hash":genesis.hash(),"fee_accounting_activation_height":1,"native_address_context_height":1,"block_commitment_height":1}),
        )?;
        chain.commit_genesis_block(&genesis, &cfg)?;
        if role == "native" {
            native = Some(store);
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
    let signature = sender.sign(tx.signing_hash(sender.sig_type().as_u8()).as_bytes())?;
    let signed = SignedTransaction::new(address, tx, signature);
    node.handle_incoming_tx(signed, &MultiVerifier)?;
    let block = node.produce_block(proposer.as_ref(), 100)?;
    ensure(
        block.transactions.len() == 1 && block.system_transactions.len() == 1,
        "native production did not execute funded sender",
    )?;
    {
        let world = node.world_state.read();
        ensure(
            world.get_nonce(&address)? == 1
                && world.get_balance(&address)? == U256::from(957_999)
                && world.get_balance(&recipient)? == U256::from(1)
                && world.get_balance(&authority)? == U256::from(42_000)
                && block.header.gas_used == 21_000,
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
        &json!({"native_digest":digest(store.as_ref())?,"parent":block.header.parent_hash,"block":block.hash(),"state_root":block.header.state_root,"receipts":node.chain_store.get_receipts(&block.hash())?,"accounts":accounts(store.clone(), &block)?,"raw_fresh_sender_count":1,"private_keys_persisted":false}),
    )?;
    if capture_on_production {
        let captured = node
            .canonical_production_status(block.hash())?
            .ok_or("production hook did not capture source")?;
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
        node.config.canonical_proof_production = false;
        let mut next = block.transactions[0].tx.clone();
        next.nonce = 1;
        let signature = sender.sign(next.signing_hash(sender.sig_type().as_u8()).as_bytes())?;
        node.handle_incoming_tx(
            SignedTransaction::new(address, next, signature),
            &MultiVerifier,
        )?;
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
    ensure(
        args.len() == 2,
        "usage: mldsa-produce-proof prepare|snapshot|follower-snapshot|verify output",
    )?;
    let out = Path::new(&args[1]);
    match args[0].as_str() {
        "prepare" => prepare(out, false, false, false),
        "prepare-full" => prepare(out, false, true, true),
        "full-pause" | "full-resume" | "full-bad-proposer" => {
            tokio::runtime::Runtime::new()?.block_on(admission_runtime::full(out, &args[0]))
        }
        "full-verify" => admission_runtime::verify_full(out),
        "full-snapshot" => admission_runtime::snapshot_full(out),
        "full-history" | "full-history-verify" => {
            admission_runtime::history_full(out, args[0] == "full-history")
        }
        "prepare-runtime" => prepare(out, true, false, false),
        "prepare-production-hook" => prepare(out, false, true, false),
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
