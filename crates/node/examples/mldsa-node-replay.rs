//! Complete sender-proof consumption by the native retained-block replay engine.
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_batch.rs"]
mod graph;
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_source.rs"]
mod source;

use graph::LoadedEntry;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use shell_consensus::{ConsensusEngine, PoaConfig, WPoaConfig, WPoaEngine};
use shell_core::{Block, BlockHeader, SystemTxKind};
use shell_crypto::{DilithiumSigner, MultiVerifier, Signer};
use shell_mempool::TxPool;
use shell_node::{CanonicalProofReplay, Node, NodeConfig};
use shell_primitives::{Address, ShellHash};
use shell_stark_prover::canonical_batch::{
    CanonicalSignatureBatchProof, CanonicalTransactionProof,
};
use shell_stark_prover::registered_signature::RegisteredSignatureProof;
use shell_storage::{ChainConfig, ChainStore, KvStore, MemoryDb, RocksDbStore, WorldState};
use source::{read, write, Error};
use std::{path::Path, sync::Arc};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    version: u8,
    authority: Address,
    authority_key: Vec<u8>,
    genesis_root: ShellHash,
    block: ShellHash,
    tip: ShellHash,
}
#[derive(Deserialize)]
struct InitialState {
    state_root: [u8; 32],
}
fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn node<S: KvStore + 'static>(
    store: Arc<S>,
    authority: Address,
    key: &[u8],
) -> Result<Node<S>, Error> {
    let chain = Arc::new(ChainStore::new(store.clone()));
    ensure(
        chain.get_pubkey(&authority)?.as_deref() == Some(key),
        "saved authority key differs from native registry",
    )?;
    let head = chain.get_head_block()?.ok_or("node genesis missing")?;
    let world = Arc::new(RwLock::new(WorldState::at_root(
        store.clone(),
        &head.header.state_root,
    )?));
    let mut config = NodeConfig::dev(authority);
    config.chain_id = 10;
    config.mempool.chain_id = 10;
    config.enable_stark_aggregation = false;
    config.block_time_ms = 1_000;
    let pool = Arc::new(TxPool::new(config.mempool.clone()));
    let mut consensus_config = WPoaConfig::from_poa(PoaConfig::new(vec![authority], 1));
    consensus_config.chain_id = 10;
    config.consensus = shell_node::ConsensusEngineConfig::WPoa(consensus_config.clone());
    let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(WPoaEngine::new(
        consensus_config,
        Arc::new(MultiVerifier),
    )));
    let node = Node::new(config, store, chain, world, pool, consensus);
    node.known_authorities
        .write()
        .insert(authority, key.to_vec());
    Ok(node)
}
fn open(dir: &Path, c: &Context) -> Result<Node<RocksDbStore>, Error> {
    let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
    node(Arc::new(stores.state), c.authority, &c.authority_key)
}
fn genesis<S: KvStore + 'static>(
    store: Arc<S>,
    original: &RocksDbStore,
    root: ShellHash,
    authority: Address,
    entries: [&LoadedEntry; 2],
) -> Result<(), Error> {
    for (key, value) in original.scan_all()? {
        if key.len() == 32 && shell_primitives::keccak256(&value).as_bytes().as_slice() == key {
            store.put(&key, &value)?;
        }
    }
    let chain = ChainStore::new(store);
    for entry in entries {
        chain.put_pubkey(
            &entry.expected.from,
            entry
                .expected
                .public_key()
                .ok_or("fixture needs Embedded key")?,
        )?;
    }
    let block = Block {
        header: BlockHeader {
            state_root: root,
            number: 0,
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
    let config: ChainConfig = serde_json::from_value(serde_json::json!({
        "chain_id":10,"genesis_hash":block.hash(),"fee_accounting_activation_height":1,
        "native_address_context_height":1,"block_commitment_height":1
    }))?;
    chain.commit_genesis_block(&block, &config)?;
    Ok(())
}
fn init(first: &LoadedEntry, second: &LoadedEntry, state: &Path, dir: &Path) -> Result<(), Error> {
    if dir.join("context.json").try_exists()? {
        return reopen(first, second, dir);
    }
    ensure(
        !dir.join("native-db").try_exists()? && !dir.join("leader-db").try_exists()?,
        "partial node fixture exists; refusing overwrite",
    )?;
    std::fs::create_dir_all(dir)?;
    let state_source: InitialState = read(&state.join("state-source.json"))?;
    let root = ShellHash::from(state_source.state_root);
    let original = RocksDbStore::open_all(state.join("native-db"), None)?;
    let before = original.state.scan_all()?;
    let proposer = DilithiumSigner::generate();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    ensure(
        authority != first.expected.from
            && authority != second.expected.from
            && Some(authority) != first.expected.tx.to,
        "authority collides with transfer parties",
    )?;
    let c;
    {
        let leader_stores = RocksDbStore::open_all(dir.join("leader-db"), None)?;
        let follower_stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
        let leader_store = Arc::new(leader_stores.state.clone());
        let follower_store = Arc::new(follower_stores.state.clone());
        genesis(
            leader_store.clone(),
            &original.state,
            root,
            authority,
            [first, second],
        )?;
        genesis(
            follower_store.clone(),
            &original.state,
            root,
            authority,
            [first, second],
        )?;
        ChainStore::new(leader_store.clone()).put_pubkey(&authority, proposer.public_key())?;
        ChainStore::new(follower_store.clone()).put_pubkey(&authority, proposer.public_key())?;
        let leader = node(leader_store, authority, proposer.public_key())?;
        let follower = node(follower_store, authority, proposer.public_key())?;
        for entry in [first, second] {
            ensure(
                entry.expected.tx.tx_type == 0 && entry.expected.tx.to.is_some(),
                "fixture requires ordinary transfers",
            )?;
            leader.handle_incoming_tx(entry.expected.clone(), &MultiVerifier)?;
        }
        let block = leader.produce_block(&proposer, 100)?;
        ensure(
            block.transactions.len() == 2
                && block.system_transactions.len() == 1
                && block.system_transactions[0].kind == SystemTxKind::BlockGasReward,
            "native producer must include real transfers and fee reward",
        )?;
        follower.import_block(block.clone(), &MultiVerifier)?;
        let tip = leader.produce_block(&proposer, 100)?;
        follower.import_block(tip.clone(), &MultiVerifier)?;
        ensure(
            tip.transactions.is_empty(),
            "second native block must be empty",
        )?;
        ensure(
            leader.chain_store.get_receipts(&block.hash())?
                == follower.chain_store.get_receipts(&block.hash())?,
            "producer/import receipts differ",
        )?;
        ensure(
            leader.world_state.write().state_root()?
                == follower.world_state.write().state_root()?,
            "producer/import state differs",
        )?;
        follower.store.flush()?;
        leader.store.flush()?;
        c = Context {
            version: 1,
            authority,
            authority_key: proposer.public_key().to_vec(),
            genesis_root: root,
            block: block.hash(),
            tip: tip.hash(),
        };
    }
    ensure(
        original.state.scan_all()? == before,
        "input native database changed",
    )?;
    write(&dir.join("context.json"), &c)?;
    reopen(first, second, dir)?;
    println!(
        "{}",
        serde_json::json!({"mode":"init","actual_Node_production_and_import":true,"native_fee_reward":true,"raw_signature_graphs_regenerated":0})
    );
    Ok(())
}
fn block_proof(
    first: &LoadedEntry,
    second: &LoadedEntry,
    state: &Path,
    block: &Block,
) -> Result<CanonicalSignatureBatchProof, Error> {
    let mut transactions = Vec::new();
    for tx in &block.transactions {
        let (entry, name) = if tx == &first.expected {
            (first, "first-account.json")
        } else if tx == &second.expected {
            (second, "second-account.json")
        } else {
            return Err(
                "native source differs from the two independently expected graph inputs".into(),
            );
        };
        transactions.push(CanonicalTransactionProof {
            account: read(&state.join(name))?,
            signature: RegisteredSignatureProof {
                version: 1,
                transaction: entry.proof.identified.sender.transaction.clone(),
                transaction_id: entry.proof.identified.transaction_id.clone(),
                leaf: entry.proof.leaf.clone(),
                tagged_key: None,
            },
        });
    }
    Ok(CanonicalSignatureBatchProof {
        version: 1,
        proposer: None,
        transactions,
    })
}
fn verify(
    first: &LoadedEntry,
    second: &LoadedEntry,
    state: &Path,
    dir: &Path,
) -> Result<(), Error> {
    let c: Context = read(&dir.join("context.json"))?;
    let node = open(dir, &c)?;
    let before = node.store.scan_all()?;
    let algorithms = shell_crypto::AlgorithmRegistry::global().clone();
    let block = node
        .chain_store
        .get_block_by_hash(&c.block)?
        .ok_or("native block absent")?;
    let proof = block_proof(first, second, state, &block)?;
    let result = node.replay_canonical_transactions_with_proof(c.tip, c.block, &proof)?;
    ensure(
        result.proved_sender_signatures == 2
            && result.state_root == block.header.state_root
            && Some(result.receipts.clone()) == node.chain_store.get_receipts(&c.block)?,
        "proof-backed native replay differs from persisted producer/import result",
    )?;
    ensure(
        node.store.scan_all()? == before,
        "historical proof replay wrote base KV",
    )?;
    ensure(
        *shell_crypto::AlgorithmRegistry::global() == algorithms,
        "historical proof replay changed global algorithms",
    )?;
    let output = dir.join("result.json");
    if output.try_exists()? {
        ensure(
            read::<CanonicalProofReplay>(&output)? == result,
            "saved replay result differs",
        )?;
    } else {
        write(&output, &result)?;
    }
    println!(
        "{}",
        serde_json::json!({"mode":"verify","actual_Node_historical_replay":true,"complete_sender_proofs":2,"sender_native_crypto_fallback":false,"native_fee_reward_and_receipts_match":true,"base_KV_unchanged":true,"gas_used":block.header.gas_used,"state_root":result.state_root})
    );
    Ok(())
}
fn rejections(
    first: &LoadedEntry,
    second: &LoadedEntry,
    state: &Path,
    dir: &Path,
) -> Result<(), Error> {
    let c: Context = read(&dir.join("context.json"))?;
    let node = open(dir, &c)?;
    let block = node
        .chain_store
        .get_block_by_hash(&c.block)?
        .ok_or("missing block")?;
    let mut proof = block_proof(first, second, state, &block)?;
    let before = node.store.scan_all()?;
    let mut refused = Vec::new();
    for version in [0, 2, 255] {
        proof.version = version;
        ensure(
            node.replay_canonical_transactions_with_proof(c.tip, c.block, &proof)
                .is_err(),
            "unsupported version accepted",
        )?;
        refused.push(format!("version-{version}"));
    }
    proof.version = 1;
    let last = proof.transactions.pop().ok_or("missing proof")?;
    ensure(
        node.replay_canonical_transactions_with_proof(c.tip, c.block, &proof)
            .is_err(),
        "missing proof accepted",
    )?;
    proof.transactions.push(last);
    proof.transactions.swap(0, 1);
    ensure(
        node.replay_canonical_transactions_with_proof(c.tip, c.block, &proof)
            .is_err(),
        "reordered proof accepted",
    )?;
    proof.transactions.swap(0, 1);
    refused.extend(["missing-proof".into(), "reordered-proof".into()]);
    let extra = proof.transactions[0].clone();
    proof.transactions.push(extra);
    ensure(
        node.replay_canonical_transactions_with_proof(c.tip, c.block, &proof)
            .is_err(),
        "extra proof accepted",
    )?;
    proof.transactions.pop();
    refused.push("extra-proof".into());
    proof.transactions[0]
        .signature
        .transaction
        .signature
        .equation
        .matrix
        .polynomials[0]
        .proof_bytes[0] ^= 1;
    ensure(
        node.replay_canonical_transactions_with_proof(c.tip, c.block, &proof)
            .is_err(),
        "invalid AIR proof fell back to native sender crypto",
    )?;
    proof.transactions[0]
        .signature
        .transaction
        .signature
        .equation
        .matrix
        .polynomials[0]
        .proof_bytes[0] ^= 1;
    refused.push("genuine-native-signature-corrupt-AIR".into());
    ensure(
        node.replay_canonical_transactions_with_proof(ShellHash::ZERO, c.block, &proof)
            .is_err(),
        "foreign tip accepted",
    )?;
    ensure(
        node.replay_canonical_transactions_with_proof(c.tip, ShellHash::ZERO, &proof)
            .is_err(),
        "foreign block accepted",
    )?;
    refused.extend(["foreign-tip".into(), "foreign-block".into()]);
    ensure(node.store.scan_all()? == before, "refusal wrote native KV")?;
    // An owned corrupt-history control retains the same genuine sender inputs.
    // Full sender proofs must not override deterministic native execution/root checks.
    let memory = Arc::new(MemoryDb::new());
    for (k, v) in &before {
        memory.put(k, v)?;
    }
    let corrupt = node_for_corrupt_history(memory.clone(), &c, &block)?;
    let corrupt_before = memory.scan_all()?;
    let bad_hash = corrupt
        .chain_store
        .get_head_hash()?
        .ok_or("missing corrupt tip")?;
    let error = corrupt
        .replay_canonical_transactions_with_proof(bad_hash, bad_hash, &proof)
        .err()
        .ok_or("invalid native state root accepted")?;
    ensure(
        error
            .to_string()
            .contains("state root mismatch after deterministic replay"),
        "control did not reach native execution root refusal",
    )?;
    ensure(
        memory.scan_all()? == corrupt_before && node.store.scan_all()? == before,
        "failed replay wrote state",
    )?;
    refused.push("genuine-proofs-native-state-root".into());
    println!(
        "{}",
        serde_json::json!({"mode":"rejections","refused":refused,"late_native_refusal":error.to_string(),"base_KV_unchanged":true})
    );
    Ok(())
}
fn node_for_corrupt_history(
    store: Arc<MemoryDb>,
    c: &Context,
    block: &Block,
) -> Result<Node<MemoryDb>, Error> {
    let node = node(store.clone(), c.authority, &c.authority_key)?;
    let mut changed = block.clone();
    changed.header.state_root = ShellHash::from([0x99; 32]);
    let overlay = Arc::new(shell_storage::OverlayStore::new(store));
    let chain = ChainStore::new(overlay.clone());
    let checkpoint = chain.address_metadata_checkpoint()?;
    chain.stage_address_metadata_undo(&changed.hash(), &checkpoint)?;
    chain.put_block(&changed)?;
    chain.set_canonical(changed.number(), &changed.hash())?;
    chain.set_head(&changed.hash())?;
    overlay.commit()?;
    Ok(node)
}
fn reopen(first: &LoadedEntry, second: &LoadedEntry, dir: &Path) -> Result<(), Error> {
    let c: Context = read(&dir.join("context.json"))?;
    ensure(c.version == 1, "unsupported saved context")?;
    let node = open(dir, &c)?;
    let block = node
        .chain_store
        .get_block_by_hash(&c.block)?
        .ok_or("native target absent after reopen")?;
    ensure(
        node.chain_store.get_head_hash()? == Some(c.tip) && block.transactions.len() == 2,
        "native canonical tip/body changed",
    )?;
    for entry in [first, second] {
        ensure(
            block.transactions.contains(&entry.expected)
                && node.world_state.read().get_nonce(&entry.expected.from)? == 1,
            "reopened native sender/source mismatch",
        )?;
    }
    let receipts = node
        .chain_store
        .get_receipts(&c.block)?
        .ok_or("reopened receipts absent")?;
    ensure(
        receipts.len() == 3
            && shell_core::block_receipts_root(&receipts) == block.header.receipts_root,
        "native reward/receipt root mismatch",
    )?;
    let view = node
        .chain_store
        .canonical_parent_view(c.tip, block.header.parent_hash)?;
    let parent_state = view.world_state()?;
    let mut fees = shell_primitives::U256::ZERO;
    let mut actors = Vec::new();
    for (tx, receipt) in block.transactions.iter().zip(&receipts) {
        let price = tx.tx.max_fee_per_gas.min(
            block
                .header
                .base_fee_per_gas
                .saturating_add(tx.tx.max_priority_fee_per_gas),
        );
        let fee =
            shell_primitives::U256::from(receipt.gas_used) * shell_primitives::U256::from(price);
        fees += fee;
        let account_before = parent_state
            .get_account(&tx.from)?
            .ok_or("parent sender missing")?;
        let account_after = node
            .world_state
            .read()
            .get_account(&tx.from)?
            .ok_or("current sender missing")?;
        ensure(
            account_after.balance == account_before.balance - tx.tx.value - fee
                && account_after.nonce == account_before.nonce + 1,
            "native sender value/fee/nonce accounting mismatch",
        )?;
        actors.push(serde_json::json!({"address":tx.from,"before":account_before,"after":account_after,"fee":fee}));
    }
    let recipient = first.expected.tx.to.ok_or("missing transfer recipient")?;
    ensure(
        second.expected.tx.to == Some(recipient),
        "fixture requires one shared recipient",
    )?;
    ensure(
        node.world_state.read().get_balance(&recipient)?
            == parent_state.get_balance(&recipient)?
                + first.expected.tx.value
                + second.expected.tx.value,
        "native recipient value mismatch",
    )?;
    ensure(
        block.system_transactions[0].value == fees
            && node.world_state.read().get_balance(&c.authority)?
                == parent_state.get_balance(&c.authority)? + fees,
        "native gas reward value/balance mismatch",
    )?;
    let native = serde_json::json!({"version":1,"block":block,"parent":view.parent(),"receipts":receipts,
        "senders":actors,"gas_reward":fees,"recipient":recipient,
        "recipient_balance":node.world_state.read().get_balance(&recipient)?,
        "authority":c.authority,"authority_balance":node.world_state.read().get_balance(&c.authority)?});
    let path = dir.join("native-source.json");
    if path.try_exists()? {
        ensure(
            read::<serde_json::Value>(&path)? == native,
            "saved native output differs",
        )?;
    } else {
        write(&path, &native)?;
    }
    println!(
        "{}",
        serde_json::json!({"mode":"reopen","actual_Node_RocksDB_reopen":true,"native_receipts":3,"historical_parent_nonce":0,"current_nonce":1,"native_value_fee_reward_accounting":true,"gas_reward":fees})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure(args.len()==5,"usage: mldsa-node-replay init|verify|rejections|reopen first-graph second-graph account-state output")?;
    let first_paths = graph::paths(Path::new(&args[1]))?;
    let second_paths = graph::paths(Path::new(&args[2]))?;
    let state = Path::new(&args[3]).canonicalize()?;
    let output = std::path::absolute(&args[4])?;
    let parent = output
        .parent()
        .ok_or("missing output parent")?
        .canonicalize()?;
    let output = if output.try_exists()? {
        output.canonicalize()?
    } else {
        parent.join(output.file_name().ok_or("invalid output")?)
    };
    for input in [
        &first_paths.source,
        &first_paths.equation,
        &first_paths.signature,
        &first_paths.sender,
        &first_paths.id,
        &first_paths.entry,
        &second_paths.source,
        &second_paths.equation,
        &second_paths.signature,
        &second_paths.sender,
        &second_paths.id,
        &second_paths.entry,
        &state,
    ] {
        let input = input.canonicalize()?;
        ensure(
            !output.starts_with(&input) && !input.starts_with(&output),
            "output overlaps immutable proof input",
        )?;
    }
    let (first, _, _) = graph::load(Path::new(&args[1]))?;
    let (second, _, _) = graph::load(Path::new(&args[2]))?;
    match args[0].as_str() {
        "init" => init(&first, &second, &state, &output),
        "verify" => verify(&first, &second, &state, &output),
        "rejections" => rejections(&first, &second, &state, &output),
        "reopen" => reopen(&first, &second, &output),
        _ => Err("unknown node proof replay operation".into()),
    }
}
