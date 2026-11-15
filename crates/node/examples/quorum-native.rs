//! Controlled primary quorum AIR with real Native transfers and RocksDB history.
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shell_consensus::{ConsensusEngine, PoaConfig, WPoaConfig, WPoaEngine};
use shell_core::{Account, Block, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, MlDsaSigner, MultiVerifier, Signer};
use shell_mempool::TxPool;
use shell_node::{Node, NodeConfig};
use shell_primitives::{blake3_hash, Address, U256};
use shell_stark_prover::commit_quorum::{
    verify_commit_quorum, CommitQuorumProof, CommitQuorumSource,
};
use shell_storage::{ChainConfig, ChainStore, KvStore, RocksDbStore, WorldState};
use std::{collections::HashMap, io::Read, path::Path, sync::Arc};
type Error = Box<dyn std::error::Error>;
const INITIAL: u64 = 1_000_000_000;

#[derive(Serialize, Deserialize)]
struct Control {
    authority: Address,
    authority_key: Vec<u8>,
    sender: Address,
    sender_key: Vec<u8>,
    recipient: Address,
    genesis: Block,
    blocks: Vec<Block>,
    certificates: Vec<Vec<u8>>,
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > 512 * 1024 * 1024 {
        return Err("native quorum input bound".into());
    }
    let mut file = std::io::BufReader::new(file);
    let value = ciborium::de::from_reader(&mut file)?;
    if file.read(&mut [0])? != 0 {
        return Err("trailing native quorum input".into());
    }
    Ok(value)
}
fn write(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    ciborium::ser::into_writer(value, &mut file)?;
    file.sync_all()?;
    Ok(())
}
fn ensure(value: bool, message: &str) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn node(path: &Path, control: &Control, initialize: bool) -> Result<Node<RocksDbStore>, Error> {
    if !initialize {
        ensure(
            path.join("CURRENT").is_file(),
            "existing Native database required",
        )?;
    }
    let stores = RocksDbStore::open_all(path, None)?;
    node_on_store(Arc::new(stores.state), control, initialize)
}
fn node_on_store<S: KvStore + 'static>(
    store: Arc<S>,
    control: &Control,
    initialize: bool,
) -> Result<Node<S>, Error> {
    node_on_store_with_activation(store, control, initialize, Some(1))
}
fn node_on_store_with_activation<S: KvStore + 'static>(
    store: Arc<S>,
    control: &Control,
    initialize: bool,
    commitment_height: Option<u64>,
) -> Result<Node<S>, Error> {
    let chain = Arc::new(ChainStore::new(store.clone()));
    if initialize {
        ensure(
            store.scan_all()?.is_empty(),
            "Native destination is not empty",
        )?;
        let mut world = WorldState::new(store.clone());
        world.set_account(
            &control.sender,
            &Account::new_user_account(blake3_hash(&control.sender_key), U256::from(INITIAL)),
        )?;
        ensure(
            world.state_root()? == control.genesis.header.state_root,
            "funded genesis root mismatch",
        )?;
        chain.put_pubkey(&control.sender, &control.sender_key)?;
        chain.put_pubkey(&control.authority, &control.authority_key)?;
        let cfg: ChainConfig = serde_json::from_value(
            serde_json::json!({"chain_id":1337,"genesis_hash":control.genesis.hash(),"fee_accounting_activation_height":1,"native_address_context_height":1,"block_commitment_height":commitment_height}),
        )?;
        chain.commit_genesis_block(&control.genesis, &cfg)?;
    }
    ensure(
        chain.get_pubkey(&control.authority)?.as_ref() == Some(&control.authority_key),
        "Native authority registry mismatch",
    )?;
    let head = chain.get_head_block()?.ok_or("Native head absent")?;
    let world = Arc::new(RwLock::new(WorldState::at_root(
        store.clone(),
        &head.header.state_root,
    )?));
    let mut config = NodeConfig::dev(control.authority);
    config.chain_id = 1337;
    config.mempool.chain_id = 1337;
    config.enable_stark_aggregation = false;
    let mut poa = WPoaConfig::from_poa(PoaConfig::new(vec![control.authority], 1));
    poa.chain_id = 1337;
    config.consensus = shell_node::ConsensusEngineConfig::WPoa(poa.clone());
    let pool = Arc::new(TxPool::new(config.mempool.clone()));
    let consensus: Arc<RwLock<dyn ConsensusEngine>> =
        Arc::new(RwLock::new(WPoaEngine::new(poa, Arc::new(MultiVerifier))));
    Ok(Node::new(config, store, chain, world, pool, consensus))
}
fn balances<S: KvStore + 'static>(node: &Node<S>, c: &Control, count: usize) -> Result<(), Error> {
    let state = node.world_state.read();
    let sender = state.get_account(&c.sender)?.ok_or("sender missing")?;
    let recipient = state
        .get_account(&c.recipient)?
        .ok_or("recipient missing")?;
    let sent = (1..=count as u64).map(|i| 100 * i).sum::<u64>();
    let fees: u64 = c.blocks[..count]
        .iter()
        .map(|b| b.header.gas_used * b.header.base_fee_per_gas)
        .sum();
    ensure(
        sender.nonce == count as u64
            && sender.balance == U256::from(INITIAL - sent - fees)
            && recipient.balance == U256::from(sent),
        "Native nonce/value/fee balance mismatch",
    )
}
fn prepare(root: &Path) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    let authority = MlDsaSigner::generate();
    let sender = DilithiumSigner::generate();
    let mut c = Control {
        authority: Address::from_public_key(authority.public_key(), authority.sig_type().as_u8()),
        authority_key: authority.public_key().to_vec(),
        sender: Address::from_public_key(sender.public_key(), sender.sig_type().as_u8()),
        sender_key: sender.public_key().to_vec(),
        recipient: Address::from([0x34; 32]),
        genesis: Block {
            header: BlockHeader::default(),
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        },
        blocks: vec![],
        certificates: vec![],
    };
    let memory = Arc::new(shell_storage::MemoryDb::new());
    let mut world = WorldState::new(memory);
    world.set_account(
        &c.sender,
        &Account::new_user_account(blake3_hash(&c.sender_key), U256::from(INITIAL)),
    )?;
    c.genesis.header = BlockHeader {
        state_root: world.state_root()?,
        timestamp: 1_700_000_000,
        gas_limit: 30_000_000,
        base_fee_per_gas: 1,
        proposer: c.authority,
        ..Default::default()
    };
    let provider = node(&root.join("provider-db"), &c, true)?;
    let follower = node(&root.join("control-db"), &c, true)?;
    for nonce in 0..3 {
        let tx = Transaction {
            chain_id: 1337,
            nonce,
            to: Some(c.recipient),
            value: U256::from(100 * (nonce + 1)),
            data: Default::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 0,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let signature = sender.sign(tx.signing_hash(sender.sig_type().as_u8()).as_bytes())?;
        let signed = SignedTransaction::new(c.sender, tx, signature);
        if nonce == 0 {
            let before = provider.store.scan_all()?;
            let mut bad = signed.clone();
            bad.signature.data[0] ^= 1;
            ensure(
                provider.handle_incoming_tx(bad, &MultiVerifier).is_err(),
                "tampered sender admitted",
            )?;
            ensure(
                provider.store.scan_all()? == before,
                "sender refusal wrote Native rows",
            )?;
        }
        provider.handle_incoming_tx(signed, &MultiVerifier)?;
        let block = provider.produce_block(&authority, 1)?;
        ensure(
            block.transactions.len() == 1 && block.header.gas_used == 21_000,
            "Native transfer not executed",
        )?;
        let cert = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([(
            c.authority,
            authority.sign(block.hash().as_bytes())?,
        )]))?;
        write(&root.join(format!("block-{}.cbor", nonce + 1)), &block)?;
        write(&root.join(format!("certificate-{}.cbor", nonce + 1)), &cert)?;
        follower.import_block(block.clone(), &MultiVerifier)?;
        let receipts = provider
            .chain_store
            .get_receipts(&block.hash())?
            .ok_or("receipt missing")?;
        let ordinary: Vec<_> = receipts
            .iter()
            .filter(|r| r.tx_hash == block.transactions[0].uncached_hash())
            .collect();
        ensure(
            ordinary.len() == 1
                && ordinary[0].status == 1
                && ordinary[0].gas_used == 21_000
                && Some(receipts) == follower.chain_store.get_receipts(&block.hash())?,
            "Native receipt/import mismatch",
        )?;
        if nonce == 0 {
            let source = provider.commit_quorum_source(1, block.hash(), &cert)?;
            write(&root.join("source.cbor"), &source)?;
            ensure(
                provider.fast_finalize_with_certificate(1, block.hash(), &cert)
                    && follower.fast_finalize_with_certificate(1, block.hash(), &cert),
                "ordinary Native QC control failed",
            )?;
        }
        c.blocks.push(block);
        c.certificates.push(cert);
        write(&root.join(format!("control-{}.cbor", nonce + 1)), &c)?;
        ensure(
            provider.world_state.write().state_root()?
                == follower.world_state.write().state_root()?,
            "Native execution/import root mismatch",
        )?;
    }
    let source = provider.commit_quorum_source(1, c.blocks[0].hash(), &c.certificates[0])?;
    ensure(
        source.signatures[0].signature.sig_type == shell_crypto::SignatureType::MlDsa65,
        "primary QC profile missing",
    )?;
    provider.store.flush()?;
    follower.store.flush()?;
    write(&root.join("control.cbor"), &c)?;
    balances(&provider, &c, 3)?;
    balances(&follower, &c, 3)?;
    drop(sender);
    drop(authority);
    println!(
        "{}",
        serde_json::json!({"prepared":true,"genuineNativeTransfers":3,"independentRocksDBControls":2,"primaryQuorumSignature":true,"finalized":1,"temporaryKeysDroppedAfterAllControls":true,"newCohort":true})
    );
    Ok(())
}
fn verify(root: &Path, proof_file: &Path) -> Result<(), Error> {
    let c: Control = read(&root.join("control.cbor"))?;
    let source: CommitQuorumSource = read(&root.join("source.cbor"))?;
    let mut proof: CommitQuorumProof = read(proof_file)?;
    ensure(
        c.blocks.len() == 3 && c.certificates.len() == 3,
        "complete original Native controls required",
    )?;
    {
        let provider = node(&root.join("provider-db"), &c, false)?;
        ensure(
            provider.commit_quorum_source(1, c.blocks[0].hash(), &c.certificates[0])? == source,
            "expected source differs from Native provider",
        )?;
        verify_commit_quorum(&proof, &source)?;
    }
    let fresh = !root.join("receiver-db").exists();
    let receiver = node(&root.join("receiver-db"), &c, fresh)?;
    if fresh {
        receiver.import_block(c.blocks[0].clone(), &MultiVerifier)?;
        let before = receiver.store.scan_all()?;
        proof.version = 0;
        ensure(
            !receiver.fast_finalize_with_certificate_proof(
                1,
                c.blocks[0].hash(),
                &c.certificates[0],
                &proof,
            ),
            "bad proof finalized",
        )?;
        proof.version = 1;
        ensure(
            receiver.store.scan_all()? == before,
            "proof refusal wrote Native rows",
        )?;
        ensure(
            receiver.fast_finalize_with_certificate_proof(
                1,
                c.blocks[0].hash(),
                &c.certificates[0],
                &proof,
            ),
            "full primary quorum proof refused",
        )?;
        for block in &c.blocks[1..] {
            let before = receiver.store.scan_all()?;
            let mut bad = block.clone();
            bad.transactions[0].signature.data[0] ^= 1;
            ensure(
                receiver.import_block(bad, &MultiVerifier).is_err()
                    && receiver.store.scan_all()? == before,
                "bad imported body changed Native rows",
            )?;
            receiver.import_block(block.clone(), &MultiVerifier)?;
        }
        receiver.store.flush()?;
    }
    balances(&receiver, &c, 3)?;
    ensure(
        receiver.chain_store.get_finalized_number()? == Some(1)
            && receiver
                .chain_store
                .get_commit_certificate(&c.blocks[0].hash())?
                == Some(c.certificates[0].clone())
            && receiver
                .chain_store
                .get_block_signers(&c.blocks[0].hash())?
                == source.signatures,
        "persisted proof finality/evidence mismatch",
    )?;
    let mut replay = None;
    for name in ["provider-db", "control-db", "receiver-db"] {
        // Receiver is already exclusively open in this process.
        let reopened;
        let current = if name == "receiver-db" {
            &receiver
        } else {
            reopened = node(&root.join(name), &c, false)?;
            &reopened
        };
        let before = current.store.scan_all()?;
        ensure(
            current.commit_quorum_source(1, c.blocks[0].hash(), &c.certificates[0])? == source,
            "independent current authority context differs",
        )?;
        let result = current.replay_canonical_block_with_commit_proof(
            c.blocks[2].hash(),
            c.blocks[0].hash(),
            &c.certificates[0],
            &proof,
        )?;
        ensure(
            result.proved_commit_signatures == 1
                && result.execution.proved_sender_signatures == 0
                && result.execution.state_root == c.blocks[0].header.state_root
                && Some(result.execution.receipts.clone())
                    == current.chain_store.get_receipts(&c.blocks[0].hash())?,
            "historical quorum/Native execution mismatch",
        )?;
        if let Some(expected) = &replay {
            ensure(
                expected == &result,
                "independent historical controls differ",
            )?;
        } else {
            replay = Some(result);
        }
        let mut corrupt = source.signatures[0].signature.clone();
        corrupt.data[0] ^= 1;
        let bad_cert = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([(
            c.authority,
            corrupt,
        )]))?;
        ensure(
            current
                .replay_canonical_block_with_commit_proof(
                    c.blocks[2].hash(),
                    c.blocks[0].hash(),
                    &bad_cert,
                    &proof,
                )
                .is_err(),
            "changed historical certificate accepted",
        )?;
        current
            .consensus
            .write()
            .set_authorities_with_weights(vec![c.authority], vec![2]);
        let changed_weight_refused = current
            .replay_canonical_block_with_commit_proof(
                c.blocks[2].hash(),
                c.blocks[0].hash(),
                &c.certificates[0],
                &proof,
            )
            .is_err();
        current
            .consensus
            .write()
            .set_authorities_with_weights(vec![c.authority], vec![1]);
        ensure(
            changed_weight_refused,
            "changed current quorum weights accepted",
        )?;
        ensure(
            current
                .replay_canonical_block_with_commit_proof(
                    c.blocks[0].hash(),
                    c.blocks[0].hash(),
                    &c.certificates[0],
                    &proof,
                )
                .is_err(),
            "stale expected tip accepted",
        )?;
        proof.weight.proof_bytes[0] ^= 1;
        let damaged_weight_refused = current
            .replay_canonical_block_with_commit_proof(
                c.blocks[2].hash(),
                c.blocks[0].hash(),
                &c.certificates[0],
                &proof,
            )
            .is_err();
        proof.weight.proof_bytes[0] ^= 1;
        ensure(damaged_weight_refused, "damaged weight proof accepted")?;
        proof.signatures[0].version = 0;
        let missing_signature_refused = current
            .replay_canonical_block_with_commit_proof(
                c.blocks[2].hash(),
                c.blocks[0].hash(),
                &c.certificates[0],
                &proof,
            )
            .is_err();
        proof.signatures[0].version = 1;
        ensure(
            missing_signature_refused,
            "missing full signature graph accepted",
        )?;
        proof.version = 0;
        ensure(
            current
                .replay_canonical_block_with_commit_proof(
                    c.blocks[2].hash(),
                    c.blocks[0].hash(),
                    &c.certificates[0],
                    &proof,
                )
                .is_err(),
            "bad historical proof accepted",
        )?;
        proof.version = 1;
        ensure(
            !current.fast_finalize_with_certificate_proof(
                2,
                c.blocks[1].hash(),
                &c.certificates[1],
                &proof,
            ),
            "wrong target finalized",
        )?;
        balances(current, &c, 3)?;
        ensure(
            current.world_state.write().state_root()? == c.blocks[2].header.state_root
                && current.chain_store.get_finalized_number()? == Some(1),
            "historical/refusal path changed current state or finality",
        )?;
        ensure(
            current.store.scan_all()? == before,
            "historical/refusal path wrote current Native rows",
        )?;
    }
    println!(
        "{}",
        serde_json::json!({"freshReceiverImport":fresh,"currentHeight":3,"finalized":1,"primaryCommitSignaturesProved":1,"senderSignaturesNative":true,"gasAndBalancesVerified":true,"historicalRootAndReceiptsMatch":true,"allThreeNativeStoresUnchangedByHistoryAndRefusals":true,"realPeerTransport":false,"historicalValidatorProvenanceAir":false})
    );
    Ok(())
}
fn inspect(root: &Path) -> Result<(), Error> {
    ensure(
        root.join("provider-db/CURRENT").is_file(),
        "original Native provider required",
    )?;
    let c = {
        let stores = RocksDbStore::open_all(root.join("provider-db"), None)?;
        let chain = ChainStore::new(Arc::new(stores.state));
        let block: Block = read(&root.join("block-1.cbor"))?;
        let sender = block
            .transactions
            .first()
            .ok_or("original transaction absent")?
            .from;
        let authority = block.header.proposer;
        Control {
            authority,
            authority_key: chain
                .get_pubkey(&authority)?
                .ok_or("authority key absent")?,
            sender,
            sender_key: chain.get_pubkey(&sender)?.ok_or("sender key absent")?,
            recipient: block.transactions[0].tx.to.ok_or("recipient absent")?,
            genesis: chain.get_block_by_number(0)?.ok_or("genesis absent")?,
            blocks: vec![block],
            certificates: vec![read(&root.join("certificate-1.cbor"))?],
        }
    };
    let mut count = 0;
    let mut expected_receipts = None;
    for name in ["provider-db", "control-db"] {
        let current = node(&root.join(name), &c, false)?;
        let before = current.store.scan_all()?;
        let receipts = current
            .chain_store
            .get_receipts(&c.blocks[0].hash())?
            .ok_or("original receipts absent")?;
        let ordinary: Vec<_> = receipts
            .iter()
            .filter(|r| r.tx_hash == c.blocks[0].transactions[0].uncached_hash())
            .collect();
        ensure(
            ordinary.len() == 1 && ordinary[0].status == 1 && ordinary[0].gas_used == 21_000,
            "original ordinary receipt invalid",
        )?;
        count = receipts.len();
        if let Some(expected) = &expected_receipts {
            ensure(expected == &receipts, "original imported receipts differ")?;
        } else {
            expected_receipts = Some(receipts);
        }
        balances(&current, &c, 1)?;
        ensure(
            current.store.scan_all()? == before,
            "original receipt inspection wrote Native rows",
        )?;
    }
    println!(
        "{}",
        serde_json::json!({"sameOriginalReceiptAssertionCorrected":true,"ordinaryReceiptCount":1,"totalReceiptCount":count,"independentNativeStoresUnchanged":true,"originalHeaderAndQuorumRetained":true,"successor2Retained":root.join("block-2.cbor").is_file(),"privateIdentityRecreated":false})
    );
    Ok(())
}
type Rows = Vec<(Vec<u8>, Vec<u8>)>;
struct FailingBatch {
    inner: RocksDbStore,
    armed: std::sync::atomic::AtomicBool,
    attempted: std::sync::atomic::AtomicBool,
    complete_tuple: std::sync::atomic::AtomicBool,
    certificate: Vec<u8>,
}
impl KvStore for FailingBatch {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, shell_storage::StorageError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), shell_storage::StorageError> {
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), shell_storage::StorageError> {
        self.inner.delete(key)
    }
    fn flush(&self) -> Result<(), shell_storage::StorageError> {
        self.inner.flush()
    }
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Rows, shell_storage::StorageError> {
        self.inner.scan_prefix(prefix)
    }
    fn snapshot_prefixes(
        &self,
        prefixes: &[&[u8]],
        max_bytes: usize,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, shell_storage::StorageError> {
        self.inner.snapshot_prefixes(prefixes, max_bytes)
    }
    fn write_batch(
        &self,
        batch: shell_storage::WriteBatch,
    ) -> Result<(), shell_storage::StorageError> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.armed.swap(false, SeqCst) {
            let puts = batch
                .ops()
                .iter()
                .filter_map(|op| match op {
                    shell_storage::WriteBatchOp::Put { key, value } => {
                        Some((key.as_slice(), value.as_slice()))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            self.attempted.store(true, SeqCst);
            self.complete_tuple.store(
                puts.iter().any(|(key, _)| *key == b"HEAD")
                    && puts.iter().any(|(key, _)| *key == b"FINALIZED")
                    && puts.iter().any(|(_, value)| *value == self.certificate),
                SeqCst,
            );
            return Err(shell_storage::StorageError::Database(
                "injected canonical batch failure".into(),
            ));
        }
        self.inner.write_batch(batch)
    }
}
fn receive(
    controls: &Path,
    proof_file: &Path,
    root: &Path,
    fresh: bool,
    resume: bool,
) -> Result<(), Error> {
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    let c: Control = read(&controls.join("control.cbor"))?;
    let source: CommitQuorumSource = read(&controls.join("source.cbor"))?;
    let proof: CommitQuorumProof = read(proof_file)?;
    ensure(
        c.blocks.len() == 3 && c.certificates.len() == 3,
        "original complete controls required",
    )?;
    if fresh {
        std::fs::create_dir(root)?;
    } else {
        ensure(
            root.join("db/CURRENT").is_file() && root.join("control-db/CURRENT").is_file(),
            "existing import controls required",
        )?;
    }
    let stores = RocksDbStore::open_all(root.join("db"), None)?;
    let store = Arc::new(FailingBatch {
        inner: stores.state,
        armed: AtomicBool::new(false),
        attempted: AtomicBool::new(false),
        complete_tuple: AtomicBool::new(false),
        certificate: c.certificates[0].clone(),
    });
    let mut receiver = node_on_store(store.clone(), &c, fresh)?;
    let normal = node(&root.join("control-db"), &c, fresh)?;
    if fresh || resume {
        ensure(
            receiver.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && normal.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && receiver.finality.read().last_finalized_number() == 0
                && normal.finality.read().last_finalized_number() == 0
                && receiver.store.scan_all()? == normal.store.scan_all()?,
            "resume requires original unchanged genesis controls",
        )?;
        let before = receiver.store.scan_all()?;
        for case in 0..7 {
            let mut altered = proof.clone();
            let mut cert = c.certificates[0].clone();
            let mut block = c.blocks[0].clone();
            let mut parent = c.genesis.hash();
            match case {
                0 => altered.version = 0,
                1 => altered.weight.proof_bytes[0] ^= 1,
                2 => altered.signatures[0].version = 0,
                3 => {
                    let mut sig = source.signatures[0].signature.clone();
                    sig.data[0] ^= 1;
                    cert = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([(
                        c.authority,
                        sig,
                    )]))?;
                }
                4 => parent = c.blocks[0].hash(),
                5 => block.transactions[0].signature.data[0] ^= 1,
                _ => receiver
                    .consensus
                    .write()
                    .set_authorities_with_weights(vec![c.authority], vec![2]),
            }
            let refused = receiver
                .import_block_with_commit_proof(parent, block, &cert, &altered)
                .is_err();
            receiver
                .consensus
                .write()
                .set_authorities_with_weights(vec![c.authority], vec![1]);
            ensure(
                refused
                    && receiver.store.scan_all()? == before
                    && receiver.finality.read().last_finalized_number() == 0,
                "fresh quorum refusal changed Native rows/finality",
            )?;
        }
        let original_config = receiver
            .chain_store
            .get_chain_config()?
            .ok_or("configuration absent")?;
        let mut changed_config = original_config.clone();
        changed_config.block_commitment_height = None;
        // Retained genesis configuration is immutable. Recheck the original
        // failed operation as an expected refusal rather than bypassing it.
        ensure(
            receiver
                .chain_store
                .put_chain_config(&changed_config)
                .is_err()
                && receiver.store.scan_all()? == before,
            "stored configuration mutation accepted/wrote rows",
        )?;
        for (name, activation) in [("inactive-none", None), ("inactive-two", Some(2))] {
            let path = root.join(name);
            let initialize = !path.exists();
            ensure(
                initialize || path.join("CURRENT").is_file(),
                "inactive control database incomplete",
            )?;
            let stores = RocksDbStore::open_all(&path, None)?;
            let mut inactive =
                node_on_store_with_activation(Arc::new(stores.state), &c, initialize, activation)?;
            ensure(
                inactive
                    .chain_store
                    .get_chain_config()?
                    .ok_or("inactive configuration absent")?
                    .block_commitment_height
                    == activation,
                "inactive genesis configuration differs",
            )?;
            let rows = inactive.store.scan_all()?;
            ensure(
                inactive
                    .import_block_with_commit_proof(
                        c.genesis.hash(),
                        c.blocks[0].clone(),
                        &c.certificates[0],
                        &proof,
                    )
                    .is_err()
                    && inactive.store.scan_all()? == rows
                    && inactive.finality.read().last_finalized_number() == 0,
                "inactive genesis quorum import accepted/wrote rows",
            )?;
        }
        store.armed.store(true, SeqCst);
        ensure(
            receiver
                .import_block_with_commit_proof(
                    c.genesis.hash(),
                    c.blocks[0].clone(),
                    &c.certificates[0],
                    &proof,
                )
                .is_err(),
            "injected batch failure accepted",
        )?;
        ensure(
            store.attempted.load(SeqCst)
                && store.complete_tuple.load(SeqCst)
                && receiver.store.scan_all()? == before
                && receiver.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && receiver.world_state.write().state_root()? == c.genesis.header.state_root
                && receiver.finality.read().last_finalized_number() == 0,
            "canonical batch failure published partial execution/QC/finality",
        )?;
        let result = receiver.import_block_with_commit_proof(
            c.genesis.hash(),
            c.blocks[0].clone(),
            &c.certificates[0],
            &proof,
        )?;
        ensure(
            result.proved_commit_signatures == 1
                && result.execution.proved_sender_signatures == 0
                && result.execution.state_root == c.blocks[0].header.state_root
                && Some(result.execution.receipts)
                    == receiver.chain_store.get_receipts(&c.blocks[0].hash())?
                && receiver.finality.read().last_finalized_number() == 1,
            "atomic full quorum import result differs",
        )?;
        normal.import_block(c.blocks[0].clone(), &MultiVerifier)?;
        ensure(
            normal.fast_finalize_with_certificate(1, c.blocks[0].hash(), &c.certificates[0]),
            "Native reference finality failed",
        )?;
        for block in &c.blocks[1..] {
            receiver.import_block(block.clone(), &MultiVerifier)?;
            normal.import_block(block.clone(), &MultiVerifier)?;
        }
        receiver.store.flush()?;
        normal.store.flush()?;
    }
    balances(&receiver, &c, 3)?;
    balances(&normal, &c, 3)?;
    ensure(
        receiver.store.scan_all()? == normal.store.scan_all()?,
        "atomic/ordinary independent Native stores differ",
    )?;
    ensure(
        normal.chain_store.get_finalized_number()? == Some(1)
            && normal.finality.read().last_finalized_number() == 1,
        "cold normal finality mismatch",
    )?;
    ensure(
        receiver.chain_store.get_finalized_number()? == Some(1)
            && receiver.finality.read().last_finalized_number() == 1
            && receiver
                .chain_store
                .get_commit_certificate(&c.blocks[0].hash())?
                == Some(c.certificates[0].clone())
            && receiver
                .chain_store
                .get_block_signers(&c.blocks[0].hash())?
                == source.signatures,
        "cold proof import evidence/finality mismatch",
    )?;
    let before = receiver.store.scan_all()?;
    let result = receiver.replay_canonical_block_with_commit_proof(
        c.blocks[2].hash(),
        c.blocks[0].hash(),
        &c.certificates[0],
        &proof,
    )?;
    let normal_before = normal.store.scan_all()?;
    ensure(
        result
            == normal.replay_canonical_block_with_commit_proof(
                c.blocks[2].hash(),
                c.blocks[0].hash(),
                &c.certificates[0],
                &proof,
            )?
            && receiver
                .import_block_with_commit_proof(
                    c.genesis.hash(),
                    c.blocks[0].clone(),
                    &c.certificates[0],
                    &proof,
                )
                .is_err()
            && receiver.store.scan_all()? == before
            && normal.store.scan_all()? == normal_before,
        "cold import history/duplicate refusal changed Native rows",
    )?;
    println!(
        "{}",
        serde_json::json!({"freshAtomicImport":fresh || resume,"resumedOriginalPartial":resume,"backendFailureRollbackChecked":fresh || resume,"independentNativeRowsEqual":true,"currentHeight":3,"finalized":1,"commitSignaturesProved":1,"senderAndProposerCryptoNative":true,"historicalRowsUnchanged":true,"originalControlsAndProofReused":true,"newSigningOrProofGeneration":false,"realPeerTransport":false})
    );
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("receive" | "receive-resume" | "receive-verify") if args.len() == 4 => receive(Path::new(&args[1]), Path::new(&args[2]), Path::new(&args[3]), args[0] == "receive", args[0] == "receive-resume"),
        Some("prepare") if args.len() == 2 => prepare(Path::new(&args[1])),
        Some("inspect") if args.len() == 2 => inspect(Path::new(&args[1])),
        Some("verify") if args.len() == 3 => verify(Path::new(&args[1]), Path::new(&args[2])),
        _ => Err("usage: quorum-native prepare <new-control-directory> | inspect <control-directory> | verify <control-directory> <full-quorum-proof.cbor> | receive <original-controls> <full-proof.cbor> <new-import-directory> | receive-resume <original-controls> <full-proof.cbor> <original-genesis-import-directory> | receive-verify <original-controls> <full-proof.cbor> <existing-import-directory>".into()),
    }
}
