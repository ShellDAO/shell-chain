//! Controlled primary quorum AIR with real Native transfers and RocksDB history.
#[path = "common/quorum_rpc.rs"]
mod quorum_rpc;
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shell_consensus::{ConsensusEngine, PoaConfig, WPoaConfig, WPoaEngine};
use shell_core::{Account, Block, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, MlDsaSigner, MultiVerifier, Signer, SphincsSigner};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    co_authority: Option<(Address, Vec<u8>)>,
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
        if let Some((address, key)) = &control.co_authority {
            chain.put_pubkey(address, key)?;
        }

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
    if let Some((address, key)) = &control.co_authority {
        ensure(
            chain.get_pubkey(address)?.as_ref() == Some(key),
            "co-authority registry mismatch",
        )?;
    }
    let (authorities, weights) = authority_weights(control);
    let mut poa = WPoaConfig::with_weights(PoaConfig::new(authorities, 1), weights);
    poa.chain_id = 1337;
    config.consensus = shell_node::ConsensusEngineConfig::WPoa(poa.clone());
    let pool = Arc::new(TxPool::new(config.mempool.clone()));
    let consensus: Arc<RwLock<dyn ConsensusEngine>> =
        Arc::new(RwLock::new(WPoaEngine::new(poa, Arc::new(MultiVerifier))));
    Ok(Node::new(config, store, chain, world, pool, consensus))
}
fn authority_weights(c: &Control) -> (Vec<Address>, Vec<u64>) {
    match &c.co_authority {
        Some((address, _)) => (vec![c.authority, *address], vec![2, 1]),
        None => (vec![c.authority], vec![1]),
    }
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
fn prepare(
    root: &Path,
    certified_spacing: bool,
    slh: bool,
    slh_history: bool,
    mixed: bool,
) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    let authority: Box<dyn Signer> = if slh {
        Box::new(SphincsSigner::generate())
    } else {
        Box::new(MlDsaSigner::generate())
    };
    let co = mixed.then(MlDsaSigner::generate);
    let sender = DilithiumSigner::generate();
    let mut c = Control {
        co_authority: co.as_ref().map(|signer| {
            (
                Address::from_public_key(signer.public_key(), signer.sig_type().as_u8()),
                signer.public_key().to_vec(),
            )
        }),
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
    let mut provider = node(&root.join("provider-db"), &c, true)?;
    let mut follower = node(&root.join("control-db"), &c, true)?;
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
        if certified_spacing && nonce > 0 {
            // Build new controls at real elapsed times. A later co-signed
            // certificate cannot authorize a rotated proposer before timeout.
            std::thread::sleep(std::time::Duration::from_millis(
                shell_consensus::VIEW_CHANGE_TIMEOUT_MS,
            ));
        }
        let proposer: &dyn Signer = if provider
            .consensus
            .read()
            .is_proposer(nonce + 1, &c.authority)
        {
            authority.as_ref()
        } else {
            co.as_ref().ok_or("expected proposer key absent")?
        };
        provider.config.proposer_address = Some(Address::from_public_key(
            proposer.public_key(),
            proposer.sig_type().as_u8(),
        ));
        let block = provider.produce_block(proposer, 1)?;
        ensure(
            block.transactions.len() == 1 && block.header.gas_used == 21_000,
            "Native transfer not executed",
        )?;
        let mut votes = HashMap::from([(c.authority, authority.sign(block.hash().as_bytes())?)]);
        if let Some(co) = &co {
            let address = c
                .co_authority
                .as_ref()
                .ok_or("coauthority context absent")?
                .0;
            votes.insert(address, co.sign(block.hash().as_bytes())?);
        }
        let cert = Node::<RocksDbStore>::encode_commit_certificate(&votes)?;
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
        if let Some((address, _)) = &c.co_authority {
            let only = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([(
                c.authority,
                votes[&c.authority].clone(),
            )]))?;
            let mut damaged = votes[address].clone();
            damaged.data[0] ^= 1;
            let bad = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([
                (c.authority, votes[&c.authority].clone()),
                (*address, damaged),
            ]))?;
            for n in [&provider, &follower] {
                let before = n.store.scan_all()?;
                let finality = {
                    let f = n.finality.read();
                    (f.last_finalized_number(), *f.last_finalized_hash())
                };
                for rejected in [&only, &bad] {
                    ensure(
                        !n.fast_finalize_with_certificate(nonce + 1, block.hash(), rejected)
                            && n.store.scan_all()? == before
                            && {
                                let f = n.finality.read();
                                (f.last_finalized_number(), *f.last_finalized_hash())
                            } == finality,
                        "mixed quorum refusal changed Native rows/finality",
                    )?;
                }
                if nonce > 0 {
                    ensure(
                        n.fast_finalize_with_certificate(nonce + 1, block.hash(), &cert),
                        "mixed successor finality failed",
                    )?;
                }
            }
        }
        if nonce == 0 && slh {
            ensure(
                provider.fast_finalize_with_certificate(1, block.hash(), &cert)
                    && follower.fast_finalize_with_certificate(1, block.hash(), &cert),
                "ordinary SLH Native QC control failed",
            )?;
            c.blocks.push(block.clone());
            c.certificates.push(cert.clone());
            write(&root.join("control.cbor"), &c)?;
            provider.store.flush()?;
            follower.store.flush()?;
            balances(&provider, &c, 1)?;
            balances(&follower, &c, 1)?;
            println!(
                "{}",
                serde_json::json!({"ordinaryNativeSLHAuthorityAccepted":true,"head":1,"finalized":1,"independentReceiptsEqual":true,"authorityKeyBytes":c.authority_key.len(),"signedControlsRetained":true,"privateKeysPersisted":false})
            );
            // Keep the exact original signed block/certificate even if source capture refuses.
            let source = provider.commit_quorum_source(1, block.hash(), &cert)?;
            write(&root.join("source.cbor"), &source)?;
            if !slh_history {
                return Ok(());
            }
            // Preserve the independent Native1 pair for bounded production.
            // Advance separate stores while the temporary signers still exist.
            drop(provider);
            drop(follower);
            provider = node(&root.join("history-provider-db"), &c, true)?;
            follower = node(&root.join("history-control-db"), &c, true)?;
            for n in [&provider, &follower] {
                n.import_block(block.clone(), &MultiVerifier)?;
                ensure(
                    n.fast_finalize_with_certificate(1, block.hash(), &cert),
                    "history reference first SLH certificate failed",
                )?;
            }
            continue;
        }
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
    let before = provider.store.scan_all()?;
    let source = provider.commit_quorum_source(1, c.blocks[0].hash(), &c.certificates[0])?;
    ensure(
        source.signatures.len() == 1 + usize::from(mixed)
            && source.signatures.iter().any(|signer| {
                signer.signature.sig_type
                    == if slh {
                        shell_crypto::SignatureType::SphincsSha2256f
                    } else {
                        shell_crypto::SignatureType::MlDsa65
                    }
            }),
        "control QC profile missing",
    )?;
    if slh_history {
        ensure(
            source == read::<CommitQuorumSource>(&root.join("source.cbor"))?
                && provider.store.scan_all()? == before,
            "historical SLH source changed or wrote current Native rows",
        )?;
    }
    provider.store.flush()?;
    follower.store.flush()?;
    write(
        &root.join(if slh_history {
            "history-control.cbor"
        } else {
            "control.cbor"
        }),
        &c,
    )?;
    balances(&provider, &c, 3)?;
    balances(&follower, &c, 3)?;
    if mixed {
        ensure(
            provider.store.scan_all()? == follower.store.scan_all()?,
            "independent mixed Native3 rows differ",
        )?;
    }
    drop(co);
    drop(sender);
    drop(authority);
    println!(
        "{}",
        serde_json::json!({"prepared":true,"genuineNativeTransfers":3,"independentRocksDBControls":if slh_history {4}else{2},"primaryQuorumSignature":!slh,"fullSLHHistoryControls":slh_history,"firstBlockSourceUnchangedAtHeight3":slh_history,"mixedAuthority":mixed,"head":provider.chain_store.get_head_block()?.ok_or("prepared head absent")?.number(),"finalized":provider.chain_store.get_finalized_number()?,"temporaryKeysDroppedAfterAllControls":true,"privateKeysPersisted":false,"newCohort":true})
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
            result.proved_commit_signatures == source.signatures.len()
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
            .set_authorities_with_weights(authority_weights(&c).0, authority_weights(&c).1);
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
            co_authority: None,
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
    canonical_only: bool,
    state_error: bool,
    persistent: bool,
    rejections: std::sync::atomic::AtomicUsize,
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
        if self.armed.load(SeqCst) {
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
            let complete_tuple = puts.iter().any(|(key, _)| *key == b"HEAD")
                && puts.iter().any(|(key, _)| *key == b"FINALIZED")
                && puts.iter().any(|(_, value)| *value == self.certificate);
            if (!self.canonical_only || complete_tuple)
                && (self.persistent || self.armed.swap(false, SeqCst))
            {
                self.rejections.fetch_add(1, SeqCst);
                self.attempted.store(true, SeqCst);
                self.complete_tuple.store(complete_tuple, SeqCst);
                return Err(if self.state_error {
                    shell_storage::StorageError::State("injected canonical state failure".into())
                } else {
                    shell_storage::StorageError::Database("injected canonical batch failure".into())
                });
            }
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
    count: usize,
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
        canonical_only: false,
        state_error: false,
        persistent: false,
        rejections: std::sync::atomic::AtomicUsize::new(0),
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
        for case in 0..if c.co_authority.is_some() { 8 } else { 7 } {
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
                7 => {
                    altered.signatures.pop();
                }
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
                .set_authorities_with_weights(authority_weights(&c).0, authority_weights(&c).1);
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
            result.proved_commit_signatures == source.signatures.len()
                && result.execution.proved_sender_signatures == 0
                && result.execution.state_root == c.blocks[0].header.state_root
                && Some(result.execution.receipts)
                    == receiver.chain_store.get_receipts(&c.blocks[0].hash())?
                && receiver.finality.read().last_finalized_number() == 1,
            "atomic full quorum import result differs",
        )?;
        if c.co_authority.is_some() {
            let primary = source
                .signatures
                .iter()
                .find(|e| e.address == c.authority)
                .ok_or("primary entry absent")?;
            let only = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([(
                c.authority,
                primary.signature.clone(),
            )]))?;
            let rows = receiver.store.scan_all()?;
            ensure(
                !receiver.fast_finalize_with_certificate(1, c.blocks[0].hash(), &only)
                    && receiver.store.scan_all()? == rows,
                "exact two-thirds primary-only certificate accepted",
            )?;
        }
        normal.import_block(c.blocks[0].clone(), &MultiVerifier)?;
        ensure(
            normal.fast_finalize_with_certificate(1, c.blocks[0].hash(), &c.certificates[0]),
            "Native reference finality failed",
        )?;
        for block in &c.blocks[1..count] {
            receiver.import_block(block.clone(), &MultiVerifier)?;
            normal.import_block(block.clone(), &MultiVerifier)?;
        }
        receiver.store.flush()?;
        normal.store.flush()?;
    }
    balances(&receiver, &c, count)?;
    balances(&normal, &c, count)?;
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
        c.blocks[count - 1].hash(),
        c.blocks[0].hash(),
        &c.certificates[0],
        &proof,
    )?;
    let normal_before = normal.store.scan_all()?;
    ensure(
        result
            == normal.replay_canonical_block_with_commit_proof(
                c.blocks[count - 1].hash(),
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
        serde_json::json!({"freshAtomicImport":fresh || resume,"resumedOriginalPartial":resume,"backendFailureRollbackChecked":fresh || resume,"independentNativeRowsEqual":true,"currentHeight":count,"finalized":1,"commitSignaturesProved":source.signatures.len(),"senderAndProposerCryptoNative":true,"historicalRowsUnchanged":true,"originalControlsAndProofReused":true,"newSigningOrProofGeneration":false,"realPeerTransport":false})
    );
    Ok(())
}
fn co_sign_input(controls: &Path, output: &Path) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    ensure(
        c.blocks.len() == 3 && c.certificates.len() == 3,
        "complete original controls required",
    )?;
    let value = serde_json::json!({"version":1,"messages":c.blocks.iter().map(|b|format!("0x{}",hex::encode(b.hash().as_bytes()))).collect::<Vec<_>>()});
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    serde_json::to_writer(&file, &value)?;
    file.sync_all()?;
    Ok(())
}
fn prepare_mixed(root: &Path) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    // Produce a fresh, genuinely signed SLH block before adding the coauthority.
    // Keep its original controls; no private key or completed graph is copied.
    prepare(&root.join("single-slh"), false, true, false, false)?;
    let mut c: Control = read(&root.join("single-slh/control.cbor"))?;
    let co = MlDsaSigner::generate();
    let address = Address::from_public_key(co.public_key(), co.sig_type().as_u8());
    ensure(address != c.authority, "mixed authority collision")?;
    c.co_authority = Some((address, co.public_key().to_vec()));
    let block = &c.blocks[0];
    let hash = block.hash();
    let original: HashMap<String, shell_crypto::PQSignature> =
        serde_json::from_slice(&c.certificates[0])?;
    let primary = original
        .get(&c.authority.to_string())
        .ok_or("original SLH signature absent")?
        .clone();
    let co_signature = co.sign(hash.as_bytes())?;
    let primary_only = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([(
        c.authority,
        primary.clone(),
    )]))?;
    let mut damaged = co_signature.clone();
    damaged.data[0] ^= 1;
    let tampered = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([
        (c.authority, primary.clone()),
        (address, damaged),
    ]))?;
    let certificate = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([
        (c.authority, primary),
        (address, co_signature),
    ]))?;
    let provider = node(&root.join("provider-db"), &c, true)?;
    let follower = node(&root.join("control-db"), &c, true)?;
    for n in [&provider, &follower] {
        n.import_block(block.clone(), &MultiVerifier)?;
        let before = n.store.scan_all()?;
        let finality = {
            let f = n.finality.read();
            (f.last_finalized_number(), *f.last_finalized_hash())
        };
        for rejected in [&primary_only, &tampered] {
            ensure(
                !n.fast_finalize_with_certificate(1, hash, rejected),
                "mixed quorum accepted exact two-thirds or tampered cosignature",
            )?;
            let after = {
                let f = n.finality.read();
                (f.last_finalized_number(), *f.last_finalized_hash())
            };
            ensure(
                n.store.scan_all()? == before && after == finality,
                "mixed certificate refusal changed persistent or in-memory finality",
            )?;
        }
        ensure(
            n.fast_finalize_with_certificate(1, hash, &certificate),
            "genuine mixed certificate refused",
        )?;
        balances(n, &c, 1)?;
        n.store.flush()?;
    }
    ensure(
        provider.store.scan_all()? == follower.store.scan_all()?,
        "independent mixed Native1 rows differ",
    )?;
    let before = provider.store.scan_all()?;
    let source = provider.commit_quorum_source(1, hash, &certificate)?;
    source.validate()?;
    ensure(
        source.signatures.len() == 2
            && source.signatures.iter().any(|s| {
                s.address == address && s.signature.sig_type == shell_crypto::SignatureType::MlDsa65
            })
            && source.signatures.iter().any(|s| {
                s.address == c.authority
                    && s.signature.sig_type == shell_crypto::SignatureType::SphincsSha2256f
            })
            && provider.store.scan_all()? == before,
        "mixed source profile/count mismatch or capture wrote Native rows",
    )?;
    c.certificates[0] = certificate;
    write(&root.join("control.cbor"), &c)?;
    write(&root.join("source.cbor"), &source)?;
    drop(co);
    println!(
        "{}",
        serde_json::json!({"genuineMixedNativeControls":true,"head":1,"finalized":1,"SLHSigners":1,"MLDSASigners":1,"primaryWeight":2,"coWeight":1,"certificateRefusals":4,"independentNativeRowsEqual":true,"privateKeysPersisted":false,"newProofComponents":0,"fullMixedGraphAccepted":false})
    );
    Ok(())
}
fn augment(controls: &Path, signed: &Path, output: &Path) -> Result<(), Error> {
    use shell_core::BlockSignerEvidence;
    use shell_crypto::{PQSignature, SignatureType, Verifier};
    use shell_stark_prover::weighted_quorum::AuthorityWeight;
    let mut c: Control = read(&controls.join("control.cbor"))?;
    let mut source: CommitQuorumSource = read(&controls.join("source.cbor"))?;
    ensure(
        c.co_authority.is_none()
            && c.blocks.len() == 3
            && source.signatures.len() == 1
            && source.context.chain_id == 1337
            && source.context.block_hash == c.blocks[0].hash()
            && source.signatures[0].address == c.authority
            && source.signatures[0].public_key == c.authority_key,
        "original single primary controls required",
    )?;
    let file = std::fs::File::open(signed)?;
    ensure(file.metadata()?.len() <= 128 * 1024, "co-sign input bound")?;
    let value: serde_json::Value = serde_json::from_reader(file)?;
    ensure(
        value["version"] == 1 && value["algorithm"] == "Dilithium3",
        "co-sign format/tag mismatch",
    )?;
    let key = hex::decode(
        value["publicKey"]
            .as_str()
            .ok_or("co-key absent")?
            .trim_start_matches("0x"),
    )?;
    let address: Address = serde_json::from_value(value["address"].clone())?;
    ensure(
        address == Address::from_public_key(&key, 0) && address != c.authority,
        "SDK address/key mismatch",
    )?;
    let signatures = value["signatures"]
        .as_array()
        .ok_or("co-signatures absent")?;
    ensure(signatures.len() == 3, "all original co-signatures required")?;
    for (i, block) in c.blocks.iter().enumerate() {
        let message = hex::decode(
            signatures[i]["message"]
                .as_str()
                .ok_or("co-message absent")?
                .trim_start_matches("0x"),
        )?;
        let sig = PQSignature::new(
            SignatureType::Dilithium3,
            hex::decode(
                signatures[i]["signature"]
                    .as_str()
                    .ok_or("co-signature absent")?
                    .trim_start_matches("0x"),
            )?,
        );
        ensure(
            message == block.hash().as_bytes()
                && shell_crypto::DilithiumVerifier.verify_sdk_transcript(&key, &message, &sig)
                && !shell_crypto::DilithiumVerifier.verify_legacy_transcript(&key, &message, &sig),
            "co-signature is not SDK FIPS transcript",
        )?;
        let original: HashMap<String, PQSignature> = serde_json::from_slice(&c.certificates[i])?;
        ensure(
            original.len() == 1,
            "single original primary certificate required",
        )?;
        let primary = original
            .get(&c.authority.to_string())
            .ok_or("primary signature absent")?
            .clone();
        ensure(
            MultiVerifier.verify(&c.authority_key, &message, &primary)?,
            "original primary signature invalid",
        )?;
        c.certificates[i] = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([
            (c.authority, primary),
            (address, sig.clone()),
        ]))?;
        if i == 0 {
            source.signatures.push(BlockSignerEvidence {
                address,
                public_key: key.clone(),
                signature: sig,
            });
        }
    }
    c.co_authority = Some((address, key));
    source
        .signatures
        .sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
    source.context.signers = source.signatures.iter().map(|e| e.address).collect();
    source.context.authorities = vec![
        AuthorityWeight {
            address: c.authority,
            weight: 2,
        },
        AuthorityWeight { address, weight: 1 },
    ];
    source
        .context
        .authorities
        .sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
    std::fs::create_dir(output)?;
    write(&output.join("control.cbor"), &c)?;
    write(&output.join("source.cbor"), &source)?;
    for (i, block) in c.blocks.iter().enumerate() {
        write(&output.join(format!("block-{}.cbor", i + 1)), block)?;
        write(
            &output.join(format!("certificate-{}.cbor", i + 1)),
            &c.certificates[i],
        )?;
    }
    println!(
        "{}",
        serde_json::json!({"originalBlocksUnchanged":true,"originalPrimarySignaturesReused":3,"SDKCoSignaturesVerified":3,"primaryWeight":2,"coWeight":1,"primaryProofPosition":source.signatures.iter().position(|e|e.address==c.authority),"newPrimarySigning":false,"threeBlockMixedNativeFollowAcceptance":false})
    );
    Ok(())
}
fn inspect_follow(controls: &Path) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    ensure(
        c.co_authority.is_some() && c.blocks.len() == 3,
        "two-authority controls required",
    )?;
    let (authorities, weights) = authority_weights(&c);
    let mut config = WPoaConfig::with_weights(PoaConfig::new(authorities, 1), weights);
    config.chain_id = 1337;
    let engine = WPoaEngine::new(config, Arc::new(MultiVerifier));
    let mut parent = &c.genesis;
    let mut rows = Vec::new();
    let mut valid = true;
    for block in &c.blocks {
        let result = engine.verify_header_for_finalized_import(&block.header, &parent.header);
        valid &= result.is_ok();
        rows.push(serde_json::json!({"block":block.number(),"parentTimestamp":parent.header.timestamp,"timestamp":block.header.timestamp,"elapsed":block.header.timestamp.saturating_sub(parent.header.timestamp),"headerAccepted":result.is_ok(),"rejection":result.err().map(|e|e.to_string())}));
        parent = block;
    }
    println!(
        "{}",
        serde_json::json!({"certifiedHeaderTiming":rows,"viewTimeoutMs":shell_consensus::VIEW_CHANGE_TIMEOUT_MS,"allAccepted":valid})
    );
    ensure(valid,"retained header predates its legal proposer view; keep it as refusal evidence and prepare new timed controls")
}

fn response_hash(message: &shell_network::NetworkMessage) -> Option<shell_primitives::ShellHash> {
    matches!(message, shell_network::NetworkMessage::BlockResponse { .. })
        .then(|| blake3_hash(&serde_json::to_vec(message).expect("network message serialization")))
}

/// Observe completion of real event-loop dispatch without changing any message.
struct ObservedNetwork {
    inner: shell_network::Libp2pNetwork,
    handled: Arc<parking_lot::Mutex<Option<shell_primitives::ShellHash>>>,
    pending: Option<shell_primitives::ShellHash>,
}
#[async_trait::async_trait]
impl shell_network::NetworkService for ObservedNetwork {
    async fn broadcast(
        &self,
        message: shell_network::NetworkMessage,
    ) -> Result<(), shell_network::NetworkError> {
        self.inner.broadcast(message).await
    }
    async fn send_to_peer(
        &self,
        peer: &shell_network::PeerId,
        message: shell_network::NetworkMessage,
    ) -> Result<(), shell_network::NetworkError> {
        self.inner.send_to_peer(peer, message).await
    }
    async fn next_event(&mut self) -> Option<shell_network::NetworkEvent> {
        // Node.run polls again only after the previous handler has completed.
        // A queued send or transport acknowledgement alone is insufficient.
        if let Some(hash) = self.pending.take() {
            *self.handled.lock() = Some(hash);
        }
        let event = self.inner.next_event().await;
        if let Some(shell_network::NetworkEvent::MessageReceived { message, .. }) = &event {
            self.pending = response_hash(message);
        }
        event
    }
    async fn peer_count(&self) -> usize {
        self.inner.peer_count().await
    }
    fn peer_count_handle(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        self.inner.peer_count_handle()
    }
    fn local_node_info_handle(&self) -> Arc<std::sync::RwLock<shell_network::LocalNodeInfo>> {
        self.inner.local_node_info_handle()
    }
    fn supports_canonical_proof_transfer(&self) -> bool {
        self.inner.supports_canonical_proof_transfer()
    }
    async fn shutdown(&self) -> Result<(), shell_network::NetworkError> {
        self.inner.shutdown().await
    }
}

/// Resume an existing first-block import through the ordinary certified sync path.
async fn follow_peer(path: &Path, c: &Control, refusals: bool) -> Result<serde_json::Value, Error> {
    use shell_network::{
        Libp2pNetwork, NetworkConfig, NetworkEvent, NetworkMessage, NetworkService,
    };
    use std::time::Duration;
    let mut n = node(path, c, false)?;
    ensure(
        n.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
            && n.chain_store.get_finalized_number()? == Some(1),
        "peer follow requires the retained finalized first block",
    )?;
    let before = n.store.scan_all()?;
    let config = NetworkConfig {
        listen_addr: "127.0.0.1:0".parse()?,
        enable_mdns: false,
        enable_kademlia: false,
        enable_relay: false,
        enable_relay_server: false,
        enable_dcutr: false,
        enable_autonat: false,
        identity_key_path: None,
        ..Default::default()
    };
    let mut provider = Libp2pNetwork::new(&config).await?;
    let info = provider.local_node_info_handle();
    tokio::time::timeout(Duration::from_secs(10), async {
        while info.read().unwrap().listen_addresses.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| "provider listener timeout")?;
    let dial = {
        let info = info.read().unwrap();
        format!("{}/p2p/{}", info.listen_addresses[0], info.peer_id)
    };
    let receiver_config = NetworkConfig {
        boot_nodes: vec![dial],
        ..config
    };
    let inner = Libp2pNetwork::new(&receiver_config).await?;
    let peers = inner.peer_count_handle();
    let handled = Arc::new(parking_lot::Mutex::new(None));
    let mut network = ObservedNetwork {
        inner,
        handled: handled.clone(),
        pending: None,
    };
    n.config.node_role = shell_node::NodeRole::Prover;
    n.config.proposer_address = None;
    n.config.rpc_enabled = false;
    n.config.metrics.enabled = false;
    n.config.network = receiver_config;
    let signer = Arc::new(DilithiumSigner::generate());
    let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    ensure(
        !authority_weights(c).0.contains(&address),
        "runtime signer must not be an authority",
    )?;
    let n = Arc::new(n);
    let runner = n.clone();
    let task = tokio::spawn(async move { runner.run(signer, &mut network).await });
    // The sender is a real loopback peer serving retained signed data. It never
    // imports into the receiver or calls a private finalized-import method.
    let outcome = tokio::time::timeout(Duration::from_secs(90), async {
        let mut phase = 0usize;
        let mut requests = Vec::new();
        let mut responses=Vec::new();
        loop {
            if n.chain_store.get_finalized_number()? == Some(3) {
                ensure(n.chain_store.get_head_hash()? == Some(c.blocks[2].hash()), "certified peer head mismatch")?;
                ensure(!refusals || phase >= 4, "peer refusals not exercised")?;
                ensure(peers.load(std::sync::atomic::Ordering::SeqCst) > 0, "peer disconnected before import")?;
                return Ok::<_, Error>(serde_json::json!({"requests":requests,"responses":responses,"refusalStages":if refusals {3} else {0},"actualTCPNoise":true,"head":3,"finalized":3}));
            }
            ensure(!task.is_finished(), "Node.run exited before certified follow")?;
            tokio::select! {
                event = provider.next_event() => {
                    let Some(NetworkEvent::MessageReceived { peer, message: NetworkMessage::BlockRequest {start_number, count, nonce} }) = event else { continue };
                    requests.push(serde_json::json!({"start":start_number,"count":count,"nonce":nonce,"phase":phase}));
                    eprintln!("certified peer request start={start_number} count={count} nonce={nonce} phase={phase} head={:?} finality={:?}",n.chain_store.get_head_block()?.map(|b|b.number()),n.chain_store.get_finalized_number()?);
                    if !(2..=3).contains(&start_number) { continue }
                    ensure(count>0,"empty block request")?;
                    if refusals && phase <= 3 {
                        ensure(start_number==2 && n.store.scan_all()? == before
                            && n.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
                            && n.finality.read().last_finalized_number() == 1,
                            "stale or invalid certificate changed retained Native state")?;
                    }
                    let start=(start_number-1) as usize;
                    let end=(start+count.min(c.blocks.len() as u64)as usize).min(c.blocks.len());
                    let blocks=c.blocks[start..end].to_vec();
                    let mut certificates: Vec<_> = c.blocks[start..end].iter().zip(&c.certificates[start..end]).map(|(b, cert)|(b.hash(),cert.clone())).collect();
                    let response_nonce = if refusals && phase == 0 {nonce.checked_add(1).ok_or("nonce overflow")?} else {nonce};
                    if refusals && (phase == 1 || phase == 2) {
                        let mut signatures: HashMap<String, shell_crypto::PQSignature> = serde_json::from_slice(&certificates[0].1)?;
                        let co = c.co_authority.as_ref().ok_or("two-authority controls required")?.0.to_string();
                        if phase == 1 {signatures.remove(&co);} else {signatures.get_mut(&co).ok_or("SDK signature absent")?.data[0] ^= 1;}
                        certificates[0].1 = serde_json::to_vec(&signatures)?;
                    }
                    let block_count=blocks.len();
                    let response=NetworkMessage::BlockResponse {blocks,commit_certificates:certificates,nonce:response_nonce};
                    let hash=response_hash(&response).ok_or("response hash absent")?;
                    provider.send_to_peer(&peer,response).await?;
                    tokio::time::timeout(Duration::from_secs(10),async {
                        loop {
                            let complete=*handled.lock()==Some(hash);
                            if complete {break;}
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }).await.map_err(|_| "Node response dispatch did not complete")?;
                    if refusals && phase<3 {
                        ensure(n.store.scan_all()?==before && n.chain_store.get_head_hash()?==Some(c.blocks[0].hash()) && n.finality.read().last_finalized_number()==1,"dispatched invalid response changed Native state")?;
                    }
                    ensure(block_count as u64<=count,"response exceeds requested range")?;
                    responses.push(serde_json::json!({"start":start_number,"requestedCount":count,"blockCount":block_count,"requestNonce":nonce,"responseNonce":response_nonce,"hash":hash,"dispatchComplete":true,"phase":phase,"head":n.chain_store.get_head_block()?.map(|b|b.number()),"finalized":n.chain_store.get_finalized_number()?}));
                    phase += 1;
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    }).await;
    eprintln!(
        "certified peer outcome complete={} head={:?} finality={:?}",
        outcome.is_ok(),
        n.chain_store.get_head_block()?.map(|b| b.number()),
        n.chain_store.get_finalized_number()?
    );
    // Always use the node's graceful shutdown, including on a failed assertion.
    n.shutdown();
    let stopped = tokio::time::timeout(Duration::from_secs(30), task).await;
    let provider_stopped = provider.shutdown().await;
    stopped.map_err(|_| "Node shutdown timeout")???;
    provider_stopped?;
    let result = outcome.map_err(|_| "certified peer follow timeout")??;
    balances(&n, c, 3)?;
    n.store.flush()?;
    Ok(result)
}
fn follow_verify(controls: &Path, proof_file: &Path, root: &Path) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    let source: CommitQuorumSource = read(&controls.join("source.cbor"))?;
    let proof: CommitQuorumProof = read(proof_file)?;
    ensure(
        c.co_authority.is_some() && c.blocks.len() == 3 && c.certificates.len() == 3,
        "complete two-authority controls required",
    )?;
    let mut receiver = node(&root.join("db"), &c, false)?;
    let normal = node(&root.join("control-db"), &c, false)?;
    for n in [&receiver, &normal] {
        balances(n, &c, 3)?;
        ensure(
            n.chain_store.get_head_hash()? == Some(c.blocks[2].hash())
                && n.chain_store.get_finalized_number()? == Some(3)
                && n.finality.read().last_finalized_number() == 3,
            "cold certified follow head/finality mismatch",
        )?;
        for (block, cert) in c.blocks.iter().zip(&c.certificates) {
            ensure(
                n.chain_store.get_commit_certificate(&block.hash())? == Some(cert.clone())
                    && n.chain_store.get_block_by_hash(&block.hash())? == Some(block.clone())
                    && n.chain_store.get_receipts(&block.hash())?.is_some(),
                "cold signed block/certificate/receipts missing",
            )?;
        }
    }
    ensure(
        receiver.store.scan_all()? == normal.store.scan_all()?,
        "independent certified Native rows differ",
    )?;
    let before = receiver.store.scan_all()?;
    let reference_before = normal.store.scan_all()?;
    let result = receiver.replay_canonical_block_with_commit_proof(
        c.blocks[2].hash(),
        c.blocks[0].hash(),
        &c.certificates[0],
        &proof,
    )?;
    ensure(
        result
            == normal.replay_canonical_block_with_commit_proof(
                c.blocks[2].hash(),
                c.blocks[0].hash(),
                &c.certificates[0],
                &proof,
            )?
            && result.proved_commit_signatures == source.signatures.len(),
        "historical first-block quorum replay mismatch",
    )?;
    ensure(
        receiver
            .import_block_with_commit_proof(
                c.genesis.hash(),
                c.blocks[0].clone(),
                &c.certificates[0],
                &proof,
            )
            .is_err()
            && receiver.store.scan_all()? == before
            && normal.store.scan_all()? == reference_before,
        "cold historical query/duplicate wrote rows",
    )?;
    println!(
        "{}",
        serde_json::json!({"coldAfterState3":true,"firstBlockFullQuorumSignatures":source.signatures.len(),"successorQuorumCryptoNative":true,"independentNativeRowsEqual":true,"currentHeight":3,"finalized":3,"historicalRowsUnchanged":true,"newSigningOrProofGeneration":false})
    );
    Ok(())
}
fn follow(controls: &Path, proof_file: &Path, root: &Path) -> Result<(), Error> {
    inspect_follow(controls)?;
    let c: Control = read(&controls.join("control.cbor"))?;
    ensure(
        c.co_authority.is_some() && c.blocks.len() == 3 && c.certificates.len() == 3,
        "complete two-authority controls required",
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let observed = runtime.block_on(async {
        let receiver = follow_peer(&root.join("db"), &c, true).await?;
        let reference = follow_peer(&root.join("control-db"), &c, false).await?;
        Ok::<_, Error>(serde_json::json!({"receiver":receiver,"reference":reference}))
    })?;
    drop(runtime);
    follow_verify(controls, proof_file, root)?;
    println!("{observed}");
    Ok(())
}

fn accept_slh(controls: &Path, proof_file: &Path, root: &Path) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    let proof: CommitQuorumProof = read(proof_file)?;
    ensure(
        c.blocks.len() == 1 && c.certificates.len() == 1 && c.authority_key.len() == 64,
        "original SLH controls required",
    )?;
    std::fs::create_dir(root)?;
    let mut receiver = node(&root.join("db"), &c, true)?;
    let before = receiver.store.scan_all()?;
    match receiver.import_block_with_commit_proof(
        c.genesis.hash(),
        c.blocks[0].clone(),
        &c.certificates[0],
        &proof,
    ) {
        Ok(result) => ensure(
            result.proved_commit_signatures == 1
                && result.execution.state_root == c.blocks[0].header.state_root,
            "SLH proof execution result mismatch",
        )?,
        Err(error) => {
            ensure(
                receiver.store.scan_all()? == before
                    && receiver.finality.read().last_finalized_number() == 0
                    && receiver
                        .chain_store
                        .get_receipts(&c.blocks[0].hash())?
                        .is_none(),
                "SLH import refusal changed canonical state",
            )?;
            println!(
                "{}",
                serde_json::json!({"slhCommitProofRejectedWithoutNativeMutation":true,"head":0,"finalized":0,"noChildReceipts":true,"error":error.to_string()})
            );
            return Err(error.into());
        }
    }
    balances(&receiver, &c, 1)?;
    receiver.store.flush()?;
    drop(receiver);
    let reopened = node(&root.join("db"), &c, false)?;
    let reference = node(&controls.join("control-db"), &c, false)?;
    ensure(
        reopened.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
            && reopened.chain_store.get_finalized_number()? == Some(1)
            && reopened.store.scan_all()? == reference.store.scan_all()?
            && reopened.chain_store.get_receipts(&c.blocks[0].hash())?
                == reference.chain_store.get_receipts(&c.blocks[0].hash())?,
        "SLH cold Native result differs from independent reference",
    )?;
    balances(&reopened, &c, 1)?;
    println!(
        "{}",
        serde_json::json!({"fullSLHCommitAIRImported":true,"provedCommitSignatures":1,"head":1,"finalized":1,"independentColdNativeRowsReceiptsBalancesNonceFeesEqual":true,"newAuthoritySigningOrProving":false})
    );
    Ok(())
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("live-cold-intent-recheck") if args.len()==5 => quorum_rpc::run_cold_intent_recheck(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4])),
        Some("live-explicit-recheck") if args.len()==5 => quorum_rpc::run_explicit_recheck(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4])),
        Some("producer-step") if args.len()==5 => quorum_rpc::run_producer_step(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),args[4].parse()?),
        Some("producer-seed") if args.len()==4 => quorum_rpc::seed_producer(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3])),
        Some("producer-live"|"producer-cold"|"producer-corrupt"|"producer-disabled"|"producer-manifest"|"producer-auto"|"producer-auto-wait"|"producer-auto-resume"|"producer-auto-partial"|"producer-auto-worker"|"producer-auto-recover"|"producer-auto-batch-fault"|"producer-auto-batch-recover"|"producer-intact-rejection") if args.len()==5 => quorum_rpc::run_producer(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4]),&args[0]),
        Some("live-pause"|"live-import"|"live-cold"|"live-default"|"live-history3"|"live-invalid-recheck"|"slh-live-pause"|"slh-live-import"|"slh-live-cold"|"slh-live-default"|"slh-live-history3"|"slh-live-invalid-recheck"|"slh-live-batch-fault"|"slh-live-batch-recover"|"slh-live-persistent-batch-fault"|"slh-live-persistent-batch-cold"|"slh-live-crash-worker"|"slh-live-crash-recover"|"mixed-live-history3") if args.len()==5 => quorum_rpc::run_live(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4]),&args[0]),
        Some("follow-peer") if args.len()==4 => follow(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3])),
        Some("follow-verify") if args.len()==4 => follow_verify(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3])),
        Some("rpc-pause"|"rpc-verify"|"rpc-recheck") if args.len()==4 => quorum_rpc::run(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),&args[0]),
        Some("co-sign-input") if args.len()==3 => co_sign_input(Path::new(&args[1]),Path::new(&args[2])),
        Some("augment") if args.len()==4 => augment(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3])),

        Some("receive" | "receive-resume" | "receive-verify" | "receive-one" | "receive-one-verify") if args.len() == 4 => receive(Path::new(&args[1]), Path::new(&args[2]), Path::new(&args[3]), args[0] == "receive" || args[0] == "receive-one", args[0] == "receive-resume", if args[0].starts_with("receive-one") {1} else {3}),
        Some("accept-slh") if args.len()==4 => accept_slh(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3])),
        Some("prepare-slh") if args.len()==2 => prepare(Path::new(&args[1]),false,true,false,false),
        Some("prepare-slh-history") if args.len()==2 => prepare(Path::new(&args[1]),false,true,true,false),
        Some("prepare-mixed") if args.len()==2 => prepare_mixed(Path::new(&args[1])),
        Some("prepare-mixed-history") if args.len()==2 => prepare(Path::new(&args[1]),false,true,true,true),
        Some("inspect-slh") if args.len()==2 => {
            let root=Path::new(&args[1]);
            let c:Control=read(&root.join("control.cbor"))?;
            ensure(c.blocks.len()==1 && c.certificates.len()==1 && c.authority_key.len()==64,"original one-block SLH controls required")?;
            let n=node(&root.join("provider-db"),&c,false)?;
            let source=n.commit_quorum_source(1,c.blocks[0].hash(),&c.certificates[0])?;
            source.validate()?;
            let path=root.join("source.cbor");
            if path.exists() {ensure(read::<CommitQuorumSource>(&path)?==source,"retained SLH source differs")?;} else {write(&path,&source)?;}
            println!("{}",serde_json::json!({"originalSLHQuorumSourceCaptured":true,"signers":source.signatures.len(),"newAuthoritySigningOrProving":false}));Ok(())
        },
        Some("prepare") if args.len() == 2 => prepare(Path::new(&args[1]),false,false,false,false),
        Some("prepare-certified") if args.len() == 2 => prepare(Path::new(&args[1]),true,false,false,false),
        Some("inspect-follow") if args.len() == 2 => inspect_follow(Path::new(&args[1])),
        Some("inspect") if args.len() == 2 => inspect(Path::new(&args[1])),
        Some("verify") if args.len() == 3 => verify(Path::new(&args[1]), Path::new(&args[2])),
        _ => Err("usage: quorum-native slh-live-crash-worker|slh-live-crash-recover|slh-live-persistent-batch-fault|slh-live-persistent-batch-cold <retained-slh-controls> <complete-proof.cbor> <receiver-root> <existing-Native1-provider-db> | prepare-mixed|prepare-mixed-history <new-control-directory> | prepare-slh-history <new-control-directory> | slh-live-history3|mixed-live-history3 <history-controls> <complete-first-proof.cbor> <existing-receiver-root> <existing-Native3-provider-db> | producer-step <slh-controls> <existing-Native1-provider-db> <new-receiver-root> <new-component-budget-1..16> | slh-live-pause|slh-live-import|slh-live-cold|slh-live-default|slh-live-invalid-recheck|slh-live-batch-fault|slh-live-batch-recover <original-slh-controls> <complete-proof.cbor> <receiver-root> <existing-Native-one-provider-db> | accept-slh <slh-controls> <complete-proof.cbor> <new-import-directory> | prepare-slh <new-control-directory> | inspect-slh <retained-slh-controls> | live-cold-intent-recheck <controls> <proof> <retained-rejected-root> <independent-first-block-db> | live-explicit-recheck <controls> <proof> <retained-rejected-receiver-root> <independent-first-block-db> | producer-seed <controls> <completed-job-root> <owned-provider-db> | producer-live|producer-cold|producer-corrupt|producer-disabled|producer-manifest|producer-auto|producer-auto-wait|producer-auto-resume|producer-auto-partial|producer-auto-worker|producer-auto-recover|producer-auto-batch-fault|producer-auto-batch-recover|producer-intact-rejection <controls> <owned-provider-db> <new-receiver-root> <full-proof.cbor> | live-pause|live-import|live-cold|live-history3|live-default|live-invalid-recheck <controls> <proof> <receiver-root> <owned-provider-db> | rpc-pause <controls> <proof> <existing-native-root> | rpc-verify <controls> <proof> <existing-native-root> | rpc-recheck <controls> <proof> <existing-native-root> | prepare-certified <new-timed-controls> | inspect-follow <two-signer-controls> | follow-peer <two-signer-controls> <full-proof.cbor> <existing-first-block-directory> | follow-verify <two-signer-controls> <full-proof.cbor> <existing-follow-directory> | co-sign-input <original-controls> <new-messages.json> | augment <original-controls> <sdk-signatures.json> <new-two-signer-controls> | receive-one <two-signer-controls> <full-proof.cbor> <new-import-directory> | receive-one-verify <two-signer-controls> <full-proof.cbor> <existing-import-directory> | prepare <new-control-directory> | inspect <control-directory> | verify <control-directory> <full-quorum-proof.cbor> | receive <original-controls> <full-proof.cbor> <new-import-directory> | receive-resume <original-controls> <full-proof.cbor> <original-genesis-import-directory> | receive-verify <original-controls> <full-proof.cbor> <existing-import-directory>".into()),
    }
}
