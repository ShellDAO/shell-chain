//! Stable account identity across real rotations, proof import and historical replay.
use super::*;
use shell_crypto::MlDsaSigner;
use shell_storage::MemoryDb;

fn commitment(key: &[u8], tagged: bool) -> ShellHash {
    if tagged {
        blake3_hash(&[&[shell_crypto::SignatureType::MlDsa65.as_u8()], key].concat())
    } else {
        blake3_hash(key)
    }
}
fn genesis(
    path: &Path,
    keys: &[MlDsaSigner],
    proposer: &MlDsaSigner,
    active: bool,
) -> Result<RocksDbStore, Error> {
    let stores = RocksDbStore::open_all(path, None)?;
    let store = stores.state;
    let address = Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    let mut world = WorldState::new(Arc::new(store.clone()));
    world.set_account(
        &address,
        &Account::new_user_account(
            commitment(keys[0].public_key(), false),
            U256::from(2_000_000),
        ),
    )?;
    let block = Block {
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
    let chain = ChainStore::new(Arc::new(store.clone()));
    chain.put_pubkey(&address, keys[0].public_key())?;
    chain.put_pubkey(&authority, proposer.public_key())?;
    let config: ChainConfig = serde_json::from_value(
        json!({"chain_id":10,"genesis_hash":block.hash(),
        "fee_accounting_activation_height":1,"native_address_context_height":1,"block_commitment_height":1,
        "registered_key_algorithm_height": if active { Some(1) } else { None }}),
    )?;
    chain.commit_genesis_block(&block, &config)?;
    store.flush()?;
    Ok(store)
}
fn signed(
    key: &MlDsaSigner,
    address: Address,
    nonce: u64,
    replacement: Option<&MlDsaSigner>,
) -> Result<SignedTransaction, Error> {
    let tx = Transaction {
        chain_id: 10,
        nonce,
        to: Some(if replacement.is_some() {
            shell_pqvm::system_contracts::account_manager_address()
        } else {
            Address::from([0x11; 32])
        }),
        value: if replacement.is_some() {
            U256::ZERO
        } else {
            U256::from(1)
        },
        data: replacement
            .map(|key| {
                shell_pqvm::system_contracts::encode_rotate_key_calldata(
                    key.public_key(),
                    key.sig_type().as_u8(),
                )
                .into()
            })
            .unwrap_or_default(),
        gas_limit: if replacement.is_some() {
            100_000
        } else {
            21_000
        },
        max_fee_per_gas: 2,
        max_priority_fee_per_gas: 1,
        tx_type: 0,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let signature = key.sign(tx.signing_hash(key.sig_type().as_u8()).as_bytes())?;
    Ok(SignedTransaction::new(address, tx, signature))
}
fn finalize(
    node: &shell_node::Node<RocksDbStore>,
    block: &Block,
    proposer: &MlDsaSigner,
) -> Result<(), Error> {
    let mut round = shell_consensus::wpoa_state::WPoaRound::new(
        block.number(),
        0,
        node.consensus.read().validator_weights(),
    );
    let _ = round.on_block_proposed(block.hash(), block.header.proposer);
    *node.wpoa_round.lock() = Some(round);
    node.handle_wpoa_vote(
        block.header.proposer,
        block.hash(),
        block.number(),
        proposer.sign(block.hash().as_bytes())?,
    )
    .ok_or("rotation genuine quorum vote absent")?;
    ensure(
        node.finality.read().last_finalized_number() == block.number(),
        "rotation native vote not finalized",
    )
}
fn binding<S: KvStore + 'static>(
    node: &shell_node::Node<S>,
    address: Address,
    key: &[u8],
    tagged: bool,
) -> Result<(), Error> {
    ensure(
        node.chain_store.get_pubkey(&address)?.as_deref() == Some(key),
        "rotation registry key differs",
    )?;
    let account = node
        .world_state
        .read()
        .get_account(&address)?
        .ok_or("rotation account absent")?;
    ensure(
        account.pq_pubkey_hash == commitment(key, tagged),
        "rotation account commitment differs",
    )
}
fn control(
    node: &shell_node::Node<RocksDbStore>,
    block: &Block,
    address: Address,
    key: &[u8],
    tagged: bool,
) -> Result<Value, Error> {
    binding(node, address, key, tagged)?;
    let receipts = node
        .chain_store
        .get_receipts(&block.hash())?
        .ok_or("rotation receipts absent")?;
    let gas = if block.transactions[0].tx.data.is_empty() {
        21_000
    } else {
        shell_pqvm::system_contracts::SYSTEM_CALL_BASE_GAS
            + shell_pqvm::system_contracts::SYSTEM_CALL_OP_GAS
    };
    ensure(
        receipts.len() == 2
            && receipts[0].status == 1
            && receipts[0].gas_used == gas
            && receipts[0].cumulative_gas_used == gas
            && receipts[1].gas_used == 0,
        "rotation native gas/receipt mismatch",
    )?;
    Ok(
        json!({"head":block.hash(),"height":block.number(),"state_root":block.header.state_root,"receipts":receipts,
        "accounts":accounts(node.store.clone(),block)?,"address":address,"key":key,"commitment":commitment(key,tagged),"tagged":tagged}),
    )
}
pub(crate) fn prepare(out: &Path) -> Result<(), Error> {
    if out.exists() {
        ensure(
            std::fs::read_dir(out)?.all(|e| e.is_ok_and(|e| e.file_name() == "commands")),
            "rotation output already contains data",
        )?;
    } else {
        std::fs::create_dir(out)?;
    }
    let keys: Vec<_> = (0..3).map(|_| MlDsaSigner::generate()).collect();
    let proposer = MlDsaSigner::generate();
    let address = Address::from_public_key(keys[0].public_key(), keys[0].sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    ensure(
        keys.iter()
            .skip(1)
            .all(|k| Address::from_public_key(k.public_key(), k.sig_type().as_u8()) != address)
            && authority != address,
        "rotation identities not independent",
    )?;
    let store = Arc::new(genesis(&out.join("native/db"), &keys, &proposer, true)?);
    let genesis_rows = store.scan_all()?;
    let mut node = fixture::node(store.clone(), authority, proposer.public_key())?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    node.config.canonical_proof_production = true;
    let rotation = signed(&keys[0], address, 0, Some(&keys[1]))?;
    node.handle_incoming_tx(rotation.clone(), &MultiVerifier)?;
    let first = node.produce_block(&proposer, 100)?;
    finalize(&node, &first, &proposer)?;
    write(
        &out.join("control1.json"),
        &control(&node, &first, address, keys[1].public_key(), true)?,
    )?;
    let captured = node
        .canonical_production_status(first.hash())?
        .ok_or("rotation1 native step did not capture proving inputs")?;
    ensure(
        captured["status"]["state"] == "queued",
        "rotation1 proving input state differs",
    )?;
    write(&out.join("capture1.json"), &captured)?;
    let failed = Arc::new(MemoryDb::new());
    for (k, v) in genesis_rows {
        failed.put(&k, &v)?;
    }
    let failed_node = fixture::node(failed.clone(), authority, proposer.public_key())?;
    let mut bad = first.clone();
    bad.header.state_root = ShellHash::ZERO;
    bad.proposer_seal = Some(proposer.sign(bad.hash().as_bytes())?);
    let before = failed.scan_all()?;
    let error = failed_node
        .import_block(bad, &MultiVerifier)
        .err()
        .ok_or("wrong-root rotation accepted")?
        .to_string();
    ensure(
        error.contains("state root mismatch")
            && error.contains(&format!("{:?}", first.header.state_root))
            && before == failed.scan_all()?,
        "wrong-root rotation leaked writes or failed before execution",
    )?;
    binding(&failed_node, address, keys[0].public_key(), false)?;
    write(
        &out.join("rotation-native-rollback.json"),
        &json!({"native_crypto_control_not_proof_admission":true,"all_kv_unchanged":true,"old_key_and_commitment_preserved":true,"error":error}),
    )?;
    let mut refusals = Vec::new();
    let stale = signed(&keys[0], address, 1, None)?;
    let before = store.scan_all()?;
    let error = node
        .handle_incoming_tx(stale, &MultiVerifier)
        .err()
        .ok_or("stale K0 accepted after rotation")?
        .to_string();
    ensure(before == store.scan_all()?, "stale key changed native data")?;
    refusals.push(json!({"case":"K0-after-K1","error":error,"all_kv_unchanged":true}));
    let transfer = signed(&keys[1], address, 1, None)?;
    node.handle_incoming_tx(transfer.clone(), &MultiVerifier)?;
    let second = node.produce_block(&proposer, 100)?;
    finalize(&node, &second, &proposer)?;
    write(
        &out.join("control2.json"),
        &control(&node, &second, address, keys[1].public_key(), true)?,
    )?;
    let captured = node
        .canonical_production_status(second.hash())?
        .ok_or("replacement Reference native step did not capture proving inputs")?;
    ensure(
        captured["status"]["state"] == "queued",
        "replacement Reference proving input state differs",
    )?;
    write(&out.join("capture2.json"), &captured)?;
    // Preserve the exact two-job provider before the ordinary control advances.
    std::fs::create_dir(out.join("network-rotation"))?;
    std::fs::create_dir(out.join("network-rotation/provider"))?;
    store.flush()?;
    // Checkpoint all native column families through their original shared handle.
    drop(node);
    drop(store);
    let stores = RocksDbStore::open_all(out.join("native/db"), None)?;
    stores.create_checkpoint(out.join("network-rotation/provider/db"))?;
    let mut node = fixture::node(Arc::new(stores.state), authority, proposer.public_key())?;
    node.config.proposer_address = Some(authority);
    let genesis_block = node
        .chain_store
        .get_block_by_hash(&first.header.parent_hash)?
        .ok_or("rotation genesis absent")?;
    let context = fixture::Context {
        version: 1,
        authority,
        authority_key: proposer.public_key().to_vec(),
        genesis_root: genesis_block.header.state_root,
        block: first.hash(),
        tip: second.hash(),
    };
    write(&out.join("context.json"), &context)?;
    write(
        &out.join("blocks.json"),
        &vec![first.clone(), second.clone()],
    )?;
    let receiver = genesis(
        &out.join("network-rotation/receiver/db"),
        &keys,
        &proposer,
        true,
    )?;
    ensure(
        ChainStore::new(Arc::new(receiver.clone())).get_head_hash()? == Some(genesis_block.hash()),
        "rotation independent genesis mismatch",
    )?;
    write(
        &out.join("network-rotation/initial.json"),
        &json!({"independent_genesis":true,"head":genesis_block.hash(),"native_digest":canonical_digest(&receiver)?,"registered_key_algorithm_height":1,"key":keys[0].public_key()}),
    )?;
    drop(receiver);
    let mut advance = Vec::new();
    node.handle_incoming_tx(
        signed(&keys[1], address, 2, Some(&keys[2]))?,
        &MultiVerifier,
    )?;
    let third = node.produce_block(&proposer, 100)?;
    advance.push(third);
    binding(&node, address, keys[2].public_key(), true)?;
    let before = node.store.scan_all()?;
    let error = node
        .handle_incoming_tx(signed(&keys[1], address, 3, None)?, &MultiVerifier)
        .err()
        .ok_or("stale K1 accepted after K2")?
        .to_string();
    ensure(
        before == node.store.scan_all()?,
        "second stale key wrote native data",
    )?;
    refusals.push(json!({"case":"K1-after-K2","error":error,"all_kv_unchanged":true}));
    node.handle_incoming_tx(signed(&keys[2], address, 3, None)?, &MultiVerifier)?;
    let fourth = node.produce_block(&proposer, 100)?;
    write(
        &out.join("advanced-control.json"),
        &control(&node, &fourth, address, keys[2].public_key(), true)?,
    )?;
    advance.push(fourth);
    write(&out.join("advance-blocks.json"), &advance)?;
    write(&out.join("native-refusals.json"), &refusals)?;
    node.store.flush()?;
    let legacy = Arc::new(genesis(
        &out.join("default-off/db"),
        &keys,
        &proposer,
        false,
    )?);
    let mut legacy_node = fixture::node(legacy.clone(), authority, proposer.public_key())?;
    legacy_node.config.proposer_address = Some(authority);
    legacy_node.handle_incoming_tx(rotation, &MultiVerifier)?;
    let legacy_first = legacy_node.produce_block(&proposer, 100)?;
    binding(&legacy_node, address, keys[1].public_key(), false)?;
    legacy_node.handle_incoming_tx(transfer, &MultiVerifier)?;
    let legacy_second = legacy_node.produce_block(&proposer, 100)?;
    write(
        &out.join("default-off-control.json"),
        &json!({"ordinary_native_not_proof_admitted":true,"registered_key_algorithm_height":null,"rotation":control(&legacy_node,&legacy_first,address,keys[1].public_key(),false)?,"reference":control(&legacy_node,&legacy_second,address,keys[1].public_key(),false)?}),
    )?;
    write(
        &out.join("rotation.json"),
        &json!({"address":address,"keys":keys.iter().map(|k|k.public_key().to_vec()).collect::<Vec<_>>(),"private_keys_persisted":false,"activation_height":1}),
    )?;
    legacy.flush()?;
    Ok(())
}
pub(crate) async fn run(out: &Path, pause: bool) -> Result<(), Error> {
    let network = out.join("network-rotation");
    ensure(
        !network.join("complete.json").exists(),
        "rotation complete; use verify",
    )?;
    let context: fixture::Context = read(&out.join("context.json"))?;
    let blocks: Vec<Block> = read(&out.join("blocks.json"))?;
    let info: Value = read(&out.join("rotation.json"))?;
    let address: Address = serde_json::from_value(info["address"].clone())?;
    let keys: Vec<Vec<u8>> = serde_json::from_value(info["keys"].clone())?;
    let faults = Arc::new(Faults::default());
    *faults.withheld_block.write().unwrap() = Some(context.tip);
    let provider = Live::start(
        &network.join("provider/db"),
        &context,
        vec![],
        false,
        true,
        Some(faults.clone()),
    )
    .await?;
    let receiver = match Live::start(
        &network.join("receiver/db"),
        &context,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await
    {
        Ok(receiver) => receiver,
        Err(error) => {
            provider.stop().await?;
            return Err(error);
        }
    };
    let result=async {
        let deadline=tokio::time::Instant::now()+Duration::from_secs(12*60*60);
        let mut last_progress=tokio::time::Instant::now();let mut previous=None;
        loop {
            ensure(!provider.task.is_finished()&&!receiver.task.is_finished(),"rotation live node exited")?;
            let mut productions=Vec::new();let mut admissions=Vec::new();let mut counts=Vec::new();
            for block in &blocks {
                let status=provider.call("admin_canonicalProofProduction",json!([block.hash()])).await?;
                ensure(status["status"]["state"]!="failed",&format!("rotation proof production failed: {}",status["status"]))?;
                productions.push(status["status"].clone());
                let status=receiver.call("admin_canonicalProofAdmission",json!([block.hash()])).await?;
                ensure(status["status"]["state"]!="failed",&format!("rotation proof admission failed: {status}"))?;
                admissions.push(status);
                counts.push(checkpoint_components(provider.node.store.as_ref(),block.hash())?);
            }
            let height=receiver.node.chain_store.get_head_block()?.ok_or("rotation receiver head absent")?.number();
            let finalized=receiver.node.finality.read().last_finalized_number();
            let progress=json!({"components":counts,"production":productions,"admission":admissions,"height":height,"finalized":finalized});
            if previous.as_ref()!=Some(&progress){previous=Some(progress.clone());last_progress=tokio::time::Instant::now();let tmp=network.join("progress.tmp");std::fs::write(&tmp,serde_json::to_vec(&progress)?)?;std::fs::rename(tmp,network.join("progress.json"))?;println!("rotation components={counts:?}; height={height}; finalized={finalized}");}
            if pause&&counts[0]>0 {ensure(height==0&&finalized==0,"partial rotation proof changed native head")?;break;}
            if height>=1&&finalized>=1 {
                binding(receiver.node.as_ref(),address,&keys[1],true)?;
                *faults.withheld_block.write().unwrap()=None;
            }
            if height==2&&finalized==2 {
                for (index,block)in blocks.iter().enumerate(){
                    ensure(productions[index]["state"]=="complete"&&admissions[index]["nativeCanonical"]==true&&admissions[index]["status"]["state"]=="complete","rotation did not consume both full proofs")?;
                    let expected:Value=read(&out.join(format!("control{}.json",index+1)))?;
                    ensure(receiver.node.chain_store.get_receipts(&block.hash())?.map(serde_json::to_value).transpose()?==Some(expected["receipts"].clone())&&accounts(receiver.node.store.clone(),block)?==expected["accounts"],"rotation peer receipts/accounts differ from control")?;
                    let manifest:CanonicalProofManifest=serde_json::from_value(admissions[index]["status"]["manifest"].clone())?;
                    let cache=shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
                    ensure(cache.status(&manifest.id())?.result.as_ref().is_some_and(|v|v["proved_sender_signatures"]==1&&v["proved_proposer_signature"]==true),"rotation admission omitted complete signature AIR")?;
                    let bytes=cache.payload(&manifest.id())?;
                    let proof=shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
                    ensure(proof.version==2&&proof.proposer.is_some()&&proof.transactions.len()==1&&proof.transactions[0].signature.version==1&&proof.transactions[0].signature.tagged_key.is_some()==(index==1),"rotation raw/tagged signature profile mismatch")?;
                    let path=network.join(format!("proof{}.bin",index+1));
                    if path.exists(){ensure(std::fs::read(&path)?==bytes,"rotation retained proof changed")?;}else{std::fs::write(path,&bytes)?;}
                    write(&network.join(format!("manifest{}.json",index+1)),&manifest)?;
                }
                let first=receiver.node.chain_store.canonical_parent_view(context.tip,blocks[0].header.parent_hash)?;
                let second=receiver.node.chain_store.canonical_parent_view(context.tip,blocks[1].header.parent_hash)?;
                ensure(first.registered_key(&address)?.as_deref()==Some(keys[0].as_slice())&&second.registered_key(&address)?.as_deref()==Some(keys[1].as_slice()),"rotation historical registry resolution drifted")?;
                write(&network.join("complete.json"),&json!({"production":productions,"admission":admissions,"height":2,"finalized":2,"both_full_proof_admitted":true,"stable_address":address,"initial_key":keys[0],"replacement_key":keys[1],"raw_then_tagged_proof_binding":true,"native_outputs_match":true,"served_chunks":faults.chunks.load(Ordering::SeqCst)}))?;break;
            }
            ensure(tokio::time::Instant::now()<deadline&&last_progress.elapsed()<Duration::from_secs(1800),"rotation progress bound exceeded")?;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok::<_,Error>(())
    }.await;
    let receiver_stop = receiver.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    if pause {
        write(
            &network.join("paused.json"),
            &json!({"gracefully_stopped":true}),
        )?;
    }
    Ok(())
}
pub(crate) fn snapshot(out: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("network-rotation/provider/db"), None)?;
    let rows = stores
        .state
        .scan_prefix(b"local/canonical-production/v1/")?;
    let bytes: usize = rows
        .iter()
        .filter(|(k, _)| k != b"local/canonical-production/v1/bytes")
        .map(|(k, v)| k.len() + v.len())
        .sum();
    let recorded = stores
        .state
        .get(b"local/canonical-production/v1/bytes")?
        .unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
    ensure(
        recorded.as_slice() == (bytes as u64).to_be_bytes() && bytes <= 256 * 1024 * 1024,
        "rotation global checkpoint accounting mismatch",
    )?;
    println!(
        "{}",
        json!({"native_digest":canonical_digest(&stores.state)?,"physical_checkpoint_bytes":bytes,"rows":rows.into_iter().map(|(k,v)|json!({"key":hex::encode(k),"bytes":v.len(),"hash":blake3_hash(&v)})).collect::<Vec<_>>() })
    );
    Ok(())
}
pub(crate) fn verify(out: &Path, advance: bool) -> Result<(), Error> {
    let network = out.join("network-rotation");
    ensure(
        network.join("complete.json").exists(),
        "rotation proof admission incomplete",
    )?;
    let context: fixture::Context = read(&out.join("context.json"))?;
    let info: Value = read(&out.join("rotation.json"))?;
    let address: Address = serde_json::from_value(info["address"].clone())?;
    let keys: Vec<Vec<u8>> = serde_json::from_value(info["keys"].clone())?;
    let blocks: Vec<Block> = read(&out.join("blocks.json"))?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state),
        context.authority,
        &context.authority_key,
    )?;
    if advance {
        let later: Vec<Block> = read(&out.join("advance-blocks.json"))?;
        for block in later {
            if node
                .chain_store
                .get_head_block()?
                .ok_or("rotation head absent")?
                .number()
                < block.number()
            {
                node.import_block(block, &MultiVerifier)?;
            }
        }
    }
    let current = node
        .chain_store
        .get_head_block()?
        .ok_or("rotation head absent")?;
    let changed = current.number() == 4;
    binding(&node, address, &keys[if changed { 2 } else { 1 }], true)?;
    let before = digest(node.store.as_ref())?;
    let mut replays = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let proof = shell_stark_prover::compact_canonical::decode_payload(&std::fs::read(
            network.join(format!("proof{}.bin", index + 1)),
        )?)?;
        let replay =
            node.replay_canonical_transactions_with_proof(current.hash(), block.hash(), &proof)?;
        let control: Value = read(&out.join(format!("control{}.json", index + 1)))?;
        ensure(
            replay.proved_sender_signatures == 1
                && replay.proved_proposer_signature
                && replay.state_root.to_string()
                    == control["state_root"].as_str().unwrap_or_default()
                && serde_json::to_value(&replay.receipts)? == control["receipts"],
            "rotation cold historical replay differs",
        )?;
        replays.push(replay);
    }
    ensure(
        before == digest(node.store.as_ref())?,
        "rotation historical replay wrote current data",
    )?;
    let mut path = network.join(if changed {
        "history-verified.json"
    } else {
        "verified.json"
    });
    let mut index = 2;
    while path.exists() {
        path = network.join(format!(
            "{}-{index}.json",
            if changed {
                "history-verified"
            } else {
                "verified"
            }
        ));
        index += 1;
    }
    write(
        &path,
        &json!({"all_kv_unchanged":true,"current_head":current.hash(),"current_height":current.number(),"current_key":keys[if changed{2}else{1}],"ordinary_advance_not_proof_admitted":changed,"replays":replays}),
    )?;
    Ok(())
}
pub(crate) fn negative(out: &Path) -> Result<(), Error> {
    let network = out.join("network-rotation");
    let context: fixture::Context = read(&out.join("context.json"))?;
    let blocks: Vec<Block> = read(&out.join("blocks.json"))?;
    let first = shell_stark_prover::compact_canonical::decode_payload(&std::fs::read(
        network.join("proof1.bin"),
    )?)?;
    let raw = std::fs::read(network.join("proof2.bin"))?;
    let mut proof = shell_stark_prover::compact_canonical::decode_payload(&raw)?;
    proof.transactions[0]
        .signature
        .transaction
        .signature
        .equation
        .key = first.transactions[0]
        .signature
        .transaction
        .signature
        .equation
        .key
        .clone();
    let bytes =
        shell_stark_prover::compact_canonical::encode_payload(&proof, 256 * 1024 * 1024, true)?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state),
        context.authority,
        &context.authority_key,
    )?;
    let before = digest(node.store.as_ref())?;
    let tip = node
        .chain_store
        .get_head_hash()?
        .ok_or("rotation negative tip absent")?;
    let decoded = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
    let error = node
        .replay_canonical_transactions_with_proof(tip, blocks[1].hash(), &decoded)
        .err()
        .ok_or("old key certificate authorized replacement key")?;
    ensure(
        error.to_string().contains("public key")
            && before == digest(node.store.as_ref())?
            && raw == std::fs::read(network.join("proof2.bin"))?,
        "rotation negative changed original data or failed before key binding",
    )?;
    std::fs::write(network.join("old-key-refused.cbor"), &bytes)?;
    write(
        &network.join("old-key-refused.json"),
        &json!({"genuine_old_key_certificate":true,"correct_outer_hash":blake3_hash(&bytes),"error":error.to_string(),"all_kv_unchanged":true,"original_proof_unchanged":true,"new_proofs_generated":0,"scope":"full historical predicate refusal; not a new native block import"}),
    )?;
    Ok(())
}
